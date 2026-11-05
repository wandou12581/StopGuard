import os
import re
import signal
import subprocess
import threading
import time
from typing import Optional, Tuple

import psutil
from mcdreforged.api.all import *

PLUGIN_METADATA = {
    'id': 'stop_guard',
    'version': '1.0.0',
    'name': 'StopGuard',
    'description': {
        'en_us': 'Kill the server JVM if it lingers after the world has been saved',
        'zh_cn': '服务端关服卡死（世界已保存但 JVM 不退出）时自动强杀该 JVM',
    },
    'author': ['server admin'],
    'dependencies': {'mcdreforged': '>=2.13.0'},
}


class Config(Serializable):
    enabled: bool = True
    # 正则（完全匹配）：服务端开始关闭
    stopping_pattern: str = 'Stopping the server'
    # 正则（完全匹配）：世界保存完成
    saved_pattern: str = '.*All dimensions are saved'
    # 开始关服后，最多等多久让世界保存完成（秒）
    save_timeout: float = 120.0
    # 世界保存完成后，再等多久让进程自己退出（秒）
    exit_timeout: float = 10.0
    # SIGTERM 之后等多久再 SIGKILL（秒）
    term_wait: float = 15.0


config: Config = Config()
guard: Optional['StopGuard'] = None


class StopGuard:
    def __init__(self, server: PluginServerInterface):
        self.server = server
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self._saved = threading.Event()
        self._stopping = False
        self._pid: Optional[int] = None
        self._starttime: Optional[int] = None

    # ---------------- /proc helpers ----------------
    @staticmethod
    def read_starttime(pid: int) -> Optional[int]:
        """读取进程启动时间，用来防 PID 复用"""
        try:
            with open('/proc/{}/stat'.format(pid), 'rb') as f:
                raw = f.read()
            # comm 可能含空格/括号，从最后一个 ')' 后解析；第 22 个字段为 starttime
            return int(raw[raw.rfind(b')') + 2:].split()[19])
        except Exception:
            return None

    @staticmethod
    def read_stat(pid: int) -> Tuple[Optional[str], Optional[int]]:
        """返回 (进程状态, starttime)"""
        try:
            with open('/proc/{}/stat'.format(pid), 'rb') as f:
                raw = f.read()
            rest = raw[raw.rfind(b')') + 2:].split()
            return rest[0].decode(), int(rest[19])
        except Exception:
            return None, None

    @staticmethod
    def is_jvm(pid: int) -> bool:
        try:
            with open('/proc/{}/maps'.format(pid)) as f:
                return 'libjvm.so' in f.read()
        except Exception:
            return False

    def is_alive(self, pid: int, starttime: Optional[int]) -> bool:
        if starttime is None:
            return False
        state, st = self.read_stat(pid)
        # 僵尸进程（Z）已经退出，只是还没被父进程回收
        return st == starttime and state not in (None, 'Z')

    def find_server_jvm(self) -> Tuple[Optional[int], Optional[int]]:
        """找到服务端 java 进程的 pid（MCDR 的 get_server_pid 返回的是 sh 包装进程）"""
        pids = []
        try:
            pids = list(self.server.get_server_pid_all())
        except Exception:
            pids = []
        for pid in pids:
            if self.is_jvm(pid):
                return pid, self.read_starttime(pid)
        # 兜底：从 MCDR 进程的后代里找加载了 libjvm.so 的进程
        try:
            for child in psutil.Process(os.getpid()).children(recursive=True):
                if self.is_jvm(child.pid):
                    return child.pid, self.read_starttime(child.pid)
        except Exception:
            pass
        return None, None

    # ---------------- state ----------------
    def is_stopping(self) -> bool:
        with self._lock:
            return self._stopping

    def state(self) -> Tuple[bool, Optional[int], bool]:
        with self._lock:
            return self._stopping, self._pid, self._saved.is_set()

    def reset(self) -> None:
        with self._lock:
            self._stopping = False
            self._cancel.set()
            self._saved.clear()
            self._pid = None
            self._starttime = None

    def arm(self, reason: str) -> None:
        with self._lock:
            # 取消上一轮，重置存档标记
            self._cancel.set()
            self._cancel = threading.Event()
            cancel = self._cancel
            self._saved.clear()
            self._stopping = True
            pid, starttime = self.find_server_jvm()
            self._pid, self._starttime = pid, starttime

        if pid is None:
            self.server.logger.warning('[StopGuard] 检测到关服（%s），但没有找到服务端 JVM 进程', reason)
            return

        self.server.logger.info(
            '[StopGuard] 检测到关服（%s），JVM pid=%s；等待存档最多 %.0fs，之后等待退出 %.0fs',
            reason, pid, config.save_timeout, config.exit_timeout,
        )
        threading.Thread(
            target=self._worker, args=(pid, starttime, cancel, self._saved),
            name='StopGuard', daemon=True,
        ).start()

    def mark_saved(self) -> None:
        with self._lock:
            if self._stopping and not self._saved.is_set():
                self._saved.set()
                self.server.logger.info('[StopGuard] 世界已保存')

    # ---------------- worker ----------------
    def _worker(self, pid: int, starttime: Optional[int],
                cancel: threading.Event, saved: threading.Event) -> None:
        try:
            self._wait_and_kill(
                pid, starttime, cancel, saved,
                config.save_timeout, config.exit_timeout, config.term_wait,
            )
        except Exception:
            self.server.logger.exception('[StopGuard] 工作线程异常')

    def _wait_and_kill(self, pid: int, starttime: Optional[int],
                       cancel: threading.Event, saved: threading.Event,
                       save_timeout: float, exit_timeout: float, term_wait: float) -> None:
        # 阶段 1：等待世界保存完成（或超时）
        deadline = time.time() + save_timeout
        while time.time() < deadline:
            if cancel.is_set():
                return
            if saved.is_set():
                break
            time.sleep(0.2)
        if not saved.is_set():
            self.server.logger.warning(
                '[StopGuard] 等待存档超时（%.0fs），继续等待进程退出；若此时仍在存档，强杀有风险',
                save_timeout,
            )

        # 阶段 2：等待进程自己退出
        deadline = time.time() + exit_timeout
        while time.time() < deadline:
            if cancel.is_set():
                return
            if not self.is_alive(pid, starttime):
                self.server.logger.info('[StopGuard] 服务端已自行退出，取消强杀')
                return
            time.sleep(0.2)

        if cancel.is_set() or not self.is_alive(pid, starttime):
            return

        # 阶段 3：SIGTERM -> SIGKILL
        self.server.logger.warning('[StopGuard] 世界已保存但进程 %s 仍未退出，发送 SIGTERM', pid)
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return

        deadline = time.time() + term_wait
        while time.time() < deadline:
            if not self.is_alive(pid, starttime):
                self.server.logger.info('[StopGuard] 进程 %s 已退出', pid)
                return
            time.sleep(0.2)

        self.server.logger.warning('[StopGuard] 进程 %s 仍未退出，发送 SIGKILL', pid)
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


# ---------------- MCDR events ----------------

def on_load(server: PluginServerInterface, prev_module):
    global config, guard
    config = server.load_config_simple(target_class=Config)
    guard = StopGuard(server)
    server.register_command(
        Literal('!!stopguard')
        .runs(_status_command)
        .then(Literal('status').runs(_status_command))
        .then(Literal('test').runs(_test_command))
    )
    pid, _ = guard.find_server_jvm()
    server.logger.info(
        '[StopGuard] loaded, enabled=%s, detected server JVM=%s, config: save_timeout=%.0fs exit_timeout=%.0fs term_wait=%.0fs',
        config.enabled, pid, config.save_timeout, config.exit_timeout, config.term_wait,
    )


def on_unload(server: PluginServerInterface):
    if guard is not None:
        guard.reset()


def on_info(server: PluginServerInterface, info: Info):
    if info.is_user or guard is None or not config.enabled:
        return
    if re.fullmatch(config.stopping_pattern, info.content):
        guard.arm('server output')
        return
    if guard.is_stopping() and re.fullmatch(config.saved_pattern, info.content):
        guard.mark_saved()


def on_server_startup(server: PluginServerInterface):
    if guard is not None:
        guard.reset()
        pid, _ = guard.find_server_jvm()
        server.logger.info('[StopGuard] 服务端已启动，检测到 JVM=%s', pid)


def on_server_stop(server: PluginServerInterface, return_code: int):
    if guard is not None:
        guard.reset()


# ---------------- commands ----------------

def _check_admin(source: CommandSource) -> bool:
    if source.has_permission(PermissionLevel.ADMIN):
        return True
    source.reply('§cStopGuard: 需要管理员权限')
    return False


def _status_command(source: CommandSource):
    if not _check_admin(source):
        return
    stopping, pid, saved = guard.state()
    exist_pid, _ = guard.find_server_jvm()
    lines = [
        'StopGuard: enabled={}, stopping={}, saved={}'.format(config.enabled, stopping, saved),
        '  config: save_timeout={}s, exit_timeout={}s, term_wait={}s'.format(
            config.save_timeout, config.exit_timeout, config.term_wait),
        '  current server JVM: {}'.format(exist_pid),
    ]
    source.reply('\n'.join(lines))
    for line in lines:
        guard.server.logger.info('[StopGuard] %s', line)


def _test_command(source: CommandSource):
    if not _check_admin(source):
        return
    source.reply('§bStopGuard§r 自测已开始，约 5 秒内完成，结果见 MCDR 日志')
    threading.Thread(target=_run_selftest, name='StopGuard-test', daemon=True).start()


def _run_selftest():
    server = guard.server
    proc = None
    try:
        proc = subprocess.Popen(['sleep', '300'])
        starttime = StopGuard.read_starttime(proc.pid)
        server.logger.info(
            '[StopGuard] 自测：启动假进程 pid=%s，模拟“存档已完成”，应在约 1 秒后被 SIGTERM',
            proc.pid,
        )
        cancel = threading.Event()
        saved = threading.Event()
        saved.set()
        guard._wait_and_kill(proc.pid, starttime, cancel, saved, 0.2, 1.0, 3.0)
        time.sleep(0.2)
        if proc.poll() is None:
            server.logger.error('[StopGuard] 自测失败：假进程仍存活')
        else:
            server.logger.info('[StopGuard] 自测通过：假进程已被清理（returncode=%s）', proc.returncode)
    except Exception:
        server.logger.exception('[StopGuard] 自测异常')
    finally:
        if proc is not None and proc.poll() is None:
            try:
                proc.kill()
                proc.wait(timeout=3)
            except Exception:
                pass
