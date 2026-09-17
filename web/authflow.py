from __future__ import annotations

import errno
import fcntl
import os
import pty
import secrets
import signal
import struct
import termios
import threading
import time
from dataclasses import dataclass, field

from pathlib import Path

from internal.auth import PROVIDER_ALIASES, ensure_alive_cwd, host_cli_env, opencode_bin


@dataclass
class LoginSession:
    sid: str
    provider: str
    method: str
    pid: int
    fd: int
    started: float
    buffer: bytearray = field(default_factory=bytearray)
    alive: bool = True
    exit_code: int | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    def read_into_buffer(self) -> None:
        try:
            data = os.read(self.fd, 8192)
        except OSError as exc:
            if exc.errno in (errno.EIO, errno.EBADF):
                self._reap()
            return
        if not data:
            self._reap()
            return
        with self.lock:
            self.buffer.extend(data)
            if len(self.buffer) > 262144:
                del self.buffer[: len(self.buffer) - 262144]

    def snapshot(self) -> str:
        with self.lock:
            return self.buffer.decode("utf-8", "replace")

    def write(self, text: str) -> None:
        if not self.alive:
            return
        try:
            os.write(self.fd, text.encode("utf-8"))
        except OSError:
            pass

    def _reap(self) -> None:
        if not self.alive:
            return
        self.alive = False
        try:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.exit_code = os.waitstatus_to_exitcode(status)
        except OSError:
            pass
        try:
            os.close(self.fd)
        except OSError:
            pass

    def close(self) -> None:
        if self.alive:
            try:
                os.kill(self.pid, signal.SIGTERM)
            except OSError:
                pass
        self._reap()


def new_login_sid() -> str:
    """sid de login no adivinable (no es epoch)."""
    return "login-" + secrets.token_urlsafe(16)


class LoginManager:
    """Corre `opencode auth login` en un PTY y lo expone como terminal web.

    Así el operador completa el flujo real (URL de consentimiento, código
    device, o pegar API key) desde el navegador, sin adivinar labels que
    cambian entre versiones de OpenCode.
    """

    def __init__(self) -> None:
        self.sessions: dict[str, LoginSession] = {}
        self.lock = threading.Lock()

    def create(self, provider: str, method: str = "") -> LoginSession:
        p = (provider or "").strip().lower()
        if p in {"claude", "claude-code"}:
            from internal.claude import ensure_host_home, wrapper_bin

            binary = wrapper_bin()
            if binary is None:
                raise RuntimeError("Claude Code no está instalado en el host")
            argv = [str(binary), "auth", "login"]
            env = host_cli_env()
            ensure_host_home()
        elif p in {"codex", "codex-cli"}:
            from internal.codex import ensure_host_home, login_argv, wrapper_bin

            binary = wrapper_bin()
            if binary is None:
                raise RuntimeError("Codex CLI no está instalado en el host")
            argv = login_argv(binary)
            env = host_cli_env()
            env["CODEX_HOME"] = str(ensure_host_home(Path.home() / ".codex"))
        else:
            binary = opencode_bin()
            if binary is None:
                raise RuntimeError("OpenCode no está instalado en el host")
            argv = [str(binary), "auth", "login"]
            pid_provider = PROVIDER_ALIASES.get(provider, provider) if provider else ""
            if pid_provider:
                argv += ["--provider", pid_provider]
            env = host_cli_env()
        env["COLUMNS"] = "512"
        env["LINES"] = "40"
        home = Path.home()
        ensure_alive_cwd(home)
        env["PWD"] = str(home)
        env["HOME"] = str(home)
        sid = new_login_sid()
        pid, fd = pty.fork()
        if pid == 0:  # hijo
            try:
                os.chdir(str(home))
                os.environ.update(env)
                os.execvp(argv[0], argv)
            except Exception:
                os._exit(127)
        try:
            _set_winsize(fd, 40, 512)
        except OSError:
            pass
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        sess = LoginSession(
            sid=sid, provider=provider, method=method, pid=pid, fd=fd, started=time.time()
        )
        with self.lock:
            self.sessions[sid] = sess
        return sess

    def get(self, sid: str) -> LoginSession | None:
        with self.lock:
            return self.sessions.get(sid)

    def close(self, sid: str) -> bool:
        with self.lock:
            sess = self.sessions.pop(sid, None)
        if sess:
            sess.close()
            return True
        return False

    def gc(self) -> None:
        with self.lock:
            dead = [s for s in self.sessions.values() if not s.alive and time.time() - s.started > 300]
            for s in dead:
                self.sessions.pop(s.sid, None)


def _set_winsize(fd: int, rows: int, cols: int) -> None:
    winsize = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)
