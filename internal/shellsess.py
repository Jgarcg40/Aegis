"""Sesión de shell persistente (un socket, muchos comandos).

Sin dependencias de Aegis: se copia al sandbox como aegis_shell.py.
"""
from __future__ import annotations

import argparse
import os
import select
import socket
import sys
import time
from pathlib import Path

OUT = Path(os.environ.get("AEGIS_OUT", "/run/aegis/out"))
SESS = OUT / "loot" / "shell"


def _paths() -> tuple[Path, Path, Path]:
    SESS.mkdir(parents=True, exist_ok=True)
    return SESS / "session.log", SESS / "session.cmd", SESS / "session.meta"


def listen(host: str, port: int) -> int:
    log, cmd, meta = _paths()
    cmd.write_text("", encoding="utf-8")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(1)
    sock.settimeout(1.0)
    meta.write_text(f"{host}:{port}\n", encoding="utf-8")
    print(f"aegis-shell: listening {host}:{port}", flush=True)
    conn: socket.socket | None = None
    offset = 0
    with log.open("ab") as lf:
        while True:
            if conn is None:
                try:
                    conn, addr = sock.accept()
                    conn.setblocking(False)
                    lf.write(f"\n[+] connected {addr}\n".encode())
                    lf.flush()
                    print(f"aegis-shell: connected {addr}", flush=True)
                except TimeoutError:
                    continue
            rlist = [conn]
            try:
                ready, _, _ = select.select(rlist, [], [], 0.3)
            except (ValueError, OSError):
                conn = None
                continue
            if ready:
                try:
                    chunk = conn.recv(4096)
                except (OSError, ConnectionError):
                    chunk = b""
                if not chunk:
                    lf.write(b"\n[-] disconnected\n")
                    lf.flush()
                    try:
                        conn.close()
                    except OSError:
                        pass
                    conn = None
                    continue
                lf.write(chunk)
                lf.flush()
            if conn is not None:
                try:
                    data = cmd.read_bytes()
                except OSError:
                    data = b""
                if len(data) > offset:
                    payload = data[offset:]
                    offset = len(data)
                    if not payload.endswith(b"\n"):
                        payload += b"\n"
                    try:
                        conn.sendall(payload)
                    except OSError:
                        conn = None
    return 0


def send(line: str) -> int:
    _, cmd, _ = _paths()
    with cmd.open("a", encoding="utf-8") as fh:
        fh.write(line.rstrip("\n") + "\n")
    print("queued", line)
    return 0


def tail(seconds: float = 2.0) -> int:
    log, _, _ = _paths()
    if not log.is_file():
        print("sin session.log — aegis-shell listen primero", file=sys.stderr)
        return 1
    pos = log.stat().st_size
    time.sleep(max(0.2, seconds))
    data = log.read_bytes()[pos:]
    sys.stdout.buffer.write(data or b"(sin salida nueva)\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="aegis-shell")
    sub = p.add_subparsers(dest="cmd", required=True)
    pl = sub.add_parser("listen")
    pl.add_argument("--host", default="0.0.0.0")
    pl.add_argument("--port", type=int, required=True)
    ps = sub.add_parser("send")
    ps.add_argument("line")
    pt = sub.add_parser("recv")
    pt.add_argument("--wait", type=float, default=2.0)
    args = p.parse_args(argv)
    if args.cmd == "listen":
        return listen(args.host, args.port)
    if args.cmd == "send":
        return send(args.line)
    return tail(args.wait)


if __name__ == "__main__":
    raise SystemExit(main())
