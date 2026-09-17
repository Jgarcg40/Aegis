"""Invocador ya fijado tras foothold: el relevo manda comandos sin rehacer el PoC.

No guarda payloads. Solo argv local que ya imprimió un uid= en consola
y el hueco del último argumento (el comando remoto).
"""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

HOLD_NAME = ".cmd-hold.json"
WRAPPER_NAME = "aegis-cmd"
MODULE_COPY = "aegis_cmdhold.py"

_REMOTE_HEAD = re.compile(
    r"^(id|whoami|hostname|uname|pwd|env|printenv|cat|ls|find|head|tail|"
    r"sqlite3|python3?|php|perl|awk|sed|cut|wc|stat|strings|file|xxd|"
    r"curl|wget|nc|ncat|ss|ps|netstat|ip|ifconfig|mount|df|du|id;)\b",
    re.I,
)
_INVOKER = re.compile(
    r"\b(python3?|node|nodejs|bash|sh)\b.*\.(py|js|mjs|cjs|sh)\b",
    re.I,
)
_SKIP = re.compile(
    r"git\s+clone|readme\.md|\bls\s+/run/aegis/out/loot/poc|"
    r"mkdir\s+-p\s+/run/aegis/out/loot|"
    r"python3?\s+-|<<",
    re.I,
)
_BINS = {"python3", "python", "node", "nodejs", "bash", "sh"}
_FRAG = re.compile(
    r"(?:cd\s+(?P<dir>[^\s;|&]+)\s*&&\s*)?"
    r"(?P<bin>python3?|node|nodejs|bash|sh)\s+"
    r"(?P<script>\S+\.(?:py|js|mjs|cjs|sh))"
    r"(?P<tail>[^|;]*)",
    re.I,
)


def hold_path(out_dir: Path) -> Path:
    return Path(out_dir) / HOLD_NAME


def load_hold(out_dir: Path) -> dict[str, Any] | None:
    p = hold_path(out_dir)
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def commands_from_console(text: str) -> list[str]:
    found: list[str] = []
    for line in text.splitlines():
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        found.extend(_commands_from_obj(obj))
    return found


def commands_from_audit(text: str) -> list[str]:
    found: list[str] = []
    for line in text.splitlines():
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        cmd = obj.get("argv") or obj.get("command")
        if cmd:
            found.append(str(cmd))
    return found


def _commands_from_obj(obj: Any) -> list[str]:
    out: list[str] = []
    if not isinstance(obj, dict):
        return out
    msg = obj.get("message")
    content = msg.get("content") if isinstance(msg, dict) else None
    if isinstance(content, list):
        for part in content:
            if not isinstance(part, dict):
                continue
            name = str(part.get("name") or part.get("tool") or "").lower()
            if name not in {"bash", "shell"}:
                continue
            cmd = (part.get("input") or {}).get("command") if isinstance(part.get("input"), dict) else None
            if cmd:
                out.append(str(cmd))
    part = obj.get("part")
    if isinstance(part, dict):
        state = part.get("state") if isinstance(part.get("state"), dict) else {}
        inp = state.get("input") if isinstance(state.get("input"), dict) else {}
        cmd = inp.get("command")
        tool = str(part.get("tool") or part.get("type") or "").lower()
        if cmd and tool in {"bash", "shell", "tool", ""}:
            out.append(str(cmd))
    return out


def _looks_remote_cmd(arg: str) -> bool:
    text = (arg or "").strip()
    if not text or len(text) > 500:
        return False
    if text.startswith(("-", "http://", "https://", "/")):
        return False
    if text.endswith((".py", ".js", ".sh", ".mjs", ".cjs")):
        return False
    return bool(_REMOTE_HEAD.match(text))


def _is_invoker(cmd: str) -> bool:
    if not cmd or _SKIP.search(cmd):
        return False
    if _INVOKER.search(cmd):
        return True
    return bool(re.search(r"/(?:tmp|run/aegis/out)/[^\s]+\.(py|js|mjs|cjs|sh)\b", cmd))


def _resolve_script(script: str, cd_dir: str) -> str:
    if script.startswith("/") or not cd_dir:
        return script
    return str(Path(cd_dir.rstrip("/'\"")) / script)


def _argv_and_slot(cmd: str) -> tuple[list[str], int] | None:
    """Invocador corto (intérprete + script + hueco), no el for/pipe de alrededor."""
    if "<<" in cmd or re.search(r"\bpython3?\s+-", cmd):
        return None
    chosen: tuple[list[str], int] | None = None
    for m in _FRAG.finditer(cmd):
        bin_name = m.group("bin")
        script = _resolve_script(m.group("script"), m.group("dir") or "")
        tail = m.group("tail") or ""
        try:
            extra = shlex.split(tail, posix=True)
        except ValueError:
            continue
        extra = [a for a in extra if a not in {"2>&1", "2>/dev/null", ">/dev/null"}]
        argv = [bin_name, script, *extra]
        slot = None
        for i in range(len(argv) - 1, 1, -1):
            if _looks_remote_cmd(argv[i]):
                slot = i
                break
        if slot is None:
            continue
        chosen = (argv, slot)
    return chosen


def hold_ok(hold: dict[str, Any] | None) -> bool:
    if not hold or not isinstance(hold, dict):
        return False
    argv = hold.get("argv")
    slot = hold.get("slot")
    if not isinstance(argv, list) or len(argv) < 3 or not isinstance(slot, int):
        return False
    if slot < 2 or slot >= len(argv):
        return False
    bin_name = Path(str(argv[0])).name.lower()
    if bin_name not in _BINS:
        return False
    script = str(argv[1])
    if not re.search(r"\.(py|js|mjs|cjs|sh)$", script, re.I):
        return False
    return _looks_remote_cmd(str(argv[slot]))


def hold_ready(out_dir: Path) -> bool:
    return hold_ok(load_hold(out_dir))


def _pick_hold(cmds: list[str], *, uid: str = "") -> dict[str, Any] | None:
    for cmd in reversed(cmds):
        parsed = _argv_and_slot(cmd)
        if not parsed:
            continue
        argv, slot = parsed
        hold = {
            "uid": uid,
            "argv": argv,
            "slot": slot,
            "bin": argv[0],
        }
        if hold_ok(hold):
            return hold
    return None


def capture_from_console(console: str, *, uid: str = "", audit: str = "") -> dict[str, Any] | None:
    """Último invocador local (script + hueco de comando) antes del uid=."""
    mark = console.rfind("[aegis] T")
    turn = console[mark:] if mark >= 0 else ""
    blobs = []
    if turn:
        blobs.append([c for c in commands_from_console(turn) if _is_invoker(c)])
    blobs.append([c for c in commands_from_console(console[-200000:]) if _is_invoker(c)])
    if audit:
        blobs.append([c for c in commands_from_audit(audit) if _is_invoker(c)])
    for cmds in blobs:
        hold = _pick_hold(cmds, uid=uid)
        if hold:
            return hold
    return None


def write_hold(out_dir: Path, hold: dict[str, Any]) -> Path:
    dest = hold_path(out_dir)
    dest.write_text(json.dumps(hold, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return dest


def capture_out(out_dir: Path) -> dict[str, Any] | None:
    """Lee consola + .foothold y escribe .cmd-hold.json si hay invocador."""
    out = Path(out_dir)
    try:
        console = (out / "console.log").read_text(encoding="utf-8", errors="replace")
    except OSError:
        console = ""
    try:
        audit = (out / ".audit" / "commands.jsonl").read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        audit = ""
    uid = ""
    fp = out / ".foothold"
    if fp.is_file():
        try:
            uid = fp.read_text(encoding="utf-8", errors="replace").strip().splitlines()[0]
        except OSError:
            uid = ""
    if not uid:
        m = re.search(r"\buid=\d+\([^)]+\)", console)
        if m:
            uid = m.group(0)
    hold = capture_from_console(console, uid=uid, audit=audit)
    prev = load_hold(out)
    if not hold:
        return prev
    if hold_ok(prev) and not hold_ok(hold):
        return prev
    write_hold(out, hold)
    return hold


def replay(out_dir: Path, remote: str) -> int:
    hold = load_hold(out_dir)
    if not hold:
        print("aegis-cmd: no hay invocador fijado en este run", file=sys.stderr)
        return 2
    argv = hold.get("argv")
    slot = hold.get("slot")
    if not isinstance(argv, list) or not argv or not isinstance(slot, int):
        print("aegis-cmd: invocador sin hueco de comando", file=sys.stderr)
        return 2
    if slot < 0 or slot >= len(argv):
        print("aegis-cmd: hueco inválido", file=sys.stderr)
        return 2
    if not (remote or "").strip():
        print("uso: aegis-cmd 'comando'", file=sys.stderr)
        return 2
    run = [str(x) for x in argv]
    run[slot] = remote.strip()
    return subprocess.call(run)


WRAPPER = """#!/usr/bin/env python3
import os, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
mod = HERE / "aegis_cmdhold.py"
out = Path(os.environ.get("AEGIS_OUT", "/run/aegis/out"))
if not mod.is_file():
    print("aegis-cmd: falta aegis_cmdhold.py", file=sys.stderr)
    raise SystemExit(2)
import importlib.util
spec = importlib.util.spec_from_file_location("aegis_cmdhold", mod)
pkg = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(pkg)
raise SystemExit(pkg.replay(out, " ".join(sys.argv[1:])))
"""


def write_aegis_cmd(bin_dir: Path) -> Path:
    dest_dir = Path(bin_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_mod = dest_dir / MODULE_COPY
    dest_mod.write_text(Path(__file__).read_text(encoding="utf-8"), encoding="utf-8")
    dest = dest_dir / WRAPPER_NAME
    dest.write_text(WRAPPER, encoding="utf-8")
    dest.chmod(0o755)
    return dest


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("uso: cmdhold.py capture <out>| replay <out> <comando>", file=sys.stderr)
        return 2
    verb = args[0]
    if verb == "capture":
        out = Path(args[1] if len(args) > 1 else os.environ.get("AEGIS_OUT", "/run/aegis/out"))
        hold = capture_out(out)
        print("ok" if hold else "none")
        return 0 if hold else 1
    if verb == "ready":
        out = Path(args[1] if len(args) > 1 else os.environ.get("AEGIS_OUT", "/run/aegis/out"))
        ok = hold_ready(out)
        print("ready" if ok else "no")
        return 0 if ok else 1
    if verb == "replay":
        out = Path(args[1] if len(args) > 1 else os.environ.get("AEGIS_OUT", "/run/aegis/out"))
        remote = " ".join(args[2:])
        return replay(out, remote)
    print("uso: cmdhold.py capture|replay", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
