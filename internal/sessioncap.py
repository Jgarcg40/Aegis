"""Tope de sesión / rate-limit del proveedor. Sin el paquete internal.

El contenedor copia este fichero a bin/aegis_sessioncap.py.
Crédito/saldo lo sigue tratando looks_quota (pausa hasta el operador).
Solo dispara si el proveedor bloquea la IA, no si el agente habla del target.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

STALE_PAST_S = 15 * 60
MAX_WAIT_S = 24 * 60 * 60
CONSOLE_TAIL = 16_000
LAST_TAIL = 8_000

CREDIT_RX = re.compile(
    r"spending-limit|out of credits|insufficient.?quota|quota.?exceeded|"
    r"need a grok subscription|credit balance is too low|"
    r"exceeded your (current )?quota|out of extra usage|"
    r"you've hit your weekly limit|weekly limit|"
    r"billing|usage.?cap|no tokens? (left|remaining)|tokens? exhausted|"
    r"out of tokens|token.?limit|"
    r"余额不足|账号欠费|配额已用|额度不足|余额不够|欠费",
    re.I,
)

SESSION_RX = re.compile(
    r"session limit|you've hit your session|hit your session limit",
    re.I,
)

PROVIDER_API_RX = re.compile(
    r"API Error:[^\n]*(?:429|rate limit|too many requests|throttl)"
    r"|Rate limit reached for "
    r"|Throttling\.(?:Rate|Allocation)Quota"
    r"|\"error\"\s*:\s*\"rate_limit\""
    r"|resource_exhausted",
    re.I,
)
REFUSAL_RX = re.compile(
    r"safeguards flagged|cyber verification program|"
    r"api_refusal_category|model_refusal_no_fallback|"
    r"stop_reason\"\s*:\s*\"refusal\"|"
    r"\"stop_reason\"\s*:\s*\"refusal\"",
    re.I,
)

PROVIDER_RATE_RX = re.compile(
    r"rate limit reached|"
    r"too many requests|"
    r"throttling\.(rate|allocation)quota|"
    r"resource.?exhausted|rate_limit_exceeded|"
    r"rpm (limit|exceeded)|tpm (limit|exceeded)|"
    r"限流|请求过于频繁|速率限制|频率超限|访问频率|请求太频繁|并发超限",
    re.I,
)

ERROR_LINE_RX = re.compile(
    r"^\s*(?:API Error|You(?:'ve| have) hit|Rate limit reached|"
    r"Error[:\s]|Throttling|too many requests|"
    r"usage limit reached|resource_exhausted|"
    r"请求|限流)",
    re.I | re.M,
)

NARRATION_RX = re.compile(
    r"\b(ejecuto|crackeo|enumer|mejor:|el reset|la carrera|"
    r"el token|voy a|vamos a|el target|la web|"
    r"peticiones seguidas|filtrado)\b",
    re.I,
)

SOFT_LIMIT_RX = re.compile(r"you've hit your limit|usage limit reached", re.I)

# Saldo real del proveedor. Sin «billing» suelto (billing.corp, Flowise, etc.).
CREDIT_HOLD_RX = re.compile(
    r"spending-limit|"
    r"out of extra usage|"
    r"need a grok subscription|"
    r"credit balance is too low|"
    r"you've hit your limit|"
    r"you've hit your weekly limit|weekly limit|"
    r"billing_hard_limit|"
    r"insufficient[_\s-]?quota|"
    r"余额不足|账号欠费|配额已用|额度不足|余额不够|欠费",
    re.I,
)
CREDIT_WEAK_RX = re.compile(
    r"out of credits|quota.?exceeded|exceeded your (current )?quota|"
    r"usage limit reached|out of tokens|tokens? exhausted|"
    r"no tokens? (left|remaining)|usage.?cap|"
    r"l[ií]mite de (uso|gasto|cr[eé]dito)",
    re.I,
)
CREDIT_CTX_RX = re.compile(
    r"API Error:|is_api_error_message\"\s*:\s*true|"
    r"\"error\"\s*:\s*\"(?:insufficient_quota|billing_hard_limit)\"",
    re.I,
)
AUTH_HOLD_RX = re.compile(
    r"oauth session expired|"
    r"claude auth login|"
    r"not logged in\.\s*please run|"
    r"please run (?:claude |/)?(?:auth )?login|"
    r"please use /login|"
    r"failed to authenticate with (?:claude|anthropic)|"
    r"(?:claude|anthropic).{0,40}(?:oauth session|token (?:invalid|expired|revoked)|"
    r"could not be refreshed|authentication_failed)",
    re.I,
)
HARNESS_RX = re.compile(
    r"(?:opencode|codex).{0,120}(?:session not found|unknownerror|unexpected server error)|"
    r"(?:session not found|unknownerror).{0,80}(?:opencode|codex)",
    re.I,
)

RESET_CLOCK_RX = re.compile(
    r"resets?\s+(\d{1,2})(?::(\d{2}))?\s*(am|pm)?(?:\s*\(?UTC\)?)?",
    re.I,
)
TRY_IN_RX = re.compile(
    r"(?:try again in|please try again in|retry[- ]after|重试)\s*[:：]?\s*"
    r"(\d+(?:\.\d+)?)\s*(hours?|hrs?|h|minutes?|mins?|m|seconds?|secs?|s)?",
    re.I,
)
RETRY_AFTER_HDR_RX = re.compile(r"retry[- ]after[:\s]+(\d+(?:\.\d+)?)", re.I)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_epoch(ts: datetime) -> int:
    return int(ts.timestamp())


def read_limit_blobs(out: Path) -> tuple[str, str]:
    """last-message (corto) + cola de consola tras .quota-off."""
    console = out / "console.log"
    last = out / "last-message.txt"
    off = 0
    mark = out / ".quota-off"
    if mark.is_file():
        try:
            off = int((mark.read_text() or "0").strip() or 0)
        except ValueError:
            off = 0
    cons = ""
    if console.is_file():
        data = console.read_bytes()
        cons = data[off:][-CONSOLE_TAIL:].decode("utf-8", errors="replace")
    msg = ""
    if last.is_file() and (not mark.is_file() or last.stat().st_mtime >= mark.stat().st_mtime):
        msg = last.read_bytes()[-LAST_TAIL:].decode("utf-8", errors="replace")
    return msg, cons


def _is_credit(text: str) -> bool:
    t = text or ""
    if SESSION_RX.search(t):
        return False
    return bool(CREDIT_RX.search(t))


def parse_reset_at(text: str, *, now: datetime | None = None) -> int | None:
    """Epoch UTC del reset, o None. Mensaje recién vencido → 0 (ya pasó)."""
    now = now or _now()
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    t = text or ""

    m = RESET_CLOCK_RX.search(t)
    if m:
        hour = int(m.group(1))
        minute = int(m.group(2) or 0)
        ampm = (m.group(3) or "").lower()
        if ampm == "pm" and hour < 12:
            hour += 12
        if ampm == "am" and hour == 12:
            hour = 0
        if hour > 23 or minute > 59:
            return None
        candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        delta = (candidate - now).total_seconds()
        if delta >= 0:
            return _iso_epoch(candidate)
        if delta > -STALE_PAST_S:
            return 0
        nxt = candidate + timedelta(days=1)
        return _iso_epoch(nxt)

    m = TRY_IN_RX.search(t)
    if m:
        raw = float(m.group(1))
        unit = (m.group(2) or "s").lower()
        if unit.startswith("h"):
            sec = raw * 3600
        elif unit.startswith("m"):
            sec = raw * 60
        else:
            sec = raw
        if sec < 1:
            return 0
        return _iso_epoch(now + timedelta(seconds=min(sec, MAX_WAIT_S)))
    m = RETRY_AFTER_HDR_RX.search(t)
    if m:
        sec = float(m.group(1))
        if sec < 1:
            return 0
        return _iso_epoch(now + timedelta(seconds=min(sec, MAX_WAIT_S)))
    return None


def _json_objects(text: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            found.append(obj)
    return found


def _rate_event_info(obj: dict[str, Any]) -> dict[str, Any] | None:
    if str(obj.get("type") or "") != "rate_limit_event":
        return None
    info = obj.get("rate_limit_info")
    return info if isinstance(info, dict) else None


def _blocked_rate_event(text: str) -> int | bool:
    """Epoch de resetsAt, True si hay bloqueo sin hora, False si no hay bloqueo."""
    seen = False
    for obj in _json_objects(text):
        info = _rate_event_info(obj)
        if info is None:
            continue
        status = str(info.get("status") or "").strip().lower()
        # allowed / allowed_warning: la ventana sigue abierta. No es tope.
        if status.startswith("allowed") or status in ("", "ok"):
            continue
        kind = str(info.get("rateLimitType") or "").strip().lower()
        # seven_day / weekly / overage = cuota del plan (días). No esperar hora.
        if kind in {"seven_day", "weekly", "overage"}:
            continue
        seen = True
        try:
            ts = int(info.get("resetsAt"))
        except (TypeError, ValueError):
            ts = 0
        if ts > 0:
            return ts
    return True if seen else False


def _is_refusal(text: str) -> bool:
    return bool(REFUSAL_RX.search(text or ""))


def _provider_rate_error(text: str) -> bool:
    if PROVIDER_API_RX.search(text or ""):
        return True
    for obj in _json_objects(text):
        err = obj.get("error")
        if err == "rate_limit":
            return True
        if isinstance(err, dict) and str(err.get("type") or "") == "rate_limit_error":
            return True
    return False


def _short_provider_rate(text: str) -> bool:
    t = (text or "").strip()
    if not t or len(t) > 400:
        return False
    if '"tool_use"' in t or '"tool_result"' in t:
        return False
    if NARRATION_RX.search(t):
        return False
    if not ERROR_LINE_RX.search(t):
        return False
    return bool(PROVIDER_RATE_RX.search(t) or SOFT_LIMIT_RX.search(t))


def classify_limit(text: str, *, trusted: bool = True, now: datetime | None = None) -> dict[str, Any]:
    """kind=session|rate|none. resume_at: epoch, 0=ya pasó, None=sin hora."""
    t = text or ""
    if not t.strip():
        return {"kind": "none", "resume_at": None}
    if _is_credit(t) and not SESSION_RX.search(t):
        return {"kind": "none", "resume_at": None}

    reset = parse_reset_at(t, now=now)
    clock = now or _now()
    if reset and reset > 0:
        cap = _iso_epoch(clock) + MAX_WAIT_S
        if reset > cap:
            reset = cap

    if SESSION_RX.search(t):
        return {"kind": "session", "resume_at": reset}

    blocked = _blocked_rate_event(t)
    if blocked is not False:
        resume = blocked if isinstance(blocked, int) else reset
        return {"kind": "rate", "resume_at": resume}

    if _is_refusal(t) and not _provider_rate_error(t):
        return {"kind": "none", "resume_at": None}

    if _provider_rate_error(t):
        return {"kind": "rate", "resume_at": reset}

    if trusted and _short_provider_rate(t):
        return {"kind": "rate", "resume_at": reset}
    if trusted and reset and reset > 0 and SOFT_LIMIT_RX.search(t) and ERROR_LINE_RX.search(t):
        return {"kind": "rate", "resume_at": reset}
    return {"kind": "none", "resume_at": None}


def inspect_out(out: Path, *, now: datetime | None = None) -> dict[str, Any]:
    msg, cons = read_limit_blobs(out)
    hit = classify_limit(msg, trusted=True, now=now)
    if hit["kind"] != "none":
        return hit
    return classify_limit(cons, trusted=False, now=now)


def classify_quota(text: str, *, trusted: bool = True) -> bool:
    """Saldo/crédito del proveedor. No billing del target ni refusal."""
    t = text or ""
    if not t.strip() or SESSION_RX.search(t):
        return False
    if _is_refusal(t) and not CREDIT_HOLD_RX.search(t):
        return False
    if CREDIT_HOLD_RX.search(t):
        return True
    if CREDIT_WEAK_RX.search(t) and CREDIT_CTX_RX.search(t):
        return True
    if trusted and _short_credit_error(t):
        return True
    return False


def _short_credit_error(text: str) -> bool:
    t = (text or "").strip()
    if not t or len(t) > 400:
        return False
    if '"tool_use"' in t or '"tool_result"' in t or NARRATION_RX.search(t):
        return False
    if not ERROR_LINE_RX.search(t):
        return False
    return bool(CREDIT_HOLD_RX.search(t) or CREDIT_WEAK_RX.search(t))


def classify_auth(text: str, *, trusted: bool = True) -> bool:
    """OAuth/sesión del harness, no login del target."""
    t = text or ""
    if not t.strip() or _is_refusal(t):
        return False
    return bool(AUTH_HOLD_RX.search(t))


def classify_harness(text: str, *, trusted: bool = True) -> bool:
    t = text or ""
    return bool(t.strip() and HARNESS_RX.search(t))


def _inspect_bool(out: Path, fn) -> bool:
    msg, cons = read_limit_blobs(out)
    return bool(fn(msg, trusted=True) or fn(cons, trusted=False))


def inspect_quota(out: Path) -> bool:
    return _inspect_bool(out, classify_quota)


def inspect_auth(out: Path) -> bool:
    return _inspect_bool(out, classify_auth)


def inspect_harness(out: Path) -> bool:
    return _inspect_bool(out, classify_harness)


def _read_meta(out: Path) -> dict[str, Any]:
    path = out / "meta.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _own_like_console(path: Path, out: Path) -> None:
    """El contenedor corre como root: no dejar meta.json en 0600/root o el host no lo ve."""
    try:
        os.chmod(path, 0o644)
    except OSError:
        pass
    ref = out / "console.log"
    if not ref.is_file():
        return
    try:
        st = ref.stat()
        os.chown(path, st.st_uid, st.st_gid)
    except OSError:
        pass


def _write_meta(out: Path, meta: dict[str, Any]) -> None:
    path = out / "meta.json"
    tmp = path.with_name("meta.json.tmp")
    tmp.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    _own_like_console(tmp, out)
    tmp.replace(path)
    _own_like_console(path, out)


def mark_open_pause(out: Path, *, now: datetime | None = None) -> bool:
    """Abre paused_since. Si ya hay tramo, no pisa."""
    meta = _read_meta(out)
    if not meta or str(meta.get("paused_since") or "").strip():
        return False
    clock = now or _now()
    if clock.tzinfo is None:
        clock = clock.replace(tzinfo=timezone.utc)
    meta["paused_since"] = clock.isoformat()
    _write_meta(out, meta)
    return True


def fold_open_pause(out: Path, *, now: datetime | None = None) -> int:
    """Suma el tramo abierto a paused_s. Sin paused_since no toca (evita doble cuenta)."""
    meta = _read_meta(out)
    if not meta:
        return 0
    since = str(meta.get("paused_since") or "").strip()
    if not since:
        return 0
    try:
        start = datetime.fromisoformat(since.replace("Z", "+00:00"))
    except ValueError:
        start = None
    if start is None:
        meta.pop("paused_since", None)
        _write_meta(out, meta)
        return 0
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    clock = now or _now()
    if clock.tzinfo is None:
        clock = clock.replace(tzinfo=timezone.utc)
    add = max(0, int((clock - start).total_seconds()))
    try:
        held = int(meta.get("paused_s") or 0)
    except (TypeError, ValueError):
        held = 0
    meta["paused_s"] = held + add
    meta.pop("paused_since", None)
    _write_meta(out, meta)
    return add


def format_line(hit: dict[str, Any]) -> str:
    kind = str(hit.get("kind") or "none")
    if kind == "none":
        return "none"
    resume = hit.get("resume_at")
    if resume is None:
        return f"{kind} -"
    return f"{kind} {int(resume)}"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="aegis_sessioncap")
    sub = p.add_subparsers(dest="cmd", required=True)
    ins = sub.add_parser("inspect")
    ins.add_argument("out")
    for name in ("quota", "auth", "harness"):
        sp = sub.add_parser(name)
        sp.add_argument("out")
    pr = sub.add_parser("parse")
    pr.add_argument("text", nargs="?")
    mk = sub.add_parser("mark-pause")
    mk.add_argument("out")
    fd = sub.add_parser("fold-pause")
    fd.add_argument("out")
    args = p.parse_args(argv)
    if args.cmd == "inspect":
        print(format_line(inspect_out(Path(args.out))))
        return 0
    if args.cmd == "quota":
        return 0 if inspect_quota(Path(args.out)) else 1
    if args.cmd == "auth":
        return 0 if inspect_auth(Path(args.out)) else 1
    if args.cmd == "harness":
        return 0 if inspect_harness(Path(args.out)) else 1
    if args.cmd == "mark-pause":
        return 0 if mark_open_pause(Path(args.out)) else 1
    if args.cmd == "fold-pause":
        fold_open_pause(Path(args.out))
        return 0
    text = args.text if args.text is not None else sys.stdin.read()
    print(format_line(classify_limit(text, trusted=True)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
