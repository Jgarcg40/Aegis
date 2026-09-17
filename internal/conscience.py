"""Conciencia: otro modelo revisa el run y, si hay atasco, corta el turno.

El siguiente turno es persist seco. El STEER lleva rutas, no proofs.
El juez lee el disco como el comprobador de cierre (findings, consola, loot).
No reescribe fichas: eso es el cierre y el verificador de cuentas.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FIRST_REVIEW_S = 20 * 60
TIGHT_S = 12 * 60
STRETCH_S = 20 * 60
AFTER_CUT_S = 15 * 60
RETRY_S = 5 * 60
LLM_TIMEOUT_S = 90
HARNESS_REVIEW_S = 180
CONSOLE_CHARS = 24_000
CMD_KEEP = 40
INTENT_KEEP = 16
RESULT_KEEP = 28
CONSOLE_PARSE_BYTES = 400_000
STUCK_PAUSE_AT = 4
TOKEN_BURN = 80_000
# muchos argv distintos recientes = exploración, no bucle
ACTIVE_DISTINCT_MIN = 12
# Ventana de diversidad: misma idea que engage.LOOP_WINDOW. Mirar el cmd_log
# entero (hasta 40) enmascaraba un bucle tardío detrás de recon diversa.
ACTIVITY_WINDOW = 15
# El juez escribe poco; no recortar el memo que ve el atacante.
WHAT_MAX = 16_000
WHY_MAX = 16_000
ROUTE_MAX = 4_000
ROUTE_N = 8
ISSUE_MAX = 4_000
ISSUE_N = 16
HIST_WHAT_MAX = 16_000

META_NAME = "CONSCIENCE.json"
MD_NAME = "CONSCIENCE.md"
CUT_NAME = ".conscience-cut"
PAUSE_NAME = ".conscience-pause"
CUT_STEER = (
    "Sesión nueva tras un atasco. No reinicies ni rehagas lo ya cubierto.\n"
    "Sigue solo RESUME.md. No abras STATE.md, BRIEF.md, PIVOT.md ni engagement.json.\n"
    "No leas findings/*.json.\n"
    "No repitas el último tipo de trabajo; cambia de capa o de tipo de ejecutor. "
    "Que un ejecutor falle no cierra el plano.\n"
)


def enabled() -> bool:
    raw = (os.environ.get("AEGIS_CONSCIENCE") or "1").strip().lower()
    return raw not in {"0", "off", "false", "no"}


def _now() -> float:
    return time.time()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def load_meta(out_dir: Path) -> dict[str, Any]:
    meta = _read_json(out_dir / META_NAME)
    meta.setdefault("next_ts", 0.0)
    meta.setdefault("last_ts", 0.0)
    meta.setdefault("last_verdict", "")
    meta.setdefault("stuck_streak", 0)
    meta.setdefault("progress", {"flags": 0, "findings": 0})
    meta.setdefault("console_off", 0)
    meta.setdefault("reviews", 0)
    meta.setdefault("fail_n", 0)
    meta.setdefault("last_error", "")
    meta.setdefault("history", [])
    return meta


def public_status(
    out_dir: Path,
    *,
    now: float | None = None,
    watcher: bool | None = None,
    ended: bool = False,
) -> dict[str, Any]:
    """Snapshot para la UI: pendiente / atrasada / ok / corte. Sin LLM."""
    meta = load_meta(out_dir)
    now = _now() if now is None else now
    next_ts = float(meta.get("next_ts") or 0)
    last_ts = float(meta.get("last_ts") or 0)
    reviews = int(meta.get("reviews") or 0)
    last_verdict = str(meta.get("last_verdict") or "")
    if ended:
        if reviews <= 0:
            phase = "idle"
        elif last_verdict == "stuck":
            phase = "stuck"
        elif last_verdict == "repeat":
            phase = "repeat"
        else:
            phase = "ok"
    elif reviews <= 0 and next_ts <= 0:
        phase = "idle"
    elif reviews <= 0 and now < next_ts:
        phase = "pending"
    elif reviews <= 0:
        phase = "overdue"
    elif watcher is False:
        phase = "dead"
    elif last_verdict == "stuck":
        phase = "stuck"
    elif last_verdict == "repeat":
        phase = "repeat"
    elif watcher is True and next_ts and now >= next_ts:
        phase = "overdue"
    else:
        phase = "ok"
    return {
        "reviews": reviews,
        "next_ts": next_ts,
        "next_in_s": max(0, int(round(next_ts - now))) if next_ts else 0,
        "last_ts": last_ts,
        "last_verdict": last_verdict,
        "fail_n": int(meta.get("fail_n") or 0),
        "last_error": str(meta.get("last_error") or ""),
        "phase": phase,
        "watcher": bool(watcher),
        "has_briefing": (out_dir / MD_NAME).is_file(),
        "enabled": enabled(),
        "history": list(meta.get("history") or [])[-16:],
    }


def save_meta(out_dir: Path, meta: dict[str, Any]) -> None:
    dest = out_dir / META_NAME
    tmp = dest.with_name(dest.name + ".tmp")  # atómico: un crash a mitad no corrompe
    tmp.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(dest)


def _push_history(
    meta: dict[str, Any],
    *,
    now: float,
    verdict: str,
    action: str,
    kind: str,
    what: str,
) -> None:
    hist = list(meta.get("history") or [])
    hist.append(
        {
            "ts": now,
            "iso": _iso(now),
            "verdict": verdict,
            "action": action,
            "kind": kind,
            "what": str(what or "")[:HIST_WHAT_MAX],
        }
    )
    meta["history"] = hist[-40:]


def progress_counts(out_dir: Path) -> dict[str, int]:
    """Señales de avance real, no solo flags/findings. Encadenar credenciales,
    ganar accesos, descubrir hosts/usuarios o dejar loot en disco ES progreso
    aunque no se emita una finding nueva (típico en máquinas hard y en
    auditorías: la cadena avanza sin un F-xxx por paso). La conciencia usa esto
    para no declarar 'atascado' a quien de hecho progresa, y para espaciar
    revisiones cuando hay avance."""
    state = _read_json(out_dir / "engagement.json")

    def _n(key: str) -> int:
        v = state.get(key)
        return len(v) if isinstance(v, list) else 0

    findings = out_dir / "findings"
    n_find = 0
    if findings.is_dir():
        n_find = len(list(findings.glob("F-*.json")))
    loot = out_dir / "loot"
    n_loot = 0
    if loot.is_dir():
        try:
            n_loot = sum(1 for p in loot.rglob("*") if p.is_file() and p.stat().st_size > 0)
        except OSError:
            n_loot = 0
    ingest = state.get("_ingest") if isinstance(state.get("_ingest"), dict) else {}
    phase = str(state.get("phase") or "")
    return {
        "flags": _n("flags"),
        "findings": n_find,
        "creds": _n("creds"),
        "access": _n("access"),
        "users": _n("users"),
        "hosts": _n("hosts"),
        "loot": n_loot,
        "tried": _n("tried"),
        "phase": {"recon": 1, "foothold": 2, "exploit": 3, "post": 4}.get(phase, 0),
        "cmds": _n("cmd_log"),
        "audit": int(ingest.get("audit") or 0),
        "tokens": _tokens_total(out_dir),
    }


def _tokens_total(out_dir: Path) -> int:
    stats = _read_json(out_dir / "stats.json")
    toks = stats.get("tokens") if isinstance(stats.get("tokens"), dict) else {}
    return int(toks.get("in") or 0) + int(toks.get("out") or 0)


def recent_command_activity(out_dir: Path) -> tuple[int, int]:
    """(total, distintos) fingerprints del cmd_log RECIENTE (ACTIVITY_WINDOW).

    Mucha diversidad reciente = explora/explota, no un bucle. Un bucle tardío
    detrás de recon diversa no debe heredar esa diversidad: solo cuenta la cola.
    """
    state = _read_json(out_dir / "engagement.json") or {}
    log = state.get("cmd_log") if isinstance(state, dict) else None
    if not isinstance(log, list):
        return (0, 0)
    fps = [str(c.get("fp") or "") for c in log if isinstance(c, dict) and c.get("fp")]
    recent = fps[-ACTIVITY_WINDOW:]
    return (len(recent), len(set(recent)))


def run_start_ts(out_dir: Path) -> float:
    meta = _read_json(out_dir / "meta.json")
    raw = str(meta.get("started_at") or "")
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return out_dir.stat().st_mtime if out_dir.is_dir() else _now()


def next_delay(verdict: str, progressed: bool) -> int:
    if verdict == "stuck":
        return AFTER_CUT_S
    if verdict == "repeat":
        return TIGHT_S
    if progressed:
        return STRETCH_S
    return TIGHT_S


def due(out_dir: Path, now: float | None = None) -> bool:
    now = _now() if now is None else now
    meta = load_meta(out_dir)
    nxt = float(meta.get("next_ts") or 0)
    if nxt <= 0:
        nxt = run_start_ts(out_dir) + FIRST_REVIEW_S
        meta["next_ts"] = nxt
        save_meta(out_dir, meta)
    return now >= nxt


def defer(out_dir: Path, seconds: int | None = None, *, now: float | None = None) -> None:
    """Aplaza la próxima revisión. Un refuse no debe coincidir con un corte."""
    now = _now() if now is None else now
    delay = AFTER_CUT_S if seconds is None else max(0, int(seconds))
    meta = load_meta(out_dir)
    nxt = float(meta.get("next_ts") or 0)
    meta["next_ts"] = max(nxt, now + delay)
    save_meta(out_dir, meta)


_PROOF_NAMES = frozenset(
    {
        "proof.txt",
        "proof.md",
        "proof.json",
        "poc.txt",
        "poc.md",
        "reproduce.txt",
        "reproduction.txt",
    }
)
_EVIDENCE_OMIT = "(omitida; fía título/status/consola)"


def _is_proof_name(name: str) -> bool:
    n = (name or "").lower()
    return n in _PROOF_NAMES or n.startswith("proof")


def _scrub_evidence_item(item: Any) -> str:
    """Path a proof/blob no se ofrece: el juez no debe ir a buscarlo."""
    text = str(item or "").strip()[:200]
    if not text:
        return text
    name = Path(text.split()[0]).name.lower()
    if _is_proof_name(name) or "/proof" in text.lower().replace("\\", "/"):
        return _EVIDENCE_OMIT
    if re.search(r"findings/F-\d+/", text, re.I):
        return _EVIDENCE_OMIT
    return text


def pack_findings(out_dir: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    d = out_dir / "findings"
    if not d.is_dir():
        return items
    for path in sorted(d.glob("F-*.json")):
        data = _read_json(path)
        if not data.get("id"):
            continue
        ev = data.get("evidence") or []
        if isinstance(ev, str):
            ev = [ev]
        items.append(
            {
                "id": data.get("id"),
                "title": data.get("title"),
                "kind": data.get("kind"),
                "severity": data.get("severity"),
                "status": data.get("status"),
                "asset": data.get("asset"),
                "explain": str(data.get("explain") or data.get("summary") or "")[:500],
                "impact": str(data.get("impact") or "")[:300],
                "evidence": [_scrub_evidence_item(x) for x in ev if x][:8],
            }
        )
    return items


def pack_state(out_dir: Path) -> dict[str, Any]:
    st = _read_json(out_dir / "engagement.json")
    state_md = ""
    md = out_dir / "STATE.md"
    if md.is_file():
        state_md = md.read_text(encoding="utf-8", errors="replace")[:8000]
    return {
        "phase": st.get("phase"),
        "layer": st.get("layer"),
        "current": (st.get("graph") or {}).get("current") if isinstance(st.get("graph"), dict) else "",
        "flags": st.get("flags") or [],
        "access": st.get("access") or [],
        "creds": [
            {k: c.get(k) for k in ("user", "type", "role", "via") if c.get(k)}
            for c in (st.get("creds") or [])
            if isinstance(c, dict)
        ],
        "hosts": st.get("hosts") or [],
        "state_md": state_md,
    }


def _clip_cmd(cmd: str, n: int = 160) -> str:
    one = " ".join(cmd.split())
    return one if len(one) <= n else one[: n - 1] + "…"


def extract_console_events(raw: str) -> tuple[list[str], list[str]]:
    """Comandos e intenciones desde Claude / OpenCode / Codex JSONL."""
    cmds: list[str] = []
    intents: list[str] = []
    for line in raw.splitlines():
        i = line.find("{")
        if i < 0:
            continue
        try:
            obj = json.loads(line[i:])
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        if obj.get("type") == "aegis_conscience":
            continue
        cmds.extend(_cmds_from_obj(obj))
        text = _intent_from_obj(obj)
        if text:
            intents.append(text)
    return cmds, intents


def _cmds_from_obj(obj: dict[str, Any]) -> list[str]:
    out: list[str] = []
    msg = obj.get("message")
    if isinstance(msg, dict):
        for part in msg.get("content") or []:
            if not isinstance(part, dict) or part.get("type") != "tool_use":
                continue
            name = str(part.get("name") or "tool")
            inp = part.get("input") if isinstance(part.get("input"), dict) else {}
            cmd = inp.get("command") or inp.get("cmd") or ""
            if cmd:
                out.append(f"{name}: {_clip_cmd(str(cmd))}")
            else:
                out.append(f"{name}")
    part = obj.get("part")
    if isinstance(part, dict):
        tool = str(part.get("tool") or part.get("name") or "")
        state = part.get("state") if isinstance(part.get("state"), dict) else {}
        inp = state.get("input") if isinstance(state.get("input"), dict) else {}
        if not inp and isinstance(part.get("input"), dict):
            inp = part["input"]
        cmd = inp.get("command") or inp.get("cmd") or ""
        if cmd:
            out.append(f"{tool or 'bash'}: {_clip_cmd(str(cmd))}")
        elif tool:
            out.append(tool)
    if obj.get("type") in {"item.completed", "item.started", "command"}:
        cmd = obj.get("command") or (obj.get("item") or {}).get("command") if isinstance(obj.get("item"), dict) else ""
        if cmd:
            out.append(_clip_cmd(str(cmd)))
    return out


def _intent_from_obj(obj: dict[str, Any]) -> str:
    msg = obj.get("message")
    if isinstance(msg, dict) and msg.get("role") in {None, "assistant"}:
        for part in msg.get("content") or []:
            if isinstance(part, dict) and part.get("type") == "text":
                t = str(part.get("text") or "").strip()
                if t:
                    return t[:220]
    part = obj.get("part")
    if isinstance(part, dict) and part.get("type") == "text":
        t = str(part.get("text") or "").strip()
        if t:
            return t[:220]
    item = obj.get("item") if isinstance(obj.get("item"), dict) else {}
    if item.get("type") == "agent_message":
        t = str(item.get("text") or "").strip()
        if t:
            return t[:220]
    return ""


_RESULT_HIT = re.compile(
    r"\[\+\]|\[\-\]|\[\*\]|READ\b|WRITE\b|ACCESS_DENIED|NT_STATUS|"
    r"STATUS_|denied|invalid|valid(?:o|ated)?|error|failed|success|"
    r"SidTypeUser|Last PW Set|Sharename|IPC\$|user\.txt|root\.txt|"
    r"permission|no such|not found|STATUS_OBJECT",
    re.I,
)


def extract_console_hits(raw: str) -> list[str]:
    """Líneas de salida (tool_result) que demuestran avance o fallo, no solo argv."""
    from internal.identities import _event_tool_texts

    hits: list[str] = []
    for line in raw.splitlines():
        i = line.find("{")
        if i < 0:
            continue
        try:
            obj = json.loads(line[i:])
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict) or obj.get("type") == "aegis_conscience":
            continue
        for text in _event_tool_texts(obj):
            n = 0
            for ln in text.splitlines():
                one = ln.strip()
                if not one or not _RESULT_HIT.search(one):
                    continue
                hits.append(one[:180])
                n += 1
                if n >= 4:
                    break
    return hits


def summarize_console(out_dir: Path, console_off: int) -> tuple[str, int]:
    path = out_dir / "console.log"
    if not path.is_file():
        return "(sin consola)", 0
    data = path.read_bytes()
    # Cola del fichero entero: console_off solo marca «ya vimos esto» en meta.
    # Un delta de 80 KB se comía el foothold y dejaba solo la cola (pip/bloodyAD).
    _ = console_off
    chunk = data[-CONSOLE_PARSE_BYTES:] if len(data) > CONSOLE_PARSE_BYTES else data
    text = chunk.decode("utf-8", errors="replace")
    cmds, intents = extract_console_events(text)
    hits = extract_console_hits(text)
    audit = out_dir / ".audit" / "commands.jsonl"
    if audit.is_file():
        for line in audit.read_text(encoding="utf-8", errors="replace").splitlines()[-CMD_KEEP:]:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            argv = str(rec.get("argv") or rec.get("cmd") or "")
            if argv:
                cmds.append(_clip_cmd(argv))
    cmds = cmds[-CMD_KEEP:]
    intents = intents[-INTENT_KEEP:]
    hits = hits[-RESULT_KEEP:]
    lines = ["## Comandos recientes"]
    lines.extend(f"- {c}" for c in cmds or ["(ninguno en la ventana)"])
    lines.append("## Salidas que importan")
    lines.extend(f"- {h}" for h in hits or ["(sin [+]/error/READ en la cola)"])
    lines.append("## Intención reciente del agente")
    lines.extend(f"- {t}" for t in intents or ["(sin texto)"])
    blob = "\n".join(lines)
    if len(blob) > CONSOLE_CHARS:
        blob = blob[: CONSOLE_CHARS - 1] + "…"
    return blob, len(data)


def pack_inventory(out_dir: Path) -> str:
    """Mapa de artefactos. El modelo elige qué abrir; no es el material entero."""
    lines: list[str] = []
    for name in (
        "console.log",
        "STATE.md",
        "PIVOT.md",
        "NEXT.md",
        "CONSCIENCE.md",
        "RESUME.md",
        "engagement.json",
        "accounts.json",
        "meta.json",
    ):
        path = out_dir / name
        if path.is_file():
            try:
                lines.append(f"- {name} ({path.stat().st_size} bytes)")
            except OSError:
                lines.append(f"- {name}")
    findings = out_dir / "findings"
    if findings.is_dir():
        cards = sorted(p.name for p in findings.glob("F-*.json") if p.is_file())
        if cards:
            lines.append("- findings/: " + ", ".join(cards[:24]))
    loot = out_dir / "loot"
    if loot.is_dir():
        try:
            names = [str(p.relative_to(out_dir)) for p in sorted(loot.rglob("*")) if p.is_file()]
        except OSError:
            names = []
        if names:
            lines.append("- loot/: " + ", ".join(names[:40]))
    return "\n".join(lines) or "(vacío)"


def pack_previous_brief(out_dir: Path) -> str:
    path = out_dir / MD_NAME
    if not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:3000]
    except OSError:
        return ""


_WS_TEXT = frozenset({".txt", ".md", ".json", ".log", ".csv", ".xml", ".conf", ".ini", ".yml", ".yaml"})
_WS_MAX_FILE = 200_000
_WS_CONSOLE = 2_000_000


def _copy_tail(src: Path, dest: Path, cap: int) -> None:
    if not src.is_file():
        return
    try:
        data = src.read_bytes()
    except OSError:
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data[-cap:] if len(data) > cap else data)


def _copy_capped(src: Path, dest: Path, cap: int) -> None:
    if not src.is_file():
        return
    try:
        data = src.read_bytes()[:cap]
    except OSError:
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)


def _copy_tree_text(src: Path, dest: Path) -> None:
    if not src.is_dir():
        return
    try:
        paths = sorted(src.rglob("*"))
    except OSError:
        return
    for path in paths:
        if not path.is_file():
            continue
        if path.suffix.lower() not in _WS_TEXT:
            continue
        if _is_proof_name(path.name):
            continue
        try:
            if path.stat().st_size > _WS_MAX_FILE:
                continue
            rel = path.relative_to(src)
        except OSError:
            continue
        _copy_capped(path, dest / rel, _WS_MAX_FILE)


def _sanitize_finding_card(src: Path, dest: Path) -> None:
    data = _read_json(src)
    if not data.get("id"):
        return
    for key in ("proof", "reproduction", "poc", "payload"):
        data.pop(key, None)
    ev = data.get("evidence") or []
    if isinstance(ev, str):
        ev = [ev]
    data["evidence"] = [_scrub_evidence_item(x) for x in ev if x][:8]
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _copy_finding_cards(src: Path, dest: Path) -> None:
    """Solo fichas JSON, sin proof ni blobs findings/F-xxx/."""
    if not src.is_dir():
        return
    dest.mkdir(parents=True, exist_ok=True)
    for path in sorted(src.glob("F-*.json")):
        if path.is_file():
            _sanitize_finding_card(path, dest / path.name)


def review_ws_root(out_dir: Path) -> Path:
    """Fuera del run: si el juez hace ls .. no cae en findings/ vivos."""
    meta = _read_json(out_dir / "meta.json")
    rid = str(meta.get("run_id") or out_dir.name)
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", rid).strip("-.")[:48] or "run"
    return Path(tempfile.gettempdir()) / f"aegis-conscience-{safe}"


def prepare_review_ws(out_dir: Path) -> Path:
    """Copia de solo lectura para el harness. El agente vivo sigue escribiendo out/."""
    stale = Path(out_dir) / ".conscience-ws"
    if stale.exists():
        shutil.rmtree(stale, ignore_errors=True)
    root = review_ws_root(out_dir)
    dest = root / "run"
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)
    _copy_tail(out_dir / "console.log", dest / "console.log", _WS_CONSOLE)
    for name in (
        "STATE.md",
        "PIVOT.md",
        "NEXT.md",
        "CONSCIENCE.md",
        "RESUME.md",
        "engagement.json",
        "accounts.json",
        "meta.json",
        "brief.json",
    ):
        src = out_dir / name
        if src.is_file():
            _copy_capped(src, dest / name, _WS_MAX_FILE)
    _copy_finding_cards(out_dir / "findings", dest / "findings")
    _copy_tree_text(out_dir / "loot", dest / "loot")
    inv = pack_inventory(out_dir)
    inv += (
        "\n\nSin proof.txt ni blobs findings/F-xxx/. "
        "Juzga con las fichas JSON, STATE.md y la consola. "
        "No salgas de run/ ni abras el disco vivo del agente.\n"
    )
    (dest / "INVENTARIO.md").write_text(inv, encoding="utf-8")
    (root / "README.md").write_text(
        "Solo lectura. Quédate en run/. No hay proofs a propósito.\n",
        encoding="utf-8",
    )
    return root


def build_user_pack(out_dir: Path, console_off: int) -> tuple[str, int]:
    findings = pack_findings(out_dir)
    state = pack_state(out_dir)
    summary, new_off = summarize_console(out_dir, console_off)
    run = _read_json(out_dir / "meta.json")
    prog = progress_counts(out_dir)
    body = {
        "run": {
            "id": run.get("run_id"),
            "title": run.get("title"),
            "harness": run.get("harness"),
            "model": run.get("model"),
            "mode": run.get("mode"),
            "elapsed_min": int(max(0, _now() - run_start_ts(out_dir)) // 60),
        },
        "progress": prog,
        "inventory": pack_inventory(out_dir),
        "state": {k: v for k, v in state.items() if k != "state_md"},
        "state_md": state.get("state_md"),
        "findings": findings,
        "previous": pack_previous_brief(out_dir),
        "console": summary,
    }
    note = (
        "Si puedes leer archivos, están SOLO en run/ (console.log, "
        "findings/F-xxx.json, STATE.md, loot/, engagement.json, INVENTARIO.md). "
        "Este JSON es un índice. No abras proof.txt, poc ni nada bajo "
        "findings/F-xxx/ (no están en esta copia). Si un path no existe en run/, "
        "no lo busques fuera: el disco del agente no es tu cwd. "
        "No escribas ni lances red.\n\n"
    )
    return note + json.dumps(body, ensure_ascii=False, indent=2), new_off


SYSTEM = """Eres la conciencia de un orquestador de pentest autorizado (Aegis).
Revisas un agente (Claude, OpenCode o Codex) como el comprobador de cierre:
contrasta disco (findings/F-xxx.json, console.log, STATE.md, loot/, engagement.json)
con lo que el agente afirma. Puedes abrir esos archivos en run/.

NO eres el atacante. NO inventes CVEs, hosts, creds ni payloads.
NO copies curls, proofs ni recetas de explotación.
NO abras proof.txt, poc, dumps de auth ni nada bajo findings/F-xxx/.
Si un path no está en run/, no lo busques en el disco vivo del agente.
NO reescribas fichas ni lances scans: solo juzgas.

Revisa:
- Si cada finding (status, evidence, título) cuadra con consola/loot. Evidence
  que no es un path de disco no invalida el hallazgo si la consola lo demuestra.
  Un path omitido no es un hueco.
- Si el trabajo avanza o está atascado.

Un nmap/ffuf/Monitor largo ÚNICO no es un bucle.
Si hay progreso reciente (flag, cred, tried o cambio de fase) y el trabajo es coherente, stuck=false.
Ocupado no es avance: muchos comandos distintos en la misma fase sin tried/creds nuevos es stall.
Soliloquio: cmd_log crece y el audit no (habla y no ejecuta).

Atasco = repetir la MISMA clase de trabajo o el mismo comando sin información nueva, o
seguir enumerando cuando ya hay foothold/acceso que explotar. Eso es stuck=true.
Probar vectores DISTINTOS, aunque fallen, NO es atasco: es trabajo legítimo.
No juzgues por la técnica ni por la capa (host o contenedor); juzga por la repetición
y la falta de progreso. No decidas la vulnerabilidad por el agente ni prohíbas técnicas.
Si stuck=true, explica qué se repite y sugiere 2-3 rutas ancladas a findings/estado ya existentes.

Responde SOLO un JSON:
{
  "stuck": true|false,
  "kind": "ok|repeat|stall|wrong_layer",
  "what": "qué está pasando, 1-3 frases",
  "why": "por qué otra ruta, cita F-xxx o flags/layer",
  "routes": ["ruta 1", "ruta 2", "ruta 3"],
  "issues": ["ficha o hueco que no cuadra, si lo hay"]
}
Castellano. routes vacías si stuck=false. issues vacío si las fichas cuadran.
Sin proof, sin comandos concretos de exploit.
No uses herramientas: el índice JSON del prompt basta. Responde YA el JSON."""


def _empty_verdict() -> dict[str, Any]:
    return {"stuck": False, "kind": "ok", "what": "", "why": "", "routes": [], "issues": []}


def _json_objects(raw: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    i = 0
    while i < len(raw):
        start = raw.find("{", i)
        if start < 0:
            break
        depth = 0
        end = -1
        for j in range(start, len(raw)):
            ch = raw[j]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = j
                    break
        if end < 0:
            break
        try:
            data = json.loads(raw[start : end + 1])
        except json.JSONDecodeError:
            i = start + 1
            continue
        if isinstance(data, dict):
            found.append(data)
        i = end + 1
    return found


def fail_detail(raw: str, blocked: bool) -> str:
    """Por qué el shot no valió: para consola y CONSCIENCE.json. Sin secretos."""
    if blocked:
        return "cuota o salvaguarda del modelo"
    blob = (raw or "").strip()
    if not blob:
        return "sin respuesta (timeout o error)"
    low = blob.lower()
    if "permission denied" in low or "eacces" in low:
        return "el juez no pudo escribir la sesión de OpenCode"
    one = re.sub(r"\s+", " ", blob)
    if "stuck" not in blob:
        return ("el juez no devolvió JSON: " + one[:160]).strip()
    return "sin veredicto"


def _write_last(path: Path, text: str) -> None:
    try:
        path.write_text((text or "")[:80_000], encoding="utf-8", errors="replace")
    except OSError:
        pass


def judge_xdg(cfg: dict[str, Any], out_dir: Path) -> Path:
    """XDG propio del juez. El del agente es root en el contenedor: el host no escribe."""
    meta = _read_json(out_dir / "meta.json")
    rid = str(meta.get("run_id") or out_dir.name)
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", rid).strip("-.")[:48] or "run"
    dest = Path(tempfile.gettempdir()) / f"aegis-conscience-xdg-{safe}"
    dest.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(dest, 0o700)
    except OSError:
        pass
    oc = dest / "opencode"
    oc.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(oc, 0o700)
    except OSError:
        pass
    src = Path(str(cfg.get("xdg_data_home") or "")) / "opencode" / "auth.json"
    if not src.is_file():
        from internal.auth import host_auth_path

        src = host_auth_path()
    auth_dest = oc / "auth.json"
    if src.is_file():
        try:
            if (not auth_dest.is_file()) or src.stat().st_mtime > auth_dest.stat().st_mtime:
                shutil.copy2(src, auth_dest)
                auth_dest.chmod(0o600)
        except OSError:
            pass
    return dest


def provider_blocked(text: str) -> bool:
    """Cuota o salvaguarda del proveedor: no es un veredicto."""
    t = (text or "").lower()
    if "session limit" in t or "you've hit your" in t:
        return True
    if "safeguards flagged" in t or "api_refusal" in t:
        return True
    if "api error:" in t and "safeguard" in t:
        return True
    return False


def parse_verdict(text: str) -> dict[str, Any]:
    raw = (text or "").strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[-1]
        if raw.endswith("```"):
            raw = raw[: raw.rfind("```")]
    data = None
    for obj in reversed(_json_objects(raw)):
        if "stuck" in obj:
            data = obj
            break
    if data is None:
        return _empty_verdict()
    routes = data.get("routes") or []
    if not isinstance(routes, list):
        routes = []
    issues = data.get("issues") or []
    if not isinstance(issues, list):
        issues = []
    return {
        "stuck": bool(data.get("stuck")),
        "kind": str(data.get("kind") or ("stall" if data.get("stuck") else "ok")),
        "what": str(data.get("what") or "").strip()[:WHAT_MAX],
        "why": str(data.get("why") or "").strip()[:WHY_MAX],
        "routes": [str(r).strip()[:ROUTE_MAX] for r in routes if str(r).strip()][:ROUTE_N],
        "issues": [str(x).strip()[:ISSUE_MAX] for x in issues if str(x).strip()][:ISSUE_N],
    }


def agent_briefing(verdict: dict[str, Any]) -> str:
    routes = verdict.get("routes") or []
    route_s = "\n".join(f"- {r}" for r in routes) or "- Cambia de tipo de comando; usa loot/findings ya en disco."
    issues = verdict.get("issues") or []
    issue_s = "\n".join(f"- {x}" for x in issues)
    body = (
        "CONCIENCIA (revisión periódica — obligatorio):\n\n"
        f"## Qué está pasando\n{verdict.get('what') or 'Atasco: mismo trabajo sin progreso.'}\n\n"
        f"## Por qué otra ruta\n{verdict.get('why') or 'Los findings/flags ya cubren este pozo.'}\n\n"
        f"## Rutas recomendadas\n{route_s}\n"
    )
    if issue_s:
        body += f"\n## Fichas / huecos\n{issue_s}\n"
    return body


def cut_steer_text(verdict: dict[str, Any]) -> str:
    """STEER del persist: encabezado de sesión nueva + memo completo. Sin proofs."""
    return CUT_STEER.rstrip() + "\n\n" + agent_briefing(verdict).rstrip() + "\n"


def conscience_authored_steer(text: str) -> bool:
    t = text or ""
    return "CONCIENCIA (revisión periódica — obligatorio):" in t or t.startswith(
        "Sesión nueva tras un atasco"
    )


def write_conscience_steer(out_dir: Path, text: str) -> bool:
    """Escribe STEER.md. No pisa un steer del operador; sí actualiza el propio."""
    dest = out_dir / "STEER.md"
    body = text if text.endswith("\n") else text + "\n"
    if dest.is_file():
        try:
            cur = dest.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        if not conscience_authored_steer(cur):
            return False
    dest.write_text(body, encoding="utf-8")
    return True


def visible_message(verdict: dict[str, Any], action: str) -> str:
    """Mismo memo que ve el operador y, si hay STEER, el atacante."""
    brief = agent_briefing(verdict)
    if action == "ok":
        what = verdict.get("what") or "El trabajo avanza; no corto."
        extra = verdict.get("issues") or []
        note = (" Revisa: " + "; ".join(extra)) if extra else ""
        head = f"SIGUE ({verdict.get('kind') or 'ok'}). {what}{note}"
        if verdict.get("routes") or verdict.get("why") or extra:
            return head + "\n\n" + brief
        return head
    if action == "nudge":
        what = verdict.get("what") or "Misma clase de trabajo sin vector nuevo."
        return f"AVISA ({verdict.get('kind') or 'repeat'}). {what}\n\n{brief}"
    if action == "refuse":
        return (
            "SALVAGUARDA. Sesión nueva. No abras BRIEF.md, STATE.md ni findings/*.json. "
            "Sigue RESUME.md. Si hay hold=, es usuario y vía (no contraseña); "
            "úsalo. No abras un servicio nuevo."
        )
    return brief


def note_refuse_turn(out_dir: Path) -> bool:
    """El entrypoint dejó .refuse-turn: lo mostramos como conciencia, sin shot ofensivo."""
    marker = out_dir / ".refuse-turn"
    if not marker.is_file():
        return False
    try:
        raw = marker.read_text(encoding="utf-8", errors="replace").strip()
        marker.unlink()
    except OSError:
        return False
    n = 0
    try:
        n = int(raw or "0")
    except ValueError:
        n = 0
    verdict = {
        "stuck": True,
        "kind": "refuse",
        "what": f"El turno cerró por salvaguarda del proveedor ({n}).",
        "why": "No reinyectar el mensaje flagged ni recap ofensivo.",
        "routes": [],
    }
    emit_console(out_dir, verdict, "refuse")
    now = _now()
    meta = load_meta(out_dir)
    meta["last_ts"] = now
    meta["last_verdict"] = "stuck"
    _push_history(meta, now=now, verdict="stuck", action="refuse", kind="refuse", what=verdict["what"])
    save_meta(out_dir, meta)
    defer(out_dir)
    return True


def _append_console(out_dir: Path, line: str) -> None:
    """El contenedor deja console.log como root; si el host no puede, entra por docker."""
    if not line.endswith("\n"):
        line += "\n"
    path = out_dir / "console.log"
    try:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
        return
    except OSError:
        pass
    name = str(_read_json(out_dir / "meta.json").get("container") or "").strip()
    if not name:
        return
    try:
        subprocess.run(
            ["docker", "exec", "-i", name, "tee", "-a", "/run/aegis/out/console.log"],
            input=line.encode("utf-8"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass


def emit_console(out_dir: Path, verdict: dict[str, Any], action: str) -> None:
    rec = {
        "type": "aegis_conscience",
        "action": action,
        "stuck": bool(verdict.get("stuck")),
        "kind": verdict.get("kind") or "",
        "text": visible_message(verdict, action),
        "timestamp": _iso(_now()),
    }
    _append_console(out_dir, f"{rec['timestamp']} {json.dumps(rec, ensure_ascii=False)}\n")


def operator_md(verdict: dict[str, Any], action: str) -> str:
    issues = verdict.get("issues") or []
    issue_s = "\n".join(f"- {x}" for x in issues) if issues else "- (ninguno)"
    return (
        f"# CONSCIENCE\n\n"
        f"- stuck: {verdict.get('stuck')}\n"
        f"- kind: {verdict.get('kind')}\n"
        f"- action: {action}\n\n"
        f"## Qué\n{verdict.get('what')}\n\n"
        f"## Por qué\n{verdict.get('why')}\n\n"
        f"## Rutas\n" + "\n".join(f"- {r}" for r in (verdict.get("routes") or [])) + "\n\n"
        f"## Fichas / huecos\n{issue_s}\n"
    )


def write_backend(
    out_dir: Path,
    *,
    harness: str,
    model: str,
    claude_bin: Path | None = None,
    claude_home: Path | None = None,
    codex_bin: Path | None = None,
    codex_home: Path | None = None,
    xdg_data_home: Path | None = None,
) -> Path:
    """El juez usa la misma cuenta/harness que el run. Sin campo extra en Lanzar."""
    dest = Path(out_dir) / ".conscience-backend.json"
    dest.write_text(
        json.dumps(
            {
                "harness": harness,
                "model": model,
                "claude_bin": str(claude_bin) if claude_bin else "",
                "claude_home": str(claude_home) if claude_home else "",
                "codex_bin": str(codex_bin) if codex_bin else "",
                "codex_home": str(codex_home) if codex_home else "",
                "xdg_data_home": str(xdg_data_home) if xdg_data_home else "",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    dest.chmod(0o600)
    return dest


def load_run_backend(out_dir: Path | None) -> dict[str, Any]:
    """Harness + modelo del run (el mismo que el agente). No un modelo 'barato' aparte."""
    if out_dir is None:
        return {}
    cfg = _read_json(Path(out_dir) / ".conscience-backend.json")
    if cfg.get("harness") and cfg.get("model"):
        return cfg
    meta = _read_json(Path(out_dir) / "meta.json")
    harness = str(cfg.get("harness") or meta.get("harness") or "")
    model = str(cfg.get("model") or meta.get("model") or "")
    if not harness and model:
        low = model.lower()
        if any(x in low for x in ("claude", "anthropic", "opus", "sonnet", "haiku")):
            harness = "claude"
        elif any(x in low for x in ("codex", "gpt-5")):
            harness = "codex"
        else:
            harness = "opencode"
    if not harness or not model:
        return cfg if cfg.get("harness") else {}
    merged = dict(cfg)
    merged["harness"] = harness
    merged["model"] = model
    return merged


def has_backend(out_dir: Path) -> bool:
    if (os.environ.get("AEGIS_CONSCIENCE_ENDPOINT") or "").strip():
        return True
    if load_run_backend(out_dir).get("harness"):
        return True
    return resolve_backend() is not None


def resolve_backend() -> dict[str, str] | None:
    """Endpoint OpenAI-compatible o Anthropic. Distinto del lead si se puede."""
    ep = (os.environ.get("AEGIS_CONSCIENCE_ENDPOINT") or "").strip().rstrip("/")
    model = (os.environ.get("AEGIS_CONSCIENCE_MODEL") or "").strip()
    key = (os.environ.get("AEGIS_CONSCIENCE_KEY") or "").strip()
    if ep and model:
        return {"kind": "openai", "url": _chat_url(ep), "model": model, "key": key}
    ep = (os.environ.get("AEGIS_CRITIC_ENDPOINT") or "").strip().rstrip("/")
    model = (os.environ.get("AEGIS_CRITIC_MODEL") or "").strip()
    if ep and model:
        return {"kind": "openai", "url": _chat_url(ep), "model": model, "key": key}
    oai = (os.environ.get("OPENAI_API_KEY") or os.environ.get("AEGIS_OPENAI_API_KEY") or "").strip()
    if oai:
        return {
            "kind": "openai",
            "url": "https://api.openai.com/v1/chat/completions",
            "model": os.environ.get("AEGIS_CONSCIENCE_MODEL") or "gpt-4.1-mini",
            "key": oai,
        }
    anth = (os.environ.get("ANTHROPIC_API_KEY") or "").strip()
    if anth:
        return {
            "kind": "anthropic",
            "url": "https://api.anthropic.com/v1/messages",
            "model": os.environ.get("AEGIS_CONSCIENCE_MODEL") or "claude-sonnet-4-5",
            "key": anth,
        }
    xai = (os.environ.get("XAI_API_KEY") or os.environ.get("AEGIS_XAI_API_KEY") or "").strip()
    if xai:
        return {
            "kind": "openai",
            "url": "https://api.x.ai/v1/chat/completions",
            "model": os.environ.get("AEGIS_CONSCIENCE_MODEL") or "grok-4-fast",
            "key": xai,
        }
    return None


def _chat_url(endpoint: str) -> str:
    if endpoint.endswith("/chat/completions"):
        return endpoint
    return endpoint.rstrip("/") + "/chat/completions"


def call_llm(user: str, out_dir: Path | None = None) -> str:
    """Mismo harness/modelo que el run, salvo override explícito por endpoint."""
    if (os.environ.get("AEGIS_CONSCIENCE_ENDPOINT") or "").strip():
        backend = resolve_backend()
        if backend:
            return _call_anthropic(backend, user) if backend["kind"] == "anthropic" else _call_openai(backend, user)
        return ""
    if out_dir is not None and load_run_backend(out_dir).get("harness"):
        return _call_harness(Path(out_dir), user)
    backend = resolve_backend()
    if not backend:
        return ""
    if backend["kind"] == "anthropic":
        return _call_anthropic(backend, user)
    return _call_openai(backend, user)


def _harness_model(raw: str) -> str:
    raw = (raw or "").strip()
    if "/" in raw:
        return raw.split("/", 1)[1]
    return raw


def _call_harness_prompt(
    out_dir: Path,
    prompt: str,
    *,
    cwd: Path | None = None,
    timeout: int | None = None,
    model: str = "",
    harness: str = "",
) -> str:
    cfg = load_run_backend(out_dir)
    # Override opcional (modelo/harness de relevo) para reintentar si el principal refusa.
    if model:
        cfg = {**cfg, "model": model}
    if harness:
        cfg = {**cfg, "harness": harness}
    h = str(cfg.get("harness") or "")
    if not h:
        return ""
    if h == "claude":
        return _shot_claude(cfg, prompt, cwd=cwd, timeout=timeout)
    if h == "codex":
        return _shot_codex(cfg, out_dir, prompt, cwd=cwd, timeout=timeout)
    return _shot_opencode(cfg, out_dir, prompt, cwd=cwd, timeout=timeout)


def conscience_system(out_dir: Path | None = None) -> str:
    """SYSTEM de conciencia. En Red, enumerar no es atasco."""
    mode = ""
    exploit = False
    if out_dir is not None:
        meta = _read_json(out_dir / "meta.json")
        brief = _read_json(out_dir / "brief.json")
        mode = str(meta.get("mode") or brief.get("mode") or "")
        exploit = bool(meta.get("exploit_mgmt") or brief.get("exploit_mgmt"))
    if mode != "net":
        return SYSTEM
    extra = (
        "\n\nEste run es auditoría de RED (mode=net). Enumerar, mapear, DNS y "
        "reachability ES el trabajo, no un atasco. Un HTTP de usuario no es foothold. "
        "stuck=true solo si repite el mismo probe/panel sin dato nuevo. "
        "No sugieras explotar webs o servidores."
    )
    if exploit:
        extra += (
            " exploit_mgmt está activo: puede explotar SOLO el plano de gestión "
            "de fw/switch/AP. Si se clava en ese panel y no cubre DNS/fugas, stuck=true."
        )
    else:
        extra += " Cero explotación."
    return SYSTEM + extra


def _call_harness(out_dir: Path, user: str) -> str:
    """Shot de conciencia: workspace con copia del disco + índice en el prompt."""
    ws = prepare_review_ws(out_dir)
    prompt = (
        conscience_system(out_dir)
        + "\n\nDATOS DEL RUN:\n"
        + user
    )
    return _call_harness_prompt(out_dir, prompt, cwd=ws, timeout=HARNESS_REVIEW_S)


def call_llm_text(
    system: str,
    user: str,
    out_dir: Path | None = None,
    *,
    max_tokens: int = 2000,
    model: str = "",
    harness: str = "",
) -> str:
    """Shot suelto con el harness/modelo del run (o el override model/harness). No usa el
    SYSTEM de la conciencia."""
    if out_dir is not None and load_run_backend(out_dir).get("harness"):
        return _call_harness_prompt(
            Path(out_dir), system.strip() + "\n\n" + user, model=model, harness=harness
        )
    backend = resolve_backend()
    if not backend:
        return ""
    if backend["kind"] == "anthropic":
        return _call_anthropic(backend, user, system=system, max_tokens=max_tokens)
    return _call_openai(backend, user, system=system, max_tokens=max_tokens)


def _shot_claude(
    cfg: dict[str, Any],
    prompt: str,
    *,
    cwd: Path | None = None,
    timeout: int | None = None,
) -> str:
    bin_p = Path(str(cfg.get("claude_bin") or ""))
    home = Path(str(cfg.get("claude_home") or ""))
    if not bin_p.is_file():
        return ""
    env = os.environ.copy()
    env["IS_SANDBOX"] = "1"
    env["CLAUDE_CODE_SANDBOXED"] = "1"
    if home.is_dir():
        env["CLAUDE_CONFIG_DIR"] = str(home / ".claude") if (home / ".claude").is_dir() else str(home)
    model = _harness_model(str(cfg.get("model") or ""))
    args = [
        str(bin_p),
        "--print",
        "--dangerously-skip-permissions",
        "--permission-mode",
        "bypassPermissions",
        "--output-format",
        "text",
    ]
    if model:
        args += ["--model", model]
    args.append(prompt)
    return _run_cmd(args, env, cwd=cwd, timeout=timeout)


def _shot_codex(
    cfg: dict[str, Any],
    out_dir: Path,
    prompt: str,
    *,
    cwd: Path | None = None,
    timeout: int | None = None,
) -> str:
    bin_p = Path(str(cfg.get("codex_bin") or ""))
    if not bin_p.is_file():
        return ""
    last = out_dir / ".conscience-last.txt"
    env = os.environ.copy()
    home = str(cfg.get("codex_home") or "")
    if home:
        env["CODEX_HOME"] = home
    model = _harness_model(str(cfg.get("model") or ""))
    args = [
        str(bin_p),
        "exec",
        "--skip-git-repo-check",
        "--dangerously-bypass-approvals-and-sandbox",
        "--color",
        "never",
        "--output-last-message",
        str(last),
    ]
    if model:
        args += ["--model", model]
    args.append(prompt)
    _run_cmd(args, env, cwd=cwd or out_dir, timeout=timeout)
    if last.is_file():
        return last.read_text(encoding="utf-8", errors="replace").strip()
    return ""


def _shot_opencode(
    cfg: dict[str, Any],
    out_dir: Path,
    prompt: str,
    *,
    cwd: Path | None = None,
    timeout: int | None = None,
) -> str:
    from internal.auth import opencode_bin

    bin_p = opencode_bin()
    if bin_p is None:
        return ""
    env = os.environ.copy()
    env["XDG_DATA_HOME"] = str(judge_xdg(cfg, out_dir))
    ws = Path(cwd) if cwd is not None else review_ws_root(out_dir)
    ws.mkdir(parents=True, exist_ok=True)
    model = str(cfg.get("model") or "")
    args = [str(bin_p), "run", "--dir", str(ws)]
    if model:
        args += ["--model", model]
    args.append(prompt)
    return _run_cmd(
        args,
        env,
        cwd=ws,
        timeout=timeout,
        last_path=out_dir / ".conscience-last.txt",
    )


def _run_cmd(
    args: list[str],
    env: dict[str, str],
    *,
    cwd: Path | None = None,
    timeout: int | None = None,
    last_path: Path | None = None,
) -> str:
    def _chunk(val: Any) -> str:
        if val is None:
            return ""
        if isinstance(val, str):
            return val
        if isinstance(val, (bytes, bytearray)):
            return bytes(val).decode("utf-8", errors="replace")
        return str(val)

    try:
        proc = subprocess.run(
            args,
            env=env,
            cwd=str(cwd) if cwd is not None else None,
            capture_output=True,
            text=True,
            timeout=LLM_TIMEOUT_S if timeout is None else timeout,
        )
    except subprocess.TimeoutExpired as exc:
        text = (_chunk(exc.stdout).strip() or _chunk(exc.stderr).strip() or "[timeout]")
        if last_path is not None:
            _write_last(last_path, text)
        return ""
    except OSError as exc:
        if last_path is not None:
            _write_last(last_path, str(exc))
        return ""
    text = (proc.stdout or "").strip() or (proc.stderr or "").strip()
    if last_path is not None:
        _write_last(last_path, text)
    return text


def _call_openai(backend: dict[str, str], user: str, *, system: str = SYSTEM, max_tokens: int = 700) -> str:
    payload = {
        "model": backend["model"],
        "temperature": 0.2,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    headers = {"Content-Type": "application/json"}
    if backend.get("key"):
        headers["Authorization"] = f"Bearer {backend['key']}"
    req = urllib.request.Request(
        backend["url"],
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=LLM_TIMEOUT_S) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return ""
    try:
        return str(data["choices"][0]["message"]["content"] or "").strip()
    except (KeyError, IndexError, TypeError):
        return ""


def _call_anthropic(backend: dict[str, str], user: str, *, system: str = SYSTEM, max_tokens: int = 700) -> str:
    payload = {
        "model": backend["model"],
        "max_tokens": max_tokens,
        "temperature": 0.2,
        "system": system,
        "messages": [{"role": "user", "content": user}],
    }
    req = urllib.request.Request(
        backend["url"],
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-api-key": backend["key"],
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=LLM_TIMEOUT_S) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return ""
    parts = data.get("content") or []
    texts = [p.get("text") for p in parts if isinstance(p, dict) and p.get("type") == "text"]
    return "\n".join(t for t in texts if t).strip()


def _busy(out_dir: Path) -> bool:
    if (out_dir / "ABORT").is_file() or (out_dir / ".end-reason").is_file():
        return True
    if (out_dir / ".pause-reason").is_file():
        return True
    if (out_dir / CUT_NAME).is_file() or (out_dir / PAUSE_NAME).is_file():
        return True
    if (out_dir / ".ctf-complete-at").is_file() or (out_dir / ".doc-grace-at").is_file():
        return True
    return False


def _logc(out_dir: Path, msg: str) -> None:
    _append_console(out_dir, f"{_iso(_now())} [aegis] — {msg} —\n")


def tick_conscience(out_dir: Path, *, now: float | None = None, llm: Any = None) -> dict[str, Any]:
    """Reloj + shot. llm es inyectable en tests (callable pack -> text)."""
    out_dir = Path(out_dir)
    result = {"ran": False, "action": "skip"}
    if note_refuse_turn(out_dir):
        result["action"] = "refuse"
        return result
    if not enabled() or _busy(out_dir):
        return result
    now = _now() if now is None else now
    if not due(out_dir, now):
        return result
    meta = load_meta(out_dir)
    pack, new_off = build_user_pack(out_dir, int(meta.get("console_off") or 0))
    if not callable(llm) and not has_backend(out_dir):
        meta["next_ts"] = now + STRETCH_S
        save_meta(out_dir, meta)
        if not meta.get("warned_no_backend"):
            meta["warned_no_backend"] = True
            save_meta(out_dir, meta)
            _logc(
                out_dir,
                "conciencia: no hay cuenta del run ni endpoint. No reviso",
            )
        result["action"] = "no_backend"
        return result
    raw = llm(pack) if callable(llm) else call_llm(pack, out_dir)
    result["ran"] = True
    blocked = provider_blocked(raw or "")
    verdict = parse_verdict(raw or "")
    has_verdict = "stuck" in (raw or "")
    # Tope/salvaguarda del juez (o eco del agente): no es atasco. El persist
    # ya espera o releva. Sin consola.
    if blocked and not has_verdict:
        meta["next_ts"] = now + RETRY_S
        save_meta(out_dir, meta)
        result["action"] = "retry"
        return result
    if not raw or not has_verdict:
        why = fail_detail(raw or "", False)
        meta["fail_n"] = int(meta.get("fail_n") or 0) + 1
        meta["last_error"] = why
        meta["next_ts"] = now + RETRY_S
        meta["console_off"] = new_off
        save_meta(out_dir, meta)
        _logc(out_dir, f"conciencia: {why}; reintento en 5 min (no corto)")
        result["action"] = "retry"
        return result
    prev = meta.get("progress") or {}
    cur = progress_counts(out_dir)
    # Avance real: flags/creds/tried/fase. cmd_log creciendo solo no cuenta.
    # La 1ª revisión no es stale: load_meta pone progress={flags:0,findings:0}.
    run_mode = str((_read_json(out_dir / "meta.json") or {}).get("mode") or "")
    if not run_mode:
        run_mode = str((_read_json(out_dir / "brief.json") or {}).get("mode") or "")
    if run_mode == "net":
        _real = ("findings", "hosts", "tried", "loot")
    else:
        _real = ("flags", "findings", "creds", "access", "users", "hosts", "loot", "tried", "phase")
    progressed = any(int(cur.get(k) or 0) > int(prev.get(k) or 0) for k in _real)
    seen = int(meta.get("reviews") or 0) >= 1
    burned = int(cur.get("tokens") or 0) - int(prev.get("tokens") or 0)
    token_burn = seen and not progressed and burned >= TOKEN_BURN
    _total, distinct = recent_command_activity(out_dir)
    busy = _total >= 8  # ocupado: >½ de la ventana con comandos
    stale = (
        seen
        and not progressed
        and int(cur.get("phase") or 0) == int(prev.get("phase") or 0)
        and int(cur.get("tried") or 0) <= int(prev.get("tried") or 0)
    )
    soliloquy = (
        seen
        and not progressed
        and int(cur.get("cmds") or 0) > int(prev.get("cmds") or 0)
        and int(cur.get("audit") or 0) <= int(prev.get("audit") or 0)
    )
    # Ocupado≠avance solo si HAY actividad. Un brute/nmap silencioso (pocos comandos,
    # tried plano) NO es stall del cuaderno: eso lo juzga el LLM, no lo cortamos aquí.
    busy_stall = soliloquy or (stale and busy) or token_burn
    stale_n = int(meta.get("stale_n") or 0) + 1 if busy_stall else 0
    meta["stale_n"] = stale_n
    action = ""
    if verdict["stuck"]:
        # muchos fp distintos = explora, no el mismo curl. Excepción: kind=repeat
        # (linpeas en pasos) — 1er aviso, 2º corta. stale_n≥2 tampoco se salva.
        warned = str(meta.get("last_verdict") or "") == "repeat"
        kind = str(verdict.get("kind") or "")
        allow_busy_guard = stale_n < 2
        if distinct >= ACTIVE_DISTINCT_MIN and not (warned and kind == "repeat") and allow_busy_guard:
            if kind == "repeat" and not warned:
                _logc(
                    out_dir,
                    f"conciencia: veredicto=stuck/repeat con {distinct} comandos distintos "
                    "→ aviso, no corto",
                )
                verdict["stuck"] = False
                action = "nudge"
            else:
                _logc(
                    out_dir,
                    f"conciencia: veredicto=stuck pero {distinct} comandos distintos recientes "
                    "→ trabajo activo; no corto ni pauso",
                )
                verdict["stuck"] = False
    if not verdict["stuck"] and busy_stall and stale_n >= 1:
        why = "quema de tokens" if token_burn else ("soliloquio" if soliloquy else "ocupado≠avance")
        if stale_n == 1:
            action = "nudge"
            verdict["kind"] = "stall"
            _logc(out_dir, f"conciencia: {why} → aviso, no corto")
        else:
            verdict["stuck"] = True
            verdict["kind"] = "stall"
            _logc(out_dir, f"conciencia: {why} → corte")
    if verdict["stuck"]:
        streak = int(meta.get("stuck_streak") or 0) + 1
        action = "pause" if streak >= STUCK_PAUSE_AT else "cut"
    elif action == "nudge":
        streak = 1
    else:
        streak = 0
        action = "ok"
    meta["fail_n"] = 0
    meta["last_error"] = ""
    meta["last_ts"] = now
    if verdict["stuck"]:
        last_verdict = "stuck"
    elif action == "nudge":
        last_verdict = "repeat"
    else:
        last_verdict = "ok"
    meta["last_verdict"] = last_verdict
    meta["stuck_streak"] = streak
    meta["progress"] = cur
    meta["console_off"] = new_off
    meta["reviews"] = int(meta.get("reviews") or 0) + 1
    meta["next_ts"] = now + next_delay(last_verdict, progressed)
    _push_history(
        meta,
        now=now,
        verdict=last_verdict,
        action=action,
        kind=str(verdict.get("kind") or ""),
        what=str(verdict.get("what") or ""),
    )
    save_meta(out_dir, meta)
    (out_dir / MD_NAME).write_text(operator_md(verdict, action), encoding="utf-8")
    emit_console(out_dir, verdict, action)
    if action == "ok":
        if verdict.get("routes") or verdict.get("why"):
            write_conscience_steer(out_dir, agent_briefing(verdict))
        result.update(action=action, verdict=verdict)
        return result
    if action == "nudge":
        write_conscience_steer(out_dir, agent_briefing(verdict))
        result.update(action=action, verdict=verdict)
        return result
    write_conscience_steer(out_dir, cut_steer_text(verdict))
    if action == "pause":
        (out_dir / PAUSE_NAME).write_text("pause\n", encoding="utf-8")
        (out_dir / CUT_NAME).write_text("cut\n", encoding="utf-8")
        _logc(out_dir, f"conciencia: {verdict.get('kind')} ×{streak} → pausa")
    else:
        (out_dir / CUT_NAME).write_text("cut\n", encoding="utf-8")
        _logc(out_dir, f"conciencia: {verdict.get('kind')} → corte + persist seco")
    result.update(action=action, verdict=verdict, streak=streak)
    return result
