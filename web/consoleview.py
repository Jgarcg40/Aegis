"""Consola para la UI: el JSONL crudo (firmas, tool_result) no se manda al navegador."""
from __future__ import annotations

import json
import re
from collections import deque
from pathlib import Path
from typing import Any

MAX_TEXT = 800
MAX_SPEECH = 32_000
MAX_ROWS = 12_000
CMD_DETAIL = 360  # igual que formatOpevent en app.js
_SPEECH = frozenset({"c-agent", "c-conscience", "c-guard"})
_CYBER_NOISE = re.compile(
    r"safeguards flagged|cyber-related safeguards|api_refusal_category|"
    r"intentionally broad|legitimate cybersecurity|this request triggered|"
    r"model_refusal|capabilities faster|trusted access for cyber|"
    r"chatgpt\.com/cyber|offensive exploitation",
    re.I,
)
_PROMPT_LEAK = re.compile(
    r"^(?:STEER \(obligatorio\)|Target y avance en |Este es un laboratorio de "
    r"ciberseguridad autorizado|Lab autorizado del operador|"
    r"Instrucción del operador \(obligatoria\)|"
    r"Sesión nueva\.(?: Sigue| No abras)|"
    r"SALVAGUARDA\.|"
    r"No abras (?:STATE\.md|BRIEF\.md|john)|"
    r"No leas findings/\*\.json|"
    r"No reescribas RESUME\.md|"
    r"Narra en castellano\. No pares|"
    r"YA HAY ACCESO al objetivo|"
    r"El vector de entrada YA cumplió|"
    r"Empieza ahora\. No preguntes|"
    r"Sigue solo RESUME\.md|"
    r"Si hay hold=, es usuario y vía|"
    r"No rehagas ids cubiertos|"
    r"DOCUMENTA el impacto en findings)",
    re.I,
)
_ARGV_DUMP = re.compile(
    r"^\[aegis\] (?:claude --print --|claude print exit=|codex exec --|"
    r"foothold detectado →|foothold presente →|de-escala salvaguarda →|"
    r"— conciencia: salvaguarda)|"
    r"--dangerously-skip-permissions|--dangerously-bypass-approvals",
    re.I,
)
_CYBER_SHORT = "SALVAGUARDA · cyber — el modelo cortó este turno."


def _clip(text: str, n: int = MAX_TEXT, *, keep_breaks: bool = False) -> str:
    raw = str(text or "")
    if keep_breaks:
        t = raw.strip()
        return t if len(t) <= n else t[: n - 1] + "…"
    one = " ".join(raw.split())
    return one if len(one) <= n else one[: n - 1] + "…"


def _strip_agent_md(s: str) -> str:
    """Misma limpieza que stripAgentMd en app.js."""
    t = str(s or "")
    t = re.sub(r"\*\*([^*]+)\*\*", r"\1", t)
    t = re.sub(r"__([^_]+)__", r"\1", t)
    t = re.sub(r"`([^`\n]+)`", r"\1", t)
    return t.replace("**", "")


def polish_row(row: dict[str, str] | None) -> dict[str, str] | None:
    """Oculta dumps de salvaguarda/STEER/argv; un cyber vale con una línea corta."""
    if not row:
        return None
    text = str(row.get("text") or "").strip()
    if not text:
        return None
    if _CYBER_NOISE.search(text):
        out = dict(row)
        out["cls"] = "c-guard"
        out["text"] = _CYBER_SHORT
        return out
    if _PROMPT_LEAK.search(text) or _ARGV_DUMP.search(text):
        return None
    if "salvaguarda" in text.lower() and row.get("cls") == "c-sys":
        out = dict(row)
        out["cls"] = "c-guard"
        return out
    return row


def polish_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for row in rows:
        polished = polish_row(row)
        if not polished:
            continue
        prev = out[-1] if out else None
        if prev and prev.get("cls") == polished.get("cls") and prev.get("text") == polished.get("text"):
            continue
        out.append(polished)
    return out


def _row_text(cls: str, text: str) -> str:
    # El vivo (formatConsoleLine) no aplasta espacios ni recorta a 800: el historial
    # tiene que verse igual. Solo un techo de seguridad en narración enorme.
    raw = str(text or "")
    if cls in _SPEECH:
        raw = _strip_agent_md(raw).strip()
        return raw if len(raw) <= MAX_SPEECH else raw[: MAX_SPEECH - 1] + "…"
    return raw


def _ts(obj: dict[str, Any], fallback: str = "") -> str:
    raw = obj.get("timestamp") or obj.get("ts") or fallback or ""
    return str(raw) if raw else ""


def _model_from_aegis_text(text: str) -> str:
    """Modelo activo en una línea de turno/arranque del orquestador (todos los harness)."""
    t = str(text or "").strip()
    if t.startswith("[aegis] T"):
        # [aegis] T12: claude-opus-4-8   /   [aegis] T3: xai/grok-4.3
        parts = t.split(":", 1)
        if len(parts) == 2:
            return parts[1].strip().split()[0] if parts[1].strip() else ""
    if t.startswith("[aegis] harness="):
        for tok in t.split():
            if tok.startswith("model="):
                return tok.split("=", 1)[1]
    return ""


def _with_model(row: dict[str, str], model: str) -> dict[str, str]:
    if model:
        row["model"] = model
    return row


def _classify_plain(text: str) -> str:
    """Misma idea que classifyRaw en app.js (sin el extra CTF de la UI)."""
    t = text.strip()
    if t.startswith("[aegis] — conciencia:") or t.startswith(("SIGUE (", "AVISA (", "SALVAGUARDA.", "CONCIENCIA (")):
        return "c-conscience"
    if "salvaguarda" in t.lower():
        return "c-guard"
    if t.startswith("[aegis") or t.startswith("[opencode") or t.startswith("[runner") or t.startswith("[sandbox"):
        return "c-sys"
    low = t.lower()
    if re.search(
        r"(^|\s)(fatal|traceback|exception|segfault|permission denied|connection refused|no route to host)\b",
        low,
    ) or re.search(r"\berror\b", low):
        return "c-err"
    return "c-agent"


def _cmd_text(name: str, detail: str = "", tail: str = "") -> str:
    d = str(detail or "")[:CMD_DETAIL]
    return f"$ {name}" + (f"  {d}" if d else "") + tail


def _claude_detail(inp: Any) -> str:
    if not isinstance(inp, dict):
        return ""
    for key in ("command", "file_path", "filePath", "path", "pattern", "url", "description"):
        val = inp.get(key)
        if val:
            return str(val)
    return ""


def rows_from_obj(obj: dict[str, Any], line_ts: str = "") -> list[dict[str, str]]:
    """Misma idea que formatOpevent en app.js: una línea corta, sin thinking ni stdout."""
    if obj.get("cls") and obj.get("text") is not None and not obj.get("type"):
        cls = str(obj["cls"])
        text = _row_text(cls, obj.get("text") or "")
        model = str(obj.get("model") or "") or _model_from_aegis_text(text)
        return [_with_model({"cls": cls, "text": text, "ts": _ts(obj, line_ts)}, model)]
    typ = str(obj.get("type") or "")
    ts = _ts(obj, line_ts)
    if typ in {"aegis_conscience", "aegis_claimcheck"}:
        text = str(obj.get("text") or "").strip()
        return [{"cls": "c-conscience", "text": _row_text("c-conscience", text), "ts": ts}] if text else []
    if typ in {"step_start", "step_finish"}:
        return []
    if typ == "assistant":
        msg = obj.get("message") if isinstance(obj.get("message"), dict) else {}
        model = str(msg.get("model") or obj.get("model") or "")
        out: list[dict[str, str]] = []
        for part in msg.get("content") or []:
            if not isinstance(part, dict):
                continue
            if part.get("type") == "text":
                text = str(part.get("text") or "").strip()
                if text:
                    cls = _classify_plain(text)
                    out.append(_with_model({"cls": cls, "text": _row_text(cls, text), "ts": ts}, model))
            elif part.get("type") == "tool_use":
                name = str(part.get("name") or "tool")
                detail = _claude_detail(part.get("input"))
                out.append({"cls": "c-cmd", "text": _cmd_text(name, detail), "ts": ts})
        return out
    if typ == "system" and obj.get("subtype") == "init":
        return [{"cls": "c-sys", "text": f"claude listo · {obj.get('model') or 'claude'}", "ts": ts}]
    if typ == "result" and obj.get("is_error"):
        text = str(obj.get("result") or obj.get("error") or "").strip()
        # Corte nuestro (timeout/relevo/cierre): Claude deja result vacío.
        if not text or re.search(r"interrupted by user|request interrupted", text, re.I):
            return []
        return [{"cls": "c-err", "text": _clip(text), "ts": ts}]
    if typ == "rate_limit_event":
        info = obj.get("rate_limit_info") if isinstance(obj.get("rate_limit_info"), dict) else {}
        status = str(info.get("status") or "")
        if status.startswith("allowed"):
            return []
        if status:
            return [{"cls": "c-err", "text": f"cuota Claude: {status}", "ts": ts}]
        return []
    part = obj.get("part") if isinstance(obj.get("part"), dict) else {}
    if typ == "text" or part.get("type") == "text":
        text = str(part.get("text") or obj.get("text") or "").strip()
        cls = _classify_plain(text)
        model = str(obj.get("model") or part.get("model") or "")
        if not model and isinstance(obj.get("message"), dict):
            model = str(obj["message"].get("model") or "")
        return [_with_model({"cls": cls, "text": _row_text(cls, text), "ts": ts}, model)] if text else []
    if typ == "tool_use" or part.get("type") == "tool":
        st = part.get("state") if isinstance(part.get("state"), dict) else {}
        if st.get("status") in {"pending", "running"}:
            return []
        tool = str(part.get("tool") or "tool")
        inp = st.get("input") if isinstance(st.get("input"), dict) else {}
        if not inp and isinstance(part.get("input"), dict):
            inp = part["input"]
        detail = _claude_detail(inp) or str(st.get("title") or "")
        err = bool(st.get("error") or st.get("status") == "error")
        tail = f" — {st.get('error') or 'error'}" if err else ""
        return [{"cls": "c-err" if err else "c-cmd", "text": _cmd_text(tool, detail, tail), "ts": ts}]
    if typ in {"thread.started", "turn.started", "turn.completed"}:
        return []
    if typ in {"item.started", "item.updated", "item.completed"}:
        return _codex_item_rows(obj, ts)
    if typ == "error" or obj.get("error"):
        return [{"cls": "c-err", "text": _clip(obj.get("error") or obj.get("message") or "error"), "ts": ts}]
    return []


def _codex_item_rows(obj: dict[str, Any], ts: str) -> list[dict[str, str]]:
    """Codex CLI ≥0.15: item.started/completed (agent_message / command_execution)."""
    typ = str(obj.get("type") or "")
    item = obj.get("item") if isinstance(obj.get("item"), dict) else {}
    if not item:
        return []
    kind = str(item.get("type") or "")
    if typ in {"item.started", "item.updated"}:
        return []
    if kind == "agent_message":
        text = str(item.get("text") or "").strip()
        if not text:
            return []
        cls = _classify_plain(text)
        return [{"cls": cls, "text": _row_text(cls, text), "ts": ts}]
    if kind == "command_execution":
        cmd = str(item.get("command") or "").strip()
        if not cmd:
            return []
        status = str(item.get("status") or "")
        code = item.get("exit_code")
        failed = status in {"failed", "error"} or (
            isinstance(code, int) and code not in (0,)
        )
        tail = ""
        if failed:
            tail = f" — exit {code}" if isinstance(code, int) else " — error"
        return [
            {
                "cls": "c-err" if failed else "c-cmd",
                "text": _cmd_text("bash", cmd, tail),
                "ts": ts,
            }
        ]
    return []


def compact_line(raw: str) -> list[dict[str, str]]:
    t = raw.strip()
    if not t:
        return []
    line_ts = ""
    if len(t) > 20 and t[0].isdigit() and "T" in t[:20]:
        sp = t.find(" ")
        if sp > 0 and t[sp - 1] == "Z":
            line_ts, t = t[:sp], t[sp + 1 :].lstrip()
    if not t:
        return []
    if _CYBER_NOISE.search(t):
        return [{"cls": "c-guard", "text": _CYBER_SHORT, "ts": line_ts}]
    i, j = t.find("{"), t.rfind("}")
    if i >= 0 and j > i:
        try:
            obj = json.loads(t[i : j + 1])
        except json.JSONDecodeError:
            return []
        if isinstance(obj, dict):
            return polish_rows(rows_from_obj(obj, line_ts))
        return []
    if t.startswith("{"):
        return []
    low = t.lower()
    if "aegis-entrypoint:" in low or "unexpected eof" in low or "syntax error" in low:
        return [{"cls": "c-err", "text": _clip(t), "ts": line_ts}]
    cls = _classify_plain(t)
    return polish_rows(
        [_with_model({"cls": cls, "text": _row_text(cls, t), "ts": line_ts}, _model_from_aegis_text(t))]
    )


def compact_console(path: Path, *, max_rows: int = MAX_ROWS) -> tuple[bytes, int]:
    """Texto JSONL corto para la UI + tamaño real de console.log (para el SSE)."""
    if not path.is_file():
        return b"", 0
    try:
        size = path.stat().st_size
    except OSError:
        return b"", 0
    rows: deque[dict[str, str]] = deque(maxlen=max_rows)
    cur_model = ""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                for row in compact_line(line):
                    hinted = row.get("model") or _model_from_aegis_text(row.get("text") or "")
                    if hinted:
                        cur_model = hinted
                    if row.get("cls") == "c-agent" and cur_model and not row.get("model"):
                        row["model"] = cur_model
                    prev = rows[-1] if rows else None
                    if prev and prev.get("text") == _CYBER_SHORT and row.get("text") == _CYBER_SHORT:
                        continue
                    rows.append(row)
    except OSError:
        return b"", size
    blob = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
    return blob.encode("utf-8"), size
