"""Contrato de flags solo para modo CTF. La auditoría no lo usa."""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

CONTRACT_NAME = "ctf.json"
_WRAP = re.compile(r"([A-Za-z][A-Za-z0-9_-]{1,24})\{([^\s{}]{3,160})\}")
_HEX32 = re.compile(r"^[a-fA-F0-9]{32}$")
_PRIV_NAMES = frozenset({"root.txt", "proof.txt", "root"})
_USER_NAMES = frozenset({"user.txt", "user"})
_LOOT_KIND = {
    "user.txt": "user",
    "local.txt": "user",
    "root.txt": "root",
    "proof.txt": "root",
}
_FINDING_KIND_FIELDS = {
    "user_flag": "user",
    "root_flag": "root",
    "local_flag": "user",
    "proof_flag": "root",
}
_HEX_IN = re.compile(r"\b([a-fA-F0-9]{32})\b")
_NAME_IN = re.compile(r"\b(user|root|proof|local)\.txt\b", re.I)
_FLAG_NEAR = 120


def _token_ok(val: str) -> bool:
    v = (val or "").strip().strip("`\"'")
    return bool(v) and bool(_HEX32.match(v) or _WRAP.fullmatch(v))


def _kind_from_flag_name(data: dict[str, Any]) -> str:
    name = str(data.get("flag_name") or data.get("name") or "").strip().lower()
    if name in _LOOT_KIND:
        return _LOOT_KIND[name]
    blob = " ".join(
        str(data.get(k) or "") for k in ("flag_name", "title", "path", "explain", "summary")
    ).lower()
    if "root.txt" in blob or "proof.txt" in blob:
        return "root"
    if "user.txt" in blob or "local.txt" in blob:
        return "user"
    return ""


def _add_kind(kinds: set[str], val: str, kind: str) -> None:
    v = (val or "").strip().strip("`\"'")
    token = v.split()[0] if v else ""
    if not _token_ok(token):
        return
    if kind in ("root", "proof"):
        kinds.add("root")
    elif kind in ("user", "local"):
        kinds.add("user")


def _finding_flag_kinds(out: Path) -> set[str]:
    """user/root en F-xxx.json (flag / flag_value / flag_name), no solo loot/*.txt."""
    kinds: set[str] = set()
    fdir = out / "findings"
    if not fdir.is_dir():
        return kinds
    for fp in fdir.glob("F-*.json"):
        try:
            raw = fp.read_text(encoding="utf-8", errors="replace")
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        blobs: list[Any] = [data]
        loot_obj = data.get("loot")
        if isinstance(loot_obj, dict):
            blobs.append(loot_obj)
        for blob in blobs:
            if not isinstance(blob, dict):
                continue
            for field, kind in _FINDING_KIND_FIELDS.items():
                _add_kind(kinds, str(blob.get(field) or ""), kind)
            guess = _kind_from_flag_name(data if blob is data else {**data, **blob})
            if guess:
                for field in ("flag", "flag_value"):
                    _add_kind(kinds, str(blob.get(field) or ""), guess)
        for hm in _HEX_IN.finditer(raw):
            window = raw[max(0, hm.start() - _FLAG_NEAR) : hm.end() + _FLAG_NEAR]
            lab = _NAME_IN.search(window)
            if not lab:
                continue
            word = lab.group(1).lower()
            if word in ("root", "proof"):
                kinds.add("root")
            else:
                kinds.add("user")
    return kinds


def _engagement_flag_kinds(out: Path) -> set[str]:
    """Kinds (user/root) con token válido ya registrados en engagement.json.

    Cierra el slot "name" del contrato cuando el agente capturó la flag pero no
    dejó un fichero user.txt/root.txt en loot (p.ej. la leyó por una shell y el
    relevo/refusal interrumpió antes de guardarla). El parser de flags que puebla
    engagement es estricto (literal *.txt o etiqueta "user/root flag" pegada al
    hash), así que esto no relaja la prueba, solo la vía por la que llega.
    """
    p = out / "engagement.json"
    if not p.is_file():
        return set()
    try:
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return set()
    kinds: set[str] = set()
    for f in data.get("flags") or []:
        if not isinstance(f, dict):
            continue
        val = str(f.get("value") or "").strip()
        if not (_HEX32.match(val) or _WRAP.fullmatch(val)):
            continue
        kind = str(f.get("kind") or "").strip().lower()
        if kind in ("root", "proof"):
            kinds.add("root")
        elif kind in ("user", "local"):
            kinds.add("user")
    return kinds


def slot_from_text(raw: str) -> dict[str, str]:
    text = (raw or "").strip()
    if not text:
        raise ValueError("flag vacía")
    if "{" in text:
        prefix = text.split("{", 1)[0].strip() or "FLAG"
        return {"match": f"{prefix}{{", "style": "wrap"}
    return {"match": text, "style": "name"}


def default_slots(count: int) -> list[dict[str, str]]:
    if count == 2:
        return [slot_from_text("user.txt"), slot_from_text("root.txt")]
    raise ValueError("con N≠2 indica el formato de cada flag o uno para todas")


def build_contract(
    *,
    enabled: bool,
    flags: list[str] | None = None,
    count: int | None = None,
    same: str = "",
) -> dict[str, Any]:
    if not enabled:
        return {"enabled": False, "slots": []}
    slots: list[dict[str, str]]
    cleaned = [s.strip() for s in (flags or []) if str(s).strip()]
    n = count if count is not None else (len(cleaned) or 2)
    if n < 1 or n > 32:
        raise ValueError("el número de flags debe estar entre 1 y 32")
    if cleaned:
        if len(cleaned) == 1 and n > 1:
            slots = [slot_from_text(cleaned[0]) for _ in range(n)]
        elif len(cleaned) == n:
            slots = [slot_from_text(s) for s in cleaned]
        else:
            raise ValueError(f"indica {n} flags o una sola para repetir")
    elif same.strip():
        slots = [slot_from_text(same) for _ in range(n)]
    else:
        slots = default_slots(n)
    return {"enabled": True, "slots": slots}


def write_contract(path: Path, contract: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(contract, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def load_contract(out: Path) -> dict[str, Any]:
    p = out / CONTRACT_NAME
    if not p.is_file():
        return {"enabled": False, "slots": []}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"enabled": False, "slots": []}
    if not isinstance(data, dict) or not data.get("enabled"):
        return {"enabled": False, "slots": []}
    slots = data.get("slots") or []
    if not isinstance(slots, list) or not slots:
        return {"enabled": False, "slots": []}
    return {"enabled": True, "slots": slots}


def _wrap_prefix(match: str) -> str:
    return match.split("{", 1)[0].upper() + "{"


def collect_names(out: Path) -> set[str]:
    names: set[str] = set()
    for folder in (out / "loot", out / "findings"):
        if not folder.is_dir():
            continue
        for p in folder.rglob("*"):
            if p.is_file() and p.stat().st_size > 0:
                names.add(p.name.lower())
    return names


def _norm_slot_name(raw: str) -> str:
    name = str(raw or "").strip().lower()
    if not name or "{" in name:
        return name
    if "." not in name:
        return name + ".txt"
    return name


def _push_name_token(pool: dict[str, list[str]], name: str, raw: str) -> None:
    key = _norm_slot_name(name)
    token = (raw or "").strip().strip("`\"'")
    token = token.split()[0] if token else ""
    if not key or not _token_ok(token):
        return
    stored = token.lower() if _HEX32.match(token) else token
    seen = {v.lower() for v in pool.setdefault(key, [])}
    if stored.lower() not in seen:
        pool[key].append(stored)


def collect_name_tokens(out: Path, slot_names: set[str] | None = None) -> dict[str, list[str]]:
    """Tokens por nombre de slot: fichero en loot/ o flag_name/flag_value en F-xxx."""
    wanted = {_norm_slot_name(n) for n in (slot_names or set()) if n}
    pool: dict[str, list[str]] = {}
    for folder in (out / "loot", out / "findings"):
        if not folder.is_dir():
            continue
        for p in folder.rglob("*"):
            if not p.is_file() or p.stat().st_size == 0 or p.stat().st_size > 250_000:
                continue
            nkey = _norm_slot_name(p.name)
            if wanted and nkey not in wanted and p.suffix.lower() != ".json":
                continue
            if p.suffix.lower() != ".json":
                try:
                    raw = p.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                line = next((ln.strip() for ln in raw.splitlines() if ln.strip()), "")
                _push_name_token(pool, p.name, line)
    fdir = out / "findings"
    value_fields = (
        "flag",
        "flag_value",
        "user_flag",
        "root_flag",
        "local_flag",
        "proof_flag",
    )
    for fp in fdir.glob("F-*.json") if fdir.is_dir() else ():
        try:
            raw = fp.read_text(encoding="utf-8", errors="replace")
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        blobs: list[Any] = [data]
        if isinstance(data.get("loot"), dict):
            blobs.append(data["loot"])
        for blob in blobs:
            if not isinstance(blob, dict):
                continue
            label = str(blob.get("flag_name") or blob.get("name") or data.get("flag_name") or data.get("name") or "")
            title = str(blob.get("title") or data.get("title") or "")
            for field in value_fields:
                val = str(blob.get(field) or "")
                if label:
                    _push_name_token(pool, label, val)
                if field == "user_flag":
                    _push_name_token(pool, "user.txt", val)
                elif field == "root_flag":
                    _push_name_token(pool, "root.txt", val)
                elif field == "local_flag":
                    _push_name_token(pool, "local.txt", val)
                elif field == "proof_flag":
                    _push_name_token(pool, "proof.txt", val)
            guess = _kind_from_flag_name(data if blob is data else {**data, **blob})
            if guess == "root":
                for field in ("flag", "flag_value"):
                    _push_name_token(pool, "root.txt", str(blob.get(field) or ""))
            elif guess == "user":
                for field in ("flag", "flag_value"):
                    _push_name_token(pool, "user.txt", str(blob.get(field) or ""))
            if wanted:
                blob_txt = (label + " " + title).lower()
                for slot in wanted:
                    stem = slot[:-4] if slot.endswith(".txt") else slot
                    if slot in blob_txt or (stem and re.search(rf"\b{re.escape(stem)}\b", blob_txt)):
                        for field in value_fields:
                            _push_name_token(pool, slot, str(blob.get(field) or ""))
        if wanted:
            for slot in wanted:
                for m in re.finditer(re.escape(slot), raw, re.I):
                    window = raw[max(0, m.start() - _FLAG_NEAR) : m.end() + _FLAG_NEAR]
                    for hm in _HEX_IN.finditer(window):
                        _push_name_token(pool, slot, hm.group(1))
                    for wm in _WRAP.finditer(window):
                        _push_name_token(pool, slot, wm.group(0))
    # loot/<slot> no vacío cuenta aunque el contenido no sea md5/wrap.
    for fname in collect_names(out):
        key = _norm_slot_name(fname)
        if wanted and key not in wanted:
            continue
        if key.endswith(".json"):
            continue
        if not (pool.get(key) or []):
            pool.setdefault(key, []).append("file:" + key)
    return pool


def collect_wraps(out: Path) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    seen: set[str] = set()
    for folder in (out / "loot", out / "findings"):
        if not folder.is_dir():
            continue
        for p in folder.rglob("*"):
            if not p.is_file() or p.stat().st_size == 0 or p.stat().st_size > 250_000:
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for m in _WRAP.finditer(text):
                token = m.group(0)
                key = token.lower()
                if key in seen:
                    continue
                seen.add(key)
                prefix = m.group(1).upper() + "{"
                found.setdefault(prefix, []).append(token)
    return found


def progress(out: Path, contract: dict[str, Any] | None = None) -> list[bool]:
    spec = contract if contract is not None else load_contract(out)
    slots = spec.get("slots") or []
    if not spec.get("enabled") or not slots:
        return []
    wraps = collect_wraps(out)
    name_slots = {
        _norm_slot_name(str(s.get("match") or ""))
        for s in slots
        if isinstance(s, dict) and str(s.get("style") or "name") != "wrap"
    }
    name_tokens = collect_name_tokens(out, name_slots)
    extra_kinds = _engagement_flag_kinds(out) | _finding_flag_kinds(out)
    used_wrap: dict[str, int] = {}
    used_name: dict[str, int] = {}
    used_eng: set[str] = set()
    hits: list[bool] = []
    for slot in slots:
        style = str(slot.get("style") or "name")
        match = str(slot.get("match") or "")
        if style == "wrap":
            prefix = _wrap_prefix(match)
            pool = wraps.get(prefix) or []
            idx = used_wrap.get(prefix, 0)
            ok = idx < len(pool)
            if ok:
                used_wrap[prefix] = idx + 1
            hits.append(ok)
        else:
            key = _norm_slot_name(match)
            pool = name_tokens.get(key) or []
            idx = used_name.get(key, 0)
            ok = idx < len(pool)
            if ok:
                used_name[key] = idx + 1
            elif key in _PRIV_NAMES and "root" in extra_kinds and "root" not in used_eng:
                used_eng.add("root")
                ok = True
            elif key in _USER_NAMES and "user" in extra_kinds and "user" not in used_eng:
                used_eng.add("user")
                ok = True
            hits.append(ok)
    return hits


def is_complete(out: Path, contract: dict[str, Any] | None = None) -> bool:
    spec = contract if contract is not None else load_contract(out)
    if not spec.get("enabled"):
        return False
    hits = progress(out, spec)
    return bool(hits) and all(hits)


def found_count(out: Path, contract: dict[str, Any] | None = None) -> int:
    return sum(1 for h in progress(out, contract) if h)


def privesc_gap(out: Path, contract: dict[str, Any] | None = None) -> bool:
    """CTF clásico user.txt sin root.txt. No aplica a wraps ni a auditoría."""
    spec = contract if contract is not None else load_contract(out)
    if not spec.get("enabled"):
        return False
    slots = spec.get("slots") or []
    hits = progress(out, spec)
    user_found = False
    root_missing = False
    has_root_slot = False
    for slot, hit in zip(slots, hits):
        if str(slot.get("style") or "name") != "name":
            continue
        name = str(slot.get("match") or "").lower()
        if name in _USER_NAMES and hit:
            user_found = True
        if name in _PRIV_NAMES:
            has_root_slot = True
            if not hit:
                root_missing = True
    return bool(has_root_slot and user_found and root_missing)


_F_DIR = re.compile(r"^F-\d+$", re.I)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rel(out: Path, path: Path) -> str:
    try:
        return path.relative_to(out).as_posix()
    except ValueError:
        return path.name


def _flag_value(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    line = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
    return line[:160]


def _payload_files(out: Path) -> list[Path]:
    found: list[Path] = []
    for folder in (out / "findings", out / "loot"):
        if not folder.is_dir():
            continue
        for p in folder.rglob("*"):
            if not p.is_file() or p.stat().st_size <= 0:
                continue
            if p.name.startswith("F-") and p.suffix.lower() == ".json":
                continue
            found.append(p)
    return found


def _name_files(out: Path, match: str) -> list[Path]:
    key = match.lower()
    hits = [p for p in _payload_files(out) if p.name.lower() == key]

    def rank(p: Path) -> tuple[int, str]:
        under_f = p.parent.name.upper().startswith("F-") and p.parent.parent.name == "findings"
        in_findings = "findings" in p.parts
        return (0 if under_f else 1 if in_findings else 2, str(p))

    hits.sort(key=rank)
    return hits


def _wrap_hits(out: Path, prefix: str) -> list[tuple[Path, str]]:
    want = prefix.upper()
    out_hits: list[tuple[Path, str]] = []
    seen: set[str] = set()
    for p in _payload_files(out):
        if p.stat().st_size > 250_000:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _WRAP.finditer(text):
            token = m.group(0)
            key = token.lower()
            if key in seen:
                continue
            if (m.group(1).upper() + "{") != want:
                continue
            seen.add(key)
            out_hits.append((p, token))
    return out_hits


def _load_cards(out: Path) -> list[dict[str, Any]]:
    d = out / "findings"
    items: list[dict[str, Any]] = []
    if not d.is_dir():
        return items
    for path in sorted(d.glob("F-*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict) and data.get("id"):
            items.append(data)
    return items


def _covers_slot(card: dict[str, Any], slot: dict[str, Any], evidence: str, value: str) -> bool:
    if str(card.get("kind") or "").lower() != "flag":
        return False
    match = str(slot.get("match") or "").lower()
    style = str(slot.get("style") or "name")
    blob = " ".join(
        [
            str(card.get("id") or ""),
            str(card.get("title") or ""),
            str(card.get("summary") or ""),
            str(card.get("explain") or ""),
            " ".join(str(x) for x in (card.get("evidence") or [])),
        ]
    ).lower()
    if style == "wrap":
        return bool(value and value.lower() in blob)
    return match in blob or evidence.lower() in blob or bool(value and value.lower() in blob)


def _json_ids(out: Path) -> set[str]:
    d = out / "findings"
    if not d.is_dir():
        return set()
    return {p.stem for p in d.glob("F-*.json")}


def _dir_ids(out: Path) -> set[str]:
    d = out / "findings"
    if not d.is_dir():
        return set()
    return {p.name for p in d.iterdir() if p.is_dir() and _F_DIR.match(p.name)}


def _pick_id(out: Path, evidence: Path) -> str:
    taken = _json_ids(out)
    parent = evidence.parent
    if (
        parent.parent.name == "findings"
        and _F_DIR.match(parent.name)
        and parent.name not in taken
    ):
        return parent.name
    reserved = taken | _dir_ids(out)
    n = 1
    while True:
        fid = f"F-{n:03d}"
        if fid not in reserved:
            return fid
        n += 1


def _flag_title(slot: dict[str, Any], value: str) -> str:
    match = str(slot.get("match") or "")
    if str(slot.get("style") or "name") == "wrap":
        return f"Flag ({value or match})"
    name = match.lower()
    if name in _USER_NAMES:
        return "Flag de usuario (user.txt)"
    if name in _PRIV_NAMES:
        return f"Flag de root ({match or 'root.txt'})"
    return f"Flag ({match})"


def _flag_summary(match: str, rel: str) -> str:
    return f"Flag `{match}` en `{rel}`."


def _flag_explain(match: str, rel: str, out: Path) -> str:
    host = _first_host(_context_text(out))
    extra = f" en `{host}`" if host else ""
    slot = "usuario" if "user" in match.lower() else ("root" if "root" in match.lower() else "contrato")
    return (
        f"Se capturó la flag `{match}` y quedó en `{rel}`{extra}. "
        f"Cierra el slot de {slot} del contrato CTF."
    )


def _resolve_hit(
    out: Path,
    slot: dict[str, Any],
    used_paths: set[str],
    used_tokens: set[str],
) -> tuple[Path, str] | None:
    style = str(slot.get("style") or "name")
    match = str(slot.get("match") or "")
    if not match:
        return None
    if style == "wrap":
        prefix = _wrap_prefix(match)
        for path, token in _wrap_hits(out, prefix):
            if token.lower() in used_tokens:
                continue
            used_tokens.add(token.lower())
            used_paths.add(str(path))
            return path, token
        return None
    for path in _name_files(out, match):
        key = str(path)
        if key in used_paths:
            continue
        used_paths.add(key)
        return path, _flag_value(path)
    return None


def _card_source(dest: Path) -> str:
    if not dest.is_file():
        return ""
    try:
        data = json.loads(dest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    if not isinstance(data, dict):
        return ""
    return str(data.get("source") or "")


def _fill_missing_assets(out: Path) -> None:
    host = _first_host(_context_text(out))
    if not host:
        return
    findings = out / "findings"
    if not findings.is_dir():
        return
    for path in findings.glob("F-*.json"):
        if _card_source(path) not in {"aegis-ctf", "aegis-evidence", "aegis-harvest"}:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict) or str(data.get("asset") or "").strip():
            continue
        data["asset"] = host
        try:
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        except OSError:
            continue


def _skip_live_llm() -> bool:
    if os.environ.get("AEGIS_LIVE_DESCRIBE") == "0":
        return True
    return "unittest" in sys.modules or bool(os.environ.get("PYTEST_CURRENT_TEST"))


def _looks_english(text: str) -> bool:
    blob = (text or "").strip()
    if not blob:
        return False
    en = len(_EN_WORDS.findall(blob))
    es = len(_ES_WORDS.findall(blob))
    return en >= 2 and en > es


def _parse_json_obj(raw: str) -> dict[str, Any]:
    text = (raw or "").strip()
    if not text:
        return {}
    fence = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.S)
    if fence:
        text = fence.group(1)
    else:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            text = text[start : end + 1]
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _needs_describe(card: dict[str, Any]) -> bool:
    src = str(card.get("source") or "")
    if src not in _AEGIS_DESCRIBE:
        return False
    blob = f"{card.get('title')} {card.get('explain')} {card.get('summary')}"
    if _looks_english(blob):
        return True
    return str(card.get("described") or "") != "es"


def _describe_pack(out: Path, card: dict[str, Any]) -> str:
    parts = ["FICHA ACTUAL:\n" + json.dumps(card, ensure_ascii=False, indent=2)]
    ctx = _context_text(out)
    if ctx:
        parts.append("STATE (recorte):\n" + ctx[:8000])
    for ev in card.get("evidence") or []:
        path = out / str(ev)
        if path.is_file():
            try:
                if path.stat().st_size < 20_000 and path.suffix.lower() in {
                    ".txt",
                    ".md",
                    ".json",
                    ".py",
                    ".sh",
                    ".php",
                    ".log",
                }:
                    parts.append(f"===== {ev} =====\n" + path.read_text(encoding="utf-8", errors="replace")[:3000])
                else:
                    parts.append(f"===== {ev} =====\n" + _peek_files([path])[:2000])
            except OSError:
                parts.append(str(ev))
        else:
            parts.append(str(ev))
    proof = str(card.get("proof") or "")
    if proof:
        parts.append("AUDIT/PROOF:\n" + proof)
    return "\n\n".join(parts)[:20_000]


def _merge_described(old: dict[str, Any], rec: dict[str, Any], material: str) -> dict[str, Any] | None:
    title = str(rec.get("title") or "").strip()
    explain = str(rec.get("explain") or "").strip()
    if not title or len(explain) < 40:
        return None
    if _looks_english(f"{title} {explain} {rec.get('summary') or ''}"):
        return None
    out = dict(old)
    for key in ("title", "explain", "summary", "reproduction", "impact", "asset"):
        val = str(rec.get(key) or "").strip()
        if val:
            out[key] = val
    proof = str(rec.get("proof") or "").strip()
    old_proof = str(old.get("proof") or "")
    if proof and (proof in material or old_proof in proof or proof in old_proof or not old_proof):
        out["proof"] = proof
    kind = str(rec.get("kind") or "").strip().lower()
    if kind in {"vuln", "cve", "misconfig", "flag", "info"}:
        if str(old.get("kind") or "").lower() != "flag" or kind == "flag":
            out["kind"] = kind
    sev = str(rec.get("severity") or "").strip().lower()
    if sev in {"critical", "high", "medium", "low", "info"}:
        out["severity"] = sev
    if str(out.get("kind") or "").lower() == "flag":
        out["severity"] = "info"
    out["described"] = "es"
    return out


def _describe_lock(out: Path) -> bool:
    lock = out / _DESCRIBE_LOCK
    try:
        if lock.is_file() and time.time() - lock.stat().st_mtime < 150:
            return False
        lock.write_text(str(os.getpid()), encoding="utf-8")
    except OSError:
        return False
    return True


def _describe_unlock(out: Path) -> None:
    try:
        (out / _DESCRIBE_LOCK).unlink()
    except OSError:
        pass


def describe_live_findings(
    out: Path,
    *,
    llm: Callable[..., str] | None = None,
    limit: int = 8,
    prefer: list[str] | None = None,
) -> list[str]:
    """Redacta en español (un LLM) las fichas que Aegis acaba de indexar. No pisa las del agente."""
    if llm is None and _skip_live_llm():
        return []
    findings = out / "findings"
    if not findings.is_dir():
        return []
    cards = _load_cards(out)
    want = [c for c in cards if _needs_describe(c)]
    if not want:
        return []
    preferred = {str(x) for x in (prefer or [])}
    want.sort(key=lambda c: (str(c.get("id") or "") not in preferred, str(c.get("id") or "")))
    want = want[: max(1, limit)]
    if not _describe_lock(out):
        return []
    updated: list[str] = []
    try:
        fn = llm
        if fn is None:
            from internal.conscience import call_llm_text

            fn = call_llm_text
        for card in want:
            pack = _describe_pack(out, card)
            try:
                raw = fn(DESCRIBE_SYS, pack, out)
            except Exception:
                continue
            rec = _parse_json_obj(raw if isinstance(raw, str) else "")
            if rec.get("findings") and isinstance(rec["findings"], list) and rec["findings"]:
                first = rec["findings"][0]
                rec = first if isinstance(first, dict) else rec
            merged = _merge_described(card, rec, pack)
            if not merged:
                continue
            dest = findings / f"{merged.get('id')}.json"
            if dest.is_file() and _card_source(dest) not in _AEGIS_DESCRIBE | {"aegis-reserved"}:
                continue
            if _write_finding_card(dest, merged):
                updated.append(str(merged.get("id")))
    finally:
        _describe_unlock(out)
    return updated


def _ensure_spanish_summary(out: Path) -> None:
    """Si el resumen está en inglés y el explain en español, el resumen pasa a español."""
    findings = out / "findings"
    if not findings.is_dir():
        return
    for path in findings.glob("F-*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        summary = str(data.get("summary") or "")
        explain = str(data.get("explain") or "")
        if not _looks_english(summary) or _looks_english(explain) or not explain:
            continue
        first = re.split(r"(?<=\S\.)\s+", explain, maxsplit=1)[0].strip()
        if not first:
            continue
        if not first.endswith("."):
            first += "."
        data["summary"] = first
        text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
        try:
            path.write_text(text, encoding="utf-8")
        except PermissionError:
            try:
                path.unlink()
                path.write_text(text, encoding="utf-8")
            except OSError:
                continue
        except OSError:
            continue


def sync_findings(out: Path, *, llm: Callable[..., str] | None = None) -> list[str]:
    """Indexa disco → F-xxx.json. Idempotente. Lo llama el sidecar (en vivo) y Findings."""
    created: list[str] = []
    for step in (
        ensure_flag_findings,
        ensure_evidence_findings,
        enrich_live_findings,
        enrich_live_webshell,
        ensure_privesc_finding,
    ):
        try:
            created.extend(step(out))
        except (OSError, ImportError):
            continue
    try:
        _fill_missing_assets(out)
        _ensure_spanish_summary(out)
        if llm is not None:
            created.extend(describe_live_findings(out, llm=llm, limit=2, prefer=created))
    except OSError:
        pass
    return created


def ensure_flag_findings(out: Path) -> list[str]:
    """Si el agente no escribió F-xxx.json para un slot CTF ya en disco, lo indexa."""
    spec = load_contract(out)
    if not spec.get("enabled"):
        return []
    slots = spec.get("slots") or []
    if not slots:
        return []
    cards = _load_cards(out)
    created: list[str] = []
    used_paths: set[str] = set()
    used_tokens: set[str] = set()
    for slot, ok in zip(slots, progress(out, spec)):
        if not ok or not isinstance(slot, dict):
            continue
        hit = _resolve_hit(out, slot, used_paths, used_tokens)
        if hit is None:
            continue
        path, value = hit
        rel = _rel(out, path)
        if any(_covers_slot(c, slot, rel, value) for c in cards):
            continue
        fid = _pick_id(out, path)
        dest = out / "findings" / f"{fid}.json"
        if dest.is_file() and _card_source(dest) != "aegis-reserved":
            continue
        match = str(slot.get("match") or "")
        card = {
            "id": fid,
            "title": _flag_title(slot, value),
            "asset": _first_host(_context_text(out)),
            "severity": "info",
            "status": "proven",
            "mode_ok": ["full"],
            "explain": _flag_explain(match, rel, out),
            "summary": _flag_summary(match, rel),
            "proof": _recent_argv(out, [match, Path(rel).name]),
            "reproduction": f"Copiar `{match}` a `loot/` y a `findings/<id>/`.",
            "evidence": [rel],
            "impact": "Prueba de compromiso del contrato CTF.",
            "kind": "flag",
            "timestamp": _now_iso(),
            "source": "aegis-ctf",
        }
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            dest.write_text(json.dumps(card, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        except OSError:
            continue
        cards.append(card)
        created.append(fid)
    return created


_CRED_HINTS = ("cred", "iam", "aws", "token", "secret", "password", "akid", "session", "cookie")
_EXPLOIT_HINTS = ("rev", "runcmd", "pwn", "exploit", "payload", "shell", "ssrf", "rce", "xss")
_SKIP_LOOSE_DIRS = {"scans", "screenshots", "http", "raw", "tmp", "cache"}
_SKIP_LOOSE_FILE = re.compile(
    r"^(nmap[-_]|gobuster[-_]|reverify[-_]|vhosts?|dirb[-_]|nikto[-_]|rustscan[-_]|whatweb[-_])",
    re.I,
)
_SKIP_PROSE = re.compile(
    r"^(next:|siguiente|flags?|exploit|cadena|users?|creds?|acceso|objetivo|recon)\b",
    re.I,
)
_AEGIS_DESCRIBE = frozenset({"aegis-evidence", "aegis-ctf", "aegis-harvest"})
_DESCRIBE_LOCK = ".describe.lock"
_EN_WORDS = re.compile(
    r"\b(the|with|from|this|that|into|upload|got|none|yet|valid|domain|"
    r"unauth|stacked|captured|reverse|via|in|as|on|and|stores|table|"
    r"cracked|writable|unsanitized|injection|after|reuse|share|command)\b",
    re.I,
)
_ES_WORDS = re.compile(
    r"\b(el|la|los|las|que|con|del|una|para|por|se|tras|clave|sesión|"
    r"ejecución|capturada|demostró|objetivo|usuario|escalada|quedó|hay)\b",
    re.I,
)
DESCRIBE_SYS = """Eres el redactor de fichas de un pentest autorizado (Aegis).
Redactas UNA ficha en español, al mismo nivel que si la hubiera escrito el agente
(title concreto, explain de 2-4 frases, proof real, reproduction, impact).
No inventes vectores, IPs, CVE, flags ni comandos que no estén en el material.

Responde SOLO con JSON:
{"title":"...","asset":"...","severity":"critical|high|medium|low|info","status":"proven|suspected","kind":"vuln|cve|misconfig|flag|info","explain":"...","summary":"...","proof":"...","reproduction":"...","impact":"..."}

Reglas:
- Todo el texto en español. CVE, SSH, sudo y nombres de herramienta se dejan.
- explain: 2 a 4 frases (qué es, en qué host, cómo se demostró). Nada de plantillas.
- summary: una frase en español.
- proof: un comando que YA aparezca en el material; si no hay, cadena vacía.
- No traduzcas IDs, rutas ni credenciales.
- No cambies el kind a flag si no es una flag.
"""
_AEGIS_INDEX = frozenset({"aegis-evidence", "aegis-reserved"})
_CARD_FIELDS = (
    "id",
    "title",
    "severity",
    "status",
    "explain",
    "summary",
    "proof",
    "reproduction",
    "evidence",
    "impact",
    "kind",
    "asset",
)
# No «rce» / «explot» / «shell»: el agente nombra el CVE y el intento, no la prueba.
_DEMO_RE = re.compile(
    r"\b(got\b|obtuv|demostr|uid=|reverse|pwned|pickle|sudo\s+/)\b",
    re.I,
)
_SUDO_RUN = re.compile(
    r"\bsudo\s+(?:-[A-Za-z0-9-]+\s+)*/(?:usr/)?bin/|\bsudo\s+python|\bsudo\s+-u\s+root",
    re.I,
)
_PRIV_HINT = re.compile(
    r"\b(sudo|privesc|privilege|suid|pkexec|doas|cap_setuid|trainer|olivetin|escalada)\b",
    re.I,
)
_PHP_EXEC = re.compile(r"\b(system|passthru|shell_exec|popen|proc_open|exec)\s*\(", re.I)
_HOST_URL = re.compile(r"https?://([A-Za-z0-9._-]+\.[A-Za-z]{2,})", re.I)
_HOST_COOKIE = re.compile(r"^#?HttpOnly_?([A-Za-z0-9._-]+\.[A-Za-z]{2,})\t", re.M | re.I)
_HOST_LINE = re.compile(r"^([A-Za-z0-9._-]+\.[A-Za-z]{2,})\t", re.M)
_LAB_HOST = re.compile(r"\b([a-z0-9][a-z0-9.-]{1,80}\.(?:lab|test|local|lan|internal|example))\b", re.I)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_SSH_KEY_RE = re.compile(r"BEGIN (?:OPENSSH|RSA|DSA|EC) PRIVATE KEY")
_SSH_NAME_RE = re.compile(r"\b(id_rsa|id_ed25519|id_ecdsa|id_dsa)\b")
_RUNNER_KEY_COMMENT = re.compile(r"aegis-run-\d{8}", re.I)
_PDFMINER_HINTS = ("pdfminer", "pdf2txt", "pickle", "cmap")


def _is_runner_ssh_key(files: list[Path]) -> bool:
    """Clave fabricada en el sandbox (comentario root@aegis-run-…), no loot del objetivo."""
    if not files:
        return False
    peek = _peek_files(files)
    names = " ".join(p.name.lower() for p in files)
    if not (_SSH_KEY_RE.search(peek) or _SSH_NAME_RE.search(names)):
        return False
    if _RUNNER_KEY_COMMENT.search(peek):
        return True
    for p in files:
        if "aegis-run-" in p.name.lower():
            return True
        try:
            chunk = p.read_text(encoding="utf-8", errors="replace")[:4000]
        except OSError:
            continue
        if _RUNNER_KEY_COMMENT.search(chunk):
            return True
    return False


def _void_runner_key_card(data: dict[str, Any]) -> dict[str, Any]:
    card = dict(data)
    fid = str(card.get("id") or "")
    card.update(
        {
            "title": "Clave SSH generada en el runner (no es loot del objetivo)",
            "severity": "info",
            "status": "discarded",
            "kind": "info",
            "explain": (
                "El fichero es una clave creada en el sandbox (comentario `aegis-run-*`). "
                "No es una identidad robada del objetivo."
            ),
            "summary": "Clave del runner, no del objetivo.",
            "impact": "Ninguno: no hay compromiso adicional.",
            "proof": "",
            "reproduction": "No usar como hallazgo; el artefacto queda en disco por si hay que auditar el run.",
        }
    )
    if fid:
        card["id"] = fid
    return card


def _void_runner_generated_keys(out: Path) -> list[str]:
    findings = out / "findings"
    if not findings.is_dir():
        return []
    voided: list[str] = []
    for path in sorted(findings.glob("F-*.json")):
        if _card_source(path) not in _AEGIS_INDEX:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        files = [out / str(ev) for ev in (data.get("evidence") or [])]
        files = [p for p in files if p.is_file() and p.stat().st_size > 0]
        if not files and (findings / path.stem).is_dir():
            files = _nonempty_files(findings / path.stem)
        if not _is_runner_ssh_key(files):
            continue
        card = _void_runner_key_card(data)
        if _write_finding_card(path, card):
            voided.append(str(card.get("id") or path.stem))
    return voided


def _peek_files(files: list[Path]) -> str:
    parts: list[str] = []
    budget = 8000
    for p in files[:10]:
        try:
            chunk = p.read_bytes()[:2500]
        except OSError:
            continue
        parts.append(chunk.decode("utf-8", errors="replace"))
        budget -= len(chunk)
        if budget <= 0:
            break
    return "\n".join(parts)


def _first_host(text: str) -> str:
    for rx in (_HOST_URL, _HOST_COOKIE, _HOST_LINE, _LAB_HOST):
        m = rx.search(text)
        if m:
            return m.group(1).lower()
    return ""


def _context_text(out: Path) -> str:
    parts: list[str] = []
    for name in ("STATE.md", "PIVOT.md"):
        path = out / name
        if not path.is_file():
            continue
        try:
            parts.append(path.read_text(encoding="utf-8", errors="replace")[:12_000])
        except OSError:
            continue
    return "\n".join(parts)


def _token_in(text: str, tokens: tuple[str, ...]) -> bool:
    """Pistas como palabras, no substrings (`rce`≠resources, `iam`≠diameter, `rev`≠reverify)."""
    blob = (text or "").lower()
    for tok in tokens:
        if not tok:
            continue
        if len(tok) <= 3:
            if re.search(rf"\b{re.escape(tok)}\b", blob):
                return True
        elif re.search(rf"\b{re.escape(tok)}", blob):
            return True
    return False


def _cves_in(text: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in _CVE_RE.finditer(text or ""):
        cve = m.group(0).upper()
        if cve in seen:
            continue
        seen.add(cve)
        out.append(cve)
    return out


def _describe_evidence(files: list[Path], *, context: str = "") -> dict[str, str]:
    """Qué es el hallazgo. Nombres + peek + CVE de STATE; no texto del indexador."""
    names = " ".join(p.name.lower() for p in files)
    dirs = " ".join(sorted({p.parent.name.lower() for p in files}))
    peek = _peek_files(files)
    blob = f"{names} {dirs} {peek.lower()}"
    asset = _first_host(peek) or _first_host(context)
    main = files[0].name
    for p in files:
        if p.name.lower() in _USER_NAMES or p.name.lower() in _PRIV_NAMES:
            return {
                "kind": "flag",
                "title": f"Flag ({p.name})",
                "severity": "info",
                "explain": f"Flag `{p.name}` capturada en disco.",
                "impact": "Prueba de compromiso del contrato CTF.",
                "asset": asset,
            }

    if _SSH_KEY_RE.search(peek) or _SSH_NAME_RE.search(names):
        who = ""
        comment = re.search(r"([A-Za-z0-9._-]+)@[A-Za-z0-9._-]+", peek)
        if comment:
            who = comment.group(1)
        else:
            stem = re.sub(r"(^|_)id_(rsa|ed25519|ecdsa|dsa)$", "", Path(main).stem, flags=re.I)
            stem = stem.replace("_id_rsa", "").replace("id_rsa", "").strip("_-.")
            if stem and stem.lower() not in {"id", "rsa", "key"}:
                who = stem
        extra = f" del usuario `{who}`" if who else ""
        title = f"Clave SSH privada ({who})" if who else "Clave SSH privada"
        host = f" en `{asset}`" if asset else ""
        return {
            "kind": "misconfig",
            "title": title,
            "severity": "high",
            "explain": (
                f"Hay una clave privada OpenSSH{extra} en la evidencia{host}. "
                "Permite autenticación SSH con esa identidad."
            ),
            "impact": "Acceso SSH con la identidad robada.",
            "asset": asset,
        }

    php_rce = bool(_PHP_EXEC.search(peek))
    php_plugin = "plugin name:" in peek.lower()
    if php_rce or (".php" in names and ("pwn" in blob or "webshell" in blob)):
        if php_plugin or "pwn" in dirs or "plugin" in blob:
            title = "Ejecución remota: plugin WordPress (webshell)"
            explain = (
                "Hay un plugin PHP que ejecuta comandos en el servidor web. "
                "En la evidencia aparece system()/exec() sobre un parámetro de la petición."
                if php_rce
                else "Hay un plugin PHP que ejecuta comandos en el servidor web."
            )
        else:
            title = "Ejecución remota de comandos"
            explain = (
                "Hay código que ejecuta comandos en el servidor. "
                "En la evidencia aparece system()/exec() sobre un parámetro de la petición."
                if php_rce
                else "Hay código que ejecuta comandos en el servidor."
            )
        return {
            "kind": "vuln",
            "title": title,
            "severity": "critical",
            "explain": explain,
            "impact": "Control del proceso web: lectura y ejecución en el host de la app.",
            "asset": asset,
        }

    if any(x in blob for x in ("xss", "exfil", "onerror", "document.cookie")):
        explain = "Cross-site scripting con salida de sesión o páginas internas."
        if "wp-admin" in blob:
            explain = "XSS que exfiltra cookies y páginas de wp-admin."
        return {
            "kind": "vuln",
            "title": "XSS con exfiltración de sesión",
            "severity": "critical",
            "explain": explain,
            "impact": "Robo de la sesión del navegador (a menudo admin).",
            "asset": asset,
        }

    if "wordpress_logged_in" in blob or "wordpress_sec" in blob:
        who = ""
        m = re.search(r"wordpress_logged_in_[^\t\s]+\s+(\S+)", peek)
        if m:
            who = m.group(1).split("%")[0].split("|")[0]
        extra = f" Usuario `{who}`." if who else ""
        return {
            "kind": "misconfig",
            "title": "Sesión WordPress (cookies)",
            "severity": "critical",
            "explain": f"Cookies de sesión WordPress (`wordpress_logged_in`).{extra}",
            "impact": "Acceso a wp-admin con la sesión capturada.",
            "asset": asset,
        }

    if re.search(r"accesskeyid|akia[0-9a-z]{8}|aws_secret|sessiontoken", blob):
        return {
            "kind": "misconfig",
            "title": "Credenciales IAM / AWS",
            "severity": "critical",
            "explain": "Claves de acceso AWS (AccessKeyId u homólogo) en disco.",
            "impact": "Acceso al plano cloud con el rol robado.",
            "asset": asset,
        }

    if (
        "wp-config" in names
        or "wp-config" in peek.lower()
        or "db_password" in peek.lower()
        or "db_user" in peek.lower()
    ):
        return {
            "kind": "misconfig",
            "title": "Credenciales WordPress (wp-config)",
            "severity": "high",
            "explain": (
                "En disco hay un volcado o recorte de `wp-config.php` "
                "(usuario/clave de la base o de un login SSH reutilizado)."
            ),
            "impact": "Acceso a WordPress/MySQL y, si reutilizan la clave, a SSH.",
            "asset": asset,
        }

    if re.search(r"uid=0\(root\)", peek) or "sysid" in blob or (
        "ocr" in blob and ("uid=0" in peek.lower() or "root.txt" in blob)
    ):
        return {
            "kind": "misconfig",
            "title": "Escalada a root (OCR / PHP)",
            "severity": "critical",
            "explain": (
                "Hay prueba de `uid=0` vía un PHP local (OCR/sysid) y lectura de `root.txt`. "
                "No es un login SSH root ni un sudo clásico."
            ),
            "impact": "Control del host como root.",
            "asset": asset,
        }

    if _token_in(blob, _CRED_HINTS):
        return {
            "kind": "misconfig",
            "title": "Credenciales o cookies capturadas",
            "severity": "high",
            "explain": "Hay secretos de sesión o autenticación en la evidencia.",
            "impact": "Suplantación de un usuario o servicio.",
            "asset": asset,
        }

    if "ssrf" in blob:
        return {
            "kind": "vuln",
            "title": "SSRF",
            "severity": "critical",
            "explain": "El servidor pide URLs que controla el atacante.",
            "impact": "Alcance a red interna o metadatos.",
            "asset": asset,
        }

    is_pdf_rce = any(h in blob for h in _PDFMINER_HINTS)
    is_exploit = (
        _token_in(blob, _EXPLOIT_HINTS)
        or any(p.suffix.lower() in {".py", ".sh"} for p in files)
        or is_pdf_rce
    )
    cves = _cves_in(peek) or (_cves_in(context) if is_exploit else [])
    pdfminer = any(h in blob or h in context.lower() for h in _PDFMINER_HINTS) if is_exploit else False
    if cves and is_exploit:
        cve = cves[0]
        if pdfminer:
            return {
                "kind": "cve",
                "title": f"{cve}: ejecución remota pickle/CMap (pdfminer.six)",
                "severity": "critical",
                "explain": (
                    f"{cve} en pdfminer.six: el parser trata un CMap/Encoding malicioso "
                    "y deserializa pickle. En disco hay el PDF o el watcher que llama a pdf2txt."
                ),
                "impact": "Ejecución de código en el proceso que parsea el PDF.",
                "asset": asset,
            }
        return {
            "kind": "cve",
            "title": f"{cve}: ejecución de código",
            "severity": "critical",
            "explain": (
                    f"{cve} demostrado: hay un artefacto de explotación en disco "
                    "y el estado del run lo documenta."
                ),
            "impact": "Ejecución de comandos en el objetivo.",
            "asset": asset,
        }
    if is_pdf_rce and pdfminer:
        return {
            "kind": "vuln",
            "title": "Ejecución remota pickle/CMap (pdfminer.six)",
            "severity": "critical",
            "explain": (
                "Deserialización pickle vía CMap/Encoding en un PDF (pdfminer.six). "
                "Hay artefacto de explotación en disco."
            ),
            "impact": "Ejecución de código en el proceso que parsea el PDF.",
            "asset": asset,
        }

    if (
        "toctou" in blob
        or "scm_rights" in blob
        or "mgmt.sock" in blob
        or ("fifo" in blob and ("commands.log" in blob or "paperwork" in blob))
    ):
        return {
            "kind": "misconfig",
            "title": "Escalada a root (TOCTOU / SCM_RIGHTS)",
            "severity": "critical",
            "explain": (
                "Hay una carrera TOCTOU sobre el log del daemon: FIFO o symlink hace que "
                "un proceso root abra un fichero arbitrario y ceda el descriptor (SCM_RIGHTS). "
                "En disco quedó la prueba de lectura de `root.txt`."
            ),
            "impact": "Lectura de ficheros de root y cierre del slot root.txt.",
            "asset": asset,
        }

    if _token_in(blob, _EXPLOIT_HINTS) or any(p.suffix.lower() in {".py", ".sh"} for p in files):
        return {
            "kind": "vuln",
            "title": "Ejecución de código / shell",
            "severity": "critical",
            "explain": "Hay un script o artefacto de explotación en disco.",
            "impact": "Ejecución de comandos en el objetivo.",
            "asset": asset,
        }

    return {
        "kind": "vuln",
        "title": f"Hallazgo ({main})",
        "severity": "medium",
        "explain": f"Evidencia en `{main}`.",
        "impact": "Revisar la evidencia en disco.",
        "asset": asset,
    }


def _nonempty_files(folder: Path) -> list[Path]:
    return [p for p in sorted(folder.rglob("*")) if p.is_file() and p.stat().st_size > 0]


def _write_finding_card(dest: Path, card: dict) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_file():
        try:
            old = json.loads(dest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            old = {}
        if isinstance(old, dict) and all(old.get(k) == card.get(k) for k in _CARD_FIELDS):
            return False
        if isinstance(old, dict) and old.get("timestamp"):
            card = dict(card)
            card["timestamp"] = old["timestamp"]
            if all(old.get(k) == card.get(k) for k in _CARD_FIELDS) and old.get("timestamp") == card.get("timestamp"):
                return False
    try:
        dest.write_text(json.dumps(card, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError:
        return False
    return True


def _recent_argv(out: Path, hints: list[str], *, limit: int = 240) -> str:
    path = out / ".audit" / "commands.jsonl"
    cleaned = [h for h in hints if h and len(h) > 1]
    if not path.is_file() or not cleaned:
        return ""
    rx = re.compile("|".join(re.escape(h) for h in cleaned), re.I)
    last = ""
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    for line in raw[-300_000:].splitlines()[-250:]:
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        argv = str(rec.get("argv") or "") if isinstance(rec, dict) else ""
        if rx.search(argv):
            last = " ".join(argv.split())
    return last[:limit]


def _state_window(text: str, needle: str, radius: int = 10) -> str:
    lines = (text or "").splitlines()
    idx = next((i for i, ln in enumerate(lines) if needle.lower() in ln.lower()), -1)
    if idx < 0:
        return ""
    chunk = lines[max(0, idx - 1) : idx + radius]
    return "\n".join(chunk)


def _prose_from_md(text: str, limit: int = 420) -> str:
    parts: list[str] = []
    for line in (text or "").splitlines():
        s = line.strip().lstrip("#").strip()
        s = s.lstrip("-*").strip()
        if not s or s.lower().startswith("next:"):
            continue
        if _SKIP_PROSE.match(s) and len(s) < 48:
            continue
        parts.append(s.rstrip(" ."))
        if len(parts) >= 4 or len(". ".join(parts)) >= limit:
            break
    if not parts:
        return ""
    return (". ".join(parts)[:limit].rstrip(".") + ".")


def _card_blob(card: dict) -> str:
    return " ".join(
        str(card.get(k) or "")
        for k in ("id", "title", "explain", "summary", "kind")
    )


def _evidence_card(fid: str, files: list[Path], out: Path, *, source: str = "aegis-evidence") -> dict:
    context = _context_text(out)
    desc = _describe_evidence(files, context=context)
    explain = desc["explain"]
    if desc["kind"] == "cve" and _looks_generic_title(desc["title"], explain):
        cves = _cves_in(desc["title"])
        extra = _prose_from_md(_state_window(context, cves[0])) if cves else ""
        if extra and len(extra) > len(explain):
            explain = extra
    hints = [p.name for p in files] + _cves_in(desc["title"] + " " + explain)
    for token in ("pickle", "pdfminer", "pdf2txt", "sudo /", "id_rsa", "ssh "):
        if token in f"{desc['title']} {explain}".lower() or token in " ".join(p.name.lower() for p in files):
            hints.append(token)
    proof = _recent_argv(out, hints)
    repro = explain.split(".")[0].strip()
    if repro and not repro.endswith("."):
        repro += "."
    return {
        "id": fid,
        "title": desc["title"],
        "asset": desc.get("asset") or _first_host(context),
        "severity": desc["severity"],
        "status": "proven",
        "mode_ok": ["full"],
        "explain": explain,
        "summary": (explain.split(".")[0] + ".") if explain else desc["title"],
        "proof": proof,
        "reproduction": repro,
        "evidence": [_rel(out, p) for p in files],
        "impact": desc["impact"],
        "kind": desc["kind"],
        "timestamp": _now_iso(),
        "source": source,
    }


def _loose_clusters(findings: Path) -> list[list[Path]]:
    """Evidencia fuera de F-xxx/: pwn/, xsslog/, cookies.txt… No indexa dumps de recon."""
    clusters: list[list[Path]] = []
    for p in sorted(findings.iterdir()):
        if p.is_dir():
            if _F_DIR.match(p.name) or p.name.lower() in _SKIP_LOOSE_DIRS:
                continue
            # dumps tipo F-003-ssrf / F-002-user-flag: ya son fichas, no loot suelto
            if re.match(r"^F-\d+", p.name, re.I):
                continue
            if any(p.rglob("F-*.json")):
                continue
            files = _nonempty_files(p)
            if files:
                clusters.append(files)
            continue
        if not p.is_file() or p.suffix.lower() == ".json" or p.stat().st_size <= 0:
            continue
        if _SKIP_LOOSE_FILE.match(p.name):
            continue
        low = p.name.lower()
        if _token_in(low, _CRED_HINTS) or _token_in(low, _EXPLOIT_HINTS):
            clusters.append([p])
    return clusters


def _empty_reserved(findings: Path) -> list[str]:
    ids: list[str] = []
    for folder in sorted(findings.iterdir()):
        if not folder.is_dir() or not _F_DIR.match(folder.name):
            continue
        if (findings / f"{folder.name}.json").is_file():
            continue
        if _nonempty_files(folder):
            continue
        ids.append(folder.name.upper())
    return ids


def _next_f_id(findings: Path) -> str:
    n = 1
    while True:
        fid = f"F-{n:03d}"
        if not (findings / fid).exists() and not (findings / f"{fid}.json").exists():
            return fid
        n += 1


def _cited_evidence(findings: Path) -> set[str]:
    cited: set[str] = set()
    for path in findings.glob("F-*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        for ev in data.get("evidence") or []:
            cited.add(str(ev).replace("\\", "/"))
    return cited


def _refresh_ctf_copy(findings: Path) -> None:
    for path in findings.glob("F-*.json"):
        if _card_source(path) != "aegis-ctf":
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        expl = str(data.get("explain") or "")
        if "Ficha escrita por Aegis" not in expl and "capturada en disco" not in expl:
            continue
        ev = str((data.get("evidence") or ["flag"])[0])
        name = Path(ev).name or "flag"
        data["explain"] = _flag_explain(name, ev, path.parent.parent)
        data["summary"] = _flag_summary(name, ev)
        try:
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        except OSError:
            continue


def _looks_generic_title(title: str, explain: str = "") -> bool:
    t = (title or "").strip().lower()
    e = (explain or "").strip().lower()
    if t in {"ejecución de código / shell", "credenciales o cookies capturadas"}:
        return True
    if t.startswith(("hallazgo (", "reservado (")):
        return True
    return e.startswith("hay un script o artefacto") or e.startswith("evidencia en `")


# Stubs automáticos de enrich_live_findings: "CVE-YYYY-N: ejecución de código".
_CVE_STUB_TITLE = re.compile(r"^CVE-\d{4}-\d+:\s*ejecuci[oó]n de c[oó]digo\s*$", re.I)
_CVE_STUB_EXPLAIN = re.compile(
    r"documentado en el estado del run|hay indicios de ejecuci[oó]n de c[oó]digo",
    re.I,
)


def finding_is_draft(card: dict[str, Any]) -> bool:
    """Solo stubs genéricos Aegis pendientes de ficha. No las fichas ya escritas."""
    src = str(card.get("source") or "")
    if src not in _AEGIS_DESCRIBE:
        return False
    if str(card.get("described") or "") == "es":
        return False
    title = str(card.get("title") or "")
    explain = str(card.get("explain") or "")
    if _looks_generic_title(title, explain):
        return True
    if _CVE_STUB_TITLE.match(title.strip()):
        return True
    if _CVE_STUB_EXPLAIN.search(explain):
        return True
    return False


def _already_described(dest: Path) -> bool:
    try:
        old = json.loads(dest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(old, dict) and str(old.get("described") or "") == "es"


def _would_downgrade(dest: Path, card: dict) -> bool:
    try:
        old = json.loads(dest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(old, dict):
        return False
    if str(old.get("source") or "") == "aegis-reserved":
        return False
    old_generic = _looks_generic_title(str(old.get("title") or ""), str(old.get("explain") or ""))
    new_generic = _looks_generic_title(str(card.get("title") or ""), str(card.get("explain") or ""))
    return (not old_generic) and new_generic


def _refresh_indexed_cards(out: Path, findings: Path) -> list[str]:
    """Reescribe fichas aegis-evidence cuando ya sabemos mejor qué son."""
    updated: list[str] = []
    for path in sorted(findings.glob("F-*.json")):
        if _card_source(path) != "aegis-evidence":
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        if str(data.get("described") or "") == "es":
            continue
        if str(data.get("status") or "").lower() == "discarded":
            continue
        files = [out / str(ev) for ev in (data.get("evidence") or [])]
        files = [p for p in files if p.is_file() and p.stat().st_size > 0]
        if not files:
            continue
        card = _evidence_card(str(data.get("id") or path.stem), files, out)
        if data.get("timestamp"):
            card["timestamp"] = data["timestamp"]
        if _would_downgrade(path, card):
            continue
        if _write_finding_card(path, card):
            updated.append(card["id"])
    return updated


def ensure_evidence_findings(out: Path) -> list[str]:
    """Indexa evidencia en disco a F-xxx.json. No pisa fichas del agente."""
    findings = out / "findings"
    if not findings.is_dir():
        return []
    created: list[str] = _void_runner_generated_keys(out)
    for folder in sorted(findings.iterdir()):
        if not folder.is_dir() or not _F_DIR.match(folder.name):
            continue
        dest = findings / f"{folder.name}.json"
        files = _nonempty_files(folder)
        if _is_runner_ssh_key(files):
            continue
        if dest.is_file() and _card_source(dest) not in _AEGIS_INDEX:
            continue
        if dest.is_file() and _already_described(dest):
            continue
        if not files:
            continue
        fid = folder.name.upper()
        card = _evidence_card(fid, files, out)
        if dest.is_file() and _would_downgrade(dest, card):
            continue
        # No abras otra ficha «uid=X» si ya hay un vuln/cve que cubre ese acceso.
        cards_now = _load_cards(out)
        uid_users = re.findall(r"uid=\d+\(([^)]+)\)", _card_blob(card), flags=re.I)
        if uid_users and any(_covers_webshell(cards_now, u) for u in uid_users):
            continue
        if _write_finding_card(dest, card):
            created.append(fid)

    reserved = _empty_reserved(findings)
    cited = _cited_evidence(findings)
    cited_names = {Path(c).name.lower() for c in cited}
    cards = _load_cards(out)
    agent_rich = any(
        str(c.get("source") or "") not in _AEGIS_INDEX | {"aegis-ctf", "aegis-harvest"}
        and str(c.get("kind") or "").lower() in {"vuln", "cve", "misconfig"}
        for c in cards
    )
    for files in _loose_clusters(findings):
        if _is_runner_ssh_key(files):
            continue
        if any(_rel(out, p) in cited for p in files):
            continue
        if any(p.name.lower() in cited_names for p in files):
            continue
        if reserved:
            fid = reserved.pop(0)
        else:
            fid = _next_f_id(findings)
        dest = findings / f"{fid}.json"
        if dest.is_file() and _card_source(dest) not in _AEGIS_INDEX:
            continue
        if dest.is_file() and _already_described(dest):
            continue
        card = _evidence_card(fid, files, out)
        if any(_covers_cve(cards, cve) for cve in _cves_in(f"{card.get('title')} {card.get('explain')}")):
            continue
        if agent_rich and _looks_generic_title(str(card.get("title") or ""), str(card.get("explain") or "")):
            continue
        if _write_finding_card(dest, card):
            created.append(fid)
            cited.update(card["evidence"])
            cards.append(card)

    created.extend(_refresh_indexed_cards(out, findings))
    _refresh_ctf_copy(findings)
    return created


def _covers_cve(cards: list[dict[str, Any]], cve: str) -> bool:
    needle = cve.upper()
    return any(needle in _card_blob(c).upper() for c in cards)


def _pick_live_id(out: Path) -> str:
    findings = out / "findings"
    findings.mkdir(parents=True, exist_ok=True)
    reserved = _empty_reserved(findings)
    return reserved[0] if reserved else _next_f_id(findings)


def enrich_live_findings(out: Path) -> list[str]:
    """Durante el run: STATE.md → ficha en vivo (title/explain/proof) sin esperar al cierre."""
    state = _context_text(out)
    if len(state) < 80:
        return []
    cards = _load_cards(out)
    created: list[str] = []
    for cve in _cves_in(state):
        if _covers_cve(cards, cve):
            continue
        window = _state_window(state, cve)
        demo = bool(_DEMO_RE.search(window or state))
        if not demo:
            continue
        asset = _first_host(state)
        low = (window or state).lower()
        pdfminer = any(h in low for h in _PDFMINER_HINTS)
        if pdfminer:
            title = f"{cve}: ejecución remota pickle/CMap (pdfminer.six)"
            explain = (
                f"{cve} en pdfminer.six: el parser trata un CMap/Encoding malicioso "
                f"y deserializa pickle{' en `' + asset + '`' if asset else ''}."
            )
        else:
            title = f"{cve}: ejecución de código"
            explain = (
                f"{cve} documentado en el estado del run"
                f"{' sobre `' + asset + '`' if asset else ''}. "
                "Hay indicios de ejecución de código en el objetivo."
            )
        if demo:
            explain += " El estado indica que el vector se llegó a demostrar."
        fid = _pick_live_id(out)
        dest = out / "findings" / f"{fid}.json"
        if dest.is_file() and _card_source(dest) not in _AEGIS_INDEX:
            continue
        ev: list[str] = []
        if (out / "STATE.md").is_file():
            ev.append("STATE.md")
        card = {
            "id": fid,
            "title": title,
            "asset": asset,
            "severity": "critical",
            "status": "proven" if demo else "suspected",
            "mode_ok": ["full"],
            "explain": explain,
            "summary": title,
            "proof": _recent_argv(out, [cve, "pickle", "pdfminer", "pdf2txt"]),
            "reproduction": (explain.split(".")[0] + ".") if explain else "",
            "evidence": ev,
            "impact": (
                "Ejecución de código en el objetivo."
                if demo
                else "Vector documentado en STATE.md; falta evidencia en disco."
            ),
            "kind": "cve",
            "timestamp": _now_iso(),
            "source": "aegis-evidence",
        }
        if _write_finding_card(dest, card):
            created.append(fid)
            cards.append(card)
    return created


_RCE_ALREADY = re.compile(
    r"\b(webshell|uid=|shell\.php|rce|ejecuci[oó]n remota|ejecuci[oó]n de comandos)\b",
    re.I,
)


def _covers_webshell(cards: list[dict[str, Any]], user: str) -> bool:
    u = (user or "").lower()
    if not u:
        return False
    for card in cards:
        blob = _card_blob(card).lower()
        if u not in blob:
            continue
        kind = str(card.get("kind") or "").lower()
        if kind not in {"vuln", "cve", "misconfig"}:
            continue
        if _RCE_ALREADY.search(blob):
            return True
    return False


def enrich_live_webshell(out: Path) -> list[str]:
    """Consola con `uid=N(user)` remoto (webshell, pickle, helper TCP) → ficha."""
    try:
        from identities import console_uid_snippets
    except ImportError:
        from internal.identities import console_uid_snippets

    hits = console_uid_snippets(out)
    if not hits:
        return []
    cards = _load_cards(out)
    pending = [(u, snip) for u, snip in hits if not _covers_webshell(cards, u)]
    if not pending:
        return []
    user, snippet = pending[0]
    fid = _pick_live_id(out)
    dest = out / "findings" / f"{fid}.json"
    if dest.is_file() and _card_source(dest) not in _AEGIS_INDEX:
        return []
    slot = out / "findings" / fid
    slot.mkdir(parents=True, exist_ok=True)
    ev_rel = f"findings/{fid}/id.txt"
    ev_path = out / ev_rel
    try:
        ev_path.write_text(snippet.rstrip() + "\n", encoding="utf-8")
    except OSError:
        return []
    asset = _first_host(_context_text(out)) or _first_host(snippet)
    proof = _recent_argv(out, ["shell.php", "cmd=id", user])
    card = {
        "id": fid,
        "title": f"RCE como {user}",
        "asset": asset,
        "severity": "critical",
        "status": "proven",
        "mode_ok": ["full"],
        "explain": (
            f"Hay ejecución de código en el objetivo como `{user}` "
            f"(salida `uid=`). El agente no escribió la ficha; la consola sí tiene la prueba."
        ),
        "summary": f"RCE activa como {user}.",
        "proof": proof,
        "reproduction": proof or f"Comando remoto que devolvió uid=({user}).",
        "evidence": [ev_rel],
        "impact": f"Sesión de servicio como {user}; no es un login con contraseña.",
        "kind": "vuln",
        "timestamp": _now_iso(),
        "source": "aegis-evidence",
    }
    if not _write_finding_card(dest, card):
        return []
    return [fid]


def _has_privesc_card(cards: list[dict[str, Any]]) -> bool:
    for card in cards:
        if str(card.get("kind") or "").lower() == "flag":
            continue
        if _PRIV_HINT.search(_card_blob(card)):
            return True
    return False


def _has_root_loot(out: Path, cards: list[dict[str, Any]]) -> bool:
    loot = out / "loot" / "root.txt"
    try:
        if loot.is_file() and loot.stat().st_size > 0:
            return True
    except OSError:
        pass
    for card in cards:
        if str(card.get("kind") or "").lower() != "flag":
            continue
        blob = f"{card.get('title') or ''} {card.get('evidence') or ''}".lower()
        if "root.txt" in blob:
            return True
    return False


_PRIV_RUN = re.compile(
    r"\bsudo\s+(?:-[A-Za-z0-9-]+\s+)*/(?:usr/)?bin/"
    r"|\bsudo\s+python|\bsudo\s+-u\s+root"
    r"|olivetin|StartActionAndWait|/tmp/rootbash",
    re.I,
)


def _argv_hits_privesc(argv: str) -> bool:
    return bool(_PRIV_RUN.search(argv or "") or _SUDO_RUN.search(argv or ""))


def privesc_proof(out: Path) -> str:
    """Último comando de escalada: sudo, OliveTin o /tmp/rootbash en audit/engagement."""
    last = ""
    path = out / ".audit" / "commands.jsonl"
    if path.is_file():
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            lines = []
        for line in lines:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            argv = str(rec.get("argv") or "") if isinstance(rec, dict) else ""
            if _argv_hits_privesc(argv):
                last = " ".join(argv.split())
    if last:
        return last[:240]
    eng = out / "engagement.json"
    if not eng.is_file():
        return ""
    try:
        data = json.loads(eng.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return ""
    if not isinstance(data, dict):
        return ""
    for key in ("tried", "cmd_log", "commands"):
        rows = data.get(key) or []
        if not isinstance(rows, list):
            continue
        for rec in rows:
            if not isinstance(rec, dict):
                continue
            argv = str(rec.get("argv") or rec.get("cmd") or "")
            if _argv_hits_privesc(argv):
                last = " ".join(argv.split())
    return last[:240]


def _sudo_proof(out: Path) -> str:
    return privesc_proof(out)


def _privesc_title(proof: str) -> str:
    low = (proof or "").lower()
    if "trainer" in low:
        return "Escalada a root (sudo / trainer)"
    if "olivetin" in low or "startaction" in low:
        return "Escalada a root (OliveTin)"
    if "rootbash" in low:
        return "Escalada a root (SUID)"
    return "Escalada a root (sudo)"


def _privesc_card(fid: str, out: Path, proof: str, evidence: list[str]) -> dict:
    title = _privesc_title(proof)
    low = (proof or "").lower()
    if "olivetin" in low or "startaction" in low:
        explain = (
            "Tras comprometer al usuario, OliveTin (acción como root, argumento "
            "sin sanear) ejecutó un comando inyectado y quedó `root.txt` en disco."
        )
        repro = "Repetir la acción OliveTin del proof y leer root.txt."
    elif "rootbash" in low:
        explain = (
            "Tras comprometer al usuario, quedó un bash SUID en `/tmp/rootbash` "
            "y `root.txt` en disco."
        )
        repro = "Repetir el proof y leer root.txt con `/tmp/rootbash -p`."
    else:
        explain = (
            "Tras comprometer al usuario, el audit muestra `sudo` sobre un binario "
            "del host y quedó `root.txt` en disco."
        )
        repro = "Repetir el `sudo` del proof y leer root.txt."
    if proof:
        explain += f" Comando: `{proof}`."
    return {
        "id": fid,
        "title": title,
        "asset": _first_host(_context_text(out)),
        "severity": "high",
        "status": "proven",
        "kind": "misconfig",
        "explain": explain,
        "summary": title + ".",
        "proof": proof,
        "reproduction": repro,
        "evidence": evidence,
        "impact": "Control del host como root.",
        "mode_ok": ["full"],
        "source": "aegis-harvest",
        "timestamp": _now_iso(),
    }


def _privesc_evidence(out: Path) -> list[str]:
    evidence: list[str] = []
    cands = [out / "loot" / "root.txt"]
    dest_dir = out / "findings"
    if dest_dir.is_dir():
        cands.extend(sorted(dest_dir.glob("*/root.txt")))
    for cand in cands:
        if cand.is_file() and cand.stat().st_size > 0:
            evidence.append(_rel(out, cand))
            break
    return evidence


def ensure_privesc_finding(out: Path) -> list[str]:
    """En vivo: root.txt + sudo/OliveTin en audit y ninguna ficha de escalada → la escribe."""
    cards = _load_cards(out)
    if not _has_root_loot(out, cards):
        return []
    proof = privesc_proof(out)
    if not proof:
        return []
    if _has_privesc_card(cards):
        updated: list[str] = []
        for old in cards:
            if str(old.get("source") or "") != "aegis-harvest":
                continue
            if "escalada a root" not in str(old.get("title") or "").lower():
                continue
            dest = out / "findings" / f"{old.get('id')}.json"
            if not dest.is_file():
                continue
            card = _privesc_card(str(old.get("id")), out, proof, list(old.get("evidence") or _privesc_evidence(out)))
            if old.get("timestamp"):
                card["timestamp"] = old["timestamp"]
            if _write_finding_card(dest, card):
                updated.append(card["id"])
        return updated
    dest_dir = out / "findings"
    dest_dir.mkdir(parents=True, exist_ok=True)
    fid = _pick_live_id(out)
    dest = dest_dir / f"{fid}.json"
    if dest.is_file() and _card_source(dest) not in _AEGIS_INDEX:
        return []
    card = _privesc_card(fid, out, proof, _privesc_evidence(out))
    if _write_finding_card(dest, card):
        return [fid]
    return []
