"""Juez en vivo: el mismo modelo del run contrasta cuentas y findings con la consola."""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

DEBOUNCE_S = 12
BUSY_MAX_S = 180
ACTION_CAP = 12
STATE_NAME = ".claim-check.json"
DOC_DONE = ".doc-done"
CITE_MIN = 10

SYSTEM = """Eres el verificador de un orquestador de pentest autorizado (Aegis).
Revisas cuentas y findings que el extractor o el agente acaban de afirmar.
NO eres el atacante. NO inventes CVEs, hosts, creds ni payloads.
NO copies exploits. Cada drop/add/promote/demote/patch DEBE citar un trozo
literal del pack (consola, evidence o argv).

Cuentas:
- keep: la fila cuadra con la evidencia.
- promote: ya está el principal y hay login real ([+] user:pass o cred en disco).
  No borres y recrees: súbelo a comprometida.
- demote: comprometida sin prueba dura.
- drop: ruido (SAN DNS:, flag --rid-brute, share, métrica).
- add: SAM que YA aparece en SidTypeUser / tabla --users / [+] y no está pintado.
- NUNCA drop/demote de una cuenta con prueba dura (login con cred, RCE/webshell,
  privesc, ssh-key, flag o priv root): esa ya está demostrada.

Findings:
- keep / downgrade (proven→suspected) / drop (basura).
- patch: title/explain/status si la ficha miente (SAN ≠ login).
- add: solo con un path de evidence que exista. status suspected. Sin CVE inventado.
- NUNCA downgrade/drop de una ficha con archivo de evidencia en disco, ni la
  marques «sin confirmar»: si hay prueba (shell, euid=0, flag), corrige el texto
  hacia arriba, no la rebajes. La prueba de root puede llegar más tarde.

Responde SOLO un JSON:
{
  "accounts": [{"op":"keep|promote|demote|drop|add","principal":"...","via":"","secret":"","cite":"..."}],
  "findings": [{"op":"keep|downgrade|drop|patch|add","id":"F-001","title":"","explain":"","status":"","cite":"...","evidence":[]}]
}
Castellano en title/explain. secret vacío salvo promote. cite vacío solo en keep."""

_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


def enabled() -> bool:
    raw = (os.environ.get("AEGIS_CLAIMCHECK") or "1").strip().lower()
    return raw not in {"0", "off", "false", "no"}


def _now() -> float:
    return time.time()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_lock(out_dir: Path) -> threading.Lock:
    key = str(out_dir.resolve())
    with _LOCKS_GUARD:
        lock = _LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _LOCKS[key] = lock
        return lock


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def load_state(out_dir: Path) -> dict[str, Any]:
    st = _read_json(out_dir / STATE_NAME)
    st.setdefault("accounts", {})
    st.setdefault("findings", {})
    st.setdefault("dropped", [])
    st.setdefault("demoted", [])
    st.setdefault("promoted", {})
    st.setdefault("added", [])
    st.setdefault("watch_fp", "")
    st.setdefault("pending_since", 0.0)
    st.setdefault("busy", False)
    st.setdefault("busy_at", 0.0)
    return st


def save_state(out_dir: Path, st: dict[str, Any]) -> None:
    dest = out_dir / STATE_NAME
    tmp = dest.with_name(dest.name + ".tmp")
    tmp.write_text(json.dumps(st, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(dest)


def account_fp(row: dict[str, Any]) -> str:
    sec = str(row.get("_secret") or row.get("secret") or "")
    digest = hashlib.sha256(sec.encode("utf-8", errors="replace")).hexdigest()[:12]
    return "|".join(
        [
            str(row.get("status") or ""),
            str(row.get("via") or ""),
            "1" if sec else "0",
            digest,
        ]
    )


def finding_fp(f: dict[str, Any]) -> str:
    blob = json.dumps(
        {
            "id": str(f.get("id") or ""),
            "title": str(f.get("title") or ""),
            "status": str(f.get("status") or ""),
            "kind": str(f.get("kind") or ""),
            "explain": str(f.get("explain") or "")[:400],
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:24]


def snapshot_fp(out_dir: Path) -> str:
    from internal.identities import extract_identities
    from internal.report import load_findings

    parts: list[str] = []
    for row in extract_identities(out_dir):
        parts.append(
            "a:"
            + "|".join(
                [
                    str(row.get("principal") or "").lower(),
                    str(row.get("status") or ""),
                    str(row.get("via") or ""),
                    "1" if row.get("has_secret") or row.get("_secret") else "0",
                ]
            )
        )
    for f in load_findings(out_dir):
        if str(f.get("status") or "").lower() in {"discarded", "void"}:
            continue
        parts.append(
            "f:"
            + "|".join(
                [
                    str(f.get("id") or ""),
                    str(f.get("status") or ""),
                    str(f.get("title") or "")[:80],
                ]
            )
        )
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()[:24]


def apply_account_verdicts(out_dir: Path, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aplica drop/promote/demote/add del juez. Lo llama el extractor."""
    from internal.identities import _new, _sam_key

    st = load_state(out_dir)
    dropped = {str(x).strip().lower() for x in (st.get("dropped") or []) if str(x).strip()}
    demoted = {str(x).strip().lower() for x in (st.get("demoted") or []) if str(x).strip()}
    promoted = st.get("promoted") if isinstance(st.get("promoted"), dict) else {}
    added = st.get("added") if isinstance(st.get("added"), list) else []
    verified = st.get("accounts") if isinstance(st.get("accounts"), dict) else {}

    out: list[dict[str, Any]] = []
    for row in rows:
        key = _sam_key(str(row.get("principal") or ""))
        if not key or key in dropped:
            continue
        rec = dict(row)
        if key in demoted:
            from internal.identities import _has_hard_evidence

            # Un demote del juez no puede tapar un login ya en disco.
            if not _has_hard_evidence(rec):
                rec["status"] = "enumerated"
                rec["has_secret"] = False
                rec["_secret"] = ""
                rec["secret_type"] = ""
        promo = promoted.get(key) if isinstance(promoted.get(key), dict) else None
        if promo:
            rec["status"] = "compromised"
            secret = str(promo.get("secret") or "")
            if secret:
                rec["_secret"] = secret
                rec["has_secret"] = True
                rec["secret_type"] = str(promo.get("secret_type") or "password")
            if promo.get("via"):
                rec["via"] = str(promo.get("via"))
        rec["reviewed"] = bool(
            isinstance(verified.get(key), dict) and verified[key].get("fp") == account_fp(rec)
        )
        out.append(rec)

    have = {_sam_key(str(r.get("principal") or "")) for r in out}
    sip = ""
    for r in out:
        sip = str(r.get("ip") or r.get("host") or "")
        if sip:
            break
    if not sip:
        meta = _read_json(out_dir / "meta.json")
        tg = meta.get("targets") or []
        if isinstance(tg, list) and tg:
            first = tg[0]
            sip = str(first.get("value") if isinstance(first, dict) else first).split("/")[0]
    for item in added:
        if not isinstance(item, dict):
            continue
        name = str(item.get("principal") or "").strip()
        key = _sam_key(name)
        if not key or key in dropped or key in have:
            continue
        status = str(item.get("status") or "enumerated")
        if status not in {"compromised", "enumerated"}:
            status = "enumerated"
        extra = _new(
            principal=name,
            host=sip,
            ip=sip,
            via=str(item.get("via") or "enum"),
            priv="user",
            status=status,
            secret=str(item.get("secret") or ""),
            secret_type=str(item.get("secret_type") or ("password" if item.get("secret") else "")),
        )
        if not extra:
            continue
        extra["reviewed"] = bool(
            isinstance(verified.get(key), dict) and verified[key].get("fp") == account_fp(extra)
        )
        out.append(extra)
        have.add(key)
    return out


def mark_reviewed_findings(out_dir: Path, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    st = load_state(out_dir)
    verified = st.get("findings") if isinstance(st.get("findings"), dict) else {}
    out: list[dict[str, Any]] = []
    for raw in items:
        it = dict(raw)
        fid = str(it.get("id") or "")
        rec = verified.get(fid) if isinstance(verified.get(fid), dict) else None
        it["reviewed"] = bool(rec and rec.get("fp") == finding_fp(it))
        out.append(it)
    return out


def _enum_blob(out_dir: Path) -> str:
    from internal.identities import _console_enum_blob, _loot_plus_blob, _tried_blob

    eng = _read_json(out_dir / "engagement.json")
    return f"{_tried_blob(eng)}\n{_console_enum_blob(out_dir)}\n{_loot_plus_blob(out_dir)}"


def _allowed_add(user: str, blob: str) -> bool:
    from internal.identities import parse_nxc_plus_hits, parse_nxc_users_table, parse_sid_users

    key = user.strip().lower()
    if not key:
        return False
    names = {n.lower() for n in parse_sid_users(blob)}
    names.update(n.lower() for n in parse_nxc_users_table(blob))
    names.update(str(c.get("user") or "").lower() for c in parse_nxc_plus_hits(blob))
    return key in names


def _secret_on_disk(out_dir: Path, user: str, offered: str, blob: str, pack: str = "") -> str:
    from internal.identities import _looks_like_password, _sam_key, parse_nxc_plus_hits

    key = _sam_key(user)
    cand = (offered or "").strip()
    hay = f"{blob}\n{pack}"
    if cand and cand in hay and _looks_like_password(cand):
        return cand
    for cred in parse_nxc_plus_hits(blob):
        if _sam_key(str(cred.get("user") or "")) == key and _looks_like_password(str(cred.get("secret") or "")):
            return str(cred.get("secret") or "")
    eng = _read_json(out_dir / "engagement.json")
    for cred in eng.get("creds") or []:
        if not isinstance(cred, dict):
            continue
        secret = str(cred.get("secret") or "")
        if _sam_key(str(cred.get("user") or "")) == key and _looks_like_password(secret):
            if not cand or cand == secret or cand in hay:
                return secret
    return ""


def _cite_ok(cite: str, pack: str) -> bool:
    c = (cite or "").strip()
    if len(c) < CITE_MIN:
        return False
    return c.lower() in (pack or "").lower()


def _claim_console(out_dir: Path, needles: list[str]) -> str:
    from internal.identities import _event_tool_texts

    keys = [n.lower() for n in needles if n and len(n) >= 2]
    path = out_dir / "console.log"
    if not path.is_file():
        return ""
    lines: list[str] = []
    try:
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                rec = json.loads(raw[raw.find("{") :] if "{" in raw else raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(rec, dict):
                continue
            for text in _event_tool_texts(rec):
                for ln in text.splitlines():
                    low = ln.lower()
                    if (
                        "sidtypeuser" in low
                        or "last pw set" in low
                        or "-username-" in low
                        or "[+]" in ln
                        or any(k in low for k in keys)
                    ):
                        lines.append(ln[:240])
            if len(lines) > 80:
                break
    except OSError:
        return ""
    return "\n".join(lines[:80])


def _evidence_heads(out_dir: Path, findings: list[dict[str, Any]]) -> str:
    chunks: list[str] = []
    n = 0
    for f in findings:
        ev = f.get("evidence") or []
        if isinstance(ev, str):
            ev = [ev]
        for raw in ev[:4]:
            rel = str(raw or "").lstrip("/")
            if not rel or ".." in rel.split("/"):
                continue
            path = out_dir / rel
            if not path.is_file():
                alt = out_dir / "evidence" / Path(rel).name
                path = alt if alt.is_file() else path
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")[:1500]
            except OSError:
                continue
            chunks.append(f"## {rel}\n{text}")
            n += 1
            if n >= 6:
                return "\n".join(chunks)
    return "\n".join(chunks)


def _pending(out_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    from internal.identities import extract_identities, _sam_key
    from internal.report import load_findings

    st = load_state(out_dir)
    vacct = st.get("accounts") if isinstance(st.get("accounts"), dict) else {}
    vfind = st.get("findings") if isinstance(st.get("findings"), dict) else {}
    accounts: list[dict[str, Any]] = []
    for row in extract_identities(out_dir):
        key = _sam_key(str(row.get("principal") or ""))
        rec = vacct.get(key) if isinstance(vacct.get(key), dict) else None
        if rec and rec.get("fp") == account_fp(row):
            continue
        accounts.append(row)
    findings: list[dict[str, Any]] = []
    for f in load_findings(out_dir):
        if str(f.get("status") or "").lower() in {"discarded", "void"}:
            continue
        fid = str(f.get("id") or "")
        rec = vfind.get(fid) if isinstance(vfind.get(fid), dict) else None
        if rec and rec.get("fp") == finding_fp(f):
            continue
        findings.append(f)
    return accounts, findings


def build_pack(
    out_dir: Path,
) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]], str]:
    from internal.identities import _tried_blob

    accounts, findings = _pending(out_dir)
    needles = [str(r.get("principal") or "") for r in accounts]
    needles.extend(str(f.get("id") or "") for f in findings)
    console = _claim_console(out_dir, needles)
    ev = _evidence_heads(out_dir, findings)
    tried = _tried_blob(_read_json(out_dir / "engagement.json"))[:4000]
    body = {
        "accounts": [
            {
                "principal": str(r.get("principal") or ""),
                "status": str(r.get("status") or ""),
                "via": str(r.get("via") or ""),
                "has_secret": bool(r.get("has_secret") or r.get("_secret")),
                "finding": str(r.get("finding") or ""),
            }
            for r in accounts
        ],
        "findings": [
            {
                "id": str(f.get("id") or ""),
                "title": str(f.get("title") or ""),
                "status": str(f.get("status") or ""),
                "kind": str(f.get("kind") or ""),
                "asset": str(f.get("asset") or ""),
                "explain": str(f.get("explain") or f.get("summary") or "")[:500],
                "evidence": f.get("evidence") or [],
            }
            for f in findings
        ],
        "console": console[:8000],
        "tried": tried,
        "evidence": ev[:8000],
    }
    hay = "\n".join([console, tried, ev])
    return json.dumps(body, ensure_ascii=False, indent=2), accounts, findings, hay


def parse_payload(text: str) -> dict[str, Any]:
    raw = (text or "").strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[-1]
        if raw.endswith("```"):
            raw = raw[: raw.rfind("```")]
        raw = raw.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*\})\s*```", raw, re.S)
    if fence:
        raw = fence.group(1)
    else:
        start = raw.find("{")
        end = raw.rfind("}")
        if start >= 0 and end > start:
            raw = raw[start : end + 1]
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {"accounts": [], "findings": []}
    if not isinstance(data, dict):
        return {"accounts": [], "findings": []}
    accts = data.get("accounts")
    finds = data.get("findings")
    return {
        "accounts": accts if isinstance(accts, list) else [],
        "findings": finds if isinstance(finds, list) else [],
    }


def _emit(out_dir: Path, action: str, what: str) -> None:
    from internal.conscience import _append_console

    rec = {
        "type": "aegis_claimcheck",
        "action": action,
        "text": f"claimcheck: {action} {what}".strip(),
        "timestamp": _iso(_now()),
    }
    _append_console(out_dir, f"{rec['timestamp']} {json.dumps(rec, ensure_ascii=False)}\n")


def _next_fid(out_dir: Path) -> str:
    taken: set[str] = set()
    d = out_dir / "findings"
    if d.is_dir():
        for path in d.glob("F-*.json"):
            taken.add(path.stem.upper())
    n = 1
    while f"F-{n:03d}" in taken:
        n += 1
    return f"F-{n:03d}"


def _safe_evidence_path(out_dir: Path, raw: str) -> str:
    rel = str(raw or "").strip().lstrip("/")
    if not rel or ".." in rel.split("/"):
        return ""
    path = (out_dir / rel).resolve()
    try:
        path.relative_to(out_dir.resolve())
    except ValueError:
        return ""
    return rel if path.is_file() else ""


def _apply_account_ops(
    out_dir: Path,
    ops: list[dict[str, Any]],
    pack: str,
    blob: str,
) -> list[str]:
    from internal.engage import add_access, add_cred, add_users, locked_state
    from internal.identities import _has_hard_evidence, _principal_ok, _sam_key, extract_identities

    # Prueba dura ya en disco (password real, priv root, RCE/webshell, ssh-key,
    # flag, login web con finding). El juez puede corregir ruido, pero NO puede
    # tirar ni degradar una cuenta genuinamente comprometida: en CTF la prueba
    # (p.ej. el root) llega más tarde y un demote a destiempo la borraba.
    rows_by_key: dict[str, dict[str, Any]] = {}
    for _r in extract_identities(out_dir):
        rows_by_key[_sam_key(str(_r.get("principal") or ""))] = _r

    done: list[str] = []
    st = load_state(out_dir)
    dropped = {str(x).strip().lower() for x in (st.get("dropped") or [])}
    demoted = {str(x).strip().lower() for x in (st.get("demoted") or [])}
    promoted = dict(st.get("promoted") or {})
    added = [x for x in (st.get("added") or []) if isinstance(x, dict)]
    verified = dict(st.get("accounts") or {})
    n_mut = 0

    def persist_lists() -> None:
        st["dropped"] = sorted(dropped)
        st["demoted"] = sorted(demoted)
        st["promoted"] = promoted
        st["added"] = added
        st["accounts"] = verified

    host = ""
    meta = _read_json(out_dir / "meta.json")
    tg = meta.get("targets") or []
    if isinstance(tg, list) and tg:
        first = tg[0]
        host = str(first.get("value") if isinstance(first, dict) else first).split("/")[0]

    with locked_state(out_dir / "engagement.json", sidecars=False) as eng:
        if not host:
            tgt = eng.get("targets") or []
            if isinstance(tgt, list) and tgt:
                host = str(tgt[0]).split("/")[0]
        for raw in ops:
            if n_mut >= ACTION_CAP:
                break
            if not isinstance(raw, dict):
                continue
            op = str(raw.get("op") or "").strip().lower()
            principal = str(raw.get("principal") or "").strip()
            if not principal or not _principal_ok(principal):
                continue
            key = _sam_key(principal)
            if not key:
                continue
            cite = str(raw.get("cite") or "")
            if op == "keep":
                continue
            if not _cite_ok(cite, pack):
                continue
            # No degradar (drop/demote) una cuenta con prueba dura de compromiso.
            if op in {"drop", "demote"}:
                hard_row = rows_by_key.get(key)
                if hard_row and _has_hard_evidence(hard_row):
                    verified[key] = {"fp": account_fp(hard_row), "verdict": "keep"}
                    done.append(f"keep {principal} (prueba dura)")
                    continue
            if op == "drop":
                dropped.add(key)
                demoted.discard(key)
                promoted.pop(key, None)
                added[:] = [a for a in added if _sam_key(str(a.get("principal") or "")) != key]
                users = [u for u in (eng.get("users") or []) if _sam_key(str(u)) != key]
                eng["users"] = users
                eng["creds"] = [
                    c
                    for c in (eng.get("creds") or [])
                    if isinstance(c, dict) and _sam_key(str(c.get("user") or "")) != key
                ]
                eng["access"] = [
                    a
                    for a in (eng.get("access") or [])
                    if isinstance(a, dict) and _sam_key(str(a.get("user") or "")) != key
                ]
                verified[key] = {"fp": "dropped", "verdict": "drop"}
                n_mut += 1
                done.append(f"drop {principal}")
                continue
            if op == "demote":
                held = _secret_on_disk(out_dir, principal, str(raw.get("secret") or ""), blob, pack)
                if held:
                    continue
                demoted.add(key)
                promoted.pop(key, None)
                dropped.discard(key)
                eng["creds"] = [
                    c
                    for c in (eng.get("creds") or [])
                    if isinstance(c, dict) and _sam_key(str(c.get("user") or "")) != key
                ]
                eng["access"] = [
                    a
                    for a in (eng.get("access") or [])
                    if isinstance(a, dict) and _sam_key(str(a.get("user") or "")) != key
                ]
                add_users(eng, [principal.split("\\")[-1].split("@")[0]])
                verified[key] = {
                    "fp": account_fp({"status": "enumerated", "via": str(raw.get("via") or "enum")}),
                    "verdict": "demote",
                }
                n_mut += 1
                done.append(f"demote {principal}")
                continue
            if op == "promote":
                secret = _secret_on_disk(out_dir, principal, str(raw.get("secret") or ""), blob, pack)
                if not secret:
                    continue
                via = str(raw.get("via") or "smb")
                if via in {"", "enum", "unknown"}:
                    via = "smb"
                dropped.discard(key)
                demoted.discard(key)
                promoted[key] = {"via": via, "secret": secret, "secret_type": "password"}
                add_users(eng, [principal.split("\\")[-1].split("@")[0]])
                add_cred(eng, principal, secret, "password", host or via, emit=False)
                add_access(eng, host or "target", principal, via=via, priv="user", emit=False)
                verified[key] = {
                    "fp": account_fp(
                        {"status": "compromised", "via": via, "_secret": secret}
                    ),
                    "verdict": "promote",
                }
                n_mut += 1
                done.append(f"promote {principal}")
                continue
            if op == "add":
                if not _allowed_add(principal.split("\\")[-1].split("@")[0], blob):
                    continue
                dropped.discard(key)
                status = "enumerated"
                secret = _secret_on_disk(out_dir, principal, str(raw.get("secret") or ""), blob, pack)
                via = str(raw.get("via") or "enum")
                if secret:
                    status = "compromised"
                    if via in {"", "enum", "unknown"}:
                        via = "smb"
                    promoted[key] = {"via": via, "secret": secret, "secret_type": "password"}
                    add_cred(eng, principal, secret, "password", host or via, emit=False)
                    add_access(eng, host or "target", principal, via=via, priv="user", emit=False)
                add_users(eng, [principal.split("\\")[-1].split("@")[0]])
                if not any(_sam_key(str(a.get("principal") or "")) == key for a in added):
                    added.append(
                        {
                            "principal": principal.split("\\")[-1].split("@")[0],
                            "status": status,
                            "via": via,
                            "secret": secret,
                        }
                    )
                verified[key] = {
                    "fp": account_fp({"status": status, "via": via, "_secret": secret}),
                    "verdict": "add",
                }
                n_mut += 1
                done.append(f"add {principal}")

    persist_lists()
    save_state(out_dir, st)
    return done


def _mark_account_keeps(out_dir: Path, ops: list[dict[str, Any]], rows: list[dict[str, Any]]) -> list[str]:
    from internal.identities import _sam_key

    st = load_state(out_dir)
    verified = dict(st.get("accounts") or {})
    by_key = {_sam_key(str(r.get("principal") or "")): r for r in rows}
    done: list[str] = []
    for raw in ops:
        if not isinstance(raw, dict):
            continue
        if str(raw.get("op") or "").strip().lower() != "keep":
            continue
        key = _sam_key(str(raw.get("principal") or ""))
        row = by_key.get(key)
        if not row:
            continue
        verified[key] = {"fp": account_fp(row), "verdict": "keep"}
        done.append(f"keep {row.get('principal')}")
    st["accounts"] = verified
    save_state(out_dir, st)
    return done


def _apply_finding_ops(
    out_dir: Path,
    ops: list[dict[str, Any]],
    pack: str,
) -> list[str]:
    from internal.report import load_findings
    from internal.report.harvest import _finding_has_disk_evidence

    st = load_state(out_dir)
    verified = dict(st.get("findings") or {})
    existing = {str(f.get("id") or ""): f for f in load_findings(out_dir)}
    dest = out_dir / "findings"
    dest.mkdir(parents=True, exist_ok=True)
    done: list[str] = []
    n_mut = 0

    def write_card(fid: str, data: dict[str, Any]) -> None:
        path = dest / f"{fid}.json"
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    for raw in ops:
        if n_mut >= ACTION_CAP:
            break
        if not isinstance(raw, dict):
            continue
        op = str(raw.get("op") or "").strip().lower()
        fid = str(raw.get("id") or "").strip()
        cite = str(raw.get("cite") or "")
        if op == "add":
            if not _cite_ok(cite, pack):
                continue
            ev_in = raw.get("evidence") or []
            if isinstance(ev_in, str):
                ev_in = [ev_in]
            evidence = [p for p in (_safe_evidence_path(out_dir, str(x)) for x in ev_in) if p]
            if not evidence:
                continue
            title = str(raw.get("title") or "").strip()
            if not title:
                continue
            new_id = _next_fid(out_dir)
            rec = {
                "id": new_id,
                "title": title[:200],
                "explain": str(raw.get("explain") or "")[:800],
                "status": "suspected",
                "severity": "info",
                "kind": "info",
                "evidence": evidence,
                "source": "aegis-claimcheck",
            }
            write_card(new_id, rec)
            verified[new_id] = {"fp": finding_fp(rec), "verdict": "add"}
            n_mut += 1
            done.append(f"add {new_id}")
            continue
        card = existing.get(fid)
        if not card:
            continue
        if str(card.get("source") or "") == "aegis-reserved":
            continue
        if str(card.get("kind") or "").lower() == "flag" and op != "keep":
            continue
        if op == "keep":
            verified[fid] = {"fp": finding_fp(card), "verdict": "keep"}
            done.append(f"keep {fid}")
            continue
        if not _cite_ok(cite, pack):
            continue
        # Prueba dura en disco (archivo de evidence o carpeta findings/F-xxx con
        # contenido). El juez NO puede tirar ni degradar una ficha demostrada:
        # en CTF la evidencia de root llega tarde y un downgrade a destiempo
        # dejaba la ficha «proven» con texto de «suspected» (incoherente).
        has_ev = _finding_has_disk_evidence(out_dir, card)
        data = dict(card)
        if op == "drop":
            if has_ev:
                verified[fid] = {"fp": finding_fp(card), "verdict": "keep"}
                done.append(f"keep {fid} (evidencia)")
                continue
            data["status"] = "discarded"
            write_card(fid, data)
            verified[fid] = {"fp": finding_fp(data), "verdict": "drop"}
            n_mut += 1
            done.append(f"drop {fid}")
            continue
        if op == "downgrade":
            if has_ev:
                verified[fid] = {"fp": finding_fp(card), "verdict": "keep"}
                done.append(f"keep {fid} (evidencia)")
                continue
            data["status"] = "suspected"
            write_card(fid, data)
            verified[fid] = {"fp": finding_fp(data), "verdict": "downgrade"}
            n_mut += 1
            done.append(f"downgrade {fid}")
            continue
        if op == "patch":
            if raw.get("title"):
                data["title"] = str(raw.get("title") or "")[:200]
            if raw.get("explain"):
                data["explain"] = str(raw.get("explain") or "")[:800]
            status = str(raw.get("status") or "").strip().lower()
            # Con evidencia en disco no se acepta bajar el estado (a suspected):
            # el juez puede reescribir texto y confirmar, no rebajar lo demostrado.
            allowed = {"proven", "confirmed"} if has_ev else {"proven", "suspected", "confirmed"}
            if status in allowed:
                data["status"] = status
            write_card(fid, data)
            verified[fid] = {"fp": finding_fp(data), "verdict": "patch"}
            n_mut += 1
            done.append(f"patch {fid}")
    st["findings"] = verified
    save_state(out_dir, st)
    return done


def run_shot(
    out_dir: Path,
    *,
    llm: Callable[[str], str] | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    """Un pase: pack de no verificados → modelo → apply."""
    out_dir = Path(out_dir)
    result: dict[str, Any] = {"ran": False, "actions": []}
    if not enabled():
        return result
    accounts, findings = _pending(out_dir)
    if not accounts and not findings:
        st = load_state(out_dir)
        st["pending_since"] = 0.0
        st["watch_fp"] = snapshot_fp(out_dir)
        st["busy"] = False
        save_state(out_dir, st)
        return result
    pack, pend_acct, pend_find, hay = build_pack(out_dir)
    try:
        if not callable(llm):
            from internal.conscience import call_llm_text, has_backend

            if not has_backend(out_dir):
                return result
            raw = call_llm_text(SYSTEM, "DATOS:\n" + pack, out_dir)
        else:
            raw = llm(pack)
        if not raw:
            st = load_state(out_dir)
            st["pending_since"] = (now if now is not None else _now()) + DEBOUNCE_S
            save_state(out_dir, st)
            return result
        payload = parse_payload(raw)
        blob = _enum_blob(out_dir)
        actions: list[str] = []
        actions.extend(_mark_account_keeps(out_dir, payload["accounts"], pend_acct))
        actions.extend(_apply_account_ops(out_dir, payload["accounts"], hay, blob))
        actions.extend(_apply_finding_ops(out_dir, payload["findings"], hay))
        for line in actions:
            if not line.startswith("keep "):
                op, _, what = line.partition(" ")
                _emit(out_dir, op, what)
        st = load_state(out_dir)
        st["watch_fp"] = snapshot_fp(out_dir)
        st["pending_since"] = 0.0
        save_state(out_dir, st)
        result.update(ran=True, actions=actions)
        return result
    finally:
        st = load_state(out_dir)
        if st.get("busy"):
            st["busy"] = False
            save_state(out_dir, st)


def poll(
    out_dir: Path,
    *,
    now: float | None = None,
    llm: Callable[[str], str] | None = None,
    sync: bool = False,
) -> dict[str, Any]:
    """Watcher: si cambió el conjunto, espera DEBOUNCE_S y dispara un shot."""
    out_dir = Path(out_dir)
    result: dict[str, Any] = {"ran": False, "action": "skip"}
    if not enabled():
        return result
    if (out_dir / DOC_DONE).is_file():
        return result
    now = _now() if now is None else now
    with _run_lock(out_dir):
        st = load_state(out_dir)
        cur = snapshot_fp(out_dir)
        if cur != str(st.get("watch_fp") or ""):
            st["watch_fp"] = cur
            st["pending_since"] = now
            save_state(out_dir, st)
        if st.get("busy"):
            busy_at = float(st.get("busy_at") or 0)
            if busy_at and now - busy_at < BUSY_MAX_S:
                result["action"] = "busy"
                return result
            st["busy"] = False
        accounts, findings = _pending(out_dir)
        if not accounts and not findings:
            if st.get("pending_since"):
                st["pending_since"] = 0.0
                save_state(out_dir, st)
            result["action"] = "idle"
            return result
        since = float(st.get("pending_since") or 0)
        if since <= 0:
            st["pending_since"] = now
            save_state(out_dir, st)
            result["action"] = "wait"
            return result
        if now - since < DEBOUNCE_S:
            result["action"] = "wait"
            return result
        st["busy"] = True
        st["busy_at"] = now
        save_state(out_dir, st)

    if sync or callable(llm):
        return run_shot(out_dir, llm=llm, now=now)

    def _bg() -> None:
        try:
            run_shot(out_dir, llm=None, now=None)
        except Exception:
            st2 = load_state(out_dir)
            st2["busy"] = False
            save_state(out_dir, st2)

    threading.Thread(target=_bg, name="aegis-claimcheck", daemon=True).start()
    result["action"] = "started"
    return result
