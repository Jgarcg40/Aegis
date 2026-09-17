"""Vistas de misión: cadena, CTF, cuaderno, grafo. Lee disco, no inventa."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from internal.engage import flag_kinds, next_move
from internal.flagspec import load_contract, progress
from internal.identities import overlay_graph, public_identities
from internal.report import load_findings


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _parse_ts(raw: Any) -> float:
    if raw is None or raw == "":
        return 0.0
    if isinstance(raw, (int, float)):
        n = float(raw)
        return n / 1000.0 if n > 1e12 else n
    s = str(raw).strip()
    if s.replace(".", "", 1).isdigit():
        return _parse_ts(float(s))
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s).timestamp()
    except ValueError:
        return 0.0


def _iso(ts: float) -> str:
    if not ts:
        return ""
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_events(root: Path) -> list[dict[str, Any]]:
    path = root / "events.jsonl"
    if not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def _eng(root: Path) -> dict[str, Any]:
    return _read_json(root / "engagement.json")


def _disk_flag_map(root: Path) -> dict[str, str]:
    """Valor real de user.txt/root.txt. `proof.txt` solo cuenta en loot/;
    en findings/F-xxx/proof.txt es evidencia de un hallazgo, no la flag de root."""
    names = {
        "user.txt": "user",
        "local.txt": "user",
        "root.txt": "root",
    }
    out: dict[str, str] = {}
    loot = root / "loot"
    for folder in (loot, root / "findings"):
        if not folder.is_dir():
            continue
        for path in folder.rglob("*"):
            if not path.is_file() or path.stat().st_size <= 0:
                continue
            name = path.name.lower()
            kind = names.get(name)
            if not kind and name == "proof.txt":
                try:
                    path.resolve().relative_to(loot.resolve())
                except (ValueError, OSError):
                    kind = None
                else:
                    kind = "root"
            if not kind or kind in out:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            line = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
            if line:
                out[kind] = line[:160]
    return out


def _flag_bucket(kind: str) -> str:
    k = (kind or "").lower()
    if "root" in k or k in {"admin", "system", "proof"}:
        return "root"
    return "user"


def _best_flag(eng: dict[str, Any], kind: str, prefer: str = "") -> dict[str, Any] | None:
    want = "root" if kind == "root" else "user"
    prefer = (prefer or "").strip()
    cands: list[dict[str, Any]] = []
    for f in eng.get("flags") or []:
        if not isinstance(f, dict):
            continue
        if _flag_bucket(str(f.get("kind") or "")) != want:
            continue
        if not str(f.get("value") or "").strip():
            continue
        cands.append(f)
    if prefer:
        for f in cands:
            if str(f.get("value") or "").strip() == prefer:
                return f
        return {"kind": want, "value": prefer, "path": "", "ts": str((cands[-1] if cands else {}).get("ts") or "")}
    return cands[-1] if cands else None


def _host_key(raw: str) -> str:
    s = (raw or "").strip().lower()
    if s.startswith("host:"):
        s = s[5:]
    if ":" in s and s.count(":") == 1:
        host, _, port = s.rpartition(":")
        if port.isdigit():
            s = host
    return s


def _hosts_of_flag(findings: list[dict[str, Any]], value: str, kind: str) -> set[str]:
    fid = _finding_for_flag(findings, value, kind)
    hosts: set[str] = set()
    slot = "root.txt" if kind == "root" else "user.txt"
    for f in findings:
        if fid and str(f.get("id") or "") != fid:
            continue
        blob = " ".join(
            str(f.get(k) or "") for k in ("id", "title", "summary", "explain", "kind")
        ).lower()
        if not fid and slot not in blob:
            continue
        h = _host_key(str(f.get("asset") or ""))
        if h:
            hosts.add(h)
    return hosts


def _row_hosts(row: dict[str, Any]) -> set[str]:
    return {x for x in (_host_key(str(row.get("ip") or "")), _host_key(str(row.get("host") or ""))) if x}


def _is_os_root(row: dict[str, Any]) -> bool:
    """Root de SO (uid=0 / SYSTEM / vía privesc). Admin web no cuenta."""
    if not isinstance(row, dict):
        return False
    priv = str(row.get("priv") or "").lower()
    via = str(row.get("via") or "").lower()
    principal = str(row.get("principal") or row.get("user") or "").lower()
    if via == "privesc" or priv == "root":
        return True
    if principal == "root" and via not in {"enum", "unknown", "web"}:
        return True
    if priv == "system" and via not in {"web", "enum", "unknown"}:
        return True
    return False


def _os_root_on_hosts(
    identities: list[dict[str, Any]],
    access: list[Any],
    hosts: set[str],
) -> dict[str, Any] | None:
    """CTF: root de SO en el host de user.txt. Sin hosts no cuenta (pivot ≠ contrato)."""
    if not hosts:
        return None
    for row in identities:
        if _is_os_root(row) and (_row_hosts(row) & hosts):
            return row
    for raw in access:
        if isinstance(raw, dict) and _is_os_root(raw) and (_row_hosts(raw) & hosts):
            return raw
    return None


def _os_root_rows(
    identities: list[dict[str, Any]],
    access: list[Any],
) -> list[dict[str, Any]]:
    """Un root de SO por principal×host. El pivot no se fusiona en una sola fila."""
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    pool: list[dict[str, Any]] = [r for r in identities if isinstance(r, dict)]
    pool.extend(a for a in access if isinstance(a, dict))
    for raw in pool:
        if not _is_os_root(raw):
            continue
        principal = str(raw.get("principal") or raw.get("user") or "root").strip() or "root"
        hosts = _row_hosts(raw) or {""}
        for h in sorted(hosts):
            key = (principal.lower(), h)
            if key in seen:
                continue
            seen.add(key)
            rec = dict(raw)
            rec["principal"] = principal
            if h and not rec.get("host"):
                rec["host"] = h
            out.append(rec)
    return out


def _os_root_detail(rows: list[dict[str, Any]]) -> str:
    labels: list[str] = []
    for r in rows[:5]:
        host = next(iter(_row_hosts(r)), "") or str(r.get("host") or "")
        name = str(r.get("principal") or r.get("user") or "root")
        labels.append(f"{name}@{host}" if host else name)
    extra = len(rows) - 5
    if extra > 0:
        labels.append(f"+{extra}")
    return " · ".join(labels)


def _finding_for_flag(findings: list[dict[str, Any]], value: str, kind: str) -> str:
    needle = (value or "").strip().lower()
    kind_l = kind.lower()
    slot = "root.txt" if kind_l == "root" else "user.txt"

    def blob_of(f: dict[str, Any]) -> str:
        return " ".join(
            str(f.get(k) or "")
            for k in ("id", "title", "summary", "explain", "kind", "asset", "impact")
        ).lower()

    if needle:
        for f in findings:
            if needle in blob_of(f):
                return str(f.get("id") or "")
    for f in findings:
        if slot in blob_of(f):
            return str(f.get("id") or "")
    return ""


def ctf_progress(root: Path) -> dict[str, Any] | None:
    """Progreso del contrato CTF. None si el run no es CTF."""
    contract = load_contract(root)
    if not contract.get("enabled"):
        return None
    eng = _eng(root)
    findings = load_findings(root)
    slots_out: list[dict[str, Any]] = []
    hits = progress(root, contract)
    slots = contract.get("slots") or []
    kinds = flag_kinds(eng)
    disk = _disk_flag_map(root)
    for i, slot in enumerate(slots):
        if not isinstance(slot, dict):
            continue
        match = str(slot.get("match") or "")
        style = str(slot.get("style") or "name")
        found = bool(i < len(hits) and hits[i])
        kind = "root" if any(x in match.lower() for x in ("root", "proof", "admin")) else "user"
        rec = _best_flag(eng, kind, disk.get(kind, ""))
        value = str((rec or {}).get("value") or "")
        ts = str((rec or {}).get("ts") or "")
        path = str((rec or {}).get("path") or "")
        fid = _finding_for_flag(findings, value, kind)
        if not found and kind in kinds:
            found = True
        slots_out.append(
            {
                "match": match,
                "style": style,
                "kind": kind,
                "found": found,
                "value": value,
                "ts": ts,
                "path": path,
                "finding": fid,
            }
        )
    got = sum(1 for s in slots_out if s["found"])
    return {
        "total": len(slots_out),
        "got": got,
        "complete": bool(slots_out) and got == len(slots_out),
        "slots": slots_out,
    }


def notebook_view(root: Path, *, ctf: bool | None = None) -> dict[str, Any]:
    eng = _eng(root)
    if ctf is None:
        ctf = bool(load_contract(root).get("enabled"))
    hyps = []
    for h in eng.get("hypotheses") or []:
        if not isinstance(h, dict):
            continue
        hyps.append(
            {
                "text": str(h.get("text") or ""),
                "status": str(h.get("status") or "viva"),
                "fails": int(h.get("fails") or 0),
                "ts": str(h.get("ts") or ""),
            }
        )
    tried = []
    for t in (eng.get("tried") or [])[-24:]:
        if not isinstance(t, dict):
            continue
        tried.append(
            {
                "argv": str(t.get("argv") or t.get("cmd") or "")[:240],
                "kind": str(t.get("kind") or ""),
                "ts": str(t.get("ts") or ""),
            }
        )
    loops = []
    for lp in (eng.get("loops") or [])[-8:]:
        if isinstance(lp, dict):
            loops.append(
                {
                    "cls": str(lp.get("cls") or ""),
                    "count": int(lp.get("count") or 0),
                    "ts": str(lp.get("ts") or ""),
                }
            )
    creds = []
    for c in eng.get("creds") or []:
        if not isinstance(c, dict):
            continue
        creds.append(
            {
                "user": str(c.get("user") or ""),
                "type": str(c.get("type") or ""),
                "where": str(c.get("where") or ""),
                "ts": str(c.get("ts") or ""),
            }
        )
    access = []
    for a in eng.get("access") or []:
        if isinstance(a, dict):
            access.append(
                {
                    "host": str(a.get("host") or ""),
                    "user": str(a.get("user") or ""),
                    "via": str(a.get("via") or ""),
                    "priv": str(a.get("priv") or ""),
                    "ts": str(a.get("ts") or ""),
                }
            )
    flags: list[dict[str, Any]] = []
    if ctf:
        prefer_vals = set(_disk_flag_map(root).values())
        for f in eng.get("flags") or []:
            if not isinstance(f, dict):
                continue
            val = str(f.get("value") or "").strip()
            if prefer_vals and val not in prefer_vals:
                continue
            flags.append(
                {
                    "kind": str(f.get("kind") or ""),
                    "value": val,
                    "path": str(f.get("path") or ""),
                    "ts": str(f.get("ts") or ""),
                }
            )
    move = ""
    try:
        move = next_move(eng, out=root, ctf=ctf)
    except Exception:
        move = ""
    graph = eng.get("graph") if isinstance(eng.get("graph"), dict) else {"nodes": [], "edges": [], "current": ""}
    identities = public_identities(root, eng=eng, secrets=True)
    return {
        "phase": str(eng.get("phase") or ""),
        "layer": str(eng.get("layer") or ""),
        "next_move": move,
        "hypotheses": hyps,
        "tried": tried,
        "loops": loops,
        "creds": creds,
        "access": access,
        "identities": identities,
        "flags": flags,
        "graph": overlay_graph(
            {
                "nodes": list(graph.get("nodes") or []),
                "edges": list(graph.get("edges") or []),
                "current": str(graph.get("current") or ""),
            },
            identities,
        ),
        "updated": str(eng.get("updated") or ""),
    }


def _cmd_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for ev in events:
        if ev.get("type") != "command":
            continue
        p = ev.get("payload") or {}
        argv = p.get("argv") if isinstance(p, dict) else ""
        if isinstance(argv, list):
            argv = " ".join(str(x) for x in argv)
        argv = str(argv or "").strip()
        if not argv:
            continue
        out.append({"ts": ev.get("ts") or "", "argv": argv[:300], "epoch": _parse_ts(ev.get("ts"))})
    return out


def nearest_command(
    commands: list[dict[str, Any]],
    ts: Any,
    *,
    needle: str = "",
) -> dict[str, Any] | None:
    epoch = _parse_ts(ts)
    want = (needle or "").lower()
    best: dict[str, Any] | None = None
    best_d = 1e18
    for c in commands:
        if want and want not in str(c.get("argv") or "").lower():
            if best is not None:
                continue
        d = abs(float(c.get("epoch") or 0) - epoch) if epoch else 1e17
        if d < best_d:
            best_d = d
            best = c
    if best is None:
        return None
    if epoch and best_d > 45 * 60:
        return None
    return {"ts": best.get("ts") or "", "argv": best.get("argv") or ""}


def attach_finding_commands(root: Path, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cmds = _cmd_events(_load_events(root))
    out: list[dict[str, Any]] = []
    for raw in findings:
        it = dict(raw)
        proof = str(it.get("proof") or it.get("reproduction") or "").strip()
        if proof:
            it["command"] = {"argv": proof.splitlines()[0][:300], "ts": it.get("timestamp") or ""}
        else:
            hit = nearest_command(cmds, it.get("timestamp"), needle=str(it.get("asset") or ""))
            if hit:
                it["command"] = hit
        out.append(it)
    return out


def _net_timeline(
    root: Path,
    meta: dict[str, Any],
    eng: dict[str, Any],
    findings: list[dict[str, Any]],
    start: float,
) -> list[dict[str, Any]]:
    from internal.engage import exploit_mgmt_on, net_coverage

    state = dict(eng) if isinstance(eng, dict) else {}
    if not state.get("targets"):
        state["targets"] = [
            (t.get("value") if isinstance(t, dict) else t)
            for t in (meta.get("targets") or [])
        ]
    state.setdefault("mode", "net")
    if meta.get("exploit_mgmt") or _read_json(root / "brief.json").get("exploit_mgmt"):
        state["exploit_mgmt"] = True
    cov = net_coverage(state, out=root)
    hosts = [h for h in (state.get("hosts") or []) if isinstance(h, dict) and h.get("ip")]

    def _hit(
        *needles: str,
        prefer: tuple[str, ...] = (),
        reject: tuple[str, ...] = (),
    ) -> dict[str, Any] | None:
        try:
            from internal.flagspec import finding_is_draft
        except Exception:
            finding_is_draft = lambda _f: False  # noqa: E731
        best: dict[str, Any] | None = None
        best_score = -1
        for f in findings:
            if not isinstance(f, dict) or finding_is_draft(f):
                continue
            title = str(f.get("title") or "").lower()
            blob = " ".join(
                str(f.get(k) or "") for k in ("title", "explain", "summary", "asset", "kind")
            ).lower()
            if not any(n in blob for n in needles):
                continue
            if reject and any(r in title for r in reject):
                continue
            score = 1
            if any(n in title for n in needles):
                score += 10
            if prefer:
                score += 20 * sum(1 for p in prefer if p in title)
            if score > best_score:
                best = f
                best_score = score
        return best

    steps: list[dict[str, Any]] = []

    def add(sid: str, label: str, ok: bool, *, detail: str = "", finding: str = "", ts: str = "") -> None:
        steps.append(
            {
                "id": sid,
                "label": label,
                "ts": ts or "",
                "ok": ok,
                "detail": detail,
                "finding": finding,
            }
        )

    gw_f = _hit(
        "firewall", "unifi", "ubiquiti", "gateway", "fortigate", "mikrotik",
        prefer=("unifi", "ubiquiti", "mgmt", "gateway"),
        reject=("fuga", "túnel", "tunel", "segment", "reachab", "inter-segmento"),
    )
    dns_f = _hit("dns", "axfr", "resolv", "bind", "dnsmasq", prefer=("dns", "dnsmasq", "axfr"))
    seg_f = _hit(
        "segment", "alcanza", "reachab", "vlan", "aisl", "dual-stack", "bypass",
        prefer=("dual-stack", "bypass", "segment", "aisl"),
        reject=("túnel", "tunel", "vpn"),
    )
    leak_f = _hit(
        "fuga", "ruta", "ipv6", "túnel", "tunel", "docker", "prefijo",
        prefer=("fuga", "túnel", "tunel", "visibilidad"),
    )
    start_ts = _iso(start) if start else ""
    add(
        "map",
        "Inventario",
        bool(cov.get("map") or hosts),
        detail=f"{len(hosts)} hosts" if hosts else "",
        ts=start_ts,
    )
    add(
        "gw",
        "Gateway",
        bool(cov.get("gw") or gw_f),
        detail=str((gw_f or {}).get("title") or ""),
        finding=str((gw_f or {}).get("id") or ""),
        ts=str((gw_f or {}).get("timestamp") or ""),
    )
    add(
        "dns",
        "DNS",
        bool(cov.get("dns") or dns_f),
        detail=str((dns_f or {}).get("title") or ""),
        finding=str((dns_f or {}).get("id") or ""),
        ts=str((dns_f or {}).get("timestamp") or ""),
    )
    add(
        "seg",
        "Segmentación",
        bool(cov.get("seg") or seg_f),
        detail=str((seg_f or {}).get("title") or ""),
        finding=str((seg_f or {}).get("id") or ""),
        ts=str((seg_f or {}).get("timestamp") or ""),
    )
    add(
        "leak",
        "Fugas",
        bool(cov.get("leak") or leak_f),
        detail=str((leak_f or {}).get("title") or ""),
        finding=str((leak_f or {}).get("id") or ""),
        ts=str((leak_f or {}).get("timestamp") or ""),
    )
    if exploit_mgmt_on(root, state) or bool(meta.get("exploit_mgmt")):
        mgmt_f = _hit("mgmt", "management", "login", "unifi", "controller")
        add(
            "mgmt",
            "Acceso mgmt",
            bool(cov.get("mgmt_access") or (mgmt_f and str(mgmt_f.get("status") or "") == "proven")),
            detail=str((mgmt_f or {}).get("title") or ""),
            finding=str((mgmt_f or {}).get("id") or ""),
            ts=str((mgmt_f or {}).get("timestamp") or ""),
        )
    return steps


def timeline(root: Path, *, ctf: bool | None = None) -> list[dict[str, Any]]:
    """Cadena recon → … . Pasos de flags solo si CTF."""
    meta = _read_json(root / "meta.json")
    if ctf is None:
        ctf = bool(load_contract(root).get("enabled") or meta.get("ctf"))
    eng = _eng(root)
    events = _load_events(root)
    findings = load_findings(root)
    start = _parse_ts(meta.get("started_at"))
    facts: dict[str, list[dict[str, Any]]] = {"cred": [], "flag": [], "access": []}
    for ev in events:
        typ = str(ev.get("type") or "")
        if typ.startswith("fact.") and typ[5:] in facts:
            facts[typ[5:]].append(ev)
        if typ == "run.start" and not start:
            start = _parse_ts(ev.get("ts"))

    def _ts_of(key: str, fallback: str = "") -> str:
        rows = facts.get(key) or []
        if rows:
            return str(rows[0].get("ts") or "")
        return fallback

    first_cred = ""
    creds = eng.get("creds") or []
    if creds and isinstance(creds[0], dict):
        first_cred = str(creds[0].get("ts") or "")
    first_acc = ""
    access = eng.get("access") or []
    if access and isinstance(access[0], dict):
        first_acc = str(access[0].get("ts") or "")
    high = None
    for a in access:
        if isinstance(a, dict) and str(a.get("priv") or "") in {"root", "admin", "system"}:
            high = a
            break
    disk = _disk_flag_map(root)
    user_fl = _best_flag(eng, "user", disk.get("user", ""))
    root_fl = _best_flag(eng, "root", disk.get("root", ""))
    proven_hi = next(
        (
            f
            for f in findings
            if str(f.get("status") or "") == "proven"
            and str(f.get("severity") or "") in {"critical", "high"}
        ),
        None,
    )

    steps: list[dict[str, Any]] = []

    def add(sid: str, label: str, ts: str, *, ok: bool, detail: str = "", finding: str = "") -> None:
        steps.append(
            {
                "id": sid,
                "label": label,
                "ts": ts or "",
                "ok": ok,
                "detail": detail,
                "finding": finding,
            }
        )

    mode = str(meta.get("mode") or "").strip().lower()
    if not mode:
        mode = str(_read_json(root / "brief.json").get("mode") or "").strip().lower()
    if mode == "net":
        return _net_timeline(root, meta, eng, findings, start)

    add("recon", "Recon", _iso(start) if start else "", ok=True, detail=str(meta.get("mode") or ""))
    idents = public_identities(root, eng=eng)
    got = [i for i in idents if i.get("status") == "compromised"]

    def _foot_key(i: dict[str, Any]) -> tuple[str, int]:
        priv = {"user": 0, "admin": 0, "service": 1, "root": 2}.get(str(i.get("priv") or ""), 1)
        return (str(i.get("ts") or "9999"), priv)

    hit = min(got, key=_foot_key) if got else None
    foothold_ts = _ts_of("cred", first_cred) or _ts_of("access", first_acc) or str((hit or {}).get("ts") or "")
    foothold_ok = bool(creds or access or hit or str(eng.get("phase") or "") not in {"", "recon"})
    add(
        "foothold",
        "Foothold",
        foothold_ts,
        ok=foothold_ok,
        detail=(str((hit or {}).get("principal") or "")
        or (str((creds[0] or {}).get("user")) if creds and isinstance(creds[0], dict) else "")
        or (str((access[0] or {}).get("user")) if access and isinstance(access[0], dict) else "")),
        finding=str((hit or {}).get("finding") or ""),
    )
    if ctf:
        add(
            "user",
            "User",
            str((user_fl or {}).get("ts") or ""),
            ok=bool(user_fl),
            detail=str((user_fl or {}).get("value") or ""),
            finding=_finding_for_flag(findings, str((user_fl or {}).get("value") or ""), "user"),
        )
        user_hosts = _hosts_of_flag(findings, str((user_fl or {}).get("value") or ""), "user")
        if user_fl and not user_hosts:
            for t in list(eng.get("targets") or []) + list(meta.get("targets") or []):
                v = t.get("value") if isinstance(t, dict) else t
                k = _host_key(str(v or ""))
                if k:
                    user_hosts.add(k)
        chain_root = _os_root_on_hosts(got, access, user_hosts)
        add(
            "privesc",
            "Privesc",
            str((chain_root or {}).get("ts") or (root_fl or {}).get("ts") or ""),
            ok=bool(root_fl or chain_root),
            detail=str(
                (chain_root or {}).get("priv")
                or (chain_root or {}).get("principal")
                or ("root" if root_fl else "")
            ),
            finding=str((chain_root or {}).get("finding") or ""),
        )
        add(
            "root",
            "Root",
            str((root_fl or {}).get("ts") or ""),
            ok=bool(root_fl),
            detail=str((root_fl or {}).get("value") or ""),
            finding=_finding_for_flag(findings, str((root_fl or {}).get("value") or ""), "root"),
        )
    else:
        add(
            "access",
            "Acceso",
            _ts_of("access", first_acc),
            ok=bool(access),
            detail=(
                f"{access[0].get('user')}@{access[0].get('host')}"
                if access and isinstance(access[0], dict)
                else ""
            ),
        )
        roots = _os_root_rows(got, access)
        os_root = roots[0] if roots else None
        add(
            "privesc",
            "Privesc",
            str((os_root or {}).get("ts") or ""),
            ok=bool(roots),
            detail=_os_root_detail(roots),
            finding=str((os_root or {}).get("finding") or ""),
        )
        add(
            "impact",
            "Impacto",
            str((proven_hi or {}).get("timestamp") or ""),
            ok=bool(proven_hi or high),
            detail=str((proven_hi or {}).get("title") or (high or {}).get("priv") or ""),
            finding=str((proven_hi or {}).get("id") or ""),
        )
    return steps


def mission_view(root: Path, *, ctf: bool | None = None) -> dict[str, Any]:
    contract = load_contract(root)
    if ctf is None:
        ctf = bool(contract.get("enabled"))
    nb = notebook_view(root, ctf=ctf)
    return {
        "timeline": timeline(root, ctf=ctf),
        "ctf": ctf_progress(root) if ctf else None,
        "notebook": nb,
        "graph": nb.get("graph") or {"nodes": [], "edges": [], "current": ""},
    }


def launch_preset(root: Path, meta: dict[str, Any] | None = None) -> dict[str, Any]:
    meta = meta if isinstance(meta, dict) else _read_json(root / "meta.json")
    brief = _read_json(root / "brief.json")
    targets = []
    for t in meta.get("targets") or []:
        if isinstance(t, dict):
            v = str(t.get("value") or t.get("raw") or "").strip()
            if v:
                targets.append(v)
    contract = load_contract(root)
    flags = [str(s.get("match") or "") for s in (contract.get("slots") or []) if isinstance(s, dict)]
    if not flags:
        flags = [str(x) for x in (meta.get("ctf_flags") or []) if str(x).strip()]
    ssh_host = str(meta.get("ssh_host") or brief.get("ssh_host") or "").strip()
    ssh_user = str(meta.get("ssh_user") or brief.get("ssh_user") or "").strip()
    if ssh_host:
        obj = []
        for t in brief.get("targets") or []:
            if isinstance(t, dict):
                v = str(t.get("raw") or t.get("value") or "").strip()
                if v:
                    obj.append(v)
        if obj:
            targets = obj
    return {
        "target": ",".join(targets),
        "title": str(meta.get("title") or ""),
        "mode": str(meta.get("mode") or brief.get("mode") or "full"),
        "harness": str(meta.get("harness") or "opencode"),
        "model": str(meta.get("model") or meta.get("model_alias") or ""),
        "timeout": str(brief.get("time_budget") or meta.get("timeout") or "6h"),
        "note": str(brief.get("operator_note") or ""),
        "ctf": bool(contract.get("enabled") or meta.get("ctf")),
        "flags": flags,
        "flag_count": len(flags) if flags else 0,
        "backup_harness": str(meta.get("backup_harness") or ""),
        "backup_model": str(meta.get("backup_model") or ""),
        "rescue_model": str(meta.get("rescue_model") or ""),
        "rescue_harness": str(meta.get("rescue_harness") or ""),
        "persist": True,
        "ssh": bool(ssh_host),
        "ssh_host": ssh_host,
        "ssh_user": ssh_user,
        "exploit_mgmt": bool(meta.get("exploit_mgmt") or brief.get("exploit_mgmt")),
    }
