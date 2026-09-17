"""Cierre: promociona fichas anidadas. LLM solo si las de primer nivel son pobres."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

from internal.report import _read_json, ensure_reports, load_findings

HARVEST_SYS = """Eres el redactor de cierre de un engagement de pentest autorizado (Aegis).
Te pasan solo lo que hay en disco. Extrae hallazgos YA demostrados. No inventes
vectores, IPs, flags ni PoCs que no estén en el material. No des recetas de una
máquina concreta que no aparezcan en el texto.
Todo el texto de title, explain, summary, reproduction e impact va en español.
Los términos técnicos (CVE, SSH, sudo) se dejan. No traduzcas IDs, rutas ni credenciales.

Responde SOLO con JSON:
{"findings":[{"id":"F-00N","title":"...","asset":"...","severity":"critical|high|medium|low|info","status":"proven|suspected","kind":"vuln|cve|misconfig|flag|info","explain":"...","summary":"...","proof":"...","reproduction":"...","evidence":["rutas relativas que existan"],"impact":"..."}]}

Reglas:
- Si el material nombra un CVE demostrado, `kind=cve` y el ID en el título.
- Puedes reemplazar una ficha genérica (source aegis-evidence, título tipo
  "Ejecución de código / shell", "RCE: webshell como …", "Hallazgo (...)")
  con la misma id. Escribe la causa real (plugin, CVE, OCR, etc.).
- No pises fichas del agente ni fichas ya específicas (CVE, servicio, causa).
- No dupliques el mismo vector con otro ID.
- Si hay root.txt y no hay ficha de escalada específica, escríbela desde el
  material (sudo, OliveTin, SUID, OCR, hashdump…). No inventes el vector.
- proven exige evidencia en disco (loot/, findings/, flags) o un comando del audit.
- Si solo hay user.txt y nada más, un finding kind=flag basta.
- Si no hay nada nuevo, {"findings":[]}.
"""

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_GENERIC_TITLES = frozenset(
    {
        "ejecución de código / shell",
        "resumen del engagement (reconstruido del estado)",
        "credenciales o cookies capturadas",
    }
)
_GENERIC_TITLE_PREFIXES = ("hallazgo (", "reservado (")
_GENERIC_EXPLAIN_PREFIXES = (
    "hay un script o artefacto de explotación en disco.",
    "evidencia en `",
    "hay ejecución de código en el objetivo como",
    "el agente no escribió la ficha",
)
_PRIV_HINT = re.compile(
    r"\b(sudo|privesc|privilege|suid|pkexec|doas|cap_setuid|trainer|olivetin|"
    r"escalada|ocr|sysid|hashdump)\b",
    re.I,
)
_PRIV_LOOT = re.compile(r"ocr|sysid|hashdump|rootbash|olivetin|startaction", re.I)
_AEGIS_UPGRADE = frozenset({"aegis-evidence", "aegis-reserved"})
_AUDIT_KEEP = re.compile(
    r"pickle|pdfminer|sudo\s|ssh\s|cve-|id_rsa|trainer|privesc|pdf2txt|"
    r"olivetin|startaction|rootbash|ocr|sysid|pluginzip|aegis_cmd|"
    r"wp-config|wordpress|plugin-install|canvas_image",
    re.I,
)


def promote_nested_findings(out_dir: Path) -> list[str]:
    """Copia findings/**/F-xxx.json a findings/F-xxx.json si falta arriba."""
    d = out_dir / "findings"
    if not d.is_dir():
        return []
    moved: list[str] = []
    paths = sorted(d.rglob("F-*.json"), key=lambda p: (len(p.relative_to(d).parts), str(p)))
    for path in paths:
        if path.parent == d or not path.is_file():
            continue
        data = _read_json(path)
        if not (isinstance(data, dict) and data.get("id")):
            continue
        fid = str(data["id"])
        dest = d / f"{fid}.json"
        if dest.is_file():
            continue
        dest.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        moved.append(fid)
    return moved


def _finding_has_disk_evidence(out_dir: Path, rec: dict[str, Any]) -> bool:
    fid = str(rec.get("id") or "").strip()
    rels = [str(x) for x in (rec.get("evidence") or []) if x]
    for rel in rels:
        raw = rel.strip().lstrip("/")
        for cand in (out_dir / raw, out_dir / "findings" / raw):
            if cand.is_file() and cand.stat().st_size > 0:
                return True
    if fid:
        sub = out_dir / "findings" / fid
        if sub.is_dir() and any(p.is_file() and p.stat().st_size > 0 for p in sub.iterdir()):
            return True
    return False


def demote_unproven_findings(out_dir: Path) -> int:
    """Comprobador host: proven sin archivo en disco → suspected."""
    d = out_dir / "findings"
    if not d.is_dir():
        return 0
    n = 0
    for path in sorted(d.glob("F-*.json")):
        rec = _read_json(path)
        if not isinstance(rec, dict):
            continue
        if str(rec.get("status") or "").strip().lower() != "proven":
            continue
        if str(rec.get("kind") or "").strip().lower() == "flag":
            continue
        if _finding_has_disk_evidence(out_dir, rec):
            continue
        rec["status"] = "suspected"
        path.write_text(json.dumps(rec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        n += 1
    return n


def needs_harvest(out_dir: Path) -> bool:
    """True si el disco tiene más historia que las fichas específicas."""
    findings = load_findings(out_dir)
    # Stubs (Hallazgo (…), webshell auto) junto a una ficha “RCE” genérica:
    # MakeSense cerró 2/2 y el informe se quedó sin la cadena.
    if any(_is_generic_card(f) for f in findings):
        return True
    if _rich_state(out_dir) and _thin_cards(findings):
        return True
    if _uncovered_cves(out_dir, findings):
        return True
    if _privesc_gap(out_dir, findings):
        return True
    loot = out_dir / "loot"
    if loot.is_dir() and any(p.is_file() and p.stat().st_size > 0 for p in loot.rglob("*")):
        if _thin_cards(findings):
            return True
    return False


def _finding_text(findings: list[dict[str, Any]]) -> str:
    return " ".join(
        f"{f.get('title') or ''} {f.get('explain') or ''} {f.get('summary') or ''}" for f in findings
    )


def _is_generic_card(f: dict[str, Any]) -> bool:
    src = str(f.get("source") or "")
    title = str(f.get("title") or "").strip().lower()
    explain = str(f.get("explain") or "").strip().lower()
    if src == "aegis-reserved":
        return True
    if src != "aegis-evidence":
        return False
    if title in _GENERIC_TITLES or title.startswith(_GENERIC_TITLE_PREFIXES):
        return True
    return any(explain.startswith(p) for p in _GENERIC_EXPLAIN_PREFIXES)


def _thin_cards(findings: list[dict[str, Any]]) -> bool:
    vulns = [
        f
        for f in findings
        if not _is_generic_card(f)
        and (
            str(f.get("kind") or "").lower() in {"vuln", "cve", "misconfig"}
            or str(f.get("severity") or "") in {"critical", "high", "medium"}
        )
    ]
    return len(vulns) < 1


def _state_text(out_dir: Path) -> str:
    md = out_dir / "STATE.md"
    if not md.is_file():
        return ""
    try:
        return md.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _state_cves(out_dir: Path) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in _CVE_RE.finditer(_state_text(out_dir)):
        cve = m.group(0).upper()
        if cve in seen:
            continue
        seen.add(cve)
        out.append(cve)
    return out


def _uncovered_cves(out_dir: Path, findings: list[dict[str, Any]]) -> bool:
    blob = _finding_text(findings).upper()
    return any(cve not in blob for cve in _state_cves(out_dir))


def _has_privesc_card(findings: list[dict[str, Any]]) -> bool:
    for f in findings:
        if str(f.get("kind") or "").lower() == "flag":
            continue
        if _is_generic_card(f):
            continue
        if _PRIV_HINT.search(_finding_text([f])):
            return True
    return False


def _has_root_loot(out_dir: Path, findings: list[dict[str, Any]]) -> bool:
    loot = out_dir / "loot" / "root.txt"
    try:
        if loot.is_file() and loot.stat().st_size > 0:
            return True
    except OSError:
        pass
    for f in findings:
        if str(f.get("kind") or "").lower() != "flag":
            continue
        blob = f"{f.get('title') or ''} {f.get('evidence') or ''}".lower()
        if "root.txt" in blob or blob.strip().endswith("root"):
            return True
    return False


def _audit_sudo_argv(out_dir: Path) -> str:
    from internal.flagspec import privesc_proof

    return privesc_proof(out_dir)


def _privesc_material(out_dir: Path) -> bool:
    """Hay rastro de escalada en disco (sudo/OliveTin o loot OCR/sysid), no solo root.txt."""
    if _audit_sudo_argv(out_dir):
        return True
    for folder in (out_dir / "loot", out_dir / "findings"):
        if not folder.is_dir():
            continue
        try:
            for p in folder.rglob("*"):
                if p.is_file() and _PRIV_LOOT.search(p.name):
                    return True
        except OSError:
            continue
    return False


def _privesc_gap(out_dir: Path, findings: list[dict[str, Any]]) -> bool:
    """root.txt y ninguna ficha de escalada, pero sí material en disco → cosechar."""
    return bool(
        _has_root_loot(out_dir, findings)
        and not _has_privesc_card(findings)
        and _privesc_material(out_dir)
    )


def _rich_state(out_dir: Path) -> bool:
    md = out_dir / "STATE.md"
    if not md.is_file():
        return False
    try:
        text = md.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    if len(text) < 500:
        return False
    return "(auto:" not in text[:240] or len(text) > 1800


def _pack(out_dir: Path) -> str:
    parts: list[str] = []
    existing = load_findings(out_dir)
    parts.append(
        "FICHAS YA INDEXADAS:\n"
        + (
            "\n".join(
                f"- {f.get('id')} [{f.get('severity')}] {f.get('title')}" for f in existing
            )
            or "(ninguna)"
        )
    )
    for name in ("STATE.md", "PIVOT.md", "NEXT.md"):
        p = out_dir / name
        if p.is_file():
            try:
                parts.append(f"===== {name} =====\n" + p.read_text(encoding="utf-8", errors="replace")[:12000])
            except OSError:
                continue
    loot = out_dir / "loot"
    if loot.is_dir():
        names = [str(p.relative_to(out_dir)) for p in sorted(loot.rglob("*")) if p.is_file()]
        if names:
            parts.append("LOOT:\n" + "\n".join(names[:80]))
        snippets: list[str] = []
        for p in sorted(loot.rglob("*")):
            if not p.is_file() or not _AUDIT_KEEP.search(p.name):
                continue
            if p.stat().st_size >= 12_000 or p.suffix.lower() not in {
                ".txt",
                ".md",
                ".php",
                ".py",
                ".json",
                ".log",
            }:
                continue
            try:
                snippets.append(
                    f"===== loot/{p.relative_to(loot)} =====\n"
                    + p.read_text(encoding="utf-8", errors="replace")[:3000]
                )
            except OSError:
                continue
            if len(snippets) >= 12:
                break
        if snippets:
            parts.append("LOOT (recorte):\n" + "\n".join(snippets))
    findings = out_dir / "findings"
    if findings.is_dir():
        extra: list[str] = []
        for p in sorted(findings.rglob("*")):
            if not p.is_file():
                continue
            rel = str(p.relative_to(out_dir))
            if p.suffix.lower() in {".txt", ".md", ".json", ".php", ".py", ".log"} and p.stat().st_size < 20_000:
                try:
                    extra.append(f"===== {rel} =====\n" + p.read_text(encoding="utf-8", errors="replace")[:4000])
                except OSError:
                    extra.append(rel)
            else:
                extra.append(rel)
        if extra:
            parts.append("FINDINGS EN DISCO:\n" + "\n".join(extra[:40]))
    audit = _pack_audit(out_dir)
    if audit:
        parts.append(audit)
    tried = _pack_tried(out_dir)
    if tried:
        parts.append(tried)
    return "\n\n".join(parts)[:60_000]


def _pack_tried(out_dir: Path) -> str:
    path = out_dir / "engagement.json"
    if not path.is_file():
        return ""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return ""
    if not isinstance(data, dict):
        return ""
    hits: list[str] = []
    tail: list[str] = []
    for key in ("tried", "cmd_log"):
        rows = data.get(key) or []
        if not isinstance(rows, list):
            continue
        for rec in rows:
            if not isinstance(rec, dict):
                continue
            argv = str(rec.get("argv") or rec.get("cmd") or "")
            compact = " ".join(argv.split())[:400]
            if not compact:
                continue
            tail.append(compact)
            if _AUDIT_KEEP.search(argv):
                hits.append(compact)
    if not hits and not tail:
        return ""
    picked = list(dict.fromkeys(hits[-20:] + tail[-10:]))
    return "ENGAGEMENT (recorte):\n" + "\n".join(picked)


def _pack_audit(out_dir: Path) -> str:
    path = out_dir / ".audit" / "commands.jsonl"
    if not path.is_file():
        return ""
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    hits: list[str] = []
    for line in raw[-200_000:].splitlines()[-400:]:
        if _AUDIT_KEEP.search(line):
            hits.append(line[:400])
    if not hits:
        return ""
    return "AUDIT (recorte):\n" + "\n".join(hits[-25:])


def _parse_payload(raw: str) -> dict[str, Any]:
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


def _next_fid(taken: set[str]) -> str:
    n = 1
    while f"F-{n:03d}" in taken:
        n += 1
    return f"F-{n:03d}"


def _card_source(path: Path) -> str:
    data = _read_json(path)
    if not isinstance(data, dict):
        return ""
    return str(data.get("source") or "")


def harvest_findings_llm(
    out_dir: Path,
    *,
    llm: Callable[[str, str, Path], str] | None = None,
) -> list[str]:
    """Escribe F-xxx.json nuevos o enriquece fichas genéricas aegis-evidence."""
    from internal.conscience import call_llm_text

    pack = _pack(out_dir)
    if not pack.strip():
        return []
    raw = (llm or call_llm_text)(HARVEST_SYS, pack, out_dir)
    data = _parse_payload(raw if isinstance(raw, str) else "")
    items = data.get("findings")
    if not isinstance(items, list):
        return []
    dest_dir = out_dir / "findings"
    dest_dir.mkdir(parents=True, exist_ok=True)
    existing = {str(f.get("id") or ""): f for f in load_findings(out_dir)}
    taken = set(existing)
    written: list[str] = []
    for rec in items:
        if not isinstance(rec, dict):
            continue
        title = str(rec.get("title") or "").strip()
        if not title:
            continue
        fid = str(rec.get("id") or "").strip()
        if fid and fid in existing:
            old = existing[fid]
            src = str(old.get("source") or "") or _card_source(dest_dir / f"{fid}.json")
            if src not in _AEGIS_UPGRADE or not _is_generic_card(old):
                continue
        elif not fid:
            fid = _next_fid(taken)
        rec = dict(rec)
        rec["id"] = fid
        rec.setdefault("status", "suspected")
        rec.setdefault("severity", "info")
        rec.setdefault("kind", "info")
        rec.setdefault("mode_ok", ["full"])
        rec.setdefault("evidence", [])
        rec.setdefault("source", "aegis-harvest")
        path = dest_dir / f"{fid}.json"
        if path.is_file() and _card_source(path) not in _AEGIS_UPGRADE:
            continue
        path.write_text(json.dumps(rec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        taken.add(fid)
        existing[fid] = rec
        written.append(fid)
    return written


def _fallback_from_state(out_dir: Path) -> list[str]:
    """Si no hay fichas y el LLM no devolvió nada, una ficha desde STATE.md."""
    if load_findings(out_dir):
        return []
    md = out_dir / "STATE.md"
    if not md.is_file():
        return []
    try:
        chain = md.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return []
    if len(chain) < 200:  # nada sustancial que preservar
        return []
    state = _read_json(out_dir / "engagement.json") or {}
    if not isinstance(state, dict):
        state = {}
    asset = ""
    tgt = state.get("target")
    if isinstance(tgt, str) and tgt.strip():
        asset = tgt.strip()
    if not asset:
        tg = state.get("targets") or []
        if isinstance(tg, list) and tg:
            first = tg[0]
            asset = str(first.get("value") if isinstance(first, dict) else first)
    if not asset:
        brief = _read_json(out_dir / "brief.json") or {}
        tg = (brief.get("targets") or []) if isinstance(brief, dict) else []
        if tg:
            first = tg[0]
            asset = str(first.get("value") if isinstance(first, dict) else first)
    # Acceso/creds documentados => impacto real => severidad media; si no, informativo.
    sev = "medium" if (state.get("access") or state.get("creds")) else "info"
    resumen = " ".join(chain.splitlines()[1:4]).strip()[:200] or "Ver STATE.md"
    rec = {
        "id": "F-001",
        "title": "Resumen del engagement (reconstruido del estado)",
        "asset": asset or "scope",
        "severity": sev,
        "status": "suspected",
        "kind": "info",
        "explain": (
            "El agente documentó progreso en STATE.md pero no emitió fichas F-xxx, y la "
            "extracción por LLM al cierre no devolvió nada (p. ej. refuso del modelo sobre "
            "contenido ofensivo). Esta ficha preserva la cadena documentada para que el "
            "informe no salga vacío; revísese STATE.md/engagement.json para el detalle."
        ),
        "summary": resumen,
        "proof": "",
        "reproduction": "",
        "evidence": ["STATE.md"],
        "impact": "Ver la cadena documentada en STATE.md y engagement.json.",
        "mode_ok": ["full", "assess", "recon"],
    }
    dest = out_dir / "findings"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "F-001.json").write_text(json.dumps(rec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return ["F-001"]


def _ensure_privesc_card(out_dir: Path) -> list[str]:
    """Cierre: misma ficha que el sidecar en vivo."""
    from internal.flagspec import ensure_privesc_finding

    return ensure_privesc_finding(out_dir)


def close_and_report(
    out_dir: Path,
    *,
    mode: str,
    model: str,
    run_id: str,
    llm: Callable[[str, str, Path], str] | None = None,
    quick: bool = False,
) -> None:
    """Cierre (fin, timeout, cancel, reap): ingest + huecos; LLM solo si hace falta.

    Tras el pase del agente (.doc-done + report.agent.md) no se relanza la IA
    para prosa ni para describir fichas. Harvest solo si las fichas siguen
    pobres. Si no queda ninguna, sintetiza desde STATE.md.

    quick=True («cortar ya»): solo disco. Sin harvest/prosa LLM — eso era el
    minuto extra del modal.
    """
    # Último ingest de consola/audit: el sidecar para antes y sin esto
    # timeout/abort pierden el tramo final. En «cortar ya» no: el modal no
    # puede esperar a releer console.log entero.
    if not quick:
        try:
            from internal.engage import refresh_state

            refresh_state(out_dir, sidecars=False)
        except Exception:
            pass
    # ctf_complete lee loot antes de que el sidecar meta flags → 1/2 en UI.
    try:
        from internal.engage import ingest_disk_flags, locked_state, sanitize_host_paths, settle_hypotheses
        from internal.identities import ingest_disk_identities

        with locked_state(out_dir / "engagement.json", sidecars=False) as st:
            ingest_disk_flags(st, out_dir)
            ingest_disk_identities(st, out_dir)
            sanitize_host_paths(st)
            settle_hypotheses(st)
    except Exception:
        pass
    promote_nested_findings(out_dir)
    try:
        demote_unproven_findings(out_dir)
    except Exception:
        pass
    agent_done = (out_dir / ".doc-done").is_file()
    if not quick and needs_harvest(out_dir):
        try:
            harvest_findings_llm(out_dir, llm=llm)
        except Exception:
            pass
    try:
        _ensure_privesc_card(out_dir)
    except Exception:
        pass
    if not quick and not agent_done:
        try:
            from internal.flagspec import describe_live_findings

            describe_live_findings(out_dir, llm=llm, limit=8)
        except Exception:
            pass
    if not load_findings(out_dir):
        try:
            _fallback_from_state(out_dir)
        except Exception:
            pass
    ensure_reports(out_dir, mode=mode, model=model, run_id=run_id, llm=llm, polish=not quick)
    try:
        from internal.engage import locked_state, settle_hypotheses

        with locked_state(out_dir / "engagement.json", sidecars=False) as st:
            settle_hypotheses(st)
    except Exception:
        pass
