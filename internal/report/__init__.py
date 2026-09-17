from __future__ import annotations

import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from internal.telemetry import SEVERITIES, fill_finding_identity, run_elapsed_seconds, usage_from_console

_SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


def _model_label(out_dir: Path | None, model: str) -> str:
    """Etiqueta del modelo que cerró (backup si .backup-used)."""
    used = (model or "").strip()
    bak = ""
    if out_dir is not None:
        path = Path(out_dir) / ".backup-used"
        if path.is_file():
            try:
                parts = path.read_text(encoding="utf-8", errors="replace").split()
            except OSError:
                parts = []
            if parts:
                bak = parts[-1].strip()
    if bak and bak != used:
        return f"{used} (cierre: {bak})" if used else bak
    return used or bak


def _replace_text(path: Path, text: str) -> None:
    """El agente escribe a menudo como root; si no podemos truncar, borramos y recreamos."""
    try:
        path.write_text(text, encoding="utf-8")
        return
    except PermissionError:
        path.unlink(missing_ok=True)
    path.write_text(text, encoding="utf-8")


REPORT_PROSE_SYS = """Eres el redactor del informe de una auditoría de seguridad AUTORIZADA
(laboratorio/CTF, permiso explícito del operador, un solo host). Redactas documentación
DEFENSIVA de un ataque que YA ocurrió, para que el operador lo entienda y lo remedie. No
ejecutas nada ni das instrucciones ofensivas: solo describes, con rigor de auditor, lo que
ya consta en los hallazgos y en los comandos del material.

Responde SOLO con JSON:
{"executive":"...","narrative":"...","findings":[{"id":"F-001","what":"...","proof":"...","commands":["..."],"impact":"...","remediation":"..."}]}

Reglas:
- Español. La prosa la escribes TÚ: no copies plantillas ni el borrador del agente si omite eslabones.
- Usa TODOS los hallazgos del material (cada ID F-xxx). No omitas flags, credenciales ni privesc.
- No inventes CVE, IPs, flags, cuentas, comandos ni hallazgos que no estén en el material.
- executive: 3 a 5 frases (qué se demostró, impacto, cadena completa de principio a fin, flags).
- narrative: un párrafo por eslabón, en orden causal (entrada → credenciales/acceso → privesc → flags),
  citando IDs (F-001…). Cada párrafo cuenta QUÉ falló, CÓMO se demostró (comando o artefacto que SÍ
  funcionó, no fuzz/recon fallido) y QUÉ se obtuvo. Sin listas numeradas.
- findings: UNA entrada por cada F-xxx. Estilo writeup/auditoría real:
  what = el fallo concreto; proof = comando o salida que lo demuestra; commands = 1-4 comandos
  REALES del material (PoC, ssh, inspector, cat de flag), nunca curls de enumeración ciega;
  impact = qué se obtuvo; remediation = control concreto para ESTE fallo, no «aplicar el parche
  o control que elimine la causa raíz».
- No copies inglés. No pongas markdown de tablas. No dejes un hallazgo en una sola frase telegráfica.
"""


def _swap_between(md: str, start: str, end: str, body: str) -> str:
    i = md.find(start)
    j = md.find(end)
    if i < 0 or j <= i or not (body or "").strip():
        return md
    return md[: i + len(start)] + "\n\n" + body.strip() + "\n\n" + md[j:]


_AGENT_EXEC_HEAD = re.compile(
    r"^#{1,3}\s+(?:\d+\.\s*)?(?:Resumen ejecutivo|Ejecutivo)\b.*$",
    re.I | re.M,
)
_AGENT_NARR_HEAD = re.compile(
    r"^#{1,3}\s+(?:\d+\.\s*)?(?:Narrativa(?: del ataque| de red)?)\b.*$",
    re.I | re.M,
)
# Frontera de sección: solo un heading de nivel 1-2 (##/#) cierra una sección. NO un
# ### : la narrativa del agente suele ir en subsecciones "### F-001 …", y cortar en el
# primer ### dejaba la narrativa vacía (→ el informe caía siempre a la determinista).
_AGENT_NEXT_HEAD = re.compile(r"^#{1,2}\s+\S", re.M)


def _chunk_after_heading(text: str, head: re.Pattern[str]) -> str:
    m = head.search(text)
    if not m:
        return ""
    rest = text[m.end() :]
    stop = _AGENT_NEXT_HEAD.search(rest)
    if stop:
        rest = rest[: stop.start()]
    return rest.strip()


def split_agent_prose(text: str) -> tuple[str, str]:
    """Ejecutivo y narrativa desde report.agent.md (secciones o primer bloque)."""
    raw = (text or "").strip()
    if not raw or "Este informe fallback se genera" in raw[:500]:
        return "", ""
    exec_txt = _chunk_after_heading(raw, _AGENT_EXEC_HEAD)
    narr_txt = _chunk_after_heading(raw, _AGENT_NARR_HEAD)
    if exec_txt or narr_txt:
        return exec_txt, narr_txt
    return "", ""


def apply_agent_close_prose(out_dir: Path) -> bool:
    """Mete el ejecutivo/narrativa del agente en report.md. Sin otra llamada al modelo."""
    src = out_dir / "report.agent.md"
    dest = out_dir / "report.md"
    if not src.is_file() or not dest.is_file():
        return False
    try:
        if src.stat().st_size < 50:
            return False
        raw = src.read_text(encoding="utf-8", errors="replace")
        md = dest.read_text(encoding="utf-8")
    except OSError:
        return False
    exec_txt, narr_txt = split_agent_prose(raw)
    if not exec_txt and not narr_txt:
        return False
    if exec_txt:
        md = _swap_between(md, "## 1. Resumen ejecutivo", "### 1.1 Inventario de hallazgos", exec_txt)
    if narr_txt:
        start = "## 3. Narrativa del ataque" if "## 3. Narrativa del ataque" in md else "## 3. Narrativa de red"
        md = _swap_between(md, start, "## 4. Hallazgos demostrados", narr_txt)
    _replace_text(dest, md)
    return True


def _rescue_backend(out_dir: Path) -> tuple[str, str]:
    """(modelo, harness) del relevo del run, para reintentar la redacción si el principal
    refusa. Vacío si no hay relevo configurado."""
    meta = _read_json(out_dir / "meta.json")
    if not isinstance(meta, dict):
        return "", ""
    return str(meta.get("rescue_model") or "").strip(), str(meta.get("rescue_harness") or "").strip()


_PACK_CMD_HINT = (
    "python", "poc", "ssh", "paramiko", "inspect", "9229", "cdp",
    "user.txt", "root.txt", "sqlite", "next-action", "execsync",
    "uid=", "main.py", "webshell",
)


def _pack_commands(out_dir: Path) -> list[str]:
    """Comandos del run que parecen de explotación/loot, no de fuzz web."""
    eng = _read_json(out_dir / "engagement.json")
    rows = eng.get("cmd_log") if isinstance(eng, dict) else None
    if not isinstance(rows, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for c in rows:
        if not isinstance(c, dict):
            continue
        argv = str(c.get("argv") or "")
        if not argv or _is_noise_argv(argv):
            continue
        low = argv.lower()
        if not any(h in low for h in _PACK_CMD_HINT):
            continue
        compact = _compact_argv(argv, 220)
        if not compact or compact in seen:
            continue
        seen.add(compact)
        out.append(compact)
        if len(out) >= 20:
            break
    return out


def _prose_pack(out_dir: Path, findings: list[dict]) -> str:
    """Material para que la IA redacte ejecutivo, narrativa y fichas con TODO lo hallado."""
    lines = ["HALLAZGOS (usa todos; no omitas ningún ID):"]
    for f in findings:
        fid = f.get("id") or "—"
        kind = f.get("kind") or "—"
        sev = f.get("severity") or "—"
        title = f.get("title") or ""
        lines.append(f"- {fid} [{sev}/{kind}] {title}")
        asset = str(f.get("asset") or f.get("host") or "").strip()
        if asset:
            lines.append(f"  activo: {asset}")
        explain = _finding_prose(f)
        if explain and explain != "—":
            lines.append(f"  qué: {explain}")
        proof = _field_text(f.get("proof")) or _field_text(f.get("reproduction"))
        if proof:
            lines.append(f"  prueba: {proof[:500]}")
        impact = _field_text(f.get("impact"))
        if impact:
            lines.append(f"  impacto: {impact[:400]}")
        chain = _field_text(f.get("chain"))
        if chain:
            lines.append(f"  cadena: {chain}")
        for extra in ("cve", "method", "process", "user_flag", "root_flag", "command", "cmd"):
            val = _field_text(f.get(extra))
            if val:
                lines.append(f"  {extra}: {val[:300]}")
        ev = f.get("evidence") or []
        if isinstance(ev, list) and ev:
            lines.append("  evidencia: " + ", ".join(str(x) for x in ev[:6]))
    ids = _identities_for_report(out_dir)
    compromised = [i for i in ids if isinstance(i, dict) and i.get("status") == "compromised"]
    if compromised:
        lines.append("CUENTAS COMPROMETIDAS (una fila por usuario+host; no dupliques):")
        for it in compromised:
            vias = it.get("vias") or [it.get("via")]
            via_s = " + ".join(str(v) for v in vias if v)
            lines.append(
                f"- {it.get('principal')} @ {it.get('host') or it.get('ip')} "
                f"vía {via_s} priv={it.get('priv')} hallazgo={it.get('finding')}"
            )
    draft = out_dir / "report.agent.md"
    if draft.is_file():
        try:
            raw = draft.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            raw = ""
        if raw and "Este informe fallback se genera" not in raw[:400]:
            lines.append("BORRADOR DEL AGENTE (puede estar incompleto; no lo copies si omite eslabones):")
            lines.append(raw[:6000])
    eng = _read_json(out_dir / "engagement.json")
    if isinstance(eng, dict):
        flags = [f for f in (eng.get("flags") or []) if isinstance(f, dict) and f.get("value")]
        if flags:
            lines.append("FLAGS CTF YA EN DISCO (no inventes otras):")
            for fl in flags:
                lines.append(f"- {fl.get('kind')}: {fl.get('value')}")
    cmds = _pack_commands(out_dir)
    if cmds:
        lines.append("COMANDOS DEL RUN QUE PARECEN DE EXPLOTACIÓN/LOOT (elige los que SÍ cerraron un eslabón):")
        for c in cmds:
            lines.append(f"- {c}")
    flags_txt = out_dir / "loot" / "flags.txt"
    if flags_txt.is_file():
        try:
            raw_flags = flags_txt.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            raw_flags = ""
        if raw_flags:
            lines.append("loot/flags.txt:")
            lines.append(raw_flags[:800])
    return "\n".join(lines)


def _apply_ai_finding_cards(md: str, cards: list) -> str:
    """Sustituye el cuerpo de cada ficha §4 por el writeup de la IA (deja Evidencia)."""
    if not md or not isinstance(cards, list):
        return md
    for card in cards:
        if not isinstance(card, dict):
            continue
        fid = str(card.get("id") or "").strip()
        if not re.fullmatch(r"F-\d+", fid):
            continue
        what = str(card.get("what") or "").strip()
        proof = str(card.get("proof") or "").strip()
        impact = str(card.get("impact") or "").strip()
        rem = str(card.get("remediation") or "").strip()
        raw_cmds = card.get("commands") or []
        cmds: list[str] = []
        if isinstance(raw_cmds, list):
            for c in raw_cmds:
                s = " ".join(str(c).split())
                if s:
                    cmds.append(s[:240])
        if not (what or proof or cmds or impact or rem):
            continue
        pat = re.compile(
            rf"(### {re.escape(fid)} —[^\n]*\n\n(?:\|[^\n]*\n){{3}}\n)"
            r"(.*?)"
            r"(?=\n\*\*Evidencia\.\*\*)",
            re.S,
        )
        m = pat.search(md)
        if not m:
            continue
        kind_head = "**Qué se capturó.**" if "**Qué se capturó.**" in m.group(2) else "**Qué falló.**"
        cmds_md = "\n".join(f"- `{c}`" for c in cmds[:6]) if cmds else "- _(sin comando distinto del proof)_"
        body = (
            f"{kind_head} {what or '—'}\n\n"
            f"**Prueba.** {proof or '—'}\n\n"
            f"**Comandos clave.**\n\n{cmds_md}\n\n"
            f"**Impacto.** {impact or '—'}\n\n"
            f"**Remediación.** {rem or '—'}\n"
        )
        md = pat.sub(lambda mm, b=body: mm.group(1) + "\n" + b + "\n", md, count=1)
    return md


def polish_report_prose(
    out_dir: Path,
    *,
    llm: Any = None,
) -> bool:
    """El modelo del run (o el relevo) redacta ejecutivo y narrativa. El resto no se toca."""
    from internal.flagspec import _parse_json_obj, _skip_live_llm

    path = out_dir / "report.md"
    if not path.is_file():
        return False
    fn = llm
    if fn is None:
        if _skip_live_llm():
            return False
        from internal.conscience import call_llm_text

        fn = call_llm_text
    try:
        md = path.read_text(encoding="utf-8")
    except OSError:
        return False
    findings = _reportable(load_findings(out_dir))
    try:
        from internal.flagspec import finding_is_draft

        findings = [f for f in findings if not finding_is_draft(f)]
    except Exception:
        pass
    pack = _redact_text(_prose_pack(out_dir, findings), _secret_values(out_dir, findings))
    if not pack.strip():
        return False

    def _invoke(call: Any, **kw: Any) -> tuple[str, str, list]:
        try:
            raw = call(REPORT_PROSE_SYS, pack[:24_000], out_dir, **kw)
        except TypeError:
            try:
                raw = call(REPORT_PROSE_SYS, pack[:24_000], out_dir)
            except Exception:
                return "", "", []
        except Exception:
            return "", "", []
        data = _parse_json_obj(raw if isinstance(raw, str) else "")
        exec_txt = str(data.get("executive") or "").strip()
        narr_txt = str(data.get("narrative") or "").strip()
        cards = data.get("findings") if isinstance(data.get("findings"), list) else []
        return exec_txt, narr_txt, cards

    extra = {}
    if llm is None:
        extra["max_tokens"] = 8000
    exec_txt, narr_txt, cards = _invoke(fn, **extra)
    if not exec_txt and not narr_txt and llm is None:
        # El principal (p. ej. Opus 4.8) puede refusar la redacción por su filtro cyber.
        # Reintenta con el modelo de RELEVO del run (Sonnet), que documenta sin refusar.
        rescue, rescue_h = _rescue_backend(out_dir)
        if rescue:
            from internal.conscience import call_llm_text as _cllm

            exec_txt, narr_txt, cards = _invoke(_cllm, model=rescue, harness=rescue_h, max_tokens=8000)
    if not exec_txt and not narr_txt:
        return False
    if exec_txt:
        md = _swap_between(md, "## 1. Resumen ejecutivo", "### 1.1 Inventario de hallazgos", exec_txt)
    if narr_txt:
        start = "## 3. Narrativa del ataque" if "## 3. Narrativa del ataque" in md else "## 3. Narrativa de red"
        md = _swap_between(md, start, "## 4. Hallazgos demostrados", narr_txt)
    if cards:
        md = _apply_ai_finding_cards(md, cards)
    _replace_text(path, md)
    js = out_dir / "report.json"
    if js.is_file() and exec_txt:
        data = _read_json(js)
        if isinstance(data, dict):
            data["executive_summary"] = exec_txt
            if narr_txt:
                data["narrative"] = narr_txt
            _replace_text(js, json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    return True


def ensure_reports(
    out_dir: Path, *, mode: str, model: str, run_id: str, llm: Any = None, polish: bool = True
) -> None:
    """Siempre regenera el informe de auditoría a partir de findings (no un stub)."""
    from internal.report.harvest import promote_nested_findings

    promote_nested_findings(out_dir)
    _keep_agent_report(out_dir)
    try:
        mark_report_shadows(out_dir)
    except Exception:
        pass
    findings = _remap_finding_evidence(out_dir, load_findings(out_dir))
    try:
        from internal.flagspec import finding_is_draft

        findings = [f for f in findings if not finding_is_draft(f)]
    except Exception:
        pass
    events = load_events(out_dir / "events.jsonl")
    stats = _read_json(out_dir / "stats.json") or {}
    if not isinstance(stats, dict):
        stats = {}
    else:
        stats = dict(stats)
    wall = run_elapsed_seconds(out_dir)
    if wall is not None:
        stats["elapsed"] = wall
    extra = usage_from_console(out_dir)
    if extra:
        if not float(stats.get("cost") or 0) and extra.get("cost"):
            stats["cost"] = extra["cost"]
        toks = dict(stats.get("tokens") or {})
        changed = False
        if not int(toks.get("cache") or 0) and extra.get("cache"):
            toks["cache"] = extra["cache"]
            changed = True
        if not int(toks.get("in") or 0) and extra.get("in"):
            toks["in"] = extra["in"]
            changed = True
        if not int(toks.get("out") or 0) and extra.get("out"):
            toks["out"] = extra["out"]
            changed = True
        if changed:
            stats["tokens"] = toks
    brief = _read_json(out_dir / "brief.json") or {}
    try:
        from internal.pocsrc import enrich_findings, persist_poc

        findings = enrich_findings(out_dir, findings)
        persist_poc(out_dir, findings)
    except Exception:
        pass
    identities = _identities_for_report(out_dir)
    _replace_text(
        out_dir / "report.md",
        render_markdown(
            run_id=run_id,
            mode=mode,
            model=model,
            brief=brief,
            findings=findings,
            events=events,
            stats=stats,
            out_dir=out_dir,
            identities=identities,
        ),
    )
    _replace_text(
        out_dir / "report.json",
        json.dumps(
            render_json(
                run_id=run_id,
                mode=mode,
                model=model,
                brief=brief,
                findings=findings,
                events=events,
                stats=stats,
                out_dir=out_dir,
                identities=identities,
            ),
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
    )
    polished = False
    if polish:
        # La prosa (ejecutivo + narrativa) la escribe la IA con TODOS los hallazgos
        # actuales. El report.agent.md es solo borrador: si gana, omite fichas
        # indexadas al cierre (flags, ecos) y la historia queda incompleta.
        try:
            polished = polish_report_prose(out_dir, llm=llm)
        except Exception:
            polished = False
    if not polished:
        try:
            apply_agent_close_prose(out_dir)
        except Exception:
            pass
    _redact_report_file(out_dir, findings)


def load_findings(out_dir: Path) -> list[dict[str, Any]]:
    from internal.telemetry import coerce_flag_finding

    try:
        from internal.flagspec import sync_findings

        sync_findings(out_dir)
    except OSError:
        pass
    d = out_dir / "findings"
    items: list[dict[str, Any]] = []
    if not d.is_dir():
        return items
    seen: set[str] = set()
    paths = sorted(d.rglob("F-*.json"), key=lambda p: (len(p.relative_to(d).parts), str(p)))
    for path in paths:
        if not path.is_file():
            continue
        data = _read_json(path)
        if not isinstance(data, dict):
            continue
        data = fill_finding_identity(data, path)
        if not data.get("id"):
            continue
        if data.get("duplicate_of"):  # marcado por hostloop.dedup_findings
            continue
        if data.get("source") == "aegis-reserved":
            continue
        fid = str(data["id"])
        if fid in seen:
            continue
        seen.add(fid)
        items.append(coerce_flag_finding(data))
    items.sort(key=lambda f: (_SEV_ORDER.get(str(f.get("severity", "info")).lower(), 9), f.get("id", "")))
    return items


def _remap_finding_evidence(out_dir: Path, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from internal.telemetry import resolve_evidence_rel

    out: list[dict[str, Any]] = []
    for raw in findings:
        f = dict(raw)
        ev = f.get("evidence") or []
        if isinstance(ev, str):
            ev = [ev]
        fid = str(f.get("id") or "")
        f["evidence"] = [resolve_evidence_rel(out_dir, str(r), fid) or str(r) for r in ev]
        out.append(f)
    return out


def _live_report_ids(out_dir: Path) -> set[str]:
    findings = load_findings(out_dir)
    try:
        from internal.flagspec import finding_is_draft

        findings = [f for f in findings if not finding_is_draft(f)]
    except Exception:
        pass
    return {str(f.get("id")) for f in _reportable(findings) if f.get("id")}


def _snapshot_report_ids(data: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    for key in ("findings_proven", "findings_suspected"):
        for f in data.get(key) or []:
            if isinstance(f, dict) and f.get("id"):
                ids.add(str(f["id"]))
    return ids


def _snapshot_report_accounts(data: dict[str, Any]) -> set[str]:
    return {
        str(i.get("principal"))
        for i in (data.get("identities") or [])
        if isinstance(i, dict) and i.get("principal")
    }


def report_needs_refresh(out_dir: Path) -> bool:
    """True si el run ya cerró y el informe no coincide con findings/cuentas actuales."""
    meta = _read_json(out_dir / "meta.json") or {}
    if not isinstance(meta, dict) or str(meta.get("status") or "") != "ended":
        return False
    js = out_dir / "report.json"
    md = out_dir / "report.md"
    if not js.is_file() or not md.is_file():
        return True
    data = _read_json(js) or {}
    if not isinstance(data, dict):
        return True
    if _live_report_ids(out_dir) != _snapshot_report_ids(data):
        return True
    try:
        from internal.identities import public_identities

        now = {
            str(i.get("principal"))
            for i in public_identities(out_dir)
            if i.get("status") == "compromised" and i.get("principal")
        }
    except Exception:
        now = set()
    return now != _snapshot_report_accounts(data)


def refresh_report_if_stale(out_dir: Path, *, mode: str, model: str, run_id: str) -> bool:
    """Reescribe el informe desde el panel actual. Sin LLM. True si tocó disco."""
    if not report_needs_refresh(out_dir):
        return False
    ensure_reports(out_dir, mode=mode, model=model, run_id=run_id, polish=False)
    return True


def load_events(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def render_json(
    *,
    run_id: str,
    mode: str,
    model: str,
    brief: dict,
    findings: list[dict],
    events: list[dict],
    stats: dict,
    out_dir: Path | None = None,
    identities: list[dict] | None = None,
) -> dict[str, Any]:
    findings = _reportable(findings)
    proven, suspected, flags, defects = _split_findings(findings)
    ids = identities if identities is not None else _identities_for_report(out_dir)
    return {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "model": model,
        "scope": brief.get("targets") or [],
        "operator_note": brief.get("operator_note") or "",
        "executive_summary": _executive(mode, proven, suspected, stats, findings, identities=ids),
        "risk_rating": _risk_rating(proven),
        "findings_proven": [{**f, "remediation": _remediation(f)} for f in proven],
        "findings_suspected": [{**f, "remediation": _remediation(f)} for f in suspected],
        "identities": [
            {k: v for k, v in i.items() if k != "secret"}
            for i in ids
            if i.get("status") == "compromised"
        ],
        "counts": {
            "defects": len(defects),
            "flags": len(flags),
            "suspected": len(suspected),
            "accounts": sum(1 for i in ids if i.get("status") == "compromised"),
        },
        "timeline": _timeline(events),
        "surface": _surface(events, findings),
        "commands_that_mattered": _commands_that_mattered(events),
        "stats": stats,
        "limitations": _limitations(mode, events, out_dir),
        "evidence_index": [
            {"id": f.get("id"), "paths": f.get("evidence") or []} for f in findings
        ],
    }


def render_markdown(
    *,
    run_id: str,
    mode: str,
    model: str,
    brief: dict,
    findings: list[dict],
    events: list[dict],
    stats: dict,
    out_dir: Path,
    identities: list[dict] | None = None,
) -> str:
    try:
        from internal.pocsrc import enrich_findings

        findings = enrich_findings(out_dir, findings)
    except Exception:
        pass
    findings = _reportable(findings)
    proven, suspected, flags, defects = _split_findings(findings)
    ids = identities if identities is not None else _identities_for_report(out_dir)
    n_acct = sum(1 for i in ids if i.get("status") == "compromised")
    show_accounts = mode != "net" or bool(brief.get("exploit_mgmt"))
    targets = brief.get("targets") or []
    scope = "\n".join(
        f"- `{t.get('raw') or t.get('value')}` ({t.get('kind')})" for t in targets
    ) or "- (sin scope en brief)"
    model = _model_label(out_dir, model)
    exec_sum = _executive(
        mode,
        proven,
        suspected,
        stats,
        findings,
        identities=ids if show_accounts else [],
    )
    risk = _risk_rating(proven)
    cmds = _load_commands(out_dir, events)
    downloads = _extract_downloads(cmds)
    story = _story_clusters(proven, cmds)
    narrative = _narrative(mode, story, out_dir)
    table = _findings_table(findings)
    proven_md = "\n\n".join(_finding_audit(f, out_dir, cmds, downloads) for f in proven) or "_Ningún hallazgo demostrado._"
    recs = _recommendations(proven, identities=ids)
    anex = _appendix(out_dir, findings)
    toks = stats.get("tokens") or {}
    elapsed = stats.get("elapsed") or 0
    try:
        elapsed_h = f"{int(elapsed) // 3600}h {(int(elapsed) % 3600) // 60}m"
    except (TypeError, ValueError):
        elapsed_h = str(elapsed)
    if not int(stats.get("commands_count") or 0):
        stats["commands_count"] = len(cmds)
    if not int(stats.get("tools_count") or 0):
        names = {_tool_name(c.get("argv") or "") for c in cmds}
        stats["tools_count"] = len({n for n in names if n})
    tok_in = int(toks.get("in") or 0)
    tok_out = int(toks.get("out") or 0)
    cost = stats.get("cost") or 0
    try:
        cost_f = float(cost)
    except (TypeError, ValueError):
        cost_f = 0.0
    cost_s = f"{cost_f:.4f} USD" if cost_f else "no reportado"
    if suspected:
        sus_md = "\n\n".join(_finding_audit(f, out_dir, cmds, downloads) for f in suspected)
    else:
        sus_md = "_Ninguno._"
    id_md = _identities_md(ids)
    acct_row = f"| Cuentas comprometidas | {n_acct} |\n" if show_accounts else ""
    lead = (
        "Este documento describe la superficie de red demostrada desde el asiento, "
        "cómo se vio y cómo remediarla."
        if mode == "net"
        else (
            "Este documento describe lo que un atacante con el mismo scope pudo demostrar, "
            "cómo lo hizo y cómo remediarlo."
        )
    )
    sec3_title = "Narrativa de red" if mode == "net" else "Narrativa del ataque"
    sec3_lead = (
        "Una historia de visibilidad y misconfig de red. El detalle está en §4."
        if mode == "net"
        else "Una sola historia causal. El detalle (comandos, PoC, evidencia) está en §4, no se vuelve a copiar aquí."
    )
    sec5 = (
        f"## 5. Cuentas comprometidas\n\n{id_md}\n\n"
        if show_accounts
        else ""
    )
    md = f"""# Informe de auditoría de seguridad — `{run_id}`

| Campo | Valor |
|-------|-------|
| Fecha | {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")} |
| Clasificación | Confidencial — solo destinatarios autorizados |
| Modo | **{mode}** |
| Modelo | `{model}` |
| Duración | {elapsed_h} |
| Riesgo global | **{risk}** |
| Hallazgos (defectos / flags / hipótesis) | {len(defects)} / {len(flags)} / {len(suspected)} |
{acct_row}
{lead} Se genera al cierre (timeout, cancelación o flags CTF). No se inventa superficie que no esté en findings o evidencia. Las contraseñas no van en este markdown.

## 1. Resumen ejecutivo

{exec_sum}

### 1.1 Inventario de hallazgos

{table}

## 2. Alcance

- Autorización: engagement autorizado (Aegis).
- Activos:
{scope}
- Nota del operador: {brief.get("operator_note") or "(ninguna)"}
- Fuera de alcance: cualquier host no listado, DoS y acciones no cubiertas por el modo {mode}.

## 3. {sec3_title}

{sec3_lead}

{narrative}

## 4. Hallazgos demostrados

Ficha técnica de cada ID: fallo, prueba, loot, origen del PoC y remediación. No relee la narrativa. Las fichas `kind=flag` son cierre de contrato CTF, no un defecto aislado.

{proven_md}

{sec5}## 6. Hallazgos no demostrados por completo

{sus_md}

## 7. Recomendaciones priorizadas

{recs}

## 8. Métricas del engagement

- Tokens entrada / salida: {tok_in} / {tok_out}
- Coste reportado: {cost_s}
- Comandos / herramientas: {stats.get("commands_count", 0)} / {stats.get("tools_count", 0)}

## 9. Limitaciones

{_lim_md(mode, events, out_dir)}

## 10. Anexos (evidencia)

Rutas relativas a `data/runs/{run_id}/`. Un revisor debe poder repetir el hallazgo con estos archivos.

{anex}
"""
    return _redact_text(md, _secret_values(out_dir, findings))


def _is_empty_finding(f: dict) -> bool:
    """Cascarón sin contenido (título/summary/explain vacíos) o duplicado que el agente
    anotó en 'note'. No aporta nada al informe y salía como finding fantasma."""
    if not any(str(f.get(k) or "").strip() for k in ("title", "summary", "explain")):
        return True
    note = str(f.get("note") or "").strip().lower()
    if note.startswith("duplicado") or re.search(r"duplicad[oa] de f-\d+", note):
        return True
    return False


_ACCESS_ECHO = re.compile(
    r"ejecuci[oó]n remota de comandos|"
    r"sesi[oó]n de servicio activa|"
    r"no se trata de un login|"
    r"^rce(?:\s+como|\s*:\s*webshell)|"
    r"rce activa como",
    re.I,
)
_MECH_TOK = (
    "cve-", "next.js", "server action", "inspector", "sqlite", "deserial",
    "pickle", "middleware", "sudo", "suid", "cron", "kernel", "capabilit",
)


def _finding_users(f: dict) -> set[str]:
    blob = _finding_blob(f)
    users = {m.group(1).lower() for m in re.finditer(r"uid=\d+\(([^)]+)\)", blob)}
    for m in re.finditer(r"\b(?:como|usuario|user)\s+`?([a-z_][a-z0-9_-]{1,31})`?", blob, re.I):
        users.add(m.group(1).lower())
    title = str(f.get("title") or "")
    for m in re.finditer(r"\b([a-z_][a-z0-9_-]{1,31})@", title, re.I):
        users.add(m.group(1).lower())
    return {u for u in users if u not in {"www", "http", "the", "una", "del", "como"}}


def _is_access_echo(f: dict) -> bool:
    """Ficha que solo dice «hay una shell como X», sin el fallo que la hizo posible."""
    if str(f.get("kind") or "").lower() not in {"vuln", "cve", "info"}:
        return False
    blob = _finding_blob(f)
    if any(t in blob for t in _MECH_TOK):
        return False
    title = str(f.get("title") or "")
    src = str(f.get("source") or "")
    if src in {"aegis-evidence", "aegis-harvest", "aegis-reserved"} and _ACCESS_ECHO.search(
        f"{title} {blob}"
    ):
        return True
    return bool(_ACCESS_ECHO.search(title))


def _shadow_of(f: dict, others: list[dict]) -> str:
    """ID de la ficha rica que ya cubre el mismo acceso; vacío si f no es un eco."""
    if not _is_access_echo(f) and not _is_empty_finding(f):
        return ""
    host = _host_key(f)
    users = _finding_users(f)
    for o in others:
        if not isinstance(o, dict) or o.get("id") == f.get("id"):
            continue
        if _is_access_echo(o) or _is_empty_finding(o):
            continue
        if str(o.get("kind") or "").lower() not in {"vuln", "cve", "misconfig"}:
            continue
        oh = _host_key(o)
        if host and oh and host != oh:
            continue
        if users and not (users & _finding_users(o)):
            continue
        return str(o.get("id") or "")
    return ""


def _reportable(findings: list) -> list:
    base = [
        f
        for f in findings
        if isinstance(f, dict)
        and str(f.get("status") or "").lower() not in {"discarded", "void"}
        and not _is_empty_finding(f)
    ]
    drop = {str(f.get("id") or "") for f in base if _shadow_of(f, base)}
    return [f for f in base if str(f.get("id") or "") not in drop]


def mark_report_shadows(out_dir: Path) -> list[str]:
    """Marca en disco cascarones y ecos (duplicate_of) para que no salgan en UI ni informe."""
    d = out_dir / "findings"
    if not d.is_dir():
        return []
    items = [f for f in load_findings(out_dir) if isinstance(f, dict) and f.get("id")]
    marked: list[str] = []
    for f in items:
        fid = str(f.get("id") or "")
        parent = ""
        if _is_empty_finding(f):
            parent = next(
                (
                    str(o.get("id") or "")
                    for o in items
                    if o.get("id") != fid and not _is_empty_finding(o)
                ),
                "",
            )
        else:
            parent = _shadow_of(f, items)
        if not parent and not _is_empty_finding(f):
            continue
        path = d / f"{fid}.json"
        if not path.is_file():
            continue
        data = _read_json(path)
        if not isinstance(data, dict):
            continue
        data["duplicate_of"] = parent or data.get("duplicate_of") or fid
        if _is_empty_finding(f):
            data["status"] = "discarded"
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        marked.append(fid)
    return marked


_PASS_ASSIGN = re.compile(
    r"(?i)\b(?:password|passwd|db_password|secret)\s*[=:]\s*(\S{4,80})"
)


def _secret_values(out_dir: Path | None, findings: list) -> list[str]:
    found: set[str] = set()
    if out_dir is not None:
        eng = _read_json(out_dir / "engagement.json")
        if not isinstance(eng, dict):
            eng = {}
        for c in eng.get("creds") or []:
            if not isinstance(c, dict):
                continue
            s = str(c.get("secret") or "").strip()
            if s and s != "(sesión)" and len(s) >= 5:
                found.add(s)
        try:
            from internal.identities import extract_identities

            for row in extract_identities(out_dir, eng=eng):
                s = str(row.get("_secret") or "").strip()
                if s and len(s) >= 5:
                    found.add(s)
        except Exception:
            pass
    for f in findings:
        if not isinstance(f, dict):
            continue
        blob = " ".join(str(f.get(k) or "") for k in ("explain", "summary", "proof", "reproduction"))
        for m in _PASS_ASSIGN.finditer(blob):
            tok = m.group(1).strip(".,;\"'`")
            if len(tok) >= 5 and not re.fullmatch(r"[a-fA-F0-9]{32}", tok):
                found.add(tok)
    return sorted(found, key=len, reverse=True)


_SESSION_TOKEN = re.compile(
    r"(?i)\b(session|cookie)\s*[=:]\s*[A-Za-z0-9._\-]{16,}"
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]+=*(?:\.[A-Za-z0-9_\-=]+)+")


def _redact_text(text: str, secrets: list[str]) -> str:
    out = text or ""
    out = _SESSION_TOKEN.sub(lambda m: m.group(1) + "=[redactado]", out)
    out = _JWT.sub("[redactado]", out)
    for s in secrets:
        if not s:
            continue
        if re.fullmatch(r"[A-Za-z0-9._-]+", s):
            if s.isalpha() and len(s) <= 6:
                out = re.sub(
                    rf"(?i)(\b(?:user|password|passwd|usuario)\s*[=:]\s*){re.escape(s)}\b",
                    r"\1[redactado]",
                    out,
                )
                out = re.sub(
                    rf"(?<![A-Za-z0-9._-]){re.escape(s)}:{re.escape(s)}(?![A-Za-z0-9._-])",
                    "[redactado]:[redactado]",
                    out,
                )
                continue
            out = re.sub(
                rf"(?<![A-Za-z0-9._-]){re.escape(s)}(?![A-Za-z0-9_-]|\.[A-Za-z0-9])",
                "[redactado]",
                out,
            )
        elif s in out:
            out = out.replace(s, "[redactado]")
    return out


_PEM_BLOCK_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.S)
_PEM_STRAY_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[^`\n]*")


_PATH_Q_RE = re.compile(r"(?<![\w:/`])(/[A-Za-z0-9_./%\-]*\?[A-Za-z0-9_=&%.\-\[\]<>]+)")
_PATH_SEG_RE = re.compile(r"(?<![\w:/`])(/[A-Za-z][A-Za-z0-9_.\-]*(?:/[A-Za-z0-9_.<>\-]+)+)")


def _wrap_path(m: "re.Match") -> str:
    tok = m.group(1)
    trail = ""
    while tok and tok[-1] in ".,;:)":
        trail = tok[-1] + trail
        tok = tok[:-1]
    return f"`{tok}`" + trail if tok else m.group(0)


def _autocode_line(line: str) -> str:
    # Solo transforma los tramos que NO están ya entre backticks.
    parts = re.split(r"(`[^`]*`)", line)
    for i, seg in enumerate(parts):
        if seg.startswith("`"):
            continue
        seg = _PATH_Q_RE.sub(_wrap_path, seg)
        seg = _PATH_SEG_RE.sub(_wrap_path, seg)
        parts[i] = seg
    return "".join(parts)


def _autocode_md(text: str) -> str:
    """Formatea como código los endpoints/rutas que el modelo dejó en texto plano
    (`/greet?name=`, `/status?debug=1`, `/notes/view`). No toca headings, tablas,
    citas, bloques cercados ni lo que ya está entre backticks."""
    out: list[str] = []
    in_fence = False
    for line in text.split("\n"):
        s = line.lstrip()
        if s.startswith("```"):
            in_fence = not in_fence
            out.append(line)
            continue
        if in_fence or s.startswith("#") or s.startswith("|") or s.startswith(">"):
            out.append(line)
            continue
        out.append(_autocode_line(line))
    return "\n".join(out)


def _tidy_report_md(text: str) -> str:
    """Limpia el markdown del informe: nunca incrusta material de clave privada
    (ni entero ni el prefijo suelto que a veces cita el agente en la narrativa) y
    formatea como código los endpoints/rutas sueltos para uniformidad visual."""
    text = _PEM_BLOCK_RE.sub("[clave privada omitida]", text)
    text = _PEM_STRAY_RE.sub("[clave privada omitida]", text)
    text = _autocode_md(text)
    return text


def _redact_report_file(out_dir: Path, findings: list) -> None:
    path = out_dir / "report.md"
    if not path.is_file():
        return
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return
    red = _tidy_report_md(_redact_text(raw, _secret_values(out_dir, findings)))
    if red != raw:
        _replace_text(path, red)


def _vector_descartado(f: dict) -> bool:
    if str(f.get("status") or "").lower() in {"discarded", "void"}:
        return True
    title = str(f.get("title") or "").lower()
    explain = str(f.get("explain") or "").lower()
    return (
        "descartado" in title
        or "no es explotable" in explain
        or explain.startswith("ninguno por este vector")
    )


def _split_findings(findings: list) -> tuple[list, list, list, list]:
    findings = _reportable(findings)
    proven = [f for f in findings if f.get("status") == "proven"]
    suspected = [f for f in findings if f.get("status") != "proven"]
    flags = [f for f in proven if str(f.get("kind") or "").lower() == "flag"]
    defects = [f for f in proven if str(f.get("kind") or "").lower() != "flag"]
    return proven, suspected, flags, defects


def _identities_for_report(out_dir: Path | None) -> list[dict]:
    if out_dir is None:
        return []
    try:
        from internal.identities import public_identities

        return public_identities(out_dir)
    except Exception:
        return []


def _identities_md(identities: list[dict]) -> str:
    got = [i for i in identities if isinstance(i, dict) and i.get("status") == "compromised"]
    if not got:
        return "_Ninguna cuenta persistida en disco._"
    lines = [
        "Inventario al cierre. Este markdown no incluye secretos; "
        "el operador los ve pinchando la cuenta en la pestaña Cuentas.",
        "",
    ]
    for it in got:
        p = str(it.get("principal") or "—")
        host = str(it.get("host") or "").strip()
        ip = str(it.get("ip") or "").strip()
        if host and ip and host != ip:
            where = f"{host} · {ip}"
        else:
            where = host or ip or "—"
        via = str(it.get("via") or "—")
        priv = str(it.get("priv") or "user")
        fid = str(it.get("finding") or "—")
        if it.get("has_secret"):
            secret_lab = "contraseña **obtenida**"
        else:
            secret_lab = "contraseña **no obtenida** (sesión o sin login)"
        how = str(it.get("how") or "").strip()
        lines.append(
            f"- **`{p}`** en `{where}` — vía `{via}`, privilegio `{priv}`, "
            f"hallazgo `{fid}`. {secret_lab}."
            + (f" {how}" if how else "")
        )
    return "\n".join(lines)


def _executive(
    mode: str,
    proven: list,
    suspected: list,
    stats: dict,
    findings: list,
    identities: list | None = None,
) -> str:
    defects = [f for f in proven if str(f.get("kind") or "").lower() != "flag"]
    crit = sum(1 for f in defects if f.get("severity") == "critical")
    highs = sum(1 for f in defects if f.get("severity") == "high")
    flags = [f for f in proven if str(f.get("kind") or "").lower() == "flag"]
    if not proven and not suspected:
        return (
            f"En modo {mode} no se indexó ningún hallazgo. No se puede afirmar compromiso "
            "ni ausencia de riesgo. Revisar consola y events.jsonl."
        )
    if flags:
        bits = [
            f"Se demostraron **{len(defects)}** defectos ({crit} críticos, {highs} altos) "
            f"y **{len(flags)}** flags de cierre CTF; quedaron {len(suspected)} como hipótesis."
        ]
        bits.append(
            "Flags: " + ", ".join(f"`{f.get('id')}`" for f in flags) + "."
        )
    else:
        bits = [
            f"Se demostraron **{len(proven)}** hallazgos ({crit} críticos, {highs} altos) "
            f"y quedaron {len(suspected)} como hipótesis."
        ]
    chain_ids = []
    causal_nodes = [
        f
        for f in proven
        if not _is_inventory(f)
        and (
            str(f.get("kind") or "").lower() in {"vuln", "cve", "misconfig"}
            or (str(f.get("kind") or "").lower() == "flag" and not _is_pure_capture(f))
        )
    ]
    for f in _causal_order(causal_nodes):
        fid = f.get("id")
        if fid and fid not in chain_ids:
            chain_ids.append(fid)
    if chain_ids:
        bits.append("Cadena (IDs, orden causal): " + " → ".join(f"`{i}`" for i in chain_ids[:8]) + ".")
    n_acct = sum(
        1
        for i in (identities or [])
        if isinstance(i, dict) and i.get("status") == "compromised"
    )
    if n_acct:
        bits.append(
            f"Cuentas comprometidas: **{n_acct}** (detalle en §5; las contraseñas no van en este markdown)."
        )
    bits.append("La historia va en §3; el detalle técnico (prueba, PoC, remediación) en §4.")
    return " ".join(bits)


def _risk_rating(proven: list) -> str:
    sevs = {str(f.get("severity") or "") for f in proven}
    if "critical" in sevs:
        return "Crítico"
    if "high" in sevs:
        return "Alto"
    if "medium" in sevs:
        return "Medio"
    if proven:
        return "Bajo"
    return "Indeterminado"


def _findings_table(findings: list) -> str:
    if not findings:
        return "_Sin hallazgos._"
    rows = [
        "| ID | Severidad | Tipo | Estado | Activo | Título |",
        "|----|-----------|------|--------|--------|--------|",
    ]
    for f in findings:
        rows.append(
            f"| `{f.get('id')}` | {f.get('severity') or '—'} | {f.get('kind') or '—'} | "
            f"{f.get('status') or '—'} | `{f.get('asset') or '—'}` | {f.get('title') or '—'} |"
        )
    return "\n".join(rows)


# Tokens que delatan que un finding kind=flag NO es una simple captura sino un
# ESLABÓN causal (reutilización de credenciales, RCE, privesc…). Esos van como
# eslabón; las capturas puras (user.txt/root.txt "capturada") cuelgan como loot.
_CAUSAL_FLAG_TOK = (
    "reutiliz", "credential", "reuse", "rce", "deserial", "sqli", "lfi", "rfi",
    "ssrf", "xxe", "inspector", "privesc", "escalad", "sudo", "suid", "cron",
    "upload", "inyec", "injection", "bypass", "traversal", "kerberos", "webshell",
    "command inj", "foothold",
)

# Título que delata una CAPTURA de flag (aunque el explain narre el cómo: "tras
# crackear el hash", "vía el Node Inspector (F-010)"). Manda el título: si LIDERA con
# "Flag de usuario/root …" o dice "user.txt capturada", es captura, no eslabón.
_FLAG_CAPTURE_TITLE = re.compile(
    r"^\s*flag\s+de\s+(usuario|root|user|sistema)"
    r"|captur\w+\s+(la\s+)?flag"
    r"|\bflag\b[^.]*\(?(user|root|flag)\.txt"
    r"|(user|root|flag)\.txt\)?\s*captur"
    r"|^\s*(user|root|flag)\.txt\b",
    re.I,
)


def _is_pure_capture(f: dict) -> bool:
    """Flag que solo documenta la captura (user.txt/root.txt), aunque mencione el fallo
    que la hizo posible. Cuelga como loot del eslabón causal; NO es eslabón por sí misma
    (si lo fuera, el orden por tiempo de escritura la pone al principio, antes que la RCE
    que se redacta al cierre → narrativa invertida). El título manda; si no es de captura,
    se cae a tokens/CVE (una flag con título de vuln, p. ej. reutilización, es eslabón)."""
    if str(f.get("kind") or "").lower() != "flag":
        return False
    if _FLAG_CAPTURE_TITLE.search(str(f.get("title") or "")):
        return True
    blob = _finding_blob(f)
    if _CVE_RE.search(blob):
        return False
    return not any(t in blob for t in _CAUSAL_FLAG_TOK)


def _is_root_flag(f: dict) -> bool:
    # Solo título/asset/evidencia: el explain de una flag de USUARIO suele decir "sin
    # privilegios de root todavía" y disparaba un falso positivo de root.
    hay = " ".join(str(f.get(k) or "") for k in ("id", "title", "asset")).lower()
    hay += " " + " ".join(str(x).lower() for x in (f.get("evidence") or []))
    if "root.txt" in hay:
        return True
    if "user.txt" in hay or "flag de usuario" in hay or "flag.txt" in hay:
        return False
    return bool(re.search(r"\broot\b", hay))


def _host_key(f: dict) -> str:
    asset = str(f.get("asset") or "")
    m = re.search(r"\d{1,3}(?:\.\d{1,3}){3}", asset)
    if m:
        return m.group(0)
    m = re.search(r"host:([^\s/]+)", asset)
    return m.group(1) if m else ""


def _causal_order(leads: list[dict]) -> list[dict]:
    """Ordena eslabones por la CADENA causal real, no por el timestamp de escritura.
    En CTF los findings de vuln se redactan al cierre —después de las flags—, así que
    ordenar por tiempo invierte la historia. Señal robusta: las referencias cruzadas de
    IDs que escribe el propio agente ("vía la RCE (F-001)", "obtenido en F-002"). Se hace
    un orden topológico (prerequisito antes que quien lo cita); empate o sin referencias:
    (timestamp, id). Genérico, no por caja."""
    ids = {str(f.get("id")): f for f in leads if f.get("id")}
    if len(ids) <= 1:
        return list(leads)
    blob = {i: _finding_blob(ids[i]) for i in ids}
    adj: dict[str, set[str]] = {i: set() for i in ids}
    indeg: dict[str, int] = {i: 0 for i in ids}
    for i in ids:
        for j in ids:
            if i == j:
                continue
            # i cita a j  =>  j es prerequisito  =>  j antes que i  (arista j->i).
            if re.search(rf"(?<![A-Za-z0-9]){re.escape(j)}(?![0-9])", blob[i], re.I):
                if i not in adj[j]:
                    adj[j].add(i)
                    indeg[i] += 1

    def key(i: str) -> tuple:
        # Sin referencia que lo fije, el desempate es la NUMERACIÓN del finding, no el
        # timestamp de escritura: el agente numera en orden de cadena (F-001 entrada →
        # … → F-010 privesc), mientras que las vulns se redactan al cierre en cualquier
        # orden. El timestamp queda de tercer criterio.
        m = re.search(r"(\d+)", i)
        num = int(m.group(1)) if m else 10**9
        ts = _parse_ts(str(ids[i].get("timestamp") or ""))
        return (num, ts or datetime.max.replace(tzinfo=timezone.utc), i)

    ready = sorted((i for i in ids if indeg[i] == 0), key=key)
    order: list[str] = []
    while ready:
        cur = ready.pop(0)
        order.append(cur)
        newly = []
        for k in adj[cur]:
            indeg[k] -= 1
            if indeg[k] == 0:
                newly.append(k)
        if newly:
            ready.extend(newly)
            ready.sort(key=key)
    if len(order) < len(ids):  # ciclo/resto: por (timestamp, id)
        for i in sorted(ids, key=key):
            if i not in order:
                order.append(i)
    ordered = [ids[i] for i in order]
    ordered += [f for f in leads if not f.get("id")]  # sin id (raro): al final
    return ordered


def _story_clusters(proven: list[dict], cmds: list[dict]) -> list[dict]:
    """Cadena causal para la narrativa: eslabones (vuln/cve/misconfig y flags causales)
    en orden causal, con las capturas puras colgadas del eslabón que las produjo. No se
    ordena por el timestamp de escritura (invertía la historia: flags antes que la RCE)."""
    captures = [f for f in proven if _is_pure_capture(f)]
    cap_ids = {id(f) for f in captures}
    leads = [f for f in proven if id(f) not in cap_ids]
    if not leads:  # solo flags: no hay eslabón donde colgarlas; cada una es su cluster
        leads, captures = captures, []
    leads_ordered = _causal_order(leads)
    clusters = [{"lead": lead, "loot": []} for lead in leads_ordered]

    _ROOT_RE = re.compile(r"root|privesc|escalad|inspector|sudo|suid|kernel|capabilit", re.I)
    _USER_RE = re.compile(
        r"ssh|login|credencial|credential|reuse|reutiliz|foothold|\brce\b|webshell", re.I
    )

    def _target_for(cap: dict) -> dict:
        # 1) CVE compartido explícito (misma vuln): cuélgala de ese eslabón.
        cves = {m.group(0).upper() for m in _CVE_RE.finditer(_finding_blob(cap))}
        if cves:
            for cl in clusters:
                if any(c in _finding_blob(cl["lead"]).upper() for c in cves):
                    return cl
        # 2) Scoring por ROL (root.txt→privesc, user.txt→acceso) + host, sin filtro
        #    duro: un servicio de privesc suele exponerse en loopback (127.0.0.1), así
        #    que un host distinto NO descarta el eslabón. Una flag de USUARIO no cuelga
        #    del paso de privesc (penalización). Desempate: posición en la cadena (más
        #    tarde gana → la flag la captura el último paso relevante de su rol).
        host = _host_key(cap)
        is_root = _is_root_flag(cap)
        role_re = _ROOT_RE if is_root else _USER_RE
        best, best_key = None, None
        for idx, cl in enumerate(clusters):
            blob = _finding_blob(cl["lead"])
            score = 3 if role_re.search(blob) else 0
            if not is_root and _ROOT_RE.search(blob):
                score -= 2  # user.txt no se captura en el eslabón de escalada a root
            lh = _host_key(cl["lead"])
            if not host or lh == host or lh in ("127.0.0.1", "localhost", ""):
                score += 1
            cand_key = (score, idx)
            if best_key is None or cand_key > best_key:
                best_key, best = cand_key, cl
        return best or clusters[-1]

    for cap in captures:
        _target_for(cap)["loot"].append(cap)
    return clusters


def _field_text(v: Any) -> str:
    """Coacciona un campo de finding a texto legible. El agente a veces escribe proof/
    reproduction/impact como DICT (p. ej. {command, output, response_status}) o lista;
    sin esto, un .strip() directo rompía la generación del informe."""
    if v is None:
        return ""
    if isinstance(v, str):
        return v.strip()
    if isinstance(v, dict):
        order = ("command", "cmd", "request", "payload", "url", "output", "response",
                 "response_status", "status", "response_header", "note", "detail")
        parts = [f"{k}: {v[k]}" for k in order if v.get(k) not in (None, "")]
        if not parts:
            parts = [f"{k}: {val}" for k, val in v.items() if val not in (None, "")]
        return " · ".join(str(p) for p in parts).strip()
    if isinstance(v, (list, tuple)):
        return " ".join(_field_text(x) for x in v).strip()
    return str(v).strip()


def _finding_prose(f: dict) -> str:
    """Texto del hallazgo: explain en español manda si el summary está en inglés."""
    from internal.flagspec import _looks_english

    explain = _field_text(f.get("explain"))
    summary = _field_text(f.get("summary"))
    if explain and (not summary or (_looks_english(summary) and not _looks_english(explain))):
        return explain
    return summary or explain or "—"


def _finding_blob(f: dict) -> str:
    return " ".join(
        str(f.get(k) or "")
        for k in ("id", "title", "asset", "summary", "explain", "proof", "kind")
    ).lower()


def _is_inventory(f: dict) -> bool:
    if str(f.get("kind") or "").lower() == "info":
        return True
    blob = _finding_blob(f)
    return any(
        x in blob
        for x in (
            "operador suministr",
            "cuenta de inventario",
            "provided by the operator",
            "source operator",
        )
    )


def _keep_agent_report(out_dir: Path) -> None:
    src = out_dir / "report.md"
    if not src.is_file() or src.stat().st_size < 200:
        return
    try:
        head = src.read_text(encoding="utf-8", errors="replace")[:800]
    except OSError:
        return
    if "Este informe fallback se genera" in head:
        return
    dest = out_dir / "report.agent.md"
    if dest.is_file() and dest.stat().st_size > 40:
        return
    try:
        shutil.copy2(src, dest)
    except OSError:
        try:
            dest.write_text(src.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
        except OSError:
            return


def _narrative(mode: str, story: list[dict], out_dir: Path) -> str:
    if mode == "recon":
        return "Modo recon: no hay narrativa de explotación, solo inventario e hipótesis."
    if mode == "net" and not story:
        return "Modo Red: narrativa de visibilidad y misconfig de red, no de explotación de apps."
    if not story:
        return "No hay cadena demostrada en disco."
    parts = []
    for i, cl in enumerate(story, 1):
        lead = cl["lead"]
        loot = cl.get("loot") or []
        ids = [str(lead.get("id") or "")] + [str(x.get("id") or "") for x in loot]
        ids = [x for x in ids if x]
        explain = _finding_prose(lead)
        if explain == "—":
            explain = str(lead.get("title") or "—").strip()
        result = ""
        proof = str(lead.get("proof") or "")
        if "→" in proof:
            result = proof.split("→", 1)[1].strip()
        if not result:
            result = _result_line(lead, out_dir)
        # No repetir: si el "resultado" es lo mismo que el explain (o está contenido
        # en él), no se añade la frase "Resultado:" para no duplicar la línea.
        res_n = result.strip().rstrip(".").lower()
        exp_n = explain.strip().rstrip(".").lower()
        show_result = bool(res_n) and res_n not in exp_n and exp_n not in res_n
        loot_bit = ""
        if loot:
            loot_bit = " Impacto directo: " + "; ".join(
                f"`{x.get('id')}` {(x.get('title') or '').split(' via ')[0]}"
                for x in loot
            ) + "."
        nxt = story[i]["lead"] if i < len(story) else None
        bridge = ""
        if nxt:
            prev = str(lead.get("id") or "").lower()
            if prev and prev in _finding_blob(nxt):
                bridge = f" Siguiente eslabón: `{nxt.get('id')}`."
        head = (
            f"{i}. **{lead.get('title') or lead.get('id')}** "
            f"({', '.join(f'`{x}`' for x in ids)}). {explain.rstrip('.')}."
        )
        result_bit = f" Resultado: {result.rstrip('.')}." if show_result else ""
        parts.append(head + result_bit + loot_bit + bridge)
    return "\n\n".join(parts)


def _finding_audit(f: dict, out_dir: Path, cmds: list[dict] | None = None, downloads: list[dict] | None = None) -> str:
    cmds = cmds or []
    downloads = downloads or []
    explain = _finding_prose(f)
    proof = _field_text(f.get("proof")) or _field_text(f.get("reproduction")) or "—"
    impact = _field_text(f.get("impact"))
    rem = _remediation(f)
    related = _related_commands(f, cmds, limit=4)
    tools = _tools_used(related, f)
    tools_md = ", ".join(f"**{name}** ({why})" for name, why in tools.items()) if tools else "las del `proof`"
    cmds_md = (
        "\n".join(f"- `{_compact_argv(c.get('argv') or '')}`" for c in related)
        if related
        else "- _(sin comando distinto del proof)_"
    )
    poc_md = _poc_origin(f, out_dir, related, downloads)
    loot_md = _loot_line(f, out_dir)
    got = impact
    if loot_md:
        got = f"{impact} {loot_md}".strip() if impact else loot_md
    if not got:
        got = "—"
    ev_rels = _pick_evidence(f)
    ev_lines = []
    for rel in ev_rels:
        snippet = _evidence_snippet(out_dir, rel, limit=12)
        ev_lines.append(f"**`{rel}`**\n\n```\n{snippet}\n```")
    ev_block = "\n\n".join(ev_lines) if ev_lines else "_Sin archivos de evidencia._"
    kind = str(f.get("kind") or "").lower()
    is_flag = kind == "flag"
    scripts = _finding_scripts(f, out_dir)
    title_l = str(f.get("title") or "").lower()
    if is_flag:
        what = "**Qué se capturó.**"
        bits = [explain]
        if any(x in title_l for x in ("ssh", "login", "acceso")):
            bits.append(
                "El título mezcla el acceso (cuenta o servicio) con el flag de cierre CTF; "
                "el defecto de autenticación o reutilización es el hallazgo de acceso, no el fichero de flag."
            )
        if "root.txt" in title_l or "root.txt" in explain.lower():
            if scripts:
                bits.append(
                    "La vía de escalada no está redactada en esta ficha: ver "
                    + ", ".join(f"`{s}`" for s in scripts[:6])
                    + "."
                )
            else:
                bits.append("Cierra el slot root del contrato CTF.")
        explain_out = " ".join(x for x in bits if x and x != "—")
        copyish = proof == "—" or bool(re.match(r"(?i)^copiar\s+`", proof))
        if copyish:
            if scripts:
                proof_md = (
                    "Captura del flag (el `proof` no describe la explotación). "
                    "Artefactos de la vía: " + ", ".join(f"`{s}`" for s in scripts[:6]) + "."
                )
            else:
                proof_md = (
                    "Captura del flag en disco (loot / findings). "
                    "No hay comando de explotación en el `proof`."
                )
        else:
            proof_md = f"`{proof}`"
    else:
        what = "**Qué falló.**"
        explain_out = explain
        proof_md = f"`{proof}`"
    return (
        f"### {f.get('id')} — {f.get('title') or '(sin título)'}\n\n"
        f"| Severidad | Tipo | Estado | Activo |\n"
        f"|-----------|------|--------|--------|\n"
        f"| {f.get('severity')} | {f.get('kind')} | {f.get('status')} | `{f.get('asset') or '—'}` |\n\n"
        f"{what} {explain_out}\n\n"
        f"**Prueba.** {proof_md}\n\n"
        f"**Comandos clave.**\n\n{cmds_md}\n\n"
        f"**Impacto.** {got}\n\n"
        f"**Herramientas.** {tools_md}\n\n"
        f"**PoC / artefactos.** {poc_md}\n\n"
        f"**Remediación.** {rem}\n\n"
        f"**Evidencia.**\n\n{ev_block}\n"
    )


def _pick_evidence(f: dict) -> list[str]:
    rels = [str(x) for x in (f.get("evidence") or []) if x]
    if len(rels) <= 2:
        return rels
    prefer = ("user.txt", "root.txt", "proof", "version", "status", "suid", "req-bypass")
    ranked = []
    for rel in rels:
        name = Path(rel).name.lower()
        score = 0
        for i, key in enumerate(prefer):
            if key in name:
                score = 20 - i
                break
        ranked.append((score, rel))
    ranked.sort(key=lambda x: -x[0])
    return [r for _, r in ranked[:2]]


def _remediation(f: dict) -> str:
    if _vector_descartado(f):
        return "Ninguna: el vector se descartó; no hay defecto que remediar en este ID."
    # remediación del agente si es concreta
    own = str(f.get("remediation") or "").strip()
    if own and len(own) > 40 and "parche o control que elimine" not in own.lower():
        return own
    # si no, guía por clase (sin producto/CVE de lab)
    blob = " ".join(
        str(f.get(k) or "") for k in ("id", "title", "summary", "explain", "kind", "asset")
    ).lower()
    if f.get("kind") == "flag":
        return (
            "La flag es prueba de impacto, no un defecto aislado. Cierra los hallazgos "
            "de la cadena que la hicieron posible (ver IDs relacionados) y rota secretos "
            "si el atacante leyó datos sensibles."
        )
    if "ssh" in blob and any(
        x in blob for x in ("authorized_keys", "persistencia", "clave inyectada", "clave pública")
    ):
        return (
            "Revocar las claves SSH no autorizadas, auditar authorized_keys y cerrar "
            "el vector que permitió escribirlas. Rotar las claves del auditor si siguen en el host."
        )
    head = " ".join(str(f.get(k) or "") for k in ("title", "summary", "kind")).lower()
    if any(x in head for x in ("xss", "cross-site scripting", "scripting cruzado")):
        return (
            "Escapar o sanitizar la salida HTML según el contexto. No emitir entrada "
            "del usuario con `|safe` ni concatenarla en el DOM; CSP que bloquee scripts en línea."
        )
    if any(x in blob for x in ("ssti", "template injection", "inyección de plantilla", "jinja2", "jinja")):
        return (
            "No evaluar entrada del usuario como plantilla. Autoescape o sandbox; "
            "plantillas precompiladas, nunca `render_template_string` con datos del cliente."
        )
    if any(x in blob for x in ("directorio de personal", "/staff")) and "staff" in blob:
        return (
            "Exigir autenticación en el directorio de personal y no publicar correos "
            "ni pistas a endpoints internos. El listado de empleados no es un recurso público."
        )
    if any(
        x in blob
        for x in (
            "debug=1",
            "secret_key",
            "information disclosure",
            "status?debug",
        )
    ) or (
        "divulgación" in blob
        and any(x in blob for x in ("debug", "secret_key", "/status", "endpoint"))
    ):
        return (
            "No exponer secretos ni listados de usuarios en endpoints de estado. "
            "Desactivar debug en producción; el SECRET_KEY solo vive en el servidor."
        )
    head = " ".join(str(f.get(k) or "") for k in ("title", "summary", "kind")).lower()
    if any(
        x in head
        for x in (
            "credenciales débiles",
            "credenciales por defecto",
            "default cred",
            "password default",
            "contraseña trivial",
        )
    ):
        return (
            "Prohibir contraseñas por defecto o triviales. Forzar rotación al primer "
            "arranque, complejidad mínima y bloqueo tras fallos."
        )
    if "redis" in blob and any(
        x in blob for x in ("sin autentic", "unauth", "requirepass", "sin credencial")
    ):
        return (
            "Exigir autenticación en Redis (ACL o requirepass), no publicar el puerto "
            "en 0.0.0.0 sin red de confianza y desactivar comandos peligrosos (CONFIG/FLUSH)."
        )
    if any(
        x in blob
        for x in (
            "tinymce",
            "file upload",
            "unrestricted upload",
            "arbitrary upload",
            "subida sin filtr",
            "subida de fichero",
            "upload sin valid",
            "/tinymce/upload",
            "tinymce/upload",
        )
    ):
        return (
            "Validar tipo, contenido y extensión de los ficheros subidos; "
            "guardarlos fuera del document root y servirlos sin ejecución. "
            "Desactivar plugins de editor que acepten HTML/PHP arbitrario y parchear el componente de carga."
        )
    if (
        ".git" in blob
        or "git historial" in blob
        or "historial de git" in blob
        or ("git" in blob and (".env" in blob or "historial" in blob or "gitea" in blob))
    ):
        return (
            "No exponer `.git` ni el historial de un repositorio con secretos. "
            "Quitar el path del vhost, rotar las credenciales que hayan vivido en commits "
            "y reescribir o archivar el historial si el repo sigue público."
        )
    if "ssrf" in blob:
        return (
            "Dejar de pedir URLs arbitrarias desde el servidor. Allowlist de destinos "
            "(solo orígenes de negocio). Rechazar loopback y redes privadas en **todas** "
            "las formas (127.1, 0.0.0.0, decimal, hex, IPv6 mapeado, DNS a 127.0.0.0/8). "
            "No seguir redirects. Timeout corto y sin FTP/file/gopher. Validar en red, no solo con string match."
        )
    if any(x in blob for x in ("deserial", "pickle", "yaml.load", "unmarshal", "insecure deserial")):
        return (
            "No deserializar datos no confiables con constructores que ejecuten código "
            "(usar cargadores seguros / listas de tipos permitidos). Firmar o validar el "
            "origen del payload y aislar el proceso que lo procesa."
        )
    if any(x in blob for x in ("command injection", "inyección de comandos", "shell=true", "os.system", "job_name")) or re.search(
        r"\brce\b", blob
    ):
        return (
            "No interpolar entrada del usuario en un shell. Ejecutar con lista de "
            "argumentos (sin `shell=True`), validar contra un allowlist y minimizar los "
            "privilegios del proceso que ejecuta el comando."
        )
    if any(x in blob for x in ("path travers", "lfi", "directory travers", "../", "arbitrary file")):
        return (
            "Anclar las rutas al directorio permitido con `realpath` y comprobar que el "
            "resultado sigue bajo él. Denegar `..` y rutas absolutas; separar lectura de "
            "escritura y no exponer ficheros fuera del jail."
        )
    if "sqli" in blob or "sql injection" in blob or "inyección sql" in blob:
        return (
            "Usar consultas parametrizadas / ORM; nunca concatenar entrada en SQL. "
            "Aplicar mínimo privilegio en la cuenta de base de datos y validar tipos."
        )
    if any(x in blob for x in ("nfs", "showmount", "no_root_squash", "smb share", "world-readable", "mundo-legible")):
        return (
            "Cerrar el recurso compartido anónimo: lista de clientes, root_squash/permisos "
            "restrictivos y autenticación. No dejar documentos con secretos en un share "
            "legible por todos. Rotar las credenciales filtradas."
        )
    if any(x in blob for x in ("password reuse", "credential reuse")) or ("reutilizaci" in blob and "contrase" in blob):
        return (
            "Prohibir reutilización de contraseñas entre cuentas. Forzar rotación, "
            "contraseñas únicas y MFA. No distribuir credenciales en documentos compartidos."
        )
    if any(x in blob for x in ("dmsa", "badsuccessor", "delegated managed service", "kerberos", "acl abuse", "generic all", "genericall")):
        return (
            "Revisar y minimizar ACLs sobre cuentas y objetos privilegiados del directorio "
            "(WRITE_PROPERTY/CREATE_CHILD/GenericAll no justificados). Aplicar los parches "
            "del proveedor y auditar objetos huérfanos o mal delegados."
        )
    if any(x in blob for x in ("hashdump", "lsass", "memory dump", "vmem")) or re.search(
        r"(?<![a-z])sam(?![a-z])", blob
    ):
        return (
            "No dejar volcados de memoria/SAM ni backups accesibles por cuentas no admin. "
            "Rotar los hashes extraídos, cifrar los backups y restringir quién puede leerlos."
        )
    if any(
        x in blob
        for x in (
            "samesite",
            "content-security",
            "cabeceras de seguridad",
            "security header",
            "sin csrf",
            "missing csrf",
        )
    ):
        return (
            "Fijar cookies con Secure, HttpOnly y SameSite; tokens CSRF en mutaciones; "
            "cabeceras CSP, HSTS, X-Frame-Options y X-Content-Type-Options. No publicar "
            "el banner del runtime."
        )
    if any(x in blob for x in ("sudo", "suid", "cron", "capabilit", "privilege escal")):
        return (
            "Revisar sudoers, binarios SUID, capabilities y cron del usuario comprometido. "
            "Quitar binarios con owner root y bit SUID no justificados. Rotar credenciales "
            "leídas en disco."
        )
    if any(x in blob for x in ("container", "docker.sock", "escape", "namespace")):
        return (
            "No exponer el socket del runtime de contenedores ni montar rutas sensibles del "
            "host. Ejecutar sin privilegios extra ni capabilities innecesarias y aislar el "
            "plano de orquestación del workload."
        )
    if "error 500" in blob and "path" in blob or "stack trace" in blob or "traceback" in blob:
        return (
            "No incluir rutas de filesystem ni trazas en errores hacia el cliente. Páginas "
            "de error genéricas y logging solo del lado servidor."
        )
    return (
        "Aplicar el parche o control que elimine la causa raíz, verificar con el mismo "
        "comando de prueba (`proof`) y documentar el cambio. Priorizar si la severidad "
        "es critical/high."
    )


_GENERIC_REMED = "Aplicar el parche o control que elimine la causa raíz"


def _recommendations(proven: list, identities: list | None = None) -> str:
    if not proven:
        return "_Sin recomendaciones: no hay hallazgos demostrados._"
    actionable = [
        f
        for f in proven
        if str(f.get("kind") or "").lower() != "flag" and not _vector_descartado(f)
    ] or proven
    seen: list[str] = []
    for f in actionable:
        r = _remediation(f)
        if r not in seen:
            seen.append(r)
    specific = [r for r in seen if _GENERIC_REMED not in r]
    if specific:
        seen = specific
    got = [i for i in (identities or []) if isinstance(i, dict) and i.get("status") == "compromised"]
    extra: list[str] = []
    if any(i.get("has_secret") for i in got):
        extra.append(
            "Rotar todas las contraseñas obtenidas (y las reutilizadas entre git, aplicaciones y SSH) "
            "y exigir MFA o secretos únicos por servicio."
        )
    service = {"www-data", "apache", "nginx", "mysql", "postgres", "tomcat"}
    if any(
        i.get("via") == "webshell"
        and (
            str(i.get("priv") or "") == "service"
            or str(i.get("principal") or "").lower() in service
        )
        for i in got
    ):
        extra.append(
            "Invalidar la sesión de servicio (www-data u otra) y cerrar el vector de carga que dio RCE."
        )
    if any(i.get("via") == "ssh" and not i.get("has_secret") for i in got):
        extra.append(
            "Revocar authorized_keys no autorizadas y rotar las claves que el auditor dejó en el host."
        )
    for r in extra:
        if r not in seen:
            seen.append(r)
    return "\n".join(f"{i}. {r}" for i, r in enumerate(seen, 1))


_SKIP_EV = re.compile(
    r"(?i)^(progress:\s|\[\*\] creating missing|\[\*\] initializing|"
    r"\[\*\] copying default|\[\*\] scanning |scanning (filelayer|layer_name))"
)
_HIT_EV = re.compile(
    r"(?i)(\[\+\]|pwn3d|nthash|administrator\s+\d+|user\.txt|root\.txt|"
    r"FLAG\{|CTF\{|[0-9a-f]{32}\b|READ,WRITE|CREATE_CHILD|WRITE_PROPERTY)"
)


def _evidence_snippet(out_dir: Path, rel: str, limit: int = 12) -> str:
    path = out_dir / rel
    if not path.is_file():
        return "(archivo no encontrado en disco)"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "(no se pudo leer)"
    if re.search(r"BEGIN (?:OPENSSH|RSA|DSA|EC) PRIVATE KEY", text):
        return "[clave privada omitida del informe; el fichero está en disco]"
    lines = [ln for ln in text.replace("\x00", "").splitlines() if ln.strip()]
    useful = [ln for ln in lines if not _SKIP_EV.search(ln)]
    if not useful:
        useful = lines or [""]
    hits = [ln for ln in useful if _HIT_EV.search(ln)]
    pick = hits[:limit] if hits else useful[:limit]
    clip = "\n".join(pick)
    if len(useful) > len(pick):
        clip += "\n…"
    return clip[:4000]


def _appendix(out_dir: Path, findings: list) -> str:
    rows = []
    for f in findings:
        for p in f.get("evidence") or []:
            rows.append(f"- `{f.get('id')}` → `{p}`")
    return "\n".join(rows) or "- (sin anexos)"


def _lim_md(mode: str, events: list, out_dir: Path | None = None) -> str:
    return "\n".join(f"- {x}" for x in _limitations(mode, events, out_dir))


_SKIP_ARGV = re.compile(
    r"^(ls\b|mkdir\b|true\b|type\b|which\b|command -v\b|pwd\b|ip route\b|"
    r"cat /etc/resolv|head\b|wc\b|echo ALIVE|echo '|echo \"|export |cp |# |"
    r"printf |tee |cd |date\b|sha256sum\b|mv |chmod |cat /etc/hosts|"
    r"grep --help|searchsploit --help)"
)
_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# Escrituras del cuaderno (no son el probe). Cubre cat>/>> a report/STATE y
# a findings/F-xxx/*, mkdir de esa ruta, y python que abre report.json.
_DOC_WRITE = re.compile(
    r"(?:"
    r"cat\s*>>?\s+\S*(?:STATE\.md|report\.md|report\.json|CARD\.md|PIVOT\.md|NEXT\.md|(?:findings/)?F-\d+\.json)"
    r"|cat\s*>>?\s+\S*findings/F-\d+"
    r"|mkdir\s+(?:-[^\s]+\s+)*\S*findings/F-\d+"
    r"|open\(\s*['\"][^'\"]*(?:report\.json|findings/F-\d+)"
    r")"
)


def _core_argv(argv: str) -> str:
    """Quita prefijos VAR=val (CLIPBOARD=0, B=http://...) y deja el binario."""
    parts = (argv or "").split()
    i = 0
    while i < len(parts) and _ASSIGN_RE.match(parts[i]):
        i += 1
    return " ".join(parts[i:])


def _is_noise_argv(argv: str) -> bool:
    compact = " ".join((argv or "").split())
    if not compact:
        return True
    if _DOC_WRITE.search(compact):
        return True
    if compact.startswith("((") or "edbdb=" in compact or "/tmp/edb" in compact:
        return True
    core = _core_argv(compact)
    if core and any(re.search(rf"(^|[\s/`]){re.escape(name)}\b", core) for name in _TOOL_WHY):
        return False
    if not core:
        return True
    if _SKIP_ARGV.match(compact) or _SKIP_ARGV.match(core):
        return True
    first = core.split(None, 1)[0]
    if "=" in first or first.startswith("-"):
        return True
    return False


_URL_RE = re.compile(r"https?://[^\s'\"\\]+", re.I)
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)
_TOOL_WHY = {
    "nmap": "descubrimiento de puertos y servicios",
    "rustscan": "barrido rápido de puertos antes de nmap",
    "masscan": "barrido masivo de puertos",
    "curl": "hablar HTTP(S) con el objetivo y leer respuestas",
    "wget": "descargar un PoC, wordlist o binario",
    "httpx": "probar HTTP a escala",
    "python3": "PoC, cliente WebSocket o lógica que no cabe en un one-liner",
    "python": "PoC o script de explotación",
    "nc": "canal crudo TCP / PTY",
    "ncat": "canal crudo TCP / PTY",
    "bash": "orquestar la cadena en el propio host comprometido",
    "dpkg": "comprobar paquetes vulnerables / holds",
    "git": "clonar un repositorio de exploit",
    "searchsploit": "buscar exploits locales",
    "nxc": "autenticación y enum de servicios (SMB/WinRM/LDAP/SSH)",
    "netexec": "autenticación y enum de servicios",
    "bloodyad": "lectura y escritura de atributos AD",
    "impacket-getST": "pedir tickets Kerberos / S4U",
    "impacket-getTGT": "pedir TGT Kerberos",
    "impacket-smbclient": "SMB interactivo con hash o ticket",
    "smbclient": "listar y transferir en shares SMB",
    "vol": "análisis de memoria (Volatility)",
    "volatility3": "análisis de memoria",
    "evil-winrm": "shell WinRM",
    "ldapdomaindump": "volcado LDAP",
    "hashcat": "romper hashes",
    "john": "romper hashes",
    "ffuf": "fuzzing HTTP",
    "gobuster": "descubrimiento de rutas HTTP",
    "feroxbuster": "descubrimiento de rutas HTTP",
    "sqlmap": "inyección SQL",
    "hydra": "fuerza bruta de login",
    "linpeas": "enum de escalada Linux",
    "pspy": "procesos y cron en vivo",
    "ssh": "acceso remoto Linux",
    "aegis-ssh": "comando en el asiento del salto SSH",
    "proxychains": "salir por el SOCKS del salto",
    "proxychains4": "salir por el SOCKS del salto",
    "showmount": "enumerar exports NFS",
    "nfs-cat": "leer un export NFS sin mount del kernel",
    "nfs-ls": "listar un export NFS",
    "pdftotext": "extraer texto de un PDF",
}


def _load_commands(out_dir: Path, events: list[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for e in events:
        if e.get("type") != "command":
            continue
        p = e.get("payload") or {}
        argv = str(p.get("argv") or "").strip()
        if not argv or _is_noise_argv(argv):
            continue
        key = argv[:400]
        if key in seen:
            continue
        seen.add(key)
        out.append({"ts": str(e.get("ts") or ""), "argv": argv})
    audit = out_dir / ".audit" / "commands.jsonl"
    if audit.is_file():
        for line in audit.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(rec, dict):
                continue
            argv = str(rec.get("argv") or "").strip()
            if not argv or _is_noise_argv(argv):
                continue
            key = argv[:400]
            if key in seen:
                continue
            seen.add(key)
            out.append({"ts": str(rec.get("ts") or ""), "argv": argv})
    for c in _load_console_commands(out_dir):
        argv = str(c.get("argv") or "").strip()
        if not argv or _is_noise_argv(argv):
            continue
        key = argv[:400]
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


def _load_console_commands(out_dir: Path) -> list[dict]:
    path = out_dir / "console.log"
    if not path.is_file():
        return []
    rows: list[dict] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for raw in lines:
        i = raw.find("{")
        if i < 0:
            continue
        try:
            ev = json.loads(raw[i:])
        except json.JSONDecodeError:
            continue
        if not isinstance(ev, dict):
            continue
        ts = str(ev.get("timestamp") or ev.get("ts") or ev.get("time") or "")
        part = ev.get("part") if isinstance(ev.get("part"), dict) else {}
        st = part.get("state") if isinstance(part.get("state"), dict) else {}
        inp = st.get("input") if isinstance(st.get("input"), dict) else {}
        if ev.get("type") in {"tool_use", "tool"} or part.get("type") in {"tool", "tool-invocation"}:
            cmd = str(inp.get("command") or inp.get("cmd") or "").strip()
            if cmd:
                rows.append({"ts": ts, "argv": cmd})
            continue
        if ev.get("type") != "assistant":
            continue
        msg = ev.get("message") if isinstance(ev.get("message"), dict) else {}
        for block in msg.get("content") or []:
            if not isinstance(block, dict) or block.get("type") != "tool_use":
                continue
            if str(block.get("name") or "") not in {"Bash", "bash"}:
                continue
            cin = block.get("input") if isinstance(block.get("input"), dict) else {}
            cmd = str(cin.get("command") or cin.get("cmd") or "").strip()
            if cmd:
                rows.append({"ts": ts, "argv": cmd})
    return rows


def _looks_download(argv: str, url: str) -> bool:
    a = argv.lower()
    u = url.lower()
    try:
        from internal.pocsrc import is_poc_fetch_url

        if is_poc_fetch_url(url):
            return True
    except Exception:
        pass
    if any(x in u for x in ("example.com", "localhost", "api.github.com/search")):
        return False
    if any(x in u for x in ("github.com", "githubusercontent.com", "gitlab.com", "exploit-db.com")):
        return True
    if "git clone" in a:
        return True
    if re.search(r"\bwget\b", a):
        return True
    if re.search(r"\bcurl\b", a) and re.search(r"(?:\s-o\s|\s-O\b|\s--output\b)", a):
        # no contar el recon HTTP del propio objetivo como “descarga de PoC”
        if any(x in u for x in ("/api/validate", "127.1", "127.0.0.1")):
            return False
        if re.search(r"https?://(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)", u):
            return False
        if re.search(r"\.(?:lab|test|local|internal|example)(?:[:/]|$)", u):
            return False
        return True
    return False


def _extract_downloads(cmds: list[dict]) -> list[dict]:
    rows = []
    for c in cmds:
        argv = c.get("argv") or ""
        if not re.search(r"\b(curl|wget|git)\b", argv):
            continue
        for url in _URL_RE.findall(argv):
            url = url.rstrip(").,;\"'")
            if _looks_download(argv, url):
                rows.append({"ts": c.get("ts") or "", "url": url, "argv": argv})
    return rows


def _finding_keys(f: dict) -> list[str]:
    blob = " ".join(
        str(f.get(k) or "")
        for k in ("id", "title", "asset", "summary", "explain", "proof", "reproduction")
    )
    keys: list[str] = []
    for m in _CVE_RE.finditer(blob):
        keys.append(m.group(0).lower())
    for m in re.finditer(r"[a-z0-9._-]{3,}\.(lab|test|local|internal|example)|nb-[a-z0-9]+\.[a-z0-9.-]+", blob, re.I):
        keys.append(m.group(0).lower())
    # Tokens de CLASE de vulnerabilidad (genéricos, no de ninguna máquina concreta).
    # Los identificadores específicos ya salen del regex de CVE, del host y de la
    # evidencia del propio hallazgo.
    for token in (
        "ssrf",
        "lfi",
        "rce",
        "sqli",
        "xxe",
        "deserial",
        "shell=true",
        "path travers",
        "user.txt",
        "root.txt",
        "suid",
        "sudo",
        "nfs",
        "showmount",
        "imap",
        "smb",
        "kerberos",
    ):
        if token in blob.lower():
            keys.append(token)
    fid = str(f.get("id") or "").lower()
    if fid:
        keys.append(fid.lower())
        keys.append(fid.replace("-", "").lower())
    # paths in evidence
    for rel in f.get("evidence") or []:
        name = Path(str(rel)).name.lower()
        if name and name not in {"note.txt", "proof.txt"}:
            keys.append(name)
    out = []
    for k in keys:
        if k and k not in out:
            out.append(k)
    return out


def _written_finding_ids(argv: str) -> list[str]:
    """IDs a los que un argv escribe (ruta findings/F-xxx o insert en report.json)."""
    ids: list[str] = []
    for m in re.findall(r"findings/(F-\d+)", argv or "", re.I):
        u = m.upper()
        if u not in ids:
            ids.append(u)
    if ids:
        return ids
    for m in re.findall(r"""['\"]id['\"]\s*:\s*['\"](F-\d+)['\"]""", argv or "", re.I):
        u = m.upper()
        if u not in ids:
            ids.append(u)
    return ids


def _foreign_finding_write(fid: str, argv: str) -> bool:
    own = (fid or "").upper()
    written = _written_finding_ids(argv)
    return bool(own and written and all(w != own for w in written))


def _related_commands(f: dict, cmds: list[dict], limit: int = 8) -> list[dict]:
    keys = _finding_keys(f)
    scored: list[tuple[int, dict]] = []
    fts = _parse_ts(str(f.get("timestamp") or ""))
    own = str(f.get("id") or "")
    for c in cmds:
        argv = str(c.get("argv") or "")
        compact = " ".join(argv.split())
        if not compact or _is_noise_argv(compact) or _DOC_WRITE.search(compact):
            continue
        if _foreign_finding_write(own, compact):
            continue
        low = compact.lower()
        score = 0
        for k in keys:
            if k and k in low:
                score += 3 if len(k) > 5 else 2
        if score <= 0:
            continue
        cts = _parse_ts(str(c.get("ts") or ""))
        if fts and cts and abs((fts - cts).total_seconds()) <= 1800:
            score += 1
        scored.append((score, c))
    scored.sort(key=lambda x: (-x[0], str(x[1].get("ts") or "")))
    seen: set[str] = set()
    out = []
    for _, c in scored:
        key = _command_fingerprint(c.get("argv") or "")
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
        if len(out) >= limit:
            break
    return out


def _command_fingerprint(argv: str) -> str:
    a = (argv or "").lower()
    if "def ssrf" in a or ("urllib.request" in a and "/api/validate" in a and "python" in a):
        return "ssrf-loop"
    if "websockets" in a and "terminal/ws" in a:
        inner = _compact_argv(argv)
        return "ws:" + inner[40:140]
    if "api.github.com/search" in a:
        return "gh-search"
    return _compact_argv(argv, 160)


def _parse_ts(raw: str):
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    # Sin zona horaria se asume UTC: así no se mezclan datetimes naive y aware
    # al restar (rompía la regeneración de informes con timestamps sin 'Z').
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _compact_argv(argv: str, limit: int = 240) -> str:
    if not argv:
        return ""
    if "websockets" in argv and ("terminal/ws" in argv or "await sh(" in argv):
        m = re.search(r"await sh\(\s*(['\"])(.+?)\1", argv, re.S)
        if m:
            inner = " ".join(m.group(2).split())
            return f"python3 → PTY /terminal/ws → {inner[: max(80, limit - 40)]}"
        return "python3 → cliente WebSocket /terminal/ws"
    one = " ".join(argv.split())
    if len(one) > limit:
        return one[: limit - 1] + "…"
    return one


_NOISE_TOOLS = {
    "echo",
    "export",
    "cp",
    "#",
    "tee",
    "printf",
    "cat",
    "ls",
    "mkdir",
    "cd",
    "true",
    "head",
    "tail",
    "date",
    "pwd",
    "mv",
    "chmod",
    "sha256sum",
    "sleep",
    "yes",
    "set",
    "source",
    "unset",
    "local",
    "declare",
    "read",
    "test",
    "[",
    "[[",
    "EOF",
    "FI",
    "THEN",
    "DO",
    "DONE",
    "ESAC",
    "IN",
    "ELIF",
    "ELSE",
    "PY",
}


def _tool_name(argv: str) -> str:
    if "websockets" in argv or "terminal/ws" in argv:
        return "python3"
    core = _core_argv(" ".join((argv or "").split()))
    if not core or _is_noise_argv(core):
        return ""
    low = core.lower()
    for name in _TOOL_WHY:
        if re.search(rf"(^|[\s/`]){re.escape(name)}\b", low):
            if name not in _NOISE_TOOLS:
                return name
    for line in (argv or "").splitlines():
        line = _core_argv(line.strip())
        if not line or line.startswith("#") or line.startswith("export "):
            continue
        tok = line.split(None, 1)
        if not tok:
            continue
        name = Path(tok[0]).name
        if "=" in name or name.startswith("-"):
            continue
        if "." in name and name.lower().endswith((".lab", ".test", ".local", ".com", ".org")):
            continue
        if name in {"sudo", "env", "command"}:
            rest = line.split()
            for x in rest[1:]:
                if x.startswith("-") or "=" in x:
                    continue
                name = Path(x).name
                break
        if re.fullmatch(r"[A-Z][A-Z0-9_]{0,30}", name):
            continue
        if name and name not in _NOISE_TOOLS:
            return name
    return ""


def _tools_used(cmds: list[dict], f: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for c in cmds:
        name = _tool_name(c.get("argv") or "")
        if not name or name in out or name in _NOISE_TOOLS:
            continue
        out[name] = _TOOL_WHY.get(name, "usada en la explotación o el descubrimiento de este hallazgo")
    blob = f"{f.get('proof') or ''} {f.get('reproduction') or ''}".lower()
    for name, why in _TOOL_WHY.items():
        if name in blob and name not in out and name not in _NOISE_TOOLS:
            out[name] = why
    return out


def _result_line(f: dict, out_dir: Path) -> str:
    proof = str(f.get("proof") or "")
    if "→" in proof:
        return proof.split("→", 1)[1].strip() or proof
    loot = _loot_line(f, out_dir).strip()
    if loot:
        return f"{_finding_prose(f)} {loot}".strip()
    return _finding_prose(f) if _finding_prose(f) != "—" else "respuesta no anotada en el finding"


def _loot_line(f: dict, out_dir: Path) -> str:
    bits = []
    for rel in f.get("evidence") or []:
        path = out_dir / str(rel)
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > 500:
                continue
        except OSError:
            continue
        if path.suffix.lower() not in {"", ".txt", ".out", ".md"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        if not text or text[0] in "{[<":
            continue
        if re.search(r"BEGIN (?:OPENSSH|RSA|DSA|EC) PRIVATE KEY", text):
            continue
        name = path.name.lower()
        if name.startswith("id_") and not name.endswith(".pub"):
            continue
        line = " ".join(text.split())[:160]
        bits.append(f"`{rel}` → `{line}`")
        if len(bits) >= 3:
            break
    return ("Loot en disco: " + "; ".join(bits) + ".") if bits else ""


def _finding_scripts(f: dict, out_dir: Path) -> list[str]:
    fid = str(f.get("id") or "")
    scripts: list[str] = []
    folder = out_dir / "findings" / fid if fid else None
    skip = {"user.txt", "root.txt", "proof.txt", "note.txt"}
    if folder and folder.is_dir():
        for p in sorted(folder.iterdir()):
            if not p.is_file():
                continue
            try:
                if p.stat().st_size <= 0:
                    continue
            except OSError:
                continue
            name = p.name.lower()
            if name in skip:
                continue
            if p.suffix.lower() in {".py", ".sh", ".c", ".go", ".rb", ".pl"} or name.startswith("cve-"):
                scripts.append(f"findings/{fid}/{p.name}")
    for rel in f.get("evidence") or []:
        s = str(rel)
        if s.endswith((".py", ".sh", ".c", ".go", ".rb", ".pl")) and s not in scripts:
            scripts.append(s)
    return scripts


def _poc_origin(f: dict, out_dir: Path, cmds: list[dict], downloads: list[dict]) -> str:
    poc = f.get("poc") if isinstance(f.get("poc"), dict) else {}
    urls = [str(u) for u in (poc.get("urls") or []) if u]
    local = [str(p) for p in (poc.get("local") or []) if p]
    origin = str(poc.get("origin") or "")
    label = str(poc.get("label") or "")
    if not urls and not local:
        keys = [k for k in _finding_keys(f) if len(k) > 3]

        def _url_for_finding(url: str) -> bool:
            u = url.lower()
            return any(k in u for k in keys)

        for d in downloads:
            url = str(d.get("url") or "").strip()
            if url and _url_for_finding(url) and url not in urls:
                urls.append(url)
        for c in cmds:
            argv = c.get("argv") or ""
            for url in _URL_RE.findall(argv):
                url = url.rstrip(").,;\"'")
                if not _looks_download(argv, url):
                    continue
                if _url_for_finding(url) and url not in urls:
                    urls.append(url)
    scripts = _finding_scripts(f, out_dir)
    bits: list[str] = []
    if origin == "inline":
        bits.append(label or "Explotación in-line (sin PoC en red ni searchsploit)")
    elif label and (urls or local):
        bits.append(label)
    if local:
        bits.append("copia local: " + ", ".join(f"`{p}`" for p in local[:4]))
    if urls:
        bits.append("publicado en: " + ", ".join(f"`{u}`" for u in urls[:6]))
    if scripts:
        bits.append("en el run: " + ", ".join(f"`{s}`" for s in scripts[:6]))
    if not bits:
        return (
            "No hay rastro de un PoC bajado de GitHub, Exploit-DB u otro sitio "
            "(tampoco searchsploit). La prueba es el comando in-line del `proof`."
        )
    return ". ".join(bits) + "."


def _timeline(events: list[dict]) -> list[dict]:
    keep = {
        "run.start",
        "run.end",
        "finding",
        "error",
        "command",
        "net.out_of_scope",
        "note",
    }
    out = []
    for e in events:
        if e.get("type") in keep:
            out.append({"ts": e.get("ts"), "type": e.get("type")})
    return out


def _surface(events: list[dict], findings: list[dict]) -> list[str]:
    seen: set[str] = set()
    for e in events:
        if e.get("type") in {"net.conn", "net.out_of_scope"}:
            p = e.get("payload") or {}
            dest = _real_net_dest(p)
            if dest:
                seen.add(dest)
    for f in findings:
        if f.get("asset"):
            seen.add(str(f["asset"]))
    return sorted(seen)


def _commands_that_mattered(events: list[dict]) -> list[dict]:
    cmds = []
    for e in events:
        if e.get("type") != "command":
            continue
        p = e.get("payload") or {}
        argv = str(p.get("argv") or "")
        if not argv or _is_noise_argv(argv):
            continue
        cmds.append({"argv": argv[:300], "exit": p.get("exit")})
    # únicos, últimos primero, cap
    uniq = []
    seen = set()
    for c in reversed(cmds):
        if c["argv"] in seen:
            continue
        seen.add(c["argv"])
        uniq.append(c)
    uniq.reverse()
    return uniq


_OOS_IGNORE = {
    "0",
    "0.0.0.0",
    "*",
    "127.0.0.1",
    "::1",
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "kali.download",
    "http.kali.org",
    "pypi.org",
    "files.pythonhosted.org",
}


def _real_net_dest(payload: dict) -> str:
    ip = str(payload.get("dst_ip") or payload.get("dst") or "").strip()
    host = str(payload.get("dst_host") or payload.get("host") or "").strip().lower()
    try:
        port = int(payload.get("dst_port") or 0)
    except (TypeError, ValueError):
        port = 0
    if ip in _OOS_IGNORE or host in _OOS_IGNORE:
        return ""
    if not ip or ip == "0":
        return ""
    if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip) and ":" not in ip and "." not in ip:
        return ""
    if port <= 0 and ip in {"0", "0.0.0.0"}:
        return ""
    return f"{ip}:{port}" if port else ip


def _limitations(mode: str, events: list[dict], out_dir: Path | None = None) -> list[str]:
    out: list[str] = []
    if mode != "full":
        out.append(f"El modo {mode} restringe lo que cuenta como éxito (sin explotación completa).")
    out.append("La superficie listada es lo observado en este run, no un inventario de toda la red.")
    if out_dir is not None and (out_dir / "report.agent.md").is_file():
        out.append("El modelo escribió report.agent.md; este informe estructurado se genera a partir de findings.")
    oos = []
    for e in events:
        if e.get("type") != "net.out_of_scope":
            continue
        dest = _real_net_dest(e.get("payload") or {})
        if dest and dest not in oos:
            oos.append(dest)
    if oos:
        out.append("Tráfico fuera de scope hacia: " + ", ".join(oos[:8]) + ".")
    if any(e.get("type") == "run.end" and (e.get("payload") or {}).get("reason") == "timeout" for e in events):
        out.append("El run terminó por timeout.")
    return out


def _read_json(path: Path) -> Any:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
