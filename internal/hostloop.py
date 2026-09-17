"""Sidecar del host: ingiere consola/audit y deduplica findings."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from internal.engage import finding_fingerprint, refresh_state
from internal.jobs import host_tick


def maybe_recover_claude_auth(out_dir: Path) -> bool:
    """Si el run está en pausa por OAuth y el host ya tiene sesión, reinyecta y sigue."""
    flag = out_dir / ".pause-reason"
    if not flag.is_file():
        return False
    try:
        reason = flag.read_text(encoding="utf-8").strip()
    except OSError:
        return False
    if reason != "auth":
        return False
    from internal.claude import ensure_fresh_access, refresh_staged_claude

    if not ensure_fresh_access():
        return False
    if not refresh_staged_claude(out_dir.name):
        return False
    try:
        flag.unlink()
    except OSError:
        return False
    return True


def tick(out_dir: Path, *, sidecars: bool = True) -> dict[str, Any]:
    if not sidecars:
        return {}
    maybe_recover_claude_auth(out_dir)
    try:
        from internal.claude import keep_claude_oauth

        keep_claude_oauth(out_dir.name)
    except Exception:
        pass
    refresh_state(out_dir, sidecars=sidecars)
    dedup_findings(out_dir)
    return host_tick(out_dir, sidecars=sidecars)


def dedup_findings(out_dir: Path) -> int:
    findings = out_dir / "findings"
    if not findings.is_dir():
        return 0
    seen: dict[str, str] = {}
    n = 0
    for path in sorted(findings.rglob("F-*.json"), key=lambda p: (len(p.relative_to(findings).parts), str(p))):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        fp = finding_fingerprint(data)
        fid = str(data.get("id") or path.stem)
        if fp in seen and seen[fp] != fid:
            if data.get("duplicate_of") != seen[fp]:
                data["duplicate_of"] = seen[fp]
                if data.get("kind") == "info" or data.get("severity") == "info":
                    data["status"] = "suspected"
                path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
                n += 1
        else:
            seen[fp] = fid
    return n
