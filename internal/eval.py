"""Scorecard offline de runs ya persistidos. No lanza cajas."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from internal.flagspec import found_count, is_complete, load_contract
from internal.telemetry import run_elapsed_seconds

from internal.engage import flag_kinds


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _findings_n(root: Path) -> tuple[int, int]:
    proven = suspected = 0
    folder = root / "findings"
    if not folder.is_dir():
        return 0, 0
    for p in folder.glob("F-*.json"):
        data = _read_json(p)
        if str(data.get("status") or "") == "proven":
            proven += 1
        else:
            suspected += 1
    return proven, suspected


def _tokens(root: Path, stats: dict[str, Any]) -> int:
    toks = stats.get("tokens") if isinstance(stats.get("tokens"), dict) else {}
    return int(toks.get("in") or 0) + int(toks.get("out") or 0)


def score_run(root: Path) -> dict[str, Any]:
    """Puntúa un run en disco. Flags solo si hay contrato CTF."""
    root = Path(root)
    meta = _read_json(root / "meta.json")
    stats = _read_json(root / "stats.json")
    eng = _read_json(root / "engagement.json")
    contract = load_contract(root)
    ctf = bool(contract.get("enabled") or meta.get("ctf"))
    kinds = flag_kinds(eng) if isinstance(eng, dict) else set()
    user = "user" in kinds
    root_flag = "root" in kinds or "admin" in kinds
    if ctf:
        user = user or bool(found_count(root, contract) >= 1 and user)
        # found_count cuenta slots en disco; kinds cubre engagement.flags
        hits = found_count(root, contract)
        complete = is_complete(root, contract)
        if hits >= 1 and not user and not root_flag:
            # wrap u otro contrato: al menos una slot
            user = True
    else:
        complete = False
    proven, suspected = _findings_n(root)
    elapsed = run_elapsed_seconds(root)
    if elapsed is None:
        elapsed = int(stats.get("elapsed") or 0)
    tokens = _tokens(root, stats)
    if ctf:
        points = (1.0 if user else 0.0) + (1.0 if root_flag else 0.0)
        max_pts = 2.0
        if complete:
            points = max_pts
    else:
        points = float(proven)
        max_pts = max(1.0, float(proven + suspected) or 1.0)
    rid = str(meta.get("run_id") or root.name)
    return {
        "run_id": rid,
        "title": str(meta.get("title") or ""),
        "harness": str(meta.get("harness") or ""),
        "model": str(meta.get("model") or ""),
        "mode": str(meta.get("mode") or ""),
        "reason": str(meta.get("reason") or meta.get("status") or ""),
        "ctf": ctf,
        "user": user if ctf else None,
        "root": root_flag if ctf else None,
        "complete": complete if ctf else None,
        "elapsed": int(elapsed or 0),
        "tokens": tokens,
        "findings_proven": proven,
        "findings_suspected": suspected,
        "points": points,
        "max_points": max_pts,
    }


def score_runs(runs_dir: Path, ids: list[str] | None = None) -> list[dict[str, Any]]:
    runs_dir = Path(runs_dir)
    if not runs_dir.is_dir():
        return []
    if ids:
        roots = [runs_dir / i for i in ids if (runs_dir / i / "meta.json").is_file()]
    else:
        roots = sorted(
            (p.parent for p in runs_dir.glob("*/meta.json")),
            key=lambda p: p.name,
            reverse=True,
        )
    return [score_run(r) for r in roots]


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(rows)
    ctf_rows = [r for r in rows if r.get("ctf")]
    nc = len(ctf_rows)
    user_n = sum(1 for r in ctf_rows if r.get("user"))
    root_n = sum(1 for r in ctf_rows if r.get("root"))
    done_n = sum(1 for r in ctf_rows if r.get("complete"))
    return {
        "runs": n,
        "ctf_runs": nc,
        "user_rate": (user_n / nc) if nc else None,
        "root_rate": (root_n / nc) if nc else None,
        "complete_rate": (done_n / nc) if nc else None,
        "median_elapsed": _median([int(r.get("elapsed") or 0) for r in rows]),
        "median_tokens": _median([int(r.get("tokens") or 0) for r in rows]),
        "findings_proven": sum(int(r.get("findings_proven") or 0) for r in rows),
    }


def _median(vals: list[int]) -> int | None:
    if not vals:
        return None
    s = sorted(vals)
    mid = len(s) // 2
    if len(s) % 2:
        return s[mid]
    return (s[mid - 1] + s[mid]) // 2


def format_table(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "sin runs"
    lines = [
        f"{'run':<26} {'tipo':<6} {'u/r':<5} {'t':>8} {'tok':>8} {'F':>5} reason",
    ]
    for r in rows:
        ur = "—"
        if r.get("ctf"):
            ur = ("✓" if r.get("user") else "·") + "/" + ("✓" if r.get("root") else "·")
        lines.append(
            f"{r['run_id']:<26} "
            f"{'ctf' if r.get('ctf') else 'audit':<6} "
            f"{ur:<5} "
            f"{int(r.get('elapsed') or 0):>8} "
            f"{int(r.get('tokens') or 0):>8} "
            f"{int(r.get('findings_proven') or 0):>5} "
            f"{r.get('reason') or ''}"
        )
    summ = summarize(rows)
    extra = []
    if summ["ctf_runs"]:
        extra.append(
            f"CTF {summ['ctf_runs']}: user {summ['user_rate']:.0%} · "
            f"root {summ['root_rate']:.0%} · complete {summ['complete_rate']:.0%}"
        )
    extra.append(
        f"n={summ['runs']} mediana t={summ['median_elapsed']}s "
        f"tok={summ['median_tokens']} proven={summ['findings_proven']}"
    )
    return "\n".join(lines + [""] + extra) + "\n"
