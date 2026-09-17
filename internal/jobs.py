"""Jobs del host: resume, cola y NEXT.md. Spray/forense va por engage.py."""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from internal.engage import (
    load,
    run_jobs,
    save,
    write_next,
)


_RESUME_DIRS = ("loot", "scans", "vmbackups")


def _copy_run_dir(src: Path, dest: Path) -> None:
    if dest.exists():
        return
    try:
        real = src.resolve() if src.exists() else src
    except OSError:
        return
    if not real.exists():
        return
    if real.is_dir():
        shutil.copytree(real, dest, dirs_exist_ok=True, symlinks=False)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(real, dest)


def detach_resume_links(doomed: Path, runs_dir: Path) -> bool:
    """Copia loot/scans/vmbackups de quien aún enlaza este run.

    True si no quedan dependientes colgando. False si alguna copia falló:
    el caller no debe borrar el origen.
    """
    try:
        doomed = doomed.resolve()
    except OSError:
        return False
    if not runs_dir.is_dir():
        return True
    ok = True
    for other in runs_dir.iterdir():
        if not other.is_dir():
            continue
        try:
            if other.resolve() == doomed:
                continue
        except OSError:
            continue
        for name in _RESUME_DIRS:
            link = other / name
            tmp = other / f".aegis-detach-{name}"
            try:
                is_link = link.is_symlink()
            except OSError:
                ok = False
                continue
            # Un rename a medias dejó la copia en tmp: termínala antes de borrar el origen.
            if tmp.exists() and not is_link:
                try:
                    if not link.exists():
                        tmp.rename(link)
                except OSError:
                    ok = False
                    continue
            if not is_link:
                continue
            try:
                dest = link.resolve()
            except OSError:
                ok = False
                continue
            try:
                inside = dest == doomed or doomed in dest.parents
            except OSError:
                ok = False
                continue
            if not inside:
                continue
            unlinked = False
            try:
                if tmp.exists():
                    if tmp.is_dir():
                        shutil.rmtree(tmp)
                    else:
                        tmp.unlink()
                if dest.is_dir():
                    shutil.copytree(dest, tmp, dirs_exist_ok=True, symlinks=False)
                elif dest.is_file():
                    shutil.copy2(dest, tmp)
                else:
                    ok = False
                    continue
                link.unlink()
                unlinked = True
                tmp.rename(link)
            except OSError:
                ok = False
                if unlinked:
                    if tmp.exists() and not link.exists() and not link.is_symlink():
                        try:
                            tmp.rename(link)
                        except OSError:
                            try:
                                link.symlink_to(dest)
                            except OSError:
                                pass
                    if link.is_symlink() and tmp.exists():
                        if tmp.is_dir():
                            shutil.rmtree(tmp, ignore_errors=True)
                        else:
                            try:
                                tmp.unlink()
                            except OSError:
                                pass
                elif tmp.exists():
                    if tmp.is_dir():
                        shutil.rmtree(tmp, ignore_errors=True)
                    else:
                        try:
                            tmp.unlink()
                        except OSError:
                            pass
    return ok


def seed_resume(src: Path, dest: Path) -> dict[str, Any]:
    """Copia estado y loot/scans/vmbackups de un run viejo. No enlaza."""
    dest.mkdir(parents=True, exist_ok=True)
    state: dict[str, Any] = {}
    src_eng = src / "engagement.json"
    if src_eng.is_file():
        try:
            state = json.loads(src_eng.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            state = {}
        if not isinstance(state, dict):
            state = {}
        state["_ingest"] = {"console": 0, "audit": 0}
        state["_clock"] = {}  # reloj nuevo: critic_rules no debe disparar RELOJ al instante
        state["_resume_from"] = src.name
        save(state, dest / "engagement.json")
    for name in _RESUME_DIRS:
        s, d = src / name, dest / name
        if s.exists() and not d.exists():
            _copy_run_dir(s, d)
    src_find = src / "findings"
    if src_find.is_dir():
        shutil.copytree(src_find, dest / "findings", dirs_exist_ok=True)
    # STATE.md/NEXT.md NO se copian: save() ya los regeneró frescos desde el JSON;
    # copiar los del run muerto dejaría al modelo con estado obsoleto. Solo el
    # contrato de flags (ctf.json) debe heredarse.
    s = src / "ctf.json"
    if s.is_file():
        shutil.copy2(s, dest / "ctf.json")
    # El CVE ya gastado debe sobrevivir al resume: si no, el relevo rearma el mismo PoC.
    blocked = src / ".poc-blocked"
    if blocked.is_file():
        shutil.copy2(blocked, dest / ".poc-blocked")
    (dest / "STEER.md").write_text(
        f"RESUME de {src.name}. No re-enumeres. Lee STATE.md, engagement.json y loot/.\n",
        encoding="utf-8",
    )
    return load(dest / "engagement.json") if (dest / "engagement.json").is_file() else {}


def write_steer(out_dir: Path, text: str) -> Path:
    """Orden del operador. Si el agente está en turno, corta ya: el entrypoint
    vigila `.conscience-cut` y el persist inyecta STEER.md como obligatorio."""
    dest = out_dir / "STEER.md"
    dest.write_text(text.strip() + "\n", encoding="utf-8")
    if (out_dir / ".agent-pid").is_file():
        (out_dir / ".conscience-cut").write_text("steer\n", encoding="utf-8")
    return dest


def host_tick(out_dir: Path, *, sidecars: bool = True) -> dict[str, Any]:
    """Tras refresh_state: jobs locales y NEXT.md por reloj/bucle.

    NO llama persist_tick ni escribe .pivot-action.json. Ese reloj (stall CTF
    de 6 ticks, corte de sesión al primer user.txt) es del contenedor
    (refresh-pivot --tick). Si el host incrementa stall cada 75 s, un run
    con user y sin root muere en ~8 min. persist_ts del host también puede
    marcar cut_done y saltarse el corte de sesión del contenedor.
    """
    state = run_jobs(out_dir, execute=False, heavy=False, sidecars=sidecars)
    if not sidecars:
        return state
    write_next(state, out_dir / "NEXT.md")
    return state
