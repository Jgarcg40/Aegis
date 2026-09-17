"""Inbox: staging en data/web/inbox/, copia a runs/<id>/inbox/.

Comprimidos se extraen (path traversal / zip bombs). Cifrados se ignoran.
"""
from __future__ import annotations

import re
import secrets
import shutil
import subprocess
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path
from typing import BinaryIO
from urllib.parse import unquote

from internal.config import Config

INBOX_MOUNT = "/run/aegis/inbox"
INBOX_ID_RE = re.compile(r"^ib-[a-f0-9]{12}$")
MAX_FILES = 20                       # elementos que se pueden soltar (un comprimido = 1)
MAX_FILE = 150 * 1024 * 1024         # tamaño de un archivo (subido o extraído)
MAX_TOTAL = 200 * 1024 * 1024        # tamaño total del lote (ya descomprimido)
MAX_ENTRIES = 2000                   # ficheros que puede aportar un comprimido
MAX_DEPTH = 24                       # profundidad de carpetas dentro de un comprimido
_CHUNK = 1024 * 1024
_NAME_OK = re.compile(r"^[A-Za-z0-9._+\-\[\]][A-Za-z0-9._+\-\[\] ]{0,119}$")
_BAD_COMPONENT = re.compile(r"[\x00-\x1f/\\]")
_STALE_S = 24 * 3600

# Comprimidos que sabemos descomprimir. Orden importa: .tar.gz antes que .gz.
_ARCHIVE_EXTS = (
    ".zip",
    ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tbz", ".tar.xz", ".txz",
    ".rar", ".7z",
)


class InboxError(ValueError):
    pass


def new_id() -> str:
    return "ib-" + secrets.token_hex(6)


def staging_root(cfg: Config) -> Path:
    return cfg.data_dir / "web" / "inbox"


def staging_dir(cfg: Config, inbox_id: str) -> Path:
    if not INBOX_ID_RE.match(inbox_id or ""):
        raise InboxError("inbox inválido")
    return staging_root(cfg) / inbox_id


def safe_name(raw: str) -> str:
    """Un solo componente de nombre (para archivos sueltos)."""
    text = unquote(str(raw or "")).replace("\\", "/").strip()
    text = text.rsplit("/", 1)[-1].strip()
    if text.endswith(".part"):
        text = text[: -len(".part")]
    if not text or text in {".", ".."} or not _NAME_OK.match(text):
        raise InboxError("nombre de archivo no válido")
    return text


def _safe_parts(raw: str) -> list[str] | None:
    """Ruta relativa saneada (para contenidos de un comprimido). None = descartar."""
    text = unquote(str(raw or "")).replace("\\", "/").strip()
    parts: list[str] = []
    for comp in text.split("/"):
        comp = comp.strip()
        if comp in ("", "."):
            continue
        if comp == ".." or _BAD_COMPONENT.search(comp) or re.match(r"^[A-Za-z]:$", comp):
            return None
        if len(comp) > 200:
            return None
        parts.append(comp)
    if not parts or len(parts) > MAX_DEPTH:
        return None
    return parts


def create_staging(cfg: Config) -> str:
    inbox_id = new_id()
    dest = staging_dir(cfg, inbox_id)
    dest.mkdir(parents=True, exist_ok=False)
    return inbox_id


def _iter_files(folder: Path):
    for p in sorted(folder.rglob("*")):
        if p.is_symlink() or not p.is_file():
            continue
        if p.name.endswith(".part"):
            continue
        yield p


def list_files(folder: Path) -> list[dict]:
    """Listado recursivo. `name` es la ruta relativa (posix)."""
    if not folder.is_dir():
        return []
    out: list[dict] = []
    for p in _iter_files(folder):
        try:
            size = p.stat().st_size
        except OSError:
            continue
        out.append({"name": p.relative_to(folder).as_posix(), "size": size})
    return out


def _top_count(folder: Path) -> int:
    if not folder.is_dir():
        return 0
    return sum(1 for p in folder.iterdir() if not p.name.endswith(".part"))


def _total_bytes(folder: Path) -> int:
    return sum(int(f["size"]) for f in list_files(folder))


def _archive_ext(name: str) -> str:
    low = name.lower()
    for ext in sorted(_ARCHIVE_EXTS, key=len, reverse=True):
        if low.endswith(ext):
            return ext
    return ""


def add_file(cfg: Config, inbox_id: str, name: str, reader: BinaryIO, length: int) -> dict:
    dest_dir = staging_dir(cfg, inbox_id)
    if not dest_dir.is_dir():
        raise InboxError("inbox no encontrado")
    display = unquote(str(name or "")).replace("\\", "/").rsplit("/", 1)[-1].strip()
    if length < 1:
        raise InboxError("archivo vacío")
    if length > MAX_FILE:
        raise InboxError(f"cada anexo como mucho {MAX_FILE // (1024 * 1024)} MB")
    if _top_count(dest_dir) >= MAX_FILES:
        raise InboxError(f"como mucho {MAX_FILES} anexos")
    existing = _total_bytes(dest_dir)
    if existing + length > MAX_TOTAL:
        raise InboxError(f"el lote no puede superar {MAX_TOTAL // (1024 * 1024)} MB")

    tmp = dest_dir / f".upload-{secrets.token_hex(6)}.part"
    written = 0
    try:
        with tmp.open("wb") as out:
            left = length
            while left > 0:
                chunk = reader.read(min(_CHUNK, left))
                if not chunk:
                    break
                out.write(chunk)
                written += len(chunk)
                left -= len(chunk)
        if written != length:
            raise InboxError("cuerpo incompleto")

        ext = _archive_ext(display)
        if ext:
            budget = MAX_TOTAL - existing
            sub = _unique_dir(dest_dir, _archive_stem(display, ext))
            try:
                extracted = _extract(tmp, sub, ext, budget)
            except InboxError:
                shutil.rmtree(sub, ignore_errors=True)
                raise
            if not extracted:
                shutil.rmtree(sub, ignore_errors=True)
                raise InboxError(f"{display}: comprimido vacío o cifrado, nada que extraer")
            return {
                "name": display,
                "size": length,
                "archive": True,
                "extracted": len(extracted),
                "files": list_files(dest_dir),
            }

        clean = safe_name(display)
        dest = _unique_dest(dest_dir, clean)
        tmp.replace(dest)
        tmp = None  # ya movido
        return {"name": dest.name, "size": written, "files": list_files(dest_dir)}
    finally:
        if tmp is not None:
            try:
                tmp.unlink()
            except OSError:
                pass



def _extract(src: Path, dest: Path, ext: str, budget: int) -> list[dict]:
    dest.mkdir(parents=True, exist_ok=True)
    if ext == ".zip":
        return _extract_zip(src, dest, budget)
    if ext == ".rar":
        return _extract_external(src, dest, budget, "rar")
    if ext == ".7z":
        return _extract_external(src, dest, budget, "7z")
    return _extract_tar(src, dest, budget)


def _guard(entry_name: str, declared: int, used: int, count: int, budget: int) -> list[str] | None:
    parts = _safe_parts(entry_name)
    if parts is None:
        return None
    if count >= MAX_ENTRIES:
        raise InboxError(f"el comprimido tiene más de {MAX_ENTRIES} archivos")
    if declared > MAX_FILE:
        raise InboxError(f"{parts[-1]} supera {MAX_FILE // (1024 * 1024)} MB")
    if used + declared > budget:
        raise InboxError("la descompresión supera el límite (posible zip bomb)")
    return parts


def _stream(fh, target: Path, declared: int, used: int, budget: int) -> int:
    written = 0
    with target.open("wb") as out:
        while True:
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            written += len(chunk)
            # El tamaño declarado mintió y crece sin control: bomba.
            if written > declared + 4096 or used + written > budget:
                out.close()
                target.unlink(missing_ok=True)
                raise InboxError("comprimido inconsistente (posible bomba de descompresión)")
            out.write(chunk)
    return written


def _extract_zip(src: Path, dest: Path, budget: int) -> list[dict]:
    if not zipfile.is_zipfile(src):
        raise InboxError("ZIP corrupto o no reconocido")
    out: list[dict] = []
    used = 0
    with zipfile.ZipFile(src) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            if info.flag_bits & 0x1:  # cifrado con contraseña → se ignora
                continue
            parts = _guard(info.filename, info.file_size, used, len(out), budget)
            if parts is None:
                continue
            target = _dest_for(dest, parts)
            with zf.open(info) as fh:
                written = _stream(fh, target, info.file_size, used, budget)
            used += written
            out.append({"name": target.relative_to(dest).as_posix(), "size": written})
    return out


def _extract_tar(src: Path, dest: Path, budget: int) -> list[dict]:
    try:
        tf = tarfile.open(src, "r:*")
    except tarfile.TarError as exc:
        raise InboxError("TAR corrupto o no reconocido") from exc
    out: list[dict] = []
    used = 0
    with tf:
        for member in tf:
            if not member.isreg():  # descarta dirs, symlinks, hardlinks, devices, fifos
                continue
            parts = _guard(member.name, member.size, used, len(out), budget)
            if parts is None:
                continue
            fh = tf.extractfile(member)
            if fh is None:
                continue
            target = _dest_for(dest, parts)
            with fh:
                written = _stream(fh, target, member.size, used, budget)
            used += written
            out.append({"name": target.relative_to(dest).as_posix(), "size": written})
    return out


def _tmp_usage(root: Path) -> tuple[int, int]:
    """Bytes y ficheros reales bajo root (sin seguir symlinks)."""
    total = 0
    n = 0
    for p in root.rglob("*"):
        try:
            if p.is_symlink() or not p.is_file():
                continue
            total += p.stat().st_size
            n += 1
        except OSError:
            continue
    return total, n


def _external_cmd(src: Path, tmpd: str, kind: str) -> list[str] | None:
    """Comando de extracción. Destino solo `tmpd`. Sin -P / --absolute-names / -spf."""
    if shutil.which("bsdtar"):
        return ["bsdtar", "-x", "-f", str(src), "-C", tmpd]
    if shutil.which("7z"):
        return ["7z", "x", "-p", "-y", f"-o{tmpd}", str(src)]
    if kind == "rar" and shutil.which("unrar"):
        return ["unrar", "x", "-p-", "-y", str(src), tmpd.rstrip("/") + "/"]
    return None


def _stop_proc(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    proc.kill()
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _run_extract_capped(args: list[str], tmpd: Path, budget: int, kind: str) -> None:
    """Extrae con tope de tamaño/entradas y de tiempo. Mata el proceso si se pasa."""
    try:
        proc = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        raise InboxError(f"no pude descomprimir el {kind.upper()}") from exc
    deadline = time.monotonic() + 180
    reason = ""
    try:
        while True:
            rc = proc.poll()
            used, nfiles = _tmp_usage(tmpd)
            if used > budget or nfiles > MAX_ENTRIES:
                reason = "budget"
                break
            if rc is not None:
                return
            if time.monotonic() > deadline:
                reason = "timeout"
                break
            time.sleep(0.2)
    finally:
        if reason:
            _stop_proc(proc)
    if reason == "budget":
        raise InboxError("la descompresión supera el límite (posible zip bomb)")
    if reason == "timeout":
        raise InboxError(f"no pude descomprimir el {kind.upper()}")


def _extract_external(src: Path, dest: Path, budget: int, kind: str) -> list[dict]:
    """RAR / 7z: requiere una herramienta del host. Sin ella, se avisa claro."""
    with tempfile.TemporaryDirectory() as tmpd:
        args = _external_cmd(src, tmpd, kind)
        if not args:
            raise InboxError(
                f"no puedo abrir {kind.upper()} en este host "
                "(instala unrar, 7z o bsdtar; usa .zip o .tar como alternativa)"
            )
        _run_extract_capped(args, Path(tmpd), budget, kind)
        return _ingest_dir(Path(tmpd), dest, budget)


def _ingest_dir(src: Path, dest: Path, budget: int) -> list[dict]:
    """Copia un árbol ya extraído aplicando saneo y límites."""
    out: list[dict] = []
    used = 0
    for p in sorted(src.rglob("*")):
        if p.is_symlink() or not p.is_file():
            continue
        rel = p.relative_to(src).as_posix()
        parts = _guard(rel, p.stat().st_size, used, len(out), budget)
        if parts is None:
            continue
        target = _dest_for(dest, parts)
        with p.open("rb") as fh:
            written = _stream(fh, target, p.stat().st_size, used, budget)
        used += written
        out.append({"name": target.relative_to(dest).as_posix(), "size": written})
    return out



def remove_staging(cfg: Config, inbox_id: str) -> None:
    if not INBOX_ID_RE.match(inbox_id or ""):
        return
    folder = staging_root(cfg) / inbox_id
    if folder.is_dir():
        shutil.rmtree(folder, ignore_errors=True)


def sweep_stale(cfg: Config, *, now: float | None = None, keep: set[str] | None = None) -> None:
    root = staging_root(cfg)
    if not root.is_dir():
        return
    keep = keep or set()
    stamp = now if now is not None else time.time()
    for p in root.iterdir():
        if not p.is_dir() or p.name in keep or not INBOX_ID_RE.match(p.name):
            continue
        try:
            age = stamp - p.stat().st_mtime
        except OSError:
            continue
        if age > _STALE_S:
            shutil.rmtree(p, ignore_errors=True)


def copy_into_run(src: Path, dest: Path) -> list[dict]:
    """Copia un directorio de anexos (recursivo) al run. No sigue symlinks."""
    if not src.is_dir():
        raise InboxError("no hay anexos en esa ruta")
    dest.mkdir(parents=True, exist_ok=True)
    copied: list[dict] = []
    total = 0
    for p in _iter_files(src):
        parts = _safe_parts(p.relative_to(src).as_posix())
        if parts is None:
            continue
        try:
            size = p.stat().st_size
        except OSError as exc:
            raise InboxError(f"no puedo leer {p.name}") from exc
        if size < 1:
            continue
        if size > MAX_FILE:
            raise InboxError(f"{parts[-1]} supera {MAX_FILE // (1024 * 1024)} MB")
        if len(copied) >= MAX_ENTRIES:
            raise InboxError(f"como mucho {MAX_ENTRIES} archivos")
        if total + size > MAX_TOTAL:
            raise InboxError(f"el lote no puede superar {MAX_TOTAL // (1024 * 1024)} MB")
        target = _dest_for(dest, parts)
        shutil.copy2(p, target, follow_symlinks=False)
        copied.append({"name": target.relative_to(dest).as_posix(), "size": size})
        total += size
    if not copied:
        raise InboxError("el directorio de anexos está vacío")
    return copied


def copy_paths(files: list[Path], dest: Path) -> list[dict]:
    """Anexos sueltos (CLI --anexo). Un comprimido se descomprime igual que en la UI."""
    dest.mkdir(parents=True, exist_ok=True)
    copied: list[dict] = []
    total = 0
    for raw in files:
        p = Path(raw)
        if p.is_symlink() or not p.is_file():
            raise InboxError(f"anexo no válido: {p.name or p}")
        size = p.stat().st_size
        if size < 1:
            raise InboxError(f"{p.name} está vacío")
        if size > MAX_FILE:
            raise InboxError(f"{p.name} supera {MAX_FILE // (1024 * 1024)} MB")
        ext = _archive_ext(p.name)
        if ext:
            sub = _unique_dir(dest, _archive_stem(p.name, ext))
            extracted = _extract(p, sub, ext, MAX_TOTAL - total)
            if not extracted:
                shutil.rmtree(sub, ignore_errors=True)
                raise InboxError(f"{p.name}: comprimido vacío o cifrado")
            for f in extracted:
                total += int(f["size"])
            copied.extend({"name": f"{sub.name}/{f['name']}", "size": f["size"]} for f in extracted)
            continue
        clean = safe_name(p.name)
        if len(copied) >= MAX_ENTRIES:
            raise InboxError(f"como mucho {MAX_ENTRIES} archivos")
        if total + size > MAX_TOTAL:
            raise InboxError(f"el lote no puede superar {MAX_TOTAL // (1024 * 1024)} MB")
        target = _unique_dest(dest, clean)
        shutil.copy2(p, target, follow_symlinks=False)
        copied.append({"name": target.name, "size": size})
        total += size
    return copied


def materialize(
    dest: Path, *, inbox_dir: str = "", attach: list[str] | None = None
) -> list[dict]:
    """Instala anexos en dest. Devuelve la lista o [] si no hay nada."""
    files = [str(x).strip() for x in (attach or []) if str(x).strip()]
    src = (inbox_dir or "").strip()
    if not src and not files:
        return []
    dest = Path(dest)
    copied: list[dict] = []
    if src:
        copied = copy_into_run(Path(src), dest)
    if files:
        extra = copy_paths([Path(p) for p in files], dest)
        copied.extend(extra)
    return copied


def brief_lines(files: list[dict], *, compact: bool = False) -> str:
    if not files:
        return ""
    if compact:
        return f"Anexos: `{INBOX_MOUNT}` ({len(files)})\n"
    rows = "\n".join(f"- `{f['name']}` ({_size_label(int(f.get('size') or 0))})" for f in files)
    return (
        f"## Anexos del operador\n"
        f"Solo lectura en `{INBOX_MOUNT}/`. Léelos **antes** de planear. "
        f"No los copies a findings salvo que sean evidencia de un hallazgo.\n\n"
        f"{rows}\n"
    )



def _archive_stem(name: str, ext: str) -> str:
    base = name[: -len(ext)] if ext and name.lower().endswith(ext) else name
    base = base.strip() or "anexos"
    try:
        return safe_name(base)
    except InboxError:
        return "anexos"


def _dest_for(base: Path, parts: list[str]) -> Path:
    target = base.joinpath(*parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        return target
    stem, suf = target.stem, target.suffix
    n = 2
    while True:
        cand = target.with_name(f"{stem}-{n}{suf}")
        if not cand.exists():
            return cand
        n += 1


def _unique_dest(folder: Path, name: str) -> Path:
    dest = folder / name
    if not dest.exists():
        return dest
    stem, suf = dest.stem, dest.suffix
    n = 2
    while True:
        cand = folder / f"{stem}-{n}{suf}"
        if not cand.exists():
            return cand
        n += 1


def _unique_dir(folder: Path, name: str) -> Path:
    cand = folder / name
    n = 2
    while cand.exists():
        cand = folder / f"{name}-{n}"
        n += 1
    cand.mkdir(parents=True, exist_ok=False)
    return cand


def _size_label(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"
