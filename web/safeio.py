from __future__ import annotations

import os
from pathlib import Path

_LEAF = frozenset(
    {
        "STATE.md",
        "console.log",
        "events.jsonl",
    }
)


def path_inside(root: Path, candidate: Path) -> bool:
    try:
        base = root.resolve()
        target = candidate.resolve()
        return target == base or base in target.parents
    except OSError:
        return False


def contained_file(root: Path, name: str) -> Path | None:
    """Fichero real con ese nombre dentro de root. Rechaza symlink y escape."""
    if name not in _LEAF:
        return None
    try:
        base = root.resolve()
    except OSError:
        return None
    raw = base / name
    try:
        if raw.is_symlink() or not raw.is_file():
            return None
        target = raw.resolve()
    except OSError:
        return None
    if not path_inside(base, target) or not target.is_file() or target.is_symlink():
        return None
    return target


def read_contained_text(root: Path, name: str, *, max_bytes: int | None = None) -> str:
    path = contained_file(root, name)
    if path is None:
        return ""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return ""
    try:
        with os.fdopen(fd, "rb", closefd=True) as fh:
            data = fh.read() if max_bytes is None else fh.read(max_bytes)
    except OSError:
        return ""
    return data.decode("utf-8", errors="replace")


def read_contained_bytes(root: Path, name: str) -> bytes | None:
    path = contained_file(root, name)
    if path is None:
        return None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb", closefd=True) as fh:
            return fh.read()
    except OSError:
        return None
