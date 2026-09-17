from __future__ import annotations

import csv
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

_HOSTPORT = re.compile(
    r"^(?P<host>(?:\d{1,3}(?:\.\d{1,3}){3})|(?:\[[0-9a-fA-F:]+\])):(?P<port>\d{1,5})$"
)


@dataclass(frozen=True)
class Target:
    raw: str
    kind: str  # ipv4 | ipv6 | hostport | cidr | url
    value: str
    port: int | None = None

    def asset(self) -> str:
        if self.port:
            return f"{self.value}:{self.port}"
        return self.value

    def in_scope_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if self.kind == "cidr":
            return addr in ipaddress.ip_network(self.value, strict=False)
        if self.kind in {"ipv4", "ipv6", "hostport"}:
            try:
                return addr == ipaddress.ip_address(self.value)
            except ValueError:
                return False
        if self.kind == "url":
            host = urlparse(self.value).hostname
            if not host:
                return False
            try:
                return addr == ipaddress.ip_address(host)
            except ValueError:
                return False
        return False


def parse_targets(spec: str) -> list[Target]:
    spec = spec.strip()
    if not spec:
        raise ValueError("target vacío")
    path = Path(spec)
    if path.is_file():
        return _from_file(path)
    if "," in spec:
        items: list[Target] = []
        for part in spec.split(","):
            part = part.strip()
            if part:
                items.append(parse_one(part))
        if not items:
            raise ValueError("lista de targets vacía")
        return _dedupe(items)
    return [parse_one(spec)]


def parse_one(item: str) -> Target:
    item = item.strip()
    if not item or item.startswith("#"):
        raise ValueError("target vacío")
    if item.startswith(("http://", "https://")):
        parsed = urlparse(item)
        if not parsed.hostname:
            raise ValueError(f"URL inválida: {item}")
        return Target(raw=item, kind="url", value=item, port=parsed.port)
    try:
        net = ipaddress.ip_network(item, strict=False)
        if "/" in item:
            return Target(raw=item, kind="cidr", value=str(net))
    except ValueError:
        pass
    m = _HOSTPORT.match(item)
    if m:
        host = m.group("host").strip("[]")
        port = int(m.group("port"))
        if not 1 <= port <= 65535:
            raise ValueError(f"puerto inválido: {item}")
        kind = "hostport"
        try:
            addr = ipaddress.ip_address(host)
            return Target(raw=item, kind=kind, value=str(addr), port=port)
        except ValueError as exc:
            raise ValueError(f"host inválido: {item}") from exc
    try:
        addr = ipaddress.ip_address(item)
        kind = "ipv4" if addr.version == 4 else "ipv6"
        return Target(raw=item, kind=kind, value=str(addr))
    except ValueError as exc:
        raise ValueError(
            f"target no reconocido: {item}. "
            "Usa IPv4, IPv6, IP:puerto, CIDR, URL http(s) o un archivo/CSV."
        ) from exc


def _from_file(path: Path) -> list[Target]:
    text = path.read_text(encoding="utf-8")
    items: list[Target] = []
    if path.suffix.lower() == ".csv" or "," in text.splitlines()[0] if text.strip() else False:
        reader = csv.reader(text.splitlines())
        for row in reader:
            for cell in row:
                cell = cell.strip()
                if cell and not cell.startswith("#") and cell.lower() not in {"target", "targets", "ip", "url"}:
                    items.append(parse_one(cell))
    else:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "," in line:
                for cell in line.split(","):
                    cell = cell.strip()
                    if cell:
                        items.append(parse_one(cell))
            else:
                items.append(parse_one(line))
    if not items:
        raise ValueError(f"ningún target en {path}")
    return _dedupe(items)


def _dedupe(items: list[Target]) -> list[Target]:
    seen: set[str] = set()
    out: list[Target] = []
    for t in items:
        key = f"{t.kind}:{t.value}:{t.port}"
        if key in seen:
            continue
        seen.add(key)
        out.append(t)
    return out


IP_KINDS = frozenset({"ipv4", "ipv6", "hostport", "cidr"})


def has_ip_target(targets: list[Target]) -> bool:
    """True si hay una IP/CIDR (una URL sola no cuenta)."""
    return any(t.kind in IP_KINDS for t in targets)


def has_cidr(targets: list[Target]) -> bool:
    """True si hay al menos un prefijo CIDR."""
    return any(t.kind == "cidr" for t in targets)


def ip_in_scope(ip: str, targets: list[Target]) -> bool:
    return any(t.in_scope_ip(ip) for t in targets)
