"""MAC vendor (OUI) lookup."""

from __future__ import annotations

import re

_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", re.I)


def _is_randomized_mac(mac: str) -> bool:
    """Locally administered MAC — OUI vendor lookup is meaningless."""
    try:
        first_octet = int(mac.split(":")[0], 16)
    except ValueError:
        return False
    return bool(first_octet & 0x02)


def lookup_vendor(mac: str) -> str:
    mac = mac.lower()
    if not _MAC_RE.match(mac) or _is_randomized_mac(mac):
        return ""

    try:
        from scapy.config import conf

        short, long = conf.manufdb.lookup(mac)
    except Exception:
        return _lookup_vendor_legacy(mac)

    for candidate in (long, short):
        if not candidate:
            continue
        normalized = candidate.strip()
        if normalized.lower() == mac.lower():
            continue
        if _MAC_RE.match(normalized):
            continue
        return normalized
    return ""


def _lookup_vendor_legacy(mac: str) -> str:
    try:
        from scapy.layers.l2 import get_manuf
    except ImportError:
        return ""
    try:
        vendor = get_manuf(mac)
        return vendor if vendor and vendor != "Unknown" else ""
    except Exception:
        return ""
