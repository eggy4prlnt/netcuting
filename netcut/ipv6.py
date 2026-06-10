"""IPv6 discovery and NDP helpers for dual-stack cutting."""

from __future__ import annotations

import ipaddress
import re
import subprocess
from typing import Iterable

from scapy.all import sniff
from scapy.layers.inet6 import IPv6

from netcut.verbose import vlog


def normalize_ipv6(addr: str) -> str:
    return str(ipaddress.ip_address(addr.split("%")[0]))


def mac_to_link_local(mac: str) -> str:
    """Derive stable link-local IPv6 from MAC (EUI-64)."""
    octets = [int(part, 16) for part in mac.split(":")]
    eui64 = bytes(
        [
            octets[0] ^ 0x02,
            octets[1],
            octets[2],
            0xFF,
            0xFE,
            octets[3],
            octets[4],
            octets[5],
        ]
    )
    hexstr = eui64.hex()
    return (
        f"fe80::{hexstr[0:4]}:{hexstr[4:8]}:"
        f"{hexstr[8:12]}:{hexstr[12:16]}"
    )


def parse_ndp_table(interface: str) -> dict[str, list[str]]:
    """Map MAC address -> IPv6 addresses seen on an interface."""
    try:
        result = subprocess.run(
            ["ndp", "-an"],
            capture_output=True,
            text=True,
            check=True,
        )
    except Exception:
        return {}

    mac_to_ipv6: dict[str, list[str]] = {}

    for line in result.stdout.splitlines():
        if interface not in line:
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        ipv6_raw = parts[0]
        mac = parts[1].lower()
        if mac == "(incomplete)" or ":" not in mac:
            continue

        try:
            ipv6 = normalize_ipv6(ipv6_raw)
        except ValueError:
            continue

        mac_to_ipv6.setdefault(mac, [])
        if ipv6 not in mac_to_ipv6[mac]:
            mac_to_ipv6[mac].append(ipv6)

    return mac_to_ipv6


def get_local_link_locals(interface: str, local_mac: str) -> list[str]:
    addrs = parse_ndp_table(interface).get(local_mac.lower(), [])
    link_locals = [addr for addr in addrs if addr.startswith("fe80:")]
    if link_locals:
        return link_locals

    try:
        output = subprocess.run(
            ["ifconfig", interface],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except Exception:
        return []

    found: list[str] = []
    for line in output.splitlines():
        match = re.search(r"inet6\s+(fe80:[0-9a-f:]+)", line, re.IGNORECASE)
        if not match:
            continue
        try:
            found.append(normalize_ipv6(match.group(1)))
        except ValueError:
            continue
    return found


def sniff_ipv6_from_mac(mac: str, interface: str, timeout: float = 1.5) -> list[str]:
    try:
        packets = sniff(
            filter=f"ether src {mac} and ip6",
            iface=interface,
            timeout=timeout,
            store=True,
        )
    except Exception:
        return []

    addrs: set[str] = set()
    for pkt in packets:
        if IPv6 not in pkt:
            continue
        try:
            addrs.add(normalize_ipv6(pkt[IPv6].src))
        except ValueError:
            continue
    return sorted(addrs)


def resolve_ipv6_for_mac(
    mac: str,
    interface: str,
    *,
    include_guess: bool = True,
    sniff_seconds: float = 1.0,
) -> list[str]:
    """Collect IPv6 addresses for a MAC from NDP cache, sniffing, and EUI-64."""
    mac = mac.lower()
    found: list[str] = []

    for addr in parse_ndp_table(interface).get(mac, []):
        if addr not in found:
            found.append(addr)

    for addr in sniff_ipv6_from_mac(mac, interface, sniff_seconds):
        if addr not in found:
            found.append(addr)

    if include_guess:
        guess = mac_to_link_local(mac)
        if guess not in found:
            found.append(guess)
            vlog(3, f"IPv6 EUI-64 guess untuk {mac}: {guess}")

    vlog(2, f"IPv6 untuk {mac}: {found or ['-']}")
    return found


def pick_gateway_ipv6(
    gateway_mac: str,
    interface: str,
    *,
    fallback_guess: bool = True,
) -> list[str]:
    """Resolve router IPv6 addresses used for on-link NDP."""
    gateway_mac = gateway_mac.lower()
    addrs = resolve_ipv6_for_mac(
        gateway_mac,
        interface,
        include_guess=fallback_guess,
        sniff_seconds=0.5,
    )

    link_locals = [addr for addr in addrs if addr.startswith("fe80:")]
    if link_locals:
        return link_locals
    return addrs


def merge_unique(*groups: Iterable[str]) -> list[str]:
    merged: list[str] = []
    for group in groups:
        for item in group:
            if item not in merged:
                merged.append(item)
    return merged
