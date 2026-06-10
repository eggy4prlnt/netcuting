"""Network interface and routing helpers."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass


@dataclass
class NetworkInfo:
    interface: str
    local_ip: str
    local_mac: str
    gateway_ip: str
    gateway_mac: str
    subnet: str


def _run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return result.stdout


def get_default_interface() -> str:
    output = _run(["route", "-n", "get", "default"])
    match = re.search(r"interface:\s*(\S+)", output)
    if not match:
        raise RuntimeError("Tidak bisa menemukan interface default")
    return match.group(1)


def get_gateway_ip() -> str:
    output = _run(["route", "-n", "get", "default"])
    match = re.search(r"gateway:\s*(\S+)", output)
    if not match:
        raise RuntimeError("Tidak bisa menemukan gateway")
    return match.group(1)


def get_local_ip(interface: str) -> str:
    output = subprocess.run(
        ["ipconfig", "getifaddr", interface],
        capture_output=True,
        text=True,
    )
    ip = output.stdout.strip()
    if not ip:
        raise RuntimeError(f"Tidak ada IP di interface {interface}")
    return ip


def get_local_mac(interface: str) -> str:
    output = _run(["ifconfig", interface])
    match = re.search(r"ether\s+([0-9a-f:]+)", output, re.IGNORECASE)
    if not match:
        raise RuntimeError(f"Tidak bisa membaca MAC address di {interface}")
    return match.group(1).lower()


def _cidr_to_subnet(cidr: str) -> str:
    """Convert route notation like 192.168.100/22 to scapy format 192.168.100.0/22."""
    if "/" not in cidr:
        return cidr

    network, prefix = cidr.split("/", 1)
    octets = network.split(".")

    if len(octets) == 3:
        return f"{network}.0/{prefix}"
    if len(octets) == 4:
        return f"{network}/{prefix}"

    raise ValueError(f"Format CIDR tidak dikenal: {cidr}")


def get_subnet_from_route(interface: str) -> str:
    output = _run(["netstat", "-rn"])
    best: tuple[int, str] | None = None

    for line in output.splitlines():
        if interface not in line:
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        destination, _gateway = parts[0], parts[1]
        if destination in {"default", "link#", "localhost"}:
            continue
        if destination.startswith("127.") or destination.startswith("169.254"):
            continue
        if destination.startswith("224.") or destination.startswith("239."):
            continue
        if destination.startswith("fe80:") or destination.startswith("ff"):
            continue
        if "/" not in destination:
            continue

        try:
            prefix = int(destination.split("/", 1)[1])
        except ValueError:
            continue

        if best is None or prefix < best[0]:
            best = (prefix, _cidr_to_subnet(destination))

    if best:
        return best[1]

    raise RuntimeError(f"Tidak bisa menemukan subnet untuk {interface}")


def ip_to_subnet(ip: str) -> str:
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def is_root() -> bool:
    import os

    return os.geteuid() == 0


def detect_network() -> NetworkInfo:
    interface = get_default_interface()
    local_ip = get_local_ip(interface)
    local_mac = get_local_mac(interface)
    gateway_ip = get_gateway_ip()

    try:
        subnet = get_subnet_from_route(interface)
    except RuntimeError:
        subnet = ip_to_subnet(local_ip)

    return NetworkInfo(
        interface=interface,
        local_ip=local_ip,
        local_mac=local_mac,
        gateway_ip=gateway_ip,
        gateway_mac="",
        subnet=subnet,
    )
