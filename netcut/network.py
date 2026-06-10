"""Network interface and routing helpers."""

from __future__ import annotations

from dataclasses import dataclass

from netcut.platform_ops import (
    get_default_interface,
    get_gateway_ip,
    get_local_ip,
    get_local_mac,
    get_subnet_for_interface,
    is_privileged,
    resolve_packet_interface,
)


@dataclass
class NetworkInfo:
    interface: str
    local_ip: str
    local_mac: str
    gateway_ip: str
    gateway_mac: str
    subnet: str


def ip_to_subnet(ip: str) -> str:
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def detect_network() -> NetworkInfo:
    interface = get_default_interface()
    local_ip = get_local_ip(interface)
    local_mac = get_local_mac(interface)
    gateway_ip = get_gateway_ip()

    try:
        subnet = get_subnet_for_interface(interface, local_ip)
    except RuntimeError:
        subnet = ip_to_subnet(local_ip)

    interface = resolve_packet_interface(interface, local_ip)

    return NetworkInfo(
        interface=interface,
        local_ip=local_ip,
        local_mac=local_mac,
        gateway_ip=gateway_ip,
        gateway_mac="",
        subnet=subnet,
    )


def is_root() -> bool:
    return is_privileged()
