"""ARP network scanner."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field

from scapy.all import ARP, Ether, srp

from netcut.classifier import classify_device, kind_label
from netcut.ipv6 import resolve_ipv6_for_mac
from netcut.resolver import resolve_hostnames
from netcut.verbose import vlog


@dataclass
class Device:
    ip: str
    mac: str
    vendor: str = ""
    hostname: str = ""
    ipv6_addresses: list[str] = field(default_factory=list)
    device_kind: str = "unknown"
    device_type: str = "?"
    is_gateway: bool = False
    is_self: bool = False


@dataclass
class ScanResult:
    devices: list[Device] = field(default_factory=list)
    gateway_mac: str = ""


def _lookup_vendor(mac: str) -> str:
    try:
        from scapy.layers.l2 import get_manuf
    except ImportError:
        return ""

    try:
        vendor = get_manuf(mac)
        return vendor if vendor and vendor != "Unknown" else ""
    except Exception:
        return ""


def arp_scan_raw(
    subnet: str,
    interface: str,
    local_ip: str,
    gateway_ip: str,
    timeout: int = 3,
) -> tuple[list[Device], str]:
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    answered, _ = srp(
        packet,
        timeout=timeout,
        verbose=False,
        iface=interface,
    )

    devices: list[Device] = []
    gateway_mac = ""

    for _, received in answered:
        ip = received.psrc
        mac = received.hwsrc.lower()

        if ip == gateway_ip:
            gateway_mac = mac

        devices.append(
            Device(
                ip=ip,
                mac=mac,
                vendor=_lookup_vendor(mac),
                is_gateway=(ip == gateway_ip),
                is_self=(ip == local_ip),
            )
        )

    devices.sort(key=lambda d: [int(x) for x in d.ip.split(".")])
    vlog(2, f"ARP scan: {len(devices)} respons, gateway_mac={gateway_mac or '-'}")
    return devices, gateway_mac


def _scan_via_sudo(
    subnet: str,
    interface: str,
    local_ip: str,
    gateway_ip: str,
    timeout: int = 3,
) -> tuple[list[Device], str]:
    payload = json.dumps(
        {
            "subnet": subnet,
            "interface": interface,
            "local_ip": local_ip,
            "gateway_ip": gateway_ip,
            "timeout": timeout,
        }
    )

    result = subprocess.run(
        ["sudo", "-E", sys.executable, "-m", "netcut.scan_worker"],
        input=payload,
        capture_output=True,
        text=True,
        timeout=120,
    )

    if result.returncode != 0:
        err = result.stderr.strip() or "ARP scan gagal"
        raise RuntimeError(err)

    data = json.loads(result.stdout)
    devices = [
        Device(
            ip=item["ip"],
            mac=item["mac"],
            vendor=item.get("vendor", ""),
            is_gateway=item.get("is_gateway", False),
            is_self=item.get("is_self", False),
        )
        for item in data["devices"]
    ]
    return devices, data.get("gateway_mac", "")


def scan_network(
    subnet: str,
    interface: str,
    local_ip: str,
    gateway_ip: str,
    timeout: int = 3,
) -> ScanResult:
    if os.geteuid() == 0:
        vlog(2, "ARP scan langsung (root)")
        devices, gateway_mac = arp_scan_raw(
            subnet, interface, local_ip, gateway_ip, timeout
        )
    else:
        vlog(2, "ARP scan via sudo worker")
        devices, gateway_mac = _scan_via_sudo(
            subnet, interface, local_ip, gateway_ip, timeout
        )

    resolve_hostnames(devices)

    for device in devices:
        device.ipv6_addresses = resolve_ipv6_for_mac(
            device.mac,
            interface,
            sniff_seconds=0.5,
        )
        device.device_kind = classify_device(
            hostname=device.hostname,
            vendor=device.vendor,
            is_gateway=device.is_gateway,
        )
        device.device_type = kind_label(device.device_kind)
        vlog(
            2,
            f"{device.ip} {device.mac} name={device.hostname or '-'} "
            f"vendor={device.vendor or '-'} tipe={device.device_type} "
            f"ipv6={device.ipv6_addresses or ['-']}",
        )

    return ScanResult(devices=devices, gateway_mac=gateway_mac)
