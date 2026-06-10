"""ARP network scanner."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field

from scapy.all import ARP, Ether, srp

from netcut.classifier import classify_device, kind_label
from netcut.ipv6 import resolve_ipv6_for_mac
from netcut.platform_ops import is_privileged
from netcut.resolver import collect_mdns_names, resolve_hostnames
from netcut.vendor import lookup_vendor
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
    return lookup_vendor(mac)


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


def _scan_via_privileged(
    subnet: str,
    interface: str,
    local_ip: str,
    gateway_ip: str,
    timeout: int = 3,
) -> tuple[list[Device], str]:
    payload = {
        "subnet": subnet,
        "interface": interface,
        "local_ip": local_ip,
        "gateway_ip": gateway_ip,
        "timeout": timeout,
    }

    if sys.platform == "win32":
        return _scan_via_windows_elevated(payload)

    result = subprocess.run(
        ["sudo", "-E", sys.executable, "-m", "netcut.scan_worker"],
        input=json.dumps(payload),
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


def _scan_via_windows_elevated(payload: dict) -> tuple[list[Device], str]:
    import ctypes
    import tempfile

    out_fd, out_path = tempfile.mkstemp(suffix=".json", prefix="netcut_scan_out_")
    os.close(out_fd)
    in_fd, in_path = tempfile.mkstemp(suffix=".json", prefix="netcut_scan_in_")
    payload = {**payload, "output": out_path}
    try:
        with os.fdopen(in_fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
        params = f"-m netcut.scan_worker --payload {in_path}"
        ret = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            params,
            None,
            0,
        )
        if ret <= 32:
            raise RuntimeError("Gagal elevate ke Administrator (UAC ditolak?)")

        for _ in range(120):
            if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
                with open(out_path, encoding="utf-8") as handle:
                    data = json.load(handle)
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
            time.sleep(1)
        raise RuntimeError("ARP scan timeout — pastikan UAC disetujui")
    finally:
        for path in (in_path, out_path):
            try:
                os.remove(path)
            except OSError:
                pass


def scan_network(
    subnet: str,
    interface: str,
    local_ip: str,
    gateway_ip: str,
    timeout: int = 3,
) -> ScanResult:
    if is_privileged():
        vlog(2, "ARP scan langsung (root/admin)")
        devices, gateway_mac = arp_scan_raw(
            subnet, interface, local_ip, gateway_ip, timeout
        )
    else:
        vlog(2, "ARP scan via privileged worker")
        devices, gateway_mac = _scan_via_privileged(
            subnet, interface, local_ip, gateway_ip, timeout
        )

    for device in devices:
        if not device.vendor:
            device.vendor = lookup_vendor(device.mac)

    vlog(1, "Mendengarkan mDNS di LAN (2.5s)...")
    mdns_cache = collect_mdns_names(interface, timeout=2.5)
    resolve_hostnames(devices, interface=interface, mdns_cache=mdns_cache)

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
