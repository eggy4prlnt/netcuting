"""Hostname resolution for discovered devices."""

from __future__ import annotations

import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

from netcut.verbose import vlog


def _clean_hostname(name: str) -> str:
    name = name.strip().rstrip(".")
    if name.endswith(".lan"):
        return name[:-4]
    return name


def _resolve_mdns(ip: str) -> str:
    try:
        result = subprocess.run(
            ["/usr/bin/dig", "@224.0.0.251", "-x", ip, "+short", "+time=1", "+tries=1"],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""

    for line in result.stdout.splitlines():
        line = line.strip()
        if line and not line.startswith(";"):
            return _clean_hostname(line)
    return ""


def _resolve_reverse_dns(ip: str) -> str:
    try:
        result = subprocess.run(
            ["/usr/bin/dig", "+short", "-x", ip, "+time=1", "+tries=1"],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""

    for line in result.stdout.splitlines():
        line = line.strip()
        if line and not line.startswith(";") and not re.match(r"^\d+\.\d+\.\d+\.\d+", line):
            return _clean_hostname(line)
    return ""


def resolve_hostname(ip: str) -> str:
    name = _resolve_mdns(ip)
    if name:
        vlog(3, f"Hostname {ip} via mDNS: {name}")
        return name
    name = _resolve_reverse_dns(ip)
    if name:
        vlog(3, f"Hostname {ip} via rDNS: {name}")
    else:
        vlog(3, f"Hostname {ip}: tidak ditemukan")
    return name


def resolve_hostnames(devices: list, max_workers: int = 12) -> None:
    """Fill device.hostname in parallel (mutates devices in place)."""
    if not devices:
        return

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(resolve_hostname, d.ip): d for d in devices}
        for future in as_completed(futures):
            device = futures[future]
            try:
                device.hostname = future.result(timeout=4)
            except Exception:
                device.hostname = ""
