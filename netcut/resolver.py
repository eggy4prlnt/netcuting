"""Hostname resolution for discovered devices."""

from __future__ import annotations

import re
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from netcut.platform_ops import find_dig
from netcut.verbose import vlog

_MDNS_CACHE: dict[str, str] = {}


def _clean_hostname(name: str) -> str:
    name = name.strip().rstrip(".")
    for suffix in (".local", ".lan", ".home", ".localdomain"):
        if name.lower().endswith(suffix):
            name = name[: -len(suffix)]
    return name


def _rr_name(raw: str | bytes) -> str:
    if isinstance(raw, bytes):
        text = raw.decode(errors="ignore")
    else:
        text = str(raw)
    return _clean_hostname(text)


def collect_mdns_names(interface: str, timeout: float = 2.5) -> dict[str, str]:
    """Passive mDNS sniff — build IP -> hostname map."""
    if not interface:
        return {}

    ip_to_name: dict[str, str] = {}

    try:
        from scapy.all import DNS, sniff
    except ImportError:
        return ip_to_name

    def _ingest_rr(rr) -> None:
        try:
            rtype = int(rr.type)
        except Exception:
            return
        name = _rr_name(getattr(rr, "rrname", b""))
        if not name:
            return
        if rtype == 1 and getattr(rr, "rdata", None):
            ip_to_name[str(rr.rdata)] = name
        elif rtype == 12 and getattr(rr, "rdata", None):
            ip_to_name.setdefault(str(rr.rdata), name)

    def _handle_packet(pkt) -> None:
        if DNS not in pkt:
            return
        dns = pkt[DNS]
        for section, count_attr in (
            (dns.an, "ancount"),
            (dns.ns, "nscount"),
            (dns.ar, "arcount"),
        ):
            if not section:
                continue
            count = int(getattr(dns, count_attr, 0) or 0)
            for idx in range(count):
                try:
                    _ingest_rr(section[idx])
                except Exception:
                    continue

    try:
        sniff(
            filter="udp port 5353",
            iface=interface,
            timeout=timeout,
            store=False,
            prn=_handle_packet,
        )
    except Exception as exc:
        vlog(2, f"mDNS sniff gagal: {exc}", style="dim red")

    if ip_to_name:
        vlog(2, f"mDNS cache: {len(ip_to_name)} entri")
    return ip_to_name


def _resolve_mdns_scapy(ip: str, interface: str) -> str:
    try:
        from scapy.all import DNS, DNSQR, Ether, IP, UDP, srp1
    except ImportError:
        return ""

    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    pkt = (
        Ether(dst="01:00:5e:00:00:fb")
        / IP(dst="224.0.0.251")
        / UDP(sport=53535, dport=5353)
        / DNS(rd=0, qd=DNSQR(qname=rev, qtype="PTR"))
    )
    kwargs: dict = {"timeout": 0.8, "verbose": 0}
    if interface:
        kwargs["iface"] = interface
    try:
        ans = srp1(pkt, **kwargs)
    except Exception:
        return ""
    if not ans or DNS not in ans:
        return ""

    dns = ans[DNS]
    if dns.an:
        for idx in range(int(dns.ancount or 0)):
            try:
                rr = dns.an[idx]
                if int(rr.type) == 12:
                    name = _rr_name(rr.rdata)
                    if name:
                        return name
            except Exception:
                continue
    return ""


def _resolve_mdns_dig(ip: str) -> str:
    dig = find_dig()
    if not dig:
        return ""
    try:
        result = subprocess.run(
            [dig, "@224.0.0.251", "-x", ip, "+short", "+time=1", "+tries=1"],
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


def _resolve_reverse_dns_dig(ip: str) -> str:
    dig = find_dig()
    if not dig:
        return ""
    try:
        result = subprocess.run(
            [dig, "+short", "-x", ip, "+time=1", "+tries=1"],
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


def _resolve_socket(ip: str) -> str:
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(1.0)
        name = socket.gethostbyaddr(ip)[0]
        return _clean_hostname(name)
    except OSError:
        return ""
    finally:
        socket.setdefaulttimeout(old_timeout)


def _resolve_nslookup(ip: str) -> str:
    try:
        result = subprocess.run(
            ["nslookup", ip],
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""

    for line in result.stdout.splitlines():
        line = line.strip()
        if line.lower().startswith("name:"):
            name = line.split(":", 1)[1].strip()
            if name and not re.match(r"^\d+\.\d+\.\d+\.\d+", name):
                return _clean_hostname(name)
    return ""


def _resolve_ping_a(ip: str) -> str:
    if sys.platform == "win32":
        cmd = ["ping", "-a", "-n", "1", "-w", "800", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""

    match = re.search(r"Pinging\s+(\S+)\s+\[", result.stdout, re.I)
    if match:
        name = _clean_hostname(match.group(1))
        if name != ip:
            return name
    return ""


def _resolve_netbios(ip: str) -> str:
    if sys.platform != "win32":
        return ""
    try:
        result = subprocess.run(
            ["nbtstat", "-A", ip],
            capture_output=True,
            text=True,
            timeout=4,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""

    for line in result.stdout.splitlines():
        line = line.strip()
        if "<00>" in line and "UNIQUE" in line.upper():
            parts = line.split()
            if parts and not parts[0].startswith("-"):
                name = _clean_hostname(parts[0])
                if name and name.upper() != "HOST NOT FOUND":
                    return name
    return ""


def resolve_hostname(
    ip: str,
    *,
    interface: str = "",
    mdns_cache: dict[str, str] | None = None,
) -> str:
    cache = mdns_cache if mdns_cache is not None else _MDNS_CACHE
    cached = cache.get(ip)
    if cached:
        vlog(3, f"Hostname {ip} via mDNS cache: {cached}")
        return cached

    if interface:
        name = _resolve_mdns_scapy(ip, interface)
        if name:
            vlog(3, f"Hostname {ip} via mDNS query: {name}")
            return name

    for resolver, label in (
        (_resolve_mdns_dig, "mDNS dig"),
        (_resolve_socket, "socket"),
        (_resolve_nslookup, "nslookup"),
        (_resolve_reverse_dns_dig, "rDNS dig"),
        (_resolve_ping_a, "ping -a"),
        (_resolve_netbios, "NetBIOS"),
    ):
        try:
            name = resolver(ip)
        except Exception:
            name = ""
        if name and name != ip:
            vlog(3, f"Hostname {ip} via {label}: {name}")
            return name

    vlog(3, f"Hostname {ip}: tidak ditemukan")
    return ""


def resolve_hostnames(
    devices: list,
    *,
    interface: str = "",
    mdns_cache: dict[str, str] | None = None,
    max_workers: int = 12,
) -> None:
    """Fill device.hostname in parallel (mutates devices in place)."""
    if not devices:
        return

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(
                resolve_hostname,
                d.ip,
                interface=interface,
                mdns_cache=mdns_cache,
            ): d
            for d in devices
        }
        for future in as_completed(futures):
            device = futures[future]
            try:
                device.hostname = future.result(timeout=6)
            except Exception:
                device.hostname = ""
