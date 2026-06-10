"""Attacker-side verification that a cut target lost internet access."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from scapy.all import ICMP, IP, TCP, sniff
from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6EchoRequest, IPv6

from netcut.cutter import BLACKHOLE_MAC
from netcut.platform_ops import ping_once


@dataclass
class CutStatus:
    lan_up: bool | None
    poison_target: bool | None
    poison_gateway: bool | None
    ndp_poison_target: bool | None = None
    ndp_poison_gateway: bool | None = None
    outbound_attempts: int = 0
    inbound_responses: int = 0
    ipv6_outbound_attempts: int = 0
    ipv6_inbound_responses: int = 0
    internet_cut: bool | None = None
    summary: str = ""
    target_ipv6: list[str] = field(default_factory=list)


def _subnet_network(subnet: str) -> ipaddress.IPv4Network:
    return ipaddress.ip_network(subnet, strict=False)


def ping_target(ip: str, timeout: float = 1.0) -> bool | None:
    return ping_once(ip, timeout)


def _is_external_v4(ip: str, local_net: ipaddress.IPv4Network) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr not in local_net


def _is_external_v6(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback or addr.is_link_local or addr.is_private:
        return False
    return True


def _packet_is_outbound_attempt_v4(
    pkt,
    target_ip: str,
    local_net: ipaddress.IPv4Network,
) -> bool:
    if IP not in pkt:
        return False
    ip = pkt[IP]
    if ip.src != target_ip:
        return False
    if not _is_external_v4(ip.dst, local_net):
        return False
    if TCP in pkt and pkt[TCP].flags & 0x02:
        return True
    if ICMP in pkt and pkt[ICMP].type == 8:
        return True
    return False


def _packet_is_inbound_response_v4(
    pkt,
    target_ip: str,
    local_net: ipaddress.IPv4Network,
) -> bool:
    if IP not in pkt:
        return False
    ip = pkt[IP]
    if ip.dst != target_ip:
        return False
    if not _is_external_v4(ip.src, local_net):
        return False
    if TCP in pkt and pkt[TCP].flags & 0x12 == 0x12:
        return True
    if ICMP in pkt and pkt[ICMP].type == 0:
        return True
    return False


def _packet_is_outbound_attempt_v6(pkt, target_ipv6: set[str]) -> bool:
    if IPv6 not in pkt:
        return False
    ip = pkt[IPv6]
    if ip.src not in target_ipv6:
        return False
    if not _is_external_v6(ip.dst):
        return False
    if TCP in pkt and pkt[TCP].flags & 0x02:
        return True
    if ICMPv6EchoRequest in pkt:
        return True
    return False


def _packet_is_inbound_response_v6(pkt, target_ipv6: set[str]) -> bool:
    if IPv6 not in pkt:
        return False
    ip = pkt[IPv6]
    if ip.dst not in target_ipv6:
        return False
    if not _is_external_v6(ip.src):
        return False
    if TCP in pkt and pkt[TCP].flags & 0x12 == 0x12:
        return True
    if ICMPv6EchoReply in pkt:
        return True
    return False


def _sniff_blackhole_from(
    src_ip: str,
    interface: str,
    duration: float,
) -> bool:
    try:
        packets = sniff(
            filter=f"ether dst {BLACKHOLE_MAC} and src host {src_ip}",
            iface=interface,
            timeout=duration,
            store=True,
        )
        return len(packets) > 0
    except Exception:
        return False


def _sniff_blackhole_from_mac(
    src_mac: str,
    interface: str,
    duration: float,
) -> bool:
    try:
        packets = sniff(
            filter=f"ether dst {BLACKHOLE_MAC} and ether src {src_mac}",
            iface=interface,
            timeout=duration,
            store=True,
        )
        return len(packets) > 0
    except Exception:
        return False


def probe_cut_status(
    target_ip: str,
    gateway_ip: str,
    subnet: str,
    interface: str,
    *,
    target_mac: str = "",
    gateway_mac: str = "",
    target_ipv6: list[str] | None = None,
    sniff_seconds: float = 2.0,
) -> CutStatus:
    """Check from attacker POV whether target lost internet while staying on LAN."""
    local_net = _subnet_network(subnet)
    target_v6 = set(target_ipv6 or [])

    lan_up = ping_target(target_ip)

    poison_target = _sniff_blackhole_from(target_ip, interface, sniff_seconds)
    poison_gateway = _sniff_blackhole_from(gateway_ip, interface, sniff_seconds)

    ndp_poison_target = None
    ndp_poison_gateway = None
    if target_mac:
        ndp_poison_target = _sniff_blackhole_from_mac(
            target_mac, interface, sniff_seconds
        )
    if gateway_mac:
        ndp_poison_gateway = _sniff_blackhole_from_mac(
            gateway_mac, interface, sniff_seconds
        )

    outbound_attempts = 0
    inbound_responses = 0
    ipv6_outbound_attempts = 0
    ipv6_inbound_responses = 0

    filters = [f"host {target_ip}"]
    if target_v6:
        filters.append(" or ".join(f"host {addr}" for addr in target_v6))
    bpf_filter = " or ".join(f"({item})" for item in filters)

    try:
        packets = sniff(
            filter=bpf_filter,
            iface=interface,
            timeout=sniff_seconds,
            store=True,
        )
        for pkt in packets:
            if _packet_is_outbound_attempt_v4(pkt, target_ip, local_net):
                outbound_attempts += 1
            if _packet_is_inbound_response_v4(pkt, target_ip, local_net):
                inbound_responses += 1
            if target_v6:
                if _packet_is_outbound_attempt_v6(pkt, target_v6):
                    ipv6_outbound_attempts += 1
                if _packet_is_inbound_response_v6(pkt, target_v6):
                    ipv6_inbound_responses += 1
    except Exception:
        pass

    total_inbound = inbound_responses + ipv6_inbound_responses
    total_outbound = outbound_attempts + ipv6_outbound_attempts
    poison_any = poison_target or poison_gateway or ndp_poison_target or ndp_poison_gateway

    internet_cut: bool | None
    if total_inbound > 0:
        internet_cut = False
    elif poison_any:
        internet_cut = True
    elif total_outbound > 0:
        internet_cut = True
    else:
        internet_cut = None

    summary = _build_summary(
        lan_up=lan_up,
        poison_target=poison_target,
        poison_gateway=poison_gateway,
        ndp_poison_target=ndp_poison_target,
        ndp_poison_gateway=ndp_poison_gateway,
        outbound_attempts=total_outbound,
        inbound_responses=total_inbound,
        internet_cut=internet_cut,
        has_ipv6=bool(target_v6),
    )

    return CutStatus(
        lan_up=lan_up,
        poison_target=poison_target,
        poison_gateway=poison_gateway,
        ndp_poison_target=ndp_poison_target,
        ndp_poison_gateway=ndp_poison_gateway,
        outbound_attempts=outbound_attempts,
        inbound_responses=inbound_responses,
        ipv6_outbound_attempts=ipv6_outbound_attempts,
        ipv6_inbound_responses=ipv6_inbound_responses,
        internet_cut=internet_cut,
        summary=summary,
        target_ipv6=sorted(target_v6),
    )


def _build_summary(
    *,
    lan_up: bool | None,
    poison_target: bool,
    poison_gateway: bool,
    ndp_poison_target: bool | None,
    ndp_poison_gateway: bool | None,
    outbound_attempts: int,
    inbound_responses: int,
    internet_cut: bool | None,
    has_ipv6: bool,
) -> str:
    if inbound_responses > 0:
        return "Internet masih aktif (ada respons dari luar)"

    if internet_cut is True:
        if outbound_attempts > 0:
            return "Internet terputus (target coba keluar, tidak ada respons)"
        if poison_target and poison_gateway:
            if has_ipv6 and (ndp_poison_target or ndp_poison_gateway):
                return "Internet terputus (ARP + NDP poison aktif)"
            return "Internet terputus (ARP poison aktif di kedua sisi)"
        if ndp_poison_target or ndp_poison_gateway:
            return "Internet terputus (NDP poison terdeteksi)"
        if poison_target or poison_gateway:
            return "Internet terputus (ARP poison terdeteksi)"
        return "Internet kemungkinan terputus"

    if lan_up is False:
        return "Target offline dari LAN"

    if lan_up is True:
        return "Target online di LAN, internet belum bisa dipastikan (idle)"

    return "Status belum diketahui"
