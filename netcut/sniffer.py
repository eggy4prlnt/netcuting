"""Passive DNS / HTTP / TLS-SNI sniffer for a LAN target."""

from __future__ import annotations

import re
import threading
import time
from collections import deque
from dataclasses import dataclass

from scapy.all import DNS, IP, TCP, UDP, sniff
from scapy.layers.inet6 import IPv6

from netcut.verbose import vlog

_HOST_RE = re.compile(rb"Host:\s*([^\r\n]+)", re.I)


@dataclass(frozen=True)
class SniffHit:
    ts: float
    kind: str
    domain: str

    @property
    def label(self) -> str:
        prefix = {"dns": "DNS", "http": "HTTP", "tls": "HTTPS"}.get(self.kind, self.kind.upper())
        return f"{prefix} {self.domain}"


def _normalize_domain(raw: str | bytes) -> str:
    if isinstance(raw, bytes):
        text = raw.decode(errors="ignore")
    else:
        text = raw
    text = text.strip().rstrip(".")
    if text.endswith("."):
        text = text[:-1]
    return text.lower()


def _extract_http_host(payload: bytes) -> str | None:
    match = _HOST_RE.search(payload)
    if not match:
        return None
    host = match.group(1).decode(errors="ignore").strip()
    if ":" in host:
        host = host.split(":", 1)[0]
    return host or None


def _extract_tls_sni(payload: bytes) -> str | None:
    """Parse TLS ClientHello Server Name Indication."""
    if len(payload) < 43 or payload[0] != 0x16:
        return None

    try:
        rec_len = int.from_bytes(payload[3:5], "big")
        hs = payload[5 : 5 + rec_len]
        if len(hs) < 38 or hs[0] != 0x01:
            return None

        idx = 38
        sid_len = hs[38]
        idx = 39 + sid_len
        if idx + 2 > len(hs):
            return None
        cs_len = int.from_bytes(hs[idx : idx + 2], "big")
        idx += 2 + cs_len
        if idx >= len(hs):
            return None
        comp_len = hs[idx]
        idx += 1 + comp_len
        if idx + 2 > len(hs):
            return None
        ext_total = int.from_bytes(hs[idx : idx + 2], "big")
        idx += 2
        ext_end = idx + ext_total

        while idx + 4 <= ext_end and idx + 4 <= len(hs):
            ext_type = int.from_bytes(hs[idx : idx + 2], "big")
            ext_len = int.from_bytes(hs[idx + 2 : idx + 4], "big")
            idx += 4
            ext_data = hs[idx : idx + ext_len]
            idx += ext_len
            if ext_type != 0:
                continue
            if len(ext_data) < 5:
                continue
            name_len = int.from_bytes(ext_data[3:5], "big")
            name = ext_data[5 : 5 + name_len].decode(errors="ignore")
            if name:
                return name
    except Exception:
        return None
    return None


def _packet_src_ips(pkt) -> set[str]:
    ips: set[str] = set()
    if IP in pkt:
        ips.add(pkt[IP].src)
    if IPv6 in pkt:
        ips.add(str(pkt[IPv6].src).split("%")[0])
    return ips


class TargetSniffer:
    """Background sniffer filtered to one target's traffic."""

    def __init__(
        self,
        *,
        target_ip: str,
        target_mac: str,
        target_ipv6: list[str] | None = None,
        interface: str,
        max_hits: int = 100,
        dedupe_seconds: float = 3.0,
    ):
        self.target_ip = target_ip
        self.target_mac = target_mac.lower()
        self.target_ipv6 = list(target_ipv6 or [])
        self.interface = interface
        self.max_hits = max_hits
        self.dedupe_seconds = dedupe_seconds

        self._hits: deque[SniffHit] = deque(maxlen=max_hits)
        self._seen: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _bpf_filter(self) -> str:
        ports = "(udp port 53 or tcp port 80 or tcp port 443)"
        return f"ether host {self.target_mac} and {ports}"

    def _from_target(self, pkt) -> bool:
        if getattr(pkt, "src", None) and pkt.src.lower() == self.target_mac:
            return True
        return bool(_packet_src_ips(pkt) & {self.target_ip, *self.target_ipv6})

    def _remember(self, kind: str, domain: str) -> None:
        domain = _normalize_domain(domain)
        if not domain or domain in {".", "localhost"}:
            return
        if domain.endswith(".local") or domain.endswith(".lan"):
            return

        now = time.time()
        key = (kind, domain)
        with self._lock:
            last = self._seen.get(key)
            if last is not None and now - last < self.dedupe_seconds:
                return
            self._seen[key] = now
            self._hits.append(SniffHit(ts=now, kind=kind, domain=domain))

        vlog(2, f"Sniff {kind.upper()} {domain}")

    def _handle_packet(self, pkt) -> None:
        if not self._from_target(pkt):
            return

        if DNS in pkt and pkt[DNS].qr == 0 and pkt[DNS].qd is not None:
            qname = pkt[DNS].qd.qname
            if qname:
                self._remember("dns", qname.decode() if isinstance(qname, bytes) else str(qname))
            return

        if TCP not in pkt:
            return

        payload = bytes(pkt[TCP].payload)
        if not payload:
            return

        dport = int(pkt[TCP].dport)
        sport = int(pkt[TCP].sport)

        if dport == 80 or sport == 80:
            host = _extract_http_host(payload)
            if host:
                self._remember("http", host)
            return

        if dport == 443 or sport == 443:
            sni = _extract_tls_sni(payload)
            if sni:
                self._remember("tls", sni)

    def _run(self) -> None:
        vlog(1, f"Sniffer aktif filter={self._bpf_filter()}")
        try:
            sniff(
                filter=self._bpf_filter(),
                iface=self.interface,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _: self._stop.is_set(),
            )
        except Exception as exc:
            vlog(1, f"Sniffer berhenti: {exc}", style="dim red")

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    def recent(self, limit: int = 8) -> list[SniffHit]:
        with self._lock:
            return list(self._hits)[-limit:]

    @property
    def total(self) -> int:
        with self._lock:
            return len(self._hits)
