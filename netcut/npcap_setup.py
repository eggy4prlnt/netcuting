"""Npcap detection and guided install on Windows."""

from __future__ import annotations

import ctypes
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from rich.console import Console
from rich.prompt import Confirm

_NPCAP_DIR = Path(r"C:\Program Files\Npcap")
_FALLBACK_URL = "https://npcap.com/dist/npcap-1.88.exe"


def is_npcap_installed() -> bool:
    if sys.platform != "win32":
        return True

    if (_NPCAP_DIR / "NPFInstall.exe").is_file():
        return True
    if (_NPCAP_DIR / "wpcap.dll").is_file():
        return True

    try:
        import winreg

        for subkey in (r"SOFTWARE\Npcap", r"SOFTWARE\WOW6432Node\Npcap"):
            try:
                winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey)
                return True
            except OSError:
                continue
    except ImportError:
        pass

    try:
        result = subprocess.run(
            ["sc", "query", "npcap"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if "npcap" in result.stdout.lower():
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Npcap"
    if (system32 / "wpcap.dll").is_file():
        return True

    return False


def _latest_npcap_url() -> str:
    try:
        request = urllib.request.Request(
            "https://npcap.com/dist/",
            headers={"User-Agent": "NetCut-CLI/1.0"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            html = response.read().decode(errors="ignore")
        versions = re.findall(r"npcap-(\d+\.\d+(?:\.\d+)?)\.exe", html, re.I)
        if versions:

            def _version_key(raw: str) -> tuple[int, ...]:
                return tuple(int(part) for part in raw.split("."))

            latest = max(versions, key=_version_key)
            return f"https://npcap.com/dist/npcap-{latest}.exe"
    except (urllib.error.URLError, TimeoutError, ValueError):
        pass
    return _FALLBACK_URL


def _download_installer(url: str, dest: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "NetCut-CLI/1.0"})
    with urllib.request.urlopen(request, timeout=120) as response:
        data = response.read()
    dest.write_bytes(data)


def _launch_installer(installer: Path) -> None:
    ret = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        str(installer),
        None,
        None,
        1,
    )
    if ret <= 32:
        raise RuntimeError("Gagal membuka installer Npcap (UAC ditolak?)")


def _wait_for_install(console: Console, timeout_seconds: int = 300) -> bool:
    console.print(
        "[dim]Menunggu instalasi selesai — ikuti wizard Npcap "
        "(I Agree → Install → Finish)...[/dim]"
    )
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if is_npcap_installed():
            return True
        time.sleep(2)
    return is_npcap_installed()


def ensure_npcap(console: Console | None = None, *, interactive: bool = True) -> bool:
    """Ensure Npcap is present on Windows. Returns True if ready to use."""
    if sys.platform != "win32":
        return True
    if is_npcap_installed():
        return True

    out = console or Console()
    out.print()
    out.print("[bold yellow]Npcap tidak terdeteksi[/bold yellow]")
    out.print(
        "NetCut butuh [cyan]Npcap[/cyan] untuk ARP scan, poison, dan sniff di Windows."
    )
    out.print("[dim]https://npcap.com/[/dim]")
    out.print()

    if interactive and not Confirm.ask("Download & jalankan installer Npcap sekarang?", default=True):
        out.print("[red]Dibatalkan — install Npcap manual lalu jalankan ulang NetCut.[/red]")
        return False

    url = _latest_npcap_url()
    out.print(f"[cyan]Mengunduh[/cyan] {url}")

    temp_dir = Path(tempfile.mkdtemp(prefix="netcut_npcap_"))
    installer = temp_dir / "npcap-installer.exe"
    try:
        _download_installer(url, installer)
        out.print(f"[green]Download selesai[/green] ({installer.stat().st_size // 1024} KB)")
        out.print("[cyan]Membuka installer Npcap...[/cyan] [dim](butuh konfirmasi UAC)[/dim]")
        _launch_installer(installer)
    except Exception as exc:
        out.print(f"[red]Gagal unduh/install Npcap: {exc}[/red]")
        out.print(f"[dim]Unduh manual: {url}[/dim]")
        return False

    if _wait_for_install(out):
        out.print("[bold green]Npcap terpasang — melanjutkan NetCut.[/bold green]")
        out.print()
        return True

    out.print("[red]Npcap belum terdeteksi setelah timeout.[/red]")
    out.print("[dim]Selesaikan wizard install, lalu jalankan ulang NetCut.[/dim]")
    return False
