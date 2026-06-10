"""Cross-platform OS helpers (macOS, Linux, Windows)."""

from __future__ import annotations

import ctypes
import json
import os
import re
import subprocess
import sys
import tempfile
from typing import Callable

RunResult = subprocess.CompletedProcess[str]

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _looks_like_ipv4(value: str) -> bool:
    if not value or not _IPV4_RE.match(value):
        return False
    try:
        return all(0 <= int(part) <= 255 for part in value.split("."))
    except ValueError:
        return False


def get_interface_label(interface: str, local_ip: str = "") -> str:
    """Human-friendly adapter label for UI (Windows Npcap GUID → adapter name)."""
    if sys.platform == "win32" and local_ip:
        label = _windows_adapter_for_ipv4(local_ip)
        if label and label != local_ip:
            return label
    return interface


def _run(cmd: list[str], *, check: bool = True) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, check=check)
    return result.stdout


def is_privileged() -> bool:
    if sys.platform == "win32":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def run_privileged_worker(module: str, payload: dict) -> int:
    """Delegate to a root/admin worker process."""
    if sys.platform == "win32":
        return _run_windows_elevated_worker(module, payload)
    result = subprocess.run(
        ["sudo", "-E", sys.executable, "-m", module],
        input=json.dumps(payload),
        text=True,
    )
    return result.returncode


def _run_windows_elevated_worker(module: str, payload: dict) -> int:
    fd, path = tempfile.mkstemp(suffix=".json", prefix="netcut_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
        params = f'-m {module} --payload {path}'
        ret = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            params,
            None,
            1,
        )
        if ret <= 32:
            raise RuntimeError("Gagal elevate ke Administrator (UAC ditolak?)")
    except Exception:
        try:
            os.remove(path)
        except OSError:
            pass
        raise
    return 0


def load_worker_request() -> dict:
    if "--payload" in sys.argv:
        idx = sys.argv.index("--payload")
        path = sys.argv[idx + 1]
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        try:
            os.remove(path)
        except OSError:
            pass
        return data
    return json.load(sys.stdin)


def require_privileged_worker(name: str) -> None:
    if not is_privileged():
        print(f"ERROR: {name} butuh root/Administrator", file=sys.stderr)
        sys.exit(1)


def ping_once(ip: str, timeout: float = 1.0) -> bool | None:
    try:
        if sys.platform == "win32":
            ms = int(max(timeout, 0.2) * 1000)
            result = subprocess.run(
                ["ping", "-n", "1", "-w", str(ms), ip],
                capture_output=True,
                text=True,
            )
        else:
            wait = str(int(max(timeout, 1)))
            if sys.platform == "darwin":
                cmd = ["ping", "-c", "1", "-W", wait, ip]
            else:
                cmd = ["ping", "-c", "1", "-W", wait, ip]
            result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0
    except Exception:
        return None


def find_dig() -> str | None:
    candidates = [
        "/usr/bin/dig",
        "/bin/dig",
        "dig",
    ]
    if sys.platform == "win32":
        candidates = ["dig"] + candidates
    for candidate in candidates:
        try:
            result = subprocess.run(
                [candidate, "-v"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            if result.returncode == 0 or "DiG" in (result.stdout + result.stderr):
                return candidate
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            continue
    return None


def set_ip_forwarding(enabled: bool) -> None:
    value = enabled
    handlers: dict[str, Callable[[bool], None]] = {
        "darwin": _set_ip_forwarding_darwin,
        "linux": _set_ip_forwarding_linux,
        "win32": _set_ip_forwarding_windows,
    }
    handler = handlers.get(sys.platform)
    if handler:
        handler(value)


def _set_ip_forwarding_darwin(enabled: bool) -> None:
    flag = "1" if enabled else "0"
    subprocess.run(
        ["sysctl", "-w", f"net.inet.ip.forwarding={flag}"],
        capture_output=True,
    )
    subprocess.run(
        ["sysctl", "-w", f"net.inet6.ip6.forwarding={flag}"],
        capture_output=True,
    )


def _set_ip_forwarding_linux(enabled: bool) -> None:
    flag = "1" if enabled else "0"
    for path in (
        "/proc/sys/net/ipv4/ip_forward",
        "/proc/sys/net/ipv6/conf/all/forwarding",
    ):
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(flag)
        except OSError:
            pass
    subprocess.run(
        ["sysctl", "-w", f"net.ipv4.ip_forward={flag}"],
        capture_output=True,
    )
    subprocess.run(
        ["sysctl", "-w", f"net.ipv6.conf.all.forwarding={flag}"],
        capture_output=True,
    )


def _set_ip_forwarding_windows(enabled: bool) -> None:
    state = "enabled" if enabled else "disabled"
    subprocess.run(
        ["netsh", "interface", "ipv4", "set", "global", f"forwarding={state}"],
        capture_output=True,
    )
    subprocess.run(
        ["netsh", "interface", "ipv6", "set", "global", f"forwarding={state}"],
        capture_output=True,
    )


def parse_neighbor_table(interface: str) -> dict[str, list[str]]:
    if sys.platform == "darwin":
        return _parse_neighbor_table_darwin(interface)
    if sys.platform == "linux":
        return _parse_neighbor_table_linux(interface)
    if sys.platform == "win32":
        return _parse_neighbor_table_windows(interface)
    return {}


def _parse_neighbor_table_darwin(interface: str) -> dict[str, list[str]]:
    try:
        output = _run(["ndp", "-an"])
    except Exception:
        return {}

    mac_to_ipv6: dict[str, list[str]] = {}
    for line in output.splitlines():
        if interface not in line:
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        ipv6_raw, mac = parts[0], parts[1].lower()
        if mac == "(incomplete)" or ":" not in mac:
            continue
        try:
            ipv6 = _normalize_ipv6(ipv6_raw)
        except ValueError:
            continue
        mac_to_ipv6.setdefault(mac, [])
        if ipv6 not in mac_to_ipv6[mac]:
            mac_to_ipv6[mac].append(ipv6)
    return mac_to_ipv6


def _parse_neighbor_table_linux(interface: str) -> dict[str, list[str]]:
    mac_to_ipv6: dict[str, list[str]] = {}
    try:
        output = _run(["ip", "-6", "neigh", "show", "dev", interface], check=False)
    except Exception:
        return mac_to_ipv6

    for line in output.splitlines():
        match = re.match(
            r"(\S+)\s+dev\s+\S+\s+lladdr\s+([0-9a-f:]+)",
            line,
            re.I,
        )
        if not match:
            continue
        ipv6_raw, mac = match.group(1), match.group(2).lower()
        try:
            ipv6 = _normalize_ipv6(ipv6_raw)
        except ValueError:
            continue
        mac_to_ipv6.setdefault(mac, [])
        if ipv6 not in mac_to_ipv6[mac]:
            mac_to_ipv6[mac].append(ipv6)
    return mac_to_ipv6


def _parse_neighbor_table_windows(interface: str) -> dict[str, list[str]]:
    mac_to_ipv6: dict[str, list[str]] = {}
    try:
        output = _run(["netsh", "interface", "ipv6", "show", "neighbors"], check=False)
    except Exception:
        return mac_to_ipv6

    in_section = False
    for line in output.splitlines():
        if interface.lower() in line.lower() and "interface" in line.lower():
            in_section = True
            continue
        if in_section and line.strip().startswith("Interface"):
            break
        if not in_section:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ipv6_raw = parts[0]
        mac_raw = parts[1].replace("-", ":").lower()
        if ":" not in mac_raw or len(mac_raw.split(":")) != 6:
            continue
        try:
            ipv6 = _normalize_ipv6(ipv6_raw)
        except ValueError:
            continue
        mac_to_ipv6.setdefault(mac_raw, [])
        if ipv6 not in mac_to_ipv6[mac_raw]:
            mac_to_ipv6[mac_raw].append(ipv6)
    return mac_to_ipv6


def get_link_local_addresses(interface: str, local_mac: str) -> list[str]:
    addrs = parse_neighbor_table(interface).get(local_mac.lower(), [])
    link_locals = [addr for addr in addrs if addr.startswith("fe80:")]
    if link_locals:
        return link_locals

    if sys.platform == "darwin":
        return _link_locals_darwin(interface)
    if sys.platform == "linux":
        return _link_locals_linux(interface)
    if sys.platform == "win32":
        return _link_locals_windows(interface)
    return []


def _link_locals_darwin(interface: str) -> list[str]:
    try:
        output = _run(["ifconfig", interface])
    except Exception:
        return []
    return _extract_fe80_from_text(output)


def _link_locals_linux(interface: str) -> list[str]:
    try:
        output = _run(["ip", "-6", "addr", "show", "dev", interface, "scope", "link"])
    except Exception:
        return []
    return _extract_fe80_from_text(output)


def _link_locals_windows(interface: str) -> list[str]:
    try:
        output = _run(["ipconfig"])
    except Exception:
        return []
    found: list[str] = []
    capture = interface.lower() in output.lower()
    for line in output.splitlines():
        if interface.lower() in line.lower():
            capture = True
            continue
        if capture and line and not line.startswith(" "):
            if interface.lower() not in line.lower():
                capture = False
        if capture:
            for addr in _extract_fe80_from_text(line):
                if addr not in found:
                    found.append(addr)
    return found


def _extract_fe80_from_text(text: str) -> list[str]:
    found: list[str] = []
    for match in re.finditer(r"(fe80:[0-9a-f:]+)", text, re.I):
        try:
            addr = _normalize_ipv6(match.group(1))
        except ValueError:
            continue
        if addr not in found:
            found.append(addr)
    return found


def _normalize_ipv6(addr: str) -> str:
    import ipaddress

    return str(ipaddress.ip_address(addr.split("%")[0]))


def detect_network_via_scapy() -> tuple[str, str, str, str, str] | None:
    """Return (interface, local_ip, local_mac, gateway_ip, subnet) or None."""
    try:
        from scapy.all import conf, get_if_addr, get_if_hwaddr
    except ImportError:
        return None

    try:
        route = conf.route.route("8.8.8.8")
    except Exception:
        return None

    if not route or len(route) < 3:
        return None

    first, second, third = route[0], route[1], route[2]

    # Windows/Npcap: (\\Device\\NPF_{GUID}, local_ip, gateway_ip)
    if sys.platform == "win32" and _looks_like_ipv4(second):
        iface = str(first)
        local_ip = second
        gateway_ip = third if _looks_like_ipv4(third) else _gateway_windows()
    else:
        # Unix: (gateway_ip, interface_name, dest_ip)
        gateway_ip = first if _looks_like_ipv4(first) else ""
        iface = second
        try:
            local_ip = get_if_addr(iface)
        except Exception:
            return None
        if not gateway_ip or gateway_ip == "0.0.0.0":
            gateway_ip = _gateway_for_interface(iface)

    if not iface:
        return None

    if not _looks_like_ipv4(local_ip):
        try:
            local_ip = get_if_addr(iface)
        except Exception:
            return None

    if not local_ip or local_ip == "0.0.0.0":
        return None

    try:
        local_mac = get_if_hwaddr(iface).lower()
    except Exception:
        local_mac = ""

    if not gateway_ip or gateway_ip == "0.0.0.0":
        gateway_ip = _gateway_for_interface(iface)

    subnet = _subnet_from_scapy(iface, local_ip)
    if not subnet:
        try:
            if sys.platform == "darwin":
                subnet = _subnet_darwin(iface)
            elif sys.platform == "linux":
                subnet = _subnet_linux(iface, local_ip)
            elif sys.platform == "win32":
                adapter = _windows_adapter_for_ipv4(local_ip)
                subnet = _subnet_windows(adapter, local_ip) or ""
        except RuntimeError:
            subnet = ""
    if not subnet:
        parts = local_ip.split(".")
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return iface, local_ip, local_mac, gateway_ip, subnet


def _subnet_from_scapy(interface: str, local_ip: str) -> str:
    try:
        import ipaddress

        from scapy.all import conf

        local = ipaddress.ip_address(local_ip)
        best: tuple[int, str] | None = None
        for route in conf.route.routes:
            if len(route) < 5:
                continue
            net, mask, _gw, iface, _addr = route[:5]
            if iface != interface or mask in {"0.0.0.0", "255.255.255.255"}:
                continue
            try:
                network = ipaddress.ip_network(f"{net}/{mask}", strict=False)
            except ValueError:
                continue
            if local not in network:
                continue
            if best is None or network.prefixlen < best[0]:
                best = (network.prefixlen, str(network))
        return best[1] if best else ""
    except Exception:
        return ""


def _gateway_for_interface(interface: str) -> str:
    if sys.platform == "darwin":
        return _gateway_darwin()
    if sys.platform == "linux":
        return _gateway_linux(interface)
    if sys.platform == "win32":
        return _gateway_windows()
    return ""


def _gateway_darwin() -> str:
    try:
        output = _run(["route", "-n", "get", "default"])
    except Exception:
        return ""
    match = re.search(r"gateway:\s*(\S+)", output)
    return match.group(1) if match else ""


def _gateway_linux(interface: str) -> str:
    try:
        output = _run(["ip", "route", "show", "default", "dev", interface], check=False)
        if not output.strip():
            output = _run(["ip", "route", "show", "default"])
    except Exception:
        return ""
    match = re.search(r"default via (\S+)", output)
    return match.group(1) if match else ""


def _windows_parse_ipconfig() -> list[tuple[str, str, str]]:
    """Return list of (adapter_name, ipv4, mac) from ipconfig."""
    try:
        output = _run(["ipconfig", "/all"])
    except Exception:
        return []

    adapters: list[tuple[str, str, str]] = []
    name = ""
    ipv4 = ""
    mac = ""
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.endswith(":") and "adapter" in stripped.lower():
            if name and ipv4:
                adapters.append((name, ipv4, mac))
            name = stripped.rstrip(":")
            ipv4 = ""
            mac = ""
            continue
        if not name:
            continue
        ip_match = re.search(r"IPv4 Address[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", stripped, re.I)
        if ip_match:
            ipv4 = ip_match.group(1)
        mac_match = re.search(r"Physical Address[^:]*:\s*([0-9A-F-]+)", stripped, re.I)
        if mac_match:
            mac = mac_match.group(1).replace("-", ":").lower()
    if name and ipv4:
        adapters.append((name, ipv4, mac))
    return adapters


def _windows_default_route() -> tuple[str, str]:
    """Return (gateway_ip, interface_ipv4) from route table."""
    try:
        output = _run(["route", "print", "0.0.0.0"], check=False)
    except Exception:
        return "", ""
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            return parts[2], parts[3]
    return "", ""


def _windows_adapter_for_ipv4(ipv4: str) -> str:
    for name, addr, _mac in _windows_parse_ipconfig():
        if addr == ipv4:
            return name
    return ipv4


def _gateway_windows() -> str:
    gateway, _iface_ip = _windows_default_route()
    return gateway


def get_default_interface() -> str:
    scapy_info = detect_network_via_scapy()
    if scapy_info:
        return scapy_info[0]

    if sys.platform == "darwin":
        output = _run(["route", "-n", "get", "default"])
        match = re.search(r"interface:\s*(\S+)", output)
        if match:
            return match.group(1)
    elif sys.platform == "linux":
        try:
            output = _run(["ip", "route", "show", "default"])
            match = re.search(r"dev (\S+)", output)
            if match:
                return match.group(1)
        except Exception:
            pass
    elif sys.platform == "win32":
        _gateway, iface_ip = _windows_default_route()
        if iface_ip:
            return _windows_adapter_for_ipv4(iface_ip)
        try:
            output = _run(["route", "print", "0.0.0.0"], check=False)
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0] == "0.0.0.0":
                    return _windows_adapter_for_ipv4(parts[3])
        except Exception:
            pass

    raise RuntimeError("Tidak bisa menemukan interface default")


def get_local_ip(interface: str) -> str:
    scapy_info = detect_network_via_scapy()
    if scapy_info and scapy_info[0] == interface:
        return scapy_info[1]

    if sys.platform == "darwin":
        result = subprocess.run(
            ["ipconfig", "getifaddr", interface],
            capture_output=True,
            text=True,
        )
        ip = result.stdout.strip()
        if ip:
            return ip
    elif sys.platform == "linux":
        try:
            output = _run(["ip", "-4", "addr", "show", "dev", interface])
            match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", output)
            if match:
                return match.group(1)
        except Exception:
            pass
    elif sys.platform == "win32":
        for name, addr, _mac in _windows_parse_ipconfig():
            if name.lower() == interface.lower() or addr == interface:
                return addr
        ip = _windows_ipv4_for_interface(interface)
        if ip:
            return ip

    raise RuntimeError(f"Tidak ada IP di interface {interface}")


def get_local_mac(interface: str) -> str:
    scapy_info = detect_network_via_scapy()
    if scapy_info and scapy_info[0] == interface and scapy_info[2]:
        return scapy_info[2]

    try:
        from scapy.all import get_if_hwaddr

        return get_if_hwaddr(interface).lower()
    except Exception:
        pass

    if sys.platform == "darwin":
        output = _run(["ifconfig", interface])
    elif sys.platform == "linux":
        output = _run(["ip", "link", "show", interface])
    elif sys.platform == "win32":
        output = _run(["getmac", "/fo", "list", "/v"], check=False)
    else:
        raise RuntimeError(f"Tidak bisa membaca MAC address di {interface}")

    if sys.platform == "win32":
        mac = _windows_mac_for_interface(interface, output)
        if mac:
            return mac
    else:
        match = re.search(r"(?:ether|link/ether)\s+([0-9a-f:]+)", output, re.I)
        if match:
            return match.group(1).lower()

    raise RuntimeError(f"Tidak bisa membaca MAC address di {interface}")


def _windows_ipv4_for_interface(interface: str) -> str:
    for name, addr, _mac in _windows_parse_ipconfig():
        if name.lower() == interface.lower():
            return addr
    return ""


def _windows_mac_for_interface(interface: str, output: str = "") -> str:
    for name, _addr, mac in _windows_parse_ipconfig():
        if name.lower() == interface.lower() and mac:
            return mac
    if output:
        current = ""
        for line in output.splitlines():
            if line.startswith("Connection Name:"):
                current = line.split(":", 1)[1].strip().lower()
            if current != interface.lower():
                continue
            match = re.search(r"Physical Address:\s*([0-9A-F-]+)", line, re.I)
            if match:
                return match.group(1).replace("-", ":").lower()
    return ""


def _cidr_to_subnet(cidr: str) -> str:
    if "/" not in cidr:
        return cidr
    network, prefix = cidr.split("/", 1)
    octets = network.split(".")
    if len(octets) == 3:
        return f"{network}.0/{prefix}"
    if len(octets) == 4:
        return f"{network}/{prefix}"
    raise ValueError(f"Format CIDR tidak dikenal: {cidr}")


def get_subnet_for_interface(interface: str, local_ip: str) -> str:
    scapy_info = detect_network_via_scapy()
    if scapy_info and scapy_info[0] == interface and scapy_info[4]:
        return scapy_info[4]

    if sys.platform == "darwin":
        return _subnet_darwin(interface)
    if sys.platform == "linux":
        return _subnet_linux(interface, local_ip)
    if sys.platform == "win32":
        subnet = _subnet_windows(interface, local_ip)
        if subnet:
            return subnet

    parts = local_ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def _subnet_darwin(interface: str) -> str:
    output = _run(["netstat", "-rn"])
    best: tuple[int, str] | None = None
    for line in output.splitlines():
        if interface not in line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        destination = parts[0]
        if destination in {"default", "link#", "localhost"}:
            continue
        if destination.startswith(("127.", "169.254", "224.", "239.", "fe80:", "ff")):
            continue
        if "/" not in destination:
            continue
        try:
            prefix = int(destination.split("/", 1)[1])
        except ValueError:
            continue
        if best is None or prefix < best[0]:
            best = (prefix, _cidr_to_subnet(destination))
    if best:
        return best[1]
    raise RuntimeError(f"Tidak bisa menemukan subnet untuk {interface}")


def _subnet_linux(interface: str, local_ip: str) -> str:
    try:
        output = _run(["ip", "route", "show", "dev", interface])
    except Exception:
        parts = local_ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    best: tuple[int, str] | None = None
    for line in output.splitlines():
        match = re.match(r"(\d+\.\d+\.\d+\.\d+/\d+)", line)
        if not match:
            continue
        cidr = match.group(1)
        prefix = int(cidr.split("/", 1)[1])
        if best is None or prefix < best[0]:
            best = (prefix, cidr)
    if best:
        return best[1]
    parts = local_ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def _subnet_windows(interface: str, local_ip: str) -> str:
    try:
        output = _run(["ipconfig"])
    except Exception:
        return ""

    capture = False
    for line in output.splitlines():
        if interface.lower() in line.lower() and "adapter" in line.lower():
            capture = True
            continue
        if capture and "adapter" in line.lower() and interface.lower() not in line.lower():
            capture = False
        if capture:
            match = re.search(r"Subnet Mask[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line, re.I)
            if match:
                mask = match.group(1)
                return _ipv4_mask_to_cidr(local_ip, mask)
    return ""


def _ipv4_mask_to_cidr(ip: str, mask: str) -> str:
    import ipaddress

    network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
    return str(network)


def resolve_packet_interface(interface: str, local_ip: str = "") -> str:
    """Map OS interface name to Scapy/Npcap device name when possible."""
    try:
        from scapy.all import IFACES
    except ImportError:
        return interface

    iface_l = interface.lower()
    ip_match: str | None = None

    for dev in IFACES.values():
        desc = (getattr(dev, "description", "") or "").lower()
        net_name = (getattr(dev, "network_name", "") or "").lower()
        dev_name = (getattr(dev, "name", "") or "").lower()
        if iface_l and (
            iface_l in desc
            or iface_l in net_name
            or iface_l == dev_name
            or desc in iface_l
        ):
            return dev.name
        if local_ip:
            try:
                from scapy.all import get_if_addr

                if get_if_addr(dev.name) == local_ip:
                    ip_match = dev.name
            except Exception:
                continue

    return ip_match or interface


def get_gateway_ip() -> str:
    scapy_info = detect_network_via_scapy()
    if scapy_info and scapy_info[3]:
        return scapy_info[3]
    gateway = _gateway_for_interface(get_default_interface())
    if gateway:
        return gateway
    raise RuntimeError("Tidak bisa menemukan gateway")
