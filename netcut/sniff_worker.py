"""Privileged sniff / combined worker — must run as root/administrator."""

from __future__ import annotations

from netcut.cli import _run_cut_and_sniff, _run_sniff_only
from netcut.network import NetworkInfo
from netcut.platform_ops import load_worker_request, require_privileged_worker
from netcut.scanner import Device
from netcut.verbose import set_verbose, vlog


def main() -> None:
    require_privileged_worker("sniff worker")
    req = load_worker_request()
    set_verbose(req.get("verbose", 0))
    action = req.get("action", "sniff")
    vlog(1, f"Sniff worker (privileged) started mode={action}")

    target = Device(**req["target"])
    net = NetworkInfo(**req["net"])
    gateway_mac = req.get("gateway_mac", "")

    if action == "both":
        _run_cut_and_sniff(target, net, gateway_mac)
    else:
        _run_sniff_only(target, net, gateway_mac)


if __name__ == "__main__":
    main()
