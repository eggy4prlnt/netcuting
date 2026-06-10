"""Privileged sniff / combined worker — must run as root."""

from __future__ import annotations

import json
import os
import sys

from netcut.cli import _run_cut_and_sniff, _run_sniff_only
from netcut.network import NetworkInfo
from netcut.scanner import Device
from netcut.verbose import set_verbose, vlog


def main() -> None:
    if os.geteuid() != 0:
        print("ERROR: sniff worker butuh root", file=sys.stderr)
        sys.exit(1)

    req = json.load(sys.stdin)
    set_verbose(req.get("verbose", 0))
    action = req.get("action", "sniff")
    vlog(1, f"Sniff worker (root) started mode={action}")

    target = Device(**req["target"])
    net = NetworkInfo(**req["net"])
    gateway_mac = req.get("gateway_mac", "")

    if action == "both":
        _run_cut_and_sniff(target, net, gateway_mac)
    else:
        _run_sniff_only(target, net, gateway_mac)


if __name__ == "__main__":
    main()
