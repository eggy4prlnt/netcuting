"""Privileged cut worker — must run as root."""

from __future__ import annotations

import json
import os
import sys

from netcut.cli import _run_cut_only
from netcut.network import NetworkInfo
from netcut.scanner import Device
from netcut.verbose import set_verbose, vlog


def main() -> None:
    if os.geteuid() != 0:
        print("ERROR: cut worker butuh root", file=sys.stderr)
        sys.exit(1)

    req = json.load(sys.stdin)
    set_verbose(req.get("verbose", 0))
    vlog(1, "Cut worker (root) started")
    target = Device(**req["target"])
    net = NetworkInfo(**req["net"])
    _run_cut_only(target, net, req["gateway_mac"])


if __name__ == "__main__":
    main()
