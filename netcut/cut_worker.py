"""Privileged cut worker — must run as root/administrator."""

from __future__ import annotations

from netcut.cli import _run_cut_only
from netcut.network import NetworkInfo
from netcut.platform_ops import load_worker_request, require_privileged_worker
from netcut.scanner import Device
from netcut.verbose import set_verbose, vlog


def main() -> None:
    require_privileged_worker("cut worker")
    req = load_worker_request()
    set_verbose(req.get("verbose", 0))
    vlog(1, "Cut worker (privileged) started")
    target = Device(**req["target"])
    net = NetworkInfo(**req["net"])
    _run_cut_only(target, net, req["gateway_mac"])


if __name__ == "__main__":
    main()
