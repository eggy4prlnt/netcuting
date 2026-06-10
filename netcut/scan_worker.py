"""Privileged ARP scan worker — must run as root/administrator."""

from __future__ import annotations

import json
import sys

from netcut.platform_ops import load_worker_request, require_privileged_worker
from netcut.scanner import arp_scan_raw


def main() -> None:
    require_privileged_worker("scan worker")
    req = load_worker_request()
    output_path = req.pop("output", None)

    devices, gateway_mac = arp_scan_raw(
        subnet=req["subnet"],
        interface=req["interface"],
        local_ip=req["local_ip"],
        gateway_ip=req["gateway_ip"],
        timeout=req.get("timeout", 3),
    )

    payload = json.dumps(
        {
            "devices": [
                {
                    "ip": d.ip,
                    "mac": d.mac,
                    "vendor": d.vendor,
                    "is_gateway": d.is_gateway,
                    "is_self": d.is_self,
                }
                for d in devices
            ],
            "gateway_mac": gateway_mac,
        }
    )

    if output_path:
        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(payload)
    else:
        print(payload)


if __name__ == "__main__":
    main()
