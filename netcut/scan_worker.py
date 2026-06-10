"""Privileged ARP scan worker — must run as root."""

from __future__ import annotations

import json
import os
import sys

from netcut.scanner import arp_scan_raw


def main() -> None:
    if os.geteuid() != 0:
        print("ERROR: scan worker butuh root", file=sys.stderr)
        sys.exit(1)

    req = json.load(sys.stdin)
    devices, gateway_mac = arp_scan_raw(
        subnet=req["subnet"],
        interface=req["interface"],
        local_ip=req["local_ip"],
        gateway_ip=req["gateway_ip"],
        timeout=req.get("timeout", 3),
    )

    print(
        json.dumps(
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
    )


if __name__ == "__main__":
    main()
