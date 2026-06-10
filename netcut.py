#!/usr/bin/env python3
"""NetCut CLI - Scan network devices and cut connections."""

from __future__ import annotations

import argparse

from netcut.cli import run_dashboard
from netcut.verbose import set_verbose


def main() -> None:
    parser = argparse.ArgumentParser(
        description="NetCut — scan LAN devices and cut internet connection",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Verbose output (-v, -vv, -vvv untuk lebih detail)",
    )
    parser.add_argument(
        "--cut",
        action="store_true",
        help="Langsung ke mode Cut setelah scan",
    )
    parser.add_argument(
        "--sniff",
        action="store_true",
        help="Langsung ke mode Sniff setelah scan",
    )
    args = parser.parse_args()
    default_mode = None
    if args.cut and args.sniff:
        default_mode = "both"
    elif args.cut:
        default_mode = "cut"
    elif args.sniff:
        default_mode = "sniff"
    set_verbose(args.verbose)
    run_dashboard(verbose=args.verbose, default_mode=default_mode)


if __name__ == "__main__":
    main()
