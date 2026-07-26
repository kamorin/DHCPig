#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deprecated entry point. Kept so the legacy `./pig.py <iface>` invocation keeps working.

Prefer the new command:  dhcpig exhaust <iface>
"""
import sys

try:
    from dhcpig.cli.compat import main
except ImportError:
    sys.stderr.write(
        "dhcpig is not installed. Run: pip install .  (or: pipx install dhcpig)\n"
    )
    raise SystemExit(1) from None

if __name__ == "__main__":
    raise SystemExit(main())
