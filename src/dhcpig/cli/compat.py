"""Legacy `pig.py` shim: translate old getopt flags to the new CLI, with a deprecation notice.

Only the common exhaustion flags are mapped; anything unusual falls back to plain exhaust on
the given interface so old muscle-memory keeps working for one release.
"""

from __future__ import annotations

import getopt
import sys

from .main import main as new_main

_DEPRECATION = (
    "pig.py is deprecated; use the 'dhcpig' command "
    "(e.g. 'dhcpig exhaust <iface>'). Translating for now.\n"
)


def translate(argv: list[str]) -> list[str]:
    try:
        opts, args = getopt.getopt(
            argv,
            "haiolx:y:z:6fgrnsSc1v:t:O:",
            [
                "help",
                "show-arp",
                "show-icmp",
                "show-options",
                "timeout-threads=",
                "timeout-dos=",
                "timeout-dhcprequest=",
                "neighbors-scan-arp",
                "neighbors-attack-release",
                "neighbors-attack-garp",
                "fuzz",
                "ipv6",
                "client-src=",
                "ethernet-mac",
                "color",
                "v6-rapid-commit",
                "verbosity=",
                "threads=",
                "show-lease-confirm",
                "request-options=",
            ],
        )
    except getopt.GetoptError:
        opts, args = [], argv

    iface = args[0] if args else None
    # A neighbor-release legacy run maps to the "release" subcommand, which now requires
    # explicit authorization; steer the user rather than silently arming them. -g/
    # --neighbors-attack-garp had no direct replacement once GARP_DOS was retired as a
    # standalone mode (2.3) -- ARP-conflict eviction now runs automatically as part of
    # exhaust/release, not as something invoked on its own -- so it falls through to plain
    # exhaust like any other unusual legacy flag.
    for o, _ in opts:
        if o in ("-r", "--neighbors-attack-release"):
            return ["release", iface or "", "--help"]

    out = ["exhaust"]
    if iface:
        out.append(iface)
    # Legacy pig.py only spoofed the ethernet src when -S was given; preserve that by
    # disabling the new default unless -S/--ethernet-mac is present.
    if not any(o in ("-S", "--ethernet-mac") for o, _ in opts):
        out.append("--no-spoof-eth-src")
    for o, a in opts:
        if o in ("-6", "--ipv6"):
            out.append("--ipv6")
        elif o in ("-f", "--fuzz"):
            pass  # legacy no-op: --fuzz was never implemented and has been removed
        elif o in ("-S", "--ethernet-mac"):
            out.append("--spoof-eth-src")
        elif o in ("-t", "--threads"):
            pass  # legacy no-op: --rate is the pacing control now, there is one sender
        elif o in ("-O", "--request-options"):
            out += ["--request-option", a]
        elif o in ("-s", "--client-src"):
            for mac in a.split(","):
                out += ["--client-mac", mac]
        elif o in ("-v", "--verbosity"):
            out += ["--verbosity", a]
    return out


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    sys.stderr.write(_DEPRECATION)
    return new_main(translate(argv))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
