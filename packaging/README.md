# Packaging

## Debian / Kali

**The Debian packaging is not in this repo.** It lives in the Debian Security Tools team's
git-buildpackage repository:

    https://salsa.debian.org/pkg-security-team/dhcpig

Kali carries no fork of its own — it imports the package from Debian testing — so there is
nothing separate to file or maintain for Kali.

The `debian/` directory beside this file is a stale leftover that has diverged from what Debian
actually ships. Don't build from it and don't sync it upstream; use the salsa repository above.

Runtime dependencies of the built package are `python3` and `python3-scapy`. The web UI is pure
standard library and adds none.

## PyPI / pipx

```bash
pipx install "dhcpig"          # CLI + web UI (web has no extra deps)
```

## Manual pages

`dhcpig.1` and `dhcpig-web.1` are shipped here and installed by the Debian package.

## Desktop launcher

`dhcpig-web.desktop` runs `pkexec dhcpig-web --open`, since root is required for raw sockets, and
appears in the Kali menu under Sniffing/Spoofing. The server stays loopback-bound and prints a
tokenized URL; the launcher opens a browser to it.

Note the `Categories=09-sniffing-spoofing` value is Kali-specific and is not valid under the
freedesktop menu specification, so Debian ships a corrected copy of this file.
