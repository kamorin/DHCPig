# Packaging

## Debian / Kali `.deb`

The `debian/` files build a `.deb` that installs the `dhcpig` and `dhcpig-web` console scripts
plus the desktop launcher under **Applications → 09 Sniffing/Spoofing**.

```bash
sudo apt install devscripts debhelper dh-python python3-hatchling python3-scapy
dpkg-buildpackage -us -uc -b
sudo apt install ../dhcpig_2.0.0_all.deb
```

Runtime deps are only `python3`, `python3-scapy`, `libpcap0.8` — the web UI is pure stdlib.

## PyPI / pipx

```bash
pipx install "dhcpig"          # CLI + web UI (web has no extra deps)
```

## Desktop launcher

`dhcpig-web.desktop` runs `pkexec dhcpig-web --open` (root is required for raw sockets) and
appears in the Kali menu under Sniffing/Spoofing. The server stays loopback-bound and prints
a tokenized URL; the launcher opens the browser to it.
