DHCPig
======

Tags: DHCP, IPv4, IPv6, exhaustion, pentest, fingerprinting, security, scapy

SUMMARY
-------

DHCPig is a whitehat network-hardening validation tool. It exercises DHCP starvation,
lease-hijack, forced lease release, gratuitous-ARP disruption, and passive host
fingerprinting so security engineers can confirm a network is defended (DHCP snooping,
port security, etc.).

`dhcpig` 2.x is a refactor of the original single-file `pig.py` into an installable,
tested package. It requires `scapy>=2.5` and root/CAP_NET_RAW. Destructive actions are
opt-in, authorization-gated, scope-restricted, rate-limited, and reversible.

INSTALL
-------

    pipx install dhcpig        # or: pip install .

USAGE (V1.0 — CLI)
------------------

    sudo dhcpig exhaust eth1 --rate 50 --report run.json
    sudo dhcpig scan eth1 --report inventory.json          # passive, read-only
    sudo dhcpig release eth1 --scope 172.20.0.0/16 --i-am-authorized   # DESTRUCTIVE
    sudo dhcpig garp    eth1 --scope 172.20.0.0/16 --i-am-authorized   # DESTRUCTIVE
    sudo dhcpig restore eth1                               # release leases we grabbed
    dhcpig ifaces

Safety flags:

    --dry-run            build + log packets, send nothing on the wire
    --rate N             cap packets/sec (authoritative — the only pacing mechanism)
    --scope CIDR         restrict destructive actions to these networks (repeatable)
    --i-am-authorized    required for release/garp; you attest you have permission
    --no-control         skip the control transaction (see below; not recommended)
    --restore-on-exit    release the acquired leases when the run ends
    --status-interval N  periodic status line, default every 5s (0 disables)

Leases are **kept by default** so the exhausted state can be observed and verified after the
run. Release them with `sudo dhcpig restore eth1` (or the Restore button in the web UI) when
you are done. `--rate` is the remaining bound on how fast a run can consume a pool.

CONTROL TRANSACTION & FINDINGS
------------------------------

`exhaust` runs a **control transaction** before and after the test: one ordinary DHCP cycle
(DISCOVER/OFFER/REQUEST/ACK/RELEASE) using the interface's real MAC, labelled `CONTROL[pre]`
and `CONTROL[post]` in the output. The lease is released immediately, so the control consumes
nothing.

This is what makes a null result meaningful:

* `pre` **succeeds**, spoofed MACs get nothing → the network defended itself (**PASS**).
* `pre` **fails** → the test itself is invalid (wrong VLAN, wrong interface, no server), so the
  run is reported **INCONCLUSIVE** rather than as a pass.
* `post` **fails** while leases are held → a real client is being denied service, which
  confirms genuine pool exhaustion (**FAIL**).

Runs end with **findings** — an ID, verdict, severity, the evidence behind it, and a
recommendation — printed by the CLI, shown in the web UI's Findings tab, and included in the
JSON/HTML reports.

A run **ends by itself**: once offers stop arriving for `offer_silence` seconds (10s by
default) the pool is treated as drained, and the engine runs the post-control and produces the
verdict without waiting for you to press Stop. `POOL EXHAUSTED` therefore only ever refers to
the server ceasing to serve — there is no self-imposed lease cap that could be mistaken for it.

Legacy `./pig.py eth1` still works via a deprecated shim.

WEB UI
------

    sudo dhcpig-web            # prints a tokenized loopback URL; open it in a browser

The web UI (`dhcpig-web`) is Python-stdlib only (no framework, no build step). It is bound to
`127.0.0.1`, requires the printed bearer token, and enforces same-origin. All four modes are
available with a live dashboard, OS-inventory tables, JSON/CSV/HTML export, "Copy as CLI", and
profile save/load. Destructive modes require the authorization checkbox, a scope, and a typed
confirmation (re-validated server-side). For a headless VM, reach it from your host with:

    ssh -L 8787:127.0.0.1:8787 kali@<vm-ip>

MODES
-----

* __exhaust__     — DISCOVER/OFFER/REQUEST loop that consumes the address pool (non-destructive).
* __scan__        — passive ARP + DHCP capture; fingerprints every host (OS/device/vendor).
* __active-scan__ — active discovery: ARP sweep of the scope + a DHCP INFORM to find/fingerprint
                    servers. Non-destructive; requires `--scope` (auto-filled from the interface).
* __release__     — DHCPRELEASE for in-scope neighbors (DESTRUCTIVE, gated).
* __garp__        — standalone gratuitous-ARP flood, no exhaustion phase (DESTRUCTIVE, gated).

STATUS OUTPUT
-------------

At normal verbosity a status line is printed every 5 seconds with running totals, the change
over the last window, and rates — so you can tell a working run from a stalled one:

    [##] t=220s  RUNNING  leases 1022 (+0 in 5s, 0.0/s)  discovers 4300 (+250 in 5s, 50.0/s)
         offers 1030 (+0 in 5s)  servers 1  last offer 6s ago

Leases flat while discovers keep climbing, with `last offer` growing, is the pool draining.
Counters that are idle are left out. Use `--status-interval 0` to switch it off.

FINGERPRINTING
--------------

`scan` (and server discovery during `exhaust`) resolves OS/device from the DHCP option-55
parameter-request-list order (exact, order-sensitive match) with option-60 vendor-class /
MAC-OUI as a fallback signal. It ships a static `combined_dhcp_os_lookup.json` (PacketFence +
Huginn-Muninn fingerprints merged by `data/fingerprint-merge.py`, 594 fingerprints) plus a
small builtin fallback table for signals the combined DB doesn't carry — no API, no key, works
fully offline/airgapped. A fingerprint matching more than one device is reported with lower
confidence and flagged ambiguous. Drop a refreshed `combined_dhcp_os_lookup.json` into
`src/dhcpig/data/` to update coverage; see `data/DATA_ATTRIBUTION.md`. In `scan`/`active-scan`,
neighbors discovered via ARP are automatically paired with any DHCP fingerprint seen for the
same MAC, so the Neighbors table shows OS/Device whichever signal arrives first.

Hosts with **no** usable DHCP fingerprint fall back to **MAC vendor** identification, so the
OS/Device column is never blank: scapy's bundled IEEE/Wireshark OUI database (~50k entries,
offline) plus a small `mac-vendor.txt` from arp-scan for prefixes the IEEE registry omits
(QEMU, HSRP, VRRP/CARP, WLBS). These are shown as `Vendor (MAC vendor)` at low confidence —
a NIC manufacturer is not an OS. Randomised/locally-administered MACs are labelled as such.

DEFENSE
-------

The most common defense against DHCP exhaustion is access-layer switching / wireless
controllers. On Cisco, enable DHCP snooping — it defends against pool exhaustion, IP
hijacking, and rogue DHCP servers, all of which DHCPig exercises:

    ip dhcp snooping
    interface fa0/1
      ip dhcp snooping trust        ! your DHCP uplink
    show ip dhcp snooping
    show ip dhcp snooping binding

DISCLAIMER
----------

All information and software here are for authorized testing and educational purposes only.
The authors are not responsible for misuse. Only run DHCPig against networks you own or are
explicitly authorized to test.

LICENSE
-------

GPL v2 or later. See LICENSE.
