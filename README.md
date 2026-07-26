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
tested package. It requires `scapy>=2.5` and root/CAP_NET_RAW. Destructive modes
(`release`/`garp`) are opt-in by subcommand, take an optional `--scope`, and are rate-limited
and reversible (`dhcpig restore`) — there is no separate authorization gate; see DISCLAIMER.

INSTALL
-------

    pipx install dhcpig        # or: pip install .

USAGE (CLI)
-----------

    sudo dhcpig exhaust eth1 --report run.json
    sudo dhcpig scan eth1 --report inventory.json          # passive, read-only
    sudo dhcpig release eth1 --scope 172.20.0.0/16 --rate 20  # DESTRUCTIVE
    sudo dhcpig garp    eth1 --scope 172.20.0.0/16 --rate 20  # DESTRUCTIVE
    sudo dhcpig restore eth1                               # release leases we grabbed
    dhcpig ifaces

`release` and `garp` disrupt live clients. They take no confirmation step — `--scope` is
optional and **defaults to the interface's own network**, so `dhcpig garp eth1` will target
every host on the segment. Pass `--scope` to bound it.

Safety flags:

    --dry-run            build + log packets, send nothing on the wire
    --rate N             cap packets/sec — release/garp/active-scan only, default 10
                          (exhaust has no --rate; see EXHAUST PIPELINE below)
    --scope CIDR         restrict targets to these networks (repeatable; optional)
    --no-control         skip the control transaction (see below; not recommended)
    --no-release         skip releasing ARP-discovered neighbors before exhausting
    --no-arp-scan        skip the pre-run ARP inventory
    --restore-on-exit    release the acquired leases when the run ends
    --status-interval N  periodic status line, default every 5s (0 disables)

Leases are **kept by default** so the exhausted state can be observed and verified after the
run. Release them with `sudo dhcpig restore eth1` (or the Restore button in the web UI) when
you are done.

EXHAUST PIPELINE
-----------------

`exhaust` runs four phases before the sender starts: an ARP sweep (pre-run inventory), a
control transaction (baseline reachability), a **release phase** (DHCPRELEASE for every
ARP-discovered neighbor, so the pool has addresses to give up rather than only whatever was
already free — `--no-release` to skip), then the sender.

The sender is a **windowed, adaptive pipeline**, not an open-loop flood: a handful of
DISCOVER/REQUEST transactions are in flight at once, growing on a clean ACK and halving on a
NAK, timeout, or duplicate offer. Flooding faster than handshakes can complete saturates the
server's pending-offer table — which looks like exhaustion but isn't, and produced a false
result on a real `/22` (the server re-offered the same address to two of our MACs, then NAKed,
then went silent at 56/~1000 addresses). This is why `exhaust` has no `--rate`: the window paces
it, and backs off automatically.

If a defensive control fires mid-run — a NAK burst, offers going quiet, the link going down
(port-security err-disable), a timeout storm, or the same address offered to two of our MACs —
sending **stops immediately**, but leases already held are kept and both post-run control
transactions still run, so the report is complete rather than truncated.

CONTROL TRANSACTION & FINDINGS
------------------------------

`exhaust` first **ARP-sweeps the segment** to record which hosts were present beforehand
(`--no-arp-scan` to skip), then runs **control transactions** before and after the test: an
ordinary DHCP cycle (DISCOVER/OFFER/REQUEST/ACK/RELEASE) whose lease is released immediately.

Each control runs as **two legs**, because they answer different questions:

* **`self`** — this machine's real NIC MAC. The server usually already has a binding for it, so
  this is effectively a *renewal*. It proves DHCP is reachable and you are on the right VLAN,
  but it can succeed even against a completely drained pool.
* **`new`** — a MAC the server has never seen, which must be given an address off the free
  list. **This is the only leg that can tell you whether a new client can still join**, so it
  is what the exhaustion verdict is based on.

Reading the matrix:

* `pre/self` **fails** → the test is invalid (wrong VLAN/interface/no server) → **INCONCLUSIVE**.
* `pre/self` OK but `pre/new` **fails** → unknown MACs are refused up front: DHCP snooping or
  port security → **PASS** (`DHCP_STARVATION_NOT_ATTAINED`, reason `blocked_at_baseline`).
* `post/new` **fails** while leases are held → a new client is denied service → genuine
  exhaustion → **FAIL** (`DHCP_STARVATION_ATTAINED`).
* `post/new` still **succeeds** → **PASS** (`DHCP_STARVATION_NOT_ATTAINED`), with a `reason`:
  `control_fired` if a defensive control halted sending first (the expected result on a
  defended network — see EXHAUST PIPELINE above), otherwise `pool_headroom_remaining`.
* Offers stopped but `post/new` still succeeds *and* a control never fired → the server stopped
  answering *you* specifically (rate-limiting, offer-table saturation, anti-starvation), which
  is reported separately as `SERVER_STOPPED_SERVING_TEST_CLIENTS`.

Runs end with **findings** — an ID, verdict, severity, the evidence behind it, and a
recommendation — printed by the CLI, shown in the web UI's Findings tab, and included in the
JSON/HTML reports.

A run **ends by itself**: once offers stop arriving for `offer_silence` seconds (10s by
default), or a defensive control fires (EXHAUST PIPELINE above), the engine runs the post-control
and produces the verdict without waiting for you to press Stop. `POOL EXHAUSTED` therefore only
ever refers to the server ceasing to serve — there is no self-imposed lease cap that could be
mistaken for it.

Legacy `./pig.py eth1` still works via a deprecated shim.

HEADROOM
--------

The dashboard/status line also surfaces a **headroom** estimate for `exhaust`:
`pool_size - leases_held - observed_in_use`, floored at 0. `pool_size` comes from an explicit
`--scope` when given, else it's inferred from the first OFFER's subnet (DHCP option 1); if
neither is available it shows `—` rather than a fabricated number, and every surface (CLI, web,
JSON/HTML report) renders the source alongside it. A separate `POOL_HEADROOM_LOW` finding fires
when the *pre-test* ARP baseline already shows the scope at ≥80% utilization — independent of
whether exhausting the pool succeeded.

WEB UI
------

    sudo dhcpig-web            # prints a tokenized loopback URL; open it in a browser

The web UI (`dhcpig-web`) is Python-stdlib only (no framework, no build step). It is bound to
`127.0.0.1`, requires the printed bearer token, and enforces same-origin. All four modes are
available with a live dashboard (including the headroom counter for exhaust), OS-inventory
tables, JSON/CSV/HTML export, "Copy as CLI", and profile save/load. For a headless VM, reach it
from your host with:

    ssh -L 8787:127.0.0.1:8787 kali@<vm-ip>

MODES
-----

* __exhaust__     — DISCOVER/OFFER/REQUEST loop that consumes the address pool (non-destructive).
* __scan__        — passive ARP + DHCP capture; fingerprints every host (OS/device/vendor).
* __active-scan__ — active discovery: ARP sweep of the scope + a DHCP INFORM to find/fingerprint
                    servers. Non-destructive; requires `--scope` (auto-filled from the interface).
* __release__     — DHCPRELEASE for neighbors (DESTRUCTIVE; scope defaults to the iface network).
* __garp__        — sustained ARP cache poisoning, no exhaustion phase (DESTRUCTIVE). See below.

ARP-GARP DoS
------------

Per target, each round sends three frames:

1. a broadcast gratuitous ARP **request** claiming the victim's own IP,
2. a broadcast gratuitous ARP **reply** making the same claim,
3. a **unicast** ARP reply to the victim putting the **default gateway** at an unused MAC.

(3) is what actually costs a host connectivity. (1) and (2) only trip duplicate-address
detection — a well-behaved host defends its address and carries on, which is why announcements
alone look like they do nothing. Rounds repeat every `garp_interval` (2s) until you stop,
because hosts re-ARP within seconds and the legitimate owner re-answers, undoing a single pass.

The forged MAC is always a **bogus, unused address**, so poisoned traffic is blackholed. DHCPig
deliberately never points a forged mapping at its own MAC — that would be traffic interception
rather than a denial-of-service check, and is out of scope for this tool.

While poisoning, DHCPig watches ARP and records which targets re-announce their address. A host
defending itself proves the forged frame was *delivered* (so Dynamic ARP Inspection is not
filtering the port). It does **not** prove the gateway entry survived — confirm with `arp -a` /
`ip neigh` on a target, or DAI drop counters on the switch.

STATUS OUTPUT
-------------

At normal verbosity a status line is printed every 5 seconds with running totals, the change
over the last window, and rates — so you can tell a working run from a stalled one. `exhaust`
also carries the send window/inflight count and the headroom estimate:

    [##] t=220s  RUNNING  leases 412 (+8 in 5s, 1.6/s)  discovers 480 (+9 in 5s, 1.8/s)
         offers 420 (+8 in 5s)  servers 1  window 16 (inflight 12)  headroom 610 / ~1022 est.
         last offer 1s ago

Leases flat while discovers keep climbing, with `last offer` growing, is the pool draining. A
shrinking window with rising `timeouts` means NAKs/timeouts/duplicate offers are throttling the
run back — that's the adaptive pacing working, not a bug. Counters that are idle are left out.
Use `--status-interval 0` to switch it off.

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
