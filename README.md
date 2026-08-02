<h1>
  <img src="packaging/dhcpig.svg" alt="" width="110" height="110" align="left" />
  DHCPig
</h1>

Whitehat DHCP hardening validation: exhaust a pool, hijack neighbours' leases, evict hosts off
their addresses with forged ARP, and report whether the network stopped you. Needs root and
Python 3.11+.

Run the web UI
--------------

**Debian / Kali:** grab the latest `.deb` from
[Releases](https://github.com/kamorin/DHCPig/releases/latest) and install it —
puts `dhcpig` and `dhcpig-web` on `PATH`, no venv needed:

    curl -LO https://github.com/kamorin/DHCPig/releases/download/v2.7.2/dhcpig_2.7.2-1_all.deb
    sudo apt install ./dhcpig_2.7.2-1_all.deb
    sudo dhcpig-web --open

**From source** (any Linux, Python 3.11+):

    git clone https://github.com/kamorin/DHCPig && cd DHCPig
    python3 -m venv .venv && .venv/bin/pip install -e .
    sudo .venv/bin/dhcpig-web --open

Open the printed `http://127.0.0.1:8787/?token=...` URL. Three gotchas:

* **Root is required either way** (raw sockets). From source, use the full `.venv/bin/` path
  — `sudo` resets `PATH`.
* **The `?token=` is mandatory.** Without it you get 401s and a blank page.
* **Headless?** It binds loopback on purpose. Forward it, don't re-bind:
  `ssh -L 8787:127.0.0.1:8787 user@<vm-ip>`. Drop `--open`.

On Debian/Kali, `sudo apt install -y python3-venv` first if the venv step fails.

CLI
---

    sudo .venv/bin/dhcpig exhaust eth0 --report run.json
    sudo .venv/bin/dhcpig release eth0 --scope 192.168.4.0/22     # DESTRUCTIVE
    sudo .venv/bin/dhcpig active-scan eth0 --scope 192.168.4.0/22 # read-only
    sudo .venv/bin/dhcpig release-previous eth0                   # undo a previous run
    dhcpig ifaces

| Flag | |
|---|---|
| `--dry-run` | recon only: ARP sweep + control transactions run for real, nothing mutating is sent |
| `--scope CIDR` | bound the targets (repeatable); defaults to the interface's own network |
| `--rate N` | pps, default 7 — not on `exhaust`, which self-paces |
| `--no-evict` | skip the ARP-conflict phase |
| `--report FILE` | write a session report to `FILE` when the run ends; format follows `FILE`'s extension (`.json`/`.csv`/`.html`, default JSON) |
| `--client-mac MAC` | `exhaust` only; use this MAC instead of a random one (repeatable — rotates through the list) |
| `--request-option SPEC` | `exhaust` only; DHCP options to request, e.g. `12,14-19,23` (default: 0-79) |
| `--no-spoof-eth-src` | `exhaust` only; use the real NIC MAC as the Ethernet source for every frame (Wi-Fi; APs drop frames whose source MAC isn't the associated station) |

`-v0` prints results only; `-v3` adds packet-level debug. Full flag reference: `man dhcpig`
(or `packaging/dhcpig.1` before install).

What each mode does
-------------------

**DHCP Exhaustion** (`exhaust`) — destructive
* ARP-inventories the segment, then proves DHCP works from this machine and for an unknown MAC
* DHCPRELEASEs every neighbour's lease — the protocol requires no proof of ownership
* Floods DISCOVER/REQUEST from fabricated MACs until the server stops answering
* Re-requests the released addresses by name (option 50) once the pool is drained
* Forges RFC 5227 ARP conflicts against what it took, to see if hosts surrender the address
* **Verdict:** could a brand-new client still get an address afterwards?

**DHCP Release Active Clients** (`release`) — destructive
* Same chain minus the flood: inventory → release → re-request by name → ARP conflict
* Hits devices connected right now; the pool is left intact so most can re-acquire
* **Verdict:** did any host lose its address and fail to get a new one?

**Post Exhaustion / Reset** (`release-previous`) — recovery
* Replays the on-disk lease journal and hands back every address this tool took
* Filtered to this interface, network and DHCP server; `--max-age` drops stale entries
* Sends nothing at all if a new client can already get an address
* **Verdict:** is the pool usable again?

**Find Neighbors** (`active-scan`) — read-only
* ARP-sweeps the scope, sends one DHCPINFORM to fingerprint the DHCP servers
* Takes no addresses, disturbs no leases

**Passive scan** (`scan`) — read-only, CLI only
* Watches DHCP and ARP; fingerprints hosts by option-55 order, falling back to MAC vendor
* Sends nothing. Runs until stopped

Reading a run
-------------

Everything lands in the event log, worst first: findings, then one line per host, then an
`OUTCOME` roll-up. `Verbosity 0` (web) or `-v0` (CLI) hides the packet traffic. The JSON export
is the complete record — the log is a summary.

Undoing a run
-------------

Leases are **kept** after a run so the exhausted state can be verified. Release them:

    sudo .venv/bin/dhcpig restore eth0             # same process still running
    sudo .venv/bin/dhcpig release-previous eth0    # any time later, from the lease journal

The journal (`$XDG_STATE_HOME/dhcpig/leases-<iface>.jsonl`) records MAC, IP, server and
timestamp per lease taken — engagement data. Delete it when you're done.

Disclaimer
----------

Only run this against networks you own or are explicitly authorized to test. `release` and
`exhaust` disrupt live clients by design; `--scope` is optional and defaults to the whole
segment. The authors are not responsible for misuse.

Design notes and internals: `docs/DESIGN.md`. Contributing: `CONTRIBUTING.md`.
Licence: GPL v2 or later.
