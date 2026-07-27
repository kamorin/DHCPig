DHCPig
======

Tags: DHCP, IPv4, IPv6, exhaustion, pentest, fingerprinting, security, scapy

SUMMARY
-------

DHCPig is a whitehat network-hardening validation tool. It exercises DHCP starvation,
lease-hijack, forced lease release with targeted re-acquisition, RFC 5227 ARP-conflict
eviction, and passive host fingerprinting so security engineers can confirm a network is
defended (DHCP snooping, port security, Dynamic ARP Inspection, etc.).

`dhcpig` 2.x is a refactor of the original single-file `pig.py` into an installable,
tested package. It requires `scapy>=2.5` and root/CAP_NET_RAW. The destructive mode
(`release`) is opt-in by subcommand, takes an optional `--scope`, and is rate-limited
and reversible (`dhcpig restore`) — there is no separate authorization gate; see DISCLAIMER.

INSTALL
-------

    pipx install dhcpig        # or: pip install .

USAGE (CLI)
-----------

    sudo dhcpig exhaust eth1 --report run.json
    sudo dhcpig scan eth1 --report inventory.json          # passive, read-only
    sudo dhcpig release eth1 --scope 172.20.0.0/16 --rate 20  # DESTRUCTIVE
    sudo dhcpig restore eth1                               # release leases we grabbed
    dhcpig ifaces

`release` disrupts live clients — it runs the same phase chain `exhaust` does (see RELEASE
below), including RFC 5227 ARP-conflict eviction. It takes no confirmation step — `--scope`
is optional and **defaults to the interface's own network**, so `dhcpig release eth1` will
target every host on the segment. Pass `--scope` to bound it.

Safety flags:

    --dry-run            reconnaissance pass: ARP sweep and control transactions run for
                          real, everything mutating (release, re-acquisition, the sender,
                          eviction) is logged but not sent — needs root, not a no-op (see
                          DRY-RUN below)
    --rate N             cap packets/sec — release/active-scan/release-previous only,
                          default 7 (exhaust has no --rate; see EXHAUST PIPELINE below)
    --scope CIDR         restrict targets to these networks (repeatable; optional)
    --no-release         skip releasing ARP-discovered neighbors before exhausting
    --no-arp-scan        skip the pre-run ARP inventory
    --no-journal         don't record acquired leases to the recovery journal (see RECOVERY)
    --no-evict           skip RFC 5227 ARP-conflict eviction (exhaust and release; see EVICTION)
    --status-interval N  periodic status line, default every 5s (0 disables)
    --no-race-freed      exhaust only: don't race to grab addresses freed mid-run (see RACING
                         FREED ADDRESSES below)
    --race-on-rediscover exhaust only: also race a known neighbor's address on rediscovery

DRY-RUN
-------

`--dry-run` is a genuine reconnaissance pass, not a shape-only preview: the pre-run ARP sweep
and the pre/post control transactions (an ordinary DHCP cycle from the real NIC MAC, released
immediately) all run for real, because they self-clean and cost the target network nothing.
Only **mutating** sends are suppressed — the release phase, targeted re-acquisition, the
windowed exhaust sender, and eviction are built and logged but never touch the wire. Because
the ARP sweep and control transactions are real traffic, `--dry-run` needs a raw-capable
interface and root, the same as a live run.

Leases are **always kept** after the run so the exhausted state can be observed and verified.
There is no auto-restore-on-exit — release them explicitly with `sudo dhcpig restore eth1` (or
the Restore button in the web UI) if the same process/session is still around, or
`sudo dhcpig release-previous eth1` once it isn't — see RECOVERY below.

EXHAUST PIPELINE
-----------------

`exhaust` runs a shared prelude before the sender starts (`_common_prelude()`, also used by
`release` — see RELEASE below): an ARP sweep (pre-run inventory), a control transaction
(baseline reachability), a **release phase** (DHCPRELEASE for every ARP-discovered neighbor, so
the pool has addresses to give up rather than only whatever was already free — `--no-release` to
skip), and **targeted re-acquisition** (a DISCOVER carrying DHCP option 50 for each freed
address specifically, so the release phase's effect is actually confirmed rather than assumed —
see RECOVERY/`NEIGHBOR_LEASES_RELEASED` below). Then the sender starts; after it finishes,
**eviction** runs (see EVICTION below) before the verdict is produced.

The sender is a **windowed, adaptive pipeline**, not an open-loop flood: a handful of
DISCOVER/REQUEST transactions are in flight at once, growing slowly on clean ACKs (0.01 of a
slot per ACK — **100** clean ACKs in a row to widen the window by one) and halving instantly on
a NAK, timeout, or duplicate offer. Flooding faster than handshakes can complete saturates the
server's pending-offer table — which looks like exhaustion but isn't, and produced a false
result on a real `/22` (the server re-offered the same address to two of our MACs, then NAKed,
then went silent at 56/~1000 addresses). Growth is deliberately far slower than shrink, so a
window that's been knocked down stays down rather than climbing back — a small, steady window is
the whole point. This is why `exhaust` has no `--rate`: the window paces it, and backs off
automatically.

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

RECOVERY
--------

`exhaust` leaves the network broken on purpose — that's the point of a successful run. The
usual way back is `dhcpig restore eth1`, which releases exactly the leases the *currently
running* engine acquired, from its own memory. That covers the happy path and nothing else: if
the process was killed, the box rebooted, or you're back at this days later from a different
machine, `restore` has nothing to work with.

`release-previous` is the recovery path for that. Every lease `exhaust` acquires is recorded to
an on-disk **lease journal** the moment the ACK lands (`--no-journal` to opt out, though there's
rarely a reason to), so recovery survives however badly the run ended:

    sudo dhcpig release-previous eth1

It replays the journal for the current network only: it loads every still-open entry, keeps the
ones inside `--scope` (or the interface's own network), keeps the ones recorded against the
DHCP server that's actually reachable right now (guards against a journal carried between
engagements on the same laptop producing release targets on the wrong network — `--any-server`
overrides), drops anything older than `--max-age` days (default 7), and sends DHCPRELEASE for
what's left. It runs a "can a new client get an address?" probe before starting (skips entirely
if the pool isn't actually exhausted) and again after, so the result is a verdict
(`POOL_RECOVERED` / `POOL_RECOVERY_PARTIAL` / `POOL_RECOVERY_FAILED`), not just a packet count.

It needs no ARP sweep and no server discovery: the journal already carries the MAC, IP, and
server identity for every lease, so recovery works from disk alone. It's also not gated behind
`DESTRUCTIVE_MODES` — it only ever releases leases the journal proves this tool took, so it adds
no capability beyond what `exhaust` already used. Default `--rate` is 50, not the usual 7: this
runs during an outage you're trying to end, and the frames are unicast to one server rather than
sprayed at the segment.

The journal lives at `$XDG_STATE_HOME/dhcpig/leases-<iface>.jsonl` (falling back to
`~/.local/state/dhcpig/`) — never under `/var/lib` or another system path, since it's
per-engagement data, not system state. See SECURITY.md for what it contains and how to clear it.

WEB UI
------

    sudo dhcpig-web            # prints a tokenized loopback URL; open it in a browser

The web UI (`dhcpig-web`) is Python-stdlib only (no framework, no build step). It is bound to
`127.0.0.1`, requires the printed bearer token, and enforces same-origin. All modes are
available with a live dashboard (including the headroom counter for exhaust), OS-inventory
tables, JSON/CSV/HTML export, "Copy as CLI", and profile save/load. For a headless VM, reach it
from your host with:

    ssh -L 8787:127.0.0.1:8787 kali@<vm-ip>

MODES
-----

* __exhaust__     — DISCOVER/OFFER/REQUEST loop that consumes the address pool (non-destructive
                    until you count what it does to *other* hosts' current leases — see RELEASE
                    and EVICTION below). Web UI label: "DHCP Exhaustion".
* __scan__        — passive ARP + DHCP capture; fingerprints every host (OS/device/vendor). Not
                    offered in the web UI dropdown (still a valid CLI subcommand / API mode).
* __active-scan__ — active discovery: ARP sweep of the scope + a DHCP INFORM to find/fingerprint
                    servers. Non-destructive; requires `--scope` (auto-filled from the interface).
                    Web UI label: "Find Neighbors".
* __release__     — runs the same phase chain as `exhaust` minus the windowed sender: ARP
                    inventory, release, targeted re-acquisition, and RFC 5227 ARP-conflict
                    eviction (DESTRUCTIVE; scope defaults to the iface network — see RELEASE and
                    EVICTION below). Web UI label: "DHCP Release Active Clients".
* __release-previous__ — recovers a pool this tool previously drained, by replaying the lease
                    journal (not destructive — see RECOVERY below). Web UI label:
                    "Reset / Recover DHCP Records".

RELEASE
-------

`release` is not just "send RELEASE and stop" — it runs the same chain `exhaust` runs before its
sender: an ARP sweep, a control transaction (real-NIC-MAC leg only — it does not run the
new-client leg `exhaust` uses for its starvation verdict, since that verdict is meaningless
here), the release phase, targeted re-acquisition of every freed address, and then RFC 5227
ARP-conflict eviction (see EVICTION below) against whatever it just re-acquired.

That means `release` can force a *currently connected* client both off its lease **and** off its
address at the link layer, then watch whether it comes back cleanly. This is a materially bigger
blast radius than the name suggests on its own — see SECURITY.md. `--no-evict` skips just the
eviction step; there's no equivalent `--no-release` for the `release` subcommand, since skipping
the release step is the entire point of `release` mode existing.

`release` never triggers `DHCP_STARVATION_ATTAINED`/`_NOT_ATTAINED` — those are exhaust's
verdict, derived from a control leg `release` doesn't run. Its own findings are
`NEIGHBOR_LEASES_RELEASED` and the eviction findings below.

EVICTION
--------

After re-acquiring a freed address (RELEASE / EXHAUST PIPELINE above), both `exhaust`
and `release` contest the real owner's claim to it via forged broadcast ARP, per **RFC 5227 §2.4
address conflict detection** — the same mechanism a host uses to defend itself against an
accidental duplicate assignment, turned into a way to force it off an address it no longer holds
a DHCP binding for. `--no-evict` skips this phase entirely.

Per target per round, two frames (`ARP_REQUEST` + `ARP_REPLY` forms — stacks differ in which
they honour), claiming the target's own IP at a fresh, always-bogus MAC. **The forged MAC is
never our own** — a bogus MAC blackholes the claim; our own MAC would instead intercept the
victim's traffic, which is out of scope for this tool. By default 4 rounds, spaced 3 seconds
apart (`timeouts.evict_interval`, must stay under RFC 5227's 10-second `DEFEND_INTERVAL` — a
host defends once, then must give up on a *second* conflict inside that window; spaced further
apart, each round looks like a fresh, independently-defensible conflict and the host never gives
up the address). After the last round, DHCPig waits 16 seconds (`evict_settle`) for a
DECLINE/restart/APIPA to land, then measures — a target that declines right as the window closes
needs time for its follow-up DISCOVER to land too, or its outcome locks in one rung too low.

**Outcome ladder** (each target's *highest* rung reached wins):

| Rung | Signal | Meaning |
|------|--------|---------|
| `no_reaction` | nothing | frame may not have been delivered, or the stack ignores ACD |
| `defended` | ARP announcement from the victim's real MAC | our frame arrived — DAI isn't filtering this port |
| `declined` | DHCPDECLINE from the victim | the host gave up the address — gold-standard proof |
| `rediscovered` | fresh DISCOVER from the victim | it restarted at INIT |
| `discover_unanswered` | that DISCOVER got no OFFER | real denial of service |
| `apipa` | victim's MAC now sourcing ARP from `169.254.0.0/16` | full eviction — DHCP totally failed |

Findings are **mode-aware**, because "success" means different things in the two modes: under
`exhaust` the pool is meant to be drained, so even a plain `rediscovered` (the DISCOVER got
answered) is already evidence the address was taken by force — `declined` and above raises
`CLIENTS_EVICTED_FROM_ADDRESSES` (FAIL, high). Under `release` the pool is never drained, so a
clean restart-and-immediate-reacquire is the *expected*, low-harm result of the mode, not a
denial — only `discover_unanswered`/`apipa` count as FAIL there; `declined`/`rediscovered` land
in `CLIENTS_DEFENDED_ADDRESSES` (INCONCLUSIVE) instead, alongside targets that merely defended.
Nothing reacting at all is `ARP_CONFLICTS_UNANSWERED` (INCONCLUSIVE) — a filtered switch port and
a network that simply ignored the conflict look identical from this vantage point, so no PASS
verdict is offered here; check DAI drop counters to tell them apart.

Under `--dry-run` the phase still runs and logs its target list and round count, but sends
nothing — `DRY_RUN_SUMMARY`'s `would_evict` count covers that case instead of the findings above.

RACING FREED ADDRESSES
-----------------------

`exhaust` also reacts to addresses that come free **mid-run for reasons other than its own
RELEASE phase** — a NAK'd renewal, a client DECLINE, or (opt-in) a known neighbor restarting at
INIT — by firing a priority, targeted DISCOVER (option 50) for that exact address ahead of the
normal untargeted flood, rather than waiting for the flood to land on it by chance. `release`
does not do this — it has no concurrent flood to race ahead of.

Expected yield is low by design: the trigger set only includes signals that are both *observable*
(broadcast, not the unicast DHCPRELEASE a departing client actually sends) and *actually imply the
server considers the binding free* — a client can abandon an address while the server holds the
binding until lease expiry regardless. That's why the win/loss counters exist: they tell you
empirically whether this is worth anything on a given segment rather than assuming it.

    --no-race-freed        disable racing entirely (exhaust only; on by default)
    --race-on-rediscover   also race a known neighbor's address the moment it re-DISCOVERs
                            (off by default — highest-volume, lowest-precision trigger)

Races take at most a handful of extra send slots (`race_max_inflight`, default 4) **above** the
normal window — bounded, not an open bypass of the pacing that EXHAUST PIPELINE describes above.
Results land in the `races` counter and a `RACED_FREED_ADDRESSES` (INFO) finding once any race
has actually run, broken down by how many were won (`granted`) vs. lost, and by which trigger
fired. Under `--dry-run` the sends are suppressed like everything else mutating; `DRY_RUN_SUMMARY`
carries a `would_race` count instead.

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
parameter-request-list order (exact, order-sensitive match), falling back to MAC-OUI. It ships
a static `packetfence_dhcp_fingerprints.json` (PacketFence fingerprints, 535 entries) — no API,
no key, works fully offline/airgapped. A fingerprint matching more than one device is reported
with lower confidence and flagged ambiguous. Drop a refreshed
`packetfence_dhcp_fingerprints.json` into `src/dhcpig/data/` to update coverage; see
`data/DATA_ATTRIBUTION.md`. In `scan`/`active-scan`, neighbors discovered via ARP are
automatically paired with any DHCP fingerprint seen for the same MAC, so the Neighbors table
shows OS/Device whichever signal arrives first.

Hosts with **no** usable DHCP fingerprint fall back to **MAC vendor** identification, so the
OS/Device column is never blank: scapy's bundled IEEE/Wireshark OUI database (~50k entries,
offline). These are shown as `Vendor (MAC vendor)` at low confidence — a NIC manufacturer is
not an OS. Randomised/locally-administered MACs are labelled as such.

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
