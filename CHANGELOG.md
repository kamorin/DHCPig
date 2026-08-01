# Changelog

## 2.5.0 — 2026-07-29

- **Fixed: "Copy as CLI" produced an unparseable command for exhaust.** The web UI offers a
  Scope box for every mode and `as_cli()` emits `--scope` accordingly, but the `exhaust`
  subparser never accepted it — the copied command exited 2. Added, with `dest="scope_cidrs"`
  to match the other subcommands. Scope does real work in exhaust: it bounds the ARP sweep and
  `_send()`'s scope guard, and makes the pool-size estimate deterministic instead of inferred
  from the first OFFER's subnet.
- **README rewritten** as a getting-started doc: 344 lines down to ~100. Web UI first (three
  commands plus the sudo/token/port-forward gotchas), then the CLI, then what each mode
  actually does in bullets. Design detail now lives in `docs/DESIGN.md`.

- **Exhaust now re-acquires released addresses *after* draining the pool**, not in the prelude.
  RFC 2131 §4.3.1 has a server pick, in order: an address already bound to the client, the
  client's previous address, the option-50 request *if available*, then anything free. Our
  DISCOVER comes from a MAC the server has never seen, so while the pool has headroom the
  server prefers a fresh address and `granted=0` is the expected answer whether or not the
  RELEASE was honoured — the measurement said nothing. Run once the free list is empty, that
  rule is the only one left and the result finally discriminates. `release` keeps the inline
  call (it never drains anything) and its finding now says the evidence is weaker.
- **`NEIGHBOR_LEASES_RELEASED` no longer claims the server defended itself on a zero.** The old
  text read "The server ignored the unauthenticated RELEASE … (the desired behavior)" for any
  `granted=0`, which is a false PASS in everything but name when the pool had free addresses.
  It's now three-way: hijack confirmed, zero-with-pool-drained (real evidence), and
  zero-with-headroom (explicitly not evidence, with a pointer to re-run as exhaust).
- **RUN_SUMMARY steps tightened** — "Inventoried the network by ARP → 4 devices found" becomes
  "ARP inventory → 4 devices"; the right column no longer repeats the left. Protocol names stay
  on the right, per the rule a test enforces.

- **Icon redesigned to actually look like a pig.** The first version led with a full hoodie and
  a visor across half the face, which at 28px in the header read as a dark blob rather than an
  animal. The head now fills the canvas, ears and snout carry the silhouette, and the hacker cue
  is reduced to slim shades plus a thin hood brim that stays clear of the ears. Same file serves
  as `/icon.svg`, the favicon, `packaging/dhcpig.svg` for the `.desktop` entry, and the README
  header.

- **Fixed: `active-scan` never finished.** Its worker is an ARP sweep plus one DHCPINFORM and
  then it's done, but `ACTIVE_SCAN` wasn't in `RUN_ONCE_MODES`, so neither the CLI polling loop
  nor the web reaper ever called `stop()` — the run sat in RUNNING emitting status ticks until
  someone pressed Stop, and no findings or report were ever produced. The set is about "does
  the worker finishing mean the run is over", not about whether a mode is destructive; deriving
  it from `DESTRUCTIVE_MODES` is what hid this. `scan` stays out deliberately — a passive
  listener has no natural end.

- **Removed `EXECUTION-PLAN-*.md` and `SECURITY.md`** from the repo. The plan docs were
  build-time blueprints that had served their purpose; everything load-bearing from them, and
  from SECURITY.md, was folded into docs/DESIGN.md and the README, and the ~20 source and doc
  comments that pointed at them now point at the AGENT_HANDOFF section covering the same ground.
  docs/DESIGN.md is the only design document in the repo now.

First tagged release of the 2.x rewrite. Everything below this line shipped in it: the package
refactor of the single-file `pig.py` (2.0), the windowed/adaptive exhaust sender and the
control-transaction verdict model (2.1), the lease journal and `release-previous` recovery
(2.2), RFC 5227 ARP-conflict eviction with targeted re-acquisition (2.3), racing freed
addresses (2.3.1), and the reporting rework that ends a run with a plain-language summary and
a per-host roll-call on the event log (2.3.2 – 2.3.5).

**Not yet validated against real hardware beyond a single live `/22` exhaust run** — see
docs/DESIGN.md §9 before relying on the eviction, re-acquisition or recovery paths.

## Pre-2.5.0 development history (condensed)

Everything from here down predates the 2.5.0 tag (none of these intermediate points were
themselves released/tagged) and shipped as part of it — see the 2.5.0 section above for what's
actually running today. Kept as release-level summaries rather than the original detailed
entries; the design rationale behind each still-live decision lives in `docs/DESIGN.md`, not
here.

- **2.3.2–2.3.5 — the reporting rework.** Findings moved out of a web Findings tab (deleted,
  along with its client-side stores) and into the event log, worst-severity-first, rendered
  identically everywhere via one shared summary rule. Added `RUN_SUMMARY` (a plain-English,
  always-present step list explaining what the run actually did) and `NeighborSummary` (a
  per-host end-of-run roll-call, later folded into `NEIGHBORS_OBSERVED` so it also reaches the
  JSON/HTML report). The pre-run ARP sweep and neighbor-release phase became unconditional
  (`--no-arp-scan`/`--no-release` removed) since every later phase depends on their output.
- **2.3.1 — race-to-grab-freed-addresses**, plus two real ownership-check bugs the work
  surfaced: `_handle_nak()` was counting *every* NAK on the segment as ours (shrinking the
  window / feeding halt-on-control off unrelated traffic), and `_handle_offer()`/`_handle_ack()`
  had no ownership check at all — the latter meant `restore()`/`release-previous` could later
  DHCPRELEASE a real, uninvolved client's active lease. Both fixed by checking
  `xid in self._inflight` before acting.
- **2.3.0 — targeted re-acquisition, RFC 5227 ARP-conflict eviction, `release` restructured.**
  `dry_run`/`offline` split into genuinely different concerns; the sniffer BPF widened to see
  foreign DHCP traffic; `Mode.GARP_DOS` retired in favour of RFC 5227 §2.4 address-conflict
  eviction (no more gateway-blackhole third frame); `release` moved onto the same shared
  prelude `exhaust` uses, fixing a bug where it never started a sniffer and so its control
  transaction always failed.
- **2.2.0 — lease journal + `release-previous`.** An append-only, crash-tolerant JSONL journal
  records every lease the moment it's acquired, so a drained pool can be recovered even after
  the process that drained it is gone. `release-previous` replays it, bounded to the current
  interface/CIDR/server/age — leasequery, blind sweeps, and ARP-derived targets were all
  considered and rejected because none of them can *prove* this tool took a given address.
- **2.1.0 — release-first exhaust, windowed pacing, halt-on-control, headroom.** Prompted by a
  live run on a real `/22` that stalled at 56/~1000 addresses from pending-offer-table
  saturation, not real exhaustion. Replaced the open-loop DISCOVER flood with a bounded,
  adaptive window; added halt-on-control (stop sending on the first defensive signal, keep
  leases held, still run the post-controls); replaced four ad hoc verdicts with
  `DHCP_STARVATION_ATTAINED`/`_NOT_ATTAINED`; fixed two release-phase bugs (server identity
  defaulting to `0.0.0.0`, and `build_release_v4()` building an L3-only packet despite being
  sent via L2).
- **2.0.0 (V1.0–V2.0) — the rewrite.** Refactored the single-file `pig.py` into an installable,
  tested `dhcpig` package with a UI-free `core` engine driving both a CLI and a stdlib-only web
  UI (SSE, vanilla JS, no build step). Along the way: the authorization gate was added then
  later removed; the two-leg (self/new-MAC) control transaction replaced a single-MAC check that
  produced false verdicts against a drained pool; `Mode.GARP_DOS`'s original single-frame form
  was rewritten into a real per-round eviction mechanism before later being retired in 2.3;
  fingerprinting moved from a bundled FingerBank `.conf` to a static PacketFence-derived JSON,
  later trimmed to PacketFence-only; MAC-vendor (OUI) fallback identification was added for
  ARP-only neighbours; runs gained the ability to finalize themselves instead of sitting idle
  after the pool drained; auto-restore-on-exit was added, then later removed once the lease
  journal made it unnecessary. Carried forward two pre-existing upstream fixes: PR #27
  (server-id = option 54 else siaddr) and PR #28 (client MAC = `chaddr[:6]`, REQUEST includes
  option 61).

## 1.6 (legacy) — 2024-01
- Python 3 & scapy 2.5 support.
