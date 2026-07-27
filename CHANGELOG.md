# Changelog

## 2.3.1 (unreleased) — race to grab addresses the moment they're freed

Design doc: `EXECUTION-PLAN-race-freed.md`. §5f's targeted re-acquisition only reacts to
addresses `exhaust`/`release` freed themselves via their own RELEASE phase; any address freed
mid-run some other way previously only got picked up if the untargeted exhaust flood happened to
land on it. This release reacts to those addresses too, plus two ownership-check bugs the work
surfaced along the way, and a web-UI stall fix.

- **Race to grab freed addresses (`exhaust` only).** Three triggers, ranked by how strongly they
  imply the *server* considers a binding free: a foreign NAK (strongest — the server told some
  other client its binding is invalid), a foreign DECLINE (weaker — most servers quarantine
  rather than free a declined address, kept on by default so the counters can show the real hit
  rate), and — opt-in via `--race-on-rediscover`, off by default — a foreign DISCOVER from a MAC
  already in the ARP inventory (weakest signal, highest volume). **Never DHCPRELEASE-triggered**:
  it's unicast to the server and invisible on a switched segment. Each trigger fires a priority,
  targeted DISCOVER (option 50) into a bounded reserve of up to `race_max_inflight` (default 4)
  slots *above* the normal exhaust window — not a window bypass, a small overtake. Race state
  (`_race_targets`/`_race_outcomes`) is kept entirely separate from re-acquisition's, so racing
  can never silently widen eviction's target set. New `races`/`d_races` counters (CLI status
  line, web dashboard, `status()`/report); new `RACED_FREED_ADDRESSES` (INFO) finding once any
  race has run, broken down by outcome and trigger; `would_race` in `DRY_RUN_SUMMARY` under
  `--dry-run`. New flags `--no-race-freed` (on by default) / `--race-on-rediscover` (off by
  default), exhaust-only on both CLI and web.
- **Fixed: foreign NAKs were polluting our own window/halt state.** `_handle_nak()` counted
  *every* NAK on the segment as ours, shrinking the send window and feeding the `nak_burst` halt
  signal off traffic addressed to other clients. Now gated on `xid in self._inflight`; a foreign
  NAK is observed (it's a race trigger) but no longer touches `self.naks`/the window/halt
  detection.
- **Fixed, more severe: `_handle_offer()`/`_handle_ack()` had no ownership check at all.**
  `_handle_offer()` would build and send a REQUEST impersonating whichever MAC any observed
  OFFER's `chaddr` belonged to — potentially a real third-party client. `_handle_ack()` would
  unconditionally register/journal/count any ACK witnessed on the segment, meaning `restore()` /
  `release-previous` could later send DHCPRELEASE for a genuine, uninvolved client's active
  lease. Both now check `xid in self._inflight` first; a foreign packet is debug-logged and
  otherwise ignored (server identity/fingerprint learning from foreign traffic is unaffected —
  that was never the bug).
- **Web UI no longer stalls after a run-once mode finishes.** `release`/`release-previous` ended
  their worker thread on completion, but only the CLI polled for that and called `stop()` — the
  web UI sat idle for up to ~65s (the sniffer's own idle timeout) before a verdict appeared.
  `WebApp` now runs the same polling loop (`RUN_ONCE_MODES`, promoted to `core/models.py` as the
  canonical definition both the CLI and web import).
- **Info-level packet logging.** `DiscoverSent`/`RequestSent` now carry `option50`/`hostname`;
  the CLI renderer and web log show `chaddr=`/`option50=`/`hostname=` on every outbound
  DISCOVER/REQUEST line at normal verbosity, not just at `-v3` debug.
- 312 unit tests passing (up from 265 at the start of 2.3.1); ruff clean. Not yet exercised
  against real hardware — see AGENT_HANDOFF.md §9.

## 2.3.0 (unreleased) — targeted re-acquisition, RFC 5227 ARP-conflict eviction, restructured `release`

Design doc: `EXECUTION-PLAN-eviction.md`. Prompted by four goals: force a still-connected client
off an address it holds (not just a free one), do it via RFC 5227 address-conflict detection
rather than a blunt gateway-blackhole ARP flood, observe third-party DHCP traffic during a run as
direct evidence of client-visible outage, and give `release` the same phase discipline `exhaust`
already had rather than its own thinner, buggier path.

- **`dry_run`/`offline` split into genuinely different concerns.** `offline` is now the hard
  "never touch a socket" switch (no sniffer, no `sendp`, no `srp()`) — what makes web/CLI tests
  and a no-root preview possible. `dry_run` alone now runs the ARP sweep and the control
  transaction's own DISCOVER/REQUEST/RELEASE **for real** (they self-clean and cost the target
  nothing) and only suppresses **mutating** sends: release, re-acquisition, the windowed exhaust
  sender, eviction. Mechanism: `_send(pkt, probe=False)` — `probe=True` bypasses dry-run
  suppression (never `offline`) at exactly two call sites, the ARP sweep and the control
  transaction. `--dry-run` now needs a raw-capable interface and root, the same as a live run.
- **Sniffer BPF widened** from server→client only (`src port 67 and dst port 68`) to both
  directions (`port 67 or port 68`) — needed to observe foreign DISCOVERs/DHCPDECLINEs, which are
  client→server and were invisible before. A self-filter (`_is_own_traffic()`) drops our own
  echoed DISCOVER/REQUEST/RELEASE before it reaches foreign-DISCOVER handling.
- **`Mode.GARP_DOS` retired.** Removed from the UI and CLI (`build_arp_poison()`, `_garp_worker()`,
  `_on_garp_arp()`, both `ARP_FORGERIES_*` findings gone from `src/`). Its frame-building core
  survives, rewritten: `_do_garp()` → `_do_arp_conflict()` — no more unicast gateway-blackhole
  third frame, now the mechanism eviction (below) uses.
- **Foreign DISCOVER observation.** Every DISCOVER from a MAC that isn't ours is now tracked
  (first sighting per MAC emits `ForeignDiscover`; every sighting is tracked so a later OFFER can
  mark it answered), with `foreign_discovers`/`foreign_discovers_unanswered` counters reaching
  status/StatusTick/CLI/web. New findings: `FOREIGN_DISCOVERS_UNANSWERED` (FAIL, high — "other
  people's machines asked for an address and got nothing," the most direct evidence of
  client-visible outage this tool can produce) / `FOREIGN_DISCOVERS_ANSWERED` (INFO).
- **Targeted re-acquisition.** After the release phase frees addresses, `exhaust`/`release` now
  push one DISCOVER per freed `(mac, ip)` carrying DHCP option 50 (`requested_addr`) into the
  existing windowed pipeline — no parallel sender — and classify each outcome as `granted` /
  `offered_different` / `naked` / `no_response`. **Fixes a real unsoundness**:
  `NEIGHBOR_LEASES_RELEASED`'s evidence used to be an ARP re-probe, which reads 0 even on a fully
  successful RELEASE (a released victim keeps using its old address until its own lease's T1,
  with no way to know it was released) — evidence is now the re-acquisition `granted` count.
- **RFC 5227 §2.4 ARP-conflict eviction.** After re-acquiring a freed address, contest the real
  owner's claim to it via forged broadcast ARP (`ARP_REQUEST` + `ARP_REPLY`, bogus MAC, never our
  own), by default 4 rounds spaced 3s apart (`evict_rounds`/`timeouts.evict_interval`, validated
  at config build against RFC 5227's 10s `DEFEND_INTERVAL` — `ConfigError` if violated), then an
  16s settle (`evict_settle`, bumped from 8.0s after a live run showed a DECLINE could be
  measured before its follow-up DISCOVER arrived, understating the outcome by one rung) before
  measuring the outcome ladder: `no_reaction` < `defended` <
  `declined` < `rediscovered` < `discover_unanswered` < `apipa`. New `--no-evict` (default on).
  New findings `CLIENTS_EVICTED_FROM_ADDRESSES` (FAIL, high) / `CLIENTS_DEFENDED_ADDRESSES`
  (INCONCLUSIVE) / `ARP_CONFLICTS_UNANSWERED` (INCONCLUSIVE) — deliberately no PASS, since
  "nobody reacted" can't be told apart from "the frames never arrived." **Findings are
  mode-aware**: under `exhaust` the pool is meant to be drained, so `declined` and above counts
  as evicted; under `release` the pool is never drained, so a clean restart-and-reacquire
  (`rediscovered`) is the expected, low-harm result and only `discover_unanswered`/`apipa` count.
- **`release` restructured onto the shared prelude.** Runs the same chain as `exhaust` minus the
  windowed sender: ARP inventory → control/self → release → re-acquisition → eviction → findings,
  via a new `_common_prelude()` extracted from `_exhaust_prelude()`. **Fixes a second real bug**:
  the old `_release_worker()` ran a control transaction to learn the server identity but never
  started a sniffer, so the OFFER/ACK reply could never arrive and the control always failed.
  `release`'s control outcome is stored separately (`self._rel_pre_control`, never
  `self.control_pre`) so it can never trigger `DHCP_STARVATION_*` — that verdict is exhaust's
  alone, derived from a control leg `release` doesn't run.
- **Window growth ratchet slowed 50× (0.5 → 0.01 per clean ACK).** 100 clean ACKs now widen the
  window by one slot instead of 2 — on any realistic pool the window now stays close to
  `window_initial` (8) for the whole run, keeping the server's pending-offer table from
  saturating. New `SessionConfig.window_growth_per_ack` (config-driven, not hardcoded). Growth is
  now ~5000× slower than `_shrink_window()`'s halving, so a noisy run trends toward the floor of
  1 rather than climbing back — a deliberate trade-off, see `_grow_window()`'s docstring.
- **Web UI mode labels relabeled**: "DHCP Exhaustion" / "DHCP Release Active Clients" /
  "Reset / Recover DHCP Records" / "Find Neighbors". Passive `scan` removed from the dropdown
  (still a valid CLI subcommand / API mode — `config_from_payload()` unchanged).
- 265 unit tests passing (up from 200 at the start of 2.3); ruff clean. **Not yet exercised
  against real hardware** — see AGENT_HANDOFF.md §9/§10.

## Unreleased — auto-restore-on-exit removed

`--restore-on-exit`/`restore_on_exit` is gone. `release-previous`'s lease journal is now the
real cross-process recovery path, so an in-process "release everything when the run ends" flag
no longer earns its complexity — it never survived a killed process or reboot anyway. Leases are
now **always** kept after a run; the caller releases them explicitly via `dhcpig restore
<iface>` (or `POST /api/session/restore`) if the same session is still around, or `dhcpig
release-previous <iface>` once it isn't.

- `core/models.py`: removed `SessionConfig.restore_on_exit`.
- `core/engine.py`: `stop()` no longer conditionally calls `self.restore()`; `restore()` itself
  is unchanged and still available for explicit, caller-initiated cleanup.
- `cli/main.py`: removed `--restore-on-exit` and the legacy `--no-restore` no-op from the
  `exhaust` subparser.
- `web/schemas.py`: removed `restore_on_exit` from `config_from_payload()` and `as_cli()`.
- `web/static/index.html`/`app.js`: removed the "disable auto-restore" checkbox and its wiring.

## Unreleased — fingerprint/OUI data simplified to single-source

`src/dhcpig/data/` now ships exactly two sources: PacketFence DHCP fingerprints and scapy's
bundled OUI database. Dropped: the Huginn-Muninn fingerprint merge, the custom
`fingerprints.json` builtin fallback table (option-60 vendor-class / representative-PRL / OUI
hints), and the `mac-vendor.txt` supplement vendored from arp-scan.

- `combined_dhcp_os_lookup.json` (PacketFence + Huginn-Muninn, 594 fingerprints) replaced by
  `packetfence_dhcp_fingerprints.json` (PacketFence only, 535 fingerprints). Same lookup
  semantics (exact, order-sensitive option-55 match; ambiguous multi-candidate entries flagged
  and reported at lower confidence).
- `core/fingerprint.py`: removed `_builtin()`/`_resolve_from_builtin()`; a miss on the
  PacketFence DB now falls straight through to `from_mac()` OUI-only identification.
- `core/oui.py`: removed the `mac-vendor.txt` supplement and its longest-prefix-wins merge
  logic; MAC vendor lookup is scapy's bundled Wireshark `manuf` DB only, with the
  locally-administered-bit fallback kept (it's a computed check, not vendored data).
- `data/DATA_ATTRIBUTION.md` rewritten to reflect single-source provenance for both fingerprints
  and OUI.

## 2.2.0 (unreleased) — lease journal + release-previous recovery

`dhcpig restore` only ever released leases held in the memory of the currently-running engine —
useless once the process was killed, the box rebooted, or you're recovering from a different
machine. This release adds a real recovery path.

- **Lease journal.** Every lease `exhaust` acquires is now recorded to an append-only,
  crash-tolerant JSONL file the moment the ACK lands (`core/journal.py`), not just at the end of
  a clean run. Lives at `$XDG_STATE_HOME/dhcpig/leases-<iface>.jsonl` (falling back to
  `~/.local/state/dhcpig/`) — deliberately never under `/var/lib` or another system-owned path,
  since it's per-engagement data, not system state. On by default; `--no-journal` opts out.
  DHCP option 51 (lease-time) is now parsed into `Lease.lease_time`, which was declared but
  never actually populated before this.
- **`release-previous` command.** Replays the journal to recover a network this tool previously
  drained: filters to the current interface, the current CIDR (`--scope`, else the interface's
  own network — refuses to run if neither resolves), the currently-reachable DHCP server (guards
  against a journal carried between engagements producing targets on the wrong network;
  `--any-server` overrides), and `--max-age` (default 7 days). Runs a "can a new client get an
  address?" probe before starting (skips entirely, sending nothing, if the pool isn't actually
  exhausted) and again after, producing a verdict (`POOL_RECOVERED` /
  `POOL_RECOVERY_PARTIAL` / `POOL_RECOVERY_FAILED`) rather than just a packet count. Needs no ARP
  sweep, server discovery, or leasequery — the journal already carries everything. Not gated
  behind `DESTRUCTIVE_MODES`: it only ever releases leases the journal proves this tool took, so
  it adds no capability beyond what `exhaust` already used. Default `--rate` is 50, not the usual
  7 — it runs during an outage the operator is trying to end, and the frames are unicast to one
  server rather than sprayed at the segment.
- Design plan: `EXECUTION-PLAN-release-previous.md`. A broader recovery-command proposal
  (`EXECUTION-PLAN-release-all.md`) considered and narrowed away from leasequery, blind sweeps,
  and ARP-derived targets in favor of the journal-only approach above — see that doc for why.

## 2.1.0 (unreleased) — release-first exhaust, windowed pacing, halt-on-control, headroom

Prompted by a live run on a real `/22` that stalled at 56/~1000 addresses. The capture showed
the server re-offering the same address to two of our MACs, then NAKing, then going silent —
**pending-offer table saturation from flooding faster than handshakes could complete, not real
pool exhaustion.**

- **Release phase runs first, inside `exhaust`.** Before the sender starts, DHCPRELEASE is sent
  for every ARP-discovered neighbor (`release_neighbors`, default on; `--no-release` opts out),
  freeing addresses so "take every address in the range" has somewhere to go. Fixed two bugs
  that made release a no-op before this: (1) the server identity was always `0.0.0.0` because
  `_discover_neighbors()` is ARP-only and never learns a DHCP server — it now comes from the
  control transaction; (2) `build_release_v4()` built an L3-only packet despite being sent via
  L2 `sendp()` — it now carries an `Ether` layer, unicast to the server MAC when known. Standalone
  `release` mode got the same server-discovery fix. Re-probes released addresses by ARP and
  raises `NEIGHBOR_LEASES_RELEASED` reporting observed effect, not frames sent.
- **Windowed, adaptive handshake pipeline replaces the open-loop DISCOVER flood.** At most
  `window_initial` (8) DISCOVER/REQUEST transactions in flight; a clean ACK grows the window
  half a slot at a time — two clean ACKs in a row to widen it by one, up to `window_max` (64) —
  and a NAK/timeout/duplicate-offer halves it instantly (and wipes any banked half-slot, so
  ramping back up after a throttle is just as cautious as ramping up cold). Only an ACK counts
  as a held address. `--rate` is **removed from `exhaust`** (the window paces it now) but
  unchanged on `release`/`garp`/`active-scan`.
- **Halt-and-report.** On the first of five signals — a NAK burst, offers going quiet, link
  carrier loss (port-security err-disable), a timeout storm, or the same address offered to two
  of our MACs — sending stops immediately, but leases already held are **kept** and both
  post-run controls still run so the report is complete. New `HALTED` state, `ControlDetected`
  event.
- **Headroom.** A best-effort pool-size estimate (from `--scope`, else the first OFFER's subnet;
  never fabricated — shows `—` when unknown) surfaces as a live dashboard number:
  `headroom = pool_size - leases_held - observed_in_use`, floored at 0, always labelled with its
  source. New `POOL_HEADROOM_LOW` finding when the pre-test baseline is already ≥80% utilized.
- **The control transaction is no longer optional.** Removed `--no-control` (CLI) and the
  Control checkbox (web); `SessionConfig.control` is gone. `exhaust` always runs the legitimate
  pre/post DHCP cycle from the real NIC MAC — a run without it can't produce a trustworthy
  verdict, so there's no longer a way to skip it.
- **Default `--rate` lowered from 10 to 7 pps** (`release`/`garp`/`active-scan`; exhaust has no
  `--rate` of its own — see above).
- **Verdict rename.** `DHCP_STARVATION_POSSIBLE`, `DHCP_STARVATION_BLOCKED`,
  `POOL_EXHAUSTED_CONFIRMED`, and `POOL_NOT_EXHAUSTED` are retired in favor of two:
  `DHCP_STARVATION_ATTAINED` (FAIL — acks>0 and the post-run new-MAC control was denied and its
  own baseline succeeded) and `DHCP_STARVATION_NOT_ATTAINED` (PASS — everything else), with a
  `reason` (`control_fired`, `pool_headroom_remaining`, `blocked_at_baseline`, or
  `inconclusive_baseline`). Because halt-on-control now stops the run on the first defensive
  signal, `ATTAINED` is rare by construction on a defended network — `NOT_ATTAINED +
  control_fired`, naming the control and the lease count it fired at, is the expected result.

## 2.0.0 (unreleased) — garp actually works; UI trimmed

- **ARP-GARP DoS rewritten.** It previously sent *one* broadcast gratuitous-ARP request per
  victim, claiming the victim's own address — which mostly trips duplicate-address detection,
  and is undone within seconds when the host re-announces. Now, per target per round:
  a GARP request **and** reply (stacks differ in which they honour), plus a **unicast ARP reply
  putting the default gateway at an unused MAC**, which is the frame that actually cuts the
  victim's route. Rounds repeat every `garp_interval` (2s) until stopped.
  The forged MAC is always bogus — never our own — so traffic is blackholed, not intercepted.
- `netutils.default_gateway()` added; the gateway is excluded from the target list.
- garp now runs an ARP observer and records which targets defend their address, yielding
  `ARP_FORGERIES_REACHED_TARGETS` (delivery confirmed, so no DAI on this port) or
  `ARP_FORGERIES_UNANSWERED` (INCONCLUSIVE — filtered or silently accepted look identical from
  one vantage point; both findings say how to tell them apart).
- Much more garp debug output: target list with vendor, every frame with op/claimed IP/forged
  MAC/real owner, per-round summaries, and defenders as they appear.
- Removed from the UI: the **Restore** button and the **Threads** input. Removed from the CLI:
  `--threads` (legacy `-t` is now a no-op). There is one sender thread; `--rate` is the pacing
  control, and extra threads only contended for the same token bucket.
  Lease cleanup is still available via `dhcpig restore <iface>` and `POST /api/session/restore`.
- Findings card scrolls; `SSE:` status pinned to the top-right; dashboard column narrowed 20%
  and the findings/tables column widened by the same amount.

## 2.0.0 (unreleased) — destructive-mode gate removed

**Behaviour change.** At the maintainer's request the authorization workflow is gone from both
front ends. `release` and `garp` now run like any other mode.

- Removed: the `⚠ DESTRUCTIVE MODE` banner, the `I am authorized` checkbox, the typed
  confirmation modal, the CLI's `--i-am-authorized` / `--yes` flags and interactive prompt,
  `core.safety.authorize()`, the `Unauthorized` exception, the web's 403 re-validation, the
  `authorized` config field and the `authorization_attested` report key. Exit code 4 retired.
- `--scope` is now **optional** for `release`/`garp`; with none supplied they target the
  interface's own network. Supplying a scope still bounds targets via `ScopeGuard` at the
  `_send()` chokepoint. `active-scan` still requires an explicit scope.
- Remaining bounds on a run: `--rate`, `--dry-run`, `--scope` when given, and `restore`.
- Default `--rate` lowered from 20 to 10 pps.

## 2.0.0 (unreleased) — baseline inventory & a control that can actually detect exhaustion

- **Fixed a false verdict.** The post-run control used this machine's real NIC MAC, which the
  server usually already has a binding for — so it was really testing *renewal* and could
  succeed against a completely drained pool, wrongly reporting `POOL_NOT_EXHAUSTED`. Controls
  now run two legs at both `pre` and `post`: `self` (real MAC — proves DHCP is reachable) and
  **`new` (a never-seen MAC that must come off the free list)**. Exhaustion is judged solely on
  the `new` leg, and only when its own baseline succeeded.
- New finding `SERVER_STOPPED_SERVING_TEST_CLIENTS`: offers ceased but a brand-new client is
  still served — i.e. DHCP rate-limiting / offer-table saturation / anti-starvation protection,
  not pool exhaustion. Carries the NAK count and rate as evidence.
- New finding `NEW_CLIENT_BLOCKED_AT_BASELINE` (PASS): our own MAC is served but an unknown MAC
  is refused before testing even starts — the signature of DHCP snooping or port security.
- **Pre-run ARP sweep** (`arp_sweep`, on by default, `--no-arp-scan` / UI checkbox) inventories
  which hosts were on the segment *before* exhausting; results populate the Neighbors tab.
  Falls back to the interface's own network when no scope is given. Destructive modes are
  unaffected — their discovery stays pinned to `--scope`.
- The exhaust prelude (ARP sweep + controls) now runs off-thread, so `POST /api/session/start`
  returns immediately instead of blocking for the duration.
- Default `--rate` lowered from 50 to 20 pps.

## 2.0.0 (unreleased) — run visibility & MAC vendor identification

- **Periodic status line, every 5s at normal verbosity.** The `StatusTick` event existed since
  V1.0 but nothing ever emitted it; the engine now runs a heartbeat thread reporting running
  totals *with per-window deltas and rates*, so a stalled or draining run is obvious at a
  glance. Zero-valued counters are omitted, so a scan run doesn't carry empty lease columns.
  `--status-interval SEC` (0 disables).

      [##] t=220s  RUNNING  leases 1022 (+0 in 5s, 0.0/s)  discovers 4300 (+250 in 5s, 50.0/s)
           offers 1030 (+0 in 5s)  servers 1  last offer 6s ago

- **MAC vendor identification** for hosts with no usable DHCP fingerprint. ARP-only neighbours
  previously showed an empty OS/Device column; they now show the hardware vendor at a
  deliberately low confidence (15) that can never be mistaken for an OS match. Two offline
  sources: scapy's bundled Wireshark/IEEE `manuf` database (~50k OUIs — already a dependency,
  so nothing extra to ship) plus a vendored `mac-vendor.txt` from arp-scan covering prefixes
  the IEEE registry omits (QEMU, Bochs, HSRP, VRRP/CARP, WLBS), matched longest-prefix-first.
  Unresolved MACs are labelled as locally administered (randomised/spoofed) rather than blank.

## 2.0.0 (unreleased) — run completion & lease retention

- **Runs now finalize themselves.** Previously, when the pool drained the sender threads exited
  on `EXHAUSTED` but nothing called `stop()` — in the web UI the session sat idle with no
  post-control and no verdict until the operator pressed Stop. A terminal condition now spawns
  a background finisher that runs the post-control, emits findings and ends the session.
- New `OffersCeased` event: once offers have been quiet for 2s the UI reports the countdown to
  the exhaustion deadline, instead of appearing to hang.
- **Removed `--max-leases` / `max_leases`** entirely (CLI, config, web UI, `as-cli`). With no
  self-imposed cap, `POOL EXHAUSTED` can only ever mean the server stopped serving; the
  now-unreachable `LimitReached` event and `LIMIT_REACHED` state were removed with it.
  `--rate` remains the bound on run impact.
- **Auto-restore is now off by default** (`restore_on_exit=False`; the web UI's "disable
  auto-restore" box ships checked). Leases are retained so the exhausted state can be verified;
  clean up with `dhcpig restore <iface>` / the Restore button, or opt back in with the new
  `--restore-on-exit`. `--no-restore` is kept as a hidden legacy no-op.

## 2.0.0 (unreleased) — confidence work

Changes aimed at making results trustworthy enough to put in a hardening report.

- **Control transaction.** `exhaust` now runs a legitimate DHCP cycle from the real NIC MAC
  before and after the test (labelled `CONTROL[pre]` / `CONTROL[post]`; the lease is released
  immediately). A failed baseline turns a null result into INCONCLUSIVE instead of a false PASS;
  a failed post-run control while leases are held is what confirms real pool exhaustion.
  `--no-control` opts out.
- **`POOL EXHAUSTED` no longer fires on your own `--max-leases` cap** — that is now
  `LIMIT REACHED` (`LimitReached` event, `LIMIT_REACHED` state). Genuine exhaustion requires
  offers to have flowed and then stopped, and is only reported as *confirmed* once the
  post-run control transaction is also denied.
- **Findings.** Runs now produce auditable verdicts (id, PASS/FAIL/INFO/INCONCLUSIVE, severity,
  evidence, recommendation): `CONTROL_BASELINE_FAILED`, `DHCP_STARVATION_POSSIBLE`,
  `DHCP_STARVATION_BLOCKED`, `POOL_EXHAUSTED_CONFIRMED`, `POOL_NOT_EXHAUSTED`,
  `DHCP_NAK_OBSERVED`, `MULTIPLE_DHCP_SERVERS`. Surfaced in the CLI summary, a new web
  Findings tab, and the JSON/HTML reports.
- **DHCPNAK is no longer discarded.** `packets.is_nak()` added and the engine emits
  `NakReceived` (the renderer already handled the event, but nothing ever produced it).
- **`--rate` is now authoritative.** The exhaust sender had a fixed 0.4s per-packet sleep on top
  of the rate limiter, capping it at ~2.5 pps per thread regardless of `--rate`. Removed.
- `stop()` is idempotent; status now reports naks, control results and finding count.

## 2.0.0 (unreleased) — post-V2.0 polish

- Fingerprint database swapped from the bundled FingerBank `.conf` to a static
  `combined_dhcp_os_lookup.json` (PacketFence + Huginn-Muninn DHCP option-55 fingerprints,
  merged by `data/fingerprint-merge.py`; 594 fingerprints, exact/order-sensitive match,
  ambiguous multi-candidate matches reported at lower confidence). Still fully offline, no
  API, no key. Attribution moved to `data/DATA_ATTRIBUTION.md`.
- Removed the unused `--fingerbank-api-key` stub (CLI flags, `SessionConfig` field, report
  redaction) — it was never wired to an actual online lookup.
- `scan`/`active-scan`: neighbors discovered via ARP are now correlated with any DHCP
  fingerprint seen for the same MAC (in either order), so the web UI's Neighbors tab and
  JSON/CSV/HTML reports show OS/Device instead of a blank column. Report/session neighbors are
  deduped by MAC.
- Web UI: Dry-run checkbox now defaults unchecked (live sends by default, matching the CLI's
  existing `--dry-run`-is-opt-in default); Neighbors tab moved ahead of Servers and is now the
  default-active tab.

## 2.0.0 (unreleased) — V1.1 / V2.0

- Web UI (`dhcpig-web`): stdlib `http.server` + Server-Sent Events, vanilla-JS SPA (no build
  step, no framework). Loopback-bound, bearer-token-gated, same-origin, single-session guard.
- All four modes in the browser (Exhaust / Passive Scan / DHCP Release / ARP-GARP DoS) with a
  live dashboard, canvas sparkline, servers/neighbors/leases tables, and colored event log.
- Destructive modes gated by an `I am authorized` checkbox + scope + typed-confirmation modal,
  re-validated server-side (`core.safety`).
- Report export in JSON / CSV / HTML; "Copy as CLI"; save/load profile.
- Packaging: Debian/Kali `.deb` control files + `dhcpig-web.desktop` (Sniffing/Spoofing);
  PyPI-ready.
- Privileged integration test (veth pair + fake DHCP server) proving grant-then-release.
- Rich `Debug` events from the engine (config, option dumps, xids, MACs, sniffer/restore) with
  a CLI `[DBG]` tier (`-v3`) and a web verbosity dropdown (0–3) that filters the live log.
- New `active-scan` mode: ARP sweep of the scope + a DHCP INFORM to find/fingerprint servers.
  Non-destructive; requires `--scope`, auto-filled from the interface's own network. `/api/ifaces`
  now returns each interface's network CIDR for the UI to auto-fill scope.
- Ethernet source MAC now defaults to a distinct per-client MAC (`--no-spoof-eth-src` for Wi-Fi).
- Fingerprinting now ships the static **FingerBank** DHCP database
  (`dhcp_fingerprints.conf`, ODbL, no API) parsed by `core.fingerprint_db`, merged with the
  builtin fallback — direct option-55/option-60 → OS/device mapping, offline. Attribution in
  `data/FINGERBANK_ATTRIBUTION.md`.

## 2.0.0 (unreleased) — V1.0

Refactor of the single-file `pig.py` into an installable, tested `dhcpig` package.

- New `dhcpig` CLI: `exhaust`, `scan`, `release`, `garp`, `restore`, `ifaces`, `report`.
- UI-free `dhcpig.core` engine (models, packets, fingerprint, sniffer, events, safety,
  engine, reporting) that both the CLI and the upcoming web UI consume.
- Safety guardrails: authorization gate, scope guard, rate limiter, dry-run, auto-restore.
- Passive host fingerprinting (option-55 order + option-60 vendor class + OUI), offline-first.
- JSON session reports.
- Carried upstream fixes: PR #27 (server-id = option 54 else siaddr) and PR #28
  (client MAC = `chaddr[:6]`, REQUEST includes option 61 client-id).
- Legacy `pig.py <iface>` still works via a deprecation shim.

## 1.6 (legacy) — 2024-01
- Python 3 & scapy 2.5 support.
