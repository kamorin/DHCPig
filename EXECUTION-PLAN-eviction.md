# Execution Plan — targeted re-acquisition, client eviction, release rework (2.3)

Whitehat scope: this is a network-hardening validation tool, run by security engineers on
networks they own or are explicitly authorized to test. Everything below is L2/L3 DHCP/ARP
denial and measurement. **Nothing here enables host compromise, lateral movement, or traffic
interception** — see "Boundaries" at the end, which is load-bearing, not boilerplate.

## Objective

Close the gap between "we hold every address" and "hosts on this segment actually lost service",
and make `release` a complete workflow rather than a one-shot packet blast.

| Goal | Status today | This plan |
|------|--------------|-----------|
| 3. Exhaust all addresses | Works (§5c windowed sender) | Unchanged |
| 4. All DISCOVERs fail | Happens, but is **unobservable** | Observe + report foreign DISCOVERs and whether they were answered |
| 2. Block renewal of the previous IP | Not implemented | Targeted re-acquisition — we take the freed address, so the victim's renewal gets NAKed by the real server |
| 7. Force clients off their address | Not implemented | ARP conflict → DHCPDECLINE → INIT |

Still **not** in this plan, deferred by decision: lease hold/renew at T1, DHCPFORCERENEW.

**Prerequisite, implemented separately (not covered here):** dry-run becomes the default for
every mode, with `--live` as the flag that puts frames on the wire, and the web UI's dry-run
checkbox moves to sit immediately right of the mode dropdown. Every phase below assumes that is
already in place — it is what makes eviction safe to build incrementally, and what the "safety
comes from dry-run being default-on" decision below rests on.

Note the split: that prerequisite covers the **default and the flag**. What dry-run actually
*does* — run every non-destructive phase for real and suppress only the mutating sends — is
phase 0a below, and is in scope here.

One consequence of that change worth carrying into it, since it is easy to miss: there are 27
`SessionConfig(` constructions under `tests/`, **22 of which do not set `dry_run` explicitly**
and will silently flip to dry-run. Tests asserting on captured frames fail loudly; tests
asserting *absence* (`assert sent == []`) pass vacuously and keep passing while testing nothing.
`tests/integration/test_exhaust_live.py` is the worst case — the only test that sends real
packets, deselected by default, so nobody sees it go hollow.

## Decisions taken

- **Targeted re-acquisition is a shared phase**, used by both `exhaust` and `release`. It is
  what makes eviction stick — and it is also the *sound* measurement of whether the server
  honoured our RELEASE (see the `_reprobe_released` correction in phase 3).
- Eviction is **part of the run**, not a separate mode. Safety comes from dry-run being
  default-on, not from an opt-in flag. `--no-evict` opts out, matching `--no-release` /
  `--no-journal` / `--no-arp-scan`.
- Eviction does **not** require `--scope`; it falls back to the interface's own network, as
  `release` does today.
- `GARP_DOS` is removed as a mode. Its frame-building machinery is rewritten into eviction.
- `release` gains the full phase chain minus the windowed sender.
- Passive `scan` is **removed from the web dropdown** but stays in the CLI and the API schema.

## The mechanism, precisely (RFC 5227 §2.4)

A host receiving an ARP frame whose *sender protocol address* equals its own IP and whose
*sender hardware address* is not its own has an address conflict. RFC 5227 allows three
behaviours; the second is the exploitable one:

1. Immediately cease using the address and reconfigure.
2. **Defend once.** If the host has not sent a defending ARP Announcement within the last
   `DEFEND_INTERVAL` (**10 seconds**), it records the time and sends a single announcement.
   **If a further conflict arrives within `DEFEND_INTERVAL` of having defended, it MUST cease
   using the address.**
3. Never defend (always cease).

So "getting Windows out of the defense phase" is precisely case 2: **at least two conflict
bursts per target, spaced under 10 seconds apart.** Round 1 provokes the defense; round 2,
inside the defend window, forces the cease. For a DHCP-assigned address, ceasing means
DHCPDECLINE → restart at INIT → DISCOVER.

Two constraints from the same RFC bound the parameters:

- `DEFEND_INTERVAL = 10s` → **`evict_interval` must be < 10s.** Default **3.0s**.
- `MAX_CONFLICTS = 10`, `RATE_LIMIT_INTERVAL = 60s` → after 10 conflicts a host rate-limits its
  own address-acquisition attempts to one per 60 seconds. Past ~5 rounds we slow down the very
  DISCOVERs we are trying to observe. Default **`evict_rounds = 4`** (2 is the RFC minimum to
  force a cease; 4 gives margin for a dropped frame without tripping the rate limit).

### What the victim does next differs by mode — and this is the point

| | `exhaust` | `release` |
|---|---|---|
| Pool state when eviction runs | drained | **not drained** |
| Victim's post-DECLINE DISCOVER | unanswered | answered in <1s |
| Terminal outcome | **APIPA** (169.254/16) | **new address** |
| What it proves | segment-wide outage | every binding on the segment can be churned on demand by any host |

Both are legitimate results. The finding text must state which was expected, or `release` runs
will look like eviction "failed" when they did exactly what they should.

## Phase 0 — sniffer, parsers, and dry-run semantics

### 0a. Dry-run becomes "everything non-destructive", not "do nothing"

Today `_run_exhaust()` branches all-or-nothing: under dry-run it **skips the sniffer and the
entire prelude** and jumps straight to `_start_senders()`. So a dry run performs no ARP sweep,
no control transaction, and no release phase — it only shows you the shape of a DISCOVER. Once
dry-run is the default, that is what a bare `dhcpig exhaust eth0` would do, which is close to
useless.

New model: **dry-run runs every read-only and self-cleaning phase for real, and suppresses only
the mutating sends.**

| Phase | Traffic | Dry-run |
|---|---|---|
| ARP sweep | ARP requests | **runs** — pure discovery, any host does this |
| Control transaction | DISCOVER/REQUEST + RELEASE of **our own** lease | **runs** — exactly what a legitimate client joining the segment does, and it self-cleans |
| Release phase | RELEASE for **other hosts'** leases | suppressed; logs the target list |
| Targeted re-acquisition | DISCOVER/REQUEST holding victims' addresses | suppressed; logs intended targets |
| Windowed sender | DISCOVER/REQUEST consuming the pool | suppressed; logs intended sends |
| Eviction | forged ARP conflict frames | suppressed; logs targets and round count |

This makes a dry run a genuine reconnaissance pass: who is on the segment, is DHCP reachable,
which server, what the pool estimate and headroom are, and a precise inventory of exactly what
*would* be released, taken and evicted — with nothing changed.

**Mechanism.** `_send()` currently suppresses *all* sends under `dry_run`. Add a parameter:

```python
def _send(self, pkt, target_ip: str | None = None, probe: bool = False) -> bool:
```

`probe=True` bypasses the dry-run suppression, and marks traffic that a legitimate client on
this segment would send anyway and that leaves no lasting change. **Exactly two call sites get
it:** `_discover_neighbors()`'s ARP requests, and `_control_transaction()`'s own
DISCOVER/REQUEST/RELEASE cycle (the RELEASE included — it frees *our* lease, and skipping it
would make a dry run leak an address).

The default is `probe=False`, so anything added later is suppressed under dry-run unless someone
deliberately opts out. Fail-safe direction. Scope and rate limiting still apply to probes;
`probe` only governs the dry-run gate.

`_run_exhaust()` then loses its branch entirely: always start the sniffer, always run the
prelude. Delete the `"dry-run: sniffer disabled"` debug line.

**This changes the root requirement.** A dry run now opens a capture socket and sends ARP and
DHCP, so it **needs root** and is no longer fully offline. That property was load-bearing for
the web/CLI tests (AGENT_HANDOFF §8, "Dry-run is fully offline … this is what makes web/CLI
testable without root"). Preserve it with a separate `SessionConfig.offline: bool = False` used
only by tests and the no-root web preview, which keeps today's skip-everything behaviour. Do not
overload `dry_run` for both meanings — they are now genuinely different things.

**Findings under dry-run.** `acks` will be 0 because the sender never ran, so
`_finalize_findings()` would emit `DHCP_STARVATION_NOT_ATTAINED` — a starvation verdict for a
run that never tried to starve anything. Same trap as release mode (phase 5). Under `dry_run`:

- Suppress `DHCP_STARVATION_ATTAINED` / `_NOT_ATTAINED` entirely.
- Suppress `NEIGHBOR_LEASES_RELEASED` — nothing was released.
- **Keep `POOL_HEADROOM_LOW`** — it is derived from the pre-test ARP baseline, which genuinely ran.
- Add `DRY_RUN_SUMMARY` (**INFO**): hosts seen, server identity, pool estimate + headroom, and
  counts of what would have been released / re-acquired / evicted.

Tests: `probe=True` sends under dry-run, `probe=False` does not; ARP sweep and control run under
dry-run while release/re-acquisition/eviction do not; no starvation finding is emitted under
dry-run; `offline=True` restores skip-everything.

### 0b. Sniffer and parser prerequisites

**This is why the other features work at all.** `core/sniffer.py`'s V4 BPF filter is:

```
arp or icmp or (udp and src port 67 and dst port 68)
```

That is **server→client only**. Foreign DISCOVERs and DHCPDECLINEs are both client→server
(dst port 67) and are invisible to the engine today. Without this change, phases 2 and 4 log
nothing and silently appear to work.

- `core/sniffer.py`: widen `_BPF[IPVersion.V4]` to `arp or icmp or (udp and (port 67 or port 68))`.
  ARP is already present, so eviction's defense-announcement and APIPA observation need no
  filter change.
- `core/packets.py`: add `"decline"` (and `"inform"`) to `message_type()`'s name→code map.
  `DECLINE` already exists as a constant; the map never listed it.
- `core/packets.py`: add `is_discover(pkt)` and `is_decline(pkt)` alongside the existing
  `is_offer`/`is_ack`/`is_nak`.
- `core/engine.py` `_on_dhcp()`: the widened filter means we now see **our own** outbound
  DISCOVER/REQUEST echoed back, plus every other client's DHCP traffic. Add a cheap early
  self-filter before any other work — `xid in self._inflight`, the in-flight control
  transaction's xid, or `Ether.src` in a new `self._our_macs: set[str]`. Populate `_our_macs`
  in `_exhaust_sender()` and `_control_transaction()`.

**Cost:** on a busy segment this roughly doubles sniffer volume. The self-filter must be the
first thing `_on_dhcp` does, and must not allocate.

Tests: BPF string asserted directly; `message_type`/`is_decline`/`is_discover` round-trips;
`_on_dhcp` ignores a packet whose xid is in `_inflight`.

## Phase 1 — remove GARP_DOS as a mode

- `core/models.py`: drop `Mode.GARP_DOS`; `DESTRUCTIVE_MODES` becomes `{Mode.RELEASE_NEIGHBORS}`.
  Rename `Timeouts.garp_interval` → `evict_interval`, default `2.0` → `3.0`.
- `core/engine.py`: delete `_run_garp()`, `_garp_worker()`, `_on_garp_arp()`, and the
  `Mode.GARP_DOS` entry in `start()`'s `runners` dict. Delete the
  `ARP_FORGERIES_REACHED_TARGETS` / `ARP_FORGERIES_UNANSWERED` findings from
  `_finalize_findings()`.
- `core/packets.py`: delete `build_arp_poison()`. It exists only to blackhole a victim's
  default route, contributes nothing to eviction, and removing it takes the
  interception-adjacent code path out of the tree entirely. `build_garp()` **stays** — it is
  the conflict frame.
- `cli/main.py`: remove the `garp` subparser, its `_MODE_BY_CMD` entry, and the module
  docstring's subcommand list.
- `web/`: remove `<option value="garp">`; remove `"garp"` from `SCOPE_MODES`, the `labels`
  dict, and `pollStatus()`'s `primary` dict in `app.js`.
- Rename the counter `self.garps` → `self.arp_conflicts` and the event `ev.GarpSent` →
  `ev.ArpConflictSent`. Exactly 8 sites — miss one and a dashboard silently reads zero:
  `engine._counters()` L211, `engine.status()` L321, `cli/main.py` L318 done-line,
  `cli/render.py` L99 (event handler) and L164 (`col("garps", …)`), `web/static/app.js` L264
  (event case), L278 (`col`), L345 (`primary` dict). `core/reporting.py` does **not** reference
  it — it reads the status dict generically, so it needs no change.

Keep the three tracking sets, renamed: `_garp_bogus_macs` → `_evict_bogus_macs`,
`_garp_defenders` → `_evict_defenders`, `_garp_targets` → `_evict_targets`.

**Tests:** 9 references to `Mode.GARP_DOS` / `"garp"` across `tests/unit/test_engine.py`
(5 constructions), `test_control_findings.py`, and `test_cli.py`. These are **not** simple
deletions — `test_engine.py`'s garp cases cover scope-gating, gateway exclusion, and frame
shape, all of which eviction still must satisfy. Port them to `_do_arp_conflict()` in phase 4.
Deleting them outright would silently retire the only tests proving ARP forgeries respect
`ScopeGuard`.

## Phase 2 — observe foreign DISCOVERs

Serves goal 4: makes "all DISCOVERs fail" a *measured* result rather than an inference from our
own lease count.

In `_on_dhcp()`, after the self-filter, add a DISCOVER branch:

- Track `self._foreign_discovers: dict[int, dict]` keyed by xid →
  `{mac, hostname, ts, answered: bool, fingerprint}`.
- Emit `ev.ForeignDiscover(mac, xid, hostname)` on first sight. Reuse
  `fingerprint.extract_signature()` / `resolve()` so the log line names the device — we already
  have the packet, and this feeds `_note_fingerprint()` for free.
- In `_handle_offer()`, if the OFFER's xid matches a tracked foreign discover, set
  `answered=True`.
- Counters `foreign_discovers` / `foreign_discovers_unanswered` into `_counters()` and
  `status()`, so they reach `StatusTick`, the CLI status line, and the web dashboard.
- Rate-limit the log line per MAC (a retrying client sends DISCOVER every few seconds and would
  flood the log): first sighting at verbosity 2, subsequent at 3.

Findings in `_finalize_findings()`:

- `FOREIGN_DISCOVERS_UNANSWERED` — **FAIL**, high — when `unanswered > 0`. Evidence: observed
  count, unanswered count, distinct MACs, sample hostnames/fingerprints. This is the most direct
  evidence of client-visible outage the tool can produce: *other people's machines asked for an
  address and got nothing.*
- All observed DISCOVERs answered → **INFO**, recording that third-party DHCP kept working.
- None observed → raise nothing. Silence is not evidence, and a segment where every host is
  happily bound is expected to be quiet.

## Phase 3 — targeted re-acquisition (shared by exhaust and release)

**This is the phase that makes a RELEASE mean something.** Today, after `_release_phase()` frees
a neighbor's address, the address returns to the pool and the general flood takes *whatever the
server offers*. Nothing guarantees we take the freed one. If we don't, the victim renews at T1,
the server sees the address unbound, re-ACKs it, and the victim never notices anything happened.

### Packet change — smaller than expected

Only `build_discover_v4()` changes: add an optional `requested_addr: str | None = None`, emitting
DHCP option 50 when set. RFC 2131 Table 5 permits option 50 in a DHCPDISCOVER, and servers
generally honour it when the address is free.

**`build_request_v4()` needs no change.** If the server honours the requested IP, the OFFER
carries it in `yiaddr` and the existing REQUEST path is already correct. We verify by comparing
`offer.yiaddr` against what we asked for.

### Implementation — reuse the existing pipeline

Do **not** build a parallel sender. `_reacquire_phase(freed: list[tuple[str, str]])` pushes one
DISCOVER per freed address, each carrying option 50 and a fresh random MAC, into the **existing
`_inflight` windowed pipeline**. `_handle_offer()` → `_handle_ack()` complete them unchanged, so
the resulting leases land in `Cleanup` and the lease journal exactly like any other lease. New
state: `self._reacquire_targets: dict[int, str]` mapping xid → requested IP, so outcomes can be
attributed.

Wait for the pipeline to drain (bounded by `timeouts.control` per address, with an overall cap),
then classify each target:

| Outcome | Meaning |
|---------|---------|
| `granted` | we hold the victim's old address — **their renewal will now be NAKed by the real server** |
| `offered_different` | server ignored option 50 and offered something else; address may still be bound to the victim |
| `naked` | server refused — binding likely still the victim's, i.e. RELEASE was not honoured |
| `no_response` | no OFFER at all |

### Correcting `NEIGHBOR_LEASES_RELEASED` — an existing unsound finding

`_reprobe_released()` re-ARPs the released addresses and counts how many *stopped answering*.
That is not a valid test: a host whose lease was released server-side keeps using its address
until T1 and has no idea anything happened, so the count reads 0 even on a completely successful
release. The finding then reports *"the server appears to ignore unauthenticated RELEASE (the
desired behavior)"* — telling the operator they passed when they did not.

**Replace the evidence base with the re-acquisition result**, which is a direct test: if the
server hands us the victim's address, it honoured the RELEASE. `granted` count becomes the
evidence; keep the ARP reprobe only as supplementary colour, explicitly labelled as
"host still using the address (expected until its T1)".

Sequencing: `_release_phase()` now returns the released `(mac, ip)` list, `_reacquire_phase()`
consumes it, and the finding is raised **after** re-acquisition rather than inside
`_release_phase()`.

## Phase 4 — ARP-conflict eviction

New `_evict_phase()`. In `exhaust` it runs in `stop()` **between** the post-control transactions
and `_finalize_findings()` — the post-controls need the pool still drained, the findings need
the eviction outcomes. In `release` it runs inline in the worker (phase 5).

Guarded by `cfg.evict` (default `True`). Under dry-run the phase still executes and logs its
target list and round count, but sends nothing: its frames go through `_send()` with the default
`probe=False`, so the chokepoint suppresses them (phase 0a). Do not add a second dry-run check
here.

### Target selection

Reuse the ARP inventory (`self._neighbors_by_mac`). Exclude, exactly as `_release_phase()` does:

- the default gateway (`_release_gateway()`),
- the DHCP server (`control_pre.server_id`),
- **any address we do not hold from phase 3.** Conflicting with an address still bound to the
  victim just makes them defend and re-ARP; conflicting with one *we* now hold is what forces
  the DECLINE. Prefer `granted` targets; log the others as skipped-with-reason.

Scope-gated through `_send(pkt, target_ip=...)`; scope defaults to the interface network.

### `_do_arp_conflict(targets) -> int` (rewrite of `_do_garp`)

Per target, per round, **two** frames — the gateway-blackhole third frame is gone with
`build_arp_poison`:

1. `build_garp(n.ip, bogus, op=ARP_REQUEST)` — announcement form
2. `build_garp(n.ip, bogus, op=ARP_REPLY)` — unsolicited-reply form

Both forms because stacks differ in which they honour (`build_garp`'s existing docstring covers
this and stays accurate). `bogus` is a fresh `random_mac()` per target per round, recorded in
`_evict_bogus_macs` so the observer can distinguish our forgeries from real hosts.

**The claimed MAC is always bogus and never ours.** A bogus MAC blackholes; our MAC would
intercept. Keep that assertion in the docstring.

### `_evict_worker()`

```
for round in 1..cfg.evict_rounds:          # default 4
    _do_arp_conflict(targets)
    wait cfg.timeouts.evict_interval        # default 3.0s, MUST stay < 10s DEFEND_INTERVAL
sleep cfg.evict_settle                      # default 8.0s — let DECLINE/DISCOVER/APIPA land
_measure_eviction(targets)
```

Validate `evict_interval < 10.0` and `evict_rounds >= 2` at config build, with a `ConfigError`
naming RFC 5227 §2.4 — correctness requirements, not taste.

### Measurement — the per-host outcome ladder

Observed passively via the already-running sniffer. Highest rung reached wins:

| Rung | Signal | Meaning |
|------|--------|---------|
| `no_reaction` | nothing | frame may not have been delivered, or stack ignores ACD |
| `defended` | ARP announcement from victim's real MAC for its own IP | our frame arrived; host is in RFC 5227 case 2 |
| `declined` | DHCPDECLINE from the victim's MAC | **host gave up the address** — gold-standard proof |
| `rediscovered` | DISCOVER from victim's MAC after the conflict | host restarted at INIT |
| `discover_unanswered` | that DISCOVER got no OFFER within `timeouts.control` (5.0s) | goal 4 confirmed for this host |
| `apipa` | ARP from victim MAC with a `169.254.0.0/16` sender address | **full eviction** |

**The top two rungs are `exhaust`-only.** In `release` the pool is not drained, so a healthy
result tops out at `rediscovered` and the client immediately gets a new address. Record the mode
alongside the ladder so the finding can say which terminal rung was *expected*.

`_on_dhcp` handles `declined` / `rediscovered` / `discover_unanswered` (phase 2's tracking does
most of it). A new ARP branch handles `defended` and `apipa` — `defended` is the existing
`_on_garp_arp` logic relocated; `apipa` is a new check on `ARP.psrc`.

Emit `ev.ClientEvicted(ip, mac, outcome)` per target as each rung is reached.

### Findings

- `CLIENTS_EVICTED_FROM_ADDRESSES` — **FAIL**, high — any target reached `declined` or beyond.
  Evidence: per-outcome counts, target list per rung, rounds sent, mode. Recommendation: enable
  Dynamic ARP Inspection / port security; any host on this segment can force any other host off
  its address using only broadcast ARP.
- `CLIENTS_DEFENDED_ADDRESSES` — **INCONCLUSIVE**, medium — targets reached `defended` but no
  further. Our frames arrived (so DAI is not filtering) but the stacks held their ground.
- `ARP_CONFLICTS_UNANSWERED` — **INCONCLUSIVE**, medium — nothing reacted. Genuinely ambiguous:
  DAI dropping our frames upstream, or every host ignoring ACD. Say so rather than claiming a
  pass.

A **PASS** verdict is deliberately not available here. "Nobody reacted" cannot be distinguished
from "the frames never arrived" from this vantage point. Don't invent one.

## Phase 5 — restructure `release` mode

`_release_worker()` today is: discover neighbors → control/self → `_do_release()` → stop. It
sends RELEASEs and never checks whether they achieved anything.

New chain — the exhaust chain minus the windowed sender:

```
1. ARP inventory            _baseline_arp_scan()      (reused, currently exhaust-only)
2. control pre / self       _control_transaction()    (already present — learns server identity)
3. release                  _release_phase()          (reused; returns freed list)
4. targeted re-acquisition  _reacquire_phase()        (phase 3)
5. eviction                 _evict_phase()            (phase 4)
6. findings
```

Refactor `_exhaust_prelude()` so steps 1–4 are a shared `_common_prelude()` both modes call,
rather than copy-pasting. `exhaust` continues into `_start_senders()`; `release` continues into
eviction and finishes.

**Do not let release trigger the exhaustion verdict.** `_finalize_findings()` reads
`self.control_pre`/`control_post` to derive `DHCP_STARVATION_ATTAINED` / `_NOT_ATTAINED`. If
`release` populates those, it will emit a starvation verdict for a run that never tried to
starve anything. Follow the §5e `release-previous` precedent exactly: store release-mode control
outcomes in **separate attributes** (`self._rel_pre_control`) and make `_finalize_findings()` a
no-op for `Mode.RELEASE_NEIGHBORS`, raising only the release/re-acquisition/eviction findings.

Release mode does **not** run a `client="new"` control leg — that is the exhaustion baseline and
is meaningless here.

`--rate` still applies (release has no window of its own). `_RUN_ONCE_MODES` already covers
`RELEASE_NEIGHBORS` via `DESTRUCTIVE_MODES`, and the mode remains destructive — more so than
before.

## Phase 6 — web UI mode labels

`<option>` **labels** change; the `value` attributes stay as the existing mode strings, so
`web/schemas.py` and the API are untouched.

| value | new label |
|-------|-----------|
| `exhaust` | DHCP Exhaustion |
| `release` | DHCP Release Active Clients |
| `release-previous` | Reset / Recover DHCP Records |
| `active-scan` | Find Neighbors |
| `scan` | *removed from the dropdown* |

Passive `scan` remains a valid CLI subcommand and a valid API `mode` value — it simply is not
offered in the UI. `config_from_payload()` must keep accepting it.

Also update in `app.js`: the `labels` dict, `SCOPE_MODES` (drop `garp`; `active-scan`,
`release`, `release-previous` stay), and `pollStatus()`'s `primary` dict. Confirm the default
selected option is `exhaust`, and that `onModeChange()` still shows `#destcfg` for
`active-scan` — which requires `--scope` and is now the only discovery mode in the UI.

## Phase 7 — slow the window ramp to avoid provoking NAKs

Independent of every other phase; can land at any point.

`_grow_window()` currently hardcodes `+= 0.5`, so two clean ACKs widen the window by one slot.
Change the increment to **0.01** — one hundred clean ACKs per slot. Lift the literal into a
config field rather than swapping one magic number for another:

- `core/models.py`: new `SessionConfig.window_growth_per_ack: float = 0.01`.
- `core/engine.py` `_grow_window()`: use `self.cfg.window_growth_per_ack` in place of `0.5`.
  **Rewrite the docstring** — "Grow at half the naive rate … it takes two clean ACKs" becomes
  false the moment this lands, and a stale docstring on the pacing logic is exactly what sends
  the next reader down the wrong path.

`_shrink_window()` is unchanged: still halves on NAK, timeout, or duplicate offer, still wipes
the accumulator.

### What this actually does to a run — worth understanding before committing to 0.01

| | before (0.5) | after (0.01) |
|---|---|---|
| Clean ACKs per +1 slot | 2 | **100** |
| ACKs to ramp 8 → 64 (`window_max`) | 112 | **5,600** |
| Window after draining a /22 (~1000 leases, no errors) | 64 (capped early) | **~18** |

So on any realistic pool the window now stays close to `window_initial` (8) for the whole run,
and `window_max = 64` becomes effectively unreachable. That is the intended effect — a small
steady window is what keeps the server's pending-offer table from saturating, which is what
produced the NAK-then-silence stall this pacing logic exists to prevent.

**The consequence to accept deliberately: the ramp becomes a ratchet.** Growth is now 5,000×
slower than before while shrink is unchanged at 50%. A single timeout takes the window from 18
to 9 and wipes the accumulator, and recovering those 9 slots needs 900 more clean ACKs — which
a normal-length run will not supply. Over a long or noisy run the window trends monotonically
downward toward the floor of 1.

That is survivable (a window of 1 still completes a handshake per round-trip — roughly 20
leases/sec at 50 ms RTT, so a /22 in under a minute) and it is strictly the safe direction to
fail. But it is a real behaviour change, not just a slower ramp, so it should be a conscious
choice rather than a surprise on the first live run. If the collapse turns out to be too
aggressive in practice, the knob to reach for is a gentler `_shrink_window()` — for example
`int(w * 0.75)` instead of `w // 2` — rather than winding the growth rate back up.

Tests: 100 `_grow_window()` calls widen the window by exactly 1; 99 do not; a `_shrink_window()`
mid-sequence wipes the accumulator so the next 99 still do not; `window_growth_per_ack` is
config-driven, not hardcoded.

## Phase 8 — surfaces and docs

- `README.md`: new EVICTION section; rewritten RELEASE section for the new phase chain;
  safety-flag list gains `--no-evict`; remove `garp` from the modes list and quick-start.
  **Document what dry-run now does** — it is a reconnaissance pass (ARP sweep + control
  transactions run for real; everything mutating is logged but not sent), not a no-op, and it
  now needs root. (The `--live` flag and the default flip belong to the separately-implemented
  prerequisite, not this plan.)
- `SECURITY.md`: the biggest change to blast radius since the release phase. State plainly that
  a `--live` run now (a) takes every address and (b) actively knocks bound hosts off addresses
  they already hold. Note the dry-run default as the mitigating control. Note that
  **statically addressed hosts also conflict-detect** and go offline *without* a DHCP path back
   — they need manual intervention. That is a real operational risk and belongs in writing.
  Document that `release` churns every binding on the segment, which is not what its name
  historically implied.
- `AGENT_HANDOFF.md`: new §5f (re-acquisition + eviction); update §5b to describe the rewrite
  rather than the deleted mode; update §5c (release phase now feeds re-acquisition); update §6
  modes list; note the `_BPF` widening in §8; update §9 status and test count.
  **§8's first bullet — "Dry-run is fully offline: the engine skips the sniffer and `sendp` …
  this is what makes web/CLI testable without root" — becomes false under phase 0a** and must
  be rewritten to describe the `probe`/`offline` split. It is stated as a property to preserve,
  so leaving it stale would actively instruct the next reader to undo the change.
  **§5c lines 141–142 specifically** state "growth is half-rate … banks 0.5 per clean ACK; two
  in a row to widen the window by one" — that becomes wrong under phase 7 and must be rewritten
  to the new increment. This is the one doc claim that describes pacing behaviour precisely
  enough to mislead if left stale.
- `CHANGELOG.md`: new `2.3.0 (unreleased)` section.

## Acceptance criteria

- [ ] `_send(probe=True)` sends under dry-run; `probe=False` (the default) does not
- [ ] `probe=True` appears at exactly two call sites: ARP sweep and control transaction
- [ ] Under dry-run the ARP sweep and control transactions genuinely run; release,
      re-acquisition, the windowed sender and eviction do not send
- [ ] `_run_exhaust()` no longer branches on `dry_run`; sniffer and prelude always start
- [ ] No `DHCP_STARVATION_*` or `NEIGHBOR_LEASES_RELEASED` finding under dry-run;
      `POOL_HEADROOM_LOW` still raised; `DRY_RUN_SUMMARY` emitted
- [ ] `SessionConfig.offline=True` restores skip-everything, keeping web/CLI tests root-free
- [ ] BPF filter captures client→server DHCP; unit test asserts the string
- [ ] `is_discover`/`is_decline` parse correctly; `message_type` maps `"decline"`
- [ ] `_on_dhcp` self-filter drops our own echoed DISCOVERs (xid and MAC paths both tested)
- [ ] `Mode.GARP_DOS`, `build_arp_poison`, `_garp_worker`, `_on_garp_arp` and both ARP_FORGERIES
      findings are gone from `src/`
- [ ] The 9 GARP_DOS test references are **ported** to `_do_arp_conflict`, not deleted —
      scope-gating and gateway-exclusion coverage survives
- [ ] `garps` → `arp_conflicts` renamed across all 8 listed surfaces; no surface reads zero
- [ ] Foreign DISCOVERs counted, deduped per MAC, marked answered/unanswered by xid
- [ ] `FOREIGN_DISCOVERS_UNANSWERED` raised only when `unanswered > 0`
- [ ] `build_discover_v4` emits option 50 when `requested_addr` is set; omits it otherwise
- [ ] Re-acquisition reuses the `_inflight` pipeline — no parallel sender
- [ ] Re-acquisition classifies every target as granted/offered_different/naked/no_response
- [ ] `NEIGHBOR_LEASES_RELEASED` evidence is the re-acquisition result, **not** the ARP reprobe;
      the old "stopped == 0 means the server ignored RELEASE" claim is gone
- [ ] Eviction sends ≥2 rounds spaced `< DEFEND_INTERVAL`; config validation rejects
      `evict_interval >= 10` and `evict_rounds < 2`
- [ ] Eviction excludes gateway, DHCP server, and any address not `granted` in phase 3
- [ ] Claimed MAC always bogus — test asserts it never equals the interface MAC
- [ ] Outcome ladder resolves to the highest rung; APIPA detected via `169.254/16` sender
- [ ] Ladder records the mode; `release` runs are not reported as failed eviction for topping
      out at `rediscovered`
- [ ] `window_growth_per_ack` defaults to `0.01` and is config-driven, not hardcoded
- [ ] 100 clean ACKs widen the window by exactly 1; 99 do not; a shrink mid-sequence resets it
- [ ] `_grow_window()`'s docstring no longer claims "half the naive rate / two clean ACKs"
- [ ] `release` runs the full chain; `exhaust` and `release` share `_common_prelude()`
- [ ] `release` does **not** emit `DHCP_STARVATION_*`; its controls live in `_rel_pre_control`
- [ ] `--no-evict` skips the phase in both modes
- [ ] Dry-run runs every phase; only the mutating ones are silent (see the phase-0a criteria)
- [ ] Dropdown shows the 4 new labels; `scan` still accepted by CLI and `config_from_payload()`
- [ ] Full suite green; ruff clean

## Boundaries (do not relax without re-reading)

- The forged MAC in a conflict frame **must** be bogus. Pointing it at our own MAC converts a
  denial-of-service check into traffic interception, out of scope for this tool
  (AGENT_HANDOFF §1, §5b). `build_arp_poison`'s removal narrows this surface; don't re-add it.
- Eviction targets hosts' **own** addresses to trigger ACD. It does not touch the gateway's
  address — that was the deleted blackhole frame's job, and it is not coming back.
- Statically addressed hosts are collateral: they conflict-detect and go offline with no DHCP
  path to recover. We cannot distinguish static from dynamic by ARP alone. Document it; don't
  pretend it away.
- Recovery after a `--live` run is **not optional**. `dhcpig release-previous` frees the
  addresses we took — including everything phase 3 re-acquired, which is why re-acquisition
  must journal like any other lease. Evicted hosts then recover on their own DISCOVER retry.
  Say this in SECURITY.md next to the eviction description, not three sections away.

## Suggested commit order

One commit per phase, tests green at each:

0. *(prerequisite, implemented separately)* dry-run default + `--live` + the 22-site test sweep
1. Phase 0 — sniffer filter + parser helpers + self-filter
2. Phase 1 — GARP_DOS removal + counter/event rename
3. Phase 2 — foreign DISCOVER observation + finding
4. Phase 3 — targeted re-acquisition + `NEIGHBOR_LEASES_RELEASED` correction
5. Phase 4 — eviction + outcome ladder + findings
6. Phase 5 — `release` restructure + `_common_prelude()` extraction
7. Phase 6 — UI labels
8. Phase 7 — window ramp 0.5 → 0.01 *(independent; can land any time)*
9. Phase 8 — docs
