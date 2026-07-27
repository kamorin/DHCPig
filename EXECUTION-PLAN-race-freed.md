# Execution Plan — race to grab addresses the moment they're freed (2.3)

Whitehat scope: this is a network-hardening validation tool, run by security engineers on
networks they own or are explicitly authorized to test. Everything below is passive observation
of DHCP traffic we already receive, plus targeted DISCOVER/REQUEST — the same primitives targeted
re-acquisition (§5f) already uses. **No new capability class**; it changes *when* an existing
capability fires.

## Objective

When an address becomes free mid-run, DHCPig currently only picks it up if the untargeted exhaust
flood happens to land on it. React instead: on observing a signal that a specific address is free
*at the server*, fire a targeted DISCOVER (option 50) for that exact address ahead of the normal
flood.

## Read this before implementing — expected yield is low, and that is the point of the counters

The first draft of this plan chose DHCPRELEASE as the trigger. **That was wrong**, and the
correction reshapes the whole design:

**DHCPRELEASE is unicast to the server** (RFC 2131; `build_release_v4()` sets
`Ether(dst=server_mac or broadcast)` and its docstring says so). On a switched segment it never
reaches our port. The 2.3 BPF widening (§8) made client→server traffic *parseable*, not
*present* — a unicast frame between two other ports is simply not delivered to us. Any trigger
built on foreign RELEASE only works on a SPAN/mirror port or a hub.

More fundamentally: **what matters is whether the *server* considers the address free**, not
whether the client stopped using it. A host can abandon an address entirely while the server
holds its binding until lease expiry. That rules out most of the intuitive signals:

| Event | Observable? | Server frees the binding? |
|---|---|---|
| Client sends RELEASE | **No** — unicast to server | Yes |
| Client sends DECLINE | **Yes** — broadcast | **Usually not** — most servers quarantine a declined address rather than returning it to the pool |
| Server NAKs a foreign REQUEST | **Yes** — broadcast//client-directed | **Likely** — the server is saying that binding is not valid |
| Foreign DISCOVER from a host whose IP we inventoried | **Yes** — broadcast | Not necessarily — the client is at INIT, but the server's binding may persist to lease expiry |
| *We* sent RELEASE for it (release phase) | n/a | Yes — **already handled by `_reacquire_phase()`, §5f** |

So the addresses that (a) genuinely free up at the server mid-run, (b) are observable to us, and
(c) are not already covered by re-acquisition, are a **small set**. The mechanism is cheap — one
DISCOVER per event — so it is worth building, but it should be built **with the won/lost counters
from the start**, so a live run answers "is this worth keeping?" empirically rather than by
argument. Do not tune or expand this feature before that data exists.

## Decisions taken

- **Three triggers, ranked by how strongly they imply a free server-side binding**, all
  broadcast/observable:
  1. **Foreign NAK** (`nak_for_foreign_xid`) — strongest. The server told some other client its
     requested binding is invalid.
  2. **Foreign DECLINE** — the client refused the address. Weaker (quarantine is common), but
     free and observable; keep it enabled and let the counters show the hit rate.
  3. **Foreign DISCOVER from a MAC in `_neighbors_by_mac`** — weakest. The host is at INIT and
     has abandoned the IP our ARP inventory recorded for it. Behind its own flag
     (`race_on_rediscover`, default **False**) because it is the highest-volume and
     lowest-precision signal.
- **Never RELEASE-triggered.** Unicast, invisible. Do not add `packets.is_release()` for this
  purpose (a separate `is_release()` for other reasons is fine, but it must not feed the race
  queue).
- **Separate state from re-acquisition.** Race targets go in `_race_targets`/`_race_outcomes`,
  **never** `_reacquire_targets`. `_evict_phase()` derives `granted_ips` from
  `_reacquire_targets` + `_reacquire_outcomes`; writing race xids there would silently make every
  raced address an eviction target, quietly widening eviction's blast radius past what §5f
  documents ("targets **only** addresses this run actually re-acquired").
- **Bounded overtake, not a window bypass.** Races get up to `race_max_inflight` (default **4**)
  slots *above* `self._window`, tracked separately. A bare bypass would reintroduce the
  pending-offer-table saturation that §5c exists to prevent — `rate_limit_pps` is pinned at
  `EXHAUST_DEFAULT_RATE_PPS=500` in exhaust precisely so the limiter does not bind, so the
  limiter is **not** a meaningful backstop here. When the reserve is full, races stay queued.
- **Exhaust only.** `release` has no concurrent flood for "racing" to mean anything against; its
  sends are already deliberate and targeted (`_reacquire_phase()`).

## Design

### 1. Suppress self-inflicted and already-owned triggers

This is load-bearing and easy to get wrong. Three exclusions, checked before enqueuing any IP:

- **`ip in self._reacquire_targets.values()`** — the release phase freed it and re-acquisition
  already went after it deliberately. Without this, the release phase's own victims (which
  DISCOVER/DECLINE right after being released and evicted — that *is* the `rediscovered` rung,
  §5f) would each queue a duplicate race for an address we already hold.
- **`ip in self._raced_ips`** — dedup across retransmits; added at *enqueue* time, not send time.
- **`ip in (server_id, gateway)`** — same exclusion `_release_phase()`/`_evict_phase()` apply,
  via `_prelude_pre_control()` and `_release_gateway()`.

Note the first exclusion is *not* `_is_own_traffic()`. `_release_bindings()` spoofs the victim's
MAC as both `chaddr` and Ethernet source and uses a fresh `_rand_xid()` never registered in
`_inflight`, so `_is_own_traffic()` structurally **cannot** recognise our own release-phase
frames. Do not rely on it here.

### 2. Trigger plumbing

- `core/engine.py` `_handle_nak()`: it currently treats every NAK as ours — `self.naks += 1`,
  `_shrink_window("nak")`, `_note_nak_for_burst_detection()` — even when `xid` is not in
  `_inflight`. **Split the foreign case out first** (see "Related pre-existing bug" below), then
  enqueue the NAK'd address as a race target when it can be resolved (option 50 from the
  client's REQUEST if we tracked it, else `BOOTP.ciaddr`).
- `_handle_client_decline()`: today it only records a decline when the MAC is a known eviction
  target. Add an `else` path — a decline from any other MAC resolves to an IP via
  `BOOTP.ciaddr`/option 50 and enqueues it.
- `_handle_foreign_discover()`: when `race_on_rediscover` is on, look up
  `self._neighbors_by_mac.get(mac)` and enqueue that neighbor's `ip`.

All three funnel through one method:

```python
def _maybe_race(self, ip: str | None, why: str) -> None:
    """Queue `ip` for a priority targeted DISCOVER. Single entry point for every trigger, so
    the exclusions live in exactly one place."""
```

### 3. Race queue + sender integration

- State: `self._race_queue: deque[str]`, `self._raced_ips: set[str]`,
  `self._race_targets: dict[int, str]`, `self._race_outcomes: dict[int, str]`,
  `self._race_inflight: int`.
- `_exhaust_sender()`: at the top of each loop iteration, before the existing
  `room = self._window - len(self._inflight)` gate — if the queue is non-empty **and**
  `self._race_inflight < self.cfg.race_max_inflight`, pop one IP, send
  `build_discover_v4(mac, xid, src, requested_addr=ip)` through `_send()`, register the xid in
  `_inflight` *and* `_race_targets`, increment `_race_inflight` and `self.races`, emit
  `DiscoverSent(mac=mac, option50=ip, hostname=packets.packet_hostname(pkt))`, then `continue`.
- One race per iteration (the `continue`), capped by the reserve — so a burst drains steadily
  rather than all at once.

### 4. Outcome classification — shared, not duplicated

`_handle_ack()` currently does `requested = self._reacquire_targets.get(xid)` and derives
`granted`/`offered_different`; `_handle_nak()` sets `naked`; `_reap_timeouts()` sets
`no_response`. Factor that into one helper used by both paths:

```python
def _classify_targeted(self, xid: int, got_ip: str | None, outcome: str | None = None) -> None:
    """Record the outcome for a targeted DISCOVER, whichever table owns the xid."""
```

so re-acquisition and racing can never drift apart in how they classify. Decrement
`_race_inflight` here when the xid is race-owned.

### 5. Config

- `core/models.py`: `race_freed_addresses: bool = True`, `race_on_rediscover: bool = False`,
  `race_max_inflight: int = 4`.
- `cli/main.py`: `--no-race-freed`, `--race-on-rediscover` (exhaust only), following the existing
  `--no-evict`/`--no-journal` pattern.
- `web/schemas.py` + `web/static/`: booleans surfaced like `evict`/`journal`, with `as_cli()`
  round-trip.

### 6. Counters and findings

**Enumerate the counter surfaces** — §5b's `garps`→`arp_conflicts` rename warns "miss one and a
dashboard silently reads zero." `races` must land in all four:

1. `engine._counters()` (this also gives `d_races` for free via `_status_ticker()`'s generic
   delta comprehension)
2. `engine.status()`
3. `cli/render.py` `status_summary()` — a `col("races", "races")` call
4. `web/static/app.js` — the matching `col("races", "races")` alongside `col("arp_conflicts", …)`

Leave `app.js`'s per-mode `primary` dict alone; races is not a headline number.

**Finding** `RACED_FREED_ADDRESSES` (**INFO**, raised only when `self.races > 0`): evidence
`attempted` / `won` (`granted`) / `lost` (`offered_different`+`naked`+`no_response`), a breakdown
by trigger (`nak`/`decline`/`rediscover`), and sample IPs. Not PASS/FAIL — winning a race is the
tool working as designed, not a network weakness; the weakness, if any, is what
`DHCP_STARVATION_*` / `FOREIGN_DISCOVERS_UNANSWERED` already report.

**Dry-run gating**, exactly as eviction does it (§5f): under `dry_run` the race DISCOVERs are
suppressed at `_send()` (`probe=False`), so every outcome would read `no_response` and the
finding would be meaningless. Gate the finding on `not cfg.dry_run` and surface a `would_race`
count in `DRY_RUN_SUMMARY` instead.

## Related pre-existing bug (found while writing this; fix alongside or separately)

`_handle_nak()` runs for **every** NAK on the segment, including ones addressed to other clients
— `_on_dhcp()` correctly checks `is_nak` before the self-filter (we never originate a NAK), but
the handler then unconditionally does `self.naks += 1`, `_shrink_window("nak")` and
`_note_nak_for_burst_detection()`. So another client's NAK currently **shrinks our send window
and counts toward the `nak_burst` halt signal** (§5c), which can halt a run on someone else's
traffic. Foreign NAKs should be observed (they are a race trigger) but must not feed our own
window/halt logic. This is independent of the race feature and arguably worth its own commit.

## Tests

- Foreign NAK/DECLINE enqueues; our own release-phase-freed IPs (present in
  `_reacquire_targets.values()`) do **not**, even though `_is_own_traffic()` cannot see them.
- Dedup: repeated triggers for one IP enqueue once.
- `race_max_inflight` is respected — with the reserve full, an additional trigger stays queued
  rather than sending.
- A race DISCOVER carries option 50 and is sent even when `self._window - len(self._inflight) <= 0`
  (proves priority) but never beyond the reserve (proves the bound).
- Race xids land in `_race_targets`, **never** `_reacquire_targets` — regression test asserting
  `_evict_phase()`'s target set is unchanged by racing.
- `_classify_targeted()` produces identical outcomes for a race xid and a re-acquisition xid.
- `race_freed_addresses=False`, and `release`/`scan` mode regardless of flag: triggers still
  observed and logged, nothing sent.
- `race_on_rediscover=False` (default): a foreign DISCOVER from a known neighbor does not enqueue.
- `RACED_FREED_ADDRESSES` raised only when `races > 0`; suppressed under dry-run, where
  `DRY_RUN_SUMMARY` carries `would_race`.
- Foreign NAK does not increment `self.naks` / shrink the window / feed burst detection.

## Acceptance criteria

- [ ] No race trigger is built on DHCPRELEASE (unicast, unobservable — see the yield section)
- [ ] Triggers: foreign NAK, foreign DECLINE, and (opt-in) foreign DISCOVER from a known neighbor
- [ ] All triggers funnel through one `_maybe_race()` with the exclusions in one place
- [ ] IPs already in `_reacquire_targets.values()` are never raced (release-phase self-suppression)
- [ ] Gateway and DHCP server excluded, same as `_release_phase()`/`_evict_phase()`
- [ ] Race state is separate; `_evict_phase()`'s `granted_ips` is provably unaffected
- [ ] Races take at most `race_max_inflight` slots above the window; never an unbounded bypass
- [ ] Race and re-acquisition outcomes share one classifier
- [ ] `races`/`d_races` reach all four counter surfaces listed above
- [ ] `RACED_FREED_ADDRESSES` INFO only when `races > 0`; dry-run suppressed → `DRY_RUN_SUMMARY`
- [ ] Exhaust-only; flags round-trip through CLI and `as_cli()`
- [ ] Foreign NAKs no longer pollute `naks`/window/halt detection
- [ ] Full suite green; ruff clean

## Boundaries (do not relax without re-reading)

- Do not wire race targets into `_evict_phase()`. Eviction contests only addresses re-acquired
  from *our own* RELEASE (§5f) — a deliberate, documented limit on blast radius, not an oversight.
- Do not turn the bounded reserve into a general window bypass. §5c's window exists because a
  real `/22` run stalled at 56 addresses from pending-offer saturation.
- The rate limiter is not a backstop in exhaust (`rate_limit_pps=500`, deliberately non-binding).
  Any pacing claim for this feature must rest on the reserve, not on `_send()`.
- If a future need arises to race in `release` mode, that is a new decision, not an extension of
  this one.

## Suggested commit order

1. Foreign-NAK isolation fix (independent; makes the NAK trigger possible without side effects)
2. `_maybe_race()` + triggers + queue + exclusions, no sender integration yet (observable via
   debug logging only)
3. `_exhaust_sender()` integration + `race_max_inflight` reserve + `_classify_targeted()` refactor
4. Config flags (CLI + web + schemas)
5. Counters (4 surfaces) + `RACED_FREED_ADDRESSES` + dry-run gating
6. Docs — README, AGENT_HANDOFF §5f addendum, CHANGELOG under 2.3.0
