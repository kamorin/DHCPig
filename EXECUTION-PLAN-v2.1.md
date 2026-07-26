# DHCPig 2.1 — Execution Plan

> **For the implementing model.** Self-contained. Read `AGENT_HANDOFF.md` first (architecture,
> paths, safety model, test commands), then execute the phases below **in order**. Land each
> phase as its own commit. Do not start a phase until the previous phase's acceptance criteria
> are green.
>
> Companion context: `DHCPig-Implementation-Brief.md` (original build order) and
> `DHCPig-SoT.md` (product rationale) are in the user's outputs folder, not the repo.

## 0. Why this release exists

The maintainer's user journey for exhaust is:

1. release the leases of hosts already on the segment,
2. take every address in the range,
3. verify returning hosts cannot get back online.

A live run on a real `/22` stalled at **56 of ~1000 addresses**. Root cause was visible in the
capture: the server began re-offering addresses that were already pending (the same IP offered
to two of our MACs), then issued 8 NAKs and stopped answering us. That is **pending-offer table
saturation**, not pool exhaustion — we were flooding DISCOVERs faster than handshakes could
complete, so half-open allocations tied up the server and then timed out.

This release replaces the flood with a bounded pipeline, makes the release phase actually work,
surfaces how much of the pool remains, and renames the verdict to say what was measured.

### Constraints (unchanged, non-negotiable)
- Python ≥3.11, **`scapy>=2.5` is the only runtime dependency**. Web layer is stdlib-only;
  frontend is vanilla JS, no build step, no CDN.
- `dhcpig.core` is **UI-free** — never `print`, only `bus.emit()`.
- **Every outbound frame goes through `DhcpEngine._send()`.** That is the one chokepoint where
  scope, pacing and dry-run are enforced. Do not add a `sendp` call anywhere else.
- Whitehat boundary: no new offensive capability. Forged ARP MACs stay bogus (blackhole, never
  interception). Do not re-add the authorization gate — it was removed deliberately (§5 of the
  handoff).
- `ruff` line length 100; type hints in `core`; a test with every behaviour change.

---

## Phase 1 — Release phase runs first, inside exhaust

**Decision:** the release phase always runs as part of `exhaust`, before the senders start.
Keep `release` as a standalone mode too (unchanged surface).

### 1a. Fix two bugs that make release mode a no-op today

Both must be fixed before the phase can do anything. Verify each with a test.

**Bug 1 — the server identifier is always `0.0.0.0`.**
`_discover_neighbors()` ends with `return list(found.values()), None` — the second element is
*always* `None`. `_release_worker()` then does `self._do_release(neighbors, server_ip or
"0.0.0.0")`, so every RELEASE carries `server_id=0.0.0.0` and `IP(dst=0.0.0.0)`. Servers drop
these. Nothing has ever been released.

Fix: source the server from `control_pre.server_id`, which `_control_transaction("pre","self")`
already captures. Order in the prelude therefore matters (see 1c). If `--no-control` is set and
no server is known, **skip the release phase** with a `Debug` explaining why — do not send to
`0.0.0.0`.

**Bug 2 — `build_release_v4` returns an L3 packet but is sent with `sendp`.**
`packets.build_release_v4()` builds `IP(...)/UDP/BOOTP/DHCP` with **no `Ether` layer**, and
`_send()` calls `sendp()` (L2). Verify what scapy actually puts on the wire here — if the frame
is malformed or unsent, add an `Ether(src=<spoofed client MAC>, dst=<server MAC>)` layer.
RFC 2131 has RELEASE unicast to the server, so the destination MAC should be the server's
(available from `parse_offer`/`ServerInfo.server_mac`, or resolve by ARP). Keep the existing
signature working for the standalone `release` mode; add the L2 layer inside the builder.

### 1b. Measure whether release actually worked

Servers vary: ISC dhcpd and Windows DHCP have historically honoured an unauthenticated RELEASE;
several appliances validate the source and ignore it. Report observed effect, not frames sent.

After the release loop, re-probe the released addresses by ARP (reuse `_discover_neighbors`
against just those IPs) and count how many stopped answering. Hosts that keep answering either
never lost the lease or immediately renewed.

### 1c. New prelude order

`_exhaust_prelude()` becomes:

1. `_baseline_arp_scan()` — existing; inventories who was present *before* the test.
2. `_control_transaction("pre", "self")` — proves DHCP is reachable, **and yields the
   `server_id` the release phase needs**.
3. `_control_transaction("pre", "new")` — the baseline that the verdict depends on.
4. **`_release_phase()`** — new.
5. `_start_senders()`.

`_release_phase()`:
- returns immediately if `cfg.release_neighbors` is False, or no `server_id` is known, or
  there are no ARP neighbours — each with a `Debug` naming the reason;
- excludes the default gateway and the DHCP server itself from targets (releasing the
  gateway's lease is disruptive out of proportion to the address gained);
- sends one RELEASE per neighbour through `_send(pkt, target_ip=n.ip)` so the scope guard
  still applies;
- re-probes and emits a `Debug` summary plus a finding.

### 1d. Config, CLI, web

- `models.SessionConfig`: add `release_neighbors: bool = True`.
- CLI: `--no-release` on the `exhaust` subcommand (escape hatch; default is on).
- Web: "Release neighbours first" checkbox, checked by default, in the config panel;
  `schemas.config_from_payload` reads `release_neighbors`; `as_cli()` emits `--no-release`.

### 1e. New finding

`NEIGHBOR_LEASES_RELEASED` — verdict `INFO`, severity `medium`.
Evidence: `{targets, released_sent, stopped_answering_arp, server_id}`.
Recommendation: if `stopped_answering_arp == 0`, the server appears to ignore unauthenticated
RELEASE (good — that is the desired behaviour); if it is high, the server accepts spoofed
RELEASE from any host on the segment, which is a real finding worth reporting on its own.

### Acceptance (Phase 1)
- [ ] A test proves RELEASE carries a non-`0.0.0.0` `server_id` sourced from the pre-control.
- [ ] A test proves the release phase is skipped (not sent to `0.0.0.0`) when no server is known.
- [ ] A test proves the gateway and DHCP server are excluded from release targets.
- [ ] A test asserts the built RELEASE frame is L2-complete and unicast to the server MAC.
- [ ] Prelude order test extended: `arp → ctl-pre-self → ctl-pre-new → release → senders`.
- [ ] Dry-run sends nothing.

---

## Phase 2 — Windowed handshakes, adaptive pacing, halt-on-control

This is the phase that fixes the observed failure. Replace `_exhaust_sender()`'s open-loop
flood with a bounded pipeline.

### 2a. Windowed handshakes

Track in-flight transactions: `xid -> {mac, sent_at, state}` where state is
`DISCOVER_SENT | REQUEST_SENT`. Invariants:

- at most `window` transactions in flight (start at **8**);
- a slot is only freed on ACK, NAK, or timeout (`timeouts.dhcp_request`);
- **only an ACK counts as a held address** — half-open allocations are exactly what saturated
  the server, so they must not be counted as progress;
- retire timed-out slots and count them (`self.timeouts_seen`) — a rising timeout count is a
  throttle signal (see 2c).

### 2b. Adaptive pacing (replaces `--rate` for exhaust)

The window *is* the pacing mechanism. Controller, evaluated per completed handshake:

- clean ACK → `window += 1` up to a ceiling (default 64);
- NAK, duplicate offer (same IP offered to two of our MACs), or timeout →
  `window = max(1, window // 2)` and record the trigger;
- emit a `Debug` on every window change with the trigger, so a run's shape is legible.

**Do not delete `RateLimiter` or `rate_limit_pps`.** Windowing only bounds exhaust. The ARP
sweep, the release flood and the garp rounds have no natural window, and the rate limiter is
currently the only thing pacing them — removing it turns garp into an unbounded broadcast
flood. Concretely:
- remove `--rate` from the **exhaust** subcommand and the web config panel;
- keep `--rate` on `release`, `garp`, `active-scan`;
- keep `_send()` calling `self.rate.acquire()` unconditionally (harmless for exhaust once the
  window is the binding constraint; set the exhaust default high, e.g. 500, so it does not
  bind).

Add `SessionConfig.window_initial: int = 8`, `window_max: int = 64`; drop nothing else.

### 2c. Halt-and-report on the first control signal

**Decision:** on detection, **stop sending but keep held leases**, then continue through the
post-control transactions so the report is complete. Do *not* release, do *not* skip the
post-control — that is what makes the verdict meaningful.

Detect:
| Signal | Detection |
|---|---|
| `nak_burst` | ≥3 NAKs within 5s |
| `offer_silence` | existing `timeouts.offer_silence` after offers had flowed |
| `link_down` | `/sys/class/net/<iface>/carrier` == 0 or `operstate` != `up` — port-security err-disable |
| `timeout_storm` | ≥5 consecutive handshake timeouts |
| `duplicate_offers` | ≥3 addresses offered to more than one of our MACs |

Implementation: poll carrier in the existing `_status_ticker` (do not add a thread). On the
first signal, set `self._halt_signal = (name, detail, self.acks)`, emit a new
`ControlDetected(signal, detail, leases_held)` event, stop the sender loop, and call
`_finish_in_background(reason)`. `stop()` already joins threads, runs both post-controls,
finalizes findings and leaves leases held (`restore_on_exit=False` by default) — so no change
is needed there beyond confirming it.

Add engine state `HALTED` between RUNNING and STOPPING for status display.

### Acceptance (Phase 2)
- [ ] Window never exceeds its cap; a test drives synthetic OFFER/ACK/NAK through `_on_dhcp`.
- [ ] NAK / duplicate-offer / timeout each halve the window; a clean ACK grows it.
- [ ] Only ACKs increment `self.acks`; timed-out slots do not.
- [ ] Each of the five halt signals sets `_halt_signal`, emits `ControlDetected`, stops sending.
- [ ] After a halt: post-controls still ran, findings were produced, held leases were **not**
      released.
- [ ] `--rate` is gone from `exhaust` and still present on `release`/`garp`/`active-scan`.
- [ ] Existing `test_sender_does_not_add_fixed_sleep` is updated, not deleted — the no-fixed-
      sleep property still matters.

---

## Phase 3 — Headroom as a top-level dashboard number

### 3a. Estimating the pool

Add `models.PoolEstimate`: `{size: int | None, source: str, is_estimate: bool, detail: str}`.
Resolution order:

1. **`--scope` supplied** → usable host count of the CIDR(s). `source="scope"`,
   `is_estimate=False` for the range (still an estimate of the *server's configured scope*).
2. **Observed offers** → span of offered addresses widened to the subnet from DHCP option 1.
   `source="observed"`, `is_estimate=True`.
3. **Neither** → `size=None`; the UI shows `—`, never a fabricated number.

`headroom = size − held(acks) − in_use_observed(ARP neighbours not ours)`, floored at 0.

**This is an estimate and must be labelled one.** We cannot see the server's scope config;
reservations, exclusions, or multiple scopes on one segment will skew it. Always render the
denominator and its source beside the number (e.g. `412 / ~1022 est. from scope`). Do not let
it read as authoritative.

### 3b. Surfaces

- `status()` gains `pool_size`, `pool_source`, `headroom`, `in_use_observed`.
- `_status_ticker` includes them in `StatusTick.stats` (updates every 5s).
- Recompute on `AckReceived` too, so the number moves with leases rather than only on the tick.
- **Dashboard:** add a fifth counter cell (`c-e` / `l-e`) for headroom, beside leases, with the
  denominator as sub-text. Files: `web/static/index.html`, `app.js` (`pollStatus`, plus the
  `onModeChange` label map — headroom is meaningful only for exhaust; blank it elsewhere),
  `styles.css` if the counter row needs to reflow at five cells.
- CLI: add headroom to the `status_summary()` line (`render.py`) when known.
- Report: include the estimate object in `to_dict()` and the HTML header.

### 3c. New finding

`POOL_HEADROOM_LOW` — verdict `INFO`, severity `medium`, raised when observed steady-state
utilisation before our test exceeds ~80%. Evidence: `{in_use_observed, pool_size, source}`.
This is free from the passive ARP sweep and is a config finding in its own right: a scope
already at 90% needs only the last 10% taken to deny service.

### Acceptance (Phase 3)
- [ ] Estimate from scope, from observed offers, and the `None` case each covered by a test.
- [ ] `headroom` floors at 0 and never goes negative.
- [ ] `status()` and `StatusTick.stats` both carry the fields; a web test asserts the JSON keys.
- [ ] UI shows `—` with no estimate, and always shows source text.

---

## Phase 4 — Verdict rename

### 4a. The two verdicts

| id | verdict | when |
|---|---|---|
| `DHCP_STARVATION_ATTAINED` | `FAIL` | `acks > 0` **and** the post-run **new-MAC** control was denied **and** its own pre baseline succeeded |
| `DHCP_STARVATION_NOT_ATTAINED` | `PASS` | everything else |

`NOT_ATTAINED` carries a `reason` in evidence, one of:
- `control_fired` — plus `signal` and `leases_at_halt` from `_halt_signal`;
- `pool_headroom_remaining` — plus headroom and pool estimate;
- `blocked_at_baseline` — an unknown MAC could not get an address before we started
  (snooping / port security);
- `inconclusive_baseline` — `pre/self` failed, so the run proves nothing.

**Polarity warning.** `ATTAINED` is a *failure of the network*, not a success of the run. The
`verdict` field is the only thing the UI may colour from — the existing `renderFindings()` keys
CSS off `f.verdict`, which is correct; do not change it to key off the id.

Note the interaction with Phase 2: because the run now halts on the first control, `ATTAINED`
becomes rare on a defended network by construction, and `NOT_ATTAINED + control_fired` is the
expected pass. The recommendation text should say which control stopped the run and at what
lease count, since that is the actionable output.

### 4b. Retire and keep

Retire (fold into the two above): `DHCP_STARVATION_POSSIBLE`, `DHCP_STARVATION_BLOCKED`,
`POOL_EXHAUSTED_CONFIRMED`, `POOL_NOT_EXHAUSTED`.

Keep unchanged: `CONTROL_BASELINE_FAILED`, `NEW_CLIENT_BLOCKED_AT_BASELINE`,
`SERVER_STOPPED_SERVING_TEST_CLIENTS`, `DHCP_NAK_OBSERVED`, `MULTIPLE_DHCP_SERVERS`,
`ARP_FORGERIES_*`, plus the two added here.

`PoolExhausted` the *event* stays (the sender still detects offer silence); only the findings
are renamed.

### Acceptance (Phase 4)
- [ ] A test per `reason` branch.
- [ ] `ATTAINED` requires all three conditions; two-of-three yields `NOT_ATTAINED`.
- [ ] The four retired ids appear nowhere in `src/`.
- [ ] The CLI `[==] verdict:` summary and the web Findings tab both render the new ids with the
      correct colour.

---

## Files in scope

| File | Phases |
|---|---|
| `core/models.py` | 1d, 2b, 3a — `release_neighbors`, `window_*`, `PoolEstimate` |
| `core/engine.py` | all — prelude, `_release_phase`, windowed sender, halt detection, headroom, findings |
| `core/packets.py` | 1a — `build_release_v4` L2 layer |
| `core/events.py` | 2c — `ControlDetected` |
| `core/netutils.py` | 2c — carrier/operstate read |
| `core/reporting.py` | 1e, 3b, 4 — new findings, pool estimate in report |
| `cli/main.py` | 1d, 2b — `--no-release`, `--rate` off exhaust |
| `cli/render.py` | 2c, 3b, 4 — `ControlDetected`, headroom in status line |
| `web/schemas.py` | 1d, 2b — `release_neighbors`, drop `rate` from exhaust payload |
| `web/static/index.html` | 1d, 2b, 3b — checkbox, remove rate, fifth counter |
| `web/static/app.js` | 1d, 2c, 3b — payload, `ControlDetected`, headroom render |
| `web/static/styles.css` | 3b — counter row at five cells |
| `README.md`, `CHANGELOG.md`, `AGENT_HANDOFF.md`, `SECURITY.md` | all |

New test file: `tests/unit/test_window_headroom.py` for Phases 2–3. Extend
`test_control_findings.py` for Phases 1 and 4.

## How to run

Sandbox Python is 3.10 but the package targets 3.11+, so **do not `pip install -e .`** there:

```
cd /sessions/<id>/mnt/DHCPig
PYTHONPATH=src python3 -m pytest -q      # 115 pass today, 1 integration deselected
python3 -m ruff check src tests
python3 -m ruff format --check src tests
```

All unit tests run without root by monkeypatching `dhcpig.core.engine.sendp`. Drive the
windowed sender by feeding synthetic OFFER/ACK/NAK packets into `_on_dhcp()` — see
`tests/unit/test_control_findings.py::_reply` for the fixture builder.

## Definition of done

- [ ] Release phase runs first in exhaust, with a real `server_id`, and reports observed effect.
- [ ] Exhaust uses a windowed, adaptive pipeline; no `--rate` on exhaust; other modes keep it.
- [ ] The run halts on the first control signal, keeps its leases, and still completes both
      post-controls and the findings pass.
- [ ] Headroom is a live top-level dashboard number, labelled as an estimate with its source.
- [ ] The verdict is `DHCP_STARVATION_ATTAINED` / `_NOT_ATTAINED` with a `reason`.
- [ ] Full suite green, `ruff` clean, docs updated, one commit per phase.

## Not in scope

IPv6 (still a seam only), rogue-DHCP-server emulation, and anything that redirects traffic
through the tool rather than blackholing it.
