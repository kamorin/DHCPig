# DHCPig 2.x — Design Notes

This is the design document: what the tool does, why the code is shaped the way it is, and which
decisions are settled rather than open. It's the reference for anyone extending or reviewing this
codebase — human or agent. For the practical "how do I add a finding / run the tests / where does
this file go" workflow, see `CONTRIBUTING.md`; agent-session/sandbox specifics live in
`CLAUDE.md`; release-by-release history lives in `CHANGELOG.md` — none of that is repeated here.

## 1. What this is
A whitehat DHCP network-hardening validation tool. It exhausts DHCP pools, releases neighbor
leases and re-acquires them by name, evicts hosts off addresses via forged RFC 5227 ARP
conflicts, and passively/actively fingerprints hosts — to prove a network defends against those
(DHCP snooping, port security, Dynamic ARP Inspection, etc.). **Never add capability that
enables host compromise or lateral movement; it stays an L2/L3 DHCP/ARP stress + audit tool.**

## 2. Where the code lives
See `CLAUDE.md` for local working-copy paths and any sandbox/VM specifics — that's session
workflow, not design. From the repo root: `src/dhcpig/` is the package (§3 covers its layout),
`tests/` mirrors it, `docs/` holds this file, `packaging/` the `.deb`/`.desktop`/man-page
sources.

Section numbers in this document are cited by section markers (`§5a`, `§5f`, etc.) throughout
the source tree's comments and docstrings — don't renumber sections without also updating every
one of those citations across `src/` and `tests/`.

## 3. Architecture (the one mental model that matters)
Three layers, strictly separated:
- **`src/dhcpig/core/`** — the engine. **UI-free: never calls `print`; it only emits events.**
- **`src/dhcpig/cli/`** — `dhcpig` command; subscribes to the event bus and prints.
- **`src/dhcpig/web/`** — `dhcpig-web` stdlib HTTP server + SSE; subscribes and streams JSON.

Both front ends drive the SAME `DhcpEngine` and never touch scapy directly.

### Core files
| File | Role |
|------|------|
| `core/models.py` | dataclasses/enums: `SessionConfig`, `Lease`, `ServerInfo`, `Neighbor`, `HostFingerprint`, `PoolEstimate`, `Mode`, `IPVersion`, `Timeouts`. `DESTRUCTIVE_MODES = {RELEASE_NEIGHBORS}`; `RUN_ONCE_MODES = DESTRUCTIVE_MODES \| {RELEASE_PREVIOUS, ACTIVE_SCAN}` (re-exported by `cli/main.py`) — the set the CLI polling loop and web reaper use to detect a worker-thread run finishing; keep it "does the worker finishing mean the run is over", not "is this mode destructive". `ControlOutcome`/`Lease` carry `server_mac`. |
| `core/packets.py` | **pure** scapy builders/parsers (no I/O): `build_discover_v4` (takes `requested_addr` for option 50, §5f), `build_request_v4`, `build_release_v4` (carries an `Ether` layer, §5c), `build_inform_v4`, `build_garp` (op=1/2, reused by eviction, §5b), `build_arp_conflict_unicast` (the same claim delivered unicast to the victim, §5b), `server_identifier`, `client_mac_from_offer`, `parse_offer`, `is_offer`/`is_ack`/`is_nak`/`is_discover`/`is_decline`, `dhcp_option`. |
| `core/engine.py` | `DhcpEngine(cfg, bus)`: `start/stop/status/restore`. One state machine, `threading.Event` stop, worker threads + sniffer. **Every outbound frame goes through `_send()`** (the single chokepoint; `probe=True` bypasses dry-run suppression only, never `offline` — §8). Control transaction, release phase, re-acquisition, the windowed sender, halt detection, and pool estimate all live here (§5a–§5f); finding *text* lives in `core/findings.py`, eviction state in `core/eviction.py`, race state in `core/racing.py`, release-previous's entry filter in `core/recovery.py` — engine.py keeps the branching logic and calls into all four. Debug via `_debug()`. ~2570 lines. |
| `core/findings.py` | The finding catalogue: every id's title/verdict/severity/recommendation in one declarative dict, plus `build(id, evidence, **overrides)`, `finding_summary_lines()` + `EVIDENCE_SKIP` (the one rule for displaying a finding, shared by the CLI renderer, the HTML report, and `events.to_dict()`'s `summary` field, which `app.js` renders directly instead of re-deriving — §5a), and the two-variant recommendation helpers (`starvation_not_attained_recommendation()`, `neighbor_leases_released_recommendation()`). Engine methods decide *whether* a finding fires and with what evidence; this file owns the *text*. |
| `core/eviction.py` | `EvictionState` (the per-run eviction attributes, `self._evict` on the engine — including `forged_mac_by_ip`, the one stable forged MAC per target, §5b) and the pure outcome-rung ordering (`RUNGS`, `rung_max()`). The eviction *methods* (`_do_arp_conflict`, `_evict_phase`, `_evict_worker`, `_measure_eviction`, `_handle_evict_arp`) stay on `DhcpEngine` — they're threaded through `_send()`/the bus/`cfg`/other engine dicts closely enough that wrapping them in a class holding a back-reference to the engine would add indirection without reducing coupling. |
| `core/recovery.py` | `select_entries(cfg, entries, scope, pre_control)` — the one piece of `release-previous`'s logic that's genuinely decoupled from the engine (a pure filter over `cfg` + the loaded journal). `_run_release_previous`/`_release_selected`/`_release_previous_worker` stay engine methods, same coupling reasoning as eviction. |
| `core/racing.py` | `RaceState` (the per-run race-freed attributes, `self._race` on the engine — §5g). `races` (the plain attempted-count) stays a normal engine attribute alongside its sibling counters. |
| `core/events.py` | `EventBus` (thread-safe), event dataclasses (including `ControlDetected`, `ForeignDiscover`, `ClientEvicted`), `to_dict()` + `jsonable()` (recursively converts enums/bytes/Path so JSON never breaks). `to_dict()` also attaches `finding.summary` (via `core/findings.finding_summary_lines()`) to every `FindingRaised` payload — §5a. |
| `core/safety.py` | `ScopeGuard`, `RateLimiter` (token bucket — still wired through `_send()` for every mode; §5c for why exhaust and release no longer take `--rate`), `Cleanup` (tracks leases for restore). No authorization gate (§5). |
| `core/sniffer.py` | thin `AsyncSniffer` wrapper. BPF is `port 67 or port 68`, both directions — needed to observe foreign DISCOVERs and DHCPDECLINEs (§5f, §8). |
| `core/fingerprint.py` | `extract_signature()` + `resolve()`: exact option-55 match against `data/satori_dhcp_fingerprints.json`, then exact option-60 vendor class, else `from_mac()` OUI-only. `DB_VERSION`. |
| `core/oui.py` | MAC → hardware vendor. scapy's bundled Wireshark/IEEE `manuf` DB (~50k) only; locally-administered MACs labelled as randomised. |
| `core/reporting.py` | `SessionRecorder` → JSON/CSV/HTML (`render()` / `export()`, dispatching on the format the CLI's `--report` file extension or web UI's Report tab asks for). Neighbors deduped by MAC. Tracks `final_status` from `SessionEnded` to surface the pool estimate in reports. `finding_summary_lines()`/`EVIDENCE_SKIP` live in `core/findings.py`, re-exported here for `cli/render.py` and existing tests. |
| `core/netutils.py` | iface enumeration, `iface_network_cidr()` (scope auto-fill), `default_gateway()` (release-phase/eviction target exclusion via `_release_gateway()`), `link_is_up()` (carrier poll for `link_down` halt detection — `None` fail-open, §5c), IP math, `random_mac()`. `random_mac()`/`iface_network_cidr()` are monkeypatched by source path in tests (`dhcpig.core.netutils.*`) — `engine.py` calls them as `netutils.random_mac()` etc, never `from .netutils import random_mac`, or the patch silently stops working. Same reasoning applies to `scapy.all.get_if_hwaddr`/`scapy.all.srp`, which stay function-local imports in `engine.py` for the same reason. |
| `core/journal.py` | Lease journal for recovery (§5e): append-only JSONL, `default_path()` (XDG state dir, never `/var/lib`), `record_ack`/`record_released`, `load_open_leases()` (never raises — crash-tolerant). Powers `Mode.RELEASE_PREVIOUS`. |
| `core/exceptions.py` | `DhcpigError`, `ConfigError`, `OutOfScope`, `SessionConflict`. |
| `data/satori_dhcp_fingerprints.json` | Static Satori-derived fingerprints (319 option-55, 187 vendor-class), GPL-2.0-or-later. Queryable and regenerable via `data/satori-merge.py`. `data/DATA_ATTRIBUTION.md`. |

### Web files
`web/server.py` (`WebApp` + `Handler` + `main`), `web/api.py` (route handlers → `(status,dict)`),
`web/stream.py` (`SseSubscriber`: bus→per-client `queue.Queue`→SSE frames), `web/auth.py`
(loopback + bearer token + same-origin + security headers), `web/schemas.py` (dataclass
validation, no pydantic; `config_from_payload`, `as_cli`), `web/static/{index.html,app.js,styles.css,icon.svg}`
(vanilla JS SPA, no build step, hand-rolled canvas sparkline). `icon.svg` is the hacker-pig
logo — served unauthenticated alongside the css/js because the browser fetches it as a
favicon before any token exists; the same file is copied to `packaging/dhcpig.svg` for the
`.desktop` entry and the README header.

## 4. Event flow
`engine (worker threads) → bus.emit(Event) → subscribers`. CLI `Renderer.handle` prints;
web `SseSubscriber` puts `to_dict(event)` on a queue, the `/events` handler writes SSE frames,
the browser's `EventSource` updates the DOM. **Handlers must be cheap/non-blocking.**

## 5. Safety model
- **There is no authorization gate.** No `--i-am-authorized`, no `authorize()`, no
  `Unauthorized`, no confirmation modal or prompt, and `--scope` is optional for `release` — with
  none given it falls back to the interface's own network via `_sweep_cidrs()`. **`dhcpig
  release eth0` will target the whole segment, and runs the full re-acquisition + eviction chain
  against it (§5f) — a bigger blast radius than the name alone suggests.** Don't re-add the gate
  without asking, and don't quietly remove what's left below either.
- What still bounds a run: the windowed handshake pipeline for `exhaust` and `release`'s
  re-acquisition leg (§5c), `--rate` (default 7 pps) for `active-scan`/`release-previous`,
  `--dry-run`/`--no-evict`, `ScopeGuard` when a scope *is* supplied, and `Cleanup`/`restore()`
  for lease reversal.
- `active-scan` is non-destructive but **requires `--scope`** (`ConfigError` if missing) — this
  is the one remaining hard requirement, so its sweep can't be unbounded. It also has a bounded
  post-INFORM listen window (`active_scan_listen`, default 20s, `--active-scan-listen`) so the
  worker thread always exits on its own — `active-scan` is in `RUN_ONCE_MODES` (§3).
- **`_send()` is the chokepoint**: scope check (drops out-of-scope, emits `Skipped`), rate limit,
  `offline` (hard "never touch a socket" switch), and `dry_run` (builds + accounts, never calls
  `sendp` — **unless** `probe=True`, §8). Keep all sends flowing through it.
- `restore()` releases exactly the leases in `Cleanup`. **There is no auto-restore-on-exit** —
  leases are always kept after a run so the exhausted state can be verified; the operator cleans
  up explicitly via `dhcpig restore <iface>` or `POST /api/session/restore` (same-process/session
  only — there is no Restore button in the web UI) or, once that process is gone, `dhcpig
  release-previous <iface>` replaying the lease journal. Don't silently reintroduce an
  auto-restore flag — retention followed by an explicit recovery step is deliberate.

## 5a. Confidence model — why the tool can be believed
The engine reports **verdicts backed by evidence**, not just counters. Several pieces work
together and should be kept together:
- **Control transaction** (`_control_transaction`, `ControlOutcome`): a legitimate DHCP cycle,
  run `pre` (in `_exhaust_prelude`) and `post` (in `stop()`, deliberately **before** `restore()`
  so leases are still held). Replies route by xid via `_consume_control()` so control traffic
  never pollutes run counters; the lease is released immediately.
  **Two legs, and the distinction is load-bearing:** `client="self"` uses the real NIC MAC, which
  the server usually already has a binding for — it is a *renewal* and will succeed on a drained
  pool. `client="new"` uses a fresh unseen MAC that must come off the free list. **Exhaustion is
  judged only on the `new` leg.** A failed `pre/self` means the test was broken, not that a
  defense worked; a failed `pre/new` with a good `pre/self` means L2 admission control.
  `ControlOutcome.server_mac` (learned from the OFFER's Ethernet source) is what lets the release
  phase (§5c) unicast RELEASE to the real server instead of broadcasting blind.
- **`EXHAUSTED` means the server stopped serving — nothing else.** There is no lease cap; nothing
  self-imposed can be mistaken for exhaustion. Exhaustion needs offers to have flowed then
  stopped (`_offers_seen_any` + `offer_silence`) and is only `confirmed=True` once the post
  control is also denied.
- **`HALTED` means a defensive control fired mid-run** (§5c) — distinct from `EXHAUSTED`. Both
  route through the same `_trigger_halt()` → `_finish_in_background()` path.
- **Runs finalize themselves.** `_finish_in_background()` spawns a finisher thread that calls
  `stop()` when a terminal condition hits. This is required, not cosmetic: `stop()` joins the
  worker threads, so the sender cannot call it directly, and without it the web UI would sit idle
  after the pool drained (senders dead, no post-control, no verdict) until Stop was pressed.
  `OffersCeased` reports the quiet-period countdown so the UI shows progress meanwhile.
- **Findings** (`_finalize_findings`, `Finding`): id/verdict/severity/evidence/recommendation,
  emitted as `FindingRaised`, collected into `report["findings"]`. Add new findings there. The
  exhaustion verdict is `DHCP_STARVATION_ATTAINED` (FAIL) / `DHCP_STARVATION_NOT_ATTAINED` (PASS)
  — §5d. **`verdict` is what the UI colors off, never `id`** — keep it that way.
- **`RUN_SUMMARY` (INFO) is the one finding raised unconditionally**, first, in every mode
  including dry-run and read-only scans — it's the only finding a reader can rely on being
  present, so a report always opens with "here is what this tool did to your network" before any
  verdict. Its `steps` evidence is built by **`_run_summary_steps()`**, a list of
  **`{"did": ..., "got": ...}`** pairs (not pre-joined strings — each surface aligns the columns
  to its own width, and JSON/CSV consumers get parseable fields). Two rules govern the content:
  - **`did` is plain English and short (≤60 chars, asserted by a test); protocol names live in
    `got`.** The audience is a security engineer who is *not* a DHCP specialist, so the left
    column must be readable without knowing what DHCPRELEASE or option 50 are. The *why* behind
    these primitives is stated **once**, in the recommendation — not repeated per step.
  - **Descriptive only — do not make it infer defensive posture.** "The server ignored this, so
    snooping is probably on" belongs in the verdict findings; a second differently-worded
    conclusion from the same run is worse than one. A regression test asserts the step text
    contains no posture vocabulary.

  Its recommendation is **keyed on the mode** (`findings.run_summary_recommendation()`). For the
  sending modes it assumes a **Wi-Fi-based** attacker (controller DHCP proxy + client-MAC/chaddr
  consistency enforcement) — that's the one control that breaks every step in the chain, since
  all of them depend on sending DHCP on another device's behalf. `scan` and `active-scan` get
  their own text, because that sentence is simply untrue of them: neither sends DHCP naming
  another device (active-scan's steps are an ARP sweep and a DHCPINFORM), so they describe what
  reconnaissance alone demonstrates instead. Keep this split if you add a mode.
- **The neighbor roll-call has two surfaces, one source.** `_neighbor_rollcall()` does all the
  classifying and returns `(ip, mac, hostname, outcome, category, device)` rows (`hostname` is
  DHCP option 12 off a foreign DISCOVER, `""` when never seen — never inferred from anything
  else, and the column is omitted entirely when no host has one; `device` is `_fp_short_label()`
  on the neighbor's fingerprint — `"os (vendor)"`, falling back through device/vendor alone,
  `""` when nothing was ever fingerprinted, same omit-when-empty treatment as hostname);
  **`NeighborSummary`** (live event, event log) and the **`NEIGHBORS_OBSERVED`** INFO finding
  (durable, reaches `report["findings"]` and so the JSON/HTML exports) both just render it. The
  `device` column is deliberately **CLI/web-log only** — `NEIGHBORS_OBSERVED`'s evidence stays
  outcome-only, since that finding is about what happened to a host, not what it is, and
  fingerprint detail already reaches the report separately via `NeighborFound`/
  `HostFingerprinted`. Never let either surface compute its own classification — they'd drift,
  and then a report and the log it came from
  would disagree about what happened to a host. The finding exists because `NeighborSummary` is
  an event and events don't survive into the report at all.
- **`NeighborSummary` is the event-log counterpart to `RUN_SUMMARY`**: emitted once from
  `stop()` (after `_evict_phase()` so outcomes are settled, before `_finalize_findings()` so the
  log reads "who was affected" then "the verdicts about it"), built by `_emit_neighbor_summary()`.
  It emits **one row per host and lists every discovered neighbor** — including untouched ones,
  so `unaffected` is visibly distinct from `not examined` — sorted worst-first. Silent when the
  ARP sweep found nothing. The bucket boundaries are load-bearing and are pinned by tests in both
  directions:
  - `offline` — `discover_unanswered`/`apipa`, **or** (any mode, but this is exhaust's whole
    point) a neighbor whose DISCOVER during the run went unanswered because the pool was
    drained. Reading only `_evict.outcomes` would report those as `unaffected`, exactly backwards.
    `rediscovered` is **not** offline: it restarted and *was served*.
  - `lease_taken` — re-acquisition `granted` for that IP, and the host either showed no eviction
    reaction **or reached the `defended` rung**. **Do not merge this into either neighbouring
    bucket.** The host is working at the moment the summary is emitted (so it isn't offline) but
    the server has handed us its address, so it fails at its next renewal, silently, with nothing
    observable from our vantage point (same reason `_reprobe_released()` is colour only, §5f).
    `_renewal_suffix()` appends an **upper bound** (`(within ~12h)`) derived from the lease
    duration the server gave *us* for that address — never a countdown, because the victim's own
    T1 depends on when it originally got its lease, which we cannot see.
  - `defended` + `granted` is `lease_taken`, not `reacted` (2.7.1) — the one rung that does not
    outrank the inferred state. Defending settles the ARP exchange while the lease underneath it
    is already gone, so the host is in exactly the position a silent `lease_taken` host is in;
    reporting "defended its address" described the packets and buried the outcome. The other
    rungs still win, because they are genuinely different news rather than the same news:
    `apipa`/`discover_unanswered` mean no working address *now*, `declined`/`rediscovered` mean
    the host is no longer on the stolen address at all.
  - Outright denial still outranks a stolen binding: a neighbour in `denied_macs` is reported
    `offline` even when we hold its lease — present-tense outage beats a future one.
  - **`ARP-conflicted -> ` prefix (2.7.2).** Any row whose IP was an eviction target this run
    gets the prefix, independent of *why* it landed in its category — a target that also
    happens to be in `denied_macs` was still contested, even though the pool drain is what
    actually took it offline. It never reaches `unaffected`: eviction only ever targets
    `_granted_ips()`, so a targeted host is already guaranteed `lease_taken` or better.
  - **`released_unconfirmed` (2.7.3)** — a neighbour with a forged `DHCPRELEASE` sent in its
    name (`n.ip in set(self._reacquire_targets.values())`) whose re-acquisition never came back
    `granted`. Before this it fell straight through to `unaffected`, which claims more
    confidence than the run has: `_finish_release()`'s own docstring explains that on a pool
    with headroom (`release` mode; `exhaust` differs once the pool actually drains, per RFC
    2131 §4.3.1 rule 3 vs. rule 4) an `offered_different`/`naked`/`no_response` result is the
    *expected* answer whether or not the server honoured the RELEASE — this vantage point
    cannot distinguish "the real host kept its lease" from "the binding was freed and handed to
    someone else before we asked". Ranked between `reacted` (positive evidence the host is
    fine) and `unaffected` (nothing sent at all) — worse than the former, better than the
    latter, and never `lease_taken`-adjacent since that category requires certainty this one by
    definition lacks.
- **CLI/web render one merged `[==] OUTCOME` section (2.7.2), not two.** Per-host detail and the
  aggregate tally used to sit under separate headers (`NEIGHBOR SUMMARY` then `OUTCOME`), which
  read as two different findings about the run rather than one. `Renderer._neighbor_summary()`
  in `cli/render.py` is the source layout; the `NeighborSummary` handler in `web/static/app.js`
  mirrors it by hand (no shared renderer between Python and JS here) — keep them in sync if
  either changes.
- **The event log is the only results surface.** There is **no findings tab** in the web UI, and
  no client-side finding store — `FindingRaised` renders straight into the log. Findings are all
  raised in one pass at the end of a run, so a panel that fills instantly at the end was never
  doing anything a log tail couldn't, and it duplicated content the log already printed.
- **`findings.finding_summary_lines()` is the single rule for how a finding is displayed.**
  `cli/render.py` and `_findings_html()` both call it directly; `events.to_dict()` calls it once
  per `FindingRaised` and attaches the result as `finding.summary`, and `web/static/app.js`
  renders that field instead of re-deriving its own copy in JS. **There is exactly one place to
  change the rule** — the rule: numbers line (nested dicts flattened, zero/empty and
  `EVIDENCE_SKIP` keys dropped), list evidence one item per line, then the **first sentence** of
  the recommendation. `EVIDENCE_SKIP` holds run context already in the header, config echoes, and
  `still_using_address_arp` — which `_finish_release()` itself documents as not being evidence
  either way.
- **The JSON export stays the complete record.** Summarising happens at render time; `Finding`
  keeps `verdict`, `severity`, full `evidence` and the full multi-sentence `recommendation`, and
  all of it still reaches `report["findings"]`. If someone asks for more detail, the answer is
  the JSON export, not a longer log line.
- **Findings are emitted worst-severity-first.** `_finalize_findings()` buffers what it raises
  and sorts on `severity` before emitting (`_raise()` honours `self._finding_buffer`). A log is
  a stream and can't be re-ranked after the fact, so ordering has to happen before it's written.
  Findings raised *during* a run (`NEIGHBOR_LEASES_RELEASED`, the release-previous verdicts) go
  out immediately via the unbuffered path — on a long run those are live progress.
- **The verdict word is not printed on the log.** `verdict` still colours the line and still
  carries PASS/FAIL into the report; a bare `[FAIL]` beside a title mid-run reads as a judgement
  on the operator's network when the log's job is to say what happened. The run's conclusion is
  the `OUTCOME` roll-up (§5h).

## 5b. ARP-conflict eviction — why `_do_arp_conflict()` is shaped the way it is
`_do_arp_conflict()` is the mechanism eviction (§5f) uses to force a host off an address it's
*already lost the DHCP binding for* (re-acquired in §5f's re-acquisition step) — not a
general-purpose connectivity-denial tool.

Per target per round, three frames claiming the target's own IP:

1. broadcast ARP **request** (`build_garp(op=1)`) — the announcement form
2. broadcast ARP **reply** (`build_garp(op=2)`) — the unsolicited form; stacks honour different
   ones, which is why both go out
3. unicast ARP **reply** to the victim's own MAC (`build_arp_conflict_unicast()`, 2.7.1) — the
   *same claim as 2*, differing in delivery rather than form. Broadcast is the RFC 5227 form and
   is what conforming ACD listens for; this exists for the segments where the broadcast never
   arrives (wireless APs with client isolation drop station-to-station broadcast while still
   forwarding unicast to a known station; some stacks filter broadcast ARP far harder on the
   input path). Skipped when the neighbour's MAC is unknown, which the ARP inventory means is
   never the case in practice.

There is still no frame targeting the **default gateway's** mapping — that would cross from
denial-of-service into traffic-interception-adjacent territory and adds nothing eviction needs:
RFC 5227 §2.4 address conflict detection is what does the work (§5f), not a severed default
route. Frame 3 is not a reintroduction of it: it contests the victim's *own* address and points
at a blackhole, not at us.

The forged MAC is always bogus, recorded in `_evict.bogus_macs` so the ARP observer
(`_handle_evict_arp()`) can tell forged frames apart from the real owner's. **Never point it at
our own MAC** — blackhole is address-conflict detection (in scope); redirecting traffic through
us would be interception (out of scope, §1). It is generated **once per target and reused for
every round** (`_evict.forged_mac_by_ip`, 2.7.1), not re-rolled per round: §2.4 makes a host
cease only on a *repeat* conflict inside `DEFEND_INTERVAL`, and a new sender MAC each round can
read to a stack that tracks conflicts per peer as a different host's first conflict — precisely
the case it may defend again. A stable MAC also keeps the victim's ARP cache pointed at one
consistent blackhole. Distinct targets still get distinct MACs.

## 5c. Release phase, windowed sender, halt-on-control
Three pieces, run in `_common_prelude()` order (shared by both `exhaust` and `release`, §5f):

1. **Release phase** (`_release_phase()`, runs after `ctl-pre-new` for exhaust / after `ctl-pre-
   self` for release, before senders/re-acquisition). Sources the server identity from
   `_prelude_pre_control()` — **never** guess or fall back to `0.0.0.0`; `_discover_neighbors()`
   is ARP-only and never learns a DHCP server, so RELEASE must get the server identity from the
   control transaction. Excludes the gateway and the DHCP server from targets, feeds the freed
   list into re-acquisition (§5f) which is what actually confirms whether the RELEASE took
   (`_reprobe_released` is colour only — see its docstring for why an ARP re-probe structurally
   reads 0 even on full success). **No opt-out**: there is no `--no-release` or `--no-arp-scan`.
   Every later phase reads what the release phase and ARP sweep produce — release targets,
   re-acquisition, eviction, the `NeighborSummary` roll-call — so turning either off would
   silently hollow out the rest of the run rather than just make it quicker. The release phase
   still self-skips with a Debug when no server identity is confirmed; that's a precondition, not
   an option. `packets.build_release_v4()` carries an `Ether` layer since it's sent via L2
   `sendp()` — an L3-only packet would be malformed on the wire.
2. **Windowed sender** (`_exhaust_sender`, `_inflight`, `self._window`; also reused by
   re-acquisition's bounded batch, §5f). A bounded pipeline: at most `self._window` (starts at
   `cfg.window_initial=8`) DISCOVER/REQUEST transactions in flight at once, rather than an
   open-loop DISCOVER flood. **Only an ACK counts as a held address** (`_grow_window`) — growth is
   deliberately slow: `self._window_growth_accum` banks `cfg.window_growth_per_ack` (default
   **0.005**) per clean ACK, so **200** clean ACKs widen the window by one — NAKs, timeouts, and
   duplicate offers all shrink the window immediately (halve it) and wipe the accumulator
   (`_shrink_window`) instead of being pushed through. Growth is ~10000× slower than shrink, so a
   noisy run trends toward the floor of 1 rather than climbing back — that's the deliberate
   trade-off, see `_grow_window()`'s docstring. `--rate` is **gone from exhaust and release**
   (release's re-acquisition leg reuses this same window/backoff — `rate_limit_pps` is fixed at
   `EXHAUST_DEFAULT_RATE_PPS=500` for both so the limiter doesn't bind) but unchanged on
   `active-scan`/`release-previous`, which have no window of their own — **do not remove
   `RateLimiter` globally.**
3. **Halt-on-control** (`_trigger_halt`, `ControlDetected`, `HALTED` state). On the first of five
   signals — `nak_burst` (≥3/5s), `offer_silence` (existing), `link_down` (carrier poll in
   `_status_ticker`, `netutils.link_is_up()`), `timeout_storm` (≥5 consecutive), `duplicate_offers`
   (≥3 addresses offered to two of our MACs) — sending stops immediately but **leases already
   held are kept**, and `stop()` still runs both post-controls so the report is complete. First
   signal wins (`self._halt_signal` is set once). Don't make halt release leases or skip the
   post-control — that would break the verdict (§5d).

## 5d. Verdict: DHCP_STARVATION_ATTAINED / _NOT_ATTAINED
- **`DHCP_STARVATION_ATTAINED`** (`FAIL`): `acks > 0` **and** the post-run **new-MAC** control
  was denied **and** its own pre baseline succeeded. This is a failure of the network, not a
  success of the run.
- **`DHCP_STARVATION_NOT_ATTAINED`** (`PASS`): everything else, with `evidence["reason"]` — one
  of `control_fired` (+ `signal`/`leases_at_halt` from `self._halt_signal`), `pool_headroom_remaining`
  (+ `headroom`/`pool_size` from `_pool_headroom()`), `blocked_at_baseline`, or
  `inconclusive_baseline`. **Because halt-on-control (§5c) stops the run on the first signal,
  `ATTAINED` is rare by construction on a defended network** — `NOT_ATTAINED + control_fired`
  naming the control and the lease count it fired at is the expected, actionable result, not a
  consolation prize.
- **Pool estimate / headroom** (`PoolEstimate`, `_estimate_pool()`, `_pool_headroom()`): resolved
  from an explicit `--scope` (deterministic host count) or, failing that, the first OFFER's
  subnet (option 1) via `_note_offer_for_pool_estimate()`. `size=None` when neither is known —
  **never fabricate a denominator**; every surface (status, StatusTick, CLI line, web counter,
  report) must show `source`/`detail` alongside the number. `POOL_HEADROOM_LOW` is a separate,
  independent finding raised when the *pre-test* ARP baseline already shows ≥80% utilization.

## 5e. Lease journal + `release-previous`
`restore()` only releases leases the *currently running* engine object acquired, from memory —
useless once the process is killed, the box reboots, or you're back days later on a different
machine. The lease journal is the recovery path for that:

- **`core/journal.py`** — append-only JSONL, two record kinds (`ack` opens a lease, `released`
  closes it), folded at read time. `load_open_leases()` **never raises** on a bad file — a
  truncated final line (the exact killed-mid-write case this exists for), malformed JSON, or an
  unknown record kind is skipped with a warning. `default_path()` resolves under
  `$XDG_STATE_HOME` (or `~/.local/state`, via the effective user's passwd entry, not `$HOME` —
  `sudo` doesn't always reset it) — **never `/var/lib` or another system-owned path**; this is
  per-engagement data, not system state, and is deleted by the operator at engagement end.
  `SessionConfig.journal` (default `True`) / `--no-journal` opts out. `_handle_ack()` writes an
  `ack`; `restore()` and `_release_bindings()` write a `released`. Writes are best-effort
  (`OSError` → `ev.Debug`, never kills the run); `dry_run` suppresses journal writes the same as
  it suppresses packets.
- **`Mode.RELEASE_PREVIOUS`** (`_run_release_previous`/`_release_previous_worker` in
  `engine.py`) replays the journal for the *current* network: filters by interface, current
  CIDR (`--scope`, else the interface network — **refuses to run** if neither resolves; an
  unbounded sweep is exactly what this prevents), same-server (only evaluable when the
  pre-flight control actually learned a server identity — it usually won't on a genuinely
  exhausted pool, since no OFFER means no `server_id`; falls back to CIDR-only rather than
  silently excluding everything), then age (`--max-age`, default 7d — an optimisation, not a
  safety measure: a stale entry's MAC simply won't match the server's current binding per RFC
  2131 identity matching, so it's harmless either way — **do not add an ARP-liveness check**,
  it isn't needed and would skip legitimate targets). Groups releases by
  `(server_ip, server_mac)` before calling `_release_bindings()` — a journal can span multiple
  servers on one segment. `--passes` (default 2) resends the whole selected set since RELEASE
  has no reply (RFC 2131).
- Needs **no ARP sweep, no server discovery, no leasequery** — the journal already carries
  everything. The pre/post `_control_transaction(phase, client="new")` probes exist purely to
  produce a trustworthy verdict, stored in **`self._rp_pre_control`/`self._rp_post_control`**,
  deliberately *not* `self.control_pre`/`self.control_post` — those are read by the generic
  exhaust `_finalize_findings()`, and keeping them untouched is what makes that method a safe
  no-op for this mode. Findings raised directly in the worker (same pattern as
  `_release_phase()`), not through `_finalize_findings()`: `NO_RECOVERY_NEEDED`,
  `NO_JOURNAL_DATA`, `RELEASE_PREVIOUS_SCOPE_REQUIRED`, `POOL_RECOVERED`,
  `POOL_RECOVERY_PARTIAL`, `POOL_RECOVERY_FAILED` — reporting **addresses observed recovered**
  (re-folding the journal post-release), never just frames sent, same discipline as
  `_reprobe_released()`.
- **Not in `DESTRUCTIVE_MODES`** — it only releases leases the journal proves this tool took, so
  it adds no capability beyond what `exhaust` already used. It *is* in `RUN_ONCE_MODES` (§3),
  which is what the CLI's polling loop and web reaper use to detect a worker-thread run
  finishing — don't confuse the two sets.
- Default `--rate` is **50**, not 7 (see the inline comment in `cli/main.py`) — the one mode
  where a faster default is the right call (unicast to one server, run during an active outage).
- Strategies considered and deliberately narrowed away from, so don't re-propose them without
  a reason: **leasequery** (needs server cooperation this tool can't assume), **blind sweeps**
  (unbounded, and the whole point of the journal is to be bounded), and **ARP-derived targets**
  (an ARP-visible address says nothing about who holds its lease — §5f's `_reprobe_released()`
  note is the same trap). The journal is the only source that *proves* we took an address.

## 5f. Targeted re-acquisition + ARP-conflict eviction + shared `release` chain
Ties §5b/§5c together into the actual attack chain both `exhaust` and `release` run via
`_common_prelude()`: ARP inventory → control/self [→ control/new, exhaust only] → release →
**re-acquisition** → **eviction**.

- **Re-acquisition** (`_reacquire_phase(freed)`, `_finish_release()`). Pushes one targeted
  DISCOVER per freed `(mac, ip)` — fresh random MAC, DHCP **option 50** (`requested_addr`) asking
  for the specific address just RELEASEd — into the *existing* windowed `_inflight` pipeline
  (no parallel sender). `_handle_ack()`/`_handle_nak()`/`_reap_timeouts()` classify each into
  `granted` (offer matched the request) / `offered_different` (server ignored option 50) /
  `naked` (REQUEST refused) / `no_response`, tracked in `_reacquire_targets`
  (xid→ip)/`_reacquire_outcomes` (xid→outcome). `NEIGHBOR_LEASES_RELEASED`'s evidence is the
  re-acquisition `granted` count, not an ARP re-probe — a released victim keeps using its old
  address until its own lease's T1, with no observable way to tell "stopped == 0" apart from
  "the server ignored RELEASE", so an ARP-based measurement would structurally read 0 even on a
  fully successful RELEASE. Under `exhaust`, re-acquisition runs **after** the pool has been
  drained by the sender, not in the prelude: while the pool has headroom, RFC 2131 §4.3.1 lets
  the server prefer a fresh address over honouring option 50, so `granted=0` would say nothing
  either way until the free list is actually empty. `release` re-acquires inline (it never drains
  anything, so the ordering doesn't apply) and its finding says the evidence is weaker.
- **ARP-conflict eviction** (`_evict_phase()`/`_evict_worker()`/`_measure_eviction()`, `_do_arp_
  conflict()` — see §5b for the frame shape). Targets **only** addresses this run actually
  re-acquired (`granted`, from re-acquisition above) — conflicting with an address still bound to
  the victim just makes them defend and re-ARP; conflicting with one *we* now hold is what forces
  the DECLINE/restart. Excludes gateway and DHCP server (via `_prelude_pre_control()` — see
  below). Guarded by `cfg.evict` (default `True`) / `--no-evict`. `evict_rounds` (default 6,
  **must be ≥ 2**) spaced `timeouts.evict_interval` (default 1.5s, **must stay < 10.0s** —
  RFC 5227 §2.4's `DEFEND_INTERVAL`: a host defends once, then MUST cease on a *second* conflict
  inside that window; spaced 10s+ apart, each round looks like a fresh independently-defensible
  conflict and the host never gives up the address). `SessionConfig.__post_init__` raises
  `ConfigError` naming RFC 5227 if either constraint is violated. The 2.7.1 defaults (was 4 ×
  3.0s) put all six conflicts inside a *single* `DEFEND_INTERVAL` (t=0…7.5s) rather than four
  straddling its edge, so one dropped or filtered frame no longer costs the eviction — and the
  phase finishes marginally sooner than it used to. Denser spacing buys nothing: back-to-back
  frames get coalesced into one conflict event by the victim's ARP input path, so what counts is
  separate arrivals, not frame count. After the last round, sleeps
  `evict_settle` (default 16.0s) before measuring — gives a DECLINE/restart/APIPA time to land.
  **Outcome ladder** (causal/temporal order, not evidence-strength — a host that reaches a later
  rung passed through the earlier ones, whether or not we directly observed them):
  `no_reaction` < `defended` (ARP announcement from the real owner MAC — our frame was delivered,
  DAI isn't filtering) < `declined` (DHCPDECLINE from the victim — gold-standard proof it gave up
  the address) < `rediscovered` (fresh DISCOVER from the victim after the conflict — restarted at
  INIT) < `discover_unanswered` (that DISCOVER got no OFFER — real denial of service) < `apipa`
  (victim's MAC now sourcing ARP from `169.254.0.0/16` — full eviction, DHCP totally failed).
  `eviction.rung_max()` always keeps the highest rung reached; `_handle_evict_arp()` covers
  `defended`/`apipa` (ignoring our own forged MACs via `_evict.bogus_macs`), `_handle_client_
  decline()` covers `declined`, phase 2's foreign-DISCOVER tracking covers
  `rediscovered`/`discover_unanswered`.
  **Findings are mode-aware** — this is the one place `exhaust` and `release` genuinely diverge:
  under `exhaust` the pool is meant to be drained, so even a bare `rediscovered` (DISCOVER
  answered) is already evidence the address was taken by force, so `declined`+ all count as
  `CLIENTS_EVICTED_FROM_ADDRESSES` (FAIL). Under `release` the pool is **never** drained — a
  clean restart-and-immediate-reacquire is the whole point of the mode, not harm — so only
  `discover_unanswered`/`apipa` count as FAIL there; `declined`/`rediscovered` land in
  `CLIENTS_DEFENDED_ADDRESSES` (INCONCLUSIVE, "reacted but not denied service") instead. Don't
  collapse this distinction back to one threshold.
  **`CLIENTS_HOLDING_STOLEN_LEASES` (FAIL/high, 2.7.1) is the exception to all of the above**:
  targets at the `defended` rung whose address is in `_granted_ips()` are held out of `reacted`
  and reported separately, because "defended" describes the ARP exchange while the binding
  underneath was already reassigned to us — a pending outage with a known cause, not the
  INCONCLUSIVE "reacted but unharmed" case. It is **mode-independent** (it turns only on the
  server having handed us the binding, which `release` does as thoroughly as `exhaust`) and it is
  raised **alongside** `CLIENTS_EVICTED_FROM_ADDRESSES`, outside the if/elif chain, not instead
  of it — the two describe disjoint sets of hosts, so a run that evicts two targets and leaves a
  third on a dead binding has two things to report. `ARP_CONFLICTS_UNANSWERED` is suppressed when
  `holding` is non-empty (something plainly did react).
  `_granted_ips()` is the single definition of "the server bound this to us", shared by eviction
  target selection, the roll-call and these findings — they must never disagree about whose lease
  we hold. Under dry-run every outcome reads
  `no_reaction` because nothing was ever sent — not evidence of anything — so the whole findings
  block is gated on `not cfg.dry_run`; `DRY_RUN_SUMMARY` covers that case (`would_evict` count).
  **No PASS verdict exists here on purpose** — "nobody reacted" can't be told apart from "the
  frames never arrived" from this vantage point.
- **`release` shares `_common_prelude()`**, not its own ARP-only, sniffer-less path — the sniffer
  must be up for the control transaction's OFFER/ACK to arrive at all, so `_run_release()` starts
  one exactly like `_run_exhaust()` does (skipped under `offline`). `release`'s own pre/self
  control outcome goes into **`self._rel_pre_control`**, never `self.control_pre` — same
  precedent as `_rp_pre_control` (§5e) — so `_finalize_findings()`'s `DHCP_STARVATION_*`/
  `CONTROL_BASELINE_FAILED`/`NEW_CLIENT_BLOCKED_AT_BASELINE` derivations (which read
  `control_pre`/`control_pre_new`) stay a no-op for a release run without an explicit mode gate.
  `_release_phase()`/`_finish_release()`/`_evict_phase()` all read whichever one applies via
  **`_prelude_pre_control()`** rather than `self.control_pre` directly — if you add a new phase
  that needs the server identity, read it through that helper, not the raw attribute. `release`
  never runs the `client="new"` control leg (exhaust's starvation baseline, meaningless here).
  Eviction runs **inline in `_release_worker()`**, before the thread exits — not from `stop()`
  like exhaust — because the sniffer needs to still be up to observe eviction's rounds+settle,
  and for `release` that means staying inside the worker thread `stop()` is about to `join()`.

## 5g. Race-freed addresses — grab a freed address ahead of the untargeted flood
Answers a gap §5f's re-acquisition doesn't cover: re-acquisition only reacts to addresses **we**
just freed via our own RELEASE phase; any address that becomes free *some other way* mid-run (a
NAK'd renewal, a DECLINE, a rediscovering neighbor) previously only got picked up if the
untargeted exhaust flood happened to land on it. `exhaust` only — `release` has no concurrent
flood for "racing ahead of" to mean anything against.

- **Triggers, ranked by how strongly they imply the *server* now considers the binding free**
  (not just that the client stopped using it — the server can hold a binding to lease expiry
  regardless of what the client does), all broadcast/observable. **DHCPRELEASE is deliberately
  never a trigger** — it's unicast to the server (`build_release_v4`'s `Ether(dst=server_mac or
  broadcast)`), invisible on a switched segment.
  1. **Foreign NAK** (strongest) — `_handle_nak()`'s foreign branch resolves the address via
     `_foreign_requests` (populated by `_handle_foreign_request()` off any foreign REQUEST) and
     calls `_maybe_race(ip, "nak")`.
  2. **Foreign DECLINE** — `_handle_client_decline()`'s `else` branch (a decline from a MAC that
     isn't a known eviction target) resolves the address and calls `_maybe_race(ip, "decline")`.
     Weaker signal (most servers quarantine a declined address rather than freeing it), kept on
     by default so the win/lose counters can show the actual hit rate empirically.
  3. **Foreign DISCOVER from a known neighbor** (weakest) — opt-in only via
     `cfg.race_on_rediscover` (default **False**), inside `_handle_foreign_discover()`'s
     `first_sighting` branch.
- **One entry point, `_maybe_race(ip, why)`**, so every exclusion lives in exactly one place:
  unresolved ip, already queued this run (`_race.raced_ips`), already targeted by *our own*
  re-acquisition (`ip in self._reacquire_targets.values()` — without this, every one of the
  release phase's own victims re-DISCOVERing/DECLINEing right after being released+evicted would
  queue a duplicate race for an address we already hold), and the gateway/DHCP server (via
  `_prelude_pre_control()`/`_release_gateway()`). **Deliberately not `_is_own_traffic()`** —
  `_release_bindings()` spoofs the victim's MAC as both `chaddr` and Ethernet source with a fresh
  xid never registered in `_inflight`, so that filter structurally cannot recognise our own
  release-phase frames.
- **Race state is entirely separate from `_reacquire_targets`/`_reacquire_outcomes`** —
  `_race.queue`/`_race.raced_ips`/`_race.reasons`/`_race.targets`/`_race.outcomes`/`_race.triggers`/
  `_race.inflight`. This is load-bearing: `_evict_phase()` derives its target set (`granted_ips`)
  from `_reacquire_targets`/`_reacquire_outcomes` alone — writing a race xid into either would
  silently widen eviction's blast radius past what §5f documents ("targets **only** addresses
  this run actually re-acquired"). A regression test asserts this never happens.
- **`_exhaust_sender()` drains the race queue ahead of the untargeted path**, one per loop
  iteration, gated on `self._race.inflight < cfg.race_max_inflight` (default 4) —
  **deliberately not gated on window/inflight room** (`self._window - len(self._inflight)`): a
  race is a single, bounded, time-sensitive send, not a sustained load pattern, so it takes a
  reserve of slots *above* the window rather than waiting a turn. This is a bounded overtake, not
  a window bypass — §5c's window exists to avoid stalling on pending-offer-table saturation;
  don't widen the reserve into a general bypass. Every race send still goes through `_send()`'s
  rate limiter, but that limiter is **not** a meaningful backstop in exhaust (`rate_limit_pps`
  pinned at `EXHAUST_DEFAULT_RATE_PPS=500`, deliberately non-binding) — the reserve is the only
  real bound.
- **`_classify_targeted(xid, outcome, overwrite=True)`** is the outcome classifier shared by
  re-acquisition and racing — `granted`/`offered_different` (from `_handle_ack()`), `naked`
  (from `_handle_nak()`'s owned branch), `no_response` (from `_reap_timeouts()`, `overwrite=
  False` so a later NAK/ACK for a xid that already timed out doesn't get silently discarded).
  Whichever of `_reacquire_targets`/`_race.targets` owns the xid is where the outcome lands;
  decrements `_race.inflight` exactly once, only for a race-owned xid.
- **Counters land in all four required surfaces**: `engine._counters()`/`.status()`,
  `cli/render.py`'s `status_summary()`, `web/static/app.js`'s `StatusTick` handler.
- **`RACED_FREED_ADDRESSES` (INFO)**, raised only when `self.races > 0` **and** `not
  cfg.dry_run` — under dry-run every race send is suppressed at `_send()`'s chokepoint so every
  outcome would misleadingly read `no_response`; `DRY_RUN_SUMMARY` carries a `would_race` count
  instead, same pattern as eviction's `would_evict` (§5f). Evidence: `attempted`/
  `won`(`granted`)/`lost`(`offered_different`+`naked`+`no_response`)/`by_outcome`/`by_trigger`.
  Not PASS/FAIL by design — winning a race is the tool working as intended, not itself a network
  weakness; `DHCP_STARVATION_*`/`FOREIGN_DISCOVERS_UNANSWERED` already report the weakness, if
  any.
- **Config**: `SessionConfig.race_freed_addresses` (default `True`, `--no-race-freed` to opt
  out), `race_on_rediscover` (default `False`, `--race-on-rediscover` to opt in),
  `race_max_inflight` (default 4) — all exhaust-only; the flags don't exist on `release`'s
  argparse subcommand rather than existing and silently doing nothing.
- **Ownership checks this feature depends on** — any new handler for OFFER/ACK/NAK/DECLINE must
  check xid ownership (`xid in self._inflight`) before acting on it, same as §8's gotcha:
  `_handle_nak()` counts only NAKs addressed to our own xids toward `self.naks`/window-shrink/
  `nak_burst`, with the foreign branch feeding the race trigger instead; `_handle_offer()` and
  `_handle_ack()` likewise only build a REQUEST or register/journal/count a lease for a xid we
  actually own — an unowned ACK being journaled would let `restore()`/`release-previous` later
  DHCPRELEASE a genuine third party's active lease. Both still passively learn from foreign
  traffic where safe (server identity, fingerprints, marking a tracked foreign DISCOVER as
  answered); only the send/mutate side requires ownership.

## 5h. What a run ends with, on the log
In order, after the sender/eviction finish: the findings (worst severity first, §5a), then
`NeighborSummary` — one row per **every** discovered host (`ip  mac  [hostname]  outcome`,
worst first) — then an `OUTCOME` roll-up grouping those rows into "N host(s) did X".

- `_emit_neighbor_summary()` runs **after** `_finalize_findings()` in `stop()`, so the roll-call
  is the last thing on the log: it's the conclusion an operator reads, not something to scroll
  past on the way to a verdict.
- The `OUTCOME` block is **counts of hosts and what happened to them, never a verdict.** The
  findings own pass/fail; a second differently-worded judgement of the same run on the same
  screen is the drift `_run_summary_steps()` is already documented to avoid. A test asserts the
  block contains no PASS/FAIL vocabulary.
- `NEIGHBORS_OBSERVED` is deliberately **not** printed to the log (`FINDINGS_NOT_LOGGED` in
  `app.js`) — it is the same rows as the block directly beneath it. It stays in
  `report["findings"]`, which is the only place the roll-call reaches the JSON/HTML export.
- Hostnames come from DHCP option 12 on a foreign DISCOVER only, so most ARP-only neighbours
  have none; the column is omitted entirely when nobody does, and is never inferred from a
  fingerprint.

## 6. Modes (`Mode` enum)
`EXHAUST` (default; runs the shared prelude — ARP inventory, control, release, re-acquisition —
then its windowed sender, then eviction in `stop()` — §5c/§5f), `SCAN` (passive, read-only),
`ACTIVE_SCAN` (ARP sweep + one DHCP INFORM; non-destructive, scope required, bounded
post-INFORM listen — §5), `RELEASE_NEIGHBORS` (destructive; runs the *same* shared prelude as
exhaust minus the windowed sender, then eviction inline — §5f; web UI label "DHCP Release Active
Clients"), `RELEASE_PREVIOUS` (recovery; replays the lease journal — §5e; not destructive). The
web dropdown (`web/static/index.html`) doesn't offer `SCAN` as an option but the CLI subcommand
and `config_from_payload()` still accept it — don't remove either.

## 7. How to run tests / lint
See `CONTRIBUTING.md` for the commands. Two things worth knowing at the design level:
- Everything is unit-tested **without root** by monkeypatching `dhcpig.core.engine.sendp` (and,
  for the handful of scapy/netutils functions tests patch by source-module path rather than via
  the sendp seam, calling them through the module object at call time rather than importing the
  bare name — see `core/netutils.py`'s row in §3's file table for why that distinction matters).
- The one integration test (`tests/integration/test_exhaust_live.py`, `@pytest.mark.integration`)
  needs root + Linux (veth pair + fake DHCP server); it's deselected by default (`addopts` in
  `pyproject.toml`). Run it with `make integration` on a real Linux box.

## 8. Gotchas / decisions already made (don't re-litigate)
- **`dry_run` and `offline` are genuinely different concerns.** `offline` is the hard "never
  touch a socket" switch (no sniffer, no `sendp`, no `srp()`) — it's what makes web/CLI tests and
  a no-root preview possible. `dry_run` alone runs every non-destructive phase **for real**: the
  ARP sweep, and the control transaction's own DISCOVER/REQUEST/RELEASE — it's a genuine
  reconnaissance pass, not a shape-only preview, and it needs a raw-capable interface + root. It
  only suppresses **mutating** sends: release, re-acquisition, the windowed exhaust sender,
  eviction. The mechanism is `_send(pkt, probe=False)`'s `probe` parameter — `probe=True` marks
  traffic a legitimate client on this segment would send anyway and that self-cleans (bypasses
  dry-run suppression, never bypasses `offline`); it appears at exactly two call sites: the ARP
  sweep (`_discover_neighbors`'s `srp()` doesn't go through `_send()` at all, so it's gated on
  `offline` directly) and the control transaction (`_control_transaction()`'s three
  `_send(..., probe=True)` calls). Don't add a third `probe=True` site without re-reading why
  only these two exist.
- **The sniffer BPF is `port 67 or port 68`**, both directions — needed to see our own echoed
  sends and, more importantly, foreign DISCOVERs/DHCPDECLINEs, which are client→server. This
  means `_on_dhcp()` also receives our *own* outbound traffic reflected back; the self-filter
  (`_is_own_traffic()`) drops it before it reaches foreign-DISCOVER handling, keyed on Ethernet
  src being one of `_our_macs` or xid membership in `_inflight`/`_control_xid`. **Only apply the
  self-filter to message types we actually send ourselves** (DISCOVER/REQUEST/RELEASE) — never to
  OFFER/ACK/NAK/DECLINE, none of which we ever originate (DECLINE included: we never send one);
  `_on_dhcp()`'s dispatch checks those never-self-originated types first, for exactly this reason.
- **For OFFER/ACK/NAK/DECLINE, `xid in self._inflight` is the ownership test — not
  `_is_own_traffic()`.** Since we never originate these, the self-filter above doesn't apply to
  them, but that means a naive handler processes *every* such packet on the segment as if it were
  ours. Any new handler for these four message types must check xid ownership before acting, and
  should still passively learn from foreign traffic where safe (server identity, fingerprints,
  marking a tracked foreign DISCOVER as answered) — the risk is on the *send/mutate* side, not
  observation. See §5g's closing bullet for the two real bugs this pattern was written to prevent.
- **JSON serialization**: always route event/report dicts through `jsonable()` — a raw `IPVersion`
  enum will crash `json.dumps`. Regression test exists.
- **Ethernet source MAC** defaults to the per-client random MAC (`spoof_ethernet_src=True`) so
  each simulated client is distinct at L2 (exercises port-security/snooping). `--no-spoof-eth-src`
  for Wi-Fi, where the AP will drop frames from a MAC it hasn't associated.
- **Server-id/client-MAC handling in `packets.py`** (server-id = opt54 else siaddr; client MAC =
  `chaddr[:6]`; REQUEST includes option-61; broadcast flag 0x8000) has regression tests. Don't
  lose them.
- **Fingerprint DB is `data/satori_dhcp_fingerprints.json`** (derived from Satori, 319
  option-55 and 187 vendor-class signatures; queryable and regenerable via
  `data/satori-merge.py`). **It is GPL-2.0-or-later, deliberately** — it replaced a
  PacketFence/Fingerbank-derived table that was ODbL/DbCL, so the project now ships under one
  license end to end. A test asserts the bundled `license` field, so a relicensed reimport
  fails loudly rather than quietly. Three rungs, and the confidence bands keep them apart:
  exact/order-sensitive option-55 (90, or 75 with more than one candidate), then exact option-60
  vendor class (70 / 55), then `from_mac()` OUI-only (15). A signature with more than one
  candidate keeps them all and is flagged `(ambiguous xN)` in `matched_via`. `os` **is** now
  populated — the Satori data separates OS from device — but only when every candidate agrees on
  one, since "Windows 10 / iOS 12" is two guesses rather than an answer.
- **Neighbors ↔ fingerprints are correlated by MAC** (`engine._note_neighbor` /
  `_note_fingerprint`, `_neighbors_by_mac` / `_fp_by_mac`): whichever signal arrives first (ARP
  is-at vs. a DHCP packet from that MAC), the other backfills it and re-emits `NeighborFound` so
  the web UI's Neighbors tab and reports show OS/Device. Keep `app.js`'s neighbor Map keyed by
  MAC (not IP) if you touch it — IP-keying was the original bug that kept OS/Device blank.
- **Web backend is stdlib only** — no FastAPI/Flask/pydantic; frontend is vanilla JS, no build,
  no CDN. Charting is a hand-rolled canvas sparkline (not Chart.js). Keep it dependency-free.
- **Verbosity**: engine emits `Debug` events always; the CLI shows them only at `-v3`, the web
  filters client-side via the dropdown (each log line tagged level 0–3; errors always show).
- **Status heartbeat**: `_status_ticker()` emits `StatusTick` every `status_interval` (5s) with
  totals *and* per-window deltas — deltas are the point, totals alone don't show whether
  anything is still happening. The thread is deliberately **not** in `_threads`: callers treat
  that list as "work in progress" and a forever-thread there would stall destructive runs.
- **OUI fallback confidence is 15 on purpose.** A NIC vendor is not an OS; keep it far below
  DHCP matches (75–98) so it can never be mistaken for one, and keep `os=None` for these.
- **`--rate` removal covers `exhaust` and `release`, not every mode.** It's gone from both
  CLI/web surfaces (release's re-acquisition leg reuses exhaust's window/backoff — §5c) but
  still required on `active-scan`/`release-previous`, which have no window of their own. Don't
  remove `RateLimiter`/`rate.acquire()` from `_send()` — it's still the only thing pacing
  `active-scan`/`release-previous` (`scan` sends nothing at all; `release`'s eviction sub-phase
  paces itself via `evict_rounds`/`evict_interval`, not `--rate`; `release`'s own RELEASE-send
  loop is unwindowed but now runs at the same non-binding `rate_limit_pps` as exhaust).
- **Halt-on-control never releases leases.** `_trigger_halt()` stops the sender but leaves
  `Cleanup` untouched; there's no auto-restore-on-exit to accidentally trigger either.
  If you're tempted to auto-release on halt, don't — the post-controls need the leases held to
  be meaningful.
- **Pool-size estimates must never be presented as authoritative.** `PoolEstimate.size` is either
  `None` (show `—`) or a number that must always render next to its `source`/`detail` — a
  fabricated-looking denominator is exactly the kind of false confidence the two-leg control
  work (§5a) was meant to eliminate. Don't cache/round it into something that loses that context.

## 9. Current status
**2.6.1** (`pyproject.toml` + `dhcpig.__version__`). **361 unit tests pass; ruff clean.** See
`CHANGELOG.md` for the full release-by-release history (the legacy `pig.py` compatibility layer
was removed in 2.6.0 — `dhcpig exhaust`/`dhcpig release` are the only entry points now).

**Validation status — read this before trusting a result.** One real exhaust run against a live
`/22` on a Kali VM (pcap reviewed) is the *only* hardware validation this codebase has. That run
exposed the pending-offer saturation bug §5c fixes and the renewal-vs-fresh-allocation control
bug §5a fixes. **Re-acquisition, eviction, the `release` chain, racing, and `release-previous`
have passing unit tests and zero live-network confirmation.** Treat their findings as unproven
until that changes.

## 10. Open follow-ups (not yet done)
- **IPv6**: `IPVersion.V6` is a seam only; v6 packet builders/flows are NOT implemented (`start()`
  refuses rather than silently sending v4 while listening for v6). The v4 modes are the working
  ones.
- **Fingerprint coverage**: `satori_dhcp_fingerprints.json` has 319 option-55 and 187
  vendor-class signatures; refresh it with `python3 data/satori-merge.py --convert
  <satori>/fingerprints/dhcp.xml` against a newer Satori checkout. Satori's 131 `partial`
  vendor-class tests are **not** imported — they are substring matches and need a different
  matcher than the dict lookup in `core/fingerprint.py`; add them in both places together if
  wanted.
- **Active-scan** fingerprints the DHCP *server* via the INFORM reply; ARP-only neighbours now
  get MAC-vendor identification (`core/oui.py`), but never an OS — that needs DHCP evidence.
- **Integration coverage** only exercises exhaust; add netns cases for release/active-scan, and
  ideally one that actually exercises re-acquisition + eviction end to end. `release-previous`
  also needs one, but it requires rewriting the `FakeDhcpServer` fixture in
  `tests/integration/test_exhaust_live.py` first — it currently has an unbounded address pool and
  never NAKs, so it can't simulate an exhausted-then-recovered pool at all. Give it a bounded
  pool, NAK-when-full behavior, and RELEASE handling that actually frees a binding, then: exhaust
  to drain it, destroy the engine object (simulating a killed process), run `release-previous
  --journal <path>` on a fresh engine, assert a new MAC gets an address afterward.
- **Web UI** exposes `release-previous` mode selection, scope, and rate, but not
  `--journal`/`--max-age`/`--any-server`/`--passes` as dedicated controls yet (the backend/schema
  round-trip already supports them — see `web/schemas.py` — just no HTML inputs). Add a config
  sub-panel following the `#ratecfg`/`#destcfg` show/hide pattern in `app.js`'s `onModeChange()`
  if the web UI needs full parity with the CLI.
- **Packaging** `.deb`/`.desktop`/`dhcpig.1` exist under `packaging/` but haven't been built/
  tested on a real Kali box yet. CI does build a wheel and confirm
  `data/satori_dhcp_fingerprints.json` ships inside it (`.github/workflows/ci.yml`'s
  `build-check` job) — that specific packaging regression is covered; a full `.deb` build on
  real Kali is still not.

## 11. Conventions
Ruff (line length 100) + format; type hints throughout `core`; dataclasses over dicts; no
module-level mutable globals in `core`. Add a test with every behavior change. Keep `core`
import-clean of CLI/web/`print`.
