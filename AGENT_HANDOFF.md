# DHCPig 2.x — Agent Handoff

> Read this first. It transfers everything you need to keep working on this codebase without
> re-deriving it. Companion docs: `DHCPig-SoT.md` (product spec, CUJs, roadmap) and
> `DHCPig-Implementation-Brief.md` (original build order) — both in the user's outputs folder,
> not the repo.

## 1. What this is
A whitehat DHCP network-hardening validation tool — a full rewrite of the legacy single-file
`pig.py` into an installable, tested package. It exhausts DHCP pools, releases neighbor leases
and re-acquires them by name, evicts hosts off addresses via forged RFC 5227 ARP conflicts, and
passively/actively fingerprints hosts — to prove a network defends against those (DHCP snooping,
port security, Dynamic ARP Inspection, etc.). **Never add capability that enables host
compromise or lateral movement; it stays an L2/L3 DHCP/ARP stress + audit tool.**

## 2. Where the code lives / how paths work
- **Canonical working copy:** `/Users/kamorin/Documents/code/DHCPig` (the user's Mac; a
  connected Cowork folder). Edit here with Read/Write/Edit.
- **In the sandbox `mcp__workspace__bash`** the same folder is `/sessions/<id>/mnt/DHCPig`.
  Use that path for bash only. (There is a stale earlier copy under `.../outputs/DHCPig` — ignore it.)
- The user runs it on a **Kali VM** where the Mac folder is mounted at `/mnt/hgfs/code/DHCPig`
  (VMware shared folder) — so your edits appear on the VM immediately; they just restart the process.

## 3. Architecture (the one mental model that matters)
Three layers, strictly separated:
- **`src/dhcpig/core/`** — the engine. **UI-free: never calls `print`; it only emits events.**
- **`src/dhcpig/cli/`** — `dhcpig` command; subscribes to the event bus and prints.
- **`src/dhcpig/web/`** — `dhcpig-web` stdlib HTTP server + SSE; subscribes and streams JSON.

Both front ends drive the SAME `DhcpEngine` and never touch scapy directly.

### Core files
| File | Role |
|------|------|
| `core/models.py` | dataclasses/enums: `SessionConfig`, `Lease`, `ServerInfo`, `Neighbor`, `HostFingerprint`, `PoolEstimate`, `Mode`, `IPVersion`, `Timeouts`. `DESTRUCTIVE_MODES`, `SCOPE_REQUIRED_MODES`, `EXHAUST_DEFAULT_RATE_PPS`. `ControlOutcome` carries `server_mac`; `Lease` carries `server_mac`. |
| `core/packets.py` | **pure** scapy builders/parsers (no I/O). `build_discover_v4` (takes `requested_addr` for option 50 — see §5f), `build_request_v4`, `build_release_v4` (now emits an `Ether` layer — see §5c), `build_inform_v4`, `build_garp` (op=1/2 — reused by eviction, see §5b), `server_identifier`, `client_mac_from_offer`, `parse_offer`, `is_offer`/`is_ack`/`is_nak`/`is_discover`/`is_decline`, `dhcp_option`. `build_arp_poison` was removed (2.3) — don't re-add it, see §5b. |
| `core/engine.py` | `DhcpEngine(cfg, bus)`: `start/stop/status/restore`. One state machine, `threading.Event` stop, worker threads + sniffer. **Every outbound frame goes through `_send()`** (the single chokepoint; `probe=True` bypasses dry-run suppression only, never `offline` — see §8). Control transaction, release phase, re-acquisition, eviction, windowed sender, halt detection, pool estimate, and findings derivation all live here (§5a–§5f). Debug via `_debug()`. |
| `core/events.py` | `EventBus` (thread-safe), event dataclasses (including `ControlDetected`, `ForeignDiscover`, `ClientEvicted`), `to_dict()` + `jsonable()` (recursively converts enums/bytes/Path so JSON never breaks). |
| `core/safety.py` | `ScopeGuard`, `RateLimiter` (token bucket — still wired through `_send()` for every mode; see §5c for why exhaust no longer takes `--rate`), `Cleanup` (tracks leases for restore). No `authorize()` — the gate was removed, see §5. |
| `core/sniffer.py` | thin `AsyncSniffer` wrapper. BPF widened (2.3) to see client→server traffic too (`port 67 or port 68`, both directions) — needed to observe foreign DISCOVERs and DHCPDECLINEs; see §5f. |
| `core/fingerprint.py` | `extract_signature()` + `resolve()`: exact option-55 match against `data/packetfence_dhcp_fingerprints.json`, else `from_mac()` OUI-only. `DB_VERSION`. |
| `core/oui.py` | MAC → hardware vendor. scapy's bundled Wireshark/IEEE `manuf` DB (~50k) only; locally-administered MACs labelled as randomised. No bundled IEEE copy needed — scapy already ships one. |
| `core/reporting.py` | `SessionRecorder` → JSON/CSV/HTML (`render()` / `export()`). Neighbors deduped by MAC. Tracks `final_status` from `SessionEnded` to surface the pool estimate in reports. |
| `core/netutils.py` | iface enumeration, `iface_network_cidr()` (scope auto-fill), `default_gateway()` (release-phase/eviction target exclusion via `_release_gateway()`), `link_is_up()` (carrier poll for `link_down` halt detection — `None` fail-open, see §5c), IP math, `random_mac()`. |
| `core/journal.py` | Lease journal for recovery (2.2, §5e): append-only JSONL, `default_path()` (XDG state dir, never `/var/lib`), `record_ack`/`record_released`, `load_open_leases()` (never raises — crash-tolerant). Powers `Mode.RELEASE_PREVIOUS`. |
| `core/exceptions.py` | `DhcpigError`, `ConfigError`, `OutOfScope`, `SessionConflict`. |
| `data/packetfence_dhcp_fingerprints.json` | Static PacketFence-only fingerprints (535), queryable standalone via `data/fingerprint-merge.py`. `data/DATA_ATTRIBUTION.md`. |

### Web files
`web/server.py` (`WebApp` + `Handler` + `main`), `web/api.py` (route handlers → `(status,dict)`),
`web/stream.py` (`SseSubscriber`: bus→per-client `queue.Queue`→SSE frames), `web/auth.py`
(loopback + bearer token + same-origin + security headers), `web/schemas.py` (dataclass
validation, no pydantic; `config_from_payload`, `as_cli`), `web/static/{index.html,app.js,styles.css,icon.svg}`
(vanilla JS SPA, no build step, hand-rolled canvas sparkline). `icon.svg` is the hacker-pig
logo -- served unauthenticated alongside the css/js because the browser fetches it as a
favicon before any token exists; the same file is copied to `packaging/dhcpig.svg` for the
`.desktop` entry and the README header.

## 4. Event flow
`engine (worker threads) → bus.emit(Event) → subscribers`. CLI `Renderer.handle` prints;
web `SseSubscriber` puts `to_dict(event)` on a queue, the `/events` handler writes SSE frames,
the browser's `EventSource` updates the DOM. **Handlers must be cheap/non-blocking.**

## 5. Safety model
- **The authorization gate was removed at the maintainer's request** (2026-07). There is no
  `--i-am-authorized`, no `authorize()`, no `Unauthorized`, no confirmation modal or prompt, and
  `--scope` is optional for `release` — with none given it falls back to the interface's own
  network via `_sweep_cidrs()`. **`dhcpig release eth0` will target the whole segment, and now
  runs the full re-acquisition + eviction chain against it (§5f) — a bigger blast radius than the
  name alone suggests.** Don't re-add the gate without asking, and don't quietly remove what's
  left below either. (`Mode.GARP_DOS` was retired in 2.3 — see §5b.)
- What still bounds a run: the windowed handshake pipeline for `exhaust` (§5c), `--rate` (default
  7 pps) for every other mode, `--dry-run`/`--no-evict`, `ScopeGuard` when a scope *is* supplied,
  and `Cleanup`/`restore()` for lease reversal.
- `active-scan` is non-destructive but **requires `--scope`** (`ConfigError` if missing) — this
  is the one remaining hard requirement, so its sweep can't be unbounded.
- **`_send()` is the chokepoint**: scope check (drops out-of-scope, emits `Skipped`), rate limit,
  `offline` (hard "never touch a socket" switch), and `dry_run` (builds + accounts, never calls
  `sendp` — **unless** `probe=True`, see §8). Keep all sends flowing through it.
- `restore()` releases exactly the leases in `Cleanup`. **There is no auto-restore-on-exit
  anymore** (`restore_on_exit`/`--restore-on-exit` were removed, 2.2) — leases are always kept
  after a run so the exhausted state can be verified; the operator cleans up explicitly via
  `dhcpig restore <iface>` or `POST /api/session/restore` (same-process/session only — the UI's
  Restore button was removed at the maintainer's request) or, once that process is gone,
  `dhcpig release-previous <iface>` replaying the lease journal. Don't silently reintroduce
  an auto-restore flag — retention followed by an explicit recovery step is deliberate.

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
- **`EXHAUSTED` means the server stopped serving — nothing else.** There is no lease cap
  (`--max-leases` was removed precisely so nothing self-imposed could be mistaken for
  exhaustion). Exhaustion needs offers to have flowed then stopped (`_offers_seen_any` +
  `offer_silence`) and is only `confirmed=True` once the post control is also denied.
- **`HALTED` means a defensive control fired mid-run** (§5c) — distinct from `EXHAUSTED`. Both
  route through the same `_trigger_halt()` → `_finish_in_background()` path.
- **Runs finalize themselves.** `_finish_in_background()` spawns a finisher thread that calls
  `stop()` when a terminal condition hits. This is required, not cosmetic: `stop()` joins the
  worker threads, so the sender cannot call it directly, and without it the web UI sat idle
  after the pool drained (senders dead, no post-control, no verdict) until Stop was pressed.
  `OffersCeased` reports the quiet-period countdown so the UI shows progress meanwhile.
- **Findings** (`_finalize_findings`, `Finding`): id/verdict/severity/evidence/recommendation,
  emitted as `FindingRaised`, collected into `report["findings"]`. Add new findings there. The
  exhaustion verdict is `DHCP_STARVATION_ATTAINED` (FAIL) / `DHCP_STARVATION_NOT_ATTAINED` (PASS)
  — see §5d. **`verdict` is what the UI colors off, never `id`** — keep it that way.
- **`RUN_SUMMARY` (INFO) is the one finding raised unconditionally**, first, in every mode
  including dry-run and read-only scans — it's the only finding a reader can rely on being
  present, so a report always opens with "here is what this tool did to your network" before any
  verdict. Its `steps` evidence is built by **`_run_summary_steps()`**, a list of
  **`{"did": ..., "got": ...}`** pairs (not pre-joined strings — each surface aligns the columns
  to its own width, and JSON/CSV consumers get parseable fields). Two rules govern the content:
  - **`did` is plain English and short (≤60 chars, asserted by a test); protocol names live in
    `got`.** The audience is a security engineer who is *not* a DHCP specialist, so the left
    column must be readable without knowing what DHCPRELEASE or option 50 are. It's terse on
    purpose: the *why* behind these primitives is stated **once** in the recommendation, and an
    earlier version that explained it per step ran ~290 words and read as prose, not a list.
  - **Descriptive only — do not make it infer defensive posture.** "The server ignored this, so
    snooping is probably on" belongs in the verdict findings; a second differently-worded
    conclusion from the same run is worse than one. A regression test asserts the step text
    contains no posture vocabulary.

  Its single recommendation assumes a **Wi-Fi-based** attacker (controller DHCP proxy +
  client-MAC/chaddr consistency enforcement) — that's the one control that breaks every step in
  the chain, since all of them depend on sending DHCP on another device's behalf.
- **`NeighborSummary` (2.3.3) is the event-log counterpart to `RUN_SUMMARY`**: emitted once from
  `stop()` (after `_evict_phase()` so outcomes are settled, before `_finalize_findings()` so the
  log reads "who was affected" then "the verdicts about it"), built by
  `_emit_neighbor_summary()`. It emits **one row per host and lists every discovered neighbor** -- including untouched ones,
  so `unaffected` is visibly distinct from `not examined` -- sorted worst-first. Silent when the ARP sweep found nothing. The bucket boundaries are
  load-bearing and are pinned by tests in both directions:
  - `offline` — `discover_unanswered`/`apipa`, **or** (any mode, but this is exhaust's whole
    point) a neighbor whose DISCOVER during the run went unanswered because the pool was
    drained. Reading only `_evict_outcomes` reported those as `unaffected`, exactly backwards.
    `rediscovered` is **not** offline: it restarted and *was served*.
  - `lease_taken` — re-acquisition `granted` for that IP with no eviction reaction observed. **Do
    not merge this into either neighbouring bucket.** The host is working at the moment the
    summary is emitted (so it isn't offline) but the server has handed us its address, so it
    fails at its next renewal, silently, with nothing observable from our vantage point (same
    reason `_reprobe_released()` is colour only, §5f).
  - An observed eviction rung always wins over the inferred `lease_taken` state for the same
    host — eviction only ever targets addresses re-acquisition granted, so every evicted host is
    also a `lease_taken` candidate, and the observed reaction is the better evidence.
- **Evidence rendering is list-aware** in both front ends (`cli/render.py` `_evidence_lines()`,
  `web/static/app.js` `evidenceHtml()`): a list of `{did, got}` pairs renders as two aligned
  columns (CLI padding / an HTML table), any other list renders as indented bullets, scalars stay
  in the compact one-line dict, and **empty lists stay in the compact dict** (a bare `servers:`
  header with nothing under it reads like truncated output). `RUN_SUMMARY` forced this, but
  `servers`/`sample_hosts` benefit too — a new finding whose evidence carries a list renders
  correctly for free.

## 5b. ARP-conflict eviction — why `_do_arp_conflict()` is shaped the way it is (2.3)
`Mode.GARP_DOS` (standalone sustained ARP-cache poisoning, no exhaustion phase) was **retired**
in 2.3 — `build_arp_poison()`, `_garp_worker()`, `_on_garp_arp()` and both `ARP_FORGERIES_*`
findings are gone from `src/`. Its frame-building core survives, rewritten and repurposed:
`_do_garp()` → **`_do_arp_conflict()`**, no longer a standalone mode, now the mechanism eviction
(§5f) uses to force a host off an address it's *already lost the DHCP binding for* (re-acquired
in §5f's re-acquisition step) — not a general-purpose connectivity-denial tool anymore.

Per target per round: a broadcast ARP **request** + **reply** (`build_garp`, stacks honour
different forms — kept from the old implementation), claiming the target's own IP at a fresh
`random_mac()`. **The old third frame — a unicast ARP reply putting the default gateway at an
unused MAC (`build_arp_poison()`) — is gone and is not coming back.** It crossed from
denial-of-service into traffic-interception-adjacent territory (it targeted the *gateway*
mapping, not the victim's own address) and added nothing eviction needs: RFC 5227 §2.4 address
conflict detection is what does the work now (§5f), not a severed default route.

The forged MAC is always bogus, recorded in `_evict_bogus_macs` so the ARP observer
(`_handle_evict_arp()`) can tell forged frames apart from the real owner's. **Never point it at
our own MAC** — blackhole is address-conflict detection (in scope); redirecting traffic through
us would be interception (out of scope, see §1).

## 5c. Release phase, windowed sender, halt-on-control (2.1; shared prelude 2.3 §5f)
This is the direct fix for a real run that stalled at 56/~1000 addresses on a `/22`. The capture
showed the server re-offering the same address to two of our MACs, then NAKing, then going
silent — **pending-offer table saturation from flooding faster than handshakes could complete,
not real pool exhaustion.** Three pieces address this, in `_common_prelude()` order (extracted
from `_exhaust_prelude()` in 2.3 so `release` mode shares it too — see §5f):

1. **Release phase** (`_release_phase()`, runs after `ctl-pre-new` for exhaust / after `ctl-pre-
   self` for release, before senders/re-acquisition). Sources the server identity from
   `_prelude_pre_control()` — **never** guess or fall back to `0.0.0.0` (that was Bug 1:
   `_discover_neighbors()` is ARP-only and never learns a DHCP server, so every RELEASE used to
   go to `0.0.0.0` and get dropped). Excludes the gateway and the DHCP server from targets,
   feeds the freed list into re-acquisition (§5f) which is what actually confirms whether the
   RELEASE took (`_reprobe_released` is colour only — see its docstring for why an ARP re-probe
   structurally reads 0 even on full success). `cfg.release_neighbors` (default True) /
   `--no-release` opt out (exhaust only — no equivalent flag on the `release` subcommand, since
   disabling it there defeats the mode's purpose). `packets.build_release_v4()` also gained the
   `Ether` layer it was missing (Bug 2: it built an L3-only packet despite being sent via L2
   `sendp()` — every RELEASE this tool ever sent before this fix was malformed on the wire, not
   just the exhaust-embedded ones).
2. **Windowed sender** (`_exhaust_sender`, `_inflight`, `self._window`; also reused by
   re-acquisition's bounded batch, §5f). Replaces the open-loop DISCOVER flood with a bounded
   pipeline: at most `self._window` (starts at `cfg.window_initial=8`) DISCOVER/REQUEST
   transactions in flight at once. **Only an ACK counts as a held address** (`_grow_window`) —
   growth is deliberately slow (2.3, Phase 7): `self._window_growth_accum` banks
   `cfg.window_growth_per_ack` (default **0.01**) per clean ACK, so **100** clean ACKs widen the
   window by one — NAKs, timeouts, and duplicate offers all shrink the window immediately (halve
   it) and wipe the accumulator (`_shrink_window`) instead of being pushed through. Growth is now
   ~5000× slower than shrink, so a noisy run trends toward the floor of 1 rather than climbing
   back — that's the deliberate trade-off, see `_grow_window()`'s docstring. `--rate` is **gone
   from exhaust** (the window paces it now; `rate_limit_pps` is fixed at
   `EXHAUST_DEFAULT_RATE_PPS=500` so the limiter doesn't bind) but unchanged on
   `release`/`active-scan`/`release-previous`, which have no window of their own — **do not
   remove `RateLimiter` globally.**
3. **Halt-on-control** (`_trigger_halt`, `ControlDetected`, `HALTED` state). On the first of five
   signals — `nak_burst` (≥3/5s), `offer_silence` (existing), `link_down` (carrier poll in
   `_status_ticker`, `netutils.link_is_up()`), `timeout_storm` (≥5 consecutive), `duplicate_offers`
   (≥3 addresses offered to two of our MACs) — sending stops immediately but **leases already
   held are kept**, and `stop()` still runs both post-controls so the report is complete. First
   signal wins (`self._halt_signal` is set once). Don't make halt release leases or skip the
   post-control — that would break the verdict (§5d).

## 5d. Verdict: DHCP_STARVATION_ATTAINED / _NOT_ATTAINED (2.1)
Replaces four retired findings (`DHCP_STARVATION_POSSIBLE`, `DHCP_STARVATION_BLOCKED`,
`POOL_EXHAUSTED_CONFIRMED`, `POOL_NOT_EXHAUSTED` — must never reappear in `src/`) with two:
- **`DHCP_STARVATION_ATTAINED`** (`FAIL`): `acks > 0` **and** the post-run **new-MAC** control
  was denied **and** its own pre baseline succeeded. This is a failure of the network, not a
  success of the run.
- **`DHCP_STARVATION_NOT_ATTAINED`** (`PASS`): everything else, with `evidence["reason"]` — one
  of `control_fired` (+ `signal`/`leases_at_halt` from `self._halt_signal`), `pool_headroom_remaining`
  (+ `headroom`/`pool_size` from `_pool_headroom()`), `blocked_at_baseline`, or
  `inconclusive_baseline`. **Because halt-on-control (§5c) stops the run on the first signal,
  `ATTAINED` is now rare by construction on a defended network** — `NOT_ATTAINED +
  control_fired` naming the control and the lease count it fired at is the expected, actionable
  result, not a consolation prize.
- **Pool estimate / headroom** (`PoolEstimate`, `_estimate_pool()`, `_pool_headroom()`): resolved
  from an explicit `--scope` (deterministic host count) or, failing that, the first OFFER's
  subnet (option 1) via `_note_offer_for_pool_estimate()`. `size=None` when neither is known —
  **never fabricate a denominator**; every surface (status, StatusTick, CLI line, web counter,
  report) must show `source`/`detail` alongside the number. `POOL_HEADROOM_LOW` is a separate,
  independent finding raised when the *pre-test* ARP baseline already shows ≥80% utilization.

## 5e. Lease journal + `release-previous` (2.2)
`restore()` only releases leases the *currently running* engine object acquired, from memory —
useless once the process is killed, the box reboots, or you're back days later on a different
machine. 2.2 adds a recovery path for that:

- **`core/journal.py`** — append-only JSONL, two record kinds (`ack` opens a lease, `released`
  closes it), folded at read time. `load_open_leases()` **never raises** on a bad file — a
  truncated final line (the exact killed-mid-write case this exists for), malformed JSON, or an
  unknown record kind is skipped with a warning. `default_path()` resolves under
  `$XDG_STATE_HOME` (or `~/.local/state`, via the effective user's passwd entry, not `$HOME` —
  `sudo` doesn't always reset it) — **never `/var/lib` or another system-owned path**; this is
  per-engagement data, not system state (see SECURITY.md). `SessionConfig.journal` (default
  `True`) / `--no-journal` opts out. `_handle_ack()` writes an `ack`; `restore()` and
  `_release_bindings()` write a `released`. Writes are best-effort (`OSError` → `ev.Debug`,
  never kills the run); `dry_run` suppresses journal writes the same as it suppresses packets.
- **`Mode.RELEASE_PREVIOUS`** (`_run_release_previous`/`_release_previous_worker` in
  `engine.py`) replays the journal for the *current* network: filters by interface, current
  CIDR (`--scope`, else the interface network — **refuses to run** if neither resolves; an
  unbounded sweep is exactly what this prevents), same-server (only evaluable when the
  pre-flight control actually learned a server identity — **it usually won't** on a genuinely
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
  it adds no capability beyond what `exhaust` already used. It *is* in `cli/main.py`'s
  `_RUN_ONCE_MODES` (`DESTRUCTIVE_MODES | {RELEASE_PREVIOUS}`), which is what the CLI's polling
  loop uses to detect a worker-thread run finishing — don't confuse the two sets.
- Default `--rate` is **50**, not 7 — see the inline comment in `cli/main.py`; this is the one
  mode where a faster default is the right call (unicast to one server, run during an active
  outage).
- Design rationale in full: `EXECUTION-PLAN-release-previous.md` (the executed plan) and
  `EXECUTION-PLAN-release-all.md` (background — broader strategies considered and narrowed away
  from: leasequery, blind sweeps, ARP-derived targets — don't re-add them without re-reading why).

## 5f. Targeted re-acquisition + ARP-conflict eviction + shared `release` chain (2.3)
Ties §5b/§5c together into the actual attack chain both `exhaust` and `release` now run via
`_common_prelude()`: ARP inventory → control/self [→ control/new, exhaust only] → release →
**re-acquisition** → **eviction**. Design doc: `EXECUTION-PLAN-eviction.md`.

- **Re-acquisition** (`_reacquire_phase(freed)`, `_finish_release()`). Pushes one targeted
  DISCOVER per freed `(mac, ip)` — fresh random MAC, DHCP **option 50** (`requested_addr`) asking
  for the specific address just RELEASEd — into the *existing* windowed `_inflight` pipeline
  (no parallel sender). `_handle_ack()`/`_handle_nak()`/`_reap_timeouts()` classify each into
  `granted` (offer matched the request) / `offered_different` (server ignored option 50) /
  `naked` (REQUEST refused) / `no_response`, tracked in `_reacquire_targets`
  (xid→ip)/`_reacquire_outcomes` (xid→outcome). **This fixed a real unsoundness**:
  `NEIGHBOR_LEASES_RELEASED`'s evidence used to be `_reprobe_released()` (an ARP re-probe), which
  structurally reads 0 even on a fully successful RELEASE — a released victim keeps using its
  old address until its own lease's T1, with no way to know it was released, so "stopped == 0"
  never meant "the server ignored RELEASE". Evidence is now the re-acquisition `granted` count.
- **ARP-conflict eviction** (`_evict_phase()`/`_evict_worker()`/`_measure_eviction()`, `_do_arp_
  conflict()` — see §5b for the frame shape). Targets **only** addresses this run actually
  re-acquired (`granted`, from re-acquisition above) — conflicting with an address still bound to
  the victim just makes them defend and re-ARP; conflicting with one *we* now hold is what forces
  the DECLINE/restart. Excludes gateway and DHCP server (via `_prelude_pre_control()` — see
  below). Guarded by `cfg.evict` (default `True`) / `--no-evict`. `evict_rounds` (default 4,
  **must be ≥ 2**) spaced `timeouts.evict_interval` (default 3.0s, **must stay < 10.0s** —
  RFC 5227 §2.4's `DEFEND_INTERVAL`: a host defends once, then MUST cease on a *second* conflict
  inside that window; spaced 10s+ apart, each round looks like a fresh independently-defensible
  conflict and the host never gives up the address). `SessionConfig.__post_init__` raises
  `ConfigError` naming RFC 5227 if either constraint is violated. After the last round, sleeps
  `evict_settle` (default 16.0s, bumped from 8.0s after a live run showed a DECLINE could be
  measured before its follow-up DISCOVER arrived, understating the outcome by one rung) before
  measuring — gives a DECLINE/restart/APIPA time to land.
  **Outcome ladder** (causal/temporal order, not evidence-strength — a host that reaches a later
  rung passed through the earlier ones, whether or not we directly observed them):
  `no_reaction` < `defended` (ARP announcement from the real owner MAC — our frame was delivered,
  DAI isn't filtering) < `declined` (DHCPDECLINE from the victim — gold-standard proof it gave up
  the address) < `rediscovered` (fresh DISCOVER from the victim after the conflict — restarted at
  INIT) < `discover_unanswered` (that DISCOVER got no OFFER — real denial of service) < `apipa`
  (victim's MAC now sourcing ARP from `169.254.0.0/16` — full eviction, DHCP totally failed).
  `_evict_rung_max()` always keeps the highest rung reached; `_handle_evict_arp()` covers
  `defended`/`apipa` (ignoring our own forged MACs via `_evict_bogus_macs`), `_handle_client_
  decline()` covers `declined`, phase 2's foreign-DISCOVER tracking covers
  `rediscovered`/`discover_unanswered`.
  **Findings are mode-aware** — this is the one place `exhaust` and `release` genuinely diverge:
  under `exhaust` the pool is meant to be drained, so even a bare `rediscovered` (DISCOVER
  answered) is already evidence the address was taken by force, so `declined`+ all count as
  `CLIENTS_EVICTED_FROM_ADDRESSES` (FAIL). Under `release` the pool is **never** drained — a
  clean restart-and-immediate-reacquire is the whole point of the mode, not harm — so only
  `discover_unanswered`/`apipa` count as FAIL there; `declined`/`rediscovered` land in
  `CLIENTS_DEFENDED_ADDRESSES` (INCONCLUSIVE, "reacted but not denied service") instead. Don't
  collapse this distinction back to one threshold. Under dry-run every outcome reads
  `no_reaction` because nothing was ever sent — not evidence of anything — so the whole findings
  block is gated on `not cfg.dry_run`; `DRY_RUN_SUMMARY` covers that case (`would_evict` count).
  **No PASS verdict exists here on purpose** — "nobody reacted" can't be told apart from "the
  frames never arrived" from this vantage point.
- **`release` now shares `_common_prelude()`** rather than its own ARP-only, sniffer-less path.
  This fixed a second real bug: the old `_release_worker()` ran `_control_transaction()` to learn
  the server identity but never started a sniffer, so the OFFER/ACK reply could never physically
  arrive and the control always failed with "no OFFER within timeout" — `_run_release()` now
  starts one exactly like `_run_exhaust()` does (skipped under `offline`). `release`'s own
  pre/self control outcome goes into **`self._rel_pre_control`**, never `self.control_pre` — same
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

## 5g. Race-freed addresses — grab a freed address ahead of the untargeted flood (2.3.1)
Design doc: `EXECUTION-PLAN-race-freed.md`. Answers a gap §5f's re-acquisition doesn't cover:
re-acquisition only reacts to addresses **we** just freed via our own RELEASE phase; any address
that becomes free *some other way* mid-run (a NAK'd renewal, a DECLINE, a rediscovering neighbor)
previously only got picked up if the untargeted exhaust flood happened to land on it. `exhaust`
only — `release` has no concurrent flood for "racing ahead of" to mean anything against.

- **Triggers, ranked by how strongly they imply the *server* now considers the binding free**
  (not just that the client stopped using it — the server can hold a binding to lease expiry
  regardless of what the client does), all broadcast/observable. **DHCPRELEASE is deliberately
  never a trigger** — it's unicast to the server (`build_release_v4`'s `Ether(dst=server_mac or
  broadcast)`), invisible on a switched segment; the first draft of this plan got this wrong,
  see the plan doc's "Read this before implementing" section if you're tempted to add it back.
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
  unresolved ip, already queued this run (`_raced_ips`), already targeted by *our own*
  re-acquisition (`ip in self._reacquire_targets.values()` — without this, every one of the
  release phase's own victims re-DISCOVERing/DECLINEing right after being released+evicted would
  queue a duplicate race for an address we already hold), and the gateway/DHCP server (via
  `_prelude_pre_control()`/`_release_gateway()`). **Deliberately not `_is_own_traffic()`** —
  `_release_bindings()` spoofs the victim's MAC as both `chaddr` and Ethernet source with a fresh
  xid never registered in `_inflight`, so that filter structurally cannot recognise our own
  release-phase frames.
- **Race state is entirely separate from `_reacquire_targets`/`_reacquire_outcomes`** —
  `_race_queue`/`_raced_ips`/`_race_reasons`/`_race_targets`/`_race_outcomes`/`_race_triggers`/
  `_race_inflight`. This is load-bearing: `_evict_phase()` derives its target set (`granted_ips`)
  from `_reacquire_targets`/`_reacquire_outcomes` alone — writing a race xid into either would
  silently widen eviction's blast radius past what §5f documents ("targets **only** addresses
  this run actually re-acquired"). A regression test asserts this never happens.
- **`_exhaust_sender()` drains the race queue ahead of the untargeted path**, one per loop
  iteration, gated on `self._race_inflight < cfg.race_max_inflight` (default 4) —
  **deliberately not gated on window/inflight room** (`self._window - len(self._inflight)`): a
  race is a single, bounded, time-sensitive send, not a sustained load pattern, so it takes a
  reserve of slots *above* the window rather than waiting a turn. This is a bounded overtake, not
  a window bypass — §5c's window exists because a real `/22` run stalled at 56 addresses from
  pending-offer-table saturation; don't widen the reserve into a general bypass. Every race send
  still goes through `_send()`'s rate limiter, but that limiter is **not** a meaningful backstop
  in exhaust (`rate_limit_pps` pinned at `EXHAUST_DEFAULT_RATE_PPS=500`, deliberately
  non-binding) — the reserve is the only real bound.
- **`_classify_targeted(xid, outcome, overwrite=True)`** is the outcome classifier shared by
  re-acquisition and racing — `granted`/`offered_different` (from `_handle_ack()`), `naked`
  (from `_handle_nak()`'s owned branch), `no_response` (from `_reap_timeouts()`, `overwrite=
  False` so a later NAK/ACK for a xid that already timed out doesn't get silently discarded).
  Whichever of `_reacquire_targets`/`_race_targets` owns the xid is where the outcome lands;
  decrements `_race_inflight` exactly once, only for a race-owned xid.
- **Counters land in all four required surfaces** (`engine._counters()`/`.status()`,
  `cli/render.py`'s `status_summary()`, `web/static/app.js`'s `StatusTick` handler) — see §6's
  `garps`→`arp_conflicts` rename precedent for why this list is enumerated explicitly rather
  than trusted to memory.
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
- **Related pre-existing bugs found and fixed while building this** (independent of racing
  itself, but the ownership-check pattern this feature needed exposed both):
  - `_handle_nak()` used to count **every** NAK on the segment as ours — including ones
    addressed to other clients — shrinking our send window and feeding the `nak_burst` halt
    signal off traffic we had nothing to do with. Fixed by checking `xid in self._inflight`
    before touching `self.naks`/`_shrink_window()`/`_note_nak_for_burst_detection()`; the foreign
    branch is debug-logged only (and now also feeds the race trigger above).
  - **More severe**: `_handle_offer()` and `_handle_ack()` had no ownership check at all —
    `_handle_offer()` would build and send a REQUEST impersonating whichever MAC *any* observed
    OFFER's `chaddr` belonged to (potentially a real third-party client's), and `_handle_ack()`
    would unconditionally `cleanup.register()`/journal/count **any** ACK witnessed on the
    segment, meaning `restore()`/`release-previous` could later send DHCPRELEASE for a real,
    uninvolved client's active lease. Both now check `xid in self._inflight` first and return
    early (debug-logged) if the xid isn't ours; `_handle_offer()` still passively marks a
    tracked foreign DISCOVER as answered and still learns server identity/fingerprint from
    foreign traffic (both read-only, not the send-side bug). Ten existing tests were unknowingly
    relying on the old always-act behavior and had to be corrected, not just re-asserted.

## 6. Modes (`Mode` enum)
`EXHAUST` (default; runs the shared prelude — ARP inventory, control, release, re-acquisition —
then its windowed sender, then eviction in `stop()` — see §5c/§5f), `SCAN` (passive, read-only),
`ACTIVE_SCAN` (ARP sweep + one DHCP INFORM; non-destructive, scope required),
`RELEASE_NEIGHBORS` (destructive; runs the *same* shared prelude as exhaust minus the windowed
sender, then eviction inline — see §5f; web UI label "DHCP Release Active Clients"),
`RELEASE_PREVIOUS` (recovery; replays the lease journal — see §5e; not destructive). **`GARP_DOS`
was retired in 2.3** — don't re-add it to this enum; see §5b for where its frame-building logic
went. The web dropdown (`web/static/index.html`) doesn't offer `SCAN` as an option anymore
(Phase 6) but the CLI subcommand and `config_from_payload()` still accept it — don't remove
either.

## 7. How to run tests / lint (IMPORTANT sandbox quirks)
Sandbox Python is **3.10**, but the package targets **3.11+**, so **do NOT `pip install -e .`
in the sandbox** — run against the source path instead:
```
cd /sessions/<id>/mnt/DHCPig
PYTHONPATH=src python3 -m pytest -q          # 344 pass, 1 integration deselected
python3 -m ruff check src tests
python3 -m ruff format --check src tests
```
- Everything is unit-tested **without root** by monkeypatching `dhcpig.core.engine.sendp`.
- The one integration test (`tests/integration/test_exhaust_live.py`, `@pytest.mark.integration`)
  needs root + Linux (veth pair + fake DHCP server); it's deselected by default (`addopts` in
  `pyproject.toml`). Run on the VM with `make integration`.
- After runs, delete caches on the VMware share (they can't always be removed by the coverage
  plugin): `rm -rf .pytest_cache .ruff_cache .coverage*; find . -name __pycache__ -exec rm -rf {} +`.
  Prefer `pytest -q` (no `--cov`) on the share to avoid a coverage cleanup `PermissionError`
  (test results are still correct even if that error prints).
- On the user's VM (real 3.11+): `python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"`,
  then run with `sudo .venv/bin/dhcpig ...` (raw sockets need root; `sudo` ignores the venv on
  PATH so use the full `.venv/bin/...` path).

## 8. Gotchas / decisions already made (don't re-litigate)
- **`dry_run` and `offline` are genuinely different concerns now (2.3) — this replaces the old
  "dry-run is fully offline" property, which is no longer true and must not be reinstated.**
  `offline` is the hard "never touch a socket" switch (no sniffer, no `sendp`, no `srp()`) — it's
  what makes web/CLI tests and a no-root preview possible. `dry_run` alone now runs every
  non-destructive phase **for real**: the ARP sweep, and the control transaction's own
  DISCOVER/REQUEST/RELEASE — it's a genuine reconnaissance pass, not a shape-only preview, and it
  needs a raw-capable interface + root. It only suppresses **mutating** sends: release,
  re-acquisition, the windowed exhaust sender, eviction. The mechanism is `_send(pkt,
  probe=False)`'s `probe` parameter — `probe=True` marks traffic a legitimate client on this
  segment would send anyway and that self-cleans (bypasses dry-run suppression, never bypasses
  `offline`); it appears at exactly two call sites: the ARP sweep (`_discover_neighbors`'s
  `srp()` doesn't go through `_send()` at all, so it's gated on `offline` directly) and the
  control transaction (`_control_transaction()`'s three `_send(..., probe=True)` calls). Don't
  add a third `probe=True` site without re-reading why only these two exist.
- **The sniffer BPF was widened (2.3)** from server→client only (`src port 67 and dst port 68`)
  to both directions (`port 67 or port 68`) — needed to see our own echoed sends and, more
  importantly, foreign DISCOVERs/DHCPDECLINEs, which are client→server and were invisible before.
  This means `_on_dhcp()` now also receives our *own* outbound traffic reflected back; the
  self-filter (`_is_own_traffic()`) drops it before it reaches foreign-DISCOVER handling, keyed
  on Ethernet src being one of `_our_macs` or xid membership in `_inflight`/`_control_xid`.
  **Only apply the self-filter to message types we actually send ourselves** (DISCOVER/REQUEST/
  RELEASE) — never to OFFER/ACK/NAK/DECLINE, none of which we ever originate (DECLINE included:
  we never send one); `_on_dhcp()`'s dispatch checks those never-self-originated types first, for
  exactly this reason.
- **For OFFER/ACK/NAK/DECLINE, `xid in self._inflight` is the ownership test — not
  `_is_own_traffic()`.** Since we never originate these, the self-filter above doesn't apply to
  them, but that means a naive handler processes *every* such packet on the segment as if it were
  ours (2.3.1's §5g found this had actually happened in `_handle_nak()`/`_handle_offer()`/
  `_handle_ack()` — the last two had real blast radius: an unowned ACK being journaled meant
  `restore()`/`release-previous` could later RELEASE a genuine third party's active lease). Any
  new handler for these four message types must check xid ownership before acting, and should
  still passively learn from foreign traffic where safe (server identity, fingerprints, marking a
  tracked foreign DISCOVER as answered) — the bug was in the *send/mutate* side, not observation.
- **JSON serialization**: always route event/report dicts through `jsonable()` — a live run once
  crashed because an `IPVersion` enum hit `json.dumps`. Regression test exists.
- **Ethernet source MAC** defaults to the per-client random MAC (`spoof_ethernet_src=True`) so
  each simulated client is distinct at L2 (exercises port-security/snooping). `--no-spoof-eth-src`
  for Wi-Fi. The legacy `pig.py` shim injects `--no-spoof-eth-src` to preserve old behavior.
- **PR #27/#28 fixes** live in `packets.py` (server-id = opt54 else siaddr; client MAC =
  `chaddr[:6]`; REQUEST includes option-61; broadcast flag 0x8000) with regression tests. Don't lose them.
- **Fingerprint DB is `data/packetfence_dhcp_fingerprints.json`** (PacketFence-only, 535
  fingerprints; queryable standalone via `data/fingerprint-merge.py`), replacing the earlier
  bundled FingerBank `.conf`. Matching is exact/order-sensitive on option-55; a fingerprint with
  more than one candidate device is returned at lower confidence (75 vs 90) and flagged
  `(ambiguous xN)` in `matched_via`. `os` is intentionally left `None` for DB matches (the data
  doesn't cleanly separate OS from device); `device` carries the candidate name(s). No builtin
  vendor-class/PRL fallback table anymore — a miss falls straight through to `from_mac()`
  OUI-only identification. There's no `--fingerbank-api-key` anymore — that stub was removed
  (never implemented, never used).
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
- **`--rate` is exhaust-specific removal, not a global one.** It's gone from the `exhaust`
  CLI/web surface (the window paces it — §5c) but still required on `release`/`active-scan`/
  `release-previous`, none of which have a window of their own. Don't remove
  `RateLimiter`/`rate.acquire()` from `_send()` — it's still the only thing pacing three of the
  five modes (`scan` sends nothing at all; `release`'s eviction sub-phase paces itself via
  `evict_rounds`/`evict_interval`, not `--rate`).
- **Halt-on-control never releases leases.** `_trigger_halt()` stops the sender but leaves
  `Cleanup` untouched; there's no auto-restore-on-exit to accidentally trigger either (§5, 2.2).
  If you're tempted to auto-release on halt, don't — the post-controls need the leases held to
  be meaningful.
- **Pool-size estimates must never be presented as authoritative.** `PoolEstimate.size` is either
  `None` (show `—`) or a number that must always render next to its `source`/`detail` — a
  fabricated-looking denominator is exactly the kind of false confidence the two-leg control
  work (§5a) was meant to eliminate. Don't cache/round it into something that loses that context.

## 9. Current status
Roadmap V1.0 (CLI), V1.1 (web Exhaust), V2.0 (web all modes + packaging) are all **done**, plus
these later additions: combined-DB fingerprinting (replacing FingerBank), distinct-MAC default,
debug logging + verbosity dropdown, `active-scan`, neighbor↔fingerprint correlation by MAC,
MAC-vendor fallback identification, pre-run ARP inventory, the full 2.1 release (§5c/§5d:
release-first exhaust, windowed/adaptive sender, halt-on-control, headroom, verdict rename), 2.2
(§5e: lease journal + `release-previous` recovery), and now **2.3** (§5b/§5f,
`EXECUTION-PLAN-eviction.md`): `dry_run`/`offline` split into genuinely separate concerns, the
sniffer BPF widened + a self-filter to see foreign DISCOVER/DECLINE traffic,
`Mode.GARP_DOS` retired in favor of targeted re-acquisition (option 50) + RFC 5227 §2.4
ARP-conflict eviction shared by `exhaust` and a restructured `release` (both via
`_common_prelude()`), mode-aware eviction findings, the web UI's mode labels relabeled (Phase 6),
and the window-growth ratchet slowed from 0.5 to 0.01 per clean ACK (Phase 7). On top of that,
**2.3.1** (§5g, `EXECUTION-PLAN-race-freed.md`): race-to-grab-freed-addresses (foreign NAK/
DECLINE/opt-in rediscover triggers, a bounded reserve above the exhaust window, the
`RACED_FREED_ADDRESSES` finding), plus the two ownership-check bugs it surfaced and fixed along
the way (foreign NAKs no longer pollute our window/halt state; `_handle_offer()`/`_handle_ack()`
no longer act on traffic that isn't ours — the latter had real blast radius, since an unowned ACK
being journaled meant `restore()`/`release-previous` could send DHCPRELEASE for a genuine third
party's active lease). The web auto-stop fix (run-once modes now poll for their worker thread
finishing and auto-`stop()`, mirroring the CLI, instead of stalling ~65s) and info-level DHCP
option50/chaddr/hostname logging landed alongside it. Then **2.3.2**: the always-raised
`RUN_SUMMARY` finding (§5a) that opens every report with a plain-language, step-by-step account
of what the run did, plus list-aware evidence rendering in both front ends to display it.
**344 unit tests pass; ruff clean.** The
user validated a real exhaust run on their Kali VM against a live `/22` (pcap reviewed) — that
run is what exposed the pending-offer saturation bug §5c fixes and the renewal-vs-fresh-allocation
control-transaction bug §5a fixes. **Neither 2.1, 2.2, 2.3, nor 2.3.1 has been exercised against
real hardware yet** — that's the next validation step, and 2.3/2.3.1 (re-acquisition, eviction,
the restructured `release` chain, and now racing) are the least-proven: passing unit tests only,
zero live-network confirmation.

## 10. Open follow-ups (not yet done)
- **IPv6**: `IPVersion.V6` is a seam only; v6 packet builders/flows are NOT implemented. The v4
  modes are the working ones.
- **Fingerprint coverage**: `packetfence_dhcp_fingerprints.json` has 535 fingerprints
  (PacketFence-only); regenerate it from a newer PacketFence export to expand coverage. `os` is
  always `None` for DB matches by design (see §8) — if the report/UI should distinguish OS from
  device, that needs a curated taxonomy layered on top of `name`.
- **Active-scan** fingerprints the DHCP *server* via the INFORM reply; ARP-only neighbours now
  get MAC-vendor identification (`core/oui.py`), but never an OS — that needs DHCP evidence.
- **Integration coverage** only exercises exhaust; add netns cases for release/active-scan, and
  ideally one that actually exercises re-acquisition + eviction end to end (2.3 has none — see
  §9). `release-previous` also needs one, but it requires rewriting the `FakeDhcpServer` fixture
  in `tests/integration/test_exhaust_live.py` first — it currently has an unbounded address pool
  and never NAKs, so it can't simulate an exhausted-then-recovered pool at all. Give it a bounded
  pool, NAK-when-full behavior, and RELEASE handling that actually frees a binding, then: exhaust
  to drain it, destroy the engine object (simulating a killed process), run `release-previous
  --journal <path>` on a fresh engine, assert a new MAC gets an address afterward.
- **Web UI** exposes `release-previous` mode selection, scope, and rate, but not
  `--journal`/`--max-age`/`--any-server`/`--passes` as dedicated controls yet (the backend/schema
  round-trip already supports them — see `web/schemas.py` — just no HTML inputs). Add a config
  sub-panel following the `#ratecfg`/`#destcfg` show/hide pattern in `app.js`'s `onModeChange()`
  if the web UI needs full parity with the CLI.
- **Packaging** `.deb`/`.desktop` exist under `packaging/` but haven't been built/tested on a
  real Kali box yet.

## 11. Conventions
Ruff (line length 100) + format; type hints throughout `core`; dataclasses over dicts; no
module-level mutable globals in `core`. Add a test with every behavior change. Keep `core`
import-clean of CLI/web/`print`.
