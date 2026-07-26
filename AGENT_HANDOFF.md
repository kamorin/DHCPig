# DHCPig 2.x — Agent Handoff

> Read this first. It transfers everything you need to keep working on this codebase without
> re-deriving it. Companion docs: `DHCPig-SoT.md` (product spec, CUJs, roadmap) and
> `DHCPig-Implementation-Brief.md` (original build order) — both in the user's outputs folder,
> not the repo.

## 1. What this is
A whitehat DHCP network-hardening validation tool — a full rewrite of the legacy single-file
`pig.py` into an installable, tested package. It exhausts DHCP pools, releases neighbor
leases, floods gratuitous ARP, and passively/actively fingerprints hosts — to prove a network
defends against those (DHCP snooping, port security, etc.). **Never add capability that enables
host compromise or lateral movement; it stays an L2/L3 DHCP/ARP stress + audit tool.**

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
| `core/models.py` | dataclasses/enums: `SessionConfig`, `Lease`, `ServerInfo`, `Neighbor`, `HostFingerprint`, `Mode`, `IPVersion`, `Timeouts`. `DESTRUCTIVE_MODES`, `SCOPE_REQUIRED_MODES`. |
| `core/packets.py` | **pure** scapy builders/parsers (no I/O). `build_discover_v4`, `build_request_v4`, `build_release_v4`, `build_inform_v4`, `build_garp` (op=1/2), `build_arp_poison`, `server_identifier`, `client_mac_from_offer`, `parse_offer`, `is_offer`/`is_ack`, `dhcp_option`. |
| `core/engine.py` | `DhcpEngine(cfg, bus)`: `start/stop/status/restore`. One state machine, `threading.Event` stop, worker threads + sniffer. **Every outbound frame goes through `_send()`** (the single chokepoint). Control transaction + findings derivation live here too (§5a). Debug via `_debug()`. |
| `core/events.py` | `EventBus` (thread-safe), event dataclasses, `to_dict()` + `jsonable()` (recursively converts enums/bytes/Path so JSON never breaks). |
| `core/safety.py` | `ScopeGuard`, `RateLimiter` (token bucket), `Cleanup` (tracks leases for restore). No `authorize()` — the gate was removed, see §5. |
| `core/sniffer.py` | thin `AsyncSniffer` wrapper. |
| `core/fingerprint.py` | `extract_signature()` + `resolve()`: exact option-55 match against `data/combined_dhcp_os_lookup.json`, else builtin vendor-class/PRL table, else `from_mac()` OUI-only. `DB_VERSION`. |
| `core/oui.py` | MAC → hardware vendor. `data/mac-vendor.txt` supplement (longest prefix wins) then scapy's bundled Wireshark/IEEE `manuf` DB (~50k); locally-administered MACs labelled as randomised. No bundled IEEE copy needed — scapy already ships one. |
| `core/reporting.py` | `SessionRecorder` → JSON/CSV/HTML (`render()` / `export()`). Neighbors deduped by MAC. |
| `core/netutils.py` | iface enumeration, `iface_network_cidr()` (scope auto-fill), `default_gateway()` (garp), IP math, `random_mac()`. |
| `core/exceptions.py` | `DhcpigError`, `ConfigError`, `OutOfScope`, `SessionConflict`. |
| `data/combined_dhcp_os_lookup.json` | Static PacketFence + Huginn-Muninn merge (594 fingerprints), built by `data/fingerprint-merge.py` (also a standalone lookup CLI). `data/fingerprints.json` builtin fallback. `data/DATA_ATTRIBUTION.md`. |

### Web files
`web/server.py` (`WebApp` + `Handler` + `main`), `web/api.py` (route handlers → `(status,dict)`),
`web/stream.py` (`SseSubscriber`: bus→per-client `queue.Queue`→SSE frames), `web/auth.py`
(loopback + bearer token + same-origin + security headers), `web/schemas.py` (dataclass
validation, no pydantic; `config_from_payload`, `as_cli`), `web/static/{index.html,app.js,styles.css}`
(vanilla JS SPA, no build step, hand-rolled canvas sparkline).

## 4. Event flow
`engine (worker threads) → bus.emit(Event) → subscribers`. CLI `Renderer.handle` prints;
web `SseSubscriber` puts `to_dict(event)` on a queue, the `/events` handler writes SSE frames,
the browser's `EventSource` updates the DOM. **Handlers must be cheap/non-blocking.**

## 5. Safety model
- **The authorization gate was removed at the maintainer's request** (2026-07). There is no
  `--i-am-authorized`, no `authorize()`, no `Unauthorized`, no confirmation modal or prompt, and
  `--scope` is optional for `release`/`garp` — with none given they fall back to the interface's
  own network via `_sweep_cidrs()`. **`dhcpig garp eth0` will target the whole segment.** Don't
  re-add the gate without asking, and don't quietly remove what's left below either.
- What still bounds a run: `--rate` (default 10 pps), `--dry-run`, `ScopeGuard` when a scope
  *is* supplied, and `Cleanup`/`restore()` for lease reversal.
- `active-scan` is non-destructive but **requires `--scope`** (`ConfigError` if missing) — this
  is the one remaining hard requirement, so its sweep can't be unbounded.
- **`_send()` is the chokepoint**: scope check (drops out-of-scope, emits `Skipped`), rate limit,
  and **dry-run** (builds + accounts, never calls `sendp`). Keep all sends flowing through it.
- `restore()` releases exactly the leases in `Cleanup`. **Auto-restore is OFF by default**
  (`restore_on_exit=False`) so the exhausted state can be verified after a run; the operator
  cleans up via `dhcpig restore <iface>` or `POST /api/session/restore` (the UI's
  Restore button was removed at the maintainer's request), or opts in with
  `--restore-on-exit`. Don't silently flip this back — retention is deliberate.

## 5a. Confidence model — why the tool can be believed
The engine reports **verdicts backed by evidence**, not just counters. Three pieces work together
and should be kept together:
- **Control transaction** (`_control_transaction`, `ControlOutcome`): a legitimate DHCP cycle,
  run `pre` (in `_exhaust_prelude`) and `post` (in `stop()`, deliberately **before** `restore()`
  so leases are still held). Replies route by xid via `_consume_control()` so control traffic
  never pollutes run counters; the lease is released immediately.
  **Two legs, and the distinction is load-bearing:** `client="self"` uses the real NIC MAC, which
  the server usually already has a binding for — it is a *renewal* and will succeed on a drained
  pool. `client="new"` uses a fresh unseen MAC that must come off the free list. **Exhaustion is
  judged only on the `new` leg** (this was a real bug: the self leg reported POOL_NOT_EXHAUSTED
  on a network where offers had stopped). A failed `pre/self` means the test was broken, not that
  a defense worked; a failed `pre/new` with a good `pre/self` means L2 admission control.
- **`EXHAUSTED` means the server stopped serving — nothing else.** There is no lease cap
  (`--max-leases` was removed precisely so nothing self-imposed could be mistaken for
  exhaustion); `--rate` is the only self-imposed bound. Exhaustion needs offers to have flowed
  then stopped (`_offers_seen_any` + `offer_silence`) and is only `confirmed=True` once the post
  control is also denied.
- **Runs finalize themselves.** `_finish_in_background()` spawns a finisher thread that calls
  `stop()` when a terminal condition hits. This is required, not cosmetic: `stop()` joins the
  worker threads, so the sender cannot call it directly, and without it the web UI sat idle
  after the pool drained (senders dead, no post-control, no verdict) until Stop was pressed.
  `OffersCeased` reports the quiet-period countdown so the UI shows progress meanwhile.
- **Findings** (`_finalize_findings`, `Finding`): id/verdict/severity/evidence/recommendation,
  emitted as `FindingRaised`, collected into `report["findings"]`. Add new findings there.

## 5b. ARP-GARP DoS — why it is shaped the way it is
A single broadcast GARP claiming the victim's own address does essentially nothing: it trips
duplicate-address detection, the host defends, and it re-ARPs within seconds. So `_do_garp()`
sends, per target per round, a GARP **request** + **reply** (stacks honour different forms)
*plus* a **unicast ARP reply putting the default gateway at an unused MAC** — that last frame is
the one that costs the victim connectivity. `_garp_worker()` repeats rounds every
`timeouts.garp_interval`. **Don't "simplify" this back to one broadcast frame.**
The forged MAC is always bogus. **Never point it at our own MAC** — blackhole is DoS (in scope);
redirecting traffic through us would be interception (out of scope, see §1).

## 6. Modes (`Mode` enum)
`EXHAUST` (default), `SCAN` (passive, read-only), `ACTIVE_SCAN` (ARP sweep + one DHCP INFORM;
non-destructive, scope required), `RELEASE_NEIGHBORS` (destructive), `GARP_DOS` (destructive,
standalone — no exhaustion phase).

## 7. How to run tests / lint (IMPORTANT sandbox quirks)
Sandbox Python is **3.10**, but the package targets **3.11+**, so **do NOT `pip install -e .`
in the sandbox** — run against the source path instead:
```
cd /sessions/<id>/mnt/DHCPig
PYTHONPATH=src python3 -m pytest -q          # 73 pass, 1 integration deselected
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
- **Dry-run is fully offline**: the engine skips the sniffer and `sendp` under `dry_run`, and
  `_src_mac` falls back to a random MAC if `get_if_hwaddr` fails — this is what makes web/CLI
  testable without root. Keep that property.
- **JSON serialization**: always route event/report dicts through `jsonable()` — a live run once
  crashed because an `IPVersion` enum hit `json.dumps`. Regression test exists.
- **Ethernet source MAC** defaults to the per-client random MAC (`spoof_ethernet_src=True`) so
  each simulated client is distinct at L2 (exercises port-security/snooping). `--no-spoof-eth-src`
  for Wi-Fi. The legacy `pig.py` shim injects `--no-spoof-eth-src` to preserve old behavior.
- **PR #27/#28 fixes** live in `packets.py` (server-id = opt54 else siaddr; client MAC =
  `chaddr[:6]`; REQUEST includes option-61; broadcast flag 0x8000) with regression tests. Don't lose them.
- **Fingerprint DB is `data/combined_dhcp_os_lookup.json`** (PacketFence + Huginn-Muninn merged
  by `data/fingerprint-merge.py`, 594 fingerprints), replacing the earlier bundled FingerBank
  `.conf`. Matching is exact/order-sensitive on option-55; a fingerprint with more than one
  candidate device is returned at lower confidence (75 vs 90) and flagged `(ambiguous xN)` in
  `matched_via`. `os` is intentionally left `None` for combined-DB matches (the data doesn't
  cleanly separate OS from device); `device` carries the candidate name(s). The small builtin
  `fingerprints.json` table is a fallback for option-60 vendor-class / OUI signals the combined
  DB doesn't carry at all, checked only when the combined DB has no exact PRL match. There's no
  `--fingerbank-api-key` anymore — that stub was removed (never implemented, never used).
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

## 9. Current status
Roadmap V1.0 (CLI), V1.1 (web Exhaust), V2.0 (web all modes + packaging) are all **done**, plus
these later additions: combined-DB fingerprinting (replacing FingerBank), distinct-MAC default,
debug logging + verbosity dropdown, `active-scan`, and neighbor↔fingerprint correlation by MAC.
**115 unit tests pass; ruff clean.** The user validated a real exhaust run on their Kali VM (pcap
reviewed — worked; the single-MAC finding drove the spoof-default change). The confidence work
in §5a (control transaction, limit-vs-exhaustion, NAKs, findings, `--rate` pacing fix) is done
but has **not yet been exercised against real hardware** — that's the next validation step.

## 10. Open follow-ups (not yet done)
- **IPv6**: `IPVersion.V6` is a seam only; v6 packet builders/flows are NOT implemented. The v4
  modes are the working ones.
- **Fingerprint coverage**: `combined_dhcp_os_lookup.json` has 594 fingerprints (PacketFence +
  Huginn-Muninn); regenerate it from newer source exports to expand coverage. `os` is always
  `None` for combined-DB matches by design (see §8) — if the report/UI should distinguish OS
  from device, that needs a curated taxonomy layered on top of `name`.
- **Active-scan** fingerprints the DHCP *server* via the INFORM reply; ARP-only neighbours now
  get MAC-vendor identification (`core/oui.py`), but never an OS — that needs DHCP evidence.
- **Integration coverage** only exercises exhaust; add netns cases for release/garp/active-scan.
- **Packaging** `.deb`/`.desktop` exist under `packaging/` but haven't been built/tested on a
  real Kali box yet.

## 11. Conventions
Ruff (line length 100) + format; type hints throughout `core`; dataclasses over dicts; no
module-level mutable globals in `core`. Add a test with every behavior change. Keep `core`
import-clean of CLI/web/`print`.
