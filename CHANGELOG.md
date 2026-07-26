# Changelog

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
