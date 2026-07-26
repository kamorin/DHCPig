# Changelog

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
