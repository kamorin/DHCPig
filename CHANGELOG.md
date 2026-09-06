# Changelog

## Unreleased

Four small changes aimed at using DHCPig in a lab exercise or a scripted engagement, where the
report is handed to someone else and the run's result has to be machine-readable.

- **`--fail-on {fail,inconclusive,never}` carries the verdict in the exit status.** A run that
  drove a segment to starvation exited `0`, same as one that found nothing, so no scoring script
  could branch on the outcome. `--fail-on fail` now exits `1` when a `FAIL` finding was raised
  (`inconclusive` widens that to a broken baseline, which means the segment was never really
  tested). Default is `never`: exit `0` keeps meaning "the run worked", which is what every
  existing caller reads it as, and a run that failed to execute keeps its own code (`2`/`3`/`130`)
  rather than being overwritten.
- **Findings carry a MITRE ATT&CK technique id.** `Finding.attck`, populated from the catalogue
  in `core/findings.py` and rendered in the JSON, CSV and HTML reports: `T1498` for the
  pool-drain findings, `T1557.003` for everything that speaks DHCP for another device (forged
  RELEASE, option-50 re-acquisition), `T1557.002` for the forged-ARP eviction chain, `T1018` for
  the neighbour inventory. Controls, recovery and dry-run findings stay unmapped — they describe
  the tool reporting on itself, not a technique — as does `RUN_SUMMARY`, which is raised by every
  mode including the read-only scans, so no one static technique is true of it. A test asserts
  every id in the catalogue is a known technique, so a typo fails CI instead of reaching a report.
- **The CSV export no longer drops the findings.** It emitted the host inventory alone, so
  exporting a run for a spreadsheet silently lost every verdict the run existed to produce. Both
  now share one header, discriminated by a leading `section` column
  (`section,time,id,verdict,severity,attck,title,summary,kind,mac,...`), findings first. One
  header rather than two stacked ones because two did not fail a strict reader — `csv.DictReader`
  shifted every inventory row left, putting a MAC under `id` and an IP under `verdict`, and
  handed back plausible garbage.
- **Timestamps for correlating a run against the defender's logs.** Each `Finding` is stamped
  with `ts` when it is raised, not when the report is rendered (the report is written once at the
  end, minutes later), and the report header gains `started_at_iso`/`ended_at_iso` alongside the
  existing epoch floats — UTC, because the operator's timezone is not knowable by whoever reads
  the report. Shown per finding in the HTML report and in the CSV's `time` column.
- **`ended_at` is now the instant the run ended, read from `SessionEnded`, rather than the moment
  `to_dict()` happened to be called.** The web UI renders a report on download, so the reported
  run window used to keep growing for as long as nobody downloaded it. Still falls back to "now"
  for a run that never emitted `SessionEnded` (mid-run, or killed), which is the honest answer
  there.

## 2.7.3 — 2026-08-09

Nine fixes to the exhaustion verdict path, from a penetration-testing review of `exhaust`. Each
one either stopped the tool from reporting a wrong verdict or removed something that misled the
operator.

- **Deleted `SERVER_STOPPED_SERVING_TEST_CLIENTS`, a finding that could never fire.** Its
  condition required `self.state == EXHAUSTED` while `post_new.success` was true, but `state`
  only ever becomes `EXHAUSTED` when `post_new` is *denied* — the condition was unsatisfiable
  outside its own test, which faked the state by hand. The distinction it was reaching for is
  already carried by `DHCP_STARVATION_NOT_ATTAINED` with `reason="control_fired"`.
- **The control transaction now retransmits (`SessionConfig.control_attempts`, default 3).** The
  exhaustion verdict was previously derived from a single DISCOVER/OFFER/REQUEST/ACK exchange
  with no retry — one lost UDP packet could flip a clean network to a false
  `DHCP_STARVATION_ATTAINED`, or flip a genuinely exhausted one to a false
  `NEW_CLIENT_BLOCKED_AT_BASELINE`. Retried only on "nothing came back"; a NAK is a definite
  answer and stops immediately. `ControlOutcome.attempts` and `post_new_attempts` evidence make
  the retry count auditable in the report.
- **Fixed `timeout_storm` firing on a successful pool drain.** It used to count every expired
  in-flight handshake rather than reap *cycles*, so a full window (up to 64) expiring together
  the moment the pool emptied read as "N consecutive timeouts" and halted in ~2s — well before
  `offer_silence`'s 10s could report the drain correctly. It no longer accumulates once offers
  have already ceased, which is `offer_silence`'s job.
- **A foreign OFFER no longer resets the exhaustion clock.** `_handle_offer()`'s counters
  (`offers`, `_offers_seen_any`, `_last_offer_ts` — what `offer_silence` reads) were incremented
  before the ownership check, so any other client's routine DHCP churn on the promiscuous BPF
  kept `offer_silence` from ever firing on a busy segment. Split into a passive half (server
  registry, pool estimate — safe from anyone's packet) and an owned half (the exhaustion
  counters, the REQUEST leg), gated by ownership between them.
- **Pool-size estimate no longer trusts the subnet mask alone.** A real DHCP scope is usually a
  slice of its subnet; the mask-based estimate overestimated it, which made
  `pool_headroom_remaining` the reflexive explanation for any non-result. Added
  `source="observed_span"`: a measured lower bound from the min/max address actually seen
  offered (≥8 samples), preferred over the mask guess and explicitly excluded from
  `POOL_HEADROOM_LOW`'s utilization check (a lower bound would read artificially high there).
- **Runs now report leases that expired mid-run.** On a short-lease network a long exhaust could
  lose its own early leases without anything in the report saying so, making a later successful
  control read as unexplained headroom. New `_leases_expired()` / `leases_expired_during_run`
  evidence on both `DHCP_STARVATION_*` findings and the RUN_SUMMARY drain step.
- **The pre-run ARP sweep no longer silently truncates past 1024 hosts per CIDR.** Wider than a
  /22 used to report a partial host list as if it were the whole segment with no indication.
  `_sweep_targets()` now returns how many addresses it skipped; surfaced in the "ARP inventory"
  step and `NEIGHBORS_OBSERVED`'s evidence.
- **`--request-option` now actually changes the DHCP option-55 content sent.** It was accepted by
  both `exhaust` and (via `SessionConfig.request_options`) `active-scan`'s INFORM builder, but
  neither packet builder read the value — every DISCOVER/INFORM always sent the built-in
  macOS-order list regardless of the flag. Also added to `active-scan`'s CLI, the mode that was
  already plumbed to receive it. The control transaction's own DISCOVER is deliberately exempt —
  it must stay a vanilla client, since it's the baseline the verdict is measured against.
- **Fixed:** the CLI described `exhaust` as `(non-destructive)`. It is the most destructive mode
  in the tool — it releases every ARP-discovered neighbour's lease, floods the pool, and
  ARP-evicts hosts off addresses it took. The README and design doc already said so correctly;
  only `--help` was wrong.

## 2.7.2 — 2026-08-02

- **Fixed `debian-package`'s `publish` job, which had never actually published anything.**
  `gh release create --generate-notes` shells out to `git` to build notes from commit history, but
  the job never checked out the source — every prior tag push failed at "Attach it to the GitHub
  release" with `fatal: not a git repository`, silently, since it ran only after the (successful)
  build job. v2.7.1 was cut without noticing this for exactly that reason; this release exists to
  get a working publish step onto a tag.

## 2.7.1 — 2026-08-02

- **The OUTCOME roll-call now names the device: a short OS/vendor tag trails each host line.**
  `_neighbor_rollcall()` rows carry a sixth field, `device` — `"os (vendor)"`, falling back
  through device or vendor alone, `""` when the host was never fingerprinted (the same
  omit-when-empty treatment `hostname` already had). CLI and web log both render it as a
  trailing `[Windows 10 (Microsoft Corp.)]` tag; the aggregated tally line is unaffected, since
  it counts outcomes, not devices. Deliberately **not** added to the durable
  `NEIGHBORS_OBSERVED` finding's evidence — that finding is about what happened to a host, not
  what it is, and fingerprint detail already reaches the JSON/HTML/CSV export separately via
  `NeighborFound`/`HostFingerprinted`.
- **A target that defended an address we already hold the lease for is now reported as
  `lease_taken`, not `reacted`.** This was the biggest misreport in the roll-call. Eviction only
  ever targets addresses re-acquisition *granted*, so a host at the `defended` rung won the ARP
  exchange while the DHCP binding underneath it had already been handed to us — it is sitting on
  a lease the server no longer recognizes and drops it at the next renewal, exactly like a silent
  `lease_taken` host. The old row ("defended its address", filed under `reacted`) described the
  packet exchange and buried the outcome, and it read as the one host on the segment that got
  away. Outright denial still outranks it: a neighbour that asked for an address and got none is
  reported `offline`, because that is a present-tense outage rather than a future one.
- **New finding `CLIENTS_HOLDING_STOLEN_LEASES` (FAIL/high).** Those same targets used to fall
  under `CLIENTS_DEFENDED_ADDRESSES` (INCONCLUSIVE, "reacted but not denied service"), which
  understates a pending outage with a known cause and a known mechanism. It is raised *alongside*
  `CLIENTS_EVICTED_FROM_ADDRESSES` rather than instead of it — the two cover disjoint sets of
  hosts — and is mode-independent, since it turns only on the server having reassigned the
  binding. Its recommendation names the actual defense: DHCP snooping with a binding table stops
  this; Dynamic ARP Inspection alone would not have.
- **Roll-call rows now carry a renewal bound (`fails at next renewal (within ~12h)`).** Derived
  from the lease duration the server handed *us* for that address. Deliberately an upper bound,
  never a countdown — the victim's own T1 depends on when it originally got its lease, which this
  vantage point cannot see, so `within ~L/2` is the strongest honest claim. Omitted entirely when
  no lease duration is known.
- **The forged MAC contesting a target is now stable for the whole eviction.** It was re-rolled
  every round. RFC 5227 §2.4 makes a host cease only on a *repeat* conflict inside
  `DEFEND_INTERVAL`, and a new sender MAC each round can read to a stack that tracks conflicts
  per peer as a different host's *first* conflict — precisely the case it is allowed to defend
  again. One MAC per target for every round makes each one unambiguously "the same host is still
  claiming my address", and keeps the victim's ARP cache pointed at a single consistent
  blackhole. Distinct targets still get distinct MACs.
- **A third, unicast ARP-conflict frame per target per round.** Same claim as the broadcast
  reply, addressed straight to the victim's MAC (`build_arp_conflict_unicast()`). Broadcast is
  the RFC 5227 form and stays the primary; this covers the delivery paths where a broadcast never
  arrives at all — wireless APs with client isolation drop station-to-station broadcast while
  still forwarding unicast to a known station, and some stacks filter broadcast ARP far harder on
  the input path. Not a return of the 2.3-era gateway blackhole: it contests the victim's own
  address and points at a blackhole, not at us.
- **Denser conflict rounds: `evict_rounds` 4 → 6, `timeouts.evict_interval` 3.0s → 1.5s.** Staying
  under `DEFEND_INTERVAL` was already the correctness floor, but the odds improve with the number
  of *distinct* conflicts landing inside one window, not merely with there being two. All six now
  fall inside a single 10s window (t=0…7.5s) instead of four straddling its edge, so one dropped
  or filtered frame no longer costs the eviction — and the phase finishes marginally sooner than
  the old 4 × 3.0s did. No denser than that on purpose: back-to-back frames get coalesced into one
  conflict event by the victim's ARP input path, so separate arrivals are what count.
- **Pool exhaustion is now stated plainly in OUTCOME, not just a live `[!!]` log line.**
  `NeighborSummary` carries `pool_exhausted`/`leases_acquired`, so the end-of-run block reports it
  with the lease count, and `released_unconfirmed` rows escalate to the stronger renewal-risk
  wording once the pool is confirmed drained rather than the generic "unknown from here" text. The
  neighbors/hosts panel gets a matching per-host **Result** column fed by the same roll-call data,
  and the OUTCOME block's per-host detail is now separated from its tally by a blank line.
- **`dhcpig-web` now opens a browser by default; `--no-open` opts out.** Every documented usage
  already passed `--open`, so the flag was pure friction.
- **The `[device/OS]` tag now leads the roll-call outcome text instead of trailing it** — who a
  host is, then what happened to it, reads more naturally than the reverse.
- **Dropped the Conf(idence) column from the neighbors/hosts panel.** It's a debugging detail of
  the fingerprint match; the OS/Device label it's derived from is the part an operator scanning
  the table actually needs.
- **`window_growth_per_ack` halved again: 0.01 → 0.005 (200 clean ACKs per +1 window slot,
  not 100).** Applies to both exhaust's windowed sender and release's re-acquisition leg, which
  share the pipeline.
- **Roll-call outcome text trimmed across the board** — RELEASE/lease/renewal sentences carry the
  same information in fewer words (`"within ~12h"` → `"~12h"`), the neighbors/hosts table gained a
  hairline per-cell grid, and a long **Result** cell now scrolls the table sideways instead of
  wrapping to two lines. The OUI-only vendor label shortened `"(MAC vendor)"` → `"(vendor)"`, and
  the locally-administered-MAC label to `"randomised/spoofed"`.
- **"observed only" is now specific about how a host was found.** A host that only ever sourced a
  DHCP packet (never answered ARP) has no confirmed IP, so reporting it identically to an
  ARP-confirmed neighbor implied an address we don't actually have — `Neighbor` now tracks
  `seen_via`, and the passive-scan outcome text distinguishes observed-via-ARP from
  observed-via-DHCP.
- **The sparkline now graphs DHCPRELEASE pps alongside DISCOVER pps, with a legend**, and
  release/release-previous modes — previously stuck showing `0` pps because only the DISCOVER rate
  was tracked — now show their own real rate. `release-previous` also now reports a CIDR-derived
  pool size and a live count of journal entries selected for reset in the headroom cell instead of
  always showing `-`, and runs the same pre-run ARP inventory sweep exhaust/release already do,
  fixing a step-summary line that always read "0 devices".
- **Dashboard panel layout rebalanced and its alert flag broadened.** Config narrows from 260px to
  208px, with the freed space going to the center Neighbors/Hosts panel; the `[!!]`-triggered
  highlight moves from the Dashboard panel to the center tables panel, and now triggers on *any*
  alert-styled log line (previously only lines literally prefixed `[!!]`, which missed failed
  CONTROL transactions like `CONTROL[pre/own MAC/renewal] FAILED`) rather than the log-line-prefix
  heuristic. The dashboard's counters row was widened past one line by a crammed
  `"headroom / ~1022"` label plus 6 counters; headroom now reads as a plain `"61 / 1022"` number
  with "headroom" as a subtitle, keeping the row on one line.
- **The dashboard graph now plots four separate transmit-side lines — ARP, DISCOVER, RELEASE,
  RENEW — instead of one merged rate**, with the top-row "pps" tile as their straight,
  mode-independent sum. ARP covers both who-has sweep requests and forged eviction frames
  (`arp_sent`); RENEW is the DHCPREQUEST sent after every OFFER, including the control
  transaction's own self-leg, tracked by a new `requests_sent` counter. This replaced an
  intermediate arp/s tile that briefly existed as its own dashboard item and graph line before
  being folded in, since a separate ARP-only view was mostly redundant with, and competed for
  space against, the DHCP-driven rate already shown. The "pps" tile is now the third counter slot
  in every mode, including scan/active-scan, which previously never showed it at all (that slot
  duplicated the adjacent "hosts" tile under the "resolved" label instead).

## 2.7.0 — 2026-08-01

- **Fingerprint data relicensed to GPL by replacing its source.** The bundled DHCP fingerprint
  table was `packetfence_dhcp_fingerprints.json`, derived from PacketFence and therefore from
  Fingerbank (Inverse inc.), which is **ODbL v1.0 / DbCL v1.0 — not GPL**. That made DHCPig a
  GPL-2+ program shipping non-GPL data, which is legal but meant two licenses to carry and, for
  Debian, ~580 lines of license text in `debian/copyright`. It is replaced wholesale by
  `satori_dhcp_fingerprints.json`, derived from [Satori](https://github.com/xnih/satori) (Eric
  Kollmann and contributors), which is **GPL-2.0-or-later** — the same terms as this project, so
  everything now ships under one license. A test asserts the bundled `license` field so a
  relicensed reimport fails loudly instead of quietly.
- **Vendor class (DHCP option 60) is a new matching rung.** Fingerprinting used to go
  straight from "no exact option-55 match" to a bare MAC-vendor guess at confidence 15. There is
  now a middle tier: 187 exact vendor-class signatures at confidence 70 (55 when ambiguous),
  between option-55's 90/75 and the OUI floor. Plenty of stacks send a distinctive vendor class
  while sharing a parameter-request-list with a dozen other devices, and those hosts are now
  identified instead of written off.
- **`os` is populated for database matches.** It was hardcoded `None` because the old data
  didn't cleanly separate OS from device. Satori does, so `os` (`Windows 10`, `iOS 12`,
  `ChromeOS`, `Raspbian 8`) is now reported alongside `device` — but only when every candidate
  for a signature agrees on one, since "Windows 10 / iOS 12" is two guesses rather than an
  answer. `vendor` benefits the same way: it was an empty string on **100%** of the old data's
  536 entries and is set on 97% of the new one's. The data also carries a 40-category
  `device_type` on 66% of entries, which `satori-merge.py` prints; `HostFingerprint` has no
  field for a category, so a report row still shows the specific name.
- **Coverage moved, and not uniformly up.** 319 option-55 signatures against the old 535: 258
  carried over, 63 are new, and 277 old ones are gone. That is a real reduction on the raw
  exact-match dimension, traded for the vendor-class tier, the populated taxonomy, one license,
  and an upstream that is still being updated (Satori's data has 2025 entries; the PacketFence
  snapshot was frozen).
- `data/fingerprint-merge.py` becomes `data/satori-merge.py`, which is now both the standalone
  lookup CLI and the converter that regenerates the JSON from Satori's `dhcp.xml`
  (`--convert`). Keeping both halves in one file is deliberate: the rules that build the table
  and the rules that query it cannot drift apart.
- The old data file also embedded an absolute path from the maintainer's own machine in its
  `sources` field; that is gone with it.

## 2.6.1 — 2026-08-01

- **Fixed: `active-scan`'s ARP inventory step always reported 0 devices.** Its worker runs its
  own ARP sweep but never wrote the result into the field the "ARP inventory" summary step
  reads, so the step showed "0 devices" regardless of how many hosts actually answered, while
  the neighbor summary (fed by the sniffer's passive capture from the same run) could show a
  nonzero count.
- **Fixed: the web UI's pig icon was broken.** `web/static/icon.svg` had the same invalid `--`
  sequence inside its XML comment as `packaging/dhcpig.svg` (fixed for the README in 2.6.0);
  browsers parse SVG as XML, so the malformed comment broke the logo in the header.
- **Fixed: `mypy src/dhcpig/core` wasn't actually running in CI.** It sits after `ruff format
  --check`, which was failing, so every job short-circuited before reaching it. Fixing format
  exposed 19 real errors (scapy's `import *` re-exports needing `follow_imports = "skip"`,
  a couple of `None`-pinned attribute types, a fallback return that violated its own signature)
  — all fixed, no behavior change.
- **Web UI now defaults the mode dropdown to "Find Neighbors" (`active-scan`)** instead of DHCP
  Exhaustion — non-destructive discovery is the sensible first thing to run against an
  unfamiliar network.
- `docs/DESIGN.md` streamlined to drop duplicated version-history/changelog narrative (now just
  points at this file) and to match current code (`RUN_ONCE_MODES` location, `active_scan_listen`,
  the `--report` format-dispatch fix, removal of the legacy `pig.py` shim).

## 2.6.0 — 2026-08-01

- **Breaking: the legacy `pig.py` compatibility layer is gone.** `pig.py` at the repo root, the
  `pig` console script, and `dhcpig/cli/compat.py` (the getopt-to-new-CLI translator) have all
  been removed. The shim was introduced to keep `./pig.py <iface>` working "for one release"
  during the 2.0 rewrite; five releases on, it was translating flags into a CLI that had since
  dropped or repurposed most of them — `-t/--threads` and `-f/--fuzz` were already silent
  no-ops, `-g` fell through to plain exhaust, and `-r` did nothing but print `release --help`.
  Use `dhcpig exhaust <iface>` and `dhcpig release <iface>` directly.
- Behavior carried over from the original tool is unaffected: simulated clients still use the
  `DE:AD:` MAC prefix so captures stay recognizable, and DISCOVER/REQUEST still send the
  macOS-style parameter-request-list order to avoid trivial fingerprint-based rejection.

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
