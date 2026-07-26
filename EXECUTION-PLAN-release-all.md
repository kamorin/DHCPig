# DHCPig — `release-all` Execution Plan (proposal)

> **Status: PROPOSAL, not yet approved.** §3 and §10 contain open decisions the maintainer must
> settle before any code is written. Read `AGENT_HANDOFF.md` first (architecture, safety model,
> test commands) and `EXECUTION-PLAN-v2.1.md` for the conventions this plan follows.
>
> Companion context: `DHCPig-SoT.md` (product rationale) lives in the user's outputs folder,
> not the repo.

---

## 0. Why this command exists

`exhaust` is a validation tool, and the whole point of a successful validation is that the
network is left in a broken state: the pool is drained and legitimate clients cannot get an
address. Today the only way back is `dhcpig restore <iface>`, which releases **exactly the
leases the currently-running engine acquired, from its own memory**. That covers the happy path
and nothing else. If the process was killed, the box was rebooted, the run happened yesterday,
or the operator is standing at a different machine than the one that ran the test, there is no
recovery path in the tool at all — the network stays down until every lease times out or someone
gets on the DHCP server console.

`release-all` is the recovery command: **given a network and whatever evidence is available,
give the pool back.**

### Relationship to the existing `release` mode

`release` (`Mode.RELEASE_NEIGHBORS`) is an *attack* — it ARP-sweeps the segment and sends
DHCPRELEASE for hosts that answer, to test whether the switch permits third-party lease
teardown. It only ever touches addresses with a **live host behind them**.

`release-all` is the exact inverse. The leases created by an exhaustion run are held by MACs
that exist nowhere — they never answer ARP, they never send traffic, they are pure phantoms in
the server's binding table. `release` cannot see them by construction. `release-all` targets
the address range rather than the live hosts, and its default posture is to *avoid* live hosts
rather than seek them out.

That inversion is the cleanest discriminator available and §5 leans on it heavily:
**an address that answers ARP belongs to a real client; an address that holds a binding but
answers nothing is a likely phantom.**

---

## 1. The identification problem (read this before designing anything)

DHCPRELEASE is not addressed to an IP. Per RFC 2131 the server locates the binding to tear
down by matching the message's **client identity** — option 61 client-id if present, otherwise
`chaddr` — against `ciaddr`. ISC dhcpd, Windows DHCP Server and dnsmasq all discard
a RELEASE whose client identity does not match the binding they hold, and they do so
**silently**: no NAK, no ICMP, no error. A wrong-MAC release is indistinguishable on the wire
from a successful one.

So the entire difficulty of `release-all` reduces to one question:

> **For each address in the pool, what MAC is the lease bound to?**

`exhaust` generates client MACs with `netutils.random_mac()`, which is
`de:ad:` + `randint(0x00,0x29)` + `randint(0x00,0x7f)` + two free octets. That is roughly
352 million combinations per address — **the prefix is a filter, never an enumeration source.**
Do not let anyone talk you into a brute-force sweep; it is nine orders of magnitude too slow
and would be indistinguishable from an attack.

There are only four honest ways to answer the question, plus one dishonest one. §2 ranks them.

---

## 2. Strategies for recovering the MAC↔IP bindings

Ranked by fidelity. `--strategy auto` (proposed default) walks this ladder top-down, verifying
after each rung and stopping as soon as the pool is serving again.

### S1 — Replay our own records (authoritative)

The engine already knows every binding it created. Two sources:

| Source | Flag | Availability |
|---|---|---|
| Saved JSON report | `--from-report run.json` | Only if the operator passed `--report` and the run finished cleanly |
| **Lease journal** | `--from-journal PATH\|auto` | **Always, if we build it** — see below |

`reporting.SessionRecorder` already stores `asdict(event.lease)` for every `LeaseReleased` /
`AckReceived`, so `leases[]` in an existing report is *already* a complete, correct recovery
manifest containing `mac`, `ip`, `server_ip`, `xid` and `server_mac`. `--from-report` is nearly
free to implement and should ship first.

The report's weakness is that it is written **once, at the end**. A `kill -9`, a switch putting
the port in err-disable, or a power cut leaves the network drained and no record of it. The fix
is a **lease journal**: an append-only JSONL file written from `_handle_ack()` at the moment
each ACK lands, and `fsync`'d cheaply (or opened line-buffered). One line per lease:

```json
{"ts":1753500000.12,"iface":"eth1","mac":"de:ad:11:22:33:44","ip":"172.20.0.83",
 "server_ip":"172.20.15.1","server_mac":"00:0c:29:aa:bb:cc","xid":305419896,"lease_time":3600}
```

Location: `/var/lib/dhcpig/leases-<iface>.jsonl` when running as root (which exhaust always is),
falling back to `$XDG_STATE_HOME/dhcpig/`. `--from-journal auto` discovers the newest journal
for the named interface. Entries are marked released rather than deleted, so a partially
successful recovery can be resumed.

**This is the single highest-value piece of work in the plan.** It converts recovery from
"hopefully" to "deterministically" for every run made after it ships, and it is a ~60-line
module. Everything below exists to cover runs that predate the journal, runs by other tools,
and journals that were lost.

### S2 — Ask the server: DHCPLEASEQUERY (RFC 4388)

RFC 4388 defines exactly the query this problem needs: `DHCPLEASEQUERY` (message type 10) asks a
server "who holds this address?" and the server answers `DHCPLEASEACTIVE` (13) carrying the
binding's `chaddr`, client-id and remaining lease time — or `DHCPLEASEUNASSIGNED` (11) /
`DHCPLEASEUNKNOWN` (12). Query by IP address, by MAC, or by client-id.

This is the *only* strategy that works with **zero prior records**, from a different machine,
days later. Walk the scope, ask for each address, release each one that comes back active with
the MAC the server itself just handed us. It is a read-only query, which fits the tool's
posture, and combining it with the `de:ad:` prefix filter (§1) lets us release *only the leases
this tool created* and leave every legitimate client alone — a level of precision none of the
other strategies can reach.

**Be honest about the caveats in the docs and in the finding text:**

- Leasequery was designed for relay agents and access concentrators. ISC dhcpd requires an
  explicit `allow leasequery;` and by default answers only configured, permitted sources; many
  deployments never enable it. Windows DHCP Server supports it but likewise scoped.
- The query normally carries a `giaddr` identifying the requesting relay. Sending it from a
  plain client with `giaddr=0.0.0.0` is a legitimate thing to try, and is quietly dropped by
  some servers.
- A non-answer is ambiguous: unsupported, not permitted, or lost. Treat silence as "strategy
  unavailable" and fall through — never as "address is free".

Cost: one new builder plus one parser in `packets.py` (~50 lines), and a probe-then-fallback
loop. Worth it; it is the difference between a recovery tool and a recovery tool that only works
on our own leases from our own machine.

### S3 — MAC-prefix filter (`de:ad:`) — a filter, not a source

Every MAC this tool has ever generated starts `de:ad:`, a deliberate legacy carry-over from
`pig.py` so captures are recognizable. That makes provenance decidable: given a binding from S1
or S2, we can say whether *we* created it.

It cannot enumerate anything on its own (§1). Its job is to power `--only-ours` (proposed
default ON), which is what keeps `release-all` from being a network-wide denial of service.

### S4 — ARP-derived bindings (the existing `release` behaviour)

`_discover_neighbors()` gives live MAC↔IP pairs. For `release-all` this is **the wrong set**:
it finds real clients and misses every phantom. It is included only as `--include-live`
(default OFF) for the case where an operator genuinely wants to clear the whole segment —
and that case is an attack, not a recovery.

### S5 — Blind release sweep (`--blind`) — include, but tell the truth about it

Send RELEASE for every in-scope address with a forged `chaddr`. Against ISC dhcpd, Windows
DHCP and dnsmasq this **will not work**, for the reason in §1. Some embedded/SOHO servers key
the teardown on `ciaddr` + `server_id` alone and will honour it.

If it ships it must be off by default, must print a warning saying it is expected to fail on
any real server, and — critically — its effect must be **measured, not assumed** (§6). Shipping
a flag that fires thousands of packets and reports "12,000 releases sent" while changing nothing
would be the single most misleading thing in the tool.

### S6 — Out-of-band (documented, never implemented)

When every strategy fails, the report should say so plainly and recommend the server-side fix:
`omshell` / `dhcp-lease-list` + config reload on ISC, `netsh dhcp server scope <s> delete
clientsbyip` or a scope reconcile on Windows, or a service restart. DHCPig should not attempt
to log into DHCP servers. A `POOL_RECOVERY_FAILED` finding carrying that recommendation is the
correct output.

### Explicitly rejected

- **DHCPDECLINE.** Wrong semantics and actively harmful: DECLINE tells the server the address
  is in conflict, so it marks it **abandoned** and holds it out of the pool for a long time
  (ISC dhcpd's `abandon-lease-time` defaults to 24 hours). That deepens the outage instead of
  fixing it, and turns a recovery command into a more durable attack than `exhaust` itself.
  Do not add it.
- **Brute-forcing the MAC space.** See §1.
- **Spoofing a relay agent (`giaddr`) to unlock leasequery.** Impersonating infrastructure to
  bypass a server's access control is over the whitehat line. Set `giaddr=0.0.0.0`, and if the
  server declines to answer, fall through.

### The zeroth option: wait

If the journal has `lease_time` we can compute when each phantom lease expires naturally.
When the remaining time is short, "wait 11 minutes" beats any risky sweep, and the tool should
say so up front rather than sending a single packet. This requires a small prerequisite fix:
**`_handle_ack()` does not currently parse DHCP option 51, so `Lease.lease_time` is always
`None`.** Fix that as part of the journal work (§8, phase 0).

---

## 3. Proposed CLI surface

```
dhcpig release-all <iface> [options]

BINDING SOURCES (tried in this order under --strategy auto)
  --from-journal PATH|auto   replay the lease journal written during exhaust   [auto]
  --from-report PATH         replay leases[] out of a saved JSON report
  --leasequery               ask the server for each binding (RFC 4388)
  --include-live             also release addresses that answer ARP (real clients!)  [off]
  --blind                    last resort: RELEASE every in-scope address, forged chaddr [off]
  --strategy auto|journal|report|leasequery|blind                                 [auto]

TARGETING
  --scope CIDR               repeatable; defaults to the interface's own network
  --exclude IP|CIDR          repeatable; never release these
  --only-ours / --all-macs   restrict to de:ad: MACs this tool created            [--only-ours]
  --keep-infra               never release the gateway, DHCP server, or our own IP     [on]
  --server IP                skip discovery; use this DHCP server identity

EXECUTION
  --rate N                   pps                                                      [50]
  --passes N                 repeat the sweep N times (servers can drop the first)      [2]
  --verify / --no-verify     control transaction + headroom, before and after          [on]
  --dry-run                  build and log every RELEASE, send nothing
  --report PATH              write the recovery report
```

Notes on the defaults, since each is a claim:

- **`--only-ours` ON.** This is what makes the command a recovery tool. Without it,
  `release-all` on a production segment is a network-wide outage. `--all-macs` should require an
  interactive confirmation (or `--yes`).
- **`--keep-infra` ON.** Releasing the gateway or the DHCP server's own lease turns a
  recoverable outage into a site visit.
- **`--rate 50`, not 7.** Every other mode defaults to 7 pps because it is *causing* disruption
  and should do so gently. `release-all` runs during an outage the operator is trying to end;
  a /22 at 7 pps is two and a half minutes of avoidable downtime. RELEASE is unicast to the
  server, so the segment sees almost none of it. **Open decision — see §10.**
- **`--passes 2`.** RELEASE is unacknowledged by design (RFC 2131 has no reply to it), so a
  dropped frame is an address that stays lost with no indication. A second pass over whatever
  is still unrecovered is cheap insurance.

---

## 4. Execution flow

```
0. resolve scope (--scope, else the interface's network) and exclusions
1. control transaction, `new` client leg          -> is the pool actually exhausted?
     |
     +-- succeeds -> NO_RECOVERY_NEEDED finding, exit 0 without sending a single RELEASE
     |
     +-- fails/denied -> continue
2. learn the server identity + MAC (from control_pre, or --server)
3. estimate the pool and record baseline headroom
4. for each strategy on the ladder (§2), until the pool serves again:
       a. gather candidate bindings
       b. filter: scope, --exclude, --keep-infra, --only-ours, ARP-liveness
       c. report what will be released; if --dry-run, stop here
       d. send RELEASE for each binding through _send()   (rate-limited, scope-gated)
       e. re-run the control transaction  -> did a new client just get an address?
5. --passes: repeat 4 for anything still unrecovered
6. final control + headroom re-estimate; emit the recovery finding; write the report
```

Step 1 is the one that must not be skipped. Firing a recovery sweep at a healthy network is
pure downside, and the tool already owns a reliable "can a new client get an address?" probe in
`_control_transaction(phase, client="new")`. Reuse it.

---

## 5. Safety model

`release-all` is, mechanically, the most destructive command in the tool — it is the only one
whose natural target set is "every address on the network". The safety posture has to come from
the defaults, because the packets themselves are indistinguishable from an attack.

Never released, regardless of strategy:

- the default gateway and the DHCP server(s) (`--keep-infra`, on by default)
- this machine's own address
- anything matching `--exclude`
- anything outside `--scope` — enforced in `_send()` by `ScopeGuard`, as always
- **anything that answers ARP**, unless `--include-live` (this is the big one — a live host is
  by definition not a phantom lease, so releasing it cannot be recovery)
- any MAC that is not `de:ad:`-prefixed, unless `--all-macs`

### The whitehat line

`EXECUTION-PLAN-v2.1.md` fixed the constraint "no new offensive capability", and this plan has
to be measured against it honestly:

- Default `release-all` (journal/report/leasequery + `--only-ours` + live hosts skipped) adds
  **no** offensive capability. It releases leases the tool itself created, and it can only do
  that because it has records proving it created them. It is strictly a cleanup tool.
- `--include-live` is a re-skin of the existing `release` mode across a wider address range.
  No new capability, but broader blast radius.
- **`--blind --all-macs` together are a new offensive capability** — an unauthenticated,
  network-wide lease teardown against clients the tool never touched. That combination should
  either be dropped from the plan or gated behind an interactive typed confirmation and
  documented in `SECURITY.md` as the disruptive path it is. **Open decision — see §10.**

---

## 6. Verification and findings — measure the effect, never the frames

The project's established rule is that a phase reports *observed effect* rather than packets
sent; `_reprobe_released()` exists precisely because servers vary in whether they honour an
unauthenticated RELEASE. `release-all` follows the same discipline, and it has a better probe
available than ARP: **the control transaction.** "A brand-new MAC just received an address" is
direct, unambiguous evidence the pool is serving again.

Proposed findings:

| id | verdict | when |
|---|---|---|
| `NO_RECOVERY_NEEDED` | INFO | pre-flight control succeeded; nothing was sent |
| `POOL_RECOVERED` | PASS | post control succeeds and headroom returned |
| `POOL_RECOVERY_PARTIAL` | INCONCLUSIVE | some bindings cleared, a new client still can't get an address |
| `POOL_RECOVERY_FAILED` | FAIL | releases sent, control still denied — carries the §2 S6 recommendation |
| `LEASEQUERY_UNAVAILABLE` | INFO | server did not answer leasequery; records-based recovery only |
| `BLIND_RELEASE_INEFFECTIVE` | INFO | `--blind` ran and measurably changed nothing (the expected result) |

Every one of these reports counts of *addresses observed recovered*, alongside frames sent, and
never conflates the two.

---

## 7. What gets reused

Most of this command already exists. The point of the design is to add a new **target-selection
strategy** in front of machinery that is already correct and tested.

| Existing | Reuse |
|---|---|
| `packets.build_release_v4()` | **Unchanged.** Already carries the 2.1 fixes (Ether layer, real `server_id`, unicast to `server_mac`) |
| `engine._do_release()` | Generalize slightly — it takes `list[Neighbor]`; extract `_release_bindings(pairs, server_ip, server_mac)` and have both callers use it, so there is still one send path |
| `engine._control_transaction()` | Pre-flight check, server discovery, and post-recovery verification |
| `engine._discover_neighbors()` | The ARP-liveness filter |
| `engine._reprobe_released()` | Secondary per-address effect check |
| `engine._estimate_pool()` / `_pool_headroom()` | Before/after headroom in the report |
| `engine._send()`, `ScopeGuard`, `RateLimiter` | Unchanged invariant — every frame still funnels through `_send()` |
| `reporting.SessionRecorder` | `leases[]` is already a recovery manifest; also the `--from-report` input |
| `events.LeaseReleased` | Already emitted per release |
| `cli/render.py`, web SPA | New mode slots into the existing event/tab plumbing |

New code:

- `Mode.RELEASE_ALL = "release-all"` in `models.py`
- `core/journal.py` — append-only JSONL lease journal (~60 lines)
- `packets.build_leasequery_v4()` + `parse_leasequery_reply()` (only if S2 is approved)
- `engine._run_release_all()` + the strategy ladder
- findings from §6; CLI subcommand; web mode entry

---

## 8. Phasing

Each phase is its own commit, tests green before the next starts — the convention from
`EXECUTION-PLAN-v2.1.md`.

- **Phase 0 — prerequisites.** Parse DHCP option 51 into `Lease.lease_time` (currently never
  populated). Extract `_release_bindings()` out of `_do_release()`. Tests for both.
- **Phase 1 — lease journal.** `core/journal.py`; write from `_handle_ack()`; mark entries
  released from `restore()` / `_do_release()`. Tests: journal survives a simulated crash,
  round-trips, and is idempotent on resume.
- **Phase 2 — `release-all` skeleton, records-only.** New mode, CLI subcommand, `--from-journal`
  / `--from-report`, filters, pre/post control verification, findings, dry-run. This alone is a
  complete and useful recovery tool.
- **Phase 3 — leasequery (if approved).** Builder, parser, probe-and-fallback, the
  `LEASEQUERY_UNAVAILABLE` finding.
- **Phase 4 — `--include-live` / `--blind` (if approved).** Confirmation gate, warnings,
  effectiveness measurement, `SECURITY.md` update.
- **Phase 5 — web UI + docs.** Mode in the SPA, README/SECURITY/AGENT_HANDOFF/CHANGELOG.

Recommendation: **ship phases 0–2 and stop for review.** They deliver deterministic recovery for
every future run, add zero offensive capability, and are the parts with no open questions.

---

## 9. Acceptance criteria (phases 0–2)

- [ ] `Lease.lease_time` is populated from option 51; regression test with a fixture ACK.
- [ ] A journal written during an exhaust run replays into a correct release set after the
      engine object is destroyed (simulating a killed process).
- [ ] `release-all --dry-run` sends zero packets and lists exactly the bindings it would release.
- [ ] Pre-flight control success ⇒ `NO_RECOVERY_NEEDED`, zero frames sent, exit 0.
- [ ] Gateway, DHCP server, own IP, `--exclude` targets and non-`de:ad:` MACs are all absent from
      the release set under default flags.
- [ ] An address that answers ARP is skipped without `--include-live`.
- [ ] Recovery findings report addresses-observed-recovered separately from frames-sent.
- [ ] Integration test (netns + `FakeDhcpServer`): exhaust to drain, kill the engine, run
      `release-all --from-journal`, assert a fresh MAC gets an address afterwards.
- [ ] `ruff check` / `ruff format --check` clean; full suite green.

---

## 10. Open decisions for the maintainer

1. **Is DHCPLEASEQUERY (S2) in scope?** It is the only strategy that recovers a network with no
   local records, and the only one that can precisely distinguish our leases from real clients
   without a journal. Cost is a new message type in `packets.py` and honest handling of the
   common case where the server just doesn't answer.
2. **Do `--blind` and `--all-macs` ship at all?** Together they cross the "no new offensive
   capability" line (§5). Options: drop both; ship `--blind` only in combination with
   `--only-ours`; or ship both behind a typed confirmation and document them as disruptive.
3. **Default `--rate`: 50 or 7?** Every other mode is 7. Recovery is time-critical and the
   traffic is unicast to one server, which argues for faster — but it breaks the "7 everywhere"
   consistency you just established.
4. **Journal location and retention.** `/var/lib/dhcpig/` with an `$XDG_STATE_HOME` fallback is
   proposed. Do journals get pruned automatically, and after how long? They are a record of
   which addresses the tool took on a customer network, so retention is also a data-handling
   question.
5. **Does `dhcpig restore` become an alias?** `restore` is `release-all --from-journal` scoped
   to the current session. Keeping both is fine; folding `restore` into the new command would
   be a breaking change to a documented command.
