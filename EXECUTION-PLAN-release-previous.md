# DHCPig — `release-previous` Execution Plan

> **For the implementing model. Self-contained.** Read `AGENT_HANDOFF.md` first (architecture,
> paths, safety model, test commands), then execute the phases below **in order**. Land each
> phase as its own commit. Do not start a phase until the previous phase's acceptance criteria
> are green.
>
> Background on why this design was chosen over the alternatives (DHCPLEASEQUERY, ARP-derived
> bindings, blind sweeps) is in `EXECUTION-PLAN-release-all.md` §2. You do not need to read it
> to execute this plan, but do not "improve" this plan by adding those strategies — they were
> considered and rejected for this command.

---

## 0. What you are building, and why

`exhaust` drains a DHCP pool. When it succeeds, the network is left broken on purpose: every
address is bound to a MAC that exists nowhere, so no legitimate client can get an address. The
only recovery today is `dhcpig restore <iface>`, which releases the leases held **in the memory
of the currently-running engine object**. If the process was killed, the box rebooted, or the
run happened yesterday, there is no recovery path in the tool at all.

`release-previous` is that path:

> **Read the on-disk lease journal, take every lease we ACKed that belongs to the network we are
> plugged into right now, and send DHCPRELEASE for each one.**

Two pieces of work: a **lease journal** that `exhaust` writes as ACKs land (Phase 1), and the
**`release-previous` command** that replays it (Phase 2).

### The one fact that makes this design work

DHCPRELEASE is not addressed to an IP. Per RFC 2131 the server finds the binding to tear down by
matching the message's **client identity** — DHCP option 61 client-id if present, otherwise
`chaddr` — against `ciaddr`. ISC dhcpd, Windows DHCP Server and dnsmasq all discard a RELEASE
whose client identity doesn't match the binding they hold, and they do it **silently**: no NAK,
no ICMP, nothing on the wire distinguishes a successful release from an ignored one.

Two consequences that shape everything below:

1. **You cannot release an address without knowing its MAC.** `exhaust` generates MACs with
   `netutils.random_mac()` (`de:ad:` + 4 random-ish octets, ~352 million combinations). Guessing
   is not an option. The journal exists because it is the only reliable source of those MACs.
2. **A stale journal entry is harmless.** If one of our phantom leases already expired and the
   server has since given that address to a real client, our RELEASE carries the old `de:ad:`
   MAC, doesn't match the new binding, and is ignored. The same identity check that makes
   recovery hard also makes it safe. **This is why `release-previous` needs no ARP-liveness
   check** — do not add one.

### Scope of this command — read this before designing anything

`release-previous` releases **only leases this tool recorded taking.** It is a cleanup tool, not
an attack. It adds **no new offensive capability**: every address it touches is one the journal
proves we acquired, and the RELEASE only works because we hold the matching identity.

Do not add: leasequery, blind sweeps, ARP-derived targets, an `--all-macs` escape hatch, or
anything else that would let it release a lease the tool did not create. If a future request
needs that, it is a different command.

---

## 1. Constraints (non-negotiable)

Carried from `EXECUTION-PLAN-v2.1.md`; they still hold.

- Python ≥3.11. **`scapy>=2.5` is the only runtime dependency.** The journal is stdlib `json` +
  plain file I/O — no new deps, not even a TOML/YAML reader.
- `dhcpig.core` is **UI-free** — never `print`, only `bus.emit()`. The journal module must not
  print or log to stderr; surface problems as `ev.Debug` / `ev.ErrorEvent` through the engine.
- **Every outbound frame goes through `DhcpEngine._send()`** (`engine.py:127`). That is the one
  chokepoint enforcing scope, rate limiting and dry-run. Do not add a `sendp` call anywhere.
- Forged MACs stay bogus. Do not re-add the authorization gate — it was removed deliberately.
- `ruff` line length 100; type hints in `core`; a test with every behaviour change.
- The control transaction is mandatory in `exhaust` and has no opt-out. Do not add a `control`
  field back to `SessionConfig`.

### Running the tests

The package requires Python ≥3.11, so `pip install -e .` fails on the 3.10 sandbox. Run:

```
cd <repo root>
PYTHONPATH=src python3 -m pytest -q
python3 -m ruff check src tests
python3 -m ruff format --check src tests
```

Baseline before you start: **155 passed, 1 deselected.**

---

## 2. Orientation — the code you will touch

| File | What's there now |
|---|---|
| `src/dhcpig/core/models.py` | `Mode` enum (:15), `SessionConfig` (:50), `Lease` (:110), `Finding` (:177) |
| `src/dhcpig/core/engine.py` | `_send` (:127), mode `runners` dict (:162), `restore` (:269), `_control_transaction` (:359), `_raise` (:442), `_do_release` (:739), `_handle_ack` (:1231), `_run_release`/`_release_worker` (:1327) |
| `src/dhcpig/core/packets.py` | `build_release_v4(mac, ip, server_ip, xid, server_mac=None, src_mac=None)` (:89) — **correct, do not change** |
| `src/dhcpig/core/netutils.py` | `random_mac()` (:24), `iface_network_cidr(iface)` (:104), `get_if_ip` |
| `src/dhcpig/core/safety.py` | `ScopeGuard`, `RateLimiter`, `CleanupRegistry` |
| `src/dhcpig/core/events.py` | event dataclasses; `LeaseReleased`, `FindingRaised`, `Debug` already exist |
| `src/dhcpig/cli/main.py` | `_MODE_BY_CMD` (:30), `build_parser` (:~60), `build_config` (:156), `main` dispatch (:276) |
| `src/dhcpig/web/schemas.py` | `config_from_payload`, `as_cli` |
| `tests/unit/` | `test_control_findings.py`, `test_engine.py`, `test_packets.py`, `test_cli.py`, `test_web.py` |

Line numbers are from the current HEAD and will drift as you edit — use them as a starting
point, not gospel.

---

## Phase 0 — prerequisites

Two small changes that Phases 1 and 2 both depend on. Land as one commit.

### 0a. Populate `Lease.lease_time` from DHCP option 51

`models.Lease` has a `lease_time: int | None` field that **is never set** — `_handle_ack()`
builds the `Lease` without it. The journal needs it to skip entries whose lease has certainly
expired.

In `packets.py`, add a helper alongside `server_identifier()`:

```python
def lease_time_from(options: list) -> int | None:
    """DHCP option 51 (lease-time) in seconds, or None if the server didn't send one."""
    for opt in options:
        if isinstance(opt, tuple) and opt and opt[0] == "lease_time":
            try:
                return int(opt[1])
            except (TypeError, ValueError):
                return None
    return None
```

Call it from `_handle_ack()` and pass the result into the `Lease(...)` construction.

**Tests** (`tests/unit/test_packets.py`): a fixture ACK carrying `("lease_time", 3600)` yields
`3600`; an ACK with no option 51 yields `None`; a malformed value yields `None` rather than
raising.

### 0b. Extract `_release_bindings()` out of `_do_release()`

`_do_release()` takes `list[Neighbor]`, but `release-previous` works from journal records. Keep
**one** release send-path rather than growing a second.

```python
def _release_bindings(
    self, bindings: list[tuple[str, str]], server_ip: str, server_mac: str | None = None
) -> int:
    """Send DHCPRELEASE for each (mac, ip). Returns frames sent. Unit-testable."""
```

Move the body of `_do_release()` into it (build via `packets.build_release_v4`, send via
`self._send(pkt, target_ip=ip)`, increment `self.releases`, emit `ev.LeaseReleased`), and make
`_do_release()` a thin wrapper that maps neighbors to `(n.mac, n.ip)` pairs and calls it.

**Behaviour must not change.** The existing release tests are the regression check.

**Acceptance:** full suite green (155 passed), ruff clean, no behavioural diff in `release` mode
or in `exhaust`'s release phase.

---

## Phase 1 — the lease journal

New module `src/dhcpig/core/journal.py`. Roughly 100 lines. No new dependencies.

### Format: append-only JSONL, two record kinds

Never rewrite or mutate the file — a recovery tool whose state file can be corrupted by a crash
mid-write is worse than no recovery tool. Two record kinds, folded at read time:

```json
{"ev":"ack","ts":1753500000.12,"iface":"eth1","mac":"de:ad:11:22:33:44","ip":"172.20.0.83","server_ip":"172.20.15.1","server_mac":"00:0c:29:aa:bb:cc","xid":305419896,"lease_time":3600}
{"ev":"released","ts":1753500912.44,"iface":"eth1","mac":"de:ad:11:22:33:44","ip":"172.20.0.83"}
```

A reader folds these into current state keyed by `(mac, ip)`: an `ack` record opens a lease, a
later `released` record closes it. `load_open_leases()` returns only the ones still open.

### Location

`/var/lib/dhcpig/leases-<iface>.jsonl` when that directory is creatable and writable (exhaust
always runs as root, so this is the normal case). Otherwise fall back in order to
`$XDG_STATE_HOME/dhcpig/` then `~/.local/state/dhcpig/`. Resolve once and expose it — the CLI
needs to print the path, and `release-previous --journal PATH` needs to override it.

One file per interface, appended across runs. That is what makes the command *previous*: it
covers every prior run on that interface, not just the last one.

### API

```python
def default_path(iface: str) -> Path: ...
def record_ack(path: Path, iface: str, lease: Lease) -> None: ...
def record_released(path: Path, iface: str, mac: str, ip: str) -> None: ...
def load_open_leases(path: Path) -> tuple[list[JournalEntry], list[str]]: ...
```

`load_open_leases` returns `(entries, warnings)` — warnings are human-readable strings the
engine turns into `ev.Debug`. **The reader must never raise on a bad file.** A truncated final
line (the killed-mid-write case this whole feature exists for), a malformed JSON line, an
unknown `ev` value, or a missing field → skip that line, add a warning, keep going.

### Durability

Open with `open(path, "a", buffering=1)` (line buffered) and `flush()` after each record. A
single `write()` of one line to an `O_APPEND` fd is effectively atomic on local filesystems, so
concurrent exhaust-writes and release-previous-reads don't need locking. `os.fsync` after every
ACK is too expensive at exhaust rates — don't. Losing the last record or two to a power cut is
acceptable; losing the file is not.

### Wiring into the engine

- `_handle_ack()` → `journal.record_ack(...)` right after `self.cleanup.register(lease)`.
- `restore()` and `_release_bindings()` → `journal.record_released(...)` per released lease.
- Journal writes are **best-effort**: wrap in `try/except OSError`, emit `ev.Debug` on failure,
  and never let a journal problem kill a run. A read-only `/var/lib` must degrade to "no
  recovery data", not "exhaust crashes".
- Add `SessionConfig.journal: bool = True` and `journal_path: Path | None = None`. Journaling is
  on by default — a recovery tool that only sometimes records is useless. `--no-journal` exists
  for the operator who does not want the artifact on disk.

### Retention

The journal is a persistent on-disk record of which addresses the tool took on a customer's
network. It persists at the documented path; the operator removes it. `release-previous` applies
an age filter at read time (Phase 2, `--max-age`, default 7 days) so ancient entries don't slow
a recovery run. Document it in `SECURITY.md` as engagement data with a real lifetime.

### Tests (`tests/unit/test_journal.py`, new)

- Round-trip: two acks + one released ⇒ `load_open_leases` returns one entry.
- **Crash simulation:** append a truncated partial JSON line; the reader returns the good
  entries plus a warning and does not raise.
- Malformed line, unknown `ev`, and missing required field are each skipped with a warning.
- `default_path` falls back correctly when `/var/lib` is not writable (monkeypatch).
- Engine integration: driving a synthetic ACK through `_on_dhcp` (see `test_control_findings.py`
  for the existing pattern) writes an `ack` record to a `tmp_path` journal.
- `dry_run=True` writes **nothing** — no packets, no journal records.

**Acceptance:** all of the above green; full suite still green; ruff clean.

---

## Phase 2 — the `release-previous` command

### Mode and config

- `models.Mode.RELEASE_PREVIOUS = "release-previous"`.
- Do **not** add it to `DESTRUCTIVE_MODES`. It only releases leases we recorded taking; labelling
  it destructive alongside `garp` would be misleading.
- `SessionConfig` additions: `journal_path`, `max_age_days: float = 7.0`,
  `require_same_server: bool = True`.

### Selection: which journal entries get released

This is the substance of the command. Start from `load_open_leases()` and filter:

1. **Interface** — entry's `iface` matches the interface we are running on.
2. **Current CIDR** — entry's `ip` falls inside `--scope` if given, else
   `netutils.iface_network_cidr(iface)`. Use `ScopeGuard` for the test so the semantics match
   the rest of the tool. If neither a scope nor an interface network can be determined, **refuse
   to run** and say why — an unbounded release-previous is exactly what this filter prevents.
3. **Same server** (`require_same_server`, default on) — see the hazard below.
4. **Age** — skip entries where `ts + lease_time` is more than `--max-age` days in the past.
   When `lease_time` is `None` (pre-Phase-0 journals, or a server that sent no option 51), fall
   back to `ts` alone. Skipping is an optimisation, not a safety measure — stale entries are
   harmless (§0), they just waste time.

Report the counts at each filter step. "Journal: 812 open leases; 640 in 172.20.0.0/22; 12
skipped (different server); 3 skipped (expired) → 625 to release" is the output an operator
under pressure actually needs.

#### The RFC 1918 collision hazard — why filter 3 exists

Filtering by CIDR alone is not enough. `192.168.1.0/24` at customer A and customer B are
indistinguishable by address. A journal carried between engagements on the same laptop, with the
same interface name, will happily produce release targets for the *wrong network*.

Mitigation: the pre-flight control transaction learns the current server's identity
(`ControlOutcome.server_id` / `.server_mac`). Compare it against each journal entry's recorded
`server_ip`/`server_mac` and skip mismatches by default, with an explicit count in the output.
`--any-server` overrides for the legitimate case where the server was replaced or renumbered.

If the pre-flight control cannot learn a server identity at all, `require_same_server` cannot be
evaluated — warn clearly and fall back to CIDR-only filtering rather than silently doing nothing.

### Flow

```
1. resolve the journal path and load open leases     (warnings -> Debug events)
2. resolve the current CIDR (--scope, else the interface network); refuse if neither
3. pre-flight control transaction, client="new"      -> can a new client get an address?
     |
     +-- succeeds -> NO_RECOVERY_NEEDED finding, exit 0, ZERO frames sent
     |
     +-- fails    -> the pool is drained (or DHCP is unreachable); continue
4. filter the journal entries per the rules above; emit the per-step counts
5. if --dry-run: print/emit exactly what would be released, send nothing, exit
6. release: _release_bindings((mac, ip) pairs, entry.server_ip, entry.server_mac)
     - group by (server_ip, server_mac) so each batch unicasts to the right server
     - record a `released` journal record per lease as it goes (so a killed run resumes)
7. --passes (default 2): repeat 6 for entries not yet confirmed released
8. post control transaction, client="new" -> did recovery actually work?
9. emit the finding; write the report
```

**Step 3 is the one that must not be skipped.** Firing a recovery sweep at a healthy network is
pure downside, and `_control_transaction(phase, client="new")` is already a reliable "can a new
client get an address?" probe. Reuse it, don't reimplement it.

**Note what step 6 does *not* need:** no ARP sweep, no server discovery, no leasequery. The
journal already carries `mac`, `ip`, `server_ip` and `server_mac` for every lease. The control
transactions exist purely to produce a trustworthy verdict — the release itself is fully
self-sufficient from disk. Keep it that way.

`--passes 2` exists because RFC 2131 defines no reply to a RELEASE. A dropped frame is an
address that stays lost with no indication, and a second pass is cheap insurance.

### CLI surface

```
dhcpig release-previous <iface> [options]

  --journal PATH        override the journal location (default: the resolved per-iface path)
  --scope CIDR          repeatable; defaults to the interface's own network
  --max-age DAYS        ignore journal entries older than this          [7]
  --any-server          release even when the current server differs from the recorded one
  --rate N              pps                                             [50]
  --passes N            release sweeps                                  [2]
  --dry-run             list what would be released, send nothing
  --report PATH         write the recovery report
  --verbosity N
```

`--rate` defaults to **50**, not the 7 used by every other mode. This command runs during an
outage the operator is trying to end, and its RELEASE frames are unicast to a single server
rather than sprayed at the segment — a /22 of phantom leases clears in ~20 seconds instead of
~2.5 minutes. Put a comment at the default explaining the exception so nobody "fixes" it later.

Wiring: add `"release-previous": Mode.RELEASE_PREVIOUS` to `_MODE_BY_CMD`, a subparser in
`build_parser()`, the new fields in `build_config()`, and `Mode.RELEASE_PREVIOUS:
self._run_release_previous` to the `runners` dict in `engine.py`. Follow `_run_release` /
`_release_worker` as the template — discovery and release run in a worker thread so `start()`
returns promptly.

Also update `web/schemas.py` (`config_from_payload` and `as_cli`) so the mode round-trips, even
before the SPA exposes it.

### Findings

Report **addresses observed recovered**, never frames sent — the project's standing rule, and
the reason `_reprobe_released()` exists. Here the post-run control transaction is the probe, and
it is a better one than ARP: "a brand-new MAC just received an address" is direct evidence the
pool is serving again.

| id | verdict | severity | when |
|---|---|---|---|
| `NO_RECOVERY_NEEDED` | INFO | info | pre-flight control succeeded; nothing sent |
| `POOL_RECOVERED` | PASS | info | post-control succeeds |
| `POOL_RECOVERY_PARTIAL` | INCONCLUSIVE | medium | releases sent, post-control still denied, but journal entries remain unreleased |
| `POOL_RECOVERY_FAILED` | FAIL | high | everything released, post-control still denied |
| `NO_JOURNAL_DATA` | INFO | info | no journal, or nothing matched the filters |

`POOL_RECOVERY_FAILED` must carry a `recommendation` pointing at the out-of-band fix, because at
that point the tool has done everything it can: clear the bindings on the server itself —
`omshell` / lease-file edit + reload on ISC dhcpd, `netsh dhcp server scope <s> delete
clientsbyip` or a scope reconcile on Windows Server — or wait for the leases to expire.

Include in every finding's `evidence`: journal entries loaded, entries selected, frames sent,
passes run, and the pre/post control outcomes.

### Tests (`tests/unit/test_release_previous.py`, new)

Follow the existing root-free pattern: `monkeypatch.setattr(engine_mod, "sendp", ...)` and drive
synthetic packets into `_on_dhcp`.

- Only entries inside the current CIDR are selected; an entry from another subnet is skipped.
- An entry recorded against a different `server_ip` is skipped by default and included with
  `--any-server`.
- An entry older than `--max-age` is skipped.
- An already-`released` entry is never re-released.
- Pre-flight control success ⇒ `NO_RECOVERY_NEEDED`, **zero** `sendp` calls.
- `--dry-run` sends zero frames and still lists the selection.
- Empty/missing journal ⇒ `NO_JOURNAL_DATA`, exit 0, no crash.
- Neither `--scope` nor a resolvable interface network ⇒ refuses to run with a clear error.
- Releases are grouped so each batch carries the `server_ip`/`server_mac` from its own entries.
- A `released` record is journalled per lease, so a second run selects nothing.

### Integration test (`tests/integration/`)

Extend the existing netns + `FakeDhcpServer` harness: run a bounded `exhaust` to drain the fake
pool, **destroy the engine object** (simulating a killed process), run `release-previous
--journal <tmp>`, and assert a fresh MAC gets an address afterwards. That single test is the
whole feature.

---

## Phase 3 — surfaces and docs

- **CLI renderer** (`cli/render.py`): the new findings and a recovery-shaped status line
  (selected / released / passes).
- **Web UI**: `release-previous` in the mode `<select>`; hide the exhaust-only config controls
  for it; show the selection counts on the dashboard. Follow the existing `onModeChange()`
  show/hide pattern in `static/app.js`. Vanilla JS, no build step, no CDN.
- **README**: a RECOVERY section — what the journal is, where it lives, and the
  exhaust → verify → `release-previous` loop.
- **SECURITY.md**: the journal is engagement data on disk (which addresses were taken on whose
  network); document the path, the default-on behaviour, `--no-journal`, and that removal is the
  operator's job.
- **AGENT_HANDOFF.md**: new section on the journal and the recovery command; add
  `core/journal.py` to the core-files table; add to §8 gotchas: *a stale journal entry is
  harmless because the MAC won't match — do not "fix" this with an ARP liveness check.*
- **CHANGELOG.md**: new entry under the unreleased heading.

---

## 3. Acceptance criteria (whole plan)

- [ ] `Lease.lease_time` is populated from option 51; regression tests cover present/absent/malformed.
- [ ] `_release_bindings()` is the single release send-path; `_do_release()` wraps it; no behaviour change.
- [ ] Journal survives a truncated final line, malformed lines, and unknown record kinds without raising.
- [ ] A journal written during exhaust replays correctly after the engine object is destroyed.
- [ ] `release-previous --dry-run` sends zero packets and lists exactly what it would release.
- [ ] Pre-flight control success ⇒ `NO_RECOVERY_NEEDED`, zero frames sent, exit 0.
- [ ] Entries outside the current CIDR, from a different server, or past `--max-age` are excluded.
- [ ] `dry_run=True` writes no journal records.
- [ ] Journal write failure (read-only path) degrades to a Debug event; exhaust still completes.
- [ ] Findings report addresses-observed-recovered separately from frames-sent.
- [ ] Integration test: exhaust → destroy engine → `release-previous` → a fresh MAC gets an address.
- [ ] `ruff check` and `ruff format --check` clean; full suite green (155 baseline + new tests).

---

## 4. Gotchas

- **Do not change `packets.build_release_v4()`.** It was fixed in 2.1 (it now carries an `Ether`
  layer — it was L3-only despite being sent via L2 `sendp()`, so every RELEASE the tool sent
  before that fix was malformed — and it unicasts to `server_mac` when known). It is correct.
- **`server_ip` must come from the journal entry, not from discovery.** The bug that made the
  release phase a silent no-op for years was `server_id=0.0.0.0`, because ARP discovery never
  learns a DHCP server. The journal records the real one per lease. Use it.
- **Group releases by server.** A journal can span multiple servers on the same segment
  (failover pairs, a second scope). Don't send every RELEASE to whichever server you saw first.
- **Never let a journal error kill a run.** Both directions: a write failure must not stop
  `exhaust`, and a corrupt file must not stop `release-previous`.
- **`dry_run` must suppress journal writes too**, not just packets. A dry run that pollutes the
  recovery journal with leases that were never acquired is worse than useless.
- **Don't add an ARP-liveness check.** §0 explains why it's unnecessary; adding one would skip
  legitimate recovery targets on networks where something else answers for a released address.
- **Don't re-add an authorization gate or a `control` opt-out.** Both were removed deliberately.
- **Backtick hazard in commit messages.** Use `git commit -F <file>` with a quoted heredoc
  (`<< 'EOF'`) for multi-line messages; a previous session had backticks in a `-m` message
  interpreted as command substitution and had to amend the result.
