# Contributing to DHCPig

Practical workflow for working on this codebase. For *why* things are shaped the way they are —
the safety model, the confidence/evidence model behind a verdict, the eviction outcome ladder,
and every settled decision not to re-litigate — see `docs/DESIGN.md`. If you're an agent working
from a sandboxed checkout, `CLAUDE.md` has the session-specific bits (paths, sandbox Python
version).

## Layer rules

Three layers, strictly separated:

- **`src/dhcpig/core/`** — the engine. UI-free: never calls `print`; it only emits events on an
  `EventBus`.
- **`src/dhcpig/cli/`** — the `dhcpig` command; subscribes to the bus and prints.
- **`src/dhcpig/web/`** — `dhcpig-web`, a stdlib HTTP server + SSE; subscribes and streams JSON.

Both front ends drive the same `DhcpEngine` and never touch scapy directly. If you're adding
something that needs to reach the operator, it's an event, not a `print()` in `core/`.

Within `core/`, the engine (`engine.py`) holds the state machine and the phase-ordering logic;
several concerns have their own module because their *state* (not their control flow) is
genuinely decoupled from the engine:

| Module | Owns |
|---|---|
| `core/findings.py` | The text of every finding (title/verdict/severity/recommendation) |
| `core/eviction.py` | `EvictionState`, the eviction outcome-rung ordering |
| `core/racing.py` | `RaceState` (race-freed-address bookkeeping) |
| `core/recovery.py` | `release-previous`'s pure journal-entry filter |

The *methods* that drive eviction, racing, and recovery stay on `DhcpEngine` — they're threaded
through `_send()`, the event bus, and `cfg` closely enough that wrapping them in a class holding
a back-reference to the engine would add an indirection layer without reducing coupling. Don't
extract a method into a new module unless it's actually decoupled from the engine instance, the
way `core/recovery.py`'s `select_entries()` is (see its docstring).

## The one invariant that matters most

**Every outbound frame goes through `DhcpEngine._send()`.** It's the single chokepoint that
enforces scope, rate limiting, `offline`, and `dry_run` in one place. If you add a send path that
bypasses it, you've bypassed the whitehat guarantees. See `docs/DESIGN.md` §5 for the full
safety model and §8 for the `dry_run`/`offline`/`probe` distinctions — they're easy to get wrong
by analogy and the doc explains exactly why each exists.

## Running tests and lint

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q                          # unit tests, no root needed
.venv/bin/ruff check src tests
.venv/bin/ruff format --check src tests
.venv/bin/mypy src/dhcpig/core
```

- Everything unit-tested runs **without root** by monkeypatching `dhcpig.core.engine.sendp`.
  `tests/unit/conftest.py`'s `build_engine(monkeypatch, **cfg)` is the shared engine-construction
  helper — use it (or a file-local `_engine()` wrapper around it) rather than reimplementing the
  `EventBus`/monkeypatch/`DhcpEngine` boilerplate again.
- A handful of functions (`random_mac`, `iface_network_cidr`, `scapy.all.get_if_hwaddr`,
  `scapy.all.srp`) are monkeypatched by tests via their *source module's* attribute path (e.g.
  `monkeypatch.setattr("dhcpig.core.netutils.random_mac", ...)`), not by patching `engine.py`'s
  own namespace. Code that calls these **must** go through the module object (`netutils.
  random_mac()`) rather than a bare name bound via `from .netutils import random_mac` — the
  latter freezes a pre-patch reference at import time and silently defeats the monkeypatch. If
  you're not sure whether a function you're calling falls into this category, grep the test
  suite for `monkeypatch.setattr("dhcpig` or `monkeypatch.setattr("scapy` before hoisting an
  import to module level.
- The one integration test (`tests/integration/test_exhaust_live.py`) needs root + Linux (a veth
  pair + a fake DHCP server) and is deselected by default. Run it with `make integration` on a
  real Linux box.
- Add a test with every behaviour change. `mypy` only checks `src/dhcpig/core` (see
  `pyproject.toml`); it currently has pre-existing errors from scapy's stub gaps — a change
  shouldn't add new ones, but don't chase the existing count to zero as part of an unrelated
  change.

## How to add a finding

Findings are the tool's actual output — the auditable verdicts an operator reads. Adding one:

1. Add its static text to the catalogue in `core/findings.py`: an entry in `_CATALOG` keyed by
   the finding id, with `title`, `verdict`, `severity`, `recommendation`. If the title or
   recommendation genuinely varies by call (like `DHCP_STARVATION_NOT_ATTAINED`'s four reason
   variants), leave the catalogue value as a placeholder and pass the real text via `build()`'s
   `title=`/`recommendation=` override instead — see `starvation_not_attained_recommendation()`
   for the pattern.
2. In `engine.py` (or wherever the triggering logic actually lives), call
   `self._raise(findings.build("YOUR_ID", evidence_dict))`. The engine decides *whether* and
   *with what evidence*; `findings.py` owns the *text*. Don't construct a bare `Finding(...)`
   directly outside `findings.py` — every finding should be reachable by id from the catalogue,
   so a reader can find the complete list of verdicts this tool can emit in one file.
3. If the finding carries list-shaped evidence (e.g. a list of hosts), check
   `findings.finding_summary_lines()` renders it sensibly — that function is the single rule for
   how a finding is *summarized* on the CLI, in the HTML report, and in the web event log (via
   `events.to_dict()`'s `summary` field). Don't add a fourth place that reformats evidence.
4. Add a test asserting the finding fires under the right conditions and not otherwise — see
   `tests/unit/test_control_transaction.py` or `test_release_mode.py` for the pattern
   (`_finding_ids(events)` helper).

## How to add a mode

Modes live in `core/models.py`'s `Mode` enum. Adding one means touching, at minimum:

- `core/models.py`: the enum member, and whether it belongs in `DESTRUCTIVE_MODES` /
  `SCOPE_REQUIRED_MODES` / `RUN_ONCE_MODES` (read each set's own comment before adding to it —
  they answer different questions: destructive-or-not, scope-required-or-not, and
  finishes-itself-or-not are three independent axes, not one).
- `core/engine.py`: a `_run_<mode>()` entry point wired into `start()`'s `runners` dict, plus
  whatever worker logic the mode needs.
- `cli/main.py`: a subparser (`_MODE_BY_CMD`, `build_parser()`, `build_config()`).
- `web/schemas.py`: `config_from_payload()` needs to accept the new mode value.
- `web/static/index.html` / `app.js`: if the mode should be selectable from the web UI.
- A test file under `tests/unit/`.

Read `docs/DESIGN.md` §6 for what's already there and why `GARP_DOS` was retired rather than
kept — a genuinely new standalone mode is rare; most new capability belongs as a phase inside
`exhaust`/`release`'s shared prelude instead (see §5f).

## Style

Ruff (line length 100) + `ruff format`; type hints throughout `core`; dataclasses over dicts; no
module-level mutable globals in `core`. Default to no comments — when you do add one, it should
explain a non-obvious *why* (a hidden constraint, a workaround for a specific bug, a subtle
invariant), not restate what the code does. `docs/DESIGN.md`'s density of "why" comments in
`core/` is deliberate and worth matching when you touch that code, not a style to dilute.
