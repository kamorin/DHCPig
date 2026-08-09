Agent-session and sandbox specifics for working on DHCPig — for any coding agent (Claude, GPT/Codex,
or otherwise), not just one vendor's tooling. Design rationale lives in `docs/DESIGN.md`; practical
contributor workflow (tests, lint, how to add a finding/mode) lives in `CONTRIBUTING.md`. This file
is only what differs about doing that work from inside an agent session or a sandboxed environment.

## Where the code lives / how paths work
- **Canonical working copy:** `/Users/kamorin/Documents/code/DHCPig` on the user's Mac. Edit here
  whenever your tool's file-edit operations can reach it directly.
- **Some agent tools run shell commands in a separate sandbox/container from the one their file-edit
  tools see**, and that sandbox may mount this repo at a different path than the canonical one above
  (e.g. under a session-scoped directory). If a `bash`-style tool and a `read`/`write`-style tool
  disagree about where the repo lives, trust the path each tool itself reports rather than assuming
  they match — don't hardcode one path across both. Also watch for a stale duplicate checkout under
  a session's `outputs/`-style directory if your sandbox provisions one; the canonical copy above
  (or whatever your `read`/`write` tools resolve to) is the one to trust.
- The user also runs this on a **Kali VM** where the Mac folder is mounted at
  `/mnt/hgfs/code/DHCPig` (VMware shared folder) — so edits made through the canonical path appear
  on the VM immediately; the user just restarts the process there to pick them up.
- Git worktrees: if you're working from a checkout under `.git/worktrees` or similar (some tools
  create one per session/branch), treat it as the working copy for that session — it's a real
  checkout, not a sandbox mount, so ordinary git and file operations behave normally there.

## Running tests/lint
This package requires **Python 3.11+** (`requires-python` in `pyproject.toml`). If the interpreter
available in your environment is older, don't `pip install -e .` — an editable install will fight
the version floor. Run directly against the source tree instead, from the repo root:
```
PYTHONPATH=src python3 -m pytest -q
python3 -m ruff check src tests
python3 -m ruff format --check src tests
```
(`scapy` must already be importable in that interpreter — these tests monkeypatch `sendp`/`srp`
rather than touching a real socket, but they still import scapy's packet classes.) `mypy` needs a
proper environment to resolve imports cleanly; prefer running it via the venv setup below rather
than against a bare source tree. See `CONTRIBUTING.md` for what each command actually checks and
the full command set (`mypy src/dhcpig/core`, `make lint`/`make test`).

- After a test run, clean up caches if they land somewhere synced/shared (e.g. a VMware share, where
  the coverage plugin can't always remove its own files):
  `rm -rf .pytest_cache .ruff_cache .coverage*; find . -name __pycache__ -exec rm -rf {} +`.
  Prefer `pytest -q` (no `--cov`) on a shared filesystem to avoid a coverage-cleanup
  `PermissionError` (test results are still correct even if that error prints).
- With a real Python 3.11+ available: `python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"`,
  then run with `sudo .venv/bin/dhcpig ...` (raw sockets need root; `sudo` resets `PATH`, so use the
  full `.venv/bin/...` path rather than relying on an activated venv).
- The one integration test (`tests/integration/test_exhaust_live.py`, `make integration`) needs
  root + Linux (a veth pair + fake DHCP server) and is deselected by default (`-m "not integration"`
  in `pyproject.toml`) — it's not runnable in most sandboxes; verify it on the Kali VM or an
  equivalent real Linux box instead.
- CI (`.github/workflows/ci.yml`) runs `ruff check`, `ruff format --check`, `mypy`, and `pytest`
  across Python 3.11–3.13 on every push and pull request, plus a `build-check` job that builds a
  real wheel and confirms the fingerprint data file shipped inside it. Opening a PR against `master`
  triggers it automatically — no separate step needed.

## Docs in this repo
- `docs/DESIGN.md` — the only design document; everything load-bearing from earlier planning docs
  (deleted `EXECUTION-PLAN-*.md`, `SECURITY.md`) was folded into it. Don't recreate those.
- `CONTRIBUTING.md` — practical workflow for a human or agent contributor.
- This file (`AGENTS.md`) — sandbox/session specifics only. `CLAUDE.md` is a one-line pointer to
  this file (`@AGENTS.md`) so Claude Code's auto-load mechanism still picks it up; edit `AGENTS.md`,
  not `CLAUDE.md`.

Section numbers in `docs/DESIGN.md` (`§5a`, `§5f`, etc.) are cited throughout `src/`'s comments and
docstrings. Don't renumber sections there without updating every citation across the tree.
