Agent-session and sandbox specifics for working on DHCPig. Design rationale lives in
`docs/DESIGN.md`; practical contributor workflow (tests, lint, how to add a finding/mode) lives
in `CONTRIBUTING.md`. This file is only what differs about doing that work from inside an agent
session or a sandboxed environment.

## Where the code lives / how paths work
- **Canonical working copy:** `/Users/kamorin/Documents/code/DHCPig` (the user's Mac; a
  connected Cowork folder). Edit here with Read/Write/Edit.
- **In the sandbox `mcp__workspace__bash`** the same folder is `/sessions/<id>/mnt/DHCPig`.
  Use that path for bash only. (There is a stale earlier copy under `.../outputs/DHCPig` —
  ignore it.)
- The user runs it on a **Kali VM** where the Mac folder is mounted at `/mnt/hgfs/code/DHCPig`
  (VMware shared folder) — so edits appear on the VM immediately; the user just restarts the
  process to pick them up.

## Running tests/lint from the sandbox
Sandbox Python is **3.10**, but the package targets **3.11+**, so **do NOT `pip install -e .`
in the sandbox** — run against the source path instead:
```
cd /sessions/<id>/mnt/DHCPig
PYTHONPATH=src python3 -m pytest -q
python3 -m ruff check src tests
python3 -m ruff format --check src tests
```
See `CONTRIBUTING.md` for what the commands actually check and the current pass count.

- After runs, delete caches on the VMware share (they can't always be removed by the coverage
  plugin): `rm -rf .pytest_cache .ruff_cache .coverage*; find . -name __pycache__ -exec rm -rf {} +`.
  Prefer `pytest -q` (no `--cov`) on the share to avoid a coverage cleanup `PermissionError`
  (test results are still correct even if that error prints).
- On the user's VM (real 3.11+): `python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"`,
  then run with `sudo .venv/bin/dhcpig ...` (raw sockets need root; `sudo` ignores the venv on
  PATH so use the full `.venv/bin/...` path).
- The one integration test (`tests/integration/test_exhaust_live.py`) needs root + Linux and is
  not runnable from the sandbox at all — verify it (`make integration`) on the Kali VM, not here.

## Docs in this repo
- `docs/DESIGN.md` — the only design document; everything load-bearing from earlier planning
  docs (deleted `EXECUTION-PLAN-*.md`, `SECURITY.md`) was folded into it. Don't recreate those.
- `CONTRIBUTING.md` — practical workflow for a human or agent contributor.
- This file — sandbox/session specifics only.

Section numbers in `docs/DESIGN.md` (`§5a`, `§5f`, etc.) are cited throughout `src/`'s comments
and docstrings. Don't renumber sections there without updating every citation across the tree.
