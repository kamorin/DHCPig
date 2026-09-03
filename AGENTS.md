Agent-session and sandbox specifics for working on DHCPig — for any coding agent (Claude, GPT/Codex,
or otherwise), not just one vendor's tooling. Design rationale lives in `docs/DESIGN.md`; practical
contributor workflow (tests, lint, how to add a finding/mode) lives in `CONTRIBUTING.md`. This file
is only what differs about doing that work from inside an agent session or a sandboxed environment.

## Where the code lives / how paths work
- **Some agent tools run shell commands in a separate sandbox/container from the one their
  file-edit tools see**, and that sandbox may mount this repo at a different path than the one
  your file-edit tool resolves. If a `bash`-style tool and a `read`/`write`-style tool disagree
  about where the repo lives, trust the path each tool itself reports rather than assuming they
  match — don't hardcode one path across both. Also watch for a stale duplicate checkout under a
  session-scoped scratch directory if your sandbox provisions one; whatever your `read`/`write`
  tools resolve to is the one to trust.
- If this repo is also synced or mounted onto another machine/VM outside your session, edits made
  through your file-edit tool's path should appear there too — the process running it usually just
  needs restarting to pick the change up.
- Git worktrees: if you're working from a checkout under `.git/worktrees` or similar (some tools
  create one per session/branch), treat it as the working copy for that session — it's a real
  checkout, not a sandbox mount, so ordinary git and file operations behave normally there.
- This repo commonly has several such worktrees checked out at once (`git worktree list`).
  `master` itself is normally checked out in the **primary** worktree (the repo's root clone),
  not in any of the per-session ones — you can't `git checkout master` from inside a feature
  worktree while it's checked out elsewhere. To land a feature branch on `master`: from the
  feature worktree, `git fetch origin` and `git rebase master` (safe to do freely as long as
  `git ls-remote --heads origin <branch>` shows the branch was never pushed — rebasing a branch
  someone else might have pulled is a different, riskier thing); then, from wherever `master` is
  actually checked out, `git merge --ff-only <branch>` and `git push origin master`.

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

- After a test run, clean up caches if they land somewhere synced/shared (a network share or VM
  mount can leave the coverage plugin unable to remove its own files):
  `rm -rf .pytest_cache .ruff_cache .coverage*; find . -name __pycache__ -exec rm -rf {} +`.
  Prefer `pytest -q` (no `--cov`) on a shared filesystem to avoid a coverage-cleanup
  `PermissionError` (test results are still correct even if that error prints).
- With a real Python 3.11+ available: `python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"`,
  then run with `sudo .venv/bin/dhcpig ...` (raw sockets need root; `sudo` resets `PATH`, so use the
  full `.venv/bin/...` path rather than relying on an activated venv).
- A fresh sandbox's system `python3` commonly has neither `pytest`/`ruff` nor `scapy` installed —
  `ModuleNotFoundError: No module named pytest` there doesn't mean the interpreter is too old (check
  `python3 --version` against the 3.11+ floor first); it means create the venv above and run the
  suite through `.venv/bin/python3 -m pytest`/`-m ruff` instead of the bare interpreter.
- `tests/unit/test_release_previous.py::test_no_recovery_needed_when_a_new_client_already_gets_an_address`
  has been observed failing on a clean, unmodified checkout (confirmed via `git stash`, unrelated to
  any in-progress change) — before treating a failure there as a regression you introduced, check it
  against `git stash`/an unmodified tree first.
- The one integration test (`tests/integration/test_exhaust_live.py`, `make integration`) needs
  root + Linux (a veth pair + fake DHCP server) and is deselected by default (`-m "not integration"`
  in `pyproject.toml`) — it's not runnable in most sandboxes; verify it on a real, root-accessible
  Linux box instead.
- CI (`.github/workflows/ci.yml`) runs `ruff check`, `ruff format --check`, `mypy`, and `pytest`
  across Python 3.11–3.13 on every push and pull request, plus a `build-check` job that builds a
  real wheel and confirms the fingerprint data file shipped inside it. Opening a PR against `master`
  triggers it automatically — no separate step needed.

## Releasing to Debian (and thereby Kali)

Trigger: **"package this up for kali"**. Kali carries no fork of this package — its own packaging
repo (`gitlab.com/kalilinux/packages/dhcpig`) is archived — so it imports straight from Debian. The
whole job is therefore "get a new revision into Debian unstable"; Kali follows by itself (unstable
→ testing after ~5 days → kali-rolling, so 1–3 weeks). **There is nothing to file with Kali, ever.**

### The packaging is not in this repo
It is **not** `packaging/debian/` here — that directory is stale and divergent (wrong Maintainer,
old debhelper/Standards, a `libpcap0.8` dependency Debian dropped). Don't build from it and don't
sync it. The real packaging is a git-buildpackage repo:

- remote: `git@salsa.debian.org:pkg-security-team/dhcpig.git` (team-maintained; Kevin has salsa
  Developer role, so routine pushes work directly — no fork or MR needed)
- local clone: `~/Documents/code/dhcpig-debian/repo`
- branches: `debian/master`, `upstream/latest`, `pristine-tar` (DEP-14 + pristine-tar, `3.0 (quilt)`)

### The 10 steps

**No Debian bug is needed.** #1143491 existed only because it was filed as a wishlist request for
the 2.x rewrite. A routine version bump needs no BTS involvement at all — the changelog entry is
just "New upstream release X.Y.Z." with no `Closes:`, and it goes straight to the team repo. Do not
open a bug, and do not open a merge request either: direct push is correct for routine bumps.

Preconditions: the version is **tagged and pushed on GitHub** (`vX.Y.Z`) — `debian/watch` finds
GitHub tags via uscan — and **Docker is running**, because `gbp`, `uscan` and `dch` don't exist on
macOS and the toolchain runs in a `debian:sid` container.

| # | Step | Who |
|---|------|-----|
| 1 | Tag and push `vX.Y.Z` on GitHub | you |
| 2 | Confirm Docker is running | you |
| 3 | `~/Documents/code/dhcpig-debian/release.sh X.Y.Z` | agent |
| 4 | `cd ~/Documents/code/dhcpig-debian/repo && git show HEAD` — review the changelog entry | agent |
| 5 | `git push origin debian/master upstream/latest pristine-tar` | agent |
| 6 | Confirm the salsa pipeline goes green on the pushed branch | agent |
| 7 | Ask a DD to upload — salsa comment, or `#debian-security` on OFTC | you |
| 8 | DD signs and `dput`s to unstable | DD |
| 9 | Migrates to Debian testing (~5 days, urgency=medium, if no RC bug or autopkgtest regression) | automatic |
| 10 | Kali imports from testing into kali-rolling | automatic |

Steps 3–6 are the whole agent job. Step 7 is a one-line request. Steps 8–10 need nothing from you.

`release.sh` builds a tooling image on first run (~90s, cached after), then inside it: uscan finds
the tag, `gbp import-orig --uscan` imports to `upstream/latest`, commits pristine-tar data and
merges to `debian/master`, `dch` adds the changelog entry, then it builds, runs lintian, removes
build artefacts and commits.

Note a GitLab MR merges **one** branch only. If a merge request is ever used instead of a direct
push, `upstream/latest` and `pristine-tar` must still be pushed separately or the team repo cannot
regenerate the orig tarball.

### Then ask a DD to upload — the one step no agent can do
Kevin is not a DD or DM and cannot upload to the archive. Salsa "Developer" is a GitLab role and
has nothing to do with archive upload rights: uploads are GPG-signed and verified against the
Debian keyring. A Debian Developer must sign and `dput`. Ask on the salsa repo or in
`#debian-security` (OFTC); Alexandre Detiste (`@detiste-guest`) did the 2.7.3 upload and is the
natural person to ask. A bug closes only when dak accepts the upload — `Closes:` never fires on a
git merge.

### Rules that keep this a one-command job
- **Never create `debian/patches/`.** The package has no quilt patches, which is exactly why an
  upstream bump is a single `gbp import-orig`. A patch has to be refreshed on every future release.
  If Debian needs an upstream file changed, fix it upstream and cut a release instead.
- **Don't reintroduce `Repacksuffix`/`Dversionmangle` in `debian/watch`** — nothing is excluded
  from the tarball and no `+dfsg` revision was ever uploaded.
- **Keep the team Maintainer** (`Debian Security Tools <team+pkg-security@tracker.debian.org>`) and
  the existing Uploaders. Putting Kevin there reads as a package hijack.
- **Direct-push routine version bumps only.** Anything that changes packaging should go via a
  merge request.
- For a **sponsored upload the contributor's name correctly stays in the changelog trailer**; the
  sponsor's key signs the `.changes`. Don't tell a sponsor to change it.

### Known false positives — don't chase these
Salsa CI's merge-request test summary reports two failing lintian tags on every run:
`source-nmu-has-incorrect-version-number` and `debian-news-entry-has-unknown-version`. Both are
artefacts of salsa-ci rebuilding as `X.Y.Z-1+salsaci+<date>+1`, which trips the NMU check and
desynchronises `debian/NEWS` from the mangled changelog. A real build is lintian-clean at
`--display-info --pedantic`, and the `lintian` job itself passes — only the test-report widget is red.

### Upstream fixes that would shrink the Debian side
Each currently forces `debian/` to carry a workaround:
- `packaging/dhcpig-web.desktop` uses `Categories=09-sniffing-spoofing`, a Kali-only category that
  fails `desktop-file-validate`; Debian ships a corrected copy because of it.
- No upstream `dhcpig-web.1` exists, so Debian supplies one — even though `dhcpig.1` already
  cross-references it.
- `packaging/dhcpig.1` still declares `.TH ... "dhcpig 2.5.0"`.

## Docs in this repo
- `docs/DESIGN.md` — the only design document; everything load-bearing from earlier planning docs
  (deleted `EXECUTION-PLAN-*.md`, `SECURITY.md`) was folded into it. Don't recreate those.
- `CONTRIBUTING.md` — practical workflow for a human or agent contributor.
- This file (`AGENTS.md`) — sandbox/session specifics only. `CLAUDE.md` is a one-line pointer to
  this file (`@AGENTS.md`) so Claude Code's auto-load mechanism still picks it up; edit `AGENTS.md`,
  not `CLAUDE.md`.

Section numbers in `docs/DESIGN.md` (`§5a`, `§5f`, etc.) are cited throughout `src/`'s comments and
docstrings. Don't renumber sections there without updating every citation across the tree.
