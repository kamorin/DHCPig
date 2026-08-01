"""release-previous (2.2): recovery, not an attack -- replays the on-disk lease journal to
release phantom leases this tool previously took. Its finding text lives in `core/findings.py`
alongside every other finding, and `select_entries()` here is the one piece of its logic that's
genuinely decoupled from the engine (a pure filter over `cfg` + the loaded journal).

The worker itself (`_run_release_previous`/`_release_selected`/`_release_previous_worker` on
`DhcpEngine`) stays on the engine -- it needs the sniffer, `_stop`, `_control_transaction()` and
`_release_bindings()` closely enough that a separate class wrapping the engine would add an
indirection layer without reducing coupling, same judgment as `core/eviction.py`.
"""

from __future__ import annotations

import time

from .journal import JournalEntry
from .models import ControlOutcome, SessionConfig
from .safety import ScopeGuard


def select_entries(
    cfg: SessionConfig, entries: list[JournalEntry], scope: ScopeGuard, pre_control: ControlOutcome
) -> tuple[list[JournalEntry], dict]:
    """Filter journal entries down to what's safe and relevant to release right now.

    See AGENT_HANDOFF.md §5e for why each step exists: interface,
    then current CIDR (never an unbounded sweep), then same-server (guards against a
    journal carried between engagements producing targets on the wrong network -- only
    evaluable when the pre-flight control actually learned a server identity, which it
    usually won't on a genuinely exhausted pool; that's an accepted gap, not a bug), then
    age (an optimisation -- a stale entry is harmless because its MAC simply won't match
    the server's current binding, see the module-level note in journal.py).
    """
    known_server_id = pre_control.server_id if pre_control.attempted else None
    same_server_filter_applied = bool(cfg.require_same_server and known_server_id)

    step1 = [e for e in entries if e.iface == cfg.interface]
    step2 = [e for e in step1 if scope.allows(e.ip)]

    if same_server_filter_applied:
        step3 = [e for e in step2 if e.server_ip == known_server_id]
    else:
        step3 = step2

    now = time.time()
    max_age_s = max(0.0, cfg.max_age_days) * 86400
    step4 = [e for e in step3 if now - (e.ts + (e.lease_time or 0)) <= max_age_s]

    stats = {
        "journal_entries_loaded": len(entries),
        "in_cidr": len(step2),
        "same_server_filter_applied": same_server_filter_applied,
        "same_server": len(step3),
        "within_max_age": len(step4),
        "selected": len(step4),
    }
    return step4, stats
