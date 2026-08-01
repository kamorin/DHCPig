"""Race-to-grab-freed-addresses (2.3.1, docs/DESIGN.md §5g): per-run state for
`DhcpEngine._maybe_race()`/`_exhaust_sender()`/`_classify_targeted()`.

Deliberately a separate namespace from `_reacquire_targets`/`_reacquire_outcomes` -- this is
load-bearing, not just tidiness. `_evict_phase()` derives its target set from the reacquire
dicts alone; a race xid written into either would silently widen eviction's blast radius past
what §5g documents ("targets only addresses this run actually re-acquired"). A regression test
asserts this never happens.

`races` (the plain attempted-count) stays a normal `DhcpEngine` attribute alongside its sibling
counters (`discovers`, `offers`, `acks`, `naks`, `releases`, `arp_conflicts`) -- `_counters()`
reports them together, so splitting just this one into a different object would only make that
method's assembly line longer for no reason.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field


@dataclass
class RaceState:
    """Everything scoped to one freed-address race, per run, owned by `DhcpEngine._race`.

    `queue`/`raced_ips`/`reasons` track addresses waiting to be raced (deduped by IP so one
    freed address is never queued twice); `targets`/`outcomes`/`triggers` track in-flight and
    completed race transactions by xid, same shape as `_reacquire_targets`/`_reacquire_outcomes`
    but kept separate for the reason above. `inflight` is the live count against
    `cfg.race_max_inflight` -- the reserve of `_inflight` pipeline slots a race send takes
    *above* the window, not a wait-your-turn allocation.
    """

    queue: deque[str] = field(default_factory=deque)
    raced_ips: set[str] = field(default_factory=set)
    reasons: dict[str, str] = field(default_factory=dict)  # ip -> trigger ("nak"/"decline"/...)
    targets: dict[int, str] = field(default_factory=dict)  # xid -> ip
    outcomes: dict[int, str] = field(default_factory=dict)  # xid -> outcome
    triggers: dict[int, str] = field(default_factory=dict)  # xid -> trigger, for the finding
    inflight: int = 0
