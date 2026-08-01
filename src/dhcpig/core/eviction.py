"""ARP-conflict eviction (2.3, Phase 4): the outcome ladder and the per-run state it's measured
against. The behaviour methods (`_do_arp_conflict`, `_evict_phase`, `_evict_worker`,
`_measure_eviction`, `_handle_evict_arp`) stay on `DhcpEngine` -- they're threaded through
`_send()`, the event bus, `cfg`, and several other engine-owned dicts (`_reacquire_targets`,
`_neighbors_by_mac`, `_foreign_discovers`) closely enough that wrapping them in a separate class
would only add an indirection layer, not reduce coupling. What genuinely stood alone -- the pure
rung-ordering logic and the nine loose per-run attributes it's computed from -- lives here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ARP-conflict eviction outcome ladder, lowest to highest. This is a causal/temporal ordering,
# not a strength-of-evidence one: DECLINE is strong evidence on its own, but "rediscovered" (the
# host went further and restarted at INIT) is a later stage in the same eviction, so it outranks
# a bare decline. The top two rungs are exhaust-only -- release mode never drains the pool, so a
# healthy result there tops out at "rediscovered".
RUNGS = [
    "no_reaction",
    "defended",
    "declined",
    "rediscovered",
    "discover_unanswered",
    "apipa",
]


def rung_max(a: str, b: str) -> str:
    return b if RUNGS.index(b) > RUNGS.index(a) else a


@dataclass
class EvictionState:
    """Who we're ARP-conflicting, the forged MACs we used, and the observed signals per target
    IP -- one instance per run, owned by `DhcpEngine._evict`.

    `mac_by_ip`/`ip_by_mac` exist because live signals arrive keyed by whichever side the packet
    exposes (ARP by IP, DHCP by MAC). `outcomes` holds the current best rung reached per target;
    `start_ts` bounds "rediscovered" DISCOVERs to ones seen during/after this eviction, not some
    unrelated earlier sighting.
    """

    targets: set[str] = field(default_factory=set)  # target IPs
    bogus_macs: set[str] = field(default_factory=set)
    defenders: set[str] = field(default_factory=set)  # target IPs that answered our ARP conflict
    declined_ips: set[str] = field(default_factory=set)
    apipa_ips: set[str] = field(default_factory=set)
    mac_by_ip: dict[str, str] = field(default_factory=dict)
    ip_by_mac: dict[str, str] = field(default_factory=dict)
    outcomes: dict[str, str] = field(default_factory=dict)
    start_ts: float = 0.0
