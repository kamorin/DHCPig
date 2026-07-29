"""NeighborSummary (2.3.3): end-of-run roll-call of who this run affected, on the event log.

The bucket boundaries are the point of this file. "lease_taken" hosts are working at the moment
the summary is emitted but will fail at their next renewal, so folding them into either
neighbouring bucket misreports the run -- see the event's docstring.
"""

from dhcpig.cli.render import Renderer
from dhcpig.core import engine as engine_mod
from dhcpig.core.engine import DhcpEngine
from dhcpig.core.events import EventBus, NeighborSummary
from dhcpig.core.models import Mode, Neighbor, SessionConfig


def _engine(monkeypatch, **cfg):
    monkeypatch.setattr(engine_mod, "sendp", lambda *a, **k: None)
    bus = EventBus()
    events = []
    bus.subscribe(events.append)
    cfg.setdefault("mode", Mode.EXHAUST)
    cfg.setdefault("offline", True)
    return DhcpEngine(SessionConfig(interface="wlan0", **cfg), bus), events


def _neighbors(eng, n):
    ips = [f"10.0.0.{i}" for i in range(1, n + 1)]
    for i, ip in enumerate(ips):
        mac = f"aa:bb:cc:00:00:{i:02x}"
        eng._neighbors_by_mac[mac] = Neighbor(mac=mac, ip=ip)
    return ips


def _reacquired(eng, ips):
    """Mark `ips` as addresses the server handed us back (re-acquisition granted)."""
    eng._reacquire_targets = dict(enumerate(ips))
    eng._reacquire_outcomes = dict.fromkeys(range(len(ips)), "granted")


def _summary(events):
    return next(e for e in events if isinstance(e, NeighborSummary))


# ---------------------------------------------------------------- emission
def test_summary_is_emitted_with_every_discovered_neighbor_counted(monkeypatch):
    eng, events = _engine(monkeypatch)
    _neighbors(eng, 6)
    eng._emit_neighbor_summary()
    s = _summary(events)
    assert s.total == 6
    assert s.unaffected == 6  # nothing was done to any of them
    assert not s.offline and not s.lease_taken and not s.reacted


def test_no_summary_when_no_neighbors_were_discovered(monkeypatch):
    """An empty roll-call is noise -- scan never sweeps, and an empty segment has nothing
    to report."""
    eng, events = _engine(monkeypatch)
    eng._emit_neighbor_summary()
    assert not [e for e in events if isinstance(e, NeighborSummary)]


def test_buckets_partition_the_neighbor_list_exactly_once(monkeypatch):
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 9)
    _reacquired(eng, ips[:5])
    eng._evict_outcomes = {
        ips[0]: "apipa",
        ips[1]: "discover_unanswered",
        ips[2]: "defended",
        ips[3]: "rediscovered",
    }
    eng._emit_neighbor_summary()
    s = _summary(events)
    assert len(s.offline) + len(s.lease_taken) + len(s.reacted) + s.unaffected == s.total == 9
    listed = [row[0] for row in s.offline + s.lease_taken + s.reacted]
    assert len(listed) == len(set(listed))  # no host in two buckets


# ---------------------------------------------------------------- bucket boundaries
def test_only_rungs_meaning_no_working_address_count_as_offline(monkeypatch):
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 6)
    eng._evict_outcomes = {
        ips[0]: "apipa",
        ips[1]: "discover_unanswered",
        ips[2]: "rediscovered",  # restarted but WAS served -- online, new address
        ips[3]: "declined",
        ips[4]: "defended",
        ips[5]: "no_reaction",
    }
    eng._emit_neighbor_summary()
    s = _summary(events)
    assert {row[0] for row in s.offline} == {ips[0], ips[1]}
    assert {row[0] for row in s.reacted} == {ips[2], ips[3], ips[4]}
    assert s.unaffected == 1  # no_reaction, and we never took its lease


def test_host_whose_lease_we_hold_is_neither_offline_nor_unaffected(monkeypatch):
    """The bucket that exists because both neighbouring answers are wrong: it works right now,
    so it isn't offline; it fails at T1 with no warning, so it isn't unaffected either."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 2)
    _reacquired(eng, [ips[0]])
    eng._emit_neighbor_summary()
    s = _summary(events)
    assert [row[0] for row in s.lease_taken] == [ips[0]]
    assert not s.offline
    assert s.unaffected == 1  # only the host we never touched


def test_reacquisition_that_was_not_granted_does_not_count_as_lease_taken(monkeypatch):
    """offered_different / naked / no_response mean we never got that address."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 3)
    eng._reacquire_targets = dict(enumerate(ips))
    eng._reacquire_outcomes = {0: "offered_different", 1: "naked", 2: "no_response"}
    eng._emit_neighbor_summary()
    s = _summary(events)
    assert not s.lease_taken
    assert s.unaffected == 3


def test_eviction_outcome_wins_over_lease_taken_for_the_same_host(monkeypatch):
    """Eviction only ever targets addresses re-acquisition granted, so every evicted host is
    also a lease_taken candidate -- the observed reaction is the better evidence, so it wins."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 1)
    _reacquired(eng, ips)
    eng._evict_outcomes = {ips[0]: "apipa"}
    eng._emit_neighbor_summary()
    s = _summary(events)
    assert [row[0] for row in s.offline] == [ips[0]]
    assert not s.lease_taken


def test_rows_carry_ip_mac_and_why(monkeypatch):
    """The operator's next move is to go look at a specific machine, so name it."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 1)
    eng._evict_outcomes = {ips[0]: "apipa"}
    eng._emit_neighbor_summary()
    ip, mac, detail = _summary(events).offline[0]
    assert ip == ips[0]
    assert mac == "aa:bb:cc:00:00:00"
    assert detail == "apipa"


# ---------------------------------------------------------------- run wiring
def test_stop_emits_the_summary_before_the_findings(monkeypatch):
    """The log should read 'here is who was affected', then the verdicts about it."""
    eng, events = _engine(monkeypatch)
    _neighbors(eng, 2)
    eng._started = 1.0
    eng.stop()
    kinds = [type(e).__name__ for e in events]
    assert "NeighborSummary" in kinds
    assert kinds.index("NeighborSummary") < kinds.index("FindingRaised")


# ---------------------------------------------------------------- CLI rendering
def test_cli_names_affected_hosts_and_flags_the_delayed_failures(capsys, monkeypatch):
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 4)
    _reacquired(eng, ips[:2])
    eng._evict_outcomes = {ips[0]: "apipa"}
    eng._emit_neighbor_summary()
    r = Renderer(verbosity=2, color=False)
    r.handle(_summary(events))
    out = capsys.readouterr().out

    assert "NEIGHBOR SUMMARY  4 host(s) seen" in out
    assert "KNOCKED OFFLINE: 1 -- no working address now" in out
    assert "will fail at its next renewal" in out
    assert ips[0] in out and "aa:bb:cc:00:00:00" in out
    assert "unaffected: 2" in out


def test_cli_omits_buckets_that_are_empty(capsys, monkeypatch):
    eng, events = _engine(monkeypatch)
    _neighbors(eng, 3)
    eng._emit_neighbor_summary()
    r = Renderer(verbosity=2, color=False)
    r.handle(_summary(events))
    out = capsys.readouterr().out
    assert "KNOCKED OFFLINE" not in out
    assert "LEASE TAKEN" not in out
    assert "unaffected: 3" in out


def test_cli_summary_is_silent_at_verbosity_zero(capsys, monkeypatch):
    eng, events = _engine(monkeypatch)
    _neighbors(eng, 2)
    eng._emit_neighbor_summary()
    Renderer(verbosity=0, color=False).handle(_summary(events))
    assert capsys.readouterr().out == ""
