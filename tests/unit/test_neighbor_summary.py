"""NeighborSummary (2.3.3): end-of-run roll-call of who this run affected, on the event log.

One row per host, every discovered host listed. The category boundaries are the point of this
file: "lease_taken" hosts are working at the moment the summary is emitted but will fail at
their next renewal, so folding them into either neighbouring category misreports the run -- see
the event's docstring.
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


def _by_category(events):
    out: dict[str, list[str]] = {}
    for ip, _mac, _outcome, category in _summary(events).rows:
        out.setdefault(category, []).append(ip)
    return out


def _denied(eng, macs):
    """Mark `macs` as having DISCOVERed during the run and got no answer."""
    for i, mac in enumerate(macs):
        eng._foreign_discovers[i] = {"mac": mac, "hostname": None, "ts": 0.0, "answered": False}


# ---------------------------------------------------------------- emission
def test_every_discovered_neighbor_gets_exactly_one_row(monkeypatch):
    """A roll-call that omits the hosts nothing happened to isn't a roll-call -- the reader
    can't tell 'unaffected' from 'not examined'."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 6)
    eng._emit_neighbor_summary()
    s = _summary(events)
    assert s.total == 6
    assert len(s.rows) == 6
    assert [row[0] for row in s.rows] == ips  # all listed, none dropped
    assert {row[3] for row in s.rows} == {"unaffected"}


def test_no_summary_when_no_neighbors_were_discovered(monkeypatch):
    """An empty roll-call is noise -- scan never sweeps, and an empty segment has nothing
    to report."""
    eng, events = _engine(monkeypatch)
    eng._emit_neighbor_summary()
    assert not [e for e in events if isinstance(e, NeighborSummary)]


def test_rows_are_sorted_worst_first_then_by_address(monkeypatch):
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 12)  # 10.0.0.1 .. 10.0.0.12, so octet vs lexical order differ
    _reacquired(eng, [ips[5]])
    eng._evict_outcomes = {ips[11]: "apipa", ips[2]: "defended"}
    eng._emit_neighbor_summary()
    cats = [row[3] for row in _summary(events).rows]
    assert cats[0] == "offline"
    assert cats.index("lease_taken") < cats.index("reacted") < cats.index("unaffected")
    unaffected_ips = [row[0] for row in _summary(events).rows if row[3] == "unaffected"]
    assert unaffected_ips == sorted(unaffected_ips, key=lambda s: int(s.rsplit(".", 1)[1]))


# ---------------------------------------------------------------- category boundaries
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
    cats = _by_category(events)
    assert set(cats["offline"]) == {ips[0], ips[1]}
    assert set(cats["reacted"]) == {ips[2], ips[3], ips[4]}
    assert cats["unaffected"] == [ips[5]]  # no_reaction, and we never took its lease


def test_pool_exhaustion_denial_counts_as_offline_without_any_eviction(monkeypatch):
    """The whole point of exhaust is to deny service. A neighbor that asked for an address
    during the run and got none was knocked offline by the drained pool, even though we never
    contested its address by ARP -- reading only _evict_outcomes reported it as unaffected."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 3)
    _denied(eng, ["aa:bb:cc:00:00:01"])
    eng._emit_neighbor_summary()
    cats = _by_category(events)
    assert cats["offline"] == [ips[1]]
    assert set(cats["unaffected"]) == {ips[0], ips[2]}
    outcome = next(r[2] for r in _summary(events).rows if r[0] == ips[1])
    assert "pool drained" in outcome


def test_a_neighbor_whose_discover_was_answered_is_not_reported_offline(monkeypatch):
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 2)
    eng._foreign_discovers[1] = {
        "mac": "aa:bb:cc:00:00:00",
        "hostname": None,
        "ts": 0.0,
        "answered": True,
    }
    eng._emit_neighbor_summary()
    assert _by_category(events) == {"unaffected": ips}


def test_host_whose_lease_we_hold_is_neither_offline_nor_unaffected(monkeypatch):
    """The category that exists because both neighbouring answers are wrong: it works right
    now, so it isn't offline; it fails at T1 with no warning, so it isn't unaffected either."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 2)
    _reacquired(eng, [ips[0]])
    eng._emit_neighbor_summary()
    cats = _by_category(events)
    assert cats["lease_taken"] == [ips[0]]
    assert "offline" not in cats
    assert cats["unaffected"] == [ips[1]]


def test_reacquisition_that_was_not_granted_does_not_count_as_lease_taken(monkeypatch):
    """offered_different / naked / no_response mean we never got that address."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 3)
    eng._reacquire_targets = dict(enumerate(ips))
    eng._reacquire_outcomes = {0: "offered_different", 1: "naked", 2: "no_response"}
    eng._emit_neighbor_summary()
    assert _by_category(events) == {"unaffected": ips}


def test_eviction_outcome_wins_over_the_inferred_states(monkeypatch):
    """Eviction only ever targets addresses re-acquisition granted, so every evicted host is
    also a lease_taken candidate -- the observed reaction is the better evidence, so it wins."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 1)
    _reacquired(eng, ips)
    _denied(eng, ["aa:bb:cc:00:00:00"])
    eng._evict_outcomes = {ips[0]: "defended"}
    eng._emit_neighbor_summary()
    assert _by_category(events) == {"reacted": ips}


def test_rows_carry_ip_mac_outcome_and_category(monkeypatch):
    """The operator's next move is to go look at a specific machine, so name it."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 1)
    eng._evict_outcomes = {ips[0]: "apipa"}
    eng._emit_neighbor_summary()
    ip, mac, outcome, category = _summary(events).rows[0]
    assert (ip, mac, category) == (ips[0], "aa:bb:cc:00:00:00", "offline")
    assert "169.254" in outcome


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
def test_cli_prints_one_line_per_host_for_every_host(capsys, monkeypatch):
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 4)
    _reacquired(eng, ips[:2])
    eng._evict_outcomes = {ips[0]: "apipa"}
    eng._emit_neighbor_summary()
    r = Renderer(verbosity=2, color=False)
    r.handle(_summary(events))
    out = capsys.readouterr().out
    body = [ln for ln in out.splitlines() if "NEIGHBOR SUMMARY" not in ln]

    assert "NEIGHBOR SUMMARY  4 host(s) seen" in out
    assert len(body) == 4  # every host, one line each -- including the untouched ones
    for i, ip in enumerate(ips):
        assert any(ip in ln and f"aa:bb:cc:00:00:{i:02x}" in ln for ln in body)
    assert "fails at next renewal" in out


def test_cli_header_carries_the_tally(capsys, monkeypatch):
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 3)
    eng._evict_outcomes = {ips[0]: "apipa"}
    eng._emit_neighbor_summary()
    Renderer(verbosity=2, color=False).handle(_summary(events))
    out = capsys.readouterr().out
    assert "1 offline" in out and "2 unaffected" in out


def test_cli_summary_is_silent_at_verbosity_zero(capsys, monkeypatch):
    eng, events = _engine(monkeypatch)
    _neighbors(eng, 2)
    eng._emit_neighbor_summary()
    Renderer(verbosity=0, color=False).handle(_summary(events))
    assert capsys.readouterr().out == ""
