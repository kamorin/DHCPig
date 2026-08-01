"""The release mode's shared prelude chain (AGENT_HANDOFF.md §5f Phase 5) and mode-aware
eviction findings -- exhaust and release diverge on which eviction outcome rungs count as FAIL.

Split from test_control_findings.py (SIMPLIFICATION.md 4.2) -- see test_control_transaction.py
for the split's full file map.
"""

from conftest import build_engine

from dhcpig.core import events as ev
from dhcpig.core.models import ControlOutcome, Mode, Neighbor


def _engine(monkeypatch, **cfg):
    return build_engine(monkeypatch, **cfg)


def _finding_ids(events):
    return [e.finding.id for e in events if isinstance(e, ev.FindingRaised)]


# ---------------------------------------------------------------- release mode chain (2.3, Phase 5)
def test_prelude_pre_control_returns_control_pre_for_exhaust(monkeypatch):
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    out = ControlOutcome(phase="pre", client="self", success=True, server_id="10.0.0.1")
    eng.control_pre = out
    assert eng._prelude_pre_control() is out


def test_prelude_pre_control_returns_rel_pre_control_for_release(monkeypatch):
    eng, _, _ = _engine(monkeypatch, mode=Mode.RELEASE_NEIGHBORS)
    out = ControlOutcome(phase="pre", client="self", success=True, server_id="10.0.0.1")
    eng._rel_pre_control = out
    assert eng._prelude_pre_control() is out
    assert eng.control_pre is None  # never touched


def test_common_prelude_stores_control_outcome_separately_for_release(monkeypatch):
    """The whole point of _rel_pre_control (2.3, Phase 5): a release run's control leg must
    never land in self.control_pre, or _finalize_findings() would derive a DHCP_STARVATION_*
    verdict for a run that never attempted to starve anything."""
    eng, _, _ = _engine(monkeypatch, mode=Mode.RELEASE_NEIGHBORS)
    out = ControlOutcome(phase="pre", client="self", success=True, server_id="10.0.0.1")
    monkeypatch.setattr(eng, "_baseline_arp_scan", lambda: None)
    monkeypatch.setattr(eng, "_control_transaction", lambda phase, client="self": out)
    monkeypatch.setattr(eng, "_release_phase", lambda: [])
    monkeypatch.setattr(eng, "_finish_release", lambda freed: None)
    eng._common_prelude(run_new_leg=False)
    assert eng._rel_pre_control is out
    assert eng.control_pre is None
    assert eng.control_pre_new is None


def test_common_prelude_runs_new_leg_only_when_requested(monkeypatch):
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    order = []
    monkeypatch.setattr(eng, "_baseline_arp_scan", lambda: None)
    monkeypatch.setattr(
        eng,
        "_control_transaction",
        lambda phase, client="self": (
            order.append(f"{phase}-{client}") or ControlOutcome(phase=phase, client=client)
        ),
    )
    monkeypatch.setattr(eng, "_release_phase", lambda: [])
    monkeypatch.setattr(eng, "_finish_release", lambda freed: None)
    eng._common_prelude(run_new_leg=False)
    assert order == ["pre-self"]  # no client="new" leg -- meaningless for release

    order.clear()
    eng._common_prelude(run_new_leg=True)
    assert order == ["pre-self", "pre-new"]


def test_release_worker_runs_the_shared_chain_then_eviction(monkeypatch):
    eng, _, _ = _engine(monkeypatch, mode=Mode.RELEASE_NEIGHBORS)
    order = []
    monkeypatch.setattr(
        eng, "_common_prelude", lambda run_new_leg: order.append(("prelude", run_new_leg))
    )
    monkeypatch.setattr(eng, "_evict_phase", lambda: order.append("evict"))
    eng._release_worker()
    assert order == [("prelude", False), "evict"]


def test_release_worker_skips_eviction_when_stopped_mid_prelude(monkeypatch):
    eng, _, _ = _engine(monkeypatch, mode=Mode.RELEASE_NEIGHBORS)
    called = []
    monkeypatch.setattr(eng, "_common_prelude", lambda run_new_leg: eng._stop.set())
    monkeypatch.setattr(eng, "_evict_phase", lambda: called.append(True))
    eng._release_worker()
    assert called == []


def test_run_release_starts_a_sniffer_unless_offline(monkeypatch):
    eng, _, _ = _engine(monkeypatch, mode=Mode.RELEASE_NEIGHBORS)
    monkeypatch.setattr(eng, "_release_worker", lambda: None)  # don't actually run the chain
    eng._run_release()
    try:
        assert eng._sniffer is not None
    finally:
        if eng._sniffer is not None:
            eng._sniffer.stop()

    eng2, _, _ = _engine(monkeypatch, mode=Mode.RELEASE_NEIGHBORS, offline=True)
    monkeypatch.setattr(eng2, "_release_worker", lambda: None)
    eng2._run_release()
    assert eng2._sniffer is None


def test_evict_phase_excludes_server_learned_via_rel_pre_control(monkeypatch):
    """Target selection must exclude the DHCP server even when its identity came from
    _rel_pre_control rather than control_pre (release mode never populates the latter)."""
    eng, _, _ = _engine(monkeypatch, mode=Mode.RELEASE_NEIGHBORS)
    monkeypatch.setattr(eng, "_release_gateway", lambda: None)
    eng._rel_pre_control = ControlOutcome(phase="pre", client="self", server_id="172.20.15.1")
    eng._neighbors_by_mac["de:ad:00:00:00:01"] = Neighbor("de:ad:00:00:00:01", "172.20.0.7")
    eng._neighbors_by_mac["srv:mac:00:00:00"] = Neighbor("srv:mac:00:00:00", "172.20.15.1")
    eng._reacquire_targets = {1: "172.20.0.7", 2: "172.20.15.1"}
    eng._reacquire_outcomes = {1: "granted", 2: "granted"}
    eng.cfg.evict_rounds = 2
    eng.cfg.timeouts.evict_interval = 0.01
    eng.cfg.evict_settle = 0.0
    eng._evict_phase()
    assert eng._evict.targets == {"172.20.0.7"}


# ---------------------------------------------------------------- mode-aware eviction findings
def test_finalize_findings_release_rediscovered_alone_is_not_evicted(monkeypatch):
    """(2.3, Phase 5 acceptance criterion) a release run topping out at 'rediscovered' is the
    expected, low-harm outcome -- the pool was never drained, so an immediate re-lease is not
    a denial of service. Must not raise CLIENTS_EVICTED_FROM_ADDRESSES."""
    eng, events, _ = _engine(monkeypatch, mode=Mode.RELEASE_NEIGHBORS)
    eng._evict.outcomes = {"10.0.0.7": "rediscovered"}
    eng._finalize_findings()
    ids = _finding_ids(events)
    assert "CLIENTS_EVICTED_FROM_ADDRESSES" not in ids
    assert "CLIENTS_DEFENDED_ADDRESSES" in ids
    f = next(
        e.finding
        for e in events
        if isinstance(e, ev.FindingRaised) and e.finding.id == "CLIENTS_DEFENDED_ADDRESSES"
    )
    assert f.evidence["reacted"] == 1


def test_finalize_findings_release_discover_unanswered_is_evicted(monkeypatch):
    """Unlike bare 'rediscovered', a release-mode target that couldn't get back online at all
    is a genuine denial-of-service byproduct and must still FAIL."""
    eng, events, _ = _engine(monkeypatch, mode=Mode.RELEASE_NEIGHBORS)
    eng._evict.outcomes = {"10.0.0.7": "discover_unanswered"}
    eng._finalize_findings()
    ids = _finding_ids(events)
    assert "CLIENTS_EVICTED_FROM_ADDRESSES" in ids


def test_finalize_findings_exhaust_rediscovered_alone_is_evicted(monkeypatch):
    """Under exhaust, unlike release, even a successful restart is evidence the address was
    forcibly vacated -- the existing (Phase 4) behavior must be unchanged."""
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng._evict.outcomes = {"10.0.0.7": "rediscovered"}
    eng._finalize_findings()
    ids = _finding_ids(events)
    assert "CLIENTS_EVICTED_FROM_ADDRESSES" in ids
