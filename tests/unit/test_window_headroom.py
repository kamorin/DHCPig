"""Pool-size estimate and headroom (Phase 3).

Windowed-handshake and halt-on-control tests (Phase 2) live in test_control_findings.py
alongside the control-transaction/finding tests they interact with; this file covers the
headroom estimate added on top of that work.
"""

import threading
import time

from conftest import build_engine

from dhcpig.core import events as ev
from dhcpig.core.engine import DhcpEngine
from dhcpig.core.events import EventBus
from dhcpig.core.models import Mode, Neighbor, SessionConfig


def _engine(monkeypatch, **cfg):
    cfg.setdefault("mode", Mode.EXHAUST)
    eng, events, _sent = build_engine(monkeypatch, **cfg)
    return eng, events


# ---------------------------------------------------------------- estimate resolution
def test_estimate_from_explicit_scope_is_not_labelled_an_estimate(monkeypatch):
    eng, _ = _engine(monkeypatch, scope_cidrs=["10.0.0.0/24"])
    est = eng._estimate_pool()
    assert est.size == 254  # /24 minus network+broadcast
    assert est.source == "scope"
    assert est.is_estimate is False


def test_estimate_sums_multiple_scope_cidrs(monkeypatch):
    eng, _ = _engine(monkeypatch, scope_cidrs=["10.0.0.0/30", "10.0.1.0/30"])
    est = eng._estimate_pool()
    assert est.size == 4  # 2 usable hosts per /30 x 2


def test_estimate_from_observed_offer_subnet_is_labelled_an_estimate(monkeypatch):
    eng, _ = _engine(monkeypatch)
    eng._note_offer_for_pool_estimate("192.168.4.50", "255.255.252.0")  # a /22
    est = eng._estimate_pool()
    assert est.source == "observed"
    assert est.is_estimate is True
    assert est.size == 1022  # /22 usable hosts


def test_estimate_prefers_scope_over_observed_offer(monkeypatch):
    eng, _ = _engine(monkeypatch, scope_cidrs=["10.0.0.0/29"])
    eng._note_offer_for_pool_estimate("192.168.4.50", "255.255.252.0")
    est = eng._estimate_pool()
    assert est.source == "scope"
    assert est.size == 6  # /29 usable hosts, not the /22 from the offer


def test_estimate_none_when_nothing_is_known():
    eng = DhcpEngine(SessionConfig(interface="lo", mode=Mode.EXHAUST), EventBus())
    est = eng._estimate_pool()
    assert est.size is None
    assert est.source == "none"
    # never fabricated — no scope, no OFFER seen yet
    assert "no --scope" in est.detail or "OFFER" in est.detail


def test_first_offer_wins_later_offers_do_not_override_it(monkeypatch):
    eng, _ = _engine(monkeypatch)
    eng._note_offer_for_pool_estimate("192.168.4.50", "255.255.252.0")  # /22
    eng._note_offer_for_pool_estimate("10.0.0.5", "255.255.255.0")  # /24, should be ignored
    est = eng._estimate_pool()
    assert est.size == 1022


# ---------------------------------------------------------------- headroom
def test_headroom_is_none_when_the_estimate_is_unknown(monkeypatch):
    eng, _ = _engine(monkeypatch)
    est, headroom = eng._pool_headroom()
    assert est.size is None
    assert headroom is None


def test_headroom_subtracts_leases_and_observed_neighbors(monkeypatch):
    eng, _ = _engine(monkeypatch, scope_cidrs=["10.0.0.0/29"])  # size 6
    eng.acks = 2
    eng._neighbors_by_mac["de:ad:00:00:00:01"] = Neighbor("de:ad:00:00:00:01", "10.0.0.3")
    est, headroom = eng._pool_headroom()
    assert est.size == 6
    assert headroom == 3  # 6 - 2 leases - 1 observed neighbor


def test_headroom_floors_at_zero_never_negative(monkeypatch):
    eng, _ = _engine(monkeypatch, scope_cidrs=["10.0.0.0/30"])  # size 2
    eng.acks = 5
    eng._neighbors_by_mac["de:ad:00:00:00:01"] = Neighbor("de:ad:00:00:00:01", "10.0.0.1")
    _, headroom = eng._pool_headroom()
    assert headroom == 0


# ---------------------------------------------------------------- surfaces
def test_status_carries_pool_estimate_fields_for_exhaust(monkeypatch):
    eng, _ = _engine(monkeypatch, scope_cidrs=["10.0.0.0/29"])
    st = eng.status()
    assert st["pool_size"] == 6
    assert st["pool_source"] == "scope"
    assert st["headroom"] == 6
    assert "in_use_observed" in st


def test_status_omits_pool_fields_for_non_exhaust_modes(monkeypatch):
    eng, _ = _engine(monkeypatch, mode=Mode.SCAN)
    st = eng.status()
    assert "pool_size" not in st
    assert "headroom" not in st


def test_status_tick_carries_headroom_fields(monkeypatch):
    eng, events = _engine(monkeypatch, scope_cidrs=["10.0.0.0/29"], status_interval=0.05)
    eng._started = time.time()
    t = threading.Thread(target=eng._status_ticker, daemon=True)
    t.start()
    time.sleep(0.15)
    eng._stop.set()
    t.join(timeout=2)

    ticks = [e.stats for e in events if isinstance(e, ev.StatusTick)]
    assert ticks and all("headroom" in s and "pool_size" in s for s in ticks)


# ---------------------------------------------------------------- finding
def test_pool_headroom_low_finding_raised_when_baseline_utilization_is_high(monkeypatch):
    eng, events = _engine(monkeypatch, scope_cidrs=["10.0.0.0/29"])  # size 6
    eng._started = time.time()
    eng._baseline_neighbor_count = 5  # 5/6 = 83% utilized before the test even started
    eng._finalize_findings()
    ids = [e.finding.id for e in events if isinstance(e, ev.FindingRaised)]
    assert "POOL_HEADROOM_LOW" in ids


def test_pool_headroom_low_not_raised_when_utilization_is_low(monkeypatch):
    eng, events = _engine(monkeypatch, scope_cidrs=["10.0.0.0/24"])  # size 254
    eng._started = time.time()
    eng._baseline_neighbor_count = 5
    eng._finalize_findings()
    ids = [e.finding.id for e in events if isinstance(e, ev.FindingRaised)]
    assert "POOL_HEADROOM_LOW" not in ids
