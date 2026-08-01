"""Auto-finalize (the run concludes itself without waiting for the operator) and the report
surface (findings/control-transactions round-tripping through SessionRecorder).

Split from test_control_findings.py (SIMPLIFICATION.md 4.2) -- see test_control_transaction.py
for the split's full file map.
"""

import threading
import time

import pytest
from conftest import build_engine

from dhcpig.core import events as ev
from dhcpig.core.models import FAIL, ControlOutcome, Mode, SessionConfig


def _engine(monkeypatch, **cfg):
    return build_engine(monkeypatch, **cfg)


# ---------------------------------------------------------------- auto-finalize
def test_run_finalizes_itself_when_offers_cease(monkeypatch):
    """Regression: the run used to sit idle after the pool drained until Stop was pressed.

    The senders exited on EXHAUSTED but nothing called stop(), so no post-control ran and no
    verdict was ever produced. The engine must now finish the job on its own.
    """
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST, dry_run=True)
    eng._started = time.time()
    eng.cfg.timeouts.offer_silence = 0.2
    eng.acks = 12
    eng._offers_seen_any = True
    eng._last_offer_ts = time.time() - 5.0

    eng._exhaust_sender()
    for _ in range(200):  # the finisher runs off-thread
        if eng.state == "DONE":
            break
        time.sleep(0.01)

    assert eng.state == "DONE", "engine did not finalize itself"
    assert any(isinstance(e, ev.PoolExhausted) for e in events)
    assert any(isinstance(e, ev.SessionEnded) for e in events)


def test_offers_ceasing_emits_progress_before_the_verdict(monkeypatch):
    """The quiet window should report progress, not look like a hang."""
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST, dry_run=True)
    eng._started = time.time()
    eng.cfg.timeouts.offer_silence = 30.0  # long window, so we stay in the quiet period
    eng._offers_seen_any = True
    eng._last_offer_ts = time.time() - 3.0  # quiet for 3s: past the 2s notice, short of 30s
    threading.Timer(0.3, eng._stop.set).start()

    eng._exhaust_sender()

    ceased = [e for e in events if isinstance(e, ev.OffersCeased)]
    assert len(ceased) == 1, "expected exactly one progress notice while offers were quiet"
    assert ceased[0].deadline == 30.0
    assert not any(isinstance(e, ev.PoolExhausted) for e in events)  # not yet


def test_finish_in_background_is_idempotent(monkeypatch):
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST, dry_run=True)
    eng._started = time.time()
    eng._finish_in_background("first")
    eng._finish_in_background("second")  # must not spawn a second finisher
    assert eng._finishing.is_set()


# ---------------------------------------------------------------- report surface
def test_report_carries_findings_and_controls():
    from dhcpig.core.models import Finding
    from dhcpig.core.reporting import SessionRecorder

    rec = SessionRecorder(SessionConfig(interface="eth1"))
    rec.handle(
        ev.FindingRaised(
            finding=Finding(
                id="DHCP_STARVATION_ATTAINED",
                title="t",
                verdict=FAIL,
                severity="high",
                evidence={"leases": 5},
            )
        )
    )
    rec.handle(
        ev.ControlFinished(
            outcome=ControlOutcome(phase="pre", attempted=True, success=True, offered_ip="10.0.0.5")
        )
    )
    data = rec.to_dict()
    assert data["findings"][0]["id"] == "DHCP_STARVATION_ATTAINED"
    assert data["control_transactions"][0]["phase"] == "pre"
    assert data["pool_exhausted"] is False

    text, _ = rec.render("html")
    assert "DHCP_STARVATION_ATTAINED" in text and "Control transactions" in text


@pytest.mark.parametrize("confirmed", [True, False])
def test_pool_exhausted_confirmed_flag_roundtrips(confirmed):
    from dhcpig.core.reporting import SessionRecorder

    rec = SessionRecorder(SessionConfig(interface="eth1"))
    rec.handle(ev.PoolExhausted(leases=9, elapsed=2.0, confirmed=confirmed))
    data = rec.to_dict()
    assert data["pool_exhausted"] is True
    assert data["pool_exhaustion_confirmed"] is confirmed


def test_exhaust_defers_reacquisition_until_after_the_sender(monkeypatch):
    """RFC 2131 §4.3.1: a server prefers an unused address over honouring option 50 from a MAC
    it has never seen. Run before the flood, re-acquisition therefore loses to the free list and
    `granted=0` means nothing. Exhaust holds the freed list until stop(), when the pool is at its
    emptiest and rule 3 is the only rule left."""
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    order = []
    monkeypatch.setattr(eng, "_baseline_arp_scan", lambda: None)
    monkeypatch.setattr(
        eng,
        "_control_transaction",
        lambda phase, client="self": ControlOutcome(phase=phase, client=client),
    )
    freed = [("de:ad:00:00:00:01", "10.0.0.5")]
    monkeypatch.setattr(eng, "_release_phase", lambda: freed)
    monkeypatch.setattr(eng, "_finish_release", lambda f, **kw: order.append(("reacquire", f)))
    monkeypatch.setattr(eng, "_start_senders", lambda: order.append(("senders", None)))

    eng._exhaust_prelude()
    assert order == [("senders", None)]  # nothing re-acquired yet
    assert eng._freed_pending == freed  # held for stop()

    eng._sniffer = type("S", (), {"stop": lambda self: None})()
    monkeypatch.setattr(eng, "_evict_phase", lambda: None)
    monkeypatch.setattr(eng, "_finalize_findings", lambda: None)
    monkeypatch.setattr(eng, "_emit_neighbor_summary", lambda: None)
    eng._started = time.time()
    eng.stop()
    assert ("reacquire", freed) in order
    assert eng._freed_pending == []  # consumed, so a second stop() can't repeat it


def test_release_mode_still_reacquires_inline(monkeypatch):
    """release never drains the pool, so there is nothing to defer *to* -- deferring would just
    delay a weaker measurement. It keeps the inline call and the finding says the evidence is
    weaker."""
    eng, _, _ = _engine(monkeypatch, mode=Mode.RELEASE_NEIGHBORS)
    order = []
    monkeypatch.setattr(eng, "_baseline_arp_scan", lambda: None)
    monkeypatch.setattr(
        eng,
        "_control_transaction",
        lambda phase, client="self": ControlOutcome(phase=phase, client=client),
    )
    monkeypatch.setattr(eng, "_release_phase", lambda: [("de:ad:00:00:00:01", "10.0.0.5")])
    monkeypatch.setattr(eng, "_finish_release", lambda f, **kw: order.append("reacquire"))
    eng._common_prelude(run_new_leg=False)
    assert order == ["reacquire"]
    assert eng._freed_pending == []
