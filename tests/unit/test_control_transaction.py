"""Control transaction, NAK handling, and finding derivation from control outcomes.

All no-root: sendp is monkeypatched and the control transaction is driven by feeding
synthetic replies into the engine's sniffer callback.

Split from test_control_findings.py (SIMPLIFICATION.md 4.2) -- pacing/windowed-pipeline tests
live in test_window_halt.py, release-phase/re-acquisition in test_release_phase.py, the
release-mode chain and mode-aware eviction findings in test_release_mode.py, and
auto-finalize/report-surface tests in test_run_lifecycle.py.
"""

import threading
import time

from conftest import build_engine
from scapy.all import BOOTP, DHCP, IP, UDP, Ether, mac2str

from dhcpig.core import engine as engine_mod
from dhcpig.core import events as ev
from dhcpig.core import packets
from dhcpig.core.models import FAIL, INCONCLUSIVE, PASS, ControlOutcome, Lease, Mode

SERVER = "172.20.15.1"


def _reply(kind: str, xid: int, mac: str, yiaddr: str = "172.20.0.83"):
    return (
        Ether(src="00:0c:29:da:53:f9")
        / IP(src=SERVER, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, yiaddr=yiaddr, siaddr=SERVER, chaddr=mac2str(mac) + b"\x00" * 10, xid=xid)
        / DHCP(
            options=[
                ("message-type", kind),
                ("server_id", SERVER),
                ("subnet_mask", "255.255.255.0"),
                ("lease_time", 600),
                "end",
            ]
        )
    )


def _engine(monkeypatch, **cfg):
    return build_engine(monkeypatch, **cfg)


# ---------------------------------------------------------------- NAK (previously dropped)
def test_nak_is_emitted_and_counted(monkeypatch):
    eng, events, _ = _engine(monkeypatch, dry_run=True)
    eng._inflight[0x1234] = {"mac": "de:ad:00:00:00:01", "sent_at": time.time(), "state": "x"}
    eng._on_dhcp(_reply("nak", 0x1234, "de:ad:00:00:00:01"))
    assert eng.naks == 1
    naks = [e for e in events if isinstance(e, ev.NakReceived)]
    assert len(naks) == 1 and naks[0].server_ip == SERVER


def test_foreign_nak_is_not_counted_as_ours(monkeypatch):
    """(2.3, race-freed) BUG FIX regression: a NAK whose xid we never sent must not shrink our
    window or count toward naks/nak_burst -- it belongs to some other client's transaction."""
    eng, events, _ = _engine(monkeypatch, dry_run=True)
    eng._window = 8
    assert 0x9999 not in eng._inflight
    eng._on_dhcp(_reply("nak", 0x9999, "de:ad:00:00:00:99"))
    assert eng.naks == 0
    assert eng._window == 8  # unchanged -- _shrink_window() never ran
    assert eng._nak_timestamps == []  # _note_nak_for_burst_detection() never ran
    assert not any(isinstance(e, ev.NakReceived) for e in events)


def test_is_nak_helper():
    assert packets.is_nak(_reply("nak", 1, "de:ad:00:00:00:01"))
    assert not packets.is_nak(_reply("ack", 1, "de:ad:00:00:00:01"))


# ---------------------------------------------------------------- control transaction
def test_control_skipped_when_offline(monkeypatch):
    """offline=True is the hard skip-everything switch (2.3); dry_run alone no longer skips."""
    eng, events, sent = _engine(monkeypatch, offline=True)
    out = eng._control_transaction("pre")
    assert out.attempted is False and out.success is False
    assert "offline" in out.reason
    assert sent == []
    assert any(isinstance(e, ev.ControlFinished) for e in events)


def test_control_still_probes_under_dry_run(monkeypatch):
    """dry_run alone (offline=False) must not skip the control transaction (2.3): it's a probe
    that self-cleans (DISCOVER/REQUEST/RELEASE), so a dry run is real recon, not a no-op."""
    eng, _, sent = _engine(monkeypatch, dry_run=True)
    monkeypatch.setattr("scapy.all.get_if_hwaddr", lambda _i: "00:11:22:33:44:55")
    eng.cfg.timeouts.control = 0.15  # nobody answers -- we only care that it actually sent
    eng.cfg.control_attempts = 1  # single attempt: this test only cares about the first DISCOVER
    out = eng._control_transaction("pre")
    assert out.attempted is True
    assert "dry-run" not in out.reason
    assert len(sent) == 1  # the DISCOVER went out for real despite dry_run
    assert packets.message_type(sent[0]) == packets.DISCOVER


def test_control_succeeds_when_server_answers(monkeypatch):
    eng, events, sent = _engine(monkeypatch)
    monkeypatch.setattr(engine_mod, "sendp", lambda pkt, **kw: sent.append(pkt))
    monkeypatch.setattr("scapy.all.get_if_hwaddr", lambda _i: "00:11:22:33:44:55")
    eng.cfg.timeouts.control = 2.0

    def responder():
        # wait for the control xid to be set, then answer OFFER then ACK
        for _ in range(100):
            with eng._control_lock:
                xid = eng._control_xid
            if xid:
                break
            time.sleep(0.01)
        eng._on_dhcp(_reply("offer", xid, "00:11:22:33:44:55"))
        eng._control_offer_evt.wait(1)
        eng._on_dhcp(_reply("ack", xid, "00:11:22:33:44:55"))

    t = threading.Thread(target=responder, daemon=True)
    t.start()
    out = eng._control_transaction("pre")
    t.join(timeout=3)

    assert out.attempted and out.success, out.reason
    assert out.offered_ip == "172.20.0.83"
    assert out.server_id == SERVER
    assert out.phase == "pre"
    # DISCOVER, REQUEST, RELEASE — the control gives the address straight back
    assert len(sent) == 3
    assert packets.message_type(sent[-1]) == packets.RELEASE
    assert any(isinstance(e, ev.ControlStarted) for e in events)


def test_control_reports_failure_when_no_offer(monkeypatch):
    eng, _, _ = _engine(monkeypatch)
    monkeypatch.setattr("scapy.all.get_if_hwaddr", lambda _i: "00:11:22:33:44:55")
    eng.cfg.timeouts.control = 0.15  # nobody answers
    eng.cfg.control_attempts = 1  # single attempt: this test is about the failure shape, not retry
    out = eng._control_transaction("pre")
    assert out.attempted and not out.success
    assert "no OFFER" in out.reason
    assert out.attempts == 1
    assert "1 attempt" in out.reason


def test_control_retries_and_succeeds_when_the_first_offer_is_lost(monkeypatch):
    """A lost OFFER on attempt 1 must not fail the whole transaction (2.7.3) -- the verdict is
    derived from this leg's success/failure, so one dropped packet used to be able to flip it."""
    eng, _, sent = _engine(monkeypatch)
    monkeypatch.setattr(engine_mod, "sendp", lambda pkt, **kw: sent.append(pkt))
    monkeypatch.setattr("scapy.all.get_if_hwaddr", lambda _i: "00:11:22:33:44:55")
    eng.cfg.timeouts.control = 0.2
    eng.cfg.control_attempts = 3

    def responder():
        for _ in range(200):
            with eng._control_lock:
                xid = eng._control_xid
            if xid:
                break
            time.sleep(0.01)
        time.sleep(1.3)  # let attempt 1 (0.2s) and the 1.0s retry gap elapse; land inside attempt 2
        eng._on_dhcp(_reply("offer", xid, "00:11:22:33:44:55"))
        eng._control_offer_evt.wait(1)
        eng._on_dhcp(_reply("ack", xid, "00:11:22:33:44:55"))

    t = threading.Thread(target=responder, daemon=True)
    t.start()
    out = eng._control_transaction("pre")
    t.join(timeout=3)

    assert out.success, out.reason
    assert out.attempts == 2
    # DISCOVER x2, REQUEST, RELEASE -- the lost-OFFER attempt only ever sent a DISCOVER
    assert len(sent) == 4
    assert packets.message_type(sent[0]) == packets.DISCOVER
    assert packets.message_type(sent[1]) == packets.DISCOVER


def test_control_nak_stops_retrying_immediately(monkeypatch):
    """A NAK is a definite answer, not a lost packet -- retrying after one would just ask the
    same question again and waste the run's time budget for no new information."""
    eng, _, sent = _engine(monkeypatch)
    monkeypatch.setattr(engine_mod, "sendp", lambda pkt, **kw: sent.append(pkt))
    monkeypatch.setattr("scapy.all.get_if_hwaddr", lambda _i: "00:11:22:33:44:55")
    eng.cfg.timeouts.control = 2.0
    eng.cfg.control_attempts = 3

    def responder():
        for _ in range(200):
            with eng._control_lock:
                xid = eng._control_xid
            if xid:
                break
            time.sleep(0.01)
        eng._on_dhcp(_reply("nak", xid, "00:11:22:33:44:55"))

    t = threading.Thread(target=responder, daemon=True)
    t.start()
    started = time.time()
    out = eng._control_transaction("pre")
    t.join(timeout=3)

    assert not out.success
    assert out.attempts == 1
    assert "NAK" in out.reason
    assert time.time() - started < 1.0  # no 1.0s retry gap, no second 2.0s timeout wait


def test_control_reports_failure_after_exhausting_all_attempts(monkeypatch):
    eng, _, _ = _engine(monkeypatch)
    monkeypatch.setattr("scapy.all.get_if_hwaddr", lambda _i: "00:11:22:33:44:55")
    eng.cfg.timeouts.control = 0.05  # nobody ever answers
    eng.cfg.control_attempts = 3
    out = eng._control_transaction("pre")
    assert not out.success
    assert out.attempts == 3
    assert "3 attempts" in out.reason


def test_control_replies_do_not_pollute_run_counters(monkeypatch):
    """A reply carrying the control xid must not be counted as an exhaust-run offer."""
    eng, _, _ = _engine(monkeypatch)
    with eng._control_lock:
        eng._control_xid = 0xABCD
    eng._on_dhcp(_reply("offer", 0xABCD, "00:11:22:33:44:55"))
    assert eng.offers == 0
    assert eng._control_offer is not None


# ---------------------------------------------------------------- findings
def _finding_ids(events):
    return [e.finding.id for e in events if isinstance(e, ev.FindingRaised)]


def test_failed_baseline_yields_inconclusive(monkeypatch):
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng._started = time.time()
    eng.control_pre = ControlOutcome(phase="pre", attempted=True, success=False, reason="no OFFER")
    eng._finalize_findings()
    ids = _finding_ids(events)
    assert "CONTROL_BASELINE_FAILED" in ids
    f = next(
        e.finding
        for e in events
        if isinstance(e, ev.FindingRaised) and e.finding.id == "CONTROL_BASELINE_FAILED"
    )
    assert f.verdict == INCONCLUSIVE
    # a broken baseline must NOT be reported as the network defending itself, or as any
    # starvation verdict at all (no post-control ever ran here)
    assert "DHCP_STARVATION_NOT_ATTAINED" not in ids
    assert "DHCP_STARVATION_ATTAINED" not in ids


def test_acks_alone_without_a_post_control_reaches_no_verdict(monkeypatch):
    """The retired DHCP_STARVATION_POSSIBLE fired on acks>0 alone; the verdict now needs the
    full post-run new-client control leg, not just held leases."""
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng._started = time.time()
    eng.control_pre = ControlOutcome(phase="pre", attempted=True, success=True)
    eng.acks = 3
    for i in range(3):
        eng.cleanup.register(
            Lease(f"de:ad:00:00:00:0{i}", f"10.0.0.{i}", SERVER, i, eng.cfg.ip_version)
        )
    eng._finalize_findings()
    ids = _finding_ids(events)
    assert "DHCP_STARVATION_ATTAINED" not in ids
    assert "DHCP_STARVATION_NOT_ATTAINED" not in ids


def test_blocked_at_baseline_reason_when_new_mac_already_refused(monkeypatch):
    """Retired DHCP_STARVATION_BLOCKED: an unknown MAC refused pre-run now shows up as the
    'blocked_at_baseline' reason on the (still-PASS) NOT_ATTAINED verdict."""
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng._started = time.time()
    eng.control_pre = ControlOutcome(phase="pre", client="self", attempted=True, success=True)
    eng.control_pre_new = ControlOutcome(
        phase="pre", client="new", attempted=True, success=False, reason="no OFFER"
    )
    eng.control_post_new = ControlOutcome(
        phase="post", client="new", attempted=True, success=False, reason="no OFFER"
    )
    eng.discovers = 40
    eng._finalize_findings()
    fs = {e.finding.id: e.finding for e in events if isinstance(e, ev.FindingRaised)}
    assert fs["DHCP_STARVATION_NOT_ATTAINED"].verdict == PASS
    assert fs["DHCP_STARVATION_NOT_ATTAINED"].evidence["reason"] == "blocked_at_baseline"


def test_exhaustion_attained_only_when_a_NEW_client_is_denied(monkeypatch):
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng._started = time.time()
    eng.control_pre = ControlOutcome(phase="pre", client="self", attempted=True, success=True)
    eng.control_pre_new = ControlOutcome(
        phase="pre", client="new", attempted=True, success=True, offered_ip="10.0.0.7"
    )
    # renewal still works (the server remembers our own MAC) but a new client is refused
    eng.control_post = ControlOutcome(phase="post", client="self", attempted=True, success=True)
    eng.control_post_new = ControlOutcome(
        phase="post", client="new", attempted=True, success=False, reason="no OFFER"
    )
    eng.acks = 250
    eng._finalize_findings()
    fs = {e.finding.id: e.finding for e in events if isinstance(e, ev.FindingRaised)}
    assert fs["DHCP_STARVATION_ATTAINED"].verdict == FAIL
    assert fs["DHCP_STARVATION_ATTAINED"].evidence["renewal_still_worked"] is True


def test_renewal_success_alone_does_not_disprove_exhaustion(monkeypatch):
    """Regression: the self-MAC leg renews an existing binding and can succeed on a drained
    pool, so it must not be what decides DHCP_STARVATION_NOT_ATTAINED."""
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng._started = time.time()
    eng.control_pre = ControlOutcome(phase="pre", client="self", attempted=True, success=True)
    eng.control_pre_new = ControlOutcome(phase="pre", client="new", attempted=True, success=True)
    eng.control_post = ControlOutcome(
        phase="post", client="self", attempted=True, success=True, offered_ip="10.0.0.35"
    )
    eng.control_post_new = ControlOutcome(
        phase="post", client="new", attempted=True, success=False, reason="no OFFER"
    )
    eng.acks = 250
    eng._finalize_findings()
    ids = _finding_ids(events)
    assert "DHCP_STARVATION_ATTAINED" in ids
    assert "DHCP_STARVATION_NOT_ATTAINED" not in ids


def test_new_client_served_means_not_attained(monkeypatch):
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng._started = time.time()
    eng.control_pre = ControlOutcome(phase="pre", client="self", attempted=True, success=True)
    eng.control_pre_new = ControlOutcome(phase="pre", client="new", attempted=True, success=True)
    eng.control_post_new = ControlOutcome(
        phase="post", client="new", attempted=True, success=True, offered_ip="10.0.0.9"
    )
    eng.acks = 5
    eng._finalize_findings()
    fs = {e.finding.id: e.finding for e in events if isinstance(e, ev.FindingRaised)}
    assert fs["DHCP_STARVATION_NOT_ATTAINED"].verdict == PASS
    assert fs["DHCP_STARVATION_NOT_ATTAINED"].evidence["reason"] == "pool_headroom_remaining"
    assert "DHCP_STARVATION_ATTAINED" not in fs
    # zero-valued keys (no leases expired here) are dropped from the rendered summary
    from dataclasses import asdict

    from dhcpig.core.findings import finding_summary_lines

    summary = "\n".join(finding_summary_lines(asdict(fs["DHCP_STARVATION_NOT_ATTAINED"])))
    assert "leases_expired_during_run" not in summary


def test_not_attained_evidence_carries_attempts_and_expired_lease_count(monkeypatch):
    """A FAIL or a NOT_ATTAINED PASS must be auditable: how hard the post/new control tried, and
    whether some of our own leases had already lapsed by the time it ran (2.7.3)."""
    from dhcpig.core.models import IPVersion

    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng._started = time.time()
    eng.control_pre = ControlOutcome(phase="pre", client="self", attempted=True, success=True)
    eng.control_pre_new = ControlOutcome(phase="pre", client="new", attempted=True, success=True)
    eng.control_post_new = ControlOutcome(
        phase="post", client="new", attempted=True, success=True, offered_ip="10.0.0.9", attempts=2
    )
    eng.acks = 5
    eng.cleanup.register(
        Lease(
            "de:ad:00:00:00:01",
            "10.0.0.5",
            "10.0.0.254",
            1,
            IPVersion.V4,
            lease_time=60,
            acquired_at=time.time() - 120,  # expired well before the retest
        )
    )
    eng._finalize_findings()
    fs = {e.finding.id: e.finding for e in events if isinstance(e, ev.FindingRaised)}
    ev_ = fs["DHCP_STARVATION_NOT_ATTAINED"].evidence
    assert ev_["post_new_attempts"] == 2
    assert ev_["leases_expired_during_run"] == 1


def test_control_fired_is_the_reason_when_a_halt_signal_preceded_the_post_control(monkeypatch):
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng._started = time.time()
    eng.control_pre = ControlOutcome(phase="pre", client="self", attempted=True, success=True)
    eng.control_pre_new = ControlOutcome(phase="pre", client="new", attempted=True, success=True)
    eng.control_post_new = ControlOutcome(
        phase="post", client="new", attempted=True, success=True, offered_ip="10.0.0.9"
    )
    eng.acks = 40
    eng._halt_signal = ("nak_burst", "3 NAKs within 5s", 40)
    eng._finalize_findings()
    fs = {e.finding.id: e.finding for e in events if isinstance(e, ev.FindingRaised)}
    ev_ = fs["DHCP_STARVATION_NOT_ATTAINED"].evidence
    assert ev_["reason"] == "control_fired"
    assert ev_["signal"] == "nak_burst"
    assert ev_["leases_at_halt"] == 40


def test_new_client_blocked_at_baseline_is_a_pass(monkeypatch):
    """Own MAC served, unknown MAC refused = L2 admission control, not a broken test."""
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng._started = time.time()
    eng.control_pre = ControlOutcome(phase="pre", client="self", attempted=True, success=True)
    eng.control_pre_new = ControlOutcome(
        phase="pre", client="new", attempted=True, success=False, reason="no OFFER"
    )
    eng.discovers = 30
    eng._finalize_findings()
    fs = {e.finding.id: e.finding for e in events if isinstance(e, ev.FindingRaised)}
    assert fs["NEW_CLIENT_BLOCKED_AT_BASELINE"].verdict == PASS


def test_multiple_servers_and_naks_raise_findings(monkeypatch):
    from dhcpig.core.models import ServerInfo

    eng, events, _ = _engine(monkeypatch, mode=Mode.SCAN)
    eng._started = time.time()
    eng.naks = 2
    eng.servers = {
        "10.0.0.1": ServerInfo("10.0.0.1", "aa:bb:cc:00:00:01", None, eng.cfg.ip_version),
        "10.0.0.2": ServerInfo("10.0.0.2", "aa:bb:cc:00:00:02", None, eng.cfg.ip_version),
    }
    eng._finalize_findings()
    ids = _finding_ids(events)
    assert "MULTIPLE_DHCP_SERVERS" in ids
    assert "DHCP_NAK_OBSERVED" in ids


def test_no_starvation_findings_in_dry_run(monkeypatch):
    """Dry-run (2.3) still derives real findings (control/headroom), but never a starvation
    verdict -- no leases were actually held. DRY_RUN_SUMMARY stands in for it instead."""
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST, dry_run=True)
    eng._started = time.time()
    eng.acks = 10
    eng._finalize_findings()
    ids = _finding_ids(events)
    assert "DHCP_STARVATION_ATTAINED" not in ids
    assert "DHCP_STARVATION_NOT_ATTAINED" not in ids
    assert "DRY_RUN_SUMMARY" in ids
