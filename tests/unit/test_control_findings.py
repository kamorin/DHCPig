"""Control transaction, limit-vs-exhaustion, NAK handling and finding derivation.

All no-root: sendp is monkeypatched and the control transaction is driven by feeding
synthetic replies into the engine's sniffer callback.
"""

import threading
import time

import pytest
from scapy.all import BOOTP, DHCP, IP, UDP, Ether, mac2str

from dhcpig.core import engine as engine_mod
from dhcpig.core import events as ev
from dhcpig.core import packets
from dhcpig.core.engine import DhcpEngine
from dhcpig.core.events import EventBus
from dhcpig.core.models import (
    FAIL,
    INCONCLUSIVE,
    PASS,
    ControlOutcome,
    Lease,
    Mode,
    SessionConfig,
)

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
    sent = []
    monkeypatch.setattr(engine_mod, "sendp", lambda pkt, **kw: sent.append(pkt))
    bus = EventBus()
    events = []
    bus.subscribe(events.append)
    eng = DhcpEngine(SessionConfig(interface="lo", **cfg), bus)
    return eng, events, sent


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
    out = eng._control_transaction("pre")
    assert out.attempted and not out.success
    assert "no OFFER" in out.reason


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


def test_offers_ceasing_while_new_client_served_is_a_throttle_not_exhaustion(monkeypatch):
    """The real-network case: offers stop, but a brand-new client is still served."""
    from dhcpig.core.engine import EXHAUSTED

    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng._started = time.time()
    eng.state = EXHAUSTED  # senders saw offers cease
    eng.control_pre = ControlOutcome(phase="pre", client="self", attempted=True, success=True)
    eng.control_pre_new = ControlOutcome(phase="pre", client="new", attempted=True, success=True)
    eng.control_post_new = ControlOutcome(
        phase="post", client="new", attempted=True, success=True, offered_ip="192.168.4.35"
    )
    eng.acks = 56
    eng.naks = 8
    eng._finalize_findings()
    fs = {e.finding.id: e.finding for e in events if isinstance(e, ev.FindingRaised)}
    assert "DHCP_STARVATION_ATTAINED" not in fs
    assert "SERVER_STOPPED_SERVING_TEST_CLIENTS" in fs
    assert fs["SERVER_STOPPED_SERVING_TEST_CLIENTS"].evidence["naks"] == 8


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


# ---------------------------------------------------------------- pacing (windowed pipeline)
def test_sender_does_not_add_fixed_sleep(monkeypatch):
    """No per-packet fixed sleep; throughput is bound only by the window and the rate limiter.

    A high window_initial takes the window out of the picture here (dry-run gets no OFFERs, so
    slots only ever free up on the 2s dhcp_request timeout) — this test is specifically about
    the old 0.4s fixed sleep, not about window sizing, which has its own tests below.
    """
    eng, _, _ = _engine(
        monkeypatch, dry_run=True, rate_limit_pps=1000, window_initial=100000, window_max=100000
    )
    # dry-run gets no ACKs, so stop the loop on a timer rather than on a lease count
    threading.Timer(0.5, eng._stop.set).start()
    eng._exhaust_sender()
    # at 1000 pps a half-second window should comfortably clear 25; the old fixed 0.4s
    # sleep capped it at ~2/sec no matter what --rate said
    assert eng.discovers > 25, f"only {eng.discovers} discovers in 0.5s — is a fixed sleep back?"


# ---------------------------------------------------------------- windowed handshake pipeline
def test_window_never_exceeds_its_configured_cap(monkeypatch):
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST, window_initial=8, window_max=10)
    eng.cfg.window_growth_per_ack = 1.0  # cap behavior, not the ratchet rate, is under test
    for _ in range(20):
        eng._grow_window()
    assert eng._window == 10


def test_ack_grows_window_nak_and_timeout_halve_it(monkeypatch):
    """(2.3, Phase 7) 100 clean ACKs per +1 slot, not 2 -- 99 calls must not grow the window,
    the 100th must."""
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST, window_initial=8, window_max=64)
    for _ in range(99):
        eng._grow_window()
    assert eng._window == 8
    eng._grow_window()
    assert eng._window == 9
    eng._shrink_window("nak")
    assert eng._window == 4
    eng._window = 8
    eng._shrink_window("timeout")
    assert eng._window == 4


def test_growth_accumulator_resets_on_shrink(monkeypatch):
    """A partially-banked accumulator from before a NAK/timeout shouldn't give the ACKs right
    after the shrink a head start -- ramping back up should be just as cautious as ramping up
    cold: the next 99 calls still must not grow the window."""
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST, window_initial=8, window_max=64)
    for _ in range(50):
        eng._grow_window()  # bank 0.5, well short of a slot
    eng._shrink_window("nak")  # window -> 4, accumulator wiped
    for _ in range(99):
        eng._grow_window()  # starting from zero again -- should NOT grow yet
    assert eng._window == 4
    eng._grow_window()  # the 100th since the reset
    assert eng._window == 5


def test_window_growth_per_ack_is_config_driven(monkeypatch):
    """The increment is a SessionConfig field, not a hardcoded literal (2.3, Phase 7)."""
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST, window_initial=8, window_max=64)
    eng.cfg.window_growth_per_ack = 1.0
    eng._grow_window()  # a single ACK is enough to grow the window when the rate is 1.0
    assert eng._window == 9


def test_only_acks_increment_the_lease_counter_not_timeouts(monkeypatch):
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    xid = 0xAAAA
    with eng._inflight_lock:
        eng._inflight[xid] = {"mac": "de:ad:00:00:00:01", "sent_at": 0.0, "state": "DISCOVER_SENT"}
    eng.cfg.timeouts.dhcp_request = 0.01
    time.sleep(0.02)
    eng._reap_timeouts()
    assert eng.acks == 0
    assert eng.timeouts_seen == 1
    assert eng._inflight == {}
    eng._inflight[0xBBBB] = {"mac": "de:ad:00:00:00:02", "sent_at": time.time(), "state": "x"}
    eng._on_dhcp(_reply("ack", 0xBBBB, "de:ad:00:00:00:02"))
    assert eng.acks == 1


def test_ack_populates_lease_time_from_option_51(monkeypatch):
    """Regression: Lease.lease_time used to be dropped on the floor at _handle_ack -- the
    journal (2.2) needs it to know when a phantom lease naturally expires."""
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng._inflight[0xCCCC] = {"mac": "de:ad:00:00:00:03", "sent_at": time.time(), "state": "x"}
    eng._on_dhcp(_reply("ack", 0xCCCC, "de:ad:00:00:00:03"))
    acked = [e for e in events if isinstance(e, ev.AckReceived)]
    assert acked and acked[-1].lease.lease_time == 600  # _reply() bakes in lease_time=600


def test_nak_burst_triggers_halt_and_stops_sending(monkeypatch):
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    for i in range(3):
        eng._inflight[i] = {"mac": "de:ad:00:00:00:01", "sent_at": time.time(), "state": "x"}
        eng._on_dhcp(_reply("nak", i, "de:ad:00:00:00:01"))
    assert eng._halt_signal is not None
    assert eng._halt_signal[0] == "nak_burst"
    assert any(isinstance(e, ev.ControlDetected) and e.signal == "nak_burst" for e in events)


def test_foreign_naks_do_not_trigger_halt(monkeypatch):
    """Companion to test_foreign_nak_is_not_counted_as_ours: three foreign NAKs must not add up
    to a nak_burst halt the way three of our own would."""
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    for i in range(3):
        eng._on_dhcp(_reply("nak", i, "de:ad:00:00:00:01"))  # never registered in _inflight
    assert eng._halt_signal is None
    assert not any(isinstance(e, ev.ControlDetected) for e in events)


def test_timeout_storm_triggers_halt(monkeypatch):
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng.cfg.timeouts.dhcp_request = 0.01
    for i in range(5):
        with eng._inflight_lock:
            eng._inflight[i] = {
                "mac": "de:ad:00:00:00:01",
                "sent_at": 0.0,
                "state": "DISCOVER_SENT",
            }
    time.sleep(0.02)
    eng._reap_timeouts()
    assert eng._halt_signal is not None
    assert eng._halt_signal[0] == "timeout_storm"


def _mark_ours(eng, xid: int, mac: str) -> None:
    """Register xid in _inflight, simulating that we actually sent the DISCOVER this OFFER is
    replying to -- _handle_offer() now requires this (2.3 bug fix: it used to build and send a
    REQUEST for any OFFER seen, ours or not -- see the docstring on _handle_offer())."""
    eng._inflight[xid] = {"mac": mac, "sent_at": time.time(), "state": "DISCOVER_SENT"}


def test_duplicate_offer_shrinks_the_window_immediately(monkeypatch):
    """Each duplicate shrinks the window right away, not just at the halt threshold (3)."""
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST, window_initial=8, window_max=64)
    _mark_ours(eng, 0x2000, "de:ad:00:00:00:01")
    _mark_ours(eng, 0x2001, "de:ad:00:00:00:02")
    eng._on_dhcp(_reply("offer", 0x2000, "de:ad:00:00:00:01", yiaddr="172.20.0.80"))
    eng._on_dhcp(_reply("offer", 0x2001, "de:ad:00:00:00:02", yiaddr="172.20.0.80"))
    assert eng._window == 4  # one duplicate seen -> halved once
    assert eng._halt_signal is None  # threshold (3 distinct duplicated IPs) not yet reached


def test_duplicate_offers_to_our_macs_triggers_halt(monkeypatch):
    """The pending-offer-table saturation signature from the run that motivated this rewrite."""
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    for i in range(3):
        ip = f"172.20.0.{80 + i}"
        _mark_ours(eng, 0x1000 + i * 2, "de:ad:00:00:00:01")
        _mark_ours(eng, 0x1000 + i * 2 + 1, "de:ad:00:00:00:02")
        eng._on_dhcp(_reply("offer", 0x1000 + i * 2, "de:ad:00:00:00:01", yiaddr=ip))
        eng._on_dhcp(_reply("offer", 0x1000 + i * 2 + 1, "de:ad:00:00:00:02", yiaddr=ip))
    assert eng._halt_signal is not None
    assert eng._halt_signal[0] == "duplicate_offers"


def test_halt_stops_the_sender_but_leaves_leases_held(monkeypatch):
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST, dry_run=True)
    eng._started = time.time()
    eng.acks = 7
    eng._trigger_halt("nak_burst", "3 NAKs within 5s")
    eng._exhaust_sender()  # must return immediately without sending anything
    assert eng.discovers == 0
    assert eng.acks == 7  # nothing released — the post-controls still need the leases held


def test_halt_is_idempotent_first_signal_wins(monkeypatch):
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST, dry_run=True)
    eng._started = time.time()
    eng._trigger_halt("nak_burst", "first")
    eng._trigger_halt("timeout_storm", "second")
    assert eng._halt_signal[0] == "nak_burst"
    assert sum(isinstance(e, ev.ControlDetected) for e in events) == 1


def test_link_down_reported_as_none_for_an_interface_without_carrier():
    from dhcpig.core.netutils import link_is_up

    # "lo" (and any nonexistent iface) has no /sys/class/net/<iface>/carrier -> fail open
    assert link_is_up("lo") in (None, True)
    assert link_is_up("this-iface-does-not-exist-xyz") is None


# ---------------------------------------------------------------- pre-run ARP sweep
def test_prelude_sweeps_then_controls_then_release_then_senders(monkeypatch):
    """Baseline inventory, controls, and the release phase must all precede the first DISCOVER."""
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    order = []
    monkeypatch.setattr(eng, "_baseline_arp_scan", lambda: order.append("arp"))
    monkeypatch.setattr(
        eng,
        "_control_transaction",
        lambda phase, client="self": (
            order.append(f"ctl-{phase}-{client}") or ControlOutcome(phase=phase, client=client)
        ),
    )
    monkeypatch.setattr(eng, "_release_phase", lambda: order.append("release"))
    monkeypatch.setattr(eng, "_start_senders", lambda: order.append("senders"))
    eng._exhaust_prelude()
    assert order == ["arp", "ctl-pre-self", "ctl-pre-new", "release", "senders"]


def test_arp_sweep_is_unconditional(monkeypatch):
    """The sweep has no opt-out any more: every later phase (release targets, re-acquisition,
    eviction, the NeighborSummary roll-call) reads the inventory it builds, so skipping it
    hollowed out the rest of the run rather than just saving a few seconds."""
    from dhcpig.core.models import SessionConfig

    assert not hasattr(SessionConfig(interface="lo"), "arp_sweep")
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    order = []
    monkeypatch.setattr(eng, "_baseline_arp_scan", lambda: order.append("arp"))
    monkeypatch.setattr(
        eng,
        "_control_transaction",
        lambda phase, client="self": ControlOutcome(phase=phase, client=client),
    )
    monkeypatch.setattr(eng, "_release_phase", lambda: None)
    monkeypatch.setattr(eng, "_start_senders", lambda: order.append("senders"))
    eng._exhaust_prelude()
    assert order == ["arp", "senders"]


def test_sweep_range_falls_back_to_iface_network_for_exhaust(monkeypatch):
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    monkeypatch.setattr("dhcpig.core.netutils.iface_network_cidr", lambda _i: "192.168.4.0/22")
    assert eng._sweep_cidrs() == ["192.168.4.0/22"]


def test_sweep_range_prefers_explicit_scope(monkeypatch):
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST, scope_cidrs=["10.1.0.0/24"])
    assert eng._sweep_cidrs() == ["10.1.0.0/24"]


def test_destructive_discovery_is_not_widened_by_the_sweep_fallback(monkeypatch):
    """_discover_neighbors must stay pinned to cfg.scope_cidrs unless told otherwise."""
    eng, _, _ = _engine(monkeypatch, mode=Mode.RELEASE_NEIGHBORS, scope_cidrs=["10.9.9.0/30"])
    seen = {}

    def fake_srp(pkt, **kw):
        seen["targets"] = pkt.pdst if hasattr(pkt, "pdst") else pkt[1].pdst
        return [], []

    monkeypatch.setattr("scapy.all.srp", fake_srp)
    eng._discover_neighbors()  # no cidrs argument -> scope only
    assert all(t.startswith("10.9.9.") for t in seen["targets"])


# ---------------------------------------------------------------- release phase (exhaust)
from dhcpig.core.models import Neighbor  # noqa: E402


def test_release_phase_skipped_without_a_known_server(monkeypatch):
    """BUG FIX (2.1): must never fall back to server_id=0.0.0.0 — skip instead."""
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng._neighbors_by_mac["de:ad:00:00:00:01"] = Neighbor("de:ad:00:00:00:01", "10.0.0.5")
    called = []
    monkeypatch.setattr(eng, "_do_release", lambda *a, **k: called.append(a) or 0)
    assert eng.control_pre is None
    eng._release_phase()
    assert called == []
    assert any(isinstance(e, ev.Debug) and "skipped" in e.message for e in events)


def test_release_phase_has_no_config_opt_out(monkeypatch):
    """Freeing addresses and then taking them is the behaviour under test; with it off, exhaust
    competed only for whatever was already free and re-acquisition/eviction had nothing to feed
    on. A missing server identity still self-skips -- that's a precondition, not an option."""
    from dhcpig.core.models import SessionConfig

    assert not hasattr(SessionConfig(interface="lo"), "release_neighbors")
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng.control_pre = ControlOutcome(
        phase="pre", client="self", attempted=True, success=True, server_id="10.0.0.1"
    )
    eng._neighbors_by_mac["aa:bb:cc:dd:ee:01"] = Neighbor(mac="aa:bb:cc:dd:ee:01", ip="10.0.0.7")
    called = []
    monkeypatch.setattr(eng, "_do_release", lambda *a, **k: called.append(a) or 1)
    eng._release_phase()
    assert called  # it ran


def test_release_phase_uses_server_from_pre_control(monkeypatch):
    """The server identity comes from control_pre, never a guess — this is the actual bug fix."""
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng.control_pre = ControlOutcome(
        phase="pre",
        client="self",
        attempted=True,
        success=True,
        server_id="10.0.0.1",
        server_mac="aa:bb:cc:dd:ee:ff",
    )
    eng._neighbors_by_mac["de:ad:00:00:00:01"] = Neighbor("de:ad:00:00:00:01", "10.0.0.5")
    captured = {}

    def fake_do_release(neighbors, server_ip, server_mac=None):
        captured["neighbors"] = neighbors
        captured["server_ip"] = server_ip
        captured["server_mac"] = server_mac
        return len(neighbors)

    monkeypatch.setattr(eng, "_do_release", fake_do_release)
    monkeypatch.setattr(eng, "_reprobe_released", lambda ips: 0)
    monkeypatch.setattr(eng, "_release_gateway", lambda: None)
    monkeypatch.setattr(
        eng,
        "_reacquire_phase",
        lambda freed, **kw: {"granted": 1, "offered_different": 0, "naked": 0, "no_response": 0},
    )
    freed = eng._release_phase()
    eng._finish_release(freed)
    assert captured["server_ip"] == "10.0.0.1"
    assert captured["server_ip"] != "0.0.0.0"
    assert captured["server_mac"] == "aa:bb:cc:dd:ee:ff"
    assert freed == [("de:ad:00:00:00:01", "10.0.0.5")]
    ids = [e.finding.id for e in events if isinstance(e, ev.FindingRaised)]
    assert "NEIGHBOR_LEASES_RELEASED" in ids
    finding = next(
        e.finding
        for e in events
        if isinstance(e, ev.FindingRaised) and e.finding.id == "NEIGHBOR_LEASES_RELEASED"
    )
    assert finding.evidence["granted"] == 1


def test_release_phase_excludes_gateway_and_server(monkeypatch):
    """Releasing the gateway's own lease is disruption out of proportion to the address gained."""
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng.control_pre = ControlOutcome(
        phase="pre", client="self", attempted=True, success=True, server_id="10.0.0.1"
    )
    eng._neighbors_by_mac = {
        "de:ad:00:00:00:01": Neighbor("de:ad:00:00:00:01", "10.0.0.1"),  # the DHCP server itself
        "de:ad:00:00:00:02": Neighbor("de:ad:00:00:00:02", "10.0.0.254"),  # gateway
        "de:ad:00:00:00:03": Neighbor("de:ad:00:00:00:03", "10.0.0.5"),  # ordinary host
    }
    captured = {}

    def fake_do_release(neighbors, sid, server_mac=None):
        captured["neighbors"] = neighbors
        return 0

    monkeypatch.setattr(eng, "_do_release", fake_do_release)
    monkeypatch.setattr(eng, "_reprobe_released", lambda neighbors: 0)
    monkeypatch.setattr(eng, "_release_gateway", lambda: "10.0.0.254")
    eng._release_phase()
    ips = {n.ip for n in captured["neighbors"]}
    assert ips == {"10.0.0.5"}


def test_release_phase_dry_run_reprobe_sends_nothing(monkeypatch):
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST, dry_run=True)
    assert eng._reprobe_released(["10.0.0.5"]) == 0


# ---------------------------------------------------------------- targeted re-acquisition (2.3)
def test_finish_release_is_a_noop_when_nothing_was_freed(monkeypatch):
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    called = []
    monkeypatch.setattr(eng, "_reacquire_phase", lambda freed, **kw: called.append(freed) or {})
    eng._finish_release([])
    assert called == []  # never even attempted -- nothing to re-acquire
    assert not any(isinstance(e, ev.FindingRaised) for e in events)


def _nothing_granted(monkeypatch, mode):
    eng, events, _ = _engine(monkeypatch, mode=mode)
    ctl = ControlOutcome(
        phase="pre", client="self", attempted=True, success=True, server_id=SERVER
    )
    if mode is Mode.EXHAUST:
        eng.control_pre = ctl
    else:
        eng._rel_pre_control = ctl
    monkeypatch.setattr(eng, "_reprobe_released", lambda ips: 0)
    monkeypatch.setattr(
        eng,
        "_reacquire_phase",
        lambda freed, **kw: {"granted": 0, "offered_different": 2, "naked": 0, "no_response": 0},
    )
    eng._finish_release([("de:ad:00:00:00:01", "10.0.0.5"), ("de:ad:00:00:00:02", "10.0.0.6")])
    return next(
        e.finding
        for e in events
        if isinstance(e, ev.FindingRaised) and e.finding.id == "NEIGHBOR_LEASES_RELEASED"
    )


def test_nothing_granted_in_exhaust_is_real_evidence(monkeypatch):
    """In exhaust the pool is drained before re-acquisition runs, so the server had no unused
    address to prefer instead -- a zero here genuinely means it declined."""
    finding = _nothing_granted(monkeypatch, Mode.EXHAUST)
    assert finding.evidence["granted"] == 0
    assert "desired behavior" in finding.recommendation
    assert "drained" in finding.recommendation


def test_nothing_granted_outside_exhaust_must_not_claim_the_server_defended(monkeypatch):
    """The old text said "the server ignored the unauthenticated RELEASE" for any zero. With
    addresses still free, RFC 2131 §4.3.1 has the server prefer an unused one over honouring
    option 50 from an unknown MAC -- same observable result, completely different conclusion.
    Claiming the network defended itself off that is a false PASS in everything but name."""
    finding = _nothing_granted(monkeypatch, Mode.RELEASE_NEIGHBORS)
    rec = finding.recommendation
    assert finding.evidence["granted"] == 0
    assert "does NOT show the server protected" in rec
    assert "ignored the unauthenticated RELEASE" not in rec
    assert "desired behavior" not in rec


def test_finish_release_recommendation_when_some_granted(monkeypatch):
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng.control_pre = ControlOutcome(
        phase="pre", client="self", attempted=True, success=True, server_id=SERVER
    )
    monkeypatch.setattr(eng, "_reprobe_released", lambda ips: 0)
    monkeypatch.setattr(
        eng,
        "_reacquire_phase",
        lambda freed, **kw: {"granted": 1, "offered_different": 0, "naked": 0, "no_response": 0},
    )
    eng._finish_release([("de:ad:00:00:00:01", "10.0.0.5")])
    finding = next(
        e.finding
        for e in events
        if isinstance(e, ev.FindingRaised) and e.finding.id == "NEIGHBOR_LEASES_RELEASED"
    )
    assert finding.evidence["granted"] == 1
    assert "re-acquire" in finding.recommendation


def test_reacquire_phase_classifies_all_four_outcomes(monkeypatch):
    """End-to-end through the real windowed pipeline: granted (offer matches option 50),
    offered_different (server ignored option 50), naked (REQUEST refused), and no_response
    (never answered) must each land in the right bucket."""
    eng, events, sent = _engine(monkeypatch)
    eng.cfg.timeouts.control = 0.5
    eng.cfg.timeouts.dhcp_request = 0.3
    behaviors = ["granted", "offered_different", "naked", "no_response"]
    freed = [(f"de:ad:00:00:00:0{i}", f"172.20.0.{50 + i}") for i in range(len(behaviors))]
    handled: set[int] = set()

    def responder():
        deadline = time.time() + 2.0
        while len(handled) < 3 and time.time() < deadline:  # no_response is never handled
            with eng._inflight_lock:
                xids = list(eng._reacquire_targets.items())
            for idx, (xid, req_ip) in enumerate(xids):
                if xid in handled or behaviors[idx] == "no_response":
                    continue
                handled.add(xid)
                offer_ip = req_ip if behaviors[idx] in ("granted", "naked") else "10.0.0.222"
                mac = f"00:11:22:33:44:0{idx}"
                eng._on_dhcp(_reply("offer", xid, mac, yiaddr=offer_ip))
                time.sleep(0.05)  # let _handle_offer's REQUEST land before the final reply
                kind = "nak" if behaviors[idx] == "naked" else "ack"
                eng._on_dhcp(_reply(kind, xid, mac, yiaddr=offer_ip))
            time.sleep(0.02)

    t = threading.Thread(target=responder, daemon=True)
    t.start()
    counts = eng._reacquire_phase(freed)
    t.join(timeout=3)
    assert counts == {"granted": 1, "offered_different": 1, "naked": 1, "no_response": 1}


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
