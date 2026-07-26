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
    eng._on_dhcp(_reply("nak", 0x1234, "de:ad:00:00:00:01"))
    assert eng.naks == 1
    naks = [e for e in events if isinstance(e, ev.NakReceived)]
    assert len(naks) == 1 and naks[0].server_ip == SERVER


def test_is_nak_helper():
    assert packets.is_nak(_reply("nak", 1, "de:ad:00:00:00:01"))
    assert not packets.is_nak(_reply("ack", 1, "de:ad:00:00:00:01"))


# ---------------------------------------------------------------- control transaction
def test_control_skipped_in_dry_run(monkeypatch):
    eng, events, sent = _engine(monkeypatch, dry_run=True)
    out = eng._control_transaction("pre")
    assert out.attempted is False and out.success is False
    assert "dry-run" in out.reason
    assert sent == []
    assert any(isinstance(e, ev.ControlFinished) for e in events)


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
    f = next(e.finding for e in events if isinstance(e, ev.FindingRaised))
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


def test_no_findings_in_dry_run(monkeypatch):
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST, dry_run=True)
    eng._started = time.time()
    eng.acks = 10
    eng._finalize_findings()
    assert _finding_ids(events) == []


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
    for _ in range(20):
        eng._grow_window()
    assert eng._window == 10


def test_ack_grows_window_nak_and_timeout_halve_it(monkeypatch):
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST, window_initial=8, window_max=64)
    # half-rate ramp: the first clean ACK only banks half a slot, the second one cashes it in
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
    """A banked half-slot from before a NAK/timeout shouldn't give the very next ACK after
    the shrink a free head start -- ramping back up should be just as cautious as ramping
    up cold."""
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST, window_initial=8, window_max=64)
    eng._grow_window()  # banks 0.5, window still 8
    eng._shrink_window("nak")  # window -> 4, accumulator wiped
    eng._grow_window()  # banks 0.5 again, not 1.0 -- should NOT grow yet
    assert eng._window == 4
    eng._grow_window()
    assert eng._window == 5


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
    eng._on_dhcp(_reply("ack", 0xBBBB, "de:ad:00:00:00:02"))
    assert eng.acks == 1


def test_nak_burst_triggers_halt_and_stops_sending(monkeypatch):
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    for i in range(3):
        eng._on_dhcp(_reply("nak", i, "de:ad:00:00:00:01"))
    assert eng._halt_signal is not None
    assert eng._halt_signal[0] == "nak_burst"
    assert any(isinstance(e, ev.ControlDetected) and e.signal == "nak_burst" for e in events)


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


def test_duplicate_offer_shrinks_the_window_immediately(monkeypatch):
    """Each duplicate shrinks the window right away, not just at the halt threshold (3)."""
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST, window_initial=8, window_max=64)
    eng._on_dhcp(_reply("offer", 0x2000, "de:ad:00:00:00:01", yiaddr="172.20.0.80"))
    eng._on_dhcp(_reply("offer", 0x2001, "de:ad:00:00:00:02", yiaddr="172.20.0.80"))
    assert eng._window == 4  # one duplicate seen -> halved once
    assert eng._halt_signal is None  # threshold (3 distinct duplicated IPs) not yet reached


def test_duplicate_offers_to_our_macs_triggers_halt(monkeypatch):
    """The pending-offer-table saturation signature from the run that motivated this rewrite."""
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    for i in range(3):
        ip = f"172.20.0.{80 + i}"
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


def test_arp_sweep_can_be_disabled(monkeypatch):
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST, arp_sweep=False)
    order = []
    monkeypatch.setattr(eng, "_baseline_arp_scan", lambda: order.append("arp"))
    monkeypatch.setattr(
        eng,
        "_control_transaction",
        lambda phase, client="self": ControlOutcome(phase=phase, client=client),
    )
    monkeypatch.setattr(eng, "_start_senders", lambda: order.append("senders"))
    eng._exhaust_prelude()
    assert order == ["senders"]


def test_sweep_range_falls_back_to_iface_network_for_exhaust(monkeypatch):
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    monkeypatch.setattr("dhcpig.core.netutils.iface_network_cidr", lambda _i: "192.168.4.0/22")
    assert eng._sweep_cidrs() == ["192.168.4.0/22"]


def test_sweep_range_prefers_explicit_scope(monkeypatch):
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST, scope_cidrs=["10.1.0.0/24"])
    assert eng._sweep_cidrs() == ["10.1.0.0/24"]


def test_destructive_discovery_is_not_widened_by_the_sweep_fallback(monkeypatch):
    """_discover_neighbors must stay pinned to cfg.scope_cidrs unless told otherwise."""
    eng, _, _ = _engine(monkeypatch, mode=Mode.GARP_DOS, scope_cidrs=["10.9.9.0/30"])
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


def test_release_phase_disabled_by_config(monkeypatch):
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST, release_neighbors=False)
    eng.control_pre = ControlOutcome(
        phase="pre", client="self", attempted=True, success=True, server_id="10.0.0.1"
    )
    called = []
    monkeypatch.setattr(eng, "_do_release", lambda *a, **k: called.append(a) or 0)
    eng._release_phase()
    assert called == []


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
    monkeypatch.setattr(eng, "_reprobe_released", lambda neighbors: 0)
    monkeypatch.setattr(eng, "_release_gateway", lambda: None)
    eng._release_phase()
    assert captured["server_ip"] == "10.0.0.1"
    assert captured["server_ip"] != "0.0.0.0"
    assert captured["server_mac"] == "aa:bb:cc:dd:ee:ff"
    ids = [e.finding.id for e in events if isinstance(e, ev.FindingRaised)]
    assert "NEIGHBOR_LEASES_RELEASED" in ids


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
    assert eng._reprobe_released([Neighbor("de:ad:00:00:00:01", "10.0.0.5")]) == 0


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
