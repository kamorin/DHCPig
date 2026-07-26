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
from dhcpig.core.models import FAIL, INCONCLUSIVE, PASS, ControlOutcome, Lease, Mode, SessionConfig

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
    # a broken baseline must NOT be reported as the network defending itself
    assert "DHCP_STARVATION_BLOCKED" not in ids


def test_leases_obtained_is_a_fail_finding(monkeypatch):
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng._started = time.time()
    eng.control_pre = ControlOutcome(phase="pre", attempted=True, success=True)
    eng.acks = 3
    for i in range(3):
        eng.cleanup.register(
            Lease(f"de:ad:00:00:00:0{i}", f"10.0.0.{i}", SERVER, i, eng.cfg.ip_version)
        )
    eng._finalize_findings()
    fs = {e.finding.id: e.finding for e in events if isinstance(e, ev.FindingRaised)}
    assert "DHCP_STARVATION_POSSIBLE" in fs
    f = fs["DHCP_STARVATION_POSSIBLE"]
    assert f.verdict == FAIL and f.severity == "high"
    assert f.evidence["distinct_client_macs"] == 3


def test_blocked_run_with_good_baseline_is_a_pass(monkeypatch):
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng._started = time.time()
    eng.control_pre = ControlOutcome(
        phase="pre", attempted=True, success=True, offered_ip="10.0.0.5"
    )
    eng.acks = 0
    eng.discovers = 40
    eng._finalize_findings()
    fs = {e.finding.id: e.finding for e in events if isinstance(e, ev.FindingRaised)}
    assert "DHCP_STARVATION_BLOCKED" in fs
    assert fs["DHCP_STARVATION_BLOCKED"].verdict == PASS


def test_post_control_failure_confirms_exhaustion(monkeypatch):
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng._started = time.time()
    eng.control_pre = ControlOutcome(phase="pre", attempted=True, success=True)
    eng.control_post = ControlOutcome(
        phase="post", attempted=True, success=False, reason="no OFFER"
    )
    eng.acks = 250
    eng._finalize_findings()
    fs = {e.finding.id: e.finding for e in events if isinstance(e, ev.FindingRaised)}
    assert fs["POOL_EXHAUSTED_CONFIRMED"].verdict == FAIL


def test_post_control_success_means_not_exhausted(monkeypatch):
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng._started = time.time()
    eng.control_pre = ControlOutcome(phase="pre", attempted=True, success=True)
    eng.control_post = ControlOutcome(
        phase="post", attempted=True, success=True, offered_ip="10.0.0.9"
    )
    eng.acks = 5
    eng._finalize_findings()
    ids = _finding_ids(events)
    assert "POOL_NOT_EXHAUSTED" in ids
    assert "POOL_EXHAUSTED_CONFIRMED" not in ids


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


# ---------------------------------------------------------------- pacing (--rate authoritative)
def test_sender_does_not_add_fixed_sleep(monkeypatch):
    """--rate is the only pacing mechanism; a 0.4s per-packet sleep would break this."""
    eng, _, _ = _engine(monkeypatch, dry_run=True, rate_limit_pps=1000, max_leases=None)
    # dry-run gets no ACKs, so stop the loop on a timer rather than on a lease count
    threading.Timer(0.5, eng._stop.set).start()
    eng._exhaust_sender()
    # at 1000 pps a half-second window should comfortably clear 25; the old fixed 0.4s
    # sleep capped it at ~2/sec no matter what --rate said
    assert eng.discovers > 25, f"only {eng.discovers} discovers in 0.5s — is a fixed sleep back?"


# ---------------------------------------------------------------- report surface
def test_report_carries_findings_and_controls():
    from dhcpig.core.models import Finding
    from dhcpig.core.reporting import SessionRecorder

    rec = SessionRecorder(SessionConfig(interface="eth1"))
    rec.handle(
        ev.FindingRaised(
            finding=Finding(
                id="DHCP_STARVATION_POSSIBLE",
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
    rec.handle(ev.LimitReached(leases=5, elapsed=1.0))
    data = rec.to_dict()
    assert data["findings"][0]["id"] == "DHCP_STARVATION_POSSIBLE"
    assert data["control_transactions"][0]["phase"] == "pre"
    assert data["limit_reached"] is True
    assert data["pool_exhausted"] is False

    text, _ = rec.render("html")
    assert "DHCP_STARVATION_POSSIBLE" in text and "Control transactions" in text


@pytest.mark.parametrize("confirmed", [True, False])
def test_pool_exhausted_confirmed_flag_roundtrips(confirmed):
    from dhcpig.core.reporting import SessionRecorder

    rec = SessionRecorder(SessionConfig(interface="eth1"))
    rec.handle(ev.PoolExhausted(leases=9, elapsed=2.0, confirmed=confirmed))
    data = rec.to_dict()
    assert data["pool_exhausted"] is True
    assert data["pool_exhaustion_confirmed"] is confirmed
