"""Race-freed (2.3): _exhaust_sender() queue-draining and _classify_targeted() outcome parity.

Commit 3 of EXECUTION-PLAN-race-freed.md. See test_race_freed.py for trigger/queue-building
coverage (commit 2).
"""

import time

from scapy.all import BOOTP, DHCP, IP, UDP, Ether, mac2str

from dhcpig.core import engine as engine_mod
from dhcpig.core.engine import DhcpEngine
from dhcpig.core.events import EventBus
from dhcpig.core.models import Mode, SessionConfig

SERVER = "172.20.15.1"


def _engine(monkeypatch, **cfg):
    monkeypatch.setattr(engine_mod, "sendp", lambda *a, **k: None)
    bus = EventBus()
    events = []
    bus.subscribe(events.append)
    cfg.setdefault("mode", Mode.EXHAUST)
    eng = DhcpEngine(SessionConfig(interface="lo", **cfg), bus)
    return eng, events


def _run_one_iteration(eng):
    """_exhaust_sender() loops until _stop is set; wrap _send() to set it after the first call
    so exactly one loop body (one send) executes, deterministically, no threading needed."""
    original_send = eng._send
    calls = []

    def _send_once(pkt, **kw):
        calls.append(pkt)
        eng._stop.set()
        return original_send(pkt, **kw)

    eng._send = _send_once
    eng._exhaust_sender()
    return calls


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


# ---------------------------------------------------------------- queue draining
def test_race_queue_drains_before_untargeted_discover(monkeypatch):
    """A queued race IP is sent -- with option 50 set -- ahead of a plain untargeted DISCOVER,
    even when the window has room (proves priority, not just fallback-when-idle)."""
    eng, events = _engine(monkeypatch)
    eng._race_queue.append("10.0.0.40")
    calls = _run_one_iteration(eng)
    assert len(calls) == 1
    pkt = calls[0]
    from dhcpig.core import packets

    assert packets.dhcp_option(pkt[DHCP].options, "requested_addr") == "10.0.0.40"
    assert eng.races == 1
    assert eng.discovers == 1
    assert "10.0.0.40" not in eng._race_queue


def test_race_send_bypasses_the_window_gate(monkeypatch):
    """A race send happens even when the window has zero room -- the whole point of racing
    ahead rather than waiting a turn in the normal pipeline."""
    eng, events = _engine(monkeypatch)
    eng._window = 1
    eng._inflight[0xDEAD] = {"mac": "de:ad:00:00:00:01", "sent_at": time.time(), "state": "x"}
    assert eng._window - len(eng._inflight) <= 0  # room is exhausted
    eng._race_queue.append("10.0.0.41")
    calls = _run_one_iteration(eng)
    assert len(calls) == 1
    from dhcpig.core import packets

    assert packets.dhcp_option(calls[0][DHCP].options, "requested_addr") == "10.0.0.41"


def test_race_bounded_by_race_max_inflight(monkeypatch):
    """Once race_max_inflight slots are in flight, the sender falls through to the untargeted
    path instead of draining the queue further -- a bounded overtake, not an unlimited one."""
    eng, events = _engine(monkeypatch, race_max_inflight=2)
    eng._race_inflight = 2  # reserve already full
    eng._race_queue.append("10.0.0.42")
    calls = _run_one_iteration(eng)
    assert len(calls) == 1
    from dhcpig.core import packets

    # fell through to the untargeted path -- no requested_addr, queue untouched
    assert packets.dhcp_option(calls[0][DHCP].options, "requested_addr") is None
    assert "10.0.0.42" in eng._race_queue


def test_race_freed_addresses_false_ignores_queue(monkeypatch):
    eng, events = _engine(monkeypatch, race_freed_addresses=False)
    eng._race_queue.append("10.0.0.43")
    calls = _run_one_iteration(eng)
    from dhcpig.core import packets

    assert packets.dhcp_option(calls[0][DHCP].options, "requested_addr") is None
    assert "10.0.0.43" in eng._race_queue  # never drained
    assert eng.races == 0


def test_race_xid_lands_in_race_targets_never_reacquire_targets(monkeypatch):
    """Regression guarding _evict_phase()'s target selection: a raced xid must never appear in
    _reacquire_targets, which is exactly what _evict_phase() reads to pick eviction targets."""
    eng, events = _engine(monkeypatch)
    eng._race_queue.append("10.0.0.44")
    _run_one_iteration(eng)
    assert "10.0.0.44" in eng._race_targets.values()
    assert "10.0.0.44" not in eng._reacquire_targets.values()
    assert eng._reacquire_targets == {}


# ---------------------------------------------------------------- _classify_targeted parity
def test_classify_targeted_ack_parity_for_race_xid(monkeypatch):
    eng, events = _engine(monkeypatch)
    eng._race_queue.append("172.20.0.83")
    calls = _run_one_iteration(eng)
    xid = calls[0][BOOTP].xid
    assert eng._race_inflight == 1
    eng._on_dhcp(_reply("ack", xid, "de:ad:00:00:00:01", yiaddr="172.20.0.83"))
    assert eng._race_outcomes[xid] == "granted"
    assert eng._race_inflight == 0


def test_classify_targeted_ack_offered_different_for_race_xid(monkeypatch):
    eng, events = _engine(monkeypatch)
    eng._race_queue.append("172.20.0.83")
    calls = _run_one_iteration(eng)
    xid = calls[0][BOOTP].xid
    eng._on_dhcp(_reply("ack", xid, "de:ad:00:00:00:01", yiaddr="172.20.0.99"))
    assert eng._race_outcomes[xid] == "offered_different"
    assert eng._race_inflight == 0


def test_classify_targeted_nak_parity_for_race_xid(monkeypatch):
    eng, events = _engine(monkeypatch)
    eng._race_queue.append("172.20.0.83")
    calls = _run_one_iteration(eng)
    xid = calls[0][BOOTP].xid
    eng._on_dhcp(_reply("nak", xid, "de:ad:00:00:00:01"))
    assert eng._race_outcomes[xid] == "naked"
    assert eng._race_inflight == 0


def test_classify_targeted_timeout_parity_for_race_xid(monkeypatch):
    eng, events = _engine(monkeypatch)
    eng.cfg.timeouts.dhcp_request = 0.01
    eng._race_queue.append("172.20.0.83")
    calls = _run_one_iteration(eng)
    xid = calls[0][BOOTP].xid
    time.sleep(0.02)
    eng._reap_timeouts()
    assert eng._race_outcomes[xid] == "no_response"
    assert eng._race_inflight == 0


def test_classify_targeted_still_works_for_reacquire_xids(monkeypatch):
    """Non-regression: the shared classifier must not have changed re-acquisition's own
    behavior (§5f) -- granted/offered_different/naked/no_response all still land correctly."""
    eng, events = _engine(monkeypatch)
    eng._reacquire_targets[0x1] = "172.20.0.83"
    eng._inflight[0x1] = {"mac": "de:ad:00:00:00:02", "sent_at": time.time(), "state": "x"}
    eng._on_dhcp(_reply("ack", 0x1, "de:ad:00:00:00:02", yiaddr="172.20.0.83"))
    assert eng._reacquire_outcomes[0x1] == "granted"
    assert eng._race_inflight == 0  # untouched -- this was never a race xid

    eng._reacquire_targets[0x2] = "172.20.0.90"
    eng._inflight[0x2] = {"mac": "de:ad:00:00:00:03", "sent_at": time.time(), "state": "x"}
    eng._on_dhcp(_reply("nak", 0x2, "de:ad:00:00:00:03"))
    assert eng._reacquire_outcomes[0x2] == "naked"
