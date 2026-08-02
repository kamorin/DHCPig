"""Windowed handshake pipeline pacing and halt-on-control (docs/DESIGN.md §5c).

Split from test_control_findings.py (SIMPLIFICATION.md 4.2) -- see test_control_transaction.py
for the split's full file map.
"""

import threading
import time

from conftest import build_engine
from scapy.all import BOOTP, DHCP, IP, UDP, Ether, mac2str

from dhcpig.core import events as ev
from dhcpig.core.models import Mode

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
    """(2.3, Phase 7) 200 clean ACKs per +1 slot, not 2 -- 199 calls must not grow the window,
    the 200th must."""
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST, window_initial=8, window_max=64)
    for _ in range(199):
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
    cold: the next 199 calls still must not grow the window."""
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST, window_initial=8, window_max=64)
    for _ in range(100):
        eng._grow_window()  # bank 0.5, well short of a slot
    eng._shrink_window("nak")  # window -> 4, accumulator wiped
    for _ in range(199):
        eng._grow_window()  # starting from zero again -- should NOT grow yet
    assert eng._window == 4
    eng._grow_window()  # the 200th since the reset
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
