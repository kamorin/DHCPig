"""Engine chokepoint tests: dry-run, scope, restore, destructive helpers.

All run without root by monkeypatching dhcpig.core.engine.sendp.
"""

import pytest

from dhcpig.core import engine as engine_mod
from dhcpig.core import events as ev
from dhcpig.core import packets
from dhcpig.core.engine import DhcpEngine
from dhcpig.core.events import EventBus
from dhcpig.core.models import IPVersion, Lease, Mode, Neighbor, SessionConfig


@pytest.fixture
def sent(monkeypatch):
    calls = []
    monkeypatch.setattr(engine_mod, "sendp", lambda pkt, **kw: calls.append(pkt))
    return calls


def _bus_collect():
    bus = EventBus()
    events: list = []
    bus.subscribe(events.append)
    return bus, events


def _pkt():
    return packets.build_discover_v4("de:ad:00:00:00:01", 1, "de:ad:00:00:00:01")


def test_dry_run_never_sends(sent):
    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo", dry_run=True), bus)
    assert eng._send(_pkt()) is True
    assert sent == []  # nothing on the wire


def test_live_send_calls_sendp(sent):
    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo", dry_run=False), bus)
    assert eng._send(_pkt()) is True
    assert len(sent) == 1


def test_scope_blocks_out_of_scope_target(sent):
    bus, events = _bus_collect()
    cfg = SessionConfig(interface="lo", mode=Mode.RELEASE_NEIGHBORS, scope_cidrs=["10.0.0.0/24"])
    eng = DhcpEngine(cfg, bus)
    assert eng._send(_pkt(), target_ip="192.168.1.5") is False
    assert sent == []
    assert any(isinstance(e, ev.Skipped) and e.ip == "192.168.1.5" for e in events)


def test_restore_releases_exactly_acquired_leases(sent):
    bus, events = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo"), bus)
    eng.cleanup.register(Lease("de:ad:00:00:00:01", "10.0.0.5", "10.0.0.1", 1, IPVersion.V4))
    eng.cleanup.register(Lease("de:ad:00:00:00:02", "10.0.0.6", "10.0.0.1", 2, IPVersion.V4))
    eng.restore()
    assert len(sent) == 2
    assert all(ln.released for ln in eng.cleanup.all())
    assert sum(isinstance(e, ev.LeaseReleased) for e in events) == 2
    eng.restore()  # idempotent — nothing pending
    assert len(sent) == 2


def test_do_garp_only_in_scope(sent):
    """(2.3) _do_garp is the frame-building core that Phase 4's eviction reuses (renamed to
    _do_arp_conflict there); scope enforcement must survive that rewrite unchanged."""
    bus, events = _bus_collect()
    cfg = SessionConfig(interface="lo", mode=Mode.RELEASE_NEIGHBORS, scope_cidrs=["172.20.0.0/16"])
    eng = DhcpEngine(cfg, bus)
    targets = [
        Neighbor("de:ad:00:00:00:01", "172.20.0.7"),
        Neighbor("de:ad:00:00:00:02", "10.9.9.9"),  # out of scope
        Neighbor("de:ad:00:00:00:03", "172.20.0.8"),
    ]
    n = eng._do_garp(targets)
    # two in-scope targets x (ARP conflict request + reply); no third/gateway frame (2.3)
    assert n == 4
    assert len(sent) == 4
    assert any(isinstance(e, ev.Skipped) for e in events)


def test_garp_sends_both_arp_forms(sent):
    from dhcpig.core import packets as pk

    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo", mode=Mode.RELEASE_NEIGHBORS), bus)
    eng._do_garp([Neighbor("de:ad:00:00:00:01", "10.0.0.7")])
    ops = [p[pk.ARP].op for p in sent]
    assert ops == [pk.ARP_REQUEST, pk.ARP_REPLY]
    for p in sent:  # announcement form: psrc == pdst == the claimed address
        assert p[pk.ARP].psrc == p[pk.ARP].pdst == "10.0.0.7"


def test_do_garp_no_longer_takes_a_gateway_blackhole():
    """(2.3) build_arp_poison() and the third unicast gateway-blackhole frame were removed --
    _do_garp's signature no longer accepts a `gateway` argument at all."""
    import inspect

    sig = inspect.signature(DhcpEngine._do_garp)
    assert "gateway" not in sig.parameters


def test_do_release_only_in_scope(sent):
    bus, events = _bus_collect()
    cfg = SessionConfig(interface="lo", mode=Mode.RELEASE_NEIGHBORS, scope_cidrs=["172.20.0.0/16"])
    eng = DhcpEngine(cfg, bus)
    neighbors = [
        Neighbor("de:ad:00:00:00:11", "172.20.0.51"),
        Neighbor("de:ad:00:00:00:12", "10.9.9.9"),
    ]
    n = eng._do_release(neighbors, server_ip="172.20.15.1")
    assert n == 1
    assert len(sent) == 1


def test_scope_still_bounds_targets_when_supplied(sent):
    """--scope is optional now, but when given it must still be enforced at _send()."""
    bus, events = _bus_collect()
    cfg = SessionConfig(interface="lo", mode=Mode.RELEASE_NEIGHBORS, scope_cidrs=["10.0.0.0/24"])
    eng = DhcpEngine(cfg, bus)
    assert eng._send(_pkt(), target_ip="10.0.0.5") is True
    assert eng._send(_pkt(), target_ip="192.168.1.5") is False
    assert sum(isinstance(e, ev.Skipped) for e in events) == 1


def test_active_scan_requires_scope():
    from dhcpig.core.exceptions import ConfigError

    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo", mode=Mode.ACTIVE_SCAN), bus)
    with pytest.raises(ConfigError):
        eng.start()  # no scope -> refused (not gated by auth, but scope is mandatory)


def test_active_scan_dry_run_sends_nothing(sent):
    import time as _t

    bus, events = _bus_collect()
    cfg = SessionConfig(
        interface="lo", mode=Mode.ACTIVE_SCAN, dry_run=True, scope_cidrs=["10.0.0.0/24"]
    )
    eng = DhcpEngine(cfg, bus)
    eng.start()
    _t.sleep(0.2)
    eng.stop()
    assert sent == []  # dry-run: INFORM built + logged, nothing on the wire
    assert any(isinstance(e, ev.Debug) and "INFORM" in e.message for e in events)


# ---------------------------------------------------------------- self-filter (2.3)
def test_sniffer_bpf_widened_to_both_directions():
    """(2.3) Foreign DISCOVERs and DHCPDECLINEs are client->server (dst port 67) and were
    invisible under the old server-only filter."""
    from dhcpig.core.sniffer import _BPF

    assert _BPF[IPVersion.V4] == "arp or icmp or (udp and (port 67 or port 68))"


def test_is_own_traffic_true_for_our_mac(sent):
    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo"), bus)
    eng._our_macs.add("de:ad:00:00:00:01")
    pkt = packets.build_discover_v4("de:ad:00:00:00:01", 0x1111, "de:ad:00:00:00:01")
    assert eng._is_own_traffic(pkt) is True


def test_is_own_traffic_true_for_inflight_xid(sent):
    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo"), bus)
    eng._inflight[0x2222] = {"mac": "de:ad:00:00:00:02", "sent_at": 0.0, "state": "DISCOVER_SENT"}
    # a different (unregistered) src MAC -- only the xid should match
    pkt = packets.build_discover_v4("de:ad:00:00:00:02", 0x2222, "de:ad:00:00:00:02")
    assert eng._is_own_traffic(pkt) is True


def test_is_own_traffic_false_for_a_stranger(sent):
    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo"), bus)
    pkt = packets.build_discover_v4("de:ad:00:00:00:09", 0x3333, "de:ad:00:00:00:09")
    assert eng._is_own_traffic(pkt) is False


def test_on_dhcp_ignores_a_packet_whose_xid_is_in_inflight():
    """The self-filter must not raise NeighborFound/ErrorEvent or otherwise process our own
    echoed DISCOVER — it should be silently dropped."""
    bus, events = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo"), bus)
    eng._inflight[0x4444] = {"mac": "de:ad:00:00:00:03", "sent_at": 0.0, "state": "DISCOVER_SENT"}
    pkt = packets.build_discover_v4("de:ad:00:00:00:03", 0x4444, "de:ad:00:00:00:03")
    eng._on_dhcp(pkt)
    assert events == []
