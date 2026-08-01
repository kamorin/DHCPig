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


def test_do_arp_conflict_only_in_scope(sent):
    """(2.3) _do_arp_conflict (renamed from _do_garp) is the frame-building core that Phase 4's
    eviction reuses; scope enforcement must survive that rewrite unchanged."""
    bus, events = _bus_collect()
    cfg = SessionConfig(interface="lo", mode=Mode.RELEASE_NEIGHBORS, scope_cidrs=["172.20.0.0/16"])
    eng = DhcpEngine(cfg, bus)
    targets = [
        Neighbor("de:ad:00:00:00:01", "172.20.0.7"),
        Neighbor("de:ad:00:00:00:02", "10.9.9.9"),  # out of scope
        Neighbor("de:ad:00:00:00:03", "172.20.0.8"),
    ]
    n = eng._do_arp_conflict(targets)
    # two in-scope targets x (ARP conflict request + reply); no third/gateway frame (2.3)
    assert n == 4
    assert len(sent) == 4
    assert any(isinstance(e, ev.Skipped) for e in events)


def test_arp_conflict_sends_both_arp_forms(sent):
    from dhcpig.core import packets as pk

    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo", mode=Mode.RELEASE_NEIGHBORS), bus)
    eng._do_arp_conflict([Neighbor("de:ad:00:00:00:01", "10.0.0.7")])
    ops = [p[pk.ARP].op for p in sent]
    assert ops == [pk.ARP_REQUEST, pk.ARP_REPLY]
    for p in sent:  # announcement form: psrc == pdst == the claimed address
        assert p[pk.ARP].psrc == p[pk.ARP].pdst == "10.0.0.7"


def test_arp_conflict_claimed_mac_is_always_bogus_never_the_targets_real_mac(sent, monkeypatch):
    """The forged MAC must never be the victim's real MAC, or our own -- a bogus MAC blackholes
    the claim; a real MAC would redirect the victim's traffic, which is interception (out of
    scope). Pin random_mac() so the assertion isn't merely "different with high probability"."""
    from dhcpig.core import packets as pk

    # _do_arp_conflict() imports random_mac locally from .netutils -- patch it there
    monkeypatch.setattr("dhcpig.core.netutils.random_mac", lambda: "aa:bb:cc:dd:ee:ff")
    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo", mode=Mode.RELEASE_NEIGHBORS), bus)
    eng._our_macs.add("11:22:33:44:55:66")  # this run's own interface/control MAC
    target = Neighbor("de:ad:00:00:00:01", "10.0.0.7")
    eng._do_arp_conflict([target])
    assert sent  # sanity: something was actually sent
    for p in sent:
        assert p[pk.ARP].hwsrc == "aa:bb:cc:dd:ee:ff"
        assert p[pk.ARP].hwsrc != target.mac
        assert p[pk.ARP].hwsrc not in eng._our_macs
    assert "aa:bb:cc:dd:ee:ff" in eng._evict.bogus_macs


def test_do_arp_conflict_no_longer_takes_a_gateway_blackhole():
    """(2.3) build_arp_poison() and the third unicast gateway-blackhole frame were removed --
    _do_arp_conflict's signature no longer accepts a `gateway` argument at all."""
    import inspect

    sig = inspect.signature(DhcpEngine._do_arp_conflict)
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


def test_ipv6_is_refused_at_start_not_silently_broken():
    """No packet builder in core/packets.py is v6-aware -- an exhaust run would flood v4
    DISCOVERs while the sniffer listens for v6 replies (sniffer.py's BPF filter), see zero
    offers, and report a clean PASS that's actually "this never sent anything answerable".
    Refuse up front instead of producing a misleading result."""
    from dhcpig.core.exceptions import ConfigError

    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo", ip_version=IPVersion.V6), bus)
    with pytest.raises(ConfigError):
        eng.start()


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


# ---------------------------------------------------------------- foreign DISCOVER (2.3)
def _offer(xid: int, mac: str, yiaddr: str = "172.20.0.83", server="172.20.15.1"):
    from scapy.all import BOOTP, DHCP, IP, UDP, Ether, mac2str

    return (
        Ether(src="00:0c:29:da:53:f9")
        / IP(src=server, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, yiaddr=yiaddr, siaddr=server, chaddr=mac2str(mac) + b"\x00" * 10, xid=xid)
        / DHCP(options=[("message-type", "offer"), ("server_id", server), "end"])
    )


def _foreign_discover_pkt(mac: str, xid: int, hostname: str | None = None):
    """A DISCOVER as it looks *after* the sniffer parses it off the wire: chaddr is a plain
    padded 16-byte string, not the pre-serialization list form build_discover_v4() uses --
    client_mac_from_offer() only round-trips correctly on the former."""
    from scapy.all import BOOTP, DHCP, IP, UDP, Ether, mac2str

    opts = [("message-type", "discover")]
    if hostname:
        opts.append(("hostname", hostname))
    opts.append("end")
    return (
        Ether(src=mac)
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=mac2str(mac) + b"\x00" * 10, xid=xid, flags=0x8000)
        / DHCP(options=opts)
    )


def test_foreign_discover_first_sighting_emits_event_and_is_tracked():
    bus, events = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo"), bus)
    pkt = _foreign_discover_pkt("de:ad:00:00:00:05", 0x5555)
    eng._on_dhcp(pkt)
    seen = [e for e in events if isinstance(e, ev.ForeignDiscover)]
    assert len(seen) == 1
    assert seen[0].mac == "de:ad:00:00:00:05"
    assert seen[0].xid == 0x5555
    assert 0x5555 in eng._foreign_discovers
    assert eng._foreign_discovers[0x5555]["answered"] is False


def test_foreign_discover_repeat_sighting_from_same_mac_does_not_reemit():
    """A retrying client sends a fresh DISCOVER (usually a fresh xid) every few seconds --
    only the first sighting per MAC gets its own event, to avoid flooding the log."""
    bus, events = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo"), bus)
    mac = "de:ad:00:00:00:06"
    eng._on_dhcp(_foreign_discover_pkt(mac, 0x6001))
    eng._on_dhcp(_foreign_discover_pkt(mac, 0x6002))  # retry, new xid
    seen = [e for e in events if isinstance(e, ev.ForeignDiscover)]
    assert len(seen) == 1  # only the first
    # but both xids are still tracked for counting/answered purposes
    assert 0x6001 in eng._foreign_discovers
    assert 0x6002 in eng._foreign_discovers


def test_offer_marks_a_tracked_foreign_discover_as_answered(sent):
    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo"), bus)
    mac = "de:ad:00:00:00:07"
    eng._on_dhcp(_foreign_discover_pkt(mac, 0x7777))
    assert eng._foreign_discovers[0x7777]["answered"] is False
    eng._on_dhcp(_offer(0x7777, mac))
    assert eng._foreign_discovers[0x7777]["answered"] is True


def test_foreign_discover_counters_in_status_and_counters(sent):
    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo"), bus)
    eng._on_dhcp(_foreign_discover_pkt("de:ad:00:00:00:08", 0x8001))
    eng._on_dhcp(_foreign_discover_pkt("de:ad:00:00:00:09", 0x8002))
    eng._on_dhcp(_offer(0x8001, "de:ad:00:00:00:08"))  # only one answered
    assert eng._counters()["foreign_discovers"] == 2
    assert eng._counters()["foreign_discovers_unanswered"] == 1
    st = eng.status()
    assert st["foreign_discovers"] == 2
    assert st["foreign_discovers_unanswered"] == 1


def test_finalize_findings_raises_unanswered_when_any_foreign_discover_unanswered():
    bus, events = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo", mode=Mode.EXHAUST), bus)
    eng._started = __import__("time").time()
    eng._on_dhcp(_foreign_discover_pkt("de:ad:00:00:00:0a", 0x9001))
    eng._finalize_findings()
    ids = [e.finding.id for e in events if isinstance(e, ev.FindingRaised)]
    assert "FOREIGN_DISCOVERS_UNANSWERED" in ids
    f = next(
        e.finding
        for e in events
        if isinstance(e, ev.FindingRaised) and e.finding.id == "FOREIGN_DISCOVERS_UNANSWERED"
    )
    assert f.verdict == "FAIL"


def test_finalize_findings_raises_answered_info_when_all_foreign_discovers_answered(sent):
    bus, events = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo", mode=Mode.EXHAUST), bus)
    eng._started = __import__("time").time()
    mac = "de:ad:00:00:00:0b"
    eng._on_dhcp(_foreign_discover_pkt(mac, 0xA001))
    eng._on_dhcp(_offer(0xA001, mac))
    eng._finalize_findings()
    ids = [e.finding.id for e in events if isinstance(e, ev.FindingRaised)]
    assert "FOREIGN_DISCOVERS_ANSWERED" in ids
    assert "FOREIGN_DISCOVERS_UNANSWERED" not in ids


def test_finalize_findings_silent_when_no_foreign_discovers_observed():
    bus, events = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo", mode=Mode.EXHAUST), bus)
    eng._started = __import__("time").time()
    eng._finalize_findings()
    ids = [e.finding.id for e in events if isinstance(e, ev.FindingRaised)]
    assert "FOREIGN_DISCOVERS_UNANSWERED" not in ids
    assert "FOREIGN_DISCOVERS_ANSWERED" not in ids


# ------------------------------------------------------------ ARP-conflict eviction (2.3, Phase 4)
def _arp_pkt(mac: str, ip: str, op=None):
    from scapy.all import ARP, Ether

    from dhcpig.core import packets as pk

    return Ether(src=mac) / ARP(op=op or pk.ARP_REPLY, hwsrc=mac, psrc=ip, pdst=ip)


def _decline_pkt(mac: str, xid: int):
    from scapy.all import BOOTP, DHCP, IP, UDP, Ether, mac2str

    return (
        Ether(src=mac)
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=mac2str(mac) + b"\x00" * 10, xid=xid)
        / DHCP(options=[("message-type", "decline"), "end"])
    )


def test_evict_interval_too_slow_raises_config_error():
    from dhcpig.core.exceptions import ConfigError
    from dhcpig.core.models import Timeouts

    with pytest.raises(ConfigError):
        SessionConfig(interface="lo", timeouts=Timeouts(evict_interval=10.0))


def test_evict_rounds_below_two_raises_config_error():
    from dhcpig.core.exceptions import ConfigError

    with pytest.raises(ConfigError):
        SessionConfig(interface="lo", evict_rounds=1)


def test_do_arp_conflict_not_gated_on_stop_event(sent):
    """(2.3) eviction runs from within stop(), after self._stop.set() -- _do_arp_conflict must
    still send, unlike the old _do_garp which would silently no-op here."""
    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo", mode=Mode.RELEASE_NEIGHBORS), bus)
    eng._stop.set()
    n = eng._do_arp_conflict([Neighbor("de:ad:00:00:00:01", "10.0.0.7")])
    assert n == 2
    assert len(sent) == 2


def test_handle_evict_arp_marks_defended_from_real_owner_mac():
    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo"), bus)
    eng._evict.targets = {"10.0.0.7"}
    eng._evict.mac_by_ip = {"10.0.0.7": "de:ad:00:00:00:01"}
    eng._evict.ip_by_mac = {"de:ad:00:00:00:01": "10.0.0.7"}
    eng._handle_evict_arp(_arp_pkt("de:ad:00:00:00:01", "10.0.0.7"))
    assert "10.0.0.7" in eng._evict.defenders


def test_handle_evict_arp_ignores_our_own_bogus_mac():
    """A forged conflict frame, echoed back by the widened BPF, must not be mistaken for the
    victim defending -- it carries a bogus MAC we generated ourselves, not the real owner's."""
    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo"), bus)
    eng._evict.targets = {"10.0.0.7"}
    eng._evict.mac_by_ip = {"10.0.0.7": "de:ad:00:00:00:01"}
    eng._evict.ip_by_mac = {"de:ad:00:00:00:01": "10.0.0.7"}
    bogus = "aa:bb:cc:00:00:01"
    eng._evict.bogus_macs.add(bogus)
    eng._handle_evict_arp(_arp_pkt(bogus, "10.0.0.7"))
    assert eng._evict.defenders == set()


def test_handle_evict_arp_marks_apipa_when_target_mac_sources_from_link_local():
    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo"), bus)
    eng._evict.targets = {"10.0.0.7"}
    eng._evict.mac_by_ip = {"10.0.0.7": "de:ad:00:00:00:01"}
    eng._evict.ip_by_mac = {"de:ad:00:00:00:01": "10.0.0.7"}
    eng._handle_evict_arp(_arp_pkt("de:ad:00:00:00:01", "169.254.12.34"))
    assert "10.0.0.7" in eng._evict.apipa_ips


def test_handle_client_decline_records_target_ip():
    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo"), bus)
    eng._evict.ip_by_mac = {"de:ad:00:00:00:01": "10.0.0.7"}
    eng._handle_client_decline(_decline_pkt("de:ad:00:00:00:01", 0xB001))
    assert "10.0.0.7" in eng._evict.declined_ips


def test_handle_client_decline_from_unknown_mac_is_a_noop():
    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo"), bus)
    eng._evict.ip_by_mac = {}
    eng._handle_client_decline(_decline_pkt("de:ad:00:00:00:99", 0xB002))
    assert eng._evict.declined_ips == set()


def test_on_dhcp_routes_decline_and_arp_to_eviction_handlers():
    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo"), bus)
    eng._evict.targets = {"10.0.0.7"}
    eng._evict.mac_by_ip = {"10.0.0.7": "de:ad:00:00:00:01"}
    eng._evict.ip_by_mac = {"de:ad:00:00:00:01": "10.0.0.7"}
    eng._on_dhcp(_decline_pkt("de:ad:00:00:00:01", 0xB003))
    assert "10.0.0.7" in eng._evict.declined_ips
    eng._on_dhcp(_arp_pkt("de:ad:00:00:00:01", "10.0.0.7"))
    assert "10.0.0.7" in eng._evict.defenders


def test_measure_eviction_picks_highest_rung_across_multiple_signals():
    """A target that both defended an earlier round and later declined must land on the higher
    rung (declined), not whichever signal happened to be checked last."""
    bus, events = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo"), bus)
    n = Neighbor("de:ad:00:00:00:01", "10.0.0.7")
    eng._evict.targets = {"10.0.0.7"}
    eng._evict.outcomes = {"10.0.0.7": "no_reaction"}
    eng._evict.defenders.add("10.0.0.7")
    eng._evict.declined_ips.add("10.0.0.7")
    eng._measure_eviction([n])
    assert eng._evict.outcomes["10.0.0.7"] == "declined"
    evicted = [e for e in events if isinstance(e, ev.ClientEvicted)]
    assert len(evicted) == 1
    assert evicted[0].outcome == "declined"


def test_measure_eviction_rediscovered_and_unanswered_when_no_offer_followed():
    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo"), bus)
    n = Neighbor("de:ad:00:00:00:01", "10.0.0.7")
    eng._evict.targets = {"10.0.0.7"}
    eng._evict.outcomes = {"10.0.0.7": "no_reaction"}
    eng._evict.start_ts = 100.0
    eng._foreign_discovers[0xC001] = {
        "mac": "de:ad:00:00:00:01",
        "hostname": None,
        "ts": 200.0,
        "answered": False,
    }
    eng._measure_eviction([n])
    assert eng._evict.outcomes["10.0.0.7"] == "discover_unanswered"


def test_measure_eviction_rediscovered_only_when_offer_followed():
    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo"), bus)
    n = Neighbor("de:ad:00:00:00:01", "10.0.0.7")
    eng._evict.targets = {"10.0.0.7"}
    eng._evict.outcomes = {"10.0.0.7": "no_reaction"}
    eng._evict.start_ts = 100.0
    eng._foreign_discovers[0xC002] = {
        "mac": "de:ad:00:00:00:01",
        "hostname": None,
        "ts": 200.0,
        "answered": True,
    }
    eng._measure_eviction([n])
    assert eng._evict.outcomes["10.0.0.7"] == "rediscovered"


def test_measure_eviction_ignores_discover_seen_before_eviction_started():
    """A DISCOVER sighted before _evict_start_ts is unrelated prior traffic, not evidence of
    restart-at-INIT caused by this eviction round."""
    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo"), bus)
    n = Neighbor("de:ad:00:00:00:01", "10.0.0.7")
    eng._evict.targets = {"10.0.0.7"}
    eng._evict.outcomes = {"10.0.0.7": "no_reaction"}
    eng._evict.start_ts = 100.0
    eng._foreign_discovers[0xC003] = {
        "mac": "de:ad:00:00:00:01",
        "hostname": None,
        "ts": 50.0,
        "answered": False,
    }
    eng._measure_eviction([n])
    assert eng._evict.outcomes["10.0.0.7"] == "no_reaction"


def test_evict_phase_skips_when_disabled():
    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo", mode=Mode.EXHAUST, evict=False), bus)
    eng._reacquire_targets = {1: "10.0.0.7"}
    eng._reacquire_outcomes = {1: "granted"}
    eng._evict_phase()
    assert eng._evict.targets == set()


def test_evict_phase_skips_when_no_granted_reacquisitions():
    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo", mode=Mode.EXHAUST), bus)
    eng._reacquire_targets = {1: "10.0.0.7"}
    eng._reacquire_outcomes = {1: "naked"}  # not granted
    eng._evict_phase()
    assert eng._evict.targets == set()


def test_evict_phase_only_targets_granted_reacquisitions_excluding_server(sent, monkeypatch):
    """Target selection is restricted to Phase 3's `granted` outcomes and excludes the DHCP
    server, even when both are present in the ARP-discovered neighbor table."""
    from dhcpig.core import engine as engine_mod
    from dhcpig.core.models import ControlOutcome

    monkeypatch.setattr(engine_mod.DhcpEngine, "_release_gateway", lambda self: None)
    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo", mode=Mode.EXHAUST), bus)
    eng.cfg.evict_rounds = 2
    eng.cfg.timeouts.evict_interval = 0.01
    eng.cfg.evict_settle = 0.0
    eng.control_pre = ControlOutcome(phase="pre", server_id="172.20.15.1")
    eng._neighbors_by_mac["de:ad:00:00:00:01"] = Neighbor("de:ad:00:00:00:01", "172.20.0.7")
    eng._neighbors_by_mac["de:ad:00:00:00:02"] = Neighbor("de:ad:00:00:00:02", "172.20.0.8")
    eng._neighbors_by_mac["srv:mac:00:00:00"] = Neighbor("srv:mac:00:00:00", "172.20.15.1")
    eng._reacquire_targets = {1: "172.20.0.7", 2: "172.20.0.8", 3: "172.20.15.1"}
    eng._reacquire_outcomes = {1: "granted", 2: "naked", 3: "granted"}
    eng._evict_phase()
    assert eng._evict.targets == {"172.20.0.7"}


def test_finalize_findings_evicted_when_declined_or_higher():
    bus, events = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo", mode=Mode.EXHAUST), bus)
    eng._evict.outcomes = {"10.0.0.7": "declined", "10.0.0.8": "no_reaction"}
    eng._finalize_findings()
    ids = [e.finding.id for e in events if isinstance(e, ev.FindingRaised)]
    assert "CLIENTS_EVICTED_FROM_ADDRESSES" in ids
    f = next(
        e.finding
        for e in events
        if isinstance(e, ev.FindingRaised) and e.finding.id == "CLIENTS_EVICTED_FROM_ADDRESSES"
    )
    assert f.verdict == "FAIL"


def test_finalize_findings_defended_only_when_no_one_declined():
    bus, events = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo", mode=Mode.EXHAUST), bus)
    eng._evict.outcomes = {"10.0.0.7": "defended"}
    eng._finalize_findings()
    ids = [e.finding.id for e in events if isinstance(e, ev.FindingRaised)]
    assert "CLIENTS_DEFENDED_ADDRESSES" in ids
    assert "CLIENTS_EVICTED_FROM_ADDRESSES" not in ids


def test_finalize_findings_unanswered_when_nothing_reacted():
    bus, events = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo", mode=Mode.EXHAUST), bus)
    eng._evict.outcomes = {"10.0.0.7": "no_reaction"}
    eng._finalize_findings()
    ids = [e.finding.id for e in events if isinstance(e, ev.FindingRaised)]
    assert "ARP_CONFLICTS_UNANSWERED" in ids
    assert "CLIENTS_DEFENDED_ADDRESSES" not in ids
    assert "CLIENTS_EVICTED_FROM_ADDRESSES" not in ids


def test_finalize_findings_no_eviction_finding_under_dry_run():
    """Under dry-run every outcome reads no_reaction because nothing was ever sent -- that's
    not evidence of anything, so no eviction finding should be raised (DRY_RUN_SUMMARY covers
    the dry-run case instead)."""
    bus, events = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo", mode=Mode.EXHAUST, dry_run=True), bus)
    eng._evict.outcomes = {"10.0.0.7": "no_reaction"}
    eng._finalize_findings()
    ids = [e.finding.id for e in events if isinstance(e, ev.FindingRaised)]
    assert "ARP_CONFLICTS_UNANSWERED" not in ids
    assert "CLIENTS_DEFENDED_ADDRESSES" not in ids
    assert "CLIENTS_EVICTED_FROM_ADDRESSES" not in ids


def test_finalize_findings_silent_when_no_evict_targets():
    bus, events = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo", mode=Mode.EXHAUST), bus)
    eng._finalize_findings()
    ids = [e.finding.id for e in events if isinstance(e, ev.FindingRaised)]
    assert "ARP_CONFLICTS_UNANSWERED" not in ids
    assert "CLIENTS_DEFENDED_ADDRESSES" not in ids
    assert "CLIENTS_EVICTED_FROM_ADDRESSES" not in ids


def test_status_reports_evict_outcomes_when_present():
    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo", mode=Mode.EXHAUST), bus)
    eng._evict.outcomes = {"10.0.0.7": "declined"}
    st = eng.status()
    assert st["evict_targets"] == 1
    assert st["evict_outcomes"] == {"10.0.0.7": "declined"}


def test_status_omits_evict_fields_when_no_eviction_ran():
    bus, _ = _bus_collect()
    eng = DhcpEngine(SessionConfig(interface="lo", mode=Mode.EXHAUST), bus)
    st = eng.status()
    assert "evict_targets" not in st
    assert "evict_outcomes" not in st
