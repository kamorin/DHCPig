"""Extra no-root coverage: netutils, parsers, events, fingerprint extraction, engine handlers."""

from scapy.all import ARP, BOOTP, DHCP, IP, UDP, Ether, mac2str

from dhcpig.core import engine as engine_mod
from dhcpig.core import events as ev
from dhcpig.core import netutils, packets
from dhcpig.core.engine import LIMIT_REACHED, DhcpEngine
from dhcpig.core.events import EventBus, to_dict
from dhcpig.core.fingerprint import extract_signature, resolve
from dhcpig.core.models import IPVersion, Lease, Mode, SessionConfig


# ---------------------------------------------------------------- netutils
def test_netutils_math():
    assert netutils.cidr_from_mask("255.255.255.0") == 24
    assert netutils.cidr_from_mask("255.255.0.0") == 16
    assert netutils.int_to_ip(netutils.ip_to_int("10.1.2.3")) == "10.1.2.3"
    mac = netutils.random_mac()
    assert mac.startswith("de:ad:") and len(mac.split(":")) == 6
    assert isinstance(netutils.list_interfaces(), list)


def test_iface_network_cidr_is_str_or_none():
    # env-dependent; must not crash and returns a CIDR string or None
    for name in netutils.list_interfaces():
        cidr = netutils.iface_network_cidr(name)
        assert cidr is None or "/" in cidr


# ---------------------------------------------------------------- parsers
def _dhcp(msgtype, **bootp):
    opts = [
        ("message-type", msgtype),
        ("server_id", "172.20.15.1"),
        ("subnet_mask", "255.255.255.0"),
        "end",
    ]
    return (
        Ether(src="00:0c:29:da:53:f9")
        / IP(src="172.20.15.1", dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, yiaddr="172.20.0.83", siaddr="172.20.15.1", xid=0x99, **bootp)
        / DHCP(options=opts)
    )


def test_parse_offer_and_message_type():
    offer = _dhcp("offer", chaddr=mac2str("de:ad:00:00:00:07") + b"\x00" * 10)
    sid, smac, ip, subnet = packets.parse_offer(offer)
    assert sid == "172.20.15.1"
    assert ip == "172.20.0.83"
    assert subnet == "255.255.255.0"
    assert packets.message_type(offer) == packets.OFFER


def test_dhcp_option_missing_returns_none():
    offer = _dhcp("offer", chaddr=mac2str("de:ad:00:00:00:07") + b"\x00" * 10)
    assert packets.dhcp_option(offer[DHCP].options, "nope") is None


# ---------------------------------------------------------------- events
def test_to_dict_has_type_and_payload():
    lease = Lease("de:ad:00:00:00:01", "10.0.0.5", "10.0.0.1", 1, IPVersion.V4)
    d = to_dict(ev.AckReceived(lease=lease))
    assert d["type"] == "AckReceived"
    assert d["lease"]["ip"] == "10.0.0.5"


# ---------------------------------------------------------------- fingerprint extraction
def test_extract_signature_from_discover_resolves_macos_order():
    disc = packets.build_discover_v4("de:ad:be:ef:00:01", 1, "de:ad:be:ef:00:01")
    sig = extract_signature(disc, role="client")
    assert sig.prl == list(packets._MACOS_PRL)
    fp = resolve(sig)
    assert fp.confidence > 0  # matches the bundled macOS entry


# ---------------------------------------------------------------- engine handlers
def _engine(monkeypatch, **cfg):
    calls = []
    monkeypatch.setattr(engine_mod, "sendp", lambda pkt, **kw: calls.append(pkt))
    bus = EventBus()
    events = []
    bus.subscribe(events.append)
    eng = DhcpEngine(SessionConfig(interface="lo", dry_run=True, **cfg), bus)
    return eng, events, calls


def test_engine_offer_then_ack_flow(monkeypatch):
    eng, events, _ = _engine(monkeypatch)
    offer = _dhcp("offer", chaddr=mac2str("de:ad:00:00:00:07") + b"\x00" * 10)
    ack = _dhcp("ack", chaddr=mac2str("de:ad:00:00:00:07") + b"\x00" * 10)
    eng._on_dhcp(offer)
    eng._on_dhcp(ack)
    assert eng.offers == 1
    assert eng.acks == 1
    assert len(eng.servers) == 1
    assert eng.cleanup.pending()  # lease registered for restore
    assert any(isinstance(e, ev.ServerDiscovered) for e in events)
    assert any(isinstance(e, ev.RequestSent) for e in events)


def test_exhaust_sender_hits_max_leases(monkeypatch):
    eng, events, _ = _engine(monkeypatch, max_leases=0)
    eng._exhaust_sender()  # returns immediately: acks(0) >= max_leases(0)
    # hitting our own cap is LIMIT_REACHED, never a claim about the server's pool
    assert eng.state == LIMIT_REACHED
    assert any(isinstance(e, ev.LimitReached) for e in events)
    assert not any(isinstance(e, ev.PoolExhausted) for e in events)


def test_status_shape(monkeypatch):
    eng, _, _ = _engine(monkeypatch)
    st = eng.status()
    for key in ("state", "discovers", "leases", "garps", "releases", "servers"):
        assert key in st


def test_src_mac_spoof(monkeypatch):
    eng, _, _ = _engine(monkeypatch, spoof_ethernet_src=True)
    assert eng._src_mac("de:ad:00:00:00:09") == "de:ad:00:00:00:09"


def test_scan_fingerprints_dhcp(monkeypatch):
    eng, events, calls = _engine(monkeypatch, mode=Mode.SCAN)
    disc = packets.build_discover_v4("de:ad:be:ef:00:02", 2, "de:ad:be:ef:00:02")
    eng._on_scan(disc)
    assert any(isinstance(e, ev.HostFingerprinted) for e in events)
    assert calls == []  # scan sends nothing


def _arp_is_at(mac: str, ip: str):
    return Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=mac, psrc=ip, pdst="0.0.0.0")


def test_neighbor_carries_fingerprint_when_dhcp_seen_before_arp(monkeypatch):
    eng, events, _ = _engine(monkeypatch, mode=Mode.SCAN)
    mac = "de:ad:be:ef:00:03"
    eng._on_scan(packets.build_discover_v4(mac, 3, mac))  # DHCP fingerprint observed first
    eng._on_scan(_arp_is_at(mac, "172.20.0.50"))  # then the ARP sighting
    neighbor_events = [e for e in events if isinstance(e, ev.NeighborFound)]
    assert neighbor_events
    n = neighbor_events[-1].neighbor
    assert n.mac == mac
    assert n.fingerprint is not None and n.fingerprint.confidence > 0


def test_neighbor_fingerprint_backfilled_when_dhcp_seen_after_arp(monkeypatch):
    eng, events, _ = _engine(monkeypatch, mode=Mode.SCAN)
    mac = "de:ad:be:ef:00:04"
    eng._on_scan(_arp_is_at(mac, "172.20.0.51"))  # ARP first, no fingerprint yet
    first = [e.neighbor for e in events if isinstance(e, ev.NeighborFound)][-1]
    assert first.fingerprint is None
    eng._on_scan(packets.build_discover_v4(mac, 4, mac))  # DHCP arrives -> backfills the row
    neighbor_events = [e for e in events if isinstance(e, ev.NeighborFound)]
    assert len(neighbor_events) == 2  # initial ARP sighting + the fingerprint-triggered refresh
    updated = neighbor_events[-1].neighbor
    assert updated.mac == mac
    assert updated.fingerprint is not None and updated.fingerprint.confidence > 0
