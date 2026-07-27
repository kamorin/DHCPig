"""Debug event emission, serialization, and renderer verbosity gating."""

from scapy.all import BOOTP, DHCP, IP, UDP, Ether, mac2str

from dhcpig.cli.render import Renderer
from dhcpig.core import engine as engine_mod
from dhcpig.core import events as ev
from dhcpig.core.events import EventBus, to_dict
from dhcpig.core.models import IPVersion, Lease, SessionConfig


def _offer():
    opts = [
        ("message-type", "offer"),
        ("server_id", "172.20.15.1"),
        ("subnet_mask", "255.255.255.0"),
        "end",
    ]
    return (
        Ether(src="00:0c:29:da:53:f9")
        / IP(src="172.20.15.1", dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(
            op=2,
            yiaddr="172.20.0.83",
            siaddr="0.0.0.0",
            chaddr=mac2str("de:ad:00:00:00:07") + b"\x00" * 10,
            xid=0x99,
        )
        / DHCP(options=opts)
    )


def _mark_ours(eng, xid: int, mac: str = "de:ad:00:00:00:07") -> None:
    """Register xid in _inflight, simulating that we actually sent the DISCOVER/REQUEST this
    OFFER/ACK/NAK is replying to -- the ownership check _handle_offer()/_handle_ack()/
    _handle_nak() now require (2.3 bug fix: they used to act on every packet regardless)."""
    import time as _time

    eng._inflight[xid] = {"mac": mac, "sent_at": _time.time(), "state": "DISCOVER_SENT"}


def test_engine_emits_debug_on_offer(monkeypatch):
    monkeypatch.setattr(engine_mod, "sendp", lambda *a, **k: None)
    bus = EventBus()
    events: list = []
    bus.subscribe(events.append)
    eng = engine_mod.DhcpEngine(SessionConfig(interface="lo", dry_run=True), bus)
    _mark_ours(eng, 0x99)
    eng._handle_offer(_offer())
    dbg = [e for e in events if isinstance(e, ev.Debug)]
    assert dbg, "offer handling should emit Debug events"
    text = " ".join(e.message for e in dbg)
    assert "OFFER" in text and "server_id=172.20.15.1" in text and "REQUEST" in text


def test_engine_ignores_offer_it_never_solicited(monkeypatch):
    """BUG FIX regression (2.3): an OFFER whose xid we never sent must not produce a REQUEST --
    that used to mean impersonating whoever the offer was actually meant for."""
    monkeypatch.setattr(engine_mod, "sendp", lambda *a, **k: None)
    bus = EventBus()
    events: list = []
    bus.subscribe(events.append)
    eng = engine_mod.DhcpEngine(SessionConfig(interface="lo", dry_run=True), bus)
    assert 0x99 not in eng._inflight
    eng._handle_offer(_offer())
    assert not any(isinstance(e, ev.RequestSent) for e in events)
    assert not any(isinstance(e, ev.OfferReceived) for e in events)
    dbg = " ".join(e.message for e in events if isinstance(e, ev.Debug))
    assert "foreign OFFER" in dbg and "not requesting" in dbg


def test_handle_offer_emits_request_sent_with_option50_and_hostname(monkeypatch):
    """(2.3) RequestSent.option50/hostname come off the actual REQUEST packet we sent -- not
    just assumed from the OFFER -- so the info-level log reflects what was really on the wire."""
    monkeypatch.setattr(engine_mod, "sendp", lambda *a, **k: None)
    bus = EventBus()
    events: list = []
    bus.subscribe(events.append)
    eng = engine_mod.DhcpEngine(SessionConfig(interface="lo", dry_run=True), bus)
    _mark_ours(eng, 0x99)
    eng._handle_offer(_offer())
    req_sent = [e for e in events if isinstance(e, ev.RequestSent)]
    assert len(req_sent) == 1
    assert req_sent[0].option50 == "172.20.0.83"
    assert req_sent[0].hostname is not None and len(req_sent[0].hostname) == 8


def test_debug_serializes_over_sse():
    d = to_dict(ev.Debug(message="hello"))
    assert d["type"] == "Debug"
    assert d["message"] == "hello"


def test_renderer_hides_debug_below_v3(capsys):
    Renderer(verbosity=2, color=False).handle(ev.Debug(message="secret detail"))
    assert capsys.readouterr().out == ""


def test_renderer_shows_debug_at_v3(capsys):
    Renderer(verbosity=3, color=False).handle(ev.Debug(message="secret detail"))
    out = capsys.readouterr().out
    assert "[DBG]" in out and "secret detail" in out


def test_renderer_normal_traffic_still_prints(capsys):
    lease = Lease("de:ad:00:00:00:01", "10.0.0.5", "10.0.0.1", 1, IPVersion.V4)
    Renderer(verbosity=2, color=False).handle(ev.AckReceived(lease=lease))
    out = capsys.readouterr().out
    assert "DHCP_ACK" in out
    assert "chaddr=de:ad:00:00:00:01" in out  # (2.3) chaddr shown at info level, not just -v3


def test_renderer_shows_option50_hostname_chaddr_at_info_level(capsys):
    """(2.3) option 50 (requested_addr), chaddr, and hostname are visible at the normal info
    level for our own outbound DISCOVER/REQUEST -- previously only in -v3 debug lines."""
    r = Renderer(verbosity=2, color=False)
    r.handle(ev.DiscoverSent(mac="de:ad:00:00:00:02", option50="10.0.0.9", hostname="ABC123XY"))
    out = capsys.readouterr().out
    assert "chaddr=de:ad:00:00:00:02" in out
    assert "option50=10.0.0.9" in out
    assert "hostname='ABC123XY'" in out

    lease = Lease("de:ad:00:00:00:03", "10.0.0.10", "10.0.0.1", 2, IPVersion.V4)
    r.handle(ev.RequestSent(lease=lease, option50="10.0.0.10", hostname="XYZ789AB"))
    out = capsys.readouterr().out
    assert "chaddr=de:ad:00:00:00:03" in out
    assert "option50=10.0.0.10" in out
    assert "hostname='XYZ789AB'" in out


def test_renderer_discover_without_option50_omits_it(capsys):
    """A plain exhaust DISCOVER doesn't request a specific address -- no option50 clause."""
    Renderer(verbosity=2, color=False).handle(
        ev.DiscoverSent(mac="de:ad:00:00:00:04", hostname="PLAINHOST")
    )
    out = capsys.readouterr().out
    assert "option50=" not in out
    assert "hostname='PLAINHOST'" in out
