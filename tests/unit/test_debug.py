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


def test_engine_emits_debug_on_offer(monkeypatch):
    monkeypatch.setattr(engine_mod, "sendp", lambda *a, **k: None)
    bus = EventBus()
    events: list = []
    bus.subscribe(events.append)
    eng = engine_mod.DhcpEngine(SessionConfig(interface="lo", dry_run=True), bus)
    eng._handle_offer(_offer())
    dbg = [e for e in events if isinstance(e, ev.Debug)]
    assert dbg, "offer handling should emit Debug events"
    text = " ".join(e.message for e in dbg)
    assert "OFFER" in text and "server_id=172.20.15.1" in text and "REQUEST" in text


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
    assert "DHCP_ACK" in capsys.readouterr().out
