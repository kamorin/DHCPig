"""Race-freed (2.3): queue-building and exclusion logic for _maybe_race() and its triggers
(foreign NAK via foreign-REQUEST correlation, foreign DECLINE, opt-in foreign rediscover).

See AGENT_HANDOFF.md §5g. This file covers the trigger plumbing (no sender
integration yet); sender-integration/classifier tests live in test_race_freed_sender.py.
"""

from scapy.all import BOOTP, DHCP, IP, UDP, Ether, mac2str

from dhcpig.core import engine as engine_mod
from dhcpig.core.engine import DhcpEngine
from dhcpig.core.events import EventBus
from dhcpig.core.models import ControlOutcome, Mode, Neighbor, SessionConfig

SERVER = "172.20.15.1"


def _engine(monkeypatch, **cfg):
    monkeypatch.setattr(engine_mod, "sendp", lambda *a, **k: None)
    bus = EventBus()
    events = []
    bus.subscribe(events.append)
    cfg.setdefault("mode", Mode.EXHAUST)
    cfg.setdefault("dry_run", True)
    eng = DhcpEngine(SessionConfig(interface="lo", **cfg), bus)
    return eng, events


def _client_pkt(kind: str, xid: int, mac: str, requested_addr: str | None = None, ciaddr=None):
    """A client->server packet (op=1) from a foreign MAC -- REQUEST/DECLINE/DISCOVER."""
    opts = [("message-type", kind)]
    if requested_addr:
        opts.append(("requested_addr", requested_addr))
    opts.append("end")
    bootp_kwargs = {"op": 1, "chaddr": mac2str(mac) + b"\x00" * 10, "xid": xid}
    if ciaddr:
        bootp_kwargs["ciaddr"] = ciaddr
    return (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=ciaddr or "0.0.0.0", dst=SERVER)
        / UDP(sport=68, dport=67)
        / BOOTP(**bootp_kwargs)
        / DHCP(options=opts)
    )


def _server_nak(xid: int):
    return (
        Ether(src="00:0c:29:da:53:f9")
        / IP(src=SERVER, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, siaddr=SERVER, xid=xid)
        / DHCP(options=[("message-type", "nak"), ("server_id", SERVER), "end"])
    )


def _give_server_identity(eng):
    """_maybe_race() excludes the gateway/server via _prelude_pre_control(), which reads
    control_pre for exhaust (self._rel_pre_control only applies to release mode) -- give it one."""
    eng.control_pre = ControlOutcome(
        phase="pre", client="self", attempted=True, success=True, server_id="172.20.15.1"
    )


# ---------------------------------------------------------------- foreign NAK trigger
def test_foreign_nak_queues_via_foreign_request_correlation(monkeypatch):
    eng, _ = _engine(monkeypatch)
    _give_server_identity(eng)
    xid = 0x5001
    eng._on_dhcp(_client_pkt("request", xid, "de:ad:00:00:00:50", requested_addr="10.0.0.50"))
    assert eng._foreign_requests.get(xid) == "10.0.0.50"
    eng._on_dhcp(_server_nak(xid))
    assert "10.0.0.50" in eng._race_queue
    assert xid not in eng._foreign_requests  # popped once consumed


def test_foreign_nak_without_a_tracked_request_does_not_queue(monkeypatch):
    eng, _ = _engine(monkeypatch)
    _give_server_identity(eng)
    eng._on_dhcp(_server_nak(0x5002))  # no prior REQUEST observed for this xid
    assert list(eng._race_queue) == []


def test_foreign_request_renewal_form_resolves_via_ciaddr(monkeypatch):
    """A renewing REQUEST (ciaddr set, no option 50) must still resolve."""
    eng, _ = _engine(monkeypatch)
    _give_server_identity(eng)
    xid = 0x5003
    eng._on_dhcp(_client_pkt("request", xid, "de:ad:00:00:00:51", ciaddr="10.0.0.51"))
    assert eng._foreign_requests.get(xid) == "10.0.0.51"


# ---------------------------------------------------------------- foreign DECLINE trigger
def test_foreign_decline_queues_a_race(monkeypatch):
    eng, _ = _engine(monkeypatch)
    _give_server_identity(eng)
    eng._on_dhcp(
        _client_pkt("decline", 0x6001, "de:ad:00:00:00:60", requested_addr="10.0.0.60")
    )
    assert "10.0.0.60" in eng._race_queue


def test_decline_from_eviction_target_is_not_a_race_trigger(monkeypatch):
    """A decline from a MAC we're actively evicting is the gold-standard eviction signal
    (_evict_declined_ips) -- it must not also enqueue a race; we already hold that address."""
    eng, _ = _engine(monkeypatch)
    _give_server_identity(eng)
    eng._evict_ip_by_mac["de:ad:00:00:00:61"] = "10.0.0.61"
    eng._on_dhcp(
        _client_pkt("decline", 0x6002, "de:ad:00:00:00:61", requested_addr="10.0.0.61")
    )
    assert "10.0.0.61" in eng._evict_declined_ips
    assert list(eng._race_queue) == []


# ---------------------------------------------------------------- _maybe_race exclusions
def test_maybe_race_dedups(monkeypatch):
    eng, _ = _engine(monkeypatch)
    _give_server_identity(eng)
    eng._maybe_race("10.0.0.70", "test")
    eng._maybe_race("10.0.0.70", "test")
    assert list(eng._race_queue).count("10.0.0.70") == 1


def test_maybe_race_excludes_addresses_already_targeted_by_reacquisition(monkeypatch):
    """The release phase's own victims DISCOVER/DECLINE right after being evicted -- without
    this exclusion every one of those would queue a duplicate race for an address we already
    hold from our own re-acquisition (§5f)."""
    eng, _ = _engine(monkeypatch)
    _give_server_identity(eng)
    eng._reacquire_targets[0x1] = "10.0.0.80"
    eng._maybe_race("10.0.0.80", "test")
    assert list(eng._race_queue) == []


def test_maybe_race_excludes_gateway_and_server(monkeypatch):
    eng, _ = _engine(monkeypatch)
    _give_server_identity(eng)
    monkeypatch.setattr(eng, "_release_gateway", lambda: "172.20.15.254")
    eng._maybe_race("172.20.15.1", "test")  # server
    eng._maybe_race("172.20.15.254", "test")  # gateway
    assert list(eng._race_queue) == []


def test_maybe_race_ignores_none(monkeypatch):
    eng, _ = _engine(monkeypatch)
    _give_server_identity(eng)
    eng._maybe_race(None, "test")
    assert list(eng._race_queue) == []


def test_maybe_race_gated_to_exhaust_mode(monkeypatch):
    eng, _ = _engine(monkeypatch, mode=Mode.RELEASE_NEIGHBORS)
    _give_server_identity(eng)
    eng._maybe_race("10.0.0.90", "test")
    assert list(eng._race_queue) == []


def test_maybe_race_respects_race_freed_addresses_flag(monkeypatch):
    eng, _ = _engine(monkeypatch, race_freed_addresses=False)
    _give_server_identity(eng)
    eng._maybe_race("10.0.0.91", "test")
    assert list(eng._race_queue) == []


# ---------------------------------------------------------------- foreign rediscover (opt-in)
def test_rediscover_trigger_off_by_default(monkeypatch):
    eng, _ = _engine(monkeypatch)
    _give_server_identity(eng)
    eng._neighbors_by_mac["de:ad:00:00:00:99"] = Neighbor(mac="de:ad:00:00:00:99", ip="10.0.0.99")
    eng._on_dhcp(_client_pkt("discover", 0x7001, "de:ad:00:00:00:99"))
    assert list(eng._race_queue) == []


def test_rediscover_trigger_queues_when_enabled(monkeypatch):
    eng, _ = _engine(monkeypatch, race_on_rediscover=True)
    _give_server_identity(eng)
    eng._neighbors_by_mac["de:ad:00:00:00:99"] = Neighbor(mac="de:ad:00:00:00:99", ip="10.0.0.99")
    eng._on_dhcp(_client_pkt("discover", 0x7002, "de:ad:00:00:00:99"))
    assert "10.0.0.99" in eng._race_queue


def test_rediscover_trigger_ignores_unknown_mac_even_when_enabled(monkeypatch):
    eng, _ = _engine(monkeypatch, race_on_rediscover=True)
    _give_server_identity(eng)
    eng._on_dhcp(_client_pkt("discover", 0x7003, "de:ad:00:00:00:aa"))  # never ARP-inventoried
    assert list(eng._race_queue) == []
