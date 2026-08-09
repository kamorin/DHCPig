"""Extra no-root coverage: netutils, parsers, events, fingerprint extraction, engine handlers."""

from conftest import build_engine
from scapy.all import ARP, BOOTP, DHCP, IP, UDP, Ether, mac2str

from dhcpig.core import events as ev
from dhcpig.core import netutils, packets
from dhcpig.core.engine import EXHAUSTED
from dhcpig.core.events import to_dict
from dhcpig.core.fingerprint import extract_signature, resolve
from dhcpig.core.models import (
    DESTRUCTIVE_MODES,
    RUN_ONCE_MODES,
    IPVersion,
    Lease,
    Mode,
)


# ---------------------------------------------------------------- models
def test_run_once_modes_is_about_finishing_not_about_destructiveness():
    """Canonical set both control planes (CLI, web) key off to auto-finalize a run-once mode.

    The membership question is "does the worker finishing mean the run is over", NOT "is this
    mode destructive" -- deriving it from DESTRUCTIVE_MODES is what left active-scan hanging in
    RUNNING forever (2.5). Two of the three members are non-destructive.
    """
    assert RUN_ONCE_MODES == DESTRUCTIVE_MODES | {Mode.RELEASE_PREVIOUS, Mode.ACTIVE_SCAN}
    for mode in (Mode.RELEASE_PREVIOUS, Mode.ACTIVE_SCAN):
        assert mode in RUN_ONCE_MODES
        assert mode not in DESTRUCTIVE_MODES
    assert Mode.EXHAUST not in RUN_ONCE_MODES  # ends itself via _finish_in_background()
    assert Mode.SCAN not in RUN_ONCE_MODES  # passive listener, no natural end


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


def test_finding_raised_to_dict_carries_a_summary():
    """web/static/app.js renders this directly instead of re-deriving its own summary in JS --
    the two independently maintained renderers had already drifted (see
    core/findings.finding_summary_lines()'s docstring) before this existed."""
    from dhcpig.core.findings import finding_summary_lines
    from dhcpig.core.models import FAIL, Finding

    finding = Finding(
        id="MULTIPLE_DHCP_SERVERS",
        title="More than one DHCP server answered on this segment",
        verdict=FAIL,
        severity="high",
        evidence={"servers": ["10.0.0.1", "10.0.0.2"]},
        recommendation="Verify each server is authorized. More context follows.",
    )
    d = to_dict(ev.FindingRaised(finding=finding))
    assert d["finding"]["summary"] == finding_summary_lines(d["finding"])
    assert d["finding"]["summary"][-1] == "Verify each server is authorized."


def test_finding_summary_lines_formats_dict_list_items_as_key_value_not_python_repr():
    """A regression for FOREIGN_DISCOVERS_UNANSWERED's sample_hosts (list of dicts without
    did/got keys): this used to fall through to str(item), printing a Python dict repr like
    "{'mac': '...', 'hostname': ''}" on the CLI and in the HTML report."""
    from dhcpig.core.findings import finding_summary_lines

    lines = finding_summary_lines(
        {
            "evidence": {
                "sample_hosts": [
                    {"mac": "de:ad:00:00:00:01", "hostname": ""},
                    {"mac": "de:ad:00:00:00:02", "hostname": "printer"},
                ]
            },
            "recommendation": "",
        }
    )
    assert "de:ad:00:00:00:01" in "\n".join(lines)
    assert "{'mac'" not in "\n".join(lines)
    assert any("hostname=printer" in line for line in lines)


# ---------------------------------------------------------------- fingerprint extraction
def test_extract_signature_from_discover_resolves_macos_order():
    disc = packets.build_discover_v4("de:ad:be:ef:00:01", 1, "de:ad:be:ef:00:01")
    sig = extract_signature(disc, role="client")
    assert sig.prl == list(packets._MACOS_PRL)
    fp = resolve(sig)
    assert fp.confidence > 0  # matches the bundled macOS entry


# ---------------------------------------------------------------- engine handlers
def _engine(monkeypatch, **cfg):
    cfg.setdefault("dry_run", True)
    return build_engine(monkeypatch, **cfg)


def test_engine_offer_then_ack_flow(monkeypatch):
    import time as _t

    eng, events, _ = _engine(monkeypatch)
    # xid 0x99 (the fixed xid _dhcp() bakes in) must be ours -- _handle_offer()/_handle_ack() now
    # require ownership before acting (2.3 bug fix: they used to act on any OFFER/ACK observed).
    eng._inflight[0x99] = {"mac": "de:ad:00:00:00:07", "sent_at": _t.time(), "state": "x"}
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


def test_foreign_offer_does_not_pollute_exhaustion_measurement(monkeypatch):
    """A foreign OFFER (xid we never sent) must not move offers/_offers_seen_any/_last_offer_ts
    -- those drive the offer_silence halt signal, and a promiscuous BPF sees every client's DHCP
    churn (2.7.3 bug fix: this used to be incremented before the ownership check)."""
    eng, events, _ = _engine(monkeypatch)
    offer = _dhcp("offer", chaddr=mac2str("de:ad:00:00:00:09") + b"\x00" * 10)  # xid 0x99, not ours
    eng._on_dhcp(offer)
    assert eng.offers == 0
    assert eng._offers_seen_any is False
    assert eng._last_offer_ts == 0.0


def test_foreign_offer_still_registers_the_server_and_pool_estimate(monkeypatch):
    """The passive half of _handle_offer runs for anyone's OFFER: server identity and the
    pool-size estimate are facts about the network, not about our own run."""
    eng, events, _ = _engine(monkeypatch)
    offer = _dhcp("offer", chaddr=mac2str("de:ad:00:00:00:09") + b"\x00" * 10)  # not ours
    eng._on_dhcp(offer)
    assert len(eng.servers) == 1
    assert any(isinstance(e, ev.ServerDiscovered) for e in events)
    assert eng._first_offer_ip == "172.20.0.83"
    assert eng._first_offer_subnet == "255.255.255.0"


def test_leases_expired_counts_only_unreleased_leases_past_their_lease_time(monkeypatch):
    import time as _t

    eng, _, _ = _engine(monkeypatch)
    now = _t.time()
    eng.cleanup.register(
        Lease(
            "de:ad:00:00:00:01",
            "10.0.0.1",
            "10.0.0.254",
            1,
            IPVersion.V4,
            lease_time=600,
            acquired_at=now - 700,
        )  # expired 100s ago
    )
    eng.cleanup.register(
        Lease(
            "de:ad:00:00:00:02",
            "10.0.0.2",
            "10.0.0.254",
            2,
            IPVersion.V4,
            lease_time=600,
            acquired_at=now - 100,
        )  # still well within its lease
    )
    released = Lease(
        "de:ad:00:00:00:03",
        "10.0.0.3",
        "10.0.0.254",
        3,
        IPVersion.V4,
        lease_time=600,
        acquired_at=now - 700,
        released=True,
    )
    eng.cleanup.register(released)
    no_lease_time = Lease(
        "de:ad:00:00:00:04", "10.0.0.4", "10.0.0.254", 4, IPVersion.V4, acquired_at=now - 700
    )  # lease_time unknown -- never counted
    eng.cleanup.register(no_lease_time)
    assert eng._leases_expired(now=now) == 1


def test_push_discover_carries_cfg_request_options(monkeypatch):
    """cfg.request_options reaches the flood's DISCOVER (2.7.3) -- it used to be accepted by
    SessionConfig and never actually wired into any DISCOVER this tool sent."""
    eng, _, sent = _engine(monkeypatch, dry_run=False, request_options=[12, 15])
    eng._push_discover("de:ad:00:00:00:20")
    assert len(sent) == 1
    assert packets.dhcp_option(sent[0][DHCP].options, "param_req_list") == (12, 15)


def test_control_transaction_ignores_cfg_request_options(monkeypatch):
    """The control leg must stay a vanilla client regardless of cfg.request_options -- it's the
    baseline the verdict is measured against, not part of the flood's fingerprint profile."""
    eng, _, sent = _engine(monkeypatch, dry_run=False, request_options=[12, 15])
    monkeypatch.setattr("scapy.all.get_if_hwaddr", lambda _i: "00:11:22:33:44:55")
    eng.cfg.timeouts.control = 0.05  # nobody answers -- only the DISCOVER shape matters here
    eng.cfg.control_attempts = 1
    eng._control_transaction("pre")
    assert len(sent) == 1
    assert packets.dhcp_option(sent[0][DHCP].options, "param_req_list") == packets._MACOS_PRL


def test_exhaust_sender_stops_when_offers_cease(monkeypatch):
    """The only self-terminating condition is the *server* going quiet — there is no lease cap."""
    import time as _t

    eng, events, _ = _engine(monkeypatch)
    eng._started = _t.time()
    eng.cfg.timeouts.offer_silence = 0.2
    eng._offers_seen_any = True  # offers flowed...
    eng._last_offer_ts = _t.time() - 5.0  # ...and then stopped 5s ago
    eng._exhaust_sender()
    # EXHAUSTED, or already DONE if the background finisher beat us here — both are correct
    assert eng.state in (EXHAUSTED, "DONE")
    exhausted = [e for e in events if isinstance(e, ev.PoolExhausted)]
    assert len(exhausted) == 1
    assert exhausted[0].confirmed is False  # provisional until the post-control confirms
    assert eng._finishing.is_set()  # finalizes itself, no operator Stop required


def test_status_shape(monkeypatch):
    eng, _, _ = _engine(monkeypatch)
    st = eng.status()
    for key in ("state", "discovers", "leases", "arp_conflicts", "releases", "servers"):
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


def _discover_with_prl(mac: str, xid: int, prl: list[int]):
    """Like build_discover_v4, but with a caller-chosen option-55 order so a test can force a
    known satori_dhcp_fingerprints.json match (build_discover_v4's PRL is macOS-style and isn't
    in the bundled DB)."""
    opts = [
        ("message-type", "discover"),
        ("param_req_list", *prl),
        ("max_dhcp_size", 1500),
        ("client_id", b"\x01" + mac2str(mac)),
        ("lease_time", 10000),
        ("end", "00000000000000"),
    ]
    return (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=[mac2str(mac)], xid=xid, flags=0x8000)
        / DHCP(options=opts)
    )


def test_neighbor_fingerprint_backfilled_when_dhcp_seen_after_arp(monkeypatch):
    eng, events, _ = _engine(monkeypatch, mode=Mode.SCAN)
    mac = "de:ad:be:ef:00:04"
    eng._on_scan(_arp_is_at(mac, "172.20.0.51"))  # ARP first: OUI-only, no DHCP evidence yet
    first = [e.neighbor for e in events if isinstance(e, ev.NeighborFound)][-1]
    assert first.fingerprint is not None
    assert first.fingerprint.os is None  # OUI alone never claims an OS
    assert first.fingerprint.confidence <= 15
    # 'Windows 10' -- a single, unambiguous satori_dhcp_fingerprints.json entry
    prl = [1, 121, 3, 6, 15, 119, 252, 95, 44, 46]
    eng._on_scan(_discover_with_prl(mac, 4, prl))  # DHCP arrives -> backfills the row
    neighbor_events = [e for e in events if isinstance(e, ev.NeighborFound)]
    assert len(neighbor_events) == 2  # initial ARP sighting + the fingerprint-triggered refresh
    updated = neighbor_events[-1].neighbor
    assert updated.mac == mac
    assert updated.fingerprint is not None
    assert updated.fingerprint.confidence > first.fingerprint.confidence


def test_active_scan_is_a_run_once_mode():
    """Its worker is an ARP sweep plus one DHCPINFORM and then it's done. Leaving it out of
    RUN_ONCE_MODES meant neither the CLI polling loop nor the web reaper ever called stop(), so
    the run sat in RUNNING ticking status forever (found live, 2.5). `scan` stays excluded --
    a passive listener has no natural end."""
    from dhcpig.core.models import RUN_ONCE_MODES, Mode

    assert Mode.ACTIVE_SCAN in RUN_ONCE_MODES
    assert Mode.RELEASE_NEIGHBORS in RUN_ONCE_MODES
    assert Mode.RELEASE_PREVIOUS in RUN_ONCE_MODES
    assert Mode.SCAN not in RUN_ONCE_MODES
    assert Mode.EXHAUST not in RUN_ONCE_MODES  # ends on its own via _finish_in_background()
