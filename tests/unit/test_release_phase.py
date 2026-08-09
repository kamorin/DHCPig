"""Pre-run ARP sweep, the release phase, and targeted re-acquisition (docs/DESIGN.md §5c/§5f).

Split from test_control_findings.py (SIMPLIFICATION.md 4.2) -- see test_control_transaction.py
for the split's full file map.
"""

import threading
import time

from conftest import build_engine
from scapy.all import BOOTP, DHCP, IP, UDP, Ether, mac2str

from dhcpig.core import events as ev
from dhcpig.core.models import ControlOutcome, Mode, Neighbor

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


# ---------------------------------------------------------------- pre-run ARP sweep
def test_prelude_sweeps_then_controls_then_release_then_senders(monkeypatch):
    """Baseline inventory, controls, and the release phase must all precede the first DISCOVER."""
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    order = []
    monkeypatch.setattr(eng, "_baseline_arp_scan", lambda: order.append("arp"))
    monkeypatch.setattr(
        eng,
        "_control_transaction",
        lambda phase, client="self": (
            order.append(f"ctl-{phase}-{client}") or ControlOutcome(phase=phase, client=client)
        ),
    )
    monkeypatch.setattr(eng, "_release_phase", lambda: order.append("release"))
    monkeypatch.setattr(eng, "_start_senders", lambda: order.append("senders"))
    eng._exhaust_prelude()
    assert order == ["arp", "ctl-pre-self", "ctl-pre-new", "release", "senders"]


def test_arp_sweep_is_unconditional(monkeypatch):
    """The sweep has no opt-out any more: every later phase (release targets, re-acquisition,
    eviction, the NeighborSummary roll-call) reads the inventory it builds, so skipping it
    hollowed out the rest of the run rather than just saving a few seconds."""
    from dhcpig.core.models import SessionConfig

    assert not hasattr(SessionConfig(interface="lo"), "arp_sweep")
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    order = []
    monkeypatch.setattr(eng, "_baseline_arp_scan", lambda: order.append("arp"))
    monkeypatch.setattr(
        eng,
        "_control_transaction",
        lambda phase, client="self": ControlOutcome(phase=phase, client=client),
    )
    monkeypatch.setattr(eng, "_release_phase", lambda: None)
    monkeypatch.setattr(eng, "_start_senders", lambda: order.append("senders"))
    eng._exhaust_prelude()
    assert order == ["arp", "senders"]


def test_sweep_range_falls_back_to_iface_network_for_exhaust(monkeypatch):
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    monkeypatch.setattr("dhcpig.core.netutils.iface_network_cidr", lambda _i: "192.168.4.0/22")
    assert eng._sweep_cidrs() == ["192.168.4.0/22"]


def test_sweep_range_prefers_explicit_scope(monkeypatch):
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST, scope_cidrs=["10.1.0.0/24"])
    assert eng._sweep_cidrs() == ["10.1.0.0/24"]


def test_destructive_discovery_is_not_widened_by_the_sweep_fallback(monkeypatch):
    """_discover_neighbors must stay pinned to cfg.scope_cidrs unless told otherwise."""
    eng, _, _ = _engine(monkeypatch, mode=Mode.RELEASE_NEIGHBORS, scope_cidrs=["10.9.9.0/30"])
    seen = {}

    def fake_srp(pkt, **kw):
        seen["targets"] = pkt.pdst if hasattr(pkt, "pdst") else pkt[1].pdst
        return [], []

    monkeypatch.setattr("scapy.all.srp", fake_srp)
    eng._discover_neighbors()  # no cidrs argument -> scope only
    assert all(t.startswith("10.9.9.") for t in seen["targets"])


# ---------------------------------------------------------------- ARP sweep truncation (2.7.3)
def test_sweep_targets_caps_per_cidr_and_reports_what_it_skipped():
    """Pure, root-free: a /16 is capped at `cap` targets, and `skipped` says how many usable
    addresses were left unprobed -- computed from num_addresses, not by materializing them."""
    from dhcpig.core.engine import _sweep_targets

    targets, skipped = _sweep_targets(["10.0.0.0/16"], cap=1024)
    assert len(targets) == 1024
    assert skipped == 65534 - 1024


def test_sweep_targets_reports_no_skip_when_the_cidr_fits_under_the_cap():
    from dhcpig.core.engine import _sweep_targets

    targets, skipped = _sweep_targets(["10.0.0.0/24"], cap=1024)
    assert len(targets) == 254
    assert skipped == 0


def test_sweep_targets_sums_skipped_across_multiple_cidrs():
    from dhcpig.core.engine import _sweep_targets

    targets, skipped = _sweep_targets(["10.0.0.0/24", "10.0.1.0/24"], cap=100)
    assert len(targets) == 200  # 100 from each
    assert skipped == (254 - 100) * 2


def test_baseline_arp_scan_surfaces_truncation_in_the_run_summary(monkeypatch):
    """A wide scope must not silently present a partial host list as the whole segment."""
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST, scope_cidrs=["10.0.0.0/16"], dry_run=True)
    monkeypatch.setattr("scapy.all.srp", lambda pkt, **kw: ([], []))
    eng._baseline_arp_scan()
    assert eng._sweep_skipped == 65534 - 1024
    steps = eng._run_summary_steps()
    arp_step = next(s for s in steps if s["did"] == "ARP inventory")
    assert "not probed" in arp_step["got"]


# ---------------------------------------------------------------- release phase (exhaust)
def test_release_phase_skipped_without_a_known_server(monkeypatch):
    """BUG FIX (2.1): must never fall back to server_id=0.0.0.0 — skip instead."""
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng._neighbors_by_mac["de:ad:00:00:00:01"] = Neighbor("de:ad:00:00:00:01", "10.0.0.5")
    called = []
    monkeypatch.setattr(eng, "_do_release", lambda *a, **k: called.append(a) or 0)
    assert eng.control_pre is None
    eng._release_phase()
    assert called == []
    assert any(isinstance(e, ev.Debug) and "skipped" in e.message for e in events)


def test_release_phase_has_no_config_opt_out(monkeypatch):
    """Freeing addresses and then taking them is the behaviour under test; with it off, exhaust
    competed only for whatever was already free and re-acquisition/eviction had nothing to feed
    on. A missing server identity still self-skips -- that's a precondition, not an option."""
    from dhcpig.core.models import SessionConfig

    assert not hasattr(SessionConfig(interface="lo"), "release_neighbors")
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng.control_pre = ControlOutcome(
        phase="pre", client="self", attempted=True, success=True, server_id="10.0.0.1"
    )
    eng._neighbors_by_mac["aa:bb:cc:dd:ee:01"] = Neighbor(mac="aa:bb:cc:dd:ee:01", ip="10.0.0.7")
    called = []
    monkeypatch.setattr(eng, "_do_release", lambda *a, **k: called.append(a) or 1)
    eng._release_phase()
    assert called  # it ran


def test_release_phase_uses_server_from_pre_control(monkeypatch):
    """The server identity comes from control_pre, never a guess — this is the actual bug fix."""
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng.control_pre = ControlOutcome(
        phase="pre",
        client="self",
        attempted=True,
        success=True,
        server_id="10.0.0.1",
        server_mac="aa:bb:cc:dd:ee:ff",
    )
    eng._neighbors_by_mac["de:ad:00:00:00:01"] = Neighbor("de:ad:00:00:00:01", "10.0.0.5")
    captured = {}

    def fake_do_release(neighbors, server_ip, server_mac=None):
        captured["neighbors"] = neighbors
        captured["server_ip"] = server_ip
        captured["server_mac"] = server_mac
        return len(neighbors)

    monkeypatch.setattr(eng, "_do_release", fake_do_release)
    monkeypatch.setattr(eng, "_reprobe_released", lambda ips: 0)
    monkeypatch.setattr(eng, "_release_gateway", lambda: None)
    monkeypatch.setattr(
        eng,
        "_reacquire_phase",
        lambda freed, **kw: {"granted": 1, "offered_different": 0, "naked": 0, "no_response": 0},
    )
    freed = eng._release_phase()
    eng._finish_release(freed)
    assert captured["server_ip"] == "10.0.0.1"
    assert captured["server_ip"] != "0.0.0.0"
    assert captured["server_mac"] == "aa:bb:cc:dd:ee:ff"
    assert freed == [("de:ad:00:00:00:01", "10.0.0.5")]
    ids = [e.finding.id for e in events if isinstance(e, ev.FindingRaised)]
    assert "NEIGHBOR_LEASES_RELEASED" in ids
    finding = next(
        e.finding
        for e in events
        if isinstance(e, ev.FindingRaised) and e.finding.id == "NEIGHBOR_LEASES_RELEASED"
    )
    assert finding.evidence["granted"] == 1


def test_release_phase_excludes_gateway_and_server(monkeypatch):
    """Releasing the gateway's own lease is disruption out of proportion to the address gained."""
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng.control_pre = ControlOutcome(
        phase="pre", client="self", attempted=True, success=True, server_id="10.0.0.1"
    )
    eng._neighbors_by_mac = {
        "de:ad:00:00:00:01": Neighbor("de:ad:00:00:00:01", "10.0.0.1"),  # the DHCP server itself
        "de:ad:00:00:00:02": Neighbor("de:ad:00:00:00:02", "10.0.0.254"),  # gateway
        "de:ad:00:00:00:03": Neighbor("de:ad:00:00:00:03", "10.0.0.5"),  # ordinary host
    }
    captured = {}

    def fake_do_release(neighbors, sid, server_mac=None):
        captured["neighbors"] = neighbors
        return 0

    monkeypatch.setattr(eng, "_do_release", fake_do_release)
    monkeypatch.setattr(eng, "_reprobe_released", lambda neighbors: 0)
    monkeypatch.setattr(eng, "_release_gateway", lambda: "10.0.0.254")
    eng._release_phase()
    ips = {n.ip for n in captured["neighbors"]}
    assert ips == {"10.0.0.5"}


def test_release_phase_dry_run_reprobe_sends_nothing(monkeypatch):
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST, dry_run=True)
    assert eng._reprobe_released(["10.0.0.5"]) == 0


# ---------------------------------------------------------------- targeted re-acquisition (2.3)
def test_finish_release_is_a_noop_when_nothing_was_freed(monkeypatch):
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    called = []
    monkeypatch.setattr(eng, "_reacquire_phase", lambda freed, **kw: called.append(freed) or {})
    eng._finish_release([])
    assert called == []  # never even attempted -- nothing to re-acquire
    assert not any(isinstance(e, ev.FindingRaised) for e in events)


def _nothing_granted(monkeypatch, mode):
    eng, events, _ = _engine(monkeypatch, mode=mode)
    ctl = ControlOutcome(phase="pre", client="self", attempted=True, success=True, server_id=SERVER)
    if mode is Mode.EXHAUST:
        eng.control_pre = ctl
    else:
        eng._rel_pre_control = ctl
    monkeypatch.setattr(eng, "_reprobe_released", lambda ips: 0)
    monkeypatch.setattr(
        eng,
        "_reacquire_phase",
        lambda freed, **kw: {"granted": 0, "offered_different": 2, "naked": 0, "no_response": 0},
    )
    eng._finish_release([("de:ad:00:00:00:01", "10.0.0.5"), ("de:ad:00:00:00:02", "10.0.0.6")])
    return next(
        e.finding
        for e in events
        if isinstance(e, ev.FindingRaised) and e.finding.id == "NEIGHBOR_LEASES_RELEASED"
    )


def test_nothing_granted_in_exhaust_is_real_evidence(monkeypatch):
    """In exhaust the pool is drained before re-acquisition runs, so the server had no unused
    address to prefer instead -- a zero here genuinely means it declined."""
    finding = _nothing_granted(monkeypatch, Mode.EXHAUST)
    assert finding.evidence["granted"] == 0
    assert "desired behavior" in finding.recommendation
    assert "drained" in finding.recommendation


def test_nothing_granted_outside_exhaust_must_not_claim_the_server_defended(monkeypatch):
    """The old text said "the server ignored the unauthenticated RELEASE" for any zero. With
    addresses still free, RFC 2131 §4.3.1 has the server prefer an unused one over honouring
    option 50 from an unknown MAC -- same observable result, completely different conclusion.
    Claiming the network defended itself off that is a false PASS in everything but name."""
    finding = _nothing_granted(monkeypatch, Mode.RELEASE_NEIGHBORS)
    rec = finding.recommendation
    assert finding.evidence["granted"] == 0
    assert "does NOT show the server protected" in rec
    assert "ignored the unauthenticated RELEASE" not in rec
    assert "desired behavior" not in rec


def test_finish_release_recommendation_when_some_granted(monkeypatch):
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    eng.control_pre = ControlOutcome(
        phase="pre", client="self", attempted=True, success=True, server_id=SERVER
    )
    monkeypatch.setattr(eng, "_reprobe_released", lambda ips: 0)
    monkeypatch.setattr(
        eng,
        "_reacquire_phase",
        lambda freed, **kw: {"granted": 1, "offered_different": 0, "naked": 0, "no_response": 0},
    )
    eng._finish_release([("de:ad:00:00:00:01", "10.0.0.5")])
    finding = next(
        e.finding
        for e in events
        if isinstance(e, ev.FindingRaised) and e.finding.id == "NEIGHBOR_LEASES_RELEASED"
    )
    assert finding.evidence["granted"] == 1
    assert "re-acquire" in finding.recommendation


def test_reacquire_phase_classifies_all_four_outcomes(monkeypatch):
    """End-to-end through the real windowed pipeline: granted (offer matches option 50),
    offered_different (server ignored option 50), naked (REQUEST refused), and no_response
    (never answered) must each land in the right bucket."""
    eng, events, sent = _engine(monkeypatch)
    eng.cfg.timeouts.control = 0.5
    eng.cfg.timeouts.dhcp_request = 0.3
    behaviors = ["granted", "offered_different", "naked", "no_response"]
    freed = [(f"de:ad:00:00:00:0{i}", f"172.20.0.{50 + i}") for i in range(len(behaviors))]
    handled: set[int] = set()

    def responder():
        deadline = time.time() + 2.0
        while len(handled) < 3 and time.time() < deadline:  # no_response is never handled
            with eng._inflight_lock:
                xids = list(eng._reacquire_targets.items())
            for idx, (xid, req_ip) in enumerate(xids):
                if xid in handled or behaviors[idx] == "no_response":
                    continue
                handled.add(xid)
                offer_ip = req_ip if behaviors[idx] in ("granted", "naked") else "10.0.0.222"
                mac = f"00:11:22:33:44:0{idx}"
                eng._on_dhcp(_reply("offer", xid, mac, yiaddr=offer_ip))
                time.sleep(0.05)  # let _handle_offer's REQUEST land before the final reply
                kind = "nak" if behaviors[idx] == "naked" else "ack"
                eng._on_dhcp(_reply(kind, xid, mac, yiaddr=offer_ip))
            time.sleep(0.02)

    t = threading.Thread(target=responder, daemon=True)
    t.start()
    counts = eng._reacquire_phase(freed)
    t.join(timeout=3)
    assert counts == {"granted": 1, "offered_different": 1, "naked": 1, "no_response": 1}
