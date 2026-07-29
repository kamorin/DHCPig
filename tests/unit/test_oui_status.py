"""MAC-vendor (OUI) identification and the periodic status heartbeat."""

import time

from dhcpig.cli.render import Renderer, status_summary
from dhcpig.core import engine as engine_mod
from dhcpig.core import events as ev
from dhcpig.core import oui
from dhcpig.core.engine import DhcpEngine
from dhcpig.core.events import EventBus
from dhcpig.core.fingerprint import from_mac
from dhcpig.core.models import SessionConfig


# ---------------------------------------------------------------- OUI lookup
def test_ieee_oui_resolved_from_scapy_db():
    assert "VMware" in (oui.lookup("00:0c:29:da:53:f9") or "")
    assert "Apple" in (oui.lookup("f0:18:98:11:22:33") or "")


def test_lookup_is_separator_and_case_insensitive():
    want = oui.lookup("00:0c:29:da:53:f9")
    for form in ("00-0C-29-DA-53-F9", "000c29da53f9", "00:0C:29:da:53:f9"):
        assert oui.lookup(form) == want


def test_ieee_registered_prefix_resolved_without_supplement():
    # 00:00:0c is Cisco in the IEEE db -- resolved straight from scapy, no local supplement
    assert "Cisco" in (oui.lookup("00:00:0c:11:22:33") or "")


def test_qemu_prefix_unknown_to_scapy_falls_back_to_locally_administered():
    # QEMU's 52:54:00 prefix isn't in the IEEE registry; its locally-administered bit is set,
    # so we still label it rather than leaving it blank
    assert oui.lookup("52:54:00:12:34:56") == oui.LOCALLY_ADMINISTERED


def test_locally_administered_mac_is_labelled_not_blank():
    # DHCPig's own spoofed clients use a locally administered prefix
    assert oui.lookup("de:ad:00:00:00:01") == oui.LOCALLY_ADMINISTERED


def test_lookup_handles_junk():
    assert oui.lookup("") is None
    assert oui.lookup("xx") is None


def test_from_mac_fills_os_device_column_without_claiming_an_os():
    fp = from_mac("00:0c:29:da:53:f9", ip="10.0.0.5", role="neighbor")
    assert fp.os is None
    assert "VMware" in fp.device and "MAC vendor" in fp.device
    assert fp.vendor and fp.confidence == 15
    assert fp.role == "neighbor"


# ---------------------------------------------------------------- status heartbeat
def _engine(monkeypatch, **cfg):
    monkeypatch.setattr(engine_mod, "sendp", lambda *a, **k: None)
    bus = EventBus()
    events = []
    bus.subscribe(events.append)
    # offline (2.3), not dry_run: these tests call .start()/.stop() and dry_run alone no longer
    # skips the sniffer/control transaction -- offline is the hard no-socket switch they need.
    return DhcpEngine(SessionConfig(interface="lo", offline=True, **cfg), bus), events


def test_status_ticks_are_emitted_periodically(monkeypatch):
    eng, events = _engine(monkeypatch, status_interval=0.15)
    eng._started = time.time()
    t = __import__("threading").Thread(target=eng._status_ticker, daemon=True)
    t.start()
    time.sleep(0.5)
    eng._stop.set()
    t.join(timeout=2)
    ticks = [e for e in events if isinstance(e, ev.StatusTick)]
    assert len(ticks) >= 2, f"expected repeated ticks, got {len(ticks)}"


def test_status_tick_reports_deltas_not_just_totals(monkeypatch):
    eng, events = _engine(monkeypatch, status_interval=0.1)
    eng._started = time.time()
    th = __import__("threading")
    t = th.Thread(target=eng._status_ticker, daemon=True)
    t.start()
    time.sleep(0.15)
    eng.discovers += 10  # traffic happens between ticks
    eng.acks += 4
    time.sleep(0.25)
    eng._stop.set()
    t.join(timeout=2)
    ticks = [e.stats for e in events if isinstance(e, ev.StatusTick)]
    assert any(s["d_discovers"] == 10 and s["d_leases"] == 4 for s in ticks), ticks


def test_status_interval_zero_disables_the_ticker(monkeypatch):
    eng, _ = _engine(monkeypatch, status_interval=0)
    eng.start()
    eng.stop()
    assert eng._ticker is None


def test_ticker_is_not_registered_as_a_worker_thread(monkeypatch):
    """_threads means 'work in progress'; a forever-ticker there would stall destructive runs."""
    eng, _ = _engine(monkeypatch, status_interval=5.0)
    eng.start()
    try:
        assert eng._ticker is not None
        assert eng._ticker not in eng._threads
    finally:
        eng.stop()


# ---------------------------------------------------------------- status line formatting
def test_status_summary_shows_totals_deltas_and_rates():
    line = status_summary(
        {
            "state": "RUNNING",
            "elapsed": 15.0,
            "window": 5.0,
            "leases": 142,
            "d_leases": 38,
            "lease_pps": 7.6,
            "discovers": 520,
            "d_discovers": 150,
            "discover_pps": 30.0,
            "offers": 145,
            "d_offers": 40,
            "naks": 0,
            "d_naks": 0,
            "servers": 1,
            "since_last_offer": 0.2,
        }
    )
    assert "t=15s" in line and "RUNNING" in line
    assert "leases 142 (+38 in 5s, 7.6/s)" in line
    assert "discovers 520 (+150 in 5s, 30.0/s)" in line
    assert "servers 1" in line
    assert "naks" not in line  # zero-valued counters are omitted


def test_status_summary_omits_idle_counters():
    line = status_summary(
        {"state": "RUNNING", "elapsed": 5.0, "window": 5.0, "garps": 0, "d_garps": 0}
    )
    assert "garps" not in line


def test_renderer_prints_status_only_at_debug_verbosity(capsys):
    """The 5-second pulse moved to the debug tier: useful for diagnosing a stalled run, but at
    normal verbosity it repeats forever and drowns out the packet lines around it."""
    stats = {"state": "RUNNING", "elapsed": 5.0, "window": 5.0, "leases": 3, "d_leases": 3}
    Renderer(verbosity=3, color=False).handle(ev.StatusTick(stats=stats))
    assert "leases 3" in capsys.readouterr().out


def test_renderer_hides_status_at_normal_and_quiet_verbosity(capsys):
    stats = {"state": "RUNNING", "elapsed": 5.0, "window": 5.0, "leases": 3, "d_leases": 3}
    for v in (0, 1, 2):
        Renderer(verbosity=v, color=False).handle(ev.StatusTick(stats=stats))
        assert capsys.readouterr().out == ""
