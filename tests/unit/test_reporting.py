import json
import time

from dhcpig import __version__
from dhcpig.core import events as ev
from dhcpig.core.findings import build
from dhcpig.core.models import HostFingerprint, IPVersion, Lease, Neighbor, SessionConfig
from dhcpig.core.reporting import SessionRecorder


def test_report_roundtrip(tmp_path):
    cfg = SessionConfig(interface="eth1", report_path=tmp_path / "r.json")
    rec = SessionRecorder(cfg)
    rec.handle(
        ev.AckReceived(lease=Lease("de:ad:00:00:00:01", "10.0.0.5", "10.0.0.1", 1, IPVersion.V4))
    )
    out = rec.export(tmp_path / "r.json")
    data = json.loads(out.read_text())
    assert data["tool"] == "dhcpig"
    assert len(data["leases"]) == 1
    assert "fingerprint_db" in data


def test_report_version_matches_package_version():
    """The report's version field must track the installed package -- it sat hardcoded at
    "2.0.0" through every 2.1-2.5 release, mislabelling every report ever written."""
    cfg = SessionConfig(interface="eth1")
    data = SessionRecorder(cfg).to_dict()
    assert data["version"] == __version__


def test_pool_estimate_carried_from_session_ended_into_report():
    cfg = SessionConfig(interface="eth1")
    rec = SessionRecorder(cfg)
    rec.handle(
        ev.SessionEnded(
            report={
                "pool_size": 254,
                "pool_source": "scope",
                "pool_is_estimate": False,
                "pool_detail": "usable hosts in 10.0.0.0/24",
                "headroom": 200,
                "in_use_observed": 3,
            }
        )
    )
    data = rec.to_dict()
    est = data["pool_estimate"]
    assert est["size"] == 254
    assert est["source"] == "scope"
    assert est["headroom"] == 200
    text, _ = rec.render("html")
    assert "Pool headroom" in text and "254" in text


def test_pool_estimate_defaults_to_nulls_without_a_session_ended_event():
    cfg = SessionConfig(interface="eth1")
    rec = SessionRecorder(cfg)
    data = rec.to_dict()
    assert data["pool_estimate"]["size"] is None
    text, _ = rec.render("html")
    assert "Pool headroom" not in text  # nothing fabricated when the estimate is unknown


def test_neighbor_update_dedupes_by_mac_not_appended():
    cfg = SessionConfig(interface="eth1")
    rec = SessionRecorder(cfg)
    mac = "de:ad:00:00:00:09"
    rec.handle(ev.NeighborFound(neighbor=Neighbor(mac=mac, ip="10.0.0.9")))
    fp = HostFingerprint(mac=mac, ip="", role="client", device="Windows 10", confidence=90)
    rec.handle(ev.NeighborFound(neighbor=Neighbor(mac=mac, ip="10.0.0.9", fingerprint=fp)))
    data = rec.to_dict()
    assert len(data["neighbors"]) == 1
    assert data["neighbors"][0]["fingerprint"]["device"] == "Windows 10"


def _recorder_with_data():
    cfg = SessionConfig(interface="eth1")
    rec = SessionRecorder(cfg)
    rec.handle(
        ev.AckReceived(lease=Lease("de:ad:00:00:00:01", "10.0.0.5", "10.0.0.1", 1, IPVersion.V4))
    )
    return rec


def test_render_csv():
    """One header tagged by `section`; the findings half used to be missing entirely. Parsed
    with a strict reader because the earlier two-stacked-headers form didn't fail one -- it
    shifted each inventory row left, putting a MAC under `id` and an IP under `verdict`."""
    import csv
    import io

    rec = _recorder_with_data()  # one lease
    rec.handle(ev.FindingRaised(finding=build("CLIENTS_EVICTED_FROM_ADDRESSES", {"evicted": 2})))
    text, ctype = rec.render("csv")
    assert ctype == "text/csv"
    finding, inventory = list(csv.DictReader(io.StringIO(text)))
    assert (finding["section"], inventory["section"]) == ("finding", "inventory")
    assert finding["id"] == "CLIENTS_EVICTED_FROM_ADDRESSES" and finding["verdict"] == "FAIL"
    assert finding["attck"] == "T1557.002" and finding["time"].endswith("+00:00")
    assert not finding["mac"]  # cells never bleed between the two row kinds
    assert inventory["kind"] == "lease" and inventory["mac"] == "de:ad:00:00:00:01"
    assert not inventory["verdict"]


def test_render_html():
    rec = _recorder_with_data()
    rec.handle(ev.FindingRaised(finding=build("CLIENTS_EVICTED_FROM_ADDRESSES", {"evicted": 2})))
    text, ctype = rec.render("html")
    assert ctype == "text/html"
    assert "<table>" in text and "10.0.0.5" in text and "DHCPig report" in text
    assert "T1557.002 Adversary-in-the-Middle: ARP Cache Poisoning" in text
    assert "Run window (UTC)" in text


def test_render_bad_format():
    import pytest

    with pytest.raises(ValueError):
        _recorder_with_data().render("pdf")


def test_report_timestamps_belong_to_the_run_not_the_render():
    """One behaviour, three parts: epochs gain UTC strings; a finding stays stamped with its
    raise time through rendering; `ended_at` comes from SessionEnded, so rendering on download
    can't restate the run's end. Falls back to "now" only for a run that never ended."""
    rec = SessionRecorder(SessionConfig(interface="eth1"))

    assert rec.ended is None  # mid-run / killed run: "now" is the honest answer
    assert rec.to_dict()["ended_at"] >= rec.started

    f = build("DHCP_NAK_OBSERVED", {})
    f.ts = 1_000_000_000.0  # 2001-09-09, unmistakably not the render time
    rec.handle(ev.FindingRaised(finding=f))
    rec.handle(ev.SessionEnded(report={}))

    first = rec.to_dict()
    assert first["started_at_iso"].endswith("+00:00")  # UTC, not an ambiguous local time
    assert isinstance(first["started_at"], float) and isinstance(first["ended_at"], float)
    assert first["findings"][0]["ts"] == 1_000_000_000.0
    assert "2001-09-09" in rec.render("csv")[0] and "2001-09-09" in rec.render("html")[0]

    time.sleep(0.05)
    later = rec.to_dict()
    assert (first["ended_at"], first["ended_at_iso"]) == (later["ended_at"], later["ended_at_iso"])
