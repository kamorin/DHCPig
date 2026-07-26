import json

from dhcpig.core import events as ev
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
    text, ctype = _recorder_with_data().render("csv")
    assert ctype == "text/csv"
    lines = text.strip().splitlines()
    assert lines[0] == "kind,mac,ip,server_id,os,device,vendor,confidence"
    assert any(row.startswith("lease,de:ad:00:00:00:01,10.0.0.5") for row in lines[1:])


def test_render_html():
    text, ctype = _recorder_with_data().render("html")
    assert ctype == "text/html"
    assert "<table>" in text and "10.0.0.5" in text and "DHCPig report" in text


def test_render_bad_format():
    import pytest

    with pytest.raises(ValueError):
        _recorder_with_data().render("pdf")
