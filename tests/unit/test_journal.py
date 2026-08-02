"""Lease journal: pure read/write round-trips (no root), plus engine wiring.

The whole point of this module is surviving a killed process, so the crash-simulation tests
(a truncated final line, malformed JSON, an unknown record kind) are the ones that matter most.
"""

import json
import time

from conftest import build_engine
from scapy.all import BOOTP, DHCP, IP, UDP, Ether, mac2str

from dhcpig.core import events as ev
from dhcpig.core import journal
from dhcpig.core.models import IPVersion, Lease, Mode

SERVER = "172.20.15.1"


def _lease(mac="de:ad:00:00:00:01", ip="172.20.0.83", lease_time=3600):
    return Lease(
        mac=mac,
        ip=ip,
        server_ip=SERVER,
        xid=0x1234,
        ip_version=IPVersion.V4,
        lease_time=lease_time,
        server_mac="00:0c:29:aa:bb:cc",
    )


# ---------------------------------------------------------------- pure read/write round-trips
def test_round_trip_ack_then_released_closes_it(tmp_path):
    path = tmp_path / "leases-eth1.jsonl"
    journal.record_ack(path, "eth1", _lease())
    entries, warnings = journal.load_open_leases(path)
    assert warnings == []
    assert len(entries) == 1
    e = entries[0]
    assert (e.mac, e.ip, e.server_ip, e.server_mac, e.lease_time) == (
        "de:ad:00:00:00:01",
        "172.20.0.83",
        SERVER,
        "00:0c:29:aa:bb:cc",
        3600,
    )

    journal.record_released(path, "eth1", "de:ad:00:00:00:01", "172.20.0.83")
    entries, warnings = journal.load_open_leases(path)
    assert entries == []
    assert warnings == []


def test_missing_journal_file_returns_empty_no_warnings(tmp_path):
    entries, warnings = journal.load_open_leases(tmp_path / "does-not-exist.jsonl")
    assert entries == []
    assert warnings == []


def test_multiple_acks_are_independent_by_mac_ip_pair(tmp_path):
    path = tmp_path / "leases-eth1.jsonl"
    journal.record_ack(path, "eth1", _lease(mac="de:ad:00:00:00:01", ip="172.20.0.83"))
    journal.record_ack(path, "eth1", _lease(mac="de:ad:00:00:00:02", ip="172.20.0.84"))
    journal.record_released(path, "eth1", "de:ad:00:00:00:01", "172.20.0.83")
    entries, _ = journal.load_open_leases(path)
    assert len(entries) == 1
    assert entries[0].mac == "de:ad:00:00:00:02"


# ---------------------------------------------------------------- crash tolerance (the point)
def test_truncated_final_line_is_skipped_with_a_warning_not_raised(tmp_path):
    """This is the exact scenario the journal exists for: the process died mid-write."""
    path = tmp_path / "leases-eth1.jsonl"
    journal.record_ack(path, "eth1", _lease(mac="de:ad:00:00:00:01"))
    with open(path, "a") as fh:
        fh.write('{"ev": "ack", "ts": 123, "iface": "eth1", "mac": "de:ad:00:00:00:02"')  # cut off

    entries, warnings = journal.load_open_leases(path)
    assert len(entries) == 1  # the good record survives
    assert entries[0].mac == "de:ad:00:00:00:01"
    assert len(warnings) == 1
    assert "malformed" in warnings[0]


def test_malformed_json_line_is_skipped_with_a_warning(tmp_path):
    path = tmp_path / "leases-eth1.jsonl"
    path.write_text("not json at all\n")
    entries, warnings = journal.load_open_leases(path)
    assert entries == []
    assert len(warnings) == 1


def test_non_object_json_line_is_skipped_with_a_warning(tmp_path):
    path = tmp_path / "leases-eth1.jsonl"
    path.write_text("[1, 2, 3]\n")
    entries, warnings = journal.load_open_leases(path)
    assert entries == []
    assert len(warnings) == 1


def test_unknown_record_kind_is_skipped_with_a_warning(tmp_path):
    path = tmp_path / "leases-eth1.jsonl"
    rec = {"ev": "something-future-version-added", "mac": "de:ad:00:00:00:01", "ip": "1.2.3.4"}
    path.write_text(json.dumps(rec) + "\n")
    entries, warnings = journal.load_open_leases(path)
    assert entries == []
    assert any("unknown record kind" in w for w in warnings)


def test_ack_record_missing_a_required_field_is_skipped_with_a_warning(tmp_path):
    path = tmp_path / "leases-eth1.jsonl"
    rec = {"ev": "ack", "mac": "de:ad:00:00:00:01", "ip": "1.2.3.4"}  # no ts/iface/server_ip
    path.write_text(json.dumps(rec) + "\n")
    entries, warnings = journal.load_open_leases(path)
    assert entries == []
    assert len(warnings) == 1


def test_released_record_missing_mac_or_ip_is_skipped(tmp_path):
    path = tmp_path / "leases-eth1.jsonl"
    path.write_text(json.dumps({"ev": "released", "mac": "de:ad:00:00:00:01"}) + "\n")  # no ip
    entries, warnings = journal.load_open_leases(path)
    assert entries == []
    assert len(warnings) == 1


def test_blank_lines_are_ignored(tmp_path):
    path = tmp_path / "leases-eth1.jsonl"
    journal.record_ack(path, "eth1", _lease())
    with open(path, "a") as fh:
        fh.write("\n\n")
    entries, warnings = journal.load_open_leases(path)
    assert len(entries) == 1
    assert warnings == []


# ---------------------------------------------------------------- default_path resolution
def test_default_path_uses_xdg_state_home(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg-state"))
    p = journal.default_path("eth1")
    assert p == tmp_path / "xdg-state" / "dhcpig" / "leases-eth1.jsonl"


def test_default_path_never_uses_var_lib(monkeypatch, tmp_path):
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    p = journal.default_path("eth1")
    assert "/var/lib" not in str(p)
    assert ".local/state/dhcpig" in str(p)


# ---------------------------------------------------------------- engine wiring
def _engine(monkeypatch, **cfg):
    return build_engine(monkeypatch, **cfg)


def _ack_packet(xid, mac, yiaddr="172.20.0.83"):
    return (
        Ether(src="00:0c:29:da:53:f9")
        / IP(src=SERVER, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, yiaddr=yiaddr, siaddr=SERVER, chaddr=mac2str(mac) + b"\x00" * 10, xid=xid)
        / DHCP(
            options=[
                ("message-type", "ack"),
                ("server_id", SERVER),
                ("subnet_mask", "255.255.255.0"),
                ("lease_time", 1200),
                "end",
            ]
        )
    )


def _mark_ours(eng, xid: int, mac: str) -> None:
    """Register xid in _inflight, simulating that we actually sent the DISCOVER/REQUEST this ACK
    is replying to -- _handle_ack() now requires this (2.3 bug fix: it used to journal/count any
    ACK seen, ours or not)."""
    eng._inflight[xid] = {"mac": mac, "sent_at": time.time(), "state": "DISCOVER_SENT"}


def test_engine_writes_an_ack_record_to_the_journal(monkeypatch, tmp_path):
    jpath = tmp_path / "leases-lo.jsonl"
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST, journal_path=jpath)
    _mark_ours(eng, 0xAAAA, "de:ad:00:00:00:09")
    eng._handle_ack(_ack_packet(0xAAAA, "de:ad:00:00:00:09"))
    entries, warnings = journal.load_open_leases(jpath)
    assert warnings == []
    assert len(entries) == 1
    assert entries[0].mac == "de:ad:00:00:00:09"
    assert entries[0].lease_time == 1200


def test_foreign_ack_is_not_journaled_or_counted(monkeypatch, tmp_path):
    """BUG FIX regression (2.3): an ACK whose xid we never sent must not be registered in
    Cleanup or the journal -- that used to mean a later restore()/release-previous could RELEASE
    an address a real, uninvolved client is actively using."""
    jpath = tmp_path / "leases-lo.jsonl"
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST, journal_path=jpath)
    assert 0xFFFF not in eng._inflight
    eng._handle_ack(_ack_packet(0xFFFF, "de:ad:00:00:00:ff"))
    assert eng.acks == 0
    assert not jpath.exists()
    assert eng.cleanup.pending() == []
    assert not any(isinstance(e, ev.AckReceived) for e in events)


def test_dry_run_writes_no_journal_records(monkeypatch, tmp_path):
    jpath = tmp_path / "leases-lo.jsonl"
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST, dry_run=True, journal_path=jpath)
    _mark_ours(eng, 0xBBBB, "de:ad:00:00:00:0a")
    eng._handle_ack(_ack_packet(0xBBBB, "de:ad:00:00:00:0a"))
    assert not jpath.exists()


def test_no_journal_flag_writes_nothing(monkeypatch, tmp_path):
    jpath = tmp_path / "leases-lo.jsonl"
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST, journal=False, journal_path=jpath)
    _mark_ours(eng, 0xCCCC, "de:ad:00:00:00:0b")
    eng._handle_ack(_ack_packet(0xCCCC, "de:ad:00:00:00:0b"))
    assert not jpath.exists()


def test_release_bindings_writes_a_released_record_closing_the_ack(monkeypatch, tmp_path):
    jpath = tmp_path / "leases-lo.jsonl"
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST, journal_path=jpath)
    _mark_ours(eng, 0xDDDD, "de:ad:00:00:00:0c")
    eng._handle_ack(_ack_packet(0xDDDD, "de:ad:00:00:00:0c"))
    assert len(journal.load_open_leases(jpath)[0]) == 1

    eng._release_bindings([("de:ad:00:00:00:0c", "172.20.0.83")], SERVER)
    entries, warnings = journal.load_open_leases(jpath)
    assert entries == []
    assert warnings == []


def test_journal_write_failure_is_swallowed_as_debug_not_raised(monkeypatch, tmp_path):
    """A read-only/unwritable state dir must degrade to 'no recovery data', not crash exhaust."""
    jpath = tmp_path / "leases-lo.jsonl"
    eng, events, _ = _engine(monkeypatch, mode=Mode.EXHAUST, journal_path=jpath)

    def _boom(*a, **kw):
        raise OSError("disk full")

    monkeypatch.setattr(journal, "record_ack", _boom)
    _mark_ours(eng, 0xEEEE, "de:ad:00:00:00:0d")
    eng._handle_ack(_ack_packet(0xEEEE, "de:ad:00:00:00:0d"))  # must not raise
    assert eng.acks == 1  # the run itself proceeded normally
    assert any(
        isinstance(e, ev.Debug) and "journal" in e.message.lower() and "disk full" in e.message
        for e in events
    )


def test_journal_path_defaults_when_not_overridden(monkeypatch):
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST)
    assert eng.journal_path == journal.default_path("lo")


def test_journal_path_is_none_when_dry_run(monkeypatch):
    eng, _, _ = _engine(monkeypatch, mode=Mode.EXHAUST, dry_run=True)
    assert eng.journal_path is None
