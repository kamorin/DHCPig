"""release-previous: journal-driven recovery.

All no-root: sendp is monkeypatched. The pre/post "can a new client get an address?" control
transaction is faked directly (rather than driven through the real DISCOVER/OFFER/ACK dance
with a responder thread) so these tests are fast and deterministic -- the control mechanics
themselves are already covered by test_control_findings.py. This module tests
release-previous's own orchestration: journal selection, filtering, grouping, and findings.
"""

import json
import time

from conftest import build_engine
from scapy.all import BOOTP, IP, Ether

from dhcpig.core import events as ev
from dhcpig.core import journal
from dhcpig.core.models import ControlOutcome, IPVersion, Lease, Mode, Timeouts

SERVER = "172.20.15.1"
SERVER_MAC = "00:0c:29:da:53:f9"
OTHER_SERVER = "10.0.0.99"
OTHER_SERVER_MAC = "00:0c:29:11:11:11"


def _engine(monkeypatch, **cfg):
    cfg.setdefault("mode", Mode.RELEASE_PREVIOUS)
    cfg.setdefault("timeouts", Timeouts(control=0.05))  # fast timeout when a test lets the
    # real (unfaked) control transaction run and time out on its own
    return build_engine(monkeypatch, **cfg)


def _seed_journal(path, mac, ip, server_ip=SERVER, server_mac=SERVER_MAC, ts=None, lease_time=600):
    lease = Lease(
        mac=mac,
        ip=ip,
        server_ip=server_ip,
        xid=0xABCD,
        ip_version=IPVersion.V4,
        lease_time=lease_time,
        server_mac=server_mac,
    )
    journal.record_ack(path, "lo", lease)
    if ts is not None:
        # backdate the just-written record for age tests, by rewriting the last line
        lines = path.read_text().splitlines()
        rec = json.loads(lines[-1])
        rec["ts"] = ts
        lines[-1] = json.dumps(rec)
        path.write_text("\n".join(lines) + "\n")


def _fake_control(monkeypatch, eng, *outcomes):
    """Replace eng._control_transaction with a canned sequence: first call (the pre-flight
    probe) returns outcomes[0], second call (the post-release probe) returns outcomes[1]."""
    calls = []

    def fake(phase, client="self"):
        idx = len(calls)
        calls.append((phase, client))
        return outcomes[min(idx, len(outcomes) - 1)]

    monkeypatch.setattr(eng, "_control_transaction", fake)
    return calls


def _released_addrs(sent) -> set[str]:
    """RELEASE packets carry the released address in BOOTP.ciaddr; DISCOVER/REQUEST frames
    (sent by the control transaction, which is real -- only its network wait is faked, not
    _send itself) carry ciaddr 0.0.0.0. This isolates just the RELEASE traffic."""
    return {p[BOOTP].ciaddr for p in sent if p[BOOTP].ciaddr != "0.0.0.0"}


# ---------------------------------------------------------------- NO_RECOVERY_NEEDED
def test_no_recovery_needed_when_a_new_client_already_gets_an_address(monkeypatch, tmp_path):
    jpath = tmp_path / "leases-lo.jsonl"
    eng, events, sent = _engine(monkeypatch, journal_path=jpath)
    _fake_control(
        monkeypatch,
        eng,
        ControlOutcome(
            phase="pre", client="new", attempted=True, success=True, offered_ip="9.9.9.9"
        ),
    )
    eng._release_previous_worker()

    findings = [e.finding for e in events if isinstance(e, ev.FindingRaised)]
    assert any(f.id == "NO_RECOVERY_NEEDED" for f in findings)
    assert eng.releases == 0
    assert sent == []  # the fake never touches _send, so nothing hit the wire at all


# ---------------------------------------------------------------- pool not exhausted, but
# ---------------------------------------------------------------- journal still has entries
def test_release_still_runs_when_pool_is_not_exhausted_but_journal_has_entries(
    monkeypatch, tmp_path
):
    """A free address right now doesn't mean every lease this tool took has been given back --
    release-previous must keep releasing whatever the journal still holds open, and record that
    the pool wasn't exhausted rather than treating it as nothing-to-do."""
    jpath = tmp_path / "leases-lo.jsonl"
    _seed_journal(jpath, "de:ad:00:00:00:01", "172.20.0.51")
    eng, events, sent = _engine(
        monkeypatch, journal_path=jpath, scope_cidrs=["172.20.0.0/24"], release_passes=1
    )
    _fake_control(
        monkeypatch,
        eng,
        ControlOutcome(
            phase="pre", client="new", attempted=True, success=True, offered_ip="9.9.9.9"
        ),
        ControlOutcome(phase="post", client="new", attempted=True, success=True),
    )
    eng._release_previous_worker()

    assert _released_addrs(sent) == {"172.20.0.51"}
    assert eng.recovery_result["pool_exhausted"] is False
    findings = [e.finding for e in events if isinstance(e, ev.FindingRaised)]
    assert not any(f.id == "NO_RECOVERY_NEEDED" for f in findings)


# ---------------------------------------------------------------- NO_JOURNAL_DATA
def test_no_journal_data_when_journal_is_missing(monkeypatch, tmp_path):
    jpath = tmp_path / "does-not-exist.jsonl"
    eng, events, sent = _engine(monkeypatch, journal_path=jpath, scope_cidrs=["172.20.0.0/24"])
    _fake_control(monkeypatch, eng, ControlOutcome(phase="pre", client="new", attempted=True))
    eng._release_previous_worker()
    findings = [e.finding for e in events if isinstance(e, ev.FindingRaised)]
    assert any(f.id == "NO_JOURNAL_DATA" for f in findings)
    assert eng.releases == 0


def test_already_released_entry_is_never_reselected(monkeypatch, tmp_path):
    jpath = tmp_path / "leases-lo.jsonl"
    _seed_journal(jpath, "de:ad:00:00:00:01", "172.20.0.51")
    journal.record_released(jpath, "lo", "de:ad:00:00:00:01", "172.20.0.51")
    eng, events, sent = _engine(monkeypatch, journal_path=jpath, scope_cidrs=["172.20.0.0/24"])
    _fake_control(monkeypatch, eng, ControlOutcome(phase="pre", client="new", attempted=True))
    eng._release_previous_worker()
    findings = [e.finding for e in events if isinstance(e, ev.FindingRaised)]
    assert any(f.id == "NO_JOURNAL_DATA" for f in findings)
    assert eng.releases == 0
    assert _released_addrs(sent) == set()


# ---------------------------------------------------------------- CIDR filter
def test_entry_outside_current_cidr_is_excluded(monkeypatch, tmp_path):
    jpath = tmp_path / "leases-lo.jsonl"
    _seed_journal(jpath, "de:ad:00:00:00:01", "172.20.0.51")  # in scope
    _seed_journal(jpath, "de:ad:00:00:00:02", "10.9.9.9")  # out of scope
    eng, events, sent = _engine(
        monkeypatch, journal_path=jpath, scope_cidrs=["172.20.0.0/24"], release_passes=1
    )
    _fake_control(
        monkeypatch,
        eng,
        ControlOutcome(phase="pre", client="new", attempted=True),
        ControlOutcome(phase="post", client="new", attempted=True),
    )
    eng._release_previous_worker()
    assert _released_addrs(sent) == {"172.20.0.51"}


# ---------------------------------------------------------------- same-server filter
def test_entry_from_a_different_server_is_excluded_by_default(monkeypatch, tmp_path):
    jpath = tmp_path / "leases-lo.jsonl"
    _seed_journal(jpath, "de:ad:00:00:00:01", "172.20.0.51", server_ip=SERVER)
    _seed_journal(jpath, "de:ad:00:00:00:02", "172.20.0.52", server_ip=OTHER_SERVER)
    eng, events, sent = _engine(
        monkeypatch, journal_path=jpath, scope_cidrs=["172.20.0.0/24"], release_passes=1
    )
    # pre-flight learned the current server's identity (SERVER) even though it ultimately
    # failed -- e.g. it offered then NAKed. That's what makes the same-server filter evaluable.
    _fake_control(
        monkeypatch,
        eng,
        ControlOutcome(phase="pre", client="new", attempted=True, success=False, server_id=SERVER),
        ControlOutcome(phase="post", client="new", attempted=True, success=False),
    )
    eng._release_previous_worker()
    assert _released_addrs(sent) == {"172.20.0.51"}


def test_any_server_flag_includes_mismatched_entries(monkeypatch, tmp_path):
    jpath = tmp_path / "leases-lo.jsonl"
    _seed_journal(jpath, "de:ad:00:00:00:02", "172.20.0.52", server_ip=OTHER_SERVER)
    eng, events, sent = _engine(
        monkeypatch,
        journal_path=jpath,
        scope_cidrs=["172.20.0.0/24"],
        require_same_server=False,
        release_passes=1,
    )
    _fake_control(
        monkeypatch,
        eng,
        ControlOutcome(phase="pre", client="new", attempted=True, success=False, server_id=SERVER),
        ControlOutcome(phase="post", client="new", attempted=True, success=False),
    )
    eng._release_previous_worker()
    assert _released_addrs(sent) == {"172.20.0.52"}


def test_same_server_filter_falls_back_to_cidr_only_when_identity_unknown(monkeypatch, tmp_path):
    """When the pre-flight control never learns a server identity at all (the common case on a
    genuinely exhausted pool -- no OFFER ever arrives), require_same_server cannot be evaluated
    and the plan says to fall back to CIDR-only rather than silently excluding everything."""
    jpath = tmp_path / "leases-lo.jsonl"
    _seed_journal(jpath, "de:ad:00:00:00:01", "172.20.0.51", server_ip=SERVER)
    _seed_journal(jpath, "de:ad:00:00:00:02", "172.20.0.52", server_ip=OTHER_SERVER)
    eng, events, sent = _engine(
        monkeypatch, journal_path=jpath, scope_cidrs=["172.20.0.0/24"], release_passes=1
    )
    _fake_control(
        monkeypatch,
        eng,
        ControlOutcome(phase="pre", client="new", attempted=True, success=False),  # server_id=None
        ControlOutcome(phase="post", client="new", attempted=True, success=False),
    )
    eng._release_previous_worker()
    assert _released_addrs(sent) == {"172.20.0.51", "172.20.0.52"}


# ---------------------------------------------------------------- age filter
def test_entry_older_than_max_age_is_excluded(monkeypatch, tmp_path):
    jpath = tmp_path / "leases-lo.jsonl"
    ancient = time.time() - 30 * 86400  # 30 days ago, well past any lease_time
    _seed_journal(jpath, "de:ad:00:00:00:01", "172.20.0.51", ts=ancient, lease_time=600)
    _seed_journal(jpath, "de:ad:00:00:00:02", "172.20.0.52")  # fresh
    eng, events, sent = _engine(
        monkeypatch,
        journal_path=jpath,
        scope_cidrs=["172.20.0.0/24"],
        max_age_days=7.0,
        release_passes=1,
    )
    _fake_control(
        monkeypatch,
        eng,
        ControlOutcome(phase="pre", client="new", attempted=True),
        ControlOutcome(phase="post", client="new", attempted=True),
    )
    eng._release_previous_worker()
    assert _released_addrs(sent) == {"172.20.0.52"}


# ---------------------------------------------------------------- dry-run
def test_dry_run_sends_nothing_but_lists_the_selection(monkeypatch, tmp_path):
    jpath = tmp_path / "leases-lo.jsonl"
    _seed_journal(jpath, "de:ad:00:00:00:01", "172.20.0.51")
    eng, events, sent = _engine(
        monkeypatch,
        journal_path=jpath,
        scope_cidrs=["172.20.0.0/24"],
        dry_run=True,
        offline=True,  # dry_run alone now probes for real (2.3); offline keeps this test no-root
    )
    eng._release_previous_worker()  # offline: _control_transaction short-circuits on its own
    assert sent == []
    assert eng.recovery_result.get("outcome") == "dry_run"
    assert eng.recovery_result.get("selected") == 1


# ---------------------------------------------------------------- unbounded refusal
def test_refuses_to_run_without_scope_or_resolvable_interface_network(monkeypatch, tmp_path):
    monkeypatch.setattr("dhcpig.core.netutils.iface_network_cidr", lambda iface: None)
    jpath = tmp_path / "leases-lo.jsonl"
    _seed_journal(jpath, "de:ad:00:00:00:01", "172.20.0.51")
    eng, events, sent = _engine(monkeypatch, journal_path=jpath)  # no scope_cidrs
    eng._release_previous_worker()
    findings = [e.finding for e in events if isinstance(e, ev.FindingRaised)]
    assert any(f.id == "RELEASE_PREVIOUS_SCOPE_REQUIRED" for f in findings)
    assert sent == []


# ---------------------------------------------------------------- grouping by server
def test_releases_are_grouped_by_their_own_recorded_server(monkeypatch, tmp_path):
    jpath = tmp_path / "leases-lo.jsonl"
    _seed_journal(
        jpath, "de:ad:00:00:00:01", "172.20.0.51", server_ip=SERVER, server_mac=SERVER_MAC
    )
    _seed_journal(
        jpath,
        "de:ad:00:00:00:02",
        "172.20.0.52",
        server_ip="172.20.15.2",
        server_mac=OTHER_SERVER_MAC,
    )
    eng, events, sent = _engine(
        monkeypatch,
        journal_path=jpath,
        scope_cidrs=["172.20.0.0/24"],
        require_same_server=False,
        release_passes=1,
    )
    _fake_control(
        monkeypatch,
        eng,
        ControlOutcome(phase="pre", client="new", attempted=True),
        ControlOutcome(phase="post", client="new", attempted=True),
    )
    eng._release_previous_worker()
    releases = [p for p in sent if p[BOOTP].ciaddr != "0.0.0.0"]
    by_ciaddr = {p[BOOTP].ciaddr: p for p in releases}
    assert by_ciaddr["172.20.0.51"][IP].dst == SERVER
    assert by_ciaddr["172.20.0.51"][Ether].dst == SERVER_MAC
    assert by_ciaddr["172.20.0.52"][IP].dst == "172.20.15.2"
    assert by_ciaddr["172.20.0.52"][Ether].dst == OTHER_SERVER_MAC


# ---------------------------------------------------------------- journal closes on release
def test_a_released_lease_is_journalled_and_a_second_run_selects_nothing(monkeypatch, tmp_path):
    jpath = tmp_path / "leases-lo.jsonl"
    _seed_journal(jpath, "de:ad:00:00:00:01", "172.20.0.51")
    eng, events, sent = _engine(
        monkeypatch, journal_path=jpath, scope_cidrs=["172.20.0.0/24"], release_passes=1
    )
    _fake_control(
        monkeypatch,
        eng,
        ControlOutcome(phase="pre", client="new", attempted=True),
        ControlOutcome(phase="post", client="new", attempted=True),
    )
    eng._release_previous_worker()
    assert _released_addrs(sent) == {"172.20.0.51"}
    entries, _ = journal.load_open_leases(jpath)
    assert entries == []

    eng2, events2, sent2 = _engine(monkeypatch, journal_path=jpath, scope_cidrs=["172.20.0.0/24"])
    _fake_control(monkeypatch, eng2, ControlOutcome(phase="pre", client="new", attempted=True))
    eng2._release_previous_worker()
    assert _released_addrs(sent2) == set()
    findings2 = [e.finding for e in events2 if isinstance(e, ev.FindingRaised)]
    assert any(f.id == "NO_JOURNAL_DATA" for f in findings2)


# ---------------------------------------------------------------- verdicts
def test_pool_recovered_when_post_control_succeeds(monkeypatch, tmp_path):
    jpath = tmp_path / "leases-lo.jsonl"
    _seed_journal(jpath, "de:ad:00:00:00:01", "172.20.0.51")
    eng, events, sent = _engine(
        monkeypatch, journal_path=jpath, scope_cidrs=["172.20.0.0/24"], release_passes=1
    )
    _fake_control(
        monkeypatch,
        eng,
        ControlOutcome(phase="pre", client="new", attempted=True, success=False),
        ControlOutcome(phase="post", client="new", attempted=True, success=True),
    )
    eng._release_previous_worker()
    findings = [e.finding for e in events if isinstance(e, ev.FindingRaised)]
    assert any(f.id == "POOL_RECOVERED" for f in findings)
    assert eng.recovery_result["outcome"] == "recovered"


def test_pool_recovery_failed_when_everything_released_but_still_denied(monkeypatch, tmp_path):
    jpath = tmp_path / "leases-lo.jsonl"
    _seed_journal(jpath, "de:ad:00:00:00:01", "172.20.0.51")
    eng, events, sent = _engine(
        monkeypatch, journal_path=jpath, scope_cidrs=["172.20.0.0/24"], release_passes=1
    )
    _fake_control(
        monkeypatch,
        eng,
        ControlOutcome(phase="pre", client="new", attempted=True, success=False),
        ControlOutcome(phase="post", client="new", attempted=True, success=False),
    )
    eng._release_previous_worker()
    findings = [e.finding for e in events if isinstance(e, ev.FindingRaised)]
    assert any(f.id == "POOL_RECOVERY_FAILED" for f in findings)
