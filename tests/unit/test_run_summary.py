"""RUN_SUMMARY (2.3.2): the one finding raised on every run, in every mode.

It is descriptive only -- steps taken and what each returned -- and deliberately draws no
conclusions about the network's defenses; that stays with the verdict findings.
"""

import time

from conftest import build_engine

from dhcpig.cli.render import Renderer
from dhcpig.core.events import FindingRaised
from dhcpig.core.models import ControlOutcome, Mode


def _engine(monkeypatch, **cfg):
    cfg.setdefault("interface", "wlan0")
    cfg.setdefault("mode", Mode.EXHAUST)
    cfg.setdefault("offline", True)
    eng, events, _sent = build_engine(monkeypatch, **cfg)
    eng._started = time.time()
    return eng, events


def _summary(events):
    return next(
        e.finding for e in events if isinstance(e, FindingRaised) and e.finding.id == "RUN_SUMMARY"
    )


def _steps_text(events):
    return "\n".join(f"{s['did']} -> {s['got']}" for s in _summary(events).evidence["steps"])


# ---------------------------------------------------------------- always present
def test_run_summary_is_raised_for_every_mode(monkeypatch):
    for mode in Mode:
        eng, events = _engine(monkeypatch, mode=mode)
        eng._finalize_findings()
        f = _summary(events)
        assert f.verdict == "INFO"
        assert f.evidence["mode"] == mode.value
        assert f.evidence["interface"] == "wlan0"


def test_findings_are_emitted_worst_severity_first(monkeypatch):
    """The log is the only results surface now and a stream can't be re-ranked after the fact,
    so ordering happens before emission. RUN_SUMMARY is INFO, so it sinks below anything
    actionable -- a failed baseline leads, because it invalidates everything under it."""
    eng, events = _engine(monkeypatch)
    eng.control_pre = ControlOutcome(phase="pre", attempted=True, success=False, reason="no OFFER")
    eng._finalize_findings()
    raised = [e.finding for e in events if isinstance(e, FindingRaised)]
    ids = [f.id for f in raised]
    sev = [f.severity for f in raised]

    assert ids[0] == "CONTROL_BASELINE_FAILED"  # high
    assert "RUN_SUMMARY" in ids
    assert sev == sorted(sev, key=lambda s: {"high": 0, "medium": 1, "info": 2}[s])


def test_run_summary_is_raised_even_when_nothing_happened(monkeypatch):
    """No neighbors, no controls, no sends -- the finding still exists, just with fewer steps."""
    eng, events = _engine(monkeypatch)
    eng._finalize_findings()
    assert isinstance(_summary(events).evidence["steps"], list)


# ---------------------------------------------------------------- content
def test_exhaust_steps_report_actions_and_results_in_run_order(monkeypatch):
    eng, events = _engine(monkeypatch)
    eng._baseline_neighbor_count = 47
    eng.control_pre = ControlOutcome(
        phase="pre", attempted=True, success=True, offered_ip="10.0.0.5", server_id="10.0.0.1"
    )
    eng.releases = 12
    eng._reacquire_targets = {i: f"10.0.1.{i}" for i in range(12)}
    eng._reacquire_outcomes = {i: ("granted" if i < 4 else "naked") for i in range(12)}
    eng.acks, eng.discovers = 412, 690
    eng._evict.outcomes = {"10.0.1.0": "declined"}
    eng._finalize_findings()
    text = _steps_text(events)

    assert "47 devices" in text  # ARP inventory result
    assert "10.0.0.5 from 10.0.0.1" in text  # control result
    assert "12 DHCPRELEASE sent" in text  # release result
    assert "got 4 of 12 (option 50)" in text  # re-acquisition result
    assert "412 held of 690" in text  # sender result
    assert "1 targets: 1 declined" in text  # eviction result
    # order matters: the narrative must read chronologically
    assert text.index("47 devices") < text.index("DHCPRELEASE") < text.index("targets")


def test_every_step_is_a_did_got_pair(monkeypatch):
    """The two-column shape is what lets the left column be scannable on its own."""
    eng, events = _engine(monkeypatch)
    eng._baseline_neighbor_count = 2
    eng.releases = 3
    eng.acks = 9
    eng._finalize_findings()
    steps = _summary(events).evidence["steps"]
    assert steps
    for s in steps:
        assert set(s) == {"did", "got"}
        assert s["did"] and s["got"]


def test_did_column_stays_short_enough_to_scan(monkeypatch):
    """Regression against the original wall-of-prose version: the left column is a label, not
    an explanation. The 'why' is stated once in the recommendation instead."""
    eng, events = _engine(monkeypatch)
    eng._baseline_neighbor_count = 4
    eng.releases = 12
    eng._reacquire_targets = {1: "10.0.1.1"}
    eng.acks, eng.discovers = 412, 690
    eng.races = 5
    eng._evict.outcomes = {"10.0.1.0": "declined"}
    eng._finalize_findings()
    for s in _summary(events).evidence["steps"]:
        assert len(s["did"]) <= 60, s["did"]


def test_plain_english_action_with_the_protocol_name_in_the_result(monkeypatch):
    """Audience is a security engineer who isn't a DHCP specialist: the left column must be
    readable without knowing the protocol term, which belongs on the right."""
    eng, events = _engine(monkeypatch)
    eng.releases = 3
    eng._finalize_findings()
    step = next(s for s in _summary(events).evidence["steps"] if "DHCPRELEASE" in s["got"])
    assert "DHCPRELEASE" not in step["did"]
    assert "Released other devices' leases" == step["did"]


def test_release_mode_summary_omits_the_flood_and_new_client_legs(monkeypatch):
    """release has no windowed sender and never runs the new-client control leg."""
    eng, events = _engine(monkeypatch, mode=Mode.RELEASE_NEIGHBORS)
    eng._rel_pre_control = ControlOutcome(
        phase="pre", attempted=True, success=True, offered_ip="10.0.0.5", server_id="10.0.0.1"
    )
    eng.releases = 5
    eng._finalize_findings()
    text = _steps_text(events)
    assert "Drained the pool" not in text
    assert "unknown device" not in text
    assert "5 DHCPRELEASE sent" in text


def test_scan_mode_summary_says_only_that_it_listened(monkeypatch):
    eng, events = _engine(monkeypatch, mode=Mode.SCAN)
    eng._finalize_findings()
    steps = _summary(events).evidence["steps"]
    assert len(steps) == 1
    assert steps[0]["did"] == "Listened only"


def test_release_previous_summary_describes_the_journal_replay(monkeypatch):
    eng, events = _engine(monkeypatch, mode=Mode.RELEASE_PREVIOUS)
    eng.recovery_result = {
        "outcome": "recovered",
        "targeted": 9,
        "frames_sent": 18,
        "passes_run": 2,
        "post_control_success": True,
    }
    eng._finalize_findings()
    text = _steps_text(events)
    assert "9 still held (lease journal)" in text
    assert "18 DHCPRELEASE sent, 2 passes" in text
    assert "pool usable again" in text


def test_halt_signal_is_reported_as_the_senders_result(monkeypatch):
    eng, events = _engine(monkeypatch)
    eng.acks, eng.discovers = 56, 120
    eng._halt_signal = ("nak_burst", "4 NAKs in 5s", 56)
    eng._finalize_findings()
    step = next(s for s in _summary(events).evidence["steps"] if "Drained the pool" in s["did"])
    assert "stopped early at 56" in step["got"] and "nak_burst" in step["got"]


def test_dry_run_steps_say_nothing_was_sent(monkeypatch):
    eng, events = _engine(monkeypatch, dry_run=True)
    eng._dry_run_would_release = 7
    eng._finalize_findings()
    f = _summary(events)
    assert f.evidence["dry_run"] is True
    step = next(s for s in f.evidence["steps"] if "DHCPRELEASE" in s["got"])
    assert "[dry run, not sent]" in step["did"]


# ---------------------------------------------------------------- boundaries
def test_run_summary_draws_no_conclusions_about_defenses(monkeypatch):
    """Deliberate scope limit: verdicts belong to the verdict findings, not to this narrative.
    Two differently-worded conclusions from one run is worse than one."""
    eng, events = _engine(monkeypatch)
    eng.acks, eng.discovers = 412, 690
    eng._halt_signal = ("nak_burst", "4 NAKs in 5s", 412)
    eng._evict.outcomes = {"10.0.1.0": "no_reaction"}
    eng._finalize_findings()
    text = _steps_text(events).lower()
    for word in ("snooping", "dynamic arp inspection", "vulnerable", "not protected", "fail"):
        assert word not in text


def test_recommendation_gives_one_wifi_control(monkeypatch):
    eng, events = _engine(monkeypatch)
    eng._finalize_findings()
    rec = _summary(events).recommendation
    assert "Wi-Fi" in rec
    assert "client-hardware-address" in rec


def test_scan_modes_do_not_claim_dhcp_spoofing_they_never_did(monkeypatch):
    """The spoofing takeaway is true of the sending modes only. A passive scan sends nothing and
    active-scan names nobody but itself (ARP sweep + DHCPINFORM), so claiming every step above
    worked because DHCP trusts the name on a request described a run that didn't happen."""
    for mode in (Mode.SCAN, Mode.ACTIVE_SCAN):
        eng, events = _engine(monkeypatch, mode=mode)
        eng._finalize_findings()
        rec = _summary(events).recommendation
        assert "never checks that a request comes from" not in rec, mode
        assert "on that device's behalf" not in rec, mode
        assert rec  # every mode still gets a takeaway of its own


def test_active_scan_recommendation_describes_reconnaissance(monkeypatch):
    eng, events = _engine(monkeypatch, mode=Mode.ACTIVE_SCAN)
    eng._finalize_findings()
    rec = _summary(events).recommendation
    assert "took or disturbed a lease" in rec
    assert "DHCPINFORM" in rec


def test_scan_recommendation_says_nothing_was_sent(monkeypatch):
    eng, events = _engine(monkeypatch, mode=Mode.SCAN)
    eng._finalize_findings()
    assert _summary(events).recommendation.startswith("Nothing was sent")


# ---------------------------------------------------------------- CLI rendering
def test_cli_prints_the_shared_summary_lines(capsys, monkeypatch):
    """CLI, web log and HTML report all render a finding through
    reporting.finding_summary_lines(), so one run can't be described three different ways."""
    eng, events = _engine(monkeypatch)
    eng._baseline_neighbor_count = 3
    eng.releases = 4
    eng._finalize_findings()
    r = Renderer(verbosity=2, color=False)
    for e in events:
        if isinstance(e, FindingRaised):
            r.handle(e)
    out = capsys.readouterr().out

    from dhcpig.core.reporting import finding_summary_lines

    for line in finding_summary_lines(
        {"evidence": _summary(events).evidence, "recommendation": _summary(events).recommendation}
    ):
        assert f"        {line}" in out
    assert "evidence: {" not in out  # the old raw-dict dump is gone


def test_summary_lines_drop_noise_and_flatten_nested_evidence():
    """Zero/empty values, run context and config echoes say nothing on a summary line; nested
    dicts read as numbers, not as serialized JSON."""
    from dhcpig.core.reporting import finding_summary_lines

    lines = finding_summary_lines(
        {
            "evidence": {
                "targets": 4,
                "granted": 0,
                "by_rung": {"declined": 1, "no_reaction": 0},
                "mode": "exhaust",
                "still_using_address_arp": 3,
            },
            "recommendation": "First sentence. Second sentence that should not appear.",
        }
    )
    assert lines[0] == "targets=4 · declined=1"
    assert lines[-1] == "First sentence."
    assert not any("Second sentence" in ln for ln in lines)


def test_summary_lines_expand_list_evidence_one_item_per_line():
    from dhcpig.core.reporting import finding_summary_lines

    lines = finding_summary_lines(
        {
            "evidence": {
                "steps": [{"did": "Did a thing", "got": "a result"}],
                "servers": ["10.0.0.1"],
            }
        }
    )
    assert "Did a thing  ->  a result" in lines
    assert "10.0.0.1" in lines
