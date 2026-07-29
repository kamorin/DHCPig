"""RUN_SUMMARY (2.3.2): the one finding raised on every run, in every mode.

It is descriptive only -- steps taken and what each returned -- and deliberately draws no
conclusions about the network's defenses; that stays with the verdict findings.
"""

import time

from dhcpig.core import engine as engine_mod
from dhcpig.core.engine import DhcpEngine
from dhcpig.core.events import EventBus, FindingRaised
from dhcpig.core.models import ControlOutcome, Mode, SessionConfig


def _engine(monkeypatch, **cfg):
    monkeypatch.setattr(engine_mod, "sendp", lambda *a, **k: None)
    bus = EventBus()
    events = []
    bus.subscribe(events.append)
    cfg.setdefault("mode", Mode.EXHAUST)
    cfg.setdefault("offline", True)
    eng = DhcpEngine(SessionConfig(interface="wlan0", **cfg), bus)
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
    eng._evict_outcomes = {"10.0.1.0": "declined"}
    eng._finalize_findings()
    text = _steps_text(events)

    assert "47 devices found" in text  # ARP inventory result
    assert "got 10.0.0.5 from 10.0.0.1" in text  # control result
    assert "12 DHCPRELEASE sent" in text  # release result
    assert "gave us 4 of 12" in text  # re-acquisition result
    assert "412 held of 690 asked" in text  # sender result
    assert "1 contested: 1 declined" in text  # eviction result
    # order matters: the narrative must read chronologically
    assert text.index("47 devices") < text.index("DHCPRELEASE") < text.index("contested")


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
    eng._evict_outcomes = {"10.0.1.0": "declined"}
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
    assert "leases done" in step["did"]


def test_release_mode_summary_omits_the_flood_and_new_client_legs(monkeypatch):
    """release has no windowed sender and never runs the new-client control leg."""
    eng, events = _engine(monkeypatch, mode=Mode.RELEASE_NEIGHBORS)
    eng._rel_pre_control = ControlOutcome(
        phase="pre", attempted=True, success=True, offered_ip="10.0.0.5", server_id="10.0.0.1"
    )
    eng.releases = 5
    eng._finalize_findings()
    text = _steps_text(events)
    assert "drain the pool" not in text
    assert "unknown device" not in text
    assert "5 DHCPRELEASE sent" in text


def test_scan_mode_summary_says_only_that_it_listened(monkeypatch):
    eng, events = _engine(monkeypatch, mode=Mode.SCAN)
    eng._finalize_findings()
    steps = _summary(events).evidence["steps"]
    assert len(steps) == 1
    assert "without sending anything" in steps[0]["did"]


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
    step = next(s for s in _summary(events).evidence["steps"] if "drain the pool" in s["did"])
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
    eng._evict_outcomes = {"10.0.1.0": "no_reaction"}
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


# ---------------------------------------------------------------- CLI rendering
def test_cli_renders_steps_as_two_aligned_columns(capsys, monkeypatch):
    """A narrative flattened into a single dict repr is unreadable -- the whole reason
    RUN_SUMMARY needed the renderer to grow list handling."""
    from dhcpig.cli.render import Renderer

    eng, events = _engine(monkeypatch)
    eng._baseline_neighbor_count = 3
    eng.releases = 4
    eng._finalize_findings()
    r = Renderer(verbosity=2, color=False)
    for e in events:
        if isinstance(e, FindingRaised):
            r.handle(e)
    out = capsys.readouterr().out
    assert "steps:" in out
    assert "'steps'" not in out  # not flattened into the compact dict

    rendered = [ln for ln in out.splitlines() if "  ->  " in ln]
    assert len(rendered) == len(_summary(events).evidence["steps"])
    # the arrows line up, which is what makes the left column scannable
    assert len({ln.index("  ->  ") for ln in rendered}) == 1


def test_cli_still_bullets_plain_list_evidence(capsys):
    """Non-pair lists (servers, sample_hosts, ...) keep the simple bulleted form."""
    from dhcpig.cli.render import Renderer
    from dhcpig.core.models import Finding

    r = Renderer(verbosity=2, color=False)
    r._finding(
        Finding(
            id="X",
            title="t",
            verdict="INFO",
            severity="info",
            evidence={"servers": ["10.0.0.1", "10.0.0.2"]},
        )
    )
    out = capsys.readouterr().out
    assert "          - 10.0.0.1\n" in out
    assert "  ->  " not in out


def test_cli_keeps_empty_lists_out_of_their_own_block(capsys):
    """An empty list rendered as a bare header reads like truncated output."""
    from dhcpig.cli.render import Renderer
    from dhcpig.core.models import Finding

    r = Renderer(verbosity=2, color=False)
    r._finding(
        Finding(
            id="X", title="t", verdict="INFO", severity="info", evidence={"servers": [], "n": 1}
        )
    )
    out = capsys.readouterr().out
    assert "servers:\n" not in out
    assert "'servers': []" in out
