"""Race-freed (2.3): counters (4 surfaces) + RACED_FREED_ADDRESSES finding + dry-run gating.

See docs/DESIGN.md §5g. See test_race_freed.py (triggers/queue) and
test_race_freed_sender.py (sender integration + classifier, commit 3) for the rest of the feature.
"""

from conftest import build_engine

from dhcpig.core.events import FindingRaised
from dhcpig.core.models import Mode


def _engine(monkeypatch, **cfg):
    cfg.setdefault("mode", Mode.EXHAUST)
    eng, events, _sent = build_engine(monkeypatch, **cfg)
    return eng, events


def _findings_by_id(events):
    return {e.finding.id: e.finding for e in events if isinstance(e, FindingRaised)}


# ---------------------------------------------------------------- counters (surfaces 1 & 2)
def test_counters_include_races(monkeypatch):
    eng, _ = _engine(monkeypatch)
    eng.races = 3
    assert eng._counters()["races"] == 3
    assert eng.status()["races"] == 3


def test_status_ticker_delta_derives_d_races_for_free(monkeypatch):
    """_status_ticker()'s generic {f'd_{k}': cur[k]-prev[k]} comprehension over _counters()'s
    keys means 'races' needs no bespoke delta wiring -- just confirm the key round-trips."""
    eng, _ = _engine(monkeypatch)
    prev = eng._counters()
    eng.races = 2
    cur = eng._counters()
    assert cur["races"] - prev["races"] == 2


# ---------------------------------------------------------------- RACED_FREED_ADDRESSES finding
def test_raced_freed_addresses_finding_not_raised_with_no_races(monkeypatch):
    eng, events = _engine(monkeypatch)
    eng._finalize_findings()
    assert "RACED_FREED_ADDRESSES" not in _findings_by_id(events)


def test_raced_freed_addresses_finding_summarizes_outcomes(monkeypatch):
    eng, events = _engine(monkeypatch)
    eng.races = 4
    eng._race.outcomes = {
        1: "granted",
        2: "granted",
        3: "offered_different",
        4: "naked",
    }
    eng._finalize_findings()
    finding = _findings_by_id(events)["RACED_FREED_ADDRESSES"]
    assert finding.verdict == "INFO"
    assert finding.evidence["attempted"] == 4
    assert finding.evidence["won"] == 2
    assert finding.evidence["lost"] == 2
    assert finding.evidence["by_outcome"] == {
        "granted": 2,
        "offered_different": 1,
        "naked": 1,
    }


def test_raced_freed_addresses_finding_breaks_down_by_trigger(monkeypatch):
    eng, events = _engine(monkeypatch)
    eng.races = 3
    eng._race.outcomes = {1: "granted", 2: "granted", 3: "naked"}
    eng._race.triggers = {1: "nak", 2: "decline", 3: "nak"}
    eng._finalize_findings()
    finding = _findings_by_id(events)["RACED_FREED_ADDRESSES"]
    assert finding.evidence["by_trigger"] == {"nak": 2, "decline": 1}


def test_raced_freed_addresses_finding_gated_off_under_dry_run(monkeypatch):
    """Races still increment under dry-run (only _send()'s chokepoint suppresses the wire send),
    but the finding itself is gated off -- DRY_RUN_SUMMARY's would_race covers that case instead,
    same reasoning as the eviction findings block."""
    eng, events = _engine(monkeypatch, dry_run=True)
    eng.races = 2
    eng._race.outcomes = {1: "granted"}
    eng._finalize_findings()
    assert "RACED_FREED_ADDRESSES" not in _findings_by_id(events)


# ---------------------------------------------------------------- DRY_RUN_SUMMARY would_race
def test_dry_run_summary_includes_would_race(monkeypatch):
    eng, events = _engine(monkeypatch, dry_run=True)
    eng.races = 5
    eng._finalize_findings()
    finding = _findings_by_id(events)["DRY_RUN_SUMMARY"]
    assert finding.evidence["would_race"] == 5
