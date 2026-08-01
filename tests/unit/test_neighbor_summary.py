"""NeighborSummary (2.3.3): end-of-run roll-call of who this run affected, on the event log.

One row per host, every discovered host listed. The category boundaries are the point of this
file: "lease_taken" hosts are working at the moment the summary is emitted but will fail at
their next renewal, so folding them into either neighbouring category misreports the run -- see
the event's docstring.
"""

from conftest import build_engine

from dhcpig.cli.render import Renderer
from dhcpig.core.events import FindingRaised, NeighborSummary
from dhcpig.core.models import Mode, Neighbor


def _engine(monkeypatch, **cfg):
    cfg.setdefault("interface", "wlan0")
    cfg.setdefault("mode", Mode.EXHAUST)
    cfg.setdefault("offline", True)
    eng, events, _sent = build_engine(monkeypatch, **cfg)
    return eng, events


def _neighbors(eng, n):
    ips = [f"10.0.0.{i}" for i in range(1, n + 1)]
    for i, ip in enumerate(ips):
        mac = f"aa:bb:cc:00:00:{i:02x}"
        eng._neighbors_by_mac[mac] = Neighbor(mac=mac, ip=ip)
    return ips


def _reacquired(eng, ips):
    """Mark `ips` as addresses the server handed us back (re-acquisition granted)."""
    eng._reacquire_targets = dict(enumerate(ips))
    eng._reacquire_outcomes = dict.fromkeys(range(len(ips)), "granted")


def _summary(events):
    return next(e for e in events if isinstance(e, NeighborSummary))


def _by_category(events):
    out: dict[str, list[str]] = {}
    for ip, _mac, _host, _outcome, category in _summary(events).rows:
        out.setdefault(category, []).append(ip)
    return out


def _denied(eng, macs):
    """Mark `macs` as having DISCOVERed during the run and got no answer."""
    for i, mac in enumerate(macs):
        eng._foreign_discovers[i] = {"mac": mac, "hostname": None, "ts": 0.0, "answered": False}


# ---------------------------------------------------------------- emission
def test_every_discovered_neighbor_gets_exactly_one_row(monkeypatch):
    """A roll-call that omits the hosts nothing happened to isn't a roll-call -- the reader
    can't tell 'unaffected' from 'not examined'."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 6)
    eng._emit_neighbor_summary()
    s = _summary(events)
    assert s.total == 6
    assert len(s.rows) == 6
    assert [row[0] for row in s.rows] == ips  # all listed, none dropped
    assert {row[4] for row in s.rows} == {"unaffected"}


def test_no_summary_when_no_neighbors_were_discovered(monkeypatch):
    """An empty roll-call is noise -- scan never sweeps, and an empty segment has nothing
    to report."""
    eng, events = _engine(monkeypatch)
    eng._emit_neighbor_summary()
    assert not [e for e in events if isinstance(e, NeighborSummary)]


def test_rows_are_sorted_worst_first_then_by_address(monkeypatch):
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 12)  # 10.0.0.1 .. 10.0.0.12, so octet vs lexical order differ
    _reacquired(eng, [ips[5]])
    eng._evict.outcomes = {ips[11]: "apipa", ips[2]: "defended"}
    eng._emit_neighbor_summary()
    cats = [row[4] for row in _summary(events).rows]
    assert cats[0] == "offline"
    assert cats.index("lease_taken") < cats.index("reacted") < cats.index("unaffected")
    unaffected_ips = [row[0] for row in _summary(events).rows if row[4] == "unaffected"]
    assert unaffected_ips == sorted(unaffected_ips, key=lambda s: int(s.rsplit(".", 1)[1]))


# ---------------------------------------------------------------- category boundaries
def test_only_rungs_meaning_no_working_address_count_as_offline(monkeypatch):
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 6)
    eng._evict.outcomes = {
        ips[0]: "apipa",
        ips[1]: "discover_unanswered",
        ips[2]: "rediscovered",  # restarted but WAS served -- online, new address
        ips[3]: "declined",
        ips[4]: "defended",
        ips[5]: "no_reaction",
    }
    eng._emit_neighbor_summary()
    cats = _by_category(events)
    assert set(cats["offline"]) == {ips[0], ips[1]}
    assert set(cats["reacted"]) == {ips[2], ips[3], ips[4]}
    assert cats["unaffected"] == [ips[5]]  # no_reaction, and we never took its lease


def test_pool_exhaustion_denial_counts_as_offline_without_any_eviction(monkeypatch):
    """The whole point of exhaust is to deny service. A neighbor that asked for an address
    during the run and got none was knocked offline by the drained pool, even though we never
    contested its address by ARP -- reading only _evict_outcomes reported it as unaffected."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 3)
    _denied(eng, ["aa:bb:cc:00:00:01"])
    eng._emit_neighbor_summary()
    cats = _by_category(events)
    assert cats["offline"] == [ips[1]]
    assert set(cats["unaffected"]) == {ips[0], ips[2]}
    outcome = next(r[3] for r in _summary(events).rows if r[0] == ips[1])
    assert "pool drained" in outcome


def test_a_neighbor_whose_discover_was_answered_is_not_reported_offline(monkeypatch):
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 2)
    eng._foreign_discovers[1] = {
        "mac": "aa:bb:cc:00:00:00",
        "hostname": None,
        "ts": 0.0,
        "answered": True,
    }
    eng._emit_neighbor_summary()
    assert _by_category(events) == {"unaffected": ips}


def test_host_whose_lease_we_hold_is_neither_offline_nor_unaffected(monkeypatch):
    """The category that exists because both neighbouring answers are wrong: it works right
    now, so it isn't offline; it fails at T1 with no warning, so it isn't unaffected either."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 2)
    _reacquired(eng, [ips[0]])
    eng._emit_neighbor_summary()
    cats = _by_category(events)
    assert cats["lease_taken"] == [ips[0]]
    assert "offline" not in cats
    assert cats["unaffected"] == [ips[1]]


def test_reacquisition_that_was_not_granted_does_not_count_as_lease_taken(monkeypatch):
    """offered_different / naked / no_response mean we never got that address."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 3)
    eng._reacquire_targets = dict(enumerate(ips))
    eng._reacquire_outcomes = {0: "offered_different", 1: "naked", 2: "no_response"}
    eng._emit_neighbor_summary()
    assert _by_category(events) == {"unaffected": ips}


def test_eviction_outcome_wins_over_the_inferred_states(monkeypatch):
    """Eviction only ever targets addresses re-acquisition granted, so every evicted host is
    also a lease_taken candidate -- the observed reaction is the better evidence, so it wins."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 1)
    _reacquired(eng, ips)
    _denied(eng, ["aa:bb:cc:00:00:00"])
    eng._evict.outcomes = {ips[0]: "defended"}
    eng._emit_neighbor_summary()
    assert _by_category(events) == {"reacted": ips}


def _named(eng, mac, hostname, answered=True):
    """A foreign DISCOVER from `mac` carrying DHCP option 12 -- the only hostname source."""
    eng._foreign_discovers[hash(mac) & 0xFFFF] = {
        "mac": mac,
        "hostname": hostname,
        "ts": 0.0,
        "answered": answered,
    }


def test_hostname_is_picked_up_from_a_foreign_discover(monkeypatch):
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 2)
    _named(eng, "aa:bb:cc:00:00:01", "laptop-07")
    eng._emit_neighbor_summary()
    hosts = {row[0]: row[2] for row in _summary(events).rows}
    assert hosts[ips[1]] == "laptop-07"
    assert hosts[ips[0]] == ""  # ARP-only neighbour: no option 12 ever seen, so no guess


def test_cli_shows_a_hostname_column_only_when_one_is_known(capsys, monkeypatch):
    """DHCP option 12 is the only source, so most segments have none -- an always-on column
    would just sit blank."""
    eng, events = _engine(monkeypatch)
    _neighbors(eng, 2)
    eng._emit_neighbor_summary()
    Renderer(verbosity=2, color=False).handle(_summary(events))
    bare = capsys.readouterr().out
    assert "10.0.0.1        aa:bb:cc:00:00:00  unaffected" in bare  # no gap for a name

    eng2, events2 = _engine(monkeypatch)
    _neighbors(eng2, 2)
    _named(eng2, "aa:bb:cc:00:00:01", "laptop-07")
    eng2._emit_neighbor_summary()
    Renderer(verbosity=2, color=False).handle(_summary(events2))
    named = capsys.readouterr().out
    assert "aa:bb:cc:00:00:01  laptop-07  unaffected" in named
    # the nameless host keeps its columns lined up with the named one
    assert "aa:bb:cc:00:00:00             unaffected" in named


def test_rows_carry_ip_mac_outcome_and_category(monkeypatch):
    """The operator's next move is to go look at a specific machine, so name it."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 1)
    eng._evict.outcomes = {ips[0]: "apipa"}
    eng._emit_neighbor_summary()
    ip, mac, _host, outcome, category = _summary(events).rows[0]
    assert (ip, mac, category) == (ips[0], "aa:bb:cc:00:00:00", "offline")
    assert "169.254" in outcome


# ---------------------------------------------------------------- run wiring
def test_stop_emits_the_summary_last_so_the_run_ends_on_it(monkeypatch):
    """The roll-call plus its outcome roll-up is the conclusion an operator reads, so it should
    be the last thing on the log rather than something scrolled past on the way to a verdict."""
    eng, events = _engine(monkeypatch)
    _neighbors(eng, 2)
    eng._started = 1.0
    eng.stop()
    kinds = [type(e).__name__ for e in events]
    assert "NeighborSummary" in kinds
    assert kinds.index("NeighborSummary") > kinds.index("FindingRaised")


# ---------------------------------------------------------------- CLI rendering
def test_cli_prints_one_line_per_host_for_every_host(capsys, monkeypatch):
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 4)
    _reacquired(eng, ips[:2])
    eng._evict.outcomes = {ips[0]: "apipa"}
    eng._emit_neighbor_summary()
    r = Renderer(verbosity=2, color=False)
    r.handle(_summary(events))
    out = capsys.readouterr().out
    lines = out.splitlines()
    hosts = lines[1 : lines.index("[==] OUTCOME")]

    assert "NEIGHBOR SUMMARY  4 host(s) seen" in out
    assert len(hosts) == 4  # every host, one line each -- including the untouched ones
    for i, ip in enumerate(ips):
        assert any(ip in ln and f"aa:bb:cc:00:00:{i:02x}" in ln for ln in hosts)
    assert "fails at next renewal" in out


def test_cli_ends_with_an_outcome_rollup_counting_hosts_per_outcome(capsys, monkeypatch):
    """ "N host(s) did X" -- the same data as the per-host lines, aggregated, and phrased as
    counts rather than as a verdict. The findings own pass/fail; a second differently-worded
    judgement of the same run on the log is exactly the drift to avoid."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 4)
    eng._evict.outcomes = {ips[0]: "apipa", ips[1]: "defended"}
    eng._emit_neighbor_summary()
    Renderer(verbosity=2, color=False).handle(_summary(events))
    out = capsys.readouterr().out
    tail = out.split("[==] OUTCOME\n")[1]

    assert "1 host(s)  no address -- fell back to 169.254 (apipa)" in tail
    assert "1 host(s)  defended its address" in tail
    assert "2 host(s)  unaffected" in tail
    assert tail.count("host(s)") == 3  # one line per distinct outcome, not per host
    for word in ("FAIL", "PASS", "vulnerable"):
        assert word not in tail


def test_cli_finding_line_shows_no_verdict_word_but_the_verdict_survives(capsys):
    """The log says what happened; the report says whether it passed. A bare [FAIL] beside a
    title mid-run reads as a judgement on the operator's network, and the run's conclusion is
    the OUTCOME roll-up instead. `verdict` itself is untouched -- it still colours the line and
    still reaches report["findings"]."""
    from dhcpig.core.models import Finding

    f = Finding(
        id="CLIENTS_EVICTED_FROM_ADDRESSES",
        title="ARP-conflict eviction forced clients off their addresses",
        verdict="FAIL",
        severity="high",
    )
    Renderer(verbosity=2, color=False)._finding(f)
    out = capsys.readouterr().out
    assert "FAIL" not in out
    assert "ARP-conflict eviction forced clients off their addresses" in out
    assert "(CLIENTS_EVICTED_FROM_ADDRESSES)" in out
    assert f.verdict == "FAIL"  # the report still gets a real verdict


def test_cli_summary_is_silent_at_verbosity_zero(capsys, monkeypatch):
    eng, events = _engine(monkeypatch)
    _neighbors(eng, 2)
    eng._emit_neighbor_summary()
    Renderer(verbosity=0, color=False).handle(_summary(events))
    assert capsys.readouterr().out == ""


# ---------------------------------------------------------------- NEIGHBORS_OBSERVED finding
def _observed(events):
    return next(
        e.finding
        for e in events
        if isinstance(e, FindingRaised) and e.finding.id == "NEIGHBORS_OBSERVED"
    )


def test_rollcall_also_reaches_the_findings_for_every_mode(monkeypatch):
    """NeighborSummary is a live event and never lands in report["findings"], so without this
    the roll-call vanished from the JSON/HTML exports."""
    for mode in Mode:
        eng, events = _engine(monkeypatch, mode=mode)
        ips = _neighbors(eng, 3)
        eng._finalize_findings()
        f = _observed(events)
        assert f.verdict == "INFO"
        assert f.evidence["total"] == 3
        assert len(f.evidence["hosts"]) == 3
        for ip in ips:
            assert any(ip in line for line in f.evidence["hosts"])


def test_finding_and_event_never_disagree_about_a_host(monkeypatch):
    """Both read _neighbor_rollcall(); neither classifies anything itself."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 4)
    _reacquired(eng, [ips[0]])
    eng._evict.outcomes = {ips[1]: "apipa"}
    eng._emit_neighbor_summary()
    eng._finalize_findings()
    rows = _summary(events).rows
    namew = max(len(h) for *_r, h, _o, _c in rows)
    assert _observed(events).evidence["hosts"] == [
        f"{ip:<15} {mac}  " + (f"{h:<{namew}}  " if namew else "") + outcome
        for ip, mac, h, outcome, _c in rows
    ]


def test_finding_carries_a_category_tally(monkeypatch):
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 4)
    _reacquired(eng, [ips[0]])
    eng._evict.outcomes = {ips[1]: "apipa", ips[2]: "defended"}
    eng._finalize_findings()
    assert _observed(events).evidence["by_category"] == {
        "offline": 1,
        "lease_taken": 1,
        "reacted": 1,
        "unaffected": 1,
    }


def test_no_finding_when_no_neighbors_were_seen(monkeypatch):
    eng, events = _engine(monkeypatch)
    eng._finalize_findings()
    assert not [
        e for e in events if isinstance(e, FindingRaised) and e.finding.id == "NEIGHBORS_OBSERVED"
    ]


def test_finding_follows_run_summary_so_the_report_reads_in_order(monkeypatch):
    eng, events = _engine(monkeypatch)
    _neighbors(eng, 2)
    eng._finalize_findings()
    ids = [e.finding.id for e in events if isinstance(e, FindingRaised)]
    assert ids[:2] == ["RUN_SUMMARY", "NEIGHBORS_OBSERVED"]
