"""NeighborSummary (2.3.3): end-of-run roll-call of who this run affected, on the event log.

One row per host, every discovered host listed. The category boundaries are the point of this
file: "lease_taken" hosts are working at the moment the summary is emitted but will fail at
their next renewal, so folding them into either neighbouring category misreports the run -- see
the event's docstring.
"""

from conftest import build_engine

from dhcpig.cli.render import Renderer
from dhcpig.core.events import FindingRaised, NeighborSummary
from dhcpig.core.models import HostFingerprint, Mode, Neighbor


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
    for ip, _mac, _host, _outcome, category, _device in _summary(events).rows:
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
    """offered_different / naked / no_response mean we never got that address -- so it's not
    lease_taken. It's also not unaffected (2.7.3): a forged RELEASE genuinely went out naming
    each of these, we just can't tell if the server acted on it."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 3)
    eng._reacquire_targets = dict(enumerate(ips))
    eng._reacquire_outcomes = {0: "offered_different", 1: "naked", 2: "no_response"}
    eng._emit_neighbor_summary()
    assert _by_category(events) == {"released_unconfirmed": ips}
    assert "lease_taken" not in _by_category(events)


def test_released_but_not_reacquired_is_not_unaffected(monkeypatch):
    """(2.7.3) The exact scenario a live release run hits constantly: RFC 2131 rule 4 beats
    rule 3 while the pool has headroom, so offered_different is the *expected* answer whether
    or not the server honoured the forged RELEASE -- `unaffected` overclaimed certainty this
    run doesn't have. See `_finish_release()`'s docstring for the rule 3/4 reasoning."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 1)
    eng._reacquire_targets = {0: ips[0]}
    eng._reacquire_outcomes = {0: "offered_different"}
    eng._emit_neighbor_summary()
    cats = _by_category(events)
    assert cats == {"released_unconfirmed": ips}
    outcome = next(r[3] for r in _summary(events).rows if r[0] == ips[0])
    assert "RELEASE sent" in outcome
    assert "unknown" in outcome
    assert "ARP-conflicted" not in outcome  # never became an eviction target


def test_released_unconfirmed_ranks_between_reacted_and_unaffected(monkeypatch):
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 3)
    _reacquired(eng, [ips[0]])  # lease_taken -> reacted once we add a rung
    eng._evict.outcomes = {ips[0]: "rediscovered"}
    eng._reacquire_targets[1] = ips[1]
    eng._reacquire_outcomes[1] = "naked"
    # ips[2] stays completely untouched -- unaffected
    eng._emit_neighbor_summary()
    cats = [row[4] for row in _summary(events).rows]
    assert cats.index("reacted") < cats.index("released_unconfirmed") < cats.index("unaffected")


def test_eviction_outcome_wins_over_the_inferred_states(monkeypatch):
    """Eviction only ever targets addresses re-acquisition granted, so every evicted host is
    also a lease_taken candidate -- the observed reaction is the better evidence, so it wins.
    `rediscovered` in particular means the host is no longer on the address we took at all."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 1)
    _reacquired(eng, ips)
    _denied(eng, ["aa:bb:cc:00:00:00"])
    eng._evict.outcomes = {ips[0]: "rediscovered"}
    eng._emit_neighbor_summary()
    assert _by_category(events) == {"reacted": ips}


def test_defending_an_address_we_hold_the_lease_for_is_lease_taken_not_reacted(monkeypatch):
    """(2.7.1) The one rung that does *not* outrank the inferred state. Defending settles the
    ARP exchange, not the lease -- and eviction only targets addresses the server already
    reassigned to us, so this host is on a binding that dies at its next renewal, exactly like
    a silent lease_taken one. Calling it "reacted" reported the packets and buried the outcome.
    """
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 2)
    _reacquired(eng, [ips[0]])
    eng._evict.outcomes = {ips[0]: "defended"}
    eng._emit_neighbor_summary()
    assert _by_category(events) == {"lease_taken": [ips[0]], "unaffected": [ips[1]]}
    outcome = next(r[3] for r in _summary(events).rows if r[0] == ips[0])
    assert "defended" in outcome and "fails at next renewal" in outcome


def test_defending_an_address_we_did_not_take_is_still_reacted(monkeypatch):
    """The boundary the test above depends on: without a granted re-acquisition for that IP,
    a defence is just a defence and the host really is fine."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 1)
    eng._evict.outcomes = {ips[0]: "defended"}
    eng._emit_neighbor_summary()
    assert _by_category(events) == {"reacted": ips}


def test_outright_denial_still_outranks_a_stolen_lease(monkeypatch):
    """lease_taken is a *future* outage. A host that asked for an address during the run and
    got none is offline now, which is worse and is what the row must say."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 1)
    _reacquired(eng, ips)
    _denied(eng, ["aa:bb:cc:00:00:00"])
    eng._evict.outcomes = {ips[0]: "defended"}
    eng._emit_neighbor_summary()
    assert _by_category(events) == {"offline": ips}


def test_renewal_bound_is_an_upper_bound_from_our_own_lease_and_omitted_when_unknown(monkeypatch):
    """We know the pool's lease duration L (the server gave us one for this very address) but
    not when the victim got its own lease, so the only honest statement is "within ~L/2" --
    never a countdown. With no lease on file, the row says nothing rather than guessing."""
    from dhcpig.core.models import IPVersion, Lease

    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 1)
    _reacquired(eng, ips)
    eng._emit_neighbor_summary()
    assert "within" not in next(r[3] for r in _summary(events).rows if r[0] == ips[0])

    eng.cleanup.register(
        Lease("de:ad:00:00:00:99", ips[0], "10.0.0.254", 1, IPVersion.V4, lease_time=86400)
    )
    events.clear()
    eng._emit_neighbor_summary()
    assert "(within ~12h)" in next(r[3] for r in _summary(events).rows if r[0] == ips[0])


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


def test_device_label_is_picked_up_from_the_neighbor_fingerprint(monkeypatch):
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 2)
    mac = "aa:bb:cc:00:00:01"
    eng._neighbors_by_mac[mac] = Neighbor(
        mac=mac,
        ip=ips[1],
        fingerprint=HostFingerprint(
            mac=mac, ip=ips[1], role="neighbor", os="Windows 10", vendor="Microsoft Corp."
        ),
    )
    eng._emit_neighbor_summary()
    devices = {row[0]: row[5] for row in _summary(events).rows}
    assert devices[ips[1]] == "Windows 10 (Microsoft Corp.)"
    assert devices[ips[0]] == ""  # never fingerprinted: no guess, same treatment as hostname


def test_device_label_omits_vendor_when_vendor_is_already_in_the_os_string(monkeypatch):
    """`fp.os` alone is enough when it already names the vendor -- "Android (Android)" would be
    a name repeated for no reason."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 1)
    mac = "aa:bb:cc:00:00:00"
    eng._neighbors_by_mac[mac] = Neighbor(
        mac=mac,
        ip=ips[0],
        fingerprint=HostFingerprint(
            mac=mac, ip=ips[0], role="neighbor", os="Android 2.3", vendor="Android"
        ),
    )
    eng._emit_neighbor_summary()
    assert _summary(events).rows[0][5] == "Android 2.3"


def test_device_label_falls_back_to_device_then_vendor_when_no_os(monkeypatch):
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 2)
    mac0, mac1 = "aa:bb:cc:00:00:00", "aa:bb:cc:00:00:01"
    eng._neighbors_by_mac[mac0] = Neighbor(
        mac=mac0,
        ip=ips[0],
        fingerprint=HostFingerprint(
            mac=mac0, ip=ips[0], role="neighbor", device="UPS", vendor="APC"
        ),
    )
    eng._neighbors_by_mac[mac1] = Neighbor(
        mac=mac1,
        ip=ips[1],
        fingerprint=HostFingerprint(mac=mac1, ip=ips[1], role="neighbor", vendor="VMware, Inc."),
    )
    eng._emit_neighbor_summary()
    devices = {row[0]: row[5] for row in _summary(events).rows}
    assert devices[ips[0]] == "UPS"  # device wins over vendor when there's no os
    assert devices[ips[1]] == "VMware, Inc."  # vendor is the only signal at all


def test_cli_and_web_findings_never_show_the_device_column(monkeypatch):
    """The device/OS tag is deliberately CLI/web-log-only -- the durable NEIGHBORS_OBSERVED
    finding's evidence stays outcome-only, so the JSON/HTML/CSV export doesn't gain a column
    the rest of that finding's schema never had."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 1)
    mac = "aa:bb:cc:00:00:00"
    eng._neighbors_by_mac[mac] = Neighbor(
        mac=mac,
        ip=ips[0],
        fingerprint=HostFingerprint(mac=mac, ip=ips[0], role="neighbor", os="Windows 10"),
    )
    eng._finalize_findings()
    line = _observed(events).evidence["hosts"][0]
    assert mac in line
    assert "Windows 10" not in line


def test_cli_shows_a_hostname_column_only_when_one_is_known(capsys, monkeypatch):
    """DHCP option 12 is the only source, so most segments have none -- an always-on column
    would just sit blank."""
    eng, events = _engine(monkeypatch)
    _neighbors(eng, 2)
    eng._emit_neighbor_summary()
    Renderer(verbosity=2, color=False).handle(_summary(events))
    bare = capsys.readouterr().out
    assert "10.0.0.1        aa:bb:cc:00:00:00  observed only" in bare  # no gap for a name

    eng2, events2 = _engine(monkeypatch)
    _neighbors(eng2, 2)
    _named(eng2, "aa:bb:cc:00:00:01", "laptop-07")
    eng2._emit_neighbor_summary()
    Renderer(verbosity=2, color=False).handle(_summary(events2))
    named = capsys.readouterr().out
    assert "aa:bb:cc:00:00:01  laptop-07  observed only" in named
    # the nameless host keeps its columns lined up with the named one
    assert "aa:bb:cc:00:00:00             observed only" in named


def test_rows_carry_ip_mac_outcome_and_category(monkeypatch):
    """The operator's next move is to go look at a specific machine, so name it."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 1)
    eng._evict.outcomes = {ips[0]: "apipa"}
    eng._emit_neighbor_summary()
    ip, mac, _host, outcome, category, _device = _summary(events).rows[0]
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
def test_cli_prints_one_merged_outcome_section_not_two_headers(capsys, monkeypatch):
    """(2.7.2) Per-host detail and the aggregate tally used to sit under two headers
    (NEIGHBOR SUMMARY, then OUTCOME) -- now there is exactly one, since they're the same
    outcome, not two different findings about the run."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 4)
    _reacquired(eng, ips[:2])
    eng._evict.outcomes = {ips[0]: "apipa"}
    eng._emit_neighbor_summary()
    r = Renderer(verbosity=2, color=False)
    r.handle(_summary(events))
    out = capsys.readouterr().out
    lines = out.splitlines()

    assert "NEIGHBOR SUMMARY" not in out
    assert lines[0] == "[==] OUTCOME  4 host(s) seen before this run"
    assert lines.count("[==] OUTCOME  4 host(s) seen before this run") == 1
    hosts = lines[1:5]  # one line per host, in the order emitted -- including untouched ones
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
    lines = out.splitlines()
    tail = "\n".join(lines[5:])  # header + 4 per-host rows, then the tally

    assert "1 host(s)  ARP-conflicted -> no address -- fell back to 169.254 (apipa)" in tail
    assert "1 host(s)  ARP-conflicted -> defended its address" in tail
    assert "2 host(s)  observed only" in tail
    assert tail.count("host(s)") == 3  # one line per distinct outcome, not per host
    for word in ("FAIL", "PASS", "vulnerable"):
        assert word not in tail


def test_cli_outcome_rows_flag_eviction_targets_as_arp_conflicted(capsys, monkeypatch):
    """(2.7.2) A row for a host this run actually contested by ARP says so, even when the
    category it lands in was decided by something else (here, pool exhaustion) -- the operator
    shouldn't have to cross-reference the live evict-outcome lines to know it was targeted."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 2)
    _reacquired(eng, [ips[0]])
    _denied(eng, ["aa:bb:cc:00:00:00"])
    eng._evict.outcomes = {ips[0]: "no_reaction"}
    eng._emit_neighbor_summary()
    Renderer(verbosity=2, color=False).handle(_summary(events))
    out = capsys.readouterr().out
    row0 = next(ln for ln in out.splitlines() if ips[0] in ln)
    row1 = next(ln for ln in out.splitlines() if ips[1] in ln)
    assert "ARP-conflicted ->" in row0
    assert "ARP-conflicted ->" not in row1  # never targeted -- nothing to flag


def test_release_sent_prefix_appears_on_every_category_that_was_actually_released(monkeypatch):
    """(2.7.3) `RELEASE sent -> ` isn't specific to `released_unconfirmed` -- every one of
    these hosts had a forged RELEASE sent for it (lease_taken/reacted/this offline row all
    require `granted`, which is a subset of `released_ips`), and the row should say so, not
    just the one category built around not knowing what happened next. Order is chronological:
    RELEASE happens before the ARP conflict in every mode, so the prefix reads in that order."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 4)
    _reacquired(eng, ips[:3])
    eng._evict.outcomes = {
        ips[0]: "no_reaction",  # -> lease_taken
        ips[1]: "rediscovered",  # -> reacted
        ips[2]: "discover_unanswered",  # -> offline
    }
    # ips[3]: never released, never touched -- the control case
    eng._emit_neighbor_summary()
    rows = {r[0]: r[3] for r in _summary(events).rows}
    assert rows[ips[0]].startswith("RELEASE sent -> ARP-conflicted -> lease taken by us")
    assert rows[ips[1]].startswith("RELEASE sent -> ARP-conflicted -> restarted")
    assert rows[ips[2]].startswith("RELEASE sent -> ARP-conflicted -> asked for an address")
    assert rows[ips[3]] == "observed only"


def test_release_sent_prefix_never_doubles_up_on_released_unconfirmed(monkeypatch):
    """released_unconfirmed's own sentence already says a RELEASE went out -- prefixing it
    with "RELEASE sent -> " on top would just repeat the first four words of its own text."""
    eng, events = _engine(monkeypatch)
    ips = _neighbors(eng, 1)
    eng._reacquire_targets = {0: ips[0]}
    eng._reacquire_outcomes = {0: "naked"}
    eng._emit_neighbor_summary()
    outcome = next(r[3] for r in _summary(events).rows if r[0] == ips[0])
    assert outcome.startswith("RELEASE sent in its name")
    assert outcome.count("RELEASE sent") == 1


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
    namew = max(len(row[2]) for row in rows)
    assert _observed(events).evidence["hosts"] == [
        f"{ip:<15} {mac}  " + (f"{h:<{namew}}  " if namew else "") + outcome
        for ip, mac, h, outcome, _category, _device in rows
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
