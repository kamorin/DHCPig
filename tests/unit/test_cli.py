import json

import pytest

from dhcpig.cli import main as cli
from dhcpig.core import engine as engine_mod
from dhcpig.core.models import IPVersion, Mode, SessionConfig


def test_parse_request_options():
    assert cli.parse_request_options("12,14-16,23") == [12, 14, 15, 16, 23]


def test_build_config_exhaust_defaults():
    args = cli.build_parser().parse_args(["exhaust", "eth1"])
    cfg = cli.build_config(args)
    assert cfg.mode is Mode.EXHAUST
    assert cfg.ip_version is IPVersion.V4
    assert cfg.spoof_ethernet_src is True  # distinct L2 MACs by default
    # None means "use the built-in macOS-order profile" -- see SessionConfig.request_options
    assert cfg.request_options is None


def test_request_option_reaches_the_config_on_exhaust_and_active_scan():
    for cmd in ("exhaust", "active-scan"):
        args = cli.build_parser().parse_args([cmd, "eth1", "--request-option", "12,14-16,23"])
        cfg = cli.build_config(args)
        assert cfg.request_options == [12, 14, 15, 16, 23]


def test_exhaust_has_no_no_control_flag():
    """The control transaction is mandatory; there is no opt-out on exhaust."""
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["exhaust", "eth1", "--no-control"])


def test_exhaust_and_release_have_no_rate_flag_windowing_paces_them_instead():
    """--rate was removed from exhaust and release: release's re-acquisition leg shares
    exhaust's windowed handshake pipeline, so the same pacing applies to both."""
    from dhcpig.core.models import EXHAUST_DEFAULT_RATE_PPS

    for cmd in ("exhaust", "release"):
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args([cmd, "eth1", "--rate", "30"])
        cfg = cli.build_config(cli.build_parser().parse_args([cmd, "eth1"]))
        assert cfg.rate_limit_pps == EXHAUST_DEFAULT_RATE_PPS


def test_rate_flag_still_present_on_active_scan():
    args = cli.build_parser().parse_args(
        ["active-scan", "eth1", "--rate", "42", "--scope", "10.0.0.0/24"]
    )
    assert cli.build_config(args).rate_limit_pps == 42


def test_release_previous_defaults():
    args = cli.build_parser().parse_args(["release-previous", "eth1"])
    cfg = cli.build_config(args)
    assert cfg.mode is Mode.RELEASE_PREVIOUS
    assert cfg.rate_limit_pps == 50  # faster than the 7pps used elsewhere -- see main.py
    assert cfg.max_age_days == 7.0
    assert cfg.require_same_server is True
    assert cfg.release_passes == 2
    assert cfg.journal_path is None  # resolves to journal.default_path() at engine construction
    assert cfg.mode not in cli.DESTRUCTIVE_MODES  # it only releases what the journal proves


def test_release_previous_flags():
    args = cli.build_parser().parse_args(
        [
            "release-previous",
            "eth1",
            "--journal",
            "/tmp/custom-journal.jsonl",
            "--scope",
            "172.20.0.0/24",
            "--max-age",
            "3.5",
            "--any-server",
            "--rate",
            "10",
            "--passes",
            "5",
            "--dry-run",
        ]
    )
    cfg = cli.build_config(args)
    assert str(cfg.journal_path) == "/tmp/custom-journal.jsonl"
    assert cfg.scope_cidrs == ["172.20.0.0/24"]
    assert cfg.max_age_days == 3.5
    assert cfg.require_same_server is False
    assert cfg.rate_limit_pps == 10
    assert cfg.release_passes == 5
    assert cfg.dry_run is True


def test_exhaust_journal_default_on_and_opt_out():
    args = cli.build_parser().parse_args(["exhaust", "eth1"])
    assert cli.build_config(args).journal is True
    args = cli.build_parser().parse_args(["exhaust", "eth1", "--no-journal"])
    assert cli.build_config(args).journal is False


def test_release_previous_appears_in_run_once_completion_modes():
    """release-previous is not DESTRUCTIVE, but it still needs the CLI's polling loop to
    recognize a finished worker thread as 'this run is done' -- same as release."""
    assert Mode.RELEASE_PREVIOUS in cli.RUN_ONCE_MODES
    assert Mode.RELEASE_PREVIOUS not in cli.DESTRUCTIVE_MODES


def test_arp_scan_and_release_flags_are_gone():
    """Both phases are unconditional now -- every later phase reads what they produce, so an
    opt-out hollowed out the run instead of just making it quicker."""
    for flag in ("--no-arp-scan", "--no-release"):
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args(["exhaust", "eth1", flag])
    cfg = cli.build_config(cli.build_parser().parse_args(["exhaust", "eth1"]))
    assert not hasattr(cfg, "arp_sweep")
    assert not hasattr(cfg, "release_neighbors")


def test_build_config_evict_default_on_and_opt_out():
    args = cli.build_parser().parse_args(["exhaust", "eth1"])
    assert cli.build_config(args).evict is True
    args = cli.build_parser().parse_args(["exhaust", "eth1", "--no-evict"])
    assert cli.build_config(args).evict is False


def test_build_config_evict_opt_out_also_available_on_release():
    """(2.3, Phase 5) release now runs eviction too -- --no-evict must skip it in both modes."""
    args = cli.build_parser().parse_args(["release", "eth1"])
    assert cli.build_config(args).evict is True
    args = cli.build_parser().parse_args(["release", "eth1", "--no-evict"])
    assert cli.build_config(args).evict is False


def test_build_config_race_freed_default_on_and_opt_out():
    args = cli.build_parser().parse_args(["exhaust", "eth1"])
    cfg = cli.build_config(args)
    assert cfg.race_freed_addresses is True
    assert cfg.race_on_rediscover is False
    args = cli.build_parser().parse_args(["exhaust", "eth1", "--no-race-freed"])
    assert cli.build_config(args).race_freed_addresses is False
    args = cli.build_parser().parse_args(["exhaust", "eth1", "--race-on-rediscover"])
    assert cli.build_config(args).race_on_rediscover is True


def test_race_freed_flags_not_available_on_release():
    """race-freed is exhaust-only (no concurrent flood in release to race against) -- the flags
    simply don't exist on that subcommand, rather than existing and doing nothing."""
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["release", "eth1", "--no-race-freed"])
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["release", "eth1", "--race-on-rediscover"])


def test_exhaust_has_no_restore_on_exit_flag():
    """Auto-restore-on-exit was removed -- release-previous is the caller-initiated recovery
    path now, so exhaust always keeps its leases until the operator explicitly releases them."""
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["exhaust", "eth1", "--restore-on-exit"])


def test_build_config_no_spoof_eth_src():
    args = cli.build_parser().parse_args(["exhaust", "eth1", "--no-spoof-eth-src"])
    cfg = cli.build_config(args)
    assert cfg.spoof_ethernet_src is False  # Wi-Fi opt-out: single real NIC MAC


def test_active_scan_mapping_and_explicit_scope():
    args = cli.build_parser().parse_args(["active-scan", "eth1", "--scope", "192.168.1.0/24"])
    cfg = cli.build_config(args)
    assert cfg.mode is Mode.ACTIVE_SCAN
    assert cfg.scope_cidrs == ["192.168.1.0/24"]


def test_build_config_ipv6_and_request_options():
    args = cli.build_parser().parse_args(["exhaust", "eth1", "--ipv6", "--request-option", "1,3,6"])
    cfg = cli.build_config(args)
    assert cfg.ip_version is IPVersion.V6
    assert cfg.request_options == [1, 3, 6]


def test_destructive_modes_take_no_authorization_flags():
    """The gate is gone: release parses with just an interface, and --scope is optional."""
    from dhcpig.core.models import EXHAUST_DEFAULT_RATE_PPS

    cfg = cli.build_config(cli.build_parser().parse_args(["release", "eth1"]))
    assert cfg.scope_cidrs is None
    assert cfg.rate_limit_pps == EXHAUST_DEFAULT_RATE_PPS
    cfg = cli.build_config(
        cli.build_parser().parse_args(["release", "eth1", "--scope", "10.0.0.0/24"])
    )
    assert cfg.scope_cidrs == ["10.0.0.0/24"]


def test_garp_subcommand_removed():
    """(2.3) GARP_DOS was retired as a standalone mode; ARP-conflict eviction now runs as part
    of exhaust/release instead of being invoked on its own."""
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["garp", "eth1"])
    assert not hasattr(Mode, "GARP_DOS")


def test_ifaces_command_runs():
    assert cli.main(["ifaces"]) == cli.EXIT_OK


def test_report_command(tmp_path):
    p = tmp_path / "r.json"
    p.write_text(
        json.dumps(
            {
                "mode": "exhaust",
                "interface": "eth1",
                "servers": [],
                "leases": [],
                "neighbors": [],
                "pool_exhausted": False,
            }
        )
    )
    assert cli.main(["report", str(p)]) == cli.EXIT_OK


def test_report_path_extension_selects_the_written_format(tmp_path, monkeypatch):
    """--report FILE used to always write JSON regardless of FILE's extension --
    recorder.export(cfg.report_path) was called with no fmt argument. _run_session() now infers
    it from the suffix, matching what SessionRecorder.render()/.export() already support."""
    monkeypatch.setattr(engine_mod, "sendp", lambda *a, **k: None)

    csv_path = tmp_path / "run.csv"
    cfg = SessionConfig(
        interface="lo", mode=Mode.RELEASE_NEIGHBORS, offline=True, report_path=csv_path
    )
    assert cli._run_session(cfg) == cli.EXIT_OK
    assert csv_path.read_text().splitlines()[0] == (
        "section,time,id,verdict,severity,attck,title,summary,"
        "kind,mac,ip,server_id,os,device,vendor,confidence"
    )

    html_path = tmp_path / "run.html"
    cfg = SessionConfig(
        interface="lo", mode=Mode.RELEASE_NEIGHBORS, offline=True, report_path=html_path
    )
    assert cli._run_session(cfg) == cli.EXIT_OK
    assert html_path.read_text().startswith("<!doctype html>")


def test_report_path_unrecognized_extension_falls_back_to_json(tmp_path, monkeypatch):
    monkeypatch.setattr(engine_mod, "sendp", lambda *a, **k: None)

    p = tmp_path / "run.txt"
    cfg = SessionConfig(interface="lo", mode=Mode.RELEASE_NEIGHBORS, offline=True, report_path=p)
    assert cli._run_session(cfg) == cli.EXIT_OK
    data = json.loads(p.read_text())
    assert data["tool"] == "dhcpig"


def test_bad_args_exit_2():
    with pytest.raises(SystemExit) as exc:
        cli.build_parser().parse_args(["exhaust"])  # missing interface
    assert exc.value.code == 2


def test_exhaust_accepts_scope_so_copy_as_cli_round_trips():
    """The web UI offers a Scope box for every mode, so as_cli() emits --scope for exhaust --
    but the exhaust subparser didn't accept it, making "Copy as CLI" produce a command that
    exits 2. Scope is real work in exhaust: it bounds the ARP sweep and _send()'s scope guard,
    and makes the pool estimate deterministic rather than inferred from the first OFFER."""
    import shlex

    from dhcpig.web.schemas import as_cli, config_from_payload

    cfg = config_from_payload(
        {"interface": "eth0", "mode": "exhaust", "scope_cidrs": ["192.168.4.0/22"]}
    )
    cmd = as_cli(cfg)
    assert "--scope 192.168.4.0/22" in cmd
    args = cli.build_parser().parse_args(shlex.split(cmd)[1:])  # must not SystemExit
    assert cli.build_config(args).scope_cidrs == ["192.168.4.0/22"]


class _StubEngine:
    """Minimal stand-in for DhcpEngine, exposing only what _run_session() touches.

    --fail-on is pure exit-code logic over the findings a run ended with, so these state the
    findings directly rather than contriving a live run that happens to raise them.
    """

    def __init__(self, findings):
        self.findings = findings
        self.state = engine_mod.DONE
        self.discovers, self.servers, self._threads = [], [], []

    def start(self):
        pass

    def stop(self):
        pass

    def status(self):
        return dict.fromkeys(("leases", "servers", "naks", "releases", "arp_conflicts"), 0)


def _rc_for(monkeypatch, verdicts, fail_on):
    from dhcpig.core.models import Finding

    findings = [Finding(id="X", title="t", verdict=v, severity="high") for v in verdicts]
    monkeypatch.setattr(cli, "DhcpEngine", lambda cfg, bus: _StubEngine(findings))
    cfg = SessionConfig(interface="lo", mode=Mode.RELEASE_NEIGHBORS, offline=True)
    return cli._run_session(cfg, fail_on=fail_on)


def test_fail_on_defaults_to_never_so_a_fail_finding_still_exits_zero(monkeypatch):
    """Exit 0 has always meant "the run worked", and every existing caller reads it that way.
    Carrying the verdict in the exit status is opt-in, never the default."""
    assert _rc_for(monkeypatch, ["FAIL"], "never") == cli.EXIT_OK


def test_fail_on_fail_exits_one_so_a_scoring_script_can_branch(monkeypatch):
    assert _rc_for(monkeypatch, ["INFO", "FAIL"], "fail") == cli.EXIT_FINDING
    assert _rc_for(monkeypatch, ["INFO", "PASS"], "fail") == cli.EXIT_OK


def test_fail_on_inconclusive_is_the_wider_threshold(monkeypatch):
    """An inconclusive run is a result a lab wants to catch -- usually a broken baseline, which
    means the segment was never actually tested. --fail-on fail deliberately lets it pass."""
    assert _rc_for(monkeypatch, ["INCONCLUSIVE"], "inconclusive") == cli.EXIT_FINDING
    assert _rc_for(monkeypatch, ["INCONCLUSIVE"], "fail") == cli.EXIT_OK
    assert _rc_for(monkeypatch, ["FAIL"], "inconclusive") == cli.EXIT_FINDING


def test_fail_on_parses_on_every_mode_and_defaults_to_never():
    for cmd in ("exhaust", "scan", "active-scan", "release", "release-previous"):
        assert cli.build_parser().parse_args([cmd, "eth1"]).fail_on == "never"
    assert cli.build_parser().parse_args(["exhaust", "eth1", "--fail-on", "fail"]).fail_on == "fail"
    with pytest.raises(SystemExit):  # not a free-form string
        cli.build_parser().parse_args(["exhaust", "eth1", "--fail-on", "high"])
