import json

import pytest

from dhcpig.cli import compat
from dhcpig.cli import main as cli
from dhcpig.core.models import IPVersion, Mode


def test_legacy_shim_preserves_single_mac_default():
    # legacy pig.py (no -S) meant single NIC MAC -> map to --no-spoof-eth-src
    assert "--no-spoof-eth-src" in compat.translate(["eth0"])
    # legacy -S meant spoof -> keep the (new) default, no opt-out injected
    assert "--no-spoof-eth-src" not in compat.translate(["-S", "eth0"])


def test_parse_request_options():
    assert cli.parse_request_options("12,14-16,23") == [12, 14, 15, 16, 23]


def test_build_config_exhaust_defaults():
    args = cli.build_parser().parse_args(["exhaust", "eth1"])
    cfg = cli.build_config(args)
    assert cfg.mode is Mode.EXHAUST
    assert cfg.ip_version is IPVersion.V4
    assert cfg.spoof_ethernet_src is True  # distinct L2 MACs by default


def test_exhaust_has_no_no_control_flag():
    """The control transaction is mandatory; there is no opt-out on exhaust."""
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["exhaust", "eth1", "--no-control"])


def test_exhaust_has_no_rate_flag_windowing_paces_it_instead():
    """--rate was removed from exhaust: the windowed handshake pipeline is the pacing now."""
    from dhcpig.core.models import EXHAUST_DEFAULT_RATE_PPS

    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["exhaust", "eth1", "--rate", "30"])
    cfg = cli.build_config(cli.build_parser().parse_args(["exhaust", "eth1"]))
    assert cfg.rate_limit_pps == EXHAUST_DEFAULT_RATE_PPS


def test_rate_flag_still_present_on_release_and_garp_and_active_scan():
    for cmd in ("release", "garp", "active-scan"):
        extra = ["--scope", "10.0.0.0/24"] if cmd == "active-scan" else []
        args = cli.build_parser().parse_args([cmd, "eth1", "--rate", "42", *extra])
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
    recognize a finished worker thread as 'this run is done' -- same as release/garp."""
    assert Mode.RELEASE_PREVIOUS in cli._RUN_ONCE_MODES
    assert Mode.RELEASE_PREVIOUS not in cli.DESTRUCTIVE_MODES


def test_build_config_release_neighbors_default_on_and_opt_out():
    args = cli.build_parser().parse_args(["exhaust", "eth1"])
    assert cli.build_config(args).release_neighbors is True
    args = cli.build_parser().parse_args(["exhaust", "eth1", "--no-release"])
    assert cli.build_config(args).release_neighbors is False


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
    """The gate is gone: release/garp parse with just an interface, and --scope is optional."""
    for cmd in ("release", "garp"):
        cfg = cli.build_config(cli.build_parser().parse_args([cmd, "eth1"]))
        assert cfg.scope_cidrs is None
        assert cfg.rate_limit_pps == 7
    cfg = cli.build_config(
        cli.build_parser().parse_args(["garp", "eth1", "--scope", "10.0.0.0/24"])
    )
    assert cfg.scope_cidrs == ["10.0.0.0/24"]


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


def test_bad_args_exit_2():
    with pytest.raises(SystemExit) as exc:
        cli.build_parser().parse_args(["exhaust"])  # missing interface
    assert exc.value.code == 2
