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
    args = cli.build_parser().parse_args(["exhaust", "eth1", "--rate", "30"])
    cfg = cli.build_config(args)
    assert cfg.mode is Mode.EXHAUST
    assert cfg.rate_limit_pps == 30
    assert cfg.ip_version is IPVersion.V4
    assert cfg.spoof_ethernet_src is True  # distinct L2 MACs by default
    assert cfg.restore_on_exit is False  # keep leases so the exhausted state can be verified
    assert cfg.control is True


def test_build_config_restore_on_exit_opt_in():
    args = cli.build_parser().parse_args(["exhaust", "eth1", "--restore-on-exit"])
    assert cli.build_config(args).restore_on_exit is True


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


def test_release_without_flags_exits_unauthorized():
    args = cli.build_parser().parse_args(["release", "eth1"])
    cfg = cli.build_config(args)
    assert cli._run_session(cfg, yes=True) == cli.EXIT_UNAUTH


def test_garp_without_scope_exits_unauthorized():
    args = cli.build_parser().parse_args(["garp", "eth1", "--i-am-authorized"])
    cfg = cli.build_config(args)
    assert cli._run_session(cfg, yes=True) == cli.EXIT_UNAUTH


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
