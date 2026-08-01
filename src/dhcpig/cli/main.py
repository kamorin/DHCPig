"""dhcpig command-line interface (V1.0).

Subcommands: exhaust | scan | active-scan | release | release-previous | restore | ifaces | report
Exit codes: 0 ok · 2 bad args · 3 no DHCP server · 130 interrupted
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from ..core.engine import DONE, EXHAUSTED, DhcpEngine
from ..core.events import EventBus
from ..core.exceptions import ConfigError
from ..core.models import (
    DESTRUCTIVE_MODES,  # noqa: F401 -- re-exported: tests assert against cli.DESTRUCTIVE_MODES
    EXHAUST_DEFAULT_RATE_PPS,
    RUN_ONCE_MODES,
    IPVersion,
    Mode,
    SessionConfig,
    Timeouts,
)
from ..core.reporting import SessionRecorder
from .render import Renderer

EXIT_OK, EXIT_BADARGS, EXIT_NOSERVER, EXIT_INTERRUPT = 0, 2, 3, 130

_MODE_BY_CMD = {
    "exhaust": Mode.EXHAUST,
    "scan": Mode.SCAN,
    "active-scan": Mode.ACTIVE_SCAN,
    "release": Mode.RELEASE_NEIGHBORS,
    "release-previous": Mode.RELEASE_PREVIOUS,
}


# --------------------------------------------------------------------------- parsing
def parse_request_options(spec: str) -> list[int]:
    """'12,14-19,23' -> [12,14,15,16,17,18,19,23]."""
    out: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dhcpig", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp):
        sp.add_argument("interface")
        sp.add_argument("--ipv6", action="store_true", help="DHCPv6 (default v4)")
        sp.add_argument("--report", metavar="FILE", help="write a JSON session report")
        sp.add_argument("-v", "--verbosity", type=int, default=2, help="0..3")
        sp.add_argument(
            "--status-interval",
            type=float,
            default=5.0,
            metavar="SEC",
            help="periodic status line with running stats (default 5s; 0 disables)",
        )

    ex = sub.add_parser("exhaust", help="consume the DHCP pool (non-destructive)")
    common(ex)
    ex.add_argument("--request-option", default=None, help="e.g. 12,14-19,23")
    ex.add_argument("--client-mac", action="append", dest="client_macs")
    # ethernet src = per-client MAC by default (distinct L2 clients); opt out for Wi-Fi
    ex.add_argument(
        "--spoof-eth-src",
        action="store_true",
        default=True,
        help="ethernet src = client MAC (default; distinct L2 clients)",
    )
    ex.add_argument(
        "--no-spoof-eth-src",
        dest="no_spoof_eth_src",
        action="store_true",
        help="use the real NIC MAC for all frames (Wi-Fi friendly)",
    )
    ex.add_argument(
        "--scope",
        action="append",
        dest="scope_cidrs",  # build_config() reads scope_cidrs, not scope
        metavar="CIDR",
        help="bound the run to these networks (repeatable; defaults to the interface's own "
        "network). Also makes the pool-size estimate deterministic instead of inferred from "
        "the first OFFER's subnet",
    )
    ex.add_argument("--dry-run", action="store_true")
    ex.add_argument(
        "--no-journal",
        dest="no_journal",
        action="store_true",
        help="don't record acquired leases to the recovery journal (default: on) -- without "
        "it, 'dhcpig release-previous' has nothing to recover with if this run is interrupted",
    )
    ex.add_argument(
        "--no-evict",
        dest="no_evict",
        action="store_true",
        help="skip ARP-conflict eviction of re-acquired addresses (default: on) -- see "
        "RFC 5227 SS2.4; contests ownership to force a DECLINE/restart-at-INIT",
    )
    ex.add_argument(
        "--no-race-freed",
        dest="no_race_freed",
        action="store_true",
        help="skip racing a targeted DISCOVER for an address a live foreign NAK/DECLINE shows "
        "just became free (default: on) -- see docs/DESIGN.md §5g",
    )
    ex.add_argument(
        "--race-on-rediscover",
        dest="race_on_rediscover",
        action="store_true",
        help="also race on a foreign DISCOVER from a MAC our ARP inventory already has an IP "
        "for (default: off -- the highest-volume, lowest-precision trigger)",
    )

    sc = sub.add_parser("scan", help="passive ARP + DHCP fingerprint (read-only)")
    common(sc)

    asc = sub.add_parser(
        "active-scan", help="active discovery: ARP sweep + DHCP INFORM (needs --scope)"
    )
    common(asc)
    asc.add_argument(
        "--scope",
        action="append",
        dest="scope_cidrs",
        metavar="CIDR",
        help="network(s) to sweep; defaults to the interface's own network",
    )
    asc.add_argument("--rate", type=int, default=7)
    asc.add_argument("--dry-run", action="store_true")

    for name, helptext in (("release", "DHCPRELEASE in-scope neighbors (DESTRUCTIVE)"),):
        d = sub.add_parser(name, help=helptext)
        common(d)
        d.add_argument(
            "--scope",
            action="append",
            dest="scope_cidrs",
            metavar="CIDR",
            help="limit targets to these networks (default: the interface's own network)",
        )
        d.add_argument("--rate", type=int, default=7)
        d.add_argument("--dry-run", action="store_true")
        d.add_argument(
            "--no-evict",
            dest="no_evict",
            action="store_true",
            help="skip ARP-conflict eviction of re-acquired addresses (default: on) -- see "
            "RFC 5227 SS2.4; release now shares the full exhaust chain (2.3, Phase 5)",
        )

    rp2 = sub.add_parser(
        "release-previous",
        help="recover a drained pool by replaying the lease journal (not destructive)",
    )
    common(rp2)
    rp2.add_argument(
        "--journal",
        metavar="PATH",
        help="override the journal location (default: the resolved per-interface path)",
    )
    rp2.add_argument(
        "--scope",
        action="append",
        dest="scope_cidrs",
        metavar="CIDR",
        help="network(s) to recover; defaults to the interface's own network",
    )
    rp2.add_argument(
        "--max-age",
        type=float,
        default=7.0,
        metavar="DAYS",
        help="ignore journal entries older than this many days (default 7)",
    )
    rp2.add_argument(
        "--any-server",
        dest="any_server",
        action="store_true",
        help="release even when the current server differs from the one recorded in the "
        "journal (default: skip mismatches, to avoid releasing on the wrong network)",
    )
    # unlike every other mode's 7pps default: this runs during an outage the operator is
    # trying to end, and the frames are unicast to one server rather than sprayed at the
    # segment, so a faster default is the right trade-off here specifically.
    rp2.add_argument("--rate", type=int, default=50)
    rp2.add_argument(
        "--passes",
        type=int,
        default=2,
        help="RELEASE has no reply (RFC 2131), so resend the selected set this many times "
        "as cheap insurance against a dropped frame (default 2)",
    )
    rp2.add_argument("--dry-run", action="store_true")

    rs = sub.add_parser("restore", help="release leases acquired by a prior run")
    rs.add_argument("interface")

    sub.add_parser("ifaces", help="list usable interfaces")

    rp = sub.add_parser("report", help="re-render a saved JSON report")
    rp.add_argument("path")
    return p


def build_config(args) -> SessionConfig:
    mode = _MODE_BY_CMD[args.command]
    req_opts = list(range(80))
    if getattr(args, "request_option", None):
        req_opts = parse_request_options(args.request_option)
    scope = getattr(args, "scope_cidrs", None)
    # active-scan: auto-fill scope with the interface's own network when not given
    if mode is Mode.ACTIVE_SCAN and not scope:
        from ..core.netutils import iface_network_cidr

        cidr = iface_network_cidr(args.interface)
        if cidr:
            scope = [cidr]
    return SessionConfig(
        interface=args.interface,
        mode=mode,
        ip_version=IPVersion.V6 if getattr(args, "ipv6", False) else IPVersion.V4,
        client_macs=getattr(args, "client_macs", None),
        spoof_ethernet_src=not getattr(args, "no_spoof_eth_src", False),
        request_options=req_opts,
        # exhaust has no --rate: the windowed handshake pipeline paces it. Everything else
        # (release/active-scan/release-previous) still takes --rate as its only pacing mechanism.
        rate_limit_pps=(
            EXHAUST_DEFAULT_RATE_PPS if mode is Mode.EXHAUST else getattr(args, "rate", 7)
        ),
        dry_run=getattr(args, "dry_run", False),
        scope_cidrs=scope,
        report_path=Path(args.report) if getattr(args, "report", None) else None,
        evict=not getattr(args, "no_evict", False),
        race_freed_addresses=not getattr(args, "no_race_freed", False),
        race_on_rediscover=getattr(args, "race_on_rediscover", False),
        status_interval=getattr(args, "status_interval", 5.0),
        journal=not getattr(args, "no_journal", False),
        journal_path=Path(args.journal) if getattr(args, "journal", None) else None,
        max_age_days=getattr(args, "max_age", 7.0),
        require_same_server=not getattr(args, "any_server", False),
        release_passes=getattr(args, "passes", 2),
        timeouts=Timeouts(),
        verbosity=getattr(args, "verbosity", 2),
    )


# --------------------------------------------------------------------------- commands
def _cmd_ifaces() -> int:
    from ..core.netutils import list_interfaces

    for name in list_interfaces():
        print(name)
    return EXIT_OK


def _cmd_report(path: str) -> int:
    import json

    data = json.loads(Path(path).read_text())
    print(f"dhcpig report — {data.get('mode')} on {data.get('interface')}")
    print(
        f"  servers={len(data.get('servers', []))}  leases={len(data.get('leases', []))}"
        f"  neighbors={len(data.get('neighbors', []))}  "
        f"exhausted={data.get('pool_exhausted')}"
    )
    return EXIT_OK


def _run_session(cfg: SessionConfig) -> int:
    bus = EventBus()
    recorder = SessionRecorder(cfg)
    renderer = Renderer(verbosity=cfg.verbosity)
    bus.subscribe(recorder.handle)
    bus.subscribe(renderer.handle)
    engine = DhcpEngine(cfg, bus)

    try:
        engine.start()
    except ConfigError as exc:
        print(f"[XX] {exc}", file=sys.stderr)
        return EXIT_BADARGS

    rc = EXIT_OK
    try:
        # count the no-server deadline from the first DISCOVER, not from start(): the prelude
        # (ARP sweep + control transactions) legitimately runs for several seconds first
        first_discover_at = None
        while True:
            time.sleep(0.5)
            if engine.state in (EXHAUSTED, DONE):
                break
            if first_discover_at is None and engine.discovers:
                first_discover_at = time.time()
            if (
                cfg.mode is Mode.EXHAUST
                and not engine.servers
                and first_discover_at is not None
                and time.time() - first_discover_at > max(20.0, cfg.timeouts.dhcp_request * 20)
                and not cfg.dry_run
            ):
                print("[XX] no DHCP server detected — aborting", file=sys.stderr)
                rc = EXIT_NOSERVER
                break
            # "no more worker threads alive" is "this run is done" for these modes. Canonical
            # definition lives in core.models (the web control plane keys off it too).
            if cfg.mode in RUN_ONCE_MODES and not any(t.is_alive() for t in engine._threads):
                break
    except KeyboardInterrupt:
        rc = EXIT_INTERRUPT
    finally:
        engine.stop()

    if cfg.report_path:
        recorder.export(cfg.report_path)
        print(f"[--] report written: {cfg.report_path}")
    st = engine.status()
    print(
        f"[--] done: leases={st['leases']} servers={st['servers']} naks={st['naks']} "
        f"releases={st['releases']} arp_conflicts={st['arp_conflicts']}"
    )
    if engine.findings:
        worst = {"FAIL": 3, "INCONCLUSIVE": 2, "PASS": 1, "INFO": 0}
        top = max(engine.findings, key=lambda f: worst.get(f.verdict, 0))
        print(f"[==] verdict: {top.verdict} — {top.title}")
        print(f"[==] {len(engine.findings)} finding(s); see the report for full evidence")
    return rc


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "ifaces":
        return _cmd_ifaces()
    if args.command == "report":
        return _cmd_report(args.path)
    if args.command == "restore":
        cfg = SessionConfig(interface=args.interface, mode=Mode.EXHAUST)
        engine = DhcpEngine(cfg, EventBus())
        engine.restore()
        print("[--] restore complete")
        return EXIT_OK
    cfg = build_config(args)
    return _run_session(cfg)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
