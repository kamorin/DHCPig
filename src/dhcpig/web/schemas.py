"""Request validation without pydantic. core.safety remains the authoritative validator."""

from __future__ import annotations

from pathlib import Path

from ..core.exceptions import ConfigError
from ..core.models import EXHAUST_DEFAULT_RATE_PPS, IPVersion, Mode, SessionConfig


def _as_int(value, name: str, lo: int | None = None, hi: int | None = None) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if lo is not None and v < lo:
        raise ConfigError(f"{name} must be >= {lo}")
    if hi is not None and v > hi:
        raise ConfigError(f"{name} must be <= {hi}")
    return v


def config_from_payload(payload: dict) -> SessionConfig:
    if not isinstance(payload, dict):
        raise ConfigError("body must be a JSON object")
    iface = payload.get("interface")
    if not iface or not isinstance(iface, str):
        raise ConfigError("interface is required")

    mode_str = payload.get("mode", "exhaust")
    try:
        mode = Mode(mode_str)
    except ValueError as exc:
        raise ConfigError(f"unknown mode: {mode_str}") from exc

    scope = payload.get("scope_cidrs")
    if scope is not None and not isinstance(scope, list):
        raise ConfigError("scope_cidrs must be a list")

    # exhaust and release have no rate control of their own — release's re-acquisition leg
    # shares exhaust's windowed handshake pipeline, which paces and backs off on NAKs the same
    # way. release-previous defaults faster than every other mode: it runs during an outage the
    # operator is trying to end, and its frames are unicast to one server, not sprayed at the
    # segment.
    default_rate = 50 if mode is Mode.RELEASE_PREVIOUS else 7
    rate = (
        EXHAUST_DEFAULT_RATE_PPS
        if mode in (Mode.EXHAUST, Mode.RELEASE_NEIGHBORS)
        else _as_int(payload.get("rate", default_rate), "rate", lo=1, hi=100000)
    )
    journal_path = payload.get("journal_path")
    return SessionConfig(
        interface=iface,
        mode=mode,
        ip_version=IPVersion.V6 if payload.get("ipv6") else IPVersion.V4,
        rate_limit_pps=rate,
        dry_run=bool(payload.get("dry_run", False)),
        # hard no-socket switch (2.3), distinct from dry_run -- lets a no-root web preview run
        # without ever opening a raw-capture interface. Not exposed as a UI control; callers that
        # need it (tests, an unprivileged preview mode) set it directly in the POST body.
        offline=bool(payload.get("offline", False)),
        scope_cidrs=scope,
        spoof_ethernet_src=bool(payload.get("spoof_eth_src", True)),
        evict=bool(payload.get("evict", True)),
        race_freed_addresses=bool(payload.get("race_freed_addresses", True)),
        race_on_rediscover=bool(payload.get("race_on_rediscover", False)),
        status_interval=float(payload.get("status_interval", 5.0) or 0),
        journal=bool(payload.get("journal", True)),
        journal_path=Path(journal_path) if journal_path else None,
        max_age_days=float(payload.get("max_age_days", 7.0) or 0),
        require_same_server=bool(payload.get("require_same_server", True)),
        release_passes=_as_int(payload.get("release_passes", 2), "release_passes", lo=1, hi=20),
        verbosity=_as_int(payload.get("verbosity", 2), "verbosity", lo=0, hi=3),
    )


def as_cli(cfg: SessionConfig) -> str:
    parts = ["dhcpig", cfg.mode.value, cfg.interface]
    if cfg.ip_version is IPVersion.V6:
        parts.append("--ipv6")
    if cfg.mode not in (Mode.EXHAUST, Mode.RELEASE_NEIGHBORS):
        parts += ["--rate", str(cfg.rate_limit_pps)]
    for cidr in cfg.scope_cidrs or []:
        parts += ["--scope", cidr]
    if cfg.dry_run:
        parts.append("--dry-run")
    if not cfg.journal and cfg.mode is Mode.EXHAUST:
        parts.append("--no-journal")
    if not cfg.evict and cfg.mode in (Mode.EXHAUST, Mode.RELEASE_NEIGHBORS):
        parts.append("--no-evict")
    if cfg.mode is Mode.EXHAUST:  # race-freed is exhaust-only (docs/DESIGN.md §5g)
        if not cfg.race_freed_addresses:
            parts.append("--no-race-freed")
        if cfg.race_on_rediscover:
            parts.append("--race-on-rediscover")
    if cfg.mode is Mode.RELEASE_PREVIOUS:
        if cfg.journal_path:
            parts += ["--journal", str(cfg.journal_path)]
        if cfg.max_age_days != 7.0:
            parts += ["--max-age", str(cfg.max_age_days)]
        if not cfg.require_same_server:
            parts.append("--any-server")
        if cfg.release_passes != 2:
            parts += ["--passes", str(cfg.release_passes)]
    return " ".join(parts)
