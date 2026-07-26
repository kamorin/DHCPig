"""Request validation without pydantic. core.safety remains the authoritative validator."""

from __future__ import annotations

from ..core.exceptions import ConfigError
from ..core.models import IPVersion, Mode, SessionConfig


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

    return SessionConfig(
        interface=iface,
        mode=mode,
        ip_version=IPVersion.V6 if payload.get("ipv6") else IPVersion.V4,
        rate_limit_pps=_as_int(payload.get("rate", 10), "rate", lo=1, hi=100000),
        threads=_as_int(payload.get("threads", 1), "threads", lo=1, hi=64),
        dry_run=bool(payload.get("dry_run", False)),
        scope_cidrs=scope,
        spoof_ethernet_src=bool(payload.get("spoof_eth_src", True)),
        restore_on_exit=bool(payload.get("restore_on_exit", False)),
        control=bool(payload.get("control", True)),
        arp_sweep=bool(payload.get("arp_sweep", True)),
        status_interval=float(payload.get("status_interval", 5.0) or 0),
        verbosity=_as_int(payload.get("verbosity", 2), "verbosity", lo=0, hi=3),
    )


def as_cli(cfg: SessionConfig) -> str:
    parts = ["dhcpig", cfg.mode.value, cfg.interface]
    if cfg.ip_version is IPVersion.V6:
        parts.append("--ipv6")
    parts += ["--rate", str(cfg.rate_limit_pps)]
    if cfg.restore_on_exit:
        parts.append("--restore-on-exit")
    for cidr in cfg.scope_cidrs or []:
        parts += ["--scope", cidr]
    if cfg.dry_run:
        parts.append("--dry-run")
    if not cfg.control and cfg.mode is Mode.EXHAUST:
        parts.append("--no-control")
    return " ".join(parts)
