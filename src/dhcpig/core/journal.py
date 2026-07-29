"""Lease journal: an append-only, crash-tolerant record of every lease `exhaust` has ever
acquired, so a drained pool can be recovered later even if the process that drained it is long
gone (killed, rebooted, or run from a different machine entirely).

Design constraints (see AGENT_HANDOFF.md §5e):
  * Never rewrite or mutate the file — a recovery tool whose own state file can be corrupted by
    a crash mid-write is worse than no recovery tool. Two append-only record kinds ("ack" opens
    a lease, "released" closes it); a reader folds them into current state.
  * Never write to a system-owned path (`/var/lib`, etc.) — this is per-operator engagement
    data, not a system service's state.
  * The reader must never raise on a bad file. A truncated final line (the killed-mid-write case
    this whole feature exists for), a malformed JSON line, an unknown record kind, or a missing
    field is skipped with a warning, not a crash.
  * Writes are the caller's problem to make best-effort: this module raises OSError on failure
    rather than swallowing it, so `engine.py` can decide how to surface it (an `ev.Debug`) —
    `core` never prints directly.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Lease


@dataclass
class JournalEntry:
    """A still-open (not yet released) lease, folded from the journal's ack/released records."""

    ts: float
    iface: str
    mac: str
    ip: str
    server_ip: str
    server_mac: str | None
    xid: int | None
    lease_time: int | None


def _state_home() -> Path:
    """XDG_STATE_HOME if set, else the *effective* user's home + .local/state.

    Resolved via the passwd entry for the effective UID rather than trusting `$HOME` alone --
    `sudo` does not always reset it, and `exhaust` normally runs as root.
    """
    xdg = os.environ.get("XDG_STATE_HOME")
    if xdg:
        return Path(xdg)
    try:
        import pwd

        home = pwd.getpwuid(os.geteuid()).pw_dir
    except (ImportError, KeyError, OSError):
        home = os.path.expanduser("~")
    return Path(home) / ".local" / "state"


def default_path(iface: str) -> Path:
    """Never `/var/lib` or any other system-owned path — see the module docstring."""
    return _state_home() / "dhcpig" / f"leases-{iface}.jsonl"


def _append(path: Path, record: dict) -> None:
    """Append one JSON line. A single write() to an O_APPEND fd is effectively atomic on local
    filesystems, so concurrent writers/readers need no locking. Raises OSError on failure --
    callers decide how to surface it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, sort_keys=True)
    with open(path, "a", buffering=1) as fh:
        fh.write(line + "\n")
        fh.flush()


def record_ack(path: Path, iface: str, lease: Lease) -> None:
    """Called from `_handle_ack()` the moment an ACK lands -- this is what makes recovery
    survive a killed process, not just a clean `stop()`."""
    _append(
        path,
        {
            "ev": "ack",
            "ts": time.time(),
            "iface": iface,
            "mac": lease.mac,
            "ip": lease.ip,
            "server_ip": lease.server_ip,
            "server_mac": lease.server_mac,
            "xid": lease.xid,
            "lease_time": lease.lease_time,
        },
    )


def record_released(path: Path, iface: str, mac: str, ip: str) -> None:
    """Marks a (mac, ip) binding closed. Never deletes the ack record -- the journal is
    append-only end to end."""
    _append(
        path,
        {"ev": "released", "ts": time.time(), "iface": iface, "mac": mac, "ip": ip},
    )


_ACK_REQUIRED_FIELDS = ("ts", "iface", "server_ip")


def load_open_leases(path: Path) -> tuple[list[JournalEntry], list[str]]:
    """Fold the journal into (still-open leases, human-readable warnings).

    Never raises. A journal that doesn't exist yet is not an error -- it's just an empty
    recovery set (e.g. before this feature shipped, or after `--no-journal`).
    """
    warnings: list[str] = []
    if not path.exists():
        return [], warnings
    try:
        text = path.read_text()
    except OSError as exc:
        return [], [f"could not read journal {path}: {exc}"]

    open_leases: dict[tuple[str, str], JournalEntry] = {}
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            warnings.append(f"{path}:{lineno}: malformed JSON line, skipped")
            continue
        if not isinstance(rec, dict):
            warnings.append(f"{path}:{lineno}: not a JSON object, skipped")
            continue

        kind = rec.get("ev")
        mac, ip = rec.get("mac"), rec.get("ip")
        if not mac or not ip:
            warnings.append(f"{path}:{lineno}: missing mac/ip, skipped")
            continue
        key = (mac, ip)

        if kind == "ack":
            missing = [f for f in _ACK_REQUIRED_FIELDS if rec.get(f) is None]
            if missing:
                warnings.append(f"{path}:{lineno}: ack record missing {missing}, skipped")
                continue
            open_leases[key] = JournalEntry(
                ts=rec["ts"],
                iface=rec["iface"],
                mac=mac,
                ip=ip,
                server_ip=rec["server_ip"],
                server_mac=rec.get("server_mac"),
                xid=rec.get("xid"),
                lease_time=rec.get("lease_time"),
            )
        elif kind == "released":
            open_leases.pop(key, None)
        else:
            warnings.append(f"{path}:{lineno}: unknown record kind {kind!r}, skipped")

    return list(open_leases.values()), warnings
