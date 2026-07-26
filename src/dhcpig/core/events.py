"""Event bus + event types. core emits events; it never prints.

Handlers are called synchronously on the emitting (engine) thread and MUST be cheap and
non-blocking (append to a queue, update a counter). The web layer's per-client queue and the
CLI renderer both subscribe here.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import asdict, dataclass, field, is_dataclass
from enum import Enum
from pathlib import Path

from .models import ControlOutcome, Finding, HostFingerprint, Lease, Neighbor, ServerInfo


@dataclass
class Event:
    """Base event."""


@dataclass
class DiscoverSent(Event):
    mac: str


@dataclass
class OfferReceived(Event):
    lease: Lease
    server: ServerInfo


@dataclass
class RequestSent(Event):
    lease: Lease


@dataclass
class AckReceived(Event):
    lease: Lease


@dataclass
class NakReceived(Event):
    server_ip: str


@dataclass
class ServerDiscovered(Event):
    server: ServerInfo


@dataclass
class NeighborFound(Event):
    neighbor: Neighbor


@dataclass
class HostFingerprinted(Event):
    fp: HostFingerprint


@dataclass
class OffersCeased(Event):
    """Offers have gone quiet — the run may be finishing. Emitted so the UI shows progress
    instead of appearing to hang while we wait out the silence window."""

    quiet_for: float
    leases: int
    deadline: float


@dataclass
class PoolExhausted(Event):
    """Offers stopped arriving after having flowed — the pool looks genuinely drained.

    Only confirmed once the post-run control transaction also fails to get a lease.
    """

    leases: int
    elapsed: float
    confirmed: bool = False


@dataclass
class ControlStarted(Event):
    phase: str  # "pre" | "post"


@dataclass
class ControlFinished(Event):
    outcome: ControlOutcome


@dataclass
class ControlDetected(Event):
    """A defensive control fired mid-run.

    Sending stops immediately; leases already held are kept, and the post-run controls still
    run so the report is complete — see DhcpEngine._trigger_halt().
    """

    signal: str  # nak_burst | offer_silence | link_down | timeout_storm | duplicate_offers
    detail: str
    leases_held: int


@dataclass
class FindingRaised(Event):
    finding: Finding


@dataclass
class LeaseReleased(Event):
    lease: Lease


@dataclass
class ArpConflictSent(Event):
    ip: str


@dataclass
class Skipped(Event):
    ip: str
    reason: str


@dataclass
class StatusTick(Event):
    """Periodic heartbeat with running totals *and* per-window deltas.

    Deltas are the point: totals alone don't show whether anything is still happening.
    """

    stats: dict = field(default_factory=dict)


@dataclass
class ErrorEvent(Event):
    message: str


@dataclass
class Debug(Event):
    message: str


@dataclass
class SessionEnded(Event):
    report: dict = field(default_factory=dict)


Handler = Callable[[Event], None]


class EventBus:
    def __init__(self) -> None:
        self._subs: list[Handler] = []
        self._lock = threading.Lock()

    def subscribe(self, fn: Handler) -> None:
        with self._lock:
            self._subs.append(fn)

    def unsubscribe(self, fn: Handler) -> None:
        with self._lock:
            if fn in self._subs:
                self._subs.remove(fn)

    def emit(self, event: Event) -> None:
        with self._lock:
            subs = list(self._subs)
        for fn in subs:
            fn(event)


def jsonable(obj):
    """Recursively convert enums/bytes/Paths so the result is json.dumps-safe."""
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, dict):
        return {k: jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [jsonable(v) for v in obj]
    return obj


def to_dict(event: Event) -> dict:
    """Fully JSON-serializable dict with a `type` discriminator (for the SSE/web layer)."""
    data = jsonable(asdict(event)) if is_dataclass(event) else {}
    data["type"] = type(event).__name__
    return data
