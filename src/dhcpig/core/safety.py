"""Safety primitives: authorization gate, scope guard, rate limiter, cleanup/restore.

These enforce the whitehat guarantees and are all unit-testable without root.
"""

from __future__ import annotations

import ipaddress
import threading
import time

from .exceptions import Unauthorized
from .models import DESTRUCTIVE_MODES, Lease, SessionConfig


def authorize(cfg: SessionConfig) -> None:
    """Raise Unauthorized unless a destructive mode has explicit auth + non-empty scope."""
    if cfg.mode in DESTRUCTIVE_MODES:
        if not cfg.authorized:
            raise Unauthorized(
                f"{cfg.mode.value} is destructive and requires authorization (--i-am-authorized)"
            )
        if not cfg.scope_cidrs:
            raise Unauthorized(f"{cfg.mode.value} is destructive and requires --scope")


class ScopeGuard:
    """Decide whether a target IP is permitted.

    Non-destructive modes with no scope allow everything. Destructive modes must be given a
    scope (enforced by authorize()); an IP is allowed only if it falls inside one CIDR.
    """

    def __init__(self, cidrs: list[str] | None) -> None:
        self._nets = [ipaddress.ip_network(c, strict=False) for c in (cidrs or [])]

    @property
    def has_scope(self) -> bool:
        return bool(self._nets)

    def allows(self, ip: str) -> bool:
        if not self._nets:
            return True  # no scope set => unrestricted (only reachable for non-destructive)
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._nets)


class RateLimiter:
    """Simple thread-safe token bucket capping outbound packets/sec."""

    def __init__(self, pps: int) -> None:
        self.pps = max(1, int(pps))
        self._capacity = float(self.pps)
        self._tokens = float(self.pps)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, now: float | None = None) -> None:
        """Block (sleep) until a token is available, holding the average rate <= pps."""
        while True:
            with self._lock:
                t = now if now is not None else time.monotonic()
                elapsed = max(0.0, t - self._last)
                self._last = t
                self._tokens = min(self._capacity, self._tokens + elapsed * self.pps)
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                deficit = 1.0 - self._tokens
                wait = deficit / self.pps
            if now is not None:
                # deterministic mode for tests: don't sleep, just return
                return
            time.sleep(wait)


class Cleanup:
    """Track acquired leases so the network can be returned to its prior state."""

    def __init__(self) -> None:
        self._leases: list[Lease] = []
        self._lock = threading.Lock()

    def register(self, lease: Lease) -> None:
        with self._lock:
            self._leases.append(lease)

    def pending(self) -> list[Lease]:
        with self._lock:
            return [ln for ln in self._leases if not ln.released]

    def all(self) -> list[Lease]:
        with self._lock:
            return list(self._leases)
