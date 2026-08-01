"""Shared DhcpEngine construction for unit tests.

Nearly every test_*.py file used to define its own local `_engine(monkeypatch, **cfg)` --
eleven near-identical copies whose defaults had quietly drifted apart (interface "wlan0" vs
"lo", offline=True vs dry_run=True vs neither). `build_engine()` here is the one place that
does the truly identical part: the sendp monkeypatch, the EventBus + events list, and
constructing the DhcpEngine. Each file's `_engine()` is now a thin wrapper around it that states
only that file's own meaningful SessionConfig defaults (mode, offline, dry_run, interface,
timeouts) -- explicit and visible at that file's own top, not hidden in a one-size-fits-all
fixture that would either silently pick the wrong default for some file or force every test to
restate defaults it used to get for free.

Deliberately a plain function, not a `@pytest.fixture` -- every existing test calls its file's
`_engine(monkeypatch, **cfg)` directly inside the test body, and keeping that exact call
convention meant this could be a pure "extract the duplicated part" refactor touching zero test
bodies, not a `def test_foo(engine_factory)` signature change across ~150 call sites.
"""

from __future__ import annotations

from dhcpig.core import engine as engine_mod
from dhcpig.core.engine import DhcpEngine
from dhcpig.core.events import EventBus
from dhcpig.core.models import SessionConfig


def build_engine(monkeypatch, **cfg) -> tuple[DhcpEngine, list, list]:
    """(engine, events, sent) for the given SessionConfig overrides.

    `interface` defaults to "lo" unless overridden. `sent` collects every packet passed to the
    monkeypatched sendp -- discard it (`_sent`) in a test that doesn't care what was sent.
    """
    sent: list = []
    monkeypatch.setattr(engine_mod, "sendp", lambda pkt, **kw: sent.append(pkt))
    bus = EventBus()
    events: list = []
    bus.subscribe(events.append)
    cfg.setdefault("interface", "lo")
    eng = DhcpEngine(SessionConfig(**cfg), bus)
    return eng, events, sent
