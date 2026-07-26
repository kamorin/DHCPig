"""SSE plumbing: subscribe a queue to the core EventBus and yield text/event-stream frames."""

from __future__ import annotations

import json
import queue
import threading

from ..core.events import Event, EventBus, to_dict


class SseSubscriber:
    """Bridges the (thread-safe) EventBus to one SSE client via a bounded queue."""

    def __init__(self, bus: EventBus, maxsize: int = 2000) -> None:
        self.bus = bus
        self.q: queue.Queue = queue.Queue(maxsize=maxsize)
        self._fn = self._put
        bus.subscribe(self._fn)

    def _put(self, event: Event) -> None:
        try:
            self.q.put_nowait(to_dict(event))
        except queue.Full:
            pass  # drop under backpressure rather than block the engine thread

    def frames(self, stop: threading.Event, heartbeat: float = 15.0):
        """Yield encoded SSE frames until `stop` is set."""
        while not stop.is_set():
            try:
                payload = self.q.get(timeout=heartbeat)
                yield f"data: {json.dumps(payload)}\n\n".encode()
            except queue.Empty:
                yield b": keep-alive\n\n"

    def close(self) -> None:
        self.bus.unsubscribe(self._fn)
