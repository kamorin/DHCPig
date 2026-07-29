"""Local web server (stdlib only): ThreadingHTTPServer + SSE. Entry point: dhcpig-web.

Loopback-bound, bearer-token-gated, same-origin by default. Reuses dhcpig.core; the web
layer never touches scapy directly.
"""

from __future__ import annotations

import argparse
import json
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from ..core.engine import DONE, DhcpEngine
from ..core.events import EventBus
from ..core.exceptions import ConfigError, SessionConflict
from ..core.models import RUN_ONCE_MODES
from ..core.reporting import SessionRecorder
from . import api
from .auth import SECURITY_HEADERS, new_token, same_origin_ok, token_from_request, token_ok
from .schemas import as_cli
from .stream import SseSubscriber

STATIC = Path(__file__).parent / "static"
_CONTENT_TYPES = {
    ".html": "text/html",
    ".js": "text/javascript",
    ".css": "text/css",
    ".svg": "image/svg+xml",
}


class WebApp:
    """Single-session control plane shared by all handler threads."""

    def __init__(self, token: str | None = None) -> None:
        self.token = token or new_token()
        self.bus = EventBus()
        self.engine: DhcpEngine | None = None
        self.recorder: SessionRecorder | None = None
        self.cfg = None
        self._lock = threading.Lock()

    def _active(self) -> bool:
        return self.engine is not None and self.engine.state != DONE

    def start(self, cfg) -> None:
        with self._lock:
            if self._active():
                raise SessionConflict("a session is already running; stop it first")
            self.cfg = cfg
            self.recorder = SessionRecorder(cfg)
            self.bus.subscribe(self.recorder.handle)
            self.engine = DhcpEngine(cfg, self.bus)
            self.engine.start()
            if cfg.mode in RUN_ONCE_MODES:
                # release/release-previous finish their work inline in a worker thread and just
                # return -- nothing in the engine calls stop() for them (unlike exhaust, which
                # can self-finalize via _finish_in_background() on a control signal). The CLI
                # covers this with a polling loop in _run_session(); the web control plane had no
                # equivalent, so a run would sit in RUNNING (empty StatusTicks) until someone
                # clicked Stop by hand. Mirror the CLI here: watch the worker, stop() once it's
                # the last one standing. stop() is idempotent, so a race with a manual Stop click
                # is harmless.
                threading.Thread(
                    target=self._reap_when_done, args=(self.engine,), daemon=True
                ).start()

    def _reap_when_done(self, engine: DhcpEngine) -> None:
        while not engine._stop.is_set() and any(t.is_alive() for t in engine._threads):
            time.sleep(0.5)
        engine.stop()

    def stop(self) -> None:
        with self._lock:
            if self.engine is not None:
                self.engine.stop()

    def restore(self) -> None:
        with self._lock:
            if self.engine is not None:
                self.engine.restore()

    def status(self) -> dict:
        return self.engine.status() if self.engine is not None else {"state": "IDLE"}

    def report(self) -> dict:
        return self.recorder.to_dict() if self.recorder is not None else {}

    def report_render(self, fmt: str) -> tuple[str, str]:
        if self.recorder is None:
            return "{}", "application/json"
        return self.recorder.render(fmt)

    def as_cli(self) -> str:
        return as_cli(self.cfg) if self.cfg is not None else ""


class Handler(BaseHTTPRequestHandler):
    server_version = "dhcpig-web"

    # ------------------------------------------------------------------ helpers
    @property
    def app(self) -> WebApp:
        return self.server.app  # type: ignore[attr-defined]

    def _headers(self, status: int, ctype: str, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def _json(self, status: int, obj) -> None:
        body = json.dumps(obj).encode()
        self._headers(status, "application/json", {"Content-Length": str(len(body))})
        self.wfile.write(body)

    def _authed(self) -> bool:
        return token_ok(self.app.token, token_from_request(self.headers, self.path))

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if not length:
            return {}
        return json.loads(self.rfile.read(length) or b"{}")

    def log_message(self, *args):  # silence default stderr logging
        pass

    # ------------------------------------------------------------------ GET
    def do_GET(self) -> None:
        route = urlparse(self.path).path
        if route in ("/", "/index.html"):
            return self._serve_static("index.html")
        # icon.svg is unauthenticated like the other assets: the browser requests it as a
        # favicon before any token is in play
        if route in ("/app.js", "/styles.css", "/icon.svg"):
            return self._serve_static(route.lstrip("/"))
        # everything below is protected
        if not self._authed():
            return self._json(401, {"error": "missing or invalid token"})
        if route == "/api/ifaces":
            return self._json(*api.api_ifaces())
        if route == "/api/session/status":
            return self._json(*api.api_status(self.app))
        if route == "/api/session/as-cli":
            return self._json(*api.api_as_cli(self.app))
        if route == "/events":
            return self._serve_sse()
        return self._json(404, {"error": "not found"})

    # ------------------------------------------------------------------ POST
    def do_POST(self) -> None:
        route = urlparse(self.path).path
        if not self._authed():
            return self._json(401, {"error": "missing or invalid token"})
        if not same_origin_ok(self.headers, self.headers.get("Host", "")):
            return self._json(403, {"error": "cross-origin request rejected"})
        try:
            if route == "/api/session/start":
                return self._json(*api.api_start(self.app, self._read_body()))
            if route == "/api/session/stop":
                return self._json(*api.api_stop(self.app))
            if route == "/api/session/restore":
                return self._json(*api.api_restore(self.app))
            if route == "/api/report":
                return self._serve_report(self._read_body())
        except ConfigError as exc:
            return self._json(400, {"error": str(exc)})
        except SessionConflict as exc:
            return self._json(409, {"error": str(exc)})
        return self._json(404, {"error": "not found"})

    # ------------------------------------------------------------------ static + sse
    def _serve_static(self, name: str) -> None:
        path = (STATIC / name).resolve()
        if not str(path).startswith(str(STATIC.resolve())) or not path.is_file():
            return self._json(404, {"error": "not found"})
        body = path.read_bytes()
        ctype = _CONTENT_TYPES.get(path.suffix, "application/octet-stream")
        self._headers(200, ctype, {"Content-Length": str(len(body))})
        self.wfile.write(body)

    def _serve_report(self, body: dict) -> None:
        fmt = (body or {}).get("format", "json")
        ext = {"json": "json", "csv": "csv", "html": "html"}.get(fmt)
        if ext is None:
            return self._json(400, {"error": f"unsupported format: {fmt}"})
        text, ctype = self.app.report_render(fmt)
        data = text.encode()
        self._headers(
            200,
            ctype,
            {
                "Content-Length": str(len(data)),
                "Content-Disposition": f'attachment; filename="dhcpig-report.{ext}"',
            },
        )
        self.wfile.write(data)

    def _serve_sse(self) -> None:
        self._headers(
            200, "text/event-stream", {"Cache-Control": "no-cache", "Connection": "keep-alive"}
        )
        stop = threading.Event()
        sub = SseSubscriber(self.app.bus)
        try:
            for frame in sub.frames(stop):
                self.wfile.write(frame)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            stop.set()
            sub.close()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="dhcpig-web", description="DHCPig local web UI (V1.1)")
    p.add_argument("--bind", default="127.0.0.1", help="bind address (default loopback)")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--open", action="store_true", help="open the browser at the tokenized URL")
    args = p.parse_args(argv)

    app = WebApp()
    httpd = ThreadingHTTPServer((args.bind, args.port), Handler)
    httpd.app = app  # type: ignore[attr-defined]

    url = f"http://{args.bind}:{args.port}/?token={app.token}"
    if args.bind not in ("127.0.0.1", "::1", "localhost"):
        print(
            "WARNING: binding to a non-loopback address exposes a Layer-2 attack tool's "
            "control plane. Prefer 'ssh -L' to a loopback bind."
        )
    print(f"dhcpig-web listening on http://{args.bind}:{args.port}")
    print(f"open: {url}")
    if args.open:
        webbrowser.open(url)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.stop()
        httpd.shutdown()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
