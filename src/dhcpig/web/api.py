"""REST route handlers. Pure-ish functions over a WebApp; return (status_code, json_obj).

Exceptions raised here are mapped to HTTP status by the server handler.
"""

from __future__ import annotations

from ..core.netutils import iface_network_cidr, list_interfaces
from ..core.safety import authorize
from .schemas import as_cli, config_from_payload


def api_ifaces() -> tuple[int, dict]:
    # each interface plus its own network (for auto-filling the scope in the UI)
    ifaces = [{"name": n, "cidr": iface_network_cidr(n)} for n in list_interfaces()]
    return 200, {"interfaces": ifaces}


def api_status(app) -> tuple[int, dict]:
    return 200, {"status": app.status()}


def api_as_cli(app) -> tuple[int, dict]:
    return 200, {"command": app.as_cli()}


def api_start(app, body: dict) -> tuple[int, dict]:
    cfg = config_from_payload(body)
    authorize(cfg)  # server-side re-validation — never trust the client
    app.start(cfg)
    return 200, {"ok": True, "as_cli": as_cli(cfg), "status": app.status()}


def api_stop(app) -> tuple[int, dict]:
    app.stop()
    return 200, {"ok": True, "status": app.status()}


def api_restore(app) -> tuple[int, dict]:
    app.restore()
    return 200, {"ok": True, "status": app.status()}
