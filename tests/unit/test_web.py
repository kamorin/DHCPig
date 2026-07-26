"""Web layer tests — no root. A live ThreadingHTTPServer on an ephemeral loopback port,
driven with stdlib http.client; SSE plumbing tested at the unit level.
"""

import json
import threading
import time
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer

import pytest

from dhcpig.core import engine as engine_mod
from dhcpig.core import events as ev
from dhcpig.core.events import EventBus
from dhcpig.web import auth, schemas
from dhcpig.web.server import Handler, WebApp
from dhcpig.web.stream import SseSubscriber


@pytest.fixture
def server(monkeypatch):
    # ensure nothing ever hits the wire, even if a dry-run guard regresses
    monkeypatch.setattr(engine_mod, "sendp", lambda *a, **k: None)
    app = WebApp(token="TESTTOKEN")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.app = app
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield app, httpd.server_address
    app.stop()
    httpd.shutdown()


def _req(addr, method, path, token=None, body=None, origin=None):
    conn = HTTPConnection(addr[0], addr[1], timeout=5)
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    if origin:
        headers["Origin"] = origin
    payload = json.dumps(body) if body is not None else None
    if payload is not None:
        headers["Content-Type"] = "application/json"
    conn.request(method, path, body=payload, headers=headers)
    r = conn.getresponse()
    data = r.read()
    conn.close()
    return r.status, data


# ---------------------------------------------------------------- auth / gating
def test_static_index_served_without_token(server):
    _, addr = server
    status, body = _req(addr, "GET", "/")
    assert status == 200
    assert b"DHCP" in body


def test_api_requires_token(server):
    _, addr = server
    assert _req(addr, "GET", "/api/ifaces")[0] == 401
    assert _req(addr, "GET", "/api/ifaces", token="TESTTOKEN")[0] == 200
    assert _req(addr, "GET", "/api/ifaces", token="WRONG")[0] == 401


def test_ifaces_include_name_and_cidr(server):
    _, addr = server
    status, body = _req(addr, "GET", "/api/ifaces", token="TESTTOKEN")
    assert status == 200
    ifaces = json.loads(body)["interfaces"]
    assert isinstance(ifaces, list) and ifaces
    assert "name" in ifaces[0] and "cidr" in ifaces[0]  # cidr may be None


def test_cross_origin_post_rejected(server):
    _, addr = server
    status, _ = _req(
        addr, "POST", "/api/session/stop", token="TESTTOKEN", body={}, origin="http://evil.example"
    )
    assert status == 403


# ---------------------------------------------------------------- session flow
def test_dry_run_exhaust_streams_and_sends_nothing(server, monkeypatch):
    calls = []
    monkeypatch.setattr(engine_mod, "sendp", lambda *a, **k: calls.append(1))
    app, addr = server
    status, body = _req(
        addr,
        "POST",
        "/api/session/start",
        token="TESTTOKEN",
        body={"interface": "lo", "mode": "exhaust", "rate": 100, "dry_run": True},
        origin=f"http://{addr[0]}:{addr[1]}",
    )
    assert status == 200
    time.sleep(1.2)  # let a few discovers fire
    st = json.loads(_req(addr, "GET", "/api/session/status", token="TESTTOKEN")[1])["status"]
    assert st["discovers"] >= 1
    assert calls == []  # dry-run: nothing on the wire
    assert (
        _req(
            addr,
            "POST",
            "/api/session/stop",
            token="TESTTOKEN",
            body={},
            origin=f"http://{addr[0]}:{addr[1]}",
        )[0]
        == 200
    )


def test_single_session_guard(server):
    app, addr = server
    o = f"http://{addr[0]}:{addr[1]}"
    b = {"interface": "lo", "mode": "exhaust", "dry_run": True}
    assert _req(addr, "POST", "/api/session/start", token="TESTTOKEN", body=b, origin=o)[0] == 200
    assert _req(addr, "POST", "/api/session/start", token="TESTTOKEN", body=b, origin=o)[0] == 409
    _req(addr, "POST", "/api/session/stop", token="TESTTOKEN", body={}, origin=o)


def test_report_download_csv(server):
    app, addr = server
    o = f"http://{addr[0]}:{addr[1]}"
    b = {"interface": "lo", "mode": "exhaust", "dry_run": True}
    _req(addr, "POST", "/api/session/start", token="TESTTOKEN", body=b, origin=o)
    conn = HTTPConnection(addr[0], addr[1], timeout=5)
    conn.request(
        "POST",
        "/api/report",
        body=json.dumps({"format": "csv"}),
        headers={
            "Authorization": "Bearer TESTTOKEN",
            "Content-Type": "application/json",
            "Origin": o,
        },
    )
    r = conn.getresponse()
    body = r.read().decode()
    conn.close()
    assert r.status == 200
    assert r.getheader("Content-Type") == "text/csv"
    assert "attachment" in (r.getheader("Content-Disposition") or "")
    assert body.splitlines()[0] == "kind,mac,ip,server_id,os,device,vendor,confidence"
    _req(addr, "POST", "/api/session/stop", token="TESTTOKEN", body={}, origin=o)


# ---------------------------------------------------------------- SSE plumbing
def test_sse_subscriber_receives_events():
    bus = EventBus()
    sub = SseSubscriber(bus)
    bus.emit(ev.DiscoverSent(mac="de:ad:00:00:00:01"))
    stop = threading.Event()
    gen = sub.frames(stop)
    frame = next(gen)
    assert frame.startswith(b"data: ")
    assert b"DiscoverSent" in frame
    sub.close()


def test_sse_serializes_events_with_enums_and_nested_dataclasses():
    # regression: OfferReceived carries Lease/ServerInfo whose ip_version is an IPVersion enum
    from dhcpig.core.models import IPVersion, Lease, ServerInfo

    bus = EventBus()
    sub = SseSubscriber(bus)
    lease = Lease("de:ad:00:00:00:07", "172.20.0.83", "172.20.15.1", 1, IPVersion.V4)
    server = ServerInfo("172.20.15.1", "00:0c:29:da:53:f9", "255.255.255.0", IPVersion.V4)
    bus.emit(ev.OfferReceived(lease=lease, server=server))
    frame = next(sub.frames(threading.Event()))
    payload = json.loads(frame.decode().removeprefix("data: ").strip())
    assert payload["type"] == "OfferReceived"
    assert payload["lease"]["ip_version"] == "v4"  # enum -> value, json-safe
    assert payload["server"]["server_id"] == "172.20.15.1"
    sub.close()


# ---------------------------------------------------------------- schemas
def test_as_cli_roundtrip():
    cfg = schemas.config_from_payload({"interface": "eth1", "mode": "exhaust", "rate": 30})
    assert schemas.as_cli(cfg) == "dhcpig exhaust eth1 --rate 30"


def test_token_helpers():
    assert auth.token_ok("abc", "abc")
    assert not auth.token_ok("abc", "xyz")
    assert not auth.token_ok("abc", None)
