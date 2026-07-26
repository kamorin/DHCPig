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
        body={"interface": "lo", "mode": "exhaust", "rate": 100, "dry_run": True, "offline": True},
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
    b = {"interface": "lo", "mode": "exhaust", "dry_run": True, "offline": True}
    assert _req(addr, "POST", "/api/session/start", token="TESTTOKEN", body=b, origin=o)[0] == 200
    assert _req(addr, "POST", "/api/session/start", token="TESTTOKEN", body=b, origin=o)[0] == 409
    _req(addr, "POST", "/api/session/stop", token="TESTTOKEN", body={}, origin=o)


def test_report_download_csv(server):
    app, addr = server
    o = f"http://{addr[0]}:{addr[1]}"
    b = {"interface": "lo", "mode": "exhaust", "dry_run": True, "offline": True}
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


def test_release_mode_auto_finalizes_without_manual_stop(server):
    """(2.3) release's worker thread finishes on its own after release+eviction, but nothing in
    the engine calls stop() for it -- unlike exhaust, which can self-finalize via a halt signal.
    A live run exposed this: the web session just sat in RUNNING (empty StatusTicks) until a
    human clicked Stop. WebApp._reap_when_done() (started by WebApp.start() for any RUN_ONCE_MODES
    mode) is the fix -- verify a release run reaches DONE on its own, no /api/session/stop call.
    """
    app, addr = server
    o = f"http://{addr[0]}:{addr[1]}"
    # narrow scope: "lo" auto-detects to 127.0.0.0/8, and _discover_neighbors() materializes the
    # whole host list before slicing to 1024 -- several real seconds for a /8, unrelated to what
    # this test is checking. A tight scope keeps the ARP-sweep step (skipped anyway, offline) cheap.
    b = {
        "interface": "lo",
        "mode": "release",
        "dry_run": True,
        "offline": True,
        "scope_cidrs": ["127.0.0.1/32"],
    }
    status, _ = _req(addr, "POST", "/api/session/start", token="TESTTOKEN", body=b, origin=o)
    assert status == 200
    deadline = time.time() + 5.0
    state = None
    while time.time() < deadline:
        state = json.loads(_req(addr, "GET", "/api/session/status", token="TESTTOKEN")[1])[
            "status"
        ]["state"]
        if state == "DONE":
            break
        time.sleep(0.1)
    assert state == "DONE"  # reached without ever calling /api/session/stop


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
    cfg = schemas.config_from_payload({"interface": "eth1", "mode": "release", "rate": 30})
    assert schemas.as_cli(cfg) == "dhcpig release eth1 --rate 30"


def test_exhaust_ignores_rate_payload_and_as_cli_omits_it():
    """exhaust has no --rate of its own; the windowed pipeline paces it instead."""
    from dhcpig.core.models import EXHAUST_DEFAULT_RATE_PPS

    cfg = schemas.config_from_payload({"interface": "eth1", "mode": "exhaust", "rate": 30})
    assert cfg.rate_limit_pps == EXHAUST_DEFAULT_RATE_PPS
    assert "--rate" not in schemas.as_cli(cfg)


def test_release_previous_config_from_payload_defaults():
    cfg = schemas.config_from_payload({"interface": "eth1", "mode": "release-previous"})
    assert cfg.rate_limit_pps == 50  # faster default than every other mode
    assert cfg.max_age_days == 7.0
    assert cfg.require_same_server is True
    assert cfg.release_passes == 2
    assert cfg.journal_path is None


def test_release_previous_config_from_payload_overrides():
    cfg = schemas.config_from_payload(
        {
            "interface": "eth1",
            "mode": "release-previous",
            "journal_path": "/tmp/j.jsonl",
            "max_age_days": 2.0,
            "require_same_server": False,
            "release_passes": 4,
            "rate": 15,
        }
    )
    assert str(cfg.journal_path) == "/tmp/j.jsonl"
    assert cfg.max_age_days == 2.0
    assert cfg.require_same_server is False
    assert cfg.release_passes == 4
    assert cfg.rate_limit_pps == 15


def test_release_previous_as_cli_roundtrip():
    cfg = schemas.config_from_payload(
        {
            "interface": "eth1",
            "mode": "release-previous",
            "max_age_days": 3.0,
            "require_same_server": False,
            "release_passes": 5,
        }
    )
    line = schemas.as_cli(cfg)
    assert line.startswith("dhcpig release-previous eth1")
    assert "--rate 50" in line
    assert "--max-age 3.0" in line
    assert "--any-server" in line
    assert "--passes 5" in line


def test_journal_flag_from_payload_and_as_cli():
    cfg = schemas.config_from_payload({"interface": "eth1", "mode": "exhaust"})
    assert cfg.journal is True
    assert "--no-journal" not in schemas.as_cli(cfg)

    cfg = schemas.config_from_payload({"interface": "eth1", "mode": "exhaust", "journal": False})
    assert cfg.journal is False
    assert "--no-journal" in schemas.as_cli(cfg)


def test_evict_flag_from_payload_and_as_cli():
    cfg = schemas.config_from_payload({"interface": "eth1", "mode": "exhaust"})
    assert cfg.evict is True
    assert "--no-evict" not in schemas.as_cli(cfg)

    cfg = schemas.config_from_payload({"interface": "eth1", "mode": "exhaust", "evict": False})
    assert cfg.evict is False
    assert "--no-evict" in schemas.as_cli(cfg)


def test_evict_flag_as_cli_also_covers_release_mode():
    """(2.3, Phase 5) release now runs eviction too -- as_cli() must surface --no-evict there."""
    cfg = schemas.config_from_payload({"interface": "eth1", "mode": "release", "evict": False})
    assert "--no-evict" in schemas.as_cli(cfg)


def test_token_helpers():
    assert auth.token_ok("abc", "abc")
    assert not auth.token_ok("abc", "xyz")
    assert not auth.token_ok("abc", None)
