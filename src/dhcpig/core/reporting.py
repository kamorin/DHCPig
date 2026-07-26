"""Session recorder -> JSON / CSV / HTML report."""

from __future__ import annotations

import json
import time
from dataclasses import asdict
from enum import Enum
from pathlib import Path

from . import events as ev
from .fingerprint import DB_VERSION
from .models import SessionConfig


def _json_default(o):
    if isinstance(o, Enum):
        return o.value
    if isinstance(o, Path):
        return str(o)
    if isinstance(o, bytes):
        return o.hex()
    return str(o)


class SessionRecorder:
    """Subscribe to the bus; accumulate a serializable session record."""

    def __init__(self, cfg: SessionConfig) -> None:
        self.cfg = cfg
        self.started = time.time()
        self.servers: dict[str, dict] = {}
        self.leases: list[dict] = []
        # keyed by MAC so a re-emitted NeighborFound (e.g. a DHCP fingerprint arriving after the
        # initial ARP sighting) updates the same row instead of appending a duplicate
        self.neighbors_by_mac: dict[str, dict] = {}
        self.fingerprints: list[dict] = []
        self.skipped: list[dict] = []
        self.findings: list[dict] = []
        self.controls: list[dict] = []
        self.naks: list[dict] = []
        self.exhausted = False
        self.exhaustion_confirmed = False
        self.final_status: dict = {}

    def handle(self, event: ev.Event) -> None:
        if isinstance(event, ev.ServerDiscovered):
            self.servers[event.server.server_id] = asdict(event.server)
        elif isinstance(event, ev.AckReceived):
            self.leases.append(asdict(event.lease))
        elif isinstance(event, ev.NeighborFound):
            self.neighbors_by_mac[event.neighbor.mac] = asdict(event.neighbor)
        elif isinstance(event, ev.HostFingerprinted):
            self.fingerprints.append(asdict(event.fp))
        elif isinstance(event, ev.Skipped):
            self.skipped.append({"ip": event.ip, "reason": event.reason})
        elif isinstance(event, ev.NakReceived):
            self.naks.append({"server_ip": event.server_ip})
        elif isinstance(event, ev.FindingRaised):
            self.findings.append(asdict(event.finding))
        elif isinstance(event, ev.ControlFinished):
            self.controls.append(asdict(event.outcome))
        elif isinstance(event, ev.PoolExhausted):
            self.exhausted = True
            if event.confirmed:
                self.exhaustion_confirmed = True
        elif isinstance(event, ev.SessionEnded):
            self.final_status = event.report

    def _config_redacted(self) -> dict:
        d = asdict(self.cfg)
        d["mode"] = self.cfg.mode.value
        d["ip_version"] = self.cfg.ip_version.value
        if d.get("report_path") is not None:
            d["report_path"] = str(d["report_path"])
        return d

    def to_dict(self) -> dict:
        # jsonable() converts any nested enums/bytes so the web /api/report path (plain
        # json.dumps) and the file export both work.
        return ev.jsonable(
            {
                "tool": "dhcpig",
                "version": "2.0.0",
                "interface": self.cfg.interface,
                "mode": self.cfg.mode.value,
                "started_at": self.started,
                "ended_at": time.time(),
                "config": self._config_redacted(),
                "scope_cidrs": self.cfg.scope_cidrs,
                "fingerprint_db": DB_VERSION,
                "servers": list(self.servers.values()),
                "leases": self.leases,
                "neighbors": list(self.neighbors_by_mac.values()),
                "fingerprints": self.fingerprints,
                "skipped": self.skipped,
                "naks": self.naks,
                # the verdicts, and the control transactions that make them trustworthy
                "findings": self.findings,
                "control_transactions": self.controls,
                "pool_exhausted": self.exhausted,
                "pool_exhaustion_confirmed": self.exhaustion_confirmed,
                # always labelled as an estimate — see PoolEstimate / DhcpEngine._estimate_pool()
                "pool_estimate": {
                    "size": self.final_status.get("pool_size"),
                    "source": self.final_status.get("pool_source"),
                    "is_estimate": self.final_status.get("pool_is_estimate"),
                    "detail": self.final_status.get("pool_detail"),
                    "headroom": self.final_status.get("headroom"),
                    "in_use_observed": self.final_status.get("in_use_observed"),
                },
            }
        )

    # ------------------------------------------------------------------ rendering
    def render(self, fmt: str = "json") -> tuple[str, str]:
        """Return (text, content_type) for the given format: json | csv | html."""
        data = self.to_dict()
        if fmt == "json":
            return json.dumps(data, indent=2, default=_json_default), "application/json"
        if fmt == "csv":
            return _to_csv(data), "text/csv"
        if fmt == "html":
            return _to_html(data), "text/html"
        raise ValueError(f"unsupported format: {fmt} (use json|csv|html)")

    def export(self, path: str | Path, fmt: str = "json") -> Path:
        path = Path(path)
        text, _ = self.render(fmt)
        path.write_text(text)
        return path


# --------------------------------------------------------------------------- formatters


def _flat_rows(data: dict) -> list[dict]:
    """A flat inventory: one row per server / lease / neighbor / fingerprint."""
    rows: list[dict] = []
    for s in data.get("servers", []):
        fp = s.get("fingerprint") or {}
        rows.append(
            {
                "kind": "server",
                "mac": s.get("server_mac", ""),
                "ip": s.get("server_id", ""),
                "server_id": s.get("server_id", ""),
                "os": fp.get("os", ""),
                "device": fp.get("device", ""),
                "vendor": fp.get("vendor", ""),
                "confidence": fp.get("confidence", ""),
            }
        )
    for ln in data.get("leases", []):
        rows.append(
            {
                "kind": "lease",
                "mac": ln.get("mac", ""),
                "ip": ln.get("ip", ""),
                "server_id": ln.get("server_ip", ""),
                "os": "",
                "device": "",
                "vendor": "",
                "confidence": "",
            }
        )
    for n in data.get("neighbors", []):
        fp = n.get("fingerprint") or {}
        rows.append(
            {
                "kind": "neighbor",
                "mac": n.get("mac", ""),
                "ip": n.get("ip", ""),
                "server_id": "",
                "os": fp.get("os", ""),
                "device": fp.get("device", ""),
                "vendor": fp.get("vendor", ""),
                "confidence": fp.get("confidence", ""),
            }
        )
    for fp in data.get("fingerprints", []):
        rows.append(
            {
                "kind": "host",
                "mac": fp.get("mac", ""),
                "ip": fp.get("ip", ""),
                "server_id": "",
                "os": fp.get("os", ""),
                "device": fp.get("device", ""),
                "vendor": fp.get("vendor", ""),
                "confidence": fp.get("confidence", ""),
            }
        )
    return rows


def _to_csv(data: dict) -> str:
    import csv
    import io

    cols = ["kind", "mac", "ip", "server_id", "os", "device", "vendor", "confidence"]
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=cols)
    w.writeheader()
    for row in _flat_rows(data):
        w.writerow({c: row.get(c, "") for c in cols})
    return buf.getvalue()


def _findings_html(data: dict) -> str:
    from html import escape

    findings = data.get("findings", [])
    if not findings:
        return "<p><i>No findings recorded.</i></p>"
    colors = {"FAIL": "#c0392b", "PASS": "#27812f", "INCONCLUSIVE": "#b7791f", "INFO": "#555"}
    out = []
    for f in findings:
        verdict = str(f.get("verdict", ""))
        out.append(
            f'<div class="finding"><span class="v" style="background:'
            f'{colors.get(verdict, "#555")}">{escape(verdict)}</span> '
            f"<b>{escape(str(f.get('title', '')))}</b> "
            f"<code>{escape(str(f.get('id', '')))}</code>"
            f'<div class="ev">evidence: {escape(str(f.get("evidence", {})))}</div>'
            f'<div class="rec">{escape(str(f.get("recommendation", "")))}</div></div>'
        )
    return "\n".join(out)


def _control_html(data: dict) -> str:
    from html import escape

    rows = []
    for c in data.get("control_transactions", []):
        if not c.get("attempted"):
            status = f"skipped — {c.get('reason', '')}"
        elif c.get("success"):
            status = f"lease {c.get('offered_ip')} from {c.get('server_id')}"
        else:
            status = f"FAILED — {c.get('reason', '')}"
        who = "own MAC (renewal)" if c.get("client", "self") == "self" else "new client"
        rows.append(
            f"<tr><td>{escape(str(c.get('phase', '')))} / {escape(who)}</td>"
            f"<td>{escape(str(c.get('mac', '')))}</td>"
            f"<td>{escape(status)}</td>"
            f"<td>{escape(str(c.get('elapsed', '')))}s</td></tr>"
        )
    if not rows:
        return "<p><i>No control transactions were run.</i></p>"
    return (
        "<table><thead><tr><th>phase</th><th>real NIC MAC</th><th>result</th><th>elapsed</th>"
        "</tr></thead><tbody>" + "\n".join(rows) + "</tbody></table>"
    )


def _pool_estimate_line(data: dict) -> str:
    from html import escape

    est = data.get("pool_estimate") or {}
    size = est.get("size")
    if size is None:
        return ""
    headroom = est.get("headroom")
    tag = "estimate" if est.get("is_estimate") else "from scope"
    return (
        f"<p><b>Pool headroom:</b> {escape(str(headroom))} / ~{escape(str(size))} "
        f"({escape(tag)}, source: {escape(str(est.get('source')))}) &nbsp; "
        f"<i>{escape(str(est.get('detail', '')))}</i></p>"
    )


def _to_html(data: dict) -> str:
    from html import escape

    rows = _flat_rows(data)
    body = "\n".join(
        "<tr>"
        + "".join(
            f"<td>{escape(str(r.get(c, '')))}</td>"
            for c in ("kind", "mac", "ip", "server_id", "os", "device", "vendor", "confidence")
        )
        + "</tr>"
        for r in rows
    )
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>DHCPig report</title>
<style>body{{font-family:system-ui,sans-serif;margin:2rem}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccc;padding:4px 8px;
font-size:13px;text-align:left}}th{{background:#f2f2f2}}
.finding{{border:1px solid #ddd;border-left-width:5px;padding:8px 12px;margin:8px 0}}
.finding .v{{color:#fff;padding:1px 7px;border-radius:3px;font-size:11px;font-weight:700}}
.finding code{{color:#666;font-size:11px}}
.finding .ev{{font-size:12px;color:#444;margin-top:4px;font-family:ui-monospace,monospace}}
.finding .rec{{font-size:12px;color:#666;margin-top:4px}}</style></head><body>
<h1>DHCPig report</h1>
<p><b>Interface:</b> {escape(str(data.get("interface")))} &nbsp;
<b>Mode:</b> {escape(str(data.get("mode")))} &nbsp;
<b>Exhausted:</b> {escape(str(data.get("pool_exhausted")))}
(confirmed: {escape(str(data.get("pool_exhaustion_confirmed")))}) &nbsp;
<b>Scope:</b> {escape(str(data.get("scope_cidrs")))} &nbsp;
<b>Fingerprint DB:</b> {escape(str(data.get("fingerprint_db")))}</p>
{_pool_estimate_line(data)}
<h2>Findings</h2>
{_findings_html(data)}
<h2>Control transactions</h2>
<p style="font-size:12px;color:#666">A legitimate DHCP cycle from the real NIC MAC, run before
and after the test. A failed <i>pre</i> means the result is inconclusive; a failed <i>post</i>
after a good <i>pre</i> is evidence the pool was drained.</p>
{_control_html(data)}
<h2>Inventory</h2>
<table><thead><tr><th>kind</th><th>mac</th><th>ip</th><th>server_id</th><th>os</th>
<th>device</th><th>vendor</th><th>confidence</th></tr></thead>
<tbody>{body}</tbody></table></body></html>"""
