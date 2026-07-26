"""Subscribe to the core EventBus and print CUJ-style text lines. Verbosity-aware."""

from __future__ import annotations

import sys

from ..core import events as ev

_COLORS = {
    "->": "\033[36m",  # cyan  outbound
    "<-": "\033[34m",  # blue  inbound
    "--": "\033[37m",  # grey  notice
    "!!": "\033[1;31m",  # red   alert
    "??": "\033[33m",  # yellow prompt
    "XX": "\033[1;31m",  # red   error
    "DBG": "\033[35m",  # purple debug
    "CTL": "\033[1;36m",  # bright cyan — control transaction
    "==": "\033[1;37m",  # bright white — findings/verdicts
}
_RESET = "\033[0m"

_VERDICT_COLOR = {
    "PASS": "\033[1;32m",
    "FAIL": "\033[1;31m",
    "INCONCLUSIVE": "\033[1;33m",
    "INFO": "\033[1;37m",
}


class Renderer:
    def __init__(self, verbosity: int = 2, color: bool | None = None) -> None:
        self.verbosity = verbosity
        self.color = sys.stdout.isatty() if color is None else color

    def _line(self, tag: str, msg: str) -> None:
        if self.verbosity <= 0:
            return
        if self.verbosity == 1:
            sys.stdout.write(
                {"->": ".", "<-": ";", "--": "N", "!!": "!", "??": "?", "XX": "E", "DBG": "D"}.get(
                    tag, "."
                )
            )
            sys.stdout.flush()
            return
        prefix = f"[{tag}]"
        if self.color and tag in _COLORS:
            prefix = f"{_COLORS[tag]}{prefix}{_RESET}"
        sys.stdout.write(f"{prefix} {msg}\n")
        sys.stdout.flush()

    def _finding(self, f) -> None:
        """Findings are the point of the exercise — always show them, even at verbosity 0."""
        verdict = f.verdict
        label = f"[{verdict}]"
        if self.color and verdict in _VERDICT_COLOR:
            label = f"{_VERDICT_COLOR[verdict]}{label}{_RESET}"
        sys.stdout.write(f"{label} {f.title}  ({f.id})\n")
        if self.verbosity >= 2:
            if f.evidence:
                sys.stdout.write(f"        evidence: {f.evidence}\n")
            if f.recommendation:
                sys.stdout.write(f"        {f.recommendation}\n")
        sys.stdout.flush()

    def handle(self, e: ev.Event) -> None:
        if isinstance(e, ev.DiscoverSent):
            self._line("->", "DHCP_Discover")
        elif isinstance(e, ev.OfferReceived):
            self._line("<-", f"DHCP_Offer    {e.lease.ip}   from {e.server.server_id}")
        elif isinstance(e, ev.RequestSent):
            self._line("->", f"DHCP_Request  {e.lease.ip}")
        elif isinstance(e, ev.AckReceived):
            self._line("<-", f"DHCP_ACK      {e.lease.ip}")
        elif isinstance(e, ev.NakReceived):
            self._line("!!", f"DHCP_NAK from {e.server_ip}")
        elif isinstance(e, ev.ServerDiscovered):
            fp = e.server.fingerprint
            tail = f"  fp={fp.os or fp.device or 'unknown'}" if fp else ""
            self._line("--", f"DHCP server {e.server.server_id}{tail}")
        elif isinstance(e, ev.NeighborFound):
            self._line("<-", f"ARP {e.neighbor.ip} : {e.neighbor.mac}")
        elif isinstance(e, ev.HostFingerprinted):
            fp = e.fp
            label = fp.os or fp.device or "unknown"
            self._line("--", f"host {fp.mac}  {label}  conf {fp.confidence}%  via {fp.matched_via}")
        elif isinstance(e, ev.LeaseReleased):
            self._line("->", f"DHCPRELEASE  {e.lease.ip}   (in scope)")
        elif isinstance(e, ev.GarpSent):
            self._line("->", f"Gratuitous_ARP  knock offline {e.ip}   (in scope)")
        elif isinstance(e, ev.Skipped):
            self._line("!!", f"SKIPPED      {e.ip}   {e.reason}")
        elif isinstance(e, ev.LimitReached):
            self._line(
                "--",
                f"LIMIT REACHED   leases={e.leases}  in {e.elapsed:.0f}s "
                f"(your --max-leases cap, not the server's pool)",
            )
        elif isinstance(e, ev.PoolExhausted):
            suffix = (
                "CONFIRMED by post-run control"
                if e.confirmed
                else "provisional — offers stopped arriving"
            )
            self._line("!!", f"POOL EXHAUSTED  leases={e.leases}  in {e.elapsed:.0f}s  [{suffix}]")
        elif isinstance(e, ev.ControlStarted):
            self._line("CTL", f"CONTROL[{e.phase}] starting legitimate DHCP cycle (real NIC MAC)")
        elif isinstance(e, ev.ControlFinished):
            self._line("CTL", f"CONTROL[{e.outcome.phase}] {_control_summary(e.outcome)}")
        elif isinstance(e, ev.FindingRaised):
            self._finding(e.finding)
        elif isinstance(e, ev.ErrorEvent):
            self._line("XX", e.message)
        elif isinstance(e, ev.Debug):
            if self.verbosity >= 3:  # debug detail only at highest verbosity
                self._line("DBG", e.message)


def _control_summary(out) -> str:
    if not out.attempted:
        return out.reason or "skipped"
    if out.success:
        tail = f" from {out.server_id}" if out.server_id else ""
        return f"OK — obtained {out.offered_ip}{tail} in {out.elapsed}s (then released)"
    return f"FAILED — {out.reason} ({out.elapsed}s)"
