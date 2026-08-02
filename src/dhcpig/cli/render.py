"""Subscribe to the core EventBus and print CUJ-style text lines. Verbosity-aware."""

from __future__ import annotations

import sys

from ..core import events as ev
from ..core.reporting import finding_summary_lines

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
    "##": "\033[1;34m",  # bright blue — periodic status
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
                {
                    "->": ".",
                    "<-": ";",
                    "--": "N",
                    "!!": "!",
                    "??": "?",
                    "XX": "E",
                    "DBG": "D",
                    "##": "S",
                }.get(tag, ".")
            )
            sys.stdout.flush()
            return
        prefix = f"[{tag}]"
        if self.color and tag in _COLORS:
            prefix = f"{_COLORS[tag]}{prefix}{_RESET}"
        sys.stdout.write(f"{prefix} {msg}\n")
        sys.stdout.flush()

    def _finding(self, f) -> None:
        """Findings are the point of the exercise — always show them, even at verbosity 0.

        The **verdict word is deliberately not printed here**. `f.verdict` still exists, still
        colours the line, and still carries PASS/FAIL into the Findings tab and the JSON/HTML
        report -- that's the auditable output and it must keep its verdicts (§5a). But on the
        running log a bare `[FAIL]` next to a title reads as a judgement on the operator's
        network mid-run, when what the log is for is saying what happened. The run's conclusion
        is the OUTCOME roll-up at the end, in host counts. Don't reintroduce the word here
        without also re-reading why the roll-up is phrased the way it is.
        """
        label = "[==]"
        if self.color and f.verdict in _VERDICT_COLOR:
            label = f"{_VERDICT_COLOR[f.verdict]}{label}{_RESET}"
        sys.stdout.write(f"{label} {f.title}  ({f.id})\n")
        if self.verbosity >= 2:
            summary = {
                "evidence": f.evidence,
                "recommendation": f.recommendation,
            }
            for line in finding_summary_lines(summary):
                sys.stdout.write(f"        {line}\n")
        sys.stdout.flush()

    def _neighbor_summary(self, e) -> None:
        """End-of-run roll-call: **one line per host, every discovered host listed**, worst
        first. Hosts are named rather than counted -- the operator's next move is usually to go
        look at a specific machine -- and the untouched ones are listed too, so "unaffected" is
        visibly distinct from "not examined".

        Shown from verbosity 1 up: at v0 the run is deliberately silent except findings, but at
        v1 (the one-char-per-packet mode) a who-did-this-affect block is exactly what's wanted
        at the end.
        """
        if self.verbosity <= 0:
            return
        if self.verbosity == 1:
            sys.stdout.write("\n")  # close off the one-char-per-packet stream
        self._line("==", f"NEIGHBOR SUMMARY  {e.total} host(s) seen before this run")
        # hostname column only when we actually have one for somebody -- DHCP option 12 is the
        # only source, so an ARP-only segment has none and an always-on column would be blank
        namew = max((len(h) for *_r, h, _o, _c in e.rows), default=0)
        for ip, mac, host, outcome, category in e.rows:
            name = f"{host:<{namew}}  " if namew else ""
            self._line(_ROLLCALL_TAG[category], f"  {ip:<15} {mac}  {name}{outcome}")
        self._line("==", "OUTCOME")
        for outcome, n, category in outcome_tally(e.rows):
            self._line(_ROLLCALL_TAG[category], f"  {n:>3} host(s)  {outcome}")

    def handle(self, e: ev.Event) -> None:
        if isinstance(e, ev.DiscoverSent):
            tail = _opt50_hostname(e.option50, e.hostname)
            self._line("->", f"DHCP_Discover  chaddr={e.mac}{tail}")
        elif isinstance(e, ev.OfferReceived):
            self._line(
                "<-",
                f"DHCP_Offer    {e.lease.ip}   from {e.server.server_id}  chaddr={e.lease.mac}",
            )
        elif isinstance(e, ev.RequestSent):
            self._line(
                "->",
                f"DHCP_Request  {e.lease.ip}   chaddr={e.lease.mac}"
                f"{_opt50_hostname(e.option50, e.hostname)}",
            )
        elif isinstance(e, ev.AckReceived):
            self._line("<-", f"DHCP_ACK      {e.lease.ip}   chaddr={e.lease.mac}")
        elif isinstance(e, ev.NakReceived):
            self._line("!!", f"DHCP_NAK from {e.server_ip}")
        elif isinstance(e, ev.ServerDiscovered):
            fp = e.server.fingerprint
            tail = f"  fp={fp.os or fp.device or 'unknown'}" if fp else ""
            self._line("--", f"DHCP server {e.server.server_id}{tail}")
        elif isinstance(e, ev.NeighborFound):
            fp = e.neighbor.fingerprint
            who = f"  {fp.os or fp.device or fp.vendor}" if fp and (fp.os or fp.device) else ""
            self._line("<-", f"ARP {e.neighbor.ip} : {e.neighbor.mac}{who}")
        elif isinstance(e, ev.HostFingerprinted):
            fp = e.fp
            label = fp.os or fp.device or fp.vendor or "unknown"
            self._line("--", f"host {fp.mac}  {label}  conf {fp.confidence}%  via {fp.matched_via}")
        elif isinstance(e, ev.LeaseReleased):
            self._line("->", f"DHCPRELEASE  {e.lease.ip}   chaddr={e.lease.mac}   (in scope)")
        elif isinstance(e, ev.ArpConflictSent):
            self._line("->", f"ARP_conflict  contest ownership of {e.ip}   (in scope)")
        elif isinstance(e, ev.ForeignDiscover):
            who = f"  hostname={e.hostname!r}" if e.hostname else ""
            self._line("<-", f"foreign DHCP_Discover  {e.mac}{who}   (not ours)")
        elif isinstance(e, ev.ClientEvicted):
            tag = "!!" if e.outcome in ("declined", "discover_unanswered", "apipa") else "<-"
            self._line(tag, f"evict outcome  {e.ip} / {e.mac}  -> {e.outcome}")
        elif isinstance(e, ev.NeighborSummary):
            self._neighbor_summary(e)
        elif isinstance(e, ev.Skipped):
            self._line("!!", f"SKIPPED      {e.ip}   {e.reason}")
        elif isinstance(e, ev.StatusTick):
            # debug tier (-v3): the pulse is useful when diagnosing a stalled run, but at normal
            # verbosity it repeats every 5s and drowns out the packet lines around it
            if self.verbosity >= 3:
                self._line("##", status_summary(e.stats))
        elif isinstance(e, ev.OffersCeased):
            self._line(
                "--",
                f"offers quiet for {e.quiet_for:.0f}s after {e.leases} lease(s) — "
                f"declaring exhaustion at {e.deadline:.0f}s of silence",
            )
        elif isinstance(e, ev.PoolExhausted):
            suffix = (
                "CONFIRMED by post-run control"
                if e.confirmed
                else "provisional — offers stopped arriving"
            )
            self._line("!!", f"POOL EXHAUSTED  leases={e.leases}  in {e.elapsed:.0f}s  [{suffix}]")
        elif isinstance(e, ev.ControlDetected):
            self._line(
                "!!",
                f"CONTROL DETECTED [{e.signal}]  {e.detail}  "
                f"— sending stopped, {e.leases_held} lease(s) held for the report",
            )
        elif isinstance(e, ev.ControlStarted):
            self._line("CTL", f"CONTROL[{e.phase}] starting legitimate DHCP cycle")
        elif isinstance(e, ev.ControlFinished):
            o = e.outcome
            who = "own MAC/renewal" if o.client == "self" else "NEW client"
            self._line("CTL", f"CONTROL[{o.phase}/{who}] {_control_summary(o)}")
        elif isinstance(e, ev.FindingRaised):
            self._finding(e.finding)
        elif isinstance(e, ev.ErrorEvent):
            self._line("XX", e.message)
        elif isinstance(e, ev.Debug):
            if self.verbosity >= 3:  # debug detail only at highest verbosity
                self._line("DBG", e.message)


_ROLLCALL_TAG = {"offline": "!!", "lease_taken": "!!", "reacted": "<-", "unaffected": "--"}


def outcome_tally(rows: list) -> list[tuple[str, int, str]]:
    """Group roll-call rows into `(outcome, host_count, category)`, worst first.

    The concluding "N host(s) did X" block. Same data as the per-host lines above it, aggregated
    -- on a segment of any size the per-host list is the detail and this is the answer. Phrased
    as counts of hosts and what happened to them, never as a verdict: the findings own
    pass/fail, and having the log deliver a second, differently-worded judgement of the same
    run is exactly the drift `_run_summary_steps()` is documented to avoid.
    """
    seen: dict[str, tuple[int, str]] = {}
    for *_r, outcome, category in rows:  # rows arrive worst-first, so dict order is too
        count, _cat = seen.get(outcome, (0, category))
        seen[outcome] = (count + 1, category)
    return [(outcome, n, cat) for outcome, (n, cat) in seen.items()]


def _opt50_hostname(option50: str | None, hostname: str | None) -> str:
    """Trailing `  option50=...  hostname=...` clause for a DISCOVER/REQUEST line -- shown at
    the normal info level (not gated to -v3 debug) so an operator can see, without raising
    verbosity, exactly what address and hostname each outbound packet claimed."""
    tail = ""
    if option50:
        tail += f"  option50={option50}"
    if hostname:
        tail += f"  hostname={hostname!r}"
    return tail


def status_summary(s: dict) -> str:
    """One-line run pulse: totals with per-window deltas, so a stalled run is obvious.

    Only counters that are actually moving (or non-zero) are shown, so a scan run doesn't
    carry empty lease/arp_conflicts columns around.
    """
    w = s.get("window", 0)
    parts = [f"t={s.get('elapsed', 0):.0f}s", str(s.get("state", ""))]

    def col(label: str, total_key: str, rate: str | None = None) -> None:
        total = s.get(total_key, 0)
        delta = s.get(f"d_{total_key}", 0)
        if not total and not delta:
            return
        chunk = f"{label} {total} (+{delta} in {w:.0f}s"
        if rate and s.get(rate) is not None:
            chunk += f", {s[rate]}/s"
        parts.append(chunk + ")")

    col("leases", "leases", "lease_pps")
    col("discovers", "discovers", "discover_pps")
    col("offers", "offers")
    col("naks", "naks")
    col("releases", "releases")
    col("arp_conflicts", "arp_conflicts")
    col("foreign_discovers", "foreign_discovers")
    col("foreign_unanswered", "foreign_discovers_unanswered")
    col("races", "races")
    if s.get("servers"):
        parts.append(f"servers {s['servers']}")
    if s.get("neighbors"):
        parts.append(f"neighbors {s['neighbors']}")
    if s.get("send_window") is not None:
        parts.append(f"window {s['send_window']} (inflight {s.get('inflight', 0)})")
    if s.get("timeouts"):
        parts.append(f"timeouts {s['timeouts']}")
    if s.get("headroom") is not None:
        tag = "" if s.get("pool_source") == "scope" else " est."
        parts.append(f"headroom {s['headroom']} / ~{s.get('pool_size')}{tag}")
    quiet = s.get("since_last_offer")
    if quiet is not None:
        parts.append(f"last offer {quiet:.0f}s ago")
    if s.get("halt_signal"):
        parts.append(f"HALTED[{s['halt_signal']}]")
    return "  ".join(parts)


def _control_summary(out) -> str:
    if not out.attempted:
        return out.reason or "skipped"
    if out.success:
        tail = f" from {out.server_id}" if out.server_id else ""
        return f"OK — obtained {out.offered_ip}{tail} in {out.elapsed}s (then released)"
    return f"FAILED — {out.reason} ({out.elapsed}s)"
