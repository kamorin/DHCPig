"""Static catalogue of every Finding the engine can raise: id -> (title, verdict, severity,
recommendation). Evidence, and any per-run branching over *which* finding or reason-variant
applies, stays in engine.py -- this module only owns the prose, so a contributor who wants to
know every verdict this tool can emit reads this file instead of hunting through
`_derive_findings()` for `self._raise(` calls.

`build()` covers the common case (a catalogue entry supplies title/verdict/severity/
recommendation as-is; the caller supplies only `evidence`). Two findings have text that
genuinely varies per call -- NEIGHBORS_OBSERVED's title includes the host count, and
DHCP_STARVATION_NOT_ATTAINED's recommendation depends on which of four reasons applied -- so
`build()` also accepts `title`/`recommendation` overrides, and
`starvation_not_attained_recommendation()` is the one small helper that picks the right template
for the latter.
"""

from __future__ import annotations

from .models import FAIL, INCONCLUSIVE, INFO, PASS, Finding

_CATALOG: dict[str, dict] = {
    "RUN_SUMMARY": {
        "title": "What this run did, step by step",
        "verdict": INFO,
        "severity": "info",
        "recommendation": (
            # First sentence only reaches the log (finding_summary_lines); the rest is
            # for the report, so it has to stand alone.
            "Every step above works because DHCP never checks that a request comes from "
            "the device it names. Assuming this was run from Wi-Fi, the single "
            "highest-value control is to enable DHCP proxy on the WLAN and have the "
            "controller drop any DHCP message whose client-hardware-address does not "
            "match the MAC of the station that sent it. A wireless station's MAC is "
            "bound to its association (and, under WPA2/WPA3, to its encryption keys), "
            "so the controller is uniquely able to catch this -- and every step above "
            "that touched another device's address depended on being able to send DHCP "
            "on that device's behalf."
        ),
    },
    "NEIGHBORS_OBSERVED": {
        # title is overridden per call (includes the host count) -- kept here anyway so the
        # catalogue stays the complete list of finding ids.
        "title": "N host(s) were on this segment, and what happened to each",
        "verdict": INFO,
        "severity": "info",
        "recommendation": (
            "Inventory of the segment as this run found it, with each host's "
            "outcome. 'offline' means the host had no working address when the run "
            "ended. 'lease_taken' means the server gave us its address while the "
            "host carried on using it -- those hosts are working now and will fail "
            "at their next renewal, with no warning to the user and nothing "
            "observable from this vantage point, so treat that count as delayed "
            "impact rather than none."
        ),
    },
    "CONTROL_BASELINE_FAILED": {
        "title": "Baseline DHCP request from the real NIC MAC failed",
        "verdict": INCONCLUSIVE,
        "severity": "high",
        "recommendation": (
            "Results are not conclusive. Confirm the interface is on the intended "
            "VLAN with a reachable DHCP server before drawing any conclusion about "
            "the network's defenses."
        ),
    },
    "NEW_CLIENT_BLOCKED_AT_BASELINE": {
        "title": "An unknown MAC could not obtain an address even before testing",
        "verdict": PASS,
        "severity": "info",
        "recommendation": (
            "This machine's own MAC was served but an unseen MAC was not — "
            "consistent with DHCP snooping or port security. Exhaustion cannot be "
            "measured against this segment, which is itself the desired outcome."
        ),
    },
    "POOL_HEADROOM_LOW": {
        "title": "The pool was already near full before this test began",
        "verdict": INFO,
        "severity": "medium",
        "recommendation": (
            "A passive, pre-test finding independent of whether exhausting "
            "the pool succeeded: with the scope already this full, only a "
            "few more leases deny service to the next legitimate client. "
            "Consider widening the scope or adding a second one."
        ),
    },
    "DHCP_STARVATION_ATTAINED": {
        "title": "A new client was denied an address while spoofed leases were held",
        "verdict": FAIL,
        "severity": "high",
        "recommendation": (
            "The pool was driven to the point of denying service to a "
            "brand-new client. Rate-limit DHCP per port and enable DHCP "
            "snooping / port security, then re-run to confirm."
        ),
    },
    "DHCP_STARVATION_NOT_ATTAINED": {
        # recommendation is always overridden per call -- see
        # starvation_not_attained_recommendation() below.
        "title": "A new client could still obtain an address after the run",
        "verdict": PASS,
        "severity": "info",
        "recommendation": "",
    },
    "SERVER_STOPPED_SERVING_TEST_CLIENTS": {
        "title": (
            "Server stopped answering the test clients while still serving a new client"
        ),
        "verdict": INFO,
        "severity": "medium",
        "recommendation": (
            "Consistent with DHCP rate-limiting, offer-table saturation "
            "or anti-starvation protection rather than pool exhaustion. "
            "A NAK burst just before offers ceased points at the server "
            "re-offering already-pending addresses."
        ),
    },
    "DRY_RUN_SUMMARY": {
        "title": "Dry run: reconnaissance only, nothing sent that would take a lease",
        "verdict": INFO,
        "severity": "info",
        "recommendation": (
            "The control transaction and ARP discovery ran for real, but the "
            "windowed sender, RELEASE, re-acquisition, and eviction were all "
            "suppressed. Re-run with dry-run disabled to actually measure exhaustion."
        ),
    },
    "DHCP_NAK_OBSERVED": {
        "title": "Server actively refused requests (DHCPNAK)",
        "verdict": INFO,
        "severity": "medium",
        "recommendation": (
            "NAKs often indicate snooping binding-table enforcement or an address "
            "conflict. Correlate with switch logs."
        ),
    },
    "MULTIPLE_DHCP_SERVERS": {
        "title": "More than one DHCP server answered on this segment",
        "verdict": FAIL,
        "severity": "high",
        "recommendation": (
            "Verify each server is authorized. An unexpected responder is a rogue "
            "DHCP server; DHCP snooping with trusted uplink ports prevents this."
        ),
    },
    "FOREIGN_DISCOVERS_UNANSWERED": {
        "title": "Other hosts' DHCPDISCOVERs went unanswered during this run",
        "verdict": FAIL,
        "severity": "high",
        "recommendation": (
            "Other people's machines asked for an address during this run and "
            "got nothing — the most direct evidence of client-visible outage "
            "this tool can produce. Correlate the MACs above against known "
            "devices on the segment."
        ),
    },
    "FOREIGN_DISCOVERS_ANSWERED": {
        "title": "Other hosts' DHCPDISCOVERs were all answered during this run",
        "verdict": INFO,
        "severity": "info",
        "recommendation": (
            "Third-party DHCP kept working alongside this run — no client-"
            "visible outage observed via foreign DISCOVER traffic."
        ),
    },
    "CLIENTS_EVICTED_FROM_ADDRESSES": {
        "title": "ARP-conflict eviction forced clients off their addresses",
        "verdict": FAIL,
        "severity": "high",
        "recommendation": (
            "Any host on this segment can force any other host off its address "
            "using only broadcast ARP (RFC 5227's own address-conflict-detection "
            "mechanism, turned against the client). Enable Dynamic ARP "
            "Inspection / port security to drop forged ARP at the switch port; "
            "without it, this is independent of and cheaper than pool "
            "exhaustion."
        ),
    },
    "CLIENTS_DEFENDED_ADDRESSES": {
        "title": "Targets reacted to the ARP conflict but were not denied service",
        "verdict": INCONCLUSIVE,
        "severity": "medium",
        "recommendation": (
            "Our forged ARP reached the targets — Dynamic ARP Inspection is not "
            "filtering this port. Some held their ground (defended); others "
            "restarted at INIT and immediately reacquired a lease, which is the "
            "expected, low-harm outcome under release mode since the pool was "
            "never drained. Not a pass: some clients defend and still lose the "
            "gateway entry, which this vantage point cannot see, and 'defended' "
            "targets in particular show DAI is not filtering this port."
        ),
    },
    "ARP_CONFLICTS_UNANSWERED": {
        "title": "ARP-conflict frames drew no reaction from any target",
        "verdict": INCONCLUSIVE,
        "severity": "medium",
        "recommendation": (
            "Either the frames were filtered (Dynamic ARP Inspection / port "
            "security) or every target simply accepted them silently — both "
            "look identical from here. Check DAI drop counters on the switch."
        ),
    },
    "RACED_FREED_ADDRESSES": {
        "title": "Raced to re-acquire addresses as soon as they were observed freed",
        "verdict": INFO,
        "severity": "info",
        "recommendation": (
            "A foreign NAK, DECLINE, or (if --race-on-rediscover) a rediscovering "
            "known neighbor was treated as a signal that an address just came free, "
            "and this tool immediately raced to grab it ahead of the address's "
            "original owner. A high win rate here demonstrates that a departing "
            "or bounced client cannot reliably reclaim its own address on this "
            "segment without additional protection (DHCP snooping binding "
            "persistence, static reservations)."
        ),
    },
}


def build(
    id: str,  # noqa: A002 -- matches Finding's own field name
    evidence: dict,
    *,
    title: str | None = None,
    recommendation: str | None = None,
) -> Finding:
    """Build the Finding for `id` from the catalogue, with the given evidence.

    `title`/`recommendation` override the catalogue's static text for the handful of findings
    whose wording genuinely depends on the call (see the catalogue entries' own comments).
    """
    entry = _CATALOG[id]
    return Finding(
        id=id,
        title=title if title is not None else entry["title"],
        verdict=entry["verdict"],
        severity=entry["severity"],
        evidence=evidence,
        recommendation=(
            recommendation if recommendation is not None else entry["recommendation"]
        ),
    )


def starvation_not_attained_recommendation(
    reason: str,
    *,
    signal: str | None = None,
    detail: str | None = None,
    leases_at_halt: int | None = None,
    headroom: int | None = None,
) -> str:
    """The DHCP_STARVATION_NOT_ATTAINED recommendation, one of four templates keyed on `reason`
    -- see `_derive_findings()`'s reason-selection logic in engine.py, which this only renders
    text for. First reason that applies wins there; this just mirrors the same four branches."""
    if reason == "control_fired":
        return (
            f"Sending stopped on {signal} ({detail}) after {leases_at_halt} "
            "lease(s) held — that control is what's providing protection here; "
            "confirm it in switch/DHCP-server logs."
        )
    if reason == "pool_headroom_remaining":
        hr = headroom if headroom is not None else "an unknown amount of"
        return (
            f"A new client could still obtain an address, with ~{hr} address(es) "
            "of headroom estimated remaining — the pool was not driven to "
            "exhaustion within this run."
        )
    if reason == "blocked_at_baseline":
        return (
            "An unknown MAC could not obtain an address even before the test "
            "began — consistent with DHCP snooping or port security. See "
            "NEW_CLIENT_BLOCKED_AT_BASELINE for the direct evidence."
        )
    # inconclusive_baseline
    return (
        "The baseline request from this machine's real MAC failed, so "
        "nothing here can be concluded. See CONTROL_BASELINE_FAILED."
    )
