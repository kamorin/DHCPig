"""Static catalogue of every Finding the engine can raise: id -> (title, verdict, severity,
recommendation). Evidence, and any per-run branching over *which* finding or reason-variant
applies, stays in engine.py -- this module only owns the prose, so a contributor who wants to
know every verdict this tool can emit reads this file instead of hunting through
`_derive_findings()` for `self._raise(` calls.

`build()` covers the common case (a catalogue entry supplies title/verdict/severity/
recommendation as-is; the caller supplies only `evidence`). A few findings have text that
genuinely varies per call -- NEIGHBORS_OBSERVED's title includes the host count,
RUN_SUMMARY's recommendation depends on the mode, and DHCP_STARVATION_NOT_ATTAINED's on which
of four reasons applied -- so `build()` also accepts `title`/`recommendation` overrides, and the
small `*_recommendation()` helpers below pick the right template for each.
"""

from __future__ import annotations

from .models import FAIL, INCONCLUSIVE, INFO, PASS, Finding

_CATALOG: dict[str, dict] = {
    "RUN_SUMMARY": {
        # recommendation is always overridden per call -- see run_summary_recommendation()
        # below, which keys it on the mode (the read-only scans do nothing the spoofing text
        # would describe).
        "title": "What this run did, step by step",
        "verdict": INFO,
        "severity": "info",
        "recommendation": "",
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
    # Raised alongside CLIENTS_EVICTED_FROM_ADDRESSES rather than instead of it: the two cover
    # disjoint sets of hosts, so a run that evicts two targets and leaves a third sitting on a
    # binding we now own has two separate things to report, not one to choose between.
    "CLIENTS_HOLDING_STOLEN_LEASES": {
        "title": "Targets held addresses the server had already reassigned to us",
        "verdict": FAIL,
        "severity": "high",
        "recommendation": (
            "These hosts won the ARP exchange and are still using their addresses, "
            "but the server handed those same addresses to this run — they are on "
            "bindings it no longer recognizes and will lose them at their next "
            "renewal (RFC 2131 T1), with no warning and nothing to see from here "
            "until it happens. Defending the ARP conflict did not protect them, "
            "because the address was taken at the DHCP layer, not the ARP one. "
            "DHCP snooping with a binding table is what prevents the theft; "
            "Dynamic ARP Inspection alone would not have."
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
    "NEIGHBOR_LEASES_RELEASED": {
        # recommendation is always overridden per call -- see
        # neighbor_leases_released_recommendation() below.
        "title": "Sent DHCPRELEASE for ARP-discovered neighbors, then re-acquired them",
        "verdict": INFO,
        "severity": "medium",
        "recommendation": "",
    },
    # release-previous (2.2) -- recovery, not an attack. See docs/DESIGN.md §5e.
    "RELEASE_PREVIOUS_SCOPE_REQUIRED": {
        "title": ("release-previous refused to run: no scope and no resolvable interface network"),
        "verdict": INCONCLUSIVE,
        "severity": "medium",
        "recommendation": (
            "Pass --scope explicitly, or run on an interface with a configured "
            "IPv4 address, so the recovery sweep stays bounded to a known network."
        ),
    },
    "NO_RECOVERY_NEEDED": {
        "title": "A new client already obtains an address — nothing to recover",
        "verdict": INFO,
        "severity": "info",
        "recommendation": "No RELEASE frames were sent.",
    },
    "NO_JOURNAL_DATA": {
        "title": "No journal entries matched this network — nothing to recover",
        "verdict": INFO,
        "severity": "info",
        "recommendation": (
            "Either no prior run left an open lease here, or --scope / --max-age "
            "/ --any-server need adjusting. release-previous only releases leases "
            "this tool recorded taking — it cannot recover what it never recorded."
        ),
    },
    "POOL_RECOVERED": {
        "title": "A new client obtained an address after release-previous ran",
        "verdict": PASS,
        "severity": "info",
        "recommendation": "Recovery confirmed. No further action needed.",
    },
    "POOL_RECOVERY_PARTIAL": {
        "title": "Some targeted leases were not released before the run ended",
        "verdict": INCONCLUSIVE,
        "severity": "medium",
        "recommendation": (
            "Re-run release-previous to retry the remaining entries, or increase --passes."
        ),
    },
    "POOL_RECOVERY_FAILED": {
        "title": "Every targeted lease was released but a new client is still denied",
        "verdict": FAIL,
        "severity": "high",
        "recommendation": (
            "The server did not honor these RELEASE frames, or something else is "
            "denying new clients. Clear the bindings on the server itself — "
            "'omshell' / lease-file edit + reload on ISC dhcpd, 'netsh dhcp server "
            "scope <s> delete clientsbyip' or a scope reconcile on Windows Server "
            "— or wait for the leases to expire."
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
        recommendation=(recommendation if recommendation is not None else entry["recommendation"]),
    )


def run_summary_recommendation(mode: str) -> str:
    """The RUN_SUMMARY recommendation, keyed on `Mode.value`.

    Three variants, because the takeaway from a run is a property of what the run actually did.
    The sending modes all rest on the same weakness -- DHCP accepts a message that names another
    device -- but the two scan modes never send DHCP on anyone's behalf, so that sentence was
    simply false there (an ARP inventory plus a DHCPINFORM names nobody but ourselves). Their
    text says what reconnaissance alone demonstrates instead.

    First sentence of each only reaches the log (finding_summary_lines); the rest is for the
    report, so it has to stand alone.
    """
    if mode == "scan":
        return (
            "Nothing was sent: every line above was learned by listening to broadcast traffic "
            "the segment was already carrying. That is the point -- ARP and DHCP are broadcast "
            "in the clear, so any host that can join this network can build this inventory "
            "without emitting a single frame of its own and without appearing in any server or "
            "switch log. Treat the host list as what an attacker knows before they do anything. "
            "Run an active or destructive mode to test whether the segment defends against "
            "acting on it."
        )
    if mode == "active-scan":
        return (
            "Nothing above took or disturbed a lease: this run mapped the segment with ARP and "
            "asked who the DHCP servers are with DHCPINFORM. Both answer anyone -- ARP has no "
            "authentication at all, and DHCPINFORM is answered without a lease being allocated, "
            "so it identifies the servers without leaving a lease-log entry behind. The result "
            "is a free, low-noise map of the hosts and the DHCP infrastructure on this segment; "
            "the controls worth checking are the ones that limit who can reach it in the first "
            "place (client isolation on the WLAN, segmentation, and Dynamic ARP Inspection "
            "against the ARP-based follow-ups). Run exhaust or release to test what happens "
            "when someone acts on this map."
        )
    return (
        "Every step above works because DHCP never checks that a request comes from "
        "the device it names. Assuming this was run from Wi-Fi, the single "
        "highest-value control is to enable DHCP proxy on the WLAN and have the "
        "controller drop any DHCP message whose client-hardware-address does not "
        "match the MAC of the station that sent it. A wireless station's MAC is "
        "bound to its association (and, under WPA2/WPA3, to its encryption keys), "
        "so the controller is uniquely able to catch this -- and every step above "
        "that touched another device's address depended on being able to send DHCP "
        "on that device's behalf."
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


# Evidence keys that never earn a place on a summary line: run context that's already in the
# report header, config values echoed back, and one key `_finish_release()`'s own
# recommendation text calls out as "not evidence either way".
EVIDENCE_SKIP = frozenset(
    {
        "mode",
        "interface",
        "dry_run",
        "duration_sec",
        "elapsed_sec",
        "rounds",
        "server_id",
        "phase",
        "still_using_address_arp",
    }
)


def finding_summary_lines(f: dict) -> list[str]:
    """The display form of a finding, shared by every human-facing surface.

    **This is the single source of the rule.** `cli/render.py` and `_findings_html()` both call
    it; `events.to_dict()` computes it once into `summary` on every `FindingRaised` event so
    `web/static/app.js` renders the same list instead of re-deriving it in JS -- three surfaces
    used to describe one run three different ways (a divergence that shipped and went unnoticed
    until this was unified), and that's no longer possible by construction. The complete,
    unsummarised finding is still in the JSON export; that's what it's for.

    Three lines at most: the numbers, any list evidence one item per line, then the first
    sentence of the recommendation. Nested dicts flatten rather than serialize; zero, empty and
    `EVIDENCE_SKIP` keys are dropped, because a summary that reports `naked=0 · no_response=0`
    is spending the reader's attention on nothing.
    """
    out: list[str] = []
    nums: list[str] = []
    for key, value in (f.get("evidence") or {}).items():
        if key in EVIDENCE_SKIP:
            continue
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and "did" in item and "got" in item:
                    out.append(f"{item['did']}  ->  {item['got']}")
                elif isinstance(item, dict):
                    # e.g. FOREIGN_DISCOVERS_UNANSWERED's sample_hosts: key=value pairs, not a
                    # Python dict repr -- str(item) used to print {'mac': '...', 'hostname': ''}
                    out.append(" ".join(f"{k}={v}" for k, v in item.items() if v))
                else:
                    out.append(str(item))
        elif isinstance(value, dict):
            nums.extend(f"{k}={v}" for k, v in value.items() if v)
        elif value not in (None, "", 0, False):
            nums.append(f"{key}={value}")
    if nums:
        out.insert(0, " · ".join(nums))
    recommendation = str(f.get("recommendation") or "")
    first = recommendation.split(". ")[0].strip()
    if first:
        out.append(first if first.endswith(".") else first + ".")
    return out


def neighbor_leases_released_recommendation(granted: int, total: int, mode_is_exhaust: bool) -> str:
    """The NEIGHBOR_LEASES_RELEASED recommendation -- three variants, mirroring
    `_finish_release()`'s own reasoning about when a `granted=0` result is meaningful (RFC 2131
    §4.3.1 prefers a fresh free address over honouring option 50 for an unknown MAC, so a zero
    means nothing until the pool is actually drained)."""
    if granted:
        return (
            "The server acted on unauthenticated RELEASE requests for addresses held by "
            "other hosts on the segment, and this run re-acquired "
            f"{granted} of {total} of them by name (DHCP option 50) from a MAC the "
            "server had never seen — any host can force another off its lease and then "
            "take it. Independent of pool exhaustion and worth reporting on its own; "
            "verify DHCP snooping / binding validation on the access switch."
        )
    if not mode_is_exhaust:
        # granted == 0 is only meaningful once the pool is empty. With addresses free, RFC
        # 2131 §4.3.1 has the server prefer a fresh one over honouring option 50 for an
        # unknown MAC, so a zero says nothing about the RELEASE.
        return (
            "None of the freed addresses could be re-acquired. The pool still had "
            "free addresses at this point, so this does NOT show the server protected "
            "the bindings: RFC 2131 has a server prefer an unused address over honouring "
            "a specific request from a MAC it has never seen, which is the same result. "
            "Re-run as `exhaust`, where this step happens after the pool is drained and "
            "the two causes can be told apart."
        )
    return (
        "None of the freed addresses could be re-acquired even with the pool "
        "drained, so the server had no unused address to prefer instead — it "
        "declined to hand another host's address to an unknown MAC. That is the "
        "desired behavior and is real evidence here, unlike the same result before "
        "exhaustion."
    )
