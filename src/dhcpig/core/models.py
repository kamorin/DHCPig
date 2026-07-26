"""Data models: session config, discovered entities, fingerprints."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class IPVersion(Enum):
    V4 = "v4"
    V6 = "v6"


class Mode(Enum):
    EXHAUST = "exhaust"
    SCAN = "scan"  # passive: listen only
    ACTIVE_SCAN = "active-scan"  # active discovery: ARP sweep + DHCP INFORM (scope required)
    RELEASE_NEIGHBORS = "release"
    GARP_DOS = "garp"


# Modes that disrupt live clients. Used for labelling and reporting only — they are no longer
# gated behind an authorization attestation, and --scope is optional (it bounds a run when
# supplied, and otherwise the interface's own network is used).
DESTRUCTIVE_MODES: set[Mode] = {Mode.RELEASE_NEIGHBORS, Mode.GARP_DOS}
# active-scan still requires an explicit scope so its sweep can't be unbounded
SCOPE_REQUIRED_MODES: set[Mode] = {Mode.ACTIVE_SCAN}

# Exhaust no longer takes --rate: the windowed handshake pipeline (window_initial/window_max)
# is the pacing mechanism now. rate_limit_pps is set high enough here that the token bucket
# never binds; it stays wired through _send() so the invariant "everything funnels through the
# rate limiter" holds, but the window is what actually shapes exhaust's traffic.
EXHAUST_DEFAULT_RATE_PPS = 500


@dataclass
class Timeouts:
    thread_spawn: float = 0.4  # legacy -x (no longer paces the sender; --rate does)
    dos: float = 8.0  # legacy -y
    dhcp_request: float = 2.0  # legacy -z
    control: float = 5.0  # per-leg wait for the control transaction's OFFER / ACK
    offer_silence: float = 10.0  # offers must stop this long before we suspect exhaustion
    # garp re-poisoning period. Hosts re-ARP within seconds and the real owner answers, so a
    # single pass is undone almost immediately — the mapping only sticks if it is refreshed.
    garp_interval: float = 2.0


@dataclass
class SessionConfig:
    interface: str
    mode: Mode = Mode.EXHAUST
    ip_version: IPVersion = IPVersion.V4
    client_macs: list[str] | None = None  # None => random
    # Default True: ethernet frame src == per-client MAC, so each simulated client is distinct
    # at Layer 2 (exercises port-security / DHCP snooping). Set False for Wi-Fi (APs drop
    # frames with foreign/multiple source MACs) — then only the BOOTP chaddr is randomized.
    spoof_ethernet_src: bool = True
    request_options: list[int] = field(default_factory=lambda: list(range(80)))
    fuzz: bool = False
    rate_limit_pps: int = 10  # the bound on how fast a run can consume a pool
    v6_rapid_commit: bool = False
    dry_run: bool = False
    scope_cidrs: list[str] | None = None  # optional; bounds targets when supplied
    # Default False: keep the leases after the run so the exhausted state can be observed and
    # verified. Release them explicitly with `dhcpig restore` / the Restore button when done.
    restore_on_exit: bool = False
    report_path: Path | None = None
    # Run a legitimate DHCP cycle from the real NIC MAC before and after exhausting. This is
    # what separates "the network blocked us" (PASS) from "the test was broken" (INCONCLUSIVE).
    control: bool = True
    # ARP-sweep the segment before exhausting, to record who was there beforehand
    arp_sweep: bool = True
    # Release the leases of ARP-discovered neighbors before exhausting, so the CUJ of "free up
    # addresses, then take them" is actually exercised rather than assumed. Requires a known
    # server (from control_pre); skipped with a Debug if none is available.
    release_neighbors: bool = True
    status_interval: float = 5.0  # heartbeat period for StatusTick; 0 disables
    window_initial: int = 8  # exhaust: starting number of in-flight DISCOVER/REQUEST transactions
    window_max: int = 64  # exhaust: ceiling the adaptive window may grow to
    timeouts: Timeouts = field(default_factory=Timeouts)
    verbosity: int = 2


@dataclass
class HostFingerprint:
    mac: str
    ip: str
    role: str  # "server" | "client" | "neighbor"
    os: str | None = None
    device: str | None = None
    vendor: str | None = None
    confidence: int = 0
    matched_via: str = ""
    raw_prl: list[int] = field(default_factory=list)


@dataclass
class ServerInfo:
    server_id: str
    server_mac: str
    subnet: str | None
    ip_version: IPVersion
    offers_seen: int = 0
    fingerprint: HostFingerprint | None = None


@dataclass
class Lease:
    mac: str
    ip: str
    server_ip: str
    xid: int
    ip_version: IPVersion
    lease_time: int | None = None
    acquired_at: float = 0.0
    released: bool = False
    server_mac: str | None = None  # so a later RELEASE can be unicast, not just broadcast


@dataclass
class Neighbor:
    mac: str
    ip: str
    fingerprint: HostFingerprint | None = None


@dataclass
class ControlOutcome:
    """Result of one legitimate DHCP cycle from the real NIC MAC.

    `phase` is "pre" (baseline, before exhausting) or "post" (after, while our leases are
    still held). A failed *pre* means the test setup is broken, not that a defense worked;
    a failed *post* after a successful *pre* is real evidence the pool is exhausted.
    """

    phase: str  # "pre" | "post"
    # "self" = this machine's real NIC MAC. The server usually already has a binding for it, so
    # this leg tests RENEWAL and proves DHCP is reachable — it can succeed on a drained pool.
    # "new" = a never-seen MAC, which needs a fresh address off the free list. Only this leg can
    # tell you whether a new client can still join.
    client: str = "self"
    attempted: bool = False
    success: bool = False
    mac: str = ""
    offered_ip: str | None = None
    server_id: str | None = None
    server_mac: str | None = None  # the server's Ethernet address, learned from its OFFER
    subnet: str | None = None
    lease_time: int | None = None
    elapsed: float = 0.0
    reason: str = ""  # why it was skipped or failed


# Finding verdicts. PASS = a defense demonstrably worked; FAIL = the network did not defend;
# INCONCLUSIVE = the test could not establish either (usually a broken baseline).
PASS, FAIL, INFO, INCONCLUSIVE = "PASS", "FAIL", "INFO", "INCONCLUSIVE"


@dataclass
class PoolEstimate:
    """Best-effort size of the address pool being exhausted — always labelled as an estimate.

    We cannot see the server's actual scope configuration (reservations, exclusions, multiple
    scopes on one segment all skew this), so `size` must always be shown next to `source` and
    `detail`, never presented as an authoritative denominator on its own.
    """

    size: int | None  # None when it cannot be determined at all — the UI must show "—"
    source: str  # "scope" | "observed" | "none"
    is_estimate: bool
    detail: str = ""


@dataclass
class Finding:
    """An auditable conclusion with the evidence that produced it."""

    id: str
    title: str
    verdict: str  # PASS | FAIL | INFO | INCONCLUSIVE
    severity: str  # info | low | medium | high
    evidence: dict = field(default_factory=dict)
    recommendation: str = ""
