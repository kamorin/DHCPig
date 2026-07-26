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
    # Recovery: replay the lease journal to release phantom leases this tool (or an earlier run
    # of it) acquired within the current network. Not in DESTRUCTIVE_MODES -- it only releases
    # leases the journal proves this tool took, so it adds no offensive capability.
    RELEASE_PREVIOUS = "release-previous"


# Modes that disrupt live clients. Used for labelling and reporting only — they are no longer
# gated behind an authorization attestation, and --scope is optional (it bounds a run when
# supplied, and otherwise the interface's own network is used).
DESTRUCTIVE_MODES: set[Mode] = {Mode.RELEASE_NEIGHBORS}
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
    # eviction (2.3): spacing between ARP-conflict rounds. Must stay under RFC 5227's 10s
    # DEFEND_INTERVAL -- a second conflict inside that window is what moves a host out of its
    # "defend once" phase; spaced further apart than that, each round looks like a fresh,
    # independently-defensible conflict and the host never gives up the address.
    evict_interval: float = 3.0


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
    rate_limit_pps: int = 7  # the bound on how fast a run can consume a pool
    v6_rapid_commit: bool = False
    dry_run: bool = False
    # Hard "never touch a socket" switch, distinct from dry_run (2.3). dry_run now runs every
    # non-destructive phase for real -- ARP discovery, the control transaction's own
    # DISCOVER/REQUEST/RELEASE -- and only suppresses mutating sends (release, re-acquisition,
    # the windowed sender, eviction). That needs a raw-capable interface and root. `offline`
    # restores the old skip-everything behavior unconditionally (no sniffer, no srp(), the
    # control transaction short-circuits instantly) -- for the test suite and any no-root web
    # preview. Do not use `dry_run` for this; the two are now genuinely different concerns.
    offline: bool = False
    scope_cidrs: list[str] | None = None  # optional; bounds targets when supplied
    report_path: Path | None = None
    # NOTE: there is no opt-out for the control transaction. A legitimate DHCP cycle from the
    # real NIC MAC always runs before and after exhausting — it's what separates "the network
    # blocked us" (PASS) from "the test was broken" (INCONCLUSIVE), and a run without it can't
    # produce a trustworthy verdict. Don't re-add a `control` field without asking.
    # ARP-sweep the segment before exhausting, to record who was there beforehand
    arp_sweep: bool = True
    # Release the leases of ARP-discovered neighbors before exhausting, so the CUJ of "free up
    # addresses, then take them" is actually exercised rather than assumed. Requires a known
    # server (from control_pre); skipped with a Debug if none is available.
    release_neighbors: bool = True
    status_interval: float = 5.0  # heartbeat period for StatusTick; 0 disables
    window_initial: int = 8  # exhaust: starting number of in-flight DISCOVER/REQUEST transactions
    window_max: int = 64  # exhaust: ceiling the adaptive window may grow to
    # Lease journal (2.2): an append-only, crash-tolerant record of every lease acquired, so
    # `release-previous` can recover a drained pool even after the process that drained it is
    # long gone. On by default -- a recovery tool that only sometimes records is useless.
    # `journal_path=None` resolves to `journal.default_path(interface)` at engine construction.
    journal: bool = True
    journal_path: Path | None = None
    # release-previous only: how far back a journal entry may be before it's ignored (an
    # optimisation, not a safety measure -- see EXECUTION-PLAN-release-previous.md §Phase 2).
    max_age_days: float = 7.0
    # release-previous only: skip journal entries recorded against a different DHCP server than
    # the one currently reachable -- guards against a journal carried between engagements on
    # the same laptop/interface name producing release targets for the wrong network.
    require_same_server: bool = True
    # release-previous only: RELEASE has no reply (RFC 2131), so a dropped frame is silent —
    # resend the whole selected set this many times as cheap insurance.
    release_passes: int = 2
    # ARP-conflict eviction (2.3): after re-acquiring a freed address (Phase 3), contest the
    # victim's ownership of every OTHER address we now hold, per RFC 5227 §2.4, to move it out
    # of its "defend once" phase and force a DECLINE/restart-at-INIT. Runs automatically as
    # part of exhaust/release; there is no standalone "evict" mode (GARP_DOS was retired, 2.3).
    evict: bool = True
    evict_rounds: int = 4  # must be >= 2 -- one round can only ever reach "defended", never more
    # evict_settle: how long to wait, after the last round, before measuring the outcome ladder
    # -- gives a DECLINE/restart-at-INIT/APIPA time to actually land on the wire.
    evict_settle: float = 8.0
    timeouts: Timeouts = field(default_factory=Timeouts)
    verbosity: int = 2

    def __post_init__(self) -> None:
        # RFC 5227 §2.4 correctness requirements, not taste: spaced >= 10s apart, each round
        # looks like a fresh, independently-defensible conflict and the host never gives up the
        # address; fewer than 2 rounds can only ever reach "defended" (the second conflict inside
        # DEFEND_INTERVAL is what actually moves a host out of its defend-once phase).
        from .exceptions import ConfigError

        if self.timeouts.evict_interval >= 10.0:
            raise ConfigError(
                "timeouts.evict_interval must be < 10.0s (RFC 5227 SS2.4 DEFEND_INTERVAL) -- "
                f"got {self.timeouts.evict_interval}. Spaced 10s or further apart, each ARP "
                "conflict round looks like a fresh, independently-defensible conflict and the "
                "host never gives up the address."
            )
        if self.evict_rounds < 2:
            raise ConfigError(
                f"evict_rounds must be >= 2 (RFC 5227 SS2.4) -- got {self.evict_rounds}. A "
                "single round can only ever reach 'defended': the *second* conflict inside "
                "DEFEND_INTERVAL is what moves a host out of its defend-once phase."
            )


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
