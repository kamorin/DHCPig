"""Privileged integration test: real send/sniff over a veth pair with a fake DHCP server.

Run only as root on Linux:  sudo .venv/bin/pytest -m integration
Skipped everywhere else. Proves the engine actually grants leases and then releases them.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
import time

import pytest

pytestmark = pytest.mark.integration

VETH_A = "dhcpig0"  # client side (dhcpig runs here)
VETH_B = "dhcpig1"  # server side (fake DHCP server)
SERVER_IP = "172.31.9.1"


def _root_linux() -> bool:
    return sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() == 0


requires_root = pytest.mark.skipif(
    not _root_linux() or shutil.which("ip") is None,
    reason="integration test needs root on Linux with iproute2",
)


def _sh(*args: str) -> None:
    subprocess.run(args, check=True, capture_output=True)


@pytest.fixture
def veth_pair():
    subprocess.run(["ip", "link", "del", VETH_A], capture_output=True)  # cleanup stragglers
    _sh("ip", "link", "add", VETH_A, "type", "veth", "peer", "name", VETH_B)
    _sh("ip", "link", "set", VETH_A, "up")
    _sh("ip", "link", "set", VETH_B, "up")
    try:
        yield
    finally:
        subprocess.run(["ip", "link", "del", VETH_A], capture_output=True)


class FakeDhcpServer(threading.Thread):
    """Answers DISCOVER->OFFER and REQUEST->ACK on VETH_B."""

    def __init__(self) -> None:
        super().__init__(daemon=True)
        from scapy.all import get_if_hwaddr

        self.mac = get_if_hwaddr(VETH_B)
        self._sniffer = None
        self._next = 10  # offered host octet

    def _handle(self, pkt) -> None:
        from scapy.all import BOOTP, DHCP, IP, UDP, Ether, sendp

        from dhcpig.core.packets import message_type

        if DHCP not in pkt:
            return
        mt = message_type(pkt)
        if mt not in (1, 3):  # discover / request
            return
        offered = f"172.31.9.{self._next}"
        if mt == 1:
            self._next += 1
        kind = "offer" if mt == 1 else "ack"
        reply = (
            Ether(src=self.mac, dst=pkt[Ether].src)
            / IP(src=SERVER_IP, dst="255.255.255.255")
            / UDP(sport=67, dport=68)
            / BOOTP(
                op=2,
                yiaddr=offered,
                siaddr=SERVER_IP,
                chaddr=pkt[BOOTP].chaddr,
                xid=pkt[BOOTP].xid,
                flags=pkt[BOOTP].flags,
            )
            / DHCP(
                options=[
                    ("message-type", kind),
                    ("server_id", SERVER_IP),
                    ("subnet_mask", "255.255.255.0"),
                    ("lease_time", 600),
                    "end",
                ]
            )
        )
        sendp(reply, iface=VETH_B, verbose=False)

    def run(self) -> None:
        from scapy.all import AsyncSniffer

        self._sniffer = AsyncSniffer(
            iface=VETH_B, filter="udp and dst port 67", prn=self._handle, store=False
        )
        self._sniffer.start()
        while self._sniffer.running:
            time.sleep(0.1)

    def stop(self) -> None:
        if self._sniffer is not None:
            self._sniffer.stop()


@requires_root
def test_exhaust_grants_then_releases(veth_pair):
    from dhcpig.core.engine import DhcpEngine
    from dhcpig.core.events import EventBus
    from dhcpig.core.models import Mode, SessionConfig

    server = FakeDhcpServer()
    server.start()
    time.sleep(0.5)

    bus = EventBus()
    cfg = SessionConfig(
        interface=VETH_A,
        mode=Mode.EXHAUST,
        rate_limit_pps=200,
        restore_on_exit=True,
        control=False,  # the fake server has no notion of a "real" NIC MAC baseline
    )
    engine = DhcpEngine(cfg, bus)
    engine.start()

    deadline = time.time() + 15
    while engine.acks < 3 and time.time() < deadline:
        time.sleep(0.2)

    assert engine.acks >= 1, "engine should have obtained at least one lease"
    acquired = len(engine.cleanup.all())

    engine.stop()  # restore_on_exit -> releases the acquired leases
    server.stop()

    assert all(ln.released for ln in engine.cleanup.all())
    assert engine.releases == acquired
