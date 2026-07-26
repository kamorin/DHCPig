"""Thin wrapper over scapy AsyncSniffer. Classification stays in the engine."""

from __future__ import annotations

from collections.abc import Callable

from .models import IPVersion

_BPF = {
    IPVersion.V4: "arp or icmp or (udp and src port 67 and dst port 68)",
    IPVersion.V6: "icmp6 or (udp and src port 547 and dst port 546)",
}


class DhcpSniffer:
    def __init__(self, iface: str, ip_version: IPVersion, on_packet: Callable) -> None:
        self.iface = iface
        self.ip_version = ip_version
        self.on_packet = on_packet
        self._sniffer = None

    def start(self) -> None:
        from scapy.all import AsyncSniffer  # imported lazily; opening a socket needs root

        self._sniffer = AsyncSniffer(
            iface=self.iface,
            filter=_BPF[self.ip_version],
            prn=self.on_packet,
            store=False,
        )
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
