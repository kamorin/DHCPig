"""Network helpers. OS-aware (Linux + macOS). Pure enough to unit-test the math."""

from __future__ import annotations

import random
import socket
import struct


def ip_to_int(ip: str) -> int:
    """Dotted-quad string -> 32-bit int (network byte order independent)."""
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int_to_ip(value: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", value))


def cidr_from_mask(mask: str) -> int:
    """'255.255.255.0' -> 24."""
    return bin(ip_to_int(mask)).count("1")


def random_mac() -> str:
    """DE:AD:xx:xx:xx:xx — matches legacy pig.py prefix so captures are recognizable."""
    octets = [
        0xDE,
        0xAD,
        random.randint(0x00, 0x29),
        random.randint(0x00, 0x7F),
        random.randint(0x00, 0xFF),
        random.randint(0x00, 0xFF),
    ]
    return ":".join(f"{o:02x}" for o in octets)


def list_interfaces() -> list[str]:
    """Best-effort interface enumeration without extra deps."""
    names: list[str] = []
    # Python 3.11+: socket.if_nameindex works on Linux and macOS.
    try:
        names = [name for _, name in socket.if_nameindex()]
    except (OSError, AttributeError):
        names = []
    # Filter loopback to the end but keep it (useful for lab testing).
    names.sort(key=lambda n: (n == "lo", n))
    return names


def get_if_ip(iface: str) -> str | None:
    """IPv4 address of an interface, or None. Uses scapy if available, else best effort."""
    try:
        from scapy.all import get_if_addr  # type: ignore

        addr = get_if_addr(iface)
        return addr if addr and addr != "0.0.0.0" else None
    except Exception:
        return None


def default_gateway(iface: str | None = None) -> str | None:
    """Next hop of the default route, or None.

    Used to exclude the gateway itself from release/eviction targeting -- taking its lease or
    ARP-conflicting it would cut off the whole segment's routing, not just the intended victim.
    """
    try:  # Linux: /proc/net/route, columns Iface Destination Gateway ...
        with open("/proc/net/route") as fh:
            next(fh)  # header
            for line in fh:
                cols = line.split()
                if len(cols) > 2 and cols[1] == "00000000":  # default route
                    if iface and cols[0] != iface:
                        continue
                    packed = struct.pack("<L", int(cols[2], 16))
                    return socket.inet_ntoa(packed)
    except (OSError, ValueError, StopIteration):
        pass
    try:  # fall back to scapy's routing table (works on macOS too)
        from scapy.all import conf

        gw = conf.route.route("0.0.0.0")[2]
        return gw if gw and gw != "0.0.0.0" else None
    except Exception:
        return None


def link_is_up(iface: str) -> bool | None:
    """Best-effort carrier state, or None if it can't be determined.

    None covers loopback (no carrier attribute), non-Linux, and interfaces that simply don't
    exist — all of which must fail *open* (no halt decision) rather than be mistaken for a
    down link. Used to detect port-security err-disable during an exhaust run: a switch
    shutting the port down is a defensive control firing, not a glitch to retry through.
    """
    try:
        with open(f"/sys/class/net/{iface}/carrier") as fh:
            return fh.read().strip() == "1"
    except OSError:
        return None


def iface_network_cidr(iface: str) -> str | None:
    """The interface's own network in CIDR form, e.g. '192.168.7.0/24' (best effort).

    Used to auto-fill the scope. Linux: reads the netmask via SIOCGIFNETMASK; returns None
    if it can't be determined (caller then leaves the scope blank).
    """
    ip = get_if_ip(iface)
    if not ip:
        return None
    try:
        import fcntl
        import ipaddress
        import struct

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            packed = struct.pack("256s", iface.encode()[:15])
            mask = socket.inet_ntoa(
                fcntl.ioctl(s.fileno(), 0x891B, packed)[20:24]
            )  # SIOCGIFNETMASK
        finally:
            s.close()
        return str(ipaddress.ip_network(f"{ip}/{mask}", strict=False))
    except (OSError, ValueError, ImportError):
        return None
