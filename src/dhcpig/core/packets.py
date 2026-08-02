"""Pure DHCPv4 + ARP packet builders/parsers. No I/O — fully unit-testable without root.

Carries the two upstream bug fixes:
  * PR #27 — server identifier = DHCP option 54 if present, else BOOTP siaddr.
  * PR #28 — client MAC = chaddr[:6] (avoid 16-byte padding corruption) and include
             DHCP option 61 (client-id) in the REQUEST.
BOOTP broadcast flag 0x8000 is set (some routers only answer broadcast).
"""

from __future__ import annotations

import random
import string

from scapy.all import ARP, BOOTP, DHCP, IP, UDP, Ether, mac2str, str2mac

# DHCP message-type codes
DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE, INFORM = range(1, 9)

# ARP operations
ARP_REQUEST, ARP_REPLY = 1, 2

# macOS-style parameter-request-list order, from legacy pig.py, to avoid trivial
# DHCP fingerprint-based rejection by some servers/routers.
_MACOS_PRL = (1, 121, 3, 6, 15, 119, 252, 95, 44, 46)


def _hostname() -> str:
    return "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))


# --------------------------------------------------------------------------- builders


def build_discover_v4(mac: str, xid: int, src_mac: str, requested_addr: str | None = None) -> Ether:
    """`requested_addr` emits DHCP option 50 (RFC 2131 Table 5 permits it in a DISCOVER) --
    used by targeted re-acquisition (2.3) to ask the server for a specific, just-released
    address rather than whatever it would otherwise hand out. Servers generally honour it when
    the address is free; nothing here assumes they do -- the caller must still check the OFFER.
    """
    opts = [
        ("message-type", "discover"),
        ("param_req_list", *_MACOS_PRL),
        ("max_dhcp_size", 1500),
        ("client_id", b"\x01" + mac2str(mac)),
        ("lease_time", 10000),
        ("hostname", _hostname()),
    ]
    if requested_addr:
        opts.append(("requested_addr", requested_addr))
    opts.append(("end", "00000000000000"))
    return (
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=[mac2str(mac)], xid=xid, flags=0x8000)
        / DHCP(options=opts)
    )


def server_identifier(siaddr: str, options: list) -> str:
    """FIX A (PR #27): prefer DHCP option 54; fall back to BOOTP siaddr."""
    for opt in options:
        if isinstance(opt, tuple) and opt and opt[0] == "server_id":
            return opt[1]
    return siaddr


def lease_time_from(options: list) -> int | None:
    """DHCP option 51 (lease-time) in seconds, or None if the server didn't send one.

    Used by the lease journal (2.2) to know when a phantom lease naturally expires. Never
    raises on a malformed value -- a bad option 51 just means "unknown", not a crash.
    """
    for opt in options:
        if isinstance(opt, tuple) and opt and opt[0] == "lease_time":
            try:
                return int(opt[1])
            except (TypeError, ValueError):
                return None
    return None


def client_mac_from_offer(offer: BOOTP) -> str:
    """FIX B (PR #28): chaddr is a padded 16-byte field; use the first 6 bytes."""
    return str2mac(bytes(offer[BOOTP].chaddr)[:6])


def build_request_v4(offer, src_mac: str) -> Ether:
    localm = client_mac_from_offer(offer)
    sip = server_identifier(offer[BOOTP].siaddr, offer[DHCP].options)
    myip = offer[BOOTP].yiaddr
    opts = [
        ("message-type", "request"),
        ("client_id", b"\x01" + mac2str(localm)),  # FIX B: option 61
        ("server_id", sip),
        ("requested_addr", myip),
        ("hostname", _hostname()),
        ("param_req_list", 0),
        "end",
    ]
    return (
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=[mac2str(localm)], xid=offer[BOOTP].xid, flags=0x8000)
        / DHCP(options=opts)
    )


def build_release_v4(
    mac: str,
    ip: str,
    server_ip: str,
    xid: int,
    server_mac: str | None = None,
    src_mac: str | None = None,
) -> Ether:
    """RELEASE is sent via `_send()`, which is an L2 `sendp()` — so it needs an Ether layer.

    (BUG FIX, 2.1) Earlier builds returned an L3-only packet here, so every RELEASE this tool
    ever sent was malformed on the wire. RFC 2131 has RELEASE unicast to the server; if the
    server's MAC isn't known yet, fall back to broadcast rather than fail outright — some
    stacks still accept it.

    `src_mac` defaults to `mac` (the releasing client's own hardware address).
    """
    return (
        Ether(src=src_mac or mac, dst=server_mac or "ff:ff:ff:ff:ff:ff")
        / IP(src=ip, dst=server_ip)
        / UDP(sport=68, dport=67)
        / BOOTP(ciaddr=ip, chaddr=[mac2str(mac)], xid=xid)
        / DHCP(
            options=[
                ("message-type", "release"),
                ("server_id", server_ip),
                ("client_id", b"\x01" + mac2str(mac)),
                "end",
            ]
        )
    )


def build_inform_v4(mac: str, ciaddr: str, xid: int, request_options=None) -> Ether:
    """DHCP INFORM: sent by a host that already has an IP to actively pull config from the
    server (used by active-scan to discover/fingerprint DHCP servers). Takes no lease."""
    opts = [
        ("message-type", "inform"),
        ("param_req_list", *_MACOS_PRL),
        ("client_id", b"\x01" + mac2str(mac)),
        "end",
    ]
    return (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=ciaddr, dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(ciaddr=ciaddr, chaddr=[mac2str(mac)], xid=xid, flags=0)
        / DHCP(options=opts)
    )


def build_garp(ip: str, mac: str, op: int = 1) -> Ether:
    """Gratuitous ARP announcing that `ip` lives at `mac` (psrc == pdst).

    Both forms exist in the wild and stacks differ in which they honour — Linux with
    `arp_accept=0` updates an *existing* entry but won't create one, and some stacks only act
    on the reply form. Senders therefore emit both:
      op=1  ARP request  ("who has <ip>? tell <ip>") — the classic announcement
      op=2  ARP reply    (unsolicited "<ip> is at <mac>")
    """
    hwdst = "00:00:00:00:00:00" if op == ARP_REQUEST else "ff:ff:ff:ff:ff:ff"
    return Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=op, hwsrc=mac, psrc=ip, hwdst=hwdst, pdst=ip
    )


def build_arp_conflict_unicast(ip: str, mac: str, victim_mac: str) -> Ether:
    """The same claim `build_garp(op=2)` makes — `ip` is at `mac`, psrc == pdst — but delivered
    unicast to `victim_mac` instead of broadcast (§5b).

    Redundancy, not a replacement: broadcast is the RFC 5227 form and is what a conforming
    stack's address-conflict detection listens for. This exists for the delivery paths where
    the broadcast never arrives — wireless APs with client isolation routinely drop
    station-to-station *broadcast* while still forwarding unicast to a known station, and some
    stacks rate-limit or filter broadcast ARP far more aggressively than unicast on the input
    path. One extra frame per target per round buys a second, independent way in.
    """
    return Ether(src=mac, dst=victim_mac) / ARP(
        op=ARP_REPLY, hwsrc=mac, psrc=ip, hwdst=victim_mac, pdst=ip
    )


def build_arp_request(ip: str, src_ip: str, src_mac: str | None = None) -> Ether:
    eth = Ether(dst="ff:ff:ff:ff:ff:ff")
    if src_mac:
        eth.src = src_mac
    return eth / ARP(pdst=ip, psrc=src_ip)


# --------------------------------------------------------------------------- parsers


def dhcp_option(options: list, name: str):
    for opt in options:
        if isinstance(opt, tuple) and opt and opt[0] == name:
            return opt[1] if len(opt) == 2 else opt[1:]
    return None


def message_type(pkt) -> int | None:
    if DHCP not in pkt:
        return None
    mt = dhcp_option(pkt[DHCP].options, "message-type")
    if mt is None:
        return None
    # scapy may hand back an int or a name; normalise to int.
    names = {
        "discover": DISCOVER,
        "offer": OFFER,
        "request": REQUEST,
        "decline": DECLINE,
        "ack": ACK,
        "nak": NAK,
        "release": RELEASE,
        "inform": INFORM,
    }
    return names.get(mt) if isinstance(mt, str) else int(mt)


def is_discover(pkt) -> bool:
    """A DHCPDISCOVER — used to spot foreign clients probing the segment during a run."""
    return message_type(pkt) == DISCOVER


def is_decline(pkt) -> bool:
    """DHCPDECLINE — a client refusing an offered/assigned address (e.g. failed ARP probe,
    or APIPA fallback after eviction). Client->server, only visible since the BPF widen."""
    return message_type(pkt) == DECLINE


def is_request(pkt) -> bool:
    """DHCPREQUEST — client->server, sent both by us (selecting/renewing) and by every other
    client on the segment. Used (2.3, race-freed) to briefly track a foreign REQUEST's
    requested address, so a later NAK for the same xid -- which carries no address of its own,
    per RFC 2131 -- can still be resolved to a specific IP."""
    return message_type(pkt) == REQUEST


def is_offer(pkt) -> bool:
    return message_type(pkt) == OFFER


def is_ack(pkt) -> bool:
    return message_type(pkt) == ACK


def is_nak(pkt) -> bool:
    """DHCPNAK — the server actively refused. Evidence of snooping/binding enforcement."""
    return message_type(pkt) == NAK


def packet_hostname(pkt) -> str | None:
    """Decode DHCP option 12 (hostname) off a packet we built or received, if present.

    Shared by the info-level DiscoverSent/RequestSent logging (our own outbound packets always
    carry one, from `_hostname()`) and foreign-DISCOVER handling (a real client's hostname, if it
    sent one -- entirely optional on the wire).
    """
    if DHCP not in pkt:
        return None
    raw = dhcp_option(pkt[DHCP].options, "hostname")
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    if isinstance(raw, str):
        return raw
    return None


def parse_offer(pkt) -> tuple[str, str, str, str | None]:
    """Return (server_id, server_mac, offered_ip, subnet) from an OFFER packet."""
    server_id = server_identifier(pkt[BOOTP].siaddr, pkt[DHCP].options)
    server_mac = pkt[Ether].src if Ether in pkt else ""
    offered_ip = pkt[BOOTP].yiaddr
    subnet = dhcp_option(pkt[DHCP].options, "subnet_mask")
    return server_id, server_mac, offered_ip, subnet
