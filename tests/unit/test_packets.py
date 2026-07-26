"""Packet builder/parser tests, including the PR #27 and #28 regressions."""

from scapy.all import BOOTP, DHCP, IP, UDP, Ether, mac2str

from dhcpig.core import packets


def _make_offer(chaddr_bytes: bytes, siaddr: str, server_id: str | None, yiaddr="172.20.0.83"):
    opts = [("message-type", "offer")]
    if server_id is not None:
        opts.append(("server_id", server_id))
    opts += [("subnet_mask", "255.255.255.0"), "end"]
    return (
        Ether(src="00:0c:29:da:53:f9", dst="de:ad:00:00:00:01")
        / IP(src=siaddr or "0.0.0.0", dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, chaddr=chaddr_bytes, yiaddr=yiaddr, siaddr=siaddr, xid=0x1234)
        / DHCP(options=opts)
    )


def test_discover_sets_broadcast_flag_and_client_id():
    pkt = packets.build_discover_v4("de:ad:be:ef:00:01", 0xABCD, "de:ad:be:ef:00:01")
    assert pkt[BOOTP].flags == 0x8000
    cid = packets.dhcp_option(pkt[DHCP].options, "client_id")
    assert cid == b"\x01" + mac2str("de:ad:be:ef:00:01")


# ---------------------------------------------------------------- targeted re-acquisition (2.3)
def test_discover_omits_option50_by_default():
    pkt = packets.build_discover_v4("de:ad:be:ef:00:02", 0xABCE, "de:ad:be:ef:00:02")
    assert packets.dhcp_option(pkt[DHCP].options, "requested_addr") is None


def test_discover_carries_option50_when_requested_addr_given():
    pkt = packets.build_discover_v4(
        "de:ad:be:ef:00:03", 0xABCF, "de:ad:be:ef:00:03", requested_addr="172.20.0.51"
    )
    assert packets.dhcp_option(pkt[DHCP].options, "requested_addr") == "172.20.0.51"
    # message-type and client_id must both still be present -- option 50 is additive
    assert packets.dhcp_option(pkt[DHCP].options, "message-type") in ("discover", 1)
    assert packets.dhcp_option(pkt[DHCP].options, "client_id") is not None


def test_server_identifier_prefers_option54():  # PR #27
    opts = [("message-type", "offer"), ("server_id", "172.20.15.1"), "end"]
    assert packets.server_identifier("0.0.0.0", opts) == "172.20.15.1"


def test_server_identifier_falls_back_to_siaddr():  # PR #27
    opts = [("message-type", "offer"), "end"]  # no option 54
    assert packets.server_identifier("172.20.15.9", opts) == "172.20.15.9"


def test_request_uses_option54_when_siaddr_empty():  # PR #27 end-to-end
    offer = _make_offer(
        mac2str("de:ad:00:7c:a8:50") + b"\x00" * 10, siaddr="0.0.0.0", server_id="172.20.15.1"
    )
    req = packets.build_request_v4(offer, "de:ad:00:7c:a8:50")
    assert packets.dhcp_option(req[DHCP].options, "server_id") == "172.20.15.1"


def test_request_client_mac_is_six_bytes_and_option61_present():  # PR #28
    # chaddr arrives as a padded 16-byte field
    chaddr16 = mac2str("de:ad:26:4b:d3:40") + b"\x00" * 10
    offer = _make_offer(chaddr16, siaddr="172.20.15.1", server_id=None)
    req = packets.build_request_v4(offer, "de:ad:26:4b:d3:40")
    # MAC parsed from chaddr[:6] -> exactly 6 octets
    localm = packets.client_mac_from_offer(offer)
    assert localm == "de:ad:26:4b:d3:40"
    assert len(localm.split(":")) == 6
    # option 61 client-id present and 7 bytes: htype(1) + 6-byte MAC
    cid = packets.dhcp_option(req[DHCP].options, "client_id")
    assert cid == b"\x01" + mac2str("de:ad:26:4b:d3:40")
    assert len(cid) == 7
    assert req[BOOTP].flags == 0x8000


def test_release_and_garp_build():
    rel = packets.build_release_v4("de:ad:00:00:00:02", "10.0.0.5", "10.0.0.1", 42)
    assert packets.dhcp_option(rel[DHCP].options, "message-type") in ("release", 7)
    assert rel[IP].dst == "10.0.0.1"
    g = packets.build_garp("10.0.0.5", "de:ad:00:00:00:02")
    assert g.haslayer("ARP")
    assert g["ARP"].psrc == "10.0.0.5"


def test_release_is_l2_complete_and_broadcasts_without_a_known_server_mac():
    """BUG FIX (2.1): this used to be an L3-only packet sent through an L2 sendp() — malformed
    on the wire, so no RELEASE this tool ever sent could have worked."""
    rel = packets.build_release_v4("de:ad:00:00:00:02", "10.0.0.5", "10.0.0.1", 42)
    assert Ether in rel
    assert rel[Ether].src == "de:ad:00:00:00:02"
    assert rel[Ether].dst == "ff:ff:ff:ff:ff:ff"  # server MAC unknown -> broadcast fallback


def test_release_unicasts_to_the_server_mac_when_known():
    rel = packets.build_release_v4(
        "de:ad:00:00:00:02", "10.0.0.5", "10.0.0.1", 42, server_mac="aa:bb:cc:dd:ee:ff"
    )
    assert rel[Ether].dst == "aa:bb:cc:dd:ee:ff"


def test_is_offer_is_ack():
    offer = _make_offer(mac2str("de:ad:00:00:00:03") + b"\x00" * 10, "172.20.15.1", "172.20.15.1")
    assert packets.is_offer(offer)
    assert not packets.is_ack(offer)


# ---------------------------------------------------------------- decline/discover (2.3)
def test_message_type_recognizes_decline_and_inform():
    """message_type()'s name map was missing 'decline'/'inform' -- DECLINE already existed as a
    constant but was never reachable through the map, so a real DHCPDECLINE would have come
    back as None."""
    opts = [("message-type", "decline"), "end"]
    assert packets.message_type(_opts_pkt(opts)) == packets.DECLINE
    opts = [("message-type", "inform"), "end"]
    assert packets.message_type(_opts_pkt(opts)) == packets.INFORM


def _opts_pkt(opts):
    return (
        Ether(src="de:ad:00:00:00:01")
        / IP(src="10.0.0.5", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=mac2str("de:ad:00:00:00:01"), xid=0x1234)
        / DHCP(options=opts)
    )


def test_is_discover():
    pkt = packets.build_discover_v4("de:ad:00:00:00:04", 0x5678, "de:ad:00:00:00:04")
    assert packets.is_discover(pkt)
    assert not packets.is_decline(pkt)


def test_is_decline():
    pkt = _opts_pkt([("message-type", "decline"), "end"])
    assert packets.is_decline(pkt)
    assert not packets.is_discover(pkt)


def test_build_inform():
    pkt = packets.build_inform_v4("de:ad:00:00:00:05", "192.168.1.50", 0x1234)
    assert packets.dhcp_option(pkt[DHCP].options, "message-type") in ("inform", 8)
    assert pkt[BOOTP].ciaddr == "192.168.1.50"  # INFORM comes from an addressed client
    assert pkt[IP].src == "192.168.1.50"


# ---------------------------------------------------------------- lease_time_from (2.2 journal)
def test_lease_time_from_reads_option_51():
    opts = [("message-type", "ack"), ("lease_time", 3600), "end"]
    assert packets.lease_time_from(opts) == 3600


def test_lease_time_from_none_when_option_absent():
    opts = [("message-type", "ack"), "end"]
    assert packets.lease_time_from(opts) is None


def test_lease_time_from_none_on_malformed_value():
    opts = [("message-type", "ack"), ("lease_time", "not-a-number"), "end"]
    assert packets.lease_time_from(opts) is None
