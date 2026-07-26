from dhcpig.core.fingerprint import Signature, resolve


def test_vendor_class_alone_falls_back_to_mac_vendor():
    # no prl -> no packetfence db lookup possible; vendor_class alone isn't matched (no
    # builtin table) -> falls all the way to OUI-only identification
    sig = Signature(mac="00:0c:29:be:ef:01", ip="1.1.1.2", vendor_class="android-dhcp-14")
    fp = resolve(sig)
    assert fp.os is None
    assert fp.matched_via.startswith("oui:")


def test_unknown_signature_falls_back_to_mac_vendor():
    """No DHCP match -> OUI identification, at a confidence that can't be mistaken for one."""
    sig = Signature(mac="00:0c:29:be:ef:09", ip="1.1.1.3", prl=[200, 201])
    fp = resolve(sig)
    assert fp.os is None  # no OS claim from a MAC alone
    assert "VMware" in (fp.vendor or "")
    assert "VMware" in (fp.device or "") and "MAC vendor" in fp.device
    assert fp.confidence == 15
    assert fp.matched_via.startswith("oui:")


def test_unknown_signature_and_unknown_oui_is_zero_confidence():
    sig = Signature(mac="00:00:00:00:00:00", ip="1.1.1.3", prl=[200, 201])
    fp = resolve(sig)
    assert fp.confidence in (0, 15)  # 0 if the OUI is unknown too
    assert fp.os is None


# ------------------------------------------------------------- packetfence_dhcp_fingerprints.json
def test_packetfence_db_single_candidate_exact_match():
    # 'N300 Wireless Router', a single, unambiguous exact fingerprint
    sig = Signature(
        mac="00:11:22:33:44:55",
        ip="1.1.1.4",
        prl=[1, 121, 249, 3, 6, 12, 15, 28, 33, 43],
    )
    fp = resolve(sig)
    assert fp.device == "N300 Wireless Router"
    assert fp.confidence == 90
    assert fp.matched_via.startswith("opt55:")
    assert "ambiguous" not in fp.matched_via


def test_packetfence_db_ambiguous_multi_candidate_match():
    # this exact option-55 order maps to two PacketFence entries: Debian-based Linux and
    # Linux Ubuntu 14.04
    sig = Signature(
        mac="00:11:22:33:44:66",
        ip="1.1.1.5",
        prl=[1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42, 121, 249, 33, 252, 42],
    )
    fp = resolve(sig)
    assert "Debian-based Linux" in (fp.device or "")
    assert "Linux Ubuntu 14.04" in (fp.device or "")
    assert fp.confidence == 75
    assert "ambiguous" in fp.matched_via


def test_packetfence_db_loaded():
    from dhcpig.core.fingerprint import DB_VERSION, _fingerprints

    assert len(_fingerprints()) > 100  # DB actually parsed
    assert "packetfence_dhcp_fingerprints" in DB_VERSION
