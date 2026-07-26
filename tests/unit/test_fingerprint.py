from dhcpig.core.fingerprint import Signature, resolve


def test_vendor_class_match():
    # no PRL -> combined DB (option-55 only) is skipped; falls to the builtin vendor-class table
    sig = Signature(mac="aa:bb:cc:00:00:01", ip="1.1.1.2", vendor_class="android-dhcp-14")
    fp = resolve(sig)
    assert fp.os == "Android"
    assert fp.confidence > 0


def test_unknown_signature_is_low_confidence_not_crash():
    sig = Signature(mac="de:ad:be:ef:00:09", ip="1.1.1.3", prl=[200, 201])
    fp = resolve(sig)
    assert fp.confidence == 0
    assert fp.matched_via == "unknown"


# ---------------------------------------------------------------- combined_dhcp_os_lookup.json
def test_combined_db_single_candidate_exact_match():
    # 'N300 Wireless Router' (packetfence-sourced), a single, unambiguous exact fingerprint
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


def test_combined_db_ambiguous_multi_candidate_match():
    # this exact option-55 order maps to four BrightSign digital-signage models (huginn-muninn)
    sig = Signature(
        mac="00:11:22:33:44:66",
        ip="1.1.1.5",
        prl=[1, 121, 3, 6, 12, 15, 26, 28, 33, 42, 43, 51, 58, 59, 119],
    )
    fp = resolve(sig)
    assert "BrightSign" in (fp.device or "")
    assert fp.confidence == 75
    assert "ambiguous" in fp.matched_via


def test_combined_db_loaded():
    from dhcpig.core.fingerprint import DB_VERSION, _combined_fingerprints

    assert len(_combined_fingerprints()) > 100  # DB actually parsed
    assert "combined_dhcp_os_lookup" in DB_VERSION
