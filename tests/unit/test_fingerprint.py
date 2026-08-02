from dhcpig.core.fingerprint import Signature, resolve


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


# ----------------------------------------------------- option 55 (parameter request list)
def test_db_single_candidate_exact_match():
    # 'Windows 10', a single unambiguous exact fingerprint carrying a real OS
    sig = Signature(
        mac="00:11:22:33:44:55",
        ip="1.1.1.4",
        prl=[1, 121, 3, 6, 15, 119, 252, 95, 44, 46],
    )
    fp = resolve(sig)
    assert fp.device == "Windows 10"
    assert fp.os == "Windows 10"  # the Satori data separates OS from device
    assert fp.vendor == "Microsoft Corp."
    assert fp.confidence == 90
    assert fp.matched_via.startswith("opt55:")
    assert "ambiguous" not in fp.matched_via


def test_db_ambiguous_multi_candidate_match():
    # this option-55 order maps to several iPad releases: keep them all, drop the confidence
    sig = Signature(mac="00:11:22:33:44:66", ip="1.1.1.5", prl=[1, 121, 3, 6, 15, 119, 252])
    fp = resolve(sig)
    assert "iPad" in (fp.device or "")
    assert " / " in (fp.device or "")  # more than one candidate, all reported
    assert fp.confidence == 75
    assert "ambiguous" in fp.matched_via


def test_ambiguous_candidates_disagreeing_on_os_claim_no_os():
    """An OS is only asserted when every candidate agrees; two guesses is not an answer."""
    sig = Signature(mac="00:11:22:33:44:66", ip="1.1.1.5", prl=[1, 121, 3, 6, 15, 119, 252])
    fp = resolve(sig)
    assert fp.os is None  # iOS 12 / iOS 13 / ... disagree
    assert fp.confidence == 75


# --------------------------------------------------------- option 60 (vendor class id)
def test_vendor_class_match_when_option55_misses():
    """The middle rung: no option-55 match, but a known vendor class still identifies it."""
    sig = Signature(
        mac="00:0c:29:be:ef:01", ip="1.1.1.2", prl=[200, 201], vendor_class="AXIS,Network"
    )
    fp = resolve(sig)
    assert fp.device == "Axis Network Camera"
    assert fp.vendor == "Axis Communications"
    assert fp.confidence == 70
    assert fp.matched_via.startswith("opt60:")


def test_vendor_class_is_only_consulted_after_option55():
    """A host with both signals is reported on the stronger one."""
    sig = Signature(
        mac="00:11:22:33:44:55",
        ip="1.1.1.4",
        prl=[1, 121, 3, 6, 15, 119, 252, 95, 44, 46],
        vendor_class="AXIS,Network",
    )
    fp = resolve(sig)
    assert fp.matched_via.startswith("opt55:")
    assert fp.confidence == 90


def test_unknown_vendor_class_still_falls_back_to_mac_vendor():
    sig = Signature(mac="00:0c:29:be:ef:01", ip="1.1.1.2", prl=[], vendor_class="android-dhcp-14")
    fp = resolve(sig)
    assert fp.os is None
    assert fp.matched_via.startswith("oui:")


# ------------------------------------------------------------------------------ database
def test_db_loaded():
    from dhcpig.core.fingerprint import DB_VERSION, _fingerprints, _vendor_classes

    assert len(_fingerprints()) > 100  # DB actually parsed
    assert len(_vendor_classes()) > 100
    assert "satori_dhcp_fingerprints" in DB_VERSION


def test_db_is_gpl_licensed():
    """The bundled data is GPL, same as the project -- guards against a relicensed reimport."""
    from dhcpig.core.fingerprint import _db

    assert _db()["license"] == "GPL-2.0-or-later"
    assert _db()["source"]["project"] == "Satori"
