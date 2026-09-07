"""MITRE ATT&CK mapping on the finding catalogue. Its value is being right, so the integrity
check (every catalogued id is a known technique) is the point of the file."""

from dhcpig.core.findings import _CATALOG, ATTCK, attck_labels, build


def test_every_catalogued_technique_id_is_known():
    for fid, entry in _CATALOG.items():
        for tid in entry.get("attck", ()):
            assert tid in ATTCK, f"{fid} maps to unknown technique {tid}"


def test_build_carries_the_mapping_onto_the_finding():
    assert build("CLIENTS_EVICTED_FROM_ADDRESSES", {}).attck == ["T1557.002"]  # forged ARP
    assert build("DHCP_STARVATION_ATTAINED", {}).attck == ["T1498"]  # pool drained
    assert build("NEIGHBOR_LEASES_RELEASED", {}).attck == ["T1557.003"]  # spoken for elsewhere
    # Assessed, not achieved: the PASS finding carries the same id as the FAIL. See ATTCK.
    assert build("DHCP_STARVATION_NOT_ATTAINED", {}).attck == ["T1498"]


def test_findings_that_describe_no_adversary_behaviour_are_unmapped():
    """Controls, recovery and dry runs report on the tool itself. RUN_SUMMARY is raised by
    every mode including the read-only scans, so no one static technique is true of it."""
    for fid in ("RUN_SUMMARY", "CONTROL_BASELINE_FAILED", "POOL_RECOVERED", "DRY_RUN_SUMMARY"):
        assert build(fid, {}).attck == []


def test_attck_labels_names_known_ids_and_passes_unknown_through():
    assert attck_labels(["T1557.003"]) == [
        "T1557.003 Adversary-in-the-Middle: DHCP Spoofing",
    ]
    assert attck_labels(["T9999"]) == ["T9999"]  # a report is no place to raise on a typo
    assert attck_labels(None) == []
