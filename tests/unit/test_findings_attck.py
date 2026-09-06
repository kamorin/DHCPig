"""MITRE ATT&CK mapping on the finding catalogue.

The mapping exists so a report drops straight into someone else's reporting template without a
human re-deriving "which technique was that". Its whole value is being right, so the integrity
check below (every id in the catalogue is a known technique) is the point of this file -- a
typo'd id would otherwise reach a report and be believed.
"""

from dhcpig.core.findings import _CATALOG, ATTCK, attck_labels, build


def test_every_catalogued_technique_id_is_known():
    for fid, entry in _CATALOG.items():
        for tid in entry.get("attck", ()):
            assert tid in ATTCK, f"{fid} maps to unknown technique {tid}"


def test_build_carries_the_mapping_onto_the_finding():
    assert build("CLIENTS_EVICTED_FROM_ADDRESSES", {}).attck == ["T1557.002"]  # forged ARP
    assert build("DHCP_STARVATION_ATTAINED", {}).attck == ["T1498"]  # pool drained
    assert build("NEIGHBOR_LEASES_RELEASED", {}).attck == ["T1557.003"]  # spoken for elsewhere


def test_findings_that_describe_no_adversary_behaviour_are_unmapped():
    """Controls, recovery and dry runs are the tool reporting on itself, not a technique.
    RUN_SUMMARY is unmapped for a different reason: it is raised by every mode including the
    read-only scans, so no single static technique is true of it."""
    for fid in ("RUN_SUMMARY", "CONTROL_BASELINE_FAILED", "POOL_RECOVERED", "DRY_RUN_SUMMARY"):
        assert build(fid, {}).attck == []


def test_attck_labels_names_known_ids_and_passes_unknown_through():
    assert attck_labels(["T1557.003"]) == [
        "T1557.003 Adversary-in-the-Middle: DHCP Spoofing",
    ]
    assert attck_labels(["T9999"]) == ["T9999"]  # a report is no place to raise on a typo
    assert attck_labels(None) == []
