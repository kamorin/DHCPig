# Fingerprint data attribution

`packetfence_dhcp_fingerprints.json` is a static, offline DHCP option-55 (parameter-request-list)
lookup table sourced entirely from:

- **PacketFence** DHCP fingerprint conf (`packetfence_dhcp_fingerprints.conf`) — derived from
  the FingerBank project, Inverse inc., Open Database License (ODbL) v1.0 /
  Database Contents License (DbCL) v1.0. https://opendatacommons.org/licenses/odbl/1.0/

Keyed by the exact, order-sensitive option-55 string; a fingerprint with more than one candidate
device keeps all of them. Current coverage: 535 fingerprints (see the file's own `statistics`
block for the current count).

Matching is **offline and static — no API, no key, no network calls.** `dhcpig.core.fingerprint`
does an exact dict lookup on the option-55 string; a fingerprint with more than one candidate
device is reported with lower confidence and flagged ambiguous in `matched_via`.

`fingerprint-merge.py` (bundled alongside the data file) is a standalone
`python3 fingerprint-merge.py <option-55-list>` lookup CLI over this file — copy it plus the JSON
into another project if useful elsewhere.

To refresh coverage, regenerate `packetfence_dhcp_fingerprints.json` from a newer PacketFence
export and drop it in this directory — `dhcpig.core.fingerprint` loads whatever is present.

## MAC vendor (OUI) data

Hosts with no usable DHCP fingerprint — ARP-only neighbours especially — are identified by the
hardware vendor of their MAC, via **scapy's bundled Wireshark `manuf` database** (~50,000
IEEE MA-L/MA-M/MA-S assignments). scapy is already DHCPig's only runtime dependency, so this
ships for free and needs no separate copy of the registry. Wireshark's `manuf` is
GPL-2.0-or-later, same as this project, and is refreshed with each scapy release.

Unresolved MACs are checked for the locally-administered bit and labelled as randomised/spoofed
rather than left blank — that covers modern phone MAC randomisation and DHCPig's own clients.

To bundle a standalone copy of the IEEE registry instead of relying on scapy's, fetch
`https://standards-oui.ieee.org/oui/oui.csv` and teach `core/oui.py` to read it.
