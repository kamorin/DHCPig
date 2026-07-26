# Fingerprint data attribution

`combined_dhcp_os_lookup.json` is a static, offline DHCP option-55 (parameter-request-list)
lookup table merging two sources:

- **PacketFence** DHCP fingerprint conf (`packetfence_dhcp_fingerprints.conf`) — derived from
  the FingerBank project, Inverse inc., Open Database License (ODbL) v1.0 /
  Database Contents License (DbCL) v1.0. https://opendatacommons.org/licenses/odbl/1.0/
- **Huginn-Muninn** DHCP signatures (`dhcp_os_fingerprints.csv`) — Ringmast4r/Huginn-Muninn,
  MIT license. https://github.com/Ringmast4r/Huginn-Muninn

The two were merged by `fingerprint-merge.py` (bundled alongside the data file; it also works
as a standalone `python3 fingerprint-merge.py <option-55-list>` CLI — copy it plus the JSON into
another project if useful elsewhere). The merge is keyed by the exact, order-sensitive option-55
string; a fingerprint present in both sources keeps both candidate entries. Current coverage:
594 combined fingerprints (see the file's own `statistics` block for the current split).

Matching is **offline and static — no API, no key, no network calls.** `dhcpig.core.fingerprint`
does an exact dict lookup on the option-55 string; a fingerprint with more than one candidate
device is reported with lower confidence and flagged ambiguous in `matched_via`.

To refresh coverage, regenerate `combined_dhcp_os_lookup.json` from newer source exports and
drop it in this directory — `dhcpig.core.fingerprint` loads whatever is present.

## MAC vendor (OUI) data

Hosts with no usable DHCP fingerprint — ARP-only neighbours especially — are identified by the
hardware vendor of their MAC. Two offline sources, no API:

- **IEEE OUI registry**, via **scapy's bundled Wireshark `manuf` database** (~50,000 MA-L/MA-M/
  MA-S assignments). scapy is already DHCPig's only runtime dependency, so this ships for free
  and needs no separate copy of the registry. Wireshark's `manuf` is GPL-2.0-or-later, same as
  this project, and is refreshed with each scapy release.
- **`mac-vendor.txt`** — vendored from [arp-scan](https://github.com/royhills/arp-scan) (GPLv3).
  A deliberately small supplement of prefixes the IEEE registry does *not* contain: QEMU, Bochs,
  Cisco HSRP, VRRP/CARP, Microsoft WLBS, OpenBSD randomised MACs, broadcast. Longest prefix
  wins, so these override the IEEE match (e.g. `00:00:0c:07:ac:*` is HSRP, not plain Cisco).

Unresolved MACs are checked for the locally-administered bit and labelled as randomised/spoofed
rather than left blank — that covers modern phone MAC randomisation and DHCPig's own clients.

To bundle a standalone copy of the IEEE registry instead of relying on scapy's, fetch
`https://standards-oui.ieee.org/oui/oui.csv` and teach `core/oui.py` to read it; the lookup
order is already structured for it.

`fingerprints.json` is a small original fallback table (authored for DHCPig, GPL-2.0-or-later)
used only when the combined DB has no exact option-55 match: a couple of representative
option-55 orders plus option-60 vendor-class-substring and MAC-OUI hints for signals the
combined DB doesn't carry (e.g. "MSFT", "android-dhcp", "PXEClient").
