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

`fingerprints.json` is a small original fallback table (authored for DHCPig, GPL-2.0-or-later)
used only when the combined DB has no exact option-55 match: a couple of representative
option-55 orders plus option-60 vendor-class-substring and MAC-OUI hints for signals the
combined DB doesn't carry (e.g. "MSFT", "android-dhcp", "PXEClient").
