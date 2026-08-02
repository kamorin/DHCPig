# Fingerprint data attribution

`satori_dhcp_fingerprints.json` is a static, offline DHCP fingerprint lookup table derived
entirely from:

- **Satori** — `fingerprints/dhcp.xml`, Eric Kollmann and contributors,
  **GNU General Public License v2.0 or later**. https://github.com/xnih/satori

Satori has been doing passive DHCP fingerprinting since 2004 and is still updated; the data is
GPL-licensed, the same terms as this project, so DHCPig ships under a single license.

Regenerate with the converter bundled beside the data:

```
python3 satori-merge.py --convert /path/to/satori/fingerprints/dhcp.xml
```

`satori-merge.py` is also a standalone `python3 satori-merge.py <option-55-list>` lookup CLI over
the JSON — copy it plus the JSON into another project if useful elsewhere. Keeping the converter
and the matcher in one file is deliberate: the rules that build the table and the rules that
query it cannot drift apart.

## What is kept, and what is dropped

Two tables, both exact-match:

- `fingerprints` — DHCP **option 55** (parameter request list), order-sensitive. 319 signatures.
- `vendor_class` — DHCP **option 60** (vendor class id). 187 signatures.

Each candidate carries `name` plus, where Satori has them, `os`, `os_class`, `device` and
`vendor`. Absent fields are omitted rather than stored empty.

Dropped from the upstream XML: `os_url`, `device_url`, `comments`, `author`, `last_updated` and
`ipttl`. Those are per-record provenance and links; together they are most of the 448K the XML
weighs, against 83K for this file.

Only `matchtype="exact"` tests are imported. Every option-55 test in Satori is already exact, so
nothing is lost there. The `partial` tests are all vendor-class *substring* matches, which need a
different matcher than the dict lookup in `core/fingerprint.py`; add them here and there together
if that is ever wanted.

## Matching

`dhcpig.core.fingerprint` tries option 55 first (confidence 90, or 75 when a signature maps to
more than one candidate), then option 60 (70 / 55), then falls through to MAC-vendor
identification. A signature with several candidates keeps all of them and is flagged
`(ambiguous xN)` in `matched_via`; an OS is only claimed when every candidate agrees on one,
since "Windows 10 / iOS 12" is two guesses rather than an answer.

Matching is **offline and static — no API, no key, no network calls.**

## MAC vendor (OUI) data

Hosts with no usable DHCP fingerprint — ARP-only neighbours especially — are identified by the
hardware vendor of their MAC, via **scapy's bundled Wireshark `manuf` database** (~50,000
IEEE MA-L/MA-M/MA-S assignments). scapy is already DHCPig's only runtime dependency, so this
ships for free and needs no separate copy of the registry. Wireshark's `manuf` is
GPL-2.0-or-later, same as this project and same as Satori, and is refreshed with each scapy
release.

Unresolved MACs are checked for the locally-administered bit and labelled as randomised/spoofed
rather than left blank — that covers modern phone MAC randomisation and DHCPig's own clients.

To bundle a standalone copy of the IEEE registry instead of relying on scapy's, fetch
`https://standards-oui.ieee.org/oui/oui.csv` and teach `core/oui.py` to read it.

## History

Before 2.7.0 this directory shipped `packetfence_dhcp_fingerprints.json`, derived from
PacketFence's DHCP fingerprint configuration and therefore from Fingerbank (Inverse inc.), which
is licensed **ODbL v1.0 / DbCL v1.0** — not GPL. That data was replaced wholesale by the Satori
import so the project ships under one license end to end. It had 535 option-55 signatures against
319 here, but every `device_type` and `vendor` field in it was empty, it offered no vendor-class
dimension, and its upstream snapshot was static.
