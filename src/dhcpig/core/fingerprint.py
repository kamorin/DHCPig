"""Passive DHCP/host fingerprinting — resolve OS/device for every host on the segment.

Signals, strongest first, against the bundled static `satori_dhcp_fingerprints.json`
(see `data/DATA_ATTRIBUTION.md`), derived from the Satori project's DHCP fingerprint
database. Fully offline, no API keys, no network calls.

1. **option 55** (parameter-request-list), *exact and order-sensitive*. The specific
   signal: the set and order of options a stack asks for pins down an OS version.
2. **option 60** (vendor class id), exact. Coarser — "MSFT 5.0" says Windows, not
   which Windows — so it scores below option 55, but it is still DHCP evidence from
   the host itself and sits far above a MAC lookup.
3. **MAC OUI** alone (`oui_lookup`, folded in below) — no DHCP evidence at all, weak,
   but better than a blank row for ARP-only neighbours.

The matching semantics (normalize the option-55 list, exact dict lookup, flag ambiguous
multi-candidate fingerprints) mirror `data/satori-merge.py`'s `identify()` so a lookup
here and a lookup with that standalone script agree.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources

from .models import HostFingerprint
from .packets import dhcp_option

DB_FILE = "satori_dhcp_fingerprints.json"

# Confidence bands. Option 55 keeps the 90/75 it always had; vendor class lands between
# that and the OUI floor of 15 (see `from_mac`) so the three tiers can never be confused
# for one another in a report.
CONF_PRL = 90
CONF_PRL_AMBIGUOUS = 75
CONF_VENDOR_CLASS = 70
CONF_VENDOR_CLASS_AMBIGUOUS = 55


@dataclass
class Signature:
    mac: str
    ip: str
    prl: list[int] = field(default_factory=list)  # option 55, ordered
    vendor_class: str | None = None  # option 60
    hostname: str | None = None  # option 12
    oui: str = ""  # first 3 MAC octets, lowercase, colon-joined


@lru_cache(maxsize=1)
def _db() -> dict:
    """The bundled satori_dhcp_fingerprints.json, loaded once."""
    try:
        with resources.files("dhcpig.data").joinpath(DB_FILE).open(encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, ModuleNotFoundError, json.JSONDecodeError):
        return {"fingerprints": {}, "vendor_class": {}, "source": {}, "statistics": {}}


def _fingerprints() -> dict[str, list[dict]]:
    return _db().get("fingerprints", {})


def _vendor_classes() -> dict[str, list[dict]]:
    return _db().get("vendor_class", {})


def _normalize_prl_key(prl: list[int]) -> str:
    """Match `satori-merge.py`'s `normalize_fingerprint()`: comma-joined decimal options."""
    return ",".join(str(x) for x in prl)


def _db_version() -> str:
    stats = _db().get("statistics", {})
    n = stats.get("option55_signatures", len(_fingerprints()))
    v = stats.get("vendor_class_signatures", len(_vendor_classes()))
    return f"satori_dhcp_fingerprints({n} fp, {v} vc)"


DB_VERSION = _db_version()


def _normalize_prl(value) -> list[int]:
    if value is None:
        return []
    if isinstance(value, (bytes, bytearray)):
        return list(value)
    if isinstance(value, (list, tuple)):
        out: list[int] = []
        for v in value:
            if isinstance(v, (bytes, bytearray)):
                out.extend(v)
            elif isinstance(v, int):
                out.append(v)
        return out
    if isinstance(value, int):
        return [value]
    return []


def _decode(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    return str(value)


def extract_signature(pkt, role: str = "client") -> Signature:
    """Build a Signature from a scapy DHCP packet (DISCOVER/REQUEST/OFFER)."""
    from scapy.all import DHCP, Ether  # local import keeps module import light

    opts = pkt[DHCP].options if DHCP in pkt else []
    mac = pkt[Ether].src if Ether in pkt else ""
    oui = ":".join(mac.split(":")[:3]).lower() if mac else ""
    return Signature(
        mac=mac,
        ip="",
        prl=_normalize_prl(dhcp_option(opts, "param_req_list")),
        vendor_class=_decode(dhcp_option(opts, "vendor_class_id")),
        hostname=_decode(dhcp_option(opts, "hostname")),
        oui=oui,
    )


def _combine(
    candidates: list[dict], sig: Signature, role: str, via: str, conf: int, conf_ambiguous: int
) -> HostFingerprint:
    """Fold one or more candidate records into a single HostFingerprint.

    A signature with more than one candidate is reported at the lower confidence and
    flagged in `matched_via`, rather than silently picking one — the tool would rather
    say "one of these two" than assert the wrong device.
    """
    names = sorted({c.get("name", "") for c in candidates if c.get("name")})
    oses = sorted({c.get("os", "") for c in candidates if c.get("os")})
    vendors = sorted({c.get("vendor", "") for c in candidates if c.get("vendor")})
    ambiguous = len(candidates) > 1
    return HostFingerprint(
        mac=sig.mac,
        ip=sig.ip,
        role=role,
        # only claim an OS when every candidate agrees on one; "Windows 10 / iOS 12" is
        # not an OS, it is two guesses, and the device/name field already carries that
        os=oses[0] if len(oses) == 1 else None,
        # the specific record name ("Windows 10"), not the record's coarse device_type
        # ("Smartphone") -- the latter stays in the JSON for `satori-merge.py` to print,
        # since HostFingerprint has no field for a category and one name is what a report row
        # has room to say
        device=" / ".join(names) if len(names) > 1 else (names[0] if names else None),
        vendor=vendors[0] if len(vendors) == 1 else None,
        confidence=conf_ambiguous if ambiguous else conf,
        matched_via=via + (f" (ambiguous x{len(candidates)})" if ambiguous else ""),
        raw_prl=sig.prl,
    )


def _resolve_from_db(sig: Signature, role: str) -> HostFingerprint | None:
    """Exact, order-sensitive option-55 lookup against satori_dhcp_fingerprints.json."""
    if not sig.prl:
        return None
    key = _normalize_prl_key(sig.prl)
    candidates = _fingerprints().get(key)
    if not candidates:
        return None
    return _combine(candidates, sig, role, f"opt55:{key}", CONF_PRL, CONF_PRL_AMBIGUOUS)


def _resolve_from_vendor_class(sig: Signature, role: str) -> HostFingerprint | None:
    """Exact option-60 (vendor class id) lookup — the middle rung.

    Reached only when option 55 missed. Plenty of stacks send a distinctive vendor class
    while using a parameter-request-list shared with a dozen other devices, so this
    recovers hosts that would otherwise fall all the way to a bare MAC vendor.
    """
    if not sig.vendor_class:
        return None
    candidates = _vendor_classes().get(sig.vendor_class.strip())
    if not candidates:
        return None
    return _combine(
        candidates,
        sig,
        role,
        f"opt60:{sig.vendor_class.strip()}",
        CONF_VENDOR_CLASS,
        CONF_VENDOR_CLASS_AMBIGUOUS,
    )


def resolve(sig: Signature, role: str = "client") -> HostFingerprint:
    """Map a Signature to an OS/device label with a confidence score.

    1) exact option-55 order match (strongest signal)
    2) exact option-60 vendor class match
    3) MAC OUI only — no DHCP evidence, but at least says who made the hardware
    """
    for lookup in (_resolve_from_db, _resolve_from_vendor_class):
        fp = lookup(sig, role)
        if fp is not None:
            if not fp.vendor:  # fill in the hardware vendor the DHCP data didn't carry
                fp.vendor = oui_lookup(sig.mac)
            return fp
    return from_mac(sig.mac, ip=sig.ip, role=role, raw_prl=sig.prl)


def from_mac(mac: str, ip: str = "", role: str = "client", raw_prl=None) -> HostFingerprint:
    """OUI-only identification, for hosts with no usable DHCP fingerprint.

    ARP-only neighbours never send DHCP we can read, so without this they'd show a blank
    OS/Device column. The hardware vendor is weak evidence — hence the low confidence — but
    it is far more useful than nothing.
    """
    vendor = oui_lookup(mac)
    return HostFingerprint(
        mac=mac,
        ip=ip,
        role=role,
        os=None,
        # surfaced in the OS/Device column; marked so it is never mistaken for an OS match
        device=f"{vendor} (vendor)" if vendor else None,
        vendor=vendor,
        confidence=15 if vendor else 0,
        matched_via=f"oui:{mac[:8]}" if vendor else "unknown",
        raw_prl=list(raw_prl or []),
    )


# --------------------------------------------------------------------------- MAC OUI -> vendor
# Weakest signal (tier 3 in this module's docstring): who made the NIC, when there is no DHCP
# evidence to fingerprint. Single offline source, no network/API: scapy's bundled Wireshark
# `manuf` DB (~50k IEEE MA-L/MA-M/MA-S assignments). scapy is already our only runtime dependency.
# Anything unresolved is checked for the locally-administered bit, which identifies
# randomised/privacy MACs (modern phones, and DHCPig's own spoofed clients).

LOCALLY_ADMINISTERED = "randomised/spoofed"


def _normalize_mac(mac: str) -> str:
    """'00:1A:2B:...' -> '001a2b...' (separators stripped, lowercased)."""
    return mac.replace(":", "").replace("-", "").replace(".", "").lower()


def _is_locally_administered(norm: str) -> bool:
    try:
        return bool(int(norm[:2], 16) & 0x02)
    except (ValueError, IndexError):
        return False


@lru_cache(maxsize=8192)
def oui_lookup(mac: str) -> str | None:
    """Hardware vendor for a MAC, or None if genuinely unknown."""
    if not mac:
        return None
    norm = _normalize_mac(mac)
    if len(norm) < 6:
        return None

    try:
        from scapy.all import conf

        # scapy expects canonical colon-separated form, so feed it the normalised MAC
        canonical = ":".join(norm[i : i + 2] for i in range(0, 12, 2))
        found = conf.manufdb._get_manuf(canonical)
        # scapy hands back the MAC itself when it has no match — that is not a vendor
        if found and _normalize_mac(str(found)) != norm:
            return str(found)
    except Exception:
        pass

    if _is_locally_administered(norm):
        return LOCALLY_ADMINISTERED
    return None
