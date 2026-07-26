"""Passive DHCP/host fingerprinting — resolve OS/device for every host on the segment.

Signal: option 55 (parameter-request-list) *exact, order-sensitive* match against the bundled
static `packetfence_dhcp_fingerprints.json` (see `data/DATA_ATTRIBUTION.md`), sourced entirely
from the PacketFence project's DHCP fingerprint database. Fully offline, no API keys, no network
calls.

If there's no exact option-55 match, we fall back to MAC OUI identification alone (see `oui.py`)
— weak evidence, but better than a blank row.

The matching semantics (normalize the option-55 list, exact dict lookup, flag ambiguous
multi-candidate fingerprints) mirror `data/fingerprint-merge.py`'s `identify()` so a lookup
here and a lookup with that standalone script agree.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources

from . import oui
from .models import HostFingerprint
from .packets import dhcp_option

DB_FILE = "packetfence_dhcp_fingerprints.json"


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
    """The bundled packetfence_dhcp_fingerprints.json, loaded once."""
    try:
        with resources.files("dhcpig.data").joinpath(DB_FILE).open(encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, ModuleNotFoundError, json.JSONDecodeError):
        return {"fingerprints": {}, "sources": {}, "statistics": {}}


def _fingerprints() -> dict[str, list[dict]]:
    return _db().get("fingerprints", {})


def _normalize_prl_key(prl: list[int]) -> str:
    """Match `fingerprint-merge.py`'s `normalize_fingerprint()`: comma-joined decimal options."""
    return ",".join(str(x) for x in prl)


def _db_version() -> str:
    stats = _db().get("statistics", {})
    n = stats.get("packetfence_fingerprints", len(_fingerprints()))
    return f"packetfence_dhcp_fingerprints({n} fp)"


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


def _resolve_from_db(sig: Signature, role: str) -> HostFingerprint | None:
    """Exact, order-sensitive option-55 lookup against packetfence_dhcp_fingerprints.json."""
    if not sig.prl:
        return None
    key = _normalize_prl_key(sig.prl)
    candidates = _fingerprints().get(key)
    if not candidates:
        return None
    names = sorted({c.get("name", "") for c in candidates if c.get("name")})
    device = " / ".join(names) if len(names) > 1 else (names[0] if names else None)
    vendors = sorted({c.get("vendor", "") for c in candidates if c.get("vendor")})
    vendor = vendors[0] if len(vendors) == 1 else None
    ambiguous = len(candidates) > 1
    matched_via = f"opt55:{key}" + (f" (ambiguous x{len(candidates)})" if ambiguous else "")
    return HostFingerprint(
        mac=sig.mac,
        ip=sig.ip,
        role=role,
        os=None,
        device=device,
        vendor=vendor,
        confidence=75 if ambiguous else 90,
        matched_via=matched_via,
        raw_prl=sig.prl,
    )


def resolve(sig: Signature, role: str = "client") -> HostFingerprint:
    """Map a Signature to an OS/device label with a confidence score.

    1) exact option-55 order match against packetfence_dhcp_fingerprints.json (strongest signal)
    2) MAC OUI only — no DHCP evidence, but at least says who made the hardware
    """
    fp = _resolve_from_db(sig, role)
    if fp is not None:
        if not fp.vendor:  # fill in the hardware vendor the DHCP data didn't carry
            fp.vendor = oui.lookup(sig.mac)
        return fp
    return from_mac(sig.mac, ip=sig.ip, role=role, raw_prl=sig.prl)


def from_mac(mac: str, ip: str = "", role: str = "client", raw_prl=None) -> HostFingerprint:
    """OUI-only identification, for hosts with no usable DHCP fingerprint.

    ARP-only neighbours never send DHCP we can read, so without this they'd show a blank
    OS/Device column. The hardware vendor is weak evidence — hence the low confidence — but
    it is far more useful than nothing.
    """
    vendor = oui.lookup(mac)
    return HostFingerprint(
        mac=mac,
        ip=ip,
        role=role,
        os=None,
        # surfaced in the OS/Device column; marked so it is never mistaken for an OS match
        device=f"{vendor} (MAC vendor)" if vendor else None,
        vendor=vendor,
        confidence=15 if vendor else 0,
        matched_via=f"oui:{mac[:8]}" if vendor else "unknown",
        raw_prl=list(raw_prl or []),
    )
