"""Passive DHCP/host fingerprinting — resolve OS/device for every host on the segment.

Primary signal: option 55 (parameter-request-list) *exact, order-sensitive* match against the
bundled static `combined_dhcp_os_lookup.json` (see `data/DATA_ATTRIBUTION.md`) — a merge of the
PacketFence and Huginn-Muninn DHCP fingerprint sets, built by `data/fingerprint-merge.py`.
Fully offline, no API keys, no network calls.

Fallback signal: a small builtin table (option 60 vendor-class substring + MAC OUI) for signals
the combined DB doesn't carry, plus a couple of representative option-55 orders of its own.

The matching semantics (normalize the option-55 list, exact dict lookup, flag ambiguous
multi-candidate fingerprints) mirror `data/fingerprint-merge.py`'s `identify()` so a lookup
here and a lookup with that standalone script agree.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources

from .models import HostFingerprint
from .packets import dhcp_option

COMBINED_DB_FILE = "combined_dhcp_os_lookup.json"


@dataclass
class Signature:
    mac: str
    ip: str
    prl: list[int] = field(default_factory=list)  # option 55, ordered
    vendor_class: str | None = None  # option 60
    hostname: str | None = None  # option 12
    oui: str = ""  # first 3 MAC octets, lowercase, colon-joined


def _builtin() -> list[dict]:
    with resources.files("dhcpig.data").joinpath("fingerprints.json").open() as fh:
        return json.load(fh)["entries"]


@lru_cache(maxsize=1)
def _combined() -> dict:
    """The bundled combined_dhcp_os_lookup.json, loaded once."""
    try:
        with resources.files("dhcpig.data").joinpath(COMBINED_DB_FILE).open(encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, ModuleNotFoundError, json.JSONDecodeError):
        return {"fingerprints": {}, "sources": {}, "statistics": {}}


def _combined_fingerprints() -> dict[str, list[dict]]:
    return _combined().get("fingerprints", {})


def _normalize_prl_key(prl: list[int]) -> str:
    """Match `fingerprint-merge.py`'s `normalize_fingerprint()`: comma-joined decimal options."""
    return ",".join(str(x) for x in prl)


def _db_version() -> str:
    stats = _combined().get("statistics", {})
    n = stats.get("combined_fingerprints", len(_combined_fingerprints()))
    sources = ",".join(_combined().get("sources", {}).keys()) or "none"
    return f"combined_dhcp_os_lookup({n} fp; sources={sources})+builtin"


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


def _resolve_from_combined(sig: Signature, role: str) -> HostFingerprint | None:
    """Exact, order-sensitive option-55 lookup against combined_dhcp_os_lookup.json."""
    if not sig.prl:
        return None
    key = _normalize_prl_key(sig.prl)
    candidates = _combined_fingerprints().get(key)
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


def _resolve_from_builtin(sig: Signature, role: str) -> HostFingerprint | None:
    """Fallback: builtin vendor-class / OUI / representative-PRL table."""
    best: HostFingerprint | None = None
    for entry in _builtin():
        if entry.get("prl") and sig.prl and list(entry["prl"]) == sig.prl:
            cand = HostFingerprint(
                mac=sig.mac,
                ip=sig.ip,
                role=role,
                os=entry.get("os"),
                device=entry.get("device"),
                vendor=entry.get("vendor"),
                confidence=int(entry.get("confidence", 95)),
                matched_via=f"opt55:{_normalize_prl_key(sig.prl)}",
                raw_prl=sig.prl,
            )
            if best is None or cand.confidence > best.confidence:
                best = cand
        vc = entry.get("vendor_class")
        if vc and sig.vendor_class and vc.lower() in sig.vendor_class.lower():
            cand = HostFingerprint(
                mac=sig.mac,
                ip=sig.ip,
                role=role,
                os=entry.get("os"),
                device=entry.get("device"),
                vendor=entry.get("vendor"),
                confidence=int(entry.get("confidence", 90)) - 5,
                matched_via=f'opt60:"{sig.vendor_class}"',
                raw_prl=sig.prl,
            )
            if best is None or cand.confidence > best.confidence:
                best = cand
        for oui in entry.get("oui", []):
            if sig.oui and sig.oui == oui.lower():
                cand = HostFingerprint(
                    mac=sig.mac,
                    ip=sig.ip,
                    role=role,
                    os=None,
                    device=entry.get("device"),
                    vendor=entry.get("vendor"),
                    confidence=55,
                    matched_via=f"oui:{sig.oui}",
                    raw_prl=sig.prl,
                )
                if best is None or cand.confidence > best.confidence:
                    best = cand
    return best


def resolve(sig: Signature, role: str = "client") -> HostFingerprint:
    """Map a Signature to an OS/device label with a confidence score.

    1) exact option-55 order match against combined_dhcp_os_lookup.json (strongest signal)
    2) builtin fallback: representative option-55 order, then vendor-class substring, then OUI
    """
    fp = _resolve_from_combined(sig, role)
    if fp is not None:
        return fp
    fp = _resolve_from_builtin(sig, role)
    if fp is not None:
        return fp
    return HostFingerprint(
        mac=sig.mac,
        ip=sig.ip,
        role=role,
        os=None,
        device=None,
        vendor=None,
        confidence=0,
        matched_via="unknown",
        raw_prl=sig.prl,
    )
