"""MAC address -> hardware vendor ("who made this NIC").

Used to give every host an identity in the OS/Device column even when it never sent a DHCP
packet we could fingerprint (ARP-only neighbours), or sent one we don't recognise.

Single offline source, no network, no API: scapy's bundled Wireshark `manuf` database (~50k
IEEE MA-L/MA-M/MA-S assignments). scapy is already our only runtime dependency, so this costs
nothing to ship.

Anything unresolved is checked for the locally-administered bit, which identifies
randomised/privacy MACs (modern phones, and DHCPig's own spoofed clients) rather than leaving
the row blank with no explanation.
"""

from __future__ import annotations

from functools import lru_cache

LOCALLY_ADMINISTERED = "randomised/spoofed"


def _normalize(mac: str) -> str:
    """'00:1A:2B:...' -> '001a2b...' (separators stripped, lowercased)."""
    return mac.replace(":", "").replace("-", "").replace(".", "").lower()


def _is_locally_administered(norm: str) -> bool:
    try:
        return bool(int(norm[:2], 16) & 0x02)
    except (ValueError, IndexError):
        return False


@lru_cache(maxsize=8192)
def lookup(mac: str) -> str | None:
    """Vendor for a MAC, or None if genuinely unknown."""
    if not mac:
        return None
    norm = _normalize(mac)
    if len(norm) < 6:
        return None

    try:
        from scapy.all import conf

        # scapy expects canonical colon-separated form, so feed it the normalised MAC
        canonical = ":".join(norm[i : i + 2] for i in range(0, 12, 2))
        found = conf.manufdb._get_manuf(canonical)
        # scapy hands back the MAC itself when it has no match — that is not a vendor
        if found and _normalize(str(found)) != norm:
            return str(found)
    except Exception:
        pass

    if _is_locally_administered(norm):
        return LOCALLY_ADMINISTERED
    return None


def describe(mac: str) -> str | None:
    """Vendor string suitable for the OS/Device column, or None."""
    return lookup(mac)
