#!/usr/bin/env python3
"""Standalone DHCP fingerprint identifier, and the regenerator for its database.

Two jobs in one file, deliberately: the lookup half is what you copy into another
project alongside satori_dhcp_fingerprints.json, and the --convert half is how that
JSON is produced in the first place, so the matching rules and the build rules can
never drift apart.

  lookup   python3 satori-merge.py 1,121,3,6,15,119,252,95,44,46
  convert  python3 satori-merge.py --convert path/to/satori/fingerprints/dhcp.xml

Only the Python standard library is required.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

DEFAULT_DATABASE = Path(__file__).with_name("satori_dhcp_fingerprints.json")

SOURCE = {
    "project": "Satori",
    "url": "https://github.com/xnih/satori",
    "file": "fingerprints/dhcp.xml",
}


def normalize_fingerprint(value: str) -> str:
    parts = [part.strip() for part in value.split(",")]
    if not parts or any(not part for part in parts):
        raise ValueError("fingerprint contains an empty option")
    try:
        options = [int(part, 10) for part in parts]
    except ValueError as error:
        raise ValueError("fingerprint options must be decimal integers") from error
    if any(option < 0 or option > 255 for option in options):
        raise ValueError("fingerprint options must be between 0 and 255")
    return ",".join(str(option) for option in options)


# --------------------------------------------------------------------- convert
def _clean(value: str | None) -> str:
    return (value or "").strip()


def convert(xml_path: Path) -> dict[str, Any]:
    """Reduce Satori's dhcp.xml to the two lookup tables this project needs.

    Dropped on purpose: os_url/device_url, comments, author, last_updated and ipttl.
    They are provenance and links, they are repeated on every record, and together they
    are most of the 448K the XML weighs. Per-entry keys are omitted rather than stored
    empty, which is the rest of the saving.

    Only matchtype="exact" tests are kept. Every option-55 test in Satori is exact
    anyway, so nothing is lost there; the partial tests are all vendor-class substring
    matches, which would need a different matcher than the dict lookup below.
    """
    root = ET.parse(xml_path).getroot()
    by_prl: dict[str, list[dict[str, str]]] = {}
    by_vendor_class: dict[str, list[dict[str, str]]] = {}

    for node in root.findall(".//fingerprint"):
        entry: dict[str, str] = {"name": _clean(node.get("name"))}
        for src, dst in (
            ("os_name", "os"),
            ("os_class", "os_class"),
            ("device_type", "device"),
            ("device_vendor", "vendor"),
        ):
            value = _clean(node.get(src))
            if value:
                entry[dst] = value
        if "vendor" not in entry:
            value = _clean(node.get("os_vendor"))
            if value:
                entry["vendor"] = value

        for test in node.findall(".//test"):
            if test.get("matchtype") != "exact":
                continue
            prl = test.get("dhcpoption55")
            if prl:
                # a couple of Satori keys carry stray whitespace; without this they
                # would sit beside their own clean duplicates and never match
                key = normalize_fingerprint(re.sub(r"\s+", "", prl))
                by_prl.setdefault(key, [])
                if entry not in by_prl[key]:
                    by_prl[key].append(entry)
            vendor_class = _clean(test.get("dhcpvendorcode"))
            if vendor_class:
                by_vendor_class.setdefault(vendor_class, [])
                if entry not in by_vendor_class[vendor_class]:
                    by_vendor_class[vendor_class].append(entry)

    return {
        "schema": 1,
        "match_type": "exact, order-sensitive DHCP option 55; vendor class = option 60",
        "license": "GPL-2.0-or-later",
        "source": SOURCE,
        "statistics": {
            "option55_signatures": len(by_prl),
            "vendor_class_signatures": len(by_vendor_class),
        },
        "fingerprints": dict(sorted(by_prl.items())),
        "vendor_class": dict(sorted(by_vendor_class.items())),
    }


def render(payload: dict[str, Any]) -> str:
    """Serialize with one line per signature: near-compact, but still diffs readably."""

    def table(mapping: dict[str, list[dict[str, str]]]) -> str:
        rows = [
            f"  {json.dumps(key, ensure_ascii=False)}: "
            f"{json.dumps(value, separators=(',', ':'), ensure_ascii=False)}"
            for key, value in mapping.items()
        ]
        return "{\n" + ",\n".join(rows) + "\n }"

    head = {k: v for k, v in payload.items() if k not in ("fingerprints", "vendor_class")}
    parts = [json.dumps(head, indent=1, ensure_ascii=False)[1:-1].rstrip()]
    parts.append(f' "fingerprints": {table(payload["fingerprints"])}')
    parts.append(f' "vendor_class": {table(payload["vendor_class"])}')
    return "{" + ",\n".join(parts) + "\n}\n"


# ---------------------------------------------------------------------- lookup
def load_database(path: Path) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    fingerprints = payload.get("fingerprints")
    if not isinstance(fingerprints, dict):
        raise ValueError("database has no fingerprints object")
    return fingerprints, payload.get("statistics", {})


def identify(value: str, database: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    fingerprint = normalize_fingerprint(value)
    matches = database.get(fingerprint, [])
    return {
        "fingerprint": fingerprint,
        "matched": bool(matches),
        "ambiguous": len(matches) > 1,
        "match_count": len(matches),
        "matches": matches,
    }


def print_text(result: dict[str, Any]) -> None:
    print(f"Option 55: {result['fingerprint']}")
    if not result["matched"]:
        print("Result: unknown (no exact match)")
        return
    count = result["match_count"]
    print(f"Result: {count} exact match{'es' if count != 1 else ''}")
    for match in result["matches"]:
        details = [str(match.get("name", "Unknown"))]
        for label, key in (("os", "os"), ("type", "device"), ("vendor", "vendor")):
            if match.get(key):
                details.append(f"{label}: {match[key]}")
        print(f"- {'; '.join(details)}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Identify OS/device candidates using an exact, order-sensitive "
            "DHCP Option 55 fingerprint."
        )
    )
    parser.add_argument(
        "fingerprint",
        nargs="*",
        help="one or more comma-separated Option 55 lists; reads stdin if omitted",
    )
    parser.add_argument(
        "-d",
        "--database",
        type=Path,
        default=DEFAULT_DATABASE,
        help="lookup JSON beside this script by default",
    )
    parser.add_argument("--json", action="store_true", help="write JSON results")
    parser.add_argument("--stats", action="store_true", help="show database statistics and exit")
    parser.add_argument(
        "--convert",
        type=Path,
        metavar="DHCP_XML",
        help="regenerate the database from Satori's fingerprints/dhcp.xml and write it to "
        "--database, then exit",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)

    if args.convert:
        try:
            payload = convert(args.convert)
        except (OSError, ET.ParseError, ValueError) as error:
            print(f"error: cannot convert {args.convert}: {error}", file=sys.stderr)
            return 2
        args.database.write_text(render(payload), encoding="utf-8")
        stats = payload["statistics"]
        print(
            f"wrote {args.database} — {stats['option55_signatures']} option-55 and "
            f"{stats['vendor_class_signatures']} vendor-class signatures"
        )
        return 0

    try:
        database, statistics = load_database(args.database)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: cannot load {args.database}: {error}", file=sys.stderr)
        return 2

    if args.stats:
        output = statistics or {"option55_signatures": len(database)}
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    raw_fingerprints = args.fingerprint or [line.strip() for line in sys.stdin if line.strip()]
    if not raw_fingerprints:
        print("error: provide a fingerprint or pipe one on stdin", file=sys.stderr)
        return 2
    try:
        results = [identify(value, database) for value in raw_fingerprints]
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    if args.json:
        output: Any = results[0] if len(results) == 1 else results
        print(json.dumps(output, indent=2, sort_keys=True))
    else:
        for index, result in enumerate(results):
            if index:
                print()
            print_text(result)
    return 0 if all(result["matched"] for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
