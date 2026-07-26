#!/usr/bin/env python3
"""Standalone DHCP Option 55 OS/device identifier.

Copy this file and packetfence_dhcp_fingerprints.json into another repository.
Only the Python standard library is required.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

DEFAULT_DATABASE = Path(__file__).with_name("packetfence_dhcp_fingerprints.json")


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
        if match.get("device_type"):
            details.append(f"type: {match['device_type']}")
        if match.get("vendor"):
            details.append(f"vendor: {match['vendor']}")
        source = str(match.get("source", "unknown"))
        if match.get("source_id"):
            source += f" #{match['source_id']}"
        details.append(f"source: {source}")
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
        help="packetfence lookup JSON beside this script by default",
    )
    parser.add_argument("--json", action="store_true", help="write JSON results")
    parser.add_argument("--stats", action="store_true", help="show database statistics and exit")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        database, statistics = load_database(args.database)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: cannot load {args.database}: {error}", file=sys.stderr)
        return 2

    if args.stats:
        output = statistics or {"packetfence_fingerprints": len(database)}
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
