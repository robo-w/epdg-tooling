#!/usr/bin/env python3
"""Compare resolved IP endpoints across MCC-MNC carriers.

The script reads the JSON output produced by query_3gpp_dns.py, collects the
resolved A and AAAA addresses for each carrier, and then prints:

* carriers that share the same endpoint set
* carriers whose endpoint set is unique


Prompt for GPT-5.3-Codex: "create a new python script which reads the mnc json file, stores a set of resolved IPs per MCC-MNC value and then prints which providers use the same endpoints"
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import DefaultDict, Dict, Iterable, List, Set


CarrierKey = str
EndpointSet = frozenset[str]


def load_json(path: Path) -> list[dict]:
    """Load a JSON array, accepting both UTF-16 and UTF-8 exports."""
    last_error: Exception | None = None
    for encoding in ("utf-16", "utf-8"):
        try:
            with path.open("r", encoding=encoding) as handle:
                data = json.load(handle)
            if not isinstance(data, list):
                raise ValueError("expected a JSON array")
            return data
        except (UnicodeError, json.JSONDecodeError, ValueError) as error:
            last_error = error
    if last_error is not None:
        raise last_error
    raise ValueError("failed to load JSON")


def carrier_key(entry: dict) -> CarrierKey:
    mcc = str(entry.get("mcc", "")).strip()
    mnc = str(entry.get("mnc", "")).strip()
    if not mcc or not mnc:
        raise ValueError(f"missing mcc/mnc fields in entry: {entry!r}")
    return f"{mcc}-{mnc}"


def extract_addresses(records: dict) -> Set[str]:
    addresses: Set[str] = set()
    if not isinstance(records, dict):
        return addresses

    for record_type in ("A", "AAAA"):
        values = records.get(record_type, [])
        if not isinstance(values, list):
            continue
        for item in values:
            if not isinstance(item, dict):
                continue
            address = item.get("address")
            if address:
                addresses.add(str(address).strip())

    return addresses


def build_endpoint_index(entries: Iterable[dict]) -> tuple[Dict[CarrierKey, EndpointSet], DefaultDict[EndpointSet, List[CarrierKey]]]:
    per_carrier: Dict[CarrierKey, EndpointSet] = {}
    by_endpoints: DefaultDict[EndpointSet, List[CarrierKey]] = defaultdict(list)

    for entry in entries:
        key = carrier_key(entry)
        addresses = extract_addresses(entry.get("records", {}))
        endpoint_set = frozenset(addresses)
        per_carrier[key] = endpoint_set
        by_endpoints[endpoint_set].append(key)

    return per_carrier, by_endpoints


def print_shared_endpoints(groups: Dict[EndpointSet, List[CarrierKey]]) -> None:
    shared_groups = [
        (sorted(carriers), sorted(endpoints))
        for endpoints, carriers in groups.items()
        if len(carriers) > 1 and endpoints
    ]

    if not shared_groups:
        print("Shared endpoint sets: none")
        return

    print("Shared endpoint sets:")
    for carriers, endpoints in sorted(shared_groups, key=lambda item: (len(item[0]), item[0])):
        print(", ".join(carriers))
        print("  endpoints: " + ", ".join(endpoints))


def print_unique_endpoints(groups: Dict[EndpointSet, List[CarrierKey]]) -> None:
    unique_groups = [
        (carriers[0], sorted(endpoints))
        for endpoints, carriers in groups.items()
        if len(carriers) == 1 and endpoints
    ]

    if not unique_groups:
        print("Unique endpoint sets: none")
        return

    print("Unique endpoint sets:")
    for carrier, endpoints in sorted(unique_groups, key=lambda item: item[0]):
        print(carrier)
        print("  endpoints: " + ", ".join(endpoints))


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Find carriers that share or uniquely use the same resolved endpoints")
    parser.add_argument("--file", required=True, type=Path, help="JSON file produced by query_3gpp_dns.py")
    args = parser.parse_args(argv)

    entries = load_json(args.file)
    _, by_endpoints = build_endpoint_index(entries)
    print_shared_endpoints(by_endpoints)
    print()
    print_unique_endpoints(by_endpoints)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
