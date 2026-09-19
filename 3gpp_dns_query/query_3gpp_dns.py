#!/usr/bin/env python3
"""Query 3GPP DNS records for a list of MCC/MNC carriers.

This script builds the standard 3GPP operator domain names (both public and non-public
variants) and queries DNS records (NAPTR, SRV, A, AAAA, TXT) for each.

Usage examples:
  python query_3gpp_dns.py --carriers 232-001 001-01
  python query_3gpp_dns.py --file carriers.txt --json

carriers format: MCC-MNC (e.g. 232-001)
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Dict, List, Tuple

import dns.exception
import dns.resolver


DEFAULT_CARRIERS = [
    # Example entry; MCC and MNC are strings to preserve leading zeros
    ("232", "001"), # A1
    ("232", "003"), # Magenta
    ("232", "005"), # Drei
]


def build_domains(mcc: str, mnc: str) -> List[str]:
    # 3GPP commonly documents operator domains like:
    #   mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org
    #   mnc<MNC>.mcc<MCC>.3gppnetwork.org
    # We take MCC and MNC as strings and preserve any leading zeros exactly as provided.
    return [
        f"epdg.epc.mnc{mnc}.mcc{mcc}.pub.3gppnetwork.org",
#        f"sos.epdg.epc.mnc{mnc}.mcc{mcc}.pub.3gppnetwork.org",
#        f"n3iwf.5gc.mnc{mnc}.mcc{mcc}.pub.3gppnetwork.org",
    ]


def query(name: str) -> Dict[str, List[Dict[str, str]]]:
    res = dns.resolver.Resolver()
    out: Dict[str, List[Dict[str, str]]] = {
        "NAPTR": [],
        "SRV": [],
        "A": [],
        "AAAA": [],
        "TXT": [],
    }

    #naptrs = query_naptr(name, res)
    naptrs = []

    for r in naptrs:
        out["NAPTR"].append({
            "order": str(getattr(r, "order", "")),
            "preference": str(getattr(r, "preference", "")),
            "flags": getattr(r, "flags", "").decode() if getattr(r, "flags", "") else "",
            "service": getattr(r, "service", "").decode() if getattr(r, "service", "") else "",
            "regexp": getattr(r, "regexp", "").decode() if getattr(r, "regexp", "") else "",
            "replacement": str(getattr(r, "replacement", "")),
        })

    # For SRV/A/AAAA/TXT we attempt queries and ignore missing answers
    for typ in ("A", "AAAA"):
        try:
            answers = res.resolve(name, typ)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            answers = []

        for r in answers:
            if typ == "SRV":
                out["SRV"].append({
                    "priority": str(r.priority),
                    "weight": str(r.weight),
                    "port": str(r.port),
                    "target": str(r.target).rstrip('.'),
                })
            elif typ in ("A", "AAAA"):
                if r.address.startswith("127.") or r.address == "::1":
                    continue  # skip localhost addresses
                out[typ].append({"address": str(r)} )
            elif typ == "TXT":
                # r.strings is bytes in dnspython
                txt = b"".join(r.strings) if hasattr(r, "strings") else b""
                try:
                    txts = [s.decode(errors="ignore") for s in r.strings]
                except Exception:
                    txts = [str(r)]
                out["TXT"].append({"txt": ";".join(txts)})

    return out

def query_naptr(name, res):
    try:
        naptrs = res.resolve(name, "NAPTR")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        naptrs = []
    return naptrs


def parse_carrier_token(tok: str) -> Tuple[str, str]:
    # token like MCC-MNC (e.g. 232-001)
    if "-" not in tok:
        raise argparse.ArgumentTypeError(f"invalid carrier token: {tok}")
    parts = tok.split("-")
    if len(parts) != 2:
        raise argparse.ArgumentTypeError(f"invalid carrier token: {tok}")
    mcc = parts[0].strip()
    mnc = parts[1].strip()
    if not (mcc.isdigit() and mnc.isdigit()):
        raise argparse.ArgumentTypeError(f"MCC and MNC must be numeric: {tok}")
    return mcc, mnc


def main(argv: List[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Query 3GPP DNS records for carriers (MCC-MNC)")
    p.add_argument("--carriers", nargs="*", type=parse_carrier_token, help="List of MCC-MNC pairs, e.g. 232-001")
    p.add_argument("--file", type=str, help="File with MCC-MNC pairs, one per line e.g. 232-001")
    p.add_argument("--json", action="store_true", help="Output JSON")
    p.add_argument("--timeout", type=float, default=5.0, help="DNS query timeout seconds")
    args = p.parse_args(argv)

    carriers: List[Tuple[str, str]] = []
    if args.carriers:
        carriers.extend(args.carriers)
    if args.file:
        try:
            with open(args.file, "r") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    carriers.append(parse_carrier_token(line))
        except OSError as e:
            print(f"failed to open file: {e}", file=sys.stderr)
            return 2

    if not carriers:
        carriers = DEFAULT_CARRIERS

    dns.resolver.default_resolver = None
    resolver = dns.resolver.Resolver()
    resolver.timeout = args.timeout
    resolver.lifetime = args.timeout

    results = []
    for mcc, mnc in carriers:
        domains = build_domains(mcc, mnc)
        for domain in domains:
            try:
                r = query(domain)
            except Exception as e:
                r = {"error": str(e)}
            entry = {
                "mcc": mcc,
                "mnc": mnc,
                "domain": domain,
                "records": r,
            }
            results.append(entry)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for e in results:
            print(f"{e['mcc']}-{e['mnc']} -> {e['domain']}")
            recs = e["records"]
            if isinstance(recs, dict):
                for k, v in recs.items():
                    if not v:
                        continue
                    print(f"  {k}:")
                    for item in v:
                        print(f"    - {item}")
            else:
                print(f"  {recs}")
            print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
