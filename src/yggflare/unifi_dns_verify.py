"""Explicit read-only verification of address and PTR replies from the UniFi gateway."""

import argparse
import json
import os
import signal
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.reversename
from cloudflare_api import CloudflareError
from cloudflare_credentials import api_token
from unifi_api import hostname, settings
from unifi_dns import cloudflare_records, plan
from yggflare_config import domain, network

MAX_QUERIES = 512
WORKERS = 16
DNS_TIMEOUT = 2


def query(gateway, name, kind):
    request = dns.message.make_query(name, kind)
    try:
        reply, _ = dns.query.udp_with_fallback(request, gateway, timeout=DNS_TIMEOUT)
    except dns.exception.Timeout:
        return "timeout", []
    except OSError:
        return "transport_error", []
    except dns.exception.DNSException:
        return "query_error", []
    code = reply.rcode()
    if code != dns.rcode.NOERROR and reply.answer:
        return "unexpected_answer", []
    if code != dns.rcode.NOERROR:
        return dns.rcode.to_text(code).lower(), []
    question = request.question[0]
    records = set()
    for rrset in reply.answer:
        if rrset.name != question.name or rrset.rdclass != question.rdclass:
            continue
        if rrset.rdtype == question.rdtype:
            records.update(
                (
                    record.address
                    if kind in {"A", "AAAA"}
                    else record.target.to_text().lower()
                )
                for record in rrset
            )
        else:
            return "unexpected_answer", []
    if records:
        return "answered", sorted(records)
    return ("unexpected_answer", []) if reply.answer else ("nodata", [])


def verify(plan_result, gateway, selected="", request=query):
    if selected:
        selected = hostname(selected)
        if not selected:
            raise ValueError("Invalid hostname filter")
    forward = [
        row
        for row in plan_result["rows"]
        if row["status"] in {"candidate", "ambiguous_reverse"}
        and (not selected or row["hostname"] == selected)
    ]
    addresses = {row["address"] for row in forward}
    reverse = [
        row
        for row in plan_result["reverse_expectations"]
        if row["address"] in addresses
    ]
    if not forward or len(forward) + len(reverse) > MAX_QUERIES:
        raise ValueError(
            "Select an eligible exact hostname within the verification limit"
        )
    checks = [("A", row["hostname"] + ".", row["address"]) for row in forward] + [
        (
            "PTR",
            dns.reversename.from_address(row["address"]).to_text(),
            row["canonical_hostname"] + "." if row["canonical_hostname"] else None,
        )
        for row in reverse
    ]

    def check(spec):
        kind, name, expected = spec
        status, answers = request(gateway, name, kind)
        if expected is None and status == "answered":
            status = "ambiguous_expectation"
        elif status == "answered":
            status = "matched" if answers == [expected] else "mismatch"
        return {
            "type": kind,
            "name": name,
            "expected": expected,
            "answers": answers,
            "status": status,
        }

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        rows = list(pool.map(check, checks))
    return {
        "mode": "gateway_dns_verification",
        "source_zone": plan_result["source_zone"],
        "counts": dict(sorted(Counter(row["status"] for row in rows).items())),
        "rows": rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hostname", nargs="?", default="")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    signal.alarm(120)
    try:
        gateway, _, _, _ = settings(os.environ)
        zone = domain("YGGFLARE_INTERNAL_DOMAIN")
        lan = network("YGGFLARE_LAN_CIDR")
        token = api_token()
        desired = plan(cloudflare_records(zone, token), [], zone, lan)
        result = verify(desired, gateway, args.hostname)
        encoded = json.dumps(result, indent=2, sort_keys=True)
        if len(token) >= 8 and token in encoded:
            raise ValueError("DNS verification contains a credential echo")
        if args.json:
            print(encoded)
        else:
            print(json.dumps(result["counts"], sort_keys=True))
            for row in result["rows"]:
                print(f"{row['status']}: {row['type']} {row['name']}")
        return 0 if all(row["status"] == "matched" for row in result["rows"]) else 1
    except (OSError, ValueError, TypeError, CloudflareError):
        print(
            "UniFi DNS verification unavailable; check gateway configuration, Cloudflare access and hostname scope.",
            file=sys.stderr,
        )
        return 2
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    sys.exit(main())
