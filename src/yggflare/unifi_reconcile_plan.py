"""Read-only create preview for Cloudflare-to-UniFi DNS reconciliation."""

import argparse
import hashlib
import http.client
import ipaddress
import json
import os
import signal
import sys
from collections import Counter

from cloudflare_api import CloudflareError
from cloudflare_credentials import api_token
from integration_inventory import credentials
from unifi_api import all_rows, select_site, settings
from unifi_dns import cloudflare_records, plan
from unifi_dns_verify import verify
from yggflare_config import domain, network

SCHEMA_VERSION = 1
MISSING = {"nxdomain", "nodata"}


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def fingerprint(value):
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def preview(comparison, gateway, input_fingerprint, observe=verify):
    """Propose absent policies only after exact forward and reverse checks."""
    reverse_by_address = {
        row["address"]: row for row in comparison["reverse_expectations"]
    }
    rows, eligible = [], []
    for item in comparison["rows"]:
        choice = reverse_by_address.get(item["address"], {})
        status = item["status"]
        if status == "candidate":
            if item["in_configured_lan"] is not True:
                status = "outside_configured_lan"
            elif (
                choice.get("selection") != "unique"
                or choice.get("canonical_hostname") != item["hostname"]
            ):
                status = "unresolved_reverse"
            else:
                eligible.append(item)
                continue
        rows.append({"hostname": item["hostname"], "status": status})

    operations, replies = [], []
    if eligible:
        replies = observe({**comparison, "rows": eligible}, gateway)["rows"]
        observed = {(row["type"], row["name"]): row for row in replies}
        for item in eligible:
            hostname, address = item["hostname"], item["address"]
            forward = observed[("A", hostname + ".")]
            reverse = observed[
                ("PTR", ipaddress.ip_address(address).reverse_pointer + ".")
            ]
            if forward["status"] not in MISSING | {"matched"}:
                status = "forward_review"
            elif reverse["status"] in MISSING:
                status = "proposed_create"
                operations.append(
                    {
                        "operation": "create",
                        "type": "A_RECORD",
                        "domain": hostname,
                        "ipv4Address": address,
                        "enabled": True,
                    }
                )
            elif reverse["status"] == "matched" and forward["status"] == "matched":
                status = "already_resolves"
            else:
                status = "reverse_review"
            rows.append(
                {
                    "hostname": hostname,
                    "address": address,
                    "status": status,
                    "forward": forward["status"],
                    "reverse": reverse["status"],
                }
            )
    rows.sort(key=lambda row: row["hostname"])
    report = {
        "schema_version": SCHEMA_VERSION,
        "mode": "read_only_reconcile_plan",
        "source_zone": comparison["source_zone"],
        "configured_lan": comparison["configured_lan"],
        "excluded_a_records": comparison["excluded_a_records"],
        "counts": dict(sorted(Counter(row["status"] for row in rows).items())),
        "operations": operations,
        "rows": rows,
    }
    report["fingerprint"] = fingerprint(
        {"inputs": input_fingerprint, "replies": replies, "report": report}
    )
    return report


def run():
    config = settings(os.environ)
    zone = domain("YGGFLARE_INTERNAL_DOMAIN")
    lan = network("YGGFLARE_LAN_CIDR")
    token = api_token()
    key = credentials("unifi")[0]
    records = cloudflare_records(zone, token)
    site = select_site(config, key)
    policies = all_rows(config, key, "dns", site)
    comparison = plan(records, policies, zone, lan)
    inputs = fingerprint(
        {
            "gateway": config,
            "site": site,
            "cloudflare_account": os.environ.get("CLOUDFLARE_ACCOUNT_ID"),
            "records": sorted(map(canonical_json, records)),
            "policies": sorted(map(canonical_json, policies)),
        }
    )
    report = preview(comparison, config[0], inputs)
    encoded = json.dumps(report, indent=2, sort_keys=True)
    if any(secret in encoded for secret in (key, token) if len(secret) >= 8):
        raise ValueError("Reconciliation preview contains a credential echo")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    signal.alarm(120)
    try:
        report = run()
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print(f"UniFi DNS create preview ({report['fingerprint']})")
            print(json.dumps(report["counts"], sort_keys=True))
            for operation in report["operations"]:
                print(f"create {operation['domain']} {operation['ipv4Address']}")
        return 0
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        RecursionError,
        http.client.HTTPException,
        CloudflareError,
    ):
        print(
            "UniFi DNS create preview unavailable; check Cloudflare, UniFi and gateway DNS access.",
            file=sys.stderr,
        )
        return 2
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    sys.exit(main())
