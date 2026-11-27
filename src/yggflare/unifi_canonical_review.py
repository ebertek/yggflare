"""Read-only review of canonical PTR names for shared internal IPv4 addresses."""

import argparse
import http.client
import ipaddress
import json
import signal
import sys
from collections import Counter

from cloudflare_api import CloudflareError
from unifi_apply import automatic_targets
from unifi_dns import CANONICAL_TAG
from unifi_dns_verify import verify
from unifi_reconcile_plan import load_live


def review(comparison, gateway, declared, observe=verify):
    """Suggest tags from exact declarations; never authorize policy changes."""
    lan = ipaddress.IPv4Network(comparison["configured_lan"])
    shared = [
        row for row in comparison["reverse_expectations"] if len(row["hostnames"]) > 1
    ]
    addresses = {
        row["address"]
        for row in shared
        if ipaddress.IPv4Address(row["address"]) in lan
    }
    by_name = {row["hostname"]: row for row in comparison["rows"]}
    eligible = [
        row
        for row in comparison["rows"]
        if row["address"] in addresses and row["status"] == "ambiguous_reverse"
    ]
    observed = {}
    if eligible:
        result = observe({**comparison, "rows": eligible}, gateway)
        observed = {(row["type"], row["name"]): row for row in result["rows"]}

    rows = []
    for group in shared:
        address = group["address"]
        names = group["hostnames"]
        exact = sorted(name for name in names if (name, address) in declared)
        selected = group["canonical_hostname"]
        selection = group["selection"]
        suggestion = None
        if address not in addresses:
            decision = "outside_configured_lan"
        elif selection == "cloudflare_tag":
            decision = "explicit_canonical"
        elif selection != "ambiguous":
            decision = selection
        elif len(exact) == 1:
            decision = "suggest_tag"
            suggestion = exact[0]
        else:
            decision = "manual_selection"

        reverse_name = ipaddress.IPv4Address(address).reverse_pointer + "."
        ptr = observed.get(("PTR", reverse_name))
        rows.append(
            {
                "address": address,
                "hostnames": [
                    {
                        "hostname": name,
                        "declared": name in exact,
                        "cloudflare_status": by_name[name]["status"],
                        "local_policy_status": by_name[name].get("local_policy_status"),
                        "forward": observed.get(("A", name + ".")),
                    }
                    for name in names
                ],
                "selection": selection,
                "canonical_hostname": selected,
                "suggested_hostname": suggestion,
                "decision": decision,
                "reverse": ptr,
            }
        )
    return {
        "mode": "read_only_canonical_review",
        "source_zone": comparison["source_zone"],
        "configured_lan": comparison["configured_lan"],
        "canonical_tag": CANONICAL_TAG,
        "counts": dict(sorted(Counter(row["decision"] for row in rows).items())),
        "rows": rows,
        "caveat": (
            "Suggestions require review; no tags or DNS policies are changed. "
            "Missing observations are not proof of absence."
        ),
    }


def run():
    live = load_live()
    declared = automatic_targets(live.comparison["source_zone"])
    result = review(live.comparison, live.config[0], declared)
    encoded = json.dumps(result)
    if any(secret in encoded for secret in (live.key, live.token) if len(secret) >= 8):
        raise ValueError("Canonical review contains a credential echo")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    signal.alarm(120)
    try:
        result = run()
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print("UniFi canonical PTR review — READ ONLY")
            print(json.dumps(result["counts"], sort_keys=True))
            for row in result["rows"]:
                name = row["canonical_hostname"] or row["suggested_hostname"] or "-"
                print(f"{row['address']}: {row['decision']} {name}")
                for item in row["hostnames"]:
                    forward = item["forward"]
                    status = forward["status"] if forward else "not_checked"
                    print(
                        f"  {item['hostname']}: "
                        f"A={status}; policy={item['local_policy_status'] or '-'}"
                    )
                reverse = row["reverse"]
                print(f"  PTR={reverse['status'] if reverse else 'not_checked'}")
            print(result["caveat"])
        return 0
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        RecursionError,
        CloudflareError,
        http.client.HTTPException,
    ):
        print(
            "Canonical PTR review unavailable; check DNS, API and inventory access.",
            file=sys.stderr,
        )
        return 2
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    sys.exit(main())
