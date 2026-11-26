"""Explicit GET-only UniFi DNS migration preflight; never a write plan."""

import argparse
import http.client
import ipaddress
import json
import os
import signal
import sys
from collections import Counter, defaultdict

from cloudflare_api import CloudflareClient, CloudflareError, checked_id
from cloudflare_credentials import api_token
from integration_inventory import credentials
from unifi_api import MAX_ROWS, all_rows, get_page, hostname, select_site, settings
from yggflare_config import domain, network

CANONICAL_TAG = "yggflare:canonical"
RFC1918 = tuple(
    ipaddress.IPv4Network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def collect(config, key, fetch=get_page):
    site = select_site(config, key, fetch)
    return all_rows(config, key, "dns", site, fetch)


def ipv4(value):
    if not isinstance(value, str):
        return None
    try:
        return ipaddress.IPv4Address(value)
    except ValueError:
        return None


def is_rfc1918(address):
    """RFC 1918 only, not the broader ipaddress.is_private classification."""
    return isinstance(address, ipaddress.IPv4Address) and any(
        address in block for block in RFC1918
    )


def reverse_expectations(aliases, eligible, tagged):
    """Select one eligible Cloudflare owner, with an explicit tag for shared IPs."""
    results = []
    for ip, names in sorted(aliases.items()):
        if not is_rfc1918(ip):
            continue
        candidates = names & eligible
        marked = candidates & tagged
        canonical = None
        if len(names) == 1 and candidates:
            canonical = next(iter(candidates))
            reason = "unique"
        elif len(marked) == 1 and candidates == names:
            canonical = next(iter(marked))
            reason = "cloudflare_tag"
        elif len(marked) > 1:
            reason = "conflicting_tags"
        elif candidates != names:
            reason = "ineligible_alias"
        else:
            reason = "ambiguous"
        results.append(
            {
                "address": str(ip),
                "hostnames": sorted(names),
                "canonical_hostname": canonical,
                "selection": reason,
            }
        )
    return results


def plan(records, policies, zone, lan):
    """Report candidates and conflicts; never claim ownership or authorize writes."""
    if len(records) > MAX_ROWS or len(policies) > MAX_ROWS:
        raise ValueError("DNS inventory exceeds preflight limit")
    groups, aliases, local = defaultdict(list), defaultdict(set), defaultdict(list)
    local_ips, forwarders = defaultdict(set), set()
    excluded_a_records = 0
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("Invalid Cloudflare record")
        name = hostname(record.get("name"))
        if not name or not (name == zone or name.endswith("." + zone)):
            if record.get("type") == "A":
                excluded_a_records += 1
            continue
        if record.get("type") == "A":
            groups[name].append(record)
            address = ipv4(record.get("content"))
            if address is not None:
                aliases[address].add(name)
        elif record.get("type") in ("AAAA", "CNAME"):
            groups[name].append(record)
    for policy in policies:
        if not isinstance(policy, dict):
            raise ValueError("Invalid UniFi DNS policy")
        kind = policy.get("type")
        raw_name = policy.get("domain")
        if not isinstance(kind, str) or type(policy.get("enabled")) is not bool:
            raise ValueError("Invalid UniFi DNS policy")
        name = hostname(raw_name)
        if kind == "A_RECORD":
            address = ipv4(policy.get("ipv4Address"))
            if not name or address is None:
                raise ValueError("Invalid UniFi A policy")
            local_ips[address].add(name)
        if name:
            local[name].append(policy)
            if kind == "FORWARD_DOMAIN":
                forwarders.add(name)
        elif isinstance(raw_name, str) and raw_name.startswith("*."):
            suffix = hostname(raw_name[2:])
            if not suffix:
                raise ValueError("Invalid UniFi wildcard policy")
            forwarders.add(suffix)
        else:
            raise ValueError("Unsupported UniFi DNS policy identity")

    rows = []
    eligible, tagged = set(), set()
    for name, entries in sorted(groups.items()):
        a_records = [r for r in entries if r.get("type") == "A"]
        if not a_records:
            continue
        addresses = sorted(
            {
                parsed
                for r in a_records
                if (parsed := ipv4(r.get("content"))) is not None
            }
        )
        address = addresses[0] if len(a_records) == 1 and addresses else None
        row = {
            "hostname": name,
            "address": str(address) if address is not None else None,
            "addresses": [str(value) for value in addresses],
            "rfc1918": is_rfc1918(address) if address is not None else None,
            "in_configured_lan": address in lan if address is not None else None,
            "status": "candidate",
        }
        if len(a_records) != 1:
            row["status"] = "ambiguous_forward"
        elif a_records[0].get("proxied") is not False:
            row["status"] = "proxied_or_unknown"
        elif not is_rfc1918(address):
            row["status"] = "out_of_scope"
        elif address in (lan.network_address, lan.broadcast_address):
            row["status"] = "configured_lan_boundary"
        elif len(name) > 127:
            row["status"] = "unsupported_name"
        elif len(entries) != 1:
            row["status"] = "additional_address_or_alias"
        else:
            eligible.add(name)
            tags = a_records[0].get("tags")
            if isinstance(tags, list) and CANONICAL_TAG in tags:
                tagged.add(name)
        if name not in eligible:
            rows.append(row)
            continue
        if len(aliases[address]) != 1 or local_ips[address] - {name}:
            row["status"] = "ambiguous_reverse"
        elif any(
            name == suffix or name.endswith("." + suffix) for suffix in forwarders
        ):
            row["status"] = "forwarding_or_wildcard_conflict"
        elif local[name]:
            matches = local[name]
            exact = (
                len(matches) == 1
                and matches[0].get("type") == "A_RECORD"
                and matches[0]["enabled"]
                and ipv4(matches[0].get("ipv4Address")) == address
            )
            row["status"] = "matched" if exact else "local_conflict"
        rows.append(row)
    return {
        "mode": "read_only_preflight",
        "source_zone": zone,
        "configured_lan": str(lan),
        "address_scope": "rfc1918",
        "excluded_a_records": excluded_a_records,
        "counts": dict(sorted(Counter(row["status"] for row in rows).items())),
        "rows": rows,
        "reverse_expectations": reverse_expectations(aliases, eligible, tagged),
        "caveat": (
            "Configuration comparison only; PTR answers, ownership and "
            "complete upstream visibility are not verified. Private addresses "
            "outside the configured LAN require explicit scope review before writes."
        ),
    }


def cloudflare_records(zone, token):
    client = CloudflareClient(token)
    account = checked_id(os.environ.get("CLOUDFLARE_ACCOUNT_ID"), "account ID")
    zone_id = client.zone_id(zone, account)
    configured = os.environ.get("CLOUDFLARE_INTERNAL_ZONE_ID")
    if configured and checked_id(configured) != zone_id:
        raise ValueError("Configured internal zone does not match Cloudflare")
    return client.list_dns(zone_id)


def run():
    config = settings(os.environ)
    key = credentials("unifi")[0]
    zone = domain("YGGFLARE_INTERNAL_DOMAIN")
    lan = network("YGGFLARE_LAN_CIDR")
    token = api_token()
    result = plan(cloudflare_records(zone, token), collect(config, key), zone, lan)
    encoded = json.dumps(result)
    if any(secret in encoded for secret in (key, token) if len(secret) >= 8):
        raise ValueError("DNS preflight contains a credential echo")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    signal.alarm(90)
    try:
        result = run()
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print("UniFi DNS — READ ONLY")
            print(json.dumps(result["counts"], sort_keys=True))
            for row in result["rows"]:
                addresses = ", ".join(row["addresses"]) or "-"
                outside = (
                    " [outside configured LAN]"
                    if row["rfc1918"] and not row["in_configured_lan"]
                    else ""
                )
                print(f"{row['status']}: {row['hostname']} {addresses}{outside}")
            print(f"Excluded A records: {result['excluded_a_records']}")
            print(result["caveat"])
        return 0
    except (
        OSError,
        ValueError,
        TypeError,
        AttributeError,
        RecursionError,
        CloudflareError,
        http.client.HTTPException,
    ):
        print(
            "UniFi DNS preflight failed; check configuration, TLS, credentials and API support.",
            file=sys.stderr,
        )
        return 2
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    sys.exit(main())
