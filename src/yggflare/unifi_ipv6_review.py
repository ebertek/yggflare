"""Read-only IPv6 DNS and resolver migration assessment."""

import argparse
import http.client
import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor

from cloudflare_api import CloudflareError
from unifi_api import MAX_ROWS, all_rows, get_network, hostname, row_id
from unifi_dns import CANONICAL_TAG
from unifi_dns_verify import MAX_QUERIES, WORKERS, query
from unifi_reconcile_plan import load_live, policy_fingerprint

MAX_NETWORKS = 32
MAX_RA_BYTES = 65536
MAX_ROUTERS = 8
MAX_RESOLVERS = 8


def ipv6(value):
    if not isinstance(value, str) or "%" in value:
        return None
    try:
        address = ipaddress.IPv6Address(value)
    except ValueError:
        return None
    if address.is_multicast or address.is_unspecified or address.is_loopback:
        return None
    if address.ipv4_mapped is not None:
        return None
    return address


def scopes(environ):
    raw = environ.get("YGGFLARE_DISCOVERY_IPV6_CIDRS", "").strip()
    if not raw:
        return []
    parts = raw.split(",")
    if len(parts) > 32:
        raise ValueError("Too many IPv6 prefixes")
    result = [ipaddress.IPv6Network(part.strip()) for part in parts]
    if any(
        scope.prefixlen < 64
        or ipv6(str(scope.network_address)) is None
        or scope.is_link_local
        for scope in result
    ):
        raise ValueError("Invalid IPv6 discovery scope")
    return result


def compare(records, policies, zone, prefixes, gateway, request=query):
    """Verify exact AAAA sets and one canonical PTR per scoped address."""
    if len(records) > MAX_ROWS or len(policies) > MAX_ROWS:
        raise ValueError("IPv6 DNS evidence exceeds limit")
    groups, aliases, local = defaultdict(list), defaultdict(set), defaultdict(list)
    forwarders = set()
    for record in records:
        name = hostname(record.get("name"))
        if name and (name == zone or name.endswith("." + zone)):
            if record.get("type") in {"AAAA", "CNAME"}:
                groups[name].append(record)
            if record.get("type") == "AAAA":
                address = ipv6(record.get("content"))
                if address:
                    aliases[address].add(name)
    for policy in policies:
        raw = policy.get("domain")
        name = hostname(raw)
        if name:
            local[name].append(policy)
            if policy.get("type") == "FORWARD_DOMAIN":
                forwarders.add(name)
        elif isinstance(raw, str) and raw.startswith("*."):
            suffix = hostname(raw[2:])
            if suffix:
                forwarders.add(suffix)
    rows, checks, eligible, tagged = [], [], {}, defaultdict(set)
    for name, entries in sorted(groups.items()):
        aaaa = [item for item in entries if item.get("type") == "AAAA"]
        if not aaaa:
            continue
        addresses = [ipv6(item.get("content")) for item in aaaa]
        expected = sorted({str(address) for address in addresses if address})
        row = {"hostname": name, "addresses": expected, "status": "candidate"}
        if (
            len(aaaa) != len(entries)
            or any(item.get("proxied") is not False for item in aaaa)
            or None in addresses
            or len(expected) != len(addresses)
        ):
            row["status"] = "ambiguous_or_ineligible"
        elif not all(
            any(address in prefix for prefix in prefixes) for address in addresses
        ):
            row["status"] = "outside_configured_scope"
        else:
            eligible[name] = set(addresses)
            for item, address in zip(aaaa, addresses, strict=True):
                if CANONICAL_TAG in (item.get("tags") or []):
                    tagged[address].add(name)
            checks.append(("AAAA", name + ".", expected))
        configured = [
            policy for policy in local[name] if policy.get("type") == "AAAA_RECORD"
        ]
        configured_addresses = [
            ipv6(policy.get("ipv6Address")) for policy in configured
        ]
        if any(name == suffix or name.endswith("." + suffix) for suffix in forwarders):
            policy_status = "forwarding_or_wildcard"
        elif any(
            policy.get("type") not in {"A_RECORD", "AAAA_RECORD"}
            for policy in local[name]
        ):
            policy_status = "conflict"
        elif not configured:
            policy_status = "absent"
        elif (
            any(policy.get("enabled") is not True for policy in configured)
            or None in configured_addresses
            or sorted(str(value) for value in configured_addresses) != expected
        ):
            policy_status = "conflict"
        else:
            policy_status = "matched"
        row["policy_status"] = policy_status
        rows.append(row)
    for address, names in sorted(aliases.items()):
        candidates = {name for name in names if address in eligible.get(name, set())}
        if not candidates:
            continue
        canonical = None
        if candidates == names:
            if len(names) == 1:
                canonical = next(iter(names))
            elif len(tagged[address]) == 1:
                canonical = next(iter(tagged[address]))
        checks.append(
            (
                "PTR",
                address.reverse_pointer + ".",
                [canonical + "."] if canonical else None,
            )
        )
    if len(checks) > MAX_QUERIES:
        raise ValueError("IPv6 DNS query limit exceeded")

    def observe(spec):
        kind, name, expected = spec
        status, answers = request(gateway, name, kind)
        if status == "answered":
            if expected is None:
                status = "ambiguous_expectation"
            else:
                status = "matched" if sorted(answers) == expected else "mismatch"
        return {
            "type": kind,
            "name": name,
            "expected": expected,
            "answers": answers,
            "status": status,
        }

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        replies = list(pool.map(observe, checks))
    return {
        "records": rows,
        "replies": replies,
        "counts": dict(sorted(Counter(row["status"] for row in replies).items())),
        "record_counts": dict(sorted(Counter(row["status"] for row in rows).items())),
    }


def network_settings(detail):
    """Project only documented IPv6 configuration, never the raw response."""
    result = {
        "status": "not_reported",
        "interface_type": None,
        "slaac_enabled": None,
        "dhcpv6_configured": None,
        "ra_priority": None,
        "dns_selection": "unknown",
        "dns_overrides": [],
        "dhcpv6_dns_delivery": "not_observed",
    }
    config = detail.get("ipv6Configuration")
    if config is None:
        return result
    if not isinstance(config, dict):
        raise ValueError("Invalid IPv6 network configuration")
    result["status"] = "reported"
    mode = config.get("interfaceType")
    if mode in ("STATIC", "PREFIX_DELEGATION"):
        result["interface_type"] = mode
    assignment = config.get("clientAddressAssignment")
    if isinstance(assignment, dict):
        slaac = assignment.get("slaacEnabled")
        if type(slaac) is bool:
            result["slaac_enabled"] = slaac
        if "dhcpConfiguration" in assignment:
            dhcp = assignment["dhcpConfiguration"]
            if dhcp is None or isinstance(dhcp, dict):
                result["dhcpv6_configured"] = dhcp is not None
    ra = config.get("routerAdvertisement")
    if isinstance(ra, dict) and ra.get("priority") in ("LOW", "MEDIUM", "HIGH"):
        result["ra_priority"] = ra["priority"]
    if "dnsServerIpAddressesOverride" in config:
        raw = config["dnsServerIpAddressesOverride"]
        if raw is None or raw == []:
            result["dns_selection"] = "automatic"
        elif isinstance(raw, list) and 1 <= len(raw) <= 4:
            addresses = [ipv6(value) for value in raw]
            if None not in addresses:
                result["dns_selection"] = "explicit"
                result["dns_overrides"] = sorted({str(value) for value in addresses})
    return result


def networks(live, fetch=get_network):
    rows = all_rows(live.config, live.key, "networks", live.site)
    if len(rows) > MAX_NETWORKS:
        raise ValueError("Too many networks for IPv6 detail assessment")
    results = []
    for row in rows:
        identifier = row_id(row["id"])
        vlan = row.get("vlanId")
        result = {
            "network_id": identifier,
            "vlan_id": vlan if type(vlan) is int and 0 <= vlan <= 4094 else None,
        }
        try:
            detail = fetch(live.config, live.key, live.site, identifier)
            if not isinstance(detail, dict) or row_id(detail.get("id")) != identifier:
                raise ValueError("Network identity mismatch")
            result.update(network_settings(detail))
        except (OSError, ValueError, TypeError, http.client.HTTPException):
            result.update(network_settings({}))
            result["status"] = "unavailable"
        results.append(result)
    return results


def parse_ra(raw, prefixes):
    """Keep numeric link-local router identity and all valid RDNSS observations."""
    if len(raw.encode("utf-8")) > MAX_RA_BYTES:
        raise ValueError("Oversized RA sample")
    rows, pending, servers = [], [], []
    flags = {}
    for line in raw.splitlines():
        line = line.strip()
        if line.lower().startswith("from "):
            parts = line[5:].split()
            router = ipv6(parts[0].split("%", 1)[0]) if parts else None
            if router and router.is_link_local:
                if len(rows) >= MAX_ROUTERS:
                    raise ValueError("Too many RA samples")
                rows.append(
                    {
                        "router": str(router),
                        "managed": flags.get("managed"),
                        "other": flags.get("other"),
                        "rdnss": servers + pending,
                    }
                )
            flags, pending, servers = {}, [], []
            continue
        if ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        key = key.lower()
        if key == "recursive dns server":
            address = ipv6(value.split()[0]) if value.split() else None
            if address:
                if len(servers) + len(pending) >= MAX_RESOLVERS:
                    raise ValueError("Too many advertised resolvers")
                scope = (
                    "link_local"
                    if address.is_link_local
                    else (
                        "configured"
                        if any(address in prefix for prefix in prefixes)
                        else "outside_scope"
                    )
                )
                pending.append(
                    {"address": str(address), "scope": scope, "lifetime_seconds": None}
                )
        elif key in ("dns server lifetime", "dns servers lifetime"):
            match = re.match(r"^([0-9]{1,10})\b", value)
            if match and int(match.group(1)) <= 2**32 - 1:
                for item in pending:
                    item["lifetime_seconds"] = int(match.group(1))
            servers.extend(pending)
            pending = []
        elif key in ("stateful address conf.", "stateful other conf."):
            if value.lower() in ("yes", "no"):
                flag = "managed" if key == "stateful address conf." else "other"
                flags[flag] = value.lower() == "yes"
    return rows


def sample_ra(environ, prefixes, execute=subprocess.run):
    if environ.get("YGGFLARE_DISCOVERY_RA", "false") != "true":
        return {"status": "disabled", "interfaces": []}
    interfaces = [
        item.strip()
        for item in environ.get("YGGFLARE_DISCOVERY_INTERFACES", "").split(",")
    ]
    if (
        not prefixes
        or not 1 <= len(interfaces) <= 4
        or len(set(interfaces)) != len(interfaces)
        or any(
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}", item)
            for item in interfaces
        )
    ):
        raise ValueError("RA requires configured discovery interfaces and IPv6 scope")
    results = []
    for interface in interfaces:
        row = {"interface": interface, "status": "unavailable", "routers": []}
        try:
            with tempfile.TemporaryFile() as output:
                process = execute(
                    ["rdisc6", "-n", "-r", "1", "-w", "750", "ff02::2", interface],
                    stdout=output,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    check=False,
                    env={**environ, "LC_ALL": "C"},
                )
                output.seek(0)
                raw = output.read(MAX_RA_BYTES + 1).decode("utf-8", errors="replace")
            if process.returncode == 2:
                row["status"] = "no_reply"
            elif process.returncode == 0:
                row["routers"] = parse_ra(raw, prefixes)
                row["status"] = "observed" if row["routers"] else "not_observed"
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
        results.append(row)
    return {"status": "sampled", "interfaces": results}


def run():
    live = load_live()
    prefixes = scopes(os.environ)
    policies = all_rows(live.config, live.key, "dns", live.site)
    if policy_fingerprint(policies) != live.policies_id:
        raise ValueError("UniFi policies changed during IPv6 review")
    result = {
        "mode": "read_only_ipv6_review",
        "source_zone": live.comparison["source_zone"],
        "scopes": [str(prefix) for prefix in prefixes],
        "dns_transport": live.config[0],
        "dns": compare(
            live.records,
            policies,
            live.comparison["source_zone"],
            prefixes,
            live.config[0],
        ),
        "networks": networks(live),
        "router_advertisements": sample_ra(os.environ, prefixes),
        "dhcpv6_dns_delivery": "not_observed",
        "caveat": "Configuration and sampled observations only; no client resolver or DHCPv6 delivery proof.",
    }
    encoded = json.dumps(result)
    if any(secret in encoded for secret in (live.key, live.token) if len(secret) >= 8):
        raise ValueError("IPv6 report contains a credential echo")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    signal.alarm(180)
    try:
        print(json.dumps(run(), indent=2, sort_keys=True))
        return 0
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        CloudflareError,
        http.client.HTTPException,
    ):
        print(
            "IPv6 review unavailable; check configured scope and API access.",
            file=sys.stderr,
        )
        return 2
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    sys.exit(main())
