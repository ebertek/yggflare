"""Read-only internal A retirement evidence; never authorize a mutation."""

import argparse
import ipaddress
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

from cloudflare_api import CloudflareClient, CloudflareError, checked_id
from cloudflare_credentials import api_token
from cloudflare_desired import compose_inventory
from cloudflare_docker_dns import canonical_name, scoped_address
from cloudflare_internal_ownership import (
    STATIC_REGISTRY_FILE,
    detail_fingerprint,
    internal_scope,
    load_registry,
    record_matches,
)
from cloudflare_live_diff import DOCKER_NETWORK
from cloudflare_retained_dns import RETAINED, load_retained_dns
from cloudflare_static_dns import (
    INVENTORY,
    STATIC_NETWORK,
    load_inventory_aliases,
    load_inventory_details,
)
from yggflare_config import cloudflare_settings

MAX_CONTAINERS = 1024
CONTAINER_ID = re.compile(r"[0-9a-f]{64}")


def normalized(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Invalid retirement evidence name")
    return value.lower().rstrip(".")


def mentions(value, name, address):
    """Match literal references, not substrings of unrelated hostnames or IPs."""
    if isinstance(value, dict):
        return any(mentions(item, name, address) for item in value.values())
    if isinstance(value, list):
        return any(mentions(item, name, address) for item in value)
    if not isinstance(value, str):
        return False
    return any(
        re.search(
            r"(?<![a-z0-9_.-])" + re.escape(target) + r"(?![a-z0-9_.-])",
            value.lower().rstrip("."),
        )
        for target in (name, address)
    )


def add_name(names, value, zone):
    if not isinstance(value, str) or "$" in value:
        raise ValueError("Unresolved name in retirement evidence")
    if value:
        name = canonical_name(value, zone)
        if name:
            names.add(name)


def add_address(addresses, value):
    if value:
        addresses.add(str(ipaddress.IPv4Address(value)))


def compose_evidence(root, zone):
    """Keep declarations for stopped, addressless and aliased services."""
    from ruamel.yaml import YAML

    services = compose_inventory(root)
    if not services:
        raise ValueError("Empty Compose retirement inventory")
    names, addresses, references = set(), set(), []
    for service in services:
        for value in (
            service["Name"].rsplit("/", 1)[-1],
            service.get("Hostname", ""),
            service.get("ContainerName", ""),
        ):
            add_name(names, value, zone)
        for value in service.get("IPv4Addresses", []):
            add_address(addresses, value)
    parser = YAML(typ="safe")
    paths = sorted(set(root.rglob("compose.yaml")) | set(root.rglob("compose.yml")))
    for path in paths:
        raw = path.read_text(encoding="utf-8")
        references.append(raw)
        document = parser.load(raw)
        # Includes/extends may introduce declarations outside the snapshot.
        if document.get("include"):
            raise ValueError("Compose includes are not covered by retirement review")
        for config in (document.get("services") or {}).values():
            if config.get("extends"):
                raise ValueError("Compose extends is not covered by retirement review")
            networks = config.get("networks") or {}
            if isinstance(networks, dict):
                for network in networks.values():
                    if not isinstance(network, dict):
                        continue
                    aliases = network.get("aliases", [])
                    if not isinstance(aliases, list):
                        raise ValueError("Invalid Compose aliases")
                    for alias in aliases:
                        add_name(names, alias, zone)
    return names, addresses, references


def runtime_evidence(containers, zone):
    """Use every inspected container, not the creation path's filtered IP map."""
    names, addresses = set(), set()
    for container in containers:
        config = container["Config"]
        settings = container["NetworkSettings"]
        add_name(names, container["Name"].lstrip("/"), zone)
        add_name(names, config["Hostname"], zone)
        labels = config.get("Labels") or {}
        add_name(names, labels.get("com.docker.compose.service", ""), zone)
        networks = settings["Networks"]
        if not isinstance(networks, dict):
            raise ValueError("Incomplete Docker network evidence")
        for network in networks.values():
            add_address(addresses, network.get("IPAddress"))
            add_address(addresses, (network.get("IPAMConfig") or {}).get("IPv4Address"))
            for key in ("Aliases", "DNSNames"):
                aliases = network.get(key) or []
                if not isinstance(aliases, list):
                    raise ValueError("Invalid Docker alias evidence")
                for alias in aliases:
                    add_name(names, alias, zone)
    return names, addresses


def docker_containers():
    """Bound the read and reject inventory changes or partial inspections."""

    def identifiers():
        values = subprocess.check_output(
            ["docker", "ps", "-aq", "--no-trunc"], text=True, timeout=30
        ).split()
        if (
            len(values) > MAX_CONTAINERS
            or len(values) != len(set(values))
            or not all(CONTAINER_ID.fullmatch(value) for value in values)
        ):
            raise ValueError("Invalid Docker retirement inventory")
        return set(values)

    ids = identifiers()
    containers = []
    ordered = sorted(ids)
    for start in range(0, len(ordered), 50):
        batch = ordered[start : start + 50]
        result = json.loads(
            subprocess.check_output(
                ["docker", "inspect", "--type", "container", *batch],
                text=True,
                timeout=30,
            )
        )
        if (
            not isinstance(result, list)
            or len(result) != len(batch)
            or {row["Id"] for row in result} != set(batch)
        ):
            raise ValueError("Incomplete Docker inspection")
        containers.extend(result)
    if identifiers() != ids:
        raise ValueError("Docker inventory changed during retirement review")
    return containers


def checked_records(records):
    """Retain all records and reject malformed or duplicate identities."""
    if not isinstance(records, list):
        raise ValueError("Incomplete Cloudflare DNS evidence")
    seen = set()
    for row in records:
        identifier = checked_id(row["id"], "DNS record ID")
        normalized(row["name"])
        if identifier in seen or not isinstance(row["type"], str):
            raise ValueError("Invalid Cloudflare DNS evidence")
        seen.add(identifier)
        if row["type"] == "A":
            ipaddress.IPv4Address(row["content"])
    return records


def protected(name, address, evidence, records, identifier):
    """Return blockers using declarations and visible DNS dependencies."""
    declared_names, declared_addresses, references = evidence["compose"]
    runtime_names, runtime_addresses = evidence["runtime"]
    if name in declared_names or address in declared_addresses:
        return "still_declared"
    if name in runtime_names or address in runtime_addresses:
        return "runtime_present"
    if name in evidence["private"] or address in evidence["private"]:
        return "private_protected"
    if mentions(references, name, address) or mentions(
        evidence["retained"], name, address
    ):
        return "dependency_protected"
    for row in records:
        if row["id"] == identifier:
            continue
        other = normalized(row["name"])
        if other == name:
            return "record_conflict"
        if other.startswith("*.") and name.endswith(other[1:]):
            return "wildcard_protected"
        if row["type"] == "A" and row["content"] == address:
            return "shared_address"
        if mentions(row.get("content"), name, address) or mentions(
            row.get("data"), name, address
        ):
            return "dependency_protected"
    return None


def review(client, bound, owned, records, external, evidence, hostname=None):
    """Classify owned identities and unmanaged leftovers without granting approval."""
    records = checked_records(records)
    external = checked_records(external)
    by_id = {row["id"]: row for row in records}
    rows = []
    for identifier, (category, entry) in sorted(owned.items()):
        name, address = entry["hostname"], entry["address"]
        if hostname is not None and name != hostname:
            continue
        action = {"hostname": name, "content": address}
        current = by_id.get(identifier)
        status = protected(name, address, evidence, records, identifier)
        if status is None:
            status = protected(name, address, evidence, external, None)
        if status is None:
            if current is None:
                status = "missing_record"
            elif not record_matches(current, identifier, action):
                status = "identity_changed"
            else:
                detail = client.get(f"/zones/{bound['zone']}/dns_records/{identifier}")[
                    "result"
                ]
                if (
                    not record_matches(detail, identifier, action)
                    or detail_fingerprint(detail) != entry["fingerprint"]
                    or any(
                        current.get(field) != detail.get(field)
                        for field in (
                            "ttl",
                            "comment",
                            "tags",
                            "settings",
                            "modified_on",
                        )
                    )
                ):
                    status = "identity_changed"
                else:
                    status = "candidate_review_only"
        rows.append(
            {
                "hostname": name,
                "address": address,
                "record_id": identifier,
                "ownership": category,
                "status": status,
            }
        )
    for row in records:
        identifier = row["id"]
        name = normalized(row["name"])
        if identifier in owned or (hostname is not None and name != hostname):
            continue
        if row["type"] != "A" or row.get("proxied") is not False:
            continue
        address = row["content"]
        if canonical_name(name, bound["domain"]) != name or not any(
            scoped_address(address, network)
            for network in (DOCKER_NETWORK, STATIC_NETWORK)
        ):
            continue
        status = protected(name, address, evidence, records, identifier)
        if status is None:
            status = protected(name, address, evidence, external, None)
        if hostname is None and status in {
            "still_declared",
            "runtime_present",
            "private_protected",
        }:
            continue
        rows.append(
            {
                "hostname": name,
                "address": address,
                "record_id": identifier,
                "ownership": "unmanaged",
                "status": status or "unmanaged",
            }
        )
    rows.sort(key=lambda row: (row["hostname"], row["record_id"]))
    return {
        "mode": "read_only_retirement_review",
        "hostname": hostname,
        "counts": dict(sorted(Counter(row["status"] for row in rows).items())),
        "rows": rows,
        "matching_rows": bool(rows),
        "deletion_authorized": False,
    }


def collect(client, root, data, settings, hostname=None):
    """Resolve both configured zones and validate the two ownership scopes."""
    account = checked_id(settings["account_id"], "account ID")
    domain = settings["internal_zone"]
    if hostname is not None and canonical_name(hostname, domain) != hostname:
        raise ValueError("Retirement selector must be a canonical internal hostname")
    zone = checked_id(client.zone_id(domain, account), "internal zone ID")
    external_zone = checked_id(
        client.zone_id(settings["external_zone"], account), "external zone ID"
    )
    if (
        (settings.get("internal_zone_id") and settings["internal_zone_id"] != zone)
        or (
            settings.get("external_zone_id")
            and settings["external_zone_id"] != external_zone
        )
        or zone == external_zone
    ):
        raise ValueError("Configured DNS zone identity changed")
    bound = internal_scope(account, zone, domain, DOCKER_NETWORK)
    docker = load_registry(data, bound)["records"]
    static = load_registry(
        data,
        internal_scope(account, zone, domain, STATIC_NETWORK),
        filename=STATIC_REGISTRY_FILE,
    )["records"]
    if docker.keys() & static.keys():
        raise ValueError("Overlapping internal DNS ownership registries")
    owned = {key: ("docker", row) for key, row in docker.items()}
    owned.update({key: ("static", row) for key, row in static.items()})
    if len({entry["hostname"] for _, entry in owned.values()}) != len(owned) or len(
        {entry["address"] for _, entry in owned.values()}
    ) != len(owned):
        raise ValueError("Conflicting internal DNS ownership registries")
    hosts, companions = load_inventory_details(root / INVENTORY, required=True)
    retained = load_retained_dns(root / RETAINED)
    evidence = {
        "compose": compose_evidence(root, domain),
        "runtime": runtime_evidence(docker_containers(), domain),
        "private": (
            set(hosts)
            | set(hosts.values())
            | set(load_inventory_aliases(root / INVENTORY))
            | {address for values in companions.values() for address in values}
        ),
        "retained": retained,
    }
    # Keep retained exact names/addresses protected independently of content.
    evidence["private"].update(row["hostname"] for row in retained)
    evidence["private"].update(row["content"] for row in retained if row["type"] == "A")
    return review(
        client,
        bound,
        owned,
        client.list_dns(zone),
        client.list_dns(external_zone),
        evidence,
        hostname,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--hostname")
    args = parser.parse_args()
    try:
        report = collect(
            CloudflareClient(api_token()),
            args.root,
            Path("/data"),
            cloudflare_settings(),
            args.hostname,
        )
    except (
        CloudflareError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        RuntimeError,
        subprocess.SubprocessError,
    ):
        # Docker/Compose errors and API payloads may contain private data.
        print(
            "ERROR: Internal DNS retirement evidence unavailable or invalid.",
            file=sys.stderr,
        )
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
