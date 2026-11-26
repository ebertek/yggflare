"""Review-only internal A-record coverage from explicit Docker address evidence."""

import ipaddress
import re
from collections import Counter, defaultdict

LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def canonical_name(value, zone):
    if not isinstance(value, str):
        return None
    name = value.lower().rstrip(".")
    if "." not in name:
        name += "." + zone
    if (
        len(name) > 253
        or not name.endswith("." + zone)
        or not all(LABEL.fullmatch(label) for label in name.split("."))
    ):
        return None
    return name


def scoped_address(value, network):
    if not isinstance(value, str):
        return None
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError:
        return None
    if address not in network or address in (
        network.network_address,
        network.broadcast_address,
    ):
        return None
    return str(address)


def audit_docker_dns(services, running, records, zone, network):
    """Compare explicit Compose and live Docker evidence, never propose writes."""
    counts = {"hosts": 0, "matched": 0, "drift": 0}
    if records is None or running is None:
        return {"enabled": False, "counts": counts, "findings": []}
    expected = defaultdict(lambda: defaultdict(set))
    declared_names = defaultdict(set)
    for service in services:
        name = (
            service.get("ContainerName") or service.get("Name", "").rsplit("/", 1)[-1]
        )
        host = canonical_name(service.get("Hostname") or name, zone)
        if not host:
            continue
        if isinstance(name, str):
            declared_names[name].add(host)
        for value in service.get("IPv4Addresses", []):
            address = scoped_address(value, network)
            if address:
                expected[host]["compose"].add(address)
    for name, value in running.items():
        address = scoped_address(value, network)
        if not address:
            continue
        hosts = declared_names.get(name, set())
        if not hosts:
            hosts = {canonical_name(name, zone)}
        for host in hosts:
            if host:
                expected[host]["runtime"].add(address)

    index = defaultdict(list)
    for item in records:
        name = item.get("name")
        if isinstance(name, str) and item.get("type") in ("A", "CNAME"):
            index[name.lower().rstrip(".")].append(item)

    findings = []
    for host, sources in sorted(expected.items()):
        addresses = set().union(*sources.values())
        category = "+".join(sorted(sources))
        row = {"hostname": host, "category": category}
        matches = index[host]
        a_records = [item for item in matches if item["type"] == "A"]
        if len(addresses) == 1:
            row["expected"] = next(iter(addresses))
        if not a_records:
            row["status"] = "missing_a" if not matches else "cname_conflict"
        elif len(addresses) != 1:
            row["status"] = "ambiguous_address"
        elif len(a_records) != 1 or len(matches) != 1:
            row["status"] = "ambiguous_a"
        elif a_records[0].get("proxied") is not False:
            row["status"] = "proxied_or_unknown"
        elif a_records[0].get("content") != row["expected"]:
            row["status"] = "mismatch"
            actual = a_records[0].get("content")
            try:
                if isinstance(actual, str):
                    row["actual"] = str(ipaddress.IPv4Address(actual))
            except ValueError:
                pass
        else:
            counts["matched"] += 1
            continue
        findings.append(row)
    counts["hosts"] = len(expected)
    counts["drift"] = len(findings)
    counts.update(Counter(row["status"] for row in findings))
    return {"enabled": True, "counts": counts, "findings": findings}


def print_docker_dns_summary(report):
    """Show review findings separately from executable reconciliation actions."""
    section = report.get("docker_dns", {})
    if not section.get("enabled"):
        return
    counts = section["counts"]
    print(
        f"Docker DNS coverage: {counts['matched']}/{counts['hosts']} matching, "
        f"{counts['drift']} with drift (review only)"
    )
    for row in section["findings"]:
        address = row.get("expected", "ambiguous")
        print(
            f"  ! DOCKER DNS {row['status']}: {row['hostname']} "
            f"-> {address} ({row['category']})"
        )


def check_docker_target(hostname, address, zone, network):
    """Reject noncanonical names or addresses outside the Docker allocation."""
    if (
        not isinstance(hostname, str)
        or canonical_name(hostname, zone) != hostname
        or address is None
        or scoped_address(address, network) != address
    ):
        raise ValueError("Invalid Docker DNS target")


def plan_docker_creates(services, running, records, zone, network, protected=()):
    """Authorize candidates only from unique, agreeing declarations and runtime."""
    if running is None or records is None:
        return []
    declarations = []
    for service in services:
        name = (
            service.get("ContainerName") or service.get("Name", "").rsplit("/", 1)[-1]
        )
        host = canonical_name(service.get("Hostname") or name, zone)
        addresses = {
            address
            for value in service.get("IPv4Addresses", [])
            if (address := scoped_address(value, network)) is not None
        }
        declarations.append((name, host, addresses))
    by_name = Counter(name for name, _, _ in declarations)
    by_host = Counter(host for _, host, _ in declarations)
    by_address = Counter(address for _, _, ips in declarations for address in ips)
    live_addresses = Counter(running.values())
    existing = {
        row["name"].lower().rstrip(".")
        for row in records
        if isinstance(row.get("name"), str)
    }
    existing_addresses = {
        row.get("content") for row in records if row.get("type") == "A"
    }
    actions = []
    for name, host, addresses in declarations:
        if (
            not host
            or by_name[name] != 1
            or by_host[host] != 1
            or len(addresses) != 1
            or host in existing
            or host in protected
        ):
            continue
        address = next(iter(addresses))
        if (
            running.get(name) != address
            or live_addresses[address] != 1
            or by_address[address] != 1
            or address in existing_addresses
            or address in protected
        ):
            continue
        if any(
            row.get("type") in ("A", "AAAA", "CNAME")
            and isinstance(row.get("name"), str)
            and row["name"].startswith("*.")
            and host.endswith(row["name"].lower().rstrip(".")[1:])
            for row in records
        ):
            continue
        actions.append(
            {"kind": "create_docker_dns_a", "hostname": host, "content": address}
        )
    return sorted(actions, key=lambda row: row["hostname"])
