"""Read-only, private-inventory audit for non-Docker internal-domain A records.

MAC addresses, device descriptions, serials, purchase dates and ports are
private inventory metadata. They are never sent to Cloudflare or logged.
"""

import ipaddress
import json
import re
from collections import Counter
from datetime import date

from cloudflare_api import IDENTIFIER
from cloudflare_live_diff import DOCKER_NETWORK, index_records
from yggflare_config import domain, network

STATIC_NETWORK = network("YGG_DEVICES_CIDR")
HOST = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\."
    + re.escape(domain("YGG_INTERNAL_DOMAIN"))
    + r"$"
)
MAC = re.compile(r"^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")
INVENTORY = "Scripts/cloudflare/static-hosts.json"
MAX_HOSTS = 256
MAX_ADDITIONAL = 4
MAX_ALIASES = 16


def validate_metadata(entry, hostname):
    """Reject invalid optional metadata without exposing its contents."""
    for field, maximum in (("description", 512), ("serial_number", 256)):
        value = entry.get(field)
        if value is not None and (
            not isinstance(value, str)
            or not value.strip()
            or len(value) > maximum
            or any(ord(character) < 32 for character in value)
        ):
            raise ValueError(f"{hostname}: invalid optional {field}")

    purchased = entry.get("purchase_date")
    if purchased is not None:
        if not isinstance(purchased, str) or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}", purchased
        ):
            raise ValueError(f"{hostname}: invalid optional purchase_date")
        try:
            date.fromisoformat(purchased)
        except ValueError as error:
            raise ValueError(f"{hostname}: invalid optional purchase_date") from error

    validate_ports(entry, hostname)


def validate_ports(entry, hostname):
    """Validate protocol-aware port metadata; reject legacy fields."""
    if "ports" in entry:
        ports = entry["ports"]
        if not isinstance(ports, list):
            raise ValueError(f"{hostname}: ports must be a list")
        seen = set()
        for item in ports:
            if (
                not isinstance(item, dict)
                or "port" not in item
                or set(item) - {"port", "protocol", "description"}
            ):
                raise ValueError(f"{hostname}: invalid ports entry")
            port = item["port"]
            if (
                not isinstance(port, int)
                or isinstance(port, bool)
                or not 1 <= port <= 65535
            ):
                raise ValueError(f"{hostname}: invalid port number")
            description = item.get("description")
            if "description" in item and (
                not isinstance(description, str)
                or not description.strip()
                or len(description) > 256
                or any(ord(char) < 32 for char in description)
            ):
                raise ValueError(f"{hostname}: invalid port description")
            protocol = item.get("protocol")
            if "protocol" in item and (
                not isinstance(protocol, str) or protocol not in ("tcp", "udp")
            ):
                raise ValueError(f"{hostname}: invalid port protocol")
            key = (protocol, port)
            if key in seen:
                raise ValueError(f"{hostname}: duplicate port/protocol pair")
            seen.add(key)
        return


def validate_aliases(entry, hostname):
    """Validate future CNAME aliases without creating or auditing them."""
    if "aliases" not in entry:
        return []
    aliases = entry["aliases"]
    if not isinstance(aliases, list) or len(aliases) > MAX_ALIASES:
        raise ValueError(f"{hostname}: invalid aliases list")
    seen = set()
    for alias in aliases:
        if (
            not isinstance(alias, str)
            or not HOST.fullmatch(alias)
            or alias == hostname
            or alias in seen
        ):
            raise ValueError(f"{hostname}: invalid or duplicate alias")
        seen.add(alias)
    return aliases


def validate_additional_ipv4(hostname, value):
    """Accept only explicitly declared, non-boundary Docker-side A addresses.

    Companion records are protected observations, not targets for writes.
    """
    if not isinstance(value, list) or len(value) > MAX_ADDITIONAL:
        raise ValueError(f"{hostname}: invalid additional_ipv4 list")
    addresses = []
    for raw in value:
        if not isinstance(raw, str):
            raise TypeError(f"{hostname}: invalid additional_ipv4 address")
        try:
            address = ipaddress.IPv4Address(raw)
        except ValueError as error:
            raise ValueError(f"{hostname}: invalid additional_ipv4 address") from error
        allocation = ipaddress.ip_network(f"{address}/27", strict=False)
        if (
            str(address) != raw
            or address not in DOCKER_NETWORK
            or address in {allocation.network_address, allocation.broadcast_address}
            or raw in addresses
        ):
            raise ValueError(f"{hostname}: invalid additional_ipv4 address")
        addresses.append(raw)
    return addresses


def validated_entry(entry, index):
    """Validate one inventory entry and return DNS-only data."""
    if not isinstance(entry, dict) or not {"hostname", "ipv4"} <= set(entry):
        raise ValueError(f"Static DNS entry {index} requires hostname and ipv4")
    if set(entry) - {
        "hostname",
        "ipv4",
        "mac",
        "description",
        "serial_number",
        "purchase_date",
        "ports",
        "aliases",
        "additional_ipv4",
        "observed_macs",
        "interface_macs",
    }:
        raise ValueError(f"Static DNS entry {index} has unknown fields")
    hostname = entry["hostname"]
    if not isinstance(hostname, str) or not HOST.fullmatch(hostname):
        raise ValueError(f"Static DNS entry {index} has invalid internal hostname")
    value = entry["ipv4"]
    if not isinstance(value, str):
        raise TypeError(f"{hostname}: invalid IPv4 address")
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError as error:
        raise ValueError(f"{hostname}: invalid IPv4 address") from error
    allocation_group = ipaddress.ip_network(f"{address}/27", strict=False)
    edges = (allocation_group.network_address, allocation_group.broadcast_address)
    if (
        str(address) != value
        or address not in STATIC_NETWORK
        or address in edges
        or address in DOCKER_NETWORK
    ):
        raise ValueError(f"{hostname}: address is outside the static host subnet")
    mac = entry.get("mac")
    if mac is not None and (not isinstance(mac, str) or not MAC.fullmatch(mac)):
        raise ValueError(f"{hostname}: invalid optional MAC address")
    observed_macs = entry.get("observed_macs", [])
    if not isinstance(observed_macs, list) or len(observed_macs) > 16:
        raise ValueError(f"{hostname}: invalid observed_macs list")
    if any(
        not isinstance(value, str) or not MAC.fullmatch(value)
        for value in observed_macs
    ) or len({value.lower() for value in observed_macs}) != len(observed_macs):
        raise ValueError(f"{hostname}: invalid or duplicate observed MAC")
    interface_macs = entry.get("interface_macs", {})
    if not isinstance(interface_macs, dict) or len(interface_macs) > 32:
        raise ValueError(f"{hostname}: invalid interface_macs mapping")
    if any(
        not isinstance(name, str)
        or not re.fullmatch(r"[a-zA-Z0-9_.@-]{1,64}", name)
        or not isinstance(value, str)
        or not MAC.fullmatch(value)
        for name, value in interface_macs.items()
    ):
        raise ValueError(f"{hostname}: invalid interface MAC")
    validate_metadata(entry, hostname)
    validate_aliases(entry, hostname)
    additional = validate_additional_ipv4(hostname, entry.get("additional_ipv4", []))
    return hostname, value, additional


def load_inventory_details(path, required=False):
    """Return primary A targets and explicitly allowed companion addresses."""
    if not path.is_file():
        if required:
            raise ValueError(f"Required static DNS inventory is absent: {path}")
        return None, {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) != {"version", "hosts"}:
        raise ValueError("Static DNS inventory requires version and hosts")
    if (
        not isinstance(data["version"], int)
        or isinstance(data["version"], bool)
        or data["version"] != 1
    ):
        raise ValueError("Unsupported static DNS inventory version")
    entries = data["hosts"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_HOSTS:
        raise ValueError("Static DNS inventory must contain 1-256 host entries")
    wanted = {}
    companions = {}
    alias_names = set()
    alias_count = 0
    for index, entry in enumerate(entries, 1):
        hostname, value, additional = validated_entry(entry, index)
        if hostname in wanted:
            raise ValueError(f"Duplicate static DNS hostname: {hostname}")
        wanted[hostname] = value
        aliases = entry.get("aliases", [])
        alias_count += len(aliases)
        alias_names.update(aliases)
        if additional:
            companions[hostname] = additional
    if len(alias_names) != alias_count or alias_names.intersection(wanted):
        raise ValueError("Static DNS aliases conflict with inventory hostnames")
    return wanted, companions


def load_inventory_aliases(path):
    """Read declared aliases after the main inventory has been validated."""
    if not path.is_file():
        return set()
    # Reject malformed or colliding aliases instead of accidentally hiding drift.
    load_inventory_details(path, required=True)
    entries = json.loads(path.read_text(encoding="utf-8"))["hosts"]
    return {alias for entry in entries for alias in entry.get("aliases", [])}


def load_inventory(path, required=False):
    """Retain the original primary-only inventory interface for callers."""
    wanted, _ = load_inventory_details(path, required=required)
    return wanted


def check_static_target(hostname, address):
    """Validate an A record target against the private allocation policy."""
    return validated_entry({"hostname": hostname, "ipv4": address}, "DNS write")


def plan_static_dns(wanted, records, companions=None):
    """Plan primary A writes only, retaining declared companion records.

    Companion A records are never created, modified, or deleted.
    """
    if wanted is None:
        return []
    companions = companions or {}
    index = index_records(records, "name")
    actions = []
    for finding in compare_static_dns(wanted, records, companions)["findings"]:
        hostname = finding["hostname"]
        allowed = companions.get(hostname, [])
        preserved = {"additional_ipv4": allowed} if allowed else {}
        if finding["status"] == "missing":
            actions.append(
                {
                    "kind": "create_static_dns_a",
                    "hostname": hostname,
                    "content": wanted[hostname],
                    **preserved,
                }
            )
        elif finding["status"] == "mismatch":
            matched = [
                item
                for item in index.get(hostname, [])
                if item.get("type") == "A" and item.get("content") not in allowed
            ]
            if len(matched) != 1:
                continue
            record = matched[0]
            previous = record.get("content")
            record_id = record.get("id")
            try:
                existing = ipaddress.IPv4Address(previous)
            except (ValueError, TypeError):
                continue
            if (
                existing not in STATIC_NETWORK
                or not isinstance(record_id, str)
                or not IDENTIFIER.fullmatch(record_id)
            ):
                continue
            actions.append(
                {
                    "kind": "update_static_dns_a",
                    "hostname": hostname,
                    "record_id": record_id,
                    "before": previous,
                    "content": wanted[hostname],
                    **preserved,
                }
            )
    return actions


def classify_static_a(hostname, expected, matches, allowed):
    """Separate a primary static A from an explicitly declared A companion."""
    if not matches:
        if allowed:
            return {
                "hostname": hostname,
                "status": "conflict",
                "reason": "declared companion A records are absent",
            }
        return {"hostname": hostname, "status": "missing", "expected": expected}

    if any(record.get("type") != "A" for record in matches):
        return {
            "hostname": hostname,
            "status": "conflict",
            "reason": "ambiguous A/CNAME records",
        }
    if any(record.get("proxied") is not False for record in matches):
        return {
            "hostname": hostname,
            "status": "conflict",
            "reason": "A record is proxied",
        }
    extras = [r for r in matches if r.get("content") in allowed]
    primary = [r for r in matches if r.get("content") not in allowed]
    if len(extras) != len(allowed) or {r.get("content") for r in extras} != set(
        allowed
    ):
        return {
            "hostname": hostname,
            "status": "conflict",
            "reason": "declared companion A records differ",
        }
    return classify_primary_static_a(hostname, expected, primary)


def classify_primary_static_a(hostname, expected, primary):
    """Report primary-A drift after all companions have passed validation."""
    if not primary:
        return {"hostname": hostname, "status": "missing", "expected": expected}
    if len(primary) != 1:
        return {
            "hostname": hostname,
            "status": "conflict",
            "reason": "ambiguous A/CNAME records",
        }
    if primary[0].get("content") != expected:
        return {
            "hostname": hostname,
            "status": "mismatch",
            "expected": expected,
            "actual": primary[0].get("content"),
        }
    return None


def compare_static_dns(wanted, records, companions=None):
    """Compare primary and explicit companion A records without DNS mutation."""
    if wanted is None:
        return {
            "enabled": False,
            "counts": {"hosts": 0, "matched": 0, "drift": 0},
            "findings": [],
        }

    companions = companions or {}
    index = index_records(records, "name")
    findings = []
    matched = 0
    for hostname, expected in sorted(wanted.items()):
        matches = [
            record
            for record in index.get(hostname, [])
            if record.get("type") in {"A", "CNAME"}
        ]
        finding = classify_static_a(
            hostname, expected, matches, companions.get(hostname, [])
        )
        if finding is None:
            matched += 1
        else:
            findings.append(finding)

    status = Counter(finding["status"] for finding in findings)
    return {
        "enabled": True,
        "counts": {
            "hosts": len(wanted),
            "matched": matched,
            "missing": status["missing"],
            "mismatch": status["mismatch"],
            "conflict": status["conflict"],
            "drift": len(findings),
        },
        "findings": findings,
    }
