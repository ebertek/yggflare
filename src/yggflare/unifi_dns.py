"""Explicit GET-only UniFi DNS migration preflight; never a write plan."""

import argparse
import http.client
import ipaddress
import json
import os
import re
import signal
import socket
import ssl
import sys
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

from cloudflare_api import CloudflareClient, CloudflareError, checked_id
from cloudflare_credentials import api_token
from integration_inventory import credentials
from yggflare_config import domain, network

PREFIX = "/proxy/network/integration/v1"
PAGE_SIZE = 100
MAX_ROWS = 2000
MAX_RESPONSE = 1024 * 1024
CA_FILE = Path("/config/unifi-ca.pem")
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
RFC1918 = tuple(
    ipaddress.IPv4Network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def settings(env):
    """Fixed numeric HTTPS origin in the declared LAN; optional site and TLS name."""
    try:
        url = urlsplit(env["YGGFLARE_UNIFI_API_URL"])
        address = ipaddress.ip_address(url.hostname or "")
        lan = ipaddress.ip_network(env["YGGFLARE_LAN_CIDR"])
        port = url.port if url.port is not None else 443
        site = env.get("YGGFLARE_UNIFI_SITE_ID", "")
        tls_name = env.get("YGGFLARE_UNIFI_TLS_NAME") or str(address)
        if (
            url.scheme != "https"
            or url.username is not None
            or url.password is not None
            or url.path not in ("", "/")
            or url.query
            or url.fragment
            or address not in lan
            or address.is_unspecified
            or address.is_multicast
            or "%" in str(address)
            or not 1 <= port <= 65535
            or not re.fullmatch(r"[A-Za-z0-9.:-]{1,253}", tls_name)
        ):
            raise ValueError
        return str(address), port, str(UUID(site)) if site else "", tls_name
    except (KeyError, ValueError, TypeError):
        raise ValueError("Invalid or missing UniFi HTTPS LAN configuration") from None


class FixedConnection(http.client.HTTPSConnection):
    """Use a numeric destination with independent, verified TLS identity."""

    def __init__(self, address, port, tls_name, context):
        super().__init__(address, port, timeout=5, context=context)
        self.tls_name = tls_name

    def connect(self):
        raw = socket.create_connection((self.host, self.port), timeout=5)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.tls_name)
        except BaseException:
            raw.close()
            raise


def get_page(config, key, kind, site, offset):
    if kind == "sites" and not site:
        path = PREFIX + "/sites"
    elif kind == "dns" and site:
        path = PREFIX + "/sites/" + str(UUID(site)) + "/dns/policies"
    else:
        raise ValueError("Unsupported UniFi operation")
    if type(offset) is not int or not 0 <= offset < MAX_ROWS:
        raise ValueError("Invalid UniFi pagination offset")
    address, port, _, tls_name = config
    context = ssl.create_default_context()
    if CA_FILE.is_file():
        context.load_verify_locations(cafile=str(CA_FILE))
    conn = FixedConnection(address, port, tls_name, context)
    try:
        conn.request(
            "GET",
            f"{path}?offset={offset}&limit={PAGE_SIZE}",
            headers={"Accept": "application/json", "X-API-Key": key},
        )
        response = conn.getresponse()
        if response.status != 200:
            raise ValueError("UniFi API did not return HTTP 200")
        raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise ValueError("UniFi response exceeds byte limit")
        return json.loads(raw)
    finally:
        conn.close()


def all_rows(config, key, kind, site, fetch=get_page):
    rows, seen, total = [], set(), None
    while True:
        payload = fetch(config, key, kind, site, len(rows))
        if not isinstance(payload, dict):
            raise ValueError("Invalid UniFi response")
        data = payload.get("data")
        count, offset, limit, current_total = (
            payload.get(k) for k in ("count", "offset", "limit", "totalCount")
        )
        if (
            any(type(v) is not int for v in (count, offset, limit, current_total))
            or not isinstance(data, list)
            or count != len(data)
            or offset != len(rows)
            or not 1 <= limit <= PAGE_SIZE
            or count > limit
            or not 0 <= current_total <= MAX_ROWS
            or offset + count > current_total
            or (total is not None and current_total != total)
        ):
            raise ValueError("Incomplete or changing UniFi pagination")
        total = current_total
        for item in data:
            if not isinstance(item, dict):
                raise ValueError("Invalid UniFi row")
            identifier = str(UUID(item.get("id", "")))
            if identifier in seen:
                raise ValueError("Duplicate UniFi identity")
            seen.add(identifier)
            rows.append(item)
        if len(rows) == total:
            return rows
        if not count:
            raise ValueError("Incomplete UniFi collection")


def collect(config, key, fetch=get_page):
    sites = all_rows(config, key, "sites", "", fetch)
    chosen = [
        row for row in sites if not config[2] or str(UUID(row["id"])) == config[2]
    ]
    if len(chosen) != 1:
        raise ValueError("Select exactly one UniFi site")
    return all_rows(config, key, "dns", str(UUID(chosen[0]["id"])), fetch)


def hostname(value):
    if not isinstance(value, str):
        return None
    name = value.lower().rstrip(".")
    if len(name) > 253 or not all(LABEL.fullmatch(x) for x in name.split(".")):
        return None
    return name


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
        elif len(aliases[address]) != 1 or local_ips[address] - {name}:
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
        "caveat": (
            "Configuration comparison only; PTR answers, ownership and "
            "complete upstream visibility are not verified. Private addresses "
            "outside the configured LAN require explicit scope review before writes."
        ),
    }


def run():
    config = settings(os.environ)
    key = credentials("unifi")[0]
    zone = domain("YGGFLARE_INTERNAL_DOMAIN")
    lan = network("YGGFLARE_LAN_CIDR")
    token = api_token()
    client = CloudflareClient(token)
    account = checked_id(os.environ.get("CLOUDFLARE_ACCOUNT_ID"), "account ID")
    zone_id = client.zone_id(zone, account)
    configured = os.environ.get("CLOUDFLARE_INTERNAL_ZONE_ID")
    if configured and checked_id(configured) != zone_id:
        raise ValueError("Configured internal zone does not match Cloudflare")
    result = plan(client.list_dns(zone_id), collect(config, key), zone, lan)
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
