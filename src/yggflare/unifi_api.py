"""Bounded GET-only client for the local UniFi Network Integration API."""

import http.client
import ipaddress
import json
import re
import socket
import ssl
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

from traefik_inventory import finite_number, unique_object, validate_depth
from yggflare_env import env_get, env_required

PREFIX = "/proxy/network/integration/v1"
PAGE_SIZE = 100
MAX_ROWS = 2000
MAX_RESPONSE = 1024 * 1024
CA_FILE = Path("/config/unifi-ca.pem")
SITE_PATHS = {
    "devices": "devices",
    "clients": "clients",
    "networks": "networks",
    "dns": "dns/policies",
}
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def row_id(value):
    if not isinstance(value, str):
        raise ValueError("Invalid UniFi identity")
    return str(UUID(value))


def settings(env):
    """Fixed numeric HTTPS origin in the declared LAN; optional site and TLS name."""
    try:
        value = env_required(env, "YGGFLARE_UNIFI_API_URL")
        if any(not 33 <= ord(char) <= 126 for char in value):
            raise ValueError
        url = urlsplit(value)
        address = ipaddress.ip_address(url.hostname or "")
        lan = ipaddress.ip_network(env_required(env, "YGGFLARE_LAN_CIDR"))
        port = url.port if url.port is not None else 443
        site = env_get(env, "YGGFLARE_UNIFI_SITE_ID", "")
        tls_name = env_get(env, "YGGFLARE_UNIFI_TLS_NAME") or str(address)
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
    elif kind in SITE_PATHS and site:
        path = f"{PREFIX}/sites/{UUID(site)}/{SITE_PATHS[kind]}"
    else:
        raise ValueError("Unsupported UniFi operation")
    if type(offset) is not int or not 0 <= offset < MAX_ROWS:
        raise ValueError("Invalid UniFi pagination offset")
    return _get_json(config, key, f"{path}?offset={offset}&limit={PAGE_SIZE}")


def get_device(config, key, site, device):
    """Read details of one adopted device in the selected site."""
    return _get_json(config, key, f"{PREFIX}/sites/{UUID(site)}/devices/{UUID(device)}")


def get_network(config, key, site, network):
    """Read one network's configuration through its fixed Integration API path."""
    return _get_json(
        config, key, f"{PREFIX}/sites/{UUID(site)}/networks/{UUID(network)}"
    )


def connection(config):
    address, port, _, tls_name = config
    context = ssl.create_default_context()
    if CA_FILE.is_file():
        context.load_verify_locations(cafile=str(CA_FILE))
    return FixedConnection(address, port, tls_name, context)


def response_json(response, expected_status):
    if response.status != expected_status:
        raise ValueError("Unexpected UniFi HTTP status")
    raw = response.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise ValueError("UniFi response exceeds byte limit")
    document = json.loads(
        raw,
        object_pairs_hook=unique_object,
        parse_float=finite_number,
        parse_constant=finite_number,
    )
    validate_depth(document)
    return document


def _get_json(config, key, path):
    conn = connection(config)
    try:
        conn.request(
            "GET",
            path,
            headers={"Accept": "application/json", "X-API-Key": key},
        )
        return response_json(conn.getresponse(), 200)
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
            identifier = row_id(item.get("id"))
            if identifier in seen:
                raise ValueError("Duplicate UniFi identity")
            seen.add(identifier)
            rows.append(item)
        if len(rows) == total:
            return rows
        if not count:
            raise ValueError("Incomplete UniFi collection")


def select_site(config, key, fetch=get_page):
    sites = all_rows(config, key, "sites", "", fetch)
    chosen = [row for row in sites if not config[2] or row_id(row["id"]) == config[2]]
    if len(chosen) != 1:
        raise ValueError("Select exactly one UniFi site")
    return row_id(chosen[0]["id"])


def hostname(value):
    if not isinstance(value, str):
        return None
    name = value.lower().rstrip(".")
    if len(name) > 253 or not all(LABEL.fullmatch(x) for x in name.split(".")):
        return None
    return name
