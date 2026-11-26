"""Allowlisted observations from the local UniFi Network Integration API."""

import http.client
import ipaddress
import re
import time
from collections import Counter

from unifi_api import MAX_ROWS, SITE_PATHS, all_rows, hostname, row_id, select_site

KINDS = tuple(SITE_PATHS)
DETAIL_LIMIT = 32
DETAIL_START_DEADLINE_SECONDS = 60
UPLINK_STATUSES = (
    "reported",
    "not_reported",
    "parent_not_visible",
    "invalid",
    "unavailable",
    "not_checked",
)
UPLINK_FIELDS = ("uplink_status", "uplink_name", "uplink_mac")
MAX_ITEMS = len(KINDS) * MAX_ROWS
MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
TYPE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")


def text(value):
    if isinstance(value, str) and value and len(value) <= 128 and value.isprintable():
        return value
    return None


def address(value, version=None):
    if not isinstance(value, str) or "%" in value:
        return None
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return None
    return str(parsed) if version in (None, parsed.version) else None


def mac(value):
    return (
        value.lower()
        if isinstance(value, str) and MAC.fullmatch(value.lower())
        else None
    )


def vlan(value):
    return value if type(value) is int and 0 <= value <= 4094 else None


def flag(value):
    return value if type(value) is bool else None


def policy_type(value):
    return value if isinstance(value, str) and TYPE.fullmatch(value) else None


def policy_name(value):
    if isinstance(value, str) and value.startswith("*."):
        suffix = hostname(value[2:])
        return "*." + suffix if suffix else None
    return hostname(value)


def a_address(value):
    return address(value, 4)


# Each saved field has a fixed upstream key and validator. The same rules
# validate the persisted projection before any operator interface reads it.
FIELDS = {
    "devices": {
        "name": ("name", text),
        "address": ("ipAddress", address),
        "mac": ("macAddress", mac),
        "model": ("model", text),
        "state": ("state", text),
        "firmware": ("firmwareVersion", text),
    },
    "clients": {
        "name": ("name", text),
        "address": ("ipAddress", address),
        "mac": ("macAddress", mac),
        "client_type": ("type", text),
    },
    "networks": {
        "name": ("name", text),
        "vlan_id": ("vlanId", vlan),
        "enabled": ("enabled", flag),
        "management": ("management", text),
    },
    "dns": {
        "name": ("domain", policy_name),
        "policy_type": ("type", policy_type),
        "enabled": ("enabled", flag),
        "address": ("ipv4Address", a_address),
    },
}


def valid_row(row):
    kind = row.get("kind")
    fields = FIELDS.get(kind) if isinstance(kind, str) else None
    if fields is None:
        return False
    keys = fields.keys() | {"kind"}
    if kind == "devices" and row.keys() != keys:
        if row.keys() != keys | set(UPLINK_FIELDS) or not valid_uplink(row):
            return False
        keys |= set(UPLINK_FIELDS)
    if row.keys() != keys or not row["name"]:
        return False
    for name, (_, validate) in fields.items():
        value = row[name]
        if value is not None:
            normalized = validate(value)
            if type(normalized) is not type(value) or normalized != value:
                return False
    if kind == "dns":
        return (
            row["policy_type"] is not None
            and row["enabled"] is not None
            and (row["policy_type"] != "A_RECORD" or row["address"] is not None)
        )
    return True


def uplink_counts(rows):
    counts = Counter(row["uplink_status"] for row in rows if "uplink_status" in row)
    return {state: counts[state] for state in UPLINK_STATUSES} if counts else None


def valid_uplink(row):
    state, name, parent_mac = (row[field] for field in UPLINK_FIELDS)
    if state == "reported":
        return text(name) is not None and (
            parent_mac is None or mac(parent_mac) == parent_mac
        )
    return state in UPLINK_STATUSES and name is None and parent_mac is None


def uplink(details, device, devices):
    if not isinstance(details, dict) or row_id(details.get("id")) != device:
        return "invalid", None
    reported = details.get("uplink")
    if reported is None:
        return "not_reported", None
    if not isinstance(reported, dict):
        return "invalid", None
    parent = row_id(reported.get("deviceId"))
    if parent == device:
        return "invalid", None
    if parent not in devices:
        return "parent_not_visible", None
    return "reported", devices[parent]


def add_uplinks(config, key, site, devices, fetch_detail, deadline):
    ordered = sorted(devices, key=lambda device: (devices[device]["name"], device))
    for index, device in enumerate(ordered):
        parent = None
        state = "not_checked"
        if index < DETAIL_LIMIT and time.monotonic() < deadline:
            try:
                details = fetch_detail(config, key, site, device)
            except (
                OSError,
                ValueError,
                TypeError,
                RecursionError,
                http.client.HTTPException,
            ):
                state = "unavailable"
            else:
                try:
                    state, parent = uplink(details, device, devices)
                except ValueError:
                    state = "invalid"
        devices[device].update(
            uplink_status=state,
            uplink_name=parent["name"] if parent else None,
            uplink_mac=parent["mac"] if parent else None,
        )


def collect(config, key, fetch, fetch_detail=None):
    deadline = time.monotonic() + DETAIL_START_DEADLINE_SECONDS
    site = select_site(config, key, fetch)
    rows = []
    devices = {}
    for kind, fields in FIELDS.items():
        for item in all_rows(config, key, kind, site, fetch):
            row = {
                "kind": kind,
                **{
                    name: validate(item.get(upstream))
                    for name, (upstream, validate) in fields.items()
                },
            }
            if not valid_row(row):
                raise ValueError("Invalid UniFi observation")
            rows.append(row)
            if kind == "devices":
                devices[row_id(item["id"])] = row
    if fetch_detail is not None:
        add_uplinks(config, key, site, devices, fetch_detail, deadline)
    return rows
