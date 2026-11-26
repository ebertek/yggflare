"""Allowlisted observations from the local UniFi Network Integration API."""

import ipaddress
import re

from unifi_api import MAX_ROWS, SITE_PATHS, all_rows, hostname, select_site

KINDS = tuple(SITE_PATHS)
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
    if fields is None or row.keys() != fields.keys() | {"kind"} or not row["name"]:
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


def collect(config, key, fetch):
    site = select_site(config, key, fetch)
    rows = []
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
    return rows
