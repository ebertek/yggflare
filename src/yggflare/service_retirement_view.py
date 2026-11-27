"""Bounded saved retirement projection; no credentials or live collectors."""

import ipaddress
import re
import time

from traefik_inventory import read

FILENAME = "service-retirement-review.json"
FRESH_SECONDS = 900
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
LAYERS = ("compose", "docker", "external", "internal", "unifi")
STATUSES = {
    "present", "absent", "unavailable", "declared", "owned", "unmanaged",
    "blocked", "review_only", "candidate_review_only", "missing_record",
    "identity_changed", "still_declared", "runtime_present", "private_protected",
    "dependency_protected", "record_conflict", "wildcard_protected",
    "shared_address", "manual_protected", "outside_scope", "missing_policy",
    "modified_policy", "policy_conflict", "grace_period", "eligible",
    "unsupported", "pending", "orphan",
}
OWNERSHIP = {"owned", "legacy", "docker", "static", "manual", "unmanaged", "unknown"}
DNS_STATES = {"matched", "absent", "unexpected", "unavailable"}
FIELDS = {
    "layer", "hostname", "status", "observed_at", "ownership", "address",
    "dns_count", "access_count", "tunnel_count", "policy_count",
    "grace_seconds", "grace_required_seconds", "pending", "auto_cleanup",
    "forward", "reverse",
}


def name_ok(value):
    return (
        isinstance(value, str) and 0 < len(value) <= 253
        and all(LABEL.fullmatch(label) for label in value.split("."))
    )


def valid_snapshot(document):
    if (
        not isinstance(document, dict)
        or set(document) != {"version", "service", "internal", "external", "items", "item_count"}
        or document["version"] != 1
        or not isinstance(document["service"], str)
        or not LABEL.fullmatch(document["service"])
        or not all(name_ok(document[key]) for key in ("internal", "external"))
        or document["internal"] == document["external"]
        or not all(document[key].startswith(document["service"] + ".") for key in ("internal", "external"))
        or not isinstance(document["items"], list)
        or document["item_count"] != len(LAYERS)
        or len(document["items"]) != len(LAYERS)
    ):
        return False
    for layer, row in zip(LAYERS, document["items"], strict=True):
        if (
            not isinstance(row, dict) or set(row) - FIELDS
            or not {"layer", "hostname", "status", "observed_at"}.issubset(row)
            or row["layer"] != layer
            or row["hostname"] != document["external" if layer == "external" else "internal"]
            or row["status"] not in STATUSES
            or type(row["observed_at"]) is not int
            or not 0 < row["observed_at"] <= 2**32
        ):
            return False
        for key in ("dns_count", "access_count", "tunnel_count", "policy_count", "grace_seconds", "grace_required_seconds"):
            if key in row and row[key] is not None and (
                type(row[key]) is not int or not 0 <= row[key] <= 2**32
            ):
                return False
        for key in ("pending", "auto_cleanup"):
            if key in row and type(row[key]) is not bool:
                return False
        if "ownership" in row and row["ownership"] not in OWNERSHIP:
            return False
        if any(key in row and row[key] not in DNS_STATES for key in ("forward", "reverse")):
            return False
        if row.get("address") is not None:
            try:
                if str(ipaddress.IPv4Address(row["address"])) != row["address"]:
                    return False
            except (TypeError, ValueError):
                return False
    return True


def saved(data, service="", *, now=None):
    """Expose the latest exact selection only; a different service is unknown."""
    if service and not name_ok(service):
        raise ValueError("Invalid service retirement selector")
    now = time.time() if now is None else now
    document = read(data / FILENAME)
    try:
        valid = valid_snapshot(document)
    except (TypeError, KeyError, ValueError):
        valid = False
    result = {
        "mode": "saved_retirement_review",
        "available": False,
        "fresh": False,
        "complete": False,
        "deletion_authorized": False,
        "items": [],
    }
    if not valid:
        return result
    if service and service not in (document["service"], document["internal"], document["external"]):
        return result
    rows = document["items"]
    return {
        **result,
        "available": True,
        "fresh": all(0 <= now - row["observed_at"] <= FRESH_SECONDS for row in rows),
        "complete": all(row["status"] != "unavailable" for row in rows),
        "service": document["service"],
        "internal": document["internal"],
        "external": document["external"],
        "items": rows,
        "retirement_order": "external DNS, Tunnel, Access; internal DNS before UniFi",
        "caveat": "Same-label correlation and saved observations only; no approval or proof of historical retirement.",
    }
