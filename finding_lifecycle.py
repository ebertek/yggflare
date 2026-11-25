"""Bounded presentation-only history of observations, independent of alert policy."""

import hashlib
import ipaddress
import re

MAX_FINDINGS = 1024
MAX_TRANSITIONS = 256
STATES = (
    "observed",
    "not_reobserved",
    "source_incomplete",
    "inventory_match_observed",
    "advertisement_not_reobserved",
)
KINDS = ("unknown-device", "moved-device", "identity", "new-port", "dns-sd")
MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
PORT = re.compile(r"(?:tcp|udp)/[0-9]{1,5}")


def digest(key):
    return hashlib.sha256(key.encode()).hexdigest()


def identity(key):
    """Parse only known finding keys; never export raw notification messages."""
    kind, _, rest = key.partition(":")
    if kind == "dns-sd":
        host, sep, service = rest.partition("|")
        if (
            sep
            and len(host) <= 253
            and len(service) <= 128
            and host
            and service
            and all(c.isprintable() for c in host + service)
        ):
            return {"kind": kind, "hostname": host, "service": service}
        return None
    if kind not in KINDS:
        return None
    ip, _, detail = rest.partition(":")
    try:
        address = str(ipaddress.IPv4Address(ip))
    except ValueError:
        return None
    if kind == "new-port":
        if not PORT.fullmatch(detail) or not 1 <= int(detail.split("/")[1]) <= 65535:
            return None
        return {"kind": kind, "address": address, "service": detail}
    if detail and not MAC.fullmatch(detail):
        return None
    return {"kind": kind, "address": address, "mac": detail or None}


def active_rows(reported, advertisements):
    for key in reported:
        if isinstance(key, str) and (row := identity(key)):
            yield key, row
    for item in advertisements:
        if isinstance(item, str):
            key = "dns-sd:" + item.rsplit("|", 1)[0]
            if row := identity(key):
                yield key, row


def absent_status(row, inventory, hosts, ignored, dns_complete):
    """Only positive current evidence can establish an inventory match."""
    kind = row["kind"]
    if kind == "dns-sd":
        return "advertisement_not_reobserved" if dns_complete else "source_incomplete"
    ip = row.get("address")
    if ip in ignored or ip not in hosts:
        return "not_reobserved"
    actual = hosts[ip]
    declared = inventory.get(ip)
    if declared is not None:
        mac = actual.get("mac")
        allowed = declared.get("allowed_macs", {declared.get("mac")})
        # A new port is compliant only when the same open port was observed
        # again and is now declared. Disappearance is not proof of closure.
        if kind == "new-port":
            service = row.get("service")
            if (
                service in actual.get("ports", [])
                and service in declared.get("ports", set())
                and mac
                and mac in allowed
            ):
                return "inventory_match_observed"
        elif mac and mac in allowed and (row.get("mac") is None or mac == row["mac"]):
            return "inventory_match_observed"
    return "not_reobserved"


def update(
    previous, reported, advertisements, inventory, hosts, ignored, now, dns_complete
):
    """Keep stable IDs and status transitions; never feed back into alert suppression."""
    prior = previous.get("finding_lifecycle", {})
    if not isinstance(prior, dict) or prior.get("version") != 1:
        prior = {}
    rows = {
        row["finding_id"]: dict(row)
        for row in prior.get("items", [])
        if isinstance(row, dict)
        and isinstance(row.get("finding_id"), str)
        and row.get("kind") in KINDS
        and row.get("status") in STATES
    }
    transitions = list(prior.get("transitions", []))[-MAX_TRANSITIONS:]
    current = {digest(key): row for key, row in active_rows(reported, advertisements)}
    # A retained DNS-SD list is not a new observation on an incomplete browse.
    if not dns_complete:
        current = {key: row for key, row in current.items() if row["kind"] != "dns-sd"}
    migrated = not prior and previous.get("initialized") is True

    def change(row, status):
        before = row.get("status")
        if before != status:
            transitions.append(
                {
                    "finding_id": row["finding_id"],
                    "kind": row["kind"],
                    "from_status": before,
                    "to_status": status,
                    "observed_at": now,
                }
            )
            row["status_changed_at"] = now
        row["status"] = status

    for key, fields in current.items():
        row = rows.get(key)
        if row is None:
            row = {
                "finding_id": key,
                **fields,
                "first_seen": now,
                "first_seen_lower_bound": bool(migrated),
                "observation_count": 0,
                "reappearance_count": 0,
            }
            rows[key] = row
        elif row["status"] != "observed" and row["status"] != "source_incomplete":
            row["reappearance_count"] = row.get("reappearance_count", 0) + 1
        row["last_seen"] = now
        row["observation_count"] = row.get("observation_count", 0) + 1
        change(row, "observed")
    for key, row in rows.items():
        if key not in current:
            # Do not downgrade a previously proven match solely because a
            # later scan has no evidence; its timestamp remains historical.
            status = absent_status(row, inventory, hosts, ignored, dns_complete)
            if (
                row["status"] == "inventory_match_observed"
                and status == "not_reobserved"
            ):
                continue
            change(row, status)
    ordered = sorted(
        rows.values(),
        key=lambda row: (
            row["status"] == "observed",
            row.get("last_seen", ""),
            row["finding_id"],
        ),
        reverse=True,
    )
    kept = ordered[:MAX_FINDINGS]
    return {
        "version": 1,
        "observed_at": now,
        "items": kept,
        "transitions": transitions[-MAX_TRANSITIONS:],
        "truncated": len(ordered) > MAX_FINDINGS or prior.get("truncated") is True,
        "active_total": len(current),
        "retained_total": len(kept),
        "migration_baseline": bool(migrated),
    }


def rows(state):
    value = state.get("finding_lifecycle", {})
    if (
        not isinstance(value, dict)
        or value.get("version") != 1
        or value.get("available") is False
    ):
        return None
    return value
