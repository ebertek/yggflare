"""Allowlisted presentation of optional planned and historical inventories."""

from html import escape

from docker_inventory import address_key


def records(document):
    """Accept a record list or an object containing hosts/devices records."""
    if isinstance(document, dict):
        document = document.get("hosts", document.get("devices"))
    if not isinstance(document, list) or any(not isinstance(v, dict) for v in document):
        raise ValueError("Expected inventory records")
    result = []
    for item in document:
        row = {}
        for key in (
            "hostname",
            "name",
            "ipv4",
            "ipv6",
            "mac",
            "description",
            "notes",
            "reason",
            "retired_at",
            "device_class",
        ):
            value = item.get(key, "")
            if not isinstance(value, str):
                raise ValueError("Expected text inventory field")
            row[key] = value
        aliases = item.get("aliases", [])
        if not isinstance(aliases, list) or any(
            not isinstance(v, str) for v in aliases
        ):
            raise ValueError("Expected aliases list")
        row["aliases"] = aliases
        result.append(row)
    return sorted(
        result, key=lambda r: (address_key(r["ipv4"]), r["hostname"] or r["name"])
    )


def view(kind, data, table):
    filename = (
        "static-hosts-reserved.json" if kind == "reserved" else "retired-devices.json"
    )
    text = f"<p>Read-only entries from <code>{escape(filename)}</code>. These records do not create DNS, schedule scans, or change Cloudflare ownership.</p>"
    rows = [
        [
            r["hostname"] or r["name"],
            r["ipv4"],
            r["ipv6"],
            r["mac"],
            ", ".join(r["aliases"]),
            r["device_class"],
            r["notes"] or r["description"],
            r["reason"],
            r["retired_at"],
        ]
        for r in data.get(kind, [])
    ]
    return text + (
        table(
            [
                "Host",
                "IP",
                "IPv6",
                "MAC",
                "Aliases",
                "Class",
                "Comment",
                "Reason",
                "Retired at",
            ],
            rows,
        )
        if rows
        else f"<p>No entries available. Mount {escape(filename)} under /config.</p>"
    )
