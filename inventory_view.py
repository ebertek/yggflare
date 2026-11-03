"""Inventory comparison and review flags; no credentials read."""

DEVICE_CLASSES = {
    "network",
    "server",
    "computer",
    "mobile",
    "iot",
    "media",
    "printer",
    "sensor",
    "other",
}


def decorate(hosts, inventory, state):
    """Derive review flags from evidence; offline never implies retirement."""
    static = {h.get("ipv4"): h for h in inventory.get("hosts", [])}
    latest = state.get("scanned_at", "")
    diffs = []
    for host in hosts:
        ip = host["ipv4"]
        declared = static.get(ip)
        observed = state.get("hosts", {}).get(ip)
        host["last_seen"] = state.get("last_seen", {}).get(
            ip, host.get("last_seen", "")
        )
        flags = []
        missing = [
            label
            for key, label in [("hostname", "hostname"), ("mac", "MAC")]
            if not host.get(key)
        ]
        host["missing_fields"] = missing
        if missing:
            flags.append("missing")
        if host.get("source") in ("Docker", "Compose", "Compose + Docker"):
            host["device_class"] = "docker"
        elif declared:
            host["device_class"] = (
                declared.get("device_class")
                if isinstance(declared.get("device_class"), str)
                and declared.get("device_class") in DEVICE_CLASSES
                else "device"
            )
        else:
            host["device_class"] = "unknown"
        retired = declared is not None and declared.get("retired") is True
        if retired:
            flags.append("retired")
            host["status"] = "retired (still observed)" if observed else "retired"
        first_seen = state.get("first_seen", {}).get(ip)
        new_event = any(
            str(message).startswith(f"NEW DEVICE {ip} ")
            for message in state.get("latest_events", [])
        )
        if (
            not declared
            and host.get("status") == "unmanaged"
            and (new_event or (first_seen and first_seen == latest))
        ):
            flags.append("new")
        if declared is not None:

            def diff(field, expected, actual, severity):
                diffs.append(
                    {
                        "hostname": host["hostname"],
                        "ipv4": ip,
                        "field": field,
                        "expected": expected,
                        "observed": actual,
                        "severity": severity,
                    }
                )
                if severity == "drift" and "drift" not in flags:
                    flags.append("drift")

            if observed:
                if retired:
                    diff(
                        "Presence", "Retired label", "Responded in latest scan", "drift"
                    )
                expected_mac = str(declared.get("mac") or "").lower()
                seen_mac = str(observed.get("mac") or "").lower()
                allowed = {expected_mac} | {
                    str(m).lower() for m in declared.get("observed_macs", [])
                }
                if expected_mac and seen_mac and seen_mac not in allowed:
                    diff("MAC", expected_mac, seen_mac, "drift")
                elif expected_mac and not seen_mac:
                    diff("MAC", expected_mac, "Not observed", "unknown")
                expected_ports = set(host.get("ports", []))
                seen_ports = set(observed.get("ports", []))
                for port in sorted(seen_ports - expected_ports):
                    diff("Port", "Not declared", port, "drift")
                for port in sorted(expected_ports - seen_ports):
                    diff("Port", port, "Not observed (not proof of closure)", "unknown")
            else:
                diff(
                    "Presence",
                    "Retired label" if retired else "Declared device",
                    "Not observed in latest scan",
                    "unknown",
                )
        if declared is None and observed and observed.get("mac"):
            matches = [
                entry
                for entry in static.values()
                if str(entry.get("mac", "")).lower() == str(observed["mac"]).lower()
            ]
            if len(matches) == 1:
                diffs.append(
                    {
                        "hostname": matches[0].get("hostname", ""),
                        "ipv4": ip,
                        "field": "IPv4",
                        "expected": matches[0]["ipv4"],
                        "observed": ip,
                        "severity": "drift",
                    }
                )
                flags.append("drift")
        host["flags"] = flags
    return diffs


def diff_view(data, table):
    rows = [
        [
            d["hostname"],
            d["ipv4"],
            d["field"],
            d["expected"],
            d["observed"],
            d["severity"],
        ]
        for d in data.get("diffs", [])
    ]
    text = '<p class="muted">Static declarations versus the latest scan. Missing observations are unknown, not proof that a device or port is gone. Accepted alternate MACs are not drift.</p>'
    return text + (
        table(["Host", "IP", "Field", "Declared", "Observed", "Assessment"], rows)
        if rows
        else "<p>No differences in the available static/observed comparison.</p>"
    )
