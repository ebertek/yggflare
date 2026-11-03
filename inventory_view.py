"""Inventory comparison and server-side metadata privacy; no credentials read."""

from web_views import advertisements, event_type, protocol

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


def private_projection(data):
    """Construct a redacted allowlist, not a CSS mask or a raw-model copy."""
    host_names, addresses, subnets = {}, {}, {}

    def alias(mapping, value, prefix):
        if not value:
            return ""
        if value not in mapping:
            mapping[value] = f"{prefix} {len(mapping) + 1:03d}"
        return mapping[value]

    def name(value):
        return alias(host_names, value, "Device")

    def address(value):
        return alias(addresses, value, "Address")

    hosts = []
    for host in data.get("hosts", []):
        label = name(host.get("hostname") or host.get("ipv4") or f"row-{len(hosts)}")
        hosts.append(
            {
                "hostname": label,
                "ipv4": address(host.get("ipv4")),
                "ipv6": "Hidden" if host.get("ipv6") else "",
                "mac": "Hidden" if host.get("mac") else "",
                "description": "",
                "aliases": [],
                "subnet": alias(subnets, host.get("subnet"), "Subnet"),
                **{
                    key: host.get(key, [])
                    for key in ("ports", "observed_ports", "flags", "missing_fields")
                },
                **{
                    key: host.get(key, "")
                    for key in ("status", "device_class", "last_seen", "source")
                },
                "port_sources": host.get("port_sources", {}),
            }
        )
    state = data.get("network_state", {})
    network = {
        key: state.get(key, "")
        for key in ("scanned_at", "dns_sd_scanned_at", "dns_sd_complete")
    }
    network["hosts"] = {
        address(ip): {
            "mac": "Hidden" if h.get("mac") else "",
            "ports": h.get("ports", []),
            "services": {},
        }
        for ip, h in state.get("hosts", {}).items()
    }
    network["reported"] = {
        str(index): event_type(message)
        for index, message in enumerate(state.get("reported", {}).values())
    }
    network["recent_events"] = [
        {
            "observed_at": e.get("observed_at", ""),
            "message": event_type(e.get("message", "")),
            "baseline": e.get("baseline", False),
        }
        for e in state.get("recent_events", [])
    ]
    network["advertisement_details"] = [
        {
            "host": name(ad.get("host")),
            "name": "Hidden",
            "service": f"_service._{protocol(ad)}" if protocol(ad) else "Hidden",
            "port": ad.get("port"),
            "addresses": [address(ip) for ip in ad.get("addresses", [])],
        }
        for ad in advertisements(state)
    ]
    view = data.get("cloudflare_view", {})
    projected_view = {}
    if view:
        projected_view = {
            "audited_at": view.get("audited_at"),
            "scope": {},
            "hosts": [],
        }
        for item in view.get("hosts", []):
            projected_view["hosts"].append(
                {
                    "hostname": name(item["hostname"]),
                    "lifecycle": item["lifecycle"],
                    "declared": item.get("declared", False),
                    **{
                        key: "Hidden" if item.get(key) else ""
                        for key in (
                            "claimed_app_id",
                            "claimed_dns_id",
                            "claimed_tunnel_route",
                        )
                    },
                    "access_app_ids": ["Hidden"] * len(item.get("access_app_ids", [])),
                    "dns_record_ids": ["Hidden"] * len(item.get("dns_record_ids", [])),
                    "tunnel_routes": item.get("tunnel_routes", 0),
                }
            )
    timers = data.get("orphan_observations", {})
    matching = timers.get("scope") == view.get("scope")
    return {
        "hosts": hosts,
        "network_state": network,
        "cloudflare_view": projected_view,
        "cloudflare_view_status": data.get("cloudflare_view_status", {}),
        "orphan_observations": {
            "scope": {},
            "missing": (
                {
                    name(host): {k: timer.get(k, "") for k in ("first", "last")}
                    for host, timer in timers.get("missing", {}).items()
                }
                if matching
                else {}
            ),
        },
        "managed_hosts": [name(host) for host in data.get("managed_hosts", [])],
        "scanned_at": data.get("scanned_at", ""),
        "warnings": data.get("warnings", []),
        "diffs": [
            {
                **{key: entry[key] for key in ("field", "severity")},
                "hostname": name(entry["hostname"]),
                "ipv4": address(entry["ipv4"]),
                "expected": "Hidden",
                "observed": "Hidden",
            }
            for entry in data.get("diffs", [])
        ],
        "private_metadata": False,
    }


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
