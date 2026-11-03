"""Read-only detail views built exclusively from sanitized/saved observations."""

import ipaddress
import re
from collections import defaultdict
from datetime import UTC, datetime
from html import escape

from docker_inventory import address_key


def _discovery_mac(record):
    """Only link-layer reply sources provide a MAC for correlation."""
    if record.get("source") not in ("Neighbor cache", "ARP reply", "NDP reply"):
        return ""
    found = re.search(
        r"(?i)(?<![0-9a-f:])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f:])",
        str(record.get("detail", "")),
    )
    return found.group().lower() if found else ""


def _discovery_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        return ""


def discovery_view(data, table):
    """Present related evidence together without declaring device ownership.

    Competing address/MAC claims stay visible as ambiguous observations.
    No guesses based on IPv6 prefixes, names, or interface proximity.
    """
    state = data.get("network_state", {}).get("supplemental", {})
    records = state.get("records", [])
    by_address = defaultdict(set)
    by_mac = defaultdict(set)
    devices = data.get("discovery_devices", [])
    for index, device in enumerate(devices):
        addresses = [device.get("ipv4"), device.get("ipv6")]
        addresses += device.get("additional_ipv4", []) or []
        for value in addresses:
            address = _discovery_ip(value)
            if address:
                by_address[address].add(index)
        macs = [device.get("mac")]
        macs += device.get("observed_macs", []) or []
        interface_macs = device.get("interface_macs", {}) or {}
        if isinstance(interface_macs, dict):
            macs.extend(interface_macs.values())
        for value in macs:
            if isinstance(value, str) and re.fullmatch(
                r"(?i)(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", value
            ):
                by_mac[value.lower()].add(index)

    # Resolve MAC evidence across interfaces for the same address, but never
    # allow two different MAC claims to silently collapse into one identity.
    seen_macs = defaultdict(set)
    for record in records:
        ip = _discovery_ip(record.get("ip"))
        mac = _discovery_mac(record)
        if ip and mac:
            seen_macs[ip].add(mac)

    groups = {}
    for record in records:
        ip = _discovery_ip(record.get("ip"))
        macs = seen_macs[ip] if ip else set()
        mac = next(iter(macs)) if len(macs) == 1 else ""
        address_ids = by_address[ip] if ip else set()
        mac_ids = by_mac[mac] if mac else set()
        conflict = (
            len(macs) > 1
            or len(address_ids) > 1
            or len(mac_ids) > 1
            or bool(address_ids and mac_ids and address_ids.isdisjoint(mac_ids))
        )
        if conflict:
            key = ("ambiguous", ip)
            label = "Conflicting identity: " + ip
        elif address_ids or mac_ids:
            device = devices[next(iter(address_ids or mac_ids))]
            key = ("inventory", device.get("hostname", ""), device.get("ipv4", ""))
            label = device.get("hostname") or device.get("ipv4") or "Inventory device"
        elif mac:
            key = ("mac", mac)
            label = "Unassigned MAC: " + mac
        elif ip:
            key = ("ip", ip)
            label = "Unassigned address: " + ip
        else:
            # LLDP peers without management IPs are distinct link observations.
            key = (
                "link",
                str(record.get("interface", "")),
                str(record.get("detail", "")),
            )
            label = "Link neighbour: " + str(record.get("interface", ""))
        group = groups.setdefault(
            key, {"label": str(label), "addresses": set(), "macs": set(), "rows": []}
        )
        if ip:
            group["addresses"].add(ip)
        group["macs"].update(macs)
        group["rows"].append(
            [
                ip,
                record.get("interface", ""),
                record.get("source", ""),
                record.get("detail", ""),
                state.get("observed_at", ""),
            ]
        )

    content = (
        "<p>Related link-layer, probe and service observations are grouped for review. "
        "Inventory and MAC matches are evidence, not verified ownership. "
        "Stale cache entries do not prove reachability; OS matches are estimates.</p>"
    )
    content += "".join(
        f"<p>{escape(str(warning))}</p>" for warning in state.get("warnings", [])
    )
    if not groups:
        return content + "<p>No supplemental observations in the saved scan.</p>"
    for key, group in sorted(
        groups.items(),
        key=lambda item: (item[0][0] != "inventory", item[1]["label"].lower()),
    ):
        caption = group["label"] + f" · {len(group['rows'])} evidence records"
        content += (
            '<details class="card" data-group="1" open><summary>'
            + escape(caption)
            + "</summary>"
        )
        if group["addresses"]:
            content += (
                '<p class="muted">Addresses: '
                + escape(", ".join(sorted(group["addresses"], key=address_key)))
                + "</p>"
            )
        if group["macs"]:
            content += (
                '<p class="muted">Observed MACs: '
                + escape(", ".join(sorted(group["macs"])))
                + "</p>"
            )
        if key[0] == "ambiguous":
            content += (
                "<p>Conflicting or ambiguous identity evidence: no device match "
                "is asserted. Review all sources and interfaces below.</p>"
            )
        content += table(
            ["IP", "Interface", "Source", "Evidence", "Collected at"],
            group["rows"],
        )
        content += "</details>"
    return content


def event_type(message):
    for prefix, label in [
        ("NEW DEVICE", "New device"),
        ("NEW PORT", "New port"),
        ("NEW DNS-SD", "New DNS-SD service"),
        ("CHANGED MAC", "Changed MAC"),
        ("CHANGED IP", "Changed IP"),
    ]:
        if str(message).startswith(prefix) or message == label:
            return label
    return "Observation"


def advertisements(state):
    """Read old snapshots without inventing addresses or detection evidence."""
    if state.get("advertisement_details"):
        return state["advertisement_details"]
    result = []
    for raw in state.get("advertisements", []):
        parts = raw.rsplit("|", 2)
        if len(parts) == 3 and parts[2].isdigit():
            result.append(
                {
                    "host": parts[0],
                    "service": parts[1],
                    "name": "",
                    "port": int(parts[2]),
                    "addresses": [],
                }
            )
    return result


def protocol(ad):
    match = re.search(r"\._(tcp|udp)(?:\.|$)", ad.get("service", ""))
    return match[1] if match else ""


def service_rows(hosts, state):
    """One row per endpoint/transport, keeping advertisements separate from probes."""
    ads = advertisements(state)
    rows = []
    attached = set()
    for host in hosts:
        ip = host["ipv4"]
        observed = state.get("hosts", {}).get(ip, {})
        ports = set(host.get("ports", [])) | set(host.get("observed_ports", []))
        matching = [
            (index, ad)
            for index, ad in enumerate(ads)
            if ({ip, host.get("ipv6", "")} - {""}) & set(ad.get("addresses", []))
        ]
        ports.update(
            f"{protocol(ad)}/{ad['port']}" for _, ad in matching if protocol(ad)
        )
        for port in sorted(
            ports,
            key=lambda p: (
                p.split("/")[0],
                int(p.split("/")[-1]) if p.split("/")[-1].isdigit() else 0,
            ),
        ):
            parts = port.split("/")
            if len(parts) != 2:
                continue
            transport, number = parts
            announcements = []
            for index, ad in matching:
                if protocol(ad) == transport and str(ad["port"]) == number:
                    announcements.append(
                        f"{ad.get('name', '')} {ad['service']} ({ad['host']})".strip()
                    )
                    attached.add(index)
            details = observed.get("services", {}).get(port, {})
            service = " ".join(
                str(details.get(k, "")) for k in ("name", "product", "version")
            ).strip()
            if service:
                service += (
                    " (probed)"
                    if details.get("method") == "probed"
                    else " (port-name hint)"
                )
            evidence = ", ".join(host.get("port_sources", {}).get(port, []))
            if not evidence and port in host.get("ports", []):
                evidence = "Static inventory"
            status = (
                "open (scan)"
                if port in host.get("observed_ports", [])
                else (
                    "declared / inferred"
                    if port in host.get("ports", [])
                    else "advertised only"
                )
            )
            rows.append(
                [
                    host["hostname"],
                    ip,
                    number,
                    transport,
                    status,
                    service or "Not detected",
                    "; ".join(announcements),
                    evidence,
                ]
            )
    for index, ad in enumerate(ads):
        if index not in attached:
            rows.append(
                [
                    ad.get("host", ""),
                    ", ".join(ad.get("addresses", [])),
                    ad.get("port", ""),
                    protocol(ad),
                    "advertised only",
                    "Not detected",
                    f"{ad.get('name', '')} {ad.get('service', '')}".strip(),
                    "DNS-SD",
                ]
            )
    return sorted(
        rows,
        key=lambda r: (
            address_key(r[1]),
            r[0],
            str(r[3]),
            int(r[2]) if str(r[2]).isdigit() else 0,
        ),
    )


def ports_view(data, table):
    state = data.get("network_state", {})
    stamp = escape(state.get("scanned_at", "") or "not available")
    ads_stamp = escape(state.get("dns_sd_scanned_at", "") or "unknown (older snapshot)")
    notice = f'<p class="muted">Network scan: {stamp}. DNS-SD last successful observation: {ads_stamp}. Service names from port tables are hints; only probed names are labelled probed.</p>'
    if state.get("dns_sd_complete") is False:
        notice += '<p class="muted">Latest DNS-SD observation was incomplete; showing previous advertisements.</p>'
    return notice + table(
        [
            "Host",
            "IP",
            "Port",
            "Protocol",
            "Evidence status",
            "Detected service",
            "DNS-SD announcements",
            "Port sources",
        ],
        service_rows(data["hosts"], state),
    )


def drift_view(data, table):
    state = data.get("network_state", {})
    active = [
        [event_type(message), message] for message in state.get("reported", {}).values()
    ]
    history = state.get("recent_events", [])
    recent = [
        [
            item.get("observed_at", ""),
            event_type(item.get("message", "")),
            item.get("message", ""),
            (
                "Initial baseline (not notified)"
                if item.get("baseline")
                else "New finding"
            ),
        ]
        for item in reversed(history)
    ]
    content = '<p class="muted">Observed findings, not Discord delivery receipts. History retains the latest 200 findings; active drift is shown separately.</p>'
    content += f'<p class="muted">Latest network scan: {escape(state.get("scanned_at", "") or "not available")}</p>'
    content += "<h2>Current device / port drift</h2>" + (
        table(["Type", "Finding"], active)
        if active
        else "<p>No active device or port drift in the saved snapshot.</p>"
    )
    content += "<h2>Recent observations</h2>" + (
        table(["Observed at", "Type", "Finding", "Context"], recent)
        if recent
        else "<p>No saved observation history yet. History begins with the next network scan after this upgrade.</p>"
    )
    return content


def cloudflare_view(data, table):
    view = data.get("cloudflare_view", {})
    status = data.get("cloudflare_view_status", {})
    if not view:
        return (
            "<p>No complete Cloudflare audit snapshot yet. Managed/orphaned/unmanaged classifications are unavailable until the next controller audit.</p><h2>Local claims (classification unavailable)</h2>"
            + table(
                ["Hostname", "Ownership"],
                [[h, "Claim recorded"] for h in data.get("managed_hosts", [])],
            )
        )
    stamp = view.get("audited_at", "")
    try:
        age = datetime.now(UTC) - datetime.fromisoformat(stamp)
        stale = age.total_seconds() > 8 * 3600 or age.total_seconds() < 0
    except (ValueError, TypeError):
        stale = True
    content = f'<p class="muted">Last complete read-only Cloudflare audit: {escape(stamp)}. This is a snapshot; classification never authorizes cleanup.</p>'
    if not status.get("ok") or status.get("attempted_at") != stamp:
        content += "<p>Latest refresh failed, is incomplete, or has no matching completion marker. Showing the last complete snapshot.</p>"
    if stale:
        content += (
            "<p>Snapshot is stale (older than eight hours or invalid timestamp).</p>"
        )
    timers = data.get("orphan_observations", {})
    missing = (
        timers.get("missing", {}) if timers.get("scope") == view.get("scope") else {}
    )
    rows = []
    for item in view.get("hosts", []):
        timer = (
            missing.get(item["hostname"], {})
            if item.get("lifecycle") == "orphaned"
            else {}
        )
        claimed = []
        for key, label in [
            ("claimed_app_id", "Access"),
            ("claimed_dns_id", "DNS"),
            ("claimed_tunnel_route", "Route"),
        ]:
            if item.get(key):
                claimed.append(f"{label}: {item[key]}")
        rows.append(
            [
                item["hostname"],
                item["lifecycle"],
                "yes" if item.get("declared") else "no",
                "; ".join(claimed) or "No claim",
                ", ".join(item.get("access_app_ids", [])),
                ", ".join(item.get("dns_record_ids", [])),
                item.get("tunnel_routes", 0),
                timer.get("first", ""),
                timer.get("last", ""),
            ]
        )
    content += '<p class="muted">Declared / unclaimed services exist in Compose but are not owned. Absence timestamps are observations only, not cleanup eligibility or a deletion countdown.</p>'
    return content + table(
        [
            "Hostname",
            "Lifecycle",
            "Declared",
            "Claimed resources",
            "Live Access IDs",
            "Live DNS IDs",
            "Live routes",
            "First absent",
            "Last absent",
        ],
        rows,
    )
