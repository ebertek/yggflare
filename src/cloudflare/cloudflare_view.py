"""Allowlisted presentation snapshot; never an input to reconciliation/cleanup."""

import ipaddress
import json
import os
import tempfile
from datetime import UTC, datetime

from cloudflare_desired import HOST
from cloudflare_orphans import candidates


def timestamp():
    return datetime.now(UTC).isoformat()


def write_json(path, value):
    """Atomically replace private presentation state, never follow a symlink."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, name = tempfile.mkstemp(prefix=".view-", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as output:
            json.dump(value, output)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def project(registry, desired, applications, dns, config):
    """Export host classification and resource IDs, not raw API configuration."""
    observed = {a.get("domain") for a in applications} | {d.get("name") for d in dns}
    observed.update(r.get("hostname") for r in config.get("ingress", []))
    owned = registry["hosts"]
    hosts = (
        set(owned)
        | set(desired)
        | {h for h in observed if isinstance(h, str) and HOST.fullmatch(h)}
    )
    rows = []
    for host in sorted(hosts):
        apps, records, routes = candidates(host, applications, dns, config)
        claimed = owned.get(host)
        lifecycle = (
            ("managed" if host in desired else "orphaned")
            if claimed is not None
            else ("declared / unclaimed" if host in desired else "unmanaged")
        )
        rows.append(
            {
                "hostname": host,
                "lifecycle": lifecycle,
                "declared": host in desired,
                "claimed": claimed is not None,
                "claimed_app_id": str((claimed or {}).get("app_id", "")),
                "claimed_dns_id": str((claimed or {}).get("dns_id", "")),
                "claimed_tunnel_route": (claimed or {})
                .get("route", {})
                .get("hostname", ""),
                "access_app_ids": [str(a.get("id", "")) for a in apps],
                "dns_record_ids": [str(d.get("id", "")) for d in records],
                "tunnel_routes": len(routes),
            }
        )
    return {
        "version": 1,
        "audited_at": timestamp(),
        "scope": registry["scope"],
        "hosts": rows,
    }


# Bound the saved projection independently of MCP pagination.
MAX_AUDIT_ROWS = 2000
BLOCK_REASONS = frozenset(
    {
        "multiple Access apps",
        "Access app is not self_hosted",
        "Access app is missing its ordered policy list",
        "Unexpected Access policy representation",
        "Access policy lacks ID or integer precedence",
        "Access policy precedence is not consecutive from 1",
        "Duplicate Access policy IDs",
        "existing DNS records conflict with tunnel CNAME",
        "ambiguous Docker A records",
        "invalid Docker IPv4 value",
        "non-Docker address is protected",
        "declared companion A records are absent",
        "ambiguous A/CNAME records",
        "A record is proxied",
        "declared companion A records differ",
    }
)


def audit_projection(report):
    """Project findings, never raw policies, record payloads, IDs or write plans."""
    rows = []

    def add(section, item, fields):
        row = {"section": section}
        for key in fields:
            value = item.get(key)
            if isinstance(value, str):
                row[key] = value[:253]
            elif isinstance(value, bool):
                row[key] = value
        if "reason" in fields and item.get("reason"):
            reason = item["reason"]
            row["reason"] = (
                reason if reason in BLOCK_REASONS else "validation failed"
            )
        # Only numeric IP values may leave the DNS comparison.
        for key in ("expected", "actual", "before", "content"):
            if key not in fields:
                continue
            row.pop(key, None)
            try:
                row[key] = str(ipaddress.ip_address(item.get(key)))
            except ValueError:
                pass
        rows.append(row)

    for item in report.get("actions", []):
        add("proposed", item, ("hostname", "kind", "before", "content"))
    for item in report.get("blocked", []):
        add("blocked", item, ("hostname", "reason"))
    static = report.get("static_dns", {})
    for item in static.get("findings", []):
        add("static_dns", item, ("hostname", "status", "reason", "expected", "actual"))
    internal = report.get("unaccounted_ygg_dns", {})
    for item in internal.get("findings", []):
        add("unaccounted_dns", item, ("hostname", "type", "category", "proxied"))
    for item in internal.get("retained", {}).get("missing", []):
        add("retained_missing", item, ("hostname", "type"))
    rows.sort(key=lambda row: (row["section"], row.get("hostname", "")))
    return {
        "version": 1,
        "static_dns_enabled": static.get("enabled") is True,
        "internal_dns_enabled": internal.get("enabled") is True,
        "total_findings": len(rows),
        "truncated": len(rows) > MAX_AUDIT_ROWS,
        "findings": rows[:MAX_AUDIT_ROWS],
    }


def begin(data):
    """An interrupted or failed refresh leaves last-good data visibly unverified."""
    write_json(
        data / "cloudflare-view-status.json", {"ok": False, "attempted_at": timestamp()}
    )


def publish(data, view):
    write_json(data / "cloudflare-view.json", view)
    write_json(
        data / "cloudflare-view-status.json",
        {"ok": True, "attempted_at": view["audited_at"]},
    )
