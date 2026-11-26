"""Allowlisted presentation snapshot; never an input to reconciliation/cleanup."""

import ipaddress
import json
import os
import re
import tempfile
from datetime import UTC, datetime
from urllib.parse import urlsplit

from cloudflare_desired import HOST
from cloudflare_live_diff import ordered_policy_ids
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
            row["reason"] = reason if reason in BLOCK_REASONS else "validation failed"
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
    docker = report.get("docker_dns", {})
    for item in docker.get("findings", []):
        add(
            "docker_dns", item, ("hostname", "status", "category", "expected", "actual")
        )
    internal = report.get("unaccounted_ygg_dns", {})
    for item in internal.get("findings", []):
        add("unaccounted_dns", item, ("hostname", "type", "category", "proxied"))
    for item in internal.get("retained", {}).get("missing", []):
        add("retained_missing", item, ("hostname", "type"))
    rows.sort(key=lambda row: (row["section"], row.get("hostname", "")))
    return {
        "version": 1,
        "static_dns_enabled": static.get("enabled") is True,
        "docker_dns_enabled": docker.get("enabled") is True,
        "internal_dns_enabled": internal.get("enabled") is True,
        "total_findings": len(rows),
        "truncated": len(rows) > MAX_AUDIT_ROWS,
        "findings": rows[:MAX_AUDIT_ROWS],
    }


def record_set(rows):
    """Bound a section while retaining its original total."""
    return {
        "total": len(rows),
        "truncated": len(rows) > MAX_AUDIT_ROWS,
        "items": rows[:MAX_AUDIT_ROWS],
    }


def safe_dns_name(value):
    if isinstance(value, str) and re.fullmatch(r"[a-zA-Z0-9_*.-]{1,253}", value):
        return value.lower().rstrip(".")
    return ""


def safe_origin(value):
    """Expose only a scheme and host/port, never userinfo, paths or queries."""
    if not isinstance(value, str):
        return {}
    if value == "http_status:404":
        return {"origin_scheme": "http_status", "origin_status": 404}
    try:
        url = urlsplit(value)
        host = url.hostname
        if (
            url.scheme not in {"http", "https", "tcp", "ssh", "rdp", "smb"}
            or not host
            or url.username is not None
            or url.password is not None
        ):
            return {}
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            if not safe_dns_name(host):
                return {}
        return {
            "origin_scheme": url.scheme,
            "origin_host": host,
            "origin_port": url.port,
        }
    except ValueError:
        return {}


def configuration_projection(
    desired,
    apps,
    policies,
    external_dns,
    internal_dns,
    ingress,
    tunnel_id,
    *,
    internal_dns_collected,
):
    """Read-only configuration evidence; policy rules and credentials never leave."""
    decisions = {
        item["id"]: item.get("decision")
        for item in policies
        if isinstance(item.get("id"), str)
    }

    def decision_list(ids):
        return [
            (
                decisions.get(identifier)
                if decisions.get(identifier)
                in {"allow", "deny", "bypass", "non_identity"}
                else "unknown"
            )
            for identifier in ids[:64]
        ]

    by_host = {}
    for app in apps:
        hostname = safe_dns_name(app.get("domain"))
        if hostname:
            by_host.setdefault(hostname, []).append(app)
    access = []
    for hostname in sorted(set(by_host) | set(desired)):
        matches = by_host.get(hostname, [])
        expected = desired.get(hostname)
        actual = None
        status = "unmanaged" if expected is None else "missing"
        if len(matches) > 1:
            status = "ambiguous"
        elif matches:
            if matches[0].get("type") != "self_hosted":
                status = "unsupported_app_type"
            else:
                try:
                    actual = ordered_policy_ids(matches[0])
                except (TypeError, ValueError):
                    status = "invalid_policy_order"
                else:
                    if expected is not None:
                        status = "matched" if actual == expected else "mismatch"
        row = {
            "hostname": hostname,
            "declared": expected is not None,
            "app_count": len(matches),
            "status": status,
            "expected_decisions": (
                decision_list(expected) if expected is not None else None
            ),
            "observed_decisions": decision_list(actual) if actual is not None else None,
            "policy_list_truncated": len(expected or []) > 64 or len(actual or []) > 64,
        }
        access.append(row)

    dns = []
    for zone, records in (("external", external_dns), ("internal", internal_dns)):
        for item in records:
            name = safe_dns_name(item.get("name"))
            kind = item.get("type")
            if (
                not name
                or not isinstance(kind, str)
                or not re.fullmatch(r"[A-Z][A-Z0-9]{0,9}", kind)
            ):
                continue
            row = {"hostname": name, "zone": zone, "type": kind}
            if isinstance(item.get("proxied"), bool):
                row["proxied"] = item["proxied"]
            content = item.get("content")
            if kind in {"A", "AAAA"}:
                try:
                    row["address"] = str(ipaddress.ip_address(content))
                except ValueError:
                    pass
            elif zone == "external" and kind == "CNAME" and isinstance(content, str):
                row["matches_configured_tunnel"] = (
                    content.lower().rstrip(".")
                    == tunnel_id.lower() + ".cfargotunnel.com"
                )
            dns.append(row)
    dns.sort(key=lambda row: (row["zone"], row["hostname"], row["type"]))

    routes = []
    for index, item in enumerate(ingress):
        hostname = safe_dns_name(item.get("hostname"))
        row = {
            "hostname": hostname,
            "precedence": index + 1,
            "has_path_match": bool(item.get("path")),
            "declared": hostname in desired,
            **safe_origin(item.get("service")),
        }
        routes.append(row)
    return {
        "version": 1,
        "internal_dns_collected": internal_dns_collected,
        "access": record_set(access),
        "dns": record_set(dns),
        "tunnel": record_set(routes),
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
