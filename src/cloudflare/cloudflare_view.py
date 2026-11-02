"""Allowlisted presentation snapshot; never an input to reconciliation/cleanup."""

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
