"""Explicit, persistent ownership and manual-only Cloudflare orphan retirement.

Only an explicitly claimed or positively created hostname is owned. Never
infer ownership from an existing Cloudflare application, DNS record or route.
"""

import copy
import fcntl
import hashlib
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path

from cloudflare_api import checked_id, checked_tunnel_id
from cloudflare_desired import HOST, compose_inventory, discover
from cloudflare_live_diff import ordered_policy_ids, validate_ingress
from cloudflare_write_api import validate_tunnel_config

REGISTRY_FILE = "managed-hosts.json"
VERSION = 1
MAX_REGISTRY_BYTES = 1024 * 1024
TRAEFIK_SERVICE = "https://traefik.ygg.nu:443"


class OwnershipError(ValueError):
    """An ownership claim or cleanup plan has failed its safety checks."""


def digest(value):
    """Stable, non-secret approval fingerprint for a validated plan."""
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:16]


def scope(account, zone, tunnel):
    """Bind every ownership record to one exact Cloudflare resource scope."""
    return {
        "account": checked_id(account, "account ID"),
        "external_zone": checked_id(zone, "external zone ID"),
        "tunnel": checked_tunnel_id(tunnel),
    }


def empty_registry(bound):
    return {"version": VERSION, "scope": bound, "hosts": {}}


def registry_path(data):
    """Reject a symlinked ownership file rather than following it."""
    path = Path(data) / REGISTRY_FILE
    if path.is_symlink():
        raise OwnershipError("Ownership registry must not be a symlink")
    return path


def load_registry(data, bound):
    """Missing state means zero ownership. Corrupt or cross-scope state blocks."""
    path = registry_path(data)
    if not path.exists():
        return empty_registry(bound)
    if path.stat().st_size > MAX_REGISTRY_BYTES:
        raise OwnershipError("Ownership registry exceeds size limit")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as error:
        raise OwnershipError("Invalid ownership registry") from error
    if (
        not isinstance(payload, dict)
        or payload.get("version") != VERSION
        or payload.get("scope") != bound
        or not isinstance(payload.get("hosts"), dict)
        or any(not HOST.fullmatch(host) for host in payload["hosts"])
    ):
        raise OwnershipError("Ownership registry has invalid version, hosts or scope")
    return payload


@contextmanager
def locked_registry(data):
    """Serialize claims and cleanups and prevent registry update races."""
    directory = Path(data)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = directory / ".managed-hosts.lock"
    if lock.is_symlink():
        raise OwnershipError("Ownership lock must not be a symlink")
    descriptor = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "r+") as file:
        fcntl.flock(file, fcntl.LOCK_EX)
        yield


def save_registry(data, payload):
    """Atomically replace private ownership state; never modify Compose source."""
    path = registry_path(data)
    content = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if len(content.encode("utf-8")) > MAX_REGISTRY_BYTES:
        raise OwnershipError("Ownership registry exceeds size limit")
    handle, temporary = tempfile.mkstemp(prefix=".managed-hosts-", dir=data)
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, "w", encoding="utf-8") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def desired_hosts(client, root, account):
    """Validate the complete Compose-derived desired inventory before claiming."""
    wanted, errors = discover(compose_inventory(root), client.list_policies(account))
    if errors or not wanted:
        raise OwnershipError("Compose desired inventory is missing or invalid")
    return wanted


def live_resources(client, bound):
    """Read current identities, preserving duplicates and complete Tunnel config."""
    applications = client.list_applications(bound["account"])
    dns = client.list_dns(bound["external_zone"])
    remote = client.tunnel_configuration(bound["account"], bound["tunnel"])
    config = validate_tunnel_config(remote["config"])
    validate_ingress(config["ingress"])
    return applications, dns, config


def candidates(hostname, applications, dns, config):
    """Keep every matching object; ambiguity must block any cleanup."""
    return (
        [app for app in applications if app.get("domain") == hostname],
        [record for record in dns if record.get("name") == hostname],
        [
            entry
            for entry in config["ingress"][:-1]
            if entry.get("hostname") == hostname
        ],
    )


def full_app(client, account, entry):
    """Fetch policy details without trusting incomplete Access list responses."""
    identifier = checked_tunnel_id(entry["id"])
    return client.get_application(account, identifier)


def claimed_identity(client, bound, hostname, resources, wanted):
    """Require a complete, healthy public endpoint before claiming ownership."""
    applications, dns, config = resources
    apps, records, routes = candidates(hostname, applications, dns, config)
    if len(apps) != 1 or len(records) != 1 or len(routes) != 1:
        raise OwnershipError(f"{hostname}: Access, DNS and ingress must each be unique")
    app = full_app(client, bound["account"], apps[0])
    record, route = records[0], routes[0]
    target = bound["tunnel"].lower() + ".cfargotunnel.com"
    if (
        app.get("domain") != hostname
        or app.get("type") != "self_hosted"
        or ordered_policy_ids(app) != wanted
        or record.get("type") != "CNAME"
        or record.get("proxied") is not True
        or record.get("content", "").lower().rstrip(".") != target
        or route.get("service") != TRAEFIK_SERVICE
        or route.get("path")
        or (route.get("originRequest") or {}).get("access")
    ):
        raise OwnershipError(f"{hostname}: live endpoint differs from expected state")
    return {
        "app_id": checked_tunnel_id(app["id"]),
        "policies": wanted,
        "dns_id": checked_id(record["id"], "DNS record ID"),
        "dns_target": target,
        "route": copy.deepcopy(route),
    }


def claim(client, root, data, bound, hostname):
    """Opt in one currently declared hostname; never auto-adopt legacy resources."""
    if not HOST.fullmatch(hostname):
        raise OwnershipError("Not a managed external hostname")
    with locked_registry(data):
        registry = load_registry(data, bound)
        wanted = desired_hosts(client, root, bound["account"])
        if hostname not in wanted:
            raise OwnershipError(
                "Only a hostname still declared in Compose can be claimed"
            )
        identity = claimed_identity(
            client, bound, hostname, live_resources(client, bound), wanted[hostname]
        )
        existing = registry["hosts"].get(hostname)
        if existing is not None and existing != identity:
            raise OwnershipError("Already claimed with different resource identities")
        registry["hosts"][hostname] = identity
        save_registry(data, registry)
    return identity


def summarize(registry, desired, applications, dns, config):
    """Classify external resources without ever proposing a deletion."""
    owned = registry["hosts"]
    present = set(desired)
    observed = set()
    for resource in applications:
        observed.add(resource.get("domain"))
    for resource in dns:
        observed.add(resource.get("name"))
    for route in config["ingress"][:-1]:
        observed.add(route.get("hostname"))
    extra = sorted(
        host
        for host in observed
        if isinstance(host, str)
        and HOST.fullmatch(host)
        and host not in present
        and host not in owned
    )
    orphaned = []
    for host in sorted(owned.keys() - present):
        apps, records, routes = candidates(host, applications, dns, config)
        orphaned.append(
            {
                "hostname": host,
                "access_apps": len(apps),
                "external_dns": len(records),
                "tunnel_routes": len(routes),
            }
        )
    return {
        "managed": len(owned.keys() & present),
        "orphaned": orphaned,
        "unmanaged": extra,
    }


def print_summary(report):
    """Show managed, orphaned and unmanaged counts without authorizing deletion."""
    lifecycle = report.get("lifecycle", {})
    if not lifecycle:
        return
    print(
        "Cloudflare lifecycle (review only): "
        f"{lifecycle['managed']} managed, "
        f"{len(lifecycle['orphaned'])} orphaned, "
        f"{len(lifecycle['unmanaged'])} unmanaged"
    )
    for orphan in lifecycle["orphaned"]:
        print(
            f"  ! ORPHAN {orphan['hostname']}: "
            f"Access={orphan['access_apps']} DNS={orphan['external_dns']} "
            f"Tunnel={orphan['tunnel_routes']}"
        )
    for hostname in lifecycle["unmanaged"]:
        print(f"  ~ UNMANAGED {hostname}")


def review_orphan(client, root, data, bound, hostname):
    """Return a fingerprint bound to actual live resources and ownership state."""
    if not HOST.fullmatch(hostname):
        raise OwnershipError("Invalid hostname")
    registry = load_registry(data, bound)
    if hostname not in registry["hosts"]:
        raise OwnershipError("Hostname has not been explicitly claimed by Yggflare")
    wanted = desired_hosts(client, root, bound["account"])
    if hostname in wanted:
        raise OwnershipError("Hostname is still declared in Compose")
    entry = registry["hosts"][hostname]
    apps, dns, config = live_resources(client, bound)
    matches = candidates(hostname, apps, dns, config)
    access, records, routes = matches
    if any(len(items) > 1 for items in matches):
        raise OwnershipError("Duplicate Cloudflare resources: manual review required")
    if access:
        app = full_app(client, bound["account"], access[0])
        if (
            app.get("id") != entry["app_id"]
            or app.get("domain") != hostname
            or app.get("type") != "self_hosted"
            or ordered_policy_ids(app) != entry["policies"]
        ):
            raise OwnershipError("Access application identity or policies changed")
    if records:
        record = records[0]
        if (
            record.get("id") != entry["dns_id"]
            or record.get("type") != "CNAME"
            or record.get("proxied") is not True
            or record.get("content", "").lower().rstrip(".") != entry["dns_target"]
        ):
            raise OwnershipError("DNS identity or target changed")
    if routes and routes[0] != entry["route"]:
        raise OwnershipError("Tunnel ingress route changed")
    if not access and not records and not routes:
        steps = ["forget_cleaned_ownership"]
    else:
        steps = [
            name
            for name, found in (
                ("delete_dns_cname", records),
                ("remove_tunnel_ingress", routes),
                ("delete_access_app", access),
            )
            if found
        ]
    plan = {
        "scope": bound,
        "hostname": hostname,
        "identity": entry,
        "steps": steps,
        "tunnel_config": config,
    }
    return plan, digest(plan)



def require_absent_in_mounted_source(client, bound, hostname):
    """Refuse deletion if the live merged Compose source is missing or redeclared."""
    live_source = Path(os.environ.get("YGGFLARE_SOURCE", "/compose-source"))
    if not live_source.is_dir():
        raise OwnershipError("Cannot verify currently mounted Compose source")
    if hostname in desired_hosts(client, live_source, bound["account"]):
        raise OwnershipError("Hostname has reappeared in the live Compose source")


def retire(client, root, data, bound, hostname, approval):
    """One-host explicit cleanup: DNS first, then Tunnel, Access last."""
    if not isinstance(approval, str) or len(approval) != 16:
        raise OwnershipError("A reviewed 16-character fingerprint is required")
    # Use the same process lock as normal Cloudflare writes to prevent overlap.
    home_lock = Path.home() / "cloudflare" / ".cloudflare-manage.lock"
    home_lock.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(home_lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+") as guard:
        fcntl.flock(guard, fcntl.LOCK_EX)
        with locked_registry(data):
            plan, actual = review_orphan(client, root, data, bound, hostname)
            if actual != approval:
                raise OwnershipError("Orphan plan changed: review a new fingerprint")
            steps = plan["steps"]
            require_absent_in_mounted_source(client, bound, hostname)
            if "delete_dns_cname" in steps:
                # Verify exact record identity against a fresh API read.
                record = client.get_dns_record(
                    bound["external_zone"], plan["identity"]["dns_id"]
                )
                if (
                    record.get("id") != plan["identity"]["dns_id"]
                    or record.get("name") != hostname
                    or record.get("type") != "CNAME"
                    or record.get("proxied") is not True
                    or record.get("content", "").lower().rstrip(".")
                    != plan["identity"]["dns_target"]
                ):
                    raise OwnershipError("DNS changed immediately before deletion")
                client.delete_dns_record(
                    bound["external_zone"], plan["identity"]["dns_id"]
                )
            if "remove_tunnel_ingress" in steps:
                require_absent_in_mounted_source(client, bound, hostname)
                current = client.tunnel_configuration(
                    bound["account"], bound["tunnel"]
                )["config"]
                if current != plan["tunnel_config"]:
                    raise OwnershipError("Tunnel configuration changed before update")
                new_config = copy.deepcopy(current)
                new_config["ingress"] = [
                    route
                    for route in current["ingress"]
                    if route.get("hostname") != hostname
                ]
                validate_tunnel_config(new_config)
                validate_ingress(new_config["ingress"])
                client.put_tunnel_ingress(bound["account"], bound["tunnel"], new_config)
            if "delete_access_app" in steps:
                require_absent_in_mounted_source(client, bound, hostname)
                # DNS must be gone and ingress absent before removing protection.
                apps, dns, config = live_resources(client, bound)
                if (
                    candidates(hostname, apps, dns, config)[1:][0]
                    or candidates(hostname, apps, dns, config)[2]
                ):
                    raise OwnershipError("Route or DNS still present; retain Access")
                app = full_app(
                    client, bound["account"], {"id": plan["identity"]["app_id"]}
                )
                if (
                    app.get("id") != plan["identity"]["app_id"]
                    or app.get("domain") != hostname
                    or app.get("type") != "self_hosted"
                    or ordered_policy_ids(app) != plan["identity"]["policies"]
                ):
                    raise OwnershipError("Access changed immediately before deletion")
                client.delete_access_app(bound["account"], plan["identity"]["app_id"])
            require_absent_in_mounted_source(client, bound, hostname)
            apps, dns, config = live_resources(client, bound)
            if any(candidates(hostname, apps, dns, config)):
                raise OwnershipError("Incomplete cleanup; ownership retained for retry")
            registry = load_registry(data, bound)
            if registry["hosts"].get(hostname) != plan["identity"]:
                raise OwnershipError("Ownership registry changed during cleanup")
            del registry["hosts"][hostname]
            save_registry(data, registry)
    return steps
