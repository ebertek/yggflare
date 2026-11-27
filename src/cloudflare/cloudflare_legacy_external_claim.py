"""Explicit, fingerprint-approved adoption of one retired external endpoint."""

import argparse
import copy
import hmac
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from cloudflare_api import CloudflareClient, CloudflareError, checked_id, checked_tunnel_id
from cloudflare_credentials import api_token
from cloudflare_desired import HOST, UUID
from cloudflare_internal_cleanup import snapshot_digest
from cloudflare_internal_ownership import detail_fingerprint, unique_object
from cloudflare_internal_retirement import (
    checked_records,
    compose_evidence,
    docker_containers,
    mentions,
    normalized,
    runtime_evidence,
)
from cloudflare_legacy_internal_claim import APPROVAL, write_lock
from cloudflare_live_diff import ordered_policy_ids
from cloudflare_orphans import (
    AUTO_STATE,
    MAX_REGISTRY_BYTES,
    OwnershipError,
    claimed_identity,
    desired_hosts,
    digest,
    live_resources,
    load_registry,
    locked_registry,
    save_registry,
    scope,
)
from cloudflare_retained_dns import RETAINED, load_retained_dns
from cloudflare_static_dns import (
    INVENTORY,
    load_inventory_aliases,
    load_inventory_details,
)
from yggflare_config import cloudflare_settings, domain


def resolve_scope(client, settings):
    account = checked_id(settings["account_id"], "account ID")
    external = checked_id(client.zone_id(settings["external_zone"], account))
    internal = checked_id(client.zone_id(settings["internal_zone"], account))
    if external == internal or any(
        settings.get(key) and settings[key] != actual
        for key, actual in (
            ("external_zone_id", external),
            ("internal_zone_id", internal),
        )
    ):
        raise OwnershipError("Configured zone identity changed")
    tunnel = checked_tunnel_id(
        settings.get("tunnel_id")
        or client.tunnel_id(account, settings["tunnel_name"])
    )
    return scope(account, external, tunnel), internal


def overlaps(value, hostname):
    """Recognize exact, path-scoped, wildcard and subdomain destinations."""
    if not isinstance(value, str) or not value:
        raise OwnershipError("Invalid external destination evidence")
    parsed = urlsplit(value if "://" in value else "//" + value)
    name = parsed.hostname
    if not name:
        raise OwnershipError("Invalid external destination hostname")
    name = normalized(name)
    return (
        name == hostname
        or name.endswith("." + hostname)
        or (name.startswith("*.") and hostname.endswith(name[1:]))
    )


def app_domains(app):
    """Read all documented hostname representations, not just primary domain."""
    values = []
    if app.get("domain"):
        values.append(app["domain"])
    for key in ("self_hosted_domains", "destinations"):
        rows = app.get(key, [])
        if rows is None:
            rows = []
        if not isinstance(rows, list):
            raise OwnershipError("Invalid Access destinations")
        for row in rows:
            if key == "destinations":
                if not isinstance(row, dict):
                    raise OwnershipError("Invalid Access destination")
                if row.get("type") == "public":
                    values.append(row["uri"])
                elif row.get("type") not in ("private",):
                    raise OwnershipError("Unsupported Access destination type")
            else:
                values.append(row)
    return values


def exact_app(app, hostname, identifier):
    if (
        app.get("id") != identifier
        or app.get("type") != "self_hosted"
        or app.get("domain") != hostname
        or not all(value == hostname for value in app_domains(app))
        or any(row.get("type") != "public" for row in (app.get("destinations") or []))
    ):
        raise OwnershipError("Access application is not an exact single-host endpoint")


def assert_absent(client, root, bound, hostname):
    """Check all Compose and local Docker names plus private and literal references."""
    external_domain = domain("YGGFLARE_EXTERNAL_DOMAIN")
    internal_domain = domain("YGGFLARE_INTERNAL_DOMAIN")
    internal_name = hostname.split(".", 1)[0] + "." + internal_domain
    if hostname in desired_hosts(client, root, bound["account"]):
        raise OwnershipError("External hostname still declared")
    containers = docker_containers()
    for zone, candidate in (
        (external_domain, hostname),
        (internal_domain, internal_name),
    ):
        names, _, references = compose_evidence(root, zone)
        running, _ = runtime_evidence(containers, zone)
        if candidate in names or candidate in running:
            raise OwnershipError("External service name still present")
        if mentions(references, hostname, hostname):
            raise OwnershipError("External hostname referenced by Compose")
    if mentions(containers, hostname, hostname):
        raise OwnershipError("External hostname referenced by Docker runtime")
    hosts, _ = load_inventory_details(root / INVENTORY, required=True)
    aliases = load_inventory_aliases(root / INVENTORY)
    retained = load_retained_dns(root / RETAINED)
    if internal_name in hosts or internal_name in aliases or any(
        row["hostname"] == internal_name for row in retained
    ) or mentions(retained, hostname, hostname):
        raise OwnershipError("External hostname protected by private inventory")


def read_fresh_absence(client, bound, hostname):
    """Reject changes to the mounted source during each evidence collection."""
    from controller import snapshot

    with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
        root = snapshot(Path(first))
        before = snapshot_digest(root)
        assert_absent(client, root, bound, hostname)
        if snapshot_digest(snapshot(Path(second))) != before:
            raise OwnershipError("Compose or private inventory changed during review")


def inspect_resources(client, bound, internal, hostname):
    """Require exclusive resource ownership; block aliases and overlapping routes."""
    apps, external_dns, config = live_resources(client, bound)
    records = checked_records(external_dns)
    internal_dns = checked_records(client.list_dns(internal))
    app_matches = []
    seen = set()
    for listed in apps:
        identifier = checked_tunnel_id(listed["id"])
        if identifier in seen:
            raise OwnershipError("Duplicate Access application ID")
        seen.add(identifier)
        # List data may omit additional destinations. Hydrate self-hosted apps.
        app = (
            client.get_application(bound["account"], identifier)
            if listed.get("type") == "self_hosted"
            else listed
        )
        if app.get("id") != identifier:
            raise OwnershipError("Access list and detail identities differ")
        if any(overlaps(value, hostname) for value in app_domains(app)):
            exact_app(app, hostname, identifier)
            app_matches.append(app)
    dns_matches = []
    for row in records + internal_dns:
        name = normalized(row["name"])
        if row in records and name == hostname:
            dns_matches.append(row)
        elif overlaps(name, hostname) or mentions(
            [row.get("content"), row.get("data")], hostname, hostname
        ):
            raise OwnershipError("Overlapping DNS record or alias dependency")
    route_matches = []
    for route in config["ingress"][:-1]:
        name = route.get("hostname")
        if not name:
            raise OwnershipError("Unscoped Tunnel route prevents legacy adoption")
        if overlaps(name, hostname):
            if name != hostname:
                raise OwnershipError("Overlapping Tunnel route")
            route_matches.append(route)
        elif mentions(route, hostname, hostname):
            raise OwnershipError("Tunnel route depends on external hostname")
    if any(len(rows) > 1 for rows in (app_matches, dns_matches, route_matches)):
        raise OwnershipError("Ambiguous external endpoint resources")
    return app_matches, dns_matches, route_matches, config


def detail_dns(client, bound, record):
    identifier = checked_id(record["id"], "DNS record ID")
    detail = client.get(
        f"/zones/{bound['external_zone']}/dns_records/{identifier}"
    )["result"]
    if not isinstance(detail, dict) or any(
        record.get(field) != detail.get(field)
        for field in ("id", "name", "type", "content", "proxied", "ttl",
                      "comment", "tags", "settings", "modified_on")
    ):
        raise OwnershipError("External DNS list and exact detail differ")
    return detail


def inspect_identity(client, bound, internal, hostname):
    apps, records, routes, config = inspect_resources(
        client, bound, internal, hostname
    )
    if any(len(rows) != 1 for rows in (apps, records, routes)):
        raise OwnershipError("Legacy endpoint must have all three exact resources")
    app, record = apps[0], records[0]
    policies = ordered_policy_ids(app)
    reusable = client.list_policies(bound["account"])
    identifiers = [row["id"] for row in reusable]
    if (
        len(identifiers) != len(set(identifiers))
        or not all(UUID.fullmatch(policy) and policy in identifiers for policy in policies)
    ):
        raise OwnershipError("Legacy Access policy identity is not reusable")
    identity = claimed_identity(
        client, bound, hostname, (apps, records, config), policies
    )
    # claimed_identity fetches the app again; require its full detail to agree.
    if client.get_application(bound["account"], identity["app_id"]) != app:
        raise OwnershipError("Access details changed during legacy review")
    identity["legacy"] = {
        "internal_zone": internal,
        "app_hash": detail_fingerprint(app),
        "dns_hash": detail_fingerprint(detail_dns(client, bound, record)),
    }
    return identity


def verify_legacy(client, bound, hostname, identity, *,
                  dns_gone=False, route_gone=False, app_gone=False):
    """Revalidate legacy identity and visible dependencies throughout cleanup."""
    settings = cloudflare_settings()
    actual, internal = resolve_scope(client, settings)
    legacy = identity["legacy"]
    if actual != bound or internal != legacy["internal_zone"]:
        raise OwnershipError("Legacy endpoint scope changed")
    read_fresh_absence(client, bound, hostname)
    apps, records, routes, _ = inspect_resources(client, bound, internal, hostname)
    if (
        (dns_gone and records) or (route_gone and routes) or (app_gone and apps)
        or (not apps and (records or routes))
        or (not routes and records)
    ):
        raise OwnershipError("Legacy endpoint retirement ordering not verified")
    if apps and (
        apps[0]["id"] != identity["app_id"]
        or detail_fingerprint(apps[0]) != legacy["app_hash"]
    ):
        raise OwnershipError("Legacy Access application changed")
    if records and (
        records[0]["id"] != identity["dns_id"]
        or detail_fingerprint(detail_dns(client, bound, records[0])) != legacy["dns_hash"]
    ):
        raise OwnershipError("Legacy external DNS record changed")
    if routes and routes[0] != identity["route"]:
        raise OwnershipError("Legacy Tunnel route changed")


def protected_legacy_hosts(client, data, bound):
    """Blocked legacy observations must not advance automatic grace."""
    protected = set()
    registry = load_registry(data, bound)
    for hostname, entry in registry["hosts"].items():
        if "legacy" not in entry:
            continue
        try:
            verify_legacy(client, bound, hostname, entry)
        except (ValueError, CloudflareError, OSError, TypeError, KeyError, subprocess.SubprocessError):
            protected.add(hostname)
    return protected


def review_claim(client, data, settings, hostname):
    if not HOST.fullmatch(hostname):
        raise OwnershipError("Legacy claim requires an exact external hostname")
    bound, internal = resolve_scope(client, settings)
    registry = load_registry(data, bound)
    if hostname in registry["hosts"]:
        raise OwnershipError("External hostname already owned")
    read_fresh_absence(client, bound, hostname)
    identity = inspect_identity(client, bound, internal, hostname)
    if any(
        existing.get("app_id") == identity["app_id"]
        or existing.get("dns_id") == identity["dns_id"]
        for existing in registry["hosts"].values()
    ):
        raise OwnershipError("External endpoint ownership collision")
    read_fresh_absence(client, bound, hostname)
    if resolve_scope(client, settings) != (bound, internal) or inspect_identity(
        client, bound, internal, hostname
    ) != identity:
        raise OwnershipError("Legacy endpoint evidence changed")
    plan = {"action": "claim_retired_external", "scope": bound,
            "hostname": hostname, "identity": identity}
    return plan, digest(plan)


def reset_observation(data, bound, hostname):
    """Remove only this hostname's prior grace, retaining all unrelated observations."""
    path = Path(data) / AUTO_STATE
    if path.is_symlink():
        raise OwnershipError("Legacy observation file must not be a symlink")
    if not path.exists():
        return
    if not path.is_file() or path.stat().st_size > MAX_REGISTRY_BYTES:
        raise OwnershipError("Invalid external observation file")
    state = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    if (
        not isinstance(state, dict)
        or state.get("version") != 1
        or state.get("scope") != bound
        or not isinstance(state.get("missing"), dict)
    ):
        raise OwnershipError("Invalid external observation scope")
    if hostname not in state["missing"]:
        return
    del state["missing"][hostname]
    fd, temporary = tempfile.mkstemp(prefix=".legacy-observation-", dir=data)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        descriptor = os.open(data, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def apply_claim(client, data, settings, hostname, approval):
    if not isinstance(approval, str) or not APPROVAL.fullmatch(approval):
        raise OwnershipError("Legacy external claim requires a reviewed fingerprint")
    with write_lock(), locked_registry(data):
        plan, expected = review_claim(client, data, settings, hostname)
        if not hmac.compare_digest(approval, expected):
            raise OwnershipError("Legacy external plan changed")
        bound = plan["scope"]
        registry = load_registry(data, bound)
        if hostname in registry["hosts"]:
            raise OwnershipError("External hostname already owned")
        reset_observation(data, bound, hostname)
        registry["hosts"][hostname] = copy.deepcopy(plan["identity"])
        save_registry(data, registry)
    return plan["identity"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--approval")
    args = parser.parse_args()
    try:
        client = CloudflareClient(api_token())
        data = Path("/data")
        settings = cloudflare_settings()
        if args.approval is None:
            plan, token = review_claim(client, data, settings, args.hostname)
            # Do not publish raw route settings, Access policy selectors or DNS metadata.
            identity = plan["identity"]
            print(json.dumps({
                "hostname": args.hostname, "scope": plan["scope"],
                "dns_id": identity["dns_id"], "dns_target": identity["dns_target"],
                "app_id": identity["app_id"], "policy_ids": identity["policies"],
                "route_service": identity["route"]["service"],
                "detail_hashes": identity["legacy"], "approval": token,
            }, indent=2))
            print("No changes made. Approval permits subsequent guarded retirement.")
        else:
            apply_claim(client, data, settings, args.hostname, args.approval)
            print(f"Claimed retired external endpoint: {args.hostname}")
            print("No Cloudflare changes made; normal retirement safeguards apply.")
        return 0
    except (CloudflareError, ValueError, OSError, TypeError, KeyError,
            AttributeError, RuntimeError, subprocess.SubprocessError):
        print("ERROR: Legacy external claim blocked; review live evidence.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
