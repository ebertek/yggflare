"""Read-only live Cloudflare audit against merged Compose and Docker inventory.

Run from Pleiades with CLOUDFLARE_API_TOKEN exported. This command performs
GET requests only and does not use Terraform files, state, or local source repos.
"""

# Preserve established kebab-case CLI entry point filename.
# pylint: disable=invalid-name

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from cloudflare_api import CloudflareClient, CloudflareError, checked_id
from cloudflare_desired import compose_inventory, discover
from cloudflare_live_diff import DOCKER_NETWORK, compare_live
from cloudflare_retained_dns import RETAINED, load_retained_dns
from cloudflare_static_dns import (
    INVENTORY,
    compare_static_dns,
    load_inventory_aliases,
    load_inventory_details,
    plan_static_dns,
)
from cloudflare_unaccounted_dns import (
    audit_unaccounted_dns,
    declared_dns_names,
    print_unaccounted_summary,
)

CONTAINER_NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")


def docker_ipv4():
    """Read only unique container IPs on the managed Docker subnet."""
    ids = subprocess.check_output(["docker", "ps", "-q"], text=True, timeout=30).split()
    if not ids:
        return {}
    containers = json.loads(
        subprocess.check_output(["docker", "inspect", *ids], text=True, timeout=30)
    )
    result = {}
    for container in containers:
        name = container.get("Name", "").lstrip("/")
        if not CONTAINER_NAME.fullmatch(name):
            continue
        networks = container.get("NetworkSettings", {}).get("Networks") or {}
        addresses = set()
        for network in networks.values():
            address = network.get("IPAddress")
            if not address:
                continue
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError:
                continue
            if parsed in DOCKER_NETWORK:
                addresses.add(str(parsed))
        if len(addresses) == 1:
            result[name] = next(iter(addresses))
    return result


def hydrate_apps(client, account_id, apps):
    """Read individual apps if list responses omit their policy arrays."""
    result = []
    for app in apps:
        if app.get("type") != "self_hosted" or isinstance(app.get("policies"), list):
            result.append(app)
            continue
        identifier = app.get("id")
        if not identifier:
            raise CloudflareError("An Access application has no ID")
        result.append(client.get_application(account_id, identifier))
    return result


def run_audit(
    client, root, settings, skip_docker=False
):  # pylint: disable=too-many-locals
    """Query Cloudflare, validate reusable policies, and return pure drift."""
    # Optional during initial rollout; set static_dns_required after private sync.
    static_hosts, static_companions = (
        (None, {})
        if skip_docker
        else load_inventory_details(
            root / INVENTORY, required=settings.get("static_dns_required", False)
        )
    )
    account = checked_id(settings["account_id"], "account ID")
    ebi = settings.get("ebi_zone_id") or client.zone_id(settings["ebi_zone"], account)
    ygg = settings.get("ygg_zone_id") or client.zone_id(settings["ygg_zone"], account)
    tunnel_id = settings.get("tunnel_id") or client.tunnel_id(
        account, settings["tunnel_name"]
    )
    policies = client.list_policies(account)
    if not policies:
        raise CloudflareError("No reusable Access policies returned")
    compose_services = compose_inventory(root)
    desired, errors = discover(compose_services, policies)
    if errors:
        raise ValueError(
            "Compose labels failed Access validation:\n" + "\n".join(errors)
        )
    if not desired:
        raise ValueError("No managed ebi.nu hostnames found in Compose")

    apps = hydrate_apps(client, account, client.list_applications(account))
    public_dns = client.list_dns(ebi)
    internal_dns = [] if skip_docker else client.list_dns(ygg)
    config = client.tunnel_configuration(account, tunnel_id)
    routes = config["config"].get("ingress")
    docker_addresses = None if skip_docker else docker_ipv4()
    if static_hosts and docker_addresses:
        collisions = sorted(
            hostname
            for hostname in static_hosts
            if hostname.removesuffix(".ygg.nu") in docker_addresses
        )
        if collisions:
            raise ValueError(
                "Static DNS inventory overlaps running Docker containers: "
                + ", ".join(collisions)
            )
    report = compare_live(
        desired,
        apps,
        public_dns,
        routes,
        tunnel_id,
        docker_addresses=docker_addresses,
        dns_ygg=internal_dns,
    )
    report["counts"]["live_reusable_policies"] = len(policies)
    report["counts"]["live_ygg_dns_records"] = len(internal_dns)
    report["static_dns"] = compare_static_dns(
        static_hosts, internal_dns, static_companions
    )
    report["counts"]["static_dns_hosts"] = report["static_dns"]["counts"]["hosts"]
    report["counts"]["static_dns_drift"] = report["static_dns"]["counts"]["drift"]
    aliases = (
        load_inventory_aliases(root / INVENTORY) if static_hosts is not None else set()
    )
    declared = declared_dns_names(aliases, compose_services, docker_addresses or {})
    report["unaccounted_ygg_dns"] = audit_unaccounted_dns(
        None if skip_docker else internal_dns,
        static_hosts,
        declared,
        retained=(
            load_retained_dns(root / RETAINED) if static_hosts is not None else []
        ),
    )
    report["counts"]["unaccounted_ygg_dns_records"] = report["unaccounted_ygg_dns"][
        "counts"
    ]["records"]
    # Only the explicit active inventory can authorize non-Docker A writes.
    static_actions = (
        plan_static_dns(static_hosts, internal_dns, static_companions)
        if settings.get("static_dns_sync", False) and static_hosts is not None
        else []
    )
    report["actions"].extend(static_actions)
    report["counts"]["static_dns_actionable"] = len(static_actions)
    report["counts"]["proposed_operations"] = len(report["actions"])
    for action in static_actions:
        kind = action["kind"]
        report["proposed_by_kind"][kind] = report["proposed_by_kind"].get(kind, 0) + 1
    report["mode"] = "READ_ONLY_LIVE_API"
    report["notes"] = [
        "Cloudflare API GET requests only; no updates or deletions",
        "Terraform configuration and state are not consulted",
        "Unmanaged Cloudflare resources and stopped containers are preserved",
        "Policy changes are suggestions, not automatically applied",
        "Static non-Docker DNS is managed only when static_dns_sync is enabled",
        "Unaccounted ygg.nu DNS findings are review-only; never deleted automatically",
        "Retained DNS declarations are read-only exact-type expectations",
    ]
    return report


def main():
    """Load nonsecret settings and print live Cloudflare drift."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.home() / "ygg-compose",
        help="Merged GitOps repository containing Compose definitions",
    )
    parser.add_argument(
        "--settings",
        type=Path,
        default=Path(__file__).with_name("cloudflare-settings.json"),
        help="Nonsecret Cloudflare account and zone identifiers",
    )
    parser.add_argument(
        "--skip-docker",
        action="store_true",
        help="Skip Docker and ygg.nu DNS inspection",
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    root = args.root.expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Merged GitOps checkout does not exist: {root}")
    settings = json.loads(args.settings.read_text())
    if not isinstance(settings, dict):
        raise TypeError("Cloudflare settings must be a JSON object")
    for setting, name in (
        ("account_id", "CLOUDFLARE_ACCOUNT_ID"),
        ("tunnel_id", "CLOUDFLARE_TUNNEL_ID"),
        ("ebi_zone_id", "CLOUDFLARE_EBI_ZONE_ID"),
        ("ygg_zone_id", "CLOUDFLARE_YGG_ZONE_ID"),
    ):
        if os.environ.get(name):
            settings[setting] = os.environ[name]

    client = CloudflareClient(os.environ.get("CLOUDFLARE_API_TOKEN"))
    report = run_audit(client, root, settings, skip_docker=args.skip_docker)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print("Cloudflare API + Compose reconciliation — READ ONLY")
        print("Counts:", json.dumps(report["counts"], sort_keys=True))
        print("Proposals:", json.dumps(report["proposed_by_kind"], sort_keys=True))
        for action in report["actions"]:
            print(f"  - {action['kind']}: {action['hostname']}")
        for blocked in report["blocked"]:
            print(f"  ! BLOCKED {blocked['hostname']}: {blocked['reason']}")
        if report["static_dns"]["enabled"]:
            print(
                "Static DNS:",
                json.dumps(report["static_dns"]["counts"], sort_keys=True),
            )
            for finding in report["static_dns"]["findings"]:
                print(f"  ! STATIC {finding['status']}: {finding['hostname']}")
        else:
            print("Static DNS: inventory not configured (audit disabled)")
        print_unaccounted_summary(report)
        print("No changes made to Cloudflare, Terraform, or Git.")
    return 2 if report["blocked"] or report["counts"]["static_dns_drift"] else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (
        CloudflareError,
        TypeError,
        ValueError,
        KeyError,
        OSError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
