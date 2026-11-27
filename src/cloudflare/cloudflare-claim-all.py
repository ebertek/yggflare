"""Opt-in bulk claims of exact declared Cloudflare endpoints and A records."""

import argparse
import importlib.util
import sys
from pathlib import Path

from cloudflare_api import CloudflareError, checked_id, checked_tunnel_id
from cloudflare_claims import claim_internal
from cloudflare_credentials import api_token
from cloudflare_desired import compose_inventory
from cloudflare_docker_dns import plan_docker_creates
from cloudflare_internal_ownership import STATIC_REGISTRY_FILE, internal_scope
from cloudflare_live_diff import DOCKER_NETWORK
from cloudflare_orphans import claim_all, scope
from cloudflare_retained_dns import RETAINED, load_retained_dns
from cloudflare_static_dns import (
    INVENTORY,
    STATIC_NETWORK,
    load_inventory_aliases,
    load_inventory_details,
)
from cloudflare_write_api import CloudflareWriter
from yggflare_config import cloudflare_settings

SPEC = importlib.util.spec_from_file_location(
    "cloudflare_live_cli", Path(__file__).with_name("cloudflare-live.py")
)
if SPEC is None or SPEC.loader is None:
    raise ImportError("Unable to load cloudflare-live.py")
LIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIVE)


def report(category, results):
    """Report each decision only after its registry commit."""
    print(f"{category}: {sum(v == 'claimed' for v in results.values())} claimed")
    for hostname, status in results.items():
        print(f"  {hostname}: {status}")


def claim_dns(client, root, data, settings, selected):
    account = checked_id(settings["account_id"], "account ID")
    domain = settings["internal_zone"]
    zone = checked_id(client.zone_id(domain, account), "internal zone ID")
    if settings.get("internal_zone_id") and settings["internal_zone_id"] != zone:
        raise ValueError("Configured internal DNS zone identity changed")
    hosts, companions = load_inventory_details(root / INVENTORY, required=True)
    retained = load_retained_dns(root / RETAINED)
    aliases = load_inventory_aliases(root / INVENTORY)
    protected = LIVE.protected_dns_names(hosts, companions, aliases, retained)
    if selected in ("all", "docker"):
        candidates = plan_docker_creates(
            compose_inventory(root),
            LIVE.docker_ipv4(),
            [],
            domain,
            DOCKER_NETWORK,
            protected,
        )
        wanted = {row["hostname"]: row["content"] for row in candidates}
        bound = internal_scope(account, zone, domain, DOCKER_NETWORK)
        report("Docker DNS", claim_internal(client, data, bound, wanted))
    if selected in ("all", "static"):
        excluded = {row["hostname"] for row in retained} | {
            row["content"] for row in retained if row["type"] == "A"
        }
        wanted = {
            name: address
            for name, address in hosts.items()
            if name not in excluded and address not in excluded
        }
        bound = internal_scope(account, zone, domain, STATIC_NETWORK)
        report(
            "Static DNS",
            claim_internal(client, data, bound, wanted, filename=STATIC_REGISTRY_FILE),
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument(
        "--scope", choices=("all", "external", "docker", "static"), default="all"
    )
    args = parser.parse_args()
    client = CloudflareWriter(api_token())
    settings = cloudflare_settings()
    data = Path("/data")
    if args.scope in ("all", "external"):
        account = checked_id(settings["account_id"], "account ID")
        zone = checked_id(
            client.zone_id(settings["external_zone"], account), "external zone ID"
        )
        if settings.get("external_zone_id") and settings["external_zone_id"] != zone:
            raise ValueError("Configured external DNS zone identity changed")
        tunnel = checked_tunnel_id(
            settings.get("tunnel_id")
            or client.tunnel_id(account, settings["tunnel_name"])
        )
        report(
            "External endpoints",
            claim_all(client, args.root, data, scope(account, zone, tunnel)),
        )
    if args.scope in ("all", "docker", "static"):
        claim_dns(client, args.root, data, settings, args.scope)
    print("No changes made to Cloudflare.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (CloudflareError, ValueError, TypeError, KeyError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
