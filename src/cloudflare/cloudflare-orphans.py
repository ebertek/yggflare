"""Manual-only claim, orphan plan and fingerprint-approved retirement."""

import argparse
import sys
from pathlib import Path

from cloudflare_api import CloudflareError, checked_id, checked_tunnel_id
from cloudflare_credentials import api_token
from cloudflare_orphans import OwnershipError, claim, retire, review_orphan, scope
from cloudflare_write_api import CloudflareWriter
from yggflare_config import cloudflare_settings


def context(client, settings):
    """Resolve exact account, external zone and Tunnel scope from configuration."""
    account = checked_id(settings["account_id"], "account ID")
    zone = checked_id(
        settings.get("external_zone_id")
        or client.zone_id(settings["external_zone"], account),
        "external zone ID",
    )
    tunnel = checked_tunnel_id(
        settings.get("tunnel_id") or client.tunnel_id(account, settings["tunnel_name"])
    )
    return scope(account, zone, tunnel)


def main():
    """Require explicit host selection and a second approved command for deletion."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--action", choices=("claim", "plan", "apply"), required=True)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--approval")
    args = parser.parse_args()
    if (args.action == "apply") != (args.approval is not None):
        parser.error("--approval is mandatory for apply and forbidden otherwise")
    client = CloudflareWriter(api_token())
    bound = context(client, cloudflare_settings())
    data = Path("/data")
    if args.action == "claim":
        claim(client, args.root, data, bound, args.hostname)
        print(f"Claimed managed hostname: {args.hostname}")
        print("No changes made to Cloudflare.")
    elif args.action == "plan":
        plan, fingerprint = review_orphan(client, args.root, data, bound, args.hostname)
        print(f"Orphan cleanup — PLAN ONLY: {args.hostname}")
        for step in plan["steps"]:
            print(f"  - {step}")
        print(f"Approval fingerprint: {fingerprint}")
        print(
            "To apply: docker compose exec -T yggflare"
            f" yggflare cloudflare orphan-apply {args.hostname} {fingerprint}"
        )
        print("No changes made to Cloudflare.")
    else:
        steps = retire(client, args.root, data, bound, args.hostname, args.approval)
        for step in steps:
            print(f"Applied and verified: {step}: {args.hostname}")
        print(f"Retired managed orphan: {args.hostname}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (
        CloudflareError,
        OwnershipError,
        ValueError,
        TypeError,
        KeyError,
        OSError,
    ) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
