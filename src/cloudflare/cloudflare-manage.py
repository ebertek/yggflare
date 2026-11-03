"""Guarded Cloudflare API changes with two-step plan approval.

Default: GET-only audit and an approval fingerprint.
To apply: re-run with --apply <fingerprint> after reviewing the exact plan.
No Git changes, deletion, or unattended scheduling.
"""

# Preserve existing kebab-case executable naming.
# pylint: disable=invalid-name

import argparse
import fcntl
import importlib.util
import os
import sys
from pathlib import Path

from cloudflare_api import CloudflareError, checked_id, checked_tunnel_id
from cloudflare_credentials import api_token
from cloudflare_guarded import (
    UnsafePlan,
    apply_actions,
    check_plan,
    check_unattended_plan,
    fingerprint,
    preflight_compatibility,
)
from cloudflare_orphans import claim, print_summary, scope
from cloudflare_unaccounted_dns import print_unaccounted_summary
from cloudflare_write_api import CloudflareWriter
from yggflare_config import cloudflare_settings

SPEC = importlib.util.spec_from_file_location(
    "cloudflare_live_cli", Path(__file__).with_name("cloudflare-live.py")
)
if SPEC is None or SPEC.loader is None:
    raise ImportError("Unable to load cloudflare-live.py")
LIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIVE)


def resource_context(client, settings):
    """Resolve and validate exactly the intended Cloudflare account resources."""
    account = checked_id(settings["account_id"], "account ID")
    return {
        "account": account,
        "ebi": checked_id(
            settings.get("external_zone_id")
            or client.zone_id(settings["external_zone"], account),
            "external zone ID",
        ),
        "ygg": checked_id(
            settings.get("internal_zone_id")
            or client.zone_id(settings["internal_zone"], account),
            "internal zone ID",
        ),
        "tunnel": checked_tunnel_id(
            settings.get("tunnel_id")
            or client.tunnel_id(account, settings["tunnel_name"])
        ),
    }


def plan(client, root, settings, limit):
    """Return a live-reconciled plan and a scope-bound approval token."""
    context = resource_context(client, settings)
    report = LIVE.run_audit(client, root, settings)
    actions = check_plan(report, maximum=limit)
    return report, context, actions, fingerprint(report, context)


def print_static_summary(report):
    """Expose static drift even when the guarded auto plan is otherwise empty."""
    if not report["static_dns"]["enabled"]:
        print("Static DNS: inventory not configured")
        return
    counts = report["static_dns"]["counts"]
    print(
        "Static DNS: "
        f"{counts['matched']}/{counts['hosts']} matching, "
        f"{counts['missing']} missing, {counts['mismatch']} mismatched, "
        f"{counts['conflict']} conflicting; "
        f"{report['counts']['static_dns_actionable']} safe operations proposed"
    )
    for finding in report["static_dns"]["findings"]:
        reason = f" ({finding['reason']})" if finding.get("reason") else ""
        print(f"  ! STATIC {finding['status']}: {finding['hostname']}{reason}")


def require_auto_opt_in():
    """Only a private environment opt-in may authorize unattended writes."""
    if os.environ.get("YGGFLARE_CLOUDFLARE_AUTO_APPLY") != "true":
        raise UnsafePlan(
            "Unattended Cloudflare writes require YGGFLARE_CLOUDFLARE_AUTO_APPLY=true"
        )


def approval_command(token, maximum):
    """Print a host-side command that can reconstruct the required private snapshot."""
    return (
        f"docker exec yggflare yggflare cloudflare apply {token} "
        f"--max-operations {maximum}"
    )


def main():  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    """Preview operations or execute exactly one revalidated approval."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.home() / "ygg-compose")
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="GET-only validation of live Access, Tunnel and DNS templates",
    )
    parser.add_argument(
        "--apply",
        metavar="FINGERPRINT",
        help="Explicit approval of the exact live plan fingerprint",
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Unattended apply, requires YGGFLARE_CLOUDFLARE_AUTO_APPLY=true in the container environment",
    )
    parser.add_argument(
        "--max-operations",
        type=int,
        default=10,
        help="Hard limit for a single approved reconciliation (default 10)",
    )
    args = parser.parse_args()
    if sum((args.preflight, args.apply is not None, args.auto)) > 1:
        raise ValueError("--preflight, --apply and --auto are mutually exclusive")
    if not 1 <= args.max_operations <= 10:
        raise ValueError("Maximum operations must be between 1 and 10")
    if args.auto:
        require_auto_opt_in()
    root = args.root.expanduser().resolve()
    if not root.is_dir():
        raise ValueError("Merged GitOps checkout does not exist")
    settings = cloudflare_settings()
    client = CloudflareWriter(api_token())

    if args.apply is None and not args.auto:
        report, context, actions, token = plan(
            client, root, settings, args.max_operations
        )
        if args.preflight:
            details = preflight_compatibility(client, context)
            print("Cloudflare onboarding preflight — GET ONLY")
            for key, value in sorted(details.items()):
                print(f"{key}: {value}")
            print(f"Pending operations: {len(actions)}")
            print("No changes made.")
            return 0
        print("Cloudflare API reconciler — PLAN ONLY")
        print(f"Desired hostnames: {report['counts']['desired_hosts']}")
        if report["static_dns"]["enabled"]:
            counts = report["static_dns"]["counts"]
            print(
                "Static DNS (read-only): "
                f"{counts['matched']}/{counts['hosts']} matching, "
                f"{counts['drift']} with drift"
            )
            for finding in report["static_dns"]["findings"]:
                print(f"  ! STATIC {finding['status']}: {finding['hostname']}")
        print_unaccounted_summary(report)
        print_summary(report)
        for action in actions:
            print(f"  {action['kind']}: {action['hostname']}")
        if actions:
            print(f"Approval fingerprint: {token}")
            print(f"To apply: {approval_command(token, args.max_operations)}")
        else:
            print("Already synchronized. No changes required.")
        print("No changes made.")
        return 0

    lock = Path.home() / "cloudflare" / ".cloudflare-manage.lock"
    lock.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(lock, os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(descriptor, "r+") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        report, context, actions, token = plan(
            client, root, settings, args.max_operations
        )
        if args.auto:
            print_static_summary(report)
            print_unaccounted_summary(report)
            print_summary(report)
        if not actions:
            if args.auto:
                print("Cloudflare auto reconciliation: no changes required.")
                return 0
            raise UnsafePlan("Refusing apply: no operations remain")
        if args.auto:
            check_unattended_plan(
                report,
                maximum=min(3, args.max_operations),
                reusable=client.list_policies(context["account"]),
            )
        elif token != args.apply:
            raise UnsafePlan("Live plan changed; review a new fingerprint")
        completed = apply_actions(
            client,
            report,
            context,
            docker_addresses=LIVE.docker_ipv4,
            maximum=args.max_operations,
            unattended=args.auto,
        )
        # Only Yggflare-created endpoints can be claimed automatically.
        # Existing pre-migration hostnames must be claimed explicitly.
        created = sorted(
            {
                item["hostname"]
                for item in completed
                if item["kind"] == "create_access_app"
            }
        )
        if created:
            bound = scope(context["account"], context["ebi"], context["tunnel"])
            data = Path("/data")
            for hostname in created:
                claim(client, root, data, bound, hostname)
                print(f"Recorded Yggflare ownership: {hostname}")
        for item in completed:
            print(f"Applied and verified: {item['kind']} {item['hostname']}")
        print(f"Applied {len(completed)} approved Cloudflare operations.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (CloudflareError, UnsafePlan, ValueError, TypeError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
