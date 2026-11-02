"""Guarded Cloudflare API changes with two-step plan approval.

Default: GET-only audit and an approval fingerprint.
To apply: re-run with --apply <fingerprint> after reviewing the exact plan.
No Terraform invocation, Git changes, deletion, or unattended scheduling.
"""

# Preserve existing kebab-case executable naming.
# pylint: disable=invalid-name

import argparse
import fcntl
import importlib.util
import json
import os
import sys
from pathlib import Path

from cloudflare_api import CloudflareError, checked_id, checked_tunnel_id
from cloudflare_guarded import (
    UnsafePlan,
    apply_actions,
    check_plan,
    check_unattended_plan,
    fingerprint,
    preflight_compatibility,
)
from cloudflare_unaccounted_dns import print_unaccounted_summary
from cloudflare_write_api import CloudflareWriter

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
            settings.get("ebi_zone_id")
            or client.zone_id(settings["ebi_zone"], account),
            "ebi.nu zone ID",
        ),
        "ygg": checked_id(
            settings.get("ygg_zone_id")
            or client.zone_id(settings["ygg_zone"], account),
            "ygg.nu zone ID",
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
    if os.environ.get("CF_AUTO_APPLY") != "true":
        raise UnsafePlan("Unattended Cloudflare writes require CF_AUTO_APPLY=true")


def main():  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    """Preview operations or execute exactly one revalidated approval."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.home() / "ygg-compose")
    parser.add_argument(
        "--settings",
        type=Path,
        default=Path(__file__).with_name("cloudflare-settings.json"),
    )
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
        help="Unattended apply, requires CF_AUTO_APPLY=true in private cloudflare.env",
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
    settings = json.loads(args.settings.read_text())
    if not isinstance(settings, dict):
        raise TypeError("Cloudflare settings must be a JSON object")
    for key, envname in (
        ("account_id", "CLOUDFLARE_ACCOUNT_ID"),
        ("tunnel_id", "CLOUDFLARE_TUNNEL_ID"),
        ("ebi_zone_id", "CLOUDFLARE_EBI_ZONE_ID"),
        ("ygg_zone_id", "CLOUDFLARE_YGG_ZONE_ID"),
    ):
        if os.environ.get(envname):
            settings[key] = os.environ[envname]
    client = CloudflareWriter(os.environ.get("CLOUDFLARE_API_TOKEN"))

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
        for action in actions:
            print(f"  {action['kind']}: {action['hostname']}")
        if actions:
            print(f"Approval fingerprint: {token}")
            print(
                f"To apply: python3 Scripts/cloudflare/cloudflare-manage.py --apply {token}"
            )
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
