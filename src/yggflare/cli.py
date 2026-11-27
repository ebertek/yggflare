#!/usr/bin/env python3
"""Operator commands for a running Yggflare container (via docker exec)."""

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# The installed CLI lives on PATH, while the application lives in /app.
sys.path.insert(0, "/app")
import controller  # noqa: E402  # pylint: disable=wrong-import-position

FINGERPRINT = re.compile(r"^[0-9a-f]{16}$")


def main(argv=None):
    """Run a Cloudflare operation using the controller's isolated input snapshot."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version", action="version", version=controller.version_string()
    )
    parser.add_argument(
        "component",
        choices=(
            "cloudflare",
            "doctor",
            "backup",
            "network",
            "mcp",
            "services",
            "system",
            "traefik",
            "komodo",
            "kuma",
            "probes",
            "unifi",
        ),
    )
    parser.add_argument(
        "operation",
        choices=(
            "plan",
            "reconcile-plan",
            "canonical-review",
            "ipv6-review",
            "repair-plan",
            "repair-apply",
            "retirement-plan",
            "apply",
            "preflight",
            "audit",
            "claim",
            "claim-all",
            "legacy-claim-plan",
            "legacy-claim-apply",
            "legacy-external-claim-plan",
            "legacy-external-claim-apply",
            "orphan-plan",
            "orphan-apply",
            "verify",
            "restore-test",
            "run",
            "discord-test",
            "status",
            "serve",
            "check",
            "list",
            "show",
            "drift",
            "dependencies",
            "ingress",
            "assurance",
            "topology",
            "dns",
            "access",
            "tunnel",
            "jobs",
            "evidence",
            "history",
            "notifications",
            "findings",
            "transitions",
            "routes",
            "services",
            "middlewares",
            "servers",
            "stacks",
            "deployments",
            "monitors",
            "devices",
            "clients",
            "networks",
            "coverage",
            "results",
            "refresh",
        ),
    )
    parser.add_argument("argument", nargs="?")
    parser.add_argument("approval", nargs="?")
    parser.add_argument("--details", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--max-operations",
        type=int,
        default=0,
        help="Manual Cloudflare plan limit; 0 (default) means all validated actions",
    )
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--limit", type=int, help="Page size (1-50)")
    parser.add_argument(
        "--all", action="store_true", help="Read every page of a stable result set"
    )
    parser.add_argument("--project", default="")
    parser.add_argument("--snapshot-id", default="")
    args = parser.parse_args(argv)
    from operator_views import CLI_VIEWS, cli_text, query

    selection = CLI_VIEWS.get((args.component, args.operation))
    if selection:
        if args.approval is not None or args.max_operations != 0 or args.details:
            parser.error("Unsupported arguments for read-only operator view")
        from mcp_server import InventoryTools

        try:
            result = query(
                InventoryTools(),
                *selection,
                value=args.argument or "",
                offset=args.offset,
                project=args.project,
                snapshot_id=args.snapshot_id,
                limit=args.limit,
                all_pages=args.all,
            )
        except ValueError as error:
            parser.error(str(error))
        print(
            json.dumps(result, indent=2, sort_keys=True)
            if args.json
            else cli_text(result)
        )
        return 0
    if (
        args.offset
        or args.project
        or args.snapshot_id
        or args.limit is not None
        or args.all
    ):
        parser.error("Pagination and project options require a read-only operator view")
    if (
        args.component in {"traefik", "komodo", "kuma", "probes", "unifi"}
        and args.operation == "refresh"
    ):
        if (
            args.argument
            or args.approval
            or args.max_operations
            or args.json
            or args.details
        ):
            parser.error("Integration refresh accepts no additional arguments")
        if args.component == "probes":
            command = [sys.executable, "/app/probe_inventory.py"]
        elif args.component == "traefik":
            command = [sys.executable, "/app/traefik_inventory.py"]
        else:
            command = [sys.executable, "/app/integration_inventory.py", args.component]
        return subprocess.run(command, check=False).returncode
    if args.component == "unifi" and args.operation == "retirement-plan":
        if args.argument or args.approval or args.max_operations or args.details:
            parser.error("unifi retirement-plan accepts only --json")
        return subprocess.run(
            [sys.executable, "/app/unifi_apply.py", "--retirement-plan"],
            check=False,
        ).returncode
    if args.component == "unifi" and args.operation in {"repair-plan", "repair-apply"}:
        applying = args.operation == "repair-apply"
        if (
            not args.argument
            or applying != bool(args.approval)
            or args.max_operations
            or args.details
            or (applying and args.json)
        ):
            parser.error(
                "unifi repair-plan requires HOSTNAME; repair-apply also requires FINGERPRINT"
            )
        command = [sys.executable, "/app/unifi_apply.py", "--repair"]
        if args.json:
            command.append("--json")
        command.extend(("--", args.argument))
        if applying:
            command.append(args.approval)
        return subprocess.run(command, check=False).returncode
    if args.component == "unifi" and args.operation == "apply":
        if (
            not args.argument
            or not args.approval
            or args.max_operations
            or args.details
            or args.json
        ):
            parser.error("unifi apply requires HOSTNAME FINGERPRINT")
        return subprocess.run(
            [sys.executable, "/app/unifi_apply.py", "--", args.argument, args.approval],
            check=False,
        ).returncode
    if args.component == "unifi" and args.operation == "verify":
        if args.approval is not None or args.max_operations or args.details:
            parser.error("unifi verify accepts an optional hostname and --json")
        command = [sys.executable, "/app/unifi_dns_verify.py"]
        if args.json:
            command.append("--json")
        if args.argument:
            command.extend(("--", args.argument))
        return subprocess.run(command, check=False).returncode
    if args.component == "unifi" and args.operation == "ipv6-review":
        if args.argument or args.approval or args.max_operations or args.details:
            parser.error("unifi ipv6-review accepts only --json")
        return subprocess.run(
            [sys.executable, "/app/unifi_ipv6_review.py"],
            check=False,
        ).returncode
    if args.component == "unifi" and args.operation == "canonical-review":
        if args.argument or args.approval or args.max_operations or args.details:
            parser.error("unifi canonical-review accepts only --json")
        command = [sys.executable, "/app/unifi_canonical_review.py"]
        if args.json:
            command.append("--json")
        return subprocess.run(command, check=False).returncode
    if args.component == "unifi" and args.operation in {"plan", "reconcile-plan"}:
        if (
            args.approval
            or args.max_operations
            or args.details
            or (args.operation == "plan" and args.argument)
        ):
            parser.error(
                "unifi plan accepts --json; reconcile-plan also accepts an exact hostname"
            )
        script = (
            "unifi_dns.py" if args.operation == "plan" else "unifi_reconcile_plan.py"
        )
        command = [sys.executable, f"/app/{script}"]
        if args.json:
            command.append("--json")
        if args.argument:
            command.extend(("--", args.argument))
        return subprocess.run(command, check=False).returncode
    if args.component == "mcp":
        if (
            args.operation not in {"serve", "check"}
            or args.argument is not None
            or args.approval is not None
            or args.max_operations != 0
            or args.details
            or (args.operation == "serve" and args.json)
        ):
            parser.error("mcp accepts serve or check [--json]")
        script = "mcp_http_check.py" if args.operation == "check" else "mcp_server.py"
        return subprocess.run(
            [sys.executable, f"/app/{script}"], check=False
        ).returncode
    network_status = args.component == "network" and args.operation == "status"
    cloudflare_retirement = (
        args.component == "cloudflare" and args.operation == "retirement-plan"
    )
    if (args.details or args.json) and not (network_status or cloudflare_retirement):
        parser.error("--details and --json require a supported review command")
    if args.operation == "serve" and args.component != "mcp":
        parser.error("serve requires mcp")
    if network_status:
        if args.argument or args.approval or args.max_operations != 0:
            parser.error("network status accepts no additional positional arguments")
        if args.details and args.json:
            parser.error("--details and --json cannot be combined")
        command = [sys.executable, "/app/network-inventory/status.py"]
        if args.details:
            command.append("--details")
        if args.json:
            command.append("--json")
        return subprocess.run(command, check=False).returncode
    if args.component != "cloudflare":
        if args.component == "doctor" and args.operation == "run":
            return subprocess.run(
                [sys.executable, "/app/doctor.py"], check=False
            ).returncode
        if (
            args.component == "backup"
            and args.operation == "restore-test"
            and args.argument
            and args.approval is None
        ):
            return subprocess.run(
                [
                    sys.executable,
                    "/app/backup_verify.py",
                    args.argument,
                    "--restore-test",
                ],
                check=False,
            ).returncode
        if args.component == "backup" and args.operation == "verify" and args.argument:
            return subprocess.run(
                [sys.executable, "/app/backup_verify.py", args.argument],
                check=False,
            ).returncode
        if args.component == "network" and args.operation in ("run", "discord-test"):
            command = [sys.executable, "/app/network-inventory/audit.py"]
            if args.operation == "discord-test":
                command = [sys.executable, "/app/network-inventory/discord_test.py"]
            return subprocess.run(command, check=False).returncode
        parser.error("Unsupported command for this component")

    if args.operation in (
        "legacy-claim-plan",
        "legacy-claim-apply",
        "legacy-external-claim-plan",
        "legacy-external-claim-apply",
    ):
        applying = args.operation.endswith("-apply")
        external = args.operation.startswith("legacy-external-")
        if (
            not args.argument
            or applying != (args.approval is not None)
            or (applying and not FINGERPRINT.fullmatch(args.approval))
            or args.max_operations
            or args.details
            or args.json
        ):
            parser.error(
                "Legacy claim plan requires HOSTNAME; "
                "legacy claim apply also requires FINGERPRINT"
            )
        command = [
            sys.executable,
            (
                "/app/cloudflare/cloudflare_legacy_external_claim.py"
                if external
                else "/app/cloudflare/cloudflare_legacy_internal_claim.py"
            ),
            "--hostname",
            args.argument,
        ]
        if applying:
            command.extend(["--approval", args.approval])
        return subprocess.run(command, check=False).returncode

    if args.operation == "retirement-plan":
        if args.approval is not None or args.max_operations or args.details:
            parser.error(
                "cloudflare retirement-plan accepts optional HOSTNAME and --json"
            )
        controller.DATA.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="yggflare-compose-", dir=controller.DATA
        ) as folder:
            root = controller.snapshot(Path(folder))
            command = [
                sys.executable,
                "/app/cloudflare/cloudflare_internal_retirement.py",
                "--root",
                str(root),
            ]
            if args.argument is not None:
                command.extend(["--hostname", args.argument])
            return subprocess.run(command, check=False).returncode

    if args.max_operations < 0:
        parser.error("--max-operations must be nonnegative")
    if args.operation == "apply":
        if args.argument is None or not FINGERPRINT.fullmatch(args.argument):
            parser.error("apply requires the 16-character approval fingerprint")
        if args.approval is not None:
            parser.error("apply accepts only one fingerprint")
    elif args.operation == "orphan-apply":
        if (
            args.argument is None
            or args.approval is None
            or not FINGERPRINT.fullmatch(args.approval)
        ):
            parser.error("orphan-apply requires HOSTNAME and approval fingerprint")
    elif args.operation in ("claim", "orphan-plan"):
        if args.argument is None or args.approval is not None:
            parser.error(f"{args.operation} requires exactly one hostname")
    elif args.operation == "claim-all":
        if (
            args.argument not in (None, "all", "external", "docker", "static")
            or args.approval is not None
        ):
            parser.error("claim-all accepts only all, external, docker or static")
    elif args.argument is not None or args.approval is not None:
        parser.error("unexpected positional argument")
    if args.operation not in {
        "claim",
        "claim-all",
        "orphan-plan",
        "orphan-apply",
        "audit",
        "plan",
        "apply",
        "preflight",
    }:
        parser.error("Unsupported Cloudflare operation")
    if args.operation in ("claim", "claim-all", "orphan-plan", "orphan-apply"):
        if args.max_operations != 0:
            parser.error("--max-operations is not valid for the orphan workflow")

    controller.DATA.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="yggflare-compose-", dir=controller.DATA
    ) as folder:
        root = controller.snapshot(Path(folder))
        if args.operation == "claim-all":
            command = [
                sys.executable,
                "/app/cloudflare/cloudflare-claim-all.py",
                "--root",
                str(root),
                "--scope",
                args.argument or "all",
            ]
        elif args.operation in ("claim", "orphan-plan", "orphan-apply"):
            command = [
                sys.executable,
                "/app/cloudflare/cloudflare-orphans.py",
                "--root",
                str(root),
                "--action",
                {"claim": "claim", "orphan-plan": "plan", "orphan-apply": "apply"}[
                    args.operation
                ],
                "--hostname",
                args.argument,
            ]
            if args.approval is not None:
                command.extend(["--approval", args.approval])
        else:
            script = (
                "/app/cloudflare/cloudflare-live.py"
                if args.operation == "audit"
                else "/app/cloudflare/cloudflare-manage.py"
            )
            command = [sys.executable, script, "--root", str(root)]
            if args.operation != "audit":
                command.extend(["--max-operations", str(args.max_operations)])
            if args.operation == "apply":
                command.extend(["--apply", args.argument])
            elif args.operation == "preflight":
                command.append("--preflight")
        return subprocess.run(command, check=False).returncode


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
