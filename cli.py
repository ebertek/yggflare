#!/usr/bin/env python3
"""Operator commands for a running Yggflare container (via docker exec)."""

import argparse
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
        "component", choices=("cloudflare", "doctor", "backup", "network")
    )
    parser.add_argument(
        "operation",
        choices=(
            "plan",
            "apply",
            "preflight",
            "audit",
            "claim",
            "orphan-plan",
            "orphan-apply",
            "verify",
            "restore-test",
            "run",
            "discord-test",
        ),
    )
    parser.add_argument("argument", nargs="?")
    parser.add_argument("approval", nargs="?")
    parser.add_argument("--max-operations", type=int, default=10)
    args = parser.parse_args(argv)
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

    if args.max_operations < 1:
        parser.error("--max-operations must be positive")
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
    elif args.argument is not None or args.approval is not None:
        parser.error("unexpected positional argument")
    if args.operation in ("claim", "orphan-plan", "orphan-apply"):
        if args.max_operations != 10:
            parser.error("--max-operations is not valid for the orphan workflow")

    controller.DATA.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="yggflare-compose-", dir=controller.DATA
    ) as folder:
        root = controller.snapshot(Path(folder))
        if args.operation in ("claim", "orphan-plan", "orphan-apply"):
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
