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
    parser.add_argument("component", choices=("cloudflare",))
    parser.add_argument("operation", choices=("plan", "apply", "preflight", "audit"))
    parser.add_argument("approval", nargs="?")
    parser.add_argument("--max-operations", type=int, default=10)
    args = parser.parse_args(argv)

    if not 1 <= args.max_operations <= 10:
        parser.error("--max-operations must be between 1 and 10")
    if args.operation == "apply":
        if args.approval is None or not FINGERPRINT.fullmatch(args.approval):
            parser.error("apply requires the 16-character approval fingerprint")
    elif args.approval is not None:
        parser.error("an approval fingerprint is only valid for apply")

    controller.DATA.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="yggflare-compose-", dir=controller.DATA
    ) as folder:
        root = controller.snapshot(Path(folder))
        script = (
            "/app/cloudflare/cloudflare-live.py"
            if args.operation == "audit"
            else "/app/cloudflare/cloudflare-manage.py"
        )
        command = [sys.executable, script, "--root", str(root)]
        if args.operation != "audit":
            command.extend(["--max-operations", str(args.max_operations)])
        if args.operation == "apply":
            command.extend(["--apply", args.approval])
        elif args.operation == "preflight":
            command.append("--preflight")
        return subprocess.run(command, check=False).returncode


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
