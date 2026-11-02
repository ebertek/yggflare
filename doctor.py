"""Read-only diagnostic checks for Yggflare release readiness.

No Cloudflare mutations, network scans, or Discord POSTs are performed here.
"""

import argparse
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import controller
from backup import verify_archive

DAY = dt.timedelta(days=1)


def age_ok(path, max_hours):
    """Check freshness without reading potentially sensitive file contents."""
    if not path.is_file():
        return False
    age = dt.datetime.now(dt.timezone.utc).timestamp() - path.stat().st_mtime
    return 0 <= age <= max_hours * 3600


def checks():
    """Return named health findings and actionable explanations."""
    results = []

    def add(name, ok, reason):
        results.append((name, bool(ok), reason))

    config = controller.CONFIG
    data = controller.DATA
    source = controller.SOURCE
    backup = controller.BACKUP
    add(
        "config",
        config.is_dir() and (config / "static-hosts.json").is_file(),
        "static-hosts.json is required in /config",
    )
    add(
        "source",
        source.is_dir()
        and bool(
            list(source.rglob("compose.yaml")) or list(source.rglob("compose.yml"))
        ),
        "a read-only merged Compose checkout must be mounted",
    )
    add(
        "state",
        data.is_dir() and os.access(data, os.W_OK),
        "/data must be a writable persistent mount",
    )
    add(
        "backup directory",
        backup.is_dir() and os.access(backup, os.W_OK),
        "/backup must be a writable persistent mount",
    )
    token = Path(
        os.environ.get("CLOUDFLARE_API_TOKEN_FILE", "/run/secrets/cloudflare_api_token")
    )
    add(
        "Cloudflare credential",
        token.is_file() and token.stat().st_size > 0,
        "missing or empty Cloudflare token secret",
    )
    add(
        "Docker socket",
        Path("/var/run/docker.sock").is_socket(),
        "Docker socket is unavailable",
    )
    try:
        outcome = subprocess.run(
            ["docker", "info", "--format", "{{.ID}}"],
            capture_output=True,
            timeout=10,
            check=False,
        )
        docker_works = outcome.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        docker_works = False
    add("Docker API", docker_works, "Docker daemon is not accessible")
    add("nmap", shutil.which("nmap") is not None, "nmap executable missing")
    add(
        "Avahi",
        shutil.which("avahi-browse") is not None,
        "avahi-browse executable missing",
    )
    webhook = Path(
        os.environ.get(
            "YGGFLARE_NETWORK_DISCORD_WEBHOOK_FILE", "/run/secrets/network_discord_webhook"
        )
    )
    add(
        "Discord configured",
        webhook.is_file() and webhook.stat().st_size > 0,
        "webhook secret empty or unavailable; Discord alerting is disabled",
    )
    add(
        "network observations",
        (data / "network-inventory/state.json").is_file(),
        "no completed inventory state file",
    )
    archives = sorted(backup.glob("yggflare-????????T??????Z.tar.gz"))
    if archives:
        latest = archives[-1]
        try:
            verify_archive(latest)
            good = True
        except (OSError, ValueError, tarfile.TarError):
            good = False
        add("backup integrity", good, "newest archive failed structural verification")
        add(
            "backup freshness",
            age_ok(latest, 48),
            "newest archive is older than 48 hours",
        )
    else:
        add("backup integrity", False, "no snapshot archives present")
    add(
        "heartbeat",
        age_ok(data / "heartbeat", 5 / 60),
        "scheduler heartbeat older than five minutes",
    )
    return results


def main():
    """Print checks without revealing secret values or changing state."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    rows = checks()
    if args.json:
        print(
            json.dumps(
                {
                    "checks": [
                        {"name": name, "ok": ok, "detail": reason if not ok else ""}
                        for name, ok, reason in rows
                    ],
                    "passing": sum(ok for _, ok, _ in rows),
                    "total": len(rows),
                },
                indent=2,
            )
        )
    else:
        for name, ok, reason in rows:
            print(
                f"{'PASS' if ok else 'WARN'} {name}" + (f": {reason}" if not ok else "")
            )
        print(f"Checks passing: {sum(ok for _, ok, _ in rows)}/{len(rows)}")
    return 0 if all(ok for _, ok, _ in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
