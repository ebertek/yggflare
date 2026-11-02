"""Explicit opt-in, time-delayed retirement of one proven orphan per cycle."""

import json
import os
import sys
import time
import urllib.request
from pathlib import Path

from cloudflare_api import CloudflareError, checked_id, checked_tunnel_id
from cloudflare_credentials import api_token
from cloudflare_orphans import (
    OwnershipError,
    desired_hosts,
    observe_orphans,
    retire,
    review_orphan,
    scope,
)
from cloudflare_write_api import CloudflareWriter
from yggflare_config import cloudflare_settings


def main():
    """Require both opt-ins; never delete a hostname not in the ownership registry."""
    if os.environ.get("YGGFLARE_CLOUDFLARE_AUTO_CLEANUP", "false") != "true":
        print("Orphan automatic cleanup disabled.")
        return 0
    if os.environ.get("YGGFLARE_CLOUDFLARE_AUTO_APPLY") != "true":
        raise OwnershipError(
            "Auto cleanup additionally requires YGGFLARE_CLOUDFLARE_AUTO_APPLY=true"
        )
    raw_grace = os.environ.get("YGGFLARE_CLOUDFLARE_ORPHAN_GRACE_HOURS", "24")
    try:
        grace = int(raw_grace)
    except ValueError as error:
        raise OwnershipError(
            "Invalid YGGFLARE_CLOUDFLARE_ORPHAN_GRACE_HOURS"
        ) from error
    if not 24 <= grace <= 720:
        raise OwnershipError("Orphan grace period must be between 24 and 720 hours")

    client = CloudflareWriter(api_token())
    settings = cloudflare_settings()
    account = checked_id(settings["account_id"], "account ID")
    zone = checked_id(
        settings.get("external_zone_id")
        or client.zone_id(settings["external_zone"], account),
        "external zone ID",
    )
    tunnel = checked_tunnel_id(
        settings.get("tunnel_id") or client.tunnel_id(account, settings["tunnel_name"])
    )
    bound = scope(account, zone, tunnel)
    source = Path(os.environ.get("YGGFLARE_SOURCE", "/compose-source"))
    data = Path(os.environ.get("YGGFLARE_DATA", "/data"))
    if not source.is_dir():
        raise OwnershipError("Mounted Compose source is missing")

    # Validated live source, not a stale snapshot, gates all deletion timers.
    wanted = desired_hosts(client, source, account)
    eligible = observe_orphans(data, bound, wanted, time.time(), grace)
    if not eligible:
        print("Orphan cleanup: no eligible managed hostnames.")
        return 0

    hostname = eligible[0]  # At most one target per successful cycle.
    _, approval = review_orphan(client, source, data, bound, hostname)
    steps = retire(client, source, data, bound, hostname, approval)
    print(f"Auto-retired managed orphan: {hostname} ({', '.join(steps)})")

    # Best-effort reporting; never expose the webhook credential in logs.
    secret = Path(
        os.environ.get(
            "YGGFLARE_NETWORK_DISCORD_WEBHOOK_FILE",
            "/run/secrets/network_discord_webhook",
        )
    )
    if secret.is_file():
        webhook = secret.read_text(encoding="utf-8").strip()
        if webhook:
            message = json.dumps(
                {
                    "allowed_mentions": {"parse": []},
                    "embeds": [
                        {
                            "title": "Yggflare - Managed orphan retired",
                            "description": f"Removed Cloudflare resources for `{hostname}` "
                            "after the configured absence grace period.",
                            "color": 3066993,
                            "footer": {
                                "text": "Automatic cleanup • Verified ownership"
                            },
                        }
                    ],
                }
            ).encode("utf-8")
            request = urllib.request.Request(
                webhook,
                data=message,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Yggflare/0 (https://github.com/ebertek/yggflare)",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=15):
                    pass
            except OSError:
                print("WARNING: Orphan retired, but Discord notification failed.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (
        CloudflareError,
        OwnershipError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
    ) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
