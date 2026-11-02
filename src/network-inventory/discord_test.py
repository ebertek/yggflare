"""Explicit opt-in Discord delivery probe (one harmless test notification)."""

import os
import sys
from pathlib import Path

from audit import notify_discord


def main():
    webhook_path = Path(os.environ.get(
        "YGG_NETWORK_DISCORD_WEBHOOK_FILE",
        "/run/secrets/network_discord_webhook",
    ))
    if not webhook_path.is_file():
        raise ValueError("Discord webhook secret is not mounted")
    webhook = webhook_path.read_text(encoding="utf-8").strip()
    if not webhook.startswith("https://discord.com/api/webhooks/"):
        raise ValueError("Discord webhook is empty or not a standard Discord URL")
    notify_discord(
        webhook,
        ["TEST ONLY: Yggflare notification delivery check; no drift detected."],
    )
    print("Discord accepted the test notification.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
