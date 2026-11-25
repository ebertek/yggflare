"""Explicit opt-in Discord delivery probe (one harmless test notification)."""

import sys

from audit import notify_discord
from discord_webhook import read_webhook


def main():
    webhook = read_webhook()
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
