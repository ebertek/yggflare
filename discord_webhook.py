"""Strict, offline validation for Discord webhook secrets.

Never include the URL, webhook ID or token in error messages: webhook URLs
are credentials. Parsing does not contact Discord or any other service.
"""

import os
import re
from pathlib import Path
from urllib.parse import urlsplit


DEFAULT_WEBHOOK_FILE = "/run/secrets/network_discord_webhook"
WEBHOOK_FILE_ENV = "YGGFLARE_NETWORK_DISCORD_WEBHOOK_FILE"
SNOWFLAKE = re.compile(r"[0-9]{16,20}")
TOKEN = re.compile(r"[A-Za-z0-9_-]+")


def validate_webhook_url(value):
    """Return a structurally valid HTTPS Discord webhook URL or raise safely."""
    if not isinstance(value, str) or not value:
        raise ValueError("Discord webhook URL is empty")
    try:
        parts = urlsplit(value)
    except ValueError:
        raise ValueError("Discord webhook URL has invalid syntax") from None
    if (
        parts.scheme != "https"
        or parts.netloc != "discord.com"
        or parts.fragment
    ):
        raise ValueError("Discord webhook must use https://discord.com")
    path = parts.path.split("/")
    if len(path) != 5 or path[:3] != ["", "api", "webhooks"]:
        raise ValueError("Discord webhook path must be /api/webhooks/ID/TOKEN")
    if not SNOWFLAKE.fullmatch(path[3]):
        raise ValueError(
            "Discord webhook ID must contain 16-20 ASCII digits; "
            "copy the webhook URL again from Discord"
        )
    if not TOKEN.fullmatch(path[4]):
        raise ValueError("Discord webhook token is missing or malformed")
    return value


def read_webhook(path=None):
    """Read and validate the configured secret, hiding credential contents."""
    target = Path(path or os.environ.get(WEBHOOK_FILE_ENV, DEFAULT_WEBHOOK_FILE))
    try:
        value = target.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        raise ValueError("Discord webhook secret is missing or unreadable") from None
    return validate_webhook_url(value)
