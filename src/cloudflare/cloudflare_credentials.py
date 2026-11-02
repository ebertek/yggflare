"""Read Cloudflare bearer token from a Compose secret, never from legacy env files."""
import os
from pathlib import Path


def api_token():
    """Prefer Docker secret file; allow explicitly supplied environment fallback."""
    secret = os.environ.get("CLOUDFLARE_API_TOKEN_FILE")
    if secret:
        token = Path(secret).read_text(encoding="utf-8").strip()
    else:
        token = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
    if not token:
        raise ValueError("Cloudflare API token secret is missing or empty")
    return token
