"""Read the Cloudflare bearer token exclusively from the Compose secret file."""
import os
from pathlib import Path


def api_token():
    """Require an explicitly mounted file; never expose tokens via environment."""
    path = os.environ.get("CLOUDFLARE_API_TOKEN_FILE", "/run/secrets/cloudflare_api_token")
    token = Path(path).read_text(encoding="utf-8").strip()
    if not token:
        raise ValueError("Cloudflare API token secret is empty")
    return token
