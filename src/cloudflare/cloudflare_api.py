"""Small, read-only Cloudflare v4 API client with defensive pagination.

Credentials are read from the environment; neither HTTP responses nor tokens
are included in raised exception messages.
"""

import json
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

IDENTIFIER = re.compile(r"^[0-9a-f]{32}$")
TUNNEL_ID = re.compile(r"^[0-9a-f-]{36}$")
BASE_URL = "https://api.cloudflare.com/client/v4"


class CloudflareError(RuntimeError):
    """An unsuccessful Cloudflare request without sensitive response content."""


def checked_id(value, kind="identifier"):
    """Restrict account/zone identifiers to canonical hexadecimal strings."""
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError(f"Invalid Cloudflare {kind}")
    return value


def checked_tunnel_id(value):
    """Reject unexpected Tunnel identifiers before constructing an API URL."""
    if not isinstance(value, str) or not TUNNEL_ID.fullmatch(value):
        raise ValueError("Invalid Cloudflare Tunnel identifier")
    return value


class CloudflareClient:
    """Cloudflare API requests; no mutation methods are exposed."""

    def __init__(self, token, base_url=BASE_URL, timeout=25):
        """Require a bearer token without persisting it to files or logs."""
        if not token:
            raise ValueError("CLOUDFLARE_API_TOKEN is required")
        if base_url != BASE_URL and not base_url.startswith("http://127.0.0.1:"):
            raise ValueError(
                "Only the Cloudflare API or localhost test server is allowed"
            )
        self._token = token
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def get(self, path, params=None):
        """GET one JSON result and fail without exposing response bodies."""
        query = "?" + urlencode(params) if params else ""
        request = Request(
            self.base_url + path + query,
            headers={
                "Authorization": "Bearer " + self._token,
                "Accept": "application/json",
            },
            method="GET",
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                payload = json.load(response)
        except HTTPError as error:
            raise CloudflareError(
                f"Cloudflare returned HTTP {error.code} for GET {path}"
            ) from None
        except (URLError, TimeoutError, ValueError) as error:
            raise CloudflareError(f"Cloudflare GET {path} failed") from error
        if not isinstance(payload, dict) or payload.get("success") is not True:
            codes = (
                [
                    str(entry["code"])
                    for entry in payload.get("errors", [])
                    if isinstance(entry, dict) and "code" in entry
                ]
                if isinstance(payload, dict)
                else []
            )
            raise CloudflareError(
                f"Cloudflare rejected GET {path} (codes: {','.join(codes)})"
            )
        return payload

    def pages(self, path, params=None):
        """Retrieve all pages, never silently accept truncated result sets."""
        results = []
        expected_total = None
        per_page = 100
        for page in range(1, 101):
            query = dict(params or {})
            query.update({"page": page, "per_page": per_page})
            payload = self.get(path, query)
            items = payload.get("result")
            if not isinstance(items, list):
                raise CloudflareError(f"Expected a list from GET {path}")
            results.extend(items)
            info = payload.get("result_info") or {}
            total_pages = info.get("total_pages")
            if total_pages is not None:
                if not isinstance(total_pages, int) or not 1 <= total_pages <= 100:
                    raise CloudflareError("Invalid Cloudflare pagination metadata")
                expected_total = total_pages
                if page == total_pages:
                    break
            elif len(items) < per_page:
                break
            if not items:
                raise CloudflareError("Incomplete Cloudflare pagination")
        else:
            raise CloudflareError("Cloudflare pagination exceeds safety limit")
        if expected_total and page != expected_total:
            raise CloudflareError("Cloudflare pagination was incomplete")
        return results

    def list_policies(self, account):
        """List reusable Access policies."""
        return self.pages(f"/accounts/{checked_id(account)}/access/policies")

    def list_applications(self, account):
        """List account-level Access applications."""
        return self.pages(f"/accounts/{checked_id(account)}/access/apps")

    def get_application(self, account, app_id):
        """Retrieve one full Access application, including policy ordering."""
        return self.get(
            f"/accounts/{checked_id(account)}/access/apps/"
            f"{checked_tunnel_id(app_id)}"
        )["result"]

    def list_dns(self, zone):
        """List every record in a Cloudflare DNS zone."""
        return self.pages(f"/zones/{checked_id(zone)}/dns_records")

    def zone_id(self, name, account):
        """Resolve an exact zone name under the configured Cloudflare account."""
        zones = self.pages("/zones", {"name": name})
        matches = [
            item
            for item in zones
            if item.get("name") == name and item.get("account", {}).get("id") == account
        ]
        if len(matches) != 1:
            raise CloudflareError(f"Expected one {name} zone in the account")
        return checked_id(matches[0]["id"], "zone identifier")

    def tunnel_id(self, account, name):
        """Resolve exactly one remotely configured Cloudflare Tunnel by name."""
        tunnels = self.pages(f"/accounts/{checked_id(account)}/cfd_tunnel")
        matches = [
            item
            for item in tunnels
            if item.get("name") == name
            and item.get("config_src") == "cloudflare"
            and not item.get("deleted_at")
        ]
        if len(matches) != 1:
            raise CloudflareError(f"Expected one remotely managed Tunnel named {name}")
        return checked_tunnel_id(matches[0]["id"])

    def tunnel_configuration(self, account, tunnel):
        """Retrieve complete remotely managed Tunnel configuration."""
        payload = self.get(
            f"/accounts/{checked_id(account)}/cfd_tunnel/"
            f"{checked_tunnel_id(tunnel)}/configurations"
        )
        result = payload.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("config"), dict):
            raise CloudflareError("Tunnel response has no usable configuration")
        return result
