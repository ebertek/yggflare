"""Write-only Cloudflare API extension with a strict set of permitted methods.

No delete, resource replacement, policy creation, or arbitrary HTTP request API
is exposed. Every write is made through an explicitly scoped method.
"""

import json
from ipaddress import ip_address
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cloudflare_api import (
    CloudflareClient,
    CloudflareError,
    checked_id,
    checked_tunnel_id,
)
from cloudflare_desired import HOST, UUID
from cloudflare_live_diff import DOCKER_NETWORK
from cloudflare_static_dns import check_static_target

TUNNEL_CONFIG_KEYS = frozenset({"ingress", "originRequest", "warp-routing"})


def validate_tunnel_config(config):
    """Validate known Cloudflare Tunnel fields without modifying their values."""
    if not isinstance(config, dict) or not isinstance(config.get("ingress"), list):
        raise TypeError("Tunnel configuration must contain an ingress array")
    unknown = set(config) - TUNNEL_CONFIG_KEYS
    if unknown:
        raise ValueError(
            "Unsupported Tunnel configuration keys: " + ", ".join(sorted(unknown))
        )
    if "warp-routing" in config and not isinstance(config["warp-routing"], dict):
        raise TypeError("Tunnel warp-routing must be an object")
    return config


def policy_links(policies):
    """Convert ordered reusable policy IDs into Cloudflare Access links."""
    if (
        not isinstance(policies, list)
        or not policies
        or len(policies) != len(set(policies))
        or not all(
            isinstance(value, str) and UUID.fullmatch(value) for value in policies
        )
    ):
        raise ValueError("Access policies must be a unique, nonempty list of UUIDs")
    return [
        {"id": identifier, "precedence": rank}
        for rank, identifier in enumerate(policies, start=1)
    ]


class CloudflareWriter(CloudflareClient):
    """Allow only known, non-destructive Cloudflare write operations."""

    def _write(self, method, path, body):
        """Send one explicitly scoped mutation, withholding error payloads."""
        if method not in {"POST", "PUT", "PATCH"}:
            raise ValueError("Cloudflare write method is not allowed")
        request = Request(
            self.base_url + path,
            data=json.dumps(body, allow_nan=False).encode("utf-8"),
            headers={
                "Authorization": "Bearer " + self._token,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method=method,
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                result = json.load(response)
        except HTTPError as error:
            raise CloudflareError(
                f"Cloudflare returned HTTP {error.code} for {method} {path}"
            ) from None
        except (URLError, TimeoutError, ValueError) as error:
            raise CloudflareError(f"Cloudflare {method} {path} failed") from error
        if not isinstance(result, dict) or result.get("success") is not True:
            raise CloudflareError(f"Cloudflare rejected {method} {path}")
        return result.get("result")

    def create_access_app(self, account, hostname, policies):
        """Create a self-hosted, reusable-policy-backed Access application."""
        if not HOST.fullmatch(hostname):
            raise ValueError("Only one-label ebi.nu hostnames can be created")
        body = {
            "name": hostname.split(".", maxsplit=1)[0],
            "domain": hostname,
            "type": "self_hosted",
            "session_duration": "24h",
            "destinations": [{"type": "public", "uri": hostname}],
            "policies": policy_links(policies),
        }
        return self._write("POST", f"/accounts/{checked_id(account)}/access/apps", body)

    def update_access_policies(self, account, app_id, application, policies):
        """PUT a self-hosted app while preserving validated configurable settings."""
        if not isinstance(application, dict):
            raise TypeError("Access application must be an object")
        fields = {
            "name",
            "domain",
            "type",
            "session_duration",
            "destinations",
            "allowed_idps",
            "app_launcher_visible",
            "auto_redirect_to_identity",
            "custom_deny_message",
            "custom_deny_url",
            "enable_binding_cookie",
            "http_only_cookie_attribute",
            "eager_redirect_cookie_setting",
            "same_site_cookie_attribute",
            "logo_url",
            "skip_interstitial",
            "service_auth_401_redirect",
            "path_cookie_attribute",
            "cors_headers",
            "options_preflight_bypass",
            "read_service_tokens_from_header",
            "tags",
            "self_hosted_domains",
        }
        readonly = {
            "id",
            "account_id",
            "created_at",
            "updated_at",
            "aud",
            "uid",
            "domain",
            "type",
            "policies",
        }
        unknown = set(application) - fields - readonly
        if unknown:
            raise ValueError(
                "Unsupported Access application fields: " + ", ".join(sorted(unknown))
            )
        if application.get("type") != "self_hosted" or not HOST.fullmatch(
            application.get("domain", "")
        ):
            raise ValueError("Access application is not a managed self-hosted hostname")
        if application.get("id") != app_id:
            raise ValueError("Access application ID changed")
        required = {"name", "domain", "type"}
        if not required.issubset(application):
            raise ValueError("Missing required Access application fields")
        body = {key: application[key] for key in fields if key in application}
        if "destinations" in body:
            # Cloudflare documents destinations as superseding self_hosted_domains.
            body.pop("self_hosted_domains", None)
        body["policies"] = policy_links(policies)
        # Keep the original domain and type, without permitting caller overrides.
        return self._write(
            "PUT",
            f"/accounts/{checked_id(account)}/access/apps/{checked_tunnel_id(app_id)}",
            body,
        )

    def put_tunnel_ingress(self, account, tunnel, config):
        """Replace a validated complete Tunnel config; never omit existing routes."""
        validate_tunnel_config(config)
        return self._write(
            "PUT",
            f"/accounts/{checked_id(account)}/cfd_tunnel/"
            f"{checked_tunnel_id(tunnel)}/configurations",
            {"config": config},
        )

    def create_dns_cname(self, zone, hostname, target):
        """Create only a proxied ebi.nu Tunnel CNAME."""
        if not HOST.fullmatch(hostname) or not target.endswith(".cfargotunnel.com"):
            raise ValueError("Invalid managed DNS CNAME request")
        return self._write(
            "POST",
            f"/zones/{checked_id(zone)}/dns_records",
            {
                "name": hostname,
                "type": "CNAME",
                "content": target,
                "ttl": 1,
                "proxied": True,
            },
        )

    def patch_docker_a(self, zone, record_id, address):
        """Change an existing Docker A record's content without touching its flags."""
        if ip_address(address) not in DOCKER_NETWORK:
            raise ValueError("Refusing a DNS update outside the Docker subnet")
        return self._write(
            "PATCH",
            f"/zones/{checked_id(zone)}/dns_records/{checked_id(record_id)}",
            {"content": address},
        )

    def create_static_a(self, zone, hostname, address):
        """Create only an unproxied ygg.nu A record in the static allocation."""
        check_static_target(hostname, address)
        return self._write(
            "POST",
            f"/zones/{checked_id(zone)}/dns_records",
            {
                "name": hostname,
                "type": "A",
                "content": address,
                "ttl": 1,
                "proxied": False,
            },
        )

    def patch_static_a(self, zone, record_id, hostname, address):
        """Change only an existing static A record's content; preserve settings."""
        # The caller independently verifies hostname, record ID and old address.
        check_static_target(hostname, address)
        return self._write(
            "PATCH",
            f"/zones/{checked_id(zone)}/dns_records/{checked_id(record_id)}",
            {"content": address},
        )

    def get_dns_record(self, zone, record_id):
        """Read one DNS record immediately before an update."""
        return self.get(
            f"/zones/{checked_id(zone)}/dns_records/{checked_id(record_id)}"
        )["result"]
