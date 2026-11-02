"""Validated deployment-specific network and domain configuration."""

import ipaddress
import os
import re

DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def domain(name):
    value = os.environ.get(name, "").strip().lower().rstrip(".")
    if not DOMAIN.fullmatch(value):
        raise ValueError(f"{name} must be a valid DNS domain")
    return value


def network(name):
    raw = os.environ.get(name, "")
    try:
        result = ipaddress.ip_network(raw, strict=True)
    except ValueError as error:
        raise ValueError(f"{name} must be a valid CIDR network") from error
    if result.version != 4 or not result.is_private:
        raise ValueError(f"{name} must be a private IPv4 CIDR network")
    return result


def suffix(name):
    return "." + domain(name)


def in_domain(hostname, name):
    return isinstance(hostname, str) and hostname.lower().endswith(suffix(name))


def boolean(name, default=False):
    """Require explicit true/false rather than Python truthiness."""
    value = os.environ.get(name, str(default).lower()).lower()
    if value not in ("true", "false"):
        raise ValueError(f"{name} must be true or false")
    return value == "true"


def cloudflare_settings():
    """Build nonsecret Cloudflare configuration exclusively from environment."""
    account = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")
    tunnel_name = os.environ.get("CLOUDFLARE_TUNNEL_NAME", "")
    tunnel_id = os.environ.get("CLOUDFLARE_TUNNEL_ID", "")
    if not account:
        raise ValueError("CLOUDFLARE_ACCOUNT_ID is required")
    if not tunnel_name and not tunnel_id:
        raise ValueError("CLOUDFLARE_TUNNEL_NAME or CLOUDFLARE_TUNNEL_ID is required")
    return {
        "account_id": account,
        "tunnel_name": tunnel_name,
        "tunnel_id": tunnel_id,
        "external_zone": domain("YGGFLARE_EXTERNAL_DOMAIN"),
        "internal_zone": domain("YGGFLARE_INTERNAL_DOMAIN"),
        "external_zone_id": os.environ.get("CLOUDFLARE_EXTERNAL_ZONE_ID", ""),
        "internal_zone_id": os.environ.get("CLOUDFLARE_INTERNAL_ZONE_ID", ""),
        "static_dns_required": boolean("CLOUDFLARE_STATIC_DNS_REQUIRED", True),
        "static_dns_sync": boolean("CLOUDFLARE_STATIC_DNS_SYNC", False),
    }
