"""Validated deployment-specific network and domain configuration."""

import ipaddress
import os
import re

DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$")


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
