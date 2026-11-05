"""Allowlisted, bounded ICMPv6 Router Advertisement evidence from rdisc6.

Only validated numeric RA attributes are retained. Router advertisements are
interface-scoped topology hints, never device-IP candidates or DNS inputs.
"""

import ipaddress
import re

MAX_OUTPUT_BYTES = 65536
MAX_ROUTERS = 8
MAX_PREFIXES = 12
MAX_DNS_SERVERS = 8

PREFERENCE = {"low", "medium", "high"}
YES_NO = {"yes", "no"}
MAC_RE = re.compile(r"(?i)^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
NUMBER_RE = re.compile(r"^(\d{1,6})\b")


def allowed_prefix(value, scopes):
    """Keep RA prefixes intersecting configured IPv6 scope, without probing."""
    try:
        prefix = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
    if not isinstance(prefix, ipaddress.IPv6Network):
        return None
    if (
        prefix.is_multicast
        or prefix.is_link_local
        or prefix.network_address.is_unspecified
    ):
        return None
    if any(prefix.overlaps(scope) for scope in scopes):
        return str(prefix)
    return None


def router_records(raw, scopes):
    """Parse verbose rdisc6 output, preserving only scoped numeric metadata.

    Verbose rdisc6 terminates each router's advertisement with a
    'from fe80::...' line. Do not accept partial records without that source.
    """
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise ValueError("Oversized IPv6 router advertisement response")
    results = []
    seen = set()
    props = {}
    prefixes = set()
    dns_servers = set()

    for line in raw.splitlines():
        line = line.strip()
        if line.lower().startswith("from "):
            source = line[5:].split()[0].split("%", 1)[0]
            try:
                router = ipaddress.ip_address(source)
            except ValueError:
                router = None
            if isinstance(router, ipaddress.IPv6Address) and router.is_link_local:
                details = ["router: " + str(router)]
                if prefixes:
                    details.append("prefixes: " + ", ".join(sorted(prefixes)))
                else:
                    details.append("prefixes: none within configured scope")
                if dns_servers:
                    details.append("RDNSS: " + ", ".join(sorted(dns_servers)))
                for key in (
                    "router preference",
                    "router lifetime",
                    "stateful address conf.",
                    "stateful other conf.",
                ):
                    if key in props:
                        details.append(key + ": " + props[key])
                if "mac" in props:
                    details.append("router MAC: " + props["mac"])
                description = "; ".join(details)
                if description not in seen:
                    if len(results) >= MAX_ROUTERS:
                        raise ValueError("Too many IPv6 router advertisements")
                    results.append(description[:512])
                    seen.add(description)
            props = {}
            prefixes = set()
            dns_servers = set()
            continue

        if ":" not in line:
            continue
        name, value = (part.strip() for part in line.split(":", 1))
        name = name.lower()
        if name == "prefix":
            candidate = allowed_prefix(value.split()[0], scopes) if value else None
            if candidate:
                if len(prefixes) >= MAX_PREFIXES and candidate not in prefixes:
                    raise ValueError("Too many IPv6 router prefixes")
                prefixes.add(candidate)
        elif name == "recursive dns server":
            try:
                address = ipaddress.ip_address(value.split()[0])
            except (IndexError, ValueError):
                continue
            if isinstance(address, ipaddress.IPv6Address) and any(
                address in scope for scope in scopes
            ):
                if (
                    len(dns_servers) >= MAX_DNS_SERVERS
                    and str(address) not in dns_servers
                ):
                    raise ValueError("Too many IPv6 advertised DNS servers")
                dns_servers.add(str(address))
        elif name == "router preference" and value.lower() in PREFERENCE:
            props[name] = value.lower()
        elif name == "router lifetime":
            match = NUMBER_RE.match(value)
            if match:
                props[name] = match.group(1) + "s"
        elif name in ("stateful address conf.", "stateful other conf."):
            if value.lower() in YES_NO:
                props[name] = value.lower()
        elif name == "source link-layer address":
            if MAC_RE.fullmatch(value):
                props["mac"] = value.lower()

    return results
