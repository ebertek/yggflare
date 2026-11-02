"""Pure, fail-closed Cloudflare drift detection; no network or write operations."""

import ipaddress
from collections import Counter

DOCKER_NETWORK = ipaddress.ip_network("10.4.21.0/24")
ORIGIN_CNAME_SUFFIX = ".cfargotunnel.com"


def ordered_policy_ids(app):
    """Read ordered reusable-policy IDs, requiring unambiguous precedence."""
    raw = app.get("policies")
    if not isinstance(raw, list) or not raw:
        raise ValueError("Access app is missing its ordered policy list")
    precedence = []
    for policy in raw:
        if not isinstance(policy, dict):
            raise TypeError("Unexpected Access policy representation")
        identifier = policy.get("id")
        rank = policy.get("precedence")
        if not isinstance(identifier, str) or (
            not isinstance(rank, int) or isinstance(rank, bool)
        ):
            raise TypeError("Access policy lacks ID or integer precedence")
        precedence.append((rank, identifier))
    precedence.sort()
    if [rank for rank, _ in precedence] != list(range(1, len(precedence) + 1)):
        raise ValueError("Access policy precedence is not consecutive from 1")
    ids = [identifier for _, identifier in precedence]
    if len(set(ids)) != len(ids):
        raise ValueError("Duplicate Access policy IDs")
    return ids


def index_records(records, field):
    """Group live Cloudflare resources without losing duplicates."""
    result = {}
    for record in records:
        value = record.get(field)
        if isinstance(value, str):
            result.setdefault(value.lower(), []).append(record)
    return result


def validate_ingress(ingress):
    """Require an unambiguous terminal fallback before planning new routes."""
    if not isinstance(ingress, list) or not ingress:
        raise ValueError("Tunnel ingress is missing")
    final = ingress[-1]
    if not isinstance(final, dict) or final.get("service") != "http_status:404":
        raise ValueError("Tunnel must end with an explicit http_status:404 fallback")
    if final.get("hostname") or final.get("path"):
        raise ValueError("Tunnel 404 fallback is not catch-all")
    hosts = index_records(ingress[:-1], "hostname")
    if any(len(routes) != 1 for routes in hosts.values()):
        raise ValueError("Duplicate hostnames in existing Tunnel configuration")
    return hosts


# pylint: disable=too-many-arguments,too-many-positional-arguments
# pylint: disable=too-many-locals,too-many-branches,too-many-statements
def compare_live(
    desired,
    apps,
    dns_ebi,
    tunnel_ingress,
    tunnel_id,
    docker_addresses=None,
    dns_ygg=None,
):
    """Compare Compose with live Cloudflare and propose non-destructive actions."""
    actions = []
    blocked = []
    app_index = index_records(apps, "domain")
    dns_index = index_records(dns_ebi, "name")
    tunnel_hosts = validate_ingress(tunnel_ingress)
    target = tunnel_id.lower() + ORIGIN_CNAME_SUFFIX

    for hostname, wanted in sorted(desired.items()):
        matches = app_index.get(hostname, [])
        if len(matches) > 1:
            blocked.append({"hostname": hostname, "reason": "multiple Access apps"})
        elif not matches:
            actions.append(
                {"kind": "create_access_app", "hostname": hostname, "policies": wanted}
            )
        else:
            app = matches[0]
            if app.get("type") != "self_hosted":
                blocked.append(
                    {"hostname": hostname, "reason": "Access app is not self_hosted"}
                )
            else:
                try:
                    actual = ordered_policy_ids(app)
                except (TypeError, ValueError) as error:
                    blocked.append({"hostname": hostname, "reason": str(error)})
                else:
                    if actual != wanted:
                        actions.append(
                            {
                                "kind": "update_access_policies",
                                "hostname": hostname,
                                "app_id": app.get("id"),
                                "before": actual,
                                "policies": wanted,
                            }
                        )

        records = dns_index.get(hostname, [])
        if not records:
            actions.append(
                {
                    "kind": "create_dns_cname",
                    "hostname": hostname,
                    "content": target,
                    "policies": wanted,
                }
            )
        elif (
            len(records) != 1
            or records[0].get("type") != "CNAME"
            or records[0].get("content", "").lower().rstrip(".") != target
            or records[0].get("proxied") is not True
        ):
            blocked.append(
                {
                    "hostname": hostname,
                    "reason": "existing DNS records conflict with tunnel CNAME",
                }
            )

        if hostname not in tunnel_hosts:
            actions.append(
                {"kind": "add_tunnel_ingress", "hostname": hostname, "policies": wanted}
            )

    if docker_addresses is not None:
        private_index = index_records(dns_ygg or [], "name")
        for container, address in sorted(docker_addresses.items()):
            hostname = container + ".ygg.nu"
            matched = [
                record
                for record in private_index.get(hostname, [])
                if record.get("type") == "A"
            ]
            if not matched:
                continue  # No automatic creation for unknown local hostnames.
            if len(matched) != 1:
                blocked.append(
                    {"hostname": hostname, "reason": "ambiguous Docker A records"}
                )
                continue
            old = matched[0].get("content")
            if old == address:
                continue
            try:
                old_ip = ipaddress.ip_address(old)
                new_ip = ipaddress.ip_address(address)
            except ValueError:
                blocked.append(
                    {"hostname": hostname, "reason": "invalid Docker IPv4 value"}
                )
                continue
            if old_ip not in DOCKER_NETWORK or new_ip not in DOCKER_NETWORK:
                blocked.append(
                    {"hostname": hostname, "reason": "non-Docker address is protected"}
                )
                continue
            actions.append(
                {
                    "kind": "update_docker_dns_a",
                    "hostname": hostname,
                    "record_id": matched[0].get("id"),
                    "before": old,
                    "content": address,
                }
            )

    by_kind = Counter(item["kind"] for item in actions)
    return {
        "counts": {
            "desired_hosts": len(desired),
            "live_access_apps": len(apps),
            "live_ebi_dns_records": len(dns_ebi),
            "tunnel_routes": len(tunnel_ingress),
            "proposed_operations": len(actions),
            "blocked": len(blocked),
        },
        "proposed_by_kind": dict(sorted(by_kind.items())),
        "actions": actions,
        "blocked": blocked,
        "unmanaged": {
            "access_app_count": sum(host not in desired for host in app_index),
            "tunnel_host_count": sum(host not in desired for host in tunnel_hosts),
        },
    }
