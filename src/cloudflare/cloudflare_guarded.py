"""Guarded Cloudflare operations, ordered to avoid unprotected publication.

This module is inert until explicitly called by a separately approved command.
Existing Access policy updates require fresh-state verification and the
unattended path additionally enforces defensive allow/deny policy guardrails.
"""

import copy
import hashlib
import ipaddress
import json

from cloudflare_api import checked_id
from cloudflare_desired import HOST
from cloudflare_live_diff import (
    DOCKER_NETWORK,
    ordered_policy_ids,
    validate_ingress,
)
from cloudflare_static_dns import (
    STATIC_NETWORK,
    check_static_target,
    validate_additional_ipv4,
)
from cloudflare_write_api import policy_links, validate_tunnel_config

SUPPORTED = {
    "create_access_app",
    "update_access_policies",
    "add_tunnel_ingress",
    "create_dns_cname",
    "update_docker_dns_a",
    "create_static_dns_a",
    "update_static_dns_a",
}
ORDER = {
    "create_access_app": 0,
    "update_access_policies": 0,
    "add_tunnel_ingress": 1,
    "create_dns_cname": 2,
    "update_docker_dns_a": 3,
    "create_static_dns_a": 4,
    "update_static_dns_a": 4,
}
TEMPLATE_HOST = "komodo.ebi.nu"
TRAEFIK_SERVICE = "https://traefik.ygg.nu:443"


class UnsafePlan(ValueError):
    """A proposed mutation is unsafe or its preconditions have changed."""


def fingerprint(report, context):
    """Bind approval to all proposed operations and Cloudflare resource scope."""
    message = {
        "version": 1,
        "account": context["account"],
        "zone_ebi": context["ebi"],
        "zone_ygg": context["ygg"],
        "tunnel": context["tunnel"],
        "actions": report["actions"],
        "blocked": report["blocked"],
    }
    digest = hashlib.sha256(
        json.dumps(message, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return digest[:16]


def check_plan(report, maximum=10):
    """Refuse blocked, unknown, duplicate, or unreasonably large mutations."""
    if report["blocked"]:
        raise UnsafePlan("The live audit contains blocked operations")
    actions = report["actions"]
    if len(actions) > maximum:
        raise UnsafePlan(f"Plan has {len(actions)} operations (maximum {maximum})")
    if any(action.get("kind") not in SUPPORTED for action in actions):
        raise UnsafePlan("The plan contains unsupported operations")
    entries = [(a["kind"], a["hostname"]) for a in actions]
    if len(entries) != len(set(entries)):
        raise UnsafePlan("The plan contains duplicate operations")
    for entry in actions:
        if entry["kind"] in {"create_static_dns_a", "update_static_dns_a"}:
            try:
                check_static_target(entry["hostname"], entry["content"])
                validate_additional_ipv4(
                    entry["hostname"], entry.get("additional_ipv4", [])
                )
                if entry["kind"] == "update_static_dns_a":
                    checked_id(entry["record_id"], "static DNS record ID")
                    if ipaddress.IPv4Address(entry["before"]) not in STATIC_NETWORK:
                        raise ValueError("Previous address is not a static allocation")
            except (KeyError, TypeError, ValueError) as error:
                raise UnsafePlan("Invalid proposed static DNS operation") from error
        elif entry["kind"] != "update_docker_dns_a":
            if not HOST.fullmatch(entry["hostname"]):
                raise UnsafePlan("A proposed public hostname is not in ebi.nu")
            try:
                policy_links(entry["policies"])
            except (KeyError, TypeError, ValueError) as error:
                raise UnsafePlan(
                    "Missing or invalid approved Access policy links"
                ) from error
    return sorted(actions, key=lambda a: (ORDER[a["kind"]], a["hostname"]))


AUTO_SUPPORTED = {
    "create_access_app",
    "add_tunnel_ingress",
    "create_dns_cname",
    "update_docker_dns_a",
    "update_access_policies",
    "create_static_dns_a",
    "update_static_dns_a",
}


def check_auto_access_policies(wanted, reusable):
    """Require an allow policy and a terminal deny for unattended Access changes."""
    if not isinstance(reusable, list):
        raise UnsafePlan("Cannot validate reusable Access policy inventory")
    indexed = {}
    for policy in reusable:
        if not isinstance(policy, dict):
            raise UnsafePlan("Malformed reusable Access policy")
        identifier = policy.get("id")
        if not isinstance(identifier, str) or identifier in indexed:
            raise UnsafePlan("Invalid or duplicate reusable Access policy ID")
        indexed[identifier] = policy
    if not isinstance(wanted, list) or len(wanted) != len(set(wanted)):
        raise UnsafePlan("Invalid unattended Access policy assignments")
    if not wanted or any(identifier not in indexed for identifier in wanted):
        raise UnsafePlan("Unknown reusable policy in unattended Access update")
    decisions = [indexed[identifier].get("decision") for identifier in wanted]
    if decisions.count("deny") != 1 or decisions[-1] != "deny":
        raise UnsafePlan("Unattended Access update requires a final deny policy")
    if "allow" not in decisions[:-1]:
        raise UnsafePlan("Unattended Access update requires an allow policy")
    if any(decision not in {"allow", "bypass", "deny"} for decision in decisions):
        raise UnsafePlan("Unrecognized reusable Access policy decision")


def check_unattended_plan(report, maximum=3, reusable=None):
    """Allow only bounded changes with safe new and existing Access policies."""
    actions = check_plan(report, maximum=maximum)
    if any(action["kind"] not in AUTO_SUPPORTED for action in actions):
        raise UnsafePlan("Unattended plan contains unsupported operations")
    for action in actions:
        if action["kind"] in {"create_access_app", "update_access_policies"}:
            check_auto_access_policies(action["policies"], reusable)
    return actions


def verify_access(client, account, hostname, wanted):
    """Require exactly one live self-hosted application with these policies."""
    matches = [
        app
        for app in client.list_applications(account)
        if app.get("domain") == hostname
    ]
    if len(matches) != 1 or not matches[0].get("id"):
        raise UnsafePlan(f"{hostname}: expected one existing Access application")
    app = client.get_application(account, matches[0]["id"])
    if app.get("domain") != hostname or app.get("type") != "self_hosted":
        raise UnsafePlan(f"{hostname}: Access application identity changed")
    try:
        current = ordered_policy_ids(app)
    except (TypeError, ValueError) as error:
        raise UnsafePlan(f"{hostname}: invalid live Access policies") from error
    if current != wanted:
        raise UnsafePlan(f"{hostname}: Access policies differ from approved plan")
    return app


def checked_template(config):
    """Select an existing trusted Traefik route and reject unsafe variants."""
    try:
        validate_tunnel_config(config)
    except (TypeError, ValueError) as error:
        raise UnsafePlan(str(error)) from error
    hosts = validate_ingress(config.get("ingress"))
    templates = hosts.get(TEMPLATE_HOST, [])
    if len(templates) != 1 or templates[0].get("service") != TRAEFIK_SERVICE:
        raise UnsafePlan("Expected a single existing Komodo Traefik route template")
    source = templates[0]
    if source.get("path") or (source.get("originRequest") or {}).get("access"):
        raise UnsafePlan("The Tunnel route template has hostname-specific rules")
    return source


def preflight_compatibility(client, context):
    """Validate live API resource shapes before enabling a new host.

    This checks the trusted route, existing Access template and CNAME using
    GET requests only. It does not guarantee that a future POST/PUT succeeds.
    """
    account = context["account"]
    remote = client.tunnel_configuration(account, context["tunnel"])
    config = remote.get("config")
    if not isinstance(config, dict):
        raise UnsafePlan("Live Tunnel configuration is missing")
    template = checked_template(config)
    origin_request = template.get("originRequest") or {}
    if not isinstance(origin_request, dict):
        raise UnsafePlan("Komodo Tunnel origin request is not an object")

    matches = [
        item
        for item in client.list_applications(account)
        if item.get("domain") == TEMPLATE_HOST
    ]
    if len(matches) != 1 or not matches[0].get("id"):
        raise UnsafePlan("Expected exactly one existing Komodo Access application")
    app = client.get_application(account, matches[0]["id"])
    if app.get("domain") != TEMPLATE_HOST or app.get("type") != "self_hosted":
        raise UnsafePlan("Komodo Access application identity is unexpected")
    try:
        policies = ordered_policy_ids(app)
    except (TypeError, ValueError) as error:
        raise UnsafePlan("Komodo Access policy structure is unexpected") from error
    destinations = app.get("destinations")
    if destinations is not None and not isinstance(destinations, list):
        raise UnsafePlan("Komodo Access destination structure is unexpected")

    records = [
        entry
        for entry in client.list_dns(context["ebi"])
        if entry.get("name", "").lower() == TEMPLATE_HOST
    ]
    expected_target = context["tunnel"].lower() + ".cfargotunnel.com"
    if (
        len(records) != 1
        or records[0].get("type") != "CNAME"
        or records[0].get("content", "").lower().rstrip(".") != expected_target
        or records[0].get("proxied") is not True
    ):
        raise UnsafePlan("Komodo CNAME does not point to the expected Tunnel")

    return {
        "trusted_template": TEMPLATE_HOST,
        "tunnel_routes": len(config["ingress"]),
        "template_origin_options": len(origin_request),
        "template_access_policies": len(policies),
        "template_access_destinations": (
            "present" if destinations is not None else "not returned"
        ),
        "template_cname_verified": True,
    }


def audit_tunnel_route(client, context, hostname):
    """Check a route was installed without changing other ingress entries."""
    remote = client.tunnel_configuration(context["account"], context["tunnel"])
    config = remote["config"]
    return bool(validate_ingress(config["ingress"]).get(hostname))


def read_static_a_records(client, zone, hostname):
    """Find only A/CNAME records that could obstruct an A write."""
    return [
        entry
        for entry in client.list_dns(zone)
        if isinstance(entry.get("name"), str)
        and entry["name"].lower() == hostname
        and entry.get("type") in {"A", "CNAME"}
    ]


def apply_static_a(client, zone, action):
    """Write only the primary A while preserving declared companion records."""
    hostname = action["hostname"]
    wanted = action["content"]
    check_static_target(hostname, wanted)
    allowed = validate_additional_ipv4(hostname, action.get("additional_ipv4", []))
    before = read_static_a_records(client, zone, hostname)
    companions = [entry for entry in before if entry.get("content") in allowed]
    primary = [entry for entry in before if entry.get("content") not in allowed]
    if (
        len(companions) != len(allowed)
        or {entry.get("content") for entry in companions} != set(allowed)
        or any(entry.get("type") != "A" for entry in before)
        or any(entry.get("proxied") is not False for entry in before)
    ):
        raise UnsafePlan(f"{hostname}: companion A records changed")

    if action["kind"] == "create_static_dns_a":
        if primary:
            raise UnsafePlan(f"{hostname}: a primary local A record appeared")
        client.create_static_a(zone, hostname, wanted)
    else:
        if (
            len(primary) != 1
            or primary[0].get("id") != action["record_id"]
            or primary[0].get("content") != action["before"]
        ):
            raise UnsafePlan(f"{hostname}: existing static A record changed")
        current = client.get_dns_record(zone, action["record_id"])
        if (
            current.get("name") != hostname
            or current.get("type") != "A"
            or current.get("id") != action["record_id"]
            or current.get("content") != action["before"]
            or current.get("proxied") is not False
        ):
            raise UnsafePlan(f"{hostname}: static DNS record identity changed")
        client.patch_static_a(zone, action["record_id"], hostname, wanted)

    after = read_static_a_records(client, zone, hostname)
    if (
        len(after) != len(allowed) + 1
        or any(entry.get("type") != "A" for entry in after)
        or any(entry.get("proxied") is not False for entry in after)
        or {entry.get("content") for entry in after} != {wanted, *allowed}
    ):
        raise UnsafePlan(f"{hostname}: static DNS verification failed")
    for companion in companions:
        same = [
            entry for entry in after if entry.get("content") == companion["content"]
        ]
        if len(same) != 1 or same[0].get("id") != companion.get("id"):
            raise UnsafePlan(f"{hostname}: companion A identity changed")
    if action["kind"] == "update_static_dns_a":
        primary_after = next(entry for entry in after if entry["content"] == wanted)
        if primary_after.get("id") != action["record_id"]:
            raise UnsafePlan(f"{hostname}: static DNS record ID changed")


# pylint: disable=too-many-locals,too-many-branches,too-many-statements
# pylint: disable=too-many-arguments,too-many-positional-arguments
def apply_actions(
    client, report, context, docker_addresses=None, maximum=10, unattended=False
):
    """Apply only approved, narrowly scoped changes after live rechecks.

    No operation is automatically rolled back; rerunning the audit identifies
    remaining steps if a request fails mid-plan.
    """
    actions = check_plan(report, maximum)
    if unattended:
        check_unattended_plan(
            report,
            maximum=min(3, maximum),
            reusable=client.list_policies(context["account"]),
        )
    # Preflight all Tunnel shapes before any write. This avoids creating
    # orphan Access apps if a Tunnel replacement would be unsafe.
    if any(action["kind"] == "add_tunnel_ingress" for action in actions):
        tunnel_data = client.tunnel_configuration(context["account"], context["tunnel"])
        checked_template(tunnel_data["config"])

    done = []
    for action in actions:
        kind = action["kind"]
        hostname = action["hostname"]
        if kind == "create_access_app":
            if any(
                item.get("domain") == hostname
                for item in client.list_applications(context["account"])
            ):
                raise UnsafePlan(f"{hostname}: Access application appeared")
            live_policy_ids = {
                value.get("id") for value in client.list_policies(context["account"])
            }
            if not set(action["policies"]).issubset(live_policy_ids):
                raise UnsafePlan(f"{hostname}: reusable policy was removed")
            if unattended:
                check_auto_access_policies(
                    action["policies"], client.list_policies(context["account"])
                )
            client.create_access_app(context["account"], hostname, action["policies"])
            verify_access(client, context["account"], hostname, action["policies"])

        elif kind == "update_access_policies":
            app = verify_access(client, context["account"], hostname, action["before"])
            if app.get("id") != action["app_id"]:
                raise UnsafePlan(f"{hostname}: Access application ID changed")
            live_policy_ids = {
                policy.get("id") for policy in client.list_policies(context["account"])
            }
            if not set(action["policies"]).issubset(live_policy_ids):
                raise UnsafePlan(f"{hostname}: reusable policy is not available")
            if unattended:
                check_auto_access_policies(
                    action["policies"], client.list_policies(context["account"])
                )
            try:
                client.update_access_policies(
                    context["account"], action["app_id"], app, action["policies"]
                )
            except (TypeError, ValueError) as error:
                raise UnsafePlan(
                    f"{hostname}: unsupported Access application configuration"
                ) from error
            verify_access(client, context["account"], hostname, action["policies"])

        elif kind == "add_tunnel_ingress":
            verify_access(client, context["account"], hostname, action["policies"])
            remote = client.tunnel_configuration(context["account"], context["tunnel"])
            before = remote["config"]
            template = checked_template(before)
            if hostname in validate_ingress(before["ingress"]):
                raise UnsafePlan(f"{hostname}: Tunnel route already exists")
            next_config = copy.deepcopy(before)
            route = copy.deepcopy(template)
            route["hostname"] = hostname
            next_config["ingress"].insert(-1, route)
            client.put_tunnel_ingress(
                context["account"], context["tunnel"], next_config
            )
            if not audit_tunnel_route(client, context, hostname):
                raise UnsafePlan(f"{hostname}: Tunnel ingress verification failed")

        elif kind == "create_dns_cname":
            verify_access(client, context["account"], hostname, action["policies"])
            if not audit_tunnel_route(client, context, hostname):
                raise UnsafePlan(f"{hostname}: Tunnel ingress is not ready")
            if any(
                value.get("name", "").lower() == hostname
                for value in client.list_dns(context["ebi"])
            ):
                raise UnsafePlan(f"{hostname}: a DNS record appeared")
            client.create_dns_cname(context["ebi"], hostname, action["content"])
            records = [
                value
                for value in client.list_dns(context["ebi"])
                if value.get("name", "").lower() == hostname
            ]
            if (
                len(records) != 1
                or records[0].get("type") != "CNAME"
                or records[0].get("proxied") is not True
                or records[0].get("content", "").lower() != action["content"]
            ):
                raise UnsafePlan(f"{hostname}: DNS CNAME verification failed")

        elif kind in {"create_static_dns_a", "update_static_dns_a"}:
            apply_static_a(client, context["ygg"], action)

        elif kind == "update_docker_dns_a":
            name = hostname.removesuffix(".ygg.nu")
            if (
                docker_addresses is None
                or docker_addresses().get(name) != action["content"]
            ):
                raise UnsafePlan(f"{hostname}: running Docker address changed")
            record = client.get_dns_record(context["ygg"], action["record_id"])
            old = record.get("content")
            # pylint: disable=too-many-boolean-expressions
            if (
                record.get("name") != hostname
                or record.get("type") != "A"
                or old != action["before"]
                or record.get("proxied") is not False
                or ipaddress.ip_address(old) not in DOCKER_NETWORK
                or ipaddress.ip_address(action["content"]) not in DOCKER_NETWORK
            ):
                raise UnsafePlan(f"{hostname}: Docker DNS record changed")
            # pylint: enable=too-many-boolean-expressions
            client.patch_docker_a(
                context["ygg"], action["record_id"], action["content"]
            )
            updated = client.get_dns_record(context["ygg"], action["record_id"])
            if updated.get("content") != action["content"]:
                raise UnsafePlan(f"{hostname}: Docker DNS verification failed")
        done.append({"kind": kind, "hostname": hostname})
    return done
