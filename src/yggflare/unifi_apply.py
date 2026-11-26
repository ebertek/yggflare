"""Guarded, create-only UniFi DNS policy reconciliation."""

import argparse
import fcntl
import hmac
import http.client
import ipaddress
import json
import os
import re
import signal
import sys
import time
from collections import Counter
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from cloudflare_api import CloudflareError
from cloudflare_docker_dns import canonical_name, scoped_address
from discord_embed import embed_payload, inline_code
from discord_webhook import read_webhook
from job_status import DNS_VERIFICATION_PENDING_EXIT
from traefik_inventory import read, write
from unifi_api import (
    MAX_ROWS,
    PREFIX,
    all_rows,
    connection,
    hostname,
    response_json,
    row_id,
)
from unifi_dns import ipv4, is_rfc1918, plan
from unifi_dns_verify import query
from unifi_reconcile_plan import (
    TTL_SECONDS,
    load_live,
    policy_fingerprint,
    review,
)
from yggflare_config import network

DNS_VERIFICATION_WINDOW = 600
DNS_VERIFICATION_ATTEMPTS = 3
DNS_VERIFICATION_RETRY_SECONDS = 5

DIGEST = re.compile(r"[0-9a-f]{64}")
UNIFI_KEY_FILE = "/run/secrets/unifi_api_key"
NOTICE_STATES = ("pending", "attempted", "accepted", "unconfirmed")


class ApplyError(ValueError):
    """Fixed operator diagnostic without response or credential data."""


class DNSVerificationPending(ApplyError):
    """The policy matches and at least one expected DNS answer is still absent."""


def verification_deadline():
    return int(time.time()) + DNS_VERIFICATION_WINDOW


def valid_operation(operation):
    if not isinstance(operation, dict):
        return False
    name = operation.get("domain")
    return (
        operation.keys()
        == {"operation", "type", "domain", "ipv4Address", "enabled", "ttlSeconds"}
        and operation["operation"] == "create"
        and operation["type"] == "A_RECORD"
        and hostname(name) is not None
        and name == hostname(name)
        and len(name) <= 127
        and is_rfc1918(ipv4(operation["ipv4Address"]))
        and operation["enabled"] is True
        and type(operation["ttlSeconds"]) is int
        and operation["ttlSeconds"] == TTL_SECONDS
    )


def load_ledger(path, target):
    try:
        path.lstat()
    except FileNotFoundError:
        return {
            "version": 1,
            "target": target,
            "pilot_verified": False,
            "owned": [],
            "pending": None,
        }
    ledger = read(path)
    owned = ledger.get("owned")
    pending = ledger.get("pending")
    if (
        ledger.keys() != {"version", "target", "pilot_verified", "owned", "pending"}
        or ledger["target"] != target
        or type(ledger["pilot_verified"]) is not bool
        or not isinstance(owned, list)
        or len(owned) > MAX_ROWS
    ):
        raise ApplyError("Ownership ledger is invalid or belongs to another target")
    seen_ids, seen_names, seen_ips = set(), set(), set()
    entries = owned if pending is None else [*owned, pending]
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or entry.keys() - {"notice", "verification_deadline"}
            != {"operation", "policy_id", "manual"}
            or (
                "notice" in entry
                and (entry is pending or entry["notice"] not in NOTICE_STATES)
            )
            or (
                "verification_deadline" in entry
                and (
                    entry is not pending
                    or type(entry["verification_deadline"]) is not int
                    or not 0 < entry["verification_deadline"] <= 2**32
                    or entry["policy_id"] is None
                )
            )
            or not valid_operation(entry["operation"])
            or type(entry["manual"]) is not bool
        ):
            raise ApplyError("Ownership ledger contains an invalid operation")
        identifier = entry["policy_id"]
        operation = entry["operation"]
        name, address = operation["domain"], operation["ipv4Address"]
        if identifier is None:
            if entry is not pending:
                raise ApplyError("Ownership ledger lacks an acknowledged policy ID")
        elif row_id(identifier) != identifier or identifier in seen_ids:
            raise ApplyError("Ownership ledger contains an invalid policy ID")
        if name in seen_names or address in seen_ips:
            raise ApplyError("Ownership ledger contains overlapping operations")
        seen_ids.add(identifier)
        seen_names.add(name)
        seen_ips.add(address)
    if ledger["pilot_verified"] != any(entry["manual"] for entry in owned):
        raise ApplyError("Ownership ledger has inconsistent pilot evidence")
    return ledger


def policy_matches(policy, operation):
    return isinstance(policy, dict) and all(
        type(policy.get(field)) is type(value) and policy[field] == value
        for field, value in operation.items()
        if field != "operation"
    )


def create_policy(live, key, operation):
    if not valid_operation(operation):
        raise ApplyError("Create operation failed validation")
    path = f"{PREFIX}/sites/{row_id(live.site)}/dns/policies"
    payload = {key: value for key, value in operation.items() if key != "operation"}
    conn = connection(live.config)
    try:
        conn.request(
            "POST",
            path,
            body=json.dumps(payload).encode(),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-API-Key": key,
            },
        )
        created = response_json(conn.getresponse(), 201)
    finally:
        conn.close()
    if not policy_matches(created, operation):
        raise ApplyError("Create acknowledgement does not match the requested policy")
    identifier = row_id(created.get("id"))
    if hmac.compare_digest(identifier, key):
        raise ApplyError("Unexpected policy acknowledgement")
    return identifier


def discord_notice(operation):
    webhook = urlsplit(read_webhook())
    message = embed_payload(
        "UniFi DNS created",
        f"{inline_code(operation['domain'])} → "
        f"{inline_code(operation['ipv4Address'])}\n"
        f"A & PTR verified · TTL {operation['ttlSeconds']}s",
        "success",
    )
    conn = http.client.HTTPSConnection("discord.com", timeout=10)
    try:
        resource = webhook.path + ("?" + webhook.query if webhook.query else "")
        conn.request(
            "POST",
            resource,
            body=json.dumps(message).encode(),
            headers={
                "Content-Type": "application/json",
                "User-Agent": "DiscordBot (https://github.com/ebertek/yggflare, 1.0)",
            },
        )
        return conn.getresponse().status in (200, 204)
    finally:
        conn.close()


def deliver_notice(path, ledger):
    if os.environ.get("YGGFLARE_UNIFI_DISCORD_NOTIFY") != "true":
        return
    for entry in ledger["owned"]:
        if entry.get("notice") != "pending":
            continue
        # Discord provides no idempotency key. Persist before sending so a
        # crash or lost response cannot cause us to submit the same notice twice.
        entry["notice"] = "attempted"
        write(path, ledger, durable=True)
        try:
            accepted = discord_notice(entry["operation"])
        except (ValueError, OSError, http.client.HTTPException):
            accepted = False
        entry["notice"] = "accepted" if accepted else "unconfirmed"
        write(path, ledger, durable=True)
        if not accepted:
            print("UniFi DNS Discord notification was not confirmed.", file=sys.stderr)
        break


def pending_dns_missing(entry, live):
    policy_id = entry["policy_id"]
    operation = entry["operation"]
    try:
        policies = all_rows(live.config, live.key, "dns", live.site)
    except (OSError, ValueError, TypeError, RecursionError, http.client.HTTPException):
        raise ApplyError("UniFi policy lookup failed during verification") from None
    matches = [
        policy
        for policy in policies
        if hostname(policy.get("domain")) == operation["domain"]
    ]
    if (
        len(matches) != 1
        or row_id(matches[0].get("id")) != policy_id
        or not policy_matches(matches[0], operation)
    ):
        raise ApplyError(
            "Acknowledged policy could not be uniquely verified; writes remain blocked"
        )
    address, name = operation["ipv4Address"], operation["domain"]
    comparison = plan(
        [{"name": name, "type": "A", "content": address, "proxied": False}],
        policies,
        live.comparison["source_zone"],
        ipaddress.IPv4Network(live.comparison["configured_lan"]),
    )
    if comparison["counts"] != {"matched": 1}:
        raise ApplyError("New or conflicting policies prevent ownership verification")
    reverse_name = ipaddress.ip_address(address).reverse_pointer + "."
    gateway = live.config[0]
    missing = False
    for answer, expected in (
        (query(gateway, name + ".", "A"), address),
        (query(gateway, reverse_name, "PTR"), name + "."),
    ):
        status, values = answer
        if status == "answered" and values == [expected]:
            continue
        if status in {"nxdomain", "nodata"} and not values:
            missing = True
            continue
        if status in {"answered", "unexpected_answer"}:
            raise ApplyError("Gateway returned conflicting or unexpected DNS answers")
        raise ApplyError("Gateway DNS verification failed")
    return missing


def confirm_pending(path, ledger, live):
    entry = ledger["pending"]
    policy_id = entry["policy_id"]
    if policy_id is None:
        raise ApplyError(
            "Create outcome is uncertain; inspect UniFi and the private journal before any further writes"
        )
    if "verification_deadline" not in entry:
        # Legacy acknowledged entries have no create timestamp to reuse.
        entry["verification_deadline"] = verification_deadline()
        write(path, ledger, durable=True)
    deadline = entry["verification_deadline"]
    for attempt in range(DNS_VERIFICATION_ATTEMPTS):
        if time.time() >= deadline:
            raise ApplyError(
                "DNS verification deadline expired; pending policy requires review"
            )
        missing = pending_dns_missing(entry, live)
        if time.time() >= deadline:
            raise ApplyError(
                "DNS verification deadline expired; pending policy requires review"
            )
        if not missing:
            break
        if attempt + 1 < DNS_VERIFICATION_ATTEMPTS:
            time.sleep(
                min(DNS_VERIFICATION_RETRY_SECONDS, max(0, deadline - time.time()))
            )
    else:
        expires = datetime.fromtimestamp(deadline, UTC).isoformat()
        raise DNSVerificationPending(
            f"Acknowledged policy is awaiting matching A and PTR replies (deadline {expires})"
        )
    del entry["verification_deadline"]
    if os.environ.get("YGGFLARE_UNIFI_DISCORD_NOTIFY") == "true":
        entry["notice"] = "pending"
    ledger["owned"].append(entry)
    ledger["pilot_verified"] |= entry["manual"]
    ledger["pending"] = None
    write(path, ledger, durable=True)


def declared_targets(services, static_hosts, zone, docker_network):
    """Return unambiguous exact hostname/address declarations."""
    declarations = [(name, {address}) for name, address in static_hosts.items()]
    for service in services:
        name = service.get("ContainerName") or service["Name"].rsplit("/", 1)[-1]
        host = canonical_name(service.get("Hostname") or name, zone)
        if host:
            values = service.get("IPv4Addresses", [])
            addresses = {scoped_address(value, docker_network) for value in values}
            declarations.append((host, addresses))

    by_name = Counter(name for name, _ in declarations)
    by_address = Counter(
        address for _, addresses in declarations for address in addresses
    )
    return {
        (name, address)
        for name, addresses in declarations
        for address in addresses
        if by_name[name] == 1
        and len(addresses) == 1
        and address is not None
        and by_address[address] == 1
    }


def automatic_targets(zone):
    try:
        from cloudflare_desired import compose_inventory
        from cloudflare_static_dns import load_inventory_details

        services = compose_inventory(Path("/compose-source"))
        static_hosts, _ = load_inventory_details(
            Path("/config/static-hosts.json"), required=True
        )
        return declared_targets(
            services, static_hosts, zone, network("YGGFLARE_DOCKER_CIDR")
        )
    except Exception:
        # YAML parser diagnostics may include source lines from private Compose.
        raise ApplyError(
            "Cannot validate Compose and static DNS declarations"
        ) from None


def run(data, selected="", approval="", *, automatic=False):
    if automatic:
        if os.environ.get("YGGFLARE_UNIFI_AUTO_APPLY") != "true":
            raise ApplyError("Scheduled UniFi creates are disabled")
    elif hostname(selected) != selected or not DIGEST.fullmatch(approval):
        raise ApplyError(
            "Apply requires one exact hostname and a SHA-256 preview fingerprint"
        )

    with (data / "unifi-apply.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        live = load_live()
        ledger_path = data / "unifi-ownership.json"
        ledger = load_ledger(ledger_path, live.target)
        deliver_notice(ledger_path, ledger)
        if ledger["pending"] is not None:
            confirm_pending(ledger_path, ledger, live)
            deliver_notice(ledger_path, ledger)
            return "Recovered and verified the pending UniFi create"
        owned = {entry["operation"]["domain"] for entry in ledger["owned"]}
        owned_ips = {entry["operation"]["ipv4Address"] for entry in ledger["owned"]}
        if automatic:
            if not ledger["pilot_verified"]:
                raise ApplyError(
                    "A verified manual pilot is required before automatic creates"
                )
            targets = automatic_targets(live.comparison["source_zone"])
            eligible = [
                row
                for row in live.comparison["rows"]
                if (row["hostname"], row["address"]) in targets
                and row["hostname"] not in owned
                and row["address"] not in owned_ips
            ]
            report = review(
                replace(live, comparison={**live.comparison, "rows": eligible})
            )
            if not report["operations"]:
                return "No eligible declared UniFi creates"
        else:
            report = review(live, selected)
            if not hmac.compare_digest(report["fingerprint"], approval):
                raise ApplyError(
                    "Live preview changed; review a fresh hostname-specific fingerprint"
                )
            if len(report["operations"]) != 1:
                raise ApplyError("Approved hostname has no eligible create operation")

        operation = report["operations"][0]
        if operation["domain"] in owned or operation["ipv4Address"] in owned_ips:
            raise ApplyError("An owned hostname or address requires manual review")
        if len(ledger["owned"]) >= MAX_ROWS:
            raise ApplyError("Ownership ledger is at capacity")
        if os.environ.get("YGGFLARE_UNIFI_API_KEY_FILE") != UNIFI_KEY_FILE:
            raise ApplyError(
                "UniFi creates require the existing read-only Compose secret mount"
            )
        refreshed = load_live()
        if refreshed.inputs != live.inputs:
            raise ApplyError(
                "Cloudflare or UniFi policy inputs changed; regenerate the preview"
            )
        checked = review(refreshed, operation["domain"])
        if checked["operations"] != [operation] or (
            not automatic and not hmac.compare_digest(checked["fingerprint"], approval)
        ):
            raise ApplyError("Fresh gateway replies changed the preview")
        policies = all_rows(refreshed.config, refreshed.key, "dns", refreshed.site)
        if policy_fingerprint(policies) != refreshed.policies_id:
            raise ApplyError("UniFi policies changed immediately before create")
        if automatic and (
            operation["domain"],
            operation["ipv4Address"],
        ) not in automatic_targets(refreshed.comparison["source_zone"]):
            raise ApplyError("DNS declaration changed immediately before create")
        live = refreshed
        # Journal before issuing a single POST. No retry after a lost acknowledgement.
        ledger["pending"] = {
            "operation": operation,
            "policy_id": None,
            "manual": not automatic,
        }
        write(ledger_path, ledger, durable=True)
        ledger["pending"].update(
            policy_id=create_policy(live, live.key, operation),
            verification_deadline=verification_deadline(),
        )
        write(ledger_path, ledger, durable=True)
        confirm_pending(ledger_path, ledger, live)
        deliver_notice(ledger_path, ledger)
        return "Created and verified one UniFi DNS policy"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hostname", nargs="?", default="")
    parser.add_argument("fingerprint", nargs="?", default="")
    parser.add_argument("--automatic", action="store_true")
    args = parser.parse_args()
    signal.alarm(180)
    try:
        if args.automatic and (args.hostname or args.fingerprint):
            raise ApplyError("Automatic invocation accepts no positional arguments")
        print(
            run(
                Path("/data"), args.hostname, args.fingerprint, automatic=args.automatic
            )
        )
        return 0
    except DNSVerificationPending as error:
        print(str(error))
        return DNS_VERIFICATION_PENDING_EXIT
    except ApplyError as error:
        print(str(error), file=sys.stderr)
        return 2
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        RecursionError,
        http.client.HTTPException,
        CloudflareError,
    ):
        print(
            "UniFi apply stopped; inspect the private ownership journal before retrying.",
            file=sys.stderr,
        )
        return 2
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    sys.exit(main())
