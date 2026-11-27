"""Guarded UniFi DNS creation, repair and optional retirement."""

import argparse
import fcntl
import hmac
import http.client
import ipaddress
import json
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
    fingerprint,
    load_live,
    policy_fingerprint,
    review,
)
from yggflare_config import network
from yggflare_env import getenv

DNS_VERIFICATION_WINDOW = 600
DNS_VERIFICATION_ATTEMPTS = 3
DNS_VERIFICATION_RETRY_SECONDS = 5
TRANSIENT_DNS_FAILURES = frozenset({"timeout", "transport_error", "servfail"})
DNS_FAILURE_CATEGORIES = TRANSIENT_DNS_FAILURES | {
    "query_error",
    "refused",
    "formerr",
    "notimp",
    "notauth",
    "notzone",
    "yxdomain",
    "yxrrset",
    "nxrrset",
    "badvers",
    "badsig",
    "badkey",
    "badtime",
    "badmode",
    "badname",
    "badalg",
    "badtrunc",
    "badcookie",
    "answered",
    "unexpected_answer",
    "nxdomain",
    "nodata",
}

DIGEST = re.compile(r"[0-9a-f]{64}")
UNIFI_KEY_FILE = "/run/secrets/unifi_api_key"
NOTICE_STATES = ("pending", "attempted", "accepted", "unconfirmed")
REPAIR_ACTIONS = ("update", "recreate")
RETIRE_MAX_GAP = 7200
RETIRE_ACTION = "retire"


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
        or (pending is not None and not isinstance(pending, dict))
        or (len(owned) == MAX_ROWS and pending is not None and "repair" not in pending)
    ):
        raise ApplyError("Ownership ledger is invalid or belongs to another target")
    seen_ids, seen_names, seen_ips = set(), set(), set()
    repair = pending.get("repair") if isinstance(pending, dict) else None
    previous = None
    if repair is not None:
        if (
            not isinstance(repair, dict)
            or repair.keys() != {"action", "previous_id", "previous_address"}
            or repair["action"] not in (*REPAIR_ACTIONS, RETIRE_ACTION)
            or row_id(repair["previous_id"]) != repair["previous_id"]
            or not is_rfc1918(ipv4(repair["previous_address"]))
        ):
            raise ApplyError("Ownership ledger contains an invalid repair")
        matches = [
            entry
            for entry in owned
            if isinstance(entry, dict)
            and entry.get("policy_id") == repair["previous_id"]
        ]
        if len(matches) != 1:
            raise ApplyError("Repair lacks a unique previous ownership entry")
        previous = matches[0]
    entries = owned if pending is None else [*owned, pending]
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or entry.keys()
            - {"notice", "verification_deadline", "repair", "notice_kind", "legacy"}
            != {"operation", "policy_id", "manual"}
            or (
                "legacy" in entry
                and (
                    entry is pending
                    or entry["manual"] is not False
                    or not isinstance(entry["legacy"], str)
                    or not DIGEST.fullmatch(entry["legacy"])
                )
            )
            or ("repair" in entry and (entry is not pending or repair is None))
            or (
                "notice_kind" in entry
                and (
                    entry is pending
                    or "notice" not in entry
                    or entry["notice_kind"] not in REPAIR_ACTIONS
                )
            )
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
        if entry is pending and previous is not None:
            old = previous["operation"]
            if (
                name != old["domain"]
                or repair["previous_address"] != old["ipv4Address"]
                or entry["manual"] != previous["manual"]
                or ("legacy" in previous and repair["action"] != RETIRE_ACTION)
                or (
                    repair["action"] == "update"
                    and (
                        address == old["ipv4Address"]
                        or identifier not in (None, previous["policy_id"])
                    )
                )
                or (
                    repair["action"] == "recreate"
                    and identifier == previous["policy_id"]
                )
                or (
                    repair["action"] == RETIRE_ACTION
                    and (
                        entry["manual"]
                        or operation != old
                        or identifier not in (None, previous["policy_id"])
                    )
                )
            ):
                raise ApplyError("Repair does not match previous ownership")
            # Allow overlap only with the replaced entry, never another owner.
            seen_names.remove(old["domain"])
            seen_ips.remove(old["ipv4Address"])
            seen_ids.remove(previous["policy_id"])
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


def check_new_policy_id(identifier, ledger, policies):
    """Never claim an acknowledgement that reuses a known policy identity."""
    if (
        row_id(identifier) != identifier
        or any(entry["policy_id"] == identifier for entry in ledger["owned"])
        or any(row_id(policy["id"]) == identifier for policy in policies)
    ):
        raise ApplyError("Unexpected reused policy identity; write outcome uncertain")


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


def discord_notice(operation, kind="create"):
    webhook = urlsplit(read_webhook())
    title = {
        "create": "UniFi DNS created",
        "update": "UniFi DNS updated",
        "recreate": "UniFi DNS restored",
        "retire": "UniFi DNS retired",
    }[kind]
    detail = (
        "Owned policy removed · A & PTR absence verified"
        if kind == RETIRE_ACTION
        else f"A & PTR verified · TTL {operation['ttlSeconds']}s"
    )
    message = embed_payload(
        title,
        f"{inline_code(operation['domain'])} → "
        f"{inline_code(operation['ipv4Address'])}\n{detail}",
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
    if getenv("YGGFLARE_UNIFI_DISCORD_NOTIFY") != "true":
        return
    for entry in ledger["owned"]:
        if entry.get("notice") != "pending":
            continue
        # Discord provides no idempotency key. Persist before sending so a
        # crash or lost response cannot cause us to submit the same notice twice.
        entry["notice"] = "attempted"
        write(path, ledger, durable=True)
        try:
            kind = entry.get("notice_kind")
            accepted = (
                discord_notice(entry["operation"], kind)
                if kind
                else discord_notice(entry["operation"])
            )
        except (ValueError, OSError, http.client.HTTPException):
            accepted = False
        entry["notice"] = "accepted" if accepted else "unconfirmed"
        write(path, ledger, durable=True)
        if not accepted:
            print("UniFi DNS Discord notification was not confirmed.", file=sys.stderr)
        break


def dns_verification_failure(kind, status, values, *, acknowledged):
    """Retry only known transient failures without answer data after acknowledgement."""
    category = status if status in DNS_FAILURE_CATEGORIES else "other_dns_error"
    if status in TRANSIENT_DNS_FAILURES and not values and acknowledged:
        print(
            f"Gateway DNS verification retryable ({kind}: {category})",
            flush=True,
        )
        return True
    if status in {"answered", "unexpected_answer"} or values:
        raise ApplyError(
            f"Gateway returned conflicting or unexpected DNS answers ({kind}: {category})"
        )
    raise ApplyError(f"Gateway DNS verification failed ({kind}: {category})")


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
    repair = entry.get("repair")
    if (
        repair
        and repair["action"] == "recreate"
        and any(row_id(policy["id"]) == repair["previous_id"] for policy in policies)
    ):
        raise ApplyError("Previous policy reappeared; writes remain blocked")
    if repair and (
        matches[0].get("metadata") not in (None, {})
        or not repair_desired(live, name, address)
        or (name, address) not in automatic_targets(live.comparison["source_zone"])
    ):
        raise ApplyError("Repair declaration changed; writes remain blocked")
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
    for kind, answer, expected in (
        ("A", query(gateway, name + ".", "A"), address),
        ("PTR", query(gateway, reverse_name, "PTR"), name + "."),
    ):
        status, values = answer
        if status == "answered" and values == [expected]:
            continue
        if status in {"nxdomain", "nodata"} and not values:
            missing = True
            continue
        if (
            repair
            and expected == address
            and status == "answered"
            and values == [repair["previous_address"]]
            and address != repair["previous_address"]
        ):
            # A cached pre-repair forward answer is known, not a new conflict.
            missing = True
            continue
        missing |= dns_verification_failure(kind, status, values, acknowledged=True)
    return missing


def confirm_pending(path, ledger, live):
    if ledger["target"] != live.target:
        raise ApplyError("Ownership target changed; writes remain blocked")
    entry = ledger["pending"]
    policy_id = entry["policy_id"]
    if policy_id is None:
        raise ApplyError(
            "Create outcome is uncertain; inspect UniFi and the private journal before any further writes"
        )
    operation = entry["operation"]
    zone = live.comparison["source_zone"]
    lan = ipaddress.IPv4Network(live.comparison["configured_lan"])
    address = ipv4(operation["ipv4Address"])
    name = operation["domain"]
    if (
        not (name == zone or name.endswith("." + zone))
        or address not in lan
        or address in (lan.network_address, lan.broadcast_address)
    ):
        raise ApplyError(
            "Pending policy is outside current scope; writes remain blocked"
        )
    if entry.get("repair", {}).get("action") == RETIRE_ACTION:
        confirm_retirement(path, ledger, live)
        return
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
    repair = entry.pop("repair", None)
    if repair:
        ledger["owned"] = [
            old for old in ledger["owned"] if old["policy_id"] != repair["previous_id"]
        ]
    if getenv("YGGFLARE_UNIFI_DISCORD_NOTIFY") == "true":
        entry["notice"] = "pending"
        if repair:
            entry["notice_kind"] = repair["action"]
    ledger["owned"].append(entry)
    ledger["pilot_verified"] |= entry["manual"]
    ledger["pending"] = None
    write(path, ledger, durable=True)


def declared_targets(services, static_hosts, zone, docker_network):
    """Return unambiguous exact hostname/address declarations."""
    declarations = [(name, {address}) for name, address in static_hosts.items()]
    for service in services:
        name = service.get("ContainerName") or service["Name"].rsplit("/", 1)[-1]
        raw_host = service.get("Hostname") or name
        host = canonical_name(raw_host, zone)
        if host:
            values = service.get("IPv4Addresses", [])
            # Addressless short names are container-local, not LAN A declarations.
            # Explicit DNS names and malformed/out-of-scope addresses still block.
            if values == [] and "." not in raw_host.rstrip("."):
                continue
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
        if getenv("YGGFLARE_UNIFI_AUTO_APPLY") != "true":
            raise ApplyError("Scheduled UniFi creates are disabled")
    elif hostname(selected) != selected or not DIGEST.fullmatch(approval):
        raise ApplyError(
            "Apply requires one exact hostname and a SHA-256 preview fingerprint"
        )

    with (data / "unifi-apply.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            live = load_live()
        except Exception:
            if automatic:
                (data / "unifi-retirement.json").unlink(missing_ok=True)
            raise
        ledger_path = data / "unifi-ownership.json"
        ledger = load_ledger(ledger_path, live.target)
        pending = ledger["pending"]
        if (
            pending is not None
            and not automatic
            and (pending["operation"]["domain"] != selected or "repair" in pending)
        ):
            raise ApplyError("Another pending operation blocks manual create")
        deliver_notice(ledger_path, ledger)
        if pending is not None:
            action = pending.get("repair", {}).get("action")
            kind = (
                "retirement"
                if action == RETIRE_ACTION
                else ("repair" if action else "create")
            )
            confirm_pending(ledger_path, ledger, live)
            deliver_notice(ledger_path, ledger)
            return f"Recovered and verified the pending UniFi {kind}"
        if automatic:
            if retirement_enabled():
                try:
                    retired = retire_one(data, ledger_path, ledger, live)
                except Exception:
                    (data / "unifi-retirement.json").unlink(missing_ok=True)
                    raise
                if retired:
                    return retired
            else:
                (data / "unifi-retirement.json").unlink(missing_ok=True)
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
        if getenv("YGGFLARE_UNIFI_API_KEY_FILE") != UNIFI_KEY_FILE:
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
        identifier = create_policy(live, live.key, operation)
        check_new_policy_id(identifier, ledger, policies)
        ledger["pending"].update(
            policy_id=identifier, verification_deadline=verification_deadline()
        )
        write(ledger_path, ledger, durable=True)
        confirm_pending(ledger_path, ledger, live)
        deliver_notice(ledger_path, ledger)
        return "Created and verified one UniFi DNS policy"


def repair_desired(live, name, address):
    """Require one unambiguous in-LAN Cloudflare A record."""
    rows = [row for row in live.comparison["rows"] if row["hostname"] == name]
    choices = [
        row
        for row in live.comparison["reverse_expectations"]
        if row["address"] == address
    ]
    return (
        len(rows) == 1
        and rows[0]["address"] == address
        and rows[0]["in_configured_lan"] is True
        and rows[0]["status"] in {"candidate", "matched", "local_conflict"}
        and len(choices) == 1
        and choices[0]["selection"] == "unique"
        and choices[0]["canonical_hostname"] == name
    )


def repair_review(live, ledger, selected, policies, targets):
    """Build a hostname-specific, read-only repair preview from proven ownership."""
    if hostname(selected) != selected or ledger["pending"] is not None:
        raise ApplyError("Repair requires an exact hostname and no pending write")
    owned = [
        entry for entry in ledger["owned"] if entry["operation"]["domain"] == selected
    ]
    if len(owned) != 1:
        raise ApplyError("Repair requires a previously verified owned policy")
    old = owned[0]
    if "legacy" in old:
        raise ApplyError("Legacy retirement ownership cannot authorize repair")
    old_op = old["operation"]
    candidates = [row for row in live.comparison["rows"] if row["hostname"] == selected]
    address = candidates[0]["address"] if len(candidates) == 1 else None
    lan = ipaddress.IPv4Network(live.comparison["configured_lan"])
    if (
        not address
        or ipv4(old_op["ipv4Address"]) not in lan
        or not repair_desired(live, selected, address)
        or (selected, address) not in targets
        or any(
            entry is not old and entry["operation"]["ipv4Address"] == address
            for entry in ledger["owned"]
        )
    ):
        raise ApplyError(
            "Repair desired address is ambiguous, undeclared or out of scope"
        )
    if policy_fingerprint(policies) != live.policies_id:
        raise ApplyError("UniFi policies changed during repair preview")
    matching_id = [
        policy for policy in policies if row_id(policy["id"]) == old["policy_id"]
    ]
    remaining = policies
    if matching_id:
        current = matching_id[0]
        if (
            len(matching_id) != 1
            or not policy_matches(current, old_op)
            or current.get("metadata") not in (None, {})
        ):
            raise ApplyError("Owned policy was modified externally; review required")
        if address == old_op["ipv4Address"]:
            raise ApplyError("Owned policy already matches the declared address")
        action = "update"
        remaining = [policy for policy in policies if policy is not current]
    else:
        action = "recreate"
    candidate = plan(
        [{"name": selected, "type": "A", "content": address, "proxied": False}],
        remaining,
        live.comparison["source_zone"],
        ipaddress.IPv4Network(live.comparison["configured_lan"]),
    )
    if candidate["counts"] != {"candidate": 1}:
        raise ApplyError("Existing DNS policy or address conflict prevents repair")
    gateway = live.config[0]
    forward = query(gateway, selected + ".", "A")
    reverse = query(
        gateway, ipaddress.IPv4Address(address).reverse_pointer + ".", "PTR"
    )
    allowed_forward = [address]
    if action == "update":
        allowed_forward.append(old_op["ipv4Address"])
    if not (
        (
            forward[0] == "answered"
            and len(forward[1]) == 1
            and forward[1][0] in allowed_forward
        )
        or (forward[0] in {"nxdomain", "nodata"} and not forward[1])
    ):
        raise ApplyError("Unexpected forward DNS answer prevents repair")
    if not (
        (reverse[0] == "answered" and reverse[1] == [selected + "."])
        or (reverse[0] in {"nxdomain", "nodata"} and not reverse[1])
    ):
        raise ApplyError("Unexpected reverse DNS answer prevents repair")
    report = {
        "mode": "read_only_owned_repair",
        "action": action,
        "hostname": selected,
        "previous_policy_id": old["policy_id"],
        "previous_address": old_op["ipv4Address"],
        "operation": {**old_op, "ipv4Address": address},
        "forward": forward,
        "reverse": reverse,
    }
    report["fingerprint"] = fingerprint(
        {"inputs": live.inputs, "ledger": ledger, "report": report}
    )
    encoded = json.dumps(report)
    if any(secret in encoded for secret in (live.key, live.token) if len(secret) >= 8):
        raise ApplyError("Repair preview contains a credential echo")
    return report


def preview_repair(live, ledger, selected):
    policies = all_rows(live.config, live.key, "dns", live.site)
    targets = automatic_targets(live.comparison["source_zone"])
    return repair_review(live, ledger, selected, policies, targets)


def update_policy(live, key, identifier, operation):
    """Replace only the explicitly reviewed policy ID, with a matching acknowledgement."""
    if not valid_operation(operation):
        raise ApplyError("Update operation failed validation")
    identifier = row_id(identifier)
    path = f"{PREFIX}/sites/{row_id(live.site)}/dns/policies/{identifier}"
    payload = {
        field: value for field, value in operation.items() if field != "operation"
    }
    conn = connection(live.config)
    try:
        conn.request(
            "PUT",
            path,
            body=json.dumps(payload).encode(),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-API-Key": key,
            },
        )
        updated = response_json(conn.getresponse(), 200)
    finally:
        conn.close()
    if (
        not policy_matches(updated, operation)
        or row_id(updated.get("id")) != identifier
        or updated.get("metadata") not in (None, {})
    ):
        raise ApplyError("Update acknowledgement does not match the reviewed policy")
    return identifier


def run_repair(data, selected, approval=None):
    """Manual repair uses the same lock, journal and recovery path as creation."""
    if hostname(selected) != selected or (
        approval is not None and not DIGEST.fullmatch(approval)
    ):
        raise ApplyError("Repair requires an exact hostname and valid fingerprint")
    path = data / "unifi-ownership.json"
    if approval is None:
        live = load_live()
        return preview_repair(live, load_ledger(path, live.target), selected)

    with (data / "unifi-apply.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        live = load_live()
        ledger = load_ledger(path, live.target)
        if ledger["pending"] is not None:
            pending = ledger["pending"]
            if (
                pending.get("repair", {}).get("action") not in REPAIR_ACTIONS
                or pending["operation"]["domain"] != selected
            ):
                raise ApplyError("Another pending operation blocks repair")
            confirm_pending(path, ledger, live)
            deliver_notice(path, ledger)
            return "Recovered and verified the pending UniFi repair"
        deliver_notice(path, ledger)
        report = preview_repair(live, ledger, selected)
        if not hmac.compare_digest(report["fingerprint"], approval):
            raise ApplyError("Live repair preview changed; review a fresh fingerprint")
        if getenv("YGGFLARE_UNIFI_API_KEY_FILE") != UNIFI_KEY_FILE:
            raise ApplyError("UniFi repair requires the mounted Compose secret")
        refreshed = load_live()
        checked = preview_repair(refreshed, ledger, selected)
        if not hmac.compare_digest(checked["fingerprint"], approval):
            raise ApplyError("Live repair inputs changed")
        policies = all_rows(refreshed.config, refreshed.key, "dns", refreshed.site)
        if policy_fingerprint(policies) != refreshed.policies_id:
            raise ApplyError("UniFi policies changed immediately before repair")
        operation = report["operation"]
        if (selected, operation["ipv4Address"]) not in automatic_targets(
            refreshed.comparison["source_zone"]
        ):
            raise ApplyError("DNS declaration changed immediately before repair")
        old = next(
            entry
            for entry in ledger["owned"]
            if entry["policy_id"] == report["previous_policy_id"]
        )
        pending = {
            "operation": operation,
            "policy_id": None,
            "manual": old["manual"],
            "repair": {
                "action": report["action"],
                "previous_id": old["policy_id"],
                "previous_address": report["previous_address"],
            },
        }
        ledger["pending"] = pending
        write(path, ledger, durable=True)
        if report["action"] == "update":
            identifier = update_policy(
                refreshed, refreshed.key, old["policy_id"], operation
            )
        else:
            identifier = create_policy(refreshed, refreshed.key, operation)
            if identifier == old["policy_id"]:
                raise ApplyError("Recreated policy unexpectedly reused the previous ID")
            check_new_policy_id(identifier, ledger, policies)
        pending.update(
            policy_id=identifier, verification_deadline=verification_deadline()
        )
        write(path, ledger, durable=True)
        confirm_pending(path, ledger, load_live())
        deliver_notice(path, ledger)
        return "Repaired and verified one UniFi DNS policy"


def retirement_enabled():
    value = getenv("YGGFLARE_UNIFI_AUTO_CLEANUP", "false")
    if value not in ("true", "false"):
        raise ApplyError("YGGFLARE_UNIFI_AUTO_CLEANUP must be true or false")
    return value == "true"


def retirement_grace():
    raw = getenv("YGGFLARE_UNIFI_ORPHAN_GRACE_HOURS", "24")
    if not re.fullmatch(r"[0-9]{1,3}", raw) or not 24 <= int(raw) <= 720:
        raise ApplyError("UniFi retirement grace must be 24–720 hours")
    return int(raw) * 3600


def retirement_protected(live):
    """Use complete desired inputs, not the filtered create target set."""
    if not isinstance(live.records, tuple) or not live.records:
        raise ApplyError("Complete Cloudflare DNS evidence is required for retirement")
    zone = live.comparison["source_zone"]
    names, addresses, wildcards = set(), set(), set()
    for record in live.records:
        if not isinstance(record, dict):
            raise ApplyError("Invalid Cloudflare record in retirement evidence")
        name = record.get("name")
        kind = record.get("type")
        if (
            not isinstance(name, str)
            or not name.strip(".")
            or not isinstance(kind, str)
            or not kind
        ):
            raise ApplyError("Invalid Cloudflare record in retirement evidence")
        name = name.lower().rstrip(".")
        names.add(name)
        if name.startswith("*."):
            wildcards.add(name[2:])
        content = record.get("content")
        if kind == "A":
            address = ipv4(content)
            if address is None:
                raise ApplyError("Invalid Cloudflare A record in retirement evidence")
            addresses.add(str(address))
        if kind in {"CNAME", "PTR", "NS"}:
            if not isinstance(content, str) or not content.strip("."):
                raise ApplyError("Invalid Cloudflare target in retirement evidence")
            names.add(content.lower().rstrip("."))
    try:
        from cloudflare_desired import compose_inventory
        from cloudflare_retained_dns import load_retained_dns
        from cloudflare_static_dns import load_inventory_aliases, load_inventory_details

        static = Path("/config/static-hosts.json")
        hosts, companions = load_inventory_details(static, required=True)
        names.update(hosts)
        names.update(load_inventory_aliases(static))
        addresses.update(hosts.values())
        for values in companions.values():
            addresses.update(values)
        for record in load_retained_dns(Path("/config/retained-dns.json")):
            names.add(record["hostname"])
            content = record.get("content")
            if record["type"] == "A":
                addresses.add(content)
            elif record["type"] in {"CNAME", "PTR", "NS"} and content:
                names.add(content.lower().rstrip("."))
        services = compose_inventory(Path("/compose-source"))
        if not services:
            raise ValueError("Empty Compose inventory")
        for service in services:
            labels = [
                service["Name"].rsplit("/", 1)[-1],
                service.get("Hostname") or "",
                service.get("ContainerName") or "",
            ]
            values = service.get("IPv4Addresses", [])
            if any("$" in value for value in [*labels, *values]):
                raise ValueError("Unresolved Compose declaration")
            names.update(
                name for value in labels if (name := canonical_name(value, zone))
            )
            if any(ipv4(value) is None for value in values):
                raise ValueError("Invalid Compose IPv4 declaration")
            addresses.update(str(ipv4(value)) for value in values)
    except Exception:
        raise ApplyError("Cannot validate private retirement declarations") from None
    return names, addresses, wildcards


def retirement_candidate(entry, live, policies, protected):
    operation = entry["operation"]
    name, address = operation["domain"], operation["ipv4Address"]
    names, addresses, wildcards = protected
    lan = ipaddress.IPv4Network(live.comparison["configured_lan"])
    if entry["manual"]:
        return "manual_protected"
    if (
        ipv4(address) not in lan
        or ipv4(address) in (lan.network_address, lan.broadcast_address)
        or not name.endswith("." + live.comparison["source_zone"])
    ):
        return "outside_scope"
    if (
        name in names
        or address in addresses
        or any(name == suffix or name.endswith("." + suffix) for suffix in wildcards)
    ):
        return "still_declared"
    matches = [
        policy for policy in policies if row_id(policy["id"]) == entry["policy_id"]
    ]
    if not matches:
        return "missing_policy"
    if (
        len(matches) != 1
        or not policy_matches(matches[0], operation)
        or matches[0].get("metadata") not in (None, {})
        or set(matches[0]) - (set(operation) - {"operation"} | {"id", "metadata"})
    ):
        return "modified_policy"
    check = plan(
        [{"name": name, "type": "A", "content": address, "proxied": False}],
        policies,
        live.comparison["source_zone"],
        lan,
    )
    if check["counts"] != {"matched": 1}:
        return "policy_conflict"
    if "legacy" in entry:
        from unifi_legacy_claim import legacy_absence

        if fingerprint(matches[0]) != entry["legacy"]:
            return "modified_policy"
        legacy_absence(live, operation, policies, entry["policy_id"])
    return "orphan"


def retirement_state(path, target):
    try:
        path.lstat()
    except FileNotFoundError:
        return {}
    state = read(path)
    if (
        set(state) != {"version", "target", "observations"}
        or state["target"] != target
        or not isinstance(state["observations"], dict)
        or len(state["observations"]) > MAX_ROWS
    ):
        raise ApplyError("Retirement observation state invalid; review required")
    observations = state["observations"]
    for identifier, item in observations.items():
        if (
            row_id(identifier) != identifier
            or not isinstance(item, dict)
            or set(item) != {"identity", "first", "last"}
            or not isinstance(item["identity"], str)
            or not DIGEST.fullmatch(item["identity"])
            or type(item["first"]) is not int
            or type(item["last"]) is not int
            or not 0 < item["first"] <= item["last"] <= 2**32
        ):
            raise ApplyError("Retirement observation is invalid")
    return observations


def retirement_report(live, ledger, policies, protected, previous, now, grace):
    if policy_fingerprint(policies) != live.policies_id:
        raise ApplyError("UniFi policies changed during retirement review")
    observations, rows = {}, []
    for entry in ledger["owned"]:
        identifier = entry["policy_id"]
        status = retirement_candidate(entry, live, policies, protected)
        age = 0
        if status == "orphan":
            identity = fingerprint(entry)
            old = previous.get(identifier, {})
            first = now
            if (
                old.get("identity") == identity
                and 0 <= now - old["last"] <= RETIRE_MAX_GAP
            ):
                first = old["first"]
            observations[identifier] = {
                "identity": identity,
                "first": first,
                "last": now,
            }
            age = now - first
            status = "eligible" if age >= grace else "grace_period"
        rows.append(
            {
                "hostname": entry["operation"]["domain"],
                "address": entry["operation"]["ipv4Address"],
                "policy_id": identifier,
                "status": status,
                "observed_orphan_seconds": age,
            }
        )
    return rows, observations


def retirement_review(data, live, ledger):
    path = data / "unifi-retirement.json"
    previous = retirement_state(path, live.target)
    policies = all_rows(live.config, live.key, "dns", live.site)
    rows, observations = retirement_report(
        live,
        ledger,
        policies,
        retirement_protected(live),
        previous,
        int(time.time()),
        retirement_grace(),
    )
    return rows, observations


def retirement_preview(data):
    live = load_live()
    ledger = load_ledger(data / "unifi-ownership.json", live.target)
    rows, _ = retirement_review(data, live, ledger)
    report = {
        "mode": "read_only_retirement_review",
        "enabled": retirement_enabled(),
        "pending_write": ledger["pending"] is not None,
        "grace_hours": retirement_grace() // 3600,
        "counts": dict(sorted(Counter(row["status"] for row in rows).items())),
        "rows": rows,
    }
    encoded = json.dumps(report)
    if any(secret in encoded for secret in (live.key, live.token) if len(secret) >= 8):
        raise ApplyError("Retirement review contains a credential echo")
    return report


def retirement_replies(live, operation, *, deleting):
    address, name = operation["ipv4Address"], operation["domain"]
    gateway = live.config[0]
    missing = False
    for kind, answer, expected in (
        ("A", query(gateway, name + ".", "A"), address),
        (
            "PTR",
            query(gateway, ipaddress.ip_address(address).reverse_pointer + ".", "PTR"),
            name + ".",
        ),
    ):
        status, values = answer
        if status in {"nxdomain", "nodata"} and not values:
            continue
        if status == "answered" and values == [expected]:
            missing |= deleting
            continue
        missing |= dns_verification_failure(kind, status, values, acknowledged=deleting)
    return missing


def delete_owned_policy(live, identifier):
    """One exact-ID DELETE, with no retry or redirect."""
    path = f"{PREFIX}/sites/{row_id(live.site)}/dns/policies/{row_id(identifier)}"
    conn = connection(live.config)
    try:
        conn.request(
            "DELETE",
            path,
            headers={"Accept": "application/json", "X-API-Key": live.key},
        )
        if conn.getresponse().status != 200:
            raise ApplyError("UniFi retirement acknowledgement failed")
    finally:
        conn.close()


def confirm_retirement(path, ledger, live):
    entry = ledger["pending"]
    if "verification_deadline" not in entry:
        raise ApplyError("Retirement acknowledgement lacks a deadline")
    if time.time() >= entry["verification_deadline"]:
        raise ApplyError("Retirement verification deadline expired; review required")
    operation = entry["operation"]
    name, address = operation["domain"], operation["ipv4Address"]
    names, addresses, wildcards = retirement_protected(live)
    lan = ipaddress.IPv4Network(live.comparison["configured_lan"])
    if (
        ipv4(address) not in lan
        or ipv4(address) in (lan.network_address, lan.broadcast_address)
        or not name.endswith("." + live.comparison["source_zone"])
        or name in names
        or address in addresses
        or any(name == suffix or name.endswith("." + suffix) for suffix in wildcards)
    ):
        raise ApplyError("Retired policy became desired; review required")
    policies = all_rows(live.config, live.key, "dns", live.site)
    if any(row_id(policy["id"]) == entry["policy_id"] for policy in policies):
        raise ApplyError("Acknowledged retired policy remains present; review required")
    check = plan(
        [{"name": name, "type": "A", "content": address, "proxied": False}],
        policies,
        live.comparison["source_zone"],
        ipaddress.IPv4Network(live.comparison["configured_lan"]),
    )
    if check["counts"] != {"candidate": 1}:
        raise ApplyError("New local policy conflicts with retirement")
    previous = next(
        item for item in ledger["owned"] if item["policy_id"] == entry["policy_id"]
    )
    if "legacy" in previous:
        from unifi_legacy_claim import legacy_absence

        legacy_absence(live, operation, policies, entry["policy_id"])
    missing = retirement_replies(live, operation, deleting=True)
    if time.time() >= entry["verification_deadline"]:
        raise ApplyError("Retirement verification deadline expired; review required")
    if missing:
        raise DNSVerificationPending("Retired policy is awaiting A and PTR absence")
    ledger["owned"] = [
        item for item in ledger["owned"] if item["policy_id"] != entry["policy_id"]
    ]
    ledger["pending"] = None
    # Commit absence before any best-effort notice. A crash cannot replay it.
    write(path, ledger, durable=True)
    if getenv("YGGFLARE_UNIFI_DISCORD_NOTIFY") == "true":
        try:
            accepted = discord_notice(operation, RETIRE_ACTION)
        except (ValueError, OSError, http.client.HTTPException):
            accepted = False
        if not accepted:
            print(
                "UniFi retirement Discord notification was not confirmed.",
                file=sys.stderr,
            )


def retire_one(data, path, ledger, live):
    """Observe all owned policies, then retire at most one eligible orphan."""
    state = data / "unifi-retirement.json"
    try:
        rows, observations = retirement_review(data, live, ledger)
    except Exception:
        state.unlink(missing_ok=True)
        raise
    write(
        state,
        {"version": 1, "target": live.target, "observations": observations},
        durable=True,
    )
    eligible = sorted(
        (row for row in rows if row["status"] == "eligible"),
        key=lambda row: row["hostname"],
    )
    if not eligible:
        return None
    if not ledger["pilot_verified"]:
        raise ApplyError("A verified manual pilot is required before retirement")
    if getenv("YGGFLARE_UNIFI_API_KEY_FILE") != UNIFI_KEY_FILE:
        raise ApplyError("UniFi retirement requires the mounted Compose secret")
    identifier = eligible[0]["policy_id"]
    owned = next(item for item in ledger["owned"] if item["policy_id"] == identifier)
    refreshed = load_live()
    policies = all_rows(refreshed.config, refreshed.key, "dns", refreshed.site)
    if refreshed.inputs != live.inputs or refreshed.target != ledger["target"]:
        raise ApplyError("Live retirement inputs changed")
    if (
        policy_fingerprint(policies) != refreshed.policies_id
        or retirement_candidate(
            owned, refreshed, policies, retirement_protected(refreshed)
        )
        != "orphan"
    ):
        raise ApplyError("Retirement candidate changed")
    operation = owned["operation"]
    retirement_replies(refreshed, operation, deleting=False)
    final = load_live()
    if final.inputs != refreshed.inputs or final.target != refreshed.target:
        raise ApplyError("Live retirement inputs changed immediately before deletion")
    if (
        retirement_candidate(
            owned,
            final,
            all_rows(final.config, final.key, "dns", final.site),
            retirement_protected(final),
        )
        != "orphan"
    ):
        raise ApplyError("Retirement candidate changed immediately before deletion")
    policies = all_rows(final.config, final.key, "dns", final.site)
    if policy_fingerprint(policies) != refreshed.policies_id:
        raise ApplyError("UniFi policies changed immediately before retirement")
    if not retirement_enabled():
        raise ApplyError("Automatic retirement is disabled")
    pending = {
        "operation": operation,
        "policy_id": None,
        "manual": False,
        "repair": {
            "action": RETIRE_ACTION,
            "previous_id": identifier,
            "previous_address": operation["ipv4Address"],
        },
    }
    ledger["pending"] = pending
    write(path, ledger, durable=True)
    delete_owned_policy(final, identifier)
    pending.update(policy_id=identifier, verification_deadline=verification_deadline())
    write(path, ledger, durable=True)
    confirm_pending(path, ledger, load_live())
    return "Retired and verified one owned UniFi DNS policy"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hostname", nargs="?", default="")
    parser.add_argument("fingerprint", nargs="?", default="")
    parser.add_argument("--automatic", action="store_true")
    parser.add_argument("--repair", action="store_true")
    parser.add_argument("--retirement-plan", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    signal.alarm(180)
    try:
        if args.retirement_plan:
            if args.automatic or args.repair or args.hostname or args.fingerprint:
                raise ApplyError("Invalid retirement preview invocation")
            report = retirement_preview(Path("/data"))
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0
        if args.repair:
            if args.automatic or (args.json and args.fingerprint):
                raise ApplyError("Invalid repair invocation")
            result = run_repair(Path("/data"), args.hostname, args.fingerprint or None)
            print(
                json.dumps(result, indent=2, sort_keys=True)
                if isinstance(result, dict)
                else result
            )
            return 0
        if args.json or (args.automatic and (args.hostname or args.fingerprint)):
            raise ApplyError("Invalid create invocation")
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
