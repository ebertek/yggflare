"""Explicit local-only ownership adoption of one retired UniFi A policy."""

import argparse
import fcntl
import hmac
import ipaddress
import json
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

import unifi_apply as writer
from cloudflare_api import CloudflareClient, CloudflareError, checked_id
from cloudflare_internal_cleanup import snapshot_digest
from cloudflare_internal_retirement import (
    checked_records,
    compose_evidence,
    docker_containers,
    mentions,
    runtime_evidence,
)
from unifi_api import MAX_ROWS, all_rows, hostname, row_id
from unifi_reconcile_plan import fingerprint, load_live, policy_fingerprint
from yggflare_config import cloudflare_settings
from yggflare_env import getenv


def legacy_absence(live, operation, policies, identifier):
    """Check additional legacy dependencies, without exporting source or API data."""
    from controller import snapshot

    name, address = operation["domain"], operation["ipv4Address"]
    zone = live.comparison["source_zone"]
    settings = cloudflare_settings()
    account = checked_id(settings["account_id"])
    client = CloudflareClient(live.token)
    external = checked_id(client.zone_id(settings["external_zone"], account))
    internal = checked_id(client.zone_id(zone, account))
    if external == internal or any(
        settings.get(key) and settings[key] != actual
        for key, actual in (
            ("external_zone_id", external),
            ("internal_zone_id", internal),
        )
    ):
        raise writer.ApplyError("Legacy UniFi DNS scope changed")
    sibling = name.removesuffix("." + zone) + "." + settings["external_zone"]
    records = checked_records(client.list_dns(external))
    for row in [*live.records, *records]:
        record_name = row["name"].lower().rstrip(".")
        if (
            record_name in (name, sibling)
            or record_name.endswith("." + name)
            or (
                record_name.startswith("*.")
                and any(
                    candidate.endswith(record_name[1:]) for candidate in (name, sibling)
                )
            )
            or mentions([row.get("content"), row.get("data")], name, address)
        ):
            raise writer.ApplyError(
                "Legacy UniFi policy still referenced by Cloudflare"
            )
    for policy in policies:
        if row_id(policy["id"]) == identifier:
            continue
        if mentions(policy, name, address):
            raise writer.ApplyError("Legacy UniFi policy has a local dependency")
    with (
        tempfile.TemporaryDirectory() as first,
        tempfile.TemporaryDirectory() as second,
    ):
        root = snapshot(Path(first))
        before = snapshot_digest(root)
        names, addresses, references = compose_evidence(root, zone)
        containers = docker_containers()
        running_names, running_addresses = runtime_evidence(containers, zone)
        if (
            name in names | running_names
            or address in addresses | running_addresses
            or mentions(references, name, address)
            or mentions(containers, name, address)
        ):
            raise writer.ApplyError(
                "Legacy UniFi policy still referenced by Compose or Docker"
            )
        if snapshot_digest(snapshot(Path(second))) != before:
            raise writer.ApplyError("Legacy UniFi source changed during review")


def review_claim(data, live, ledger, selected, policies):
    """A positive exact local A/PTR observation permits adoption, not deletion."""
    if hostname(selected) != selected or not selected:
        raise writer.ApplyError("Legacy claim requires an exact hostname")
    if ledger["pending"] is not None or not ledger["pilot_verified"]:
        raise writer.ApplyError(
            "Legacy claim requires a verified pilot and no pending write"
        )
    if len(ledger["owned"]) >= MAX_ROWS:
        raise writer.ApplyError("Ownership ledger is at capacity")
    if policy_fingerprint(policies) != live.policies_id:
        raise writer.ApplyError("UniFi policies changed during legacy review")
    matches = [
        row
        for row in policies
        if isinstance(row.get("domain"), str)
        and row["domain"].lower().rstrip(".") == selected
    ]
    if len(matches) != 1:
        raise writer.ApplyError("Legacy claim requires exactly one local policy")
    row = matches[0]
    identifier = row_id(row["id"])
    operation = {
        "operation": "create",
        **{
            key: row.get(key)
            for key in ("type", "domain", "ipv4Address", "enabled", "ttlSeconds")
        },
    }
    if not writer.valid_operation(operation):
        raise writer.ApplyError("Legacy policy shape is unsupported")
    entry = {
        "operation": operation,
        "policy_id": identifier,
        "manual": False,
        "legacy": fingerprint(row),
    }
    if any(
        old["policy_id"] == identifier
        or old["operation"]["domain"] == selected
        or old["operation"]["ipv4Address"] == operation["ipv4Address"]
        for old in ledger["owned"]
    ):
        raise writer.ApplyError("Legacy policy conflicts with existing ownership")
    if (
        writer.retirement_candidate(
            entry, live, policies, writer.retirement_protected(live)
        )
        != "orphan"
    ):
        raise writer.ApplyError("Legacy policy is not an unblocked retired candidate")
    address = operation["ipv4Address"]
    gateway = live.config[0]
    forward = writer.query(gateway, selected + ".", "A")
    reverse = writer.query(
        gateway, ipaddress.ip_address(address).reverse_pointer + ".", "PTR"
    )
    if forward != ("answered", [address]) or reverse != ("answered", [selected + "."]):
        raise writer.ApplyError(
            "Legacy policy requires exact matching A and PTR replies"
        )
    writer.retirement_state(data / "unifi-retirement.json", live.target)
    report = {
        "mode": "read_only_legacy_claim",
        "hostname": selected,
        "target": live.target,
        "entry": entry,
        "forward": forward,
        "reverse": reverse,
    }
    report["fingerprint"] = fingerprint(
        {"inputs": live.inputs, "ledger": ledger, "report": report}
    )
    encoded = json.dumps(report)
    if any(secret in encoded for secret in (live.key, live.token) if len(secret) >= 8):
        raise writer.ApplyError("Legacy claim preview contains a credential echo")
    return report


def fresh_plan(data, selected):
    live = load_live()
    ledger = writer.load_ledger(data / "unifi-ownership.json", live.target)
    policies = all_rows(live.config, live.key, "dns", live.site)
    return review_claim(data, live, ledger, selected, policies), live, ledger


def run(data, selected, approval=None):
    if approval is None:
        return fresh_plan(data, selected)[0]
    if not isinstance(approval, str) or not writer.DIGEST.fullmatch(approval):
        raise writer.ApplyError("Legacy claim requires a reviewed SHA-256 fingerprint")
    if getenv("YGGFLARE_UNIFI_API_KEY_FILE") != writer.UNIFI_KEY_FILE:
        raise writer.ApplyError("Legacy claim requires the mounted Compose secret")
    descriptor = os.open(
        data / "unifi-apply.lock",
        os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
        0o600,
    )
    with os.fdopen(descriptor, "r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        report, _, _ = fresh_plan(data, selected)
        if not hmac.compare_digest(report["fingerprint"], approval):
            raise writer.ApplyError("Legacy claim preview changed")
        final, live, ledger = fresh_plan(data, selected)
        if final != report:
            raise writer.ApplyError("Legacy claim evidence changed before adoption")
        entry = final["entry"]
        state_path = data / "unifi-retirement.json"
        observations = writer.retirement_state(state_path, live.target)
        if entry["policy_id"] in observations:
            del observations[entry["policy_id"]]
            writer.write(
                state_path,
                {"version": 1, "target": live.target, "observations": observations},
                durable=True,
            )
        ledger["owned"].append(entry)
        writer.write(data / "unifi-ownership.json", ledger, durable=True)
    return "Claimed one retired UniFi policy; no remote changes made"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--approval")
    args = parser.parse_args()
    signal.alarm(180)
    try:
        result = run(Path("/data"), args.hostname, args.approval)
        print(
            json.dumps(result, indent=2, sort_keys=True)
            if isinstance(result, dict)
            else result
        )
        return 0
    except (
        CloudflareError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        RuntimeError,
        subprocess.SubprocessError,
    ):
        print(
            "ERROR: Legacy UniFi claim blocked; review live evidence and ownership.",
            file=sys.stderr,
        )
        return 2
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    sys.exit(main())
