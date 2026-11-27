"""Explicit, fingerprint-approved adoption of one retired internal Docker A."""

import argparse
import fcntl
import hmac
import ipaddress
import json
import os
import re
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

from cloudflare_api import CloudflareClient, CloudflareError, checked_id
from cloudflare_credentials import api_token
from cloudflare_docker_dns import canonical_name
from cloudflare_internal_cleanup import (
    fresh_review,
    journal_path,
    load_state,
    save_state,
    scope_for,
)
from cloudflare_internal_ownership import (
    assert_available,
    detail_fingerprint,
    load_registry,
    record_matches,
    save_registry,
    validate_entry,
)
from cloudflare_internal_retirement import checked_records, normalized
from cloudflare_orphans import digest, locked_registry
from yggflare_config import cloudflare_settings

APPROVAL = re.compile(r"[0-9a-f]{16}")


@contextmanager
def write_lock():
    """Use the existing normal-writer lock before the shared ownership lock."""
    path = Path.home() / "cloudflare" / ".cloudflare-manage.lock"
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "r+") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def orphan_candidate(report, owned, hostname):
    """Require one unblocked, unmanaged record and no ownership collision."""
    rows = report["rows"]
    if report["selected_dns_record_count"] != 1 or len(rows) != 1:
        raise ValueError("Legacy claim requires exactly one supported DNS record")
    row = rows[0]
    if (
        row["hostname"] != hostname
        or row["ownership"] != "unmanaged"
        or row["status"] != "unmanaged"
    ):
        raise ValueError("Legacy claim blocked by ownership or retirement evidence")
    identifier = checked_id(row["record_id"], "legacy DNS record ID")
    if any(
        identifier == entry["id"]
        or hostname == entry["hostname"]
        or row["address"] == entry["address"]
        for _, entry in owned.values()
    ):
        raise ValueError("Legacy claim conflicts with existing ownership")
    return row


def verified_entry(client, bound, row):
    """Require matching list and exact-ID detail; reject unsupported shapes."""
    identifier = row["record_id"]
    hostname = row["hostname"]
    address = row["address"]
    action = {"hostname": hostname, "content": address}
    if ipaddress.IPv4Address(address) not in ipaddress.IPv4Network(bound["network"]):
        raise ValueError("Legacy claim is limited to the Docker allocation")
    records = checked_records(client.list_dns(bound["zone"]))
    matches = [
        record
        for record in records
        if normalized(record["name"]) == hostname
        or record["id"] == identifier
        or (record["type"] == "A" and record["content"] == address)
    ]
    if len(matches) != 1 or not record_matches(matches[0], identifier, action):
        raise ValueError("Legacy DNS list identity changed")
    detail = client.get(f"/zones/{bound['zone']}/dns_records/{identifier}")["result"]
    if not record_matches(detail, identifier, action) or any(
        matches[0].get(field) != detail.get(field)
        for field in ("ttl", "comment", "tags", "settings", "modified_on")
    ):
        raise ValueError("Legacy DNS detail identity changed")
    entry = {
        "id": identifier,
        "hostname": hostname,
        "address": address,
        "fingerprint": detail_fingerprint(detail),
    }
    validate_entry(entry, bound)
    return entry


def review_claim(client, data, settings, hostname):
    """Read fresh evidence twice, without recording ownership or approval state."""
    if canonical_name(hostname, settings["internal_zone"]) != hostname:
        raise ValueError("Legacy claim requires a canonical internal hostname")
    report, bound, external, owned = fresh_review(client, data, settings, hostname)
    row = orphan_candidate(report, owned, hostname)
    scope = scope_for(bound, external)
    if journal_path(data).exists():
        state = load_state(data, scope)
        if state["pending"] is not None:
            raise ValueError("Pending internal DNS retirement blocks legacy claim")
    entry = verified_entry(client, bound, row)

    # Recheck declarations, runtime, zone scope and ownership after detail GET.
    report, actual, external, owned = fresh_review(client, data, settings, hostname)
    if (
        scope_for(actual, external) != scope
        or orphan_candidate(report, owned, hostname) != row
        or verified_entry(client, actual, row) != entry
    ):
        raise ValueError("Legacy claim evidence changed during review")
    plan = {
        "action": "claim_retired_docker_a",
        "scope": scope,
        "entry": entry,
    }
    return plan, digest(plan)


def apply_claim(client, data, settings, hostname, approval):
    """Approve local ownership only; the normal retirement scheduler owns DELETE."""
    if not isinstance(approval, str) or not APPROVAL.fullmatch(approval):
        raise ValueError("Legacy claim requires a reviewed fingerprint")
    with write_lock(), locked_registry(data):
        plan, expected = review_claim(client, data, settings, hostname)
        if not hmac.compare_digest(approval, expected):
            raise ValueError("Legacy claim plan changed; review a new fingerprint")
        bound = plan["scope"]["internal"]
        entry = plan["entry"]
        ledger = load_registry(data, bound)
        assert_available(
            ledger, {"hostname": entry["hostname"], "content": entry["address"]}
        )
        if entry["id"] in ledger["records"]:
            raise ValueError("Legacy DNS record ID already owned")
        if journal_path(data).exists():
            state = load_state(data, plan["scope"])
            if state["pending"] is not None:
                raise ValueError("Pending internal DNS retirement blocks legacy claim")
            # No previous observation may age a newly adopted identity.
            state["observations"].pop(entry["id"], None)
            save_state(data, state)
        ledger["records"][entry["id"]] = entry
        save_registry(data, ledger)
    return entry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--approval")
    args = parser.parse_args()
    try:
        # Even the apply path has no remote mutation methods available.
        client = CloudflareClient(api_token())
        data = Path("/data")
        settings = cloudflare_settings()
        if args.approval is None:
            plan, token = review_claim(client, data, settings, args.hostname)
            print(json.dumps({"plan": plan, "approval": token}, indent=2))
            print("No changes made. Approval permits subsequent guarded retirement.")
            print(
                "To approve: docker exec yggflare yggflare cloudflare "
                f"legacy-claim-apply {args.hostname} {token}"
            )
        else:
            entry = apply_claim(client, data, settings, args.hostname, args.approval)
            print(f"Claimed retired Docker A record: {entry['hostname']}")
            print(
                "No Cloudflare changes made. Automatic cleanup, if enabled, "
                "requires a new observed grace period."
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
            "ERROR: Legacy internal claim blocked; review live retirement evidence "
            "and ownership/recovery state.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
