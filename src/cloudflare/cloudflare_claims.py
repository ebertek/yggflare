"""Explicit bulk adoption of matching internal A records, with no API writes."""

from collections import Counter

from cloudflare_api import checked_id
from cloudflare_internal_ownership import (
    REGISTRY_FILE,
    assert_available,
    detail_fingerprint,
    load_registry,
    record_matches,
    save_registry,
)
from cloudflare_orphans import locked_registry


def claim_internal(client, data, bound, wanted, *, filename=REGISTRY_FILE):
    """Claim only exact unique name/address pairs; never update prior identities."""
    results = {}
    with locked_registry(data):
        document = load_registry(data, bound, filename=filename)
        records = client.list_dns(bound["zone"])
        addresses = Counter(wanted.values())
        for hostname, address in sorted(wanted.items()):
            if any(
                entry["hostname"] == hostname
                for entry in document["records"].values()
            ):
                results[hostname] = "already owned"
                continue
            action = {"hostname": hostname, "content": address}
            matches = [
                record
                for record in records
                if record.get("name", "").lower().rstrip(".") == hostname
                or (record.get("type") == "A" and record.get("content") == address)
            ]
            if len(matches) != 1 or addresses[address] != 1:
                results[hostname] = "skipped: missing or ambiguous A record"
                continue
            record = matches[0]
            identifier = checked_id(record.get("id"), "DNS record ID")
            if not record_matches(record, identifier, action):
                results[hostname] = "skipped: A record differs"
                continue
            try:
                assert_available(document, action)
            except ValueError:
                results[hostname] = "skipped: ownership conflict"
                continue
            if identifier in document["records"]:
                results[hostname] = "skipped: record ID already owned"
                continue
            detail = client.get_dns_record(bound["zone"], identifier)
            if not record_matches(detail, identifier, action) or any(
                record.get(field) != detail.get(field)
                for field in ("ttl", "comment", "tags", "settings", "modified_on")
            ):
                results[hostname] = "skipped: exact-ID verification differs"
                continue
            document["records"][identifier] = {
                "id": identifier,
                "hostname": hostname,
                "address": address,
                "fingerprint": detail_fingerprint(detail),
            }
            results[hostname] = "claimed"
        if "claimed" in results.values():
            save_registry(data, document, filename=filename)
    return results
