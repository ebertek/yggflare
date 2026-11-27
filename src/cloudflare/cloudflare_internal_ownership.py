"""Durable provenance for verified internal Docker A record creation.

This registry does not authorize deletion. Existing records are never adopted
implicitly, and a lost creation acknowledgement cannot establish ownership.
"""

import hashlib
import ipaddress
import json
import os
import re
import tempfile
from pathlib import Path

from cloudflare_api import checked_id
from cloudflare_docker_dns import check_docker_target
from cloudflare_orphans import locked_registry

REGISTRY_FILE = "managed-internal-dns.json"
MAX_BYTES = 1024 * 1024
DIGEST = re.compile(r"[0-9a-f]{64}")


def internal_scope(account, zone, domain, network):
    """Bind ownership to the exact account, zone, domain and Docker subnet."""
    if not isinstance(domain, str) or not re.fullmatch(
        r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", domain
    ):
        raise ValueError("Invalid internal DNS domain")
    parsed = ipaddress.IPv4Network(network)
    return {
        "account": checked_id(account, "account ID"),
        "zone": checked_id(zone, "internal zone ID"),
        "domain": domain,
        "network": str(parsed),
    }


def registry_path(data):
    path = Path(data) / REGISTRY_FILE
    if path.is_symlink():
        raise ValueError("Internal DNS ownership registry must not be a symlink")
    return path


def validate_entry(entry, bound):
    """Validate persisted identity and the non-secret detail fingerprint."""
    if not isinstance(entry, dict) or set(entry) != {
        "id",
        "hostname",
        "address",
        "fingerprint",
    }:
        raise ValueError("Invalid internal DNS ownership entry")
    checked_id(entry["id"], "DNS record ID")
    check_docker_target(
        entry["hostname"],
        entry["address"],
        bound["domain"],
        ipaddress.IPv4Network(bound["network"]),
    )
    fingerprint = entry["fingerprint"]
    if not isinstance(fingerprint, str) or not DIGEST.fullmatch(fingerprint):
        raise ValueError("Invalid internal DNS ownership fingerprint")


def validate_registry(document, bound=None):
    """Reject malformed, conflicting or cross-scope ownership state."""
    if (
        not isinstance(document, dict)
        or set(document) != {"version", "scope", "records"}
        or type(document["version"]) is not int
        or document["version"] != 1
        or not isinstance(document["scope"], dict)
        or not isinstance(document["records"], dict)
    ):
        raise ValueError("Invalid internal DNS ownership registry")
    scope = document["scope"]
    if set(scope) != {"account", "zone", "domain", "network"}:
        raise ValueError("Invalid internal DNS ownership scope")
    if scope != internal_scope(**scope) or (bound is not None and scope != bound):
        raise ValueError("Internal DNS ownership scope changed")
    names = set()
    addresses = set()
    for identifier, entry in document["records"].items():
        validate_entry(entry, scope)
        if (
            identifier != entry["id"]
            or entry["hostname"] in names
            or entry["address"] in addresses
        ):
            raise ValueError("Conflicting internal DNS ownership entries")
        names.add(entry["hostname"])
        addresses.add(entry["address"])
    return document


def unique_object(pairs):
    """Reject duplicate keys in persisted security state."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate internal DNS ownership key")
        result[key] = value
    return result


def load_registry(data, bound=None):
    """Missing state grants no ownership; invalid state is never ignored."""
    path = registry_path(data)
    if not path.exists():
        if bound is None:
            raise ValueError("Internal DNS ownership scope required")
        return validate_registry({"version": 1, "scope": bound, "records": {}})
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("Invalid internal DNS ownership registry file")
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=unique_object
        )
        return validate_registry(document, bound)
    except (ValueError, TypeError, KeyError, RecursionError):
        raise ValueError(
            "Invalid or incompatible internal DNS ownership registry"
        ) from None


def assert_available(document, action):
    """Never overwrite a prior identity even when its DNS record is missing."""
    if any(
        entry["hostname"] == action["hostname"] or entry["address"] == action["content"]
        for entry in document["records"].values()
    ):
        raise ValueError("Docker DNS target conflicts with recorded ownership")


def save_registry(data, document):
    """Atomically persist only validated identity and a hash, not API payloads."""
    validate_registry(document)
    path = registry_path(data)
    content = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if len(content.encode("utf-8")) > MAX_BYTES:
        raise ValueError("Internal DNS ownership registry exceeds size limit")
    handle, temporary = tempfile.mkstemp(prefix=".internal-dns-", dir=data)
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, "w", encoding="utf-8") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        descriptor = os.open(data, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def record_matches(record, identifier, action):
    return (
        isinstance(record, dict)
        and record.get("id") == identifier
        and record.get("name") == action["hostname"]
        and record.get("type") == "A"
        and record.get("content") == action["content"]
        and record.get("proxied") is False
    )


def detail_fingerprint(record):
    """Hash the exact detail response conservatively; changed fields block reuse."""
    return hashlib.sha256(
        json.dumps(
            record, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    ).hexdigest()


def record_creation(data, bound, action, acknowledged, listed, client):
    """Require the POST ID, unique listed identity and fresh exact-ID GET."""
    if not isinstance(acknowledged, dict):
        raise ValueError("Docker DNS creation acknowledgement missing")
    identifier = checked_id(acknowledged.get("id"), "created DNS record ID")
    if not record_matches(acknowledged, identifier, action) or not record_matches(
        listed, identifier, action
    ):
        raise ValueError("Docker DNS creation identity verification failed")
    detail = client.get_dns_record(bound["zone"], identifier)
    if not record_matches(detail, identifier, action):
        raise ValueError("Docker DNS exact-ID verification failed")
    # Refuse to claim an object modified between POST and the verification GET.
    for field in ("ttl", "comment", "tags", "settings", "modified_on"):
        if acknowledged.get(field) != detail.get(field):
            raise ValueError("Docker DNS creation attributes changed")
    entry = {
        "id": identifier,
        "hostname": action["hostname"],
        "address": action["content"],
        "fingerprint": detail_fingerprint(detail),
    }
    # Reuse the Cloudflare ownership lock for consistent registry serialization.
    with locked_registry(data):
        document = load_registry(data, bound)
        assert_available(document, action)
        if identifier in document["records"]:
            raise ValueError("Docker DNS record ID already owned")
        document["records"][identifier] = entry
        save_registry(data, document)
    return entry
