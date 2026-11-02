"""Private, read-only declarations of intentionally retained ygg.nu records.

These declarations recognize expected live DNS shapes; they never authorize
creation, modification, or deletion through the Cloudflare reconciler.
"""

import ipaddress
import json
import re

RETAINED = "Scripts/cloudflare/retained-dns.json"
HOST = re.compile(r"^(?:[a-z0-9_][a-z0-9_-]{0,62}\.)+ygg\.nu$")
TYPE = re.compile(r"^[A-Z][A-Z0-9]{0,9}$")
CONTENT_REQUIRED = frozenset({"A", "AAAA", "CNAME"})
DOMAIN_TARGETS = frozenset({"CNAME", "PTR", "NS"})


def validate_document(document):
    """Require an explicit, bounded version-one retained DNS record list."""
    if not isinstance(document, dict) or set(document) != {"version", "records"}:
        raise ValueError("Invalid retained DNS inventory structure")
    if document["version"] != 1 or isinstance(document["version"], bool):
        raise ValueError("Unsupported retained DNS inventory version")
    records = document["records"]
    if not isinstance(records, list) or len(records) > 256:
        raise ValueError("Invalid retained DNS record list")
    return records


def validate_identity(record, index):
    """Require canonical DNS names and record types, including DNS-SD labels."""
    if (
        not isinstance(record, dict)
        or not {"hostname", "type"} <= set(record)
        or set(record) - {"hostname", "type", "content", "description"}
    ):
        raise ValueError(f"Invalid retained DNS entry {index}")
    hostname = record["hostname"]
    kind = record["type"]
    if not isinstance(hostname, str) or len(hostname) > 253:
        raise ValueError(f"Invalid retained DNS hostname at entry {index}")
    if not HOST.fullmatch(hostname):
        raise ValueError(f"Invalid retained DNS hostname at entry {index}")
    if any(len(label) > 63 for label in hostname.split(".")):
        raise ValueError(f"Invalid retained DNS label at entry {index}")
    if not isinstance(kind, str) or not TYPE.fullmatch(kind):
        raise ValueError(f"Invalid retained DNS type at entry {index}")
    return hostname, kind


def validate_payload(record, hostname, kind):
    """Validate optional content and metadata without exposing their values."""
    content = record.get("content")
    if "content" in record and (
        not isinstance(content, str)
        or not content.strip()
        or len(content) > 512
        or any(ord(char) < 32 for char in content)
    ):
        raise ValueError(f"{hostname}: invalid retained DNS content")
    if kind in CONTENT_REQUIRED and "content" not in record:
        raise ValueError(f"{hostname}: {kind} requires expected content")
    if kind in {"A", "AAAA"}:
        try:
            address = ipaddress.ip_address(content)
        except ValueError as error:
            raise ValueError(f"{hostname}: invalid {kind} address") from error
        expected_version = 4 if kind == "A" else 6
        if address.version != expected_version or str(address) != content:
            raise ValueError(f"{hostname}: noncanonical {kind} address")
    description = record.get("description")
    if "description" in record and (
        not isinstance(description, str)
        or not description.strip()
        or len(description) > 256
        or any(ord(char) < 32 for char in description)
    ):
        raise ValueError(f"{hostname}: invalid retained DNS description")
    return content


def load_retained_dns(path):
    """Load and validate optional exact-type DNS exceptions from private GitOps."""
    if not path.is_file():
        return []
    document = json.loads(path.read_text(encoding="utf-8"))
    declarations = []
    seen = set()
    for index, record in enumerate(validate_document(document), 1):
        hostname, kind = validate_identity(record, index)
        content = validate_payload(record, hostname, kind)
        identity = (hostname, kind, content)
        if identity in seen:
            raise ValueError(f"{hostname}: duplicate retained DNS entry")
        seen.add(identity)
        declarations.append(record)
    return declarations


def matches_retained(expected, actual):
    """Require identical name, type and optional exact target."""
    raw_name = actual.get("name")
    raw_type = actual.get("type")
    if (
        not isinstance(raw_name, str)
        or raw_name.lower().rstrip(".") != expected["hostname"]
        or not isinstance(raw_type, str)
        or raw_type.upper() != expected["type"]
    ):
        return False
    if "content" not in expected:
        return True
    live_content = actual.get("content")
    if not isinstance(live_content, str):
        return False
    if expected["type"] in DOMAIN_TARGETS:
        return live_content.lower().rstrip(".") == expected["content"].lower().rstrip(
            "."
        )
    return live_content == expected["content"]


def retained_summary(expected, live):
    """Report absent retained declarations without exposing TXT-like contents."""
    missing = []
    for entry in expected:
        if not any(matches_retained(entry, record) for record in live):
            finding = {"hostname": entry["hostname"], "type": entry["type"]}
            if entry["type"] in CONTENT_REQUIRED:
                finding["content"] = entry["content"]
            missing.append(finding)
    return {
        "declared": len(expected),
        "present": len(expected) - len(missing),
        "missing": missing,
    }
