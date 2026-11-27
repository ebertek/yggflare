"""Guarded, separately opted-in retirement of owned Docker A records."""

import hashlib
import http.client
import json
import math
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

from cloudflare_api import CloudflareError, checked_id
from cloudflare_credentials import api_token
from cloudflare_internal_ownership import (
    MAX_BYTES,
    REGISTRY_FILE,
    internal_scope,
    load_registry,
    save_registry,
    unique_object,
    validate_entry,
)
from cloudflare_internal_retirement import collect_context
from cloudflare_orphans import locked_registry
from cloudflare_retained_dns import RETAINED
from cloudflare_static_dns import INVENTORY
from cloudflare_write_api import CloudflareWriter
from discord_embed import embed_payload, inline_code
from discord_webhook import read_webhook
from yggflare_config import cloudflare_settings
from yggflare_env import getenv

JOURNAL = "internal-dns-retirement.json"
MAX_GAP = 8 * 3600
CANDIDATE = "candidate_review_only"


def scope_for(bound, external_zone):
    if bound != internal_scope(**bound):
        raise ValueError("Invalid internal retirement scope")
    if checked_id(external_zone) == bound["zone"]:
        raise ValueError("Invalid external retirement scope")
    return {"internal": bound, "external_zone": external_zone}


def stamp(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def validate_state(state, scope=None):
    """Reject invalid or cross-target durable observations and recovery state."""
    if (
        not isinstance(state, dict)
        or set(state) != {"version", "scope", "observations", "pending"}
        or type(state["version"]) is not int
        or state["version"] != 1
        or not isinstance(state["scope"], dict)
        or set(state["scope"]) != {"internal", "external_zone"}
        or not isinstance(state["observations"], dict)
    ):
        raise ValueError("Invalid internal retirement journal")
    saved_scope = state["scope"]
    bound = saved_scope["internal"]
    if saved_scope != scope_for(bound, saved_scope["external_zone"]) or (
        scope is not None and saved_scope != scope
    ):
        raise ValueError("Internal retirement scope changed")
    for identifier, item in state["observations"].items():
        if not isinstance(item, dict) or set(item) != {"entry", "first", "last"}:
            raise ValueError("Invalid internal retirement observation")
        validate_entry(item["entry"], bound)
        if (
            identifier != item["entry"]["id"]
            or not stamp(item["first"])
            or not stamp(item["last"])
            or item["first"] > item["last"]
        ):
            raise ValueError("Invalid internal retirement observation")
    pending = state["pending"]
    if pending is not None:
        if (
            not isinstance(pending, dict)
            or set(pending) != {"entry", "phase"}
            or pending["phase"] not in ("intent", "acknowledged", "verified")
        ):
            raise ValueError("Invalid internal retirement pending write")
        validate_entry(pending["entry"], bound)
        if pending["entry"]["id"] in state["observations"]:
            raise ValueError("Pending retirement also has an observation")
    return state


def journal_path(data):
    path = Path(data) / JOURNAL
    if path.is_symlink():
        raise ValueError("Internal retirement journal must not be a symlink")
    return path


def load_state(data, scope=None):
    path = journal_path(data)
    if not path.exists():
        if scope is None:
            raise ValueError("Missing internal retirement scope")
        return validate_state(
            {"version": 1, "scope": scope, "observations": {}, "pending": None}
        )
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("Invalid internal retirement journal file")
    return validate_state(
        json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object),
        scope,
    )


def save_state(data, state):
    """Persist each phase before crossing the next mutation boundary."""
    validate_state(state)
    path = journal_path(data)
    encoded = json.dumps(state, sort_keys=True, indent=2, allow_nan=False) + "\n"
    if len(encoded.encode()) > MAX_BYTES:
        raise ValueError("Internal retirement journal exceeds size limit")
    fd, temporary = tempfile.mkstemp(prefix=".internal-retirement-", dir=data)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        descriptor = os.open(data, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def candidates(report, owned):
    """Only exact, currently owned Docker A identities can start a timer."""
    result = {}
    for row in report["rows"]:
        identifier = row["record_id"]
        if row["ownership"] != "docker" or row["status"] != CANDIDATE:
            continue
        category, entry = owned[identifier]
        if (
            category != "docker"
            or row["hostname"] != entry["hostname"]
            or row["address"] != entry["address"]
            or identifier != entry["id"]
            or identifier in result
        ):
            raise ValueError("Inconsistent internal retirement evidence")
        result[identifier] = entry
    return result


def observe(previous, current, now, grace):
    """Age only identical consecutive candidates; never carry across a gap."""
    if not stamp(now) or not 24 * 3600 <= grace <= 720 * 3600:
        raise ValueError("Invalid internal retirement clock or grace")
    fresh, eligible = {}, []
    for identifier, entry in sorted(current.items()):
        old = previous.get(identifier)
        first = now
        if old and old["entry"] == entry and 0 <= now - old["last"] <= MAX_GAP:
            first = old["first"]
        fresh[identifier] = {"entry": entry, "first": first, "last": now}
        if now - first >= grace:
            eligible.append(identifier)
    return fresh, eligible


def snapshot_digest(root):
    """Compare complete copied inputs without publishing their content."""
    paths = sorted(
        set(root.rglob("compose.yaml"))
        | set(root.rglob("compose.yml"))
        | {root / INVENTORY, root / RETAINED}
    )
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(root).as_posix().encode() + b"\0")
        if path.is_file():
            digest.update(hashlib.sha256(path.read_bytes()).digest())
        else:
            digest.update(b"missing")
    return digest.hexdigest()


def fresh_review(client, data, settings, hostname=None):
    """Take a fresh private snapshot and reject source changes during review."""
    from controller import snapshot

    with tempfile.TemporaryDirectory(prefix="internal-review-", dir=data) as first:
        with tempfile.TemporaryDirectory(prefix="internal-review-", dir=data) as second:
            root = snapshot(Path(first))
            before = snapshot_digest(root)
            result = collect_context(client, root, data, settings, hostname)
            if snapshot_digest(snapshot(Path(second))) != before:
                raise ValueError("Retirement source changed during review")
            return result


def notice(entry):
    """Validated fixed-host HTTPS; no redirects or credential-bearing logs."""
    try:
        webhook = urlsplit(read_webhook())
        message = embed_payload(
            "Cloudflare internal DNS retired",
            f"{inline_code(entry['hostname'])} → {inline_code(entry['address'])}\n"
            "Owned A record removed · Cloudflare API absence verified",
            "success",
        )
        conn = http.client.HTTPSConnection("discord.com", timeout=10)
        try:
            resource = webhook.path + ("?" + webhook.query if webhook.query else "")
            conn.request(
                "POST",
                resource,
                body=json.dumps(message).encode(),
                headers={"Content-Type": "application/json"},
            )
            if conn.getresponse().status not in (200, 204):
                raise ValueError("Discord rejected notification")
        finally:
            conn.close()
    except (OSError, ValueError, http.client.HTTPException):
        print("WARNING: Internal DNS retirement notification not confirmed.")


def complete_pending(client, data, settings, state, *, notify=False):
    """Recover acknowledged deletion without ever replaying DELETE."""
    pending = state["pending"]
    if pending["phase"] == "intent":
        raise ValueError(
            "Unknown internal DNS DELETE outcome; operator review required"
        )
    entry = pending["entry"]
    identifier = entry["id"]
    bound = state["scope"]["internal"]
    ledger_path = data / REGISTRY_FILE
    if not ledger_path.is_file():
        raise ValueError("Internal DNS ownership registry missing during recovery")
    ledger = load_registry(data, bound)
    current = ledger["records"].get(identifier)
    if current != entry and not (pending["phase"] == "verified" and current is None):
        raise ValueError("Internal retirement ownership changed")
    report, actual, external, owned = fresh_review(
        client, data, settings, entry["hostname"]
    )
    if scope_for(actual, external) != state["scope"]:
        raise ValueError("Internal retirement recovery scope changed")
    if pending["phase"] == "acknowledged" or current is not None:
        if (
            owned.get(identifier) != ("docker", entry)
            or report["selected_dns_record_count"] != 0
            or report["rows"]
            != [
                {
                    "hostname": entry["hostname"],
                    "address": entry["address"],
                    "record_id": identifier,
                    "ownership": "docker",
                    "status": "missing_record",
                }
            ]
        ):
            raise ValueError("Internal DNS deletion absence not verified")
        pending["phase"] = "verified"
        save_state(data, state)
    elif report["selected_dns_record_count"] != 0:
        raise ValueError("Internal DNS name reappeared during recovery")
    if current is not None:
        del ledger["records"][identifier]
        save_registry(data, ledger)
    # A crash after release but before journal clear can finish without a replay.
    state["pending"] = None
    save_state(data, state)
    print(f"Retired owned internal DNS A: {entry['hostname']}")
    if notify:
        notice(entry)


def run_cleanup(
    client, data, settings, grace, budget, *, notify=False, clock=time.time
):
    """Serialize review, grace tracking, one exact-ID write and recovery."""
    data = Path(data)
    if not 1 <= budget <= 10 or not 24 * 3600 <= grace <= 720 * 3600:
        raise ValueError("Invalid internal retirement grace or batch")
    with locked_registry(data):
        state = None
        try:
            if journal_path(data).exists():
                state = load_state(data)
                if state["pending"] is not None:
                    # Even a successful recovery must not share a deletion cycle.
                    complete_pending(client, data, settings, state, notify=notify)
                    return 0
            report, bound, external, owned = fresh_review(client, data, settings)
            scope = scope_for(bound, external)
            if not (data / REGISTRY_FILE).is_file():
                if state is not None:
                    raise ValueError("Internal DNS ownership registry missing")
                print("Internal DNS retirement: no Docker ownership registry.")
                return 0
            state = load_state(data, scope)
            current = candidates(report, owned)
            state["observations"], eligible = observe(
                state["observations"], current, clock(), grace
            )
            save_state(data, state)
            completed = 0
            for identifier in eligible[:budget]:
                entry = current[identifier]
                fresh, actual, external, owned = fresh_review(
                    client, data, settings, entry["hostname"]
                )
                if (
                    scope_for(actual, external) != scope
                    or candidates(fresh, owned).get(identifier) != entry
                ):
                    raise ValueError("Internal retirement candidate changed")
                # Revalidate age again after the live review.
                now = clock()
                _, still_eligible = observe(
                    state["observations"], {identifier: entry}, now, grace
                )
                if identifier not in still_eligible:
                    raise ValueError("Internal retirement grace evidence changed")
                state["observations"].pop(identifier)
                state["pending"] = {"entry": entry, "phase": "intent"}
                save_state(data, state)
                acknowledged = client.delete_dns_record(bound["zone"], identifier)
                if (
                    not isinstance(acknowledged, dict)
                    or acknowledged.get("id") != identifier
                ):
                    raise ValueError("Internal DNS DELETE acknowledgement invalid")
                state["pending"]["phase"] = "acknowledged"
                save_state(data, state)
                complete_pending(client, data, settings, state, notify=notify)
                completed += 1
            if not completed:
                print("Internal DNS retirement: no eligible owned Docker A records.")
            return completed
        except Exception:
            # Failed evidence cannot extend grace. Preserve any durable write intent.
            if state is not None:
                saved = load_state(data) if journal_path(data).exists() else None
                if saved is not None:
                    saved["observations"] = {}
                    save_state(data, saved)
            raise


def disabled(data):
    """Reset grace while preserving any unfinished write for explicit recovery."""
    with locked_registry(data):
        if journal_path(data).exists():
            state = load_state(data)
            state["observations"] = {}
            save_state(data, state)
            if state["pending"] is not None:
                print("Internal DNS retirement disabled; pending recovery retained.")


def boolean_setting(name):
    value = getenv(name, "false")
    if value not in ("true", "false"):
        raise ValueError("Invalid internal retirement boolean setting")
    return value == "true"


def main():
    data = Path("/data")
    try:
        if not boolean_setting("YGGFLARE_CLOUDFLARE_INTERNAL_AUTO_CLEANUP"):
            disabled(data)
            return 0
        if not boolean_setting("YGGFLARE_CLOUDFLARE_AUTO_APPLY"):
            raise ValueError("Internal retirement requires Cloudflare auto apply")
        grace = int(getenv("YGGFLARE_CLOUDFLARE_INTERNAL_ORPHAN_GRACE_HOURS", "24"))
        budget = int(getenv("YGGFLARE_CLOUDFLARE_INTERNAL_CLEANUP_BATCH_SIZE", "1"))
        notify = boolean_setting("YGGFLARE_CLOUDFLARE_INTERNAL_RETIRE_NOTIFY")
        run_cleanup(
            CloudflareWriter(api_token()),
            data,
            cloudflare_settings(),
            grace * 3600,
            budget,
            notify=notify,
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
            "ERROR: Internal DNS retirement blocked; review journal and live evidence.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
