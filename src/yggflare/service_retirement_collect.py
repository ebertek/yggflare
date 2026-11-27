"""Explicit GET-only collector for the selected service retirement view."""

import argparse
import ipaddress
import signal
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

import unifi_apply as unifi
import unifi_legacy_claim as unifi_claim
from cloudflare_api import CloudflareClient
from cloudflare_credentials import api_token
from cloudflare_internal_cleanup import (
    fresh_review,
    journal_path,
    load_state,
    scope_for,
)
from cloudflare_internal_retirement import (
    compose_evidence,
    docker_containers,
    runtime_evidence,
)
from cloudflare_legacy_external_claim import inspect_resources, resolve_scope
from cloudflare_legacy_external_claim import review_claim as external_claim
from cloudflare_legacy_internal_claim import review_claim as internal_claim
from cloudflare_orphans import (
    AUTO_STATE,
    candidates,
    desired_hosts,
    live_resources,
    load_registry,
    review_orphan,
)
from service_retirement_view import FILENAME, LABEL, LAYERS, valid_snapshot
from traefik_inventory import read, write
from unifi_api import all_rows
from unifi_reconcile_plan import load_live
from yggflare_config import cloudflare_settings
from yggflare_env import getenv


def selected_names(service, settings):
    internal, external = settings["internal_zone"], settings["external_zone"]
    label = service
    for zone in (internal, external):
        if service.endswith("." + zone):
            label = service.removesuffix("." + zone)
            break
    if not LABEL.fullmatch(label):
        raise ValueError("Select one service label or exact configured hostname")
    return label, label + "." + internal, label + "." + external


def source_row(layer, name, collect):
    """Never expose exception messages or partially collected raw data."""
    try:
        result = collect()
    except Exception:
        result = {"status": "unavailable"}
    return {"layer": layer, "hostname": name, "observed_at": int(time.time()), **result}


def external_review(client, root, data, settings, name):
    bound, internal = resolve_scope(client, settings)
    ledger = load_registry(data, bound)
    owned = ledger["hosts"].get(name)
    apps, records, routes = candidates(name, *live_resources(client, bound))
    counts = {
        "access_count": len(apps),
        "dns_count": len(records),
        "tunnel_count": len(routes),
        "ownership": (
            ("legacy" if "legacy" in owned else "owned") if owned else "unmanaged"
        ),
        "auto_cleanup": getenv("YGGFLARE_CLOUDFLARE_AUTO_CLEANUP", "false") == "true",
        "grace_required_seconds": int(
            getenv("YGGFLARE_CLOUDFLARE_ORPHAN_GRACE_HOURS", "24")
        )
        * 3600,
        "grace_seconds": None,
    }
    if name in desired_hosts(client, root, bound["account"]):
        return {**counts, "status": "declared"}
    if not owned and not any((apps, records, routes)):
        try:
            checked = inspect_resources(client, bound, internal, name)
            if any(checked[:3]):
                return {**counts, "status": "blocked"}
        except Exception:
            return {**counts, "status": "blocked"}
        return {**counts, "status": "absent"}
    try:
        if owned:
            review_orphan(client, root, data, bound, name)
            path = data / AUTO_STATE
            # Existing external observations are hostname-scoped, not identity-bound.
            state = read(path)
            old = state.get("missing", {}).get(name, {})
            if state.get("scope") == bound and old:
                first = datetime.fromisoformat(old["first"]).timestamp()
                last = datetime.fromisoformat(old["last"]).timestamp()
                now = time.time()
                if 0 < first <= last <= now and now - last <= 28800:
                    counts["grace_seconds"] = int(now - first)
        else:
            external_claim(client, data, settings, name)
    except Exception:
        return {**counts, "status": "blocked"}
    return {**counts, "status": "review_only" if owned else "unmanaged"}


def internal_review(client, data, settings, name):
    report, bound, external, owned = fresh_review(client, data, settings, name)
    rows = report["rows"]
    result = {
        "dns_count": report["selected_dns_record_count"],
        "auto_cleanup": getenv("YGGFLARE_CLOUDFLARE_INTERNAL_AUTO_CLEANUP", "false")
        == "true",
        "grace_required_seconds": int(
            getenv("YGGFLARE_CLOUDFLARE_INTERNAL_ORPHAN_GRACE_HOURS", "24")
        )
        * 3600,
        "grace_seconds": None,
        "pending": False,
    }
    state = (
        load_state(data, scope_for(bound, external))
        if journal_path(data).exists()
        else None
    )
    if state:
        result["pending"] = state["pending"] is not None
    if len(rows) != 1:
        status = "absent" if not rows and not result["dns_count"] else "unsupported"
        return {**result, "status": status}
    row = rows[0]
    result.update(
        address=row["address"], ownership=row["ownership"], status=row["status"]
    )
    if state and row["status"] == "candidate_review_only":
        observed = state["observations"].get(row["record_id"])
        entry = owned.get(row["record_id"])
        now = time.time()
        if (
            observed
            and entry
            and observed["entry"] == entry[1]
            and 0 <= now - observed["last"] <= 28800
        ):
            result["grace_seconds"] = int(now - observed["first"])
    if row["status"] == "unmanaged":
        try:
            internal_claim(client, data, settings, name)
        except Exception:
            result["status"] = "blocked"
    return result


def reply_state(answer, expected):
    status, values = answer
    if status == "answered":
        return "matched" if values == [expected] else "unexpected"
    if status in {"nxdomain", "nodata"} and not values:
        return "absent"
    return "unavailable"


def unifi_review(data, name, address_hint=None):
    live = load_live()
    ledger = unifi.load_ledger(data / "unifi-ownership.json", live.target)
    policies = all_rows(live.config, live.key, "dns", live.site)
    if unifi.policy_fingerprint(policies) != live.policies_id:
        raise ValueError("UniFi policy evidence changed")
    matches = [
        row
        for row in policies
        if isinstance(row.get("domain"), str)
        and row["domain"].lower().rstrip(".") == name
    ]
    owners = [
        entry for entry in ledger["owned"] if entry["operation"]["domain"] == name
    ]
    result = {
        "policy_count": len(matches),
        "pending": ledger["pending"] is not None,
        "auto_cleanup": unifi.retirement_enabled(),
        "grace_required_seconds": unifi.retirement_grace(),
        "grace_seconds": None,
    }
    if not matches and not owners:
        result["status"] = "absent"
        # Query the exact forward name even without a remaining policy.
        answer = unifi.query(live.config[0], name + ".", "A")
        result["forward"] = reply_state(answer, address_hint)
        result["reverse"] = "unavailable"
        if address_hint:
            address = ipaddress.IPv4Address(address_hint)
            if address in ipaddress.IPv4Network(live.comparison["configured_lan"]):
                result["address"] = str(address)
                result["reverse"] = reply_state(
                    unifi.query(live.config[0], address.reverse_pointer + ".", "PTR"),
                    name + ".",
                )
        return result
    if len(matches) > 1 or len(owners) > 1:
        return {**result, "status": "policy_conflict"}
    if owners:
        entry = owners[0]
        result["ownership"] = (
            "manual"
            if entry["manual"]
            else ("legacy" if "legacy" in entry else "owned")
        )
        result["address"] = entry["operation"]["ipv4Address"]
        try:
            previous = unifi.retirement_state(
                data / "unifi-retirement.json", live.target
            )
            rows, _ = unifi.retirement_report(
                live,
                {**ledger, "owned": owners},
                policies,
                unifi.retirement_protected(live),
                previous,
                int(time.time()),
                unifi.retirement_grace(),
            )
            result["status"] = rows[0]["status"]
            result["grace_seconds"] = rows[0]["observed_orphan_seconds"]
        except Exception:
            result["status"] = "blocked"
    else:
        result["ownership"] = "unmanaged"
        result["status"] = "unsupported"
        policy = matches[0]
        address = unifi.ipv4(policy.get("ipv4Address"))
        lan = ipaddress.IPv4Network(live.comparison["configured_lan"])
        if policy.get("type") == "A_RECORD" and address is not None and address in lan:
            result["address"] = str(address)
            try:
                unifi_claim.review_claim(data, live, ledger, name, policies)
                result["status"] = "unmanaged"
            except Exception:
                result["status"] = "blocked"
    if result.get("address"):
        address = ipaddress.IPv4Address(result["address"])
        if address in ipaddress.IPv4Network(live.comparison["configured_lan"]):
            result["forward"] = reply_state(
                unifi.query(live.config[0], name + ".", "A"), str(address)
            )
            result["reverse"] = reply_state(
                unifi.query(live.config[0], address.reverse_pointer + ".", "PTR"),
                name + ".",
            )
    return result


def collect(data, service):
    from controller import snapshot

    settings = cloudflare_settings()
    label, internal, external = selected_names(service, settings)
    names = (internal, internal, external, internal, internal)
    with tempfile.TemporaryDirectory(prefix="retirement-view-", dir=data) as folder:
        root = Path(folder)

        def compose():
            snapshot(root)
            declared, _, _ = compose_evidence(root, settings["internal_zone"])
            public, _, _ = compose_evidence(root, settings["external_zone"])
            return {
                "status": (
                    "present"
                    if internal in declared or external in public
                    else "absent"
                )
            }

        def runtime():
            containers = docker_containers()
            declared, _ = runtime_evidence(containers, settings["internal_zone"])
            public, _ = runtime_evidence(containers, settings["external_zone"])
            return {
                "status": (
                    "present"
                    if internal in declared or external in public
                    else "absent"
                )
            }

        # Credentials are read only by this explicit collector, never by saved views.
        def cloud_external():
            return external_review(
                CloudflareClient(api_token()), root, data, settings, external
            )

        def cloud_internal():
            return internal_review(
                CloudflareClient(api_token()), data, settings, internal
            )

        collectors = (compose, runtime, cloud_external, cloud_internal)
        rows = [
            source_row(layer, name, fn)
            for layer, name, fn in zip(LAYERS[:-1], names[:-1], collectors, strict=True)
        ]
        rows.append(
            source_row(
                "unifi",
                internal,
                lambda: unifi_review(data, internal, rows[-1].get("address")),
            )
        )
    document = {
        "version": 1,
        "service": label,
        "internal": internal,
        "external": external,
        "items": rows,
        "item_count": len(rows),
    }
    if not valid_snapshot(document):
        raise ValueError("Invalid sanitized retirement review")
    write(data / FILENAME, document, durable=True)
    return sum(row["status"] == "unavailable" for row in rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("service")
    args = parser.parse_args()
    signal.alarm(300)
    try:
        unavailable = collect(Path("/data"), args.service)
        print(
            f"Saved selected service retirement review; {unavailable} unavailable layers."
        )
        return 2 if unavailable else 0
    except Exception:
        print("ERROR: Retirement evidence collection failed.", file=sys.stderr)
        return 2
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    sys.exit(main())
