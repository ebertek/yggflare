"""Read-only, low-cardinality Prometheus gauges from persisted Yggflare state.

No scans, Docker calls, Cloudflare APIs, inventory writes, or secrets. The endpoint
intentionally emits no hostnames, IP addresses, MACs, zones or resource IDs.
"""

import json
from datetime import UTC, datetime
from pathlib import Path

from integration_inventory import ADAPTERS, saved as saved_integration
from job_status import JOBS, read_jobs
from traefik_inventory import saved as saved_traefik

MAX_BYTES = 4 * 1024 * 1024
STALE_CLOUDFLARE_SECONDS = 8 * 60 * 60


def read_optional(path):
    """Bound local input; missing files are distinct from malformed files."""
    if not path.is_file():
        return None
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("Metrics source exceeds size limit")
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("Metrics source must be a JSON object")
    return document


def as_object(value):
    """Treat missing optional sections as empty, malformed sections as invalid."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("Metrics state object is invalid")
    return value


def as_list(value):
    """Treat missing optional collections as empty, not as fabricated data."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("Metrics state list is invalid")
    return value


def epoch(value):
    """Return a finite POSIX timestamp or None for an absent observation."""
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise ValueError("Metrics timestamp must be a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("Invalid metrics timestamp") from error
    if parsed.tzinfo is None:
        raise ValueError("Metrics timestamps must include timezone")
    return parsed.timestamp()


def metric(name, help_text, value):
    """Emit only constant names and descriptions, no user-derived labels."""
    if value is None:
        return ""
    if isinstance(value, bool):
        value = int(value)
    if not isinstance(value, (int, float)) or not 0 <= value < float("inf"):
        raise ValueError("Metrics values must be finite and nonnegative")
    return f"# HELP {name} {help_text}\n# TYPE {name} gauge\n{name} {value}\n"


def render(config, data, now=None):
    """Render a complete exposition from local files, without active lookups."""
    now = datetime.now(UTC).timestamp() if now is None else now
    inventory = read_optional(Path(config) / "static-hosts.json")
    scan = read_optional(Path(data) / "network-inventory" / "state.json")
    view = read_optional(Path(data) / "cloudflare-view.json")
    view_status = read_optional(Path(data) / "cloudflare-view-status.json")
    inventory = as_object(inventory)
    scan = as_object(scan)
    view = as_object(view)
    view_status = as_object(view_status)

    entries = as_list(inventory.get("hosts"))
    observed = as_object(scan.get("hosts"))
    reported = as_object(scan.get("reported"))
    advertisements = as_list(scan.get("advertisements"))
    supplementary = as_object(scan.get("supplemental"))
    warnings = as_list(supplementary.get("warnings"))
    pending = as_list(scan.get("pending_discord_events"))
    identities = as_object(scan.get("identity_history"))
    identity_conflicts = as_list(scan.get("identity_conflicts"))
    view_hosts = as_list(view.get("hosts"))

    seen_at = epoch(scan.get("scanned_at"))
    dns_sd_at = epoch(scan.get("dns_sd_scanned_at"))
    view_at = epoch(view.get("audited_at"))
    duration = scan.get("scan_duration_seconds")
    if duration is not None and (
        isinstance(duration, bool)
        or not isinstance(duration, (float, int))
        or not 0 <= duration < float("inf")
    ):
        raise ValueError("Invalid network scan duration")

    orphan_count = sum(
        isinstance(host, dict) and host.get("lifecycle") == "orphaned"
        for host in view_hosts
    )
    cloudflare_ok = view_status.get("ok") is True
    cloudflare_stale = (
        view_at is None or not cloudflare_ok or now - view_at > STALE_CLOUDFLARE_SECONDS
    )
    unknown_count = sum(key.startswith("unknown-device:") for key in reported)
    findings_count = len(reported)
    observed_identities = [
        entry
        for entry in identities.values()
        if isinstance(entry, dict) and entry.get("status") == "observed"
    ]

    values = [
        (
            "yggflare_inventory_state_present",
            "Static inventory file exists",
            int((Path(config) / "static-hosts.json").is_file()),
        ),
        (
            "yggflare_inventory_declared_hosts",
            "Declared static inventory entries",
            len(entries),
        ),
        (
            "yggflare_network_state_present",
            "Successful network snapshot exists",
            int((Path(data) / "network-inventory" / "state.json").is_file()),
        ),
        (
            "yggflare_network_discovered_ipv4_hosts",
            "Responsive IPv4 hosts in the most recent saved scan",
            len(observed),
        ),
        (
            "yggflare_network_unknown_ipv4_hosts",
            "Current unidentified non-Docker IPv4 hosts in drift state",
            unknown_count,
        ),
        (
            "yggflare_network_active_findings",
            "Current network findings including new hosts IP changes and ports",
            findings_count,
        ),
        (
            "yggflare_network_dns_sd_services",
            "DNS SD service identities from the most recent available browse",
            len(advertisements),
        ),
        (
            "yggflare_network_observed_identities",
            "Evidence-based identity keys observed in the latest scan",
            len(observed_identities),
        ),
        (
            "yggflare_network_high_confidence_identities",
            "Observed identities corroborated by declared and direct MAC evidence",
            sum(entry.get("confidence") == "high" for entry in observed_identities),
        ),
        (
            "yggflare_network_identity_conflicts",
            "Addresses with unresolved competing identity evidence",
            len(identity_conflicts),
        ),
        (
            "yggflare_network_supplemental_warnings",
            "Supplemental discovery warnings in the most recent scan",
            len(warnings),
        ),
        (
            "yggflare_network_pending_discord_events",
            "Queued network notifications awaiting delivery",
            len(pending),
        ),
        (
            "yggflare_network_scan_last_success_timestamp_seconds",
            "Timestamp of most recent saved successful network scan",
            seen_at,
        ),
        (
            "yggflare_network_dns_sd_last_success_timestamp_seconds",
            "Timestamp of most recent complete DNS SD browse",
            dns_sd_at,
        ),
        (
            "yggflare_network_scan_duration_seconds",
            "Duration of most recent saved scan excluding notification delivery",
            duration,
        ),
        (
            "yggflare_cloudflare_snapshot_present",
            "Cloudflare presentation snapshot exists",
            int((Path(data) / "cloudflare-view.json").is_file()),
        ),
        (
            "yggflare_cloudflare_last_audit_timestamp_seconds",
            "Timestamp of last saved Cloudflare presentation snapshot",
            view_at,
        ),
        (
            "yggflare_cloudflare_last_refresh_success",
            "Whether the latest Cloudflare presentation refresh succeeded",
            int(cloudflare_ok),
        ),
        (
            "yggflare_cloudflare_snapshot_stale",
            "Cloudflare view is older than eight hours or latest refresh failed",
            int(cloudflare_stale),
        ),
        (
            "yggflare_cloudflare_orphan_hosts",
            "Owned Cloudflare hosts absent from desired configuration in last view",
            orphan_count,
        ),
    ]
    job_document = read_jobs(Path(data))
    values.append(
        (
            "yggflare_job_evidence_available",
            "Saved scheduler evidence is available",
            job_document is not None,
        )
    )
    for job in JOBS:
        row = (job_document or {}).get("jobs", {}).get(job, {})
        status = row.get("status")
        if status in {"succeeded", "failed", "interrupted", "completion_unknown"}:
            values.extend(
                [
                    (
                        f"yggflare_job_{job}_last_attempt_timestamp_seconds",
                        "Last scheduled attempt",
                        epoch(row.get("started_at")),
                    ),
                    (
                        f"yggflare_job_{job}_last_success_timestamp_seconds",
                        "Last successful scheduled completion",
                        epoch(row.get("last_success_at")),
                    ),
                    (
                        f"yggflare_job_{job}_last_attempt_success",
                        "Latest completed attempt succeeded; omitted if incomplete",
                        (
                            None
                            if status == "completion_unknown"
                            else status == "succeeded"
                        ),
                    ),
                    (
                        f"yggflare_job_{job}_completion_unknown",
                        "Latest attempt lacks a recorded completion",
                        status == "completion_unknown",
                    ),
                ]
            )
    delivery = as_object(scan.get("notification_status"))
    values.append(
        (
            "yggflare_network_discord_last_submission_timestamp_seconds",
            "Last successful webhook submission, not recipient receipt",
            epoch(delivery.get("last_success_at")),
        )
    )
    traefik = saved_traefik(Path(data))
    values.extend(
        [
            (
                "yggflare_traefik_snapshot_available",
                "Configured Traefik snapshot available",
                traefik["available"],
            ),
            (
                "yggflare_traefik_snapshot_fresh",
                "Latest Traefik snapshot fresh and verified",
                traefik["fresh"],
            ),
            (
                "yggflare_traefik_last_success_timestamp_seconds",
                "Latest complete saved Traefik observation",
                epoch(traefik["observed_at"]),
            ),
        ]
    )
    if traefik["available"]:
        for kind in ("routers", "services", "middlewares"):
            values.append(
                (
                    f"yggflare_traefik_{kind}",
                    "Resources in the last complete Traefik snapshot",
                    sum(row.get("kind") == kind for row in traefik["items"]),
                )
            )
    for adapter in ADAPTERS:
        source = saved_integration(adapter, Path(data))
        values.extend([
            (f"yggflare_{adapter}_snapshot_available", "Saved integration snapshot available", source["available"]),
            (f"yggflare_{adapter}_snapshot_fresh", "Saved integration snapshot fresh and verified", source["fresh"]),
            (f"yggflare_{adapter}_last_success_timestamp_seconds", "Latest complete saved integration observation", epoch(source["observed_at"])),
        ])
        if source["available"]:
            kinds = ("servers", "stacks", "stack_services", "deployments") if adapter == "komodo" else ("monitors",)
            for kind in kinds:
                values.append((f"yggflare_{adapter}_{kind}", "Resources visible in the last complete integration snapshot", sum(row.get("kind") == kind for row in source["items"])))
            if adapter == "kuma":
                for state in ("up", "down", "pending", "maintenance", "unknown"):
                    values.append((f"yggflare_kuma_monitors_{state}", "Exported monitors reporting this status", sum(row.get("status") == state for row in source["items"])))
    output = "".join(
        metric(name, description, value) for name, description, value in values
    )
    return output.encode("utf-8")
