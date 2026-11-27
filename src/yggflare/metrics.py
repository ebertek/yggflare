"""Read-only, low-cardinality Prometheus gauges from persisted Yggflare state.

No scans, Docker calls, Cloudflare APIs, inventory writes, or secrets. The endpoint
intentionally emits no hostnames, IP addresses, MACs, zones or resource IDs.
"""

import json
from datetime import UTC, datetime
from pathlib import Path

from evidence_summary import (
    cloudflare_snapshot_status,
    monitor_port_summary,
    probe_coverage,
)
from finding_lifecycle import STATES as FINDING_STATES
from finding_lifecycle import rows as finding_rows
from integration_inventory import ADAPTER_KINDS
from integration_inventory import saved as saved_integration
from job_status import DNS_VERIFICATION_PENDING, JOBS, read_jobs
from probe_inventory import saved as saved_probes
from traefik_inventory import saved as saved_traefik
from unifi_inventory import uplink_counts

MAX_BYTES = 4 * 1024 * 1024


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
    cloudflare = cloudflare_snapshot_status(
        view, view_status, datetime.fromtimestamp(now, UTC)
    )
    view_at = epoch(cloudflare["audited_at"])
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
    cloudflare_ok = cloudflare["last_refresh_verified"]
    cloudflare_stale = not cloudflare["fresh"]
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
            len(entries) if isinstance(inventory.get("hosts"), list) else None,
        ),
        (
            "yggflare_network_state_present",
            "Successful network snapshot exists",
            int((Path(data) / "network-inventory" / "state.json").is_file()),
        ),
        (
            "yggflare_network_discovered_ipv4_hosts",
            "Responsive IPv4 hosts in the most recent saved scan",
            len(observed) if seen_at is not None and "hosts" in scan else None,
        ),
        (
            "yggflare_network_unknown_ipv4_hosts",
            "Current unidentified non-Docker IPv4 hosts in drift state",
            unknown_count if "reported" in scan and seen_at is not None else None,
        ),
        (
            "yggflare_network_active_findings",
            "Current network findings including new hosts IP changes and ports",
            findings_count if "reported" in scan and seen_at is not None else None,
        ),
        (
            "yggflare_network_dns_sd_services",
            "DNS SD service identities from the most recent available browse",
            (
                len(advertisements)
                if dns_sd_at is not None and "advertisements" in scan
                else None
            ),
        ),
        (
            "yggflare_network_observed_identities",
            "Evidence-based identity keys observed in the latest scan",
            (
                len(observed_identities)
                if seen_at is not None and "identity_history" in scan
                else None
            ),
        ),
        (
            "yggflare_network_high_confidence_identities",
            "Observed identities corroborated by declared and direct MAC evidence",
            (
                sum(entry.get("confidence") == "high" for entry in observed_identities)
                if seen_at is not None and "identity_history" in scan
                else None
            ),
        ),
        (
            "yggflare_network_identity_conflicts",
            "Addresses with unresolved competing identity evidence",
            (
                len(identity_conflicts)
                if seen_at is not None and "identity_conflicts" in scan
                else None
            ),
        ),
        (
            "yggflare_network_supplemental_warnings",
            "Supplemental discovery warnings in the most recent scan",
            (
                len(warnings)
                if seen_at is not None and "warnings" in supplementary
                else None
            ),
        ),
        (
            "yggflare_network_pending_discord_events",
            "Queued network notifications awaiting delivery",
            len(pending) if "pending_discord_events" in scan else None,
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
            "Valid saved Cloudflare lifecycle snapshot available",
            cloudflare["snapshot_available"],
        ),
        (
            "yggflare_cloudflare_last_audit_timestamp_seconds",
            "Timestamp of last saved Cloudflare presentation snapshot",
            view_at,
        ),
        (
            "yggflare_cloudflare_last_refresh_success",
            "Latest Cloudflare refresh matches the saved snapshot",
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
            orphan_count if cloudflare["snapshot_available"] else None,
        ),
    ]
    coverage = scan.get("scan_coverage")
    if (
        isinstance(coverage, dict)
        and coverage.get("version") == 1
        and coverage.get("mode") == "live"
    ):
        tcp = coverage.get("tcp")
        if isinstance(tcp, dict):
            for field in (
                "requested_target_count",
                "represented_target_count",
                "omitted_target_count",
                "explicit_timeout_count",
                "selected_port_count",
            ):
                count = tcp.get(field)
                if type(count) is int and 0 <= count <= 100000:
                    values.append(
                        (
                            f"yggflare_network_tcp_{field}",
                            "Aggregate saved Nmap scan coverage; omissions do not establish absence",
                            count,
                        )
                    )
    # Only fixed collector identities and bounded aggregate counts. Never turn
    # arbitrary saved dictionary keys into metric names or labels.
    collector_evidence = supplementary.get("collector_evidence")
    if isinstance(collector_evidence, dict) and collector_evidence.get("version") == 1:
        sources = collector_evidence.get("sources")
        if isinstance(sources, dict):
            allowed_sources = (
                "neighbor_cache",
                "arp",
                "ndp",
                "router_advertisement",
                "ipv4_nmap",
                "ipv6_nmap",
                "docker_ipv6_candidates",
                "candidate_routing",
                "ssdp",
                "lldp",
                "netbios",
                "smb",
                "snmp",
                "p0f",
            )
            for name in allowed_sources:
                row = sources.get(name)
                if not isinstance(row, dict) or row.get("configured") is not True:
                    continue
                for field in (
                    "attempted",
                    "completed",
                    "failed",
                    "no_reply",
                    "parse_errors",
                    "eligible_targets",
                    "selected_targets",
                    "target_limit",
                    "workers",
                    "effective_workers",
                    "skipped_no_port_evidence",
                    "skipped_target_limit",
                    "success_with_shares",
                    "success_empty",
                    "access_denied",
                    "connection_refused",
                    "remote_timeout",
                    "execution_timeout",
                    "execution_failed",
                ):
                    count = row.get(field)
                    if type(count) is int and 0 <= count <= 100000:
                        values.append(
                            (
                                f"yggflare_discovery_{name}_{field}",
                                "Saved collector invocation count; not device coverage",
                                count,
                            )
                        )
                for field in ("limited", "unavailable", "completion_unverified"):
                    flag = row.get(field)
                    if type(flag) is bool:
                        values.append(
                            (
                                f"yggflare_discovery_{name}_{field}",
                                "Saved collector limitation or uncertainty",
                                flag,
                            )
                        )
    history = finding_rows(scan)
    values.append(
        (
            "yggflare_finding_history_available",
            "Structured finding lifecycle is available",
            history is not None,
        )
    )
    if history is not None:
        values.append(
            (
                "yggflare_finding_history_truncated",
                "Finding history has exceeded retention",
                history.get("truncated"),
            )
        )
        for state in FINDING_STATES:
            values.append(
                (
                    f"yggflare_finding_history_{state}",
                    "Retained findings with this historical observation status",
                    sum(
                        row.get("status") == state
                        for row in history.get("items", [])
                        if isinstance(row, dict)
                    ),
                )
            )
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
        if status in {
            "succeeded",
            "failed",
            "interrupted",
            "completion_unknown",
            DNS_VERIFICATION_PENDING,
        }:
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
                        "Latest attempt succeeded; omitted if incomplete or pending",
                        (
                            None
                            if status
                            in {"completion_unknown", DNS_VERIFICATION_PENDING}
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
            if job == "unifi_apply":
                values.append(
                    (
                        "yggflare_job_unifi_apply_pending_dns_verification",
                        "Latest UniFi apply attempt is awaiting DNS evidence",
                        status == DNS_VERIFICATION_PENDING,
                    )
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
    for adapter, kinds in ADAPTER_KINDS.items():
        source = saved_integration(adapter, Path(data))
        values.extend(
            [
                (
                    f"yggflare_{adapter}_snapshot_available",
                    "Saved integration snapshot available",
                    source["available"],
                ),
                (
                    f"yggflare_{adapter}_snapshot_fresh",
                    "Saved integration snapshot fresh and verified",
                    source["fresh"],
                ),
                (
                    f"yggflare_{adapter}_last_success_timestamp_seconds",
                    "Latest complete saved integration observation",
                    epoch(source["observed_at"]),
                ),
            ]
        )
        if adapter == "unifi":
            values.extend(
                [
                    (
                        "yggflare_unifi_configured",
                        "UniFi API origin configured",
                        source["configured"],
                    ),
                    (
                        "yggflare_unifi_last_refresh_verified",
                        "Latest refresh verified against the saved UniFi snapshot",
                        source["last_refresh_verified"],
                    ),
                ]
            )
        if adapter == "kuma":
            selection = monitor_port_summary(
                source["items"], scan, available=source["available"]
            )
            for key in (
                "numeric_ipv4_tcp_endpoints",
                "selected_endpoints",
                "not_selected_endpoints",
            ):
                values.append(
                    (
                        "yggflare_kuma_primary_scan_" + key,
                        "Distinct numeric IPv4 TCP monitor endpoints by global primary port selection, not reachability",
                        selection.get(key),
                    )
                )
            values.append(
                (
                    "yggflare_kuma_primary_scan_selection_available",
                    "Saved primary IPv4 port selection is available for monitor comparison",
                    selection["available"],
                )
            )
        if source["available"]:
            for kind in kinds:
                values.append(
                    (
                        f"yggflare_{adapter}_{kind}",
                        "Resources visible in the last complete integration snapshot",
                        sum(row.get("kind") == kind for row in source["items"]),
                    )
                )
            if adapter == "unifi":
                for state, count in (uplink_counts(source["items"]) or {}).items():
                    values.append(
                        (
                            f"yggflare_unifi_uplink_{state}",
                            "Saved adopted devices by UniFi uplink evidence status",
                            count,
                        )
                    )
            if adapter == "komodo":
                for state in (
                    "matched",
                    "changed",
                    "same_reported_revision",
                    "unknown",
                ):
                    values.append(
                        (
                            f"yggflare_komodo_tracked_stack_inputs_{state}",
                            "Saved stack candidates with this tracked input comparison; not a deploy decision",
                            sum(
                                row.get("kind") == "stacks"
                                and row.get("tracked_stack_inputs", "unknown") == state
                                for row in source["items"]
                            ),
                        )
                    )
            if adapter == "kuma":
                for state in ("up", "down", "pending", "maintenance", "unknown"):
                    values.append(
                        (
                            f"yggflare_kuma_monitors_{state}",
                            "Exported monitors reporting this status",
                            sum(row.get("status") == state for row in source["items"]),
                        )
                    )
    probes = saved_probes(Path(data), Path(config))
    values.extend(
        [
            (
                "yggflare_probe_snapshot_available",
                "Saved independent probe snapshot available",
                probes["available"],
            ),
            (
                "yggflare_probe_snapshot_fresh",
                "Saved independent probe snapshot fresh and verified",
                probes["fresh"],
            ),
            (
                "yggflare_probe_last_success_timestamp_seconds",
                "Latest complete saved probe collection",
                epoch(probes["observed_at"]),
            ),
        ]
    )
    coverage = probe_coverage(
        probes.get("configured_checks"),
        probes["items"],
        probes["available"],
        probes["fresh"],
    )
    values.append(
        (
            "yggflare_probe_configuration_available",
            "Validated local probe configuration is available or explicitly disabled",
            coverage["configuration_available"],
        )
    )
    for key in (
        "configured_checks",
        "observed_checks",
        "passed_checks",
        "failed_checks",
        "inconclusive_checks",
    ):
        values.append(
            (
                "yggflare_probe_coverage_" + key,
                "Configured or saved check outcome count; consult freshness separately",
                coverage.get(key),
            )
        )
    if probes["available"]:
        values.append(
            (
                "yggflare_probe_checks",
                "Checks in last complete independent probe collection",
                len(probes["items"]),
            )
        )
        for status in (
            "matched",
            "mismatch",
            "connected",
            "verified",
            "response_received",
            "certificate_invalid",
            "resolution_failed",
            "timeout",
            "connection_refused",
            "check_failed",
        ):
            values.append(
                (
                    f"yggflare_probe_{status}",
                    "Saved independent checks reporting this outcome",
                    sum(row.get("status") == status for row in probes["items"]),
                )
            )
    from service_retirement_view import saved as saved_retirement

    retirement = saved_retirement(Path(data), now=now)
    values.extend(
        [
            (
                "yggflare_retirement_review_available",
                "Selected retirement review available",
                retirement["available"],
            ),
            (
                "yggflare_retirement_review_fresh",
                "Selected retirement review is fresh",
                retirement["fresh"],
            ),
            (
                "yggflare_retirement_review_complete",
                "All selected review sources collected",
                retirement["complete"],
            ),
        ]
    )
    if retirement["available"]:
        values.append(
            (
                "yggflare_retirement_review_unavailable_sources",
                "Unavailable layers in the selected retirement review",
                sum(row["status"] == "unavailable" for row in retirement["items"]),
            )
        )
    output = "".join(
        metric(name, description, value) for name, description, value in values
    )
    return output.encode("utf-8")
