"""Pure summaries of saved evidence; no active collection."""

import ipaddress
from datetime import UTC, datetime


def selected_tcp_ports(state):
    coverage = state.get("scan_coverage", {})
    if not isinstance(coverage, dict):
        return None
    tcp = coverage.get("tcp", {})
    if not isinstance(tcp, dict):
        return None
    selected = tcp.get("selected_ports")
    if (
        coverage.get("version") == 1
        and coverage.get("mode") == "live"
        and state.get("scanned_at")
        and coverage.get("observed_at") == state.get("scanned_at")
        and isinstance(selected, list)
        and len(selected) == tcp.get("selected_port_count")
        and len(selected) <= 65535
        and all(type(item) is int and 1 <= item <= 65535 for item in selected)
        and len(set(selected)) == len(selected)
    ):
        return set(selected)
    return None


def monitor_port_summary(monitors, state, *, available):
    """Global selection evidence, not per-device scan or reachability proof."""
    ports = selected_tcp_ports(state)
    if not available or ports is None:
        return {"available": False}
    endpoints = set()
    for row in monitors:
        if (
            row.get("monitor_type") in {"docker", "group", "push"}
            or row.get("target_scheme") not in {"tcp", "http", "https", "ws", "wss"}
            or type(row.get("target_port")) is not int
            or not 1 <= row["target_port"] <= 65535
        ):
            continue
        try:
            ip = ipaddress.ip_address(row.get("target_host"))
        except ValueError:
            continue
        if ip.version == 4:
            endpoints.add((str(ip), row["target_port"]))
    missing = {(host, port) for host, port in endpoints if port not in ports}
    return {
        "available": True,
        "numeric_ipv4_tcp_endpoints": len(endpoints),
        "selected_endpoints": len(endpoints - missing),
        "not_selected_endpoints": len(missing),
        "not_selected_ports": sorted({port for _, port in missing}),
        "scan_observed_at": state["scanned_at"],
        "caveat": "Global primary IPv4 port selection only; includes numeric monitor targets outside scan scope and does not prove any endpoint was probed.",
    }


def check_identity(row):
    return tuple(
        row.get(key)
        for key in ("target", "hostname", "address", "port", "scheme", "check")
    ) + (row.get("http_method", "HEAD") if row.get("check") == "http" else None,)


def probe_outcome(row):
    """A response received and an expected result are distinct."""
    check, status = row.get("check"), row.get("status")
    if status in {
        "mismatch",
        "certificate_invalid",
        "resolution_failed",
        "timeout",
        "connection_refused",
        "check_failed",
    }:
        return "failed"
    if (
        check == "dns"
        and status == "matched"
        and row.get("expected_address_match") is True
    ):
        return "passed"
    if check == "tcp" and status == "connected":
        return "passed"
    if check == "tls" and status == "verified" and row.get("tls_verified") is True:
        return "passed"
    if check == "http" and status == "response_received":
        if row.get("expected_status_match") is False:
            return "failed"
        if row.get("expected_status_match") is True:
            return "passed"
    return "inconclusive"


def probe_coverage(configured_checks, rows, available, fresh):
    if configured_checks is None:
        return {"configuration_available": False}
    result = {
        "configuration_available": True,
        "configured_checks": len(configured_checks),
        "observed_checks": None,
        "passed_checks": None,
        "failed_checks": None,
        "inconclusive_checks": None,
        "fresh": bool(fresh),
    }
    if not available:
        return result
    expected = {check_identity(row) for row in configured_checks}
    matching = [row for row in rows if check_identity(row) in expected]
    result["observed_checks"] = len(matching)
    for outcome in ("passed", "failed", "inconclusive"):
        result[outcome + "_checks"] = sum(
            probe_outcome(row) == outcome for row in matching
        )
    return result


def observation_time(value):
    """Only explicit timezone-aware timestamps are comparable."""
    if not isinstance(value, str):
        return None
    try:
        stamp = datetime.fromisoformat(value)
        return stamp.astimezone(UTC) if stamp.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def cloudflare_snapshot_status(view, status, now):
    """Distinguish a retained lifecycle snapshot from its verified refresh."""
    stamp = observation_time(view.get("audited_at"))
    hosts = view.get("hosts")
    available = bool(
        stamp is not None
        and stamp <= now
        and isinstance(hosts, list)
        and all(isinstance(row, dict) for row in hosts)
    )
    verified = bool(
        available
        and status.get("ok") is True
        and status.get("attempted_at") == view.get("audited_at")
    )
    return {
        "snapshot_available": available,
        "audited_at": view.get("audited_at") if available else None,
        "latest_attempt_at": (
            status.get("attempted_at")
            if observation_time(status.get("attempted_at")) is not None
            else None
        ),
        "last_refresh_verified": verified,
        "fresh": bool(verified and (now - stamp).total_seconds() <= 8 * 3600),
    }


def observation_window(sources, now):
    """Describe timestamp spread without asserting synchronized collection."""
    times = {}
    unknown = []
    for source, value in sources.items():
        stamp = observation_time(value)
        if stamp is None or stamp > now:
            unknown.append(source)
        else:
            times[source] = stamp
    earliest = min(times.values()) if times else None
    latest = max(times.values()) if times else None
    return {
        "evaluated_at": now.isoformat(),
        "timestamped_sources": sorted(times),
        "unknown_timestamp_sources": sorted(unknown),
        "earliest_observed_at": earliest.isoformat() if earliest else None,
        "latest_observed_at": latest.isoformat() if latest else None,
        "spread_seconds": (
            round((latest - earliest).total_seconds(), 1) if len(times) >= 2 else None
        ),
        "caveat": (
            "Independent observation times, not an atomic snapshot. "
            "Missing or future timestamps are excluded; spread is not health."
        ),
    }


def network_collection_verified(scanned, coverage, job, now):
    """Associate scheduler outcomes only with observations in their time window."""
    observed = observation_time(scanned)
    if observed is None or observed > now:
        return None
    start = observation_time(job.get("started_at"))
    finish = observation_time(job.get("finished_at"))
    status = job.get("status")
    if start is not None and observed < start <= now:
        # A newer attempt is not evidence that the retained snapshot is current.
        return (
            False if status in ("failed", "interrupted", "completion_unknown") else None
        )
    if start is not None and start <= observed:
        if finish is not None and observed <= finish <= now:
            if status == "succeeded":
                return True
            if status in ("failed", "interrupted"):
                return False
    # Positive saved coverage also supports an explicit, unscheduled scan.
    if (
        coverage.get("available")
        and observation_time(coverage.get("observed_at")) == observed
        and coverage.get("host_discovery", {}).get("run_completed") is True
        and coverage.get("tcp", {}).get("run_completed") is not False
    ):
        return True
    return None
