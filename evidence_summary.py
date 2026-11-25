"""Pure summaries of saved evidence; no active collection."""
import ipaddress


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
    return tuple(row.get(key) for key in ("target", "hostname", "address", "port", "scheme", "check"))


def probe_outcome(row):
    """A response received and an expected result are distinct."""
    check, status = row.get("check"), row.get("status")
    if status in {"mismatch", "certificate_invalid", "resolution_failed", "timeout", "connection_refused", "check_failed"}:
        return "failed"
    if check == "dns" and status == "matched" and row.get("expected_address_match") is True:
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
        result[outcome + "_checks"] = sum(probe_outcome(row) == outcome for row in matching)
    return result
