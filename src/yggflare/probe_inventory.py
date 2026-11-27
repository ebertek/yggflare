"""Explicitly configured, bounded independent DNS/TCP/TLS/HTTP observations."""

import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
import re
import signal
import socket
import ssl
import stat
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from evidence_summary import check_identity
from traefik_inventory import read, snapshot_rows, timestamp, write
from yggflare_env import env_get, env_required

INTERVAL = 300
MAX_TARGETS = 16
CONFIG_MOUNT = Path("/yggflare-probes.json")
CHECKS = ("dns", "tcp", "tls", "http")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}")
FIELDS = (
    "target",
    "hostname",
    "address",
    "port",
    "scheme",
    "check",
    "status",
    "elapsed_ms",
    "http_method",
    "http_status",
    "expected_status_match",
    "resolved_count",
    "expected_address_match",
    "tls_verified",
    "certificate_not_after",
    "observed_at",
)


def settings(config_dir, env):
    enabled = env_get(env, "YGGFLARE_PROBES_ENABLED", "false")
    if enabled == "false":
        return None
    if enabled != "true":
        raise ValueError("Invalid probe enable setting")
    selected = env_get(env, "YGGFLARE_PROBES_CONFIG_FILE", "")
    if selected and selected != "/yggflare-probes.json":
        raise ValueError("Probe configuration requires its fixed Docker config path")
    path = CONFIG_MOUNT if selected else config_dir / "probes.json"
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 64 * 1024:
            raise ValueError("Invalid private probe configuration")
        if selected and (
            info.st_mode & 0o022
            or not os.fstatvfs(handle.fileno()).f_flag & os.ST_RDONLY
        ):
            raise ValueError(
                "Probe Docker config must be read-only and not group/world writable"
            )
        payload = handle.read(64 * 1024 + 1)
    if len(payload) > 64 * 1024:
        raise ValueError("Probe configuration exceeds size limit")
    document = json.loads(payload)
    lan = ipaddress.ip_network(env_required(env, "YGGFLARE_LAN_CIDR"))
    ipv6 = [
        ipaddress.ip_network(value.strip())
        for value in env_get(env, "YGGFLARE_DISCOVERY_IPV6_CIDRS", "").split(",")
        if value.strip()
    ]
    if not isinstance(document, dict) or document.get("version") != 1:
        raise ValueError("Unsupported probe configuration")
    targets = document.get("targets")
    if not isinstance(targets, list) or not 0 < len(targets) <= MAX_TARGETS:
        raise ValueError("Invalid probe target count")
    rows, seen = [], set()
    for target in targets:
        if not isinstance(target, dict) or set(target) - {
            "name",
            "hostname",
            "address",
            "port",
            "scheme",
            "checks",
            "expected_statuses",
            "http_method",
        }:
            raise ValueError("Invalid probe target fields")
        name = target.get("name")
        hostname = target.get("hostname")
        if not isinstance(name, str) or not NAME.fullmatch(name) or name in seen:
            raise ValueError("Invalid or duplicate probe target name")
        seen.add(name)
        if not isinstance(hostname, str) or not NAME.fullmatch(hostname):
            raise ValueError("Invalid probe hostname")
        address = ipaddress.ip_address(target["address"])
        if (
            not (
                address.is_loopback
                or address in lan
                or any(address in network for network in ipv6)
            )
            or address.is_unspecified
            or address.is_multicast
            or address.is_link_local
            or "%" in str(address)
        ):
            raise ValueError("Probe address outside configured scope")
        port = target.get("port")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("Invalid probe port")
        checks = target.get("checks")
        if (
            not isinstance(checks, list)
            or not checks
            or len(checks) > len(CHECKS)
            or any(check not in CHECKS for check in checks)
            or len(set(checks)) != len(checks)
        ):
            raise ValueError("Invalid probe checks")
        scheme = target.get("scheme", "https")
        if scheme not in {"http", "https"} or ("tls" in checks and scheme != "https"):
            raise ValueError("Invalid probe scheme")
        method = target.get("http_method", "HEAD")
        if method not in ("HEAD", "GET") or (
            "http_method" in target and "http" not in checks
        ):
            raise ValueError("Invalid HTTP probe method")
        statuses = target.get("expected_statuses", [])
        if (
            not isinstance(statuses, list)
            or len(statuses) > 16
            or any(
                type(status) is not int or not 100 <= status <= 599
                for status in statuses
            )
        ):
            raise ValueError("Invalid expected HTTP status list")
        rows.append(
            {
                "target": name,
                "hostname": hostname,
                "address": str(address),
                "port": port,
                "scheme": scheme,
                "checks": checks,
                "expected_statuses": statuses,
                **({"http_method": method} if method != "HEAD" else {}),
            }
        )
    return rows


def fingerprint(targets):
    return hashlib.sha256(json.dumps(targets, sort_keys=True).encode()).hexdigest()


def connect(target):
    # Never resolve the destination of a network connection. Only the explicit
    # numeric address is used, while hostname is used for SNI/HTTP Host.
    return socket.create_connection((target["address"], target["port"]), timeout=3)


def tls_socket(connection, hostname):
    return ssl.create_default_context().wrap_socket(
        connection, server_hostname=hostname
    )


def probe(target, check):
    row = {
        key: target[key] for key in ("target", "hostname", "address", "port", "scheme")
    }
    row.update(check=check, observed_at=timestamp())
    started = time.monotonic()
    try:
        if check == "dns":
            addresses = {
                str(ipaddress.ip_address(item[4][0]))
                for item in socket.getaddrinfo(
                    target["hostname"], None, type=socket.SOCK_STREAM
                )
            }
            row.update(
                resolved_count=len(addresses),
                expected_address_match=target["address"] in addresses,
                status="matched" if target["address"] in addresses else "mismatch",
            )
        elif check == "tcp":
            with connect(target):
                row["status"] = "connected"
        elif check == "tls":
            with connect(target) as raw, tls_socket(raw, target["hostname"]) as secure:
                cert = secure.getpeercert()
                row.update(
                    status="verified",
                    tls_verified=True,
                    certificate_not_after=cert.get("notAfter"),
                )
        elif check == "http":
            method = target.get("http_method", "HEAD")
            if method not in ("HEAD", "GET"):
                raise ValueError("Invalid HTTP probe method")
            row["http_method"] = method
            with connect(target) as raw:
                secure = (
                    tls_socket(raw, target["hostname"])
                    if target["scheme"] == "https"
                    else None
                )
                try:
                    stream = secure or raw
                    host = target["hostname"]
                    if target["port"] != (443 if secure else 80):
                        host += ":" + str(target["port"])
                    stream.sendall(
                        (
                            method
                            + " / HTTP/1.1\r\nHost: "
                            + host
                            + "\r\nConnection: close\r\nUser-Agent: Yggflare-probe\r\n\r\n"
                        ).encode("ascii")
                    )
                    response = http.client.HTTPResponse(stream, method=method)
                    try:
                        # Read response headers only, even for GET. Never read the body or follow redirects.
                        response.begin()
                        expected = target["expected_statuses"]
                        row.update(
                            status="response_received",
                            http_status=response.status,
                            expected_status_match=(
                                response.status in expected if expected else None
                            ),
                            tls_verified=True if secure else None,
                        )
                    finally:
                        response.close()
                finally:
                    if secure is not None:
                        secure.close()
        else:
            raise ValueError("Unsupported check")
    except ssl.SSLCertVerificationError:
        row.update(status="certificate_invalid", tls_verified=False)
    except socket.gaierror:
        row["status"] = "resolution_failed"
    except TimeoutError:
        row["status"] = "timeout"
    except ConnectionRefusedError:
        row["status"] = "connection_refused"
    except (OSError, http.client.HTTPException, ValueError):
        row["status"] = "check_failed"
    row["elapsed_ms"] = round((time.monotonic() - started) * 1000, 1)
    return row


def refresh(data, config, env, runner=probe):
    targets = settings(config, env)
    if targets is None:
        raise ValueError("Probes are disabled")
    with (data / "probe-refresh.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        status = {
            "version": 1,
            "source_id": fingerprint(targets),
            "attempted_at": timestamp(),
            "ok": False,
        }
        write(data / "probe-view-status.json", status)
        rows = [
            runner(target, check) for target in targets for check in target["checks"]
        ]
        result = {
            "version": 1,
            "source_id": status["source_id"],
            "observed_at": timestamp(),
            "items": rows,
        }
        write(data / "probe-view.json", result)
        status.update(ok=True, observed_at=result["observed_at"])
        write(data / "probe-view-status.json", status)
        return result


def saved(data, config=Path("/config"), env=None):
    env = os.environ if env is None else env
    configured = env_get(env, "YGGFLARE_PROBES_ENABLED", "false") == "true"
    try:
        targets = settings(config, env)
    except (OSError, KeyError, ValueError, TypeError):
        targets = None
    view = read(data / "probe-view.json")
    status = read(data / "probe-view-status.json")
    source = fingerprint(targets) if targets else None
    configured_checks = (
        [
            {
                **{
                    key: target[key]
                    for key in ("target", "hostname", "address", "port", "scheme")
                },
                "check": check,
                "http_method": (
                    target.get("http_method", "HEAD") if check == "http" else None
                ),
                "expected_http_status_configured": (
                    bool(target["expected_statuses"]) if check == "http" else None
                ),
            }
            for target in targets
            for check in target["checks"]
        ]
        if targets is not None
        else [] if env_get(env, "YGGFLARE_PROBES_ENABLED", "false") == "false" else None
    )
    rows = snapshot_rows(view, MAX_TARGETS * len(CHECKS))
    available = bool(
        source
        and view.get("source_id") == source
        and rows is not None
        and all(
            row.get("status")
            in (
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
            )
            for row in rows
        )
    )
    # Partial, duplicate and foreign check identities are not a complete snapshot.
    if available:
        try:
            identities = [check_identity(row) for row in rows]
            available = (
                len(identities) == len(configured_checks)
                and len(set(identities)) == len(identities)
                and set(identities)
                == {check_identity(row) for row in configured_checks}
            )
        except TypeError:
            available = False
    age = None
    if available:
        try:
            age = (
                datetime.now(UTC) - datetime.fromisoformat(view["observed_at"])
            ).total_seconds()
        except (KeyError, ValueError, TypeError):
            available = False
    verified = bool(
        available
        and status.get("ok") is True
        and status.get("source_id") == source
        and status.get("observed_at") == view.get("observed_at")
    )
    return {
        "configured": configured,
        "configured_checks": configured_checks,
        "available": available,
        "last_attempt_at": (
            status.get("attempted_at")
            if source and status.get("source_id") == source
            else None
        ),
        "observed_at": view.get("observed_at") if available else None,
        "fresh": bool(verified and age is not None and 0 <= age <= 900),
        "last_refresh_verified": verified,
        "items": rows if available else [],
    }


def main():
    # Separate hard deadline protects against blocked system DNS and slow peers.
    signal.alarm(120)
    try:
        result = refresh(Path("/data"), Path("/config"), os.environ)
        print(f"Probe snapshot refreshed: {len(result['items'])} checks.")
        return 0
    except (OSError, KeyError, ValueError, TypeError):
        print(
            "Probe refresh unavailable; previous complete snapshot retained.",
            file=sys.stderr,
        )
        return 2
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    sys.exit(main())
