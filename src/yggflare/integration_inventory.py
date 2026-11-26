"""Optional read-only Komodo, Kuma and UniFi collectors. No generic request interface."""

import base64
import fcntl
import http.client
import ipaddress
import json
import os
import re
import signal
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import unifi_api
import unifi_inventory
from docker_inventory import image_reference
from prometheus_client.parser import text_string_to_metric_families
from stack_revision import enrich_stacks
from traefik_inventory import read, snapshot_rows, source_id, timestamp, write

ADAPTER_KINDS = {
    "komodo": ("servers", "stacks", "stack_services", "deployments"),
    "kuma": ("monitors",),
    "unifi": unifi_inventory.KINDS,
}
ADAPTERS = tuple(ADAPTER_KINDS)
INTERVAL = 300
MAX_BYTES = 4 * 1024 * 1024
MAX_ROWS = 4000
KOMODO_READS = {
    "servers": "ListServers",
    "stacks": "ListStacks",
    "deployments": "ListDeployments",
}
SECRET_FILES = {
    "komodo": ("komodo-api-key.txt", "komodo-api-secret.txt"),
    "kuma": ("kuma-api-key.txt",),
    "unifi": ("unifi-api-key.txt",),
    "unifi_write": ("unifi-write-api-key.txt",),
}
# Explicit file settings select fixed Docker secret names. No arbitrary paths,
# credential values in environment variables, or fallback on a missing secret.
SECRET_MOUNTS = {
    "komodo-api-key.txt": ("YGGFLARE_KOMODO_API_KEY_FILE", "komodo_api_key"),
    "komodo-api-secret.txt": ("YGGFLARE_KOMODO_API_SECRET_FILE", "komodo_api_secret"),
    "kuma-api-key.txt": ("YGGFLARE_KUMA_API_KEY_FILE", "kuma_api_key"),
    "unifi-api-key.txt": ("YGGFLARE_UNIFI_API_KEY_FILE", "unifi_api_key"),
    "unifi-write-api-key.txt": (
        "YGGFLARE_UNIFI_WRITE_API_KEY_FILE",
        "unifi_write_api_key",
    ),
}
DOCKER_SECRETS = Path("/run/secrets")

STATES = {
    "running",
    "paused",
    "stopped",
    "created",
    "restarting",
    "dead",
    "removing",
    "unhealthy",
    "down",
    "unknown",
    "deploying",
    "ok",
    "not_ok",
    "disabled",
    "exited",
    "unreachable",
    "healthy",
}
FIELDS = (
    "kind",
    "name",
    "server",
    "swarm",
    "state",
    "template",
    "version",
    "deployed_hash",
    "latest_hash",
    "revision_match",
    "tracked_stack_inputs",
    "project_missing",
    "service",
    "stack",
    "image",
    "latest_image",
    "update_available",
    "container_name",
    "monitor_type",
    "target_host",
    "target_port",
    "target_scheme",
    "status",
)


def scheduled(adapter, env):
    return bool(env.get("YGGFLARE_" + adapter.upper() + "_API_URL")) and (
        adapter != "unifi" or env.get("YGGFLARE_UNIFI_COLLECT_ENABLED") == "true"
    )


def settings(adapter, env):
    if adapter == "unifi":
        return unifi_api.settings(env) if env.get("YGGFLARE_UNIFI_API_URL") else None
    if adapter not in ADAPTERS:
        raise ValueError("Unknown integration")
    prefix = "YGGFLARE_" + adapter.upper()
    value = env.get(prefix + "_API_URL", "")
    if not value:
        return None
    try:
        url = urlsplit(value)
        address = ipaddress.ip_address(url.hostname or "")
        lan = ipaddress.ip_network(env["YGGFLARE_LAN_CIDR"])
        allow_http = env.get(prefix + "_ALLOW_HTTP", "false") == "true"
        if (
            url.scheme not in {"http", "https"}
            or (url.scheme == "http" and not allow_http and not address.is_loopback)
            or url.username is not None
            or url.password is not None
            or url.path not in {"", "/"}
            or url.query
            or url.fragment
            or not (address.is_loopback or address in lan)
            or address.is_unspecified
            or address.is_multicast
            or "%" in str(address)
        ):
            raise ValueError
        port = (
            url.port if url.port is not None else (443 if url.scheme == "https" else 80)
        )
        if not 1 <= port <= 65535:
            raise ValueError
    except (KeyError, ValueError, TypeError):
        raise ValueError(
            "Integration requires a numeric scoped origin; LAN HTTP requires explicit opt-in"
        ) from None
    return url.scheme, str(address), port


def credentials(adapter, directory=Path("/config"), *, env=None):
    """Read only private config files or explicitly selected Docker secret mounts."""
    env = os.environ if env is None else env
    result = []
    for filename in SECRET_FILES[adapter]:
        variable, mount_name = SECRET_MOUNTS[filename]
        configured = env.get(variable, "")
        mounted = bool(configured)
        if mounted:
            path = DOCKER_SECRETS / mount_name
            if configured != "/run/secrets/" + mount_name:
                raise ValueError(
                    "Integration secret file must use its fixed Docker secret path"
                )
        else:
            path = directory / filename
        # Check the opened descriptor, not a separately resolved pathname.
        # NONBLOCK prevents a misconfigured FIFO from blocking the collector.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or not 0 < info.st_size <= 4096
                or (info.st_mode & (0o022 if mounted else 0o077))
            ):
                raise ValueError(
                    "Integration credential file has unsafe type or permissions"
                )
            if mounted and not (os.fstatvfs(handle.fileno()).f_flag & os.ST_RDONLY):
                raise ValueError("Integration Docker secret must be mounted read-only")
            raw = handle.read(4097)
        if len(raw) > 4096:
            raise ValueError("Integration credential exceeds size limit")
        try:
            value = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            raise ValueError("Invalid integration credential") from None
        if not value or any(not 33 <= ord(char) <= 126 for char in value):
            raise ValueError("Invalid integration credential")
        result.append(value)
    return result


def fetch(adapter, origin, secrets, kind):
    """The only outbound requests are fixed, documented read operations."""
    if adapter == "komodo" and kind in KOMODO_READS:
        method, path, body = "POST", "/read/" + KOMODO_READS[kind], b"{}"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Api-Key": secrets[0],
            "X-Api-Secret": secrets[1],
        }
    elif adapter == "kuma" and kind == "monitors":
        method, path, body = "GET", "/metrics", None
        headers = {
            "Accept": "text/plain",
            "Authorization": "Basic "
            + base64.b64encode((":" + secrets[0]).encode()).decode(),
        }
    else:
        raise ValueError("Unsupported integration operation")
    scheme, address, port = origin
    cls = (
        http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    )
    connection = cls(address, port, timeout=8)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError("Integration endpoint did not return HTTP 200")
        payload = response.read(MAX_BYTES + 1)
        if len(payload) > MAX_BYTES:
            raise ValueError("Integration response exceeds limit")
        return json.loads(payload) if adapter == "komodo" else payload.decode("utf-8")
    finally:
        connection.close()


def safe_name(value):
    return (
        value
        if isinstance(value, str)
        and 0 < len(value) <= 253
        and all(c.isprintable() for c in value)
        else None
    )


def revision(value):
    return (
        value.lower()
        if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{7,64}", value)
        else None
    )


def boolean(value):
    return value if type(value) is bool else None


def komodo_rows(kind, payload):
    if not isinstance(payload, list) or len(payload) > MAX_ROWS:
        raise ValueError("Invalid Komodo list response")
    rows = []
    for item in payload:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("info"), dict)
            or not safe_name(item.get("name"))
        ):
            raise ValueError("Invalid Komodo resource")
        info = item["info"]
        state = info.get("state")
        state = state.lower() if isinstance(state, str) else None
        row = {
            "kind": kind,
            "name": safe_name(item["name"]),
            "state": state if state in STATES else "unknown",
            "template": boolean(item.get("template")),
        }
        if kind == "servers":
            row["version"] = safe_name(info.get("version"))
        else:
            row.update(
                server=safe_name(info.get("server_name")),
                swarm=safe_name(info.get("swarm_name")),
            )
        if kind == "stacks":
            deployed, latest = revision(info.get("deployed_hash")), revision(
                info.get("latest_hash")
            )
            row.update(
                deployed_hash=deployed,
                latest_hash=latest,
                revision_match=(
                    deployed == latest
                    if deployed and latest and len(deployed) == len(latest)
                    else None
                ),
                project_missing=boolean(info.get("project_missing")),
            )
            services = info.get("services", [])
            if not isinstance(services, list) or len(services) > MAX_ROWS:
                raise ValueError("Invalid Komodo stack services")
            for service in services:
                if not isinstance(service, dict) or not safe_name(
                    service.get("service")
                ):
                    raise ValueError("Invalid Komodo stack service")
                rows.append(
                    {
                        "kind": "stack_services",
                        "name": safe_name(service["service"]),
                        "service": safe_name(service["service"]),
                        "stack": row["name"],
                        "server": row["server"],
                        "swarm": row["swarm"],
                        "image": image_reference(service.get("image")),
                        "latest_image": image_reference(service.get("latest_image")),
                        "update_available": boolean(service.get("update_available")),
                    }
                )
        elif kind == "deployments":
            row.update(
                image=image_reference(info.get("image")),
                container_name=safe_name(info.get("custom_name")),
                update_available=boolean(info.get("update_available")),
            )
        rows.append(row)
        if len(rows) > MAX_ROWS:
            raise ValueError("Komodo projection exceeds limit")
    return rows


def target(labels):
    """Interpret only labels applicable to the monitor type; ignore placeholders."""
    kind = labels.get("monitor_type")
    host = labels.get("monitor_hostname", "")
    port = labels.get("monitor_port", "")
    scheme = None
    value = labels.get("monitor_url", "")
    if kind in {"http", "keyword", "json-query", "real-browser"}:
        if not value:
            return None, None, None
    elif kind in {"port", "ping", "dns", "udp", "smtp", "mqtt"}:
        value = ""
        if kind == "ping":
            port = None
        elif kind == "port":
            scheme = "tcp"
        elif kind == "udp":
            scheme = "udp"
    else:
        return None, None, None
    if value:
        if not isinstance(value, str) or not value.isprintable():
            return None, None, None
        try:
            url = urlsplit(value)
            if url.username is not None or url.password is not None:
                return None, None, None
            if url.scheme not in {"http", "https", "ws", "wss", "tcp", "udp"}:
                return None, None, None
            if not url.hostname:
                return None, None, None
            host, port, scheme = url.hostname, url.port, url.scheme
            if port is None:
                port = {"http": 80, "https": 443, "ws": 80, "wss": 443}.get(scheme)
        except ValueError:
            return None, None, None
    if not isinstance(host, str) or host.strip().casefold() in {
        "",
        "null",
        "undefined",
    }:
        return None, None, None
    if "%" in host:
        return None, None, None
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        if not isinstance(host, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host
        ):
            host = None
        else:
            host = host.lower().rstrip(".")
    try:
        port = int(port)
        if not 1 <= port <= 65535:
            port = None
    except (TypeError, ValueError):
        port = None
    if host is None:
        return None, None, None
    return host, port, scheme


def kuma_rows(payload):
    if not isinstance(payload, str):
        raise ValueError("Invalid Kuma metrics response")
    rows = []
    saw_family = False
    for family in text_string_to_metric_families(payload):
        if family.name != "monitor_status":
            continue
        saw_family = True
        for sample in family.samples:
            if sample.name != "monitor_status":
                continue
            labels = sample.labels
            name = safe_name(labels.get("monitor_name"))
            if name is None:
                raise ValueError("Invalid Kuma monitor identity")
            host, port, scheme = target(labels)
            rows.append(
                {
                    "kind": "monitors",
                    "name": name,
                    "monitor_type": safe_name(labels.get("monitor_type")),
                    "target_host": host,
                    "target_port": port,
                    "target_scheme": scheme,
                    "status": {0: "down", 1: "up", 2: "pending", 3: "maintenance"}.get(
                        sample.value, "unknown"
                    ),
                }
            )
            if len(rows) > MAX_ROWS:
                raise ValueError("Kuma projection exceeds limit")
    if not saw_family:
        raise ValueError("Kuma monitor_status metrics unavailable")
    return rows


def reject_credential_echo(adapter, rows, secrets):
    """Reject known credential echoes in projected string fields, before writing."""
    markers = set(secrets)
    if adapter == "kuma":
        markers.add(base64.b64encode((":" + secrets[0]).encode()).decode())
    for row in rows:
        for value in row.values():
            if isinstance(value, str) and any(
                marker == value or (len(marker) >= 8 and marker in value)
                for marker in markers
                if marker
            ):
                raise ValueError("Integration projection contains a credential echo")


def refresh(
    adapter, data, env, secret_dir=Path("/config"), request=None, *, device_detail=None
):
    origin = settings(adapter, env)
    if origin is None:
        raise ValueError("Integration is not configured")
    with (data / (adapter + "-refresh.lock")).open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        status = {
            "version": 1,
            "attempted_at": timestamp(),
            "source_id": source_id(origin),
            "ok": False,
        }
        write(data / (adapter + "-view-status.json"), status)
        secret = credentials(adapter, secret_dir, env=env)
        if adapter == "unifi":
            rows = unifi_inventory.collect(
                origin,
                secret[0],
                request or unifi_api.get_page,
                device_detail if request is not None else unifi_api.get_device,
            )
        elif adapter == "komodo":
            request = request or fetch
            rows = []
            for kind in KOMODO_READS:
                rows.extend(komodo_rows(kind, request(adapter, origin, secret, kind)))
            enrich_stacks(rows)
        else:
            rows = kuma_rows((request or fetch)(adapter, origin, secret, "monitors"))
        if len(rows) > (unifi_inventory.MAX_ITEMS if adapter == "unifi" else MAX_ROWS):
            raise ValueError("Integration projection exceeds limit")
        reject_credential_echo(adapter, rows, secret)
        if adapter == "unifi":
            rows.sort(key=lambda row: (row["kind"], row["name"], json.dumps(row)))
        else:
            rows.sort(
                key=lambda row: (
                    row["kind"],
                    row.get("server") or "",
                    row.get("stack") or "",
                    row["name"],
                    row.get("target_host") or "",
                    row.get("target_port") or 0,
                )
            )
        view = {
            "version": 1,
            "source_id": source_id(origin),
            "observed_at": timestamp(),
            "items": rows,
        }
        write(data / (adapter + "-view.json"), view)
        status.update(ok=True, observed_at=view["observed_at"])
        write(data / (adapter + "-view-status.json"), status)
        return view


def valid_rows(adapter, rows):
    if rows is None:
        return False
    if adapter == "unifi":
        return all(unifi_inventory.valid_row(row) for row in rows)
    for row in rows:
        kind = row.get("kind")
        if not safe_name(row.get("name")):
            return False
        if adapter == "kuma":
            if kind != "monitors" or row.get("status") not in (
                "up",
                "down",
                "pending",
                "maintenance",
                "unknown",
            ):
                return False
            port = row.get("target_port")
            if port is not None and (type(port) is not int or not 1 <= port <= 65535):
                return False
            if row.get("target_host") is not None and not safe_name(row["target_host"]):
                return False
        elif kind == "stack_services":
            if not safe_name(row.get("stack")) or not safe_name(row.get("service")):
                return False
        elif kind not in ("servers", "stacks", "deployments") or not isinstance(
            row.get("state"), str
        ):
            return False
        elif row["state"] not in STATES:
            return False
    return True


def saved(adapter, data, env=None):
    env = os.environ if env is None else env
    configured = bool(env.get("YGGFLARE_" + adapter.upper() + "_API_URL"))
    try:
        origin = settings(adapter, env)
    except ValueError:
        origin = None
    view = read(data / (adapter + "-view.json"))
    status = read(data / (adapter + "-view-status.json"))
    match = bool(origin and view.get("source_id") == source_id(origin))
    rows = snapshot_rows(
        view, unifi_inventory.MAX_ITEMS if adapter == "unifi" else MAX_ROWS
    )
    available = (
        match
        and (adapter != "unifi" or "item_count" in view)
        and valid_rows(adapter, rows)
    )
    age = None
    if available:
        try:
            age = (
                datetime.now(UTC) - datetime.fromisoformat(view["observed_at"])
            ).total_seconds()
        except (ValueError, TypeError, KeyError):
            available = False
    verified = bool(
        available
        and status.get("ok") is True
        and status.get("source_id") == view.get("source_id")
        and status.get("observed_at") == view.get("observed_at")
    )
    return {
        "configured": configured,
        "available": bool(available),
        "observed_at": view.get("observed_at") if available else None,
        "last_attempt_at": (
            status.get("attempted_at")
            if origin and status.get("source_id") == source_id(origin)
            else None
        ),
        "last_refresh_verified": verified,
        "fresh": bool(verified and age is not None and 0 <= age <= 900),
        "items": rows if available else [],
    }


def main():
    signal.alarm(90)
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in ADAPTERS:
            raise ValueError("Unknown integration")
        view = refresh(sys.argv[1], Path("/data"), os.environ)
        print(f"Integration snapshot refreshed: {len(view['items'])} observations.")
        return 0
    except (OSError, ValueError, TypeError, RecursionError, http.client.HTTPException):
        print(
            "Integration refresh unavailable; previous complete snapshot retained.",
            file=sys.stderr,
        )
        return 2
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    sys.exit(main())
