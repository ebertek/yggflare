"""Opt-in, bounded Traefik GET collector and sanitized saved evidence."""

import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
import re
import signal
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

SECTIONS = tuple(
    (protocol, kind)
    for protocol in ("http", "tcp", "udp")
    for kind in ("routers", "services", "middlewares")
    if not (protocol == "udp" and kind == "middlewares")
)
MAX_BYTES = 4 * 1024 * 1024
PAGE_SIZE = 100
MAX_PAGES = 10
INTERVAL = 300
STALE_SECONDS = 900
SAFE_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@-]{0,252}")
SAFE_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}")
KINDS = ("routers", "services", "middlewares")


def timestamp():
    return datetime.now(UTC).isoformat()


def settings(env):
    """Accept only a fixed numeric, scoped internal API origin, no credentials."""
    value = env.get("YGGFLARE_TRAEFIK_API_URL", "")
    if not value:
        return None
    try:
        url = urlsplit(value)
        address = ipaddress.ip_address(url.hostname or "")
        lan = ipaddress.ip_network(env["YGGFLARE_LAN_CIDR"])
        if (
            url.scheme not in {"http", "https"}
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
            "Traefik API requires a numeric HTTP(S) origin inside the configured LAN or loopback"
        ) from None
    return url.scheme, str(address), port


def source_id(config):
    return hashlib.sha256(json.dumps(config).encode()).hexdigest()


def get_page(config, protocol, kind, page):
    """Fixed endpoint and sequential pagination; no proxies or redirects."""
    if (protocol, kind) not in SECTIONS or not 1 <= page <= MAX_PAGES:
        raise ValueError("Unsupported Traefik endpoint")
    scheme, address, port = config
    connection_type = (
        http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    )
    connection = connection_type(address, port, timeout=5)
    try:
        connection.request(
            "GET",
            f"/api/{protocol}/{kind}?page={page}&per_page={PAGE_SIZE}",
            headers={"Accept": "application/json"},
        )
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError("Traefik API did not return HTTP 200")
        payload = response.read(1024 * 1024 + 1)
        if len(payload) > 1024 * 1024:
            raise ValueError("Traefik API response exceeds size limit")
        rows = json.loads(payload)
        if (
            not isinstance(rows, list)
            or len(rows) > PAGE_SIZE
            or any(not isinstance(row, dict) for row in rows)
        ):
            raise ValueError("Invalid Traefik API list response")
        next_page = response.getheader("X-Next-Page", "").strip()
        # Traefik v3.8 (pkg/api/criterion.go) returns 1 on the terminal
        # page, including an empty list or an exactly full final page.
        # Never request page one again or infer continuation in that case.
        if next_page == "1":
            return rows, False
        if next_page == str(page + 1):
            if len(rows) != PAGE_SIZE:
                raise ValueError("Incomplete Traefik page with continuation")
            return rows, True
        if next_page:
            raise ValueError("Unexpected Traefik pagination")
        # Retain bounded compatibility for implementations without a header.
        return rows, len(rows) == PAGE_SIZE
    finally:
        connection.close()


def name(value):
    return value if isinstance(value, str) and SAFE_NAME.fullmatch(value) else None


def names(values):
    if not isinstance(values, list):
        return []
    return [value for value in values[:32] if name(value)]


def endpoint(value):
    """Only origin addresses, never userinfo, paths, headers or query strings."""
    if (
        not isinstance(value, str)
        or len(value) > 2048
        or not value.isprintable()
    ):
        return None
    try:
        url = urlsplit(value if "://" in value else "//" + value)
        if url.username is not None or url.password is not None:
            return None
        if url.scheme not in {"", "http", "https", "h2c", "tcp", "udp"}:
            return None
        host = url.hostname
        if not host or "%" in host:
            return None
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            if not SAFE_HOST.fullmatch(host):
                return None
        if ":" in host:
            host = "[" + host + "]"
        return (
            (url.scheme + "://" if url.scheme else "")
            + host
            + (":" + str(url.port) if url.port else "")
        )
    except ValueError:
        return None


def project(protocol, kind, raw):
    """Never return raw rules, middleware configuration, errors, or server URLs."""
    identifier = name(raw.get("name"))
    if not identifier:
        raise ValueError("Invalid Traefik resource identity")
    status = raw.get("status")
    row = {
        "protocol": protocol,
        "kind": kind,
        "name": identifier,
        "provider": name(raw.get("provider")),
        "status": status if status in ("enabled", "disabled", "warning") else "unknown",
        "error_count": (
            len(raw["error"]) if isinstance(raw.get("error"), list) else None
        ),
    }
    if kind == "routers":
        rule = raw.get("rule", "")
        hosts = []
        if protocol == "http" and isinstance(rule, str) and len(rule) <= 4096:
            hosts = sorted(
                set(
                    re.findall(
                        r'Host\(\s*[`"]([A-Za-z0-9][A-Za-z0-9.-]{0,252})[`"]\s*\)', rule
                    )
                )
            )[:32]
        row.update(
            literal_hosts=hosts,
            simple_host_rule=bool(
                isinstance(rule, str)
                and re.fullmatch(
                    r'\s*Host\(\s*[`"][A-Za-z0-9][A-Za-z0-9.-]{0,252}[`"]\s*\)\s*', rule
                )
            ),
            entrypoints=names(raw.get("entryPoints")),
            middlewares=names(raw.get("middlewares")),
            service=name(raw.get("service")),
            tls_configured="tls" in raw and raw["tls"] is not None,
        )
    elif kind == "services":
        balancer = raw.get("loadBalancer")
        servers = balancer.get("servers", []) if isinstance(balancer, dict) else []
        if not isinstance(servers, list):
            servers = []
        row["backend_count"] = len(servers)
        row["backend_origins"] = [
            value
            for server in servers[:32]
            if isinstance(server, dict)
            if (value := endpoint(server.get("url") or server.get("address")))
        ]
        row["backend_list_truncated"] = len(servers) > 32
        row["service_type"] = name(raw.get("type"))
        states = raw.get("serverStatus")
        if isinstance(states, dict):
            row["backend_up_count"] = sum(value == "UP" for value in states.values())
            row["backend_down_count"] = sum(
                value == "DOWN" for value in states.values()
            )
    else:
        # Middleware type and name only. Auth users, headers and rules are private.
        row["middleware_type"] = name(raw.get("type"))
    return row


def collect(config, fetch=get_page):
    rows = []
    for protocol, kind in SECTIONS:
        seen = set()
        for page in range(1, MAX_PAGES + 1):
            try:
                raw, more = fetch(config, protocol, kind, page)
                for item in raw:
                    row = project(protocol, kind, item)
                    if row["name"] in seen:
                        raise ValueError("Duplicate Traefik resource during pagination")
                    seen.add(row["name"])
                    rows.append(row)
            except (OSError, ValueError, TypeError, http.client.HTTPException) as error:
                # Only fixed endpoint names, page numbers and allowlisted
                # categories are logged, never raw API fields or exceptions.
                category = (
                    "transport"
                    if isinstance(error, (OSError, http.client.HTTPException))
                    else "invalid_response"
                )
                print(
                    f"Traefik {protocol}/{kind} page {page}: {category}",
                    file=sys.stderr,
                )
                raise
            if not more:
                break
        else:
            raise ValueError("Traefik inventory exceeds page limit")
    rows.sort(key=lambda item: (item["kind"], item["protocol"], item["name"]))
    return {
        "version": 1,
        "observed_at": timestamp(),
        "source_id": source_id(config),
        "items": rows,
    }


def write(path, document):
    encoded = json.dumps(document, separators=(",", ":"))
    if len(encoded.encode()) > MAX_BYTES:
        raise ValueError("Traefik snapshot exceeds size limit")
    name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as handle:
            name = handle.name
            handle.write(encoded)
        os.replace(name, path)
    finally:
        if name is not None:
            Path(name).unlink(missing_ok=True)


def read(path):
    try:
        if path.is_symlink() or path.stat().st_size > MAX_BYTES:
            return {}
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) and value.get("version") == 1 else {}
    except (OSError, ValueError, TypeError):
        return {}


def refresh(data, config, fetch=get_page):
    """Publish only a complete collection and keep last-good evidence on failure."""
    if config is None:
        raise ValueError("Traefik collector is not configured")
    with (data / "traefik-refresh.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        status = {
            "version": 1,
            "attempted_at": timestamp(),
            "source_id": source_id(config),
            "ok": False,
        }
        write(data / "traefik-view-status.json", status)
        view = collect(config, fetch)
        write(data / "traefik-view.json", view)
        status.update(ok=True, observed_at=view["observed_at"])
        write(data / "traefik-view-status.json", status)
        return view


def saved(data, env=None):
    """Read local sanitized state only. Freshness is not a reachability check."""
    env = os.environ if env is None else env
    try:
        config = settings(env)
        configured = config is not None
    except ValueError:
        config, configured = None, False
    view = read(data / "traefik-view.json")
    status = read(data / "traefik-view-status.json")
    matches = bool(config and view.get("source_id") == source_id(config))
    rows = view.get("items", [])
    available = (
        matches
        and isinstance(rows, list)
        and all(isinstance(row, dict) for row in rows)
    )
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
        and status.get("source_id") == view.get("source_id")
        and status.get("observed_at") == view.get("observed_at")
    )
    return {
        "configured": configured,
        "available": available,
        "observed_at": view.get("observed_at") if available else None,
        "last_attempt_at": (
            status.get("attempted_at")
            if config and status.get("source_id") == source_id(config)
            else None
        ),
        "last_refresh_verified": verified,
        "fresh": bool(verified and age is not None and 0 <= age <= STALE_SECONDS),
        "items": rows if available else [],
    }


def main():
    # Hard wall-clock limit in addition to socket timeouts.
    signal.alarm(90)
    try:
        view = refresh(Path("/data"), settings(os.environ))
        print(f"Traefik presentation refreshed: {len(view['items'])} resources.")
        return 0
    except (OSError, ValueError, TypeError, http.client.HTTPException):
        print(
            "Traefik refresh unavailable; previous complete snapshot retained.",
            file=sys.stderr,
        )
        return 2
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    sys.exit(main())
