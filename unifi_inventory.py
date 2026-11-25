"""Optional local UniFi Network Integration API collector; GET only."""

import fcntl
import http.client
import ipaddress
import json
import os
import re
import signal
import socket
import ssl
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

from adapter_state import saved_snapshot, source_id, timestamp, write

INTERVAL = 300
STALE_SECONDS = 900
PAGE_SIZE = 100
MAX_ROWS = 2000
MAX_RESPONSE = 1024 * 1024
KEY_FILE = Path("/config/unifi-api-key.txt")
CA_FILE = Path("/config/unifi-ca.pem")
KINDS = ("devices", "clients", "networks")
PREFIX = "/proxy/network/integration/v1"


def settings(env):
    value = env.get("YGGFLARE_UNIFI_API_URL", "")
    if not value:
        return None
    try:
        url = urlsplit(value)
        address = ipaddress.ip_address(url.hostname or "")
        lan = ipaddress.ip_network(env["YGGFLARE_LAN_CIDR"])
        port = url.port if url.port is not None else 443
        site = env.get("YGGFLARE_UNIFI_SITE_ID", "")
        tls_name = env.get("YGGFLARE_UNIFI_TLS_NAME", "") or str(address)
        if (
            url.scheme != "https" or url.username is not None or url.password is not None
            or url.path not in {"", "/"} or url.query or url.fragment
            or address not in lan or address.is_unspecified or address.is_multicast
            or "%" in str(address) or not 1 <= port <= 65535
            or not re.fullmatch(r"[A-Za-z0-9.:-]{1,253}", tls_name)
        ):
            raise ValueError
        return str(address), port, str(UUID(site)) if site else "", tls_name
    except (KeyError, ValueError, TypeError):
        raise ValueError("UniFi requires a numeric HTTPS LAN origin, optional site UUID and certificate name") from None


def read_key(path=KEY_FILE):
    with path.open("rb") as handle:
        key = handle.read(4097).strip()
    if not re.fullmatch(rb"[!-~]{1,4096}", key):
        raise ValueError("Invalid UniFi API key file")
    return key.decode("ascii")


def get_page(config, key, kind, site, offset):
    if kind == "sites" and not site:
        path = PREFIX + "/sites"
    elif kind in KINDS and site:
        path = PREFIX + "/sites/" + str(UUID(site)) + "/" + kind
    else:
        raise ValueError("Invalid UniFi endpoint")
    if not 0 <= offset < MAX_ROWS:
        raise ValueError("Invalid UniFi page offset")
    address, port, _, tls_name = config
    context = ssl.create_default_context()
    if CA_FILE.is_file():
        context.load_verify_locations(cafile=str(CA_FILE))
    # Connect only to the configured numeric IP; validate the certificate's
    # name separately. Never resolve an API-supplied host or follow redirects.
    conn = http.client.HTTPConnection(address, port, timeout=5)
    try:
        with socket.create_connection((address, port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=tls_name) as secured:
                conn.sock = secured
                conn.request("GET", f"{path}?offset={offset}&limit={PAGE_SIZE}",
                             headers={"Accept": "application/json", "X-API-Key": key})
                response = conn.getresponse()
                if response.status != 200:
                    raise ValueError("UniFi API did not return HTTP 200")
                body = response.read(MAX_RESPONSE + 1)
                if len(body) > MAX_RESPONSE:
                    raise ValueError("UniFi response exceeds byte limit")
                return json.loads(body)
    finally:
        conn.close()


def all_rows(config, key, kind, site, fetch):
    rows, seen, total = [], set(), None
    while True:
        payload = fetch(config, key, kind, site, len(rows))
        if not isinstance(payload, dict):
            raise ValueError("Invalid UniFi page")
        data = payload.get("data")
        count, offset, limit, current_total = (payload.get(k) for k in ("count", "offset", "limit", "totalCount"))
        if (
            any(type(v) is not int for v in (count, offset, limit, current_total))
            or not isinstance(data, list) or count != len(data)
            or offset != len(rows) or not 1 <= limit <= PAGE_SIZE
            or count > limit or not 0 <= current_total <= MAX_ROWS
            or offset + count > current_total
            or (total is not None and current_total != total)
        ):
            raise ValueError("Incomplete or changing UniFi pagination")
        total = current_total
        for item in data:
            if not isinstance(item, dict):
                raise ValueError("Invalid UniFi row")
            identifier = str(UUID(item.get("id", "")))
            if identifier in seen:
                raise ValueError("Duplicate UniFi identity during pagination")
            seen.add(identifier)
            rows.append(item)
        if len(rows) == total:
            return rows
        if not count:
            raise ValueError("Incomplete UniFi collection")


def text(value, limit=128):
    return "".join(c for c in value[:limit] if c.isprintable()) if isinstance(value, str) else None


def ip(value):
    try:
        return str(ipaddress.ip_address(value)) if isinstance(value, str) and "%" not in value else None
    except ValueError:
        return None


def time_value(value):
    try:
        dt = datetime.fromisoformat(value)
        return dt.astimezone(UTC).isoformat() if dt.tzinfo else None
    except (TypeError, ValueError):
        return None


def project(kind, raw):
    """Only explicit operational identity and state fields; no raw payloads."""
    result = {"kind": kind, "name": text(raw.get("name"))}
    if kind in ("devices", "clients"):
        mac = raw.get("macAddress")
        result.update(ip=ip(raw.get("ipAddress")),
                      mac=mac.lower() if isinstance(mac, str) and re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac) else None)
    if kind == "devices":
        result.update(model=text(raw.get("model")), state=text(raw.get("state")),
                      firmware=text(raw.get("firmwareVersion")),
                      firmware_updatable=raw.get("firmwareUpdatable") if type(raw.get("firmwareUpdatable")) is bool else None)
    elif kind == "clients":
        result.update(client_type=text(raw.get("type")), connected_at=time_value(raw.get("connectedAt")))
    elif kind == "networks":
        vlan = raw.get("vlanId")
        result.update(vlan_id=vlan if type(vlan) is int and 0 <= vlan <= 4094 else None,
                      enabled=raw.get("enabled") if type(raw.get("enabled")) is bool else None,
                      management=text(raw.get("management")))
    else:
        raise ValueError("Unknown UniFi kind")
    return result


def collect(config, key, fetch=get_page):
    sites = all_rows(config, key, "sites", "", fetch)
    desired = config[2]
    chosen = [row for row in sites if not desired or str(UUID(row["id"])) == desired]
    if len(chosen) != 1:
        raise ValueError("Select exactly one UniFi site by UUID")
    site = str(UUID(chosen[0]["id"]))
    rows = [project(kind, item) for kind in KINDS for item in all_rows(config, key, kind, site, fetch)]
    rows.sort(key=lambda row: (row["kind"], row["name"] or "", row.get("mac") or "", row.get("ip") or "", row.get("vlan_id") or 0))
    return {"version": 1, "observed_at": timestamp(), "source_id": source_id(config),
            "site_name": text(chosen[0].get("name")), "items": rows}


def refresh(data, config, fetch=get_page, key_loader=read_key):
    if config is None:
        raise ValueError("UniFi collector is not configured")
    with (data / "unifi-refresh.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        status = {"version": 1, "attempted_at": timestamp(), "source_id": source_id(config), "ok": False}
        write(data / "unifi-view-status.json", status)
        view = collect(config, key_loader(), fetch)
        write(data / "unifi-view.json", view)
        status.update(ok=True, observed_at=view["observed_at"])
        write(data / "unifi-view-status.json", status)
        return view


def saved(data, env=None):
    env = os.environ if env is None else env
    try:
        config = settings(env)
    except ValueError:
        config = None
    result = saved_snapshot(data, "unifi", config, config is not None, STALE_SECONDS)
    result["configuration_invalid"] = bool(env.get("YGGFLARE_UNIFI_API_URL") and config is None)
    return result


def main():
    signal.alarm(90)
    try:
        view = refresh(Path("/data"), settings(os.environ))
        print(f"UniFi presentation refreshed: {len(view['items'])} resources.")
        return 0
    except (OSError, ValueError, TypeError, AttributeError, http.client.HTTPException):
        print("UniFi refresh unavailable; previous complete snapshot retained.", file=sys.stderr)
        return 2
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    sys.exit(main())
