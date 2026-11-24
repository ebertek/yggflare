"""Sanitized, read-only Compose/Docker inventory for presentation only.

Never feed these inferred ports or names into Cloudflare reconciliation.
Only the projection below leaves this module; raw environment and labels do not.
"""

import ipaddress
import json
import re
import subprocess
import threading
import time
from datetime import UTC, datetime
from urllib.parse import urlsplit

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

MAX_BYTES = 4 * 1024 * 1024
_LOCK = threading.Lock()
_CACHE = {}
_SERVICE_CACHE = {}


def address_key(value):
    """Sort addresses/CIDRs numerically, with invalid or absent values last."""
    try:
        network = ipaddress.ip_network(value, strict=False)
        return network.version, int(network.network_address), network.prefixlen
    except (ValueError, TypeError):
        return 9, 0, 0


def mapping(value):
    """Accept Compose mapping and KEY=value list syntax."""
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        return dict(
            item.split("=", 1)
            for item in value
            if isinstance(item, str) and "=" in item
        )
    return {}


def names(values):
    """Allow DNS-like identifiers only, excluding unresolved substitutions."""
    return sorted(
        {
            str(v).rstrip(".")
            for v in values
            if re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,252}", str(v))
        }
    )


def ports(config, labels, runtime=False):
    """Collect port evidence without confusing host mappings with container ports."""
    result = {}

    def add(value, source, protocol="tcp"):
        value = str(value)
        if "/" in value:
            value, protocol = value.rsplit("/", 1)
        if protocol not in ("tcp", "udp") or not re.fullmatch(r"\d+(?:-\d+)?", value):
            return
        bounds = [int(v) for v in value.split("-")]
        if not 1 <= bounds[0] <= bounds[-1] <= 65535 or bounds[-1] - bounds[0] > 1024:
            return
        for port in range(bounds[0], bounds[-1] + 1):
            result.setdefault(f"{protocol}/{port}", set()).add(source)

    if runtime:
        for port in config.get("ExposedPorts") or {}:
            add(port, "Docker exposed")
    else:
        for port in config.get("ports") or []:
            if isinstance(port, dict):
                add(
                    port.get("target", ""), "Compose ports", port.get("protocol", "tcp")
                )
            else:
                add(str(port).rsplit(":", 1)[-1], "Compose ports")
        for port in config.get("expose") or []:
            add(port, "Compose expose")
    for key, value in labels.items():
        match = re.fullmatch(
            r"traefik\.(http|tcp|udp)\.services\.[^.]+\.loadbalancer\.server\.port",
            str(key),
        )
        if match:
            add(value, "Traefik backend", "udp" if match[1] == "udp" else "tcp")
        elif re.fullmatch(
            r"traefik\.http\.services\.[^.]+\.loadbalancer\.server\.url", str(key)
        ):
            try:
                url = urlsplit(str(value))
                if url.scheme in ("http", "https"):
                    add(
                        url.port or (443 if url.scheme == "https" else 80),
                        "Traefik backend",
                    )
            except ValueError:
                pass
    # Environment hints are candidates only. Never export keys/values or parse
    # database/remote endpoint URLs, credentials, or arbitrary integers.
    for key, value in mapping(config.get("Env" if runtime else "environment")).items():
        key = str(key).upper()
        if re.search(r"PASSWORD|SECRET|TOKEN|KEY|REMOTE|UPSTREAM|DATABASE|DB_", key):
            continue
        if re.fullmatch(r"(?:[A-Z0-9]+_)*PORT", key):
            add(value, "Environment hint", "udp" if "UDP" in key.split("_") else "tcp")
        elif key.endswith(
            ("_HTTP_ADDRESS", "_HTTPS_ADDRESS", "_LISTEN_ADDRESS")
        ) or re.fullmatch(r"TRAEFIK_ENTRYPOINTS_.+_ADDRESS", key):
            match = re.fullmatch(
                r"(?:\[[0-9a-fA-F:]+\]|[0-9.]*):(\d+)(?:/(tcp|udp))?", str(value)
            )
            if match:
                add(match[1], "Environment hint", match[2] or "tcp")
    return result


def metadata(config, name, domain, runtime=False):
    """Project only public-facing identity and port evidence."""
    labels = mapping(config.get("Labels" if runtime else "labels"))
    hostname = config.get("Hostname" if runtime else "hostname") or name
    hostname = next(iter(names([hostname])), name)
    if "." not in hostname and domain:
        hostname += "." + domain
    aliases = []
    for key, value in labels.items():
        if re.fullmatch(r"traefik\.http\.routers\.[^.]+\.rule", str(key)):
            aliases.extend(re.findall(r'Host\(\s*[`"]([^`"]+)[`"]\s*\)', str(value)))
    return {
        "hostname": hostname,
        "aliases": names(aliases),
        "port_sources": ports(config, labels, runtime),
    }


def endpoint(ip, ipv6, mac, aliases, network):
    """Keep LAN IPv4 endpoints only; never infer a host IP for host networking."""
    try:
        address = ipaddress.IPv4Address(ip)
        if address not in network:
            return None
    except (ValueError, TypeError):
        return None
    try:
        ipv6 = str(ipaddress.IPv6Address(ipv6)) if ipv6 else ""
    except (ValueError, TypeError):
        ipv6 = ""
    return {
        "ipv4": str(address),
        "ipv6": ipv6,
        "mac": str(mac or ""),
        "aliases": names(aliases or []),
    }


def image_reference(value):
    """Only literal image references, not interpolation or URLs."""
    if (
        isinstance(value, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}", value)
        and "://" not in value
    ):
        return value
    return None


def compose_records(root, network, domain):
    """Read source YAML, without executing Compose interpolation or env files."""
    records, warnings = [], []
    paths = sorted(set(root.rglob("compose.yaml")) | set(root.rglob("compose.yml")))
    for path in paths:
        try:
            if path.stat().st_size > MAX_BYTES:
                raise ValueError("Oversize input")
            document = YAML(typ="safe").load(path.read_text())
            for service, config in document.get("services", {}).items():
                name = str(config.get("container_name") or service)
                record = metadata(config, name, domain)
                endpoints = []
                for entry in mapping(config.get("networks")).values():
                    entry = entry or {}
                    item = endpoint(
                        entry.get("ipv4_address"),
                        entry.get("ipv6_address"),
                        entry.get("mac_address", config.get("mac_address")),
                        entry.get("aliases"),
                        network,
                    )
                    if item:
                        endpoints.append(item)
                records.append(
                    {
                        **record,
                        "name": name,
                        "project": str(document.get("name") or path.parent.name),
                        "service": str(service),
                        "endpoints": endpoints,
                        "status": "docker declared",
                        "source": "Compose",
                        "mode": str(config.get("network_mode") or ""),
                        "labels": mapping(config.get("labels")),
                        "declared_image": image_reference(config.get("image")),
                        "declared_networks": names(config.get("networks") or []),
                        "declared_dependencies": names(config.get("depends_on") or []),
                        "profiles": names(config.get("profiles") or []),
                        "declared_addresses": sorted(
                            {item["ipv4"] for item in endpoints}
                        ),
                    }
                )
        except (OSError, ValueError, TypeError, AttributeError, YAMLError):
            warnings.append(
                "A Compose file could not be read; its service metadata is unavailable."
            )
    return records, warnings


def inspect_containers():
    """Bounded read-only Docker CLI calls; never return stderr to the UI."""
    result = subprocess.run(
        ["docker", "ps", "-aq"], capture_output=True, text=True, timeout=5, check=True
    )
    ids = result.stdout.split()
    if not ids:
        return []
    if len(ids) > 512 or any(
        not re.fullmatch(r"[a-f0-9]{12,64}", item) for item in ids
    ):
        raise ValueError("Invalid Docker container list")
    result = subprocess.run(
        ["docker", "inspect", *ids],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    if len(result.stdout) > 16 * MAX_BYTES:
        raise ValueError("Docker inventory too large")
    return json.loads(result.stdout)


def collect(root, network, domain, *, service_view=None):
    """Merge by explicit container name or unique Compose project/service identity."""
    records, warnings = compose_records(root, network, domain)
    compose_complete = not warnings and bool(records)
    runtime_available = True
    try:
        containers = inspect_containers()
    except (OSError, ValueError, subprocess.SubprocessError):
        containers = []
        runtime_available = False
        warnings.append(
            "Docker metadata unavailable; showing Compose declarations and saved scans."
        )
    for container in containers:
        config = container.get("Config") or {}
        labels = config.get("Labels") or {}
        name = str(container.get("Name", "")).lstrip("/")
        # Match declarations only, not runtime-only records appended earlier.
        declared = [r for r in records if r.get("service") and not r.get("id")]
        by_name = [r for r in declared if r["name"] == name]
        by_service = [
            r
            for r in declared
            if r.get("project")
            and r["project"] == labels.get("com.docker.compose.project")
            and r["service"] == labels.get("com.docker.compose.service")
        ]
        if labels.get("com.docker.compose.project") and labels.get(
            "com.docker.compose.service"
        ):
            # A container name can recur on other deployment hosts. Prefer the
            # explicit Compose identity; never merge into an unrelated project.
            matches = by_service
            if len(matches) > 1:
                matches = [r for r in matches if r["name"] == name]
        else:
            matches = by_name
        record = matches[0] if len(matches) == 1 else None
        live = metadata(config, name, domain, runtime=True)
        for port in container.get("NetworkSettings", {}).get("Ports") or {}:
            match = re.fullmatch(r"(\d+)/(tcp|udp)", port)
            if match and 1 <= int(match[1]) <= 65535:
                live["port_sources"].setdefault(
                    f"{match[2]}/{int(match[1])}", set()
                ).add("Docker port binding")
        endpoints = []
        for entry in (
            container.get("NetworkSettings", {}).get("Networks") or {}
        ).values():
            item = endpoint(
                entry.get("IPAddress"),
                entry.get("GlobalIPv6Address"),
                entry.get("MacAddress"),
                entry.get("Aliases"),
                network,
            )
            if item:
                endpoints.append(item)
        if record is None:
            record = {
                **live,
                "name": name,
                "endpoints": [],
                "source": "Docker",
                "project": next(
                    iter(names([labels.get("com.docker.compose.project", "")])), ""
                ),
                "service": next(
                    iter(names([labels.get("com.docker.compose.service", "")])), ""
                ),
                "mode": str(
                    (container.get("HostConfig") or {}).get("NetworkMode") or ""
                ),
            }
            records.append(record)
        else:
            record["source"] = "Compose + Docker"
            record["aliases"] = names(record["aliases"] + live["aliases"])
            for port, sources in live["port_sources"].items():
                record["port_sources"].setdefault(port, set()).update(sources)
        record["id"] = str(container.get("Id") or "")
        record["runtime_observed"] = True
        record["runtime_image"] = image_reference(config.get("Image"))
        state = container.get("State") or {}
        status = state.get("Status")
        record["runtime_state"] = (
            status
            if status
            in {
                "created",
                "running",
                "paused",
                "restarting",
                "removing",
                "exited",
                "dead",
            }
            else "running" if state.get("Running") is True else "unknown"
        )
        status = (state.get("Health") or {}).get("Status")
        record["health"] = (
            status if status in {"healthy", "unhealthy", "starting"} else None
        )
        record["runtime_networks"] = names(
            (container.get("NetworkSettings", {}).get("Networks") or {}).keys()
        )
        record["runtime_addresses"] = sorted({item["ipv4"] for item in endpoints})
        restart_count = container.get("RestartCount")
        record["restart_count"] = (
            restart_count if type(restart_count) is int and restart_count >= 0 else None
        )
        record["mode"] = str(
            (container.get("HostConfig") or {}).get("NetworkMode") or record["mode"]
        )
        record["labels"] = {**record.get("labels", {}), **labels}
        # Live addresses replace declarations only when running; stopped services
        # retain their declared allocation, explicitly marked as not running.
        running = (container.get("State") or {}).get("Running") is True
        record["status"] = "docker running" if running else "docker stopped"
        if endpoints and running:
            old = {e["ipv4"]: e for e in record["endpoints"]}
            for item in endpoints:
                prior = old.get(item["ipv4"], {})
                item["aliases"] = names(item["aliases"] + prior.get("aliases", []))
                for key in ("ipv6", "mac"):
                    item[key] = item[key] or prior.get(key, "")
            record["endpoints"] = endpoints

    def resolve(record, visited):
        if id(record) in visited:
            return [], ""
        mode = record["mode"]
        if not mode.startswith(("service:", "container:")):
            return record["endpoints"], ""
        kind, target = mode.split(":", 1)
        if kind == "service":
            candidates = [
                r
                for r in records
                if r.get("project") == record.get("project")
                and r.get("project")
                and r.get("service") == target
            ]
        else:
            candidates = [
                r
                for r in records
                if r["name"] == target
                or (len(target) >= 12 and r.get("id", "").startswith(target))
            ]
        if len(candidates) != 1:
            return [], ""
        parent = candidates[0]
        endpoints, root = resolve(parent, visited | {id(record)})
        # Router/service names explicitly matching the child supply its own
        # declarations; do not assign every VPN-side port to every child.
        service = record.get("service", record["name"])
        labels = parent.get("labels", {})
        selected = {
            k: v
            for k, v in labels.items()
            if k.startswith(f"traefik.http.routers.{service}.")
            or k.startswith(f"traefik.http.services.{service}.")
        }
        extra = metadata({"labels": selected}, record["name"], domain)
        record["aliases"] = names(record["aliases"] + extra["aliases"])
        for port, sources in extra["port_sources"].items():
            record["port_sources"].setdefault(port, set()).update(sources)
        return endpoints, root or parent["name"]

    hosts = []
    services = []
    local_projects = {
        r.get("project")
        for r in records
        if r.get("runtime_observed") and r.get("project")
    }
    name_counts = {}
    for record in records:
        name_counts[record["name"]] = name_counts.get(record["name"], 0) + 1
    for record in records:
        endpoints, shared = resolve(record, set())
        if service_view is not None:
            services.append(
                service_record(
                    record,
                    endpoints,
                    shared,
                    local_projects,
                    runtime_available,
                    compose_complete,
                )
            )
        if not endpoints:
            continue
        evidence = {
            p: sorted(s)
            for p, s in sorted(
                record["port_sources"].items(),
                key=lambda v: (v[0].split("/")[0], int(v[0].split("/")[1])),
            )
        }
        for item in endpoints:
            hosts.append(
                {
                    **item,
                    "hostname": record["hostname"],
                    "shared_network": shared,
                    "container_name": record["name"],
                    "network_owner": (
                        shared or record["name"]
                        if name_counts[shared or record["name"]] == 1
                        else ""
                    ),
                    "aliases": names(record["aliases"] + item["aliases"]),
                    "ports": list(evidence),
                    "port_sources": evidence,
                    "source": record["source"],
                    "description": "Docker service "
                    + record["name"]
                    + (" (shared network: " + shared + ")" if shared else ""),
                    "status": record["status"],
                }
            )
    if service_view is not None:
        services.sort(
            key=lambda row: (row["project"], row["service"], row["container_name"])
        )
        service_view.update(
            observed_at=datetime.now(UTC).isoformat(),
            runtime_available=runtime_available,
            compose_complete=compose_complete,
            total=len(services),
            truncated=len(services) > 2000,
            items=services[:2000],
        )
    return hosts, sorted(set(warnings))


def service_record(
    record, endpoints, shared, local_projects, runtime_available, compose_complete
):
    """Project all services, including bridge/host-only declarations."""
    project = record.get("project", "")
    service = record.get("service", "")
    observed = record.get("runtime_observed") is True
    declared = record["source"] != "Docker"
    local_project = bool(project and project in local_projects)
    expected = record.get("declared_image")
    actual = record.get("runtime_image")
    mode = record.get("mode", "")
    mode_kind = mode.split(":", 1)[0]
    if mode_kind not in {"host", "none", "bridge", "default", "service", "container"}:
        mode_kind = "named_network" if mode else "unspecified"
    return {
        "project": project,
        "service": service,
        "container_name": record["name"],
        "hostname": record["hostname"],
        "aliases": record["aliases"][:64],
        "declared": declared,
        "runtime_observed": observed,
        "runtime_scope": "local_engine" if observed else "not_observed_locally",
        "local_project_observed": local_project,
        "runtime_state": record.get("runtime_state"),
        "health": record.get("health"),
        "restart_count": record.get("restart_count"),
        "declared_image": expected,
        "runtime_image": actual,
        "image_reference_match": expected == actual if expected and actual else None,
        "declared_networks": record.get("declared_networks", [])[:64],
        "runtime_networks": record.get("runtime_networks", [])[:64],
        "declared_dependencies": record.get("declared_dependencies", [])[:64],
        "profiles": record.get("profiles", [])[:64],
        "declared_addresses": record.get("declared_addresses", [])[:64],
        "runtime_addresses": record.get("runtime_addresses", [])[:64],
        "lan_endpoints": sorted({item["ipv4"] for item in endpoints})[:64],
        "network_mode_kind": mode_kind,
        "shared_network": shared or None,
        "ports": sorted(record["port_sources"])[:64],
        "port_list_truncated": len(record["port_sources"]) > 64,
        "presence": (
            "observed"
            if observed
            else (
                "not_observed_local_project"
                if runtime_available and local_project
                else "unknown"
            )
        ),
        "declaration_status": (
            "declared"
            if declared
            else "not_in_read_source" if compose_complete else "unknown"
        ),
    }


def service_snapshot(root, network, domain):
    """Independent bounded cache for MCP service-level topology."""
    key = str(root), str(network), domain
    with _LOCK:
        if _SERVICE_CACHE.get("key") != key or time.monotonic() >= _SERVICE_CACHE.get(
            "expires", 0
        ):
            view = {}
            collect(root, network, domain, service_view=view)
            _SERVICE_CACHE.update(key=key, expires=time.monotonic() + 30, value=view)
        return _SERVICE_CACHE["value"]


def local_macvlan_interfaces(network):
    """Identify actual local macvlan addresses, not guessed gateways."""
    try:
        result = subprocess.run(
            ["ip", "-j", "-d", "address", "show"],
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        )
        if len(result.stdout) > MAX_BYTES:
            return {}
        links = json.loads(result.stdout)
        if not isinstance(links, list):
            return {}
        found = {}
        duplicates = set()
        for link in links:
            if link.get("linkinfo", {}).get("info_kind") != "macvlan":
                continue
            name = link.get("ifname", "")
            mac = str(link.get("address", "")).lower()
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name):
                continue
            if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
                continue
            for address in link.get("addr_info", []):
                if address.get("family") != "inet":
                    continue
                ip = ipaddress.IPv4Address(address["local"])
                if ip not in network:
                    continue
                key = str(ip)
                if key in found:
                    duplicates.add(key)
                found[key] = {"interface": name, "mac": mac}
        return {key: value for key, value in found.items() if key not in duplicates}
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        subprocess.SubprocessError,
    ):
        return {}


def snapshot(root, network, domain):
    """Cache the sanitized projection for 30 seconds across HTTP threads."""
    key = str(root), str(network), domain
    with _LOCK:
        now = time.monotonic()
        if _CACHE.get("key") != key or now >= _CACHE.get("expires", 0):
            value = collect(root, network, domain)
            _CACHE.update(key=key, expires=time.monotonic() + 30, value=value)
        return _CACHE["value"]
