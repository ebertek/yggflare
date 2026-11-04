"""Bounded supplemental ARP/NDP and IPv6 observations, never DNS input."""

import ipaddress
import json
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import UTC, datetime

from service_discovery import collect as collect_services

DEFAULT_MAX_TARGETS = 512
HARD_MAX_TARGETS = 4096
NMAP_BATCH_SIZE = 64
MAX_SEEDS = 4096


def collect(network, run=None, seeds=()):
    """Explicit interfaces and prefixes gate every active probe."""
    raw_interfaces = os.environ.get("YGGFLARE_DISCOVERY_INTERFACES", "").strip()
    if not raw_interfaces:
        return {}
    interfaces = [v.strip() for v in raw_interfaces.split(",")]
    try:
        max_targets = int(
            os.environ.get("YGGFLARE_DISCOVERY_MAX_TARGETS", DEFAULT_MAX_TARGETS)
        )
    except ValueError as error:
        raise ValueError("Invalid YGGFLARE_DISCOVERY_MAX_TARGETS") from error
    if not 1 <= max_targets <= HARD_MAX_TARGETS:
        raise ValueError("YGGFLARE_DISCOVERY_MAX_TARGETS must be 1-4096")
    raw_prefixes = os.environ.get("YGGFLARE_DISCOVERY_IPV6_CIDRS", "").strip()
    config = {
        "ipv6_prefixes": (
            [v.strip() for v in raw_prefixes.split(",")] if raw_prefixes else []
        )
    }
    for flag in ("arp_scan", "ndp_probe", "ipv6_scan", "os_detection"):
        name = "YGGFLARE_DISCOVERY_" + flag.upper()
        value = os.environ.get(name, "false")
        if value not in ("true", "false"):
            raise ValueError(f"{name} must be true or false")
        config[flag] = value == "true"
    if (
        not isinstance(interfaces, list)
        or not 1 <= len(interfaces) <= 4
        or any(
            not isinstance(i, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}", i)
            for i in interfaces
        )
    ):
        raise ValueError("Invalid discovery interfaces")
    prefixes = [ipaddress.IPv6Network(p) for p in config.get("ipv6_prefixes", [])]
    if any(p.prefixlen < 64 or p.is_multicast or p.is_link_local for p in prefixes):
        raise ValueError("Use explicit unicast IPv6 prefixes of /64 or narrower")
    result = {
        "observed_at": datetime.now(UTC).isoformat(),
        "records": [],
        "warnings": [],
    }

    def note(message):
        print(f"[discovery] {message}", file=sys.stderr, flush=True)

    def command(args, timeout=30, *, no_reply_codes=()):
        try:
            if run:
                return run(args)
            started = time.monotonic()
            with subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            ) as process:
                while True:
                    remaining = timeout - (time.monotonic() - started)
                    if remaining <= 0:
                        process.kill()
                        process.communicate()
                        raise subprocess.TimeoutExpired(args[0], timeout)
                    try:
                        stdout, _ = process.communicate(timeout=min(15, remaining))
                        break
                    except subprocess.TimeoutExpired:
                        note(
                            f"{args[0]} still running "
                            f"({time.monotonic() - started:.0f}s)"
                        )
                if process.returncode:
                    raise subprocess.CalledProcessError(process.returncode, args[0])
                if len(stdout) > 2 * 1024 * 1024:
                    raise ValueError("Oversize discovery output")
                return stdout
        except subprocess.CalledProcessError as error:
            # ndisc6 returns 2 for an unanswered neighbour solicitation,
            # distinct from exit 1 for an execution/protocol error.
            if error.returncode in no_reply_codes:
                return ""
            result["warnings"].append(args[0] + ": unavailable, failed or timed out")
            return ""
        except (OSError, ValueError, subprocess.SubprocessError):
            result["warnings"].append(args[0] + ": unavailable, failed or timed out")
            return ""

    def allowed(address):
        return (
            address in network
            if address.version == 4
            else any(address in p for p in prefixes)
        )

    def add(ip, interface, source, detail):
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return
        if allowed(address):
            result["records"].append(
                {
                    "ip": str(address),
                    "interface": interface,
                    "source": source,
                    "detail": str(detail)[:512],
                }
            )

    for interface in interfaces:
        raw = command(["ip", "-j", "neigh", "show", "dev", interface])
        try:
            neighbors = json.loads(raw) if raw else []
            if not isinstance(neighbors, list):
                raise ValueError("Invalid neighbor response")
            for item in neighbors:
                if not isinstance(item, dict):
                    continue
                state = item.get("state", [])
                if any(s in state for s in ("FAILED", "INCOMPLETE")):
                    continue
                add(
                    item.get("dst", ""),
                    interface,
                    "Neighbor cache",
                    f"{item.get('lladdr', '')} ({', '.join(state)})",
                )
        except (ValueError, TypeError):
            result["warnings"].append("ip: invalid neighbor response")
        if config.get("arp_scan"):
            if network.num_addresses > 4096:
                raise ValueError("ARP discovery range exceeds 4096 addresses")
            raw = command(
                ["arp-scan", "--interface", interface, "--retry=1", str(network)]
            )
            for line in raw.splitlines():
                fields = line.split()
                if len(fields) >= 2 and re.fullmatch(
                    r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", fields[1]
                ):
                    add(fields[0], interface, "ARP reply", fields[1].lower())
    # Supplemental sources supply candidates, never a CIDR sweep. Resolve the
    # actual outgoing interface instead of copying a Docker network name.
    candidates = list(seeds)
    if len(candidates) > MAX_SEEDS:
        raise ValueError("Too many discovery seeds; refusing silent truncation")
    if config.get("ipv6_scan") and prefixes:
        try:
            ids = command(["docker", "ps", "-q"]).split()
            if len(ids) > 512 or any(
                not re.fullmatch(r"[a-f0-9]{12,64}", value) for value in ids
            ):
                raise ValueError("Invalid container list")
            containers = json.loads(command(["docker", "inspect", *ids])) if ids else []
            for container in containers:
                if (container.get("State") or {}).get("Running") is not True:
                    continue
                for endpoint in (
                    (container.get("NetworkSettings") or {}).get("Networks") or {}
                ).values():
                    candidates.append(
                        (endpoint.get("GlobalIPv6Address", ""), "Docker address")
                    )
        except (ValueError, TypeError, AttributeError):
            result["warnings"].append("Docker IPv6 candidates unavailable")
    known = {r["ip"] for r in result["records"]}
    routed = set()
    routed_counts = {4: 0, 6: 0}
    routed_limited = set()
    for raw, source in sorted(set(candidates)):
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if not allowed(address) or str(address) in known or str(address) in routed:
            continue
        if routed_counts[address.version] >= max_targets:
            if address.version not in routed_limited:
                result["warnings"].append(
                    f"IPv{address.version} routed candidates limited to "
                    f"{max_targets} addresses"
                )
                routed_limited.add(address.version)
            continue
        if address.version == 4 and not config.get("os_detection"):
            continue
        if address.version == 6 and not (
            config.get("ipv6_scan") or config.get("ndp_probe")
        ):
            continue
        routed.add(str(address))
        routed_counts[address.version] += 1
        try:
            routes = json.loads(
                command(
                    [
                        "ip",
                        "-j",
                        "-6" if address.version == 6 else "-4",
                        "route",
                        "get",
                        str(address),
                    ]
                )
            )
            interface = routes[0].get("dev", "") if routes else ""
            if interface in interfaces:
                add(
                    str(address),
                    interface,
                    source,
                    "Candidate address; reachability unverified",
                )
        except (ValueError, TypeError, KeyError, AttributeError):
            result["warnings"].append("Candidate route unavailable")
    # Preserve every observation, but probe each address once per family.
    # A host/macvlan pair may see the same address on both interfaces; route
    # selection prevents double Nmap probes and wasted target slots.
    targets = []
    for version in (4, 6):
        by_ip = defaultdict(set)
        for record in result["records"]:
            if (
                ipaddress.ip_address(record["ip"]).version == version
                and record["interface"] in interfaces
            ):
                by_ip[record["ip"]].add(record["interface"])
        selected = []
        for ip in sorted(by_ip, key=lambda value: int(ipaddress.ip_address(value))):
            observed_interfaces = by_ip[ip]
            preferred = next(
                iface for iface in interfaces if iface in observed_interfaces
            )
            if len(observed_interfaces) > 1:
                # For overlapping interfaces prefer the kernel's real egress
                # route; if absent/unusable, keep the first configured source.
                try:
                    routes = json.loads(
                        command(
                            [
                                "ip",
                                "-j",
                                "-6" if version == 6 else "-4",
                                "route",
                                "get",
                                ip,
                            ]
                        )
                    )
                    routed_interface = (
                        routes[0].get("dev", "")
                        if isinstance(routes, list) and routes
                        else ""
                    )
                    if routed_interface in observed_interfaces:
                        preferred = routed_interface
                except (TypeError, ValueError, AttributeError):
                    pass
            selected.append((ip, preferred))
        if len(selected) > max_targets:
            result["warnings"].append(
                f"IPv{version} probe targets limited to {max_targets} unique addresses"
            )
        targets.extend(selected[:max_targets])
    # NDP probes use the chosen route/interface for each candidate.
    ndp_targets = [
        (ip, interface)
        for ip, interface in targets
        if ipaddress.ip_address(ip).version == 6 and config.get("ndp_probe")
    ]
    if ndp_targets:
        note(f"NDP probes: {len(ndp_targets)} addresses")
    for index, (ip, interface) in enumerate(ndp_targets, 1):
        raw = command(
            ["ndisc6", "-q", "-r", "1", "-w", "500", ip, interface],
            no_reply_codes=(2,),
        )
        for line in raw.splitlines():
            if re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", line.strip()):
                add(ip, interface, "NDP reply", line.strip().lower())
        if index % 8 == 0 or index == len(ndp_targets):
            note(f"NDP probes completed: {index}/{len(ndp_targets)}")

    # Bound Nmap subprocess time/output per batch without truncating targets.
    # Each group contains only previously validated, explicitly scoped targets.
    grouped = defaultdict(list)
    for ip, interface in targets:
        ipv6 = ipaddress.ip_address(ip).version == 6
        if (ipv6 and config.get("ipv6_scan")) or (
            not ipv6 and config.get("os_detection")
        ):
            grouped[(ipv6, interface)].append(ip)
    batches = [
        (ipv6, interface, addresses[start : start + NMAP_BATCH_SIZE])
        for (ipv6, interface), addresses in sorted(grouped.items())
        for start in range(0, len(addresses), NMAP_BATCH_SIZE)
    ]
    for ipv6, interface, addresses in batches:
        family = "IPv6" if ipv6 else "IPv4"
        note(f"START {family} Nmap on {interface}: {len(addresses)} targets")
        started = time.monotonic()
        args = [
            "nmap",
            *(["-6"] if ipv6 else []),
            "-n",
            "-Pn",
            "-sV",
            "--version-light",
            "--top-ports",
            "20",
            "--max-retries",
            "1",
            "--host-timeout",
            "15s",
            "-e",
            interface,
            "-oX",
            "-",
        ]
        if config.get("os_detection"):
            args += ["-O", "--osscan-limit", "--max-os-tries", "1"]
        raw = command([*args, *addresses], timeout=90)
        note(f"END {family} Nmap on {interface}: {time.monotonic() - started:.1f}s")
        if not raw:
            continue
        try:
            root = ET.fromstring(raw)
            scoped = set(addresses)
            for host in root.findall("host"):
                reported = [
                    address.get("addr", "")
                    for address in host.findall("address")
                    if address.get("addrtype") == ("ipv6" if ipv6 else "ipv4")
                ]
                # Older offline single-target fixtures omit the address tag.
                if not reported and len(addresses) == 1:
                    reported = addresses
                for raw_ip in reported:
                    try:
                        ip = str(ipaddress.ip_address(raw_ip))
                    except ValueError:
                        continue
                    if ip not in scoped:
                        continue
                    for port in host.findall("./ports/port"):
                        state = port.find("state")
                        if state is not None and state.get("state") == "open":
                            service = port.find("service")
                            label = (
                                service.get("name", "") if service is not None else ""
                            )
                            add(
                                ip,
                                interface,
                                "Nmap IPv6" if ipv6 else "Nmap IPv4",
                                f"{port.get('protocol')}/{port.get('portid')} {label}",
                            )
                    for match in host.findall("./os/osmatch"):
                        add(
                            ip,
                            interface,
                            "Nmap OS estimate",
                            f"{match.get('name')} (accuracy {match.get('accuracy')}%)",
                        )
        except ET.ParseError:
            result["warnings"].append("nmap: invalid XML response")
    note("START optional service discovery")
    collect_services(interfaces, allowed, result["records"], add, result["warnings"])
    note(
        f"END supplemental discovery: {len(result['records'])} observations; {len(result['warnings'])} warnings"
    )
    return result
