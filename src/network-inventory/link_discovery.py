"""Bounded supplemental ARP/NDP and IPv6 observations, never DNS input."""

import ipaddress
import json
import re
import subprocess
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

CONFIG = Path("/config/discovery.json")


def collect(network, run=None):
    """Explicit interfaces and prefixes gate every active probe."""
    if not CONFIG.exists():
        return {}
    config = json.loads(CONFIG.read_text())
    interfaces = config.get("interfaces", [])
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
    for flag in ("arp_scan", "ndp_probe", "ipv6_scan", "os_detection"):
        if not isinstance(config.get(flag, False), bool):
            raise ValueError("Discovery switches must be boolean")
    result = {
        "observed_at": datetime.now(UTC).isoformat(),
        "records": [],
        "warnings": [],
    }

    def command(args):
        try:
            if run:
                return run(args)
            value = subprocess.run(
                args, capture_output=True, text=True, timeout=30, check=True
            )
            if len(value.stdout) > 2 * 1024 * 1024:
                raise ValueError("Oversize discovery output")
            return value.stdout
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
    targets = sorted(
        {
            (r["ip"], r["interface"])
            for r in result["records"]
            if ipaddress.ip_address(r["ip"]).version == 6
        }
    )[:64]
    for ip, interface in targets:
        if config.get("ndp_probe"):
            raw = command(["ndisc6", "-q", "-r", "1", "-w", "500", ip, interface])
            for line in raw.splitlines():
                if re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", line.strip()):
                    add(ip, interface, "NDP reply", line.strip().lower())
        if config.get("ipv6_scan"):
            args = [
                "nmap",
                "-6",
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
            raw = command([*args, ip])
            if not raw:
                continue
            try:
                root = ET.fromstring(raw)
                for port in root.findall(".//host/ports/port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        service = port.find("service")
                        label = service.get("name", "") if service is not None else ""
                        add(
                            ip,
                            interface,
                            "Nmap IPv6",
                            f"{port.get('protocol')}/{port.get('portid')} {label}",
                        )
                for match in root.findall(".//host/os/osmatch"):
                    add(
                        ip,
                        interface,
                        "Nmap OS estimate",
                        f"{match.get('name')} (accuracy {match.get('accuracy')}%)",
                    )
            except ET.ParseError:
                result["warnings"].append("nmap: invalid XML response")
    return result
