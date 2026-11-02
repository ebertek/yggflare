"""Opt-in, read-only service identification for explicitly selected LAN hosts.

A normal scheduled inventory audit remains lightweight. This command uses
Nmap version probes only when an operator explicitly requests a deeper scan.
"""

import argparse
import ipaddress
import json
import subprocess
import sys
import xml.etree.ElementTree as ET

from audit import NETWORK, syn_scan_options


def parse_services(xml):
    """Extract confirmed listening ports and probed service identities."""
    records = []
    for host in ET.fromstring(xml).findall("host"):
        addresses = {
            address.get("addrtype"): address.get("addr")
            for address in host.findall("address")
        }
        ip = addresses.get("ipv4")
        if not ip:
            continue
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            details = {
                "ip": ip,
                "protocol": port.get("protocol"),
                "port": int(port.get("portid")),
            }
            if service is not None:
                for name in (
                    "name",
                    "product",
                    "version",
                    "extrainfo",
                    "method",
                    "conf",
                ):
                    value = service.get(name)
                    if value:
                        details[name] = value[:200]
            records.append(details)
    return sorted(
        records, key=lambda item: (ipaddress.ip_address(item["ip"]), item["port"])
    )


def probe(targets, top_ports, timeout, fingerprints):
    """Bound active probes to explicitly selected RFC1918 LAN addresses."""
    args = [
        *syn_scan_options("120s"),
        "--top-ports",
        str(top_ports),
        "-oX",
        "-",
    ]
    if fingerprints:
        args.extend(["-sV", "--version-light"])
    args.extend(targets)
    result = subprocess.run(
        args, capture_output=True, text=True, timeout=timeout, check=False
    )
    if result.returncode:
        raise RuntimeError(f"Nmap failed ({result.returncode}): {result.stderr[-400:]}")
    return parse_services(result.stdout)


def main():
    """Probe one or more explicit LAN targets and output machine-readable JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("targets", nargs="+", help="One or more LAN IPv4 addresses")
    parser.add_argument("--top-ports", type=int, default=1000)
    parser.add_argument(
        "--fingerprint",
        action="store_true",
        help="Send additional service probes (-sV --version-light), use cautiously",
    )
    parser.add_argument("--timeout", type=int, default=900)
    options = parser.parse_args()
    if not 1 <= options.top_ports <= 65535 or not 30 <= options.timeout <= 3600:
        parser.error("Invalid scan limits")
    for target in options.targets:
        try:
            address = ipaddress.IPv4Address(target)
        except ipaddress.AddressValueError:
            parser.error("Targets must be explicit IPv4 addresses, not DNS names")
        if address not in NETWORK:
            parser.error("Only 10.4.20.0/23 addresses are permitted")
    print(
        json.dumps(
            {
                "targets": options.targets,
                "fingerprinted": options.fingerprint,
                "services": probe(
                    options.targets,
                    options.top_ports,
                    options.timeout,
                    options.fingerprint,
                ),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ET.ParseError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
