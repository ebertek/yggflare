"""Read-only LAN discovery and inventory drift detection.

This tool reads private static-hosts.json and writes observations only to
--state-dir, outside the deployed GitOps checkout. It never edits DNS/inventory.
"""

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from discord_format import render
from link_discovery import collect as collect_links

from discord_webhook import validate_webhook_url

NETWORK = ipaddress.ip_network(os.environ["YGGFLARE_LAN_CIDR"], strict=True)
DEFAULT_PORTS = (
    "21,22,23,53,80,81,139,443,445,554,1883,3000,5000,"
    "6053,6444,7000,8008,8009,8080,8443,8888,9000,9100,1400"
)
DEFAULT_STATE = Path(
    os.environ.get("YGGFLARE_NETWORK_STATE_DIR", "/data/network-inventory")
)
DEFAULT_INVENTORY = Path(
    os.environ.get("YGGFLARE_STATIC_INVENTORY", "/config/static-hosts.json")
)
NMAP_SERVICES = Path("/usr/share/nmap/nmap-services")
MAX_NMAP_SERVICES_BYTES = 8 * 1024 * 1024


def top_tcp_ports(database=NMAP_SERVICES, count=100):
    """Return a coverage-preserving superset of Nmap's top TCP ports.

    Nmap ranks ports using open-frequency values from its installed services
    database. Include all ties at the cutoff, so a different tie ordering
    cannot silently exclude any of the --top-ports selection.
    """
    try:
        if database.stat().st_size > MAX_NMAP_SERVICES_BYTES:
            raise ValueError("Nmap service database exceeds size bound")
        lines = database.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise RuntimeError("Nmap services database unavailable") from error
    ratios = {}
    for line in lines:
        fields = line.split()
        if len(fields) < 3 or fields[0].startswith("#"):
            continue
        port, separator, protocol = fields[1].partition("/")
        if not separator or protocol != "tcp" or not port.isdecimal():
            continue
        number = int(port)
        if not 1 <= number <= 65535:
            continue
        try:
            ratio = float(fields[2])
        except ValueError as error:
            raise ValueError("Invalid Nmap TCP service frequency") from error
        if not 0 <= ratio <= 1:
            raise ValueError("Invalid Nmap TCP service frequency")
        ratios[number] = max(ratio, ratios.get(number, 0.0))
    if not 1 <= count <= len(ratios):
        raise ValueError("Insufficient Nmap TCP service rankings")
    cutoff = sorted(ratios.values(), reverse=True)[count - 1]
    return {port for port, ratio in ratios.items() if ratio >= cutoff}


def syn_scan_options(host_timeout="90s"):
    """Build conservative shared Nmap SYN scan options."""
    return [
        "nmap",
        "-sS",
        "-Pn",
        "-n",
        "-T3",
        "--max-retries",
        "1",
        "--host-timeout",
        host_timeout,
    ]


def progress(message):
    """Give interactive and scheduled scans unbuffered, credential-free progress."""
    print(f"[network] {message}", file=sys.stderr, flush=True)


@contextmanager
def phase(label):
    """Measure individual scan phases even when a subprocess fails."""
    started = time.monotonic()
    progress(f"START {label}")
    try:
        yield
    except BaseException:
        progress(f"FAILED {label}: {time.monotonic() - started:.1f}s")
        raise
    else:
        progress(f"END {label}: {time.monotonic() - started:.1f}s")


def run_command(args, seconds):
    """Bound subprocesses and report heartbeats while their output is captured."""
    started = time.monotonic()
    with subprocess.Popen(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    ) as process:
        while True:
            remaining = seconds - (time.monotonic() - started)
            if remaining <= 0:
                process.kill()
                process.communicate()
                raise subprocess.TimeoutExpired(args[0], seconds)
            try:
                stdout, stderr = process.communicate(timeout=min(15, remaining))
                break
            except subprocess.TimeoutExpired:
                progress(f"{args[0]} still running ({time.monotonic() - started:.0f}s)")
        if process.returncode:
            raise RuntimeError(
                f"{args[0]} failed (exit {process.returncode}): {stderr[-350:]}"
            )
        return stdout


def parse_nmap_xml(xml):
    """Read live IPv4, ARP MACs, and confirmed open TCP/UDP ports."""
    result = {}
    root = ET.fromstring(xml)
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        addresses = {
            entry.get("addrtype"): entry.get("addr")
            for entry in host.findall("address")
        }
        ip = addresses.get("ipv4")
        if not ip or ipaddress.ip_address(ip) not in NETWORK:
            continue
        services = set()
        details = {}
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is not None and state.get("state") == "open":
                key = f"{port.get('protocol')}/{int(port.get('portid'))}"
                services.add(key)
                service = port.find("service")
                if service is not None:
                    details[key] = {
                        field: service.get(field, "")[:256]
                        for field in ("name", "product", "version", "method")
                    }

        result[ip] = {
            "mac": (addresses.get("mac") or "").lower(),
            "ports": sorted(services),
            "services": details,
        }
    return result


def parse_avahi(output):
    """Deduplicate resolved DNS-SD lines across interfaces and address families."""
    found = {}
    for raw in output.splitlines():
        fields = raw.split(";")
        if len(fields) < 10 or fields[0] != "=":
            continue
        service = fields[4]
        name = fields[3]
        host = fields[6]
        port = fields[8]
        if not port.isdecimal() or not 1 <= int(port) <= 65535:
            continue
        # Keep advertised type, device and port; IPv4/IPv6 duplicate sightings collapse.
        key = (host, service, name, int(port))
        addresses = found.setdefault(key, set())
        try:
            addresses.add(str(ipaddress.ip_address(fields[7])))
        except ValueError:
            pass
    return [
        {
            **dict(zip(("host", "service", "name", "port"), entry)),
            "addresses": sorted(found[entry]),
        }
        for entry in sorted(found)
    ]


def docker_ips():
    """Filter only actually running container addresses, not the entire .21 subnet."""
    try:
        ids = run_command(["docker", "ps", "-q"], 20).split()
        if not ids:
            return set()
        containers = json.loads(run_command(["docker", "inspect", *ids], 30))
        return {
            value.get("IPAddress")
            for item in containers
            for value in (
                item.get("NetworkSettings", {}).get("Networks") or {}
            ).values()
            if isinstance(value.get("IPAddress"), str)
        }
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        # Inability to inspect Docker makes LAN attribution unsafe: never
        # generate false device alerts or overwrite the known-good state.
        raise RuntimeError(
            "Docker inspection failed; refusing network audit to protect state"
        ) from error


def load_inventory(path):
    """Validate private inventory, normalize addresses and listed TCP/UDP ports."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("version") != 1 or not isinstance(data.get("hosts"), list):
        raise ValueError("Invalid static-hosts.json schema")
    known = {}
    for entry in data["hosts"]:
        if "open_ports" in entry:
            raise ValueError("Legacy open_ports is unsupported; use ports")
        address = ipaddress.ip_address(entry["ipv4"])
        if address not in NETWORK:
            raise ValueError("Static inventory address outside LAN")
        ip = str(address)
        ports = set()
        for port in entry.get("ports", []):
            protocol = port.get("protocol")
            if protocol in {"tcp", "udp"}:
                ports.add(f"{protocol}/{port['port']}")
            elif protocol is None:
                # Legacy protocol-unspecified entries denote TCP candidates.
                ports.add(f"tcp/{port['port']}")
        canonical_mac = (entry.get("mac") or "").lower()
        observed_macs = entry.get("observed_macs", [])
        if not isinstance(observed_macs, list):
            raise TypeError(f"{entry['hostname']}: observed_macs must be a list")
        allowed_macs = {canonical_mac} if canonical_mac else set()
        for mac in observed_macs:
            if not isinstance(mac, str) or not re.fullmatch(
                r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac
            ):
                raise ValueError(f"{entry['hostname']}: invalid observed MAC")
            allowed_macs.add(mac.lower())
        known[ip] = {
            "allowed_macs": allowed_macs,
            "name": entry["hostname"],
            "mac": canonical_mac,
            "ports": ports,
        }
        for raw in entry.get("additional_ipv4", []):
            additional = ipaddress.ip_address(raw)
            if additional not in NETWORK:
                raise ValueError("Companion inventory address outside LAN")
            known[str(additional)] = known[ip]
    return known


def scan(inventory, timeout, do_dns_sd=True):
    """Discover the LAN first, then TCP scan responsive and inventory addresses."""
    with phase("IPv4 host discovery"):
        discovery = run_command(
            ["nmap", "-sn", "-PR", "-n", "-oX", "-", str(NETWORK)], timeout
        )
    hosts = parse_nmap_xml(discovery)
    # Scan live hosts only; exclude observed Docker containers but not the
    # entire .21 allocation (real appliances may have addresses there).
    with phase("Docker address exclusion"):
        ignored = docker_ips()
    targets = sorted(set(hosts) - ignored, key=ipaddress.ip_address)
    progress(f"Found {len(hosts)} IPv4 hosts; {len(targets)} targets for TCP probes")
    if targets:
        recorded_tcp = {
            int(item.split("/")[1])
            for entry in inventory.values()
            for item in entry["ports"]
            if item.startswith("tcp/")
        }
        # Preserve the *union* of the earlier focused and top-100 passes.
        # Nmap cannot combine --top-ports with -p on one invocation, so
        # derive the frequency-ranked top ports from the installed database.
        ports = sorted(
            set(map(int, DEFAULT_PORTS.split(",")))
            | recorded_tcp
            | top_tcp_ports()
        )
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as targets_file:
            targets_file.write("\n".join(targets) + "\n")
            targets_file.flush()
            args = [
                *syn_scan_options(),
                "-sV",
                "--version-light",
                "--open",
                "-p",
                ",".join(map(str, ports)),
                "-iL",
                targets_file.name,
                "-oX",
                "-",
            ]
            with phase(
                f"IPv4 combined TCP scan ({len(targets)} hosts; {len(ports)} ports)"
            ):
                checked = parse_nmap_xml(run_command(args, timeout))
        for ip in targets:
            hosts[ip]["ports"] = checked.get(ip, {}).get("ports", [])
            hosts[ip]["services"] = checked.get(ip, {}).get("services", {})
    advertised = []
    if do_dns_sd:
        try:
            with phase("DNS-SD Avahi browse"):
                advertised = parse_avahi(
                    run_command(["avahi-browse", "-a", "-r", "-p", "-t"], 90)
                )
        except (FileNotFoundError, subprocess.TimeoutExpired, RuntimeError):
            # Absence of Avahi must not imply that a service was withdrawn.
            advertised = []
    return hosts, advertised, do_dns_sd and bool(advertised)


# The event reducer intentionally combines host identity, ports, and DNS-SD.
# pylint: disable=too-many-arguments,too-many-positional-arguments
# pylint: disable=too-many-locals,too-many-branches
def calculate_events(
    inventory, hosts, advertised, previous, ignored, dns_sd_complete=True
):
    """Report new identity/ports, and suppress repeatedly reported observations."""
    prior = previous.get("reported", {})
    new_reported = {}
    events = []
    by_mac = {}
    for entry in inventory.values():
        if entry["mac"]:
            by_mac.setdefault(entry["mac"], entry)
    for ip, observed in sorted(
        hosts.items(), key=lambda item: ipaddress.ip_address(item[0])
    ):
        if ip in ignored:
            continue
        entry = inventory.get(ip)
        known_mac = by_mac.get(observed["mac"]) if observed["mac"] else None
        if entry is None:
            if known_mac:
                event = f"moved-device:{ip}:{observed['mac']}"
                message = (
                    f"CHANGED IP {known_mac['name']} now responds at {ip} "
                    f"(MAC {observed['mac']})"
                )
            else:
                event = f"unknown-device:{ip}:{observed['mac']}"
                message = f"NEW DEVICE {ip} MAC {observed['mac'] or 'unknown'}"
            new_reported[event] = message
            # A recognized MAC can identify services even after an IP change.
            entry = known_mac
        elif (
            entry["mac"]
            and observed["mac"]
            and observed["mac"] not in entry.get("allowed_macs", {entry["mac"]})
        ):
            event = f"identity:{ip}:{observed['mac']}"
            message = (
                f"CHANGED MAC {entry['name']} {ip}: {observed['mac']} "
                f"(expected {entry['mac']})"
            )
            new_reported[event] = message
        if entry:
            for service in observed["ports"]:
                if service not in entry["ports"]:
                    event = f"new-port:{ip}:{service}"
                    new_reported[event] = f"NEW PORT {entry['name']} {ip}: {service}"
    # An event is sent once until it disappears from observations and reappears.
    for key, message in new_reported.items():
        if key not in prior:
            events.append(message)
    # DNS-SD is an independent evidence channel; it does not prove a port is open.
    previous_ads = set(previous.get("advertisements", []))
    current_ads = (
        {f"{item['host']}|{item['service']}|{item['port']}" for item in advertised}
        if dns_sd_complete
        else previous_ads
    )
    if previous.get("initialized") and dns_sd_complete:
        # Keep the advertised ports for diagnostics, but compare service
        # identities without ports (which may be reassigned dynamically).
        # This also understands existing host|service|port state files.
        prior_services = {item.rsplit("|", 1)[0] for item in previous_ads}
        newly_seen = set()
        for item in sorted(current_ads):
            identity = item.rsplit("|", 1)[0]
            if identity not in prior_services and identity not in newly_seen:
                events.append(f"NEW DNS-SD {item}")
                newly_seen.add(identity)
    return events, new_reported, sorted(current_ads)


def save_state(state_dir, state):
    """Atomically publish observations outside the GitOps source checkout."""
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=state_dir, delete=False
    ) as tmp:
        json.dump(state, tmp, indent=2, sort_keys=True)
        tmp.write("\n")
        temp_name = tmp.name
    os.replace(temp_name, state_dir / "state.json")


def notify_discord(webhook, messages):
    """Post only summarized events; never include credentials."""
    if not webhook or not messages:
        return
    webhook = validate_webhook_url(webhook)
    is_test = len(messages) == 1 and messages[0].startswith("TEST ONLY")
    body = json.dumps(render(messages, test=is_test)).encode("utf-8")
    request = urllib.request.Request(
        webhook,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "DiscordBot (https://github.com/ebertek/yggflare, 1.0)",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status not in {200, 204}:
                raise RuntimeError("Discord notification rejected")
    except urllib.error.HTTPError as error:
        # Report Discord's numeric code and safe summary, never the webhook URL
        # or the unfiltered response body.
        details = []
        try:
            payload = json.loads(error.read(4096))
        except (ValueError, OSError):
            payload = {}
        if isinstance(payload, dict):
            if "webhook_id" in payload:
                details.append("invalid webhook ID")
            code = payload.get("code")
            if isinstance(code, int) and not isinstance(code, bool):
                details.append(f"Discord code {code}")
            message = payload.get("message")
            if isinstance(message, str) and re.fullmatch(
                r"[A-Za-z0-9 _.,:()'-]{1,120}", message
            ):
                details.append(message)
        suffix = f" ({'; '.join(details)})" if details else ""
        raise RuntimeError(
            f"Discord webhook rejected: HTTP {error.code}{suffix}"
        ) from None


# pylint: disable=too-many-locals
def main():
    """Run one bounded audit, or analyze pre-collected XML in offline mode."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--discovery-xml", type=Path, help="Offline test: use Nmap XML")
    parser.add_argument(
        "--dns-sd-file", type=Path, help="Offline test: resolved Avahi output"
    )
    parser.add_argument("--no-dns-sd", action="store_true")
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()

    if not 30 <= args.timeout <= 3600:
        parser.error("--timeout must be between 30 and 3600")
    inventory = load_inventory(args.inventory)
    scan_started = time.monotonic()
    if args.discovery_xml:
        hosts = parse_nmap_xml(args.discovery_xml.read_text(encoding="utf-8"))
        advertised = (
            parse_avahi(args.dns_sd_file.read_text(encoding="utf-8"))
            if args.dns_sd_file
            else []
        )
        dns_sd_complete = bool(args.dns_sd_file)
    else:
        hosts, advertised, dns_sd_complete = scan(
            inventory, args.timeout, not args.no_dns_sd
        )
    ignored = docker_ips() if not args.discovery_xml else set()
    state_file = args.state_dir / "state.json"
    previous = (
        json.loads(state_file.read_text(encoding="utf-8"))
        if state_file.exists()
        else {}
    )
    events, reported, advertisements = calculate_events(
        inventory, hosts, advertised, previous, ignored, dns_sd_complete
    )

    now = datetime.now(UTC).isoformat()
    # First run is a reviewable baseline, but will not generate Discord spam.
    bootstrap = not previous.get("initialized")
    prior_seen = {
        **{ip: previous.get("scanned_at", "") for ip in previous.get("hosts", {})},
        **previous.get("last_seen", {}),
    }
    try:
        if args.discovery_xml:
            supplemental = {}
        else:
            with phase("Supplemental ARP/NDP/OS/service discovery"):
                supplemental = collect_links(
                    NETWORK,
                    seeds=[(ip, "Nmap discovery") for ip in hosts if ip not in ignored]
                    + [
                        (ip, "DNS-SD address")
                        for service in advertised
                        for ip in service.get("addresses", [])
                    ],
                )
    except (OSError, ValueError, TypeError):
        supplemental = {
            "records": [],
            "warnings": ["Supplemental discovery configuration is invalid"],
        }
    snapshot = {
        "supplemental": supplemental,
        "version": 1,
        "initialized": True,
        "scanned_at": now,
        "scan_duration_seconds": round(time.monotonic() - scan_started, 3),
        "reported": reported,
        "advertisements": advertisements,
        "hosts": hosts,
        "discovered_hosts": len(hosts),
        "first_seen": {
            ip: previous.get("first_seen", {}).get(
                ip,
                (
                    previous.get("scanned_at") or now
                    if ip in previous.get("hosts", {})
                    else now
                ),
            )
            for ip in set(previous.get("first_seen", {})) | set(hosts)
            if ipaddress.ip_address(ip) in NETWORK
        },
        "last_seen": {
            **{
                ip: stamp
                for ip, stamp in prior_seen.items()
                if ipaddress.ip_address(ip) in NETWORK
            },
            **{ip: now for ip in hosts},
        },
        "dns_sd_complete": dns_sd_complete,
        "dns_sd_scanned_at": (
            now if dns_sd_complete else previous.get("dns_sd_scanned_at", "")
        ),
        "advertisement_details": (
            advertised if dns_sd_complete else previous.get("advertisement_details", [])
        ),
        "latest_events": events,
        "baseline": bootstrap,
        "recent_events": (
            previous.get("recent_events", [])
            + [
                {"observed_at": now, "message": event, "baseline": bootstrap}
                for event in events
            ]
        )[-200:],
    }
    # Observations must be committed even when a remote notification fails.
    # Save pending alerts with the scan so a subsequent run can retry them
    # without generating duplicate discovery events.
    prior_pending = previous.get("pending_discord_events", [])
    if not isinstance(prior_pending, list) or any(
        not isinstance(event, str) for event in prior_pending
    ):
        raise ValueError("Invalid pending Discord notification state")
    snapshot["pending_discord_events"] = (
        list(dict.fromkeys([*prior_pending, *events]))[-200:] if not bootstrap else []
    )
    save_state(args.state_dir, snapshot)
    progress("Saved network observations before notification delivery")
    print(
        f"Network inventory: {len(hosts)} responsive IPv4 hosts; {len(advertised)} DNS-SD services"
    )
    for event in events:
        print("  ! " + event)
    if bootstrap:
        print("First observation saved; suppressing initial Discord notification.")
    if snapshot["pending_discord_events"]:
        try:
            webhook_file = os.environ.get("YGGFLARE_NETWORK_DISCORD_WEBHOOK_FILE")
            webhook = (
                Path(webhook_file).read_text(encoding="utf-8").strip()
                if webhook_file and Path(webhook_file).is_file()
                else ""
            )
            if webhook:
                notify_discord(webhook, snapshot["pending_discord_events"])
                snapshot["pending_discord_events"] = []
                save_state(args.state_dir, snapshot)
        except (RuntimeError, ValueError) as error:
            print(f"WARNING: Discord delivery deferred: {error}", file=sys.stderr)
        except (OSError, urllib.error.URLError):
            print(
                "WARNING: Discord delivery deferred: transport or secret error",
                file=sys.stderr,
            )
    print(f"New observations: {len(events)}; inventory and Cloudflare unchanged.")


if __name__ == "__main__":
    try:
        main()
    except (
        OSError,
        ValueError,
        RuntimeError,
        ET.ParseError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
