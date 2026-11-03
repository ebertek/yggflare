"""Allowlisted LLDP/CDP and bounded p0f observations."""

import ipaddress
import subprocess
import tempfile
import time
from pathlib import Path

LIMIT = 1024 * 1024


def lldp_records(raw, interfaces):
    """Project lldpcli XML; preserve link neighbours even without IP addresses."""
    import xml.etree.ElementTree as ET

    records = []
    root = ET.fromstring(raw)
    for interface in root.findall(".//interface"):
        name = interface.get("name", "")
        if name not in interfaces:
            continue
        chassis = interface.find("chassis")
        if chassis is None:
            continue
        values = []
        for key in ("id", "name", "descr"):
            value = chassis.findtext(key)
            if value:
                values.append(f"{key}: {value[:160]}")
        port = interface.find("port")
        if port is not None and port.findtext("id"):
            values.append("port: " + port.findtext("id")[:160])
        records.append(("", name, interface.get("via", "LLDP/CDP"), "; ".join(values)))
    return records


def p0f_records(raw, allowed):
    """Only address and OS estimate leave the temporary p0f log."""
    records = []
    for line in raw.splitlines():
        fields = dict(
            part.strip().split("=", 1) for part in line.split("|") if "=" in part
        )
        subject = fields.get("subj")
        if subject not in ("cli", "srv") or not fields.get("os"):
            continue
        address = fields.get(subject, "").rsplit("/", 1)[0]
        try:
            address = ipaddress.ip_address(address)
        except ValueError:
            continue
        if allowed(address):
            records.append((str(address), fields["os"][:256]))
    return sorted(set(records))


def sample_p0f(interface, allowed):
    """Observe traffic visible to this host for ten seconds; no packet archive."""
    with tempfile.TemporaryDirectory(prefix="yggflare-p0f-") as folder:
        log = Path(folder) / "observations.log"
        with subprocess.Popen(
            ["p0f", "-i", interface, "-o", str(log), "tcp"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ) as process:
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline and process.poll() is None:
                    if log.exists() and log.stat().st_size > LIMIT:
                        raise ValueError("p0f output exceeded bounds")
                    time.sleep(0.1)
                if process.poll() is not None:
                    raise ValueError("p0f exited early")
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
        if log.stat().st_size > LIMIT:
            raise ValueError("p0f output exceeded bounds")
        return p0f_records(log.read_text(), allowed)
