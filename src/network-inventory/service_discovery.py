"""Optional, bounded service and passive discovery; no authoritative writes."""

import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from discovery_passive import lldp_records, sample_p0f
from discovery_ssdp import ssdp

LIMIT = 1024 * 1024
NETBIOS_TIMEOUT_SECONDS = 3
NETBIOS_WORKERS = 8
SMB_TARGET_LIMIT = 16


def enabled(name):
    value = os.environ.get("YGGFLARE_DISCOVERY_" + name, "false")
    if value not in ("true", "false"):
        raise ValueError("Discovery switches must be true or false")
    return value == "true"


def execute(
    args,
    env=None,
    *,
    allow_no_reply=False,
    timeout_seconds=10,
    timeout_is_no_reply=False,
):
    """Bound local command work; NetBIOS silence is an ordinary lack of evidence."""
    with tempfile.TemporaryFile() as output:
        with subprocess.Popen(
            args, stdout=output, stderr=subprocess.DEVNULL, env=env
        ) as process:
            deadline = time.monotonic() + timeout_seconds
            while process.poll() is None:
                timed_out = time.monotonic() >= deadline
                exceeded_output = output.tell() > LIMIT
                if timed_out or exceeded_output:
                    process.kill()
                    process.wait()
                    if timed_out and not exceeded_output and timeout_is_no_reply:
                        return ""
                    raise ValueError("Collector exceeded bounds")
                time.sleep(0.05)
            if output.tell() > LIMIT or (
                process.returncode and not (allow_no_reply and process.returncode == 1)
            ):
                raise ValueError("Collector failed")
        output.seek(0)
        return output.read(LIMIT).decode("utf-8", errors="replace")


def collect(interfaces, allowed, records, add, warnings):
    """Each optional failure is isolated and reported without raw exceptions."""
    flags = {
        name: enabled(name)
        for name in ("SSDP", "LLDP", "NETBIOS", "SMB", "SNMP", "P0F")
    }
    targets = sorted(
        {
            r["ip"]
            for r in records
            if r["ip"]
            and ipaddress.ip_address(r["ip"]).version == 4
            and allowed(ipaddress.ip_address(r["ip"]))
        },
        key=ipaddress.ip_address,
    )
    # Keep anonymous SMB attempts separately bounded; NetBIOS node-status
    # probes are light and should not omit hosts after the first 16.
    smb_targets = targets[:SMB_TARGET_LIMIT]

    def attempt(source, operation):
        try:
            operation()
        except (
            OSError,
            ValueError,
            TypeError,
            ET.ParseError,
            subprocess.SubprocessError,
        ):
            warnings.append(source + ": unavailable, failed or timed out")

    for interface in interfaces:
        if flags["SSDP"]:
            attempt(
                "SSDP",
                lambda: [
                    add(ip, interface, "SSDP advertisement", detail)
                    for ip, detail in ssdp(interface, allowed)
                ],
            )
        if flags["P0F"]:
            attempt(
                "p0f",
                lambda: [
                    add(ip, interface, "p0f OS estimate", detail)
                    for ip, detail in sample_p0f(interface, allowed)
                ],
            )
    if flags["LLDP"]:

        def lldp():
            # Read an existing daemon's socket; never change its advertisements.
            raw = execute(
                [
                    "lldpcli",
                    "-u",
                    "/run/lldpd/lldpd.socket",
                    "-f",
                    "xml",
                    "show",
                    "neighbors",
                    "details",
                ]
            )
            for ip, interface, source, detail in lldp_records(raw, interfaces):
                records.append(
                    {
                        "ip": ip,
                        "interface": interface,
                        "source": source,
                        "detail": detail[:512],
                    }
                )

        attempt("LLDP/CDP", lldp)
    netbios_enabled = flags["NETBIOS"] and bool(targets)
    if netbios_enabled and shutil.which("nmblookup") is None:
        warnings.append("NetBIOS: nmblookup executable unavailable")
    elif netbios_enabled:
        print(
            f"[discovery] START NetBIOS: {len(targets)} targets, "
            f"{min(NETBIOS_WORKERS, len(targets))} workers",
            file=sys.stderr,
            flush=True,
        )

        def netbios(ip):
            try:
                # An unanswered NetBIOS query is normal for non-NetBIOS devices.
                raw = execute(
                    ["nmblookup", "-A", ip],
                    allow_no_reply=True,
                    timeout_seconds=NETBIOS_TIMEOUT_SECONDS,
                    timeout_is_no_reply=True,
                )
                names = re.findall(r"^\s*([^\s<>]+)\s+<[0-9A-Fa-f]{2}>", raw, re.M)
                return ip, sorted(set(names)), False
            except (OSError, ValueError, subprocess.SubprocessError):
                return ip, [], True

        with ThreadPoolExecutor(max_workers=NETBIOS_WORKERS) as executor:
            for index, (ip, names, failed) in enumerate(
                executor.map(netbios, targets), start=1
            ):
                if failed:
                    warnings.append("NetBIOS: unavailable, failed or timed out")
                elif names:
                    add(ip, "", "NetBIOS name", ", ".join(names))
                if index % 4 == 0 or index == len(targets):
                    print(
                        f"[discovery] NetBIOS completed: {index}/{len(targets)}",
                        file=sys.stderr,
                        flush=True,
                    )
    for ip in smb_targets:
        if flags["SMB"]:

            def smb():
                raw = execute(["smbclient", "-N", "-g", "-L", ip, "-t", "3"])
                shares = [
                    line.split("|")[1]
                    for line in raw.splitlines()
                    if line.startswith(("Disk|", "Printer|"))
                    and len(line.split("|")) >= 2
                ]
                if shares:
                    add(ip, "", "SMB anonymous share listing", ", ".join(shares))

            attempt("SMB", smb)
    if flags["SNMP"]:

        def snmp():
            # Explicit targets and credentials only; never try public/private.
            targets = os.environ.get("YGGFLARE_DISCOVERY_SNMP_TARGETS", "").split(",")
            if not 1 <= len(targets) <= 16:
                raise ValueError("Invalid SNMP target count")
            addresses = [ipaddress.ip_address(v.strip()) for v in targets]
            if any(a.version != 4 or not allowed(a) for a in addresses):
                raise ValueError("SNMP target outside scope")
            path = Path("/run/secrets/yggflare_snmp")
            if path.stat().st_size > 8192:
                raise ValueError("Invalid SNMP secret")
            secret = json.loads(path.read_text())
            version = secret.get("version")
            if version == "2c":
                values = {"defCommunity": secret.get("community", "")}
            elif version == "3":
                values = {
                    "defSecurityName": secret.get("username", ""),
                    "defAuthPassphrase": secret.get("auth_passphrase", ""),
                    "defPrivPassphrase": secret.get("priv_passphrase", ""),
                }
            else:
                raise ValueError("Explicit SNMP version required")
            if any(
                not isinstance(v, str)
                or not re.fullmatch(r"[A-Za-z0-9_.@!%-]{1,128}", v)
                for v in values.values()
            ):
                raise ValueError("Invalid SNMP credential")
            settings = "defVersion " + version + "\n"
            if version == "3":
                settings += (
                    "defSecurityLevel authPriv\ndefAuthType SHA\ndefPrivType AES\n"
                )
            settings += "".join(k + " " + v + "\n" for k, v in values.items())
            with tempfile.TemporaryDirectory(prefix="yggflare-snmp-") as folder:
                config = Path(folder) / "snmp.conf"
                config.write_text(settings)
                config.chmod(0o600)
                env = {**os.environ, "SNMPCONFPATH": folder, "MIBS": ""}
                for address in addresses:
                    raw = execute(
                        [
                            "snmpget",
                            "-t",
                            "1",
                            "-r",
                            "0",
                            "-On",
                            str(address),
                            ".1.3.6.1.2.1.1.1.0",
                            ".1.3.6.1.2.1.1.5.0",
                        ],
                        env,
                    )
                    for value in values.values():
                        raw = raw.replace(value, "[redacted]")
                    add(str(address), "", "SNMP system identity", raw)

        attempt("SNMP", snmp)
