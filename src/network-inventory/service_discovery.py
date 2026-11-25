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


def collector_evidence(configured):
    return {
        "configured": configured,
        "attempted": 0,
        "completed": 0,
        "failed": 0,
        "no_reply": 0,
        "parse_errors": 0,
        "limited": False,
    }


def smb_outcome(returncode, output):
    """Classify explicit Samba outcomes; never export raw diagnostics."""
    if returncode == 0:
        return "success"
    text = output.upper()
    if any(code in text for code in (
        "NT_STATUS_ACCESS_DENIED", "NT_STATUS_LOGON_FAILURE",
        "NT_STATUS_ACCOUNT_RESTRICTION", "NT_STATUS_ACCOUNT_DISABLED",
    )):
        return "access_denied"
    if "NT_STATUS_CONNECTION_REFUSED" in text or "CONNECTION REFUSED" in text:
        return "connection_refused"
    if "NT_STATUS_IO_TIMEOUT" in text or "NT_STATUS_CONNECTION_TIMEOUT" in text:
        return "remote_timeout"
    return "execution_failed"


def smb_listing(ip, port, timeout_seconds=10):
    """Bound both output streams and use only anonymous enumeration."""
    args = ["smbclient", "-N", "-U", "%", "-g", "-L", ip, "-t", "3", "-p", str(port)]
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        with subprocess.Popen(
            args, stdout=out, stderr=err, env={**os.environ, "LC_ALL": "C"}
        ) as process:
            deadline = time.monotonic() + timeout_seconds
            while process.poll() is None:
                if out.tell() + err.tell() > LIMIT:
                    process.kill()
                    process.wait()
                    return "execution_failed", []
                if time.monotonic() >= deadline:
                    process.kill()
                    process.wait()
                    return "execution_timeout", []
                time.sleep(0.05)
            if out.tell() + err.tell() > LIMIT:
                return "execution_failed", []
            out.seek(0)
            err.seek(0)
            raw = out.read(LIMIT).decode("utf-8", errors="replace")
            diagnostic = err.read(LIMIT).decode("utf-8", errors="replace")
            outcome = smb_outcome(process.returncode, raw + "\n" + diagnostic)
            if outcome != "success":
                return outcome, []
            shares = [
                line.split("|")[1]
                for line in raw.splitlines()
                if line.startswith(("Disk|", "Printer|")) and len(line.split("|")) >= 2
            ]
            return ("success_with_shares" if shares else "success_empty"), shares


def collect(interfaces, allowed, records, add, warnings, observed_ports=None):
    """Each optional failure is isolated and reported without raw exceptions."""
    flags = {
        name: enabled(name)
        for name in ("SSDP", "LLDP", "NETBIOS", "SMB", "SNMP", "P0F")
    }
    evidence = {
        name.lower(): collector_evidence(value) for name, value in flags.items()
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
    # Only already observed open SMB ports justify anonymous enumeration.
    smb_ports = {ip: set() for ip in targets}
    for ip, ports in (observed_ports or {}).items():
        if ip in smb_ports:
            smb_ports[ip].update(set(ports) & {"tcp/445", "tcp/139"})
    for record in records:
        ip = record.get("ip")
        if ip in smb_ports and record.get("source") == "Nmap IPv4":
            port = str(record.get("detail", "")).split(" ", 1)[0]
            if port in {"tcp/445", "tcp/139"}:
                smb_ports[ip].add(port)
    smb_candidates = [ip for ip in targets if smb_ports[ip]]
    smb_targets = sorted(
        smb_candidates, key=lambda ip: ("tcp/445" not in smb_ports[ip], ipaddress.ip_address(ip))
    )[:SMB_TARGET_LIMIT]
    if flags["SMB"]:
        evidence["smb"].update(
            eligible_targets=len(smb_candidates),
            selected_targets=len(smb_targets),
            skipped_no_port_evidence=len(targets) - len(smb_candidates),
            skipped_target_limit=len(smb_candidates) - len(smb_targets),
            limited=len(smb_candidates) > SMB_TARGET_LIMIT,
            success_with_shares=0, success_empty=0, access_denied=0,
            connection_refused=0, remote_timeout=0, execution_timeout=0,
            execution_failed=0,
        )
    evidence["netbios"]["eligible_targets"] = len(targets) if flags["NETBIOS"] else 0

    def attempt(source, operation):
        key = "lldp" if source == "LLDP/CDP" else source.lower()
        row = evidence[key]
        row["attempted"] += 1
        try:
            operation()
            row["completed"] += 1
        except (
            OSError,
            ValueError,
            TypeError,
            ET.ParseError,
            subprocess.SubprocessError,
        ):
            row["failed"] += 1
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
        evidence["netbios"]["unavailable"] = True
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
                row = evidence["netbios"]
                row["attempted"] += 1
                if failed:
                    row["failed"] += 1
                    warnings.append("NetBIOS: unavailable, failed or timed out")
                else:
                    row["completed"] += 1
                    if names:
                        add(ip, "", "NetBIOS name", ", ".join(names))
                    else:
                        row["no_reply"] += 1
                if index % 4 == 0 or index == len(targets):
                    print(
                        f"[discovery] NetBIOS completed: {index}/{len(targets)}",
                        file=sys.stderr,
                        flush=True,
                    )
    if flags["SMB"] and shutil.which("smbclient") is None:
        evidence["smb"]["unavailable"] = True
        warnings.append("SMB: smbclient executable unavailable")
    elif flags["SMB"]:
        row = evidence["smb"]
        for ip in smb_targets:
            row["attempted"] += 1
            port = 445 if "tcp/445" in smb_ports[ip] else 139
            try:
                outcome, shares = smb_listing(ip, port)
            except (OSError, ValueError, TypeError, subprocess.SubprocessError):
                outcome, shares = "execution_failed", []
            row[outcome] += 1
            if outcome in {"execution_failed", "execution_timeout"}:
                row["failed"] += 1
                warnings.append("SMB: collector execution failed or exceeded bounds")
            else:
                row["completed"] += 1
                if outcome == "remote_timeout":
                    row["no_reply"] += 1
                if outcome == "success_with_shares":
                    add(ip, "", "SMB anonymous share listing", ", ".join(shares))
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
    return evidence
