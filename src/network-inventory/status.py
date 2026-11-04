"""Read-only status report from the last saved network inventory scan."""

import argparse
import json
import re
import sys
from pathlib import Path

STATE = Path("/data/network-inventory/state.json")
MAX_STATE_BYTES = 8 * 1024 * 1024
MAX_PRINT_ITEMS = 100


def object_field(value, name):
    """Reject corrupt state rather than treating it as an empty observation."""
    if not isinstance(value, dict):
        raise ValueError(f"Invalid {name} in saved network state")
    return value


def list_field(value, name):
    if not isinstance(value, list):
        raise ValueError(f"Invalid {name} in saved network state")
    return value


def read_status(path=STATE):
    """Summarize saved evidence; no scans, sockets or mutation."""
    try:
        if path.stat().st_size > MAX_STATE_BYTES:
            raise ValueError("Saved network state exceeds 8 MiB")
        state = object_field(
            json.loads(path.read_text(encoding="utf-8")),
            "network state",
        )
    except FileNotFoundError as error:
        raise ValueError("No saved network scan; run 'yggflare network run'") from error
    except json.JSONDecodeError as error:
        raise ValueError("Saved network state is invalid JSON") from error

    if not state.get("initialized"):
        raise ValueError("No completed network scan saved yet")
    hosts = object_field(state.get("hosts", {}), "hosts")
    services = list_field(state.get("advertisements", []), "advertisements")
    supplemental = object_field(state.get("supplemental", {}), "supplemental")
    observations = list_field(supplemental.get("records", []), "supplemental records")
    warnings = list_field(supplemental.get("warnings", []), "supplemental warnings")
    history = object_field(state.get("identity_history", {}), "identity history")
    conflicts = list_field(state.get("identity_conflicts", []), "identity conflicts")
    pending = list_field(
        state.get("alert_pending_confirmations", []), "pending confirmations"
    )
    deliveries = list_field(
        state.get("pending_discord_events", []), "pending Discord deliveries"
    )

    if any(not isinstance(item, str) for item in pending):
        raise ValueError("Invalid pending confirmation entry")
    if any(not isinstance(item, dict) for item in conflicts):
        raise ValueError("Invalid identity conflict entry")
    if any(not isinstance(entry, dict) for entry in history.values()):
        raise ValueError("Invalid identity history entry")

    observed = [
        entry for entry in history.values() if entry.get("status") == "observed"
    ]
    return {
        "scanned_at": str(state.get("scanned_at", "")),
        "ipv4_hosts": len(hosts),
        "dns_sd_services": len(services),
        "supplemental_observations": len(observations),
        "supplemental_warnings": len(warnings),
        "tracked_identities": len(history),
        "currently_observed_identities": len(observed),
        "high_confidence_identities": sum(
            entry.get("confidence") == "high" for entry in observed
        ),
        "identity_conflicts": len(conflicts),
        "pending_confirmations": pending,
        "pending_discord_deliveries": len(deliveries),
        "conflict_details": [
            {
                "address": item.get("address", ""),
                "macs": item.get("macs", []),
                "reasons": item.get("reasons", []),
            }
            for item in conflicts
        ],
    }


def safe_line(value):
    """Keep untrusted discovery strings from injecting terminal control codes."""
    line = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(value))
    return line[:300] + ("…" if len(line) > 300 else "")


def render_text(status, *, details=False):
    """Show useful summary and all current confirmation candidates."""
    lines = [
        "Yggflare network status (saved observations; no scan performed)",
        f"Last scan: {safe_line(status['scanned_at'])}",
        f"IPv4 hosts: {status['ipv4_hosts']} | DNS-SD services: {status['dns_sd_services']}",
        (
            f"Supplemental observations: {status['supplemental_observations']} "
            f"| Warnings: {status['supplemental_warnings']}"
        ),
        (
            f"Device identities: {status['tracked_identities']} tracked, "
            f"{status['currently_observed_identities']} observed, "
            f"{status['high_confidence_identities']} high confidence"
        ),
        (
            f"Identity conflicts: {status['identity_conflicts']} "
            f"| Discord deliveries queued: {status['pending_discord_deliveries']}"
        ),
        "",
        f"Pending confirmations: {len(status['pending_confirmations'])}",
    ]
    for item in status["pending_confirmations"][:MAX_PRINT_ITEMS]:
        lines.append("  - " + safe_line(item))
    if len(status["pending_confirmations"]) > MAX_PRINT_ITEMS:
        lines.append("  (additional candidates omitted; use --json for all)")
    if details:
        lines.extend(["", f"Identity conflicts: {status['identity_conflicts']}"])
        for item in status["conflict_details"][:MAX_PRINT_ITEMS]:
            lines.append("  - " + safe_line(item["address"]))
            macs = item["macs"]
            reasons = item["reasons"]
            if isinstance(macs, list):
                lines.append("    MAC claims: " + safe_line(", ".join(map(str, macs))))
            if isinstance(reasons, list):
                for reason in reasons:
                    lines.append("    Reason: " + safe_line(reason))
        if len(status["conflict_details"]) > MAX_PRINT_ITEMS:
            lines.append("  (additional conflicts omitted; use --json for all)")
    return "\n".join(lines)


def main(argv=None, *, path=STATE):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--details",
        action="store_true",
        help="Include unresolved identity conflict evidence",
    )
    parser.add_argument(
        "--json", action="store_true", help="Output structured saved-state summary"
    )
    args = parser.parse_args(argv)
    if args.details and args.json:
        parser.error("--details and --json cannot be combined")
    try:
        report = read_status(path)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_text(report, details=args.details))
    return 0


if __name__ == "__main__":
    sys.exit(main())
