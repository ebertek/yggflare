"""Propose reviewed open-port inventory updates without editing the source.

This tool accepts a private static-hosts.json and emits a distinct JSON file
for diff review. It never creates DNS records or changes a deployed checkout.
"""

import argparse
import json
from pathlib import Path

DISCOVERED = {
    "aircon-sunroom.ygg.nu": [(6444, "Midea LAN control (observed)")],
    "alexa-bathroom.ygg.nu": [(5541, "Unidentified local TCP service (observed)")],
    "doorbell.ygg.nu": [(8554, "RTSP endpoint (observed)")],
    "sub.ygg.nu": [(1400, "Sonos HTTP control (observed)")],
    "fire-tv.ygg.nu": [(8009, "Local TCP service; protocol unverified (observed)")],
}
# iOS ephemeral ports deliberately excluded; investigate their service lifecycle
# before accepting them as a stable expectation.


def propose(document):
    """Return an independent inventory with missing confirmed TCP ports added."""
    if not isinstance(document, dict) or not isinstance(document.get("hosts"), list):
        raise TypeError("Expected private static-hosts.json with a hosts array")
    result = json.loads(json.dumps(document))
    changed = []
    names = set()
    for host in result["hosts"]:
        hostname = host["hostname"]
        names.add(hostname)
        proposals = DISCOVERED.get(hostname, [])
        if not proposals:
            continue
        if "ports" in host and "open_ports" in host:
            raise ValueError(f"{hostname}: conflicting port formats")
        if "open_ports" in host:
            existing = set(host["open_ports"])
            for number, _ in proposals:
                if number not in existing:
                    host["open_ports"].append(number)
                    existing.add(number)
                    changed.append(f"{hostname}: tcp/{number} (legacy format)")
        else:
            ports = host.setdefault("ports", [])
            existing = {(item.get("protocol", "tcp"), item["port"]) for item in ports}
            for number, description in proposals:
                if ("tcp", number) not in existing:
                    ports.append(
                        {"port": number, "protocol": "tcp", "description": description}
                    )
                    existing.add(("tcp", number))
                    changed.append(f"{hostname}: tcp/{number}")
    absent = sorted(set(DISCOVERED) - names)
    return result, changed, absent


def main():
    """Save a separate review file, rejecting accidental in-place changes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.inventory.resolve() == args.output.resolve():
        parser.error("--output must be a different file from the input")
    proposed, changed, absent = propose(
        json.loads(args.inventory.read_text(encoding="utf-8"))
    )
    if args.output.exists():
        parser.error("Refusing to overwrite existing proposal")
    args.output.write_text(
        json.dumps(proposed, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    for item in changed:
        print("PROPOSE: " + item)
    for name in absent:
        print("NOT IN INVENTORY: " + name)
    print(f"Proposed {len(changed)} additions; source unchanged.")


if __name__ == "__main__":
    main()
