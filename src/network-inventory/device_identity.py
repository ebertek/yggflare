"""Vendor-neutral, evidence-backed identity and bounded observation history.

Identity association is deliberately conservative. An address or mDNS hostname
does not establish device identity; conflicting MAC claims are left unmerged.
These records are informational and never authorize DNS or Cloudflare writes.
"""

import ipaddress
import re
from collections import defaultdict

MAC_PATTERN = re.compile(
    r"(?i)(?<![0-9a-f:])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f:])"
)
LINK_SOURCES = {"ARP reply", "NDP reply", "Neighbor cache"}
DIRECT_SOURCES = {"ARP reply", "NDP reply", "Nmap IPv4 host"}
MAX_IDENTITIES = 2048
MAX_CHANGES = 200
MAX_ADDRESSES = 24


def valid_ip(value):
    """Return a canonical IP address, or an empty string for bad evidence."""
    try:
        return str(ipaddress.ip_address(value))
    except (TypeError, ValueError):
        return ""


def valid_mac(value):
    """Extract only a correctly shaped MAC, never a hostname/OS guess."""
    if not isinstance(value, str):
        return ""
    match = MAC_PATTERN.search(value)
    return match.group(0).lower() if match else ""


def address_key(value):
    return (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value)))


def known_inventory(inventory):
    """Resolve declared names and allowed MACs without assuming uniqueness."""
    by_mac = defaultdict(set)
    for entry in inventory.values():
        for mac in entry.get("allowed_macs", set()):
            if valid_mac(mac) == mac and entry.get("name"):
                by_mac[mac].add(entry["name"])
    return by_mac


def observed_addresses(hosts, supplemental, advertised, ignored):
    """Collect address evidence; retain sources without inventing ownership."""
    observed = defaultdict(lambda: {"macs": set(), "sources": set(), "hints": set()})
    for ip, host in hosts.items():
        ip = valid_ip(ip)
        if not ip or ip in ignored:
            continue
        observed[ip]["sources"].add("Nmap IPv4 host")
        mac = valid_mac(host.get("mac", ""))
        if mac:
            observed[ip]["macs"].add(mac)
    for record in supplemental.get("records", []):
        if not isinstance(record, dict):
            continue
        ip = valid_ip(record.get("ip"))
        if not ip or ip in ignored:
            continue
        source = record.get("source", "")
        if not isinstance(source, str) or not source:
            continue
        # Unverified routing candidates and Docker addresses alone are not
        # evidence of a responsive device.
        if source in ("Docker address", "Candidate address"):
            continue
        observed[ip]["sources"].add(source[:80])
        if source in LINK_SOURCES:
            mac = valid_mac(record.get("detail", ""))
            if mac:
                observed[ip]["macs"].add(mac)
    for advert in advertised:
        if not isinstance(advert, dict):
            continue
        hint = advert.get("host", "")
        if not isinstance(hint, str) or not hint or len(hint) > 200:
            continue
        for raw in advert.get("addresses", []):
            ip = valid_ip(raw)
            if ip and ip in observed:
                observed[ip]["hints"].add(hint)
                observed[ip]["sources"].add("DNS-SD hint")
    return observed


def resolve(inventory, observed):
    """Build distinct identities, conflicts and source-derived confidence."""
    inventory_macs = known_inventory(inventory)
    shared = defaultdict(set)
    for ip, evidence in observed.items():
        if ipaddress.ip_address(ip).version == 4:
            for mac in evidence["macs"]:
                shared[mac].add(ip)
    identities = {}
    conflicts = []
    for ip, evidence in sorted(observed.items(), key=lambda item: address_key(item[0])):
        macs = evidence["macs"]
        declared = inventory.get(ip) if ipaddress.ip_address(ip).version == 4 else None
        matched = set()
        for mac in macs:
            matched.update(inventory_macs.get(mac, set()))
        problems = []
        if len(macs) > 1:
            problems.append("Multiple MAC claims for this address")
        if len(matched) > 1:
            problems.append("MAC is claimed by multiple inventory identities")
        if declared and macs and not macs.issubset(declared.get("allowed_macs", set())):
            problems.append("Observed MAC differs from declared identity")
        if declared and matched and declared["name"] not in matched:
            problems.append("Address and MAC point to different declared identities")
        if problems:
            conflicts.append(
                {
                    "address": ip,
                    "macs": sorted(macs),
                    "reasons": problems,
                }
            )
            continue
        mac = next(iter(macs)) if len(macs) == 1 else ""
        name = declared["name"] if declared else next(iter(matched)) if matched else ""
        ambiguous_shared = bool(mac and len(shared[mac]) > 1 and not name)
        if name:
            identity_id = "inventory:" + name
            label = name
        elif mac and not ambiguous_shared:
            identity_id = "mac:" + mac
            label = "Observed MAC " + mac
        else:
            identity_id = "address:" + ip
            label = "Unassigned address " + ip
        direct = bool(evidence["sources"] & DIRECT_SOURCES)
        if name and mac and direct:
            confidence = "high"
        elif name and mac or mac and direct and not ambiguous_shared:
            confidence = "medium"
        else:
            confidence = "low"
        if ambiguous_shared:
            note = "Shared MAC on multiple IPv4 addresses; kept separate"
        elif not mac:
            note = "IP-only association is provisional"
        elif not name:
            note = "MAC observed, not verified against inventory"
        else:
            note = "Correlated with declared inventory"
        identity = identities.setdefault(
            identity_id,
            {
                "label": label,
                "confidence": confidence,
                "addresses": set(),
                "macs": set(),
                "sources": set(),
                "name_hints": set(),
                "note": note,
            },
        )
        identity["addresses"].add(ip)
        identity["macs"].update(macs)
        identity["sources"].update(evidence["sources"])
        identity["name_hints"].update(evidence["hints"])
        if identity["confidence"] != "high" and confidence == "high":
            identity["confidence"] = "high"
        elif identity["confidence"] == "low" and confidence == "medium":
            identity["confidence"] = "medium"
    for item in identities.values():
        item["addresses"] = sorted(item["addresses"], key=address_key)[:MAX_ADDRESSES]
        item["macs"] = sorted(item["macs"])[:8]
        item["sources"] = sorted(item["sources"])[:16]
        item["name_hints"] = sorted(item["name_hints"])[:8]
    return identities, conflicts


def update_history(inventory, hosts, supplemental, advertised, previous, now, ignored):
    """Carry forward bounded identity histories across successful scans.

    'Not observed' is not offline. Only a persistent MAC or inventory key
    supplies continuity across an IP change; IP-only identifiers are tentative.
    """
    seen = observed_addresses(hosts, supplemental, advertised, ignored)
    current, conflicts = resolve(inventory, seen)
    prior = previous.get("identity_history", {})
    if not isinstance(prior, dict):
        prior = {}
    history = {}
    changes = list(previous.get("identity_changes", []))[-MAX_CHANGES:]
    old_conflicts = {
        item.get("address")
        for item in previous.get("identity_conflicts", [])
        if isinstance(item, dict)
    }
    for identity_id, evidence in current.items():
        old = prior.get(identity_id, {})
        if not isinstance(old, dict):
            old = {}
        old_addresses = [ip for ip in old.get("addresses", []) if valid_ip(ip) == ip][
            :MAX_ADDRESSES
        ]
        addresses = sorted(
            set(old_addresses) | set(evidence["addresses"]), key=address_key
        )[:MAX_ADDRESSES]
        if identity_id not in prior:
            changes.append(
                {
                    "observed_at": now,
                    "identity": identity_id,
                    "kind": "first-observed",
                    "description": evidence["label"] + " first observed",
                }
            )
        else:
            new_addresses = set(evidence["addresses"]) - set(old_addresses)
            for ip in sorted(new_addresses, key=address_key):
                changes.append(
                    {
                        "observed_at": now,
                        "identity": identity_id,
                        "kind": "new-address",
                        "description": evidence["label"] + " also observed at " + ip,
                    }
                )
        history[identity_id] = {
            **evidence,
            "addresses": addresses,
            "current_addresses": evidence["addresses"],
            "first_seen": old.get("first_seen") or now,
            "last_seen": now,
            "seen_scans": min(int(old.get("seen_scans", 0)) + 1, 1_000_000),
            "missed_scans": 0,
            "status": "observed",
        }
    for identity_id, old in prior.items():
        if identity_id in history or not isinstance(old, dict):
            continue
        missed = min(max(0, int(old.get("missed_scans", 0))) + 1, 1_000_000)
        was_present = old.get("status") == "observed"
        if was_present and missed == 1:
            changes.append(
                {
                    "observed_at": now,
                    "identity": identity_id,
                    "kind": "not-observed",
                    "description": str(old.get("label", identity_id))
                    + " not observed in this scan",
                }
            )
        history[identity_id] = {**old, "missed_scans": missed, "status": "not observed"}
    for conflict in conflicts:
        if conflict["address"] not in old_conflicts:
            changes.append(
                {
                    "observed_at": now,
                    "identity": "conflict:" + conflict["address"],
                    "kind": "conflict",
                    "description": conflict["address"]
                    + ": "
                    + "; ".join(conflict["reasons"]),
                }
            )
    # Never discard entries seen this scan; cap retained stale entries by age.
    if len(history) > MAX_IDENTITIES:
        active = {key: val for key, val in history.items() if key in current}
        stale = sorted(
            ((key, val) for key, val in history.items() if key not in current),
            key=lambda item: item[1].get("last_seen", ""),
            reverse=True,
        )
        history = dict(
            [*active.items(), *stale[: max(0, MAX_IDENTITIES - len(active))]]
        )
    return {
        "identity_history": history,
        "identity_conflicts": conflicts[:200],
        "identity_changes": changes[-MAX_CHANGES:],
    }
