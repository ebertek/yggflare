"""Read-only reporting of ygg.nu records without an inventory owner.

Findings are review hints only. Never add them to Cloudflare mutation plans.
"""

import re

from cloudflare_retained_dns import matches_retained, retained_summary

NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")
ADDRESS_TYPES = frozenset({"A", "AAAA", "CNAME"})


def declared_dns_names(static_aliases, compose_services, running):
    """Collect alias and Docker names even when services are stopped."""
    owned = set(static_aliases)
    for service in compose_services:
        name = service.get("Name", "").rsplit("/", 1)[-1]
        if NAME.fullmatch(name):
            owned.add(name + ".ygg.nu")
        custom = service.get("ContainerName")
        if isinstance(custom, str) and NAME.fullmatch(custom):
            owned.add(custom + ".ygg.nu")
    for name in running:
        if NAME.fullmatch(name):
            owned.add(name + ".ygg.nu")
    return owned


def audit_unaccounted_dns(records, static_hosts, declared_names, retained=None):
    """Find live DNS records absent from static, alias and Docker declarations."""
    retained = retained or []
    if records is None or static_hosts is None:
        return {
            "enabled": False,
            "counts": {
                "records": 0,
                "hostnames": 0,
                "address_records": 0,
                "other_records": 0,
            },
            "findings": [],
            "retained": {"declared": 0, "present": 0, "missing": []},
        }

    owned = set(static_hosts) | set(declared_names)

    findings = []
    for record in records:
        name = record.get("name")
        if not isinstance(name, str):
            continue
        name = name.lower().rstrip(".")
        if name == "ygg.nu" or not name.endswith(".ygg.nu") or name in owned:
            continue
        if any(matches_retained(wanted, record) for wanted in retained):
            continue
        kind = record.get("type")
        kind = kind.upper() if isinstance(kind, str) else "UNKNOWN"
        category = "address" if kind in ADDRESS_TYPES else "other"
        finding = {"hostname": name, "type": kind, "category": category}
        if isinstance(record.get("proxied"), bool):
            finding["proxied"] = record["proxied"]
        # Do not print TXT/MX/SRV payloads or other potentially sensitive contents.
        content = record.get("content")
        if (
            category == "address"
            and isinstance(content, str)
            and len(content) <= 255
            and all(32 <= ord(char) <= 126 for char in content)
        ):
            finding["content"] = content
        findings.append(finding)
    findings.sort(
        key=lambda item: (item["hostname"], item["type"], item.get("content", ""))
    )
    return {
        "enabled": True,
        "counts": {
            "records": len(findings),
            "hostnames": len({item["hostname"] for item in findings}),
            "address_records": sum(item["category"] == "address" for item in findings),
            "other_records": sum(item["category"] == "other" for item in findings),
        },
        "findings": findings,
        "retained": retained_summary(retained, records),
    }


def print_unaccounted_summary(report):
    """Show review-only DNS leftovers without proposing any deletion."""
    summary = report.get("unaccounted_ygg_dns", {})
    if not summary.get("enabled"):
        return
    declared = summary.get("retained", {})
    if declared.get("declared"):
        print(
            f"Retained ygg.nu DNS: {declared['present']}/"
            f"{declared['declared']} matching (review only; no writes)"
        )
        for expected in declared["missing"]:
            destination = f" -> {expected['content']}" if "content" in expected else ""
            print(
                f"  ! RETAINED missing {expected['type']} "
                f"{expected['hostname']}{destination}"
            )
    counts = summary["counts"]
    print(
        f"Unaccounted ygg.nu DNS: {counts['records']} records across "
        f"{counts['hostnames']} hostnames (review only; no deletions)"
    )
    for finding in summary["findings"]:
        destination = f" -> {finding['content']}" if "content" in finding else ""
        print(
            f"  ? REVIEW {finding['category']} {finding['type']} "
            f"{finding['hostname']}{destination}"
        )
