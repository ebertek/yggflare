"""Reduce transient discovery alerts without suppressing identity drift.

Network observations and active drift are always retained immediately.
Only new TCP ports and DNS-SD service identities require repeat sightings
before Discord delivery. Missing advertisements never mean a device is offline.
"""

import os

MAX_TRACKED = 4096
MAX_PENDING = 100


def confirmation_scans():
    """Parse opt-in alert noise setting; 1 recreates immediate legacy alerts."""
    raw = os.environ.get("YGGFLARE_NETWORK_ALERT_CONFIRM_SCANS", "2")
    try:
        count = int(raw)
    except ValueError as error:
        raise ValueError("Invalid network alert confirmation count") from error
    if not 1 <= count <= 10:
        raise ValueError("Network alert confirmations must be 1-10 scans")
    return count


def dns_identity(advertisement):
    """Service type plus advertised hostname; dynamic port isn't an identity."""
    return advertisement.rsplit("|", 1)[0]


def confirmed_alerts(
    events,
    reported,
    advertisements,
    previous,
    *,
    dns_sd_complete,
    baseline,
    required,
):
    """Filter only volatile findings; return notifications, state and review queue.

    A migration from the legacy state treats previously active port findings as
    already notified to avoid a replay storm. An incomplete DNS-SD browse does
    not erase candidate counts or cause spurious withdrawal/reappearance alerts.
    """
    if not 1 <= required <= 10:
        raise ValueError("Invalid alert confirmation threshold")
    state = previous.get("alert_state", {})
    if not isinstance(state, dict):
        raise ValueError("Invalid saved alert policy state")
    prev_port_counts = state.get("port_counts", {})
    prev_dns_counts = state.get("dns_counts", {})
    prev_port_notified = state.get("port_notified", [])
    prev_dns_notified = state.get("dns_notified", [])
    if (
        not isinstance(prev_port_counts, dict)
        or not isinstance(prev_dns_counts, dict)
        or not isinstance(prev_port_notified, list)
        or not isinstance(prev_dns_notified, list)
    ):
        raise ValueError("Invalid saved alert confirmation fields")
    previously_enabled = "alert_state" in previous
    if previous.get("initialized") and not previously_enabled:
        # Do this even if this browse fails: legacy DNS-SD announcements
        # must not replay as new services after an unavailable Avahi cycle.
        prev_dns_notified = [
            dns_identity(item) for item in previous.get("advertisements", [])
        ]
    active_ports = {
        key: message for key, message in reported.items() if key.startswith("new-port:")
    }
    if len(active_ports) > MAX_TRACKED or len(advertisements) > MAX_TRACKED:
        raise ValueError("Too many alert candidates; refusing silent truncation")

    port_counts = {
        key: min(int(prev_port_counts.get(key, 0)) + 1, required)
        for key in active_ports
    }
    port_notified = set(prev_port_notified) & set(active_ports)
    if baseline or (previous.get("initialized") and not previously_enabled):
        # Existing active observations were already surfaced by legacy policy.
        port_notified.update(active_ports)
    notifications = [
        event for event in events if not event.startswith(("NEW PORT ", "NEW DNS-SD "))
    ]
    pending = []
    for key, message in sorted(active_ports.items()):
        if port_counts[key] >= required and key not in port_notified:
            notifications.append(message)
            port_notified.add(key)
        elif key not in port_notified:
            pending.append(f"{message} ({port_counts[key]}/{required} scans)")

    if dns_sd_complete:
        # Keep one representative announcement per host|service identity.
        services = {}
        for item in sorted(advertisements):
            services.setdefault(dns_identity(item), item)
        dns_counts = {
            key: min(int(prev_dns_counts.get(key, 0)) + 1, required) for key in services
        }
        dns_notified = set(prev_dns_notified) & set(services)
        if baseline:
            dns_notified.update(services)

        for key, announcement in sorted(services.items()):
            if dns_counts[key] >= required and key not in dns_notified:
                notifications.append("NEW DNS-SD " + announcement)
                dns_notified.add(key)
            elif key not in dns_notified:
                pending.append(
                    f"NEW DNS-SD {announcement} ({dns_counts[key]}/{required} scans)"
                )
    else:
        dns_counts = dict(prev_dns_counts)
        dns_notified = set(prev_dns_notified)

    # Preserve the raw initial baseline in observation history; the audit
    # layer never queues or delivers its baseline events to Discord.
    if baseline:
        notifications = list(events)
        pending = []
    return (
        notifications,
        {
            "port_counts": port_counts,
            "port_notified": sorted(port_notified),
            "dns_counts": dns_counts,
            "dns_notified": sorted(dns_notified),
        },
        pending[:MAX_PENDING],
    )
