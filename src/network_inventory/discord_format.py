"""Grouped network discovery notifications using shared Discord styling."""

import re

from discord_embed import embed_payload, inline_code, text_units


def event_line(message):
    """Format known inventory events without changing their saved identity."""
    if message.startswith("NEW PORT "):
        match = re.fullmatch(r"NEW PORT (\S+) (\S+): (tcp|udp)/(\d+)(.*)", message)
        if match:
            host, ip, protocol, port, suffix = match.groups()
            line = (
                f"{inline_code(host)} · {inline_code(f'{protocol}/{port}')} "
                f"({inline_code(ip)})"
            )
            if suffix:
                line += " " + inline_code(suffix.strip())
            return line
    elif message.startswith("NEW DNS-SD "):
        parts = message.removeprefix("NEW DNS-SD ").rsplit("|", 2)
        if len(parts) == 3:
            return (
                f"{inline_code(parts[0])} · {inline_code(parts[1])} "
                f"({inline_code(parts[2])})"
            )
    for prefix, label in (
        ("NEW DEVICE ", "New device"),
        ("CHANGED MAC ", "MAC changed"),
        ("CHANGED IP ", "IP changed"),
        ("NEW PORT ", "New port"),
        ("NEW DNS-SD ", "New service"),
    ):
        if message.startswith(prefix):
            return f"{label} · {inline_code(message.removeprefix(prefix))}"
    return None


def render(messages, test=False):
    """Group observations within Discord's per-field and total embed limits."""
    if test:
        return embed_payload(
            "Delivery test",
            "Notification delivery verified.\nTest only · No drift detected.",
            "success",
        )
    groups = [
        ("Devices", ("NEW DEVICE", "CHANGED MAC", "CHANGED IP")),
        ("Ports", ("NEW PORT",)),
        ("Services", ("NEW DNS-SD",)),
    ]
    fields = []
    shown = 0
    units = 0
    # Leave space for the title, summary and footer within Discord's 6000-unit
    # aggregate embed limit. Count every repeated field heading as well.
    for label, prefixes in groups:
        batch = []
        size = 0
        for message in messages[:35]:
            if not message.startswith(prefixes):
                continue
            line = event_line(message)
            if line is None:
                continue
            line = "• " + line
            if text_units(line) > 950:
                line = "• " + inline_code(message)
            line_units = text_units(line)
            if batch and size + line_units + 1 > 950:
                fields.append(
                    {"name": label, "value": "\n".join(batch), "inline": False}
                )
                batch = []
                size = 0
            extra = line_units + (1 if batch else text_units(label))
            if len(fields) >= 25 or units + extra > 5400:
                break
            batch.append(line)
            size += line_units + (1 if size else 0)
            units += extra
            shown += 1
        if batch:
            fields.append({"name": label, "value": "\n".join(batch), "inline": False})
    omitted = len(messages) - shown
    warning = any(
        message.startswith(("NEW DEVICE", "CHANGED MAC", "CHANGED IP"))
        for message in messages
    )
    footer = "Read-only discovery · No DNS changes"
    if omitted:
        footer += f" · {omitted} additional observations"
    return embed_payload(
        "Network inventory changes",
        f"{len(messages)} new observations",
        "warning" if warning else "info",
        fields=fields,
        footer=footer,
    )
