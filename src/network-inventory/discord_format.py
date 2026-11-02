"""Presentation helpers for Discord webhook embeds."""

import re


def render(messages, test=False):
    """Group observations in Discord embed fields with bounded lengths."""
    if test:
        return {"allowed_mentions": {"parse": []}, "embeds": [{"title": "Yggflare - Delivery test", "description": "Notification delivery works. No drift was detected by this test.", "color": 3066993}]}
    groups = [("Devices", ("NEW DEVICE", "CHANGED MAC", "CHANGED IP")), ("Ports", ("NEW PORT",)), ("Services", ("NEW DNS-SD",))]
    fields = []
    for label, prefixes in groups:
        lines = []
        for message in messages[:35]:
            if not message.startswith(prefixes):
                continue
            safe = str(message).replace("@", "@\u200b").replace("`", "'").replace("\n", " ")
            if message.startswith("NEW PORT "):
                match = re.fullmatch(r"NEW PORT (\S+) (\S+): (tcp|udp)/(\d+)", message)
                if match:
                    host, ip, protocol, port = match.groups()
                    safe = f"**{host}** - `{protocol}/{port}` (`{ip}`)"
            elif message.startswith("NEW DNS-SD "):
                parts = message.removeprefix("NEW DNS-SD ").rsplit("|", 2)
                if len(parts) == 3:
                    safe = f"**{parts[0]}** - `{parts[1]}` / {parts[2]}"
            lines.append("• " + safe[:850])
        batch = []
        size = 0
        for line in lines:
            if batch and size + len(line) + 1 > 950:
                fields.append({"name": label, "value": "\n".join(batch), "inline": False})
                batch = []
                size = 0
            batch.append(line)
            size += len(line) + 1
        if batch:
            fields.append({"name": label, "value": "\n".join(batch), "inline": False})
    extra = max(0, len(messages) - 35)
    return {"allowed_mentions": {"parse": []}, "embeds": [{"title": "Yggflare - Network inventory", "description": f"{len(messages)} new observations", "color": 15105570 if any(m.startswith(("NEW DEVICE", "CHANGED MAC", "CHANGED IP")) for m in messages) else 3447003, "fields": fields[:25], "footer": {"text": "Read-only discovery, no DNS changes" + (f"; {extra} additional events" if extra else "")}}]}
