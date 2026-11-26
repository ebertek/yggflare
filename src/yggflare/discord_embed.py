"""Shared presentation conventions for Yggflare Discord notifications."""

STYLES = {
    "success": ("✅", 3066993),
    "warning": ("⚠️", 15105570),
    "info": ("ℹ️", 3447003),
}


def text_units(value):
    """Count UTF-16 units conservatively for Discord text limits."""
    return len(value.encode("utf-16-le")) // 2


def inline_code(value):
    """Keep observed data on one line and inside a literal code span."""
    safe = "".join(char if char.isprintable() else " " for char in str(value))
    safe = safe.replace("`", "'").replace("@", "@\u200b").strip()
    if text_units(safe) > 400:
        safe = safe.encode("utf-16-le")[:798].decode("utf-16-le", "ignore") + "…"
    return f"`{safe}`"


def embed_payload(title, description, tone, *, fields=None, footer=None):
    """Render a compact, consistently styled, mention-free notification."""
    icon, color = STYLES[tone]
    embed = {
        "title": f"{icon} {title}",
        "description": description,
        "color": color,
    }
    if fields:
        embed["fields"] = fields
    if footer:
        embed["footer"] = {"text": footer}
    return {"allowed_mentions": {"parse": []}, "embeds": [embed]}
