"""Human-readable output escaping; never change stored evidence or identities."""

from html import escape
from unicodedata import normalize


def visible_text(value):
    """Make control, format and other nonprintable characters visible."""
    return "".join(
        char if char.isprintable() else repr(char)[1:-1] for char in str(value)
    )


def html_text(value, quote=True):
    return escape(visible_text(value), quote=quote)


def csv_cell(value):
    """Discourage spreadsheet formula evaluation; JSON preserves exact values."""
    if value is None:
        return ""
    text = str(value)
    candidate = normalize("NFKC", text).lstrip()
    if text and (
        not text[0].isprintable() or candidate.startswith(("=", "+", "-", "@"))
    ):
        return "'" + visible_text(text)
    return visible_text(text)
