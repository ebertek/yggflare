"""Bounded atomic last-good presentation snapshots shared by API collectors."""

import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path

MAX_BYTES = 4 * 1024 * 1024


def timestamp():
    return datetime.now(UTC).isoformat()


def source_id(config):
    return hashlib.sha256(json.dumps(config).encode()).hexdigest()


def write(path, document):
    encoded = json.dumps(document, separators=(",", ":"))
    if len(encoded.encode()) > MAX_BYTES:
        raise ValueError("Traefik snapshot exceeds size limit")
    name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as handle:
            name = handle.name
            handle.write(encoded)
        os.replace(name, path)
    finally:
        if name is not None:
            Path(name).unlink(missing_ok=True)


def read(path):
    try:
        if path.is_symlink() or path.stat().st_size > MAX_BYTES:
            return {}
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) and value.get("version") == 1 else {}
    except (OSError, ValueError, TypeError):
        return {}


def saved_snapshot(data, prefix, config, configured, stale_seconds):
    view = read(data / f"{prefix}-view.json")
    status = read(data / f"{prefix}-view-status.json")
    matches = bool(config and view.get("source_id") == source_id(config))
    rows = view.get("items", [])
    available = (
        matches
        and isinstance(rows, list)
        and all(isinstance(row, dict) for row in rows)
    )
    age = None
    if available:
        try:
            age = (
                datetime.now(UTC) - datetime.fromisoformat(view["observed_at"])
            ).total_seconds()
        except (KeyError, ValueError, TypeError):
            available = False
    verified = bool(
        available
        and status.get("ok") is True
        and status.get("source_id") == view.get("source_id")
        and status.get("observed_at") == view.get("observed_at")
    )
    return {
        "configured": configured,
        "available": available,
        "observed_at": view.get("observed_at") if available else None,
        "last_attempt_at": (
            status.get("attempted_at")
            if config and status.get("source_id") == source_id(config)
            else None
        ),
        "last_refresh_verified": verified,
        "fresh": bool(verified and age is not None and 0 <= age <= stale_seconds),
        "items": rows if available else [],
    }
