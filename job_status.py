"""Bounded local scheduler evidence; never a source of job authorization."""

import json
import os
import re
import stat
import tempfile
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

JOBS = (
    "cloudflare_cycle",
    "cloudflare_view",
    "network_scan",
    "backup",
    "traefik",
    "komodo",
    "kuma",
    "probes",
)
MAX_HISTORY = 20
MAX_BYTES = 128 * 1024


def now():
    return datetime.now(UTC).isoformat()


def read_jobs(data):
    """Read fixed status metadata; absent or invalid data is unavailable."""
    try:
        path = data / "job-status.json"
        if path.is_symlink() or path.stat().st_size > MAX_BYTES:
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
        if (
            not isinstance(value, dict)
            or value.get("version") != 1
            or not isinstance(value.get("jobs"), dict)
            or any(not isinstance(row, dict) for row in value["jobs"].values())
        ):
            return None
        return value
    except (OSError, ValueError, TypeError):
        return None


def write_jobs(data, value):
    name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=data, delete=False
        ) as handle:
            name = handle.name
            json.dump(value, handle)
        os.replace(name, data / "job-status.json")
    finally:
        if name is not None:
            Path(name).unlink(missing_ok=True)


@contextmanager
def track(data, job, warn):
    """Record outcomes without changing scheduler failure semantics."""
    if job not in JOBS:
        raise ValueError("Unknown scheduled job")
    document = read_jobs(data) or {"version": 1, "jobs": {}}
    previous = document["jobs"].get(job, {})
    history = previous.get("history", [])
    if not isinstance(history, list):
        history = []
    if previous.get("status") == "completion_unknown":
        history = history + [
            {
                "started_at": previous.get("started_at"),
                "status": "completion_unknown",
            }
        ]
    row = {
        "started_at": now(),
        "status": "completion_unknown",
        "last_success_at": previous.get("last_success_at"),
        "history": history[-MAX_HISTORY:],
    }
    document["jobs"][job] = row

    def persist():
        try:
            write_jobs(data, document)
        except (OSError, ValueError, TypeError):
            warn("Could not persist scheduled job evidence")

    started = time.monotonic()
    persist()
    try:
        yield
    except BaseException as error:
        row["status"] = "failed" if isinstance(error, Exception) else "interrupted"
        raise
    else:
        row["status"] = "succeeded"
    finally:
        row["finished_at"] = now()
        row["duration_seconds"] = round(time.monotonic() - started, 3)
        if row["status"] == "succeeded":
            row["last_success_at"] = row["finished_at"]
        row["history"] = (
            row["history"]
            + [
                {
                    field: row[field]
                    for field in (
                        "started_at",
                        "finished_at",
                        "duration_seconds",
                        "status",
                    )
                }
            ]
        )[-MAX_HISTORY:]
        persist()


def artifact_status(backup):
    """Only stat named archives; never open or extract them."""
    count = 0
    latest = None
    try:
        for path in backup.iterdir():
            if not re.fullmatch(r"yggflare-\d{8}T\d{6}Z\.tar\.gz", path.name):
                continue
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                continue
            count += 1
            if latest is None or path.name > latest["name"]:
                latest = {
                    "name": path.name,
                    "bytes": info.st_size,
                    "modified_at": datetime.fromtimestamp(
                        info.st_mtime, UTC
                    ).isoformat(),
                }
    except OSError:
        return {"available": False}
    return {"available": True, "archive_count": count, "latest": latest}


def health(data):
    """Inspect fixed heartbeat and immutable build identity only."""
    version = os.environ.get("YGGFLARE_BUILD_VERSION", "dev")
    revision = os.environ.get("YGGFLARE_BUILD_REVISION", "unknown")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", version):
        version = "unknown"
    if not re.fullmatch(r"[a-fA-F0-9]{40}", revision):
        revision = "unknown"
    age = None
    try:
        info = (data / "heartbeat").lstat()
        if stat.S_ISREG(info.st_mode):
            age = round(time.time() - info.st_mtime, 3)
    except OSError:
        pass
    return {
        "version": version,
        "revision": revision.lower(),
        "heartbeat_age_seconds": age,
        "heartbeat_fresh": age is not None and 0 <= age < 300,
    }


BACKUP_CHECKS = ("integrity", "restore")


def archive_identity(path):
    """Bind verification evidence to an unchanged regular archive's metadata."""
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Backup must be a regular file")
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def record_backup_check(data, archive, kind, identity, succeeded):
    """Save the latest explicit check of each kind; never store archive contents."""
    if kind not in BACKUP_CHECKS:
        raise ValueError("Unknown backup check")
    if archive_identity(archive) != identity:
        raise ValueError("Archive changed during verification")
    value = {
        "version": 1,
        "archive": archive.name,
        "identity": identity,
        "checked_at": now(),
        "succeeded": succeeded,
    }
    name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=data, delete=False
        ) as handle:
            name = handle.name
            json.dump(value, handle)
        os.replace(name, data / f"backup-{kind}-evidence.json")
    finally:
        if name is not None:
            Path(name).unlink(missing_ok=True)


def backup_checks(data, archive):
    """Return evidence for this exact archive; missing or changed is unknown."""
    result = {}
    if archive is None:
        return result
    try:
        identity = archive_identity(archive)
    except (OSError, ValueError):
        return result
    for kind in BACKUP_CHECKS:
        try:
            path = data / f"backup-{kind}-evidence.json"
            if path.is_symlink() or path.stat().st_size > 4096:
                continue
            value = json.loads(path.read_text(encoding="utf-8"))
            if (
                isinstance(value, dict)
                and value.get("version") == 1
                and value.get("archive") == archive.name
                and value.get("identity") == identity
                and type(value.get("succeeded")) is bool
                and isinstance(value.get("checked_at"), str)
            ):
                result[kind] = {
                    "checked_at": value["checked_at"],
                    "succeeded": value["succeeded"],
                }
        except (OSError, ValueError, TypeError):
            continue
    return result
