"""Best-effort input change notifications for the Cloudflare reconciler.

Signals only request reconciliation. The guarded Cloudflare writer and the
read-only mode remain authoritative; watching inputs never bypasses them.
"""

import hashlib
import json
import os
import subprocess
import threading
import time
from pathlib import Path


def enabled(name, default=True):
    """Parse feature switches without accepting ambiguous truthy values."""
    value = os.getenv(name, str(default).lower()).lower()
    if value not in ("true", "false"):
        raise ValueError(f"{name} must be true or false")
    return value == "true"


def seconds(name, default, minimum, maximum):
    """Validate bounds for watcher timing configuration."""
    raw = os.getenv(name, str(default))
    try:
        result = int(raw)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error
    if not minimum <= result <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return result


def fingerprint(source, config):
    """Hash only the Compose and private inventory inputs used by audits."""
    paths = sorted(set(source.rglob("compose.yaml")) | set(source.rglob("compose.yml")))
    digest = hashlib.sha256()
    for path in [*paths, config / "static-hosts.json", config / "retained-dns.json"]:
        # Include relative paths and file presence so rename/deletion is visible.
        name = (
            "compose/" + path.relative_to(source).as_posix()
            if path.is_relative_to(source)
            else "config/" + path.name
        )
        digest.update(name.encode("utf-8"))
        digest.update(b"\\0")
        if not path.is_file():
            digest.update(b"ABSENT")
            continue
        digest.update(b"PRESENT")
        with path.open("rb") as file:
            while chunk := file.read(65536):
                digest.update(chunk)
        digest.update(b"\\0")
    return digest.digest()


class Changes:
    """Coalesce concurrent notifications and gate them by debounce/cooldown."""

    def __init__(self):
        self._lock = threading.Lock()
        self._reasons = set()
        self._changed_at = 0.0

    def mark(self, reason, *, now=None):
        moment = time.monotonic() if now is None else now
        with self._lock:
            self._reasons.add(reason)
            self._changed_at = moment

    def take(self, *, debounce, earliest=0.0, now=None):
        moment = time.monotonic() if now is None else now
        with self._lock:
            if not self._reasons:
                return []
            if moment < max(self._changed_at + debounce, earliest):
                return []
            result = sorted(self._reasons)
            self._reasons.clear()
            return result

    def clear(self):
        """Consume pending notifications covered by an immediate scheduled run."""
        with self._lock:
            result = sorted(self._reasons)
            self._reasons.clear()
            return result


def watch_files(source, config, changes, interval, log):
    """Poll content fingerprints; works even with atomic Git checkout replaces."""
    previous = None
    last_error = None
    while True:
        try:
            current = fingerprint(source, config)
            if previous is not None and current != previous:
                changes.mark("compose_or_inventory")
            previous = current
            last_error = None
        except (OSError, ValueError) as error:
            # Do not erase the last known fingerprint on a transient read failure.
            if str(error) != last_error:
                log("warning", "watch", f"Input watcher: {error}")
                last_error = str(error)
        time.sleep(interval)


ACTIONS = frozenset({"start", "die", "destroy", "rename", "connect", "disconnect"})


def event_reason(event, own_container):
    """Filter daemon events to relevant topology changes and skip self-events."""
    action = event.get("Action") or event.get("status")
    if action not in ACTIONS:
        return None
    kind = event.get("Type")
    if kind not in ("container", "network"):
        return None
    attributes = event.get("Actor", {}).get("Attributes", {})
    if not isinstance(attributes, dict):
        return None
    if kind == "container":
        if action not in ("start", "die", "destroy", "rename"):
            return None
        if attributes.get("name", "").lstrip("/") == own_container:
            return None
    elif action not in ("connect", "disconnect"):
        return None
    return "docker_topology"


def watch_docker(changes, log):
    """Subscribe to Docker events, retrying if the daemon connection ends."""
    filters = [
        "type=container",
        "type=network",
        "event=start",
        "event=die",
        "event=destroy",
        "event=rename",
        "event=connect",
        "event=disconnect",
    ]
    command = ["docker", "events", "--format", "{{json .}}"]
    for item in filters:
        command.extend(["--filter", item])
    own_container = os.getenv("YGGFLARE_CONTAINER_NAME", "yggflare")
    while True:
        try:
            with subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            ) as process:
                assert process.stdout is not None
                for line in process.stdout:
                    try:
                        reason = event_reason(json.loads(line), own_container)
                    except (ValueError, TypeError, AttributeError):
                        continue
                    if reason:
                        changes.mark(reason)
                code = process.wait()
                log("warning", "watch", f"Docker event stream ended: {code}")
        except OSError as error:
            log("warning", "watch", f"Docker event stream unavailable: {error}")
        # The periodic audit still operates if the event stream is unavailable.
        time.sleep(15)


def start(source, config, log):
    """Start optional watchers without blocking the scheduler."""
    changes = Changes()
    interval = seconds("YGG_WATCH_POLL_SECONDS", 15, 5, 300)
    debounce = seconds("YGG_WATCH_DEBOUNCE_SECONDS", 20, 5, 300)
    cooldown = seconds("YGG_WATCH_COOLDOWN_SECONDS", 60, 0, 3600)
    if enabled("YGG_WATCH_COMPOSE"):
        threading.Thread(
            target=watch_files,
            args=(Path(source), Path(config), changes, interval, log),
            name="compose-watcher",
            daemon=True,
        ).start()
    if enabled("YGG_WATCH_DOCKER"):
        threading.Thread(
            target=watch_docker,
            args=(changes, log),
            name="docker-watcher",
            daemon=True,
        ).start()
    return changes, debounce, cooldown
