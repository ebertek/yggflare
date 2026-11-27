"""UTC scheduler for Cloudflare reconciliation, inventory and backups."""

import datetime as dt
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from backup import create_snapshot, prune_snapshots
from integration_inventory import ADAPTERS, scheduled
from integration_inventory import INTERVAL as INTEGRATION_INTERVAL
from job_status import DNS_VERIFICATION_PENDING_EXIT, JobPending, track
from mcp_http import HTTPListener
from mcp_http import enabled as mcp_enabled
from mcp_http import settings as mcp_settings
from mcp_logging import http_logging
from probe_inventory import INTERVAL as PROBE_INTERVAL
from traefik_inventory import INTERVAL as TRAEFIK_INTERVAL
from watchers import start as start_watchers
from yggflare_env import env_get, getenv

CONFIG = Path("/config")
DATA = Path("/data")
SOURCE = Path("/compose-source")
BACKUP = Path("/backup")
LOG_FORMAT = getenv("YGGFLARE_LOG_FORMAT", "text").lower()
if LOG_FORMAT not in ("text", "json"):
    raise ValueError("YGGFLARE_LOG_FORMAT must be text or json")
CLOUD_INTERVAL = dt.timedelta(hours=6)
NETWORK_HOUR, NETWORK_MINUTE = 5, 15
SHUTDOWN_GRACE_SECONDS = 3
UNIFI_APPLY_INTERVAL_DEFAULT = 60
UNIFI_PENDING_INTERVAL = 30
UNIFI_FAILURE_BACKOFF = 300


class ShutdownRequested(BaseException):
    """Container stop signal; bypass routine job failure handlers."""

    def __init__(self, signum):
        super().__init__(signum)
        self.signum = signum


def on_shutdown(signum, _frame):
    """Exit even when Python runs as container PID 1."""
    raise ShutdownRequested(signum)


def stop_child_group(process):
    """Stop a job and its descendants before the container exits.

    Jobs are launched in their own process group so an interrupted Nmap
    or Cloudflare command cannot retain the stdout pipe and hang shutdown.
    """
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=SHUTDOWN_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def snapshot(root):
    """Copy only Compose YAML into an isolated working tree; no source mutation."""
    source_files = list(SOURCE.rglob("compose.yaml")) + list(
        SOURCE.rglob("compose.yml")
    )
    if not source_files:
        raise RuntimeError("No Compose files in mounted merged GitOps checkout")
    for source_file in source_files:
        target = root / source_file.relative_to(SOURCE)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_file, target)
    private_dir = root / "Scripts" / "cloudflare"
    private_dir.mkdir(parents=True, exist_ok=True)
    for name in ("static-hosts.json", "retained-dns.json"):
        source_file = CONFIG / name
        if source_file.is_file():
            shutil.copy2(source_file, private_dir / name)
    if not (private_dir / "static-hosts.json").is_file():
        raise FileNotFoundError("static-hosts.json missing from /config")
    return root


def log(level, component, message, **fields):
    """Emit one UTC record, as readable text or JSON lines."""
    timestamp = (
        dt.datetime.now(dt.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )
    if LOG_FORMAT == "json":
        print(
            json.dumps(
                {
                    "timestamp": timestamp,
                    "level": level.lower(),
                    "component": component,
                    "message": message,
                    **fields,
                },
                sort_keys=True,
            ),
            flush=True,
        )
    else:
        print(f"{timestamp} {level.upper():<5} [{component}] {message}", flush=True)


def image_identity():
    """Return safe, immutable image-build metadata or development placeholders."""
    version = getenv("YGGFLARE_BUILD_VERSION", "dev")
    revision = getenv("YGGFLARE_BUILD_REVISION", "unknown")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", version):
        version = "unknown"
    if not re.fullmatch(r"[a-fA-F0-9]{40}", revision):
        revision = "unknown"
    return version, revision.lower()


def version_string():
    """Human-readable identifier for logs and the container CLI."""
    version, revision = image_identity()
    return f"Yggflare {version} (revision {revision[:12]})"


def log_startup():
    """Identify the exact running release before starting any scheduled work."""
    version, revision = image_identity()
    log(
        "info",
        "startup",
        version_string(),
        version=version,
        revision=revision,
    )


def job_label(script):
    """Friendly stable labels without logging command arguments or secrets."""
    return {
        "cloudflare-manage.py": "Cloudflare reconciliation",
        "cloudflare-auto-cleanup.py": "Managed orphan cleanup",
        "cloudflare_internal_cleanup.py": "Managed internal DNS cleanup",
        "cloudflare-claim-all.py": "Cloudflare ownership claims",
        "cloudflare-live.py": "Cloudflare presentation refresh",
        "audit.py": "Network inventory scan",
        "traefik_inventory.py": "Traefik presentation refresh",
        "integration_inventory.py": "Integration presentation refresh",
        "unifi_apply.py": "UniFi guarded DNS create",
        "probe_inventory.py": "Independent connectivity probes",
    }.get(Path(script).name, "Scheduled job")


def run(args, *, env=None):
    component = (
        "probe"
        if Path(args[1]).name == "probe_inventory.py"
        else (
            "integration"
            if Path(args[1]).name in {"integration_inventory.py", "unifi_apply.py"}
            else (
                "traefik"
                if Path(args[1]).name == "traefik_inventory.py"
                else "cloudflare" if "/cloudflare/" in args[1] else "network"
            )
        )
    )
    label = job_label(args[1])
    started = time.monotonic()
    log("info", component, f"{label} started")
    with subprocess.Popen(
        args,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        start_new_session=True,
    ) as process:
        try:
            assert process.stdout is not None
            for line in process.stdout:
                log("info", component, line.rstrip("\n"))
            try:
                exit_code = process.wait(timeout=3300)
            except subprocess.TimeoutExpired as error:
                raise RuntimeError(f"Command timed out: {args[1]}") from error
        except BaseException:
            # Includes the SIGTERM exception. Do not leave subprocesses
            # running or block indefinitely in Popen.__exit__().
            stop_child_group(process)
            log(
                "warning",
                component,
                f"{label} interrupted after {time.monotonic() - started:.1f}s",
            )
            raise
    pending = (
        Path(args[1]).name == "unifi_apply.py"
        and exit_code == DNS_VERIFICATION_PENDING_EXIT
    )
    log(
        "info" if exit_code == 0 or pending else "error",
        component,
        f"{label} {'pending DNS verification' if pending else 'finished'} in {time.monotonic() - started:.1f}s",
        exit_code=exit_code,
    )
    if pending:
        raise JobPending
    if exit_code:
        raise RuntimeError(f"Command exited {exit_code}: {args[1]}")
    return exit_code


def cloudflare_run():
    """Run Cloudflare using environment configuration and mounted secrets."""
    auto = getenv("YGGFLARE_CLOUDFLARE_AUTO_APPLY", "false")
    if auto not in ("true", "false"):
        raise ValueError("YGGFLARE_CLOUDFLARE_AUTO_APPLY must be exactly true or false")
    auto_claim = getenv("YGGFLARE_CLOUDFLARE_AUTO_CLAIM", "false")
    if auto_claim not in ("true", "false"):
        raise ValueError("YGGFLARE_CLOUDFLARE_AUTO_CLAIM must be exactly true or false")
    internal_cleanup = getenv("YGGFLARE_CLOUDFLARE_INTERNAL_AUTO_CLEANUP", "false")
    if internal_cleanup not in ("true", "false"):
        raise ValueError("Internal DNS cleanup must be exactly true or false")
    if internal_cleanup == "true" and auto != "true":
        raise ValueError("Internal DNS cleanup requires Cloudflare auto apply")
    env = os.environ.copy()
    secret = Path(
        env_get(env, "CLOUDFLARE_API_TOKEN_FILE", "/run/secrets/cloudflare_api_token")
    )
    if not secret.is_file():
        raise FileNotFoundError("Cloudflare API token secret missing")
    env["CLOUDFLARE_API_TOKEN_FILE"] = str(secret)
    env.pop("CLOUDFLARE_API_TOKEN", None)
    # Recover an acknowledged DELETE before any creates or claims can obscure it.
    retirement_journal = DATA / "internal-dns-retirement.json"
    if (
        internal_cleanup == "true"
        or retirement_journal.exists()
        or retirement_journal.is_symlink()
    ):
        run(
            [sys.executable, "/app/cloudflare/cloudflare_internal_cleanup.py"],
            env=env,
        )
    with tempfile.TemporaryDirectory(prefix="yggflare-compose-", dir=DATA) as folder:
        root = snapshot(Path(folder))
        script = (
            "/app/cloudflare/cloudflare-manage.py"
            if auto == "true"
            else "/app/cloudflare/cloudflare-live.py"
        )
        args = [
            sys.executable,
            script,
            "--root",
            str(root),
        ]
        if auto == "true":
            args.append("--auto")
        run(args, env=env)
        if auto_claim == "true":
            run(
                [
                    sys.executable,
                    "/app/cloudflare/cloudflare-claim-all.py",
                    "--root",
                    str(root),
                ],
                env=env,
            )
        if env_get(env, "YGGFLARE_CLOUDFLARE_AUTO_CLEANUP", "false") == "true":
            if auto != "true":
                raise ValueError(
                    "YGGFLARE_CLOUDFLARE_AUTO_CLEANUP requires YGGFLARE_CLOUDFLARE_AUTO_APPLY=true"
                )
            run(
                [
                    sys.executable,
                    "/app/cloudflare/cloudflare-auto-cleanup.py",
                ],
                env=env,
            )


def refresh_cloudflare_view():
    """Refresh presentation after reconciliation; never call this from HTTP."""
    # Mark the attempt before even copying inputs, so snapshot failures cannot
    # leave an older successful audit looking like a fresh success.
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=DATA, delete=False
    ) as handle:
        json.dump(
            {"ok": False, "attempted_at": dt.datetime.now(dt.timezone.utc).isoformat()},
            handle,
        )
        pending = handle.name
    os.replace(pending, DATA / "cloudflare-view-status.json")
    with tempfile.TemporaryDirectory(prefix="yggflare-view-", dir=DATA) as folder:
        root = snapshot(Path(folder))
        run(
            [
                sys.executable,
                "/app/cloudflare/cloudflare-live.py",
                "--root",
                str(root),
                "--save-view",
            ]
        )


def network_run():
    """Read DNS-SD settings from environment and webhook from secret file."""
    env = os.environ.copy()
    env.pop("YGGFLARE_NETWORK_DISCORD_WEBHOOK_URL", None)
    run(
        [
            sys.executable,
            "/app/network-inventory/audit.py",
            "--inventory",
            str(CONFIG / "static-hosts.json"),
            "--state-dir",
            str(DATA / "network-inventory"),
        ],
        env=env,
    )


def heartbeat_loop():
    """Maintain health independently of long-running scan subprocesses."""
    while True:
        (DATA / "heartbeat").touch()
        time.sleep(30)


def main():
    # Explicit handlers are required when Python is PID 1 in Docker.
    signal.signal(signal.SIGTERM, on_shutdown)
    signal.signal(signal.SIGINT, on_shutdown)
    log_startup()
    DATA.mkdir(parents=True, exist_ok=True)
    if not mcp_enabled():
        run_scheduler(None)
        return
    listener = HTTPListener(mcp_settings(), audit_log=log)
    with http_logging(log):
        try:
            listener.start()
            log("info", "mcp", "Authenticated Streamable HTTP interface enabled")
            run_scheduler(listener)
        finally:
            listener.stop()


def tracked(job):
    return track(DATA, job, lambda message: log("warning", "controller", message))


def unifi_apply_interval(environ):
    """Validate the independent DNS writer cadence before scheduling writes."""
    name = "YGGFLARE_UNIFI_APPLY_INTERVAL_SECONDS"
    raw = env_get(environ, name, str(UNIFI_APPLY_INTERVAL_DEFAULT))
    if not re.fullmatch(r"[0-9]{1,4}", raw) or not 30 <= int(raw) <= 3600:
        raise ValueError(f"{name} must be an integer from 30 to 3600")
    return int(raw)


def run_unifi_apply(interval):
    """Schedule pending verification separately from new creates and failures."""
    delay = interval
    try:
        with tracked("unifi_apply"):
            try:
                run([sys.executable, "/app/unifi_apply.py", "--automatic"])
            except JobPending:
                delay = UNIFI_PENDING_INTERVAL
                raise
    except Exception:
        log("warning", "controller", "UniFi guarded DNS create stopped")
        delay = max(interval, UNIFI_FAILURE_BACKOFF)
    return delay


def run_scheduler(listener=None):
    threading.Thread(target=heartbeat_loop, daemon=True).start()
    web_enabled = getenv("YGGFLARE_WEB_ENABLED", "false") == "true"
    if web_enabled:
        from web import serve  # pylint: disable=import-outside-toplevel

        threading.Thread(target=serve, daemon=True, name="yggflare-web").start()
        log("info", "web", "Read-only inventory interface enabled")
    changes, debounce, cooldown = start_watchers(SOURCE, CONFIG, log)
    next_cloud = dt.datetime.now(dt.timezone.utc)
    last_cloud_completed = 0.0
    next_traefik = 0.0
    next_probe = 0.0
    next_integration = dict.fromkeys(ADAPTERS, 0.0)
    unifi_auto_apply = getenv("YGGFLARE_UNIFI_AUTO_APPLY") == "true"
    unifi_interval = (
        unifi_apply_interval(os.environ)
        if unifi_auto_apply
        else UNIFI_APPLY_INTERVAL_DEFAULT
    )
    next_unifi_apply = 0.0
    backup_marker = DATA / "backup-last-run.txt"
    last_backup_day = (
        backup_marker.read_text(encoding="utf-8").strip()
        if backup_marker.exists()
        else None
    )
    network_marker = DATA / "network-last-run.txt"
    last_network_day = (
        network_marker.read_text(encoding="utf-8").strip()
        if network_marker.exists()
        else None
    )
    while True:
        if listener is not None and not listener.is_alive():
            raise RuntimeError("MCP listener stopped unexpectedly")
        now = dt.datetime.now(dt.timezone.utc)
        periodic = now >= next_cloud
        reasons = (
            changes.clear()
            if periodic
            else changes.take(
                debounce=debounce,
                earliest=last_cloud_completed + cooldown,
            )
        )
        if periodic or reasons:
            trigger = "scheduled" if periodic else ", ".join(reasons)
            log("info", "cloudflare", f"Reconciliation triggered: {trigger}")
            try:
                with tracked("cloudflare_cycle"):
                    cloudflare_run()
            except Exception as error:
                log("error", "cloudflare", f"Cycle failed: {error}")
            if web_enabled or listener is not None:
                try:
                    with tracked("cloudflare_view"):
                        refresh_cloudflare_view()
                except Exception:
                    log(
                        "warning",
                        "controller",
                        "Cloudflare view refresh failed; previous snapshot retained",
                    )
            last_cloud_completed = time.monotonic()
            next_cloud = dt.datetime.now(dt.timezone.utc) + CLOUD_INTERVAL
        if getenv("YGGFLARE_TRAEFIK_API_URL") and time.monotonic() >= next_traefik:
            try:
                with tracked("traefik"):
                    run([sys.executable, "/app/traefik_inventory.py"])
            except Exception:
                log(
                    "warning",
                    "controller",
                    "Traefik presentation refresh failed; previous snapshot retained",
                )
            next_traefik = time.monotonic() + TRAEFIK_INTERVAL
        for adapter in ADAPTERS:
            if (
                scheduled(adapter, os.environ)
                and time.monotonic() >= next_integration[adapter]
            ):
                try:
                    with tracked(adapter):
                        run([sys.executable, "/app/integration_inventory.py", adapter])
                except Exception:
                    log(
                        "warning",
                        "controller",
                        f"{adapter} presentation refresh failed; previous snapshot retained",
                    )
                next_integration[adapter] = time.monotonic() + INTEGRATION_INTERVAL
        if unifi_auto_apply and time.monotonic() >= next_unifi_apply:
            delay = run_unifi_apply(unifi_interval)
            next_unifi_apply = time.monotonic() + delay
        if (
            getenv("YGGFLARE_PROBES_ENABLED") == "true"
            and time.monotonic() >= next_probe
        ):
            try:
                with tracked("probes"):
                    run([sys.executable, "/app/probe_inventory.py"])
            except Exception:
                log(
                    "warning",
                    "controller",
                    "Probe collection failed; previous snapshot retained",
                )
            next_probe = time.monotonic() + PROBE_INTERVAL
        current_utc = dt.datetime.now(dt.timezone.utc)
        if (current_utc.hour, current_utc.minute) >= (4, 0):
            if last_backup_day != current_utc.date().isoformat():
                try:
                    with tracked("backup"):
                        archive = create_snapshot(
                            CONFIG, DATA, BACKUP, Path("/run/secrets")
                        )
                        prune_snapshots(BACKUP)
                        log("info", "backup", f"Snapshot created: {archive.name}")
                    last_backup_day = current_utc.date().isoformat()
                    backup_marker.write_text(last_backup_day + "\n", encoding="utf-8")
                except Exception as error:
                    log("error", "backup", f"Cycle failed: {error}")
        if (current_utc.hour, current_utc.minute) >= (NETWORK_HOUR, NETWORK_MINUTE):
            if last_network_day != current_utc.date().isoformat():
                try:
                    with tracked("network_scan"):
                        network_run()
                    last_network_day = current_utc.date().isoformat()
                    network_marker.write_text(last_network_day + "\n", encoding="utf-8")
                except Exception as error:
                    log("error", "network", f"Cycle failed: {error}")
        time.sleep(5)


if __name__ == "__main__":
    try:
        main()
    except ShutdownRequested as error:
        log(
            "info",
            "controller",
            f"Shutdown requested: {signal.Signals(error.signum).name}",
        )
