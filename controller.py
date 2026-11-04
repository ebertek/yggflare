"""UTC scheduler for Cloudflare reconciliation, inventory and backups."""

import datetime as dt
import json
import os
import signal
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from backup import create_snapshot, prune_snapshots
from watchers import start as start_watchers

CONFIG = Path("/config")
DATA = Path("/data")
SOURCE = Path("/compose-source")
BACKUP = Path("/backup")
LOG_FORMAT = os.getenv("YGGFLARE_LOG_FORMAT", "text").lower()
if LOG_FORMAT not in ("text", "json"):
    raise ValueError("YGGFLARE_LOG_FORMAT must be text or json")
CLOUD_INTERVAL = dt.timedelta(hours=6)
NETWORK_HOUR, NETWORK_MINUTE = 5, 15
SHUTDOWN_GRACE_SECONDS = 3


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


def run(args, *, env=None):
    component = "cloudflare" if "/cloudflare/" in args[1] else "network"
    log("info", component, "Cycle started")
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
            raise
    log(
        "info" if exit_code == 0 else "error",
        component,
        "Cycle finished",
        exit_code=exit_code,
    )
    if exit_code:
        raise RuntimeError(f"Command exited {exit_code}: {args[1]}")
    return exit_code


def cloudflare_run():
    """Run Cloudflare using environment configuration and mounted secrets."""
    auto = os.environ.get("YGGFLARE_CLOUDFLARE_AUTO_APPLY", "false")
    if auto not in ("true", "false"):
        raise ValueError("YGGFLARE_CLOUDFLARE_AUTO_APPLY must be exactly true or false")
    env = os.environ.copy()
    secret = Path(
        env.get("CLOUDFLARE_API_TOKEN_FILE", "/run/secrets/cloudflare_api_token")
    )
    if not secret.is_file():
        raise FileNotFoundError("Cloudflare API token secret missing")
    env["CLOUDFLARE_API_TOKEN_FILE"] = str(secret)
    env.pop("CLOUDFLARE_API_TOKEN", None)
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
        if env.get("YGGFLARE_CLOUDFLARE_AUTO_CLEANUP", "false") == "true":
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
    DATA.mkdir(parents=True, exist_ok=True)
    threading.Thread(target=heartbeat_loop, daemon=True).start()
    if os.environ.get("YGGFLARE_WEB_ENABLED", "false") == "true":
        from web import serve  # pylint: disable=import-outside-toplevel

        threading.Thread(target=serve, daemon=True, name="yggflare-web").start()
        log("info", "web", "Read-only inventory interface enabled")
    changes, debounce, cooldown = start_watchers(SOURCE, CONFIG, log)
    next_cloud = dt.datetime.now(dt.timezone.utc)
    last_cloud_completed = 0.0
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
                cloudflare_run()
            except Exception as error:
                log("error", "cloudflare", f"Cycle failed: {error}")
            if os.environ.get("YGGFLARE_WEB_ENABLED", "false") == "true":
                try:
                    refresh_cloudflare_view()
                except Exception:
                    log(
                        "warning",
                        "web",
                        "Cloudflare view refresh failed; previous snapshot retained",
                    )
            last_cloud_completed = time.monotonic()
            next_cloud = dt.datetime.now(dt.timezone.utc) + CLOUD_INTERVAL
        current_utc = dt.datetime.now(dt.timezone.utc)
        if (current_utc.hour, current_utc.minute) >= (4, 0):
            if last_backup_day != current_utc.date().isoformat():
                try:
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
        log("info", "controller", f"Shutdown requested: {signal.Signals(error.signum).name}")
