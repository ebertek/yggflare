"""UTC scheduler for Cloudflare reconciliation, inventory and backups."""

import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from backup import create_snapshot, prune_snapshots

CONFIG = Path(os.getenv("YGGFLARE_CONFIG", "/config"))
DATA = Path(os.getenv("YGGFLARE_DATA", "/data"))
SOURCE = Path(os.getenv("YGGFLARE_SOURCE", "/compose-source"))
BACKUP = Path(os.getenv("YGGFLARE_BACKUP", "/backup"))
LOG_FORMAT = os.getenv("YGG_LOG_FORMAT", "text").lower()
if LOG_FORMAT not in ("text", "json"):
    raise ValueError("YGG_LOG_FORMAT must be text or json")
CLOUD_INTERVAL = dt.timedelta(hours=6)
NETWORK_HOUR, NETWORK_MINUTE = 5, 15


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
    ) as process:
        assert process.stdout is not None
        for line in process.stdout:
            log("info", component, line.rstrip("\n"))
        try:
            exit_code = process.wait(timeout=3300)
        except subprocess.TimeoutExpired as error:
            process.kill()
            process.wait()
            raise RuntimeError(f"Command timed out: {args[1]}") from error
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
    auto = os.environ.get("CF_AUTO_APPLY", "false")
    if auto not in ("true", "false"):
        raise ValueError("CF_AUTO_APPLY must be exactly true or false")
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


def network_run():
    """Read DNS-SD settings from environment and webhook from secret file."""
    env = os.environ.copy()
    env.pop("YGG_NETWORK_DISCORD_WEBHOOK_URL", None)
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
    DATA.mkdir(parents=True, exist_ok=True)
    threading.Thread(target=heartbeat_loop, daemon=True).start()
    next_cloud = dt.datetime.now(dt.timezone.utc)
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
        if now >= next_cloud:
            try:
                cloudflare_run()
            except Exception as error:
                log("error", "cloudflare", f"Cycle failed: {error}")
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
        time.sleep(20)


if __name__ == "__main__":
    main()
