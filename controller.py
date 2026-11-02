"""Single-process scheduler for the staged Ygg Cloudflare/LAN migration."""
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import threading
from zoneinfo import ZoneInfo

from backup import create_snapshot, prune_snapshots

CONFIG = Path(os.getenv("YGGFLARE_CONFIG", "/config"))
DATA = Path(os.getenv("YGGFLARE_DATA", "/data"))
SOURCE = Path(os.getenv("YGGFLARE_SOURCE", "/compose-source"))
BACKUP = Path(os.getenv("YGGFLARE_BACKUP", "/backup"))
TZ = ZoneInfo(os.getenv("TZ", "Europe/Stockholm"))
CLOUD_INTERVAL = dt.timedelta(hours=6)
NETWORK_HOUR, NETWORK_MINUTE = 5, 15


def snapshot(root):
    """Copy only Compose YAML into an isolated working tree; no source mutation."""
    source_files = list(SOURCE.rglob("compose.yaml")) + list(SOURCE.rglob("compose.yml"))
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


def run(args, *, env=None):
    print("Executing:", " ".join(args[:3]), flush=True)
    completed = subprocess.run(args, env=env, check=False, timeout=3300)
    if completed.returncode:
        raise RuntimeError(f"Command exited {completed.returncode}: {args[1]}")
    return completed.returncode


def cloudflare_run():
    """Use Compose settings and secret files; never execute or parse legacy env."""
    auto = os.environ.get("CF_AUTO_APPLY", "false")
    if auto not in ("true", "false"):
        raise ValueError("CF_AUTO_APPLY must be exactly true or false")
    env = os.environ.copy()
    secret = Path(env.get("CLOUDFLARE_API_TOKEN_FILE", "/run/secrets/cloudflare_api_token"))
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
            sys.executable, script, "--root", str(root),
            "--settings", str(CONFIG / "cloudflare-settings.json"),
        ]
        if auto == "true":
            args.append("--auto")
        run(args, env=env)

def network_run():
    """Read DNS-SD settings from environment and webhook from secret file."""
    env = os.environ.copy()
    env.pop("YGG_NETWORK_DISCORD_WEBHOOK_URL", None)
    run([
        sys.executable, "/app/network-inventory/audit.py",
        "--inventory", str(CONFIG / "static-hosts.json"),
        "--state-dir", str(DATA / "network-inventory"),
    ], env=env)

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
                print(f"ERROR Cloudflare cycle: {error}", file=sys.stderr, flush=True)
            next_cloud = dt.datetime.now(dt.timezone.utc) + CLOUD_INTERVAL
        local = dt.datetime.now(TZ)
        if (local.hour, local.minute) >= (4, 0):
            if last_backup_day != local.date().isoformat():
                try:
                    archive = create_snapshot(CONFIG, DATA, BACKUP, Path("/run/secrets"))
                    prune_snapshots(BACKUP)
                    print(f"Local snapshot created: {archive.name}", flush=True)
                    last_backup_day = local.date().isoformat()
                    backup_marker.write_text(last_backup_day + "\n", encoding="utf-8")
                except Exception as error:
                    print(f"ERROR backup cycle: {error}", file=sys.stderr, flush=True)
        if (local.hour, local.minute) >= (NETWORK_HOUR, NETWORK_MINUTE):
            if last_network_day != local.date().isoformat():
                try:
                    network_run()
                except Exception as error:
                    print(f"ERROR Network audit: {error}", file=sys.stderr, flush=True)
                last_network_day = local.date().isoformat()
                network_marker.write_text(last_network_day + "\n", encoding="utf-8")
        time.sleep(20)


if __name__ == "__main__":
    main()
