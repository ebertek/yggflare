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

CONFIG = Path(os.getenv("YGGFLARE_CONFIG", "/config"))
DATA = Path(os.getenv("YGGFLARE_DATA", "/data"))
SOURCE = Path(os.getenv("YGGFLARE_SOURCE", "/compose-source"))
TZ = ZoneInfo(os.getenv("TZ", "Europe/Stockholm"))
CLOUD_INTERVAL = dt.timedelta(hours=6)
NETWORK_HOUR, NETWORK_MINUTE = 5, 15


def read_env(path):
    """Minimal KEY=VALUE parser; no command execution or shell expansion."""
    result = {}
    if not path.is_file():
        raise FileNotFoundError(f"Required private config absent: {path.name}")
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:]
        name, delimiter, value = line.partition("=")
        if not delimiter or not name.replace("_", "").isalnum():
            raise ValueError("Unsupported environment assignment syntax")
        value = value.strip()
        if value.startswith(("'", '"')) and value.endswith(value[0]):
            value = value[1:-1]
        result[name.strip()] = value
    return result


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
    values = read_env(CONFIG / "cloudflare.env")
    auto = values.get("CF_AUTO_APPLY", "false")
    if auto not in ("true", "false"):
        raise ValueError("CF_AUTO_APPLY must be exactly true or false")
    aliases = {
        "CLOUDFLARE_API_TOKEN": ("CLOUDFLARE_API_TOKEN", "CF_API_TOKEN"),
        "CLOUDFLARE_ACCOUNT_ID": ("CF_ACCOUNT_ID", "CLOUDFLARE_ACCOUNT_ID"),
        "CLOUDFLARE_TUNNEL_ID": ("CF_TUNNEL_ID", "CLOUDFLARE_TUNNEL_ID"),
        "CLOUDFLARE_EBI_ZONE_ID": ("CF_ZONE_EBI_NU", "CLOUDFLARE_EBI_ZONE_ID"),
        "CLOUDFLARE_YGG_ZONE_ID": ("CF_ZONE_YGG_NU", "CLOUDFLARE_YGG_ZONE_ID"),
    }
    env = os.environ.copy()
    # Ignore inherited values; the on-volume private file is authoritative.
    env.pop("CF_AUTO_APPLY", None)
    for variable, names in aliases.items():
        env[variable] = next((values[n] for n in names if values.get(n)), "")
    if not env["CLOUDFLARE_API_TOKEN"]:
        raise RuntimeError("Cloudflare API token missing")
    env["CF_AUTO_APPLY"] = auto
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
    env = os.environ.copy()
    optional = CONFIG / "network-inventory.env"
    if optional.is_file():
        env["YGG_NETWORK_DISCORD_WEBHOOK_URL"] = read_env(optional).get(
            "YGG_NETWORK_DISCORD_WEBHOOK_URL", ""
        )
    else:
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
