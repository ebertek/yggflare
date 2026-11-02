#!/usr/bin/env bash
# Non-destructive preparation: no tracked checkout writes or legacy env imports.
set -Eeuo pipefail

source_root="${1:?Usage: $0 /home/docker/ygg-compose /home/docker/yggflare}"
home="${2:?Destination directory required}"
source_config="${source_root}/Scripts/cloudflare"

test -r "${source_config}/static-hosts.json"
install -d -m 0700 "${home}/config" "${home}/data" "${home}/backup" "${home}/secrets"
# Optional webhook must still exist as an empty Compose secret file.
if [[ ! -e "${home}/secrets/network_discord_webhook" ]]; then
  install -m 0600 /dev/null "${home}/secrets/network_discord_webhook"
fi

for name in cloudflare-settings.json static-hosts.json \
            static-hosts-reserved.json retained-dns.json retired-devices.json; do
  if [[ -f "${source_config}/${name}" ]]; then
    install -m 0600 "${source_config}/${name}" "${home}/config/${name}"
  fi
done

# One-time migration of the copied inventory; never alter the source checkout.
# Prior legacy port lists denoted TCP candidates in the old audit.
python3 - "${home}/config/static-hosts.json" <<'PY'
import json
import os
from pathlib import Path
import sys

path = Path(sys.argv[1])
document = json.loads(path.read_text(encoding="utf-8"))
for host in document.get("hosts", []):
    old_ports = host.pop("open_ports", [])
    if old_ports:
        new_ports = host.setdefault("ports", [])
        if not isinstance(new_ports, list):
            raise ValueError("Invalid ports metadata in migration target")
        known = {
            (entry.get("protocol", "tcp"), entry["port"])
            for entry in new_ports
        }
        for value in old_ports:
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError("Invalid legacy port in migration source")
            if ("tcp", value) not in known:
                new_ports.append({"protocol": "tcp", "port": value})
                known.add(("tcp", value))
temporary = path.with_suffix(".json.tmp")
temporary.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
os.chmod(temporary, 0o600)
temporary.replace(path)
PY

if [[ -f /home/docker/cloudflare/network-inventory/state.json ]]; then
  install -d -m 0700 "${home}/data/network-inventory"
  install -m 0600 /home/docker/cloudflare/network-inventory/state.json \
    "${home}/data/network-inventory/state.json"
fi

# Do not import or execute old .env files. Populate Compose secrets separately.
printf '%s\n' \
  'Copied JSON configuration and available network inventory state.' \
  'Old cloudflare.env and network-inventory.env were NOT imported.' \
  'Create secrets/cloudflare_api_token and secrets/network_discord_webhook (empty allowed).' \
  'Supply CF_AUTO_APPLY=false and nonsecret Cloudflare identifiers as Compose environment settings.' \
  'Legacy jobs remain enabled. No Cloudflare API calls or Git changes performed.'
