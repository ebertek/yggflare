#!/usr/bin/env bash
# Non-destructive preparation: no tracked checkout writes or legacy env imports.
set -Eeuo pipefail

source_root="${1:?Usage: $0 /home/docker/ygg-compose /home/docker/yggflare}"
home="${2:?Destination directory required}"
source_config="${source_root}/Scripts/cloudflare"

test -r "${source_config}/static-hosts.json"
install -d -m 0700 "${home}/config" "${home}/data" "${home}/backup" "${home}/secrets"

for name in cloudflare-settings.json static-hosts.json \
            static-hosts-reserved.json retained-dns.json retired-devices.json; do
  if [[ -f "${source_config}/${name}" ]]; then
    install -m 0600 "${source_config}/${name}" "${home}/config/${name}"
  fi
done

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
