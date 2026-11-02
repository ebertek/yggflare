#!/usr/bin/env bash
# COPY only: does not alter GitOps checkouts or delete old sources.
set -Eeuo pipefail
source_root="${1:?Usage: $0 /home/docker/ygg-compose /home/docker/yggflare}"
home="${2:?Destination folder required}"
source_config="$source_root/Scripts/cloudflare"
test -r "$source_config/cloudflare.env"
test -r "$source_config/static-hosts.json"
install -d -m 0700 "$home/config" "$home/data" "$home/backup"
for item in cloudflare.env cloudflare-settings.json static-hosts.json \
            static-hosts-reserved.json retained-dns.json retired-devices.json; do
  if [[ -f "$source_config/$item" ]]; then
    install -m 0600 "$source_config/$item" "$home/config/$item"
  fi
done
if [[ -f "$source_root/Scripts/network-inventory/network-inventory.env" ]]; then
  install -m 0600 "$source_root/Scripts/network-inventory/network-inventory.env" \
    "$home/config/network-inventory.env"
fi
if [[ -f /home/docker/cloudflare/network-inventory/state.json ]]; then
  install -d -m 0700 "$home/data/network-inventory"
  install -m 0600 /home/docker/cloudflare/network-inventory/state.json \
    "$home/data/network-inventory/state.json"
fi
# Force dry-run during migration; do not automatically carry forward auto-apply.
sed -i -e '/^[[:space:]]*CF_AUTO_APPLY=/d' "$home/config/cloudflare.env"
printf '\nCF_AUTO_APPLY=false\n' >> "$home/config/cloudflare.env"
echo "Copied private configuration and preserved existing network state; auto-apply disabled."
