#!/usr/bin/env bash
set -Eeuo pipefail
source_root="${1:?Usage: $0 /home/docker/ygg-compose}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test -r "$source_root/Scripts/cloudflare/cloudflare-live.py"
test -r "$source_root/Scripts/network-inventory/audit.py"
mkdir -p "$repo_root/src/cloudflare" "$repo_root/src/network-inventory"
cp "$source_root/Scripts/cloudflare/"*.py "$repo_root/src/cloudflare/"
cp "$source_root/Scripts/cloudflare/requirements.txt" "$repo_root/src/cloudflare/"
cp "$source_root/Scripts/network-inventory/"*.py "$repo_root/src/network-inventory/"
echo 'Imported legacy source. Review the imported sources, then commit them to the new repository.'
