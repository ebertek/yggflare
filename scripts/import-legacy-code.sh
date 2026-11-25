#!/usr/bin/env bash
set -Eeuo pipefail
source_root="${1:?Usage: $0 /home/docker/ygg-compose}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test -r "$source_root/Scripts/cloudflare/cloudflare-live.py"
test -r "$source_root/Scripts/network-inventory/audit.py"
# Historical import helper. Stage files separately; never overwrite maintained source.
stage="$(mktemp -d "$repo_root/legacy-import.XXXXXX")"
mkdir -p "$stage/src/cloudflare" "$stage/src/network_inventory" "$stage/tests/cloudflare" "$stage/tests/network_inventory"
for pair in cloudflare:cloudflare network-inventory:network_inventory; do
  original="${pair%%:*}"
  target="${pair#*:}"
  for file in "$source_root/Scripts/$original/"*.py; do
    case "$(basename "$file")" in
      test_*) cp "$file" "$stage/tests/$target/" ;;
      *) cp "$file" "$stage/src/$target/" ;;
    esac
  done
done
cp "$source_root/Scripts/cloudflare/requirements.txt" "$stage/requirements.txt"
printf 'Staged historical import in %s; review manually, do not commit the staging directory.\n' "$stage"
