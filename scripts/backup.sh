#!/usr/bin/env bash
set -Eeuo pipefail
home="${1:?Usage: $0 /home/docker/yggflare}"
mkdir -p "$home/backup"
stamp="$(date -u +'%Y%m%dT%H%M%SZ')"
umask 077
tar -C "$home" -czf "$home/backup/yggflare-$stamp.tar.gz" config data
echo "Created restricted backup archive in separate backup directory."
echo "IMPORTANT: replicate to off-host protected storage; backup is NOT encrypted."
