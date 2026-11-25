# Scheduling, backups and diagnostics

[Documentation index](README.md) · [Project README](../README.md)

| Job | Default schedule |
|---|---|
| Cloudflare audit and optional reconciliation | Startup, relevant changes, and every six hours |
| Network scan | Daily at 05:15 UTC |
| Backup | Daily at 04:00 UTC; keep 14 snapshots |

Watchers trigger Cloudflare audits, not new LAN scans. The controller logs job names,
durations and outcomes, and handles shutdown signals without requiring Docker init.

```sh
docker logs --tail 100 yggflare
docker exec yggflare yggflare --version
docker exec yggflare yggflare doctor run
docker exec yggflare yggflare cloudflare audit
docker exec yggflare yggflare network status
docker exec yggflare yggflare network status --details
docker exec yggflare yggflare network run
docker exec yggflare yggflare network discord-test
docker exec yggflare yggflare backup verify ARCHIVE.tar.gz
docker exec yggflare yggflare backup restore-test ARCHIVE.tar.gz
```

`doctor` validates local dependencies and mounted secrets without making Cloudflare
changes. `network status` reads the last completed scan, showing pending alerts and
identity counts without scanning, mutating state or sending notifications. Use
`network status --details` to inspect unresolved MAC conflicts or `--json` for
structured output. `network run` saves observations and may send alerts.
`discord-test` sends a deliberate test notification.

Backups may contain **plaintext credentials**. Restrict access and retain an off-host
copy. `verify` checks an archive without extracting it; `restore-test` extracts into
isolated temporary storage without replacing live data.
