# Scheduling, backups and diagnostics

[Documentation index](README.md) · [Project README](../README.md)

| Job                                          | Default schedule                               |
| -------------------------------------------- | ---------------------------------------------- |
| Cloudflare audit and optional reconciliation | Startup, relevant changes, and every six hours |
| Network scan                                 | Daily at 05:15 UTC                             |
| Backup                                       | Daily at 04:00 UTC; keep 14 snapshots          |

Watchers trigger Cloudflare audits, not LAN scans. Optional integrations
refresh every five minutes; UniFi automatic creation is separately opt-in.
The controller logs job durations and outcomes and handles shutdown signals.

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

## Deployment acceptance

After deploying a reviewed image, check its revision, enabled collectors,
freshness, scheduler outcomes and DNS drift.

```sh
docker exec yggflare yggflare --version
docker exec yggflare yggflare doctor run
docker exec yggflare yggflare cloudflare audit
docker exec yggflare yggflare system evidence --json
docker exec yggflare yggflare system jobs --json
docker exec yggflare yggflare network coverage --json
docker exec yggflare yggflare unifi status --json
docker exec yggflare yggflare backup status --json
```

Check Web UI, MCP tool/group access and Prometheus/Grafana if enabled.

### UniFi presentation parity

Compare the CLI status above with the Web UI at `/unifi?view=status`
and MCP `get_unifi_status`. Compare the aggregate metrics from the
same saved observation (match `observed_at` to the epoch timestamp):

| Status field | Prometheus metric |
| --- | --- |
| `configured` | `yggflare_unifi_configured` |
| `available` | `yggflare_unifi_snapshot_available` |
| `fresh` | `yggflare_unifi_snapshot_fresh` |
| `last_refresh_verified` | `yggflare_unifi_last_refresh_verified` |
| `observed_at` | `yggflare_unifi_last_success_timestamp_seconds` |
| `counts` | `yggflare_unifi_devices`, `yggflare_unifi_clients`, `yggflare_unifi_networks`, `yggflare_unifi_dns` |
| `uplink_counts` | `yggflare_unifi_uplink_*` |

Check `system jobs --json`, Operations jobs and MCP `get_job_status`
for the writer separately; policy counts alone do not prove DNS
verification. Pending DNS verification is not a failed create.
When collection is unavailable, counts and observation timestamps
must be unknown or absent, not zero. Failed refreshes can retain
last-good counts while marking them stale. A verified but aged
snapshot is stale, too. Repeat the comparison if a refresh occurred
between reads; Prometheus scrape times may lag the live endpoint.

UniFi snapshots missing their recorded item count are deliberately
unavailable. The next successful scheduled refresh (or explicit
`unifi refresh`) republishes a complete snapshot.

### Backup acceptance

Verify the latest saved archive and rehearse an isolated restore. Off-host
retention and application recovery require separate checks.

Compare observations against current configuration, not historical counts.
Do not trigger mutations or notifications merely to validate a release.
Keep private acceptance output out of the public repository.
