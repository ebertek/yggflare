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
MCP HTTP lifecycle and optional tool audit records use the same UTC text/JSON
formatter. SDK and Uvicorn warnings/errors retain severity but omit arbitrary
message and exception text; known fixed lifecycle messages are preserved.
Access logging stays disabled. Standalone MCP stdio diagnostics remain on stderr.

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

### MCP HTTP acceptance

```sh
docker exec yggflare yggflare mcp check --json
```

This checks the running numeric loopback listener, using configured credentials
internally. It verifies missing/invalid-token rejection, Host/Origin rejection
and the exact read-only tool list for each configured credential. It sends no
tool calls and prints no tokens or response bodies. It does not verify a
reverse proxy, external network reachability or client-specific proxy rules.

### Backup acceptance

Verify the latest saved archive and rehearse an isolated restore. Restored
UniFi ownership and retirement records are validated offline; a pending write
is reported, not replayed. The journal's target is checked for internal
consistency, not against a live gateway. Both archive checks enforce member
and decompression limits, validate the gzip trailer, and reject conflicting
or noncanonical paths. An older archive does not establish current ownership;
keep DNS writes disabled during real recovery until the journal is reviewed
against the live gateway.

For off-host acceptance:

- Record the original archive's SHA-256 digest and backup timestamp.
- Retrieve the same archive from the independent backup destination into
  private scratch storage; compare SHA-256 digests.
- Stage the retrieved copy under a distinct `yggflare-*.tar.gz` basename in
  the private backup mount, without overwriting an existing archive.
- Run `backup verify` and `backup restore-test` against that basename.
  These record checks for the retrieved copy, not the original archive.
- Record the result privately and securely remove the temporary copy.

A matching digest and isolated restore establish recoverability of that copy,
not full application recovery, retention policy or future backup availability.
Do not start a restored writer against production as part of this test.

Compare observations against current configuration, not historical counts.
Do not trigger mutations or notifications merely to validate a release.
Keep private acceptance output out of the public repository.

## Unified service retirement review

Collect one service explicitly, then read the saved evidence:

```sh
docker exec yggflare yggflare services retirement-refresh SERVICE
docker exec yggflare yggflare services retirement-plan SERVICE --json
```

SERVICE is a single DNS label or an exact hostname under either configured
zone. The collector reviews the same-label internal and external names;
this is a correlation convention, not proof of a shared service identity.
Only the latest selected service is retained. Web: Docker services → Saved
retirement review. MCP: `get_service_retirement` (inventory, cloudflare and
unifi groups). All three read the same sanitized snapshot. They do not
collect live evidence, access credentials, write ownership or authorize
mutations. The refresh is a separate operator CLI action; it is not scheduled.

Each layer has an independent observation timestamp and explicitly reports
unavailable evidence. A review is fresh for 15 minutes; refresh after any
changes. Grace ages are saved observations, not continuous absence or a
promise of eligibility. Pending state and blockers are review evidence;
use the existing hostname-specific approval commands for adoption and the
existing retirement workflow for deletion. External DNS → Tunnel → Access,
then internal DNS before UniFi, is the recommended review order; no unified
mutation command is provided. A missing resource is not proof of historical
retirement, cache expiry, or absence on other hosts. If the policy and
internal record no longer provide a known IPv4 address, PTR evidence is
unavailable; independently check the previously known address. Aggregate metrics cover
only the selected saved review and expose no resource labels.
