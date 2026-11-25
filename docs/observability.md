# Web UI, CLI and Prometheus

[Documentation index](README.md) · [Project README](../README.md)

Enable these values in the service's `environment:`:

```yaml
YGGFLARE_WEB_ENABLED: "true"
YGGFLARE_METRICS_ENABLED: "true"
YGGFLARE_WEB_BIND: "127.0.0.1"
YGGFLARE_WEB_PORT: "8787"
```

The read-only UI is available at `http://127.0.0.1:8787/` on the Docker host.
`YGGFLARE_WEB_BIND` also accepts an explicit local IPv4 or IPv6 address, for example
`10.4.21.1` on a host-side interface. An unassigned address fails at startup;
hostnames are rejected. Keep loopback as the default.

An interface-specific bind reduces accidental exposure on other host addresses,
but **is not authentication or a substitute for firewall rules**. Confirm proxy
and Prometheus reachability before changing a production listener.

The interface includes:

| Route | View |
|---|---|
| `/inventory` | Declared and observed devices, filters and export links |
| `/discovery` | Source evidence, identity confidence and unresolved conflicts |
| `/ports` | Observed services and DNS-SD announcements |
| `/diff` | Declared-versus-observed differences |
| `/drift` | Active findings, pending confirmations and timelines |
| `/reserved` / `/retired` | Display-only catalogs |
| `/cloudflare` | Managed, orphaned and unmanaged resource status |
| `/api/inventory.json` / `/api/inventory.csv` | Inventory exports |

`/metrics` exposes aggregate Prometheus gauges, scan timestamps and Cloudflare
snapshot health. It includes no device labels or credentials and triggers no scans. A
basic scrape configuration:

```yaml
- job_name: yggflare
  scrape_interval: 30s
  static_configs:
    - targets: ["YOUR_HOST_IP:8787"]
```

See the [Grafana dashboard](../dashboards/yggflare.json) for an optional import.

**The UI has no built-in authentication.** Restrict direct TCP access with a firewall
or loopback binding. If you expose it through a proxy, secure the proxy **and**
prevent bypassing it on the LAN. Cloudflare Access on a hostname alone does not
protect the listener.

### Operator views

The Web UI includes **Docker services**, **Topology**, **Cloudflare audit** and
**Operations** tabs. These expose the same bounded, sanitized query results as
MCP, including ingress correlation, job history, backup and notification
evidence. Filter the current page or follow its pagination links; observed
service names and other evidence are untrusted text.

Equivalent container CLI commands (append `--json` for structured output):

```sh
docker exec yggflare yggflare services list
docker exec yggflare yggflare services show SERVICE --project PROJECT
docker exec yggflare yggflare services drift
docker exec yggflare yggflare services dependencies SERVICE
docker exec yggflare yggflare services ingress HOSTNAME
docker exec yggflare yggflare network topology
docker exec yggflare yggflare cloudflare status
docker exec yggflare yggflare cloudflare dns HOSTNAME
docker exec yggflare yggflare cloudflare access HOSTNAME
docker exec yggflare yggflare cloudflare tunnel HOSTNAME
docker exec yggflare yggflare system status
docker exec yggflare yggflare system jobs
docker exec yggflare yggflare system history
docker exec yggflare yggflare backup status
docker exec yggflare yggflare network notifications
```

List views return at most 50 records; use `--offset` with the returned
`next_offset`. These commands read evidence only; the existing
`cloudflare audit`, `network run`, and explicit backup verification commands
retain their separate behavior. Protect direct Web UI access with network
firewall restrictions as well as reverse-proxy authentication.

## Finding lifecycle and evidence quality

The Findings tab and `yggflare network findings` / `network transitions`
read structured history from the saved network scan. Stable IDs are derived
from finding identity, not the notification text. History begins with the
first post-upgrade observation; legacy first-seen dates are not invented.
At most 1,024 findings and 256 transitions are retained; active observations
are prioritized, and truncation is reported. A failed browse does not
advance DNS-SD last-seen timestamps. Missing observations are not proof of
repair; an inventory match requires positive matching observation against
the current declaration. These presentation records never control alerts.

The Operations tab's Source evidence quality view and
`yggflare system evidence --json` distinguish freshness, last collection
verification, completeness and availability. Freshness thresholds reflect
the expected schedule, not guaranteed execution. Optional collectors now
also appear in scheduler history. New aggregate metrics describe finding
history and optional job outcomes.

```sh
docker exec yggflare yggflare network findings --json
docker exec yggflare yggflare network transitions --json
docker exec yggflare yggflare system evidence --json
```

Web pagination links carry the previous result-set fingerprint. CLI users
may pass `--snapshot-id` with `--offset` to reject changed result sets.
This fingerprint is not a frozen server-side snapshot or source timestamp.
Every paged MCP tool also accepts its own optional `snapshot_id` alongside
`offset` and `limit`. Reuse the same filters and restart on a mismatch.
Paged structured output includes the versioned, typed pagination envelope
and source-specific context; row fields remain adapter-specific.

## Coverage and pagination

Prometheus coverage metrics include fixed `yggflare_network_tcp_*` aggregate counts and `yggflare_discovery_<source>_*` invocation, failure, no-reply, parser and limitation evidence for configured sources. They describe the last saved scan, not cumulative counters; unavailable legacy observations are omitted. Metric names use a fixed allowlist, with no device identities or secret data in labels.

Read-only paginated CLI commands accept `--limit 1..50` or `--all` (stable top-level result set, up to 10,000 rows/16 MiB, rejects changed snapshots; does not aggregate nested ingress layers). Examples: `yggflare kuma coverage --all --json`, `yggflare kuma monitors --limit 10 --json`.

New aggregate gauges: `yggflare_komodo_tracked_stack_inputs_{matched,changed,same_reported_revision,unknown}`, `yggflare_kuma_primary_scan_{selection_available,numeric_ipv4_tcp_endpoints,selected_endpoints,not_selected_endpoints}`, `yggflare_probe_configuration_available`, and `yggflare_probe_coverage_{configured_checks,observed_checks,passed_checks,failed_checks,inconclusive_checks}`. Missing evidence is omitted, not zero-filled. Compare freshness and availability gauges first. Scrapes read saved state and the validated local probe allowlist only; no live Docker, Git or network activity. Fixed aggregate names only, no per-device labels.


See [Integrations and service assurance](integrations.md) for source-specific interpretation.

## Assurance dashboard

The [importable Grafana dashboard](../dashboards/yggflare.json) includes current and historical tracked-stack input comparisons, numeric monitor port selection and configured/observed probe outcomes. The evidence availability and freshness panel must be interpreted before outcome counts. Missing series are not zero-filled. Import the JSON into Grafana using the existing Prometheus datasource; the dashboard UID is unchanged. No notification rules or automatic deployment are included.

Dashboard status colors are presentation cues, not alert rules. Raw host counts, scan age and duration are neutral because their normal values depend on deployment and scheduling. Nonzero review candidates and pending events are amber; stale/unavailable evidence and failed probes are red. Unknown and inconclusive results are not failures. Missing data is not converted to zero.
