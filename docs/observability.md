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

| Route                                        | View                                                          |
| -------------------------------------------- | ------------------------------------------------------------- |
| `/inventory`                                 | Declared and observed devices, filters and export links       |
| `/discovery`                                 | Source evidence, identity confidence and unresolved conflicts |
| `/ports`                                     | Observed services and DNS-SD announcements                    |
| `/diff`                                      | Declared-versus-observed differences                          |
| `/drift`                                     | Active findings, pending confirmations and timelines          |
| `/reserved` / `/retired`                     | Display-only catalogs                                         |
| `/cloudflare`                                | Managed, orphaned and unmanaged resource status               |
| `/api/inventory.json` / `/api/inventory.csv` | Inventory exports                                             |

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

The Findings tab and CLI expose stable finding IDs and bounded history
(1,024 findings, 256 transitions). Truncation is reported; missing
observations do not prove repair. These views never control alerts.

Operations → Source evidence quality distinguishes availability, freshness,
last collection verification and completeness. A fresh snapshot is not
proof that every source or check succeeded.

```sh
docker exec yggflare yggflare network findings --json
docker exec yggflare yggflare network transitions --json
docker exec yggflare yggflare system evidence --json
```

Use source timestamps and the observation window when comparing evidence.
The window is not an atomic multi-source snapshot.

## Coverage and pagination

CLI list views support `--limit 1..50`, `--offset`, `--snapshot-id` and
`--all`. All-pages output is bounded to 10,000 rows/16 MiB and rejects
changed result sets; nested ingress layers are not aggregated.

Prometheus uses fixed, aggregate metrics for:

- Network TCP selection and supplemental discovery execution.
- Collector availability, freshness and scheduler outcomes.
- Komodo tracked inputs, Kuma monitor port selection and probe coverage.

Unavailable outcomes are omitted, not zero-filled. Scrapes read saved
state and the local probe allowlist; they never start live collection.
See [integrations](integrations.md) for interpretation.

## Assurance dashboard

Import the [Grafana dashboard](../dashboards/yggflare.json) using the existing
Prometheus datasource and preserve its UID. The UniFi section shows collection
health, resource counts, uplink evidence, observation age and writer outcomes.
Pending verification and unknown completion are separate from failure.
Check freshness and availability before interpreting counts. The dashboard
does not install alert rules.

Neutral colours represent raw counts, age and duration; amber indicates
review candidates; red indicates stale/unavailable evidence or failed
checks. Unknown and inconclusive results are not failures.

## Exports

JSON preserves projected values. Web/CLI text escapes nonprintable
characters and HTML markup. CSV also neutralizes formula-like cells.
Treat all observed names and values as untrusted data.
