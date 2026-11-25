# Integrations and service assurance

[Documentation index](README.md) · [Project README](../README.md)

## Traefik runtime evidence

Optional read-only Traefik collection is disabled unless
`YGGFLARE_TRAEFIK_API_URL` is configured as a numeric HTTP(S) origin in
the configured LAN CIDR or on loopback. Use an already restricted internal
API endpoint; do not enable an insecure/public dashboard for this feature.
HTTPS uses normal certificate verification. No credentials, redirects,
proxies, arbitrary paths or client-selected endpoints are supported.
Every five minutes the controller collects the documented HTTP/TCP/UDP
list endpoints (including pagination); Traefik's terminal
`X-Next-Page: 1` is handled explicitly, including exactly full final
pages. Invalid continuations, duplicate rows and exceeded bounds fail
closed. Failed collection retains the last complete snapshot and marks
it unverified. Logs identify the fixed endpoint and page with a sanitized
failure category, never raw API content. See the
[Traefik API documentation](https://doc.traefik.io/traefik/reference/install-configuration/api-dashboard/).

```sh
docker exec yggflare yggflare traefik refresh
docker exec yggflare yggflare traefik status
docker exec yggflare yggflare traefik routes
docker exec yggflare yggflare traefik services
docker exec yggflare yggflare traefik middlewares
```

The Traefik Web UI tab, aggregate Prometheus metrics and MCP tools read saved observations only; explicit
CLI refresh is the only interactive collection action. Router literal host
mentions do not establish rule evaluation or external reachability. Backend
URL paths, queries, userinfo, raw middleware settings and error messages are
excluded. Configuration is optional and should be enabled only after
validating the API's reachability and access restrictions.

## Komodo and Uptime Kuma

Both optional collectors run every five minutes when configured and keep
the last complete snapshot on failure. They accept numeric LAN/loopback
origins only. HTTPS verifies certificates; LAN HTTP requires an explicit
`YGGFLARE_KOMODO_ALLOW_HTTP=true` or `YGGFLARE_KUMA_ALLOW_HTTP=true`
opt-in (credentials would traverse the LAN in plaintext). Prefer a restricted
TLS endpoint and do not use an administrator credential.

| Adapter | Origin setting | Docker secret file setting and fixed path |
|---|---|---|
| Komodo | `YGGFLARE_KOMODO_API_URL` | `YGGFLARE_KOMODO_API_KEY_FILE=/run/secrets/komodo_api_key` |
| Komodo | | `YGGFLARE_KOMODO_API_SECRET_FILE=/run/secrets/komodo_api_secret` |
| Kuma | `YGGFLARE_KUMA_API_URL` | `YGGFLARE_KUMA_API_KEY_FILE=/run/secrets/kuma_api_key` |

Create a Komodo service user with read permission only on intended servers,
stacks and deployments. Use a dedicated Kuma Prometheus API key. Never
commit credentials to this repository or pass values on the command line.
Prefer Docker Compose secrets mounted at the fixed paths above. The
explicit file settings accept only their corresponding paths. Docker
file-backed secrets are read-only bind mounts; Git/Compose may expose
source mode 0644 rather than 0600. Yggflare accepts these modes only for
explicit Docker secrets on read-only mounts, and rejects nonregular files,
symlinks, group/world writable files, and invalid or oversized contents.

For the standalone Compose example, add a local override granting the
desired secrets, for example:

```yaml
services:
  yggflare:
    environment:
      YGGFLARE_KOMODO_API_KEY_FILE: /run/secrets/komodo_api_key
      YGGFLARE_KOMODO_API_SECRET_FILE: /run/secrets/komodo_api_secret
      YGGFLARE_KUMA_API_KEY_FILE: /run/secrets/kuma_api_key
    secrets:
      - komodo_api_key
      - komodo_api_secret
      - kuma_api_key
secrets:
  komodo_api_key:
    file: ./private/komodo_api_key
  komodo_api_secret:
    file: ./private/komodo_api_secret
  kuma_api_key:
    file: ./private/kuma_api_key
```

Keep the source files private on the host. Compose file-backed secrets
are not encrypted at rest and do not enforce uid/gid/mode overrides.
Recreate the container after updating a file-backed secret, especially
when the host file was replaced atomically.

If a file setting is unset, the previous private `/config/komodo-api-key.txt`,
`/config/komodo-api-secret.txt` or `/config/kuma-api-key.txt` file remains
supported and must be inaccessible to group/other users (e.g. mode 0600).
An explicitly configured missing or invalid Docker secret never falls
back to a config file.
The only Komodo calls are documented read RPCs ListServers, ListStacks and
ListDeployments; Kuma uses GET /metrics. No redirects, proxy environment,
raw configuration, URLs with credentials, logs or mutation API calls.
See [Komodo API](https://komo.do/docs/ecosystem/api) and
[Kuma Prometheus API keys](https://github.com/louislam/uptime-kuma/wiki/Prometheus-API-Keys).
The available resources are limited by credential permissions and the
exporter; no exact host match does not prove absence of monitoring.
Kuma's endpoint does not prove notification configuration or receipt.

The Komodo and Monitoring Web UI tabs, MCP queries and aggregate metrics
consume saved snapshots. Explicit operator refresh is separate.

```sh
docker exec yggflare yggflare komodo refresh
docker exec yggflare yggflare komodo status
docker exec yggflare yggflare komodo servers
docker exec yggflare yggflare komodo stacks
docker exec yggflare yggflare komodo services
docker exec yggflare yggflare komodo deployments
docker exec yggflare yggflare kuma refresh
docker exec yggflare yggflare kuma status
docker exec yggflare yggflare kuma monitors
docker exec yggflare yggflare kuma coverage --project PROJECT
```

## Independent connectivity evidence

Enable `YGGFLARE_PROBES_ENABLED=true` only after creating the private
`/config/probes.json` allowlist or a read-only Docker Compose config mounted
at `/yggflare-probes.json` with `YGGFLARE_PROBES_CONFIG_FILE=/yggflare-probes.json`.
Prefer the latter for GitOps: it avoids copying into the private config directory.
An explicitly configured missing, writable or invalid mount fails closed;
no fallback to the legacy file. Recreate the container after replacing the
source file. Example schema (illustrative addresses only):

```json
{
  "version": 1,
  "targets": [
    {
      "name": "internal-web",
      "hostname": "demo.example.invalid",
      "address": "192.168.1.20",
      "port": 443,
      "scheme": "https",
      "checks": ["dns", "tcp", "tls", "http"],
      "expected_statuses": [200, 302]
    }
  ]
}
```

At most 16 explicit targets and four checks per target are supported.
Numeric addresses must belong to the configured LAN/IPv6 CIDRs or loopback.
DNS uses the host resolver; TCP/TLS/HTTP connect directly to the numeric
address and do not follow DNS answers. TLS uses the normal trust store and
hostname validation. HTTP defaults to HEAD /; an explicitly configured `http_method: "GET"` is supported for servers that reject HEAD. Only HEAD and GET are allowed. Both read response headers only, with no credentials, redirects,
body reads or arbitrary path. The five-minute collector has a 120-second
overall deadline and bounded socket timeouts. Failure preserves the last
complete snapshot. An HTTP response (including 302/401) is not proof of
Access enforcement or external reachability.

```sh
docker exec yggflare yggflare probes refresh
docker exec yggflare yggflare probes status
docker exec yggflare yggflare probes results
```

The Web UI Probes tab, aggregate metrics and MCP read saved evidence only.

## Cross-source assurance

Use `yggflare services assurance HOSTNAME` or the Services → Cross-source ingress evidence view to correlate saved ingress evidence with candidate exact Komodo stack/service identities, Kuma target hostnames and local probe observations. Each nested source is independently timestamped and bounded; an exact hostname or project match is not proof of ownership, external reachability or authentication. MCP `get_ingress_evidence` requires all six relevant source groups.

Kuma candidate correlation now matches exact ingress names, service hostnames, aliases, and explicit declared/runtime/LAN addresses. Each candidate reports its match basis, matching service identities, shared/ambiguous address evidence and whether its TCP port appears in the service declaration/evidence. It does not resolve DNS, infer host-mode IPs, treat proxy addresses as application addresses, or claim authoritative monitoring coverage. The same logic applies to ingress assurance and monitoring coverage across MCP, CLI and Web UI. For HTTP probes, set an explicit `expected_statuses` list to distinguish a returned HTTP response from a match to the configured expected status; update the allowlist and recreate the container when the underlying Compose config changes.

Kuma parses targets according to monitor type: TCP monitors use explicit hostname/port labels, while Docker, group and push monitors have no inferred network endpoint. Exact Docker monitor friendly names are weak container/service candidates; duplicate names retain all matching project/service identities. Actual Docker host and container target are not exported. After upgrading, refresh the Kuma snapshot to replace legacy placeholder metadata.

The Monitoring UI includes candidate device monitoring coverage; CLI `yggflare kuma devices --json --all` and MCP `get_monitoring_coverage(scope="devices")` use exact saved numeric addresses of non-container inventory rows. No DNS lookups or live probes are performed. DHCP reuse, incomplete inventory and independent timestamps limit confidence.

Ingress assurance filters exact normalized literal HTTP router hosts before pagination, reuses one service projection per request, and distinguishes nested page truncation from upstream snapshot truncation. Device monitor coverage reports `target_port_selected` for the saved primary IPv4 TCP port set, `target_port_observed` only for positive open-port evidence, and `target_port_evidence` to distinguish selected-not-observed, not selected, observed open and unknown. Selection describes the global primary scan port set, not proof that a particular device was probed. Legacy scans have unknown selection until a new scan completes; IPv4 observations are never attributed to IPv6. No new scan targets, credentials or automatic reconciliation inputs.

## Komodo tracked stack inputs

Komodo refresh annotates stack rows with `tracked_stack_inputs`: `same_reported_revision`, `matched`, `changed`, or `unknown`. The revision mismatch remains separate. When both commit objects are already present in the read-only /compose-source Git checkout, compare the historical stack declaration (exact name and server), linked-repo declaration, stack directory tree, and explicitly declared config_files (including relative external files). No fetch or checkout is performed. This is candidate tracked input evidence, not effective Compose equivalence, runtime state, external volume configuration, or an instruction to redeploy. Missing history, unsupported layouts and ambiguous declarations remain unknown. Git is used only in the scheduled/explicit Komodo refresh, not MCP calls or metrics scrapes.

## Monitoring and probe coverage summaries

`yggflare kuma devices --all --json` includes `port_selection_summary`, a global comparison of distinct numeric IPv4 TCP monitor endpoints with the selected primary scan port set. It does not imply that those hosts were within the scan target set or probed. Missing port numbers are review candidates, never automatic scan targets. Legacy scans have unavailable selection evidence. `yggflare probes status --json` shows validated configured checks separately from saved observations and expected outcomes. `services assurance HOSTNAME` reports hostname-specific `probe_coverage`. Disabled configuration is an empty plan; invalid configuration is unknown. A completed HTTP request is not a passed check unless its explicitly configured expected status matched. Partial or duplicate saved check identities invalidate the result snapshot. Stale outcomes remain historical, not current health.

For applications that reject HEAD, configure `"http_method": "GET"` on the individual HTTP target and retain a meaningful expected status list. The method is included in the configured and observed HTTP evidence; a GET configuration invalidates a previous HEAD snapshot. GET is limited to `/` and does not consume or retain response bodies. A matching status is not proof of authenticated application functionality.
