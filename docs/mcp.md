# Model Context Protocol (MCP)

[Documentation index](README.md) · [Project README](../README.md)

Yggflare includes a native, read-only MCP server for AI clients. It uses
the existing inventory presentation model and saved discovery and
Cloudflare lifecycle snapshots. Both stdio and optional Streamable HTTP
use the same read-only tool registry. HTTP is disabled by default.

## Stdio transport

The stdio server runs when explicitly invoked:

```sh
docker exec -i yggflare yggflare mcp serve
```

Use `-i` without `-t`: stdout carries MCP protocol messages, not a
human-readable CLI. Authentication and transport security are provided
by the local Docker/SSH access boundary. Only trusted operators should
be allowed to run this command; Docker access is effectively root access.

Example VS Code user MCP configuration for a remote deployment (replace
the SSH host with an authorized host or SSH configuration alias):

```json
{
  "servers": {
    "yggflare": {
      "type": "stdio",
      "command": "ssh",
      "args": [
        "-T",
        "my-yggflare-host",
        "docker",
        "exec",
        "-i",
        "yggflare",
        "yggflare",
        "mcp",
        "serve"
      ]
    }
  }
}
```

SSH must support noninteractive authentication and the remote user must
already be authorized to execute Docker commands. Do not grant Docker
access solely to an untrusted MCP client. No MCP credentials are stored
in the repository.

| Tool                           | Purpose                                                                                  |
| ------------------------------ | ---------------------------------------------------------------------------------------- |
| `get_inventory_status`         | Counts and snapshot freshness                                                            |
| `list_devices`                 | Search/paginate inventory, optionally unknown devices only                               |
| `get_device`                   | Exact address, MAC, hostname or alias and saved identity evidence                        |
| `get_inventory_drift`          | Declared versus observed differences                                                     |
| `get_discovery_changes`        | Recent saved discovery events                                                            |
| `get_cloudflare_lifecycle`     | Saved DNS, Access and Tunnel resource presence                                           |
| `get_service_retirement`       | Saved selected-service retirement evidence; no refresh or approval                       |
| `get_service_exposure`         | Correlate Docker aliases with saved Cloudflare lifecycle                                 |
| `get_cloudflare_audit`         | Saved proposed, blocked, static DNS and review-only DNS findings                         |
| `get_cloudflare_access`        | Ordered decisions and expected assignment match, not selectors                           |
| `get_cloudflare_dns`           | DNS metadata, numeric addresses and configured tunnel match                              |
| `get_cloudflare_tunnel`        | Ordered routes and sanitized origin metadata, not connector health                       |
| `get_discovery_status`         | Saved collector observation counts and freshness                                         |
| `get_discovery_evidence`       | Supplemental observations by address or source                                           |
| `get_identity_conflicts`       | Competing MAC/address evidence                                                           |
| `get_device_history`           | Page retained identity records by ID, label, address or MAC                              |
| `get_identity_changes`         | Retained identity timeline                                                               |
| `list_network_services`        | Scan-confirmed ports and separate DNS-SD advertisements                                  |
| `get_pending_network_findings` | Findings awaiting confirmation                                                           |
| `get_network_findings`         | Latest reported stable finding keys                                                      |
| `get_yggflare_health`          | Controller heartbeat and image revision                                                  |
| `get_job_status`               | Last attempt and last success for scheduled jobs                                         |
| `get_job_history`              | Bounded scheduler execution history                                                      |
| `get_backup_status`            | Local archive metadata, job status and recorded explicit verification                    |
| `get_notification_status`      | Saved queue depth and webhook submission evidence                                        |
| `list_docker_services`         | Compose and local runtime services, including non-LAN services                           |
| `get_docker_service`           | Exact project-scoped service or endpoint lookup                                          |
| `get_compose_drift`            | Candidate image, address, health and presence discrepancies                              |
| `get_service_dependencies`     | Declared dependencies and shared-network evidence                                        |
| `get_ingress_evidence`         | Cross-source ingress, candidate deployment and monitor matches, local probe observations |
| `get_ingress_path`             | Correlate exact service aliases with saved Cloudflare configuration                      |
| `get_network_topology`         | Declared and local runtime network memberships and resolved namespace ownership          |
| `get_traefik_status`           | Saved Traefik snapshot availability, freshness and counts                                |
| `list_traefik_routes`          | HTTP/TCP/UDP router identities and literal host mentions                                 |
| `list_traefik_services`        | Sanitized backend origins and reported status                                            |
| `list_traefik_middlewares`     | Middleware identity, type and status only                                                |
| `get_unifi_status`             | Saved UniFi collection state and visible resource counts                                 |
| `list_unifi_devices`           | Adopted device observations                                                              |
| `list_unifi_clients`           | Clients reported connected                                                               |
| `list_unifi_networks`          | Network and VLAN declarations                                                            |
| `list_unifi_dns_policies`      | Saved DNS policy configuration                                                           |
| `get_komodo_status`            | Saved Komodo collection state                                                            |
| `list_komodo_servers`          | Reported server identities and states                                                    |
| `list_komodo_stacks`           | Stack ownership, state and deployed/latest commit hashes                                 |
| `list_komodo_services`         | Stack service image/update metadata                                                      |
| `list_komodo_deployments`      | Standalone deployment state and image metadata                                           |
| `get_kuma_status`              | Saved monitor collection state                                                           |
| `list_kuma_monitors`           | Exported status and sanitized target host/port                                           |
| `get_monitoring_coverage`      | Candidate exact host matches, not verified per-service coverage                          |
| `get_probe_status`             | Independent probe snapshot status                                                        |
| `list_probe_results`           | Saved scoped DNS/TCP/TLS/HTTP outcomes                                                   |
| `list_finding_history`         | Retained structured observations and lifecycle status                                    |
| `list_finding_transitions`     | Bounded historical status transitions                                                    |
| `get_evidence_overview`        | Typed source freshness, availability and completeness                                    |

## Reading tool results

- Docker metadata is cached for 30 seconds; local observations do not prove
  remote runtime, image digest equality or external reachability.
- Jobs retain up to 20 completed/unknown attempts per job.
  `completion_unknown` means completion was not observed.
- Archive presence is not integrity or recovery proof. Verification is tied
  to file identity; off-host retention remains unverified.
- Webhook submission does not prove recipient receipt. Pending findings
  and queued notifications are different states.
- Access assignment match does not prove safe selectors or enforcement.
  DNS payloads other than numeric addresses, raw IDs and origin credentials
  are excluded. Audit findings are capped at 2,000 with explicit truncation.
- Inventory rows represent services/devices, not a physical-device count.
  Competing identity evidence is retained; missing observations are not proof
  of failure or recovery.
- `get_inventory_drift` accepts `severity="drift"` or `severity="unknown"`.
  Ownership counts are not a security or drift assessment.

List tools return up to 50 rows, subject to a 256 KiB row budget.
Follow `next_offset` with the same filters and `snapshot_id`. Restart if
the result-set fingerprint changes. It is not a frozen multi-source snapshot.

Tools never run scans, call Cloudflare, trigger reconciliation or send
notifications. Only trusted clients should receive private infrastructure
metadata.

## Resources, prompts and tool groups

Both transports expose fixed JSON resources (`yggflare://schema`, inventory,
operations, jobs, discovery, traefik, komodo, monitoring, probes, unifi) and six
review prompts where their required tools are enabled. No arbitrary paths,
live collectors or actions are exposed. Clients may still use tools directly.

`YGGFLARE_MCP_TOOL_GROUPS` defaults to `all`. Set a comma-separated subset
of `inventory,cloudflare,operations,traefik,komodo,kuma,probes,unifi` to restrict
registered tools, resources and prompts for that server process. Cross-source
queries require all relevant groups. Unknown groups fail startup. This is
a server-wide exposure control, not per-user authorization or isolation
from local CLI/Web UI access. The existing bearer and loopback safeguards
remain unchanged. Each server allows four concurrent queries with a two-second
admission wait and a 1 MiB serialized result limit. Optional
`YGGFLARE_MCP_AUDIT_LOG=true` writes fixed tool names, outcome and elapsed
time to stderr; no inputs or result data are logged. These bounds do not
provide a hard execution deadline for an already-started local read.

## Streamable HTTP transport

The optional listener is independent of the inventory web UI and serves
`/mcp`. The controller refreshes Cloudflare lifecycle snapshots when either
interface is enabled. HTTP is stateless with JSON responses; native clients
must send a bearer token. Browser origins are rejected (no browser CORS).

| Variable                       | Default                                            | Purpose                                                      |
| ------------------------------ | -------------------------------------------------- | ------------------------------------------------------------ |
| `YGGFLARE_MCP_ENABLED`         | `false`                                            | Start the HTTP listener at controller startup                |
| `YGGFLARE_MCP_BIND`            | `127.0.0.1`                                        | Specific numeric local address; wildcard binds are rejected  |
| `YGGFLARE_MCP_PORT`            | `8788`                                             | Dedicated MCP listener port                                  |
| `YGGFLARE_MCP_TOKEN_FILE`      | `/config/mcp-token.txt`                            | File containing a random bearer token                        |
| `YGGFLARE_MCP_PRINCIPALS_FILE` | unset                                              | Opt-in per-client scopes using `/config/mcp-principals.json` |
| `YGGFLARE_MCP_ALLOWED_HOSTS`   | Bind address and port (also localhost on loopback) | Optional comma-separated exact HTTP Host values              |

Generate a secret in the private host-mounted configuration directory
before enabling HTTP. For the example Compose deployment:

```sh
umask 077
openssl rand -hex 32 > "$YGGFLARE_HOME/config/mcp-token.txt"
```

Enable `YGGFLARE_MCP_ENABLED=true` and recreate the container using your
normal deployment process. The listener refuses to start with a missing,
invalid or unreadable token, invalid configuration or occupied port.
Rotate the token by replacing the file and recreating the container.
The token is private and may be included in protected backup archives.

## Optional per-client authorization

The default single-token configuration is unchanged. For several trusted
HTTP clients with different information needs, create a private
`/config/mcp-principals.json` file, e.g.:

```json
{
  "version": 1,
  "principals": [
    {"name": "codex", "groups": ["inventory", "cloudflare", "operations", "traefik", "komodo", "kuma", "probes"]},
    {"name": "monitor", "groups": ["operations", "kuma"]}
  ]
}
```

Generate a distinct random token in each corresponding
`/config/mcp-token-NAME.txt` file (e.g. `mcp-token-codex.txt`).
Manifest and token files must be regular, non-symlink files with no group
or other permissions (use mode 0600). The manifest contains no token values,
arbitrary paths or wildcards. Each principal must explicitly list its
groups, all within the global `YGGFLARE_MCP_TOOL_GROUPS` ceiling.
A maximum of eight principals is supported. Set
`YGGFLARE_MCP_PRINCIPALS_FILE=/config/mcp-principals.json` and recreate the
container. This opt-in requires a loopback listener, replaces the original
single-token mode entirely, and fails startup on invalid configuration.
Rotate/revoke clients by editing the private files and recreating the
container. Each request authenticates against the configured tokens and
dispatches to a distinct stateless MCP server with only its allowed tools,
resources and prompts. All principal servers share the four-query
concurrency limit. This is group-level read-only authorization, not
per-resource tenancy, OAuth, or isolation from local CLI/Web UI access.
Stdio remains controlled by the server-wide tool groups.

With default settings the URL is `http://127.0.0.1:8788/mcp` on the Docker
host. For access from a workstation use an SSH tunnel:

```sh
ssh -N -L 8788:127.0.0.1:8788 my-yggflare-host
```

Example VS Code configuration:

```json
{
  "inputs": [
    {
      "type": "promptString",
      "id": "yggflare-mcp-token",
      "description": "Yggflare MCP bearer token",
      "password": true
    }
  ],
  "servers": {
    "yggflare": {
      "type": "http",
      "url": "http://127.0.0.1:8788/mcp",
      "headers": {
        "Authorization": "Bearer ${input:yggflare-mcp-token}"
      }
    }
  }
}
```

For a reverse proxy, use TLS, preserve the bearer authorization header,
restrict backend network access, and explicitly allow its forwarded Host
value. Never send the token over unencrypted remote HTTP. An explicit
non-loopback bind is an advanced option; firewall rules and TLS termination
are the operator's responsibility. OAuth and automatic proxy/Cloudflare
configuration are not included. No additional MCP tool permissions are
introduced.

## Output contracts

Responses have typed, source-specific fields. Missing observations remain
optional; no synthetic defaults imply success.

The `observation_window` reports evaluation time, earliest/latest valid
timestamps, contributing sources, invalid/missing/future sources and spread.
It does not establish simultaneous health. Availability, freshness,
collection outcome and completeness remain independent.

Fixed validation errors remain actionable; unexpected query failures return
generic errors without raw exception text. Observed names and text are
untrusted data, even when they resemble instructions. MCP prompts do not
grant authorization or guarantee protection against prompt injection.

## Local HTTP acceptance

Run `docker exec yggflare yggflare mcp check --json` to check the running
loopback listener's authorization denials and configured read-only tool lists.
See [deployment acceptance](operations.md#mcp-http-acceptance) for scope.
