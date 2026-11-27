# Integrations and service assurance

[Documentation index](README.md) · [Project README](../README.md)

## Traefik runtime evidence

Set `YGGFLARE_TRAEFIK_API_URL` to a restricted numeric HTTP(S) LAN or
loopback origin. Do not enable a public or insecure dashboard.

The collector reads paginated HTTP/TCP/UDP routes, services and middleware
every five minutes. HTTPS verifies certificates. No credentials, redirects,
proxies or arbitrary endpoints are supported.

```sh
docker exec yggflare yggflare traefik refresh
docker exec yggflare yggflare traefik status
docker exec yggflare yggflare traefik routes
docker exec yggflare yggflare traefik services
docker exec yggflare yggflare traefik middlewares
```

The Web UI, MCP and metrics read saved evidence. Failed or incomplete
collection retains the last complete snapshot and marks it unverified.
Router host mentions are not proof of rule evaluation or reachability.
See the [Traefik API documentation](https://doc.traefik.io/traefik/reference/install-configuration/api-dashboard/).

## UniFi DNS migration preflight

Configure the local UniFi Network API:

| Variable                      | Purpose                                             |
| ----------------------------- | --------------------------------------------------- |
| `YGGFLARE_UNIFI_API_URL`      | Numeric HTTPS LAN origin                            |
| `YGGFLARE_UNIFI_SITE_ID`      | Site UUID if multiple sites are visible             |
| `YGGFLARE_UNIFI_TLS_NAME`     | Verified certificate name, if different from the IP |
| `YGGFLARE_UNIFI_API_KEY_FILE` | `/run/secrets/unifi_api_key`                        |

Mount the key as a read-only Docker secret, or use a private
`/config/unifi-api-key.txt` (mode 0600) for collection/preview only.
TLS verification is mandatory; install a trusted CA at `/config/unifi-ca.pem`
if required. No redirects, insecure TLS or legacy login.

```sh
docker exec yggflare yggflare unifi plan --json
```

The read-only comparison uses the Cloudflare zone selected by
`YGGFLARE_INTERNAL_DOMAIN`. It reports DNS-only RFC1918 A records, LAN
membership, existing policies and conflicts. Public, special-use,
wildcard and invalid names cannot authorize creation.

A single eligible name defines the expected PTR. For shared IPs, tag
exactly one eligible Cloudflare A record `yggflare:canonical`.
Unresolved aliases, multiple addresses, AAAA/CNAME, forwarding policies
and local conflicts require review. Existing matching policies are not claimed.

See the [UniFi DNS policy API](https://altered-tech.github.io/unifi-openapi-specs/network/v10.3.58/openapi.html#tag/DNS-Policies).

## Review shared-address PTR names

```sh
docker exec yggflare yggflare unifi canonical-review --json
```

For each shared RFC1918 address, the report lists Cloudflare names, the
explicit canonical tag (if present), exact Compose/static-inventory
declarations, local policy conflicts and direct gateway A/PTR observations.
A single unambiguous declared name is a candidate for the
`yggflare:canonical` tag; conflicting tags, ineligible aliases and
out-of-LAN groups require review. The report never selects a name based
on an existing PTR alone.

Review the reported DNS answers before tagging the chosen Cloudflare
record. A suggestion is not a DNS write plan. This command makes no
changes; shared-address creates remain excluded from automatic and
manual apply pending validation of gateway behaviour.

## Verify gateway DNS replies

```sh
docker exec yggflare yggflare unifi verify --json
docker exec yggflare yggflare unifi verify HOSTNAME --json
```

Queries port 53 on the configured gateway directly, using UDP and TCP
fallback. Compares A and PTR replies with Cloudflare expectations, with
no CNAME chasing. The hostname-specific form still considers aliases.

Up to 512 queries per invocation. Exit status: `0` matched, `1` review,
`2` verification unavailable. IPv6 AAAA/PTR assessment uses the separate command below; IPv6 writes are not supported.

## Preview UniFi DNS creates

```sh
docker exec yggflare yggflare unifi reconcile-plan --json
```

A create requires a unique in-LAN Cloudflare A record, no existing UniFi
policy, a matching or absent A reply and an absent PTR reply.

Shared addresses (even tagged canonical aliases), conflicts, timeouts
and out-of-LAN addresses remain excluded. Already matching A/PTR pairs
need no create. The fingerprint binds live inputs and DNS replies.
This command never writes or claims ownership.

## Guarded UniFi DNS pilot

Keep automatic creation disabled for the first pilot. The mounted
`/run/secrets/unifi_api_key` must have read/create permission for the site.

```sh
docker exec yggflare yggflare unifi reconcile-plan HOSTNAME --json
docker exec yggflare yggflare unifi apply HOSTNAME FINGERPRINT
docker exec yggflare yggflare unifi verify HOSTNAME --json
```

Approve one exact hostname and its fresh fingerprint. Pause concurrent
DNS policy edits during the pilot; the API lacks a conditional create.
Yggflare revalidates Cloudflare, UniFi and gateway replies before one POST
with a 300-second TTL. Ownership requires the acknowledged policy ID,
matching live policy and matching A/PTR replies.

### Pending operations

The private `/data/unifi-ownership.json` journal records intent before POST.
After acknowledgement, verification has a ten-minute persisted deadline.
Each invocation checks up to three times, five seconds apart. Pending
verification is retried after 30 seconds; actual failures back off for
at least five minutes.

| Outcome | Behaviour |
| --- | --- |
| Matching policy; A or PTR absent | `pending_dns_verification` (exit 3) |
| Acknowledged write; timeout, transport error or SERVFAIL | Retry verification within the original deadline |
| Matching policy and A/PTR | Record ownership; eligible for notification |
| Conflicting answer or policy, REFUSED, protocol error, failed API read or expired deadline | Fail; retain journal for review |
| Missing create acknowledgement | Block further writes; operator review required |

An unresolved entry blocks new creates. Within the deadline, rerun the
same manual apply invocation to verify the existing policy without another
POST. Manual create cannot recover another hostname or a pending repair or
retirement. Recovery rechecks the current zone and LAN scope before accepting
DNS evidence. DNS replies with an unexpected answer owner, class or type,
a mismatched question/ID or unresolved truncation never prove verification.
Older acknowledged entries receive a deadline on first verification.
Never infer ownership from a matching policy alone or discard the journal.
A create or recreate acknowledgement that reuses an existing policy ID
leaves the intent unacknowledged and blocks further writes.
Transient DNS failures log the query type (A or PTR) and failure category,
without raw replies or exception text. A conflicting reply still blocks
verification even when the other query fails transiently. Pre-write checks
remain fail-closed. Acknowledged retirement also retries transient DNS
failures within its original deadline, without another DELETE.

Pending status appears in Operations jobs, `system jobs` and MCP
`get_job_status`. Prometheus sets
`yggflare_job_unifi_apply_pending_dns_verification` and omits the latest
attempt success metric while pending.

## Opt-in scheduled UniFi creates

After a verified manual pilot, enable:

```yaml
YGGFLARE_UNIFI_APPLY_INTERVAL_SECONDS: "60"
YGGFLARE_UNIFI_AUTO_APPLY: "true"
YGGFLARE_UNIFI_DISCORD_NOTIFY: "true"
```

Automatic scope is the intersection of Cloudflare A records and exact
Compose/static-inventory hostname/IPv4 declarations. Ambiguous,
runtime-only and Cloudflare-only names are excluded. The declarations
are rechecked before creation. Manual approval remains available.

The `unifi_apply` job creates at most one policy per invocation. Its independent
interval defaults to 60 seconds (30–3600 configurable). Pending verification
uses a 30-second retry interval. Other collectors keep their existing schedules.
An unresolved journal entry blocks further writes. Owned policy repair
requires manual approval; retirement requires a separate opt-in.

Discord notifications are optional and sent only after policy and A/PTR
verification. Attempts are journaled; unconfirmed deliveries are not
retried. Disable automatic creation to stop the writer or before rolling
back to an image that does not support the current journal.

## Repair owned UniFi DNS policies

```sh
docker exec yggflare yggflare unifi repair-plan HOSTNAME --json
docker exec yggflare yggflare unifi repair-apply HOSTNAME FINGERPRINT
```

The preview requires a verified ownership entry, one unique in-LAN
Cloudflare A record and an exact Compose/static-inventory declaration.
An unchanged owned policy can be updated to a new address using its
existing ID. A missing owned policy can be recreated if no replacement
or conflicting policy exists. Externally modified policies require review.

Pause concurrent policy edits. The writer rechecks the fingerprint,
live policy list and declaration, then journals intent before one
PUT or POST. Ownership changes only after acknowledgement and matching
A/PTR replies. The previous ownership entry stays intact until verification.
A cached previous forward address is pending, not proof of success.
Unknown outcomes block writes; do not retry mutations manually.

Scheduled reconciliation can recover acknowledged repairs. A manual
repair can also be resumed using the same hostname and fingerprint.
Repairs use the same lock and deadline as creation. Automatic repair
is not enabled. Verify the old reverse address separately.
Older images may reject repair journal entries or repair notification
metadata. Disable the writer before rollback and retain the journal.

## Retire obsolete owned policies

```sh
docker exec yggflare yggflare unifi retirement-plan --json
```

The preview is read-only. To observe and retire eligible policies, enable
both automatic apply and the separate cleanup opt-in:

```yaml
YGGFLARE_UNIFI_AUTO_APPLY: "true"
YGGFLARE_UNIFI_AUTO_CLEANUP: "true"
YGGFLARE_UNIFI_ORPHAN_GRACE_HOURS: "24"
```

Grace is 24–720 hours. Only previously verified automatically created
policies qualify; manual pilots and unmanaged policies are protected.
The hostname and address must be absent from complete Cloudflare DNS
and private Compose/static/retained declarations. Existing aliases,
wildcards, modified policies and local conflicts block retirement.

The writer persists observed orphan age in `/data/unifi-retirement.json`.
Reappearance, changed ownership, invalid evidence or an observation gap
over two hours resets eligibility. This is observed absence, not continuous
proof. Disabling cleanup resets observations on the next automatic cycle.

At most one exact-ID DELETE is issued per invocation after fresh checks.
The shared ownership journal retains the old entry until the API confirms
deletion and both A/PTR queries return absence. Cached old answers remain
pending within the existing deadline. Lost acknowledgement blocks writes;
never repeat a DELETE manually. Retirement notices are best-effort once
after durable verification; an interrupted notice is not replayed.

Keep both private state files. Older images cannot recover pending
retirements; disable the writer before rollback. No cleanup is enabled
by default. Verify the first retirement on the target gateway.

## IPv6 DNS and resolver assessment

```sh
docker exec yggflare yggflare unifi ipv6-review --json
```

The report compares DNS-only Cloudflare AAAA records against UniFi AAAA
policies and direct gateway AAAA/PTR replies. Only addresses in the
explicit `YGGFLARE_DISCOVERY_IPV6_CIDRS` prefixes are queried.
Dual-stack names are supported; shared addresses use a unique
`yggflare:canonical` tag or remain ambiguous. DNS queries use the
configured gateway origin, not necessarily IPv6 transport.

Network detail GET requests expose configured SLAAC, DHCPv6, RA priority
and IPv6 DNS overrides where the API supports them. Automatic resolver
selection does not identify actual advertised servers. An absent field or
failed detail request is unknown, not evidence that IPv6 is disabled.

With `YGGFLARE_DISCOVERY_RA: "true"`, the command also solicits one
bounded RA sample per configured discovery interface. RDNSS addresses,
lifetimes and M/O flags are reported separately from API configuration.
Link-local and external advertised resolvers are observations only,
never new probe targets. No response does not establish absence.

DHCPv6 DNS option 23 is not observed by this command. Before cutover,
inspect DHCPv6 Reply/Information-request exchanges on each representative
client network (UDP ports 546/547) and compare the client's effective
resolver list with RA RDNSS and the intended DNS configuration. For
example, on a Linux client use `resolvectl status` and an authorized
interface-scoped packet capture. Do not renew leases merely to collect
evidence. RA M/O flags do not prove DHCPv6 DNS delivery.

The assessment never changes DNS, DHCPv6 or RA configuration and does
not authorize IPv6 policy creation, updates or retirement.

## Technitium migration procedure

1. Export Technitium zones, reverse records and forwarding settings privately.
   Record DHCPv4/IPv6 DNS advertisements and keep Technitium running.
2. Review UniFi plans, shared IPs, conflicts and out-of-LAN records.
3. Verify A, PTR, AAAA, IPv6 reverse, forwarding and external lookups from
   representative clients against both resolvers.
4. Move a test network or client cohort to UniFi; renew leases and verify
   application resolution before expanding.
5. On failure, restore the original resolver advertisements and verify
   clients again. Retain Technitium and its backup until cutover is accepted.

## UniFi Network evidence

Set `YGGFLARE_UNIFI_COLLECT_ENABLED=true` to refresh every five minutes
using the configured origin, site and key.

```sh
docker exec yggflare yggflare unifi refresh
docker exec yggflare yggflare unifi status --json
docker exec yggflare yggflare unifi devices
docker exec yggflare yggflare unifi clients
docker exec yggflare yggflare unifi networks
docker exec yggflare yggflare unifi dns --json --all
```

CLI, Web UI, MCP and metrics share the saved projection: adopted devices,
connected clients, networks/VLANs and DNS policies. Doctor checks
configuration and freshness. A snapshot expires after 15 minutes; failed
refreshes retain the last complete snapshot.

The collector requests detail for up to 32 adopted devices, resolving
reported parent IDs to visible parent devices. Detail collection stops
starting requests after 60 seconds. Missing, invalid, unavailable and
unchecked uplinks remain distinct. This is controller topology evidence,
not proof of physical cabling, switch ports or client attachment.

DHCP leases and actual DNS replies are outside the collection.
See the [UniFi Network API](https://developer.ui.com/network/v11.0.97).

## Komodo and Uptime Kuma

Both optional collectors run every five minutes when configured and keep
the last complete snapshot on failure. They accept numeric LAN/loopback
origins only. HTTPS verifies certificates; LAN HTTP requires an explicit
`YGGFLARE_KOMODO_ALLOW_HTTP=true` or `YGGFLARE_KUMA_ALLOW_HTTP=true`
opt-in (credentials would traverse the LAN in plaintext). Prefer a restricted
TLS endpoint and do not use an administrator credential.

| Adapter | Origin setting            | Docker secret file setting and fixed path                        |
| ------- | ------------------------- | ---------------------------------------------------------------- |
| Komodo  | `YGGFLARE_KOMODO_API_URL` | `YGGFLARE_KOMODO_API_KEY_FILE=/run/secrets/komodo_api_key`       |
| Komodo  |                           | `YGGFLARE_KOMODO_API_SECRET_FILE=/run/secrets/komodo_api_secret` |
| Kuma    | `YGGFLARE_KUMA_API_URL`   | `YGGFLARE_KUMA_API_KEY_FILE=/run/secrets/kuma_api_key`           |

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
      YGGFLARE_KOMODO_API_KEY_FILE: "/run/secrets/komodo_api_key"
      YGGFLARE_KOMODO_API_SECRET_FILE: "/run/secrets/komodo_api_secret"
      YGGFLARE_KUMA_API_KEY_FILE: "/run/secrets/kuma_api_key"
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

Use the Services → Cross-source ingress evidence view or:

```sh
docker exec yggflare yggflare services assurance HOSTNAME --json
docker exec yggflare yggflare kuma devices --all --json
docker exec yggflare yggflare probes status --json
```

The views correlate saved evidence by exact hostnames, aliases, project/service
identities and explicit addresses. Shared addresses remain ambiguous.
No DNS lookups, live probes or inferred host-mode addresses are used.

### Komodo tracked stack inputs

`tracked_stack_inputs` reports `same_reported_revision`, `matched`,
`changed` or `unknown`. When both revisions exist locally, Komodo refresh
compares tracked stack declarations, directories, linked repositories and
explicit config files. No fetch or checkout occurs.

Revision mismatch alone is not stack drift. Missing history, ambiguous
declarations and unsupported layouts remain unknown.

### Kuma monitoring and probe coverage

- Match basis identifies exact hostname/address or weaker Docker friendly-name
  candidates. Docker, group and push monitors do not imply network endpoints.
- Device coverage uses saved numeric non-container addresses only.
- `target_port_selected` describes the primary IPv4 scan port set.
  `target_port_observed` requires positive open-port evidence.
- `port_selection_summary` compares distinct numeric IPv4 TCP monitor
  endpoints with that global port set, not actual per-device scan coverage.
- `probe_coverage` separates configured checks, observations and expected
  outcomes. HTTP passes only when an explicit expected status matches.

No automatic scan targets or reconciliation inputs are added.

### Evidence limits

All sources have independent timestamps, permissions and collection
limits. Exact matches do not establish ownership, reachability or
authentication. The observation window is informational.

Invalid, partial or duplicate snapshots remain unavailable; failed
refreshes retain the last successful data. Known credential reflections
are rejected before publication. This does not detect every possible
secret or make observed text trustworthy.
