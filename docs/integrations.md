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

## UniFi DNS migration preflight

The explicit local CLI preflight compares live Cloudflare internal-zone
records with local UniFi Network DNS policies. This command performs a live,
GET-only comparison independently of the saved UniFi evidence.

Configure a numeric HTTPS LAN origin in `YGGFLARE_UNIFI_API_URL`.
Set `YGGFLARE_UNIFI_SITE_ID` to the site UUID if more than one site is visible.
Use a dedicated least-privilege API key in the private
`/config/unifi-api-key.txt` (mode 0600), or explicitly mount a read-only
Docker secret at `/run/secrets/unifi_api_key` and set
`YGGFLARE_UNIFI_API_KEY_FILE=/run/secrets/unifi_api_key`.
Never paste credentials into command arguments, logs or public commits.
TLS verification is mandatory; supply a trusted CA at
`/config/unifi-ca.pem` when needed and set
`YGGFLARE_UNIFI_TLS_NAME` to the certificate's verified name if it differs
from the numeric address. No redirects, insecure TLS or legacy login.

```sh
docker exec yggflare yggflare unifi plan
docker exec yggflare yggflare unifi plan --json
```

The live Cloudflare zone selected by `YGGFLARE_INTERNAL_DOMAIN` is the
source for this comparison, including records not managed by Yggflare.
Compose and the private static inventory remain upstream declarations;
this command does not synthesize missing DNS records from either source.
Unproxied, unambiguous single A records in the exact RFC 1918 blocks
(`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) are candidates.
Loopback, link-local, CGNAT, documentation and other special-use ranges
are not RFC 1918. The report identifies whether each single address is
within the configured LAN CIDR; out-of-LAN private candidates require
explicit scope review before any future write. The configured LAN CIDR
still limits the UniFi API destination; discovery scope is unchanged.
The report includes all valid numeric A values for ambiguous names and
counts excluded A records with wildcard, invalid or out-of-zone names.
Aliases sharing an address, multiple A records, additional AAAA/CNAME
records, LAN boundary addresses, local conflicts and forwarding/wildcard
policies require review. Existing matching policies are not claimed. No
other policies are changed or deleted.
The report includes one reverse expectation per RFC1918 address in
`reverse_expectations`. A single eligible name becomes the expected PTR
target. For a shared address, tag exactly one eligible Cloudflare A record
`yggflare:canonical`. A shared address with conflicting tags, no tag, or
an ineligible alias remains unresolved. This selects a verification target
and preserves the existing preflight conflict statuses.

See the [UniFi DNS policy API reference](https://altered-tech.github.io/unifi-openapi-specs/network/v10.3.58/openapi.html#tag/DNS-Policies).

## Verify gateway DNS replies

```sh
docker exec yggflare yggflare unifi verify --json
docker exec yggflare yggflare unifi verify HOSTNAME --json
```

The explicit verification command loads the desired internal A records
from Cloudflare and queries port 53 directly at the validated numeric UniFi
gateway address. It uses the returned A set and one PTR lookup per distinct
IPv4 address, with TCP fallback for truncated UDP replies. There are no DNS
requests to record addresses, no search suffixes, and no CNAME chasing.
The optional exact hostname must be eligible in the internal zone, and its
PTR expectation still considers all Cloudflare aliases for that IP.
Each invocation supports up to 512 queries. On larger inventories, use the
exact-hostname form. An unselected PTR can be observed but cannot pass.
Exit status 0 means all selected replies match, 1 means at least one
result requires review, and 2 means verification could not run. The report
covers IPv4 A and PTR answers. AAAA records, IPv6 PTRs, and dual-stack
policy reconciliation require separate validation.

## Preview UniFi DNS creates

```sh
docker exec yggflare yggflare unifi reconcile-plan --json
```

The create preview reads the live Cloudflare zone and selected UniFi site's
policy list. It checks direct gateway replies for unique IPv4 candidates
inside the configured LAN. Only an absent UniFi policy, a matching or
absent gateway A answer, and an absent PTR answer yield a proposed create.
Existing policies, shared addresses (including tagged canonical aliases),
forwarding or wildcard conflicts, conflicting replies, timeouts, and
out-of-LAN addresses remain outside the proposed operations. An already
matching A and PTR pair requires no create.

Use the fingerprint to identify the exact preview reviewed. It binds the
live inputs, target and DNS replies, and can change when any of those
change. The command performs a dry run and leaves ownership and live DNS
unchanged. Review the counts and operations before any future rollout.

## Guarded UniFi DNS pilot

Keep automatic creates disabled for the pilot. The existing UniFi key
must be able to read and create DNS policies on the target site. Creates
require the read-only Compose secret at `/run/secrets/unifi_api_key`,
selected by `YGGFLARE_UNIFI_API_KEY_FILE`. The writer reuses this key
for the documented DNS policy POST with a 300-second TTL. Collection,
previews, and presentation continue to make read-only requests.

On the approved rollout, choose one in-scope hostname and review the exact
operation and fingerprint. Pause concurrent manual or automated DNS policy
edits on that site during the pilot. The API does not provide a conditional
create in the documented request schema.

```sh
docker exec yggflare yggflare unifi reconcile-plan HOSTNAME --json
docker exec yggflare yggflare unifi apply HOSTNAME FINGERPRINT
docker exec yggflare yggflare unifi verify HOSTNAME --json
```

`apply` recomputes the hostname-specific fingerprint from live state and
rechecks the Cloudflare, UniFi and DNS inputs immediately before the
single create. An old or bulk fingerprint cannot authorize a pilot.
If inputs or replies change, review a fresh preview. Existing policies
are left in place. Ownership requires a persisted create acknowledgement,
a matching current policy ID and values, and matching A and PTR replies.

The private `/data/unifi-ownership.json` journal records intent before
sending the request. Keep it with persistent state and include it in
recovery procedures. If the policy was acknowledged but DNS is still
settling, rerun the same apply invocation after the cache clears. That
invocation only verifies and records the pending policy. If the response
was lost before Yggflare could persist its policy ID, future creates stay
blocked. Compare the journal and actual UniFi policies before deciding
how to recover. A matching policy without a persisted acknowledgement
does not establish ownership. Preserve the journal and involve the
operator for any state repair.

## Opt-in scheduled UniFi creates

After a verified manual pilot, set `YGGFLARE_UNIFI_AUTO_APPLY=true` and
`YGGFLARE_UNIFI_AUTO_HOSTS` to a comma-separated list of up to 128 exact,
reviewed internal hostnames. To keep deployment names in private GitOps,
mount a read-only Compose config at `/yggflare-unifi-auto-hosts.txt`
with one hostname per line and select it with
`YGGFLARE_UNIFI_AUTO_HOSTS_FILE=/yggflare-unifi-auto-hosts.txt`. Select
either the file or the inline list. The controller proposes and revalidates at
most one eligible create per five-minute cycle using the same safety
checks and journal. Its outcome appears as the `unifi_apply` scheduled
job. Existing ownership blocks recreation if a previously created policy
disappears or drifts. MCP, the Web UI, and Prometheus remain read-only.
Automatic creates default to off. Disable the opt-in to stop the
scheduled writer.

Set `YGGFLARE_UNIFI_DISCORD_NOTIFY=true` to send a notice via the
existing Yggflare Discord webhook after a new policy is verified. The
notice includes the hostname, IPv4 address, and TTL. Verification after
a delayed PTR queues the same notice as immediate success. Existing
records and older journal entries are not replayed. Yggflare journals the
attempt before sending and does not resubmit an unconfirmed request,
because Discord webhooks lack an idempotency key. Check the scheduler log
for unconfirmed delivery. To roll back to a build that predates the
notification journal fields, disable automatic creates first and retain
the current journal.

## Technitium migration procedure

1. Save a private export of the existing Technitium zones, reverse records,
   forwarding rules and resolver addresses. Record the current DHCPv4 and
   IPv6 resolver settings and how to restore them. Keep Technitium running.
2. Review `unifi plan --json` and reconcile the expected scope against the
   Cloudflare zone. Resolve shared addresses explicitly and review local
   policy conflicts and out-of-LAN records. Preserve unmanaged policies.
3. Pilot a small set of operator-approved records while clients still use
   Technitium. Run `unifi verify HOSTNAME --json`, then verify from a client
   on each affected network that both resolvers yield the expected A and
   PTR answers. Include existing AAAA, IPv6 reverse, forwarding and
   external names wherever clients depend on them.
4. Move a test network or a small client cohort to UniFi. Verify the
   resolvers advertised by DHCPv4 and IPv6, refresh client leases where
   needed, and test application lookups and reverse DNS. Expand in stages
   only after the checks pass on the new resolver.
5. On failure, restore the recorded resolver advertisements, renew
   affected leases or allow the prior lease lifetime to elapse, and
   confirm the old DNS answers and application lookups again. Retain
   Technitium and the rollback export until all dependent networks and
   workloads pass after the transition.

## UniFi Network evidence

The optional collector shares the HTTPS, site selection and mounted key
configuration above. Set `YGGFLARE_UNIFI_COLLECT_ENABLED=true` for a refresh
every five minutes. The URL alone leaves scheduled collection disabled.
The Network application and credential must support the local sites, adopted
devices, connected clients, networks and DNS policy list endpoints. See the
[UniFi Network API reference](https://developer.ui.com/network/v11.0.97).

```sh
docker exec yggflare yggflare unifi refresh
docker exec yggflare yggflare unifi status --json
docker exec yggflare yggflare unifi devices
docker exec yggflare yggflare unifi clients
docker exec yggflare yggflare unifi networks
docker exec yggflare yggflare unifi dns --json --all
```

The Web UI UniFi tab, the MCP `unifi` group and CLI views use the same
saved projection. Prometheus exports aggregate collection availability,
freshness and resource counts. Doctor checks the local configuration,
mounted key and snapshot freshness when scheduled collection is enabled.
Only the scheduler and explicit refresh collect these observations.

The collector reports device state, clients visible as connected,
network/VLAN declarations and policy identities, enabled flags and
IPv4 values where available. API visibility is limited to the selected site
and credential. DHCP leases and actual DNS replies are outside this
projection. A failed list endpoint or incomplete page retains the last
successful snapshot and leaves its latest refresh unverified. A verified
snapshot expires after 15 minutes.

After the required lists succeed, the collector reads documented adopted
device details for up to 32 listed devices. It stops starting detail
requests after 60 seconds of collection. The Devices view includes
`uplink_status` and, when the reported parent ID resolves within the same
adopted-device list, the parent's projected name and MAC. API IDs stay
internal. A reported parent is controller topology evidence and does not
establish physical cabling, switch port, or client attachment.

Missing uplinks, parents outside the visible list, malformed links,
failed requests, and unchecked devices are distinct outcomes. Detail
failures preserve the successful list observations. CLI and MCP status
show aggregate `uplink_counts`; Prometheus exports fixed
`yggflare_unifi_uplink_*` counts from the saved snapshot. Legacy snapshots
gain these fields on the next refresh. See the
[adopted device details API](https://developer.ui.com/network/v11.0.97/getadopteddevicedetails).

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

Collector endpoint projections reject control-bearing URLs and scoped IPv6 addresses rather than normalizing them into ordinary origin evidence. Before publishing Komodo or Kuma snapshots, projected string fields are checked for exact configured credential echoes, including Kuma's Basic-auth encoding, and embedded echoes of markers at least eight characters long. A match fails collection and preserves the previous complete snapshot. This is a narrow defense against known credentials being reflected in allowed fields, not a general secret detector: arbitrary unknown, transformed or fragmented secrets and malicious printable names remain possible. No presentation request reads credential files for this check.

Saved adapter and probe snapshots are read through a bounded regular-file descriptor without following symlinks or blocking on FIFOs. Invalid UTF-8/JSON, duplicate JSON keys, nonfinite numbers and invalid version types are unavailable. Newly written item snapshots include `item_count`; missing item lists, inconsistent counts and malformed basic row identities/statuses do not represent successful empty collections. Older version-1 snapshots without the count remain readable if they pass row validation; count-based completeness is established after a refresh. This is structural validation, not authentication of the snapshot or proof of upstream inventory completeness. Failed refreshes continue to retain previous successful data.

Snapshot nesting is explicitly limited to 32 container levels on read and write, independent of Python's JSON parser implementation. The depth check traverses iteratively, including values following JSON nulls.

Ingress assurance exposes an observation-time window across its independent saved source projections. The spread is informational, not an atomic snapshot or a health verdict. Missing, invalid and future timestamps are excluded; inspect the per-source availability and freshness independently.
