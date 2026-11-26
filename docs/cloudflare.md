# Cloudflare reconciliation

[Documentation index](README.md) · [Project README](../README.md)

Compose Traefik `Host` rules and the `cf.access` / `cf.access.policies` labels
describe protected external services. The static inventory describes internal DNS.
Yggflare compares these declarations with live Cloudflare resources.

### Review and apply

```sh
docker exec yggflare yggflare cloudflare audit
docker exec yggflare yggflare cloudflare preflight
docker exec yggflare yggflare cloudflare plan
docker exec yggflare yggflare cloudflare apply APPROVAL_FINGERPRINT
```

Replace `APPROVAL_FINGERPRINT` with the fingerprint printed by `plan` . Apply checks
the live state again and rejects a changed plan. Manual approval works with automatic
reconciliation disabled.

Manual plans include all validated actions by default. To constrain an approval, use
matching `--max-operations N` values for both `plan` and `apply` .

When automatic apply is enabled, Yggflare validates the **complete plan** before
executing a batch. For Access changes, the assigned reusable policies must include
at least one `allow` **or** `bypass` decision, followed by exactly one terminal
`deny`. Bypass deliberately skips Access authentication for matching requests:
review policy selectors carefully and never assume a policy is restricted from
its name alone. Reconciliation error messages identify the hostname and selected
policy decisions without exposing policy rules.

New protected hostnames are created in **Access → Tunnel route → DNS** order.
Yggflare adds routes to the configured Tunnel; it does not create new Tunnel
objects.

### Internal DNS coverage

The active private static-host inventory already reports missing, mismatched
and conflicting A records. Primary static A creation is separately opt-in.
Docker DNS coverage additionally compares explicit Compose IPv4 declarations
(including stopped services) and known unique running-container IPv4 addresses
within `YGGFLARE_DOCKER_CIDR` against the internal Cloudflare zone selected by
`YGGFLARE_INTERNAL_DOMAIN`. A literal internal Compose hostname is preferred;
otherwise the existing container-name (or service-name) convention applies.
No host-mode, shared-network or bridge-only LAN address is invented. Different
Compose/runtime addresses remain ambiguous; CNAME-only names are reported as
conflicts rather than accepted as an A record. Coverage findings remain review-only. With `CLOUDFLARE_DOCKER_DNS_SYNC=true`,
a separate guarded creation plan requires one unambiguous Compose declaration
and agreeing running-container address. Existing DNS names, shared addresses,
static/alias/retained declarations and wildcard address records are protected.
Creation uses the existing fingerprint and unattended opt-ins, revalidates
live Docker, declarations and DNS, and verifies the new DNS-only A record.
Stopped containers never authorize creation or deletion.

When enabled, the reconciler reads the internal zone's actual record quota and
usage from Cloudflare `GET /zones/{zone_id}/dns_records/usage`, counting all
record types. `YGGFLARE_CLOUDFLARE_DNS_RESERVE` (default 10) retains free slots.
The full plan must fit before writes; capacity is checked again before each
internal Docker or static A creation. Unknown quota (including account-level
quota), missing API access or insufficient capacity prevents internal creations.
The external-zone workflow is unchanged. Quota is reported by the live audit
and plan; no records are automatically deleted to free capacity.

Inspect `yggflare cloudflare audit`, the saved `yggflare cloudflare status --all
--json` view, the Cloudflare audit Web UI or MCP `get_cloudflare_audit` with
`section="docker_dns"`. Old snapshots have unknown Docker DNS coverage until
refreshed. A matching A record does not establish reachability or PTR coverage.

### Ownership and cleanup

Only proven Yggflare-managed resources are eligible for retirement. Existing resources
need an explicit claim after verifying the live configuration:

```sh
docker exec yggflare yggflare cloudflare claim host.services.example.net
```

Review removal of a claimed hostname with:

```sh
docker exec yggflare yggflare cloudflare orphan-plan host.services.example.net
docker exec yggflare yggflare cloudflare orphan-apply host.services.example.net APPROVAL_FINGERPRINT
```

Automatic cleanup requires **both** `YGGFLARE_CLOUDFLARE_AUTO_APPLY=true` and
`YGGFLARE_CLOUDFLARE_AUTO_CLEANUP=true` . A managed hostname must remain absent for at
least the configured grace period. Deletion proceeds **external DNS → Tunnel route →
Access app**, with live revalidation at each step.

Unmanaged hostnames are never deleted. Leave the cleanup batch size at `1` unless
you've independently verified desired-state accuracy and recovery. Setting it to `0`
permits bulk retirement.
