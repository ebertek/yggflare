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
conflicts rather than accepted as an A record. These findings are review-only:
missing records never authorize automatic creation, and existing guarded
Docker update behavior, plan fingerprints and audit exit semantics are unchanged.

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
