# v1.4.0 release candidate

[Documentation index](README.md) · [Roadmap #65](https://github.com/ebertek/yggflare/issues/65)

**Status:** proposed release, not published. Reviewed source baseline: `887ec7ba0aedd7f33f1f81fbcc024554da032692` (2026-11-26). Latest published release at review: [v1.3.0](https://github.com/ebertek/yggflare/releases/tag/v1.3.0). A minor version increment is recommended because this cycle adds significant read-only functionality and optional integrations without requiring an inventory schema migration.

## Release notes

Yggflare expands from basic MCP inventory queries into a shared, bounded evidence layer for infrastructure and operational assurance.

- **Service topology and ingress:** Compose and local Docker identities, runtime health, declared dependencies, network namespace relationships, Cloudflare audit projections, Traefik routes and candidate cross-source ingress correlations.
- **Optional integrations:** Komodo stack/deployment revision evidence, offline comparison of tracked stack inputs, Kuma service/device monitor candidates and explicitly configured local DNS/TCP/TLS/HTTP probes. HTTP probes default to HEAD /; GET / is supported when explicitly configured.
- **Discovery and operations:** primary IPv4 port selection evidence, per-source supplemental collector execution and limits, bounded finding lifecycle, scheduler outcomes, webhook submission evidence, archive verification and isolated restore rehearsal. Missing observations are not proof of absence or resolution.
- **Interfaces:** typed read-only MCP tools, group-scoped resources/prompts, optional per-principal HTTP authorization, result-set fingerprints, shared CLI and Web UI views, bounded CLI pagination and aggregate Prometheus metrics. Grafana assurance panels distinguish availability, coverage and failed checks from raw counts.
- **Security and resilience:** sanitized MCP query errors, narrow known-credential reflection checks, endpoint validation, formula-like CSV cell neutralization, control-character escaping, bounded snapshot reads, explicit item counts and nesting limits, and timestamp-aware evidence interpretation.
- **Maintenance:** organized source and test directories and focused documentation; existing container entry points and runtime paths are retained.

## Upgrade considerations

- Keep optional integrations and HTTP listeners opt-in. Existing private configuration and fixed-path credentials remain supported; do not move them into public source.
- Snapshot readers still accept structurally valid legacy version-1 data; refresh enabled adapters to populate explicit item counts. Invalid retained snapshots become unavailable, not successful empty collections.
- CSV is a human-facing export with formula mitigation and visible escaping. JSON preserves projected values for automation.
- Additive MCP response metadata includes the observation window; source freshness, collection success and completeness remain separate. A snapshot fingerprint identifies a filtered result set, not an atomic multi-source capture.
- Import the updated [Grafana dashboard](../dashboards/yggflare.json) if used. Preserve its UID and review status colors and missing-data behavior.
- No automatic expansion of scan targets, authorization, reconciliation scope or Cloudflare cleanup settings is introduced by this release candidate.

## Roadmap implementation and evidence

| Area | Merged source references |
| --- | --- |
| Initial assurance layer, operational evidence, typed MCP and optional integrations | #64, #66, #67, #69–75 |
| Supplemental execution, Kuma correlation and SMB selection | #76–78 |
| Ingress correlation, port selection, tracked stack comparison and probe coverage | #79–80 |
| Repository organization and Grafana assurance | #81–82 |
| Explicit HTTP GET and dashboard colors | #83–84 |
| MCP error containment, collector payload hardening and presentation safety | #85–87 |
| Saved snapshot resilience and timestamp consistency | #88–89 |

The latest PR #89 head passed all three unit-test suites (213 application, 130 Cloudflare, 92 network; 435 total), Ruff, Black and container build in GitHub Actions. This is source-level verification at that PR head, not verification of a future release tag. Repeat checks for the exact final release commit.

Earlier operator-provided live results on November 25 verified Traefik, Komodo and Kuma collection, primary scan port selection (9/9 monitored numeric IPv4 TCP endpoints selected), and the expanded probe configuration (30/30 checks passed). The older Grafana dashboard rendered the corresponding aggregates. These are historical acceptance observations, not current health, external reachability, authorization proof or validation of the subsequent #85–89 hardening in production.

### Pre-publication

- [ ] Merge the documentation/release-readiness PR and confirm final main SHA.
- [ ] Confirm CI, lint and image build for the final source; confirm successful main image publication if available.
- [ ] Check the proposed v1.4.0 tag is unused, then create it at the reviewed main commit using the owner-approved release process. Never move a published tag.
- [ ] Confirm the tag-triggered publish workflow succeeds, the versioned GHCR image exists and its OCI revision identifies that exact commit.
- [ ] Publish GitHub release notes from this document. Pin a verified digest in deployment source when the operator chooses to roll out.

### Post-deployment acceptance

Run these read-only commands on the authorized host after the planned update:

```sh
docker exec yggflare yggflare --version
docker exec yggflare yggflare doctor run
docker exec yggflare yggflare system status --json
docker exec yggflare yggflare system evidence --json
docker exec yggflare yggflare system jobs --json
docker exec yggflare yggflare network coverage --json
docker exec yggflare yggflare traefik status --json
docker exec yggflare yggflare komodo status --json
docker exec yggflare yggflare kuma status --json
docker exec yggflare yggflare probes status --json
docker exec yggflare yggflare kuma devices --all --json
docker exec yggflare yggflare services assurance HOSTNAME --json
docker exec yggflare yggflare network findings --all --json
docker exec yggflare yggflare backup status --json
```

Replace HOSTNAME with an explicitly chosen known ingress hostname. Check the build revision, expected enabled adapter availability, current observation times and collection verification; do not require disabled adapters to report available. Compare coverage against the actual current configuration, not historical counts. Check the observation window and each source's timestamps. Missing or stale data is inconclusive, and failed probe results should be investigated rather than hidden.

Allow scheduled collectors to refresh, or explicitly run the relevant local refresh only when authorized. A network scan can send drift notifications; it is not a read-only view. Run a read-only Cloudflare audit separately if appropriate; never trigger apply or cleanup merely to validate the release. Verify MCP client read-only tool/group access, Prometheus scrape and imported Grafana presentation. Retain private observations outside the public repository.

### Deferred and ongoing

Technitium and UniFi integrations remain deferred by the owner. Broader adversarial testing and maintenance remain ongoing: this cycle is not a complete security audit, authenticated snapshot integrity guarantee or proof that upstream APIs expose every resource. No generic shell, arbitrary HTTP, live scan or mutation tools are planned for MCP.
