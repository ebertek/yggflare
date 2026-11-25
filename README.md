# Yggflare

Yggflare is a self-hosted, Docker-based infrastructure controller for Cloudflare,
LAN discovery and operational assurance. It correlates Docker Compose declarations
and private inventories with observed runtime and network evidence.

## Features

- Cloudflare Access, Tunnel and DNS audits, guarded reconciliation and owned-orphan cleanup.
- Scoped IPv4/IPv6 discovery, device identity history and Discord notifications.
- Traefik, Komodo, Uptime Kuma and independent connectivity evidence.
- Read-only Web UI, CLI, MCP server and Prometheus metrics.
- Scheduled diagnostics, backups and isolated restore verification.

Cloudflare writes, orphan cleanup and HTTP listeners are opt-in. Discovery never
modifies authoritative inventory or DNS. Docker socket access is effectively
host-root access; deploy only on a trusted Linux host.

## Quick start

Follow the [installation guide](docs/setup.md) to configure the supplied
[Compose file](compose.yaml), private inventory and mounted credentials. Then run:

```sh
docker compose config --quiet
docker compose pull
docker compose up -d
docker exec yggflare yggflare --version
docker exec yggflare yggflare doctor run
docker exec yggflare yggflare cloudflare audit
```

Images: `ghcr.io/ebertek/yggflare` with `main`, `sha-FULL_COMMIT_SHA` or
`vMAJOR.MINOR.PATCH` tags. Pin a digest for production.

## Documentation

| Guide | Topics |
| --- | --- |
| [Setup](docs/setup.md) | Installation, configuration and inventory |
| [Cloudflare](docs/cloudflare.md) | Audit, reconciliation and cleanup |
| [Discovery](docs/discovery.md) | Network observations, alerts and collectors |
| [Observability](docs/observability.md) | Web UI, CLI and Prometheus |
| [Integrations](docs/integrations.md) | Traefik, Komodo, Kuma, probes and assurance |
| [MCP](docs/mcp.md) | Tools, transports and permissions |
| [Operations](docs/operations.md) | Scheduling, backups and diagnostics |
| [Development](docs/development.md) | Layout, tests and releases |

Licensed under [Apache-2.0](LICENSE); see [NOTICE](NOTICE).
