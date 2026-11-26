# Yggflare

Yggflare is a self-hosted infrastructure controller for Docker Compose,
Cloudflare and UniFi, with LAN discovery and read-only operational views.

## Features

- Cloudflare Access, Tunnel and DNS reconciliation with ownership safeguards.
- UniFi device, client and network inventory, guarded DNS creation and A/PTR verification.
- IPv4/IPv6 discovery, device identity history and Discord notifications.
- Traefik, Komodo, Uptime Kuma and independent connectivity checks.
- Web UI, CLI, read-only MCP, Prometheus metrics and backups.

Automatic writes and HTTP listeners are opt-in. Run on a trusted Linux host:
Docker socket access is effectively host-root access.

## Quick start

Configure the supplied [Compose file](compose.yaml), inventory and credentials
using the [setup guide](docs/setup.md).

```sh
docker compose config --quiet
docker compose pull
docker compose up -d
docker exec yggflare yggflare doctor run
docker exec yggflare yggflare cloudflare audit
```

Image: `ghcr.io/ebertek/yggflare`. Use a [release](https://github.com/ebertek/yggflare/releases)
or pin a verified image digest.

## Documentation

See the [documentation index](docs/README.md) for all guides.

Licensed under [Apache-2.0](LICENSE); see [NOTICE](NOTICE).
