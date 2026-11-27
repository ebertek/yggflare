# Installation and configuration

[Documentation index](README.md) · [Project README](../README.md)

## Installation

### Requirements

- Linux host with Docker Compose and a supported Cloudflare account/Tunnel.
- A Docker socket, host networking and host D-Bus access for the supplied Compose deployment.
- Permission to run Nmap SYN scans.
- Private storage for configuration, state, backups and API credentials.

**Security:** Docker socket access is effectively host-root access, even when mounted
read-only. Run Yggflare only on a trusted host.

### 1. Configure your host

Use [compose.yaml](../compose.yaml) and provide these values through its environment (for
example, a local `.env` file):

| Variable                                           | Example                | Purpose                                              |
| -------------------------------------------------- | ---------------------- | ---------------------------------------------------- |
| `YGGFLARE_HOME`                                    | `/srv/yggflare`        | Host directory for configuration and persistent data |
| `YGGFLARE_MERGED_ROOT`                             | `/srv/compose`         | Compose source tree to inspect, mounted read-only    |
| `YGGFLARE_LAN_CIDR`                                | `192.168.40.0/23`      | IPv4 discovery boundary                              |
| `YGGFLARE_DEVICES_CIDR`                            | `192.168.40.0/24`      | Static device address allocation                     |
| `YGGFLARE_DOCKER_CIDR`                             | `192.168.41.0/24`      | Docker service allocation                            |
| `YGGFLARE_INTERNAL_DOMAIN`                         | `home.example.net`     | Internal DNS zone                                    |
| `YGGFLARE_EXTERNAL_DOMAIN`                         | `services.example.net` | External Access/Tunnel zone                          |
| `CLOUDFLARE_ACCOUNT_ID`                            | Your account ID        | Cloudflare account                                   |
| `CLOUDFLARE_TUNNEL_ID` or `CLOUDFLARE_TUNNEL_NAME` | Your existing Tunnel   | ID takes precedence                                  |

The sample Compose file mounts the following paths:

| Container path    | Content                                                     |
| ----------------- | ----------------------------------------------------------- |
| `/config`         | Private inventory and retained DNS declarations; read-only  |
| `/compose-source` | Compose files; read-only                                    |
| `/data`           | Scan state, Cloudflare ownership and presentation snapshots |
| `/backup`         | Backup archives                                             |
| `/run/secrets`    | Cloudflare token and optional Discord webhook               |

Create `config/`, `data/`, `backup/` and `secrets/` inside `YGGFLARE_HOME`. Store
the Cloudflare token in `secrets/cloudflare_api_token` and the optional Discord URL in
`secrets/network_discord_webhook` (an empty file disables notifications).

The token needs read access to the selected Access, Tunnel and DNS resources. Grant
edit permissions only if you intend to enable reconciliation.

### 2. Create an inventory

Save `config/static-hosts.json`:

```json
{
  "version": 1,
  "hosts": [
    {
      "hostname": "printer.home.example.net",
      "ipv4": "192.168.40.35",
      "mac": "02:00:00:00:00:35",
      "description": "Office printer",
      "ports": [
        {"protocol": "tcp", "port": 9100, "description": "Printing"}
      ],
      "aliases": ["print.home.example.net"],
      "device_class": "printer"
    }
  ]
}
```

The inventory accepts 1–256 active hosts. Addresses must fall within the configured
device range, outside the Docker range and outside each /27 allocation's
network/broadcast addresses.

Optional fields include `observed_macs`, `additional_ipv4`, `interface_macs`,
`serial_number` and `purchase_date`. See the
[inventory validator](../src/cloudflare/cloudflare_static_dns.py) for exact rules.

Other optional files in `/config`:

- `static-hosts-reserved.json` and `retired-devices.json`: display-only catalogs.
- `retained-dns.json`: audit-only exceptions for existing internal DNS records. These never authorize writes.

### 3. Launch and verify

```sh
docker compose config --quiet
docker compose pull
docker compose up -d

docker exec yggflare yggflare --version
docker exec yggflare yggflare doctor run
docker exec yggflare yggflare cloudflare audit
```

The `docker exec` commands work from any directory. Review the first audit
before enabling writes.

## Configuration

`YGGFLARE_*` controls application behaviour. `CLOUDFLARE_*` selects Cloudflare
credentials and resources. Values exported only to your shell do **not** reach the
container unless the Compose `environment:` section forwards them.

### Cloudflare

| Variable                                      | Default                             | Purpose                         |
| --------------------------------------------- | ----------------------------------- | ------------------------------- |
| `CLOUDFLARE_API_TOKEN_FILE`                   | `/run/secrets/cloudflare_api_token` | Token file                      |
| `CLOUDFLARE_DOCKER_DNS_SYNC`                  | `false`                             | Create missing Docker A records |
| `CLOUDFLARE_EXTERNAL_ZONE_ID`                 | Resolve by domain                   | Optional external zone ID       |
| `CLOUDFLARE_INTERNAL_ZONE_ID`                 | Resolve by domain                   | Optional internal zone ID       |
| `CLOUDFLARE_STATIC_DNS_REQUIRED`              | `true`                              | Require static inventory        |
| `CLOUDFLARE_STATIC_DNS_SYNC`                  | `false`                             | Enable static DNS writes        |
| `YGGFLARE_CLOUDFLARE_AUTO_APPLY`              | `false`                             | Automatic reconciliation        |
| `YGGFLARE_CLOUDFLARE_AUTO_BATCH_SIZE`         | `3`                                 | Apply operations per cycle      |
| `YGGFLARE_CLOUDFLARE_AUTO_CLEANUP`            | `false`                             | Retire owned orphans            |
| `YGGFLARE_CLOUDFLARE_AUTO_CLEANUP_BATCH_SIZE` | `1`                                 | Retirements per cycle           |
| `YGGFLARE_CLOUDFLARE_DNS_RESERVE`             | `10`                                | Reserved internal DNS slots     |
| `YGGFLARE_CLOUDFLARE_ORPHAN_GRACE_HOURS`      | `24`                                | Grace period (24–720 hours)     |

Batch size `0` opts into all validated operations. Cleanup also requires
automatic apply. See [Cloudflare](cloudflare.md) for the quota and write rules.

### Application

| Variable                               | Default     | Purpose                   |
| -------------------------------------- | ----------- | ------------------------- |
| `YGGFLARE_LOG_FORMAT`                  | `text`      | Text or JSON logs         |
| `YGGFLARE_METRICS_ENABLED`             | `false`     | Prometheus metrics        |
| `YGGFLARE_NETWORK_ALERT_CONFIRM_SCANS` | `2`         | Confirmation scans (1–10) |
| `YGGFLARE_VERSION`                     | `main`      | Image tag                 |
| `YGGFLARE_WATCH_COMPOSE`               | `true`      | Watch Compose             |
| `YGGFLARE_WATCH_COOLDOWN_SECONDS`      | `60`        | Minimum reactive interval |
| `YGGFLARE_WATCH_DEBOUNCE_SECONDS`      | `20`        | Wait for writes to settle |
| `YGGFLARE_WATCH_DOCKER`                | `true`      | Watch Docker topology     |
| `YGGFLARE_WATCH_POLL_SECONDS`          | `15`        | Compose polling interval  |
| `YGGFLARE_WEB_BIND`                    | `127.0.0.1` | HTTP bind address         |
| `YGGFLARE_WEB_ENABLED`                 | `false`     | Web UI                    |
| `YGGFLARE_WEB_PORT`                    | `8787`      | HTTP port                 |

For every application setting (`YGGFLARE_*` and `CLOUDFLARE_*`), an explicitly
empty string is equivalent to an unset variable. Optional settings use their
existing defaults; required settings still fail validation. Nonempty values
remain subject to the same validation, including credential-file paths. This
also preserves the existing unset-zone UniFi ownership target fingerprint.
Do not reset or manually rebind a journal if its target differs. To override a value not
forwarded by the supplied Compose file, add it to that service's `environment:`.

For optional settings, see [discovery](discovery.md),
[integrations](integrations.md), [MCP](mcp.md) and
[observability](observability.md).
