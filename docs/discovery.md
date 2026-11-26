# Network discovery and alerts

[Documentation index](README.md) · [Project README](../README.md)

The daily IPv4 scan checks responsive non-Docker addresses using Nmap's popular ports
plus configured and declared TCP ports. Avahi supplies separate DNS-SD service
evidence. Scans never change DNS records or device declarations.

Optional ARP, NDP, IPv6 and OS discovery are limited to explicitly configured
interfaces and address ranges:

```yaml
YGGFLARE_DISCOVERY_INTERFACES: "eth0,eth1"
YGGFLARE_DISCOVERY_IPV6_CIDRS: "fd00:1234:5678::/64"
YGGFLARE_DISCOVERY_ARP_SCAN: "true"
YGGFLARE_DISCOVERY_NDP_PROBE: "true"
YGGFLARE_DISCOVERY_RA: "false"
YGGFLARE_DISCOVERY_IPV6_SCAN: "true"
YGGFLARE_DISCOVERY_OS_DETECTION: "true"
```

These optional collector switches default to `false`. IPv6 scanning never
sweeps an entire /64. `YGGFLARE_DISCOVERY_RA` optionally solicits router
advertisements on selected interfaces, recording scoped, read-only topology
evidence—not device identities or DNS inputs. The
supplemental target budget defaults to 512 unique addresses per IP family
(`YGGFLARE_DISCOVERY_MAX_TARGETS`, 1–4096). Nmap processes targets in batches of at
most 64; this batch size is **not** a discovery cutoff.

Additional SSDP, NetBIOS, LLDP, SMB, SNMP and passive fingerprint sources are
described in [supplemental discovery options](#additional-discovery-sources). Only enable sources appropriate
to your network.

## Identity and history

Yggflare correlates inventory declarations, observed MACs, IPv4/IPv6 addresses and
discovery evidence. It retains first/last observed timestamps, address changes and an
identity timeline.

Confidence is **high**, **medium** or **low** based on corroborating evidence—not a
proof of ownership. IP-only sightings remain provisional. Conflicting MAC claims are
presented separately; DNS-SD names and OS guesses are hints, not identity keys.

A missing observation does **not** prove that a device is offline. Histories are
bounded and saved in `/data/network-inventory/state.json`.

## Notifications

Unknown devices and changed MAC/IP observations notify immediately. Newly open TCP
ports and new DNS-SD service identities require **two successful observations** by
default; setting `YGGFLARE_NETWORK_ALERT_CONFIRM_SCANS=1` restores immediate
reporting.

Unconfirmed findings remain visible in the UI. Changing a DNS-SD service's dynamic
port does not create a new identity. A failed notification doesn't lose a scan: queued
Discord messages are retried later.

## Additional discovery sources

All collectors use `YGGFLARE_DISCOVERY_INTERFACES` and the existing IPv4/IPv6
scope. Enable only the sources you want. Optional collector switches default to `false` and require literal `true` or `false`. Forward additional environment settings through the deployment Compose file when needed.
Results appear in **Discovery**, not authoritative inventory or Cloudflare state.
A failed source produces a sanitized warning while other sources continue.

| Environment variable                 | Collection                                                                                                        |
| ------------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| `YGGFLARE_DISCOVERY_SSDP`            | One IPv4 SSDP M-SEARCH per interface; up to 128 replies within three seconds                                      |
| `YGGFLARE_DISCOVERY_LLDP`            | Read LLDP/CDP neighbours from an existing lldpd socket                                                            |
| `YGGFLARE_DISCOVERY_RA`              | Solicit scoped ICMPv6 Router Advertisements with `rdisc6`; one short probe per configured interface               |
| `YGGFLARE_DISCOVERY_NETBIOS`         | NetBIOS node-status names for all observed, in-scope IPv4 addresses, with bounded workers and per-target timeouts |
| `YGGFLARE_DISCOVERY_SMB`             | Anonymous listing for scoped targets with observed TCP/445 or TCP/139                                             |
| `YGGFLARE_DISCOVERY_SMB_MAX_TARGETS` | 1–4096; inherits general discovery limit (default 512)                                                            |
| `YGGFLARE_DISCOVERY_SMB_WORKERS`     | 1–16; default 8                                                                                                   |
| `YGGFLARE_DISCOVERY_SNMP`            | Query explicitly configured SNMP targets with mounted credentials                                                 |
| `YGGFLARE_DISCOVERY_SNMP_TARGETS`    | Comma-separated IPv4 addresses within the LAN scope; empty by default, maximum 16                                 |
| `YGGFLARE_DISCOVERY_MAX_TARGETS`     | Maximum distinct active-probe candidates per address family; default 512, configurable 1–4096                     |
| `YGGFLARE_DISCOVERY_P0F`             | Ten-second passive fingerprint sample per interface                                                               |

Example first-pass configuration for a host with the selected interfaces and CIDRs:

```yaml
YGGFLARE_DISCOVERY_SSDP: "true"
YGGFLARE_DISCOVERY_NETBIOS: "true"
YGGFLARE_DISCOVERY_RA: "false"
YGGFLARE_DISCOVERY_SMB: "false"
YGGFLARE_DISCOVERY_LLDP: "false"
YGGFLARE_DISCOVERY_SNMP: "false"
YGGFLARE_DISCOVERY_P0F: "false"
```

### Collector limits

- SSDP: records service type, USN and server identity; never fetches URLs.
  IPv6 SSDP is not supported.
- NetBIOS: queries observed in-scope IPv4 addresses with up to eight workers
  and a three-second timeout per target. No reply is normal.
- SMB: anonymous listings only, for observed TCP/445 or TCP/139 (prefer 445).
  No file content or password attempts. Each listing has a ten-second limit.
- Missing utilities, invalid settings and unexpected execution errors produce
  warnings; other sources continue.

## Scan runtime and progress

Scans report phase timings and 15-second heartbeats without raw packet data.

The primary IPv4 scan uses host discovery followed by one TCP scan of
responsive non-Docker targets. The port set combines:

- Fixed IoT/management ports.
- All TCP ports declared in the private inventory.
- At least Nmap's top 100 TCP ports, including frequency ties.

The installed `nmap-services` database must be valid; a partial substitute
is not accepted. The scan uses SYN probing and light service identification.

Supplemental scans process at most 64 targets per batch by address family
and interface (90-second batch and 15-second host limits). Duplicate IPs
are probed on one observing interface, preferring the kernel egress route.
Passive observations from all configured interfaces are retained.

A missing NDP reply (exit status 2) is normal. Execution errors remain
warnings. Scan duration depends on the network; there is no fixed guarantee.

## IPv6 Router Advertisements (rdisc6)

Set `YGGFLARE_DISCOVERY_RA=true` **and** configure
`YGGFLARE_DISCOVERY_INTERFACES` and `YGGFLARE_DISCOVERY_IPV6_CIDRS`.
Yggflare sends one short router solicitation to `ff02::2` per selected interface:

```sh
rdisc6 -n -r 1 -w 750 ff02::2 eth0
```

It retains validated link-local router sources, router preference/lifetime,
address-configuration flags, and advertised prefixes or DNS server addresses
that overlap the configured IPv6 scope. A broader overlapping prefix is
**topology evidence only**; it never expands the scan boundary. Output is
bounded to eight advertisements per interface and allowlisted numeric fields.

Router observations have no device IP in Yggflare state. They appear in
**Discovery** as interface-level evidence and never become Nmap targets,
device identities, authoritative DNS records, or Cloudflare inputs.
A missing Router Advertisement (`rdisc6` exit code 2) is normal and does
not generate a warning; execution failures do. This is an *active* ICMPv6
solicitation, not passive packet capture. Yggflare does not itself configure
routes or addresses; the host kernel may independently process received RAs.

## LLDP/CDP (host daemon required)

Yggflare installs `lldpcli`, **not a running LLDP daemon**. To collect
neighbours, install and operate `lldpd` on the Linux host:

```sh
sudo apt-get install lldpd
sudo systemctl status lldpd
sudo lldpcli show neighbors details
```

Configure the host daemon's startup options for **receive-only** `-r`, CDP
support `-c`, and physical interfaces only, e.g. `-I eth0`. The flags
`lldpd -r -c -I eth0` are an *example configuration*, **not** a second daemon
to start beside the host service. The exact persistent setting depends on
the distribution and its systemd unit; inspect `systemctl cat lldpd`
before editing it.

The Yggflare collector expects the daemon's control socket at
`/run/lldpd/lldpd.socket` **inside the container**. Ubuntu/Debian packages
commonly use `/run/lldpd.socket` on the host. For that default socket,
use this explicit file bind in your *source* Compose:

```yaml
volumes:
  - /run/lldpd.socket:/run/lldpd/lldpd.socket:ro
```

For a more robust setup across daemon restarts, configure the host daemon
with `-u /run/lldpd/lldpd.socket`, ensure the host creates that runtime
directory at startup, and mount the entire directory:

```yaml
volumes:
  - /run/lldpd:/run/lldpd:ro
```

Then verify both sides:

```sh
# On the host
sudo lldpcli show neighbors details
# Inside Yggflare, after mounting the socket
docker exec yggflare lldpcli -u /run/lldpd/lldpd.socket show neighbors details
```

Finally enable `YGGFLARE_DISCOVERY_LLDP=true`. The collector only queries
neighbour details; it does not start or reconfigure the host daemon. **A
read-only socket bind is not an API-level read-only restriction.** Treat it
as trusted host access. LLDP/CDP sees only advertisements arriving at the
host's interfaces; it cannot inventory the entire switched network.
No neighbour advertisements is a normal outcome if the directly attached
equipment does not transmit LLDP/CDP.

## SNMP

Leave disabled when no devices are configured for SNMP. The collector uses
`snmpget` for system description and system name only; it does not walk arbitrary
MIBs or try default communities. Supply explicit targets and mount a Docker secret
at `/run/secrets/yggflare_snmp` containing one of:

```json
{"version":"2c","community":"YOUR_READ_ONLY_COMMUNITY"}
```

```json
{"version":"3","username":"YOUR_USER","auth_passphrase":"YOUR_AUTH_PASSPHRASE","priv_passphrase":"YOUR_PRIVACY_PASSPHRASE"}
```

SNMPv3 uses authPriv with SHA and AES; configure matching device settings. Values
accept 1–128 characters from letters, numbers and `_.@!%-`. SNMPv2c does not encrypt
its community on the network. Credentials are placed in a temporary mode-0600
Net-SNMP config and never passed in command arguments. Each request has a one-second
protocol timeout with no retries, within the ten-second process bound. No credentials
are supplied by the example Compose; add the secret mount in your deployment source.

## Passive OS estimates

p0f observes TCP traffic visible to the selected interface without enabling
promiscuous mode. It cannot identify devices whose traffic never reaches the host.
Only in-scope subject addresses and OS estimates survive collection. The temporary
log is deleted after the sample; no packet capture is retained. Raw socket/capture
permissions are required. Do not interpret an empty sample as device disappearance.

These collectors are best-effort identity evidence. They do not produce automatic
DNS changes, ownership claims or Discord drift alerts. Missing utilities, daemon
sockets or permissions are shown as collector warnings.

## Saved coverage evidence

View the last scan in Web UI Operations → Discovery coverage, MCP
`get_discovery_status` or:

```sh
docker exec yggflare yggflare network coverage --json
```

The report includes:

- Nmap completion, TCP requested/represented/omitted targets and timeouts.
- Selected ports, positive port evidence, Docker exclusions and DNS-SD outcome.
- Per-source configuration, attempts, no replies, failures, limits and parser outcomes.
- SMB target selection, concurrency and anonymous listing outcomes.

Counts describe invocations and observed evidence, not complete coverage.
An omitted Nmap `--open` result does not prove a port is closed or a host
is offline. Missing coverage remains unknown; these views never change
scan scope, DNS or alert decisions.
