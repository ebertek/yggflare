# Additional discovery sources

All collectors use `YGGFLARE_DISCOVERY_INTERFACES` and the existing IPv4/IPv6
scope. Enable only the sources you want. Every switch below defaults to `false`
and requires literal `true` or `false`; the supplied Compose passes them through.
Results appear in **Discovery**, not authoritative inventory or Cloudflare state.
A failed source produces a sanitized warning while other sources continue.

| Environment variable | Collection |
|---|---|
| `YGGFLARE_DISCOVERY_SSDP` | One IPv4 SSDP M-SEARCH per interface; up to 128 replies within three seconds |
| `YGGFLARE_DISCOVERY_LLDP` | Read LLDP/CDP neighbours from an existing lldpd socket |
| `YGGFLARE_DISCOVERY_NETBIOS` | NetBIOS node-status names for up to 16 observed IPv4 addresses |
| `YGGFLARE_DISCOVERY_SMB` | Anonymous SMB share listing for the same bounded addresses |
| `YGGFLARE_DISCOVERY_SNMP` | Query explicitly configured SNMP targets with mounted credentials |
| `YGGFLARE_DISCOVERY_SNMP_TARGETS` | Comma-separated IPv4 addresses within the LAN scope; empty by default, maximum 16 |
| `YGGFLARE_DISCOVERY_P0F` | Ten-second passive fingerprint sample per interface |

Example first-pass configuration for a host with the selected interfaces and CIDRs:

```yaml
YGGFLARE_DISCOVERY_SSDP: "true"
YGGFLARE_DISCOVERY_NETBIOS: "true"
YGGFLARE_DISCOVERY_SMB: "false"
YGGFLARE_DISCOVERY_LLDP: "false"
YGGFLARE_DISCOVERY_SNMP: "false"
YGGFLARE_DISCOVERY_P0F: "false"
```

SSDP records only service type, USN and server identity. Advertised URLs are not
fetched. This implements the discovery protocol directly; no gssdp subprocess is
needed. IPv6 SSDP is not implemented. NetBIOS and SMB have ten-second command
bounds; anonymous SMB denial is normal and does not trigger password attempts.
NetBIOS requires `nmblookup` from the Debian `samba-common-bin` package, which
the image installs and verifies at build time. Unanswered NetBIOS requests are
normal for devices that do not implement the protocol and do not count as
collector errors. A missing executable produces a single warning instead of
one warning per device; timeouts and unexpected failures remain warnings.
No SMB file content is read. Cached target addresses need not still be reachable.

## Scan runtime and progress

Manual `yggflare network run` and scheduled scans report unbuffered phase
start/end timings to stderr/stdout, with 15-second heartbeats while long-running
subprocesses are captured. This makes host discovery, focused/top-100 TCP scans,
DNS-SD and supplemental discovery distinguishable without logging packet data,
secrets or raw scan output.

Supplemental Nmap targets remain bounded to 64 address/interface pairs per
family, but are scanned in batches **by address family and selected interface**
instead of starting one Nmap process per target. Each batch has a 90-second
process limit and each host retains the existing 15-second Nmap host limit.
Parsed XML is attributed only to the explicit scoped addresses in that batch.
NDP probes remain interface-specific, while up to 16 NetBIOS targets are
queried using at most four concurrent workers. These are best-effort
observations; individual collector failures remain warnings, not DNS changes.

The regular IPv4 scan still makes distinct host-discovery, focused-port/service
and top-100-port passes. The new phase timings distinguish whether those
passes or supplemental work dominate a given deployment. Performance depends
on host reachability and service-response behavior, so no fixed runtime
guarantee is implied.

## LLDP/CDP

The image supplies `lldpcli`. Run `lldpd` on the host, configured for receive-only
mode and CDP support (`-r -c`) on the intended interfaces. Mount its runtime socket
into the container at `/run/lldpd/lldpd.socket`, then enable the LLDP switch. For a
host using the same directory:

```yaml
volumes:
  - /run/lldpd:/run/lldpd:ro
```

The collector only issues `show neighbors details`; it does not start or configure
the host daemon. A read-only bind mount does not make the socket API read-only.
Only selected interfaces' chassis/name/description/port identity is displayed.
Neighbours without management IPs remain visible as link-layer observations.
Discovery is limited to advertisements reaching that host's interfaces, not the
entire switched network.

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
