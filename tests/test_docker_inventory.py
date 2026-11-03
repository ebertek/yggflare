"""Offline Docker/Compose enrichment, fallback and confidentiality regressions."""

import ipaddress
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import docker_inventory as inventory

NETWORK = ipaddress.ip_network("10.4.20.0/23")
COMPOSE = """
name: core
x-common: &common
  hostname: resolver
  mac_address: "0e:be:00:da:00:34"
services:
  dns:
    <<: *common
    container_name: dns
    environment:
      WEB_PORT: '5380'
      PASSWORD: never-export-this
      SECRET_PORT: '12345'
      DB_PORT: '5432'
      TRAEFIK_ENTRYPOINTS_DNS_ADDRESS: ':53/udp'
    ports:
      - '127.0.0.1:15353:53/udp'
      - target: 80
        published: '8080'
        protocol: tcp
    expose: ['443', '9000-9001/tcp']
    labels:
      traefik.http.routers.dns.rule: 'Host(`dns.example.net`)'
      traefik.http.services.dns.loadbalancer.server.port: '5380'
      unrelated.secret: never-export-this
    networks:
      lan:
        ipv4_address: 10.4.21.34
        ipv6_address: fd00::34
        aliases: [ns, resolver-alias]
  host-service:
    network_mode: host
    environment:
      SERVICE_PORT: '9999'
"""


def live(ip="10.4.21.34", running=True):
    return {
        "Name": "/dns",
        "State": {"Running": running},
        "Config": {
            "Hostname": "resolver",
            "Env": ["PORT=8081", "TOKEN=never-export-this"],
            "ExposedPorts": {"53/udp": {}, "853/tcp": {}},
            "Labels": {
                "com.docker.compose.project": "core",
                "com.docker.compose.service": "dns",
            },
        },
        "NetworkSettings": {
            "Ports": {"80/tcp": [{"HostPort": "8080"}]},
            "Networks": {
                "lan": {
                    "IPAddress": ip,
                    "GlobalIPv6Address": "fd00::35",
                    "MacAddress": "aa:bb:cc:dd:ee:ff",
                    "Aliases": ["live-alias"],
                }
            },
        },
    }


class DockerInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "compose.yaml").write_text(COMPOSE)

    def test_compose_fallback_and_secret_projection(self):
        with patch.object(
            inventory, "inspect_containers", side_effect=OSError("never-export-this")
        ):
            hosts, warnings = inventory.collect(self.root, NETWORK, "home.example")
        self.assertEqual(len(hosts), 1)
        dns = hosts[0]
        self.assertEqual(dns["hostname"], "resolver.home.example")
        self.assertEqual(dns["ipv6"], "fd00::34")
        self.assertEqual(dns["mac"], "0e:be:00:da:00:34")
        self.assertEqual(dns["aliases"], ["dns.example.net", "ns", "resolver-alias"])
        self.assertEqual(
            set(dns["ports"]),
            {"udp/53", "tcp/80", "tcp/443", "tcp/5380", "tcp/9000", "tcp/9001"},
        )
        self.assertEqual(dns["status"], "docker declared")
        self.assertTrue(warnings)
        self.assertNotIn("never-export-this", json.dumps([hosts, warnings]))

    def test_runtime_merges_evidence_and_network_identity(self):
        with patch.object(inventory, "inspect_containers", return_value=[live()]):
            hosts, warnings = inventory.collect(self.root, NETWORK, "home.example")
        self.assertFalse(warnings)
        self.assertEqual(len(hosts), 1)
        dns = hosts[0]
        self.assertEqual(dns["status"], "docker running")
        self.assertEqual(dns["ipv6"], "fd00::35")
        self.assertEqual(dns["mac"], "aa:bb:cc:dd:ee:ff")
        self.assertIn("live-alias", dns["aliases"])
        self.assertIn("ns", dns["aliases"])
        self.assertIn("tcp/853", dns["ports"])
        self.assertIn("tcp/8081", dns["ports"])
        self.assertNotIn("tcp/8080", dns["ports"])
        self.assertIn("Docker port binding", dns["port_sources"]["tcp/80"])
        self.assertNotIn("never-export-this", json.dumps(hosts))

    def test_changed_live_ip_and_stopped_declarations(self):
        for running, expected in [(True, "10.4.21.35"), (False, "10.4.21.34")]:
            with (
                self.subTest(running=running),
                patch.object(
                    inventory,
                    "inspect_containers",
                    return_value=[live("10.4.21.35", running)],
                ),
            ):
                hosts, _ = inventory.collect(self.root, NETWORK, "home.example")
            self.assertEqual(hosts[0]["ipv4"], expected)
            self.assertEqual(
                hosts[0]["status"], "docker running" if running else "docker stopped"
            )

    def test_multiple_runtime_only_containers_do_not_require_compose_identity(self):
        (self.root / "compose.yaml").unlink()
        containers = [live("10.4.21.34"), live("10.4.21.35")]
        containers[0]["Name"] = "/runtime-a"
        containers[1]["Name"] = "/runtime-b"
        for item in containers:
            item["Config"]["Labels"] = {}
        with patch.object(inventory, "inspect_containers", return_value=containers):
            hosts, warnings = inventory.collect(self.root, NETWORK, "home.example")
        self.assertEqual(len(hosts), 2)
        self.assertEqual([h["ipv4"] for h in hosts], ["10.4.21.34", "10.4.21.35"])
        self.assertTrue(all(h["source"] == "Docker" for h in hosts))
        self.assertFalse(warnings)

    def test_runtime_only_and_outside_lan(self):
        (self.root / "compose.yaml").unlink()
        container = live()
        with patch.object(inventory, "inspect_containers", return_value=[container]):
            hosts, _ = inventory.collect(self.root, NETWORK, "home.example")
        self.assertEqual(hosts[0]["source"], "Docker")
        self.assertEqual(hosts[0]["hostname"], "resolver.home.example")
        self.assertIsNone(inventory.endpoint("172.17.0.2", "", "", [], NETWORK))

    def test_broken_yaml_isolated_and_warning_sanitized(self):
        broken = self.root / "broken"
        broken.mkdir()
        (broken / "compose.yaml").write_text("secret: [never-export-this")
        with patch.object(inventory, "inspect_containers", return_value=[]):
            hosts, warnings = inventory.collect(self.root, NETWORK, "")
        self.assertEqual(len(hosts), 1)
        self.assertEqual(len(warnings), 1)
        self.assertNotIn("never-export-this", str(warnings))

    def test_shared_network_resolves_scoped_parent_and_ports(self):
        (self.root / "compose.yaml").write_text(
            """
name: downloads
services:
  gluetun:
    networks:
      lan: {ipv4_address: 10.4.21.39, ipv6_address: 'fd00::39'}
    labels:
      traefik.http.routers.mousehole.rule: 'Host(`mousehole.example.net`)'
      traefik.http.services.mousehole.loadbalancer.server.port: '5010'
      traefik.http.services.other.loadbalancer.server.port: '1234'
  mousehole:
    network_mode: service:gluetun
  download:
    network_mode: service:gluetun
    environment: {QBT_WEBUI_PORT: '8080'}
  unrelated:
    network_mode: host
  cycle1:
    network_mode: service:cycle2
  cycle2:
    network_mode: service:cycle1
  missing:
    network_mode: service:absent
"""
        )
        other = self.root / "other"
        other.mkdir()
        (other / "compose.yaml").write_text(
            "name: other\nservices:\n  gluetun:\n    network_mode: host\n"
        )
        with patch.object(inventory, "inspect_containers", return_value=[]):
            hosts, _ = inventory.collect(self.root, NETWORK, "home.example")
        self.assertEqual(len(hosts), 3)
        mouse = next(h for h in hosts if h["hostname"].startswith("mousehole."))
        self.assertEqual(mouse["ipv4"], "10.4.21.39")
        self.assertEqual(mouse["ipv6"], "fd00::39")
        self.assertEqual(mouse["shared_network"], "gluetun")
        self.assertEqual(mouse["ports"], ["tcp/5010"])
        self.assertIn("mousehole.example.net", mouse["aliases"])

    def test_runtime_shared_container_id_and_bridge_exclusion(self):
        (self.root / "compose.yaml").unlink()
        parent = live()
        parent["Id"] = "a" * 64
        child = {
            "Name": "/child",
            "HostConfig": {"NetworkMode": "container:" + "a" * 64},
        }
        bridge = live("172.17.0.2")
        bridge["Name"] = "/bridge"
        with patch.object(
            inventory, "inspect_containers", return_value=[child, parent, bridge]
        ):
            hosts, _ = inventory.collect(self.root, NETWORK, "home.example")
        self.assertEqual(len(hosts), 2)
        self.assertEqual(hosts[0]["shared_network"], "dns")
        self.assertEqual(hosts[0]["ipv4"], "10.4.21.34")

    def test_port_syntax_and_limits(self):
        result = inventory.ports(
            {
                "ports": [
                    "[::1]:8080:80",
                    "1000-1002:2000-2002/udp",
                    "1-65535",
                    "${PORT}:abc",
                ],
                "environment": [
                    "PORT=7777",
                    "REMOTE_PORT=2222",
                    "OAUTH2_PROXY_HTTP_ADDRESS=0.0.0.0:4180",
                ],
            },
            {
                "traefik.http.services.host.loadbalancer.server.url": "http://10.4.21.1:8787"
            },
        )
        self.assertEqual(
            set(result),
            {
                "tcp/80",
                "udp/2000",
                "udp/2001",
                "udp/2002",
                "tcp/7777",
                "tcp/4180",
                "tcp/8787",
            },
        )

    def test_numeric_addresses_and_subnets_invalid_last(self):
        for values in [
            ["10.4.21.100", "10.4.21.10", "10.4.21.99", "10.4.21.9"],
            ["10.4.21.224/27", "10.4.21.32/27"],
            ["fd00::10", "fd00::9"],
        ]:
            ordered = sorted(values, key=inventory.address_key)
            self.assertEqual(
                ordered,
                sorted(
                    values,
                    key=lambda v: int(
                        ipaddress.ip_network(v, strict=False).network_address
                    ),
                ),
            )
        self.assertEqual(
            sorted(["", "10.4.21.9", "invalid"], key=inventory.address_key)[0],
            "10.4.21.9",
        )

    def test_cache_avoids_docker_call_per_request(self):
        inventory._CACHE.clear()
        self.addCleanup(inventory._CACHE.clear)
        with patch.object(inventory, "collect", return_value=([], [])) as collect:
            inventory.snapshot(self.root, NETWORK, "")
            inventory.snapshot(self.root, NETWORK, "")
        collect.assert_called_once()
