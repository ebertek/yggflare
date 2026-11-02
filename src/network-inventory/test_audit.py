"""Offline fixtures for network discovery and repeat-alert suppression."""

import importlib.util
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "network_audit", Path(__file__).with_name("audit.py")
)
if SPEC is None or SPEC.loader is None:
    raise ImportError("Cannot load audit.py")
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)

XML = """<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/><address addr="10.4.20.33" addrtype="ipv4"/>
    <address addr="84:7C:9B:24:5D:9A" addrtype="mac"/>
    <ports>
      <port protocol="tcp" portid="6444"><state state="open"/></port>
      <port protocol="tcp" portid="22"><state state="closed"/></port>
      <port protocol="udp" portid="5550"><state state="open|filtered"/></port>
    </ports>
  </host>
  <host><status state="down"/><address addr="10.4.20.34" addrtype="ipv4"/></host>
</nmaprun>"""


class NetworkAuditTests(unittest.TestCase):
    """Scanners must not infer open services from uncertainty."""

    def test_docker_inspection_failure_aborts_instead_of_reporting_containers(self):
        """Do not mistake running containers for unexpected LAN devices."""
        with patch.object(audit, "run_command", side_effect=FileNotFoundError("docker")):
            with self.assertRaisesRegex(RuntimeError, "Docker inspection failed"):
                audit.docker_ips()

    def test_realistic_private_inventory_loads_without_ip_type_error(self):
        """Load canonical IPv4, companion addresses and mixed port metadata."""
        fixture = {
            "version": 1,
            "hosts": [
                {
                    "hostname": "aircon-sunroom.ygg.nu",
                    "ipv4": "10.4.20.242",
                    "mac": "84:7c:9b:24:5d:9a",
                    "ports": [
                        {"port": 6444, "protocol": "tcp"},
                        {"port": 5353, "protocol": "udp"},
                    ],
                    "additional_ipv4": ["10.4.21.242"],
                },
                {
                    "hostname": "older-device.ygg.nu",
                    "ipv4": "10.4.20.25",
                    "ports": [{"protocol": "tcp", "port": 80}, {"protocol": "tcp", "port": 443}],
                },
                {
                    "hostname": "unspecified-port.ygg.nu",
                    "ipv4": "10.4.20.26",
                    "ports": [{"port": 8080}],
                },
            ],
        }
        with TemporaryDirectory() as directory:
            path = Path(directory) / "static-hosts.json"
            path.write_text(json.dumps(fixture), encoding="utf-8")
            inventory = audit.load_inventory(path)
        self.assertEqual(inventory["10.4.20.242"]["ports"], {"tcp/6444", "udp/5353"})
        self.assertIs(
            inventory["10.4.20.242"],
            inventory["10.4.21.242"],
        )
        self.assertEqual(inventory["10.4.20.25"]["ports"], {"tcp/80", "tcp/443"})
        self.assertEqual(inventory["10.4.20.26"]["ports"], {"tcp/8080"})
        self.assertEqual(inventory["10.4.20.25"]["mac"], "")

    def test_rejects_inventory_address_outside_scanning_network(self):
        """Reject unscannable primary or companion IPs before network probing."""
        for record in (
            {"hostname": "bad.ygg.nu", "ipv4": "192.0.2.1"},
            {
                "hostname": "bad.ygg.nu",
                "ipv4": "10.4.20.10",
                "additional_ipv4": ["192.0.2.1"],
            },
        ):
            with self.subTest(record=record), TemporaryDirectory() as directory:
                path = Path(directory) / "static-hosts.json"
                path.write_text(
                    json.dumps({"version": 1, "hosts": [record]}),
                    encoding="utf-8",
                )
                with self.assertRaises(ValueError):
                    audit.load_inventory(path)

    def test_xml_only_counts_confirmed_open(self):
        """Verify xml only counts confirmed open."""
        hosts = audit.parse_nmap_xml(XML)
        self.assertEqual(list(hosts), ["10.4.20.33"])
        self.assertEqual(hosts["10.4.20.33"]["mac"], "84:7c:9b:24:5d:9a")
        self.assertEqual(hosts["10.4.20.33"]["ports"], ["tcp/6444"])

    def test_avahi_deduplicates_ip_versions_and_interfaces(self):
        """Verify avahi deduplicates ip versions and interfaces."""
        line = "=;eth0;IPv4;Aircon;_example._tcp;local;air.local;10.4.20.33;6444;data"
        another = "=;eth1;IPv6;Aircon;_example._tcp;local;air.local;fd00::1;6444;data"
        records = audit.parse_avahi(line + "\n" + another)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["port"], 6444)

    def test_new_service_alert_once_until_it_disappears(self):
        """Verify new service alert once until it disappears."""
        inventory = {
            "10.4.20.33": {
                "name": "aircon-sunroom.ygg.nu",
                "mac": "84:7c:9b:24:5d:9a",
                "ports": set(),
            }
        }
        hosts = audit.parse_nmap_xml(XML)
        events, reported, services = audit.calculate_events(
            inventory, hosts, [], {}, set()
        )
        self.assertEqual(len(events), 1)
        self.assertIn("tcp/6444", events[0])
        previous = {
            "initialized": True,
            "reported": reported,
            "advertisements": services,
        }
        events, _, _ = audit.calculate_events(inventory, hosts, [], previous, set())
        self.assertEqual(events, [])

    def test_unknown_device_and_identity_drift(self):
        """Verify unknown device and identity drift."""
        inventory = {
            "10.4.20.33": {
                "name": "aircon-sunroom.ygg.nu",
                "mac": "84:7c:9b:24:5d:9a",
                "ports": set(),
            }
        }
        hosts = {
            "10.4.20.33": {"mac": "00:11:22:33:44:55", "ports": []},
            "10.4.20.118": {"mac": "18:48:be:cf:90:3d", "ports": []},
        }
        events, _, _ = audit.calculate_events(inventory, hosts, [], {}, set())
        self.assertEqual(len(events), 2)
        self.assertTrue(any("CHANGED MAC" in event for event in events))
        self.assertTrue(any("NEW DEVICE" in event for event in events))

    def test_known_mac_on_new_ip_is_address_change(self):
        """Recognize a known appliance at a new IP without mislabeling it unknown."""
        inventory = {
            "10.4.20.33": {
                "name": "aircon-sunroom.ygg.nu",
                "mac": "84:7c:9b:24:5d:9a",
                "ports": set(),
            }
        }
        hosts = {
            "10.4.21.242": {
                "mac": "84:7c:9b:24:5d:9a",
                "ports": ["tcp/6444"],
            }
        }
        events, _, _ = audit.calculate_events(inventory, hosts, [], {}, set())
        self.assertTrue(any("CHANGED IP" in item for item in events))
        self.assertTrue(any("NEW PORT" in item for item in events))
        self.assertFalse(any("NEW DEVICE" in item for item in events))

    def test_approved_observed_mac_and_unapproved_mac(self):
        """Approved proxy MAC suppresses drift; unexpected MAC still alerts."""
        record = {
            "version": 1,
            "hosts": [
                {
                    "hostname": "sub.ygg.nu",
                    "ipv4": "10.4.20.101",
                    "mac": "c4:38:75:d1:66:9a",
                    "observed_macs": ["C4:38:75:B2:8D:F7"],
                }
            ],
        }
        with TemporaryDirectory() as directory:
            path = Path(directory) / "static-hosts.json"
            path.write_text(json.dumps(record), encoding="utf-8")
            inventory = audit.load_inventory(path)
        entry = inventory["10.4.20.101"]
        self.assertEqual(entry["mac"], "c4:38:75:d1:66:9a")
        self.assertIn("c4:38:75:b2:8d:f7", entry["allowed_macs"])
        events, _, _ = audit.calculate_events(
            inventory,
            {"10.4.20.101": {"mac": "c4:38:75:b2:8d:f7", "ports": []}},
            [],
            {},
            set(),
        )
        self.assertEqual(events, [])
        events, _, _ = audit.calculate_events(
            inventory,
            {"10.4.20.101": {"mac": "00:11:22:33:44:55", "ports": []}},
            [],
            {},
            set(),
        )
        self.assertEqual(len(events), 1)
        self.assertIn("CHANGED MAC", events[0])

    def test_invalid_observed_macs_rejected(self):
        """Malformed or non-list alternate MACs must fail validation."""
        for value, error_type in (
            ("c4:38:75:b2:8d:f7", TypeError),
            (["not-a-mac"], ValueError),
            ([42], ValueError),
        ):
            with self.subTest(value=value), TemporaryDirectory() as directory:
                path = Path(directory) / "static-hosts.json"
                path.write_text(
                    json.dumps(
                        {
                            "version": 1,
                            "hosts": [
                                {
                                    "hostname": "sub.ygg.nu",
                                    "ipv4": "10.4.20.101",
                                    "observed_macs": value,
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                with self.assertRaises(error_type):
                    audit.load_inventory(path)

    def test_dns_sd_port_change_keeps_observation_without_alert(self):
        """Dynamic advertised ports should not be classified as new services."""
        previous = {
            "initialized": True,
            "reported": {},
            "advertisements": ["LGwebOSTV.local|_hap._tcp|45857"],
        }
        advertisements = [
            {"host": "LGwebOSTV.local", "service": "_hap._tcp", "port": 42963}
        ]
        events, _, saved = audit.calculate_events(
            {}, {}, advertisements, previous, set()
        )
        self.assertEqual(events, [])
        self.assertEqual(saved, ["LGwebOSTV.local|_hap._tcp|42963"])

    def test_dns_sd_new_service_and_reappearance(self):
        """New service types alert once and alert again after withdrawal."""
        previous = {
            "initialized": True,
            "reported": {},
            "advertisements": ["device.local|_hap._tcp|12345"],
        }
        advertisements = [
            {"host": "device.local", "service": "_hap._tcp", "port": 54321},
            {"host": "device.local", "service": "_other._tcp", "port": 10000},
            {"host": "device.local", "service": "_other._tcp", "port": 10001},
        ]
        events, _, saved = audit.calculate_events(
            {}, {}, advertisements, previous, set()
        )
        self.assertEqual(events, ["NEW DNS-SD device.local|_other._tcp|10000"])
        previous["advertisements"] = saved
        events, _, _ = audit.calculate_events({}, {}, advertisements, previous, set())
        self.assertEqual(events, [])
        previous["advertisements"] = []
        events, _, _ = audit.calculate_events({}, {}, advertisements, previous, set())
        self.assertEqual(len(events), 2)

    def test_unavailable_dns_sd_does_not_clear_history(self):
        """Verify unavailable dns sd does not clear history."""
        previous = {
            "initialized": True,
            "reported": {},
            "advertisements": ["air.local|_example._tcp|6444"],
        }
        _, _, recorded = audit.calculate_events(
            {}, {}, [], previous, set(), dns_sd_complete=False
        )
        self.assertEqual(recorded, previous["advertisements"])


if __name__ == "__main__":
    unittest.main()
