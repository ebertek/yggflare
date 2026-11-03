"""Offline fixtures for network discovery and repeat-alert suppression."""

import importlib.util
import io
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
        with patch.object(
            audit, "run_command", side_effect=FileNotFoundError("docker")
        ):
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
                    "ports": [
                        {"protocol": "tcp", "port": 80},
                        {"protocol": "tcp", "port": 443},
                    ],
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

    def test_discord_notification_uses_named_user_agent(self):
        """Discord requests must not use Python's default urllib User-Agent."""
        from unittest.mock import MagicMock, patch

        with patch.object(audit.urllib.request, "urlopen") as send:
            response = MagicMock()
            response.status = 204
            send.return_value.__enter__.return_value = response
            audit.notify_discord(
                "https://discord.com/api/webhooks/1234567890123456789/example",
                ["TEST ONLY"],
            )
        request = send.call_args.args[0]
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.get_header("Content-type"), "application/json")
        self.assertEqual(
            request.get_header("User-agent"),
            "DiscordBot (https://github.com/ebertek/yggflare, 1.0)",
        )
        self.assertIn(b"TEST ONLY", request.data)

    def test_invalid_discord_id_prevents_http_request(self):
        """Malformed secrets are rejected locally without leaking the token."""
        invalid = "https://discord.com/api/webhooks/123456789012345678X/secret"
        with patch.object(audit.urllib.request, "urlopen") as post:
            with self.assertRaisesRegex(ValueError, "ASCII digits") as raised:
                audit.notify_discord(invalid, ["TEST ONLY"])
        post.assert_not_called()
        self.assertNotIn("secret", str(raised.exception))

    def test_discord_http_error_exposes_code_without_webhook(self):
        """Show useful Discord error details without printing credentials."""
        from urllib.error import HTTPError

        secret = (
            "https://discord.com/api/webhooks/1234567890123456789/" "SECRET_DO_NOT_LOG"
        )
        response = io.BytesIO(
            b'{"message":"Invalid Form Body","code":50035,"errors":{"name":"secret"}}'
        )
        error = HTTPError(secret, 400, "Bad Request", None, response)
        with patch.object(audit.urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(RuntimeError) as raised:
                audit.notify_discord(secret, ["TEST ONLY"])
        self.assertIn("HTTP 400", str(raised.exception))
        self.assertIn("Discord code 50035", str(raised.exception))
        self.assertIn("Invalid Form Body", str(raised.exception))
        self.assertNotIn("SECRET_DO_NOT_LOG", str(raised.exception))
        self.assertNotIn("errors", str(raised.exception))

    def test_webhook_failure_preserves_discovery_for_retry(self):
        """A rejected Discord POST must not roll back an expensive scan."""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            xml = root / "scan.xml"
            xml.write_text(XML, encoding="utf-8")
            inventory = root / "inventory.json"
            inventory.write_text('{"version":1,"hosts":[]}', encoding="utf-8")
            webhook = root / "webhook"
            webhook.write_text(
                "https://discord.com/api/webhooks/1234567890123456789/token",
                encoding="utf-8",
            )
            args = [
                "audit",
                "--inventory",
                str(inventory),
                "--state-dir",
                str(root),
                "--discovery-xml",
                str(xml),
            ]
            with (
                patch("sys.argv", args),
                patch.dict(
                    "os.environ",
                    {"YGGFLARE_NETWORK_DISCORD_WEBHOOK_FILE": str(webhook)},
                ),
                patch.object(audit, "notify_discord") as send,
            ):
                audit.main()  # First scan establishes baseline.
                send.assert_not_called()
                state = json.loads((root / "state.json").read_text())
                state["reported"] = {}  # Trigger a new observation.
                (root / "state.json").write_text(json.dumps(state))
                send.side_effect = RuntimeError("Discord webhook rejected: HTTP 400")
                audit.main()
                failed = json.loads((root / "state.json").read_text())
                self.assertTrue(failed["hosts"])
                self.assertTrue(failed["reported"])
                self.assertTrue(failed["pending_discord_events"])

                send.reset_mock(side_effect=True)
                audit.main()  # No new observations; retry queued ones.
                send.assert_called_once_with(
                    "https://discord.com/api/webhooks/1234567890123456789/token",
                    failed["pending_discord_events"],
                )
                recovered = json.loads((root / "state.json").read_text())
                self.assertEqual(recovered["pending_discord_events"], [])
                self.assertEqual(recovered["recent_events"], failed["recent_events"])

    def test_xml_only_counts_confirmed_open(self):
        """Verify xml only counts confirmed open."""
        hosts = audit.parse_nmap_xml(XML)
        self.assertEqual(list(hosts), ["10.4.20.33"])
        self.assertEqual(hosts["10.4.20.33"]["mac"], "84:7c:9b:24:5d:9a")
        self.assertEqual(hosts["10.4.20.33"]["ports"], ["tcp/6444"])

    def test_service_metadata_excludes_unrelated_xml_attributes(self):
        xml = XML.replace('<state state="open"', '<state state="open"')
        xml = xml.replace(
            "</port>",
            '<service name="http" product="Example" version="1" method="probed" secret="DO-NOT-EXPORT"/></port>',
        )
        hosts = audit.parse_nmap_xml(xml)
        self.assertEqual(
            hosts["10.4.20.33"]["services"]["tcp/6444"]["method"], "probed"
        )
        self.assertNotIn("DO-NOT-EXPORT", json.dumps(hosts))

    def test_offline_scan_persists_bounded_history_and_baseline(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "scan.xml"
            source.write_text(XML)
            inventory = root / "inventory.json"
            inventory.write_text('{"version":1,"hosts":[]}')
            args = [
                "audit",
                "--inventory",
                str(inventory),
                "--state-dir",
                str(root),
                "--discovery-xml",
                str(source),
            ]
            with (
                patch("sys.argv", args),
                patch.object(audit, "notify_discord") as notify,
            ):
                audit.main()
                state = json.loads((root / "state.json").read_text())
                self.assertTrue(state["recent_events"][0]["baseline"])
                notify.assert_not_called()
                state["recent_events"] = state["recent_events"] * 201
                state["reported"] = {}
                (root / "state.json").write_text(json.dumps(state))
                audit.main()
                updated = json.loads((root / "state.json").read_text())
                self.assertEqual(len(updated["recent_events"]), 200)
                self.assertFalse(updated["recent_events"][-1]["baseline"])
                last = updated["last_seen"]["10.4.20.33"]
                first = updated["first_seen"]["10.4.20.33"]
                source.write_text("<nmaprun></nmaprun>")
                audit.main()
                absent = json.loads((root / "state.json").read_text())
                self.assertEqual(absent["last_seen"]["10.4.20.33"], last)
                self.assertEqual(absent["first_seen"]["10.4.20.33"], first)
                self.assertEqual(absent["hosts"], {})

    def test_avahi_deduplicates_ip_versions_and_interfaces(self):
        """Verify avahi deduplicates ip versions and interfaces."""
        line = "=;eth0;IPv4;Aircon;_example._tcp;local;air.local;10.4.20.33;6444;data"
        another = "=;eth1;IPv6;Aircon;_example._tcp;local;air.local;fd00::1;6444;data"
        records = audit.parse_avahi(line + "\n" + another)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["port"], 6444)
        self.assertEqual(records[0]["addresses"], ["10.4.20.33", "fd00::1"])

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
