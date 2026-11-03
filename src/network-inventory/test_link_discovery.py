"""Supplemental observations stay scoped and optional."""

import ipaddress
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import link_discovery as discovery


class LinkDiscoveryTests(unittest.TestCase):
    def test_scope_failed_neighbors_and_explicit_ipv6_targets(self):
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "discovery.json"
            config.write_text(
                json.dumps(
                    {
                        "interfaces": ["eth0"],
                        "ipv6_prefixes": ["fd00::/64"],
                        "ipv6_scan": True,
                        "os_detection": True,
                    }
                )
            )
            calls = []

            def run(args):
                calls.append(args)
                if args[0] == "ip":
                    return json.dumps(
                        [
                            {"dst": "fd00::2", "state": ["STALE"]},
                            {"dst": "2001:db8::2", "state": ["REACHABLE"]},
                            {"dst": "fd00::3", "state": ["FAILED"]},
                        ]
                    )
                return '<nmaprun><host><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>'

            with patch.object(discovery, "CONFIG", config):
                result = discovery.collect(ipaddress.ip_network("10.4.20.0/23"), run)
            self.assertEqual({r["ip"] for r in result["records"]}, {"fd00::2"})
            self.assertEqual(len(calls), 2)
            self.assertIn("-6", calls[1])
            self.assertIn("-O", calls[1])
            self.assertEqual(calls[1][-1], "fd00::2")

    def test_missing_configuration_is_disabled(self):
        with patch.object(discovery, "CONFIG", Path("/nonexistent-discovery-config")):
            self.assertEqual(discovery.collect(ipaddress.ip_network("10.0.0.0/24")), {})

    def test_invalid_interface_rejected_before_commands(self):
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "discovery.json"
            config.write_text('{"interfaces":["-bad"]}')
            with (
                patch.object(discovery, "CONFIG", config),
                self.assertRaises(ValueError),
            ):
                discovery.collect(ipaddress.ip_network("10.0.0.0/24"))
