"""Supplemental observations stay scoped and optional."""

import ipaddress
import json
import unittest
from unittest.mock import patch

import link_discovery as discovery


class LinkDiscoveryTests(unittest.TestCase):
    def test_scope_failed_neighbors_and_explicit_ipv6_targets(self):
        with patch.dict(
            "os.environ",
            {
                "YGGFLARE_DISCOVERY_INTERFACES": "eth0",
                "YGGFLARE_DISCOVERY_IPV6_CIDRS": "fd00::/64",
                "YGGFLARE_DISCOVERY_IPV6_SCAN": "true",
                "YGGFLARE_DISCOVERY_OS_DETECTION": "true",
            },
            clear=True,
        ):
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

            result = discovery.collect(ipaddress.ip_network("10.4.20.0/23"), run)
            self.assertEqual({r["ip"] for r in result["records"]}, {"fd00::2"})
            self.assertEqual(len(calls), 2)
            self.assertIn("-6", calls[1])
            self.assertIn("-O", calls[1])
            self.assertEqual(calls[1][-1], "fd00::2")

    def test_missing_configuration_is_disabled(self):
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(discovery.collect(ipaddress.ip_network("10.0.0.0/24")), {})

    def test_invalid_configuration_rejected_before_commands(self):
        for settings in (
            {"YGGFLARE_DISCOVERY_INTERFACES": "-bad"},
            {"YGGFLARE_DISCOVERY_INTERFACES": "eth0, "},
            {
                "YGGFLARE_DISCOVERY_INTERFACES": "eth0",
                "YGGFLARE_DISCOVERY_IPV6_CIDRS": "fd00::/32",
            },
            {
                "YGGFLARE_DISCOVERY_INTERFACES": "eth0",
                "YGGFLARE_DISCOVERY_ARP_SCAN": "yes",
            },
        ):
            with (
                patch.dict("os.environ", settings, clear=True),
                self.assertRaises(ValueError),
            ):
                discovery.collect(ipaddress.ip_network("10.0.0.0/24"))

    def test_ipv4_os_detection_and_estimate(self):
        calls = []

        def run(args):
            calls.append(args)
            if args[0] == "ip":
                return '[{"dst":"10.4.20.9","state":["REACHABLE"]}]'
            return '<nmaprun><host><os><osmatch name="Linux" accuracy="95"/></os></host></nmaprun>'

        with patch.dict(
            "os.environ",
            {
                "YGGFLARE_DISCOVERY_INTERFACES": "eth0",
                "YGGFLARE_DISCOVERY_OS_DETECTION": "true",
            },
            clear=True,
        ):
            result = discovery.collect(ipaddress.ip_network("10.4.20.0/23"), run)
        self.assertIn("-O", calls[1])
        self.assertNotIn("-6", calls[1])
        self.assertIn("--osscan-limit", calls[1])
        self.assertEqual(result["records"][-1]["source"], "Nmap OS estimate")
        self.assertIn("95%", result["records"][-1]["detail"])
