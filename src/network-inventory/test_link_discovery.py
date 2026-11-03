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
                if args[0] == "docker":
                    return ""
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
            self.assertEqual(len(calls), 3)
            self.assertIn("-6", calls[-1])
            self.assertIn("-O", calls[-1])
            self.assertEqual(calls[-1][-1], "fd00::2")

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
        self.assertIn("-O", calls[-1])
        self.assertNotIn("-6", calls[-1])
        self.assertIn("--osscan-limit", calls[-1])
        self.assertEqual(result["records"][-1]["source"], "Nmap OS estimate")
        self.assertIn("95%", result["records"][-1]["detail"])

    def test_docker_and_dns_sd_candidates_require_scope_and_allowed_route(self):
        calls = []

        def run(args):
            calls.append(args)
            if args[:3] == ["ip", "-j", "neigh"]:
                return "[]"
            if args[:2] == ["docker", "ps"]:
                return "a" * 12
            if args[:2] == ["docker", "inspect"]:
                return json.dumps(
                    [
                        {
                            "State": {"Running": True},
                            "NetworkSettings": {
                                "Networks": {"lan": {"GlobalIPv6Address": "fd00::2"}}
                            },
                        }
                    ]
                )
            if "route" in args:
                return json.dumps(
                    [{"dev": "eth0" if args[-1] != "fd00::4" else "docker0"}]
                )
            return "<nmaprun/>"

        with patch.dict(
            "os.environ",
            {
                "YGGFLARE_DISCOVERY_INTERFACES": "eth0",
                "YGGFLARE_DISCOVERY_IPV6_CIDRS": "fd00::/64",
                "YGGFLARE_DISCOVERY_IPV6_SCAN": "true",
            },
            clear=True,
        ):
            result = discovery.collect(
                ipaddress.ip_network("10.4.20.0/23"),
                run,
                seeds=[
                    ("fd00::3", "DNS-SD address"),
                    ("fd00::4", "DNS-SD address"),
                    ("2001:db8::1", "DNS-SD address"),
                ],
            )
        probes = [args for args in calls if args[0] == "nmap"]
        self.assertEqual(len(probes), 1)
        self.assertEqual(probes[0][-2:], ["fd00::2", "fd00::3"])
        self.assertEqual(
            {r["source"] for r in result["records"]},
            {"Docker address", "DNS-SD address"},
        )
        self.assertFalse(any("2001:db8::1" in args for args in calls))


    def test_batched_nmap_attaches_services_to_correct_host(self):
        """One interface/family batch must not misattribute another host's ports."""
        calls = []

        def run(args):
            calls.append(args)
            if args[:3] == ["ip", "-j", "neigh"]:
                return json.dumps(
                    [
                        {"dst": "fd00::2", "state": ["REACHABLE"]},
                        {"dst": "fd00::3", "state": ["REACHABLE"]},
                    ]
                )
            if args[0] == "docker":
                return ""
            if args[0] == "nmap":
                return (
                    "<nmaprun>"
                    '<host><address addr="fd00::2" addrtype="ipv6"/>'
                    '<ports><port protocol="tcp" portid="443">'
                    '<state state="open"/></port></ports></host>'
                    '<host><address addr="fd00::3" addrtype="ipv6"/>'
                    '<os><osmatch name="Linux" accuracy="91"/></os></host>'
                    '<host><address addr="fd00::99" addrtype="ipv6"/>'
                    '<ports><port protocol="tcp" portid="8080">'
                    '<state state="open"/></port></ports></host>'
                    "</nmaprun>"
                )
            return "[]"

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
            result = discovery.collect(ipaddress.ip_network("10.4.20.0/23"), run)
        nmap_calls = [args for args in calls if args[0] == "nmap"]
        self.assertEqual(len(nmap_calls), 1)
        self.assertEqual(nmap_calls[0][-2:], ["fd00::2", "fd00::3"])
        by_ip = {}
        for record in result["records"]:
            by_ip.setdefault(record["ip"], []).append(record["detail"])
        self.assertIn("tcp/443", " ".join(by_ip["fd00::2"]))
        self.assertNotIn("tcp/443", " ".join(by_ip["fd00::3"]))
        self.assertIn("accuracy 91%", " ".join(by_ip["fd00::3"]))
        self.assertNotIn("fd00::99", by_ip)
