"""Supplemental observations stay scoped and optional."""

import ipaddress
import json
import subprocess
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

    def test_router_advertisements_are_interface_topology_not_scan_targets(self):
        calls = []

        def run(args):
            calls.append(args)
            if args[:3] == ["ip", "-j", "neigh"]:
                return "[]"
            if args[0] == "rdisc6":
                return (
                    "Router preference : high\n"
                    "Router lifetime : 1800 (0x00000708) seconds\n"
                    " Prefix : fd0e:be00:da00:20::/64\n"
                    " Prefix : 2001:db8::/64\n"
                    " from fe80::1\n"
                )
            return ""

        with patch.dict(
            "os.environ",
            {
                "YGGFLARE_DISCOVERY_INTERFACES": "eth0",
                "YGGFLARE_DISCOVERY_IPV6_CIDRS": "fd0e:be00:da00:20::/64",
                "YGGFLARE_DISCOVERY_RA": "true",
                "YGGFLARE_DISCOVERY_IPV6_SCAN": "true",
            },
            clear=True,
        ):
            result = discovery.collect(ipaddress.ip_network("10.4.20.0/23"), run)
        probes = [args for args in calls if args[0] == "rdisc6"]
        self.assertEqual(
            probes, [["rdisc6", "-n", "-r", "1", "-w", "750", "ff02::2", "eth0"]]
        )
        self.assertFalse(any(args[0] == "nmap" for args in calls))
        ra = [r for r in result["records"] if r["source"] == "IPv6 router advertisement"]
        self.assertEqual(len(ra), 1)
        self.assertEqual(ra[0]["ip"], "")
        self.assertEqual(ra[0]["interface"], "eth0")
        self.assertIn("fd0e:be00:da00:20::/64", ra[0]["detail"])
        self.assertNotIn("2001:db8", ra[0]["detail"])
        self.assertEqual(result["warnings"], [])

    def test_rdisc6_no_reply_is_normal_but_execution_errors_warn(self):
        for returncode in (1, 2):
            calls = []

            def run(args):
                calls.append(args)
                if args[:3] == ["ip", "-j", "neigh"]:
                    return "[]"
                if args[0] == "rdisc6":
                    raise subprocess.CalledProcessError(returncode, "rdisc6")
                return ""

            with patch.dict(
                "os.environ",
                {
                    "YGGFLARE_DISCOVERY_INTERFACES": "eth0",
                    "YGGFLARE_DISCOVERY_IPV6_CIDRS": "fd00::/64",
                    "YGGFLARE_DISCOVERY_RA": "true",
                },
                clear=True,
            ):
                result = discovery.collect(
                    ipaddress.ip_network("10.0.0.0/24"), run
                )
            self.assertEqual(
                result["warnings"],
                [] if returncode == 2 else ["rdisc6: unavailable, failed or timed out"],
            )
            self.assertEqual(result["records"], [])

    def test_router_discovery_requires_explicit_ipv6_prefix(self):
        with (
            patch.dict(
                "os.environ",
                {
                    "YGGFLARE_DISCOVERY_INTERFACES": "eth0",
                    "YGGFLARE_DISCOVERY_RA": "true",
                },
                clear=True,
            ),
            self.assertRaisesRegex(ValueError, "explicit IPv6 prefix scope"),
        ):
            discovery.collect(ipaddress.ip_network("10.0.0.0/24"))

    def test_ndp_no_reply_is_not_a_failure_but_other_errors_warn(self):
        for returncode in (1, 2):
            calls = []

            def run(args):
                calls.append(args)
                if args[:3] == ["ip", "-j", "neigh"]:
                    return '[{"dst":"fd00::2","state":["REACHABLE"]}]'
                if args[0] == "ndisc6":
                    raise subprocess.CalledProcessError(returncode, "ndisc6")
                return ""

            with patch.dict(
                "os.environ",
                {
                    "YGGFLARE_DISCOVERY_INTERFACES": "eth0",
                    "YGGFLARE_DISCOVERY_IPV6_CIDRS": "fd00::/64",
                    "YGGFLARE_DISCOVERY_NDP_PROBE": "true",
                },
                clear=True,
            ):
                result = discovery.collect(ipaddress.ip_network("10.0.0.0/24"), run)
            self.assertEqual(len([x for x in calls if x[0] == "ndisc6"]), 1)
            self.assertEqual(
                result["warnings"],
                [] if returncode == 2 else ["ndisc6: unavailable, failed or timed out"],
            )
            self.assertFalse(any(r["source"] == "NDP reply" for r in result["records"]))

    def test_multi_interface_ipv4_probe_deduplicates_without_losing_evidence(self):
        """Both ARP/neighbor sightings survive, but an IP is probed once."""
        calls = []

        def run(args):
            calls.append(args)
            if args[:3] == ["ip", "-j", "neigh"]:
                return json.dumps(
                    [
                        {"dst": "10.0.0.2", "state": ["REACHABLE"]},
                        {"dst": "10.0.0.3", "state": ["STALE"]},
                    ]
                )
            if "route" in args:
                return '[{"dev":"eth1"}]'
            if args[0] == "nmap":
                return (
                    '<nmaprun><host><address addr="10.0.0.2" addrtype="ipv4"/>'
                    '<os><osmatch name="Linux" accuracy="95"/></os></host></nmaprun>'
                )
            return "[]"

        with patch.dict(
            "os.environ",
            {
                "YGGFLARE_DISCOVERY_INTERFACES": "eth0,eth1",
                "YGGFLARE_DISCOVERY_OS_DETECTION": "true",
            },
            clear=True,
        ):
            result = discovery.collect(ipaddress.ip_network("10.0.0.0/24"), run)
        nmap = [x for x in calls if x[0] == "nmap"]
        self.assertEqual(len(nmap), 1)
        self.assertEqual(nmap[0][nmap[0].index("-e") + 1], "eth1")
        self.assertEqual(nmap[0][-2:], ["10.0.0.2", "10.0.0.3"])
        self.assertEqual(
            {
                (r["ip"], r["interface"])
                for r in result["records"]
                if r["source"] == "Neighbor cache"
            },
            {
                ("10.0.0.2", "eth0"),
                ("10.0.0.2", "eth1"),
                ("10.0.0.3", "eth0"),
                ("10.0.0.3", "eth1"),
            },
        )
        self.assertTrue(
            any(
                r["source"] == "Nmap OS estimate" and r["ip"] == "10.0.0.2"
                for r in result["records"]
            )
        )

    def test_cap_counts_unique_ips_not_address_interface_pairs(self):
        """Forty hosts seen twice should not be scanned twice."""
        calls = []

        def run(args):
            calls.append(args)
            if args[:3] == ["ip", "-j", "neigh"]:
                return json.dumps(
                    [
                        {"dst": f"10.0.0.{i}", "state": ["REACHABLE"]}
                        for i in range(1, 41)
                    ]
                )
            if "route" in args:
                return '[{"dev":"eth0"}]'
            return "<nmaprun/>" if args[0] == "nmap" else "[]"

        with patch.dict(
            "os.environ",
            {
                "YGGFLARE_DISCOVERY_INTERFACES": "eth0,eth1",
                "YGGFLARE_DISCOVERY_OS_DETECTION": "true",
            },
            clear=True,
        ):
            result = discovery.collect(ipaddress.ip_network("10.0.0.0/24"), run)
        nmap = [x for x in calls if x[0] == "nmap"]
        self.assertEqual(len(nmap), 1)
        self.assertEqual(len(nmap[0][-40:]), 40)
        self.assertEqual(len(set(nmap[0][-40:])), 40)
        self.assertFalse(any("limited" in w for w in result["warnings"]))

    def test_more_than_sixty_four_hosts_are_scanned_in_bounded_batches(self):
        """Capacity is a per-Nmap-process batch, not a discovery cutoff."""
        calls = []

        def run(args):
            calls.append(args)
            if args[:3] == ["ip", "-j", "neigh"]:
                return json.dumps(
                    [
                        {"dst": f"10.0.0.{i}", "state": ["REACHABLE"]}
                        for i in range(1, 91)
                    ]
                )
            return "<nmaprun/>" if args[0] == "nmap" else "[]"

        with patch.dict(
            "os.environ",
            {
                "YGGFLARE_DISCOVERY_INTERFACES": "eth0",
                "YGGFLARE_DISCOVERY_OS_DETECTION": "true",
            },
            clear=True,
        ):
            result = discovery.collect(ipaddress.ip_network("10.0.0.0/24"), run)

        batches = [call for call in calls if call[0] == "nmap"]
        self.assertEqual(len(batches), 2)
        self.assertEqual(len(batches[0][-64:]), 64)
        self.assertEqual(len(batches[1][-26:]), 26)
        self.assertEqual(
            {ip for batch in batches for ip in batch if ip.startswith("10.0.0.")},
            {f"10.0.0.{i}" for i in range(1, 91)},
        )
        self.assertFalse(any("limited" in item for item in result["warnings"]))

    def test_discovery_budget_is_configurable_and_checked(self):
        for value in ("0", "4097", "garbage"):
            with (
                patch.dict(
                    "os.environ",
                    {
                        "YGGFLARE_DISCOVERY_INTERFACES": "eth0",
                        "YGGFLARE_DISCOVERY_MAX_TARGETS": value,
                    },
                    clear=True,
                ),
                self.assertRaises(ValueError),
            ):
                discovery.collect(ipaddress.ip_network("10.0.0.0/24"))

        def run(args):
            if args[:3] == ["ip", "-j", "neigh"]:
                return json.dumps(
                    [
                        {"dst": f"10.0.0.{i}", "state": ["REACHABLE"]}
                        for i in range(1, 6)
                    ]
                )
            return "<nmaprun/>" if args[0] == "nmap" else "[]"

        with patch.dict(
            "os.environ",
            {
                "YGGFLARE_DISCOVERY_INTERFACES": "eth0",
                "YGGFLARE_DISCOVERY_OS_DETECTION": "true",
                "YGGFLARE_DISCOVERY_MAX_TARGETS": "3",
            },
            clear=True,
        ):
            result = discovery.collect(ipaddress.ip_network("10.0.0.0/24"), run)
        self.assertIn(
            "IPv4 probe targets limited to 3 unique addresses",
            result["warnings"],
        )

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
