"""Offline IPv6 migration assessment and scope checks."""

import ipaddress
import unittest
from unittest.mock import patch

import dns.message
import dns.rrset
from unifi_dns_verify import query
from unifi_ipv6_review import compare, network_settings, parse_ra, sample_ra, scopes

ZONE = "example.invalid"
PREFIX = ipaddress.IPv6Network("fd00:1234::/64")
IP = "fd00:1234::20"
NAME = f"host.{ZONE}"


def record(name=NAME, address=IP, **extra):
    return {"name": name, "type": "AAAA", "content": address, "proxied": False, **extra}


class IPv6ReviewTests(unittest.TestCase):
    def test_dual_stack_and_aaaa_ptr_queries(self):
        def request(gateway, name, kind):
            self.assertEqual(gateway, "192.168.10.1")
            return ("answered", [IP]) if kind == "AAAA" else ("answered", [NAME + "."])

        report = compare(
            [record(), {"name": NAME, "type": "A", "content": "192.168.10.20"}],
            [{"type": "AAAA_RECORD", "domain": NAME, "enabled": True, "ipv6Address": IP}],
            ZONE, [PREFIX], "192.168.10.1", request,
        )
        self.assertEqual(report["counts"], {"matched": 2})
        self.assertEqual(report["records"][0]["policy_status"], "matched")

    def test_shared_addresses_need_explicit_tag(self):
        alias = f"alias.{ZONE}"
        for tags, expected in (([], None), (["yggflare:canonical"], [NAME + "."])):
            result = compare(
                [record(tags=tags), record(alias)], [], ZONE, [PREFIX], "192.168.10.1",
                lambda gateway, name, kind: ("answered", [IP] if kind == "AAAA" else [NAME + "."]),
            )
            ptr = next(row for row in result["replies"] if row["type"] == "PTR")
            self.assertEqual(ptr["expected"], expected)

    def test_outside_and_proxied_addresses_are_never_queried(self):
        with patch("unifi_ipv6_review.query") as request:
            report = compare(
                [record(address="fd00:9999::1"), record(f"proxy.{ZONE}", proxied=True)],
                [], ZONE, [PREFIX], "192.168.10.1", request,
            )
            request.assert_not_called()
        self.assertEqual(report["replies"], [])
        self.assertEqual(report["record_counts"], {"ambiguous_or_ineligible": 1, "outside_configured_scope": 1})

    def test_aaaa_wire_reply_parser(self):
        def answer(request, gateway, **kwargs):
            reply = dns.message.make_response(request)
            reply.answer.append(dns.rrset.from_text(NAME + ".", 300, "IN", "AAAA", IP))
            return reply, False

        with patch("dns.query.udp_with_fallback", side_effect=answer):
            self.assertEqual(query("192.168.10.1", NAME + ".", "AAAA"), ("answered", [IP]))

    def test_network_config_is_not_dhcpv6_delivery(self):
        result = network_settings({"ipv6Configuration": {
            "interfaceType": "STATIC",
            "clientAddressAssignment": {"slaacEnabled": True, "dhcpConfiguration": {}},
            "routerAdvertisement": {"priority": "HIGH"},
            "dnsServerIpAddressesOverride": [IP],
        }})
        self.assertEqual(result["dns_selection"], "explicit")
        self.assertEqual(result["dns_overrides"], [IP])
        self.assertTrue(result["dhcpv6_configured"])
        self.assertEqual(result["dhcpv6_dns_delivery"], "not_observed")
        self.assertEqual(network_settings({})["status"], "not_reported")
        self.assertEqual(network_settings({"ipv6Configuration": {}})["dns_selection"], "unknown")

    def test_ra_reports_external_and_link_local_without_probing(self):
        raw = (
            "Stateful address conf.: No\nStateful other conf.: Yes\n"
            "Recursive DNS server: fe80::1\nRecursive DNS server: 2001:4860:4860::8888\n"
            "DNS server lifetime: 600 (0x258) seconds\nfrom fe80::2\n"
        )
        row = parse_ra(raw, [PREFIX])[0]
        self.assertFalse(row["managed"])
        self.assertTrue(row["other"])
        self.assertEqual([item["scope"] for item in row["rdnss"]], ["link_local", "outside_scope"])
        self.assertEqual(row["rdnss"][0]["lifetime_seconds"], 600)
        self.assertEqual(parse_ra(raw.split("from ")[0], [PREFIX]), [])

    def test_ra_no_reply_distinct_from_disabled_and_scope_validation(self):
        with patch("subprocess.run") as execute:
            execute.return_value.returncode = 2
            result = sample_ra(
                {"YGGFLARE_DISCOVERY_RA": "true", "YGGFLARE_DISCOVERY_INTERFACES": "eth0"},
                [PREFIX], execute,
            )
            self.assertEqual(result["interfaces"][0]["status"], "no_reply")
            self.assertEqual(sample_ra({}, [], execute)["status"], "disabled")
            execute.assert_called_once()
        with self.assertRaises(ValueError):
            scopes({"YGGFLARE_DISCOVERY_IPV6_CIDRS": "fd00::/48"})
