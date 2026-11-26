"""Offline canonical selection and direct DNS verification checks."""

import ipaddress
import unittest
from unittest.mock import patch

import dns.exception
import dns.message
import dns.rrset
from unifi_dns import CANONICAL_TAG, plan
from unifi_dns_verify import query, verify

LAN = ipaddress.IPv4Network("192.168.10.0/24")
GATEWAY = "192.168.10.1"
ZONE = "example.invalid"
IP = "192.168.10.2"


def record(label, *, tagged=False, proxied=False):
    return {
        "name": f"{label}.{ZONE}",
        "type": "A",
        "content": IP,
        "proxied": proxied,
        "tags": [CANONICAL_TAG] if tagged else [],
    }


class UniFiDNSVerificationTests(unittest.TestCase):
    def test_canonical_selection_is_explicit_and_order_independent(self):
        for records, status, name in (
            ([record("b")], "unique", f"b.{ZONE}"),
            ([record("a"), record("b")], "ambiguous", None),
            ([record("a"), record("b", tagged=True)], "cloudflare_tag", f"b.{ZONE}"),
            (
                [record("a", tagged=True), record("b", tagged=True)],
                "conflicting_tags",
                None,
            ),
            (
                [record("a", proxied=True), record("b", tagged=True)],
                "ineligible_alias",
                None,
            ),
        ):
            with self.subTest(status=status):
                result = plan(records, [], ZONE, LAN)
                reverse = result["reverse_expectations"]
                self.assertEqual(
                    reverse,
                    plan(list(reversed(records)), [], ZONE, LAN)[
                        "reverse_expectations"
                    ],
                )
                self.assertEqual(reverse[0]["canonical_hostname"], name)
                self.assertEqual(reverse[0]["selection"], status)

    def test_queries_each_alias_and_deduplicates_ptr(self):
        desired = plan([record("a"), record("b", tagged=True)], [], ZONE, LAN)

        def request(gateway, name, kind):
            self.assertEqual(gateway, GATEWAY)
            if kind == "PTR":
                self.assertEqual(name, "2.10.168.192.in-addr.arpa.")
                return "answered", [f"b.{ZONE}."]
            return "answered", [IP] if name == f"b.{ZONE}." else [IP, GATEWAY]

        report = verify(desired, GATEWAY, request=request)
        self.assertEqual(report["counts"], {"matched": 2, "mismatch": 1})
        self.assertEqual(
            verify(desired, GATEWAY, f"B.{ZONE}.", request)["counts"], {"matched": 2}
        )
        with self.assertRaises(ValueError):
            verify(desired, GATEWAY, "outside.invalid", request)

    def test_distinguishes_dns_protocol_outcomes(self):
        def response(req, gateway, **kwargs):
            self.assertEqual(gateway, GATEWAY)
            return dns.message.make_response(req), False

        name = f"b.{ZONE}."
        with patch("dns.query.udp_with_fallback", side_effect=response):
            self.assertEqual(query(GATEWAY, name, "A"), ("nodata", []))

        def unexpected(req, gateway, **kwargs):
            reply, _ = response(req, gateway, **kwargs)
            reply.answer.append(
                dns.rrset.from_text(name, 60, "IN", "CNAME", "else.invalid.")
            )
            return reply, False

        with patch("dns.query.udp_with_fallback", side_effect=unexpected):
            self.assertEqual(query(GATEWAY, name, "A"), ("unexpected_answer", []))

        with patch("dns.query.udp_with_fallback", side_effect=dns.exception.Timeout):
            self.assertEqual(query(GATEWAY, name, "A"), ("timeout", []))
