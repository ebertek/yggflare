"""Validate bounded, non-authoritative IPv6 Router Advertisement evidence."""

import ipaddress
import unittest

from discovery_ra import router_records


class RouterAdvertisementTests(unittest.TestCase):
    def setUp(self):
        self.scopes = [
            ipaddress.ip_network("fd0e:be00:da00:20::/64"),
        ]

    def test_extracts_router_identity_and_only_relevant_prefixes(self):
        raw = """
Soliciting ff02::2 (ff02::2) on eth0...
Hop limit                 :           64
Stateful address conf.    :           No
Stateful other conf.      :           Yes
Router preference         :       medium
Router lifetime           :         1800 (0x00000708) seconds
 Prefix                   : fd0e:be00:da00:20::/64
 Prefix                   : 2001:db8:1234::/64
 Recursive DNS server      : fd0e:be00:da00:20::53
 Recursive DNS server      : 2001:db8::53
 DNS search list           : private.home.example
 Source link-layer address : 00:11:22:33:44:55
 from fe80::211:22ff:fe33:4455
"""
        records = router_records(raw, self.scopes)
        self.assertEqual(len(records), 1)
        detail = records[0]
        self.assertIn("router: fe80::211:22ff:fe33:4455", detail)
        self.assertIn("prefixes: fd0e:be00:da00:20::/64", detail)
        self.assertIn("RDNSS: fd0e:be00:da00:20::53", detail)
        self.assertIn("router lifetime: 1800s", detail)
        self.assertIn("stateful other conf.: yes", detail)
        self.assertIn("router MAC: 00:11:22:33:44:55", detail)
        self.assertNotIn("2001:db8", detail)
        self.assertNotIn("private.home.example", detail)

    def test_multiple_advertisements_are_distinct_and_deduplicated(self):
        a = (
            " Router preference: high\n"
            " Prefix: fd0e:be00:da00:20::/64\n"
            " from fe80::1\n"
        )
        b = " Router lifetime: 0 (0x0) seconds\n from fe80::2\n"
        entries = router_records(a + a + b, self.scopes)
        self.assertEqual(len(entries), 2)
        self.assertIn("router: fe80::1", entries[0])
        self.assertIn("router: fe80::2", entries[1])
        self.assertIn("prefixes: none within configured scope", entries[1])

    def test_untrusted_or_unscoped_data_never_becomes_router_identity(self):
        sample = (
            " Prefix: 2001:db8::/64\n"
            " Router preference: admin<script>\n"
            " Source link-layer address: bad\n"
            " from 2001:db8::1\n"
            " Prefix: fd0e:be00:da00:20::/64\n"
            " from attacker.local\n"
        )
        self.assertEqual(router_records(sample, self.scopes), [])

    def test_requires_complete_source_line_and_rejects_control_metadata(self):
        result = router_records(" Prefix: fd0e:be00:da00:20::/64\n", self.scopes)
        self.assertEqual(result, [])
        sample = (
            "Router preference: high\n"
            "Source link-layer address: malicious\x1b[31m\n"
            "from fe80::3\n"
        )
        output = router_records(sample, self.scopes)[0]
        self.assertNotIn("\x1b", output)
        self.assertNotIn("malicious", output)

    def test_rejects_large_output_and_bounds_number_of_routers(self):
        with self.assertRaises(ValueError):
            router_records("x" * 65537, self.scopes)
        raw = "".join(f"from fe80::{i}\n" for i in range(1, 20))
        with self.assertRaisesRegex(ValueError, "Too many"):
            router_records(raw, self.scopes)

    def test_large_numeric_router_details_fail_instead_of_truncating(self):
        prefixes = "".join(
            f"Prefix: fd0e:be00:da00:20::{i}/128\n" for i in range(1, 13)
        )
        dns = "".join(
            f"Recursive DNS server: fd0e:be00:da00:20::{i}\n" for i in range(1, 9)
        )
        with self.assertRaisesRegex(ValueError, "Oversized IPv6 router detail"):
            router_records(prefixes + dns + "from fe80::1\n", self.scopes)

    def test_allows_prefix_overlap_without_widening_scan_scope(self):
        router = "Prefix: fd0e:be00:da00::/56\nfrom fe80::a\n"
        output = router_records(router, self.scopes)
        self.assertEqual(len(output), 1)
        self.assertIn("fd0e:be00:da00::/56", output[0])


if __name__ == "__main__":
    unittest.main()
