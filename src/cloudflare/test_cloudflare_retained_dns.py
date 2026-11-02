"""Retained DNS inventory validation and read-only reconciliation tests."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cloudflare_retained_dns import load_retained_dns
from cloudflare_unaccounted_dns import audit_unaccounted_dns


def expected():
    """Representative private DNS declarations; no real user records."""
    return [
        {"hostname": "b._dns-sd._udp.ygg.nu", "type": "PTR"},
        {"hostname": "selector._domainkey.ygg.nu", "type": "TXT"},
        {
            "hostname": "example-ns.ygg.nu",
            "type": "A",
            "content": "10.4.21.42",
            "description": "Existing internal DNS service",
        },
    ]


class RetainedDnsTests(unittest.TestCase):
    """Retained records must be precise and cannot trigger API writes."""

    def test_absent_optional_file_returns_no_declarations(self):
        """No new file is required to keep the existing audit functional."""
        with TemporaryDirectory() as directory:
            self.assertEqual(load_retained_dns(Path(directory) / "absent.json"), [])

    def test_valid_dns_sd_and_dkim_names(self):
        """Underscore-prefixed service labels must be accepted."""
        with TemporaryDirectory() as directory:
            path = Path(directory) / "retained.json"
            path.write_text(json.dumps({"version": 1, "records": expected()}))
            self.assertEqual(load_retained_dns(path), expected())

    def test_malformed_entries_are_rejected(self):
        """Wrong types and missing targets must not silently hide drift."""
        invalid = [
            [{"hostname": "example-ns.ygg.nu", "type": "A"}],
            [{"hostname": "example-ns.ygg.nu", "type": "CNAME"}],
            [{"hostname": "example-ns.ygg.nu", "type": "A", "content": "10.4.21.999"}],
            [{"hostname": "outside.example.org", "type": "TXT"}],
            [{"hostname": "example-ns.ygg.nu", "type": "a", "content": "10.4.21.42"}],
            [expected()[0], expected()[0]],
        ]
        with TemporaryDirectory() as directory:
            path = Path(directory) / "retained.json"
            for records in invalid:
                with self.subTest(records=records):
                    path.write_text(json.dumps({"version": 1, "records": records}))
                    with self.assertRaises(ValueError):
                        load_retained_dns(path)

    def test_only_matching_record_shapes_are_retained(self):
        """A record cannot be hidden by a CNAME or mismatched IP."""
        live = [
            {"name": "b._dns-sd._udp.ygg.nu", "type": "PTR", "content": "ygg.nu"},
            {"name": "selector._domainkey.ygg.nu", "type": "TXT", "content": "private"},
            {"name": "example-ns.ygg.nu", "type": "A", "content": "10.4.21.42"},
        ]
        report = audit_unaccounted_dns(live, {}, set(), expected())
        self.assertEqual(report["counts"]["records"], 0)
        self.assertEqual(report["retained"]["present"], 3)
        self.assertEqual(report["retained"]["missing"], [])
        self.assertNotIn("private", str(report))

        live[-1] = {
            "name": "example-ns.ygg.nu",
            "type": "CNAME",
            "content": "pleiades.ygg.nu",
        }
        report = audit_unaccounted_dns(live, {}, set(), expected())
        self.assertEqual(report["counts"]["records"], 1)
        self.assertEqual(report["findings"][0]["type"], "CNAME")
        self.assertEqual(report["retained"]["present"], 2)
        self.assertEqual(
            report["retained"]["missing"],
            [{"hostname": "example-ns.ygg.nu", "type": "A", "content": "10.4.21.42"}],
        )

        live[-1] = {"name": "example-ns.ygg.nu", "type": "A", "content": "10.4.21.43"}
        report = audit_unaccounted_dns(live, {}, set(), expected())
        self.assertEqual(report["counts"]["records"], 1)
        self.assertEqual(report["findings"][0]["content"], "10.4.21.43")
        self.assertEqual(report["retained"]["present"], 2)


if __name__ == "__main__":
    unittest.main()
