"""No Cloudflare operations may be created from unaccounted record reports."""

import unittest

from cloudflare_unaccounted_dns import audit_unaccounted_dns, declared_dns_names


class UnaccountedTests(unittest.TestCase):
    """Report undeclared records, but never infer deletion authority."""

    def test_excludes_static_compose_running_alias_and_apex(self):
        """Stopped Compose services and declared aliases are accounted for."""
        records = [
            {"name": "ygg.nu", "type": "NS", "content": "ns.cloudflare.com"},
            {"name": "static.ygg.nu", "type": "A", "content": "10.4.20.2"},
            {"name": "pleiades.ygg.nu", "type": "A", "content": "10.4.21.1"},
            {"name": "alias.ygg.nu", "type": "CNAME", "content": "static.ygg.nu"},
            {"name": "stopped.ygg.nu", "type": "A", "content": "10.4.21.10"},
            {"name": "custom.ygg.nu", "type": "A", "content": "10.4.21.11"},
            {"name": "running.ygg.nu", "type": "A", "content": "10.4.21.12"},
            {
                "name": "orphan.ygg.nu",
                "type": "A",
                "content": "10.4.20.55",
                "proxied": False,
            },
        ]
        report = audit_unaccounted_dns(
            records,
            {"static.ygg.nu": "10.4.20.2", "pleiades.ygg.nu": "10.4.20.20"},
            declared_dns_names(
                {"alias.ygg.nu"},
                [
                    {"Name": "arr/stopped"},
                    {"Name": "group/service", "ContainerName": "custom"},
                ],
                {"running": "10.4.21.12"},
            ),
        )
        self.assertEqual(report["counts"]["records"], 1)
        self.assertEqual(
            report["findings"],
            [
                {
                    "hostname": "orphan.ygg.nu",
                    "type": "A",
                    "category": "address",
                    "proxied": False,
                    "content": "10.4.20.55",
                }
            ],
        )

    def test_unknown_types_listed_without_sensitive_payload(self):
        """TXT and other records are visible, without logging their values."""
        report = audit_unaccounted_dns(
            [
                {"name": "_verification.ygg.nu", "type": "TXT", "content": "secret"},
                {"name": "old.ygg.nu", "type": "CNAME", "content": "example.com"},
                {"name": "old.ygg.nu", "type": "AAAA", "content": "fd00::1"},
            ],
            {},
            set(),
        )
        self.assertEqual(
            report["counts"],
            {
                "records": 3,
                "hostnames": 2,
                "address_records": 2,
                "other_records": 1,
            },
        )
        self.assertNotIn("content", report["findings"][0])
        self.assertEqual(report["findings"][1]["content"], "fd00::1")

    def test_disabled_without_private_inventory(self):
        """Do not mark an entire zone orphaned when static inventory is absent."""
        self.assertFalse(audit_unaccounted_dns([], None, set())["enabled"])
        self.assertFalse(audit_unaccounted_dns(None, {}, set())["enabled"])


if __name__ == "__main__":
    unittest.main()
