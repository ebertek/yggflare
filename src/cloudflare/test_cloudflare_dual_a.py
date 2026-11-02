"""Offline guarded-write tests for explicitly declared companion A records."""

# Shared synthetic DNS fixtures intentionally resemble guarded writer tests.
# pylint: disable=duplicate-code

import copy
import unittest

from cloudflare_guarded import UnsafePlan, apply_actions, check_plan
from test_cloudflare_guarded import CONTEXT, FakeWriter, report


class DualAWriteTests(unittest.TestCase):
    """Protect a second A record through primary creation and updates."""

    def test_declared_companion_survives_primary_ip_update(self):
        """Guarded writes leave the second A record's ID and data unchanged."""
        client = FakeWriter()
        client.dns = [
            {
                "id": "f" * 32,
                "name": "example-device.ygg.nu",
                "type": "A",
                "content": "10.4.20.11",
                "proxied": False,
                "ttl": 7200,
            },
            {
                "id": "e" * 32,
                "name": "example-device.ygg.nu",
                "type": "A",
                "content": "10.4.21.42",
                "proxied": False,
                "ttl": 1800,
                "comment": "Second protected interface",
            },
        ]
        second_before = copy.deepcopy(client.dns[1])
        candidate = report(
            {
                "kind": "update_static_dns_a",
                "hostname": "example-device.ygg.nu",
                "record_id": "f" * 32,
                "before": "10.4.20.11",
                "content": "10.4.20.12",
                "additional_ipv4": ["10.4.21.42"],
            }
        )
        done = apply_actions(client, candidate, CONTEXT, unattended=True)
        self.assertEqual(len(done), 1)
        self.assertEqual(client.events, ["static_update"])
        self.assertEqual(client.dns[0]["content"], "10.4.20.12")
        self.assertEqual(client.dns[1], second_before)

    def test_declared_companion_survives_primary_creation(self):
        """Missing primary can be created while an existing second A stays intact."""
        client = FakeWriter()
        client.dns = [
            {
                "id": "e" * 32,
                "name": "example-device.ygg.nu",
                "type": "A",
                "content": "10.4.21.42",
                "proxied": False,
                "ttl": 1800,
            }
        ]
        second_before = copy.deepcopy(client.dns[0])
        done = apply_actions(
            client,
            report(
                {
                    "kind": "create_static_dns_a",
                    "hostname": "example-device.ygg.nu",
                    "content": "10.4.20.12",
                    "additional_ipv4": ["10.4.21.42"],
                }
            ),
            CONTEXT,
            unattended=True,
        )
        self.assertEqual(done[0]["kind"], "create_static_dns_a")
        self.assertEqual(client.events, ["static_create"])
        self.assertEqual(client.dns[0], second_before)
        self.assertEqual(client.dns[1]["content"], "10.4.20.12")

    def test_declared_companion_is_required_for_writes(self):
        """Missing, proxied, or undeclared companion records block the write."""
        client = FakeWriter()
        candidate = report(
            {
                "kind": "create_static_dns_a",
                "hostname": "example-device.ygg.nu",
                "content": "10.4.20.12",
                "additional_ipv4": ["10.4.21.42"],
            }
        )
        for records in (
            [],
            [
                {
                    "id": "e" * 32,
                    "name": "example-device.ygg.nu",
                    "type": "A",
                    "content": "10.4.21.42",
                    "proxied": True,
                }
            ],
            [
                {
                    "id": "e" * 32,
                    "name": "example-device.ygg.nu",
                    "type": "A",
                    "content": "10.4.21.42",
                    "proxied": False,
                },
                {
                    "id": "f" * 32,
                    "name": "example-device.ygg.nu",
                    "type": "A",
                    "content": "10.4.21.2",
                    "proxied": False,
                },
            ],
        ):
            client.dns = records
            with self.subTest(records=records), self.assertRaises(UnsafePlan):
                apply_actions(client, candidate, CONTEXT, unattended=True)
            self.assertEqual(client.events, [])

    def test_declared_companion_must_be_in_docker_range(self):
        """Prevent callers from claiming arbitrary extra DNS records."""
        for invalid in (
            ["10.4.20.12"],
            ["10.4.21.31"],
            ["10.4.21.42", "10.4.21.42"],
            "10.4.21.42",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(UnsafePlan):
                check_plan(
                    report(
                        {
                            "kind": "create_static_dns_a",
                            "hostname": "example-device.ygg.nu",
                            "content": "10.4.20.12",
                            "additional_ipv4": invalid,
                        }
                    )
                )


if __name__ == "__main__":
    unittest.main()
