"""Finding lifecycle is conservative and independent of delivery state."""

import unittest
from datetime import UTC, datetime

from finding_lifecycle import rows, update
from mcp_server import InventoryTools, evidence_source

IP = "192.0.2.10"
MAC = "02:00:00:00:00:01"
KEY = f"new-port:{IP}:tcp/443"
NOW = "2026-01-01T00:00:00+00:00"
LATER = "2026-01-02T00:00:00+00:00"
HOSTS = {IP: {"mac": MAC, "ports": ["tcp/443"]}}


class LifecycleTests(unittest.TestCase):
    def test_missing_port_not_resolved_and_reappearance_retains_id(self):
        first = update({}, {KEY: "private message"}, [], {}, HOSTS, set(), NOW, True)
        row = first["items"][0]
        self.assertEqual(row["status"], "observed")
        self.assertNotIn("private message", str(first))
        missing = update(
            {"finding_lifecycle": first}, {}, [], {}, {}, set(), LATER, True
        )
        self.assertEqual(missing["items"][0]["status"], "not_reobserved")
        self.assertEqual(missing["items"][0]["last_seen"], NOW)
        back = update(
            {"finding_lifecycle": missing},
            {KEY: "different message"},
            [],
            {},
            HOSTS,
            set(),
            LATER,
            True,
        )
        self.assertEqual(back["items"][0]["finding_id"], row["finding_id"])
        self.assertEqual(back["items"][0]["reappearance_count"], 1)

    def test_positive_inventory_match_requires_same_observed_port_and_mac(self):
        first = update({}, {KEY: "x"}, [], {}, HOSTS, set(), NOW, True)
        declared = {IP: {"mac": MAC, "ports": {"tcp/443"}}}
        previous = {"finding_lifecycle": first}
        result = update(previous, {}, [], declared, HOSTS, set(), LATER, True)
        self.assertEqual(result["items"][0]["status"], "inventory_match_observed")
        result = update(
            previous,
            {},
            [],
            declared,
            {IP: {"mac": MAC, "ports": []}},
            set(),
            LATER,
            True,
        )
        self.assertEqual(result["items"][0]["status"], "not_reobserved")

    def test_incomplete_dns_does_not_advance_last_seen(self):
        first = update({}, {}, ["demo.local|_http._tcp|80"], {}, {}, set(), NOW, True)
        result = update(
            {"finding_lifecycle": first},
            {},
            ["demo.local|_http._tcp|80"],
            {},
            {},
            set(),
            LATER,
            False,
        )
        self.assertEqual(result["items"][0]["status"], "source_incomplete")
        self.assertEqual(result["items"][0]["last_seen"], NOW)
        result = update(
            {"finding_lifecycle": result}, {}, [], {}, {}, set(), LATER, True
        )
        self.assertEqual(result["items"][0]["status"], "advertisement_not_reobserved")

    def test_retention_and_legacy_migration(self):
        reported = {f"new-port:{IP}:tcp/{port}": "x" for port in range(1, 1030)}
        result = update({"initialized": True}, reported, [], {}, {}, set(), NOW, True)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["active_total"], 1029)
        self.assertEqual(len(result["items"]), 1024)
        self.assertEqual(len(result["transitions"]), 256)
        self.assertTrue(result["items"][0]["first_seen_lower_bound"])
        tools = InventoryTools(lambda: {"network_state": {"finding_lifecycle": result}})
        first = tools.list_finding_history(limit=1)
        self.assertEqual(first["total"], 1024)
        with self.assertRaises(ValueError):
            tools.list_finding_history(offset=1, snapshot_id="changed")
        self.assertIsNone(
            rows({"finding_lifecycle": {"version": 1, "available": False}})
        )

    def test_freshness_independent_of_collection_verification(self):
        now = datetime(2026, 1, 2, tzinfo=UTC)
        row = evidence_source(
            "sample",
            configured=True,
            available=True,
            observed_at=LATER,
            verified=False,
            complete=False,
            now=now,
        )
        self.assertEqual(row["freshness"], "fresh")
        self.assertEqual(row["collection_status"], "unverified")
        self.assertEqual(row["completeness"], "incomplete")
        row = evidence_source(
            "sample", configured=True, available=True, observed_at=NOW, now=now
        )
        self.assertEqual(row["freshness"], "stale")
        self.assertEqual(row["collection_status"], "unknown")
