"""Regression tests for the read-only MCP interface."""

import unittest
from copy import deepcopy

from mcp_server import TOOL_NAMES, InventoryTools, build_server


def fixture():
    return {
        "scanned_at": "2026-11-24T05:15:00Z",
        "hosts": [
            {
                "hostname": "example.internal",
                "ipv4": "192.0.2.10",
                "mac": "02:00:00:00:00:10",
                "aliases": ["example.invalid"],
                "device_class": "docker",
                "status": "docker running",
                "description": "private notes",
                "secret": "never-export",
            },
            {
                "hostname": "",
                "ipv4": "192.0.2.11",
                "status": "unmanaged",
            },
        ],
        "diffs": [
            {
                "ipv4": "192.0.2.11",
                "field": "MAC",
                "severity": "drift",
                "observed": "example",
            }
        ],
        "network_state": {
            "initialized": True,
            "identity_history": {
                "example": {
                    "label": "example",
                    "addresses": ["192.0.2.10"],
                    "confidence": "high",
                    "note": "private notes",
                }
            },
            "recent_events": [
                {"observed_at": "first", "message": "older"},
                {"observed_at": "second", "message": "newer"},
            ],
            "pending_discord_events": [{"secret": "never-export"}],
        },
        "cloudflare_view": {
            "audited_at": "2026-11-24T06:00:00Z",
            "hosts": [
                {
                    "hostname": "example.invalid",
                    "declared": True,
                    "claimed": True,
                    "lifecycle": "managed",
                    "tunnel_routes": 1,
                    "access_app_ids": ["private-app-id"],
                    "dns_record_ids": ["private-dns-id"],
                }
            ],
        },
        "cloudflare_view_status": {
            "ok": True,
            "attempted_at": "2026-11-24T06:00:00Z",
        },
    }


class InventoryToolTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture()
        self.tools = InventoryTools(lambda: self.data)

    def test_filter_and_pagination(self):
        first = self.tools.list_devices(limit=1)
        self.assertEqual(first["total"], 2)
        self.assertEqual(first["next_offset"], 1)
        second = self.tools.list_devices(offset=1, limit=1)
        self.assertIsNone(second["next_offset"])
        self.assertEqual(second["items"][0]["ipv4"], "192.0.2.11")
        self.assertEqual(self.tools.list_devices(unknown_only=True)["total"], 1)
        self.assertEqual(self.tools.list_devices(query="EXAMPLE")["total"], 1)
        for offset, limit in ((-1, 1), (0, 0), (0, 51)):
            with self.assertRaises(ValueError):
                self.tools.list_devices(offset=offset, limit=limit)

    def test_identity_and_projection(self):
        before = deepcopy(self.data)
        result = self.tools.get_device("EXAMPLE.INVALID")
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["identities"]["total"], 1)
        self.assertNotIn("private notes", str(result))
        self.assertNotIn("never-export", str(result))
        self.assertEqual(self.data, before)
        self.assertEqual(self.tools.get_device("missing")["total"], 0)
        with self.assertRaises(ValueError):
            self.tools.get_device("")

    def test_drift_and_events(self):
        self.assertEqual(self.tools.get_inventory_drift()["total"], 1)
        events = self.tools.get_discovery_changes()
        self.assertEqual(events["items"][0]["message"], "newer")
        self.assertNotIn("never-export", str(events))

    def test_cloudflare_scope_and_freshness(self):
        lifecycle = self.tools.get_cloudflare_lifecycle()
        self.assertTrue(lifecycle["last_refresh_verified"])
        self.assertEqual(lifecycle["items"][0]["access_app_count"], 1)
        self.assertNotIn("private-app-id", str(lifecycle))
        self.assertNotIn("private-dns-id", str(lifecycle))
        self.assertEqual(
            self.tools.get_service_exposure("example.internal")["items"][0][
                "cloudflare_hosts"
            ][0]["hostname"],
            "example.invalid",
        )
        self.data["cloudflare_view_status"]["ok"] = False
        self.assertFalse(self.tools.get_cloudflare_lifecycle()["last_refresh_verified"])

    def test_missing_observations(self):
        status = InventoryTools(lambda: {}).get_inventory_status()
        self.assertFalse(status["scan_initialized"])
        self.assertIsNone(status["scanned_at"])
        self.assertFalse(status["cloudflare"]["last_refresh_verified"])


class MCPRegistrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_only_read_only_tools_registered(self):
        server = build_server(fixture)
        tools = await server.list_tools()
        self.assertEqual({tool.name for tool in tools}, set(TOOL_NAMES))
        for tool in tools:
            self.assertTrue(tool.annotations.readOnlyHint)
            self.assertFalse(tool.annotations.destructiveHint)
        result = await server.call_tool("list_devices", {"unknown_only": True})
        self.assertIn("192.0.2.11", str(result))
        self.assertNotIn("never-export", str(result))


if __name__ == "__main__":
    unittest.main()
