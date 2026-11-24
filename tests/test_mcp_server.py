"""Regression tests for the read-only MCP interface."""

import sys
import unittest
from copy import deepcopy
from pathlib import Path

from mcp import Client, StdioServerParameters

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

    def test_expected_shared_namespace_and_ambiguous_lookup(self):
        parent = self.data["hosts"][0]
        parent.update(
            network_owner="vpn", address_relationship="expected_shared_namespace"
        )
        child = {
            **parent,
            "hostname": "child.internal",
            "shared_network": "vpn",
        }
        self.data["hosts"].append(child)
        result = self.tools.get_device(parent["ipv4"])
        self.assertEqual(result["total"], 2)
        self.assertFalse(result["ambiguous"])
        self.assertEqual(result["lookup_relationship"], "expected_shared_namespace")
        self.assertEqual(result["items"][1]["shared_network"], "vpn")
        child["address_relationship"] = "ambiguous"
        self.assertTrue(self.tools.get_device(parent["ipv4"])["ambiguous"])

    def test_drift_severity_counts_and_historical_findings(self):
        self.data["diffs"].append({"severity": "unknown", "field": "Presence"})
        self.assertEqual(self.tools.get_inventory_drift(severity="drift")["total"], 1)
        unknown = self.tools.get_inventory_drift(severity="unknown")
        self.assertEqual(unknown["total"], 1)
        self.assertEqual(unknown["observed_discrepancies"], 1)
        self.assertEqual(unknown["inconclusive_observations"], 1)
        with self.assertRaises(ValueError):
            self.tools.get_inventory_drift(severity="high")
        self.data["network_state"]["reported"] = {"key": "newer"}
        events = self.tools.get_discovery_changes()["items"]
        self.assertEqual(
            events[0]["finding_status"], "present_in_latest_reported_findings"
        )
        self.assertEqual(
            events[1]["finding_status"], "historical_not_confirmed_current"
        )
        lifecycle = self.tools.get_cloudflare_lifecycle()
        self.assertEqual(lifecycle["ownership_counts"]["managed"], 1)
        self.assertIn("not evidence of configuration drift", lifecycle["caveat"])

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

    def test_extended_evidence_and_secret_projection(self):
        state = self.data["network_state"]
        state["supplemental"] = {
            "observed_at": "sample",
            "records": [
                {
                    "ip": "",
                    "source": "IPv6 router advertisement",
                    "detail": "prefix",
                    "secret": "never-export",
                },
                {"ip": "192.0.2.10", "source": "ARP reply", "detail": "mac"},
            ],
        }
        state["identity_conflicts"] = [
            {
                "address": "192.0.2.10",
                "macs": ["one", "two"],
                "reasons": ["conflict"],
                "secret": "never-export",
            }
        ]
        state["identity_history"]["example"]["macs"] = ["02:00:00:00:00:10"]
        state["identity_changes"] = [{"identity": "example", "kind": "first-observed"}]
        state["hosts"] = {
            "192.0.2.10": {
                "ports": ["tcp/80"],
                "services": {"tcp/80": {"name": "http", "secret": "never-export"}},
            }
        }
        state["advertisements"] = ["example.local|_http._tcp|80"]
        state["alert_pending_confirmations"] = ["candidate"]
        self.assertEqual(
            self.tools.get_discovery_status()["supplemental_source_counts"][
                "ARP reply"
            ],
            1,
        )
        self.assertEqual(
            self.tools.get_discovery_evidence(source="ARP reply")["total"], 1
        )
        self.assertNotIn("never-export", str(self.tools.get_discovery_evidence()))
        self.assertNotIn("never-export", str(self.tools.get_identity_conflicts()))
        self.assertEqual(self.tools.get_device_history("02:00:00:00:00:10")["total"], 1)
        self.assertEqual(self.tools.get_identity_changes("example")["total"], 1)
        services = self.tools.list_network_services()
        self.assertEqual([r["source"] for r in services["items"]], ["nmap", "dns_sd"])
        self.assertNotIn("never-export", str(services))
        self.assertEqual(self.tools.get_pending_network_findings()["total"], 1)

    def test_audit_missing_and_filtered(self):
        self.assertFalse(self.tools.get_cloudflare_audit()["audit_available"])
        self.data["cloudflare_view"]["audit"] = {
            "version": 1,
            "total_findings": 2,
            "truncated": False,
            "findings": [
                {
                    "section": "blocked",
                    "hostname": "example.invalid",
                    "reason": "multiple Access apps",
                    "secret": "never-export",
                },
                {
                    "section": "proposed",
                    "hostname": "other.invalid",
                    "kind": "create_dns_cname",
                },
            ],
        }
        result = self.tools.get_cloudflare_audit(section="blocked")
        self.assertTrue(result["audit_available"])
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["snapshot_total_findings"], 2)
        self.assertNotIn("never-export", str(result))
        with self.assertRaises(ValueError):
            self.tools.get_cloudflare_audit(section="unknown")

    def test_cloudflare_configuration_and_saved_findings(self):
        self.assertFalse(self.tools.get_cloudflare_access()["configuration_available"])
        self.data["cloudflare_view"]["configuration"] = {
            "version": 1,
            "internal_dns_collected": True,
            "access": {
                "total": 1,
                "items": [{"hostname": "example.invalid", "status": "matched",
                           "observed_decisions": ["allow", "deny"], "secret": "never-export"}],
            },
            "dns": {"total": 1, "items": [{"hostname": "example.invalid", "type": "TXT", "content": "never-export"}]},
            "tunnel": {"total": 1, "items": [{"hostname": "example.invalid", "origin_host": "origin.invalid", "secret": "never-export"}]},
        }
        access = self.tools.get_cloudflare_access("example.invalid")
        self.assertEqual(access["items"][0]["observed_decisions"], ["allow", "deny"])
        self.assertNotIn("never-export", str(access))
        self.assertNotIn("never-export", str(self.tools.get_cloudflare_dns()))
        self.assertNotIn("never-export", str(self.tools.get_cloudflare_tunnel()))
        self.data["network_state"]["reported"] = {"new-port:192.0.2.10:tcp/80": "new"}
        self.assertEqual(self.tools.get_network_findings()["items"][0]["finding_id"], "new-port:192.0.2.10:tcp/80")

    def test_dns_sd_address_filter(self):
        self.data["network_state"]["advertisement_details"] = [
            {"host": "example.local", "service": "_http._tcp", "port": 80,
             "addresses": ["192.0.2.10"], "txt": "never-export"}
        ]
        result = self.tools.list_network_services(address="192.0.2.10")
        self.assertEqual(result["total"], 1)
        self.assertNotIn("never-export", str(result))


class MCPRegistrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_stdio_protocol_handshake(self):
        script = Path(__file__).resolve().parents[1] / "mcp_server.py"
        parameters = StdioServerParameters(command=sys.executable, args=[str(script)])
        for mode in ("legacy", "auto"):
            with self.subTest(mode=mode):
                async with Client(parameters, mode=mode) as client:
                    result = await client.list_tools()
                    self.assertEqual(
                        {tool.name for tool in result.tools}, set(TOOL_NAMES)
                    )

    async def test_only_read_only_tools_registered(self):
        server = build_server(fixture)
        async with Client(server, raise_exceptions=True) as client:
            tools = (await client.list_tools()).tools
            self.assertEqual({tool.name for tool in tools}, set(TOOL_NAMES))
            for tool in tools:
                self.assertIsNotNone(tool.annotations)
                self.assertIsNotNone(tool.output_schema)
                self.assertEqual(tool.output_schema["type"], "object")
                self.assertTrue(tool.annotations.read_only_hint)
                self.assertFalse(tool.annotations.destructive_hint)
                self.assertTrue(tool.annotations.idempotent_hint)
                self.assertFalse(tool.annotations.open_world_hint)
            result = await client.call_tool("list_devices", {"unknown_only": True})
            self.assertFalse(result.is_error)
            self.assertIsNotNone(result.structured_content)
            self.assertEqual(result.structured_content["total"], 1)
            self.assertIn("192.0.2.11", str(result.structured_content))
            self.assertNotIn("never-export", str(result))


if __name__ == "__main__":
    unittest.main()
