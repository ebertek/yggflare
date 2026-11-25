"""Offline integration contracts and confidentiality tests."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import integration_inventory as adapter
from mcp_server import InventoryTools

ENV = {
    "YGGFLARE_LAN_CIDR": "192.168.1.0/24",
    "YGGFLARE_KOMODO_API_URL": "http://192.168.1.20:9120",
    "YGGFLARE_KOMODO_ALLOW_HTTP": "true",
    "YGGFLARE_KUMA_API_URL": "http://192.168.1.21:3001",
    "YGGFLARE_KUMA_ALLOW_HTTP": "true",
}

METRICS = """
# HELP monitor_status Monitor status
# TYPE monitor_status gauge
monitor_status{monitor_name="Demo",monitor_type="http",monitor_url="https://demo.invalid/private/SECRET?key=SECRET",monitor_hostname="",monitor_port=""} 1
monitor_status{monitor_name="Private",monitor_type="http",monitor_url="https://user:SECRET@other.invalid/path"} 0
"""


class IntegrationTests(unittest.TestCase):
    def test_scope_and_tls_opt_in(self):
        self.assertIsNone(adapter.settings("komodo", {}))
        self.assertEqual(adapter.settings("komodo", ENV), ("http", "192.168.1.20", 9120))
        for changes in (
            {"YGGFLARE_KOMODO_ALLOW_HTTP": "false"},
            {"YGGFLARE_KOMODO_API_URL": "http://8.8.8.8"},
            {"YGGFLARE_KOMODO_API_URL": "http://192.168.1.20/path"},
            {"YGGFLARE_KOMODO_API_URL": "http://user:secret@192.168.1.20"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                adapter.settings("komodo", {**ENV, **changes})

    def test_komodo_projection(self):
        rows = adapter.komodo_rows("stacks", [{"name": "core", "info": {
            "server_name": "primary", "state": "running", "deployed_hash": "abcdef0",
            "latest_hash": "abcdef1", "repo_link": "SECRET", "status": "SECRET",
            "services": [{"service": "dns", "image": "example/dns:2", "update_available": True, "environment": "SECRET"}],
        }}])
        stack = next(row for row in rows if row["kind"] == "stacks")
        self.assertEqual(stack["server"], "primary")
        self.assertFalse(stack["revision_match"])
        self.assertNotIn("SECRET", json.dumps(rows))

    def test_kuma_excludes_credentials_and_paths(self):
        rows = adapter.kuma_rows(METRICS)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["target_host"], "demo.invalid")
        self.assertEqual(rows[0]["target_port"], 443)
        self.assertEqual(rows[0]["status"], "up")
        self.assertIsNone(rows[1]["target_host"])
        self.assertNotIn("SECRET", json.dumps(rows))
        with self.assertRaises(ValueError):
            adapter.kuma_rows("# TYPE something gauge\nsomething 1")

    def test_fixed_requests_reject_redirects(self):
        with patch.object(adapter.http.client, "HTTPConnection") as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 302
            with self.assertRaises(ValueError):
                adapter.fetch("komodo", adapter.settings("komodo", ENV), ["key", "secret"], "stacks")
            args = connection.return_value.request.call_args
            self.assertEqual(args.args, ("POST", "/read/ListStacks"))
            self.assertEqual(args.kwargs["body"], b"{}")
            with self.assertRaises(ValueError):
                adapter.fetch("komodo", adapter.settings("komodo", ENV), ["key", "secret"], "execute")

    def test_failed_refresh_retains_snapshot_and_requires_private_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret = root / "kuma-api-key.txt"
            secret.write_text("sample-key")
            secret.chmod(0o644)
            with self.assertRaises(ValueError):
                adapter.credentials("kuma", root)
            secret.chmod(0o600)
            adapter.refresh("kuma", root, ENV, root, lambda *_: METRICS)
            first = adapter.saved("kuma", root, ENV)
            self.assertTrue(first["fresh"])
            secret.unlink()
            with self.assertRaises(OSError):
                adapter.refresh("kuma", root, ENV, root, lambda *_: METRICS)
            after = adapter.saved("kuma", root, ENV)
            self.assertEqual(after["items"], first["items"])
            self.assertFalse(after["fresh"])
            self.assertFalse(adapter.saved("kuma", root, {**ENV, "YGGFLARE_KUMA_API_URL": "http://192.168.1.22:3001"})["available"])

    def test_coverage_caveat_and_unknown(self):
        tools = InventoryTools(lambda: {}, lambda: {"items": [{"project": "core", "service": "demo", "aliases": ["demo.invalid"]}]})
        with patch("mcp_server.saved_integration", side_effect=lambda *_: {"available": True, "fresh": True, "items": adapter.kuma_rows(METRICS)}):
            result = tools.get_monitoring_coverage()
            self.assertEqual(result["items"][0]["match_status"], "candidate_host_match")
            self.assertEqual(result["items"][0]["matching_monitor_count"], 1)
        with patch("mcp_server.saved_integration", return_value={"available": False, "fresh": False, "items": []}):
            result = tools.get_monitoring_coverage()
            self.assertIsNone(result["items"][0]["matching_monitor_count"])
            self.assertEqual(result["items"][0]["match_status"], "unknown")
