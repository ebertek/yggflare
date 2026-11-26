"""Offline UniFi collection and read-only presentation regressions."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

import cli
import metrics
import web
from integration_inventory import refresh, saved, scheduled
from mcp_server import InventoryTools, QueryError, enabled_tools

ENV = {
    "YGGFLARE_LAN_CIDR": "192.168.12.0/24",
    "YGGFLARE_UNIFI_API_URL": "https://192.168.12.1",
}
SITE = str(UUID(int=1))
KEY = "fixture-key-never-publish"
ROWS = {
    "sites": [{"id": SITE}],
    "devices": [
        {
            "id": str(UUID(int=2)),
            "name": "<gateway>",
            "ipAddress": "192.168.12.1",
            "macAddress": "AA:BB:CC:DD:EE:FF",
            "state": "ONLINE",
            "raw": KEY,
        },
        {"id": str(UUID(int=3)), "name": "switch"},
    ],
    "clients": [{"id": str(UUID(int=4)), "name": "client", "type": "WIRELESS"}],
    "networks": [{"id": str(UUID(int=5)), "name": "lan", "vlanId": 0}],
    "dns": [
        {
            "id": str(UUID(int=6)),
            "type": "A_RECORD",
            "domain": "EXAMPLE.INVALID.",
            "enabled": True,
            "ipv4Address": "192.168.12.2",
        }
    ],
}


class UniFiInventoryTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        key_file = self.root / "unifi-api-key.txt"
        key_file.write_text(KEY)
        key_file.chmod(0o600)

    def fetch(self, config, key, kind, site, offset):
        self.assertEqual(config[0], "192.168.12.1")
        self.assertEqual(key, KEY)
        self.assertEqual(site, "" if kind == "sites" else SITE)
        rows = ROWS[kind]
        data = rows[offset : offset + 1]
        return {
            "count": len(data),
            "offset": offset,
            "limit": 1,
            "totalCount": len(rows),
            "data": data,
        }

    def refresh(self, fetch=None):
        return refresh("unifi", self.root, ENV, self.root, fetch or self.fetch)

    def test_complete_snapshot_projects_only_allowlisted_fields(self):
        view = self.refresh()
        self.assertEqual(len(view["items"]), 5)
        self.assertNotIn(KEY, json.dumps(view))
        self.assertNotIn(SITE, json.dumps(view))
        self.assertTrue(saved("unifi", self.root, ENV)["fresh"])
        self.assertFalse(
            saved("unifi", self.root, {**ENV, "YGGFLARE_UNIFI_SITE_ID": SITE})[
                "available"
            ]
        )
        self.assertFalse(scheduled("unifi", ENV))
        self.assertTrue(
            scheduled("unifi", {**ENV, "YGGFLARE_UNIFI_COLLECT_ENABLED": "true"})
        )

    def test_incomplete_collection_and_credential_echo_retain_previous_snapshot(self):
        before = self.refresh()

        def incomplete(*args):
            page = self.fetch(*args)
            if args[2] == "dns":
                page.update(count=0, data=[])
            return page

        def reflected(*args):
            page = self.fetch(*args)
            if args[2] == "clients":
                page["data"] = [{**page["data"][0], "name": KEY}]
            return page

        for fetch in (incomplete, reflected):
            with self.subTest(fetch=fetch.__name__):
                with self.assertRaises(ValueError):
                    self.refresh(fetch)
                status = saved("unifi", self.root, ENV)
                self.assertEqual(status["items"], before["items"])
                self.assertTrue(status["available"])
                self.assertFalse(status["fresh"])
                self.assertFalse(status["last_refresh_verified"])

    def test_cli_web_and_mcp_use_saved_projection_and_metrics_are_aggregate(self):
        self.refresh()
        with (
            patch.dict(os.environ, ENV),
            patch(
                "unifi_api.get_page", side_effect=AssertionError("unexpected live read")
            ),
            patch(
                "mcp_server.saved_integration",
                side_effect=lambda adapter, _: saved(adapter, self.root),
            ),
        ):
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(cli.main(["unifi", "dns", "--json"]), 0)
            rows = json.loads(output.getvalue())["items"]
            self.assertEqual(rows[0]["name"], "example.invalid")
            html = web.render("unifi", {}, {"view": ["devices"]})
            self.assertIn("&lt;gateway&gt;", html)
            self.assertNotIn("<gateway>", html)
            tools = InventoryTools()
            first = tools.list_unifi_devices(limit=1)
            second = tools.list_unifi_devices(
                offset=1, limit=1, snapshot_id=first["snapshot_id"]
            )
            self.assertEqual(second["items"][0]["name"], "switch")
            with self.assertRaises(QueryError):
                tools.list_unifi_devices(offset=1, snapshot_id="changed")
            sample = metrics.render(self.root, self.root).decode()
            self.assertIn("yggflare_unifi_devices 2", sample)
            self.assertNotIn("<gateway>", sample)
        self.assertIn(
            "list_unifi_devices", enabled_tools({"YGGFLARE_MCP_TOOL_GROUPS": "unifi"})
        )
        self.assertNotIn(
            "list_unifi_devices",
            enabled_tools({"YGGFLARE_MCP_TOOL_GROUPS": "inventory"}),
        )
