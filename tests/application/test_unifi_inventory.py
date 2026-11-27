"""Offline UniFi collection and read-only presentation regressions."""

import io
import json
import os
import re
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime
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
        self.assertEqual(view["item_count"], len(view["items"]))
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

    def test_status_parity_for_fresh_stale_and_unavailable_snapshots(self):
        self.refresh()
        view_path = self.root / "unifi-view.json"
        status_path = self.root / "unifi-view-status.json"
        initial_view = json.loads(view_path.read_text())
        initial_status = json.loads(status_path.read_text())
        for scenario in (
            "fresh",
            "failed_refresh",
            "aged",
            "missing_count",
            "bad_count",
        ):
            with self.subTest(scenario=scenario):
                view = {**initial_view}
                status = {**initial_status}
                if scenario == "failed_refresh":
                    status["ok"] = False
                elif scenario == "aged":
                    view["observed_at"] = "2020-01-01T00:00:00+00:00"
                    status["observed_at"] = view["observed_at"]
                elif scenario == "missing_count":
                    del view["item_count"]
                elif scenario == "bad_count":
                    view["item_count"] += 1
                view_path.write_text(json.dumps(view))
                status_path.write_text(json.dumps(status))
                available = scenario not in ("missing_count", "bad_count")
                fresh = scenario == "fresh"
                verified = scenario in ("fresh", "aged")
                with (
                    patch.dict(os.environ, ENV),
                    patch(
                        "mcp_server.saved_integration",
                        side_effect=lambda adapter, _: saved(adapter, self.root),
                    ),
                    patch(
                        "unifi_api.get_page",
                        side_effect=AssertionError("unexpected live read"),
                    ),
                ):
                    tools = InventoryTools()
                    state = tools.get_unifi_status()
                    self.assertEqual(state["available"], available)
                    self.assertEqual(state["fresh"], fresh)
                    self.assertEqual(state["last_refresh_verified"], verified)
                    with redirect_stdout(io.StringIO()) as output:
                        self.assertEqual(cli.main(["unifi", "status", "--json"]), 0)
                    self.assertEqual(json.loads(output.getvalue()), state)
                    html = web.render("unifi", {}, {"view": ["status"]})
                    for key in (
                        "configured",
                        "available",
                        "fresh",
                        "last_refresh_verified",
                    ):
                        expected = "Yes" if state[key] else "No"
                        self.assertIn(
                            f'data-label="Evidence"><span>{key}</span></td>'
                            f'<td data-label="Value"><span>{expected}</span></td>',
                            html,
                        )
                    sample = metrics.render(self.root, self.root).decode()
                    gauges = {
                        line.split()[0]: float(line.split()[1])
                        for line in sample.splitlines()
                        if line.startswith("yggflare_unifi_")
                    }
                    self.assertEqual(gauges["yggflare_unifi_configured"], 1)
                    self.assertEqual(
                        gauges["yggflare_unifi_snapshot_available"], available
                    )
                    self.assertEqual(gauges["yggflare_unifi_snapshot_fresh"], fresh)
                    self.assertEqual(
                        gauges["yggflare_unifi_last_refresh_verified"], verified
                    )
                    if available:
                        counts = {"devices": 2, "clients": 1, "networks": 1, "dns": 1}
                        self.assertEqual(state["counts"], counts)
                        for kind, count in counts.items():
                            self.assertEqual(gauges["yggflare_unifi_" + kind], count)
                        self.assertEqual(
                            gauges["yggflare_unifi_last_success_timestamp_seconds"],
                            datetime.fromisoformat(state["observed_at"]).timestamp(),
                        )
                    else:
                        self.assertIsNone(state["counts"])
                        for kind in ("devices", "clients", "networks", "dns"):
                            self.assertNotIn("yggflare_unifi_" + kind, gauges)
                        self.assertNotIn(
                            "yggflare_unifi_last_success_timestamp_seconds", gauges
                        )
                    self.assertNotIn(KEY, sample)
                    self.assertNotIn("192.168.12.", sample)
                    self.assertNotIn("<gateway>", sample)

    def test_unifi_dashboard_queries_match_exported_metric_names(self):
        child, parent = (row["id"] for row in ROWS["devices"])
        refresh(
            "unifi",
            self.root,
            ENV,
            self.root,
            self.fetch,
            device_detail=lambda config, key, site, device: (
                {"id": child, "uplink": {"deviceId": parent}}
                if device == child
                else {"id": parent}
            ),
        )
        (self.root / "job-status.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "jobs": {
                        "unifi_apply": {
                            "status": "succeeded",
                            "started_at": "2026-01-01T00:00:00Z",
                            "last_success_at": "2026-01-01T00:00:01Z",
                        }
                    },
                }
            )
        )
        with patch.dict(os.environ, ENV):
            scrape = metrics.render(self.root, self.root).decode()
        names = {
            line.split()[0]
            for line in scrape.splitlines()
            if line.startswith("yggflare_")
        }
        dashboard = json.loads(
            (Path(__file__).resolve().parents[2] / "dashboards/yggflare.json").read_text()
        )
        queries = [
            target["expr"]
            for panel in dashboard["panels"]
            if panel["title"].startswith("UniFi ")
            for target in panel["targets"]
        ]
        self.assertTrue(queries)
        for expr in queries:
            for name in re.findall(r"yggflare_[a-z_]+", expr):
                self.assertIn(name, names, expr)

    def test_device_uplink_projection_and_partial_failure(self):
        child, parent = (row["id"] for row in ROWS["devices"])
        for details, status in (
            ({"id": child, "uplink": {"deviceId": parent}}, "reported"),
            (
                {"id": child, "uplink": {"deviceId": str(UUID(int=999))}},
                "parent_not_visible",
            ),
            ({"id": child, "uplink": {"deviceId": child}}, "invalid"),
            ({"id": parent}, "invalid"),
            ({"id": child}, "not_reported"),
        ):
            with self.subTest(status=status):

                def detail(config, key, site, device):
                    self.assertEqual(site, SITE)
                    if device == parent:
                        raise TimeoutError
                    return details

                refresh(
                    "unifi", self.root, ENV, self.root, self.fetch, device_detail=detail
                )
                result = saved("unifi", self.root, ENV)
                self.assertTrue(result["fresh"])
                gateway, switch = [
                    row for row in result["items"] if row["kind"] == "devices"
                ]
                self.assertEqual(gateway["uplink_status"], status)
                self.assertEqual(
                    gateway["uplink_name"], "switch" if status == "reported" else None
                )
                self.assertEqual(switch["uplink_status"], "unavailable")
                self.assertNotIn(parent, json.dumps(result))

    def test_device_details_are_bounded_and_saved_for_operator_views(self):
        child, parent = (row["id"] for row in ROWS["devices"])
        with patch("unifi_inventory.DETAIL_LIMIT", 1):

            def detail(config, key, site, device):
                self.assertEqual(device, child)
                return {"id": child, "uplink": {"deviceId": parent}}

            refresh(
                "unifi", self.root, ENV, self.root, self.fetch, device_detail=detail
            )

        with (
            patch.dict(os.environ, ENV),
            patch(
                "mcp_server.saved_integration",
                side_effect=lambda adapter, _: saved(adapter, self.root),
            ),
        ):
            tools = InventoryTools()
            self.assertEqual(
                tools.list_unifi_devices()["items"][0]["uplink_name"], "switch"
            )
            self.assertEqual(
                tools.get_unifi_status()["uplink_counts"]["not_checked"], 1
            )
            self.assertIn("uplink_name", web.render("unifi", {}, {"view": ["devices"]}))
            self.assertIn(
                "yggflare_unifi_uplink_reported 1",
                metrics.render(self.root, self.root).decode(),
            )
