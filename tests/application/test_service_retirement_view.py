"""Unified retirement presentation remains saved, scoped and non-authorizing."""

import copy
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import metrics
import operator_views
import service_retirement_collect as collector
import service_retirement_view as view
from mcp_server import InventoryTools, enabled_tools
from traefik_inventory import write


class RetirementViewTests(unittest.TestCase):
    def setUp(self):
        self.data = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.now = int(time.time())
        self.document = {
            "version": 1,
            "service": "demo",
            "internal": "demo.ygg.nu",
            "external": "demo.ebi.nu",
            "items": [
                {
                    "layer": layer,
                    "hostname": "demo.ebi.nu" if layer == "external" else "demo.ygg.nu",
                    "status": "absent",
                    "observed_at": self.now,
                }
                for layer in view.LAYERS
            ],
            "item_count": len(view.LAYERS),
        }
        self.document["items"][3].update(
            status="unmanaged", ownership="unmanaged", address="10.4.21.42"
        )
        self.document["items"][4].update(status="blocked", policy_count=1)
        self.path = self.data / view.FILENAME

    def test_missing_stale_and_other_selector(self):
        self.assertFalse(view.saved(self.data)["available"])
        write(self.path, self.document)
        report = view.saved(self.data, "demo.ebi.nu", now=self.now)
        self.assertTrue(report["available"])
        self.assertTrue(report["fresh"])
        self.assertTrue(report["complete"])
        self.assertFalse(report["deletion_authorized"])
        self.assertFalse(view.saved(self.data, "other")["available"])
        self.assertFalse(view.saved(self.data, now=self.now + 901)["fresh"])
        self.assertFalse(view.saved(self.data, now=self.now - 1)["fresh"])
        self.document["items"][2]["status"] = "unavailable"
        write(self.path, self.document)
        self.assertFalse(view.saved(self.data)["complete"])

    def test_invalid_or_secret_fields_fail_closed(self):
        for key, value in (
            ("secret", "private"),
            ("status", "arbitrary"),
            ("address", "not-an-address"),
            ("observed_at", True),
        ):
            with self.subTest(key=key):
                document = copy.deepcopy(self.document)
                document["items"][3][key] = value
                write(self.path, document)
                self.assertFalse(view.saved(self.data)["available"])

    def test_shared_query_and_aggregate_metrics(self):
        write(self.path, self.document)
        with patch.object(
            view, "saved", wraps=lambda _data, service="": saved(self.data, service)
        ):
            tools = InventoryTools(lambda: {})
            report = tools.get_service_retirement("demo")
            self.assertEqual(
                operator_views.query(tools, "services", "retirement-plan", "demo"),
                report,
            )
            html = operator_views.render(
                "services",
                tools,
                lambda headers, rows: str(rows),
                {"view": ["retirement-plan"], "q": ["demo"]},
            )
            self.assertIn("Saved retirement review", html)
            self.assertIn("unmanaged", html)
        self.assertIn(
            "get_service_retirement",
            enabled_tools({"YGGFLARE_MCP_TOOL_GROUPS": "inventory,cloudflare,unifi"}),
        )
        self.assertNotIn(
            "get_service_retirement",
            enabled_tools({"YGGFLARE_MCP_TOOL_GROUPS": "cloudflare,unifi"}),
        )
        output = metrics.render(self.data, self.data).decode()
        self.assertIn("yggflare_retirement_review_available 1", output)
        self.assertNotIn("demo.ygg.nu", output)
        self.assertNotIn("10.4.21.42", output)

    def test_collection_partial_failure_is_not_absence(self):
        settings = {"internal_zone": "ygg.nu", "external_zone": "ebi.nu"}
        with (
            patch.object(collector, "cloudflare_settings", return_value=settings),
            patch.object(collector, "api_token", return_value="fixture"),
            patch.object(collector, "CloudflareClient"),
            patch("controller.snapshot"),
            patch.object(
                collector, "compose_evidence", return_value=(set(), set(), [])
            ),
            patch.object(
                collector,
                "docker_containers",
                side_effect=ValueError("private diagnostic"),
            ),
            patch.object(
                collector, "external_review", return_value={"status": "absent"}
            ),
            patch.object(
                collector,
                "internal_review",
                return_value={"status": "unmanaged", "address": "10.4.21.42"},
            ),
            patch.object(
                collector, "unifi_review", return_value={"status": "blocked"}
            ) as unifi,
        ):
            self.assertEqual(collector.collect(self.data, "demo.ebi.nu"), 1)
            unifi.assert_called_once_with(self.data, "demo.ygg.nu", "10.4.21.42")
        report = view.saved(self.data, "demo")
        self.assertFalse(report["complete"])
        self.assertEqual(report["items"][1]["status"], "unavailable")
        self.assertNotIn("private diagnostic", self.path.read_text())
        self.assertFalse(report["deletion_authorized"])


saved = view.saved
