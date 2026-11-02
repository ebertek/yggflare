"""Snapshot projection never grants ownership or exposes raw API payloads."""

import json
import tempfile
import unittest
from pathlib import Path

from cloudflare_view import begin, project, publish


class CloudflareViewTests(unittest.TestCase):
    def test_classifications_and_allowlisted_resources(self):
        registry = {
            "scope": {"account": "one"},
            "hosts": {
                "owned.ebi.nu": {
                    "app_id": "owned-app",
                    "dns_id": "owned-dns",
                    "route": {
                        "hostname": "owned.ebi.nu",
                        "service": "https://user:SECRET@origin",
                    },
                },
                "old.ebi.nu": {"app_id": "old-app"},
            },
        }
        desired = {"owned.ebi.nu": [], "legacy.ebi.nu": []}
        apps = [
            {"domain": name, "id": name + "-id", "secret": "SECRET"}
            for name in [
                "owned.ebi.nu",
                "old.ebi.nu",
                "unmanaged.ebi.nu",
                "foreign.example",
            ]
        ]
        result = project(
            registry, desired, apps, [], {"ingress": [{"service": "http_status:404"}]}
        )
        self.assertEqual(
            {r["hostname"]: r["lifecycle"] for r in result["hosts"]},
            {
                "owned.ebi.nu": "managed",
                "old.ebi.nu": "orphaned",
                "legacy.ebi.nu": "declared / unclaimed",
                "unmanaged.ebi.nu": "unmanaged",
            },
        )
        self.assertNotIn("SECRET", json.dumps(result))
        legacy = next(r for r in result["hosts"] if r["hostname"] == "legacy.ebi.nu")
        self.assertFalse(legacy["claimed"])
        self.assertEqual(legacy["claimed_app_id"], "")

    def test_failed_refresh_preserves_last_complete_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            publish(data, {"audited_at": "last-good", "hosts": []})
            begin(data)
            self.assertEqual(
                json.loads((data / "cloudflare-view.json").read_text())["audited_at"],
                "last-good",
            )
            self.assertFalse(
                json.loads((data / "cloudflare-view-status.json").read_text())["ok"]
            )
            publish(data, {"audited_at": "new-good", "hosts": []})
            self.assertTrue(
                json.loads((data / "cloudflare-view-status.json").read_text())["ok"]
            )
            self.assertEqual(
                (data / "cloudflare-view.json").stat().st_mode & 0o777, 0o600
            )
