"""Snapshot projection never grants ownership or exposes raw API payloads."""

import json
import tempfile
import unittest
from pathlib import Path

from cloudflare_view import (
    audit_projection,
    begin,
    configuration_projection,
    project,
    publish,
)


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

    def test_audit_projection_excludes_sensitive_payloads(self):
        result = audit_projection(
            {
                "actions": [
                    {
                        "hostname": "example.invalid",
                        "kind": "create_dns_cname",
                        "content": "SECRET",
                        "policies": ["SECRET"],
                    },
                    {
                        "hostname": "internal.invalid",
                        "kind": "update_docker_dns_a",
                        "before": "192.0.2.1",
                        "content": "192.0.2.2",
                    },
                ],
                "blocked": [{"hostname": "example.invalid", "reason": "SECRET"}],
                "unaccounted_ygg_dns": {
                    "enabled": True,
                    "findings": [
                        {"hostname": "txt.invalid", "type": "TXT", "content": "SECRET"}
                    ],
                    "retained": {
                        "missing": [
                            {
                                "hostname": "txt.invalid",
                                "type": "TXT",
                                "content": "SECRET",
                            }
                        ]
                    },
                },
            }
        )
        self.assertEqual(result["total_findings"], 5)
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertIn("192.0.2.2", json.dumps(result))
        self.assertTrue(result["internal_dns_enabled"])

    def test_configuration_projection_never_exports_selectors_or_payloads(self):
        result = configuration_projection(
            {"example.invalid": ["one", "two"]},
            [
                {
                    "domain": "example.invalid",
                    "type": "self_hosted",
                    "policies": [
                        {"id": "two", "precedence": 2},
                        {"id": "one", "precedence": 1},
                    ],
                }
            ],
            [
                {"id": "one", "decision": "bypass", "include": ["SECRET"]},
                {"id": "two", "decision": "deny"},
            ],
            [
                {
                    "name": "example.invalid",
                    "type": "CNAME",
                    "content": "tunnel.cfargotunnel.com",
                }
            ],
            [{"name": "txt.invalid", "type": "TXT", "content": "SECRET"}],
            [
                {
                    "hostname": "example.invalid",
                    "service": "https://origin.invalid:443/SECRET?token=SECRET",
                },
                {
                    "hostname": "other.invalid",
                    "service": "https://user:SECRET@origin.invalid",
                },
                {"service": "http_status:404"},
            ],
            "tunnel",
            internal_dns_collected=True,
        )
        self.assertNotIn("SECRET", json.dumps(result))
        row = result["access"]["items"][0]
        self.assertEqual(row["observed_decisions"], ["bypass", "deny"])
        self.assertEqual(row["status"], "matched")
        self.assertTrue(result["dns"]["items"][0]["matches_configured_tunnel"])
        routes = result["tunnel"]["items"]
        self.assertEqual(routes[0]["origin_host"], "origin.invalid")
        self.assertNotIn("origin_host", routes[1])

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
