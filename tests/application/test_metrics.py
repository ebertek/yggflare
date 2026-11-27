"""Metric exposition tests; no network access, credentials or active scans."""

import io
import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import metrics
import web
from mcp_server import InventoryTools
from web_views import cloudflare_view


class MetricsTests(unittest.TestCase):
    def test_job_metrics_do_not_invent_success_or_expose_job_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "job-status.json").write_text(
                json.dumps(
                    {
                        "version": 1,
                        "jobs": {
                            "backup": {
                                "status": "completion_unknown",
                                "started_at": "2026-11-03T00:00:00Z",
                            },
                            "private": {"status": "succeeded"},
                        },
                    }
                )
            )
            output = metrics.render(root, root).decode()
            self.assertIn("yggflare_job_evidence_available 1", output)
            self.assertIn("yggflare_job_backup_completion_unknown 1", output)
            self.assertNotIn("yggflare_job_backup_last_attempt_success ", output)
            self.assertNotIn("private", output)

    def test_coverage_metrics_are_aggregate_and_allowlisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "network-inventory").mkdir()
            (root / "network-inventory/state.json").write_text(
                json.dumps(
                    {
                        "scan_coverage": {
                            "version": 1,
                            "mode": "live",
                            "tcp": {
                                "requested_target_count": 4,
                                "omitted_target_count": 2,
                                "explicit_timeout_count": 0,
                                "represented_target_count": 2,
                                "secret": "never-export",
                            },
                        },
                        "supplemental": {
                            "collector_evidence": {
                                "version": 1,
                                "sources": {
                                    "ndp": {
                                        "configured": True,
                                        "attempted": 2,
                                        "completed": 2,
                                        "no_reply": 1,
                                        "failed": 0,
                                        "parse_errors": 0,
                                    },
                                    "smb": {
                                        "configured": True,
                                        "attempted": 1,
                                        "completed": 1,
                                        "access_denied": 1,
                                        "selected_targets": 1,
                                        "skipped_no_port_evidence": 8,
                                        "private_diagnostic": "never-export",
                                    },
                                    "private": {"configured": True, "attempted": 42},
                                    "arp": {"configured": False, "attempted": 0},
                                },
                            }
                        },
                    }
                )
            )
            output = metrics.render(root, root).decode()
        self.assertIn("yggflare_network_tcp_requested_target_count 4", output)
        self.assertIn("yggflare_network_tcp_omitted_target_count 2", output)
        self.assertIn("yggflare_discovery_ndp_no_reply 1", output)
        self.assertIn("yggflare_discovery_smb_access_denied 1", output)
        self.assertIn("yggflare_discovery_smb_skipped_no_port_evidence 8", output)
        self.assertNotIn("yggflare_discovery_smb_private_diagnostic", output)
        self.assertNotIn("yggflare_discovery_private", output)
        self.assertNotIn("yggflare_discovery_arp_attempted", output)
        self.assertNotIn("never-export", output)

    def test_probe_coverage_metrics_do_not_count_http_response_as_pass(self):
        identity = {
            "target": "private-name",
            "hostname": "private.invalid",
            "address": "192.0.2.10",
            "port": 443,
            "scheme": "https",
            "check": "http",
        }
        snapshot = {
            "configured": True,
            "available": True,
            "fresh": True,
            "observed_at": "2026-11-25T09:00:00Z",
            "configured_checks": [identity],
            "items": [
                {
                    **identity,
                    "status": "response_received",
                    "expected_status_match": False,
                }
            ],
        }
        with (
            tempfile.TemporaryDirectory() as folder,
            patch("metrics.saved_probes", return_value=snapshot),
        ):
            output = metrics.render(Path(folder), Path(folder)).decode()
        self.assertIn("yggflare_probe_coverage_configured_checks 1", output)
        self.assertIn("yggflare_probe_coverage_passed_checks 0", output)
        self.assertIn("yggflare_probe_coverage_failed_checks 1", output)
        self.assertNotIn("private-name", output)
        self.assertNotIn("192.0.2.10", output)

    def test_empty_state_has_presence_gauges_not_fake_scan_timestamps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = metrics.render(root, root, now=1000).decode()
        self.assertIn("yggflare_kuma_primary_scan_selection_available 0", output)
        self.assertNotIn("yggflare_kuma_primary_scan_not_selected_endpoints ", output)
        self.assertIn("yggflare_inventory_state_present 0", output)
        self.assertIn("yggflare_network_state_present 0", output)
        self.assertIn("yggflare_cloudflare_snapshot_stale 1", output)
        for name in (
            "inventory_declared_hosts",
            "network_discovered_ipv4_hosts",
            "network_active_findings",
            "network_dns_sd_services",
            "cloudflare_orphan_hosts",
        ):
            self.assertNotIn(f"\nyggflare_{name} ", output)
        self.assertNotIn(
            "\nyggflare_network_scan_last_success_timestamp_seconds ",
            output,
        )

    def test_bounded_snapshot_exposes_aggregates_without_private_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "network-inventory").mkdir()
            (root / "static-hosts.json").write_text(
                json.dumps(
                    {"hosts": [{"hostname": "private.example", "ipv4": "10.4.20.40"}]}
                )
            )
            (root / "network-inventory/state.json").write_text(
                json.dumps(
                    {
                        "scanned_at": "2026-11-03T19:00:00+00:00",
                        "dns_sd_scanned_at": "2026-11-03T19:00:00Z",
                        "scan_duration_seconds": 91.25,
                        "hosts": {
                            "10.4.20.40": {"mac": "aa:bb:cc:dd:ee:ff"},
                            "10.4.20.41": {},
                        },
                        "reported": {
                            "unknown-device:10.4.20.41:aa": "NEW DEVICE private.example",
                            "new-port:10.4.20.40:443": "port",
                        },
                        "advertisements": ["private.example|_http._tcp|80"],
                        "supplemental": {"warnings": ["private error", "timeout"]},
                        "pending_discord_events": ["private alert"],
                        "identity_history": {
                            "inventory:private.example": {
                                "confidence": "high",
                                "status": "observed",
                            },
                            "address:10.4.20.41": {
                                "confidence": "low",
                                "status": "not observed",
                            },
                        },
                        "identity_conflicts": [
                            {"address": "10.4.20.42", "reason": "private conflict"}
                        ],
                    }
                )
            )
            (root / "cloudflare-view.json").write_text(
                json.dumps(
                    {
                        "audited_at": "2026-11-03T19:00:00+00:00",
                        "hosts": [
                            {"hostname": "secret.example", "lifecycle": "orphaned"},
                            {"hostname": "active.example", "lifecycle": "managed"},
                        ],
                    }
                )
            )
            (root / "cloudflare-view-status.json").write_text(
                '{"ok":true,"attempted_at":"2026-11-03T19:00:00+00:00"}'
            )
            sample = metrics.render(root, root, now=1793734200).decode()
        for expected in (
            "yggflare_inventory_declared_hosts 1",
            "yggflare_network_discovered_ipv4_hosts 2",
            "yggflare_network_unknown_ipv4_hosts 1",
            "yggflare_network_active_findings 2",
            "yggflare_network_dns_sd_services 1",
            "yggflare_network_observed_identities 1",
            "yggflare_network_high_confidence_identities 1",
            "yggflare_network_identity_conflicts 1",
            "yggflare_network_supplemental_warnings 2",
            "yggflare_network_scan_duration_seconds 91.25",
            "yggflare_cloudflare_orphan_hosts 1",
        ):
            with self.subTest(metric=expected):
                self.assertIn(expected, sample)
        for private in (
            "private.example",
            "secret.example",
            "10.4.20.40",
            "aa:bb:cc:dd:ee:ff",
            "private error",
            "private alert",
        ):
            self.assertNotIn(private, sample)
        self.assertIn("# TYPE yggflare_network_active_findings gauge", sample)

    def test_stale_view_when_last_refresh_failed_or_older_than_eight_hours(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "cloudflare-view.json").write_text(
                '{"audited_at":"2026-11-03T00:00:00+00:00","hosts":[]}'
            )
            (root / "cloudflare-view-status.json").write_text(
                '{"ok":true,"attempted_at":"2026-11-03T00:00:00+00:00"}'
            )
            reference = 1793664000
            fresh = metrics.render(root, root, now=reference + 3600).decode()
            stale = metrics.render(root, root, now=reference + 9 * 3600).decode()
            self.assertIn("yggflare_cloudflare_snapshot_stale 0", fresh)
            self.assertIn("yggflare_cloudflare_snapshot_stale 1", stale)
            (root / "cloudflare-view-status.json").write_text('{"ok":false}')
            failed = metrics.render(root, root, now=reference + 3600).decode()
            self.assertIn("yggflare_cloudflare_snapshot_stale 1", failed)

    def test_cloudflare_evidence_parity(self):
        now = datetime.now(UTC)
        stamp = (now - timedelta(minutes=1)).isoformat()
        future = (now + timedelta(hours=1)).isoformat()
        for view, marker, available, verified in (
            ({"audited_at": stamp, "hosts": []}, stamp, True, True),
            ({"audited_at": stamp, "hosts": []}, future, True, False),
            ({"audited_at": future, "hosts": []}, future, False, False),
            ({"audited_at": stamp}, stamp, False, False),
            ({}, stamp, False, False),
        ):
            with (
                self.subTest(view=view, marker=marker),
                tempfile.TemporaryDirectory() as tmp,
            ):
                root = Path(tmp)
                status = {"ok": True, "attempted_at": marker}
                (root / "cloudflare-view.json").write_text(json.dumps(view))
                (root / "cloudflare-view-status.json").write_text(json.dumps(status))
                data = {"cloudflare_view": view, "cloudflare_view_status": status}
                result = InventoryTools(lambda: data).get_cloudflare_lifecycle()
                self.assertEqual(result["snapshot_available"], available)
                self.assertEqual(result["last_refresh_verified"], verified)
                self.assertEqual(result["fresh"], verified)
                self.assertEqual("ownership_counts" in result, available)
                html = cloudflare_view(data, lambda *_: "")
                self.assertEqual("No complete Cloudflare" in html, not available)
                self.assertEqual(
                    "Latest refresh failed" in html, available and not verified
                )
                scrape = metrics.render(root, root, now=now.timestamp()).decode()
                self.assertIn(
                    f"yggflare_cloudflare_snapshot_present {int(available)}", scrape
                )
                self.assertIn(
                    f"yggflare_cloudflare_last_refresh_success {int(verified)}", scrape
                )
                self.assertIn(
                    f"yggflare_cloudflare_snapshot_stale {int(not verified)}", scrape
                )
                self.assertEqual(
                    "\nyggflare_cloudflare_orphan_hosts " in scrape, available
                )

    def test_malformed_state_refuses_to_publish_misleading_zeros(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "network-inventory").mkdir()
            (root / "network-inventory/state.json").write_text(
                '{"hosts":[], "scanned_at":"not-a-date"}'
            )
            with self.assertRaises(ValueError):
                metrics.render(root, root)
            (root / "network-inventory/state.json").write_text(
                '{"hosts":{}, "scanned_at":"not-a-date"}'
            )
            with self.assertRaises(ValueError):
                metrics.render(root, root)
            (root / "network-inventory/state.json").write_text(
                '{"hosts":{}, "scan_duration_seconds":-1}'
            )
            with self.assertRaises(ValueError):
                metrics.render(root, root)

    def test_metrics_http_route_opt_in_get_head_and_no_inventory_model(self):
        class FakeOutput(io.BytesIO):
            pass

        def request(enabled, send_body=True):
            handler = web.Handler.__new__(web.Handler)
            handler.path = "/metrics?query=ignored"
            handler.wfile = FakeOutput()
            statuses = []
            headers = {}
            handler.send_response = lambda code: statuses.append(code)
            handler.send_error = lambda code, *args: statuses.append(code)
            handler.send_header = lambda key, value: headers.update({key: value})
            handler.end_headers = lambda: None
            with (
                patch.dict(
                    "os.environ",
                    {"YGGFLARE_METRICS_ENABLED": "true" if enabled else "false"},
                ),
                patch.object(web, "model", side_effect=AssertionError("active model")),
                patch.object(web, "render_metrics", return_value=b"metric 1\n"),
            ):
                handler.respond(send_body)
            return statuses, headers, handler.wfile.getvalue()

        statuses, headers, body = request(True)
        self.assertEqual(statuses, [200])
        self.assertIn("text/plain", headers["Content-Type"])
        self.assertEqual(body, b"metric 1\n")
        self.assertEqual(request(True, send_body=False)[2], b"")
        self.assertEqual(request(False)[0], [404])


if __name__ == "__main__":
    unittest.main()
