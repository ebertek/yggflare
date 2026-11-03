"""Metric exposition tests; no network access, credentials or active scans."""

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import metrics
import web


class MetricsTests(unittest.TestCase):
    def test_empty_state_has_presence_gauges_not_fake_scan_timestamps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = metrics.render(root, root, now=1000).decode()
        self.assertIn("yggflare_inventory_state_present 0", output)
        self.assertIn("yggflare_network_state_present 0", output)
        self.assertIn("yggflare_cloudflare_snapshot_stale 1", output)
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
            (root / "cloudflare-view-status.json").write_text('{"ok":true}')
            sample = metrics.render(root, root, now=1793734200).decode()
        for expected in (
            "yggflare_inventory_declared_hosts 1",
            "yggflare_network_discovered_ipv4_hosts 2",
            "yggflare_network_unknown_ipv4_hosts 1",
            "yggflare_network_active_findings 2",
            "yggflare_network_dns_sd_services 1",
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
            (root / "cloudflare-view-status.json").write_text('{"ok":true}')
            reference = 1793664000
            fresh = metrics.render(root, root, now=reference + 3600).decode()
            stale = metrics.render(root, root, now=reference + 9 * 3600).decode()
            self.assertIn("yggflare_cloudflare_snapshot_stale 0", fresh)
            self.assertIn("yggflare_cloudflare_snapshot_stale 1", stale)
            (root / "cloudflare-view-status.json").write_text('{"ok":false}')
            failed = metrics.render(root, root, now=reference + 3600).decode()
            self.assertIn("yggflare_cloudflare_snapshot_stale 1", failed)

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
