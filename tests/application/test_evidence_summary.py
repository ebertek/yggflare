"""Regression tests for bounded, pure evidence summaries."""

import unittest
from datetime import UTC, datetime

from evidence_summary import monitor_port_summary, probe_outcome


class EvidenceTests(unittest.TestCase):
    def test_global_selection_deduplicates_and_preserves_unknown(self):
        stamp = "2026-11-25T09:00:00Z"
        state = {
            "scanned_at": stamp,
            "scan_coverage": {
                "version": 1,
                "mode": "live",
                "observed_at": stamp,
                "tcp": {"selected_port_count": 1, "selected_ports": [22]},
            },
        }
        row = {
            "monitor_type": "port",
            "target_host": "192.0.2.1",
            "target_port": 38050,
            "target_scheme": "tcp",
        }
        summary = monitor_port_summary(
            [
                row,
                row,
                {**row, "target_port": 22},
                {**row, "target_host": "demo.invalid"},
            ],
            state,
            available=True,
        )
        self.assertEqual(summary["numeric_ipv4_tcp_endpoints"], 2)
        self.assertEqual(summary["not_selected_ports"], [38050])
        self.assertEqual(summary["not_selected_endpoints"], 1)
        self.assertFalse(monitor_port_summary([row], {}, available=True)["available"])

    def test_http_response_without_expectation_is_inconclusive(self):
        self.assertEqual(
            probe_outcome({"check": "http", "status": "response_received"}),
            "inconclusive",
        )


class ObservationTimingTests(unittest.TestCase):
    def test_window_excludes_unknown_future_and_naive_timestamps(self):
        from evidence_summary import observation_window

        now = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)
        result = observation_window(
            {
                "first": "2026-11-25T10:00:00Z",
                "last": "2026-11-25T12:30:00+01:00",
                "naive": "2026-11-25T11:00:00",
                "future": "2026-11-25T12:01:00Z",
                "missing": None,
                "invalid": "not-a-time",
            },
            now,
        )
        self.assertEqual(result["spread_seconds"], 5400)
        self.assertEqual(result["timestamped_sources"], ["first", "last"])
        self.assertEqual(
            result["unknown_timestamp_sources"],
            ["future", "invalid", "missing", "naive"],
        )
        self.assertIsNone(
            observation_window({"one": now.isoformat()}, now)["spread_seconds"]
        )

    def test_scan_verification_uses_related_attempt_or_saved_execution(self):
        from evidence_summary import network_collection_verified

        now = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)
        scanned = "2026-11-25T11:00:00Z"
        coverage = {
            "available": True,
            "observed_at": scanned,
            "host_discovery": {"run_completed": True},
            "tcp": {"run_completed": True},
        }
        old = {
            "status": "failed",
            "started_at": "2026-11-25T09:00:00Z",
            "finished_at": "2026-11-25T09:05:00Z",
        }
        verify = network_collection_verified
        self.assertIs(verify(scanned, coverage, old, now), True)
        self.assertIsNone(verify(scanned, {}, {**old, "status": "succeeded"}, now))
        self.assertIs(
            verify(
                scanned,
                coverage,
                {**old, "started_at": "2026-11-25T11:30:00Z"},
                now,
            ),
            False,
        )
        self.assertIs(
            verify(
                scanned,
                {},
                {
                    "status": "succeeded",
                    "started_at": "2026-11-25T10:55:00Z",
                    "finished_at": "2026-11-25T11:05:00Z",
                },
                now,
            ),
            True,
        )
        self.assertIsNone(verify(scanned, {**coverage, "observed_at": None}, {}, now))
