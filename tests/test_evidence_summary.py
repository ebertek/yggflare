"""Regression tests for bounded, pure evidence summaries."""
import unittest
from evidence_summary import monitor_port_summary, probe_outcome


class EvidenceTests(unittest.TestCase):
    def test_global_selection_deduplicates_and_preserves_unknown(self):
        stamp = "2026-11-25T09:00:00Z"
        state = {
            "scanned_at": stamp,
            "scan_coverage": {
                "version": 1, "mode": "live", "observed_at": stamp,
                "tcp": {"selected_port_count": 1, "selected_ports": [22]},
            },
        }
        row = {"monitor_type": "port", "target_host": "192.0.2.1", "target_port": 38050, "target_scheme": "tcp"}
        summary = monitor_port_summary(
            [row, row, {**row, "target_port": 22}, {**row, "target_host": "demo.invalid"}],
            state, available=True,
        )
        self.assertEqual(summary["numeric_ipv4_tcp_endpoints"], 2)
        self.assertEqual(summary["not_selected_ports"], [38050])
        self.assertEqual(summary["not_selected_endpoints"], 1)
        self.assertFalse(monitor_port_summary([row], {}, available=True)["available"])

    def test_http_response_without_expectation_is_inconclusive(self):
        self.assertEqual(probe_outcome({"check": "http", "status": "response_received"}), "inconclusive")
