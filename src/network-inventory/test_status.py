"""Tests for the read-only CLI view of saved network scan evidence."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import status


class SavedStatusTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "state.json"
        self.state = {
            "initialized": True,
            "scanned_at": "2026-11-04T13:10:00Z",
            "hosts": {"10.4.20.10": {}, "10.4.20.20": {}},
            "advertisements": ["printer.local|_ipp._tcp|631"],
            "supplemental": {"records": [{"ip": "10.4.20.10"}], "warnings": []},
            "identity_history": {
                "mac:aa:bb:cc:dd:ee:ff": {
                    "status": "observed",
                    "confidence": "high",
                },
                "address:10.4.20.20": {
                    "status": "not observed",
                    "confidence": "low",
                },
            },
            "identity_conflicts": [
                {
                    "address": "10.4.20.20",
                    "macs": ["aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55"],
                    "reasons": ["Multiple MAC claims for this address"],
                }
            ],
            "alert_pending_confirmations": [
                "NEW DNS-SD printer.local|_ipp._tcp|631 (1/2 scans)",
            ],
            "pending_discord_events": [],
        }
        self.write()

    def write(self):
        self.path.write_text(json.dumps(self.state), encoding="utf-8")

    def test_status_is_read_only_and_summarizes_saved_evidence(self):
        old = self.path.read_bytes()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = status.main([], path=self.path)
        self.assertEqual(result, 0)
        self.assertEqual(old, self.path.read_bytes())
        message = output.getvalue()
        self.assertIn("no scan performed", message)
        self.assertIn("IPv4 hosts: 2 | DNS-SD services: 1", message)
        self.assertIn("Device identities: 2 tracked, 1 observed, 1 high confidence", message)
        self.assertIn("Identity conflicts: 1", message)
        self.assertIn("Pending confirmations: 1", message)
        self.assertIn("printer.local|_ipp._tcp|631", message)
        self.assertNotIn("Multiple MAC claims for this address", message)

    def test_details_exposes_conflict_evidence_without_mutation(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = status.main(["--details"], path=self.path)
        self.assertEqual(result, 0)
        message = output.getvalue()
        self.assertIn("10.4.20.20", message)
        self.assertIn("aa:bb:cc:dd:ee:ff", message)
        self.assertIn("Multiple MAC claims for this address", message)

    def test_json_report_is_parseable_and_has_no_live_dependencies(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = status.main(["--json"], path=self.path)
        self.assertEqual(result, 0)
        parsed = json.loads(output.getvalue())
        self.assertEqual(parsed["tracked_identities"], 2)
        self.assertEqual(parsed["currently_observed_identities"], 1)
        self.assertEqual(parsed["identity_conflicts"], 1)
        self.assertEqual(len(parsed["pending_confirmations"]), 1)
        self.assertEqual(parsed["pending_discord_deliveries"], 0)

    def test_terminal_escape_characters_are_sanitized(self):
        self.state["alert_pending_confirmations"] = [
            "NEW DNS-SD bad.local\nFAKE ALERT\x1b[31m|_ipp._tcp|631"
        ]
        self.write()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            status.main([], path=self.path)
        self.assertNotIn("\x1b", output.getvalue())
        self.assertNotIn("\nFAKE ALERT", output.getvalue())
        self.assertIn("NEW DNS-SD bad.local FAKE ALERT", output.getvalue())

    def test_missing_or_invalid_state_is_explicit_error(self):
        self.path.unlink()
        with contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(status.main([], path=self.path), 2)
        self.assertIn("No saved network scan", errors.getvalue())

        for bad in ("not-json", "[]", '{"initialized": false}', '{"initialized": true, "hosts": []}'):
            with self.subTest(state=bad):
                self.path.write_text(bad, encoding="utf-8")
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(status.main([], path=self.path), 2)

    def test_bounded_input_and_reject_malformed_conflicts(self):
        self.state["identity_conflicts"] = ["not an object"]
        self.write()
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(status.main([], path=self.path), 2)
        self.path.write_text("x" * (status.MAX_STATE_BYTES + 1), encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(status.main([], path=self.path), 2)

    def test_incompatible_output_flags_are_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                status.main(["--details", "--json"], path=self.path)
        self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
