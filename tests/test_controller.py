"""Regression tests for Yggflare scheduling/configuration."""

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import controller


class ControllerTests(unittest.TestCase):
    def test_json_log_has_utc_fields(self):
        with patch.object(controller, "LOG_FORMAT", "json"):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                controller.log("info", "network", "Audit complete", hosts=101)
            record = json.loads(output.getvalue())
            self.assertEqual(record["level"], "info")
            self.assertEqual(record["component"], "network")
            self.assertEqual(record["hosts"], 101)
            self.assertTrue(record["timestamp"].endswith("Z"))

    def test_text_log_has_level_component_and_utc_timestamp(self):
        with patch.object(controller, "LOG_FORMAT", "text"):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                controller.log("warning", "cloudflare", "Drift detected")
            line = output.getvalue()
            self.assertIn("WARNING [cloudflare] Drift detected", line)
            self.assertRegex(line, r"^\\d{4}-\\d{2}-\\d{2}T.*Z ")

    def test_subprocess_failure_is_reported(self):
        with patch.object(controller, "log") as log:
            with self.assertRaises(RuntimeError):
                controller.run([sys.executable, "-c", "import sys; sys.exit(7)"])
            self.assertTrue(
                any(call.kwargs.get("exit_code") == 7 for call in log.call_args_list)
            )

    def test_cloudflare_requires_secret_file(self):
        """Cloudflare cycle must fail closed without the token secret."""
        with patch.dict(
            "os.environ",
            {
                "CF_AUTO_APPLY": "false",
                "CLOUDFLARE_API_TOKEN_FILE": "/nonexistent/yggflare-token",
            },
        ):
            with self.assertRaises(FileNotFoundError):
                controller.cloudflare_run()

    def test_invalid_auto_apply_fails_closed(self):
        """Only exact true or false values are accepted."""
        with patch.dict("os.environ", {"CF_AUTO_APPLY": "yes"}):
            with self.assertRaises(ValueError):
                controller.cloudflare_run()

    def test_snapshot_does_not_write_source(self):
        with (
            tempfile.TemporaryDirectory() as source,
            tempfile.TemporaryDirectory() as config,
        ):
            with tempfile.TemporaryDirectory() as destination:
                original = Path(source) / "stack" / "compose.yaml"
                original.parent.mkdir(parents=True)
                original.write_text("services: {}\n", encoding="utf-8")
                (Path(config) / "static-hosts.json").write_text(
                    '{"version": 1, "hosts": []}', encoding="utf-8"
                )
                with patch.object(controller, "SOURCE", Path(source)):
                    with patch.object(controller, "CONFIG", Path(config)):
                        controller.snapshot(Path(destination))
                self.assertEqual(original.read_text(encoding="utf-8"), "services: {}\n")
                self.assertTrue(
                    (
                        Path(destination) / "Scripts/cloudflare/static-hosts.json"
                    ).is_file()
                )


if __name__ == "__main__":
    unittest.main()
