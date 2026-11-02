"""Regression tests for Yggflare scheduling/configuration."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import controller


class ControllerTests(unittest.TestCase):
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
