"""Regression tests for Yggflare scheduling/configuration."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import controller


class ControllerTests(unittest.TestCase):
    def test_missing_private_env_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                controller.read_env(Path(directory) / "missing.env")

    def test_explicit_false_auto_apply(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cloudflare.env"
            path.write_text("CF_AUTO_APPLY=false\n", encoding="utf-8")
            self.assertEqual(controller.read_env(path)["CF_AUTO_APPLY"], "false")

    def test_snapshot_does_not_write_source(self):
        with tempfile.TemporaryDirectory() as source, tempfile.TemporaryDirectory() as config:
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
                    (Path(destination) / "Scripts/cloudflare/static-hosts.json").is_file()
                )


if __name__ == "__main__":
    unittest.main()
