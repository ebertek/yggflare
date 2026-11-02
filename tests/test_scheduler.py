import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import controller


class TestController(unittest.TestCase):
    def test_rejects_missing_config(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(FileNotFoundError):
                controller.read_env(Path(folder) / "missing.env")

    def test_accepts_simple_env_but_not_shell(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "test.env"
            path.write_text('CF_AUTO_APPLY="false"\nCF_API_TOKEN=example\n')
            self.assertEqual(controller.read_env(path)["CF_AUTO_APPLY"], "false")

    def test_compose_snapshot_needs_sources(self):
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as out:
            with patch.object(controller, "SOURCE", Path(folder)):
                with self.assertRaises(RuntimeError):
                    controller.snapshot(Path(out))


if __name__ == "__main__":
    unittest.main()
