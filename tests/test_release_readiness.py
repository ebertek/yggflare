"""Offline release-readiness checks; never touch live backup/configuration."""

import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import backup_verify
from backup import create_snapshot, restore_test, verify_archive


class VerificationTests(unittest.TestCase):
    def test_snapshot_passes_and_does_not_extract(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for part in ("config", "data", "backup"):
                (root / part).mkdir()
            (root / "config/static-hosts.json").write_text("{}")
            (root / "data/state.json").write_text("{}")
            archive = create_snapshot(root / "config", root / "data", root / "backup")
            self.assertGreaterEqual(verify_archive(archive)["members"], 4)
            self.assertFalse((root / "config/config").exists())

    def test_isolated_restore_and_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ("config", "data", "backup", "scratch"):
                (root / name).mkdir()
            (root / "config/static-hosts.json").write_text(
                '{"version":1,"hosts":[{"hostname":"device.ygg.nu"}]}'
            )
            (root / "data/managed-hosts.json").write_text('{"version":1,"hosts":{}}')
            archive = create_snapshot(root / "config", root / "data", root / "backup")
            result = restore_test(archive, root / "scratch")
            self.assertEqual(result["inventory_hosts"], 1)
            self.assertEqual(list((root / "scratch").iterdir()), [])
            self.assertTrue((root / "config/static-hosts.json").exists())

    def test_restore_rejects_invalid_inventory_without_touching_live(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ("config", "data", "backup", "scratch"):
                (root / name).mkdir()
            (root / "config/static-hosts.json").write_text("not-json")
            archive = create_snapshot(root / "config", root / "data", root / "backup")
            with self.assertRaises(ValueError):
                restore_test(archive, root / "scratch")
            self.assertEqual(list((root / "scratch").iterdir()), [])

    def test_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bad.tar.gz"
            with tarfile.open(path, "w:gz") as out:
                item = tarfile.TarInfo("data/../../escape")
                item.size = 1
                out.addfile(item, io.BytesIO(b"x"))
            with self.assertRaises(ValueError):
                verify_archive(path)

    def test_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bad.tar.gz"
            with tarfile.open(path, "w:gz") as out:
                item = tarfile.TarInfo("config/ref")
                item.type = tarfile.SYMTYPE
                item.linkname = "/etc/passwd"
                out.addfile(item)
            with self.assertRaises(ValueError):
                verify_archive(path)

    def test_verifier_rejects_parent_path(self):
        with patch("sys.argv", ["backup_verify", "../other.tar.gz"]):
            with self.assertRaises(SystemExit):
                backup_verify.main()


if __name__ == "__main__":
    unittest.main()
