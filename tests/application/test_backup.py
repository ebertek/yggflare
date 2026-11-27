"""Backups must be complete, private, and retain only recent snapshots."""

import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from backup import create_snapshot, prune_snapshots, restore_test
from job_status import archive_identity, backup_checks, record_backup_check


class BackupTests(unittest.TestCase):
    def test_backup_contains_configuration_and_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, data, backup = (
                root / item for item in ("config", "data", "backup")
            )
            config.mkdir()
            data.mkdir()
            (config / "cloudflare.env").write_text(
                "YGGFLARE_CLOUDFLARE_AUTO_APPLY=false\n"
            )
            (data / "state.json").write_text("{}")
            secrets = root / "secrets"
            secrets.mkdir()
            (secrets / "cloudflare_api_token").write_text("example-token")
            archive = create_snapshot(config, data, backup, secrets)
            self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
            with tarfile.open(archive, "r:gz") as content:
                self.assertIn("config/cloudflare.env", content.getnames())
                self.assertIn("data/state.json", content.getnames())
                self.assertIn("secrets/cloudflare_api_token", content.getnames())

    def test_verification_evidence_is_bound_to_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "yggflare-20260101T000000Z.tar.gz"
            archive.write_bytes(b"first")
            identity = archive_identity(archive)
            record_backup_check(root, archive, "integrity", identity, True)
            record_backup_check(root, archive, "restore", identity, False)
            checks = backup_checks(root, archive)
            self.assertTrue(checks["integrity"]["succeeded"])
            self.assertFalse(checks["restore"]["succeeded"])
            archive.write_bytes(b"replacement")
            self.assertEqual(backup_checks(root, archive), {})
            with self.assertRaises(ValueError):
                record_backup_check(root, archive, "integrity", identity, True)

    def test_restore_checks_unifi_ownership_without_live_access(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, data = root / "config", root / "data"
            config.mkdir()
            data.mkdir()
            (config / "static-hosts.json").write_text(
                json.dumps({"version": 1, "hosts": []})
            )
            path = data / "unifi-ownership.json"
            target = "a" * 64
            journal = {
                "version": 1,
                "target": target,
                "owned": [],
                "pending": None,
                "pilot_verified": False,
            }
            path.write_text(json.dumps(journal))
            (data / "unifi-retirement.json").write_text(
                json.dumps({"version": 1, "target": target, "observations": {}})
            )
            archive = create_snapshot(config, data, root / "backup")
            before = path.read_bytes()
            result = restore_test(archive, root / "scratch")
            self.assertTrue(result["unifi_ownership_present"])
            self.assertEqual(result["unifi_owned_count"], 0)
            self.assertFalse(result["unifi_pending_write"])
            self.assertEqual(path.read_bytes(), before)
            journal["pilot_verified"] = True
            path.write_text(json.dumps(journal))
            archive = create_snapshot(config, data, root / "backup")
            with self.assertRaisesRegex(ValueError, "Restored UniFi"):
                restore_test(archive, root / "scratch")

    def test_prune_removes_only_matching_old_archives(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for n in range(4):
                (root / f"yggflare-2026110{n}T040000Z.tar.gz").touch()
            unrelated = root / "unrelated.tar.gz"
            unrelated.touch()
            prune_snapshots(root, keep=2)
            self.assertEqual(len(list(root.glob("yggflare-*.tar.gz"))), 2)
            self.assertTrue(unrelated.exists())


if __name__ == "__main__":
    unittest.main()
