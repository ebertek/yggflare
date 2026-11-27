"""Backups must be complete, private, and retain only recent snapshots."""

import gzip
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backup import create_snapshot, prune_snapshots, restore_test, verify_archive
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

    def test_restore_validates_internal_dns_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, data = root / "config", root / "data"
            config.mkdir()
            data.mkdir()
            (config / "static-hosts.json").write_text(
                json.dumps({"version": 1, "hosts": []})
            )
            path = data / "managed-internal-dns.json"
            record_id = "c" * 32
            document = {
                "version": 1,
                "scope": {
                    "account": "a" * 32,
                    "zone": "b" * 32,
                    "domain": "example.net",
                    "network": "192.0.2.0/24",
                },
                "records": {
                    record_id: {
                        "id": record_id,
                        "hostname": "demo.example.net",
                        "address": "192.0.2.42",
                        "fingerprint": "d" * 64,
                    }
                },
            }
            path.write_text(json.dumps(document))
            before = path.read_bytes()
            archive = create_snapshot(config, data, root / "backup")
            self.assertEqual(
                restore_test(archive, root / "scratch")["internal_dns_owned_count"], 1
            )
            self.assertEqual(path.read_bytes(), before)
            document["records"][record_id]["fingerprint"] = "invalid"
            path.write_text(json.dumps(document))
            archive = create_snapshot(config, data, root / "backup")
            with self.assertRaisesRegex(ValueError, "internal DNS ownership"):
                restore_test(archive, root / "scratch")

    def test_verification_bounds_and_checks_gzip_trailer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, data = root / "config", root / "data"
            config.mkdir()
            data.mkdir()
            (data / "state.json").write_text("{}")
            archive = create_snapshot(config, data, root / "backup")
            self.assertEqual(verify_archive(archive)["members"], 3)
            for name, value in (
                ("MAX_RESTORE_MEMBERS", 2),
                ("MAX_RESTORE_BYTES", 1),
                ("MAX_TAR_BYTES", 1),
            ):
                with self.subTest(limit=name), patch(f"backup.{name}", value):
                    with self.assertRaisesRegex(ValueError, "limit"):
                        verify_archive(archive)
            # Tar can end before gzip's CRC/trailer. Verify the whole stream.
            archive.write_bytes(archive.read_bytes()[:-4])
            with self.assertRaises((EOFError, gzip.BadGzipFile)):
                verify_archive(archive)

    def test_verification_rejects_noncanonical_and_conflicting_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "backup.tar.gz"
            for names in (
                ["data", "data//state.json"],
                ["data", "data/state", "data/state/child"],
                ["data", "data/state", "data/state"],
            ):
                with self.subTest(names=names):
                    with tarfile.open(archive, "w:gz") as target:
                        config = tarfile.TarInfo("config")
                        config.type = tarfile.DIRTYPE
                        target.addfile(config)
                        data = tarfile.TarInfo(names[0])
                        data.type = tarfile.DIRTYPE
                        target.addfile(data)
                        for name in names[1:]:
                            member = tarfile.TarInfo(name)
                            member.size = 1
                            target.addfile(member, io.BytesIO(b"x"))
                    with self.assertRaises(ValueError):
                        verify_archive(archive)

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
