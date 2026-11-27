"""Internal DNS ownership records require a verified creation acknowledgement."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock

from cloudflare_internal_ownership import (
    REGISTRY_FILE,
    assert_available,
    detail_fingerprint,
    internal_scope,
    load_registry,
    record_creation,
)

BOUND = internal_scope("a" * 32, "b" * 32, "example.net", "192.0.2.0/24")
ACTION = {"hostname": "demo.example.net", "content": "192.0.2.42"}
RECORD = {
    "id": "c" * 32,
    "name": ACTION["hostname"],
    "content": ACTION["content"],
    "type": "A",
    "proxied": False,
    "ttl": 1,
    "comment": "private text must not be persisted",
}


class InternalOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.data = Path(self.temp.name)
        self.client = Mock()
        self.client.get_dns_record.return_value = RECORD

    def capture(self, acknowledged=RECORD, listed=RECORD):
        return record_creation(
            self.data, BOUND, ACTION, acknowledged, listed, self.client
        )

    def test_verified_creation_is_private_and_durable(self):
        self.assertEqual(load_registry(self.data, BOUND)["records"], {})
        entry = self.capture()
        path = self.data / REGISTRY_FILE
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(RECORD["comment"], path.read_text(encoding="utf-8"))
        self.assertEqual(load_registry(self.data)["records"], {RECORD["id"]: entry})
        self.assertEqual(entry["fingerprint"], detail_fingerprint(RECORD))
        self.assertNotEqual(
            entry["fingerprint"], detail_fingerprint({**RECORD, "ttl": 300})
        )
        with self.assertRaises(ValueError):
            assert_available(load_registry(self.data, BOUND), ACTION)

    def test_unacknowledged_or_conflicting_identity_never_grants_ownership(self):
        for acknowledged, listed in (
            (None, RECORD),
            ({**RECORD, "id": "d" * 32}, RECORD),
            (RECORD, {**RECORD, "proxied": True}),
        ):
            with self.subTest(acknowledged=acknowledged, listed=listed):
                with self.assertRaises(ValueError):
                    self.capture(acknowledged, listed)
                self.assertEqual(load_registry(self.data, BOUND)["records"], {})
        self.client.get_dns_record.assert_not_called()
        self.client.get_dns_record.return_value = {**RECORD, "content": "192.0.2.43"}
        with self.assertRaises(ValueError):
            self.capture()
        self.assertFalse((self.data / REGISTRY_FILE).exists())
        self.client.get_dns_record.return_value = {**RECORD, "ttl": 300}
        with self.assertRaisesRegex(ValueError, "attributes changed"):
            self.capture()
        self.assertFalse((self.data / REGISTRY_FILE).exists())

    def test_scope_and_existing_ownership_fail_closed(self):
        self.capture()
        before = (self.data / REGISTRY_FILE).read_bytes()
        with self.assertRaises(ValueError):
            self.capture()
        with self.assertRaises(ValueError):
            load_registry(self.data, {**BOUND, "zone": "d" * 32})
        self.assertEqual((self.data / REGISTRY_FILE).read_bytes(), before)

    def test_invalid_or_symlink_registry_is_not_empty_success(self):
        path = self.data / REGISTRY_FILE
        path.write_text("{}", encoding="utf-8")
        with self.assertRaises(ValueError):
            load_registry(self.data, BOUND)
        path.write_text(
            '{"version": 1, "version": 1, "scope": {}, "records": {}}',
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            load_registry(self.data, BOUND)
        path.unlink()
        target = self.data / "other.json"
        target.write_text(json.dumps({}), encoding="utf-8")
        path.symlink_to(target)
        with self.assertRaises(ValueError):
            load_registry(self.data, BOUND)
