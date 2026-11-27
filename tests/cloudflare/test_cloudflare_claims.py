"""Bulk internal ownership is explicit, exact and idempotent."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock

from cloudflare_claims import claim_internal
from cloudflare_internal_ownership import STATIC_REGISTRY_FILE, internal_scope, load_registry

BOUND = internal_scope("a" * 32, "b" * 32, "example.net", "192.0.2.0/24")
HOST = "device.example.net"
ADDRESS = "192.0.2.42"
RECORD = {"id": "c" * 32, "name": HOST, "content": ADDRESS, "type": "A", "proxied": False}


class BulkClaimTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.data = Path(temporary.name)
        self.client = Mock()
        self.client.list_dns.return_value = [RECORD]
        self.client.get_dns_record.return_value = RECORD

    def claim(self):
        return claim_internal(self.client, self.data, BOUND, {HOST: ADDRESS}, filename=STATIC_REGISTRY_FILE)

    def test_claim_is_idempotent_and_separate(self):
        self.assertEqual(self.claim()[HOST], "claimed")
        self.assertEqual(self.claim()[HOST], "already owned")
        self.assertEqual(len(load_registry(self.data, BOUND, filename=STATIC_REGISTRY_FILE)["records"]), 1)
        self.assertEqual(load_registry(self.data, BOUND)["records"], {})
        self.client.get_dns_record.assert_called_once_with(BOUND["zone"], RECORD["id"])

    def test_duplicate_or_changed_records_are_not_claimed(self):
        self.client.list_dns.return_value = [RECORD, {**RECORD, "id": "d" * 32}]
        self.assertTrue(self.claim()[HOST].startswith("skipped"))
        self.client.list_dns.return_value = [RECORD]
        self.client.get_dns_record.return_value = {**RECORD, "proxied": True}
        self.assertTrue(self.claim()[HOST].startswith("skipped"))
        self.assertFalse((self.data / STATIC_REGISTRY_FILE).exists())
