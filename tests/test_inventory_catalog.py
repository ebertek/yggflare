"""Planned/history records never become active inventory or expose raw fields."""

import unittest

from inventory_catalog import records


class CatalogTests(unittest.TestCase):
    def test_supported_shapes_numeric_order_and_allowlist(self):
        entries = [
            {"hostname": "later", "ipv4": "10.4.20.100", "token": "never-export"},
            {"name": "planned", "ipv4": "10.4.20.9"},
        ]
        for document in (entries, {"hosts": entries}, {"devices": entries}):
            result = records(document)
            self.assertEqual([r["ipv4"] for r in result], ["10.4.20.9", "10.4.20.100"])
            self.assertNotIn("never-export", str(result))

    def test_unsupported_schema_is_explicit(self):
        for document in ({"unrecognized": []}, [None], [{"aliases": "bad"}]):
            with self.assertRaises(ValueError):
                records(document)
