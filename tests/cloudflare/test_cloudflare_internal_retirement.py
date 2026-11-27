"""Read-only retirement classification and evidence safety regressions."""

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from cloudflare_internal_ownership import detail_fingerprint, internal_scope
from cloudflare_internal_retirement import (
    compose_evidence,
    docker_containers,
    review,
    runtime_evidence,
)
from cloudflare_live_diff import DOCKER_NETWORK

BOUND = internal_scope("a" * 32, "b" * 32, "ygg.nu", DOCKER_NETWORK)
NAME = "demo.ygg.nu"
ADDRESS = "10.4.21.42"
RECORD = {
    "id": "c" * 32,
    "name": NAME,
    "content": ADDRESS,
    "type": "A",
    "proxied": False,
    "ttl": 1,
}
ENTRY = {
    "id": RECORD["id"],
    "hostname": NAME,
    "address": ADDRESS,
    "fingerprint": detail_fingerprint(RECORD),
}


class RetirementReviewTests(unittest.TestCase):
    def setUp(self):
        self.client = Mock()
        self.client.get.return_value = {"result": RECORD}
        self.evidence = {
            "compose": (set(), set(), []),
            "runtime": (set(), set()),
            "private": set(),
            "retained": [],
        }

    def check(self, records=None, owned=True, external=None, selector=None):
        result = review(
            self.client,
            BOUND,
            {RECORD["id"]: ("docker", ENTRY)} if owned else {},
            [RECORD] if records is None else records,
            [] if external is None else external,
            self.evidence,
            selector,
        )
        self.assertFalse(result["deletion_authorized"])
        return result

    def test_owned_orphan_is_review_only(self):
        self.assertEqual(self.check()["counts"], {"candidate_review_only": 1})
        self.client.get.assert_called_once_with(
            f"/zones/{BOUND['zone']}/dns_records/{RECORD['id']}"
        )
        self.client.delete_dns_record.assert_not_called()

    def test_unmanaged_never_becomes_owned(self):
        self.assertEqual(self.check(owned=False)["counts"], {"unmanaged": 1})
        self.client.get.assert_not_called()

    def test_protected_name_address_and_references(self):
        for key, value, expected in (
            ("compose", ({NAME}, set(), []), "still_declared"),
            ("compose", (set(), {ADDRESS}, []), "still_declared"),
            (
                "compose",
                (set(), set(), [f"https://{NAME}:443"]),
                "dependency_protected",
            ),
            (
                "compose",
                (set(), set(), [f'hostname: "{NAME}."']),
                "dependency_protected",
            ),
            ("runtime", ({NAME}, set()), "runtime_present"),
            ("runtime", (set(), {ADDRESS}), "runtime_present"),
            ("private", {ADDRESS}, "private_protected"),
            ("retained", [{"content": NAME}], "dependency_protected"),
        ):
            with self.subTest(key=key, expected=expected):
                before = copy.deepcopy(self.evidence)
                self.evidence[key] = value
                self.assertEqual(self.check()["counts"], {expected: 1})
                self.evidence = before
        self.client.get.assert_not_called()

    def test_selected_private_blocker_identifies_retained_shared_address(self):
        self.evidence["private"] = {ADDRESS}
        self.evidence["private_sources"] = [
            ("retained_dns", "ns.ygg.nu", ADDRESS),
            ("static_companion", "gateway.ygg.nu", ADDRESS),
            ("static_primary", "other.ygg.nu", "10.4.20.2"),
        ]
        report = self.check(owned=False, selector=NAME)
        row = report["rows"][0]
        self.assertEqual(row["status"], "private_protected")
        self.assertEqual(row["private_blocker_count"], 2)
        self.assertEqual(
            row["private_blockers"],
            [
                {"source": "retained_dns", "hostname": "ns.ygg.nu", "match": "address"},
                {
                    "source": "static_companion",
                    "hostname": "gateway.ygg.nu",
                    "match": "address",
                },
            ],
        )
        self.assertEqual(self.check(owned=False)["rows"], [])
        self.client.get.assert_not_called()

    def test_duplicate_shared_wildcard_and_external_alias_block(self):
        for row, expected in (
            ({**RECORD, "name": "other.ygg.nu"}, "shared_address"),
            ({**RECORD, "name": "*.ygg.nu"}, "wildcard_protected"),
            ({**RECORD, "content": "10.4.21.43"}, "record_conflict"),
        ):
            with self.subTest(expected=expected):
                self.assertEqual(
                    self.check(
                        records=[RECORD, {**row, "id": "d" * 32}],
                        selector=NAME,
                    )["counts"].get(expected),
                    1 if expected != "record_conflict" else 2,
                )
        alias = {
            "id": "d" * 32,
            "name": "alias.example.net",
            "type": "CNAME",
            "content": NAME + ".",
        }
        self.assertEqual(
            self.check(external=[alias])["counts"], {"dependency_protected": 1}
        )

    def test_missing_and_changed_record_not_candidates(self):
        self.assertEqual(self.check(records=[])["counts"], {"missing_record": 1})
        self.client.get.return_value = {"result": {**RECORD, "ttl": 300}}
        self.assertEqual(self.check()["counts"], {"identity_changed": 1})
        with self.assertRaises(ValueError):
            self.check(records=[RECORD, RECORD])

    def test_selector_does_not_invent_absence(self):
        report = self.check(selector="missing.ygg.nu")
        self.assertFalse(report["matching_rows"])
        self.assertEqual(report["rows"], [])
        self.assertEqual(report["selected_dns_record_count"], 0)
        unsupported = {
            "id": "d" * 32,
            "name": NAME,
            "type": "AAAA",
            "content": "2001:db8::1",
        }
        report = self.check(records=[unsupported], owned=False, selector=NAME)
        self.assertFalse(report["matching_rows"])
        self.assertEqual(report["selected_dns_record_count"], 1)

    def test_compose_protects_aliases_and_addressless_services(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "compose.yaml").write_text(
                "services:\n"
                "  demo:\n"
                "    image: example\n"
                "    networks:\n"
                "      lan:\n"
                "        aliases: [alias]\n",
                encoding="utf-8",
            )
            names, addresses, _ = compose_evidence(root, "ygg.nu")
            self.assertEqual(names, {NAME, "alias.ygg.nu"})
            self.assertEqual(addresses, set())

    def test_runtime_keeps_aliases_and_configured_addresses(self):
        names, addresses = runtime_evidence(
            [
                {
                    "Name": "/stack-demo-1",
                    "Config": {"Hostname": "demo", "Labels": {}},
                    "NetworkSettings": {
                        "Networks": {
                            "lan": {
                                "IPAddress": "",
                                "IPAMConfig": {"IPv4Address": ADDRESS},
                                "Aliases": ["alias"],
                            }
                        }
                    },
                }
            ],
            "ygg.nu",
        )
        self.assertIn(NAME, names)
        self.assertIn("alias.ygg.nu", names)
        self.assertIn(ADDRESS, addresses)

    def test_partial_docker_inventory_fails_closed(self):
        with patch(
            "cloudflare_internal_retirement.subprocess.check_output",
            side_effect=["a" * 64, "[]"],
        ):
            with self.assertRaisesRegex(ValueError, "Incomplete Docker"):
                docker_containers()
        with patch(
            "cloudflare_internal_retirement.subprocess.check_output",
            side_effect=["", "a" * 64],
        ):
            with self.assertRaisesRegex(ValueError, "inventory changed"):
                docker_containers()
