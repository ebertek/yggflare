"""Retired unmanaged Docker A claims require exact operator approval."""

import contextlib
import copy
import io
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import Mock, patch

from cloudflare_internal_cleanup import load_state, save_state, scope_for
from cloudflare_internal_ownership import internal_scope, load_registry
from cloudflare_legacy_internal_claim import apply_claim, review_claim
from retirement_progress import reporting

BOUND = internal_scope("a" * 32, "b" * 32, "example.net", "192.0.2.0/24")
EXTERNAL = "e" * 32
HOST = "demo.example.net"
ADDRESS = "192.0.2.42"
IDENTIFIER = "c" * 32
RECORD = {
    "id": IDENTIFIER,
    "name": HOST,
    "type": "A",
    "content": ADDRESS,
    "proxied": False,
    "ttl": 1,
}
SETTINGS = {"internal_zone": "example.net"}
SCOPE = scope_for(BOUND, EXTERNAL)


def evidence(status="unmanaged", *, owned=None, count=1):
    return (
        {
            "rows": [
                {
                    "hostname": HOST,
                    "address": ADDRESS,
                    "record_id": IDENTIFIER,
                    "ownership": "unmanaged",
                    "status": status,
                }
            ],
            "selected_dns_record_count": count,
        },
        BOUND,
        EXTERNAL,
        {} if owned is None else owned,
    )


class LegacyInternalClaimTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.data = Path(folder.name)
        self.client = Mock()
        self.client.list_dns.return_value = [RECORD]
        self.client.get.return_value = {"result": RECORD}
        self.review = self.enterContext(
            patch(
                "cloudflare_legacy_internal_claim.fresh_review",
                return_value=evidence(),
            )
        )
        self.enterContext(
            patch(
                "cloudflare_legacy_internal_claim.write_lock", side_effect=nullcontext
            )
        )

    def plan(self):
        return review_claim(self.client, self.data, SETTINGS, HOST)

    def apply(self, token):
        return apply_claim(self.client, self.data, SETTINGS, HOST, token)

    def test_private_blocker_progress_is_safe_and_does_not_authorize(self):
        result = evidence("private_protected")
        result[0]["rows"][0]["private_blockers"] = [
            {"source": "retained_dns", "hostname": "ns.example.net", "match": "address"}
        ]
        self.review.return_value = result
        with (
            contextlib.redirect_stderr(io.StringIO()) as output,
            reporting(),
            self.assertRaises(ValueError),
        ):
            self.plan()
        self.assertIn(
            "retained_dns / ns.example.net (matching address)", output.getvalue()
        )
        self.assertEqual(load_registry(self.data, BOUND)["records"], {})
        self.client.delete_dns_record.assert_not_called()

    def test_preview_is_read_only_and_apply_only_grants_ownership(self):
        plan, token = self.plan()
        self.assertEqual(len(token), 16)
        self.assertEqual(list(self.data.iterdir()), [])
        self.assertEqual(self.plan(), (plan, token))
        entry = self.apply(token)
        self.assertEqual(entry, plan["entry"])
        self.assertEqual(
            load_registry(self.data, BOUND)["records"], {IDENTIFIER: entry}
        )
        self.client.delete_dns_record.assert_not_called()
        self.client.create_docker_a.assert_not_called()
        with self.assertRaises(ValueError):
            self.apply(token)

    def test_changed_attributes_or_approval_never_write(self):
        _, token = self.plan()
        changed = {**RECORD, "ttl": 300}
        self.client.list_dns.return_value = [changed]
        self.client.get.return_value = {"result": changed}
        with self.assertRaisesRegex(ValueError, "plan changed"):
            self.apply(token)
        self.assertEqual(load_registry(self.data, BOUND)["records"], {})
        with self.assertRaises(ValueError):
            self.apply("invalid")
        self.client.delete_dns_record.assert_not_called()

    def test_protected_or_duplicate_evidence_blocks(self):
        for status in (
            "still_declared",
            "runtime_present",
            "private_protected",
            "dependency_protected",
            "shared_address",
            "wildcard_protected",
            "record_conflict",
            "identity_changed",
        ):
            with self.subTest(status=status):
                self.review.return_value = evidence(status)
                with self.assertRaises(ValueError):
                    self.plan()
        self.review.return_value = evidence(count=2)
        with self.assertRaises(ValueError):
            self.plan()
        self.review.return_value = evidence()
        self.client.list_dns.return_value = [
            RECORD,
            {**RECORD, "id": "d" * 32, "name": "other.example.net"},
        ]
        with self.assertRaises(ValueError):
            self.plan()
        self.client.get.assert_not_called()

    def test_reappearance_and_cross_registry_conflict_block(self):
        self.review.side_effect = [evidence(), evidence("still_declared")]
        with self.assertRaises(ValueError):
            self.plan()
        self.review.side_effect = None
        entry = {
            "id": "d" * 32,
            "hostname": "other.example.net",
            "address": ADDRESS,
            "fingerprint": "f" * 64,
        }
        self.review.return_value = evidence(owned={"d" * 32: ("static", entry)})
        with self.assertRaisesRegex(ValueError, "existing ownership"):
            self.plan()

    def test_static_scope_and_changed_detail_block(self):
        result = evidence()
        result[0]["rows"][0]["address"] = "192.0.3.42"
        self.review.return_value = result
        with self.assertRaisesRegex(ValueError, "Docker allocation"):
            self.plan()
        self.review.return_value = evidence()
        self.client.get.return_value = {"result": {**RECORD, "proxied": True}}
        with self.assertRaisesRegex(ValueError, "detail identity"):
            self.plan()

    def test_pending_recovery_and_old_grace(self):
        plan, token = self.plan()
        entry = plan["entry"]
        state = load_state(self.data, SCOPE)
        state["pending"] = {"entry": entry, "phase": "intent"}
        save_state(self.data, state)
        with self.assertRaisesRegex(ValueError, "Pending"):
            self.apply(token)
        state["pending"] = None
        state["observations"] = {IDENTIFIER: {"entry": entry, "first": 1, "last": 2}}
        save_state(self.data, state)
        self.assertEqual(self.apply(token), entry)
        self.assertEqual(load_state(self.data, SCOPE)["observations"], {})
        self.client.delete_dns_record.assert_not_called()

    def test_detail_and_zone_changes_during_review(self):
        self.client.get.side_effect = [
            {"result": RECORD},
            {"result": {**RECORD, "ttl": 300}},
        ]
        with self.assertRaises(ValueError):
            self.plan()
        self.client.get.side_effect = None
        changed = list(copy.deepcopy(evidence()))
        changed[2] = "f" * 32
        self.review.side_effect = [evidence(), tuple(changed)]
        with self.assertRaisesRegex(ValueError, "evidence changed"):
            self.plan()
