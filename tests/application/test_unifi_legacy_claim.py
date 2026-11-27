"""Legacy UniFi adoption writes ownership only and retains retirement safeguards."""

import copy
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

import unifi_apply as writer
import unifi_legacy_claim as legacy
from test_unifi_retirement import (
    ADDRESS,
    NAME,
    OPERATION,
    POLICY,
    POLICY_ROW,
    PROTECTED,
    live,
)


class LegacyUniFiTests(unittest.TestCase):
    def setUp(self):
        self.data = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.data / "unifi-ownership.json"
        self.policies = [copy.deepcopy(POLICY_ROW)]
        self.live = live(self.policies)
        self.ledger = writer.load_ledger(self.path, self.live.target)
        self.ledger["owned"] = [
            {
                "operation": {
                    **OPERATION,
                    "domain": "pilot.example.invalid",
                    "ipv4Address": "192.168.10.21",
                },
                "policy_id": str(UUID(int=3)),
                "manual": True,
            }
        ]
        self.ledger["pilot_verified"] = True
        writer.write(self.path, self.ledger)
        self.enterContext(
            patch.dict(
                os.environ,
                {
                    "YGGFLARE_UNIFI_API_KEY_FILE": writer.UNIFI_KEY_FILE,
                },
            )
        )
        self.enterContext(
            patch.object(legacy, "load_live", side_effect=lambda: self.live)
        )
        self.enterContext(
            patch.object(legacy, "all_rows", side_effect=lambda *args: self.policies)
        )
        self.protected = self.enterContext(
            patch.object(writer, "retirement_protected", return_value=PROTECTED)
        )
        self.absence = self.enterContext(patch.object(legacy, "legacy_absence"))
        self.query = self.enterContext(
            patch.object(
                writer,
                "query",
                side_effect=lambda gateway, name, kind: (
                    "answered",
                    [ADDRESS if kind == "A" else NAME + "."],
                ),
            )
        )
        self.delete = self.enterContext(patch.object(writer, "delete_owned_policy"))
        self.create = self.enterContext(patch.object(writer, "create_policy"))
        self.update = self.enterContext(patch.object(writer, "update_policy"))

    def test_plan_and_apply_only_grant_legacy_ownership(self):
        original = self.path.read_bytes()
        report = legacy.run(self.data, NAME)
        self.assertEqual(self.path.read_bytes(), original)
        writer.write(
            self.data / "unifi-retirement.json",
            {
                "version": 1,
                "target": self.live.target,
                "observations": {POLICY: {"identity": "a" * 64, "first": 1, "last": 2}},
            },
        )
        legacy.run(self.data, NAME, report["fingerprint"])
        saved = writer.load_ledger(self.path, self.live.target)
        self.assertTrue(saved["pilot_verified"])
        self.assertEqual(saved["owned"][0], self.ledger["owned"][0])
        entry = saved["owned"][1]
        self.assertEqual(entry, report["entry"])
        self.assertFalse(entry["manual"])
        self.assertEqual(
            writer.retirement_state(
                self.data / "unifi-retirement.json", self.live.target
            ),
            {},
        )
        self.assertEqual(
            writer.retirement_candidate(entry, self.live, self.policies, PROTECTED),
            "orphan",
        )
        self.delete.assert_not_called()
        self.create.assert_not_called()
        self.update.assert_not_called()
        with self.assertRaises(writer.ApplyError):
            legacy.run(self.data, NAME, report["fingerprint"])
        with self.assertRaisesRegex(writer.ApplyError, "cannot authorize repair"):
            writer.repair_review(self.live, saved, NAME, self.policies, set())

    def test_protected_name_missing_reply_and_pending_block(self):
        self.protected.return_value = ({NAME}, set(), set())
        with self.assertRaises(writer.ApplyError):
            legacy.run(self.data, NAME)
        self.protected.return_value = PROTECTED
        self.query.side_effect = None
        self.query.return_value = ("nxdomain", [])
        with self.assertRaisesRegex(writer.ApplyError, "A and PTR"):
            legacy.run(self.data, NAME)
        self.ledger["pending"] = {
            "operation": OPERATION,
            "policy_id": None,
            "manual": False,
        }
        writer.write(self.path, self.ledger)
        with self.assertRaisesRegex(writer.ApplyError, "pending"):
            legacy.run(self.data, NAME)

    def test_conflicts_and_modified_identity(self):
        report = legacy.run(self.data, NAME)
        entry = report["entry"]
        self.policies[0]["metadata"] = {"other": True}
        self.live = live(self.policies)
        with self.assertRaises(writer.ApplyError):
            legacy.run(self.data, NAME, report["fingerprint"])
        self.assertEqual(
            writer.retirement_candidate(entry, self.live, self.policies, PROTECTED),
            "modified_policy",
        )
        self.policies = [
            POLICY_ROW,
            {**POLICY_ROW, "id": str(UUID(int=4)), "domain": "alias.example.invalid"},
        ]
        self.live = live(self.policies)
        with self.assertRaises(writer.ApplyError):
            legacy.run(self.data, NAME)
        self.assertEqual(writer.load_ledger(self.path, self.live.target), self.ledger)

    def test_adopted_policy_uses_journaled_retirement_and_dns_absence(self):
        report = legacy.run(self.data, NAME)
        legacy.run(self.data, NAME, report["fingerprint"])
        entry = report["entry"]
        now = 1_800_000_000
        writer.write(
            self.data / "unifi-retirement.json",
            {
                "version": 1,
                "target": self.live.target,
                "observations": {
                    POLICY: {
                        "identity": writer.fingerprint(entry),
                        "first": now - 86400,
                        "last": now - 60,
                    }
                },
            },
        )

        def delete(_live, identifier):
            pending = writer.load_ledger(self.path, self.live.target)["pending"]
            self.assertEqual(identifier, POLICY)
            self.assertIsNone(pending["policy_id"])
            self.assertEqual(pending["repair"]["action"], writer.RETIRE_ACTION)
            self.policies = []
            self.live = live([])
            self.query.side_effect = None
            self.query.return_value = ("nxdomain", [])

        self.delete.side_effect = delete
        with (
            patch.dict(
                os.environ,
                {
                    "YGGFLARE_UNIFI_AUTO_APPLY": "true",
                    "YGGFLARE_UNIFI_AUTO_CLEANUP": "true",
                    "YGGFLARE_UNIFI_DISCORD_NOTIFY": "true",
                },
            ),
            patch.object(writer.time, "time", return_value=now),
            patch.object(writer, "load_live", side_effect=lambda: self.live),
            patch.object(writer, "all_rows", side_effect=lambda *args: self.policies),
            patch.object(writer, "discord_notice", return_value=True) as notice,
        ):
            self.assertIn("Retired", writer.run(self.data, automatic=True))
            notice.assert_called_once_with(OPERATION, writer.RETIRE_ACTION)
        saved = writer.load_ledger(self.path, self.live.target)
        self.assertIsNone(saved["pending"])
        self.assertEqual(saved["owned"], self.ledger["owned"])
        self.delete.assert_called_once()
        self.create.assert_not_called()
        self.update.assert_not_called()

    def test_dependency_reappearance_and_pilot_protection(self):
        report = legacy.run(self.data, NAME)
        self.absence.side_effect = writer.ApplyError("runtime dependency")
        with self.assertRaisesRegex(writer.ApplyError, "runtime"):
            legacy.run(self.data, NAME, report["fingerprint"])
        self.assertEqual(writer.load_ledger(self.path, self.live.target), self.ledger)
        self.ledger["owned"] = []
        self.ledger["pilot_verified"] = False
        writer.write(self.path, self.ledger)
        with self.assertRaisesRegex(writer.ApplyError, "pilot"):
            legacy.run(self.data, NAME)
