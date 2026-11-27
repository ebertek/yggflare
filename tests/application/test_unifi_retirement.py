"""Offline retirement safeguards for previously verified automatic ownership."""

import ipaddress
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

import unifi_apply as apply
from unifi_dns import plan
from unifi_reconcile_plan import LiveInputs

ZONE = "example.invalid"
LAN = ipaddress.IPv4Network("192.168.10.0/24")
NAME = f"old.{ZONE}"
ADDRESS = "192.168.10.20"
POLICY = str(UUID(int=2))
OPERATION = {
    "operation": "create",
    "type": "A_RECORD",
    "domain": NAME,
    "ipv4Address": ADDRESS,
    "enabled": True,
    "ttlSeconds": 300,
}
ENTRY = {"operation": OPERATION, "policy_id": POLICY, "manual": False}
POLICY_ROW = {"id": POLICY, **{k: v for k, v in OPERATION.items() if k != "operation"}}
PROTECTED = (set(), set(), set())
NOW = 1_800_000_000
GRACE = 86400


def live(policies):
    records = (
        {
            "name": f"other.{ZONE}",
            "type": "A",
            "content": "192.168.10.50",
            "proxied": False,
        },
    )
    return LiveInputs(
        ("192.168.10.1", 443, "", "gateway.example.invalid"),
        str(UUID(int=1)),
        "fixture-read-key",
        "fixture-cloudflare-token",
        "fixture-target",
        apply.policy_fingerprint(policies),
        apply.fingerprint([records, policies]),
        plan(records, policies, ZONE, LAN),
        records,
    )


class UniFiRetirementTests(unittest.TestCase):
    def setUp(self):
        self.data = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.data / "unifi-ownership.json"
        self.before = live([POLICY_ROW])
        self.after = live([])
        self.ledger = apply.load_ledger(self.path, self.before.target)
        pilot = {
            "operation": {
                **OPERATION,
                "domain": f"pilot.{ZONE}",
                "ipv4Address": "192.168.10.21",
            },
            "policy_id": str(UUID(int=3)),
            "manual": True,
        }
        self.ledger["owned"] = [pilot, ENTRY]
        self.ledger["pilot_verified"] = True
        apply.write(self.path, self.ledger)
        self.enterContext(
            patch.dict(
                os.environ,
                {
                    "YGGFLARE_UNIFI_AUTO_APPLY": "true",
                    "YGGFLARE_UNIFI_AUTO_CLEANUP": "true",
                    "YGGFLARE_UNIFI_API_KEY_FILE": apply.UNIFI_KEY_FILE,
                    "YGGFLARE_UNIFI_DISCORD_NOTIFY": "false",
                },
            )
        )
        self.enterContext(
            patch.object(apply, "retirement_protected", return_value=PROTECTED)
        )
        self.enterContext(patch.object(apply.time, "time", return_value=NOW))

    def test_grace_resets_on_reappearance_gap_and_changed_ownership(self):
        rows, observations = apply.retirement_report(
            self.before, self.ledger, [POLICY_ROW], PROTECTED, {}, NOW, GRACE
        )
        self.assertEqual(rows[1]["status"], "grace_period")
        # Simulate the last successful observation within the allowed gap.
        observations[POLICY]["last"] = NOW + GRACE - 60
        rows, _ = apply.retirement_report(
            self.before,
            self.ledger,
            [POLICY_ROW],
            PROTECTED,
            observations,
            NOW + GRACE,
            GRACE,
        )
        self.assertEqual(rows[1]["status"], "eligible")
        rows, cleared = apply.retirement_report(
            self.before,
            self.ledger,
            [POLICY_ROW],
            ({NAME}, set(), set()),
            observations,
            NOW + GRACE,
            GRACE,
        )
        self.assertEqual(rows[1]["status"], "still_declared")
        self.assertEqual(cleared, {})
        rows, _ = apply.retirement_report(
            self.before,
            self.ledger,
            [POLICY_ROW],
            PROTECTED,
            observations,
            NOW + GRACE + 7201,
            GRACE,
        )
        self.assertEqual(rows[1]["status"], "grace_period")
        self.assertEqual(rows[0]["status"], "manual_protected")

    def test_protects_alias_address_conflicts_and_modified_policy(self):
        for protected in (
            ({NAME}, set(), set()),
            (set(), {ADDRESS}, set()),
            (set(), set(), {ZONE}),
        ):
            self.assertEqual(
                apply.retirement_candidate(ENTRY, self.before, [POLICY_ROW], protected),
                "still_declared",
            )
        modified = {**POLICY_ROW, "enabled": False}
        self.assertEqual(
            apply.retirement_candidate(ENTRY, self.before, [modified], PROTECTED),
            "modified_policy",
        )
        self.assertEqual(
            apply.retirement_candidate(ENTRY, self.after, [], PROTECTED),
            "missing_policy",
        )
        conflict = {**POLICY_ROW, "id": str(UUID(int=4)), "domain": f"alias.{ZONE}"}
        self.assertEqual(
            apply.retirement_candidate(
                ENTRY, self.before, [POLICY_ROW, conflict], PROTECTED
            ),
            "policy_conflict",
        )

    def seed_grace(self):
        apply.write(
            self.data / "unifi-retirement.json",
            {
                "version": 1,
                "target": self.before.target,
                "observations": {
                    POLICY: {
                        "identity": apply.fingerprint(ENTRY),
                        "first": NOW - GRACE,
                        "last": NOW - 60,
                    }
                },
            },
        )

    def test_delete_is_journaled_and_ownership_removed_only_after_absence(self):
        self.seed_grace()

        def delete(state, identifier):
            pending = apply.load_ledger(self.path, state.target)
            self.assertEqual(pending["owned"], self.ledger["owned"])
            self.assertIsNone(pending["pending"]["policy_id"])
            self.assertEqual(identifier, POLICY)

        with (
            patch.object(
                apply,
                "load_live",
                side_effect=[self.before, self.before, self.before, self.after],
            ),
            patch.object(apply, "all_rows", side_effect=[[POLICY_ROW]] * 4 + [[]]),
            patch.object(apply, "query", return_value=("nxdomain", [])),
            patch.object(apply, "delete_owned_policy", side_effect=delete) as remove,
        ):
            self.assertIn("Retired", apply.run(self.data, automatic=True))
            remove.assert_called_once()
        saved = apply.load_ledger(self.path, self.before.target)
        self.assertEqual(len(saved["owned"]), 1)
        self.assertTrue(saved["owned"][0]["manual"])
        self.assertIsNone(saved["pending"])

    def test_lost_acknowledgement_never_replays_delete(self):
        self.seed_grace()
        with (
            patch.object(apply, "load_live", return_value=self.before),
            patch.object(apply, "all_rows", return_value=[POLICY_ROW]),
            patch.object(apply, "query", return_value=("nxdomain", [])),
            patch.object(
                apply, "delete_owned_policy", side_effect=TimeoutError
            ) as remove,
        ):
            with self.assertRaises(TimeoutError):
                apply.run(self.data, automatic=True)
            with self.assertRaisesRegex(apply.ApplyError, "outcome is uncertain"):
                apply.run(self.data, automatic=True)
            remove.assert_called_once()
        self.assertEqual(
            apply.load_ledger(self.path, self.before.target)["owned"],
            self.ledger["owned"],
        )

    def test_acknowledged_delete_waits_for_dns_and_recovers_without_replay(self):
        self.seed_grace()
        with (
            patch.object(
                apply,
                "load_live",
                side_effect=[
                    self.before,
                    self.before,
                    self.before,
                    self.after,
                    self.after,
                ],
            ),
            patch.object(apply, "all_rows", side_effect=[[POLICY_ROW]] * 4 + [[], []]),
            patch.object(
                apply,
                "query",
                side_effect=[
                    ("answered", [ADDRESS]),
                    ("answered", [NAME + "."]),
                    ("answered", [ADDRESS]),
                    ("nxdomain", []),
                    ("nxdomain", []),
                    ("nxdomain", []),
                ],
            ),
            patch.object(apply, "delete_owned_policy") as remove,
        ):
            with self.assertRaises(apply.DNSVerificationPending):
                apply.run(self.data, automatic=True)
            self.assertEqual(
                apply.load_ledger(self.path, self.before.target)["owned"],
                self.ledger["owned"],
            )
            self.assertIn("Recovered", apply.run(self.data, automatic=True))
            remove.assert_called_once()

    def test_missing_source_and_invalid_grace_fail_closed(self):
        with (
            patch.object(apply, "all_rows", return_value=[POLICY_ROW]),
            patch.object(apply, "retirement_protected") as protection,
        ):
            protection.side_effect = apply.ApplyError("Missing source")
            with self.assertRaises(apply.ApplyError):
                apply.retirement_review(self.data, self.before, self.ledger)
        with patch.dict(os.environ, {"YGGFLARE_UNIFI_ORPHAN_GRACE_HOURS": "1"}):
            with self.assertRaises(apply.ApplyError):
                apply.retirement_grace()

    def test_delete_uses_documented_exact_id_and_status(self):
        with patch.object(apply, "connection") as connect:
            conn = connect.return_value
            conn.getresponse.return_value.status = 200
            apply.delete_owned_policy(self.before, POLICY)
            conn.request.assert_called_once_with(
                "DELETE",
                f"{apply.PREFIX}/sites/{self.before.site}/dns/policies/{POLICY}",
                headers={"Accept": "application/json", "X-API-Key": self.before.key},
            )
            conn.getresponse.return_value.status = 404
            with self.assertRaises(apply.ApplyError):
                apply.delete_owned_policy(self.before, POLICY)
