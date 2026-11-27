"""Offline owned-policy repair and recovery checks."""

import ipaddress
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

import unifi_apply as apply
from unifi_dns import plan
from unifi_reconcile_plan import LiveInputs

NAME = "owned.example.invalid"
OLD = "192.168.10.20"
NEW = "192.168.10.21"
SITE = str(UUID(int=1))
POLICY = str(UUID(int=2))
RESTORED = str(UUID(int=3))
ZONE = "example.invalid"
LAN = ipaddress.IPv4Network("192.168.10.0/24")
OPERATION = {
    "operation": "create",
    "type": "A_RECORD",
    "domain": NAME,
    "ipv4Address": OLD,
    "enabled": True,
    "ttlSeconds": 300,
}


def policy(address, identifier=POLICY):
    return {
        **{key: value for key, value in OPERATION.items() if key != "operation"},
        "ipv4Address": address,
        "id": identifier,
    }


def live(address, policies):
    records = [{"name": NAME, "type": "A", "content": address, "proxied": False}]
    return LiveInputs(
        ("192.168.10.1", 443, "", "gateway.example.invalid"),
        SITE,
        "fixture-read-key",
        "fixture-cloudflare-token",
        "fixture-target",
        apply.policy_fingerprint(policies),
        apply.fingerprint([records, policies]),
        plan(records, policies, ZONE, LAN),
    )


class UniFiRepairTests(unittest.TestCase):
    def setUp(self):
        self.data = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.data / "unifi-ownership.json"
        self.before = live(NEW, [policy(OLD)])
        self.after = live(NEW, [policy(NEW)])
        self.ledger = apply.load_ledger(self.path, self.before.target)
        self.ledger["owned"] = [
            {"operation": OPERATION, "policy_id": POLICY, "manual": True}
        ]
        self.ledger["pilot_verified"] = True
        apply.write(self.path, self.ledger)
        self.enterContext(
            patch.dict(
                os.environ,
                {
                    "YGGFLARE_UNIFI_API_KEY_FILE": apply.UNIFI_KEY_FILE,
                    "YGGFLARE_UNIFI_AUTO_APPLY": "true",
                    "YGGFLARE_UNIFI_DISCORD_NOTIFY": "false",
                },
            )
        )
        self.enterContext(patch.object(apply, "DNS_VERIFICATION_ATTEMPTS", 1))
        self.targets = self.enterContext(
            patch.object(apply, "automatic_targets", return_value={(NAME, NEW)})
        )
        self.query = self.enterContext(
            patch.object(apply, "query", side_effect=self.replies)
        )

    @staticmethod
    def replies(gateway, name, kind):
        if kind == "A":
            return "answered", [NEW]
        return "answered", [NAME + "."]

    def preview(self, state=None, policies=None):
        return apply.repair_review(
            state or self.before,
            self.ledger,
            NAME,
            [policy(OLD)] if policies is None else policies,
            self.targets.return_value,
        )

    def test_preview_requires_owned_exact_declaration_and_unchanged_policy(self):
        report = self.preview()
        self.assertEqual(report["action"], "update")
        self.assertEqual(report["operation"]["ipv4Address"], NEW)
        self.assertEqual(report["previous_policy_id"], POLICY)
        with self.assertRaisesRegex(apply.ApplyError, "previously verified"):
            apply.repair_review(
                self.before, {"owned": [], "pending": None}, NAME, [], set()
            )
        modified = [{**policy(OLD), "enabled": False}]
        with self.assertRaisesRegex(apply.ApplyError, "modified externally"):
            self.preview(live(NEW, modified), modified)
        replacement = [policy(NEW, RESTORED)]
        with self.assertRaisesRegex(apply.ApplyError, "conflict"):
            self.preview(live(NEW, replacement), replacement)
        self.targets.return_value = set()
        with self.assertRaisesRegex(apply.ApplyError, "undeclared"):
            self.preview()
        self.assertEqual(apply.load_ledger(self.path, self.before.target), self.ledger)

    def test_update_journals_before_put_and_replaces_only_after_verification(self):
        report = self.preview()

        def acknowledge(state, key, identifier, operation):
            journal = apply.load_ledger(self.path, state.target)
            self.assertEqual(journal["owned"], self.ledger["owned"])
            self.assertIsNone(journal["pending"]["policy_id"])
            self.assertEqual(identifier, POLICY)
            self.assertEqual(operation["ipv4Address"], NEW)
            return POLICY

        with (
            patch.object(
                apply, "load_live", side_effect=[self.before, self.before, self.after]
            ),
            patch.object(
                apply, "all_rows", side_effect=[[policy(OLD)]] * 3 + [[policy(NEW)]]
            ),
            patch.object(apply, "update_policy", side_effect=acknowledge) as put,
            patch.object(apply, "create_policy") as post,
        ):
            self.assertIn(
                "Repaired", apply.run_repair(self.data, NAME, report["fingerprint"])
            )
            put.assert_called_once()
            post.assert_not_called()
        journal = apply.load_ledger(self.path, self.before.target)
        self.assertIsNone(journal["pending"])
        self.assertEqual(journal["owned"][0]["operation"]["ipv4Address"], NEW)
        self.assertTrue(journal["pilot_verified"])

    def test_missing_policy_recreated_with_new_identity(self):
        before = live(NEW, [])
        after = live(NEW, [policy(NEW, RESTORED)])
        report = self.preview(before, [])
        self.assertEqual(report["action"], "recreate")
        with (
            patch.object(apply, "load_live", side_effect=[before, before, after]),
            patch.object(
                apply, "all_rows", side_effect=[[], [], [], [policy(NEW, RESTORED)]]
            ),
            patch.object(apply, "create_policy", return_value=RESTORED) as post,
            patch.object(apply, "update_policy") as put,
        ):
            apply.run_repair(self.data, NAME, report["fingerprint"])
            post.assert_called_once()
            put.assert_not_called()
        journal = apply.load_ledger(self.path, before.target)
        self.assertEqual(journal["owned"][0]["policy_id"], RESTORED)

    def test_lost_acknowledgement_blocks_automatic_and_manual_retries(self):
        report = self.preview()
        with (
            patch.object(apply, "load_live", return_value=self.before),
            patch.object(apply, "all_rows", return_value=[policy(OLD)]),
            patch.object(apply, "update_policy", side_effect=TimeoutError) as put,
            patch.object(apply, "create_policy") as post,
        ):
            with self.assertRaises(TimeoutError):
                apply.run_repair(self.data, NAME, report["fingerprint"])
            with self.assertRaisesRegex(apply.ApplyError, "outcome is uncertain"):
                apply.run(self.data, automatic=True)
            with self.assertRaisesRegex(apply.ApplyError, "outcome is uncertain"):
                apply.run_repair(self.data, NAME, report["fingerprint"])
            put.assert_called_once()
            post.assert_not_called()
        self.assertEqual(
            apply.load_ledger(self.path, self.before.target)["owned"],
            self.ledger["owned"],
        )

    def test_cached_old_a_recovers_without_second_put(self):
        report = self.preview()
        self.query.side_effect = [
            ("answered", [NEW]),
            ("answered", [NAME + "."]),
        ] * 2 + [
            ("answered", [OLD]),
            ("answered", [NAME + "."]),
            ("answered", [NEW]),
            ("answered", [NAME + "."]),
        ]
        with (
            patch.object(
                apply,
                "load_live",
                side_effect=[self.before, self.before, self.after, self.after],
            ),
            patch.object(
                apply, "all_rows", side_effect=[[policy(OLD)]] * 3 + [[policy(NEW)]] * 2
            ),
            patch.object(apply, "update_policy", return_value=POLICY) as put,
            patch.object(apply, "create_policy") as post,
        ):
            with self.assertRaises(apply.DNSVerificationPending):
                apply.run_repair(self.data, NAME, report["fingerprint"])
            self.assertEqual(
                apply.load_ledger(self.path, self.before.target)["owned"],
                self.ledger["owned"],
            )
            self.assertIn("Recovered", apply.run(self.data, automatic=True))
            put.assert_called_once()
            post.assert_not_called()

    def test_put_uses_exact_policy_id_and_requires_matching_acknowledgement(self):
        operation = {**OPERATION, "ipv4Address": NEW}
        with patch.object(apply, "connection") as connect:
            conn = connect.return_value
            response = conn.getresponse.return_value
            response.status = 200
            response.read.return_value = json.dumps(policy(NEW)).encode()
            self.assertEqual(
                apply.update_policy(self.before, self.before.key, POLICY, operation),
                POLICY,
            )
            args, kwargs = conn.request.call_args
            self.assertEqual(
                args, ("PUT", f"{apply.PREFIX}/sites/{SITE}/dns/policies/{POLICY}")
            )
            self.assertEqual(
                json.loads(kwargs["body"]),
                {k: v for k, v in operation.items() if k != "operation"},
            )
            response.read.return_value = json.dumps(policy(NEW, RESTORED)).encode()
            with self.assertRaises(apply.ApplyError):
                apply.update_policy(self.before, self.before.key, POLICY, operation)
