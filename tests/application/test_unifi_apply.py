"""Offline guards and journal recovery for UniFi create reconciliation."""

import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

import unifi_apply as apply
from unifi_reconcile_plan import TTL_SECONDS, LiveInputs

NAME = "pilot.example.invalid"
ADDRESS = "192.168.10.20"
FINGERPRINT = "a" * 64
SITE = str(UUID(int=1))
POLICY = str(UUID(int=2))
ENV = {"YGGFLARE_UNIFI_WRITE_API_KEY_FILE": apply.WRITE_KEY_FILE}
OPERATION = {
    "operation": "create",
    "type": "A_RECORD",
    "domain": NAME,
    "ipv4Address": ADDRESS,
    "enabled": True,
    "ttlSeconds": TTL_SECONDS,
}
RESPONSE = {
    "id": POLICY,
    **{key: value for key, value in OPERATION.items() if key != "operation"},
}
LIVE = LiveInputs(
    ("192.168.10.1", 443, "", "gateway.example.invalid"),
    SITE,
    "fixture-read-key",
    "fixture-cloudflare-token",
    "fixture-target",
    apply.policy_fingerprint([]),
    "fixture-state",
    {
        "rows": [{"hostname": NAME, "address": ADDRESS}],
        "source_zone": "example.invalid",
        "configured_lan": "192.168.10.0/24",
    },
)


class UniFiApplyTests(unittest.TestCase):
    def setUp(self):
        self.data = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.data / "unifi-ownership.json"
        self.enterContext(patch.dict(os.environ, ENV))
        self.load = self.enterContext(
            patch.object(apply, "load_live", return_value=LIVE)
        )
        self.review = self.enterContext(
            patch.object(
                apply,
                "review",
                return_value={"operations": [OPERATION], "fingerprint": FINGERPRINT},
            )
        )
        self.enterContext(
            patch.object(apply, "credentials", return_value=("fixture-write-key",))
        )
        self.enterContext(patch.object(apply, "select_site", return_value=SITE))
        self.policies = self.enterContext(
            patch.object(apply, "all_rows", side_effect=[[], [RESPONSE]])
        )
        self.query = self.enterContext(
            patch.object(
                apply,
                "query",
                side_effect=[("answered", [ADDRESS]), ("answered", [NAME + "."])],
            )
        )
        self.post = self.enterContext(
            patch.object(apply, "create_policy", side_effect=self.acknowledge)
        )

    def acknowledge(self, live, key, operation):
        self.assertEqual(live, LIVE)
        self.assertEqual(operation, OPERATION)
        journal = apply.load_ledger(self.path, LIVE.target)
        self.assertIsNone(journal["pending"]["policy_id"])
        self.assertEqual(journal["owned"], [])
        return POLICY

    def test_fresh_pilot_is_journaled_and_claimed_only_after_api_and_dns_match(self):
        self.assertIn("Created and verified", apply.run(self.data, NAME, FINGERPRINT))
        ledger = apply.load_ledger(self.path, LIVE.target)
        self.assertTrue(ledger["pilot_verified"])
        self.assertIsNone(ledger["pending"])
        self.assertEqual(ledger["owned"][0]["policy_id"], POLICY)
        self.assertNotIn("fixture-write-key", self.path.read_text())
        self.post.assert_called_once()

    def test_lost_create_acknowledgement_blocks_retries(self):
        self.post.side_effect = TimeoutError
        with self.assertRaises(TimeoutError):
            apply.run(self.data, NAME, FINGERPRINT)
        self.assertIsNone(
            apply.load_ledger(self.path, LIVE.target)["pending"]["policy_id"]
        )
        with self.assertRaisesRegex(apply.ApplyError, "outcome is uncertain"):
            apply.run(self.data, NAME, FINGERPRINT)
        self.post.assert_called_once()

    def test_recovery_requires_saved_policy_id_and_current_dns(self):
        self.query.side_effect = [
            ("nxdomain", []),
            ("answered", [ADDRESS]),
            ("answered", [NAME + "."]),
        ]
        self.policies.side_effect = [[], [RESPONSE], [RESPONSE]]
        with self.assertRaisesRegex(apply.ApplyError, "awaiting matching"):
            apply.run(self.data, NAME, FINGERPRINT)
        ledger = apply.load_ledger(self.path, LIVE.target)
        self.assertEqual(ledger["pending"]["policy_id"], POLICY)
        self.assertEqual(ledger["owned"], [])
        self.assertIn("Recovered", apply.run(self.data, NAME, FINGERPRINT))
        self.assertTrue(apply.load_ledger(self.path, LIVE.target)["pilot_verified"])
        self.post.assert_called_once()

    def test_stale_fingerprint_or_changed_live_inputs_block_create(self):
        with self.assertRaisesRegex(apply.ApplyError, "Live preview changed"):
            apply.run(self.data, NAME, "b" * 64)
        self.load.side_effect = [LIVE, replace(LIVE, inputs="changed")]
        with self.assertRaisesRegex(apply.ApplyError, "inputs changed"):
            apply.run(self.data, NAME, FINGERPRINT)
        self.assertFalse(self.path.exists())
        self.post.assert_not_called()

    def test_automatic_requires_explicit_scope_and_verified_manual_pilot(self):
        with patch.dict(os.environ, {"YGGFLARE_UNIFI_AUTO_APPLY": "false"}):
            with self.assertRaisesRegex(apply.ApplyError, "disabled"):
                apply.run(self.data, automatic=True)
        with patch.dict(
            os.environ,
            {
                "YGGFLARE_UNIFI_AUTO_APPLY": "true",
                "YGGFLARE_UNIFI_AUTO_HOSTS": NAME,
            },
        ):
            with self.assertRaisesRegex(apply.ApplyError, "manual pilot"):
                apply.run(self.data, automatic=True)
        self.post.assert_not_called()

    def test_automatic_creates_only_one_allowlisted_unowned_name(self):
        existing = {
            **OPERATION,
            "domain": "previous.example.invalid",
            "ipv4Address": "192.168.10.19",
        }
        other = {"hostname": "other.example.invalid", "address": "192.168.10.21"}
        live = replace(
            LIVE,
            comparison={
                **LIVE.comparison,
                "rows": [*LIVE.comparison["rows"], other],
            },
        )
        self.load.return_value = live
        ledger = apply.load_ledger(self.path, live.target)
        ledger["owned"].append(
            {
                "operation": existing,
                "policy_id": str(UUID(int=3)),
                "manual": True,
            }
        )
        ledger["pilot_verified"] = True
        apply.write(self.path, ledger)
        self.post.side_effect = None
        self.post.return_value = POLICY
        with patch.dict(
            os.environ,
            {
                "YGGFLARE_UNIFI_AUTO_APPLY": "true",
                "YGGFLARE_UNIFI_AUTO_HOSTS": NAME,
            },
        ):
            self.assertIn("Created and verified", apply.run(self.data, automatic=True))
        first_review = self.review.call_args_list[0].args[0]
        self.assertEqual(first_review.comparison["rows"], LIVE.comparison["rows"])
        self.post.assert_called_once()
        ledger = apply.load_ledger(self.path, live.target)
        self.assertEqual([entry["manual"] for entry in ledger["owned"]], [True, False])

    def test_concurrent_policy_conflict_blocks_ownership(self):
        conflict = {
            **RESPONSE,
            "id": str(UUID(int=3)),
            "domain": "other.example.invalid",
        }
        self.policies.side_effect = [[], [RESPONSE, conflict]]
        with self.assertRaisesRegex(apply.ApplyError, "conflicting policies"):
            apply.run(self.data, NAME, FINGERPRINT)
        ledger = apply.load_ledger(self.path, LIVE.target)
        self.assertEqual(ledger["pending"]["policy_id"], POLICY)
        self.assertEqual(ledger["owned"], [])
        self.post.assert_called_once()
        self.query.assert_not_called()

    def test_transport_sends_one_fixed_post_and_verifies_acknowledgement(self):
        with patch.object(apply, "connection") as connect:
            conn = connect.return_value
            response = conn.getresponse.return_value
            response.status = 201
            response.read.return_value = json.dumps(RESPONSE).encode()
            original_create = CREATE_POLICY
            self.assertEqual(
                original_create(LIVE, "fixture-write-key", OPERATION), POLICY
            )
            args, kwargs = conn.request.call_args
            self.assertEqual(
                args, ("POST", f"{apply.PREFIX}/sites/{SITE}/dns/policies")
            )
            self.assertEqual(
                json.loads(kwargs["body"]),
                {k: RESPONSE[k] for k in RESPONSE if k != "id"},
            )
            conn.request.assert_called_once()
            response.status = 302
            with self.assertRaises(ValueError):
                original_create(LIVE, "fixture-write-key", OPERATION)


CREATE_POLICY = apply.create_policy
