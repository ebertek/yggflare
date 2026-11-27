"""Legacy external ownership is scoped, exclusive and explicitly approved."""

import copy
import json
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

from cloudflare_legacy_external_claim import (
    apply_claim,
    protected_legacy_hosts,
    review_claim,
    verify_legacy,
)
from cloudflare_orphans import AUTO_STATE, OwnershipError, load_registry, retire, review_orphan
from test_cloudflare_orphans import APP_ID, BOUND, DNS_ID, HOST, TUNNEL, FakeCloudflare

INTERNAL = "f" * 32
SETTINGS = {
    "account_id": BOUND["account"],
    "external_zone": "ebi.nu",
    "internal_zone": "ygg.nu",
    "tunnel_id": TUNNEL,
}


class LegacyClient(FakeCloudflare):
    def zone_id(self, name, account):
        return BOUND["external_zone"] if name == "ebi.nu" else INTERNAL

    def list_dns(self, zone):
        return super().list_dns(zone) if zone == BOUND["external_zone"] else []

    def get(self, path):
        return {"result": self.get_dns_record(BOUND["external_zone"], path.split("/")[-1])}


class LegacyExternalTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.data = Path(folder.name)
        self.client = LegacyClient()
        self.absence = self.enterContext(
            patch("cloudflare_legacy_external_claim.read_fresh_absence")
        )
        self.enterContext(
            patch("cloudflare_legacy_external_claim.write_lock", side_effect=nullcontext)
        )
        self.enterContext(
            patch("cloudflare_legacy_external_claim.cloudflare_settings", return_value=SETTINGS)
        )

    def plan(self):
        return review_claim(self.client, self.data, SETTINGS, HOST)

    def apply(self, token):
        return apply_claim(self.client, self.data, SETTINGS, HOST, token)

    def test_preview_and_local_adoption_clear_only_target_grace(self):
        state = {
            "version": 1,
            "scope": BOUND,
            "missing": {HOST: {"first": "old"}, "other.ebi.nu": {"first": "keep"}},
        }
        path = self.data / AUTO_STATE
        path.write_text(json.dumps(state))
        plan, token = self.plan()
        self.assertEqual(len(token), 16)
        self.assertEqual(load_registry(self.data, BOUND)["hosts"], {})
        self.assertEqual(json.loads(path.read_text()), state)
        self.assertEqual(self.apply(token), plan["identity"])
        self.assertEqual(load_registry(self.data, BOUND)["hosts"], {HOST: plan["identity"]})
        self.assertEqual(json.loads(path.read_text())["missing"], {"other.ebi.nu": {"first": "keep"}})
        self.assertEqual(self.client.events, [])
        with self.assertRaises(OwnershipError):
            self.apply(token)

    def test_changed_fingerprint_and_source_never_adopt(self):
        _, token = self.plan()
        self.client.dns[0]["ttl"] = 300
        with self.assertRaisesRegex(OwnershipError, "plan changed"):
            self.apply(token)
        self.assertEqual(load_registry(self.data, BOUND)["hosts"], {})
        self.absence.side_effect = OwnershipError("still declared")
        with self.assertRaises(OwnershipError):
            self.plan()
        self.assertEqual(self.client.events, [])

    def test_incomplete_non_cname_and_multi_destination_block(self):
        original = copy.deepcopy(self.client.dns)
        self.client.dns = []
        with self.assertRaises(OwnershipError):
            self.plan()
        self.client.dns = [{**original[0], "type": "A", "content": "192.0.2.1"}]
        with self.assertRaises(OwnershipError):
            self.plan()
        self.client.dns = original
        self.client.apps[0]["destinations"] = [
            {"type": "public", "uri": HOST},
            {"type": "public", "uri": "other.ebi.nu"},
        ]
        with self.assertRaises(OwnershipError):
            self.plan()

    def test_dns_alias_wildcard_and_overlapping_app_block(self):
        for row in (
            {"name": "alias.ebi.nu", "type": "CNAME", "content": HOST},
            {"name": "*.ebi.nu", "type": "CNAME", "content": "other.example.net"},
            {"name": "path." + HOST, "type": "A", "content": "192.0.2.1"},
        ):
            with self.subTest(row=row):
                self.client.dns.append({**row, "id": "d" * 32})
                with self.assertRaises(OwnershipError):
                    self.plan()
                self.client.dns.pop()
        self.client.apps.append(
            {
                **self.client.apps[0],
                "id": "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
                "domain": "*.ebi.nu",
            }
        )
        with self.assertRaises(OwnershipError):
            self.plan()

    def test_retirement_rechecks_details_dependencies_and_order(self):
        _, token = self.plan()
        identity = self.apply(token)
        verify_legacy(self.client, BOUND, HOST, identity)
        self.client.apps[0]["name"] = "changed"
        self.assertEqual(protected_legacy_hosts(self.client, self.data, BOUND), {HOST})
        with self.assertRaises(OwnershipError):
            verify_legacy(self.client, BOUND, HOST, identity)
        self.client.apps[0]["name"] = "test"
        self.assertEqual(protected_legacy_hosts(self.client, self.data, BOUND), set())
        with self.assertRaisesRegex(OwnershipError, "ordering"):
            verify_legacy(self.client, BOUND, HOST, identity, dns_gone=True)
        with (
            patch("cloudflare_orphans.desired_hosts", return_value={}),
            patch.object(Path, "home", return_value=self.data),
            patch("cloudflare_orphans.LIVE_SOURCE", self.data),
        ):
            _, approval = review_orphan(self.client, self.data, self.data, BOUND, HOST)
            retire(self.client, self.data, self.data, BOUND, HOST, approval)
        self.assertEqual(self.client.events, ["delete_dns", "remove_ingress", "delete_access"])
        self.assertEqual(load_registry(self.data, BOUND)["hosts"], {})
        self.assertEqual(len(self.client.config["ingress"]), 2)

    def test_relocated_resource_id_is_not_absence(self):
        _, token = self.plan()
        identity = self.apply(token)
        self.client.dns[0]["name"] = "moved.ebi.nu"
        self.assertEqual(self.client.dns[0]["id"], DNS_ID)
        with self.assertRaisesRegex(OwnershipError, "moved"):
            verify_legacy(self.client, BOUND, HOST, identity)
        self.client.dns = []
        self.client.apps[0]["domain"] = "moved.ebi.nu"
        self.assertEqual(self.client.apps[0]["id"], APP_ID)
        with self.assertRaisesRegex(OwnershipError, "moved"):
            verify_legacy(self.client, BOUND, HOST, identity)
