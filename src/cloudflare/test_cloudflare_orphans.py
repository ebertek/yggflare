"""Lifecycle ownership, orphan classification and explicit retirement tests."""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cloudflare_orphans import (
    OwnershipError,
    claim,
    load_registry,
    observe_orphans,
    registry_path,
    retire,
    review_orphan,
    scope,
    summarize,
)

HOST = "test.ebi.nu"
APP_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
DNS_ID = "b" * 32
TUNNEL = "cccccccc-cccc-cccc-cccc-cccccccccccc"
POLICY = "dddddddd-dddd-dddd-dddd-dddddddddddd"
BOUND = scope("a" * 32, "e" * 32, TUNNEL)
ROUTE = {"hostname": HOST, "service": "https://traefik.ygg.nu:443"}


class FakeCloudflare:
    """Minimal in-memory Cloudflare identity and delete API."""

    def __init__(self):
        self.events = []
        self.apps = [
            {
                "id": APP_ID,
                "domain": HOST,
                "name": "test",
                "type": "self_hosted",
                "policies": [{"id": POLICY, "precedence": 1}],
            }
        ]
        self.dns = [
            {
                "id": DNS_ID,
                "name": HOST,
                "type": "CNAME",
                "content": TUNNEL + ".cfargotunnel.com",
                "proxied": True,
            }
        ]
        self.config = {
            "ingress": [
                {"hostname": "unmanaged.ebi.nu", "service": "https://other:443"},
                copy.deepcopy(ROUTE),
                {"service": "http_status:404"},
            ],
            "warp-routing": {"enabled": False},
        }

    def list_policies(self, account):
        return [{"id": POLICY, "name": "allow", "decision": "allow"}]

    def list_applications(self, account):
        return copy.deepcopy(self.apps)

    def get_application(self, account, identifier):
        return next(copy.deepcopy(app) for app in self.apps if app["id"] == identifier)

    def list_dns(self, zone):
        return copy.deepcopy(self.dns)

    def tunnel_configuration(self, account, tunnel):
        return {"config": copy.deepcopy(self.config)}

    def get_dns_record(self, zone, identifier):
        return next(
            copy.deepcopy(record) for record in self.dns if record["id"] == identifier
        )

    def delete_dns_record(self, zone, identifier):
        self.events.append("delete_dns")
        self.dns = [item for item in self.dns if item["id"] != identifier]

    def put_tunnel_ingress(self, account, tunnel, config):
        self.events.append("remove_ingress")
        self.config = copy.deepcopy(config)

    def delete_access_app(self, account, identifier):
        self.events.append("delete_access")
        self.apps = [item for item in self.apps if item["id"] != identifier]


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.client = FakeCloudflare()

    def claim(self):
        with patch("cloudflare_orphans.desired_hosts", return_value={HOST: [POLICY]}):
            return claim(self.client, self.path, self.path, BOUND, HOST)

    def plan(self, desired=None):
        with patch(
            "cloudflare_orphans.desired_hosts",
            return_value={} if desired is None else desired,
        ):
            return review_orphan(self.client, self.path, self.path, BOUND, HOST)

    def retire(self, fingerprint):
        with (
            patch("cloudflare_orphans.desired_hosts", return_value={}),
            patch.object(Path, "home", return_value=self.path),
            patch("cloudflare_orphans.LIVE_SOURCE", self.path),
        ):
            return retire(self.client, self.path, self.path, BOUND, HOST, fingerprint)

    def test_grace_period_and_reappearance_reset(self):
        self.claim()
        start = 1700000000.0
        self.assertEqual(observe_orphans(self.path, BOUND, {}, start), [])
        self.assertEqual(observe_orphans(self.path, BOUND, {}, start + 6 * 3600), [])
        self.assertEqual(observe_orphans(self.path, BOUND, {}, start + 24 * 3600), [])
        # Missing observation cycles reset the timer.
        self.assertEqual(observe_orphans(self.path, BOUND, {}, start + 30 * 3600), [])
        self.assertEqual(
            observe_orphans(self.path, BOUND, {HOST: [POLICY]}, start + 31 * 3600),
            [],
        )
        self.assertEqual(observe_orphans(self.path, BOUND, {}, start + 32 * 3600), [])
        for hour in (38, 44, 50, 56):
            result = observe_orphans(self.path, BOUND, {}, start + hour * 3600)
        self.assertEqual(result, [HOST])

    def test_unmanaged_hosts_never_eligible(self):
        self.assertEqual(observe_orphans(self.path, BOUND, {}, 1700000000.0), [])

    def test_invalid_grace_period_is_rejected(self):
        for hours in (0, 1, 23, 721):
            with self.assertRaises(OwnershipError):
                observe_orphans(self.path, BOUND, {}, 1700000000.0, hours)

    def test_missing_registry_never_claims_existing_resources(self):
        registry = load_registry(self.path, BOUND)
        summary = summarize(
            registry,
            {},
            self.client.apps,
            self.client.dns,
            self.client.config,
        )
        self.assertEqual(summary["managed"], 0)
        self.assertEqual(summary["orphaned"], [])
        self.assertIn(HOST, summary["unmanaged"])
        with self.assertRaises(OwnershipError):
            self.plan()

    def test_claim_requires_declared_host(self):
        with patch("cloudflare_orphans.desired_hosts", return_value={}):
            with self.assertRaises(OwnershipError):
                claim(self.client, self.path, self.path, BOUND, HOST)
        self.assertEqual(load_registry(self.path, BOUND)["hosts"], {})

    def test_claim_fails_if_endpoint_incomplete_or_conflicting(self):
        self.client.dns[0]["proxied"] = False
        with self.assertRaises(OwnershipError):
            self.claim()
        self.client.dns[0]["proxied"] = True
        self.client.config["ingress"].insert(-1, copy.deepcopy(ROUTE))
        with self.assertRaises((ValueError, OwnershipError)):
            self.claim()
        self.assertEqual(load_registry(self.path, BOUND)["hosts"], {})

    def test_claim_persists_protected_identity(self):
        identity = self.claim()
        registry = load_registry(self.path, BOUND)
        self.assertEqual(registry["hosts"][HOST], identity)
        self.assertEqual(registry_path(self.path).stat().st_mode & 0o777, 0o600)
        summary = summarize(
            registry,
            {HOST: [POLICY]},
            self.client.apps,
            self.client.dns,
            self.client.config,
        )
        self.assertEqual(summary["managed"], 1)
        self.assertEqual(summary["orphaned"], [])
        summary = summarize(
            registry, {}, self.client.apps, self.client.dns, self.client.config
        )
        self.assertEqual(len(summary["orphaned"]), 1)
        self.assertNotIn(HOST, summary["unmanaged"])

    def test_retirement_requires_exact_plan_fingerprint(self):
        self.claim()
        plan, token = self.plan()
        self.assertEqual(
            plan["steps"],
            ["delete_dns_cname", "remove_tunnel_ingress", "delete_access_app"],
        )
        self.assertEqual(len(token), 16)
        with self.assertRaises(OwnershipError):
            self.retire("0" * 16)
        self.assertEqual(self.client.events, [])

    def test_retirement_removes_dns_then_tunnel_then_access(self):
        self.claim()
        _, token = self.plan()
        steps = self.retire(token)
        self.assertEqual(
            steps,
            ["delete_dns_cname", "remove_tunnel_ingress", "delete_access_app"],
        )
        self.assertEqual(
            self.client.events, ["delete_dns", "remove_ingress", "delete_access"]
        )
        self.assertEqual(self.client.config["warp-routing"], {"enabled": False})
        self.assertEqual(
            self.client.config["ingress"][0]["hostname"], "unmanaged.ebi.nu"
        )
        self.assertEqual(
            self.client.config["ingress"][-1]["service"], "http_status:404"
        )
        self.assertEqual(load_registry(self.path, BOUND)["hosts"], {})

    def test_refuse_cleanup_if_compose_reintroduces_host(self):
        self.claim()
        with patch("cloudflare_orphans.desired_hosts", return_value={HOST: [POLICY]}):
            with self.assertRaises(OwnershipError):
                review_orphan(self.client, self.path, self.path, BOUND, HOST)

    def test_dns_target_replaced_blocks_all_deletes(self):
        self.claim()
        self.client.dns[0]["content"] = "other.cfargotunnel.com"
        with self.assertRaises(OwnershipError):
            self.plan()
        self.assertEqual(self.client.events, [])

    def test_replacement_access_app_blocks_cleanup(self):
        self.claim()
        self.client.apps[0]["id"] = "ffffffff-ffff-ffff-ffff-ffffffffffff"
        with self.assertRaises(OwnershipError):
            self.plan()
        self.assertEqual(self.client.events, [])

    def test_partial_cleanup_replans_without_removing_access_early(self):
        self.claim()
        _, token = self.plan()
        original = self.client.put_tunnel_ingress

        def fail_once(account, tunnel, config):
            self.client.put_tunnel_ingress = original
            raise OSError("simulated tunnel API failure")

        self.client.put_tunnel_ingress = fail_once
        with self.assertRaises(OSError):
            self.retire(token)
        self.assertEqual(self.client.events, ["delete_dns"])
        self.assertEqual(len(self.client.apps), 1)
        self.assertIn(HOST, load_registry(self.path, BOUND)["hosts"])
        plan, updated_token = self.plan()
        self.assertEqual(plan["steps"], ["remove_tunnel_ingress", "delete_access_app"])
        self.assertNotEqual(token, updated_token)
        self.retire(updated_token)
        self.assertEqual(
            self.client.events, ["delete_dns", "remove_ingress", "delete_access"]
        )

    def test_live_source_reintroduction_blocks_retirement(self):
        """A snapshot approval cannot override reintroduction in live Compose."""
        self.claim()
        _, token = self.plan()
        with (
            patch.object(Path, "home", return_value=self.path),
            patch("cloudflare_orphans.LIVE_SOURCE", self.path),
            patch(
                "cloudflare_orphans.desired_hosts",
                side_effect=[{}, {HOST: [POLICY]}],
            ),
            self.assertRaises(OwnershipError),
        ):
            retire(self.client, self.path, self.path, BOUND, HOST, token)
        self.assertEqual(self.client.events, [])

    def test_registry_fails_closed_on_corruption_and_scope_change(self):
        self.claim()
        with self.assertRaises(OwnershipError):
            load_registry(self.path, scope("b" * 32, "e" * 32, TUNNEL))
        registry_path(self.path).write_text("not json", encoding="utf-8")
        with self.assertRaises(OwnershipError):
            self.plan()

    def test_symlinked_registry_refused(self):
        target = self.path / "target"
        target.write_text(json.dumps({"hosts": {}}), encoding="utf-8")
        registry_path(self.path).symlink_to(target)
        with self.assertRaises(OwnershipError):
            load_registry(self.path, BOUND)


if __name__ == "__main__":
    unittest.main()
