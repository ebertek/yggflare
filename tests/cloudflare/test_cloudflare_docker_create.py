"""Guarded Docker DNS creation and real quota capacity regressions."""

import ipaddress
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from cloudflare_api import CloudflareClient, CloudflareError
from cloudflare_dns_quota import capacity_sufficient, quota_status
from cloudflare_docker_dns import plan_docker_creates
from cloudflare_guarded import UnsafePlan, apply_actions, check_plan
from cloudflare_internal_ownership import (
    internal_scope,
    load_registry,
)
from cloudflare_write_api import CloudflareWriter

ZONE = "ygg.nu"
NETWORK = ipaddress.ip_network("10.4.21.0/24")
ZONE_ID = "b" * 32
ACTION = {
    "kind": "create_docker_dns_a",
    "hostname": "demo.ygg.nu",
    "content": "10.4.21.42",
}
SERVICE = {"Name": "stack/compose.yaml/demo", "IPv4Addresses": ["10.4.21.42"]}
RUNTIME = {"demo": "10.4.21.42"}
QUOTA = {"usage": 152, "limit": 200, "remaining": 48, "reserve": 10}


class DockerCreationTests(unittest.TestCase):
    def plan(self, services=None, running=None, records=(), protected=()):
        return plan_docker_creates(
            [SERVICE] if services is None else services,
            RUNTIME if running is None else running,
            records,
            ZONE,
            NETWORK,
            protected,
        )

    def test_only_agreeing_unique_sources(self):
        self.assertEqual(self.plan(), [ACTION])
        self.assertEqual(self.plan(running={}), [])
        self.assertEqual(self.plan(running={"demo": "10.4.21.43"}), [])
        self.assertEqual(self.plan(services=[SERVICE, SERVICE]), [])
        self.assertEqual(self.plan(running={**RUNTIME, "other": "10.4.21.42"}), [])
        self.assertEqual(self.plan(protected={"demo.ygg.nu"}), [])
        self.assertEqual(self.plan(protected={"10.4.21.42"}), [])

    def test_protect_existing_dns_and_aliases(self):
        for record in (
            {"name": "demo.ygg.nu", "type": "AAAA"},
            {"name": "demo.ygg.nu", "type": "CNAME"},
            {"name": "other.ygg.nu", "type": "A", "content": ACTION["content"]},
            {"name": "*.ygg.nu", "type": "A", "content": "10.4.21.5"},
        ):
            with self.subTest(record=record):
                self.assertEqual(self.plan(records=[record]), [])

    def test_quota_api_and_capacity(self):
        client = CloudflareClient("fake")
        with patch.object(
            client,
            "get",
            return_value={"result": {"record_usage": 152, "record_quota": 200}},
        ) as get:
            self.assertEqual(quota_status(client, ZONE_ID, 10), QUOTA)
        get.assert_called_once_with(f"/zones/{ZONE_ID}/dns_records/usage")
        self.assertTrue(capacity_sufficient(QUOTA, 38))
        self.assertFalse(capacity_sufficient(QUOTA, 39))
        self.assertFalse(capacity_sufficient(None, 1))
        with patch.object(client, "dns_usage", side_effect=CloudflareError("denied")):
            self.assertIsNone(quota_status(client, ZONE_ID, 10)["remaining"])
        with patch.object(
            client, "dns_usage", return_value={"record_usage": 10, "record_quota": None}
        ):
            self.assertIsNone(quota_status(client, ZONE_ID, 10)["remaining"])

    def report(self, quota=QUOTA):
        return {"actions": [ACTION], "blocked": [], "internal_dns_quota": quota}

    def test_unknown_or_full_quota_blocks_plan(self):
        for quota in (None, {**QUOTA, "remaining": 10}):
            with self.assertRaises(UnsafePlan):
                check_plan(self.report(quota))

    def test_writer_is_dns_only_and_scoped(self):
        client = CloudflareWriter("fake")
        with patch.object(client, "_write") as send:
            client.create_docker_a(ZONE_ID, ACTION["hostname"], ACTION["content"])
            send.assert_called_once_with(
                "POST",
                f"/zones/{ZONE_ID}/dns_records",
                {
                    "name": ACTION["hostname"],
                    "type": "A",
                    "content": ACTION["content"],
                    "ttl": 1,
                    "proxied": False,
                },
            )
            with self.assertRaises(ValueError):
                client.create_docker_a(ZONE_ID, "demo.example.net", ACTION["content"])
            with self.assertRaises(ValueError):
                client.create_docker_a(ZONE_ID, ACTION["hostname"], "8.8.8.8")

    def test_revalidate_and_verify_creation(self):
        client = Mock()
        client.dns_usage.return_value = {"record_usage": 152, "record_quota": 200}
        record = {
            "id": "c" * 32,
            "name": ACTION["hostname"],
            "type": "A",
            "content": ACTION["content"],
            "proxied": False,
        }
        client.list_dns.return_value = [record]
        client.create_docker_a.return_value = record
        client.get_dns_record.return_value = record
        fresh = Mock(return_value=[ACTION])
        with TemporaryDirectory() as folder:
            data = Path(folder)
            context = {"account": "a" * 32, "ygg": ZONE_ID}
            done = apply_actions(
                client,
                self.report(),
                context,
                docker_creates=fresh,
                ownership_data=data,
            )
            bound = internal_scope(context["account"], ZONE_ID, ZONE, NETWORK)
            ledger = load_registry(data, bound)
            self.assertEqual(list(ledger["records"]), [record["id"]])
            self.assertEqual(
                ledger["records"][record["id"]]["hostname"], ACTION["hostname"]
            )
            client.get_dns_record.assert_called_once_with(ZONE_ID, record["id"])
        self.assertEqual(
            done, [{"kind": ACTION["kind"], "hostname": ACTION["hostname"]}]
        )
        self.assertEqual(fresh.call_count, 2)
        self.assertEqual(client.dns_usage.call_count, 2)
        client.create_docker_a.assert_called_once_with(
            ZONE_ID, ACTION["hostname"], ACTION["content"]
        )

    def test_missing_ownership_storage_blocks_creation(self):
        client = Mock()
        client.dns_usage.return_value = {"record_usage": 152, "record_quota": 200}
        with self.assertRaisesRegex(UnsafePlan, "ownership storage"):
            apply_actions(
                client, self.report(), {"ygg": ZONE_ID}, docker_creates=lambda: [ACTION]
            )
        client.create_docker_a.assert_not_called()

    def test_changed_evidence_or_capacity_stops_before_write(self):
        client = Mock()
        client.dns_usage.return_value = {"record_usage": 152, "record_quota": 200}
        with TemporaryDirectory() as folder:
            context = {"account": "a" * 32, "ygg": ZONE_ID}
            with self.assertRaisesRegex(UnsafePlan, "creation evidence changed"):
                apply_actions(
                    client,
                    self.report(),
                    context,
                    docker_creates=lambda: [],
                    ownership_data=Path(folder),
                )
            client.create_docker_a.assert_not_called()
            client.dns_usage.return_value = {"record_usage": 190, "record_quota": 200}
            with self.assertRaisesRegex(UnsafePlan, "quota changed"):
                apply_actions(
                    client,
                    self.report(),
                    context,
                    docker_creates=lambda: [ACTION],
                    ownership_data=Path(folder),
                )
            client.create_docker_a.assert_not_called()
