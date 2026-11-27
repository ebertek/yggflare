"""Shared configuration defaults and ownership identity regression tests."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import controller
import mcp_http
import probe_inventory
import unifi_apply
import unifi_reconcile_plan as reconcile
import watchers
from alert_policy import confirmation_scans
from cloudflare_credentials import api_token
from service_discovery import smb_settings
from yggflare_config import boolean, cloudflare_settings, domain, network
from yggflare_env import env_get, env_required, getenv

FIXTURE = {
    "CLOUDFLARE_ACCOUNT_ID": "a" * 32,
    "CLOUDFLARE_TUNNEL_NAME": "fixture",
    "YGGFLARE_INTERNAL_DOMAIN": "example.invalid",
    "YGGFLARE_EXTERNAL_DOMAIN": "public.invalid",
    "YGGFLARE_LAN_CIDR": "192.168.10.0/24",
    "YGGFLARE_UNIFI_API_URL": "https://192.168.10.1",
    "YGGFLARE_UNIFI_TLS_NAME": "gateway.example.invalid",
}
SITE = "00000000-0000-0000-0000-000000000001"
POLICY = "00000000-0000-0000-0000-000000000002"


class EnvironmentTests(unittest.TestCase):
    def test_literal_empty_uses_default_without_changing_environment(self):
        for default in (None, "", "false", "true", 0, 60):
            self.assertEqual(env_get({}, "setting", default), default)
            self.assertEqual(env_get({"setting": ""}, "setting", default), default)
        for value in ("false", "0", " ", "invalid"):
            self.assertEqual(env_get({"setting": value}, "setting", "default"), value)
        for env in ({}, {"required": ""}):
            with self.assertRaises(KeyError):
                env_required(env, "required")
        with patch.dict(os.environ, {"YGGFLARE_LOG_FORMAT": ""}, clear=True):
            self.assertEqual(getenv("YGGFLARE_LOG_FORMAT", "text"), "text")
            self.assertEqual(os.environ["YGGFLARE_LOG_FORMAT"], "")

    def test_mapping_based_settings_match_unset_defaults(self):
        blank = {
            "YGGFLARE_MCP_ENABLED": "",
            "YGGFLARE_MCP_BIND": "",
            "YGGFLARE_MCP_PORT": "",
            "YGGFLARE_MCP_ALLOWED_HOSTS": "",
            "YGGFLARE_MCP_TOKEN_FILE": "",
            "YGGFLARE_MCP_PRINCIPALS_FILE": "",
            "YGGFLARE_PROBES_ENABLED": "",
            "YGGFLARE_UNIFI_APPLY_INTERVAL_SECONDS": "",
            "YGGFLARE_DISCOVERY_MAX_TARGETS": "",
            "YGGFLARE_DISCOVERY_SMB_MAX_TARGETS": "",
            "YGGFLARE_DISCOVERY_SMB_WORKERS": "",
        }
        self.assertEqual(mcp_http.settings(blank), mcp_http.settings({}))
        self.assertFalse(mcp_http.enabled(blank))
        self.assertIsNone(probe_inventory.settings(Path("/nonexistent"), blank))
        self.assertEqual(controller.unifi_apply_interval(blank), 60)
        self.assertEqual(smb_settings(blank), smb_settings({}))
        with self.assertRaises(ValueError):
            mcp_http.settings({"YGGFLARE_MCP_PORT": " "})
        with self.assertRaises(ValueError):
            smb_settings({"YGGFLARE_DISCOVERY_SMB_WORKERS": "0"})

    def test_process_settings_match_unset_defaults(self):
        names = (
            "YGGFLARE_CLOUDFLARE_DNS_RESERVE",
            "CLOUDFLARE_STATIC_DNS_REQUIRED",
            "CLOUDFLARE_STATIC_DNS_SYNC",
            "CLOUDFLARE_DOCKER_DNS_SYNC",
            "CLOUDFLARE_INTERNAL_ZONE_ID",
            "CLOUDFLARE_EXTERNAL_ZONE_ID",
            "CLOUDFLARE_TUNNEL_ID",
            "YGGFLARE_UNIFI_AUTO_CLEANUP",
            "YGGFLARE_UNIFI_ORPHAN_GRACE_HOURS",
            "YGGFLARE_WATCH_COMPOSE",
            "YGGFLARE_WATCH_POLL_SECONDS",
            "YGGFLARE_NETWORK_ALERT_CONFIRM_SCANS",
            "CLOUDFLARE_API_TOKEN_FILE",
        )
        with patch.dict(os.environ, FIXTURE, clear=True):
            expected = cloudflare_settings()
            for extra in ({}, dict.fromkeys(names, "")):
                with patch.dict(os.environ, extra):
                    self.assertEqual(cloudflare_settings(), expected)
                    self.assertFalse(unifi_apply.retirement_enabled())
                    self.assertEqual(unifi_apply.retirement_grace(), 24 * 3600)
                    self.assertTrue(watchers.enabled("YGGFLARE_WATCH_COMPOSE"))
                    self.assertEqual(
                        watchers.seconds("YGGFLARE_WATCH_POLL_SECONDS", 15, 5, 300),
                        15,
                    )
                    self.assertEqual(confirmation_scans(), 2)
                    with patch("cloudflare_credentials.Path") as file_path:
                        file_path.return_value.read_text.return_value = "fixture-token"
                        self.assertEqual(api_token(), "fixture-token")
                        file_path.assert_called_once_with(
                            "/run/secrets/cloudflare_api_token"
                        )
            with patch.dict(os.environ, {"CLOUDFLARE_STATIC_DNS_REQUIRED": "yes"}):
                with self.assertRaises(ValueError):
                    boolean("CLOUDFLARE_STATIC_DNS_REQUIRED", True)
        for extra in ({}, {"YGGFLARE_LAN_CIDR": "", "YGGFLARE_INTERNAL_DOMAIN": ""}):
            with patch.dict(os.environ, extra, clear=True):
                with self.assertRaises(ValueError):
                    network("YGGFLARE_LAN_CIDR")
                with self.assertRaises(ValueError):
                    domain("YGGFLARE_INTERNAL_DOMAIN")

    def test_empty_zone_preserves_existing_ownership_and_plan_identity(self):
        with (
            tempfile.TemporaryDirectory() as folder,
            patch.dict(os.environ, FIXTURE, clear=True),
            patch.object(reconcile, "api_token", return_value="fixture-token"),
            patch.object(reconcile, "credentials", return_value=["fixture-key"]),
            patch.object(reconcile, "cloudflare_records", return_value=[]),
            patch.object(reconcile, "select_site", return_value=SITE),
            patch.object(reconcile, "all_rows", return_value=[]),
        ):
            original = reconcile.load_live()
            legacy_target = reconcile.fingerprint(
                {
                    "gateway": (
                        "192.168.10.1",
                        443,
                        "",
                        "gateway.example.invalid",
                    ),
                    "site": SITE,
                    "zone": "example.invalid",
                    "cloudflare_account": "a" * 32,
                    "cloudflare_zone": None,
                }
            )
            self.assertEqual(original.target, legacy_target)
            journal = Path(folder) / "unifi-ownership.json"
            ledger = {
                "version": 1,
                "target": legacy_target,
                "pilot_verified": True,
                "owned": [
                    {
                        "operation": {
                            "operation": "create",
                            "type": "A_RECORD",
                            "domain": "host.example.invalid",
                            "ipv4Address": "192.168.10.2",
                            "enabled": True,
                            "ttlSeconds": 300,
                        },
                        "policy_id": POLICY,
                        "manual": True,
                    }
                ],
                "pending": None,
            }
            journal.write_text(json.dumps(ledger))
            before = journal.read_bytes()
            with patch.dict(
                os.environ,
                {"CLOUDFLARE_INTERNAL_ZONE_ID": "", "YGGFLARE_UNIFI_SITE_ID": ""},
            ):
                blank = reconcile.load_live()
                self.assertEqual(blank.target, original.target)
                self.assertEqual(blank.inputs, original.inputs)
                self.assertEqual(unifi_apply.load_ledger(journal, blank.target), ledger)
            with patch.dict(os.environ, {"CLOUDFLARE_INTERNAL_ZONE_ID": "b" * 32}):
                changed = reconcile.load_live()
                self.assertNotEqual(changed.target, original.target)
                with self.assertRaises(unifi_apply.ApplyError):
                    unifi_apply.load_ledger(journal, changed.target)
            self.assertEqual(journal.read_bytes(), before)
