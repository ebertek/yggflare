"""Offline integration contracts and confidentiality tests."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import integration_inventory as adapter
from mcp_server import InventoryTools

ENV = {
    "YGGFLARE_LAN_CIDR": "192.168.1.0/24",
    "YGGFLARE_KOMODO_API_URL": "http://192.168.1.20:9120",
    "YGGFLARE_KOMODO_ALLOW_HTTP": "true",
    "YGGFLARE_KUMA_API_URL": "http://192.168.1.21:3001",
    "YGGFLARE_KUMA_ALLOW_HTTP": "true",
}

METRICS = """
# HELP monitor_status Monitor status
# TYPE monitor_status gauge
monitor_status{monitor_name="Demo",monitor_type="http",monitor_url="https://demo.invalid/private/SECRET?key=SECRET",monitor_hostname="",monitor_port=""} 1
monitor_status{monitor_name="Private",monitor_type="http",monitor_url="https://user:SECRET@other.invalid/path"} 0
"""


class IntegrationTests(unittest.TestCase):
    def test_scope_and_tls_opt_in(self):
        self.assertIsNone(adapter.settings("komodo", {}))
        self.assertEqual(
            adapter.settings("komodo", ENV), ("http", "192.168.1.20", 9120)
        )
        for changes in (
            {"YGGFLARE_KOMODO_ALLOW_HTTP": "false"},
            {"YGGFLARE_KOMODO_API_URL": "http://8.8.8.8"},
            {"YGGFLARE_KOMODO_API_URL": "http://192.168.1.20/path"},
            {"YGGFLARE_KOMODO_API_URL": "http://user:secret@192.168.1.20"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                adapter.settings("komodo", {**ENV, **changes})

    def test_komodo_projection(self):
        rows = adapter.komodo_rows(
            "stacks",
            [
                {
                    "name": "core",
                    "info": {
                        "server_name": "primary",
                        "state": "running",
                        "deployed_hash": "abcdef0",
                        "latest_hash": "abcdef1",
                        "repo_link": "SECRET",
                        "status": "SECRET",
                        "services": [
                            {
                                "service": "dns",
                                "image": "example/dns:2",
                                "update_available": True,
                                "environment": "SECRET",
                            }
                        ],
                    },
                }
            ],
        )
        stack = next(row for row in rows if row["kind"] == "stacks")
        self.assertEqual(stack["server"], "primary")
        self.assertFalse(stack["revision_match"])
        self.assertNotIn("SECRET", json.dumps(rows))

    def test_kuma_excludes_credentials_and_paths(self):
        rows = adapter.kuma_rows(METRICS)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["target_host"], "demo.invalid")
        self.assertEqual(rows[0]["target_port"], 443)
        self.assertEqual(rows[0]["status"], "up")
        self.assertIsNone(rows[1]["target_host"])
        self.assertNotIn("SECRET", json.dumps(rows))
        with self.assertRaises(ValueError):
            adapter.kuma_rows("# TYPE something gauge\nsomething 1")

    def test_kuma_live_style_metric_labels_are_projected(self):
        payload = (
            '# TYPE monitor_status gauge\n'
            'monitor_status{monitor_name="device",monitor_type="port",'
            'monitor_hostname="192.0.2.10",monitor_port="1080",'
            'monitor_url="https://"} 1\n'
            'monitor_status{monitor_name="worker",monitor_type="docker",'
            'monitor_hostname="null",monitor_port="null",monitor_url="https://"} 1\n'
        )
        port, docker = adapter.kuma_rows(payload)
        self.assertEqual(port["target_host"], "192.0.2.10")
        self.assertEqual(port["target_port"], 1080)
        self.assertEqual(port["target_scheme"], "tcp")
        self.assertIsNone(docker["target_host"])
        self.assertIsNone(docker["target_port"])
        self.assertIsNone(docker["target_scheme"])

    def test_kuma_monitor_type_ignores_unused_url(self):
        for kind, host, port, expected in (
            ("port", "192.0.2.10", "1080", ("192.0.2.10", 1080, "tcp")),
            ("port", "example.invalid", "53", ("example.invalid", 53, "tcp")),
            ("ping", "192.0.2.10", "443", ("192.0.2.10", None, None)),
            ("docker", "null", "null", (None, None, None)),
            ("group", "null", "null", (None, None, None)),
            ("push", "null", "null", (None, None, None)),
            ("port", "null", "443", (None, None, None)),
            ("http", "null", "null", (None, None, None)),
        ):
            with self.subTest(kind=kind, host=host):
                self.assertEqual(
                    adapter.target(
                        {
                            "monitor_type": kind,
                            "monitor_hostname": host,
                            "monitor_port": port,
                            "monitor_url": "https://",
                        }
                    ),
                    expected,
                )

    def test_fixed_requests_reject_redirects(self):
        with patch.object(adapter.http.client, "HTTPConnection") as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 302
            with self.assertRaises(ValueError):
                adapter.fetch(
                    "komodo",
                    adapter.settings("komodo", ENV),
                    ["key", "secret"],
                    "stacks",
                )
            args = connection.return_value.request.call_args
            self.assertEqual(args.args, ("POST", "/read/ListStacks"))
            self.assertEqual(args.kwargs["body"], b"{}")
            with self.assertRaises(ValueError):
                adapter.fetch(
                    "komodo",
                    adapter.settings("komodo", ENV),
                    ["key", "secret"],
                    "execute",
                )

    def test_failed_refresh_retains_snapshot_and_requires_private_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret = root / "kuma-api-key.txt"
            secret.write_text("sample-key")
            secret.chmod(0o644)
            with self.assertRaises(ValueError):
                adapter.credentials("kuma", root)
            secret.chmod(0o600)
            adapter.refresh("kuma", root, ENV, root, lambda *_: METRICS)
            first = adapter.saved("kuma", root, ENV)
            self.assertTrue(first["fresh"])
            secret.unlink()
            with self.assertRaises(OSError):
                adapter.refresh("kuma", root, ENV, root, lambda *_: METRICS)
            after = adapter.saved("kuma", root, ENV)
            self.assertEqual(after["items"], first["items"])
            self.assertFalse(after["fresh"])
            self.assertFalse(
                adapter.saved(
                    "kuma",
                    root,
                    {**ENV, "YGGFLARE_KUMA_API_URL": "http://192.168.1.22:3001"},
                )["available"]
            )

    def test_compose_secrets_read_only_mounts_and_no_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            docker = root / "secrets"
            docker.mkdir()
            config = root / "config"
            config.mkdir()
            fallback = config / "kuma-api-key.txt"
            fallback.write_text("legacy-key")
            fallback.chmod(0o600)
            mounted = docker / "kuma_api_key"
            mounted.write_text("mounted-key\n")
            mounted.chmod(0o644)
            env = {**ENV, "YGGFLARE_KUMA_API_KEY_FILE": "/run/secrets/kuma_api_key"}
            with (
                patch.object(adapter, "DOCKER_SECRETS", docker),
                patch.object(
                    adapter.os,
                    "fstatvfs",
                    return_value=SimpleNamespace(f_flag=os.ST_RDONLY),
                ) as mount,
            ):
                self.assertEqual(
                    adapter.credentials("kuma", config, env=env), ["mounted-key"]
                )
                mount.return_value = SimpleNamespace(f_flag=0)
                with self.assertRaises(ValueError):
                    adapter.credentials("kuma", config, env=env)
                mount.return_value = SimpleNamespace(f_flag=os.ST_RDONLY)
                mounted.chmod(0o666)
                with self.assertRaises(ValueError):
                    adapter.credentials("kuma", config, env=env)
                mounted.unlink()
                with self.assertRaises(OSError):
                    adapter.credentials("kuma", config, env=env)
                mounted.symlink_to(fallback)
                with self.assertRaises(OSError):
                    adapter.credentials("kuma", config, env=env)
                with self.assertRaises(ValueError):
                    adapter.credentials(
                        "kuma",
                        config,
                        env={**env, "YGGFLARE_KUMA_API_KEY_FILE": "/etc/passwd"},
                    )
                self.assertEqual(
                    adapter.credentials("kuma", config, env={}), ["legacy-key"]
                )

    def test_compose_komodo_credentials_passed_only_to_collector(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            docker = root / "secrets"
            docker.mkdir()
            for filename in ("komodo_api_key", "komodo_api_secret"):
                path = docker / filename
                path.write_text("test-" + filename)
                path.chmod(0o444)
            env = {
                **ENV,
                "YGGFLARE_KOMODO_API_KEY_FILE": "/run/secrets/komodo_api_key",
                "YGGFLARE_KOMODO_API_SECRET_FILE": "/run/secrets/komodo_api_secret",
            }
            with (
                patch.object(adapter, "DOCKER_SECRETS", docker),
                patch.object(
                    adapter.os,
                    "fstatvfs",
                    return_value=SimpleNamespace(f_flag=os.ST_RDONLY),
                ),
                patch.object(adapter, "fetch") as unused,
            ):
                seen = []

                def request(adapter_name, origin, credentials, kind):
                    seen.append((adapter_name, kind, credentials))
                    return []

                result = adapter.refresh("komodo", root, env, root, request)
                self.assertEqual(len(seen), 3)
                self.assertEqual(
                    seen[0][2], ["test-komodo_api_key", "test-komodo_api_secret"]
                )
                self.assertNotIn("test-komodo_api", json.dumps(result))
                unused.assert_not_called()

    def test_coverage_caveat_and_unknown(self):
        tools = InventoryTools(
            lambda: {},
            lambda: {
                "items": [
                    {"project": "core", "service": "demo", "aliases": ["demo.invalid"]}
                ]
            },
        )
        with patch(
            "mcp_server.saved_integration",
            side_effect=lambda *_: {
                "available": True,
                "fresh": True,
                "items": adapter.kuma_rows(METRICS),
            },
        ):
            result = tools.get_monitoring_coverage()
            self.assertEqual(result["items"][0]["match_status"], "candidate_host_match")
            self.assertEqual(result["items"][0]["matching_monitor_count"], 1)
        with patch(
            "mcp_server.saved_integration",
            return_value={"available": False, "fresh": False, "items": []},
        ):
            result = tools.get_monitoring_coverage()
            self.assertIsNone(result["items"][0]["matching_monitor_count"])
            self.assertEqual(result["items"][0]["match_status"], "unknown")
