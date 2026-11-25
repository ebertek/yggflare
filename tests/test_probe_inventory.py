"""Scoped probe configuration, independent check results and snapshot regressions."""

import json
import os
import socket
import ssl
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import probe_inventory as probes

ENV = {"YGGFLARE_PROBES_ENABLED": "true", "YGGFLARE_LAN_CIDR": "192.168.1.0/24"}
TARGET = {
    "name": "demo",
    "hostname": "demo.invalid",
    "address": "192.168.1.20",
    "port": 443,
    "scheme": "https",
    "checks": ["dns", "tcp", "tls", "http"],
    "expected_statuses": [200, 302],
}


class ProbeTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)

    def config(self, target=TARGET):
        (self.root / "probes.json").write_text(
            json.dumps({"version": 1, "targets": [target]})
        )

    def test_scope_and_fixed_configuration(self):
        self.assertIsNone(probes.settings(self.root, {}))
        self.config()
        target = probes.settings(self.root, ENV)[0]
        self.assertEqual(target["address"], "192.168.1.20")
        for changes in (
            {"address": "8.8.8.8"},
            {"hostname": "bad\r\nHost: x"},
            {"path": "/private"},
            {"port": 0},
            {"checks": ["shell"]},
            {"scheme": "http"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.config({**TARGET, **changes})
                probes.settings(self.root, ENV)

    def test_docker_config_mount_is_explicit_and_read_only(self):
        self.config()
        mount = self.root / "mounted.json"
        mount.write_text(
            json.dumps(
                {"version": 1, "targets": [{**TARGET, "address": "192.168.1.21"}]}
            )
        )
        mount.chmod(0o644)
        env = {**ENV, "YGGFLARE_PROBES_CONFIG_FILE": "/yggflare-probes.json"}
        with (
            patch.object(probes, "CONFIG_MOUNT", mount),
            patch.object(
                probes.os, "fstatvfs", return_value=SimpleNamespace(f_flag=os.ST_RDONLY)
            ) as info,
        ):
            self.assertEqual(
                probes.settings(self.root, env)[0]["address"], "192.168.1.21"
            )
            info.return_value = SimpleNamespace(f_flag=0)
            with self.assertRaises(ValueError):
                probes.settings(self.root, env)
            info.return_value = SimpleNamespace(f_flag=os.ST_RDONLY)
            mount.chmod(0o666)
            with self.assertRaises(ValueError):
                probes.settings(self.root, env)
            mount.unlink()
            with self.assertRaises(OSError):
                probes.settings(self.root, env)
            mount.symlink_to(self.root / "probes.json")
            with self.assertRaises(OSError):
                probes.settings(self.root, env)
            with self.assertRaises(ValueError):
                probes.settings(
                    self.root, {**env, "YGGFLARE_PROBES_CONFIG_FILE": "/etc/passwd"}
                )
            self.assertEqual(
                probes.settings(self.root, ENV)[0]["address"], TARGET["address"]
            )

    def test_dns_and_tcp_are_separate(self):
        self.config()
        target = probes.settings(self.root, ENV)[0]
        with patch.object(
            probes.socket,
            "getaddrinfo",
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.21", 0))
            ],
        ):
            result = probes.probe(target, "dns")
            self.assertEqual(result["status"], "mismatch")
            self.assertFalse(result["expected_address_match"])
        with patch.object(probes.socket, "create_connection") as connect:
            result = probes.probe(target, "tcp")
            self.assertEqual(result["status"], "connected")
            connect.assert_called_once_with(("192.168.1.20", 443), timeout=3)

    def test_tls_invalid_and_http_head_no_redirect(self):
        self.config()
        target = probes.settings(self.root, ENV)[0]
        with (
            patch.object(probes, "connect"),
            patch.object(
                probes, "tls_socket", side_effect=ssl.SSLCertVerificationError("SECRET")
            ),
        ):
            result = probes.probe(target, "tls")
            self.assertFalse(result["tls_verified"])
            self.assertNotIn("SECRET", str(result))
        target["scheme"] = "http"
        with (
            patch.object(probes, "connect") as connect,
            patch.object(probes.http.client, "HTTPResponse") as response,
        ):
            response.return_value.status = 302
            result = probes.probe(target, "http")
            self.assertTrue(result["expected_status_match"])
            self.assertEqual(result["http_status"], 302)
            raw = connect.return_value.__enter__.return_value
            sent = raw.sendall.call_args.args[0]
            self.assertTrue(sent.startswith(b"HEAD / HTTP/1.1\r\n"))
            self.assertNotIn(b"Authorization", sent)
            response.return_value.close.assert_called_once()
            connect.assert_called_once()

    def test_probe_coverage_separates_plan_results_and_expected_status(self):
        from evidence_summary import probe_coverage

        self.config()
        planned = probes.saved(self.root, self.root, ENV)
        self.assertFalse(planned["available"])
        self.assertEqual(len(planned["configured_checks"]), 4)
        self.assertIsNone(
            probe_coverage(planned["configured_checks"], [], False, False)[
                "passed_checks"
            ]
        )
        outcomes = {
            "dns": {"status": "matched", "expected_address_match": True},
            "tcp": {"status": "connected"},
            "tls": {"status": "verified", "tls_verified": True},
            "http": {"status": "response_received", "expected_status_match": False},
        }
        probes.refresh(
            self.root,
            self.root,
            ENV,
            lambda target, check: {
                **{
                    key: target[key]
                    for key in ("target", "hostname", "address", "port", "scheme")
                },
                "check": check,
                **outcomes[check],
            },
        )
        snapshot = probes.saved(self.root, self.root, ENV)
        summary = probe_coverage(
            snapshot["configured_checks"], snapshot["items"], True, True
        )
        self.assertEqual(summary["passed_checks"], 3)
        self.assertEqual(summary["failed_checks"], 1)
        self.assertEqual(summary["configured_checks"], 4)
        document = json.loads((self.root / "probe-view.json").read_text())
        document["items"].pop()
        (self.root / "probe-view.json").write_text(json.dumps(document))
        self.assertFalse(probes.saved(self.root, self.root, ENV)["available"])

    def test_failed_collection_retains_last_good_and_invalidates_changed_config(self):
        self.config()
        probes.refresh(
            self.root,
            self.root,
            ENV,
            lambda target, check: {
                **{
                    key: target[key]
                    for key in ("target", "hostname", "address", "port", "scheme")
                },
                "check": check,
                "status": "check_failed",
            },
        )
        original = probes.saved(self.root, self.root, ENV)
        self.assertTrue(original["fresh"])
        self.assertEqual(len(original["items"]), 4)

        def fail(*args):
            raise ValueError("SECRET")

        with self.assertRaises(ValueError):
            probes.refresh(self.root, self.root, ENV, fail)
        after = probes.saved(self.root, self.root, ENV)
        self.assertEqual(after["items"], original["items"])
        self.assertFalse(after["fresh"])
        self.config({**TARGET, "address": "192.168.1.22"})
        self.assertFalse(probes.saved(self.root, self.root, ENV)["available"])
