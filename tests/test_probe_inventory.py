"""Scoped probe configuration, independent check results and snapshot regressions."""

import json
import socket
import ssl
import tempfile
import unittest
from pathlib import Path
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

    def test_failed_collection_retains_last_good_and_invalidates_changed_config(self):
        self.config()
        probes.refresh(
            self.root,
            self.root,
            ENV,
            lambda target, check: {
                "target": target["target"],
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
