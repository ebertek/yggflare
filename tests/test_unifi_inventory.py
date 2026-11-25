"""Offline tests for fixed local UniFi GET collection and state."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import unifi_inventory as unifi

ENV = {
    "YGGFLARE_LAN_CIDR": "192.168.0.0/24",
    "YGGFLARE_UNIFI_API_URL": "https://192.168.0.1",
}
SITE = "00000000-0000-0000-0000-000000000001"


def fixture(config, key, kind, site, offset):
    rows = {
        "sites": [{"id": SITE, "name": "Home"}],
        "devices": [
            {
                "id": SITE,
                "name": "Gateway",
                "state": "ONLINE",
                "firmwareVersion": "1.2.3",
                "ipAddress": "192.168.0.1",
            }
        ],
        "clients": [
            {
                "id": SITE,
                "name": "Client",
                "macAddress": "00:11:22:33:44:55",
                "ipAddress": "192.168.0.2",
                "access": {"token": "SECRET"},
            }
        ],
        "networks": [
            {
                "id": SITE,
                "name": "LAN",
                "vlanId": 10,
                "enabled": True,
                "metadata": {"secret": "SECRET"},
            }
        ],
    }[kind]
    return {
        "data": rows,
        "count": len(rows),
        "offset": offset,
        "limit": 100,
        "totalCount": len(rows),
    }


class UniFiTests(unittest.TestCase):
    def test_config_scope(self):
        self.assertIsNone(unifi.settings({}))
        self.assertEqual(unifi.settings(ENV), ("192.168.0.1", 443, "", "192.168.0.1"))
        for url in (
            "http://192.168.0.1",
            "https://example.invalid",
            "https://8.8.8.8",
            "https://192.168.0.1/path",
            "https://user:pw@192.168.0.1",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                unifi.settings({**ENV, "YGGFLARE_UNIFI_API_URL": url})

    def test_projection_and_failed_refresh(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = unifi.settings(ENV)
            view = unifi.refresh(root, config, fixture, lambda: "SECRET")
            self.assertEqual(len(view["items"]), 3)
            self.assertNotIn("SECRET", json.dumps(view))
            self.assertNotIn(SITE, json.dumps(view))
            self.assertTrue(unifi.saved(root, ENV)["fresh"])

            def fail(*args):
                raise ValueError("SECRET")

            with self.assertRaises(ValueError):
                unifi.refresh(root, config, fail, lambda: "SECRET")
            self.assertEqual(unifi.saved(root, ENV)["items"], view["items"])
            self.assertFalse(unifi.saved(root, ENV)["fresh"])
            self.assertEqual(
                unifi.saved(
                    root, {**ENV, "YGGFLARE_UNIFI_API_URL": "https://192.168.0.2"}
                )["items"],
                [],
            )
            self.assertNotIn("SECRET", (root / "unifi-view-status.json").read_text())

    def test_incomplete_pagination(self):
        def incomplete(*args):
            return {"data": [], "offset": 0, "limit": 100, "count": 0, "totalCount": 1}

        with self.assertRaises(ValueError):
            unifi.collect(unifi.settings(ENV), "KEY", incomplete)

    def test_fixed_endpoint_and_tls_redirect_rejection(self):
        with (
            patch("unifi_inventory.socket.create_connection"),
            patch("unifi_inventory.ssl.create_default_context") as context,
            patch("unifi_inventory.http.client.HTTPConnection") as conn,
        ):
            conn.return_value.getresponse.return_value.status = 302
            with self.assertRaises(ValueError):
                unifi.get_page(unifi.settings(ENV), "KEY", "clients", SITE, 0)
            conn.return_value.request.assert_called_once_with(
                "GET",
                f"/proxy/network/integration/v1/sites/{SITE}/clients?offset=0&limit=100",
                headers={"Accept": "application/json", "X-API-Key": "KEY"},
            )
            context.return_value.wrap_socket.assert_called_once()
        with self.assertRaises(ValueError):
            unifi.get_page(unifi.settings(ENV), "KEY", "actions", SITE, 0)
