"""Read-only web presentation and inventory integration tests."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import web


class WebTests(unittest.TestCase):
    def test_inventory_groups_and_escapes_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "config"
            state = root / "data"
            (state / "network-inventory").mkdir(parents=True)
            config.mkdir()
            inventory = {"version": 1, "hosts": [{
                "hostname": "test.ygg.nu", "ipv4": "10.4.20.34",
                "mac": "aa:bb:cc:dd:ee:ff",
                "notes": "<script>alert(1)</script>",
                "ports": [{"protocol": "tcp", "port": 443}],
            }]}
            (config / "static-hosts.json").write_text(json.dumps(inventory))
            observed = {
                "scanned_at": "2026-11-02T18:00:00Z",
                "hosts": {"10.4.20.34": {
                    "mac": "aa:bb:cc:dd:ee:ff", "ports": ["tcp/443"]
                }},
                "advertisements": ["example.local|_http._tcp|80"],
            }
            (state / "network-inventory/state.json").write_text(json.dumps(observed))
            (state / "managed-hosts.json").write_text(
                '{"version":1,"hosts":{"test.ebi.nu":{}}}'
            )
            with patch.object(web, "CONFIG", config), patch.object(web, "DATA", state):
                data = web.model()
            self.assertEqual(data["hosts"][0]["subnet"], "10.4.20.32/27")
            self.assertEqual(data["hosts"][0]["status"], "seen")
            html = web.render("inventory", data)
            self.assertIn("10.4.20.32/27", html)
            self.assertIn("&lt;script&gt;", html)
            self.assertNotIn("<script>alert(1)</script>", html)
            self.assertIn("test.ebi.nu", web.render("cloudflare", data))

    def test_unknown_observed_host_is_visible(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "config"
            state = root / "data"
            (state / "network-inventory").mkdir(parents=True)
            config.mkdir()
            (config / "static-hosts.json").write_text('{"version":1,"hosts":[]}')
            observed = {
                "hosts": {"10.4.21.207": {"mac": "7e:92:e2:7a:5f:77", "ports": []}},
            }
            (state / "network-inventory/state.json").write_text(json.dumps(observed))
            with patch.object(web, "CONFIG", config), patch.object(web, "DATA", state):
                data = web.model()
            self.assertEqual(data["hosts"][0]["status"], "unmanaged")
            self.assertIn("10.4.21.192/27", web.render("inventory", data))


if __name__ == "__main__":
    unittest.main()
