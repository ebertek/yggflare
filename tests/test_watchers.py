"""Offline tests for reactive input notifications."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from watchers import Changes, enabled, event_reason, fingerprint, seconds


class FingerprintTests(unittest.TestCase):
    def test_compose_change_creation_and_deletion(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            source = base / "compose"
            config = base / "config"
            source.mkdir()
            config.mkdir()
            (source / "app").mkdir()
            compose = source / "app" / "compose.yaml"
            compose.write_text("services: {}\n", encoding="utf-8")
            (config / "static-hosts.json").write_text(
                '{"version":1,"hosts":[]}', encoding="utf-8"
            )
            original = fingerprint(source, config)
            (source / "README.md").write_text("not an input", encoding="utf-8")
            self.assertEqual(original, fingerprint(source, config))
            compose.write_text("services: {test: {}}\n", encoding="utf-8")
            modified = fingerprint(source, config)
            self.assertNotEqual(original, modified)
            retained = config / "retained-dns.json"
            retained.write_text("[]", encoding="utf-8")
            self.assertNotEqual(modified, fingerprint(source, config))
            retained.unlink()
            self.assertEqual(modified, fingerprint(source, config))
            compose.unlink()
            with self.assertRaises(FileNotFoundError):
                fingerprint(source, config)

    def test_private_inventory_update_detected(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "source"
            config = Path(folder) / "config"
            source.mkdir()
            config.mkdir()
            (source / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
            inventory = config / "static-hosts.json"
            inventory.write_text("{}", encoding="utf-8")
            original = fingerprint(source, config)
            inventory.write_text('{"hosts":[]}', encoding="utf-8")
            self.assertNotEqual(original, fingerprint(source, config))
            inventory.unlink()
            with self.assertRaises(FileNotFoundError):
                fingerprint(source, config)


class ChangeTests(unittest.TestCase):
    def test_debounce_and_cooldown(self):
        changes = Changes()
        changes.mark("compose_or_inventory", now=100.0)
        changes.mark("docker_topology", now=109.0)
        self.assertEqual(changes.take(debounce=20, now=128.0), [])
        self.assertEqual(changes.take(debounce=20, earliest=150, now=149), [])
        self.assertEqual(
            changes.take(debounce=20, earliest=150, now=150),
            ["compose_or_inventory", "docker_topology"],
        )
        self.assertEqual(changes.take(debounce=20, now=200), [])

    def test_scheduled_run_consumes_notifications(self):
        changes = Changes()
        changes.mark("docker_topology", now=10)
        self.assertEqual(changes.clear(), ["docker_topology"])
        self.assertEqual(changes.take(debounce=0, now=20), [])

    def test_filter_ignores_health_noise_and_self(self):
        event = {
            "Type": "container",
            "Action": "start",
            "Actor": {"Attributes": {"name": "frigate"}},
        }
        self.assertEqual(event_reason(event, "yggflare"), "docker_topology")
        event["Actor"]["Attributes"]["name"] = "yggflare"
        self.assertIsNone(event_reason(event, "yggflare"))
        event["Action"] = "health_status: healthy"
        self.assertIsNone(event_reason(event, "yggflare"))
        self.assertEqual(
            event_reason(
                {"Type": "network", "Action": "connect", "Actor": {"Attributes": {}}},
                "yggflare",
            ),
            "docker_topology",
        )
        self.assertIsNone(
            event_reason(
                {"Type": "network", "Action": "create", "Actor": {"Attributes": {}}},
                "yggflare",
            )
        )

    def test_invalid_configuration_fails_closed(self):
        with patch.dict("os.environ", {"YGG_WATCH_DOCKER": "sometimes"}):
            with self.assertRaises(ValueError):
                enabled("YGG_WATCH_DOCKER")
        with patch.dict("os.environ", {"YGG_WATCH_POLL_SECONDS": "1"}):
            with self.assertRaises(ValueError):
                seconds("YGG_WATCH_POLL_SECONDS", 15, 5, 300)


if __name__ == "__main__":
    unittest.main()
