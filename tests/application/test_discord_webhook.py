"""Regression tests for local, credential-safe Discord webhook validation."""

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from discord_webhook import read_webhook, validate_webhook_url
from doctor import discord_config_check

WEBHOOK_ID = "1234567890123456789"
WEBHOOK_TOKEN = "Test_token-0123456789_NOT_A_REAL_SECRET"
WEBHOOK = f"https://discord.com/api/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}"


class DiscordWebhookValidationTests(unittest.TestCase):
    def test_accepts_standard_webhook_and_trailing_secret_newline(self):
        self.assertEqual(validate_webhook_url(WEBHOOK), WEBHOOK)
        with TemporaryDirectory() as folder:
            secret = Path(folder) / "webhook"
            secret.write_text(WEBHOOK + "\n", encoding="utf-8")
            self.assertEqual(read_webhook(secret), WEBHOOK)

    def test_rejects_malformed_webhook_ids_without_revealing_credentials(self):
        for identifier in (
            "123456789012345678X",
            "123456789012345678９",
            "123",
            "not-a-webhook-id",
        ):
            with self.subTest(identifier=identifier):
                url = f"https://discord.com/api/webhooks/{identifier}/{WEBHOOK_TOKEN}"
                with self.assertRaisesRegex(ValueError, "ASCII digits") as error:
                    validate_webhook_url(url)
                self.assertNotIn(WEBHOOK_TOKEN, str(error.exception))
                self.assertNotIn(identifier, str(error.exception))

    def test_rejects_unexpected_hosts_paths_and_tokens(self):
        invalid = (
            WEBHOOK.replace("https://", "http://"),
            WEBHOOK.replace("discord.com", "example.com"),
            WEBHOOK.replace("discord.com", "discord.com.evil.example"),
            WEBHOOK.replace("/api/webhooks/", "/api/v1/webhooks/"),
            WEBHOOK + "/extra",
            WEBHOOK + "#fragment",
            f"https://discord.com/api/webhooks/{WEBHOOK_ID}/",
            f"https://discord.com/api/webhooks/{WEBHOOK_ID}/bad%2Ftoken",
        )
        for url in invalid:
            with self.subTest(case=url.split("/")[:3]):
                with self.assertRaises(ValueError) as raised:
                    validate_webhook_url(url)
                self.assertNotIn(WEBHOOK_TOKEN, str(raised.exception))
                self.assertNotIn(WEBHOOK_ID, str(raised.exception))
                self.assertNotIn(url, str(raised.exception))

    def test_doctor_validates_contents_without_network_access(self):
        with TemporaryDirectory() as folder:
            secret = Path(folder) / "webhook"
            with patch.dict(
                os.environ, {"YGGFLARE_NETWORK_DISCORD_WEBHOOK_FILE": str(secret)}
            ):
                self.assertFalse(discord_config_check()[0])
                secret.write_text(WEBHOOK.replace(WEBHOOK_ID, "broken-id"))
                ok, reason = discord_config_check()
                self.assertFalse(ok)
                self.assertIn("ASCII digits", reason)
                self.assertNotIn(WEBHOOK_TOKEN, reason)
                secret.write_text(WEBHOOK)
                self.assertEqual(discord_config_check(), (True, ""))

    def test_missing_or_empty_secret_has_safe_error(self):
        with TemporaryDirectory() as folder:
            secret = Path(folder) / "webhook"
            with self.assertRaisesRegex(ValueError, "missing or unreadable"):
                read_webhook(secret)
            secret.write_text("")
            with self.assertRaisesRegex(ValueError, "empty"):
                read_webhook(secret)


if __name__ == "__main__":
    unittest.main()
