"""Offline checks for readable Discord inventory embeds."""

import unittest

from discord_embed import text_units
from discord_format import render


class DiscordFormattingTests(unittest.TestCase):
    def test_groups_observations(self):
        payload = render(
            [
                "NEW PORT alexa-kitchen.ygg.nu 10.4.20.73: tcp/4070",
                "NEW DEVICE 10.4.21.207 MAC 7e:92:e2:7a:5f:77",
                "NEW DNS-SD Cassiopeia.local|_remotepairing._tcp|49152",
            ]
        )
        embed = payload["embeds"][0]
        self.assertEqual(embed["title"], "⚠️ Network inventory changes")
        self.assertEqual(embed["color"], 15105570)
        self.assertEqual(len(embed["fields"]), 3)
        self.assertEqual(embed["fields"][0]["name"], "Devices")
        self.assertIn("tcp/4070", embed["fields"][1]["value"])
        self.assertIn("_remotepairing._tcp", embed["fields"][2]["value"])
        self.assertEqual(payload["allowed_mentions"], {"parse": []})

    def test_test_message_is_not_a_drift_alert(self):
        embed = render(["TEST ONLY: delivery"], test=True)["embeds"][0]
        self.assertEqual(embed["title"], "✅ Delivery test")
        self.assertEqual(embed["color"], 3066993)
        self.assertNotIn("inventory", embed["title"])

    def test_long_alerts_respect_discord_field_limits(self):
        payload = render(["NEW DEVICE " + ("x" * 950) for _ in range(35)])
        embed = payload["embeds"][0]
        self.assertLessEqual(len(embed["fields"]), 25)
        for field in embed["fields"]:
            self.assertLessEqual(text_units(field["value"]), 1024)
        units = sum(
            text_units(field["name"]) + text_units(field["value"])
            for field in embed["fields"]
        )
        units += sum(
            text_units(value)
            for value in (embed["title"], embed["description"], embed["footer"]["text"])
        )
        self.assertLessEqual(units, 6000)
        shown = sum(field["value"].count("\n") + 1 for field in embed["fields"])
        self.assertIn(f"{35 - shown} additional observations", embed["footer"]["text"])

    def test_service_changes_use_info_style_and_preserve_confirmation(self):
        payload = render(
            ["NEW PORT host.example.invalid 192.168.1.2: tcp/443 (2/2 scans)"]
        )
        embed = payload["embeds"][0]
        self.assertEqual(embed["title"], "ℹ️ Network inventory changes")
        self.assertEqual(embed["color"], 3447003)
        self.assertIn("2/2 scans", embed["fields"][0]["value"])

    def test_observed_text_stays_inside_code_span(self):
        payload = render(["NEW DEVICE @everyone\n`unsafe`"])
        field = payload["embeds"][0]["fields"][0]["value"]
        self.assertEqual(field.count("`"), 2)
        self.assertNotIn("@everyone", field)
        self.assertNotIn("\n", field)


if __name__ == "__main__":
    unittest.main()
