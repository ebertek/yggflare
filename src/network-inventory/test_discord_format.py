"""Offline checks for readable Discord inventory embeds."""

import unittest

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
        self.assertEqual(len(embed["fields"]), 3)
        self.assertEqual(embed["fields"][0]["name"], "Devices")
        self.assertIn("tcp/4070", embed["fields"][1]["value"])
        self.assertIn("_remotepairing._tcp", embed["fields"][2]["value"])
        self.assertEqual(payload["allowed_mentions"], {"parse": []})

    def test_test_message_is_not_a_drift_alert(self):
        embed = render(["TEST ONLY: delivery"], test=True)["embeds"][0]
        self.assertIn("Delivery test", embed["title"])
        self.assertNotIn("inventory", embed["title"])

    def test_long_alerts_respect_discord_field_limits(self):
        payload = render(["NEW DEVICE " + ("x" * 950) for _ in range(35)])
        embed = payload["embeds"][0]
        self.assertLessEqual(len(embed["fields"]), 25)
        for field in embed["fields"]:
            self.assertLessEqual(len(field["value"]), 1024)


if __name__ == "__main__":
    unittest.main()
