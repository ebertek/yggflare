"""Offline tests for confirmed alerts while keeping all raw observations."""

import unittest
from unittest.mock import patch

from alert_policy import confirmation_scans, confirmed_alerts


class AlertPolicyTests(unittest.TestCase):
    def apply(
        self,
        events,
        reported,
        ads,
        previous,
        *,
        complete=True,
        threshold=2,
        baseline=False,
    ):
        return confirmed_alerts(
            events,
            reported,
            ads,
            previous,
            dns_sd_complete=complete,
            baseline=baseline,
            required=threshold,
        )

    def test_transient_tcp_port_requires_two_scans_and_alerts_only_once(self):
        key = "new-port:10.0.0.5:tcp/62078"
        message = "NEW PORT phone.example 10.0.0.5: tcp/62078"
        first, state, pending = self.apply(
            [message],
            {key: message},
            [],
            {"initialized": True, "alert_state": {}},
        )
        self.assertEqual(first, [])
        self.assertEqual(len(pending), 1)
        self.assertIn("1/2 scans", pending[0])
        second, state, pending = self.apply(
            [],
            {key: message},
            [],
            {"initialized": True, "alert_state": state},
        )
        self.assertEqual(second, [message])
        self.assertEqual(pending, [])
        third, state, _ = self.apply(
            [],
            {key: message},
            [],
            {"initialized": True, "alert_state": state},
        )
        self.assertEqual(third, [])
        _, cleared, _ = self.apply(
            [],
            {},
            [],
            {"initialized": True, "alert_state": state},
        )
        again, _, pending = self.apply(
            [message],
            {key: message},
            [],
            {"initialized": True, "alert_state": cleared},
        )
        self.assertEqual(again, [])
        self.assertEqual(len(pending), 1)

    def test_dns_sd_service_port_rotation_not_a_new_identity(self):
        first, state, pending = self.apply(
            ["NEW DNS-SD device.local|_hap._tcp|42963"],
            {},
            ["device.local|_hap._tcp|42963"],
            {"initialized": True, "alert_state": {}},
        )
        self.assertEqual(first, [])
        self.assertEqual(len(pending), 1)
        second, state, pending = self.apply(
            [],
            {},
            ["device.local|_hap._tcp|45857"],
            {"initialized": True, "alert_state": state},
        )
        self.assertEqual(second, ["NEW DNS-SD device.local|_hap._tcp|45857"])
        self.assertFalse(pending)
        third, _, _ = self.apply(
            [],
            {},
            ["device.local|_hap._tcp|50000"],
            {"initialized": True, "alert_state": state},
        )
        self.assertEqual(third, [])

    def test_missing_dns_sd_data_preserves_prior_candidates(self):
        first, state, _ = self.apply(
            [],
            {},
            ["printer.local|_ipp._tcp|631"],
            {"initialized": True, "alert_state": {}},
        )
        self.assertEqual(first, [])
        _, state, _ = self.apply(
            [],
            {},
            [],
            {"initialized": True, "alert_state": state},
            complete=False,
        )
        self.assertEqual(state["dns_counts"]["printer.local|_ipp._tcp"], 1)
        second, _, _ = self.apply(
            [],
            {},
            ["printer.local|_ipp._tcp|631"],
            {"initialized": True, "alert_state": state},
        )
        self.assertEqual(second, ["NEW DNS-SD printer.local|_ipp._tcp|631"])

    def test_legacy_dns_sd_migration_survives_first_failed_browse(self):
        previous = {
            "initialized": True,
            "advertisements": ["known.local|_ipp._tcp|631"],
        }
        _, state, _ = self.apply(
            [], {}, previous["advertisements"], previous, complete=False
        )
        self.assertEqual(state["dns_notified"], ["known.local|_ipp._tcp"])
        events, _, pending = self.apply(
            [],
            {},
            previous["advertisements"],
            {"initialized": True, "alert_state": state},
        )
        self.assertEqual(events, [])
        self.assertEqual(pending, [])

    def test_critical_identity_changes_are_immediate(self):
        message = "CHANGED MAC router.example 10.0.0.1: bad (expected good)"
        events, _, pending = self.apply(
            [message], {}, [], {"initialized": True, "alert_state": {}}
        )
        self.assertEqual(events, [message])
        self.assertEqual(pending, [])

    def test_baseline_and_legacy_migration_never_replay_known_ports(self):
        key = "new-port:10.0.0.5:tcp/443"
        message = "NEW PORT device 10.0.0.5: tcp/443"
        events, state, pending = self.apply(
            [message],
            {key: message},
            ["printer.local|_ipp._tcp|631"],
            {},
            baseline=True,
        )
        self.assertEqual(events, [message])
        self.assertEqual(pending, [])
        self.assertEqual(state["port_notified"], [key])
        self.assertEqual(state["dns_notified"], ["printer.local|_ipp._tcp"])
        events, state, pending = self.apply(
            [],
            {key: message},
            ["printer.local|_ipp._tcp|631"],
            {
                "initialized": True,
                "reported": {key: message},
                "advertisements": ["printer.local|_ipp._tcp|631"],
            },
        )
        self.assertEqual(events, [])
        self.assertEqual(pending, [])
        self.assertEqual(state["port_notified"], [key])
        self.assertEqual(state["dns_notified"], ["printer.local|_ipp._tcp"])

    def test_invalid_threshold_fails_closed(self):
        for value in ("0", "11", "oops"):
            with (
                patch.dict(
                    "os.environ",
                    {"YGGFLARE_NETWORK_ALERT_CONFIRM_SCANS": value},
                    clear=True,
                ),
                self.assertRaises(ValueError),
            ):
                confirmation_scans()
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(confirmation_scans(), 2)

    def test_single_confirmation_restores_immediate_notifications(self):
        key = "new-port:10.0.0.5:tcp/22"
        message = "NEW PORT server 10.0.0.5: tcp/22"
        events, state, _ = self.apply(
            [message],
            {key: message},
            ["device.local|_ssh._tcp|22"],
            {"initialized": True, "alert_state": {}},
            threshold=1,
        )
        self.assertEqual(
            events,
            [message, "NEW DNS-SD device.local|_ssh._tcp|22"],
        )
        self.assertIn(key, state["port_notified"])


if __name__ == "__main__":
    unittest.main()
