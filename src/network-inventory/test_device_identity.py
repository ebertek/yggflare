"""Conservative vendor-neutral identity correlation and history regression tests."""

import unittest

from device_identity import update_history


def host(mac=""):
    return {"mac": mac, "ports": []}


def record(ip, mac, source="ARP reply"):
    return {"ip": ip, "interface": "eth0", "source": source, "detail": mac}


class IdentityHistoryTests(unittest.TestCase):
    def test_declared_mac_follows_new_address_without_merging_by_ip(self):
        inventory = {
            "10.4.20.10": {
                "name": "server.example",
                "mac": "aa:bb:cc:dd:ee:ff",
                "allowed_macs": {"aa:bb:cc:dd:ee:ff"},
                "ports": set(),
            }
        }
        first = update_history(
            inventory,
            {"10.4.20.10": host("aa:bb:cc:dd:ee:ff")},
            {},
            [],
            {},
            "2026-11-01T10:00:00Z",
            set(),
        )
        identity = first["identity_history"]["inventory:server.example"]
        self.assertEqual(identity["confidence"], "high")
        self.assertEqual(identity["seen_scans"], 1)
        second = update_history(
            inventory,
            {"10.4.20.20": host("aa:bb:cc:dd:ee:ff")},
            {},
            [],
            first,
            "2026-11-02T10:00:00Z",
            set(),
        )
        identity = second["identity_history"]["inventory:server.example"]
        self.assertEqual(identity["addresses"], ["10.4.20.10", "10.4.20.20"])
        self.assertEqual(identity["current_addresses"], ["10.4.20.20"])
        self.assertEqual(identity["seen_scans"], 2)
        self.assertEqual(identity["status"], "observed")
        self.assertEqual(identity["first_seen"], "2026-11-01T10:00:00Z")
        self.assertEqual(identity["last_seen"], "2026-11-02T10:00:00Z")
        self.assertTrue(
            any(
                item["kind"] == "new-address" and "10.4.20.20" in item["description"]
                for item in second["identity_changes"]
            )
        )

    def test_competing_link_macs_are_conflicts_not_silent_merges(self):
        inventory = {
            "10.4.20.1": {
                "name": "router.example",
                "mac": "aa:aa:aa:aa:aa:aa",
                "allowed_macs": {"aa:aa:aa:aa:aa:aa"},
            }
        }
        result = update_history(
            inventory,
            {"10.4.20.1": host("aa:aa:aa:aa:aa:aa")},
            {
                "records": [
                    record("10.4.20.1", "bb:bb:bb:bb:bb:bb"),
                    record("10.4.20.1", "aa:aa:aa:aa:aa:aa"),
                ]
            },
            [],
            {},
            "2026-11-01T10:00:00Z",
            set(),
        )
        self.assertEqual(result["identity_history"], {})
        self.assertEqual(result["identity_conflicts"][0]["address"], "10.4.20.1")
        self.assertEqual(len(result["identity_conflicts"][0]["macs"]), 2)
        self.assertTrue(
            any(item["kind"] == "conflict" for item in result["identity_changes"])
        )

    def test_unique_ip_only_identity_is_provisional_and_never_named_from_mdns(self):
        result = update_history(
            {},
            {"10.4.20.30": host()},
            {},
            [
                {
                    "host": "untrusted.local",
                    "service": "_example._tcp",
                    "addresses": ["10.4.20.30"],
                }
            ],
            {},
            "2026-11-01T10:00:00Z",
            set(),
        )
        entry = result["identity_history"]["address:10.4.20.30"]
        self.assertEqual(entry["confidence"], "low")
        self.assertEqual(entry["name_hints"], ["untrusted.local"])
        self.assertNotIn("untrusted.local", entry["label"])

    def test_unique_mac_combines_ipv4_ipv6_and_preserves_weak_os_estimate(self):
        records = [
            record("fd00::5", "02:22:33:44:55:66", "NDP reply"),
            {
                "ip": "fd00::5",
                "interface": "eth0",
                "source": "Nmap OS estimate",
                "detail": "Linux accuracy 85%",
            },
        ]
        result = update_history(
            {},
            {"10.4.20.5": host("02:22:33:44:55:66")},
            {"records": records},
            [],
            {},
            "2026-11-01T10:00:00Z",
            set(),
        )
        entry = result["identity_history"]["mac:02:22:33:44:55:66"]
        self.assertEqual(entry["confidence"], "medium")
        self.assertEqual(entry["addresses"], ["10.4.20.5", "fd00::5"])
        self.assertIn("Nmap OS estimate", entry["sources"])

    def test_shared_undocumented_mac_does_not_merge_two_ipv4_addresses(self):
        result = update_history(
            {},
            {
                "10.4.20.5": host("aa:aa:aa:aa:aa:aa"),
                "10.4.20.6": host("aa:aa:aa:aa:aa:aa"),
            },
            {},
            [],
            {},
            "2026-11-01T10:00:00Z",
            set(),
        )
        self.assertEqual(
            set(result["identity_history"]),
            {"address:10.4.20.5", "address:10.4.20.6"},
        )
        self.assertTrue(
            all(
                entry["confidence"] == "low"
                for entry in result["identity_history"].values()
            )
        )

    def test_not_observed_is_not_offline_and_history_is_retained(self):
        first = update_history(
            {},
            {"10.4.20.10": host("aa:bb:cc:dd:ee:ff")},
            {},
            [],
            {},
            "2026-11-01T10:00:00Z",
            set(),
        )
        second = update_history(
            {},
            {},
            {},
            [],
            first,
            "2026-11-02T10:00:00Z",
            set(),
        )
        entry = second["identity_history"]["mac:aa:bb:cc:dd:ee:ff"]
        self.assertEqual(entry["status"], "not observed")
        self.assertEqual(entry["missed_scans"], 1)
        self.assertEqual(entry["last_seen"], "2026-11-01T10:00:00Z")
        self.assertIn("mac:aa:bb:cc:dd:ee:ff", second["identity_history"])
        self.assertNotIn("offline", str(second).lower())
        third = update_history(
            {},
            {},
            {},
            [],
            second,
            "2026-11-03T10:00:00Z",
            set(),
        )
        changes = third["identity_changes"]
        notices = [item for item in changes if item["kind"] == "not-observed"]
        self.assertEqual(len(notices), 1)

    def test_ignored_docker_hosts_and_unverified_candidates_do_not_gain_identity(self):
        result = update_history(
            {},
            {"10.4.20.1": host("aa:bb:cc:dd:ee:ff")},
            {
                "records": [
                    {
                        "ip": "fd00::3",
                        "source": "Docker address",
                        "detail": "Docker address",
                    },
                    record("fd00::4", "aa:bb:cc:dd:ee:ff"),
                ]
            },
            [],
            {},
            "2026-11-01T10:00:00Z",
            {"10.4.20.1"},
        )
        self.assertEqual(
            result["identity_history"]["mac:aa:bb:cc:dd:ee:ff"]["addresses"],
            ["fd00::4"],
        )

    def test_mac_mismatch_between_inventory_and_observation_is_unresolved(self):
        inventory = {
            "10.4.20.1": {
                "name": "host-a.example",
                "mac": "aa:aa:aa:aa:aa:aa",
                "allowed_macs": {"aa:aa:aa:aa:aa:aa"},
            },
            "10.4.20.2": {
                "name": "host-b.example",
                "mac": "bb:bb:bb:bb:bb:bb",
                "allowed_macs": {"bb:bb:bb:bb:bb:bb"},
            },
        }
        result = update_history(
            inventory,
            {"10.4.20.1": host("bb:bb:bb:bb:bb:bb")},
            {},
            [],
            {},
            "2026-11-01T10:00:00Z",
            set(),
        )
        self.assertFalse(result["identity_history"])
        self.assertTrue(result["identity_conflicts"])


if __name__ == "__main__":
    unittest.main()
