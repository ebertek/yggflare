"""Offline regressions for the GET-only DNS migration preflight."""

import ipaddress
import unittest
from unittest.mock import patch

import unifi_dns

ZONE = "home.example.net"
LAN = ipaddress.ip_network("192.168.10.0/24")
SITE = "00000000-0000-0000-0000-000000000001"
ENV = {
    "YGGFLARE_UNIFI_API_URL": "https://192.168.10.1",
    "YGGFLARE_LAN_CIDR": str(LAN),
}


def record(name="plex", address="192.168.10.40", proxied=False):
    return {
        "name": name + "." + ZONE,
        "type": "A",
        "content": address,
        "proxied": proxied,
    }


def policy(name="plex", address="192.168.10.40", enabled=True):
    return {
        "domain": name + "." + ZONE,
        "type": "A_RECORD",
        "ipv4Address": address,
        "enabled": enabled,
    }


class UniFiDNSTests(unittest.TestCase):
    def status(self, records, policies=()):
        return unifi_dns.plan(records, policies, ZONE, LAN)["counts"]

    def test_candidate_and_matching_manual_record(self):
        self.assertEqual(self.status([record()]), {"candidate": 1})
        self.assertEqual(self.status([record()], [policy()]), {"matched": 1})

    def test_scope_and_proxy(self):
        self.assertEqual(self.status([record(address="8.8.8.8")]), {"out_of_scope": 1})
        self.assertEqual(self.status([record(proxied=True)]), {"proxied_or_unknown": 1})

    def test_all_rfc1918_ranges_are_reported_without_expanding_lan(self):
        records = [
            record("a", "10.1.2.3"),
            record("b", "172.16.0.1"),
            record("c", "172.31.255.254"),
            record("d", "192.168.10.40"),
            record("e", "192.168.50.40"),
        ]
        result = unifi_dns.plan(records, [], ZONE, LAN)
        self.assertEqual(result["counts"], {"candidate": 5})
        self.assertEqual(result["source_zone"], ZONE)
        self.assertEqual(result["configured_lan"], str(LAN))
        self.assertTrue(all(row["rfc1918"] for row in result["rows"]))
        self.assertEqual(sum(row["in_configured_lan"] for row in result["rows"]), 1)

    def test_special_use_addresses_are_not_rfc1918(self):
        for address in (
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "172.15.255.255",
            "172.32.0.1",
            "224.0.0.1",
            "0.0.0.0",
        ):
            with self.subTest(address=address):
                self.assertEqual(
                    self.status([record(address=address)]), {"out_of_scope": 1}
                )

    def test_configured_lan_boundary_is_not_candidate(self):
        for address in ("192.168.10.0", "192.168.10.255"):
            self.assertEqual(
                self.status([record(address=address)]), {"configured_lan_boundary": 1}
            )

    def test_multiple_addresses_and_excluded_names_are_visible(self):
        records = [
            record(address="192.168.10.41"),
            record(address="192.168.10.40"),
            record("*"),
            {**record(), "name": "other.example.com"},
        ]
        result = unifi_dns.plan(records, [], ZONE, LAN)
        self.assertEqual(result["excluded_a_records"], 2)
        row = result["rows"][0]
        self.assertEqual(row["status"], "ambiguous_forward")
        self.assertIsNone(row["address"])
        self.assertEqual(row["addresses"], ["192.168.10.40", "192.168.10.41"])

    def test_aliases_and_multiple_addresses(self):
        self.assertEqual(
            self.status([record(), record("other")]), {"ambiguous_reverse": 2}
        )
        self.assertEqual(
            self.status([record(), record(address="192.168.10.41")]),
            {"ambiguous_forward": 1},
        )
        self.assertEqual(
            self.status([record()], [policy("other")]), {"ambiguous_reverse": 1}
        )

    def test_local_conflicts_are_not_candidates(self):
        self.assertEqual(
            self.status([record()], [policy(enabled=False)]), {"local_conflict": 1}
        )
        self.assertEqual(
            self.status([record()], [policy(address="192.168.10.42")]),
            {"local_conflict": 1},
        )
        forwarding = {"domain": ZONE, "type": "FORWARD_DOMAIN", "enabled": True}
        self.assertEqual(
            self.status([record()], [forwarding]),
            {"forwarding_or_wildcard_conflict": 1},
        )

    def test_dual_stack_is_deferred(self):
        extra = {**record(), "type": "AAAA", "content": "fd00::40"}
        self.assertEqual(
            self.status([record(), extra]), {"additional_address_or_alias": 1}
        )

    def test_settings_restrict_destination(self):
        self.assertEqual(unifi_dns.settings(ENV)[0], "192.168.10.1")
        for value in ("http://192.168.10.1", "https://8.8.8.8", "https://example.net"):
            with self.assertRaises(ValueError):
                unifi_dns.settings({**ENV, "YGGFLARE_UNIFI_API_URL": value})

    def test_only_fixed_get_and_no_redirects(self):
        with patch("unifi_dns.FixedConnection") as conn:
            conn.return_value.getresponse.return_value.status = 302
            with self.assertRaises(ValueError):
                unifi_dns.get_page(unifi_dns.settings(ENV), "KEY", "dns", SITE, 0)
            conn.return_value.request.assert_called_once_with(
                "GET",
                f"/proxy/network/integration/v1/sites/{SITE}/dns/policies?offset=0&limit=100",
                headers={"Accept": "application/json", "X-API-Key": "KEY"},
            )
        with self.assertRaises(ValueError):
            unifi_dns.get_page(unifi_dns.settings(ENV), "KEY", "delete", SITE, 0)

    def test_incomplete_pagination_rejected(self):
        def fetch(*args):
            return {"data": [], "offset": 0, "count": 0, "limit": 100, "totalCount": 1}

        with self.assertRaises(ValueError):
            unifi_dns.all_rows(unifi_dns.settings(ENV), "KEY", "sites", "", fetch)

    def test_duplicate_identity_rejected(self):
        def fetch(config, key, kind, site, offset):
            return {
                "data": [{"id": SITE}],
                "offset": offset,
                "count": 1,
                "limit": 1,
                "totalCount": 2,
            }

        with self.assertRaises(ValueError):
            unifi_dns.all_rows(unifi_dns.settings(ENV), "KEY", "dns", SITE, fetch)
