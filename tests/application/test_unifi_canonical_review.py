"""Offline canonical PTR review; no Cloudflare or UniFi writes."""

import ipaddress
import sys
import unittest
from unittest.mock import patch

import cli
from unifi_canonical_review import review
from unifi_dns import CANONICAL_TAG, plan
from unifi_dns_verify import verify

ZONE = "example.invalid"
LAN = ipaddress.IPv4Network("192.168.10.0/24")
GATEWAY = "192.168.10.1"
ADDRESS = "192.168.10.20"
PRIMARY = f"primary.{ZONE}"
ALIAS = f"alias.{ZONE}"


def record(name, address=ADDRESS, **extra):
    return {
        "name": name,
        "type": "A",
        "content": address,
        "proxied": False,
        **extra,
    }


def observe(comparison, gateway):
    def request(target, name, kind):
        if target != GATEWAY:
            raise AssertionError("Unexpected gateway")
        if kind == "PTR":
            return "answered", [ALIAS + "."]
        if name == PRIMARY + ".":
            return "answered", [ADDRESS]
        return "nxdomain", []

    return verify(comparison, gateway, request=request)


class CanonicalReviewTests(unittest.TestCase):
    def test_exact_declaration_suggests_tag_but_preserves_conflicting_evidence(self):
        comparison = plan([record(PRIMARY), record(ALIAS)], [], ZONE, LAN)
        report = review(comparison, GATEWAY, {(PRIMARY, ADDRESS)}, observe)
        self.assertEqual(report["counts"], {"suggest_tag": 1})
        row = report["rows"][0]
        self.assertEqual(row["suggested_hostname"], PRIMARY)
        self.assertIsNone(row["canonical_hostname"])
        self.assertEqual(row["reverse"]["answers"], [ALIAS + "."])
        self.assertEqual(row["reverse"]["status"], "ambiguous_expectation")
        names = {item["hostname"]: item for item in row["hostnames"]}
        self.assertEqual(names[PRIMARY]["forward"]["status"], "matched")
        self.assertEqual(names[ALIAS]["forward"]["status"], "nxdomain")
        self.assertTrue(names[PRIMARY]["declared"])
        self.assertFalse(names[ALIAS]["declared"])

    def test_explicit_tag_has_priority_over_declaration(self):
        comparison = plan(
            [record(PRIMARY), record(ALIAS, tags=[CANONICAL_TAG])], [], ZONE, LAN
        )
        row = review(comparison, GATEWAY, {(PRIMARY, ADDRESS)}, observe)["rows"][0]
        self.assertEqual(row["decision"], "explicit_canonical")
        self.assertEqual(row["canonical_hostname"], ALIAS)
        self.assertIsNone(row["suggested_hostname"])
        self.assertEqual(row["reverse"]["status"], "matched")

    def test_ambiguous_declarations_and_existing_ptr_do_not_choose_a_name(self):
        comparison = plan([record(PRIMARY), record(ALIAS)], [], ZONE, LAN)
        for declared in (set(), {(PRIMARY, ADDRESS), (ALIAS, ADDRESS)}):
            with self.subTest(declared=declared):
                row = review(comparison, GATEWAY, declared, observe)["rows"][0]
                self.assertEqual(row["decision"], "manual_selection")
                self.assertIsNone(row["suggested_hostname"])

    def test_conflicting_tags_and_ineligible_aliases_are_not_suggested(self):
        for records, decision in (
            (
                [
                    record(PRIMARY, tags=[CANONICAL_TAG]),
                    record(ALIAS, tags=[CANONICAL_TAG]),
                ],
                "conflicting_tags",
            ),
            ([record(PRIMARY), record(ALIAS, proxied=True)], "ineligible_alias"),
        ):
            with self.subTest(decision=decision):
                comparison = plan(records, [], ZONE, LAN)
                row = review(comparison, GATEWAY, {(PRIMARY, ADDRESS)}, observe)[
                    "rows"
                ][0]
                self.assertEqual(row["decision"], decision)
                self.assertIsNone(row["suggested_hostname"])

    def test_outside_lan_and_empty_groups_do_not_trigger_queries(self):
        outside = "192.168.11.20"
        for records, counts in (
            ([record(PRIMARY)], {}),
            (
                [record(PRIMARY, outside), record(ALIAS, outside)],
                {"outside_configured_lan": 1},
            ),
        ):
            with (
                self.subTest(counts=counts),
                patch("unifi_canonical_review.verify") as query,
            ):
                comparison = plan(records, [], ZONE, LAN)
                report = review(comparison, GATEWAY, {(PRIMARY, outside)}, query)
                self.assertEqual(report["counts"], counts)
                query.assert_not_called()

    def test_local_policy_conflict_is_visible_despite_alias_status(self):
        policies = [
            {
                "domain": PRIMARY,
                "type": "A_RECORD",
                "enabled": False,
                "ipv4Address": ADDRESS,
            }
        ]
        comparison = plan([record(PRIMARY), record(ALIAS)], policies, ZONE, LAN)
        row = review(comparison, GATEWAY, {(PRIMARY, ADDRESS)}, observe)["rows"][0]
        names = {item["hostname"]: item for item in row["hostnames"]}
        self.assertEqual(names[PRIMARY]["local_policy_status"], "local_conflict")
        self.assertEqual(names[ALIAS]["local_policy_status"], "shared_local_address")
        self.assertEqual(names[PRIMARY]["cloudflare_status"], "ambiguous_reverse")

    def test_cli_routes_only_read_only_review_command(self):
        with patch.object(cli.subprocess, "run") as run:
            run.return_value.returncode = 0
            self.assertEqual(cli.main(["unifi", "canonical-review", "--json"]), 0)
            run.assert_called_once_with(
                [sys.executable, "/app/unifi_canonical_review.py", "--json"],
                check=False,
            )
