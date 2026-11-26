"""Check the read-only UniFi DNS create preview against offline fixtures."""

import ipaddress
import unittest

from unifi_dns import plan
from unifi_dns_verify import verify
from unifi_reconcile_plan import preview

ZONE = "example.invalid"
LAN = ipaddress.IPv4Network("192.168.10.0/24")
GATEWAY = "192.168.10.1"


def a(label, ip):
    return {
        "name": f"{label}.{ZONE}",
        "type": "A",
        "content": ip,
        "proxied": False,
    }


def comparison():
    records = [
        a("aliased", "192.168.10.6"),
        a("alias", "192.168.10.6"),
        a("candidate", "192.168.10.2"),
        a("existing", "192.168.10.3"),
        a("foreign", "192.168.11.4"),
        a("reverse-conflict", "192.168.10.5"),
        a("forward-error", "192.168.10.7"),
        a("forward-conflict", "192.168.10.8"),
        a("already", "192.168.10.9"),
    ]
    policies = [
        {
            "type": "A_RECORD",
            "domain": f"existing.{ZONE}",
            "enabled": True,
            "ipv4Address": "192.168.10.3",
        }
    ]
    return plan(records, policies, ZONE, LAN)


def observe(desired, gateway):
    def request(_, name, kind):
        if kind == "PTR":
            if name.startswith("5."):
                return "answered", [f"other.{ZONE}."]
            if name.startswith("9."):
                return "answered", [f"already.{ZONE}."]
            return "nxdomain", []
        if name.startswith("forward-error."):
            return "timeout", []
        if name.startswith("forward-conflict."):
            return "answered", ["192.168.10.99"]
        if name.startswith("already."):
            return "answered", ["192.168.10.9"]
        if name.startswith("candidate."):
            return "answered", ["192.168.10.2"]
        return "nodata", []

    return verify(desired, gateway, request=request)


class UniFiCreatePreviewTests(unittest.TestCase):
    def test_proposes_only_create_for_unique_nonconflicting_lan_candidate(self):
        result = preview(comparison(), GATEWAY, "inputs", observe)
        self.assertEqual(
            result["operations"],
            [
                {
                    "operation": "create",
                    "type": "A_RECORD",
                    "domain": f"candidate.{ZONE}",
                    "ipv4Address": "192.168.10.2",
                    "enabled": True,
                }
            ],
        )
        self.assertEqual(
            result["counts"],
            {
                "already_resolves": 1,
                "ambiguous_reverse": 2,
                "forward_review": 2,
                "matched": 1,
                "outside_configured_lan": 1,
                "proposed_create": 1,
                "reverse_review": 1,
            },
        )

    def test_fingerprint_binds_fresh_inputs_and_observed_reply(self):
        desired = comparison()
        original = preview(desired, GATEWAY, "inputs", observe)["fingerprint"]
        self.assertEqual(
            original, preview(desired, GATEWAY, "inputs", observe)["fingerprint"]
        )
        self.assertNotEqual(
            original, preview(desired, GATEWAY, "other-target", observe)["fingerprint"]
        )

        def other_reply(desired, gateway):
            replies = observe(desired, gateway)
            for row in replies["rows"]:
                if row["status"] == "mismatch":
                    row["answers"] = ["different"]
            return replies

        self.assertNotEqual(
            original, preview(desired, GATEWAY, "inputs", other_reply)["fingerprint"]
        )
