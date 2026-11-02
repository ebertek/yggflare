"""Offline regression tests for live Cloudflare-to-Compose reconciliation."""

import unittest

from cloudflare_live_diff import compare_live, ordered_policy_ids, validate_ingress

ONE = "11111111-1111-1111-1111-111111111111"
TWO = "22222222-2222-2222-2222-222222222222"
TUNNEL = "52acd579-76f3-4b52-bec4-8c505258a7b1"


def application(host="grafana.ebi.nu", ids=None):
    """Build one Cloudflare Access application fixture."""
    policies = ids if ids is not None else [ONE, TWO]
    return {
        "id": "cccccccc-cccc-cccc-cccc-cccccccccccc",
        "domain": host,
        "type": "self_hosted",
        "policies": [
            {"id": identifier, "precedence": rank}
            for rank, identifier in enumerate(policies, 1)
        ],
    }


def dns(host="grafana.ebi.nu", target=TUNNEL):
    """Build a correctly proxied tunnel CNAME."""
    return {
        "id": "dddddddddddddddddddddddddddddddd",
        "name": host,
        "type": "CNAME",
        "proxied": True,
        "content": target + ".cfargotunnel.com",
    }


def routes(*hosts):
    """Build remotely managed Tunnel ingress with a terminal catch-all."""
    return [
        *[
            {"hostname": host, "service": "https://traefik.ygg.nu:443"}
            for host in hosts
        ],
        {"service": "http_status:404"},
    ]


class LiveDiffTests(unittest.TestCase):
    """Fail-closed drift detection with zero side effects."""

    def test_clean_baseline(self):
        """Recognize consistent Access, DNS and Tunnel resources."""
        report = compare_live(
            {"grafana.ebi.nu": [ONE, TWO]},
            [application()],
            [dns()],
            routes("grafana.ebi.nu"),
            TUNNEL,
        )
        self.assertEqual(report["actions"], [])
        self.assertEqual(report["blocked"], [])
        self.assertEqual(report["counts"]["desired_hosts"], 1)

    def test_new_host_creates_three_proposals(self):
        """Propose Access, DNS and ingress without removing existing hosts."""
        report = compare_live(
            {"new.ebi.nu": [ONE]},
            [application()],
            [dns()],
            routes("grafana.ebi.nu"),
            TUNNEL,
        )
        self.assertEqual(
            {action["kind"] for action in report["actions"]},
            {"create_access_app", "create_dns_cname", "add_tunnel_ingress"},
        )
        self.assertEqual(report["unmanaged"]["access_app_count"], 1)

    def test_existing_policy_change_is_detected(self):
        """Policy order follows Compose rather than the existing Cloudflare app."""
        report = compare_live(
            {"grafana.ebi.nu": [TWO, ONE]},
            [application()],
            [dns()],
            routes("grafana.ebi.nu"),
            TUNNEL,
        )
        self.assertEqual(report["proposed_by_kind"], {"update_access_policies": 1})
        self.assertEqual(report["actions"][0]["before"], [ONE, TWO])

    def test_existing_dns_conflict_blocks(self):
        """Never silently overwrite a non-Tunnel A or CNAME."""
        conflicting = {**dns(), "type": "A", "content": "10.4.20.1"}
        report = compare_live(
            {"grafana.ebi.nu": [ONE, TWO]},
            [application()],
            [conflicting],
            routes("grafana.ebi.nu"),
            TUNNEL,
        )
        self.assertEqual(report["counts"]["blocked"], 1)
        self.assertEqual(report["actions"], [])

    def test_duplicate_apps_block(self):
        """Never guess which Access application belongs to a hostname."""
        report = compare_live(
            {"grafana.ebi.nu": [ONE, TWO]},
            [application(), application()],
            [dns()],
            routes("grafana.ebi.nu"),
            TUNNEL,
        )
        self.assertEqual(report["counts"]["blocked"], 1)

    def test_missing_access_policy_details_block(self):
        """Don't treat unknown live policy assignments as matches."""
        app = {**application(), "policies": []}
        report = compare_live(
            {"grafana.ebi.nu": [ONE, TWO]},
            [app],
            [dns()],
            routes("grafana.ebi.nu"),
            TUNNEL,
        )
        self.assertEqual(report["counts"]["blocked"], 1)

    def test_double_ingress_and_invalid_fallback_fail(self):
        """Ambiguous or catch-all-bypassing tunnels are refused."""
        with self.assertRaises(ValueError):
            validate_ingress(routes("grafana.ebi.nu", "grafana.ebi.nu"))
        with self.assertRaises(ValueError):
            validate_ingress(
                [{"hostname": "grafana.ebi.nu", "service": "http_status:404"}]
            )

    def test_policy_precedence_validation(self):
        """Reject duplicate or nonconsecutive precedence."""
        app = application()
        app["policies"][1]["precedence"] = 4
        with self.assertRaises(ValueError):
            ordered_policy_ids(app)

    def test_docker_ipv4_updates_only_existing_docker_a(self):
        """Reconcile unique Docker addresses without touching devices."""
        local = {
            "name": "grafana.ygg.nu",
            "type": "A",
            "id": "record-one",
            "content": "10.4.21.5",
        }
        report = compare_live(
            {},
            [],
            [],
            routes("grafana.ebi.nu"),
            TUNNEL,
            docker_addresses={"grafana": "10.4.21.6"},
            dns_ygg=[local],
        )
        self.assertEqual(report["proposed_by_kind"], {"update_docker_dns_a": 1})
        changed = {**local, "content": "10.4.20.5"}
        report = compare_live(
            {},
            [],
            [],
            routes("grafana.ebi.nu"),
            TUNNEL,
            docker_addresses={"grafana": "10.4.21.6"},
            dns_ygg=[changed],
        )
        self.assertEqual(report["counts"]["blocked"], 1)
        self.assertEqual(report["actions"], [])

    def test_nonexistent_docker_name_not_created(self):
        """Never invent device or Docker A records."""
        report = compare_live(
            {},
            [],
            [],
            routes("grafana.ebi.nu"),
            TUNNEL,
            docker_addresses={"unlisted": "10.4.21.10"},
            dns_ygg=[],
        )
        self.assertEqual(report["actions"], [])


if __name__ == "__main__":
    unittest.main()
