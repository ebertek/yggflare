"""Offline tests for explicit, narrowly scoped Cloudflare writes."""

# pylint: disable=too-many-public-methods

import copy
import unittest
from unittest.mock import patch

from cloudflare_guarded import (
    UnsafePlan,
    apply_actions,
    check_plan,
    check_unattended_plan,
    fingerprint,
    preflight_compatibility,
)
from cloudflare_write_api import CloudflareWriter, policy_links

POLICY = "11111111-1111-1111-1111-111111111111"
TUNNEL = "52acd579-76f3-4b52-bec4-8c505258a7b1"
ACCOUNT = "a" * 32
ZONE = "b" * 32
CONTEXT = {"account": ACCOUNT, "ebi": ZONE, "ygg": ZONE, "tunnel": TUNNEL}
HOST = "new.ebi.nu"
TEMPLATE = "komodo.ebi.nu"


def report(*actions, blocked=None):
    """Build a minimal audit result for execution tests."""
    return {"actions": list(actions), "blocked": blocked or []}


def new_host_actions():
    """Return intentionally unordered operations for one hostname."""
    return report(
        {
            "kind": "create_dns_cname",
            "hostname": HOST,
            "content": TUNNEL + ".cfargotunnel.com",
            "policies": [POLICY],
        },
        {"kind": "add_tunnel_ingress", "hostname": HOST, "policies": [POLICY]},
        {
            "kind": "create_access_app",
            "hostname": HOST,
            "policies": [POLICY],
        },
    )


def safe_new_host_actions(allow, deny):
    """Use authenticated policy assignments in each new-host operation."""
    actions = new_host_actions()
    for action in actions["actions"]:
        action["policies"] = [allow, deny]
    return actions


class FakeWriter:
    """In-memory stand-in for the narrowly scoped Cloudflare API."""

    def __init__(self):
        """Retain routes and records as detached mutable snapshots."""
        self.events = []
        self.apps = []
        self.dns = []
        self.policies = [{"id": POLICY}]
        self.configuration = {
            "warp-routing": {"enabled": True},
            "ingress": [
                {
                    "hostname": TEMPLATE,
                    "service": "https://traefik.ygg.nu:443",
                    "originRequest": {"http2Origin": True},
                },
                {"service": "http_status:404"},
            ],
        }
        self.private_record = {
            "id": "c" * 32,
            "name": "grafana.ygg.nu",
            "type": "A",
            "content": "10.4.21.5",
            "proxied": False,
        }

    def list_applications(self, account):
        """List current app snapshots."""
        assert account == ACCOUNT
        return copy.deepcopy(self.apps)

    def list_policies(self, account):
        """List reusable policy identifiers."""
        assert account == ACCOUNT
        return copy.deepcopy(self.policies)

    def get_application(self, account, app_id):
        """Resolve the full Access app."""
        assert account == ACCOUNT
        return copy.deepcopy(next(item for item in self.apps if item["id"] == app_id))

    def create_access_app(self, account, hostname, policies):
        """Create an Access app, retaining declared policy precedence."""
        self.events.append("access")
        assert account == ACCOUNT
        item = {
            "id": "d" * 32,
            "domain": hostname,
            "type": "self_hosted",
            "policies": policy_links(policies),
        }
        self.apps.append(item)
        return copy.deepcopy(item)

    def update_access_policies(self, account, app_id, application, policies):
        """Simulate an Access application update without changing other fields."""
        assert account == ACCOUNT
        assert app_id == application["id"]
        self.events.append("access_policy_update")
        for item in self.apps:
            if item["id"] == app_id:
                item["policies"] = policy_links(policies)
                return
        raise AssertionError("Access app missing")

    def tunnel_configuration(self, account, tunnel):
        """Return the current complete remotely managed Tunnel config."""
        assert (account, tunnel) == (ACCOUNT, TUNNEL)
        return {"config": copy.deepcopy(self.configuration)}

    def put_tunnel_ingress(self, account, tunnel, config):
        """Record a complete Tunnel configuration replacement."""
        self.events.append("tunnel")
        assert (account, tunnel) == (ACCOUNT, TUNNEL)
        self.configuration = copy.deepcopy(config)

    def list_dns(self, zone):
        """Return current records from the public test zone."""
        assert zone == ZONE
        return copy.deepcopy(self.dns)

    def create_dns_cname(self, zone, hostname, target):
        """Create a proxied CNAME only after route verification."""
        assert zone == ZONE
        self.events.append("dns")
        self.dns.append(
            {
                "id": "e" * 32,
                "name": hostname,
                "type": "CNAME",
                "content": target,
                "proxied": True,
            }
        )

    def get_dns_record(self, zone, record_id):
        """Read a private-zone A record by its ID."""
        assert zone == ZONE
        if record_id == "c" * 32:
            return copy.deepcopy(self.private_record)
        return copy.deepcopy(
            next(item for item in self.dns if item.get("id") == record_id)
        )

    def create_static_a(self, zone, hostname, content):
        """Simulate an unproxied static record creation."""
        assert zone == ZONE
        self.events.append("static_create")
        self.dns.append(
            {
                "id": "f" * 32,
                "name": hostname,
                "type": "A",
                "content": content,
                "proxied": False,
                "ttl": 300,
            }
        )

    def patch_static_a(self, zone, record_id, hostname, content):
        """Change only the content of an existing static A record."""
        assert zone == ZONE
        self.events.append("static_update")
        entry = next(item for item in self.dns if item.get("id") == record_id)
        assert entry["name"] == hostname
        entry["content"] = content

    def patch_docker_a(self, zone, record_id, content):
        """Change the existing record without altering other settings."""
        self.events.append("docker_a")
        assert (zone, record_id) == (ZONE, "c" * 32)
        self.private_record["content"] = content


class GuardedTests(unittest.TestCase):
    """Ensure Cloudflare mutations cannot bypass declared safety checks."""

    def test_preflight_validates_live_template_without_writes(self):
        """Verify existing Tunnel, Access and DNS without mutating anything."""
        client = FakeWriter()
        client.apps = [
            {
                "id": "d" * 32,
                "domain": TEMPLATE,
                "type": "self_hosted",
                "policies": policy_links([POLICY]),
                "destinations": [{"type": "public", "uri": TEMPLATE}],
            }
        ]
        client.dns = [
            {
                "name": TEMPLATE,
                "type": "CNAME",
                "content": TUNNEL + ".cfargotunnel.com",
                "proxied": True,
            }
        ]
        result = preflight_compatibility(client, CONTEXT)
        self.assertEqual(result["trusted_template"], TEMPLATE)
        self.assertEqual(result["tunnel_routes"], 2)
        self.assertEqual(result["template_access_policies"], 1)
        self.assertTrue(result["template_cname_verified"])
        self.assertEqual(client.events, [])
        self.assertEqual(client.configuration["warp-routing"], {"enabled": True})

    def test_preflight_refuses_unknown_tunnel_fields(self):
        """Do not allow unknown top-level keys in a full Tunnel replacement."""
        client = FakeWriter()
        client.configuration["unexpected-option"] = {"enabled": True}
        with self.assertRaisesRegex(UnsafePlan, "unexpected-option"):
            preflight_compatibility(client, CONTEXT)
        with self.assertRaisesRegex(UnsafePlan, "unexpected-option"):
            apply_actions(client, new_host_actions(), CONTEXT)
        self.assertEqual(client.events, [])

    def test_put_preserves_warp_routing_verbatim(self):
        """Pass the complete remotely managed Tunnel config to Cloudflare."""
        client = CloudflareWriter("test-token")
        config = copy.deepcopy(FakeWriter().configuration)
        with patch.object(client, "_write", return_value={}) as sender:
            client.put_tunnel_ingress(ACCOUNT, TUNNEL, config)
        self.assertEqual(sender.call_args.args[0], "PUT")
        self.assertEqual(sender.call_args.args[2], {"config": config})
        self.assertEqual(config["warp-routing"], {"enabled": True})

    def test_invalid_warp_routing_is_refused(self):
        """Avoid replacing a Tunnel when warp-routing has an invalid shape."""
        client = CloudflareWriter("test-token")
        config = copy.deepcopy(FakeWriter().configuration)
        config["warp-routing"] = "invalid"
        with (
            patch.object(client, "_write") as sender,
            self.assertRaises(TypeError),
        ):
            client.put_tunnel_ingress(ACCOUNT, TUNNEL, config)
        sender.assert_not_called()

    def test_preflight_refuses_incompatible_tunnel_template(self):
        """Reject unexpected existing origin before any write."""
        client = FakeWriter()
        client.configuration["ingress"][0]["service"] = "http://unknown:9000"
        with self.assertRaises(UnsafePlan):
            preflight_compatibility(client, CONTEXT)
        self.assertEqual(client.events, [])

    def test_preflight_refuses_missing_access_application(self):
        """Reject missing trusted Access reference application."""
        client = FakeWriter()
        with self.assertRaises(UnsafePlan):
            preflight_compatibility(client, CONTEXT)
        self.assertEqual(client.events, [])

    def test_preflight_refuses_wrong_dns_target(self):
        """Do not trust an Access-protected hostname with conflicting DNS."""
        client = FakeWriter()
        client.apps = [
            {
                "id": "d" * 32,
                "domain": TEMPLATE,
                "type": "self_hosted",
                "policies": policy_links([POLICY]),
            }
        ]
        client.dns = [
            {
                "name": TEMPLATE,
                "type": "CNAME",
                "content": "other.cfargotunnel.com",
                "proxied": True,
            }
        ]
        with self.assertRaises(UnsafePlan):
            preflight_compatibility(client, CONTEXT)
        self.assertEqual(client.events, [])

    def test_unattended_access_update_with_allow_and_final_deny(self):
        """A verified policy update can run automatically with safe decisions."""
        allow = "22222222-2222-2222-2222-222222222222"
        deny = "33333333-3333-3333-3333-333333333333"
        client = FakeWriter()
        client.policies = [
            {"id": POLICY, "decision": "bypass"},
            {"id": allow, "decision": "allow"},
            {"id": deny, "decision": "deny"},
        ]
        client.apps = [
            {
                "id": "d" * 32,
                "name": "grafana",
                "domain": "grafana.ebi.nu",
                "type": "self_hosted",
                "session_duration": "12h",
                "policies": policy_links([POLICY, allow, deny]),
            }
        ]
        changed = report(
            {
                "kind": "update_access_policies",
                "hostname": "grafana.ebi.nu",
                "app_id": "d" * 32,
                "before": [POLICY, allow, deny],
                "policies": [allow, POLICY, deny],
            }
        )
        self.assertEqual(
            len(check_unattended_plan(changed, reusable=client.policies)), 1
        )
        result = apply_actions(client, changed, CONTEXT, unattended=True)
        self.assertEqual(result[0]["kind"], "update_access_policies")
        self.assertEqual(client.events, ["access_policy_update"])
        self.assertEqual(client.apps[0]["session_duration"], "12h")
        self.assertEqual(
            [item["id"] for item in client.apps[0]["policies"]],
            [allow, POLICY, deny],
        )

    def test_unattended_access_update_blocks_missing_allow_or_deny(self):
        """Reject unsafe automatic policy changes before any API write."""
        allow = "22222222-2222-2222-2222-222222222222"
        deny = "33333333-3333-3333-3333-333333333333"
        records = [
            {"id": POLICY, "decision": "bypass"},
            {"id": allow, "decision": "allow"},
            {"id": deny, "decision": "deny"},
        ]
        for wanted in ([POLICY, deny], [allow], [deny, allow], [allow, deny, deny]):
            with self.subTest(wanted=wanted), self.assertRaises(UnsafePlan):
                check_unattended_plan(
                    report(
                        {
                            "kind": "update_access_policies",
                            "hostname": "grafana.ebi.nu",
                            "app_id": "d" * 32,
                            "before": [POLICY, allow, deny],
                            "policies": wanted,
                        }
                    ),
                    reusable=records,
                )

    def test_unattended_access_update_refuses_changed_policy_decision(self):
        """Recheck reusable decisions immediately before updating the app."""
        allow = "22222222-2222-2222-2222-222222222222"
        deny = "33333333-3333-3333-3333-333333333333"
        client = FakeWriter()
        client.policies = [
            {"id": POLICY, "decision": "bypass"},
            {"id": allow, "decision": "bypass"},
            {"id": deny, "decision": "deny"},
        ]
        client.apps = [
            {
                "id": "d" * 32,
                "domain": "grafana.ebi.nu",
                "type": "self_hosted",
                "policies": policy_links([POLICY, allow, deny]),
            }
        ]
        candidate = report(
            {
                "kind": "update_access_policies",
                "hostname": "grafana.ebi.nu",
                "app_id": "d" * 32,
                "before": [POLICY, allow, deny],
                "policies": [allow, POLICY, deny],
            }
        )
        with self.assertRaises(UnsafePlan):
            apply_actions(client, candidate, CONTEXT, unattended=True)
        self.assertEqual(client.events, [])

    def test_unattended_accepts_bounded_new_host(self):
        """A new service's three staged operations require allow and final deny."""
        allow = "22222222-2222-2222-2222-222222222222"
        deny = "33333333-3333-3333-3333-333333333333"
        client = FakeWriter()
        client.policies = [
            {"id": allow, "decision": "allow"},
            {"id": deny, "decision": "deny"},
        ]
        candidate = safe_new_host_actions(allow, deny)
        approved = check_unattended_plan(candidate, reusable=client.policies)
        self.assertEqual(len(approved), 3)
        completed = apply_actions(client, candidate, CONTEXT, unattended=True)
        self.assertEqual(
            [step["kind"] for step in completed],
            ["create_access_app", "add_tunnel_ingress", "create_dns_cname"],
        )
        self.assertEqual(client.events, ["access", "tunnel", "dns"])
        with self.assertRaises(UnsafePlan):
            check_unattended_plan(
                report(*(candidate["actions"] * 2)), reusable=client.policies
            )

    def test_unattended_new_host_rejects_unsafe_policies_before_writes(self):
        """Missing allow/deny and wrong order must never create a public app."""
        allow = "22222222-2222-2222-2222-222222222222"
        deny = "33333333-3333-3333-3333-333333333333"
        client = FakeWriter()
        client.policies = [
            {"id": POLICY, "decision": "bypass"},
            {"id": allow, "decision": "allow"},
            {"id": deny, "decision": "deny"},
        ]
        for policies in ([POLICY], [POLICY, deny], [allow], [deny, allow]):
            candidate = safe_new_host_actions(allow, deny)
            for action in candidate["actions"]:
                action["policies"] = list(policies)
            with self.subTest(policies=policies):
                with self.assertRaises(UnsafePlan):
                    check_unattended_plan(candidate, reusable=client.policies)
                with self.assertRaises(UnsafePlan):
                    apply_actions(client, candidate, CONTEXT, unattended=True)
                self.assertEqual(client.events, [])

    def test_unattended_new_host_rechecks_decisions_before_create(self):
        """A decision change after initial plan validation must block POST."""
        allow = "22222222-2222-2222-2222-222222222222"
        deny = "33333333-3333-3333-3333-333333333333"
        client = FakeWriter()
        initial = [
            {"id": allow, "decision": "allow"},
            {"id": deny, "decision": "deny"},
        ]
        changed = [
            {"id": allow, "decision": "bypass"},
            {"id": deny, "decision": "deny"},
        ]
        with (
            patch.object(
                client, "list_policies", side_effect=[initial, initial, changed]
            ),
            self.assertRaises(UnsafePlan),
        ):
            apply_actions(
                client,
                safe_new_host_actions(allow, deny),
                CONTEXT,
                unattended=True,
            )
        self.assertEqual(client.events, [])

    def test_empty_report_requires_no_action(self):
        """An already synchronized account produces an empty execution list."""
        client = FakeWriter()
        self.assertEqual(apply_actions(client, report(), CONTEXT), [])
        self.assertEqual(client.events, [])

    def test_existing_policy_update_preserves_application(self):
        """Update only ordered reusable policy links after a live recheck."""
        client = FakeWriter()
        client.policies.append({"id": "22222222-2222-2222-2222-222222222222"})
        client.apps = [
            {
                "id": "d" * 32,
                "name": "grafana",
                "domain": "grafana.ebi.nu",
                "type": "self_hosted",
                "session_duration": "12h",
                "policies": policy_links([POLICY]),
            }
        ]
        change = {
            "kind": "update_access_policies",
            "hostname": "grafana.ebi.nu",
            "app_id": "d" * 32,
            "before": [POLICY],
            "policies": [POLICY, "22222222-2222-2222-2222-222222222222"],
        }
        done = apply_actions(client, report(change), CONTEXT)
        self.assertEqual(len(done), 1)
        self.assertEqual(client.events, ["access_policy_update"])
        self.assertEqual(client.apps[0]["session_duration"], "12h")
        self.assertEqual(len(client.apps[0]["policies"]), 2)

    def test_existing_policy_update_refuses_live_drift(self):
        """Stale policy lists cannot authorize writes."""
        client = FakeWriter()
        client.apps = [
            {
                "id": "d" * 32,
                "domain": "grafana.ebi.nu",
                "type": "self_hosted",
                "policies": policy_links([POLICY]),
            }
        ]
        change = {
            "kind": "update_access_policies",
            "hostname": "grafana.ebi.nu",
            "app_id": "d" * 32,
            "before": [],
            "policies": [POLICY],
        }
        with self.assertRaises(UnsafePlan):
            apply_actions(client, report(change), CONTEXT)
        self.assertEqual(client.events, [])

    def test_policy_put_rejects_unknown_fields(self):
        """Unknown settings must not be silently discarded by the PUT writer."""
        client = CloudflareWriter("test-token")
        app = {
            "id": "d" * 32,
            "name": "grafana",
            "domain": "grafana.ebi.nu",
            "type": "self_hosted",
            "unknown_future_setting": True,
        }
        with patch.object(client, "_write") as writer, self.assertRaises(ValueError):
            client.update_access_policies(ACCOUNT, "d" * 32, app, [POLICY])
        writer.assert_not_called()

    def test_policy_put_retains_supported_settings(self):
        """Preserve settings and replace only reusable policy references."""
        client = CloudflareWriter("test-token")
        app = {
            "id": "dddddddd-dddd-dddd-dddd-dddddddddddd",
            "name": "grafana",
            "domain": "grafana.ebi.nu",
            "type": "self_hosted",
            "session_duration": "12h",
            "http_only_cookie_attribute": True,
            "policies": policy_links([POLICY]),
        }
        with patch.object(client, "_write", return_value={}) as writer:
            client.update_access_policies(
                ACCOUNT, "dddddddd-dddd-dddd-dddd-dddddddddddd", app, [POLICY]
            )
        payload = writer.call_args.args[2]
        self.assertEqual(payload["session_duration"], "12h")
        self.assertTrue(payload["http_only_cookie_attribute"])
        self.assertEqual(payload["policies"], policy_links([POLICY]))
        self.assertNotIn("id", payload)

    def test_policy_put_supports_actual_live_application_fields(self):
        """Preserve writable fields from a real self-hosted app's GET keys."""
        client = CloudflareWriter("test-token")
        identifier = "dddddddd-dddd-dddd-dddd-dddddddddddd"
        app = {
            "id": identifier,
            "uid": identifier,
            "name": "unpackerr",
            "domain": "unpackerr.ebi.nu",
            "type": "self_hosted",
            "aud": "test-audience-tag",
            "created_at": "2026-10-27T00:00:00Z",
            "updated_at": "2026-10-27T00:00:00Z",
            "allowed_idps": [],
            "app_launcher_visible": False,
            "auto_redirect_to_identity": False,
            "destinations": [{"type": "public", "uri": "unpackerr.ebi.nu"}],
            "self_hosted_domains": ["unpackerr.ebi.nu"],
            "eager_redirect_cookie_setting": True,
            "enable_binding_cookie": True,
            "http_only_cookie_attribute": True,
            "options_preflight_bypass": False,
            "session_duration": "24h",
            "tags": [],
            "policies": policy_links([POLICY]),
        }
        with patch.object(client, "_write", return_value={}) as writer:
            client.update_access_policies(ACCOUNT, identifier, app, [POLICY])
        body = writer.call_args.args[2]
        self.assertTrue(body["eager_redirect_cookie_setting"])
        self.assertTrue(body["http_only_cookie_attribute"])
        self.assertEqual(body["destinations"], app["destinations"])
        self.assertNotIn("self_hosted_domains", body)
        self.assertNotIn("uid", body)
        self.assertNotIn("aud", body)

    def test_policy_put_preserves_legacy_domains_if_no_destinations(self):
        """Legacy hostname list is retained when destinations are absent."""
        client = CloudflareWriter("test-token")
        identifier = "dddddddd-dddd-dddd-dddd-dddddddddddd"
        app = {
            "id": identifier,
            "name": "unpackerr",
            "domain": "unpackerr.ebi.nu",
            "type": "self_hosted",
            "self_hosted_domains": ["unpackerr.ebi.nu"],
        }
        with patch.object(client, "_write", return_value={}) as writer:
            client.update_access_policies(ACCOUNT, identifier, app, [POLICY])
        self.assertEqual(
            writer.call_args.args[2]["self_hosted_domains"],
            ["unpackerr.ebi.nu"],
        )

    def test_blocked_and_duplicate_actions_refused(self):
        """Reject blocked or duplicate mutations before contacting Cloudflare."""
        with self.assertRaises(UnsafePlan):
            check_plan(report(blocked=[{"hostname": HOST, "reason": "conflict"}]))
        candidate = new_host_actions()["actions"][0]
        with self.assertRaises(UnsafePlan):
            check_plan(report(candidate, candidate))

    def test_fingerprint_depends_on_plan_and_scope(self):
        """Approval must change with targets, resources or desired operations."""
        original = new_host_actions()
        key = fingerprint(original, CONTEXT)
        self.assertEqual(len(key), 16)
        self.assertEqual(key, fingerprint(original, CONTEXT))
        changed = {**CONTEXT, "ebi": "f" * 32}
        self.assertNotEqual(key, fingerprint(original, changed))
        self.assertNotEqual(key, fingerprint(report(), CONTEXT))

    def test_host_is_protected_before_tunnel_and_dns(self):
        """Access creation and verification precede publication."""
        client = FakeWriter()
        done = apply_actions(client, new_host_actions(), CONTEXT)
        self.assertEqual(
            [entry["kind"] for entry in done],
            ["create_access_app", "add_tunnel_ingress", "create_dns_cname"],
        )
        self.assertEqual(client.events, ["access", "tunnel", "dns"])
        ingress = client.configuration["ingress"]
        self.assertEqual(ingress[-1]["service"], "http_status:404")
        self.assertEqual(ingress[-2]["hostname"], HOST)
        self.assertEqual(ingress[-2]["originRequest"], {"http2Origin": True})
        self.assertEqual(ingress[0]["hostname"], TEMPLATE)
        self.assertEqual(client.configuration["warp-routing"], {"enabled": True})

    def test_resume_after_access_was_already_created(self):
        """Complete ingress and DNS safely after an interrupted first apply."""
        client = FakeWriter()
        client.apps = [
            {
                "id": "d" * 32,
                "domain": HOST,
                "type": "self_hosted",
                "policies": policy_links([POLICY]),
            }
        ]
        changes = new_host_actions()["actions"][:2]
        done = apply_actions(client, report(*changes), CONTEXT)
        self.assertEqual(
            [value["kind"] for value in done],
            ["add_tunnel_ingress", "create_dns_cname"],
        )
        self.assertEqual(client.events, ["tunnel", "dns"])

    def test_publish_dns_if_access_and_tunnel_already_exist(self):
        """Never require recreation of an existing, correctly protected host."""
        client = FakeWriter()
        client.apps = [
            {
                "id": "d" * 32,
                "domain": HOST,
                "type": "self_hosted",
                "policies": policy_links([POLICY]),
            }
        ]
        client.configuration["ingress"].insert(
            -1, {"hostname": HOST, "service": "https://traefik.ygg.nu:443"}
        )
        change = new_host_actions()["actions"][0]
        done = apply_actions(client, report(change), CONTEXT)
        self.assertEqual(done[0]["kind"], "create_dns_cname")
        self.assertEqual(client.events, ["dns"])

    def test_conflicting_access_app_fails_without_writes(self):
        """Do not recreate an existing Access application."""
        client = FakeWriter()
        client.apps = [
            {
                "id": "d" * 32,
                "domain": HOST,
                "type": "self_hosted",
                "policies": policy_links([POLICY]),
            }
        ]
        with self.assertRaises(UnsafePlan):
            apply_actions(client, new_host_actions(), CONTEXT)
        self.assertEqual(client.events, [])

    def test_incompatible_tunnel_template_blocks_before_create(self):
        """Fail before any mutation if the trusted route is absent."""
        client = FakeWriter()
        client.configuration["ingress"][0]["service"] = "http://unknown:8000"
        with self.assertRaises(UnsafePlan):
            apply_actions(client, new_host_actions(), CONTEXT)
        self.assertEqual(client.events, [])

    def test_docker_a_requires_live_container_match(self):
        """Do not update if the container changed address after approval."""
        client = FakeWriter()
        actions = report(
            {
                "kind": "update_docker_dns_a",
                "hostname": "grafana.ygg.nu",
                "record_id": "c" * 32,
                "before": "10.4.21.5",
                "content": "10.4.21.6",
            }
        )
        with self.assertRaises(UnsafePlan):
            apply_actions(
                client,
                actions,
                CONTEXT,
                docker_addresses=lambda: {"grafana": "10.4.21.7"},
            )
        self.assertEqual(client.events, [])
        done = apply_actions(
            client,
            actions,
            CONTEXT,
            docker_addresses=lambda: {"grafana": "10.4.21.6"},
        )
        self.assertEqual(len(done), 1)
        self.assertEqual(client.events, ["docker_a"])
        self.assertEqual(client.private_record["proxied"], False)

    def test_non_docker_existing_address_blocked(self):
        """Do not change static or non-Docker A records."""
        client = FakeWriter()
        client.private_record["content"] = "10.4.20.5"
        with self.assertRaises(UnsafePlan):
            apply_actions(
                client,
                report(
                    {
                        "kind": "update_docker_dns_a",
                        "hostname": "grafana.ygg.nu",
                        "record_id": "c" * 32,
                        "before": "10.4.20.5",
                        "content": "10.4.21.6",
                    }
                ),
                CONTEXT,
                docker_addresses=lambda: {"grafana": "10.4.21.6"},
            )
        self.assertEqual(client.events, [])

    def test_static_create_uses_unproxied_a_and_readback(self):
        """The guarded worker may create only a missing static A record."""
        client = FakeWriter()
        candidate = report(
            {
                "kind": "create_static_dns_a",
                "hostname": "example-device.ygg.nu",
                "content": "10.4.20.11",
            }
        )
        done = apply_actions(client, candidate, CONTEXT, unattended=True)
        self.assertEqual(done[0]["kind"], "create_static_dns_a")
        self.assertEqual(client.events, ["static_create"])
        self.assertEqual(client.dns[0]["content"], "10.4.20.11")
        self.assertIs(client.dns[0]["proxied"], False)

    def test_static_update_preserves_other_record_fields(self):
        """An identified unproxied static A has only its IP patched."""
        client = FakeWriter()
        client.dns = [
            {
                "id": "f" * 32,
                "name": "example-device.ygg.nu",
                "type": "A",
                "content": "10.4.20.11",
                "proxied": False,
                "ttl": 7200,
                "comment": "Owned by private inventory",
            }
        ]
        candidate = report(
            {
                "kind": "update_static_dns_a",
                "hostname": "example-device.ygg.nu",
                "record_id": "f" * 32,
                "before": "10.4.20.11",
                "content": "10.4.20.12",
            }
        )
        done = apply_actions(client, candidate, CONTEXT, unattended=True)
        self.assertEqual(done[0]["kind"], "update_static_dns_a")
        self.assertEqual(client.events, ["static_update"])
        self.assertEqual(client.dns[0]["ttl"], 7200)
        self.assertEqual(client.dns[0]["comment"], "Owned by private inventory")

    def test_static_writes_refuse_collisions_and_live_drift(self):
        """No A/CNAME overwrite, duplicate takeover or stale-IP update."""
        client = FakeWriter()
        candidate = report(
            {
                "kind": "create_static_dns_a",
                "hostname": "example-device.ygg.nu",
                "content": "10.4.20.11",
            }
        )
        for kind in ("CNAME", "A"):
            client.dns = [
                {
                    "id": "f" * 32,
                    "name": "example-device.ygg.nu",
                    "type": kind,
                    "content": "10.4.20.10",
                    "proxied": False,
                }
            ]
            with self.subTest(kind=kind), self.assertRaises(UnsafePlan):
                apply_actions(client, candidate, CONTEXT, unattended=True)
            self.assertEqual(client.events, [])

        candidate["actions"][0].update(
            {
                "kind": "update_static_dns_a",
                "record_id": "f" * 32,
                "before": "10.4.20.9",
                "content": "10.4.20.11",
            }
        )
        with self.assertRaises(UnsafePlan):
            apply_actions(client, candidate, CONTEXT, unattended=True)
        self.assertEqual(client.events, [])

    def test_static_writes_reject_wrong_zone_and_allocations(self):
        """Only ygg.nu hostnames and the planned static /27 interiors are safe."""
        invalid = (
            ("other.ebi.nu", "10.4.20.11"),
            ("example-device.ygg.nu", "10.4.20.31"),
            ("example-device.ygg.nu", "10.4.21.11"),
            ("example-device.ygg.nu", "8.8.8.8"),
        )
        for hostname, content in invalid:
            with self.subTest(hostname=hostname, content=content):
                candidate = report(
                    {
                        "kind": "create_static_dns_a",
                        "hostname": hostname,
                        "content": content,
                    }
                )
                with self.assertRaises(UnsafePlan):
                    check_plan(candidate)
        client = CloudflareWriter("test-token")
        with patch.object(client, "_write", return_value={}) as sender:
            client.create_static_a(ZONE, "example-device.ygg.nu", "10.4.20.11")
            client.patch_static_a(ZONE, "f" * 32, "example-device.ygg.nu", "10.4.20.12")
        self.assertEqual(sender.call_count, 2)
        self.assertEqual(sender.call_args_list[0].args[0], "POST")
        self.assertEqual(
            sender.call_args_list[0].args[2],
            {
                "name": "example-device.ygg.nu",
                "type": "A",
                "content": "10.4.20.11",
                "ttl": 1,
                "proxied": False,
            },
        )
        self.assertEqual(sender.call_args_list[1].args[0], "PATCH")
        self.assertEqual(sender.call_args_list[1].args[2], {"content": "10.4.20.12"})

    def test_static_unattended_limit_and_conflict_isolation(self):
        """A conflicted static hostname doesn't block safe peers."""
        client = FakeWriter()
        safe = report(
            {
                "kind": "create_static_dns_a",
                "hostname": "device-a.ygg.nu",
                "content": "10.4.20.11",
            },
            {
                "kind": "create_static_dns_a",
                "hostname": "device-b.ygg.nu",
                "content": "10.4.20.12",
            },
        )
        safe["static_dns"] = {"findings": [{"hostname": "pleiades.ygg.nu"}]}
        done = apply_actions(client, safe, CONTEXT, unattended=True)
        self.assertEqual(len(done), 2)
        self.assertEqual(client.events, ["static_create", "static_create"])
        with self.assertRaises(UnsafePlan):
            check_unattended_plan(report(*(safe["actions"] * 2)))

    def test_write_api_disallows_unknown_method(self):
        """Refuse DELETE and all unsupported HTTP method names."""
        client = CloudflareWriter("test-token")
        # pylint: disable=protected-access
        with self.assertRaises(ValueError):
            client._write("DELETE", "/accounts/a", {})
        # pylint: enable=protected-access

    def test_policy_links_are_ordered_and_unique(self):
        """Reusable policy references maintain explicit precedence."""
        self.assertEqual(policy_links([POLICY]), [{"id": POLICY, "precedence": 1}])
        with self.assertRaises(ValueError):
            policy_links([POLICY, POLICY])


if __name__ == "__main__":
    unittest.main()
