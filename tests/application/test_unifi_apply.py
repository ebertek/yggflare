"""Offline guards and journal recovery for UniFi create reconciliation."""

import io
import ipaddress
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

import cli
import metrics
import unifi_apply as apply
import web
from job_status import DNS_VERIFICATION_PENDING, JobPending, read_jobs, track
from mcp_server import InventoryTools
from unifi_reconcile_plan import TTL_SECONDS, LiveInputs

NAME = "pilot.example.invalid"
ADDRESS = "192.168.10.20"
FINGERPRINT = "a" * 64
SITE = str(UUID(int=1))
POLICY = str(UUID(int=2))
ENV = {"YGGFLARE_UNIFI_API_KEY_FILE": apply.UNIFI_KEY_FILE}
OPERATION = {
    "operation": "create",
    "type": "A_RECORD",
    "domain": NAME,
    "ipv4Address": ADDRESS,
    "enabled": True,
    "ttlSeconds": TTL_SECONDS,
}
RESPONSE = {
    "id": POLICY,
    **{key: value for key, value in OPERATION.items() if key != "operation"},
}
LIVE = LiveInputs(
    ("192.168.10.1", 443, "", "gateway.example.invalid"),
    SITE,
    "fixture-read-key",
    "fixture-cloudflare-token",
    "fixture-target",
    apply.policy_fingerprint([]),
    "fixture-state",
    {
        "rows": [{"hostname": NAME, "address": ADDRESS}],
        "source_zone": "example.invalid",
        "configured_lan": "192.168.10.0/24",
    },
)


class UniFiApplyTests(unittest.TestCase):
    def setUp(self):
        self.data = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.data / "unifi-ownership.json"
        self.enterContext(patch.dict(os.environ, ENV))
        self.enterContext(patch.object(apply, "DNS_VERIFICATION_ATTEMPTS", 1))
        self.load = self.enterContext(
            patch.object(apply, "load_live", return_value=LIVE)
        )
        self.review = self.enterContext(
            patch.object(
                apply,
                "review",
                return_value={"operations": [OPERATION], "fingerprint": FINGERPRINT},
            )
        )
        self.policies = self.enterContext(
            patch.object(apply, "all_rows", side_effect=[[], [RESPONSE]])
        )
        self.query = self.enterContext(
            patch.object(
                apply,
                "query",
                side_effect=[("answered", [ADDRESS]), ("answered", [NAME + "."])],
            )
        )
        self.post = self.enterContext(
            patch.object(apply, "create_policy", side_effect=self.acknowledge)
        )

    def acknowledge(self, live, key, operation):
        self.assertEqual(live, LIVE)
        self.assertEqual(key, LIVE.key)
        self.assertEqual(operation, OPERATION)
        journal = apply.load_ledger(self.path, LIVE.target)
        self.assertIsNone(journal["pending"]["policy_id"])
        self.assertEqual(journal["owned"], [])
        return POLICY

    def test_fresh_pilot_is_journaled_and_claimed_only_after_api_and_dns_match(self):
        self.assertIn("Created and verified", apply.run(self.data, NAME, FINGERPRINT))
        ledger = apply.load_ledger(self.path, LIVE.target)
        self.assertTrue(ledger["pilot_verified"])
        self.assertIsNone(ledger["pending"])
        self.assertEqual(ledger["owned"][0]["policy_id"], POLICY)
        self.assertNotIn(LIVE.key, self.path.read_text())
        self.post.assert_called_once()

    def test_lost_create_acknowledgement_blocks_retries(self):
        self.post.side_effect = TimeoutError
        with self.assertRaises(TimeoutError):
            apply.run(self.data, NAME, FINGERPRINT)
        self.assertIsNone(
            apply.load_ledger(self.path, LIVE.target)["pending"]["policy_id"]
        )
        with self.assertRaisesRegex(apply.ApplyError, "outcome is uncertain"):
            apply.run(self.data, NAME, FINGERPRINT)
        self.post.assert_called_once()

    def test_reused_policy_id_leaves_unacknowledged_intent(self):
        ledger = apply.load_ledger(self.path, LIVE.target)
        ledger["owned"] = [
            {
                "operation": {
                    **OPERATION,
                    "domain": "previous.example.invalid",
                    "ipv4Address": "192.168.10.19",
                },
                "policy_id": POLICY,
                "manual": True,
            }
        ]
        ledger["pilot_verified"] = True
        apply.write(self.path, ledger)
        self.post.side_effect = None
        self.post.return_value = POLICY
        with self.assertRaisesRegex(apply.ApplyError, "reused policy identity"):
            apply.run(self.data, NAME, FINGERPRINT)
        saved = apply.load_ledger(self.path, LIVE.target)
        self.assertEqual(saved["owned"], ledger["owned"])
        self.assertIsNone(saved["pending"]["policy_id"])
        with self.assertRaisesRegex(apply.ApplyError, "outcome is uncertain"):
            apply.run(self.data, NAME, FINGERPRINT)
        self.post.assert_called_once()
        self.query.assert_not_called()

    def test_new_id_cannot_reuse_unmanaged_policy(self):
        with self.assertRaisesRegex(apply.ApplyError, "reused policy identity"):
            apply.check_new_policy_id(POLICY, {"owned": []}, [RESPONSE])

    def test_recovery_requires_saved_policy_id_and_current_dns(self):
        self.query.side_effect = [
            ("answered", [ADDRESS]),
            ("nxdomain", []),
            ("answered", [ADDRESS]),
            ("answered", [NAME + "."]),
        ]
        self.policies.side_effect = [[], [RESPONSE], [RESPONSE]]
        with self.assertRaisesRegex(apply.DNSVerificationPending, "awaiting matching"):
            apply.run(self.data, NAME, FINGERPRINT)
        ledger = apply.load_ledger(self.path, LIVE.target)
        self.assertEqual(ledger["pending"]["policy_id"], POLICY)
        self.assertEqual(ledger["owned"], [])
        self.assertIn("Recovered", apply.run(self.data, NAME, FINGERPRINT))
        self.assertTrue(apply.load_ledger(self.path, LIVE.target)["pilot_verified"])
        self.post.assert_called_once()

    def test_bounded_retries_verify_without_reposting(self):
        self.policies.side_effect = [[], [RESPONSE], [RESPONSE], [RESPONSE]]
        self.query.side_effect = [
            ("answered", [ADDRESS]),
            ("nxdomain", []),
            ("answered", [ADDRESS]),
            ("nodata", []),
            ("answered", [ADDRESS]),
            ("answered", [NAME + "."]),
        ]
        with (
            patch.object(apply, "DNS_VERIFICATION_ATTEMPTS", 3),
            patch.object(apply.time, "sleep") as sleep,
        ):
            self.assertIn(
                "Created and verified", apply.run(self.data, NAME, FINGERPRINT)
            )
        self.assertEqual(sleep.call_count, 2)
        self.post.assert_called_once()
        self.assertIsNone(apply.load_ledger(self.path, LIVE.target)["pending"])

    def test_persisted_deadline_expires_without_reposting(self):
        self.query.side_effect = [("answered", [ADDRESS]), ("nxdomain", [])]
        with patch.object(apply.time, "time", return_value=1_800_000_000):
            with self.assertRaises(apply.DNSVerificationPending):
                apply.run(self.data, NAME, FINGERPRINT)
        entry = apply.load_ledger(self.path, LIVE.target)["pending"]
        self.assertEqual(entry["verification_deadline"], 1_800_000_600)
        with patch.object(apply.time, "time", return_value=1_800_000_600):
            with self.assertRaisesRegex(apply.ApplyError, "deadline expired"):
                apply.run(self.data, NAME, FINGERPRINT)
        self.assertEqual(apply.load_ledger(self.path, LIVE.target)["pending"], entry)
        self.post.assert_called_once()
        self.assertEqual(self.query.call_count, 2)

    def test_legacy_acknowledgement_gets_a_deadline_once(self):
        ledger = apply.load_ledger(self.path, LIVE.target)
        ledger["pending"] = {
            "operation": OPERATION,
            "policy_id": POLICY,
            "manual": True,
        }
        apply.write(self.path, ledger)
        self.policies.side_effect = [[RESPONSE], [RESPONSE]]
        self.query.side_effect = [("answered", [ADDRESS]), ("nxdomain", [])] * 2
        for now in (1_800_000_000, 1_800_000_300):
            with patch.object(apply.time, "time", return_value=now):
                with self.assertRaises(apply.DNSVerificationPending):
                    apply.run(self.data, NAME, FINGERPRINT)
            saved = apply.load_ledger(self.path, LIVE.target)
            self.assertEqual(saved["pending"]["verification_deadline"], 1_800_000_600)
        self.post.assert_not_called()

    def test_conflict_or_nontransient_error_is_failure_not_propagation(self):
        for reply, message in (
            (("answered", ["wrong.example.invalid."]), "conflicting"),
            (("unexpected_answer", []), "conflicting"),
            (("refused", []), "PTR: refused"),
            (("query_error", []), "PTR: query_error"),
            (("formerr", []), "PTR: formerr"),
        ):
            with self.subTest(reply=reply):
                self.policies.side_effect = [[], [RESPONSE]]
                self.query.side_effect = [("answered", [ADDRESS]), reply]
                self.post.reset_mock()
                journal = self.data / "unifi-ownership.json"
                journal.unlink(missing_ok=True)
                with self.assertRaisesRegex(apply.ApplyError, message) as raised:
                    apply.run(self.data, NAME, FINGERPRINT)
                self.assertNotIsInstance(raised.exception, apply.DNSVerificationPending)
                self.post.assert_called_once()
                self.assertIsNotNone(
                    apply.load_ledger(self.path, LIVE.target)["pending"]
                )

    def test_transient_errors_remain_pending_and_recover_without_reposting(self):
        for status in sorted(apply.TRANSIENT_DNS_FAILURES):
            with self.subTest(status=status):
                self.path.unlink(missing_ok=True)
                self.post.reset_mock()
                self.policies.side_effect = [[], [RESPONSE], [RESPONSE]]
                self.query.side_effect = [
                    (status, []),
                    ("answered", [NAME + "."]),
                    ("answered", [ADDRESS]),
                    ("answered", [NAME + "."]),
                ]
                with redirect_stdout(io.StringIO()) as output:
                    with self.assertRaises(apply.DNSVerificationPending):
                        apply.run(self.data, NAME, FINGERPRINT)
                self.assertIn(f"A: {status}", output.getvalue())
                journal = apply.load_ledger(self.path, LIVE.target)
                self.assertEqual(journal["owned"], [])
                self.assertEqual(journal["pending"]["policy_id"], POLICY)
                self.assertIn("Recovered", apply.run(self.data, NAME, FINGERPRINT))
                self.post.assert_called_once()

    def test_transient_error_does_not_mask_conflicting_other_reply(self):
        self.query.side_effect = [
            ("timeout", []),
            ("answered", ["wrong.example.invalid."]),
        ]
        with redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(apply.ApplyError, "PTR: answered") as error:
                apply.run(self.data, NAME, FINGERPRINT)
        self.assertNotIsInstance(error.exception, apply.DNSVerificationPending)
        self.assertEqual(apply.load_ledger(self.path, LIVE.target)["owned"], [])
        self.post.assert_called_once()

    def test_transient_retry_respects_original_deadline(self):
        self.query.side_effect = [
            ("answered", [ADDRESS]),
            ("servfail", []),
        ]
        with (
            patch.object(apply.time, "time", return_value=1_800_000_000),
            redirect_stdout(io.StringIO()) as output,
        ):
            with self.assertRaises(apply.DNSVerificationPending):
                apply.run(self.data, NAME, FINGERPRINT)
        self.assertIn("PTR: servfail", output.getvalue())
        pending = apply.load_ledger(self.path, LIVE.target)["pending"]
        with patch.object(apply.time, "time", return_value=1_800_000_600):
            with self.assertRaisesRegex(apply.ApplyError, "deadline expired"):
                apply.run(self.data, NAME, FINGERPRINT)
        self.assertEqual(apply.load_ledger(self.path, LIVE.target)["pending"], pending)
        self.assertEqual(self.query.call_count, 2)
        self.post.assert_called_once()

    def test_manual_create_cannot_recover_different_hostname(self):
        ledger = apply.load_ledger(self.path, LIVE.target)
        ledger["pending"] = {
            "operation": OPERATION,
            "policy_id": POLICY,
            "manual": True,
        }
        apply.write(self.path, ledger)
        before = self.path.read_bytes()
        with self.assertRaisesRegex(apply.ApplyError, "Another pending operation"):
            apply.run(self.data, "other.example.invalid", FINGERPRINT)
        self.assertEqual(self.path.read_bytes(), before)
        self.query.assert_not_called()
        self.policies.assert_not_called()
        self.post.assert_not_called()

    def test_pending_policy_must_remain_in_current_scope(self):
        for lan, zone in (
            ("192.168.11.0/24", "example.invalid"),
            ("192.168.10.20/30", "example.invalid"),
            ("192.168.10.0/24", "different.invalid"),
        ):
            with self.subTest(lan=lan, zone=zone):
                ledger = apply.load_ledger(self.path, LIVE.target)
                ledger["pending"] = {
                    "operation": OPERATION,
                    "policy_id": POLICY,
                    "manual": True,
                }
                apply.write(self.path, ledger)
                before = self.path.read_bytes()
                self.load.return_value = replace(
                    LIVE,
                    comparison={
                        **LIVE.comparison,
                        "configured_lan": lan,
                        "source_zone": zone,
                    },
                )
                with self.assertRaisesRegex(apply.ApplyError, "outside current scope"):
                    apply.run(self.data, NAME, FINGERPRINT)
                self.assertEqual(self.path.read_bytes(), before)
        self.query.assert_not_called()
        self.policies.assert_not_called()
        self.post.assert_not_called()

    def test_pending_is_reported_separately_by_jobs_and_metrics(self):
        with track(self.data, "unifi_apply", self.fail):
            pass
        previous = read_jobs(self.data)["jobs"]["unifi_apply"]["last_success_at"]
        with track(self.data, "unifi_apply", self.fail):
            raise JobPending()
        document = read_jobs(self.data)
        job = document["jobs"]["unifi_apply"]
        self.assertEqual(job["status"], DNS_VERIFICATION_PENDING)
        self.assertEqual(job["last_success_at"], previous)
        self.assertEqual(job["history"][-1]["status"], DNS_VERIFICATION_PENDING)
        tools = InventoryTools(lambda: {"job_status": document})
        jobs = tools.get_job_status()["jobs"]
        self.assertEqual(
            next(row for row in jobs if row["job"] == "unifi_apply")["status"],
            DNS_VERIFICATION_PENDING,
        )
        with (
            patch("mcp_server.InventoryTools", return_value=tools),
            redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(cli.main(["system", "jobs", "--json"]), 0)
        self.assertIn(DNS_VERIFICATION_PENDING, output.getvalue())
        self.assertIn(
            DNS_VERIFICATION_PENDING,
            web.render("operations", {"job_status": document}, {"view": ["jobs"]}),
        )
        scrape = metrics.render(self.data, self.data).decode()
        self.assertIn("yggflare_job_unifi_apply_pending_dns_verification 1", scrape)
        self.assertNotIn("yggflare_job_unifi_apply_last_attempt_success", scrape)

    def test_stale_fingerprint_or_changed_live_inputs_block_create(self):
        with self.assertRaisesRegex(apply.ApplyError, "Live preview changed"):
            apply.run(self.data, NAME, "b" * 64)
        self.load.side_effect = [LIVE, replace(LIVE, inputs="changed")]
        with self.assertRaisesRegex(apply.ApplyError, "inputs changed"):
            apply.run(self.data, NAME, FINGERPRINT)
        self.assertFalse(self.path.exists())
        self.post.assert_not_called()

    def test_automatic_requires_explicit_scope_and_verified_manual_pilot(self):
        with patch.dict(os.environ, {"YGGFLARE_UNIFI_AUTO_APPLY": "false"}):
            with self.assertRaisesRegex(apply.ApplyError, "disabled"):
                apply.run(self.data, automatic=True)
        with patch.dict(
            os.environ,
            {
                "YGGFLARE_UNIFI_AUTO_APPLY": "true",
            },
        ):
            with self.assertRaisesRegex(apply.ApplyError, "manual pilot"):
                apply.run(self.data, automatic=True)
        self.post.assert_not_called()

    def test_automatic_creates_only_one_declared_unowned_name(self):
        existing = {
            **OPERATION,
            "domain": "previous.example.invalid",
            "ipv4Address": "192.168.10.19",
        }
        other = {"hostname": "other.example.invalid", "address": "192.168.10.21"}
        live = replace(
            LIVE,
            comparison={
                **LIVE.comparison,
                "rows": [*LIVE.comparison["rows"], other],
            },
        )
        self.load.return_value = live
        ledger = apply.load_ledger(self.path, live.target)
        ledger["owned"].append(
            {
                "operation": existing,
                "policy_id": str(UUID(int=3)),
                "manual": True,
            }
        )
        ledger["pilot_verified"] = True
        apply.write(self.path, ledger)
        self.post.side_effect = None
        self.post.return_value = POLICY
        with (
            patch.object(apply, "automatic_targets", return_value={(NAME, ADDRESS)}),
            patch.dict(
                os.environ,
                {
                    "YGGFLARE_UNIFI_AUTO_APPLY": "true",
                },
            ),
        ):
            self.assertIn("Created and verified", apply.run(self.data, automatic=True))
        first_review = self.review.call_args_list[0].args[0]
        self.assertEqual(first_review.comparison["rows"], LIVE.comparison["rows"])
        self.post.assert_called_once()
        ledger = apply.load_ledger(self.path, live.target)
        self.assertEqual([entry["manual"] for entry in ledger["owned"]], [True, False])

    def test_concurrent_policy_conflict_blocks_ownership(self):
        conflict = {
            **RESPONSE,
            "id": str(UUID(int=3)),
            "domain": "other.example.invalid",
        }
        self.policies.side_effect = [[], [RESPONSE, conflict]]
        with self.assertRaisesRegex(apply.ApplyError, "conflicting policies"):
            apply.run(self.data, NAME, FINGERPRINT)
        ledger = apply.load_ledger(self.path, LIVE.target)
        self.assertEqual(ledger["pending"]["policy_id"], POLICY)
        self.assertEqual(ledger["owned"], [])
        self.post.assert_called_once()
        self.query.assert_not_called()

    def test_create_requires_the_existing_compose_secret_mount(self):
        with patch.dict(os.environ, {"YGGFLARE_UNIFI_API_KEY_FILE": ""}):
            with self.assertRaisesRegex(
                apply.ApplyError, "existing read-only Compose secret"
            ):
                apply.run(self.data, NAME, FINGERPRINT)
        self.post.assert_not_called()
        self.assertFalse(self.path.exists())

    def test_exact_declarations_exclude_runtime_only_and_ambiguous_addresses(self):
        zone = "example.invalid"
        docker_range = ipaddress.IPv4Network("192.168.10.0/24")
        services = [
            {"Name": "a/app", "Hostname": "configured", "IPv4Addresses": [ADDRESS]},
            {"Name": "a/runtime-only"},
            {"Name": "a/first", "IPv4Addresses": ["192.168.10.30"]},
            {"Name": "a/second", "IPv4Addresses": ["192.168.10.30"]},
            {"Name": "a/outside", "IPv4Addresses": ["192.168.11.20"]},
        ]
        self.assertEqual(
            apply.declared_targets(
                services,
                {"printer.example.invalid": "192.168.11.10"},
                zone,
                docker_range,
            ),
            {
                ("configured.example.invalid", ADDRESS),
                ("printer.example.invalid", "192.168.11.10"),
            },
        )

    def test_addressless_short_name_does_not_block_unique_lan_declaration(self):
        zone = "example.invalid"
        net = ipaddress.IPv4Network("192.168.10.0/24")
        name = "alloy.example.invalid"
        target = (name, ADDRESS)
        services = [
            {"Name": "main/alloy", "Hostname": "alloy", "IPv4Addresses": [ADDRESS]},
            {"Name": "remote/alloy", "Hostname": "alloy", "IPv4Addresses": []},
            {"Name": "another/alloy", "Hostname": "alloy"},
            {"Name": "main/cloudflared", "Hostname": "cloudflared"},
        ]
        self.assertEqual(apply.declared_targets(services, {}, zone, net), {target})
        for duplicate in (
            {"Hostname": "alloy", "IPv4Addresses": [ADDRESS]},
            {"Hostname": "alloy", "IPv4Addresses": ["192.168.10.21"]},
            {"Hostname": "alloy", "IPv4Addresses": ["192.168.11.20"]},
            {"Hostname": "alloy", "IPv4Addresses": ["${UNRESOLVED}"]},
            {"Hostname": "alloy", "IPv4Addresses": [None]},
            {"Hostname": name, "IPv4Addresses": []},
            {"Hostname": "other", "IPv4Addresses": [ADDRESS]},
        ):
            with self.subTest(duplicate=duplicate):
                self.assertNotIn(
                    target,
                    apply.declared_targets(
                        services + [{"Name": "conflict/app", **duplicate}],
                        {},
                        zone,
                        net,
                    ),
                )
        self.assertNotIn(
            target, apply.declared_targets(services, {name: ADDRESS}, zone, net)
        )

    def test_addressless_duplicates_from_compose_source(self):
        from cloudflare_desired import compose_inventory

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for project, address in (("primary", ADDRESS), ("remote", None)):
                directory = root / project
                directory.mkdir()
                network = (
                    f"    networks:\n      lan:\n        ipv4_address: {address}\n"
                    if address
                    else ""
                )
                (directory / "compose.yaml").write_text(
                    "services:\n  alloy:\n    hostname: alloy\n" + network
                )
            self.assertEqual(
                apply.declared_targets(
                    compose_inventory(root),
                    {},
                    "example.invalid",
                    ipaddress.IPv4Network("192.168.10.0/24"),
                ),
                {("alloy.example.invalid", ADDRESS)},
            )
            (root / "remote" / "compose.yaml").write_text(
                "services:\n  alloy:\n    hostname: alloy\n"
                "    networks:\n      lan:\n        ipv4_address: null\n"
            )
            with self.assertRaisesRegex(ValueError, "Invalid static IPv4 declaration"):
                compose_inventory(root)

    def test_discord_notice_uses_compact_success_embed(self):
        webhook = "https://discord.com/api/webhooks/123456789012345678/fixture-token"
        with (
            patch.object(apply, "read_webhook", return_value=webhook),
            patch.object(apply.http.client, "HTTPSConnection") as connect,
        ):
            conn = connect.return_value
            conn.getresponse.return_value.status = 204
            self.assertTrue(apply.discord_notice(OPERATION))
            connect.assert_called_once_with("discord.com", timeout=10)
            args, kwargs = conn.request.call_args
            self.assertEqual(
                args, ("POST", "/api/webhooks/123456789012345678/fixture-token")
            )
            self.assertEqual(
                json.loads(kwargs["body"]),
                {
                    "allowed_mentions": {"parse": []},
                    "embeds": [
                        {
                            "title": "✅ UniFi DNS created",
                            "description": (
                                f"`{NAME}` → `{ADDRESS}`\n"
                                f"A & PTR verified · TTL {TTL_SECONDS}s"
                            ),
                            "color": 3066993,
                        }
                    ],
                },
            )
            conn.request.assert_called_once()
            conn.close.assert_called_once()

    def test_notice_waits_for_recovery_and_is_submitted_once(self):
        self.query.side_effect = [
            ("answered", [ADDRESS]),
            ("nxdomain", []),
            ("answered", [ADDRESS]),
            ("answered", [NAME + "."]),
        ]
        self.policies.side_effect = [[], [RESPONSE], [RESPONSE]]

        def notice(operation):
            entry = apply.load_ledger(self.path, LIVE.target)["owned"][0]
            self.assertEqual(entry["notice"], "attempted")
            self.assertEqual(operation, OPERATION)
            return True

        with (
            patch.dict(os.environ, {"YGGFLARE_UNIFI_DISCORD_NOTIFY": "true"}),
            patch.object(apply, "discord_notice", side_effect=notice) as send,
        ):
            with self.assertRaisesRegex(
                apply.DNSVerificationPending, "awaiting matching"
            ):
                apply.run(self.data, NAME, FINGERPRINT)
            send.assert_not_called()
            self.assertIn("Recovered", apply.run(self.data, NAME, FINGERPRINT))
            ledger = apply.load_ledger(self.path, LIVE.target)
            self.assertEqual(ledger["owned"][0]["notice"], "accepted")
            apply.deliver_notice(self.path, ledger)
            send.assert_called_once_with(OPERATION)
            self.post.assert_called_once()

    def test_lost_discord_response_does_not_replay_or_clear_ownership(self):
        with (
            patch.dict(os.environ, {"YGGFLARE_UNIFI_DISCORD_NOTIFY": "true"}),
            patch.object(apply, "discord_notice", side_effect=TimeoutError) as send,
        ):
            self.assertIn(
                "Created and verified", apply.run(self.data, NAME, FINGERPRINT)
            )
            ledger = apply.load_ledger(self.path, LIVE.target)
            self.assertEqual(ledger["owned"][0]["notice"], "unconfirmed")
            self.assertIsNone(ledger["pending"])
            apply.deliver_notice(self.path, ledger)
            send.assert_called_once()

    def test_transport_sends_one_fixed_post_and_verifies_acknowledgement(self):
        with patch.object(apply, "connection") as connect:
            conn = connect.return_value
            response = conn.getresponse.return_value
            response.status = 201
            response.read.return_value = json.dumps(RESPONSE).encode()
            original_create = CREATE_POLICY
            self.assertEqual(original_create(LIVE, LIVE.key, OPERATION), POLICY)
            args, kwargs = conn.request.call_args
            self.assertEqual(
                args, ("POST", f"{apply.PREFIX}/sites/{SITE}/dns/policies")
            )
            self.assertEqual(
                json.loads(kwargs["body"]),
                {k: RESPONSE[k] for k in RESPONSE if k != "id"},
            )
            conn.request.assert_called_once()
            response.status = 302
            with self.assertRaises(ValueError):
                original_create(LIVE, LIVE.key, OPERATION)


CREATE_POLICY = apply.create_policy
