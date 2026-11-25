"""Regression tests for the read-only MCP interface."""

import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from mcp import Client, StdioServerParameters

from job_status import artifact_status, read_jobs, track
from mcp_server import TOOL_NAMES, InventoryTools, build_server


def fixture():
    return {
        "scanned_at": "2026-11-24T05:15:00Z",
        "hosts": [
            {
                "hostname": "example.internal",
                "ipv4": "192.0.2.10",
                "mac": "02:00:00:00:00:10",
                "aliases": ["example.invalid"],
                "device_class": "docker",
                "status": "docker running",
                "description": "private notes",
                "secret": "never-export",
            },
            {
                "hostname": "",
                "ipv4": "192.0.2.11",
                "status": "unmanaged",
            },
        ],
        "diffs": [
            {
                "ipv4": "192.0.2.11",
                "field": "MAC",
                "severity": "drift",
                "observed": "example",
            }
        ],
        "network_state": {
            "initialized": True,
            "identity_history": {
                "example": {
                    "label": "example",
                    "addresses": ["192.0.2.10"],
                    "confidence": "high",
                    "note": "private notes",
                }
            },
            "recent_events": [
                {"observed_at": "first", "message": "older"},
                {"observed_at": "second", "message": "newer"},
            ],
            "pending_discord_events": [{"secret": "never-export"}],
        },
        "cloudflare_view": {
            "audited_at": "2026-11-24T06:00:00Z",
            "hosts": [
                {
                    "hostname": "example.invalid",
                    "declared": True,
                    "claimed": True,
                    "lifecycle": "managed",
                    "tunnel_routes": 1,
                    "access_app_ids": ["private-app-id"],
                    "dns_record_ids": ["private-dns-id"],
                }
            ],
        },
        "cloudflare_view_status": {
            "ok": True,
            "attempted_at": "2026-11-24T06:00:00Z",
        },
    }


class InventoryToolTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture()
        self.tools = InventoryTools(lambda: self.data)

    def test_nonfinite_projection_and_cross_group_scopes(self):
        from mcp_server import GROUPS, REQUIRED_GROUPS, enabled_tools, project

        self.assertEqual(
            project({"number": float("nan")}, ("number",)), {"number": None}
        )
        self.assertEqual(
            project({"number": float("inf")}, ("number",)), {"number": None}
        )
        for group in GROUPS:
            enabled = set(enabled_tools({"YGGFLARE_MCP_TOOL_GROUPS": group}))
            self.assertEqual(
                enabled,
                {
                    name
                    for name, required in REQUIRED_GROUPS.items()
                    if required <= {group}
                },
            )
            self.assertNotIn("get_ingress_evidence", enabled)
            self.assertNotIn("get_monitoring_coverage", enabled)
        self.assertIn(
            "get_monitoring_coverage",
            enabled_tools({"YGGFLARE_MCP_TOOL_GROUPS": "inventory,kuma"}),
        )

    def test_filter_and_pagination(self):
        first = self.tools.list_devices(limit=1)
        self.assertEqual(first["total"], 2)
        self.assertEqual(first["next_offset"], 1)
        second = self.tools.list_devices(offset=1, limit=1)
        self.assertIsNone(second["next_offset"])
        self.assertEqual(second["items"][0]["ipv4"], "192.0.2.11")
        self.assertEqual(self.tools.list_devices(unknown_only=True)["total"], 1)
        self.assertEqual(self.tools.list_devices(query="EXAMPLE")["total"], 1)
        for offset, limit in ((-1, 1), (0, 0), (0, 51)):
            with self.assertRaises(ValueError):
                self.tools.list_devices(offset=offset, limit=limit)

    def test_identity_and_projection(self):
        before = deepcopy(self.data)
        result = self.tools.get_device("EXAMPLE.INVALID")
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["identities"]["total"], 1)
        self.assertNotIn("private notes", str(result))
        self.assertNotIn("never-export", str(result))
        self.assertEqual(self.data, before)
        self.assertEqual(self.tools.get_device("missing")["total"], 0)
        with self.assertRaises(ValueError):
            self.tools.get_device("")

    def test_expected_shared_namespace_and_ambiguous_lookup(self):
        parent = self.data["hosts"][0]
        parent.update(
            network_owner="vpn", address_relationship="expected_shared_namespace"
        )
        child = {
            **parent,
            "hostname": "child.internal",
            "shared_network": "vpn",
        }
        self.data["hosts"].append(child)
        result = self.tools.get_device(parent["ipv4"])
        self.assertEqual(result["total"], 2)
        self.assertFalse(result["ambiguous"])
        self.assertEqual(result["lookup_relationship"], "expected_shared_namespace")
        self.assertEqual(result["items"][1]["shared_network"], "vpn")
        child["address_relationship"] = "ambiguous"
        self.assertTrue(self.tools.get_device(parent["ipv4"])["ambiguous"])

    def test_drift_severity_counts_and_historical_findings(self):
        self.data["diffs"].append({"severity": "unknown", "field": "Presence"})
        self.assertEqual(self.tools.get_inventory_drift(severity="drift")["total"], 1)
        unknown = self.tools.get_inventory_drift(severity="unknown")
        self.assertEqual(unknown["total"], 1)
        self.assertEqual(unknown["observed_discrepancies"], 1)
        self.assertEqual(unknown["inconclusive_observations"], 1)
        with self.assertRaises(ValueError):
            self.tools.get_inventory_drift(severity="high")
        self.data["network_state"]["reported"] = {"key": "newer"}
        events = self.tools.get_discovery_changes()["items"]
        self.assertEqual(
            events[0]["finding_status"], "present_in_latest_reported_findings"
        )
        self.assertEqual(
            events[1]["finding_status"], "historical_not_confirmed_current"
        )
        lifecycle = self.tools.get_cloudflare_lifecycle()
        self.assertEqual(lifecycle["ownership_counts"]["managed"], 1)
        self.assertIn("not evidence of configuration drift", lifecycle["caveat"])

    def test_drift_and_events(self):
        self.assertEqual(self.tools.get_inventory_drift()["total"], 1)
        events = self.tools.get_discovery_changes()
        self.assertEqual(events["items"][0]["message"], "newer")
        self.assertNotIn("never-export", str(events))

    def test_cloudflare_scope_and_freshness(self):
        lifecycle = self.tools.get_cloudflare_lifecycle()
        self.assertTrue(lifecycle["last_refresh_verified"])
        self.assertEqual(lifecycle["items"][0]["access_app_count"], 1)
        self.assertNotIn("private-app-id", str(lifecycle))
        self.assertNotIn("private-dns-id", str(lifecycle))
        self.assertEqual(
            self.tools.get_service_exposure("example.internal")["items"][0][
                "cloudflare_hosts"
            ][0]["hostname"],
            "example.invalid",
        )
        self.data["cloudflare_view_status"]["ok"] = False
        self.assertFalse(self.tools.get_cloudflare_lifecycle()["last_refresh_verified"])

    def test_missing_observations(self):
        status = InventoryTools(lambda: {}).get_inventory_status()
        self.assertFalse(status["scan_initialized"])
        self.assertIsNone(status["scanned_at"])
        self.assertFalse(status["cloudflare"]["last_refresh_verified"])

    def test_extended_evidence_and_secret_projection(self):
        state = self.data["network_state"]
        state["supplemental"] = {
            "observed_at": "sample",
            "records": [
                {
                    "ip": "",
                    "source": "IPv6 router advertisement",
                    "detail": "prefix",
                    "secret": "never-export",
                },
                {"ip": "192.0.2.10", "source": "ARP reply", "detail": "mac"},
            ],
        }
        state["identity_conflicts"] = [
            {
                "address": "192.0.2.10",
                "macs": ["one", "two"],
                "reasons": ["conflict"],
                "secret": "never-export",
            }
        ]
        state["identity_history"]["example"]["macs"] = ["02:00:00:00:00:10"]
        state["identity_changes"] = [{"identity": "example", "kind": "first-observed"}]
        state["hosts"] = {
            "192.0.2.10": {
                "ports": ["tcp/80"],
                "services": {"tcp/80": {"name": "http", "secret": "never-export"}},
            }
        }
        state["advertisements"] = ["example.local|_http._tcp|80"]
        state["alert_pending_confirmations"] = ["candidate"]
        self.assertEqual(
            self.tools.get_discovery_status()["supplemental_source_counts"][
                "ARP reply"
            ],
            1,
        )
        self.assertEqual(
            self.tools.get_discovery_evidence(source="ARP reply")["total"], 1
        )
        self.assertNotIn("never-export", str(self.tools.get_discovery_evidence()))
        self.assertNotIn("never-export", str(self.tools.get_identity_conflicts()))
        self.assertEqual(self.tools.get_device_history("02:00:00:00:00:10")["total"], 1)
        self.assertEqual(self.tools.get_identity_changes("example")["total"], 1)
        services = self.tools.list_network_services()
        self.assertEqual([r["source"] for r in services["items"]], ["nmap", "dns_sd"])
        self.assertNotIn("never-export", str(services))
        self.assertEqual(self.tools.get_pending_network_findings()["total"], 1)

    def test_audit_missing_and_filtered(self):
        self.assertFalse(self.tools.get_cloudflare_audit()["audit_available"])
        self.data["cloudflare_view"]["audit"] = {
            "version": 1,
            "total_findings": 2,
            "truncated": False,
            "findings": [
                {
                    "section": "blocked",
                    "hostname": "example.invalid",
                    "reason": "multiple Access apps",
                    "secret": "never-export",
                },
                {
                    "section": "proposed",
                    "hostname": "other.invalid",
                    "kind": "create_dns_cname",
                },
            ],
        }
        result = self.tools.get_cloudflare_audit(section="blocked")
        self.assertTrue(result["audit_available"])
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["snapshot_total_findings"], 2)
        self.assertNotIn("never-export", str(result))
        with self.assertRaises(ValueError):
            self.tools.get_cloudflare_audit(section="unknown")

    def test_cloudflare_configuration_and_saved_findings(self):
        self.assertFalse(self.tools.get_cloudflare_access()["configuration_available"])
        self.data["cloudflare_view"]["configuration"] = {
            "version": 1,
            "internal_dns_collected": True,
            "access": {
                "total": 1,
                "items": [
                    {
                        "hostname": "example.invalid",
                        "status": "matched",
                        "observed_decisions": ["allow", "deny"],
                        "secret": "never-export",
                    }
                ],
            },
            "dns": {
                "total": 1,
                "items": [
                    {
                        "hostname": "example.invalid",
                        "type": "TXT",
                        "content": "never-export",
                    }
                ],
            },
            "tunnel": {
                "total": 1,
                "items": [
                    {
                        "hostname": "example.invalid",
                        "origin_host": "origin.invalid",
                        "secret": "never-export",
                    }
                ],
            },
        }
        access = self.tools.get_cloudflare_access("example.invalid")
        self.assertEqual(access["items"][0]["observed_decisions"], ["allow", "deny"])
        self.assertNotIn("never-export", str(access))
        self.assertNotIn("never-export", str(self.tools.get_cloudflare_dns()))
        self.assertNotIn("never-export", str(self.tools.get_cloudflare_tunnel()))
        self.data["network_state"]["reported"] = {"new-port:192.0.2.10:tcp/80": "new"}
        self.assertEqual(
            self.tools.get_network_findings()["items"][0]["finding_id"],
            "new-port:192.0.2.10:tcp/80",
        )

    def test_dns_sd_address_filter(self):
        self.data["network_state"]["advertisement_details"] = [
            {
                "host": "example.local",
                "service": "_http._tcp",
                "port": 80,
                "addresses": ["192.0.2.10"],
                "txt": "never-export",
            }
        ]
        result = self.tools.list_network_services(address="192.0.2.10")
        self.assertEqual(result["total"], 1)
        self.assertNotIn("never-export", str(result))

    def test_operational_status(self):
        self.assertFalse(self.tools.get_job_status()["available"])
        self.data["job_status"] = {
            "version": 1,
            "jobs": {
                "backup": {
                    "status": "succeeded",
                    "last_success_at": "sample",
                    "history": [
                        {
                            "status": "succeeded",
                            "started_at": "sample",
                            "secret": "never-export",
                        }
                    ],
                }
            },
        }
        self.assertTrue(self.tools.get_job_status()["available"])
        self.assertEqual(self.tools.get_job_history("backup")["total"], 1)
        self.assertNotIn("never-export", str(self.tools.get_job_history()))
        self.assertIsNone(
            self.tools.get_notification_status()["recipient_receipt_verified"]
        )

    def test_scheduler_evidence_and_archive_metadata(self):
        with tempfile.TemporaryDirectory() as folder:
            data = Path(folder)
            self.assertIsNone(read_jobs(data))
            with track(data, "backup", self.fail):
                self.assertEqual(
                    read_jobs(data)["jobs"]["backup"]["status"], "completion_unknown"
                )
            success = read_jobs(data)["jobs"]["backup"]["last_success_at"]
            with self.assertRaisesRegex(RuntimeError, "SECRET"):
                with track(data, "backup", self.fail):
                    raise RuntimeError("SECRET")
            row = read_jobs(data)["jobs"]["backup"]
            self.assertEqual(row["status"], "failed")
            self.assertEqual(row["last_success_at"], success)
            self.assertNotIn("SECRET", str(row))
            for _ in range(25):
                with track(data, "backup", self.fail):
                    pass
            self.assertEqual(len(read_jobs(data)["jobs"]["backup"]["history"]), 20)
            (data / "yggflare-20260101T000000Z.tar.gz").write_bytes(b"test")
            (data / "yggflare-20260102T000000Z.tar.gz").symlink_to("/etc/passwd")
            result = artifact_status(data)
            self.assertEqual(result["archive_count"], 1)
            self.assertEqual(result["latest"]["bytes"], 4)

    def test_service_topology_and_ingress_are_scoped(self):
        self.tools.service_loader = lambda: {
            "runtime_available": True,
            "compose_complete": True,
            "items": [
                {
                    "project": "local",
                    "service": "dns",
                    "container_name": "dns",
                    "aliases": ["example.invalid"],
                    "declared_dependencies": ["db"],
                    "image_reference_match": False,
                    "secret": "never-export",
                },
                {"project": "remote", "service": "dns", "container_name": "dns"},
            ],
        }
        self.assertTrue(self.tools.get_docker_service("dns")["ambiguous"])
        self.assertEqual(self.tools.get_docker_service("dns", "local")["total"], 1)
        self.assertEqual(self.tools.get_compose_drift()["total"], 1)
        self.assertEqual(
            self.tools.get_service_dependencies("dns", "local")["items"][0][
                "declared_dependencies"
            ],
            ["db"],
        )
        path = self.tools.get_ingress_path("example.invalid")
        self.assertEqual(path["total"], 1)
        self.assertIsNone(path["reachability_verified"])
        self.assertNotIn("never-export", str(path))

    def test_topology_and_snapshot_pagination(self):
        rows = [
            {
                "project": "core",
                "service": "a",
                "declared_networks": ["lan"],
                "runtime_networks": ["core_lan"],
            },
            {"project": "core", "service": "b", "shared_network": "a"},
        ]
        self.tools.service_loader = lambda: {"items": rows}
        first = self.tools.list_docker_services(limit=1)
        second = self.tools.list_docker_services(
            offset=1, limit=1, snapshot_id=first["snapshot_id"]
        )
        self.assertEqual(second["items"][0]["service"], "b")
        self.assertEqual(self.tools.get_network_topology()["total"], 3)
        rows[0]["service"] = "changed"
        with self.assertRaises(ValueError):
            self.tools.list_docker_services(offset=1, snapshot_id=first["snapshot_id"])

    def test_ingress_filters_literal_hosts_before_pagination(self):
        rows = [
            {
                "kind": "routers",
                "protocol": "http",
                "name": f"example.invalid-{i}@docker",
                "literal_hosts": ["other.invalid"],
            }
            for i in range(60)
        ]
        rows.append(
            {
                "kind": "routers",
                "protocol": "http",
                "name": "real@docker",
                "literal_hosts": ["EXAMPLE.INVALID."],
            }
        )
        services = [
            {"project": "core", "service": "demo", "aliases": ["example.invalid"]}
        ]
        with (
            patch.object(
                self.tools, "service_loader", return_value={"items": services}
            ) as load,
            patch(
                "mcp_server.saved_traefik",
                return_value={"available": True, "items": rows},
            ),
        ):
            result = self.tools.get_ingress_evidence("EXAMPLE.INVALID.")
        load.assert_called_once()
        self.assertEqual(result["total"], 1)
        layer = result["layers"]["traefik"]
        self.assertEqual(layer["total"], 1)
        self.assertEqual(layer["items"][0]["name"], "real@docker")
        self.assertFalse(layer["page_truncated"])
        self.assertFalse(layer["source_truncated"])

    def test_traefik_saved_projection_and_ingress_correlation(self):
        self.tools.service_loader = lambda: {"items": []}
        row = {
            "kind": "routers",
            "protocol": "http",
            "name": "demo@docker",
            "literal_hosts": ["example.invalid"],
            "raw": "never-export",
        }
        with patch(
            "mcp_server.saved_traefik",
            side_effect=lambda _: {"available": True, "fresh": True, "items": [row]},
        ):
            result = self.tools.list_traefik_routes("example.invalid")
            self.assertEqual(result["total"], 1)
            self.assertNotIn("never-export", str(result))
            ingress = self.tools.get_ingress_path("example.invalid")
            self.assertEqual(ingress["layers"]["traefik"]["total"], 1)
            self.assertIsNone(ingress["reachability_verified"])
            self.assertIsNone(ingress["traefik_runtime_verified"])


class SupplementalCoverageTests(unittest.TestCase):
    def test_fixed_sources_and_validated_counts(self):
        from mcp_server import SUPPLEMENTAL_SOURCES, supplemental_coverage_context

        baseline = {
            "configured": False,
            "attempted": 0,
            "completed": 0,
            "failed": 0,
            "no_reply": 0,
            "parse_errors": 0,
        }
        sources = {name: dict(baseline) for name in SUPPLEMENTAL_SOURCES}
        sources["ndp"].update(configured=True, attempted=1, completed=1, no_reply=1)
        sources["smb"].update(configured=True, attempted=16, completed=16, limited=True)
        sources["ipv6_nmap"].update(configured=True)
        sources["private"] = {"token": "never-export"}
        coverage = supplemental_coverage_context(
            {"collector_evidence": {"version": 1, "sources": sources}}
        )
        self.assertTrue(coverage["available"])
        rows = {row["source"]: row for row in coverage["sources"]}
        self.assertEqual(rows["ndp"]["status"], "completed")
        self.assertEqual(rows["smb"]["status"], "partial_or_failed")
        self.assertEqual(rows["ipv6_nmap"]["status"], "not_attempted")
        self.assertEqual(rows["arp"]["status"], "not_configured")
        self.assertNotIn("never-export", str(coverage))
        sources["ndp"]["completed"] = 2
        self.assertFalse(
            supplemental_coverage_context(
                {"collector_evidence": {"version": 1, "sources": sources}}
            )["available"]
        )


class DiscoveryCoverageTests(unittest.TestCase):
    def test_old_offline_and_live_coverage(self):
        state = {}
        tools = InventoryTools(lambda: {"network_state": state})
        self.assertFalse(tools.get_discovery_status()["scan_coverage"]["available"])
        state["scan_coverage"] = {"version": 1, "mode": "offline"}
        self.assertFalse(tools.get_discovery_status()["scan_coverage"]["available"])
        state["scan_coverage"] = {
            "version": 1,
            "mode": "live",
            "observed_at": "2026-01-01T00:00:00+00:00",
            "host_discovery": {"run_completed": True, "secret": "never-export"},
            "tcp": {
                "requested_target_count": 3,
                "omitted_target_count": 1,
                "run_completed": True,
            },
            "dns_sd": {"status": "empty_browse", "observation_count": 0},
        }
        result = tools.get_discovery_status()["scan_coverage"]
        self.assertTrue(result["available"])
        self.assertEqual(result["tcp"]["omitted_target_count"], 1)
        self.assertNotIn("never-export", str(result))
        row = next(
            item
            for item in tools.get_evidence_overview()["items"]
            if item["source"] == "network_ipv4"
        )
        self.assertEqual(row["completeness"], "incomplete")


class MonitorCorrelationTests(unittest.TestCase):
    def test_device_port_evidence_distinguishes_selection_from_observation(self):
        from mcp_server import device_port_evidence

        stamp = "2026-11-25T09:00:00Z"
        data = {
            "network_state": {
                "scanned_at": stamp,
                "scan_coverage": {
                    "version": 1,
                    "mode": "live",
                    "observed_at": stamp,
                    "tcp": {"selected_port_count": 2, "selected_ports": [22, 443]},
                },
            }
        }
        device = {
            "ipv4": "192.0.2.1",
            "ipv6": "2001:db8::1",
            "observed_ports": ["tcp/22"],
            "last_seen": stamp,
        }
        for address, port, selected, observed, evidence in (
            ("192.0.2.1", 22, True, True, "observed_open"),
            ("192.0.2.1", 443, True, None, "selected_not_observed"),
            ("192.0.2.1", 38050, False, None, "not_selected_in_primary_scan"),
            ("2001:db8::1", 22, None, None, "unknown"),
        ):
            with self.subTest(address=address, port=port):
                match = device_port_evidence(
                    data, device, address, {"target_port": port, "target_scheme": "tcp"}
                )
                self.assertIs(match["target_port_selected"], selected)
                self.assertIs(match["target_port_observed"], observed)
                self.assertEqual(match["target_port_evidence"], evidence)
        data["network_state"]["scan_coverage"]["tcp"].pop("selected_ports")
        match = device_port_evidence(
            data, device, "192.0.2.1", {"target_port": 443, "target_scheme": "tcp"}
        )
        self.assertIsNone(match["target_port_selected"])
        self.assertIsNone(match["target_port_observed"])

    def test_docker_name_ambiguity_and_network_address_candidates(self):
        services = [
            {"project": "a", "service": "worker", "container_name": "worker"},
            {"project": "b", "service": "worker", "container_name": "worker"},
        ]
        devices = [
            {
                "hostname": "device.invalid",
                "ipv4": "192.0.2.10",
                "observed_ports": ["tcp/1080"],
            },
            {"hostname": "other.invalid", "ipv4": "192.0.2.11"},
        ]
        monitors = [
            {"name": "worker", "monitor_type": "docker", "target_port": 443},
            {"name": "worker", "monitor_type": "group"},
            {
                "name": "device",
                "monitor_type": "port",
                "target_host": "192.0.2.10",
                "target_port": 1080,
                "target_scheme": "tcp",
            },
        ]
        tools = InventoryTools(lambda: {"hosts": devices}, lambda: {"items": services})
        with patch(
            "mcp_server.saved_integration",
            return_value={"available": True, "fresh": True, "items": monitors},
        ):
            coverage = tools.get_monitoring_coverage(project_name="a")
            match = coverage["items"][0]["monitor_matches"][0]
            self.assertEqual(match["service_candidates"], ["a/worker", "b/worker"])
            self.assertTrue(match["ambiguous_service_identity"])
            self.assertIsNone(match["target_port"])
            self.assertEqual(coverage["items"][0]["matching_monitor_count"], 1)
            coverage = tools.get_monitoring_coverage(scope="devices")
            match = coverage["items"][0]["monitor_matches"][0]
            self.assertTrue(match["target_port_observed"])
            self.assertEqual(match["device_candidates"], ["device.invalid"])
            self.assertEqual(coverage["items"][1]["matching_monitor_count"], 0)

    def test_exact_internal_alias_address_and_shared_port_evidence(self):
        services = [
            {
                "project": "core",
                "service": "demo",
                "hostname": "demo.internal",
                "aliases": ["demo.invalid", "alt.internal"],
                "declared_addresses": ["192.0.2.10"],
                "runtime_addresses": ["192.0.2.11"],
                "lan_endpoints": ["192.0.2.11"],
                "ports": ["tcp/8080"],
            },
            {
                "project": "other",
                "service": "shared",
                "lan_endpoints": ["192.0.2.11"],
                "shared_network": "vpn",
            },
        ]
        monitors = [
            {"name": "public", "target_host": "demo.invalid", "target_port": 443},
            {"name": "internal", "target_host": "DEMO.INTERNAL."},
            {"name": "alias", "target_host": "alt.internal"},
            {"name": "declared", "target_host": "192.0.2.10"},
            {
                "name": "shared",
                "target_host": "192.0.2.11",
                "target_port": 8080,
                "secret": "never-export",
            },
            {"name": "unrelated", "target_host": "demo.invalid.example"},
            {"name": "proxy", "target_host": "192.0.2.44"},
        ]
        tools = InventoryTools(lambda: {}, lambda: {"items": services})

        def saved(adapter, _path):
            return {
                "available": True,
                "fresh": True,
                "items": monitors if adapter == "kuma" else [],
            }

        with patch("mcp_server.saved_integration", side_effect=saved):
            ingress = tools.get_ingress_evidence("demo.invalid")
            coverage = tools.get_monitoring_coverage(project_name="core")
        matched = {item["name"]: item for item in ingress["layers"]["kuma"]["items"]}
        self.assertEqual(
            set(matched), {"public", "internal", "alias", "declared", "shared"}
        )
        self.assertIn("ingress_hostname", matched["public"]["match_basis"])
        self.assertIn("service_hostname", matched["internal"]["match_basis"])
        self.assertIn("declared_address", matched["declared"]["match_basis"])
        self.assertTrue(matched["shared"]["shared_or_ambiguous_address"])
        self.assertTrue(matched["shared"]["target_port_declared"])
        self.assertEqual(coverage["items"][0]["matching_monitor_count"], 5)
        self.assertEqual(len(coverage["items"][0]["monitor_matches"]), 5)
        self.assertNotIn("never-export", str(ingress))


class CrossSourceTests(unittest.TestCase):
    def test_exact_matches_and_source_metadata(self):
        tools = InventoryTools(
            lambda: {},
            lambda: {
                "items": [
                    {"project": "core", "service": "demo", "aliases": ["demo.invalid"]}
                ]
            },
        )

        def saved(adapter, path):
            rows = (
                [
                    {"kind": "stacks", "name": "core", "secret": "never-export"},
                    {"kind": "stacks", "name": "core-extra"},
                    {"kind": "stack_services", "stack": "core", "service": "demo"},
                    {"kind": "stack_services", "stack": "core", "service": "other"},
                ]
                if adapter == "komodo"
                else [
                    {"kind": "monitors", "target_host": "demo.invalid", "name": "Demo"},
                    {
                        "kind": "monitors",
                        "target_host": "demo.invalid.example",
                        "name": "Other",
                    },
                ]
            )
            return {"available": True, "fresh": True, "items": rows}

        with (
            patch("mcp_server.saved_integration", side_effect=saved),
            patch(
                "mcp_server.saved_probes",
                return_value={
                    "available": True,
                    "fresh": False,
                    "items": [
                        {
                            "hostname": "demo.invalid",
                            "check": "tcp",
                            "status": "connected",
                            "address": "192.0.2.1",
                        },
                        {
                            "hostname": "other.invalid",
                            "check": "tcp",
                            "status": "connected",
                        },
                    ],
                },
            ),
        ):
            result = tools.get_ingress_evidence("demo.invalid")
        self.assertEqual(result["layers"]["komodo"]["total"], 2)
        self.assertEqual(result["layers"]["kuma"]["total"], 1)
        self.assertEqual(result["layers"]["probes"]["total"], 1)
        self.assertFalse(result["integration_snapshots"]["probes"]["fresh"])
        self.assertIsNone(result["reachability_verified"])
        self.assertNotIn("never-export", str(result))


class MCPRegistrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_stdio_protocol_handshake(self):
        script = Path(__file__).resolve().parents[2] / "src" / "yggflare" / "mcp_server.py"
        parameters = StdioServerParameters(command=sys.executable, args=[str(script)])
        for mode in ("legacy", "auto"):
            with self.subTest(mode=mode):
                async with Client(parameters, mode=mode) as client:
                    result = await client.list_tools()
                    self.assertEqual(
                        {tool.name for tool in result.tools}, set(TOOL_NAMES)
                    )

    async def test_group_allowlist_applies_to_tools_resources_and_prompts(self):
        server = build_server(fixture, env={"YGGFLARE_MCP_TOOL_GROUPS": "operations"})
        async with Client(server, raise_exceptions=True) as client:
            tools = (await client.list_tools()).tools
            self.assertEqual(
                {tool.name for tool in tools},
                {
                    "get_job_status",
                    "get_job_history",
                    "get_backup_status",
                    "get_notification_status",
                },
            )
            resources = (await client.list_resources()).resources
            self.assertEqual(
                {str(item.uri) for item in resources},
                {"yggflare://schema", "yggflare://jobs"},
            )
            prompts = (await client.list_prompts()).prompts
            self.assertEqual({item.name for item in prompts}, {"review_operations"})
            result = await client.read_resource("yggflare://schema")
            self.assertIn("schema_version", result.contents[0].text)
            prompt = await client.get_prompt("review_operations")
            self.assertIn("recipient receipt", prompt.messages[0].content.text)
        with self.assertRaises(ValueError):
            build_server(fixture, env={"YGGFLARE_MCP_TOOL_GROUPS": "invented"})

    async def test_evidence_overview_has_typed_schema(self):
        server = build_server(fixture)
        async with Client(server, raise_exceptions=True) as client:
            tool = next(
                item
                for item in (await client.list_tools()).tools
                if item.name == "get_evidence_overview"
            )
            self.assertIn("items", tool.output_schema["properties"])
            result = await client.call_tool("get_evidence_overview", {})
            self.assertFalse(result.is_error)
            sources = result.structured_content["items"]
            self.assertEqual(len(sources), 10)
            self.assertIn("completeness", sources[0])
            self.assertEqual(result.structured_content["schema_version"], 1)

    async def test_paged_contracts_expose_fingerprint_and_preserve_context(self):
        server = build_server(fixture)
        async with Client(server, raise_exceptions=True) as client:
            for tool in (await client.list_tools()).tools:
                if "offset" not in tool.input_schema.get("properties", {}):
                    continue
                self.assertIn("snapshot_id", tool.input_schema["properties"], tool.name)
                self.assertTrue(
                    {
                        "schema_version",
                        "total",
                        "offset",
                        "next_offset",
                        "snapshot_id",
                        "items",
                    }
                    <= set(tool.output_schema["required"]),
                    tool.name,
                )
            result = await client.call_tool("list_devices", {"limit": 1})
            first = result.structured_content
            self.assertEqual(first["schema_version"], 1)
            self.assertIn("scan_initialized", first)
            second = await client.call_tool(
                "list_devices",
                {"offset": 1, "limit": 1, "snapshot_id": first["snapshot_id"]},
            )
            self.assertEqual(
                second.structured_content["snapshot_id"], first["snapshot_id"]
            )
        async with Client(server, raise_exceptions=False) as client:
            for tool_name, args in (
                ("list_devices", {}),
                ("get_cloudflare_access", {}),
                ("list_komodo_stacks", {}),
                ("list_probe_results", {}),
                ("get_service_dependencies", {"identifier": "example"}),
            ):
                with self.subTest(tool=tool_name):
                    result = await client.call_tool(
                        tool_name, {**args, "offset": 1, "snapshot_id": "incorrect"}
                    )
                    self.assertTrue(result.is_error)

    async def test_adapter_specific_row_schema_and_projection(self):
        server = build_server(fixture)
        async with Client(server, raise_exceptions=True) as client:
            tools = {item.name: item for item in (await client.list_tools()).tools}
            for tool_name, field in (
                ("list_traefik_routes", "literal_hosts"),
                ("list_komodo_stacks", "revision_match"),
                ("list_komodo_stacks", "tracked_stack_inputs"),
                ("list_kuma_monitors", "target_port"),
                ("list_probe_results", "tls_verified"),
                ("get_job_history", "duration_seconds"),
                ("get_monitoring_coverage", "matching_monitor_count"),
                ("list_finding_history", "observation_count"),
            ):
                schema = tools[tool_name].output_schema
                row = schema["properties"]["items"]["items"]
                if "$ref" in row:
                    row = schema["$defs"][row["$ref"].rsplit("/", 1)[-1]]
                self.assertIn(field, row["properties"], tool_name)
            for name in (
                "list_traefik_routes",
                "list_komodo_stacks",
                "list_kuma_monitors",
                "list_probe_results",
                "get_job_history",
                "get_monitoring_coverage",
                "list_finding_history",
            ):
                result = await client.call_tool(name, {})
                self.assertFalse(result.is_error, name)
                self.assertEqual(result.structured_content["schema_version"], 1)

    async def test_new_evidence_summary_schemas_and_probe_group_boundary(self):
        async with Client(build_server(fixture), raise_exceptions=True) as client:
            tools = {item.name: item for item in (await client.list_tools()).tools}
            for name, field, required in (
                ("get_monitoring_coverage", "port_selection_summary", "available"),
                ("get_ingress_evidence", "probe_coverage", "configuration_available"),
                ("get_probe_status", "probe_coverage", "configuration_available"),
            ):
                schema = tools[name].output_schema
                summary = schema["properties"][field]
                if "$ref" in summary:
                    summary = schema["$defs"][summary["$ref"].rsplit("/", 1)[-1]]
                self.assertIn(required, summary["properties"])
                self.assertIn(required, summary["required"])
        async with Client(
            build_server(fixture, env={"YGGFLARE_MCP_TOOL_GROUPS": "probes"}),
            raise_exceptions=True,
        ) as client:
            names = {item.name for item in (await client.list_tools()).tools}
            self.assertIn("get_probe_status", names)
            self.assertNotIn("get_ingress_evidence", names)
            self.assertNotIn("get_monitoring_coverage", names)

    async def test_populated_adapter_rows_preserve_observed_fields(self):
        from integration_inventory import FIELDS as integration_fields
        from mcp_server import IntegrationRow, ProbeRow
        from probe_inventory import FIELDS as probe_fields

        self.assertEqual(set(IntegrationRow.__annotations__), set(integration_fields))
        self.assertEqual(set(ProbeRow.__annotations__), set(probe_fields))
        observed = {
            "target": "ingress",
            "hostname": "demo.invalid",
            "address": "192.0.2.10",
            "port": 443,
            "scheme": "https",
            "check": "http",
            "status": "response_received",
            "elapsed_ms": 2.5,
            "http_status": 302,
            "expected_status_match": None,
            "tls_verified": True,
            "observed_at": "2026-01-01T00:00:00+00:00",
        }

        def snapshot():
            return {
                "configured": True,
                "available": True,
                "fresh": True,
                "items": [{**observed, "secret": "never-export"}],
            }

        with patch("mcp_server.saved_probes", side_effect=lambda *_: snapshot()):
            async with Client(build_server(fixture), raise_exceptions=True) as client:
                result = await client.call_tool("list_probe_results", {})
                self.assertFalse(result.is_error)
                self.assertEqual(result.structured_content["items"], [observed])

    async def test_remaining_paged_tools_publish_row_fields(self):
        async with Client(build_server(fixture), raise_exceptions=True) as client:
            for tool in (await client.list_tools()).tools:
                if "offset" not in tool.input_schema.get("properties", {}):
                    continue
                row = tool.output_schema["properties"]["items"]["items"]
                if "$ref" in row:
                    row = tool.output_schema["$defs"][row["$ref"].rsplit("/", 1)[-1]]
                self.assertTrue(row.get("properties"), tool.name)

    async def test_every_tool_returns_safe_structured_fixture_evidence(self):
        data = fixture()
        before = deepcopy(data)
        arguments = {
            "get_device": {"identifier": "example.invalid"},
            "get_docker_service": {"identifier": "example.invalid"},
            "get_service_dependencies": {"identifier": "example.invalid"},
            "get_ingress_path": {"hostname": "example.invalid"},
            "get_ingress_evidence": {"hostname": "example.invalid"},
            "get_service_exposure": {"identifier": "example.internal"},
        }
        async with Client(
            build_server(lambda: data, env={}), raise_exceptions=True
        ) as client:
            for name in TOOL_NAMES:
                with self.subTest(tool=name):
                    result = await client.call_tool(name, arguments.get(name, {}))
                    self.assertFalse(result.is_error, name)
                    self.assertIsInstance(result.structured_content, dict, name)
                    for private in (
                        "never-export",
                        "private notes",
                        "private-app-id",
                        "private-dns-id",
                    ):
                        self.assertNotIn(private, str(result.structured_content), name)
        self.assertEqual(data, before)

    async def test_only_read_only_tools_registered(self):
        server = build_server(fixture)
        async with Client(server, raise_exceptions=True) as client:
            tools = (await client.list_tools()).tools
            self.assertEqual({tool.name for tool in tools}, set(TOOL_NAMES))
            for tool in tools:
                self.assertIsNotNone(tool.annotations)
                self.assertIsNotNone(tool.output_schema)
                self.assertEqual(tool.output_schema["type"], "object")
                self.assertTrue(tool.annotations.read_only_hint)
                self.assertFalse(tool.annotations.destructive_hint)
                self.assertTrue(tool.annotations.idempotent_hint)
                self.assertFalse(tool.annotations.open_world_hint)
            result = await client.call_tool("list_devices", {"unknown_only": True})
            self.assertFalse(result.is_error)
            self.assertIsNotNone(result.structured_content)
            self.assertEqual(result.structured_content["total"], 1)
            self.assertIn("192.0.2.11", str(result.structured_content))
            self.assertNotIn("never-export", str(result))


if __name__ == "__main__":
    unittest.main()
