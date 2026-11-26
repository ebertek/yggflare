"""Offline Docker DNS coverage cases; never an action plan."""

import ipaddress
import unittest

from cloudflare_docker_dns import audit_docker_dns

ZONE = "home.example.net"
NETWORK = ipaddress.ip_network("192.168.10.0/24")


def service(name, address, **extra):
    return {"Name": "compose.yaml/" + name, "IPv4Addresses": [address], **extra}


def a_record(name, address, **extra):
    return {
        "name": name + "." + ZONE,
        "type": "A",
        "content": address,
        "proxied": False,
        **extra,
    }


class DockerDNSCoverageTests(unittest.TestCase):
    def audit(self, services=(), running=None, records=()):
        return audit_docker_dns(services, running or {}, records, ZONE, NETWORK)

    def test_stopped_and_runtime_match_and_missing(self):
        report = self.audit(
            [service("stopped", "192.168.10.10")],
            {"running": "192.168.10.11"},
            [a_record("running", "192.168.10.11")],
        )
        self.assertEqual(report["counts"]["matched"], 1)
        self.assertEqual(
            report["findings"],
            [
                {
                    "hostname": "stopped." + ZONE,
                    "category": "compose",
                    "expected": "192.168.10.10",
                    "status": "missing_a",
                }
            ],
        )

    def test_explicit_hostname_combines_compose_runtime(self):
        report = self.audit(
            [
                service(
                    "service",
                    "192.168.10.10",
                    ContainerName="container",
                    Hostname="canonical." + ZONE,
                )
            ],
            {"container": "192.168.10.10"},
        )
        self.assertEqual(report["counts"]["hosts"], 1)
        row = report["findings"][0]
        self.assertEqual(row["hostname"], "canonical." + ZONE)
        self.assertEqual(row["category"], "compose+runtime")

    def test_no_ip_inference_or_out_of_scope_records(self):
        report = self.audit(
            [
                {"Name": "compose.yaml/host"},
                service("bridge", "172.20.0.5"),
                service("unresolved", "${ADDRESS}"),
                service("other", "192.168.10.15", Hostname="other.example.org"),
            ],
            {"bridge": "172.20.0.5"},
        )
        self.assertEqual(report["counts"]["hosts"], 0)

    def test_cname_conflict_and_ambiguous_addresses(self):
        report = self.audit(
            [service("alias", "192.168.10.10"), service("changed", "192.168.10.11")],
            {"changed": "192.168.10.12"},
            [
                {"name": "alias." + ZONE, "type": "CNAME"},
                a_record("changed", "192.168.10.11"),
            ],
        )
        self.assertEqual(
            [row["status"] for row in report["findings"]],
            ["cname_conflict", "ambiguous_address"],
        )
        self.assertNotIn("expected", report["findings"][1])

    def test_mismatch_and_proxied_record(self):
        report = self.audit(
            [service("a", "192.168.10.10"), service("b", "192.168.10.11")],
            records=[
                a_record("a", "192.168.10.13"),
                a_record("b", "192.168.10.11", proxied=True),
            ],
        )
        self.assertEqual(report["findings"][0]["actual"], "192.168.10.13")
        self.assertEqual(report["findings"][0]["status"], "mismatch")
        self.assertEqual(report["findings"][1]["status"], "proxied_or_unknown")

    def test_unavailable_is_not_empty_success(self):
        report = audit_docker_dns([], None, None, ZONE, NETWORK)
        self.assertFalse(report["enabled"])
