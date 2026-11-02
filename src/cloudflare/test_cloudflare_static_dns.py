"""Offline validation of private static DNS inventory and Cloudflare drift."""

# Shared synthetic DNS fixtures intentionally resemble guarded writer tests.
# pylint: disable=duplicate-code

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cloudflare_static_dns import (
    compare_static_dns,
    load_inventory,
    load_inventory_details,
    plan_static_dns,
)

HOST = "device.ygg.nu"
ADDRESS = "10.4.20.10"
MAC = "aa:bb:cc:dd:ee:ff"


def inventory(hosts=None):
    """Construct only synthetic private-device fixtures."""
    return {
        "version": 1,
        "hosts": (
            hosts
            if hosts is not None
            else [{"hostname": HOST, "ipv4": ADDRESS, "mac": MAC}]
        ),
    }


def record(name=HOST, address=ADDRESS, kind="A", proxied=False):
    """Return a fake Cloudflare DNS record."""
    return {
        "name": name,
        "type": kind,
        "content": address,
        "proxied": proxied,
    }


class InventoryTests(unittest.TestCase):  # pylint: disable=too-many-public-methods
    """Require explicit schema and safe static-only IPv4 addresses."""

    def load(self, contents, required=True):
        """Write and read a temporary private JSON source."""
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "static-hosts.json"
            path.write_text(json.dumps(contents))
            return load_inventory(path, required=required)

    def test_interface_mac_metadata_is_validated_and_not_published(self):
        """Per-interface MACs are inventory-only, not DNS targets."""
        host = {
            "hostname": HOST,
            "ipv4": ADDRESS,
            "mac": "2a:70:4e:72:c5:d8",
            "interface_macs": {
                "eth4": "28:70:4e:72:c5:db",
                "br0": "2a:70:4e:72:c5:d8",
                "eth0@switch0": "28:70:4e:72:c5:d7",
            },
        }
        self.assertEqual(self.load(inventory([host])), {HOST: ADDRESS})
        for bad in ({"br0": "not-a-mac"}, {"invalid name!": MAC}, [MAC]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.load(inventory([{**host, "interface_macs": bad}]))

    def test_valid_file_does_not_publish_mac(self):
        """MAC metadata is permitted but absent from DNS comparison data."""
        self.assertEqual(self.load(inventory()), {HOST: ADDRESS})
        self.assertNotIn(MAC, str(compare_static_dns({HOST: ADDRESS}, [])))

    def test_description_is_preserved_in_source_but_not_audit_output(self):
        """Device model details remain private and do not change DNS semantics."""
        description = "Asus NUC 15 Pro (RNUC15CRKU500000I)"
        row = {
            "hostname": HOST,
            "ipv4": ADDRESS,
            "mac": MAC,
            "description": description,
        }
        expected = {HOST: ADDRESS}
        self.assertEqual(self.load(inventory([row])), expected)
        self.assertNotIn(description, str(expected))
        self.assertNotIn(description, str(compare_static_dns(expected, [])))

    def test_invalid_optional_descriptions_are_rejected(self):
        """Reject malformed metadata without disclosing it in errors."""
        for description in ("", "  ", 23, "line" + chr(10) + "break", "x" * 513):
            with self.subTest(description=type(description).__name__):
                row = {"hostname": HOST, "ipv4": ADDRESS, "description": description}
                with self.assertRaisesRegex(ValueError, "invalid optional description"):
                    self.load(inventory([row]))

    def test_serial_date_and_ports_are_metadata_only(self):
        """All private metadata is validated and excluded from desired DNS."""
        row = {
            "hostname": HOST,
            "ipv4": ADDRESS,
            "description": "Test appliance",
            "serial_number": "0x00124b003414bac3",
            "purchase_date": "2023-01-26",
            "ports": [{"port": p, "protocol": "tcp"} for p in (5000, 7000, 49152, 62078)],
        }
        expected = {HOST: ADDRESS}
        self.assertEqual(self.load(inventory([row])), expected)
        report = compare_static_dns(expected, [])
        for metadata in ("Test appliance", row["serial_number"], "2023-01-26"):
            self.assertNotIn(metadata, str(report))
        self.assertNotIn("5000", str(report))

    def test_serial_number_validation(self):
        """Serials must be nonblank, bounded, printable strings."""
        for value in ("", "   ", 42, "line" + chr(10) + "break", "x" * 257):
            with self.subTest(kind=type(value).__name__):
                row = {"hostname": HOST, "ipv4": ADDRESS, "serial_number": value}
                with self.assertRaisesRegex(
                    ValueError, "invalid optional serial_number"
                ):
                    self.load(inventory([row]))

    def test_purchase_date_validation(self):
        """Reject impossible dates, unsupported formats and nonstrings."""
        for value in ("2023-02-30", "20230126", "2023-1-26", 20230126, ""):
            with self.subTest(value=value):
                row = {"hostname": HOST, "ipv4": ADDRESS, "purchase_date": value}
                with self.assertRaisesRegex(
                    ValueError, "invalid optional purchase_date"
                ):
                    self.load(inventory([row]))

    def test_legacy_open_ports_is_rejected(self):
        """Fresh Yggflare inventory must use ports only."""
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            self.load(inventory([{
                "hostname": HOST, "ipv4": ADDRESS, "open_ports": [80],
            }]))

    def test_protocol_aware_ports_and_aliases_are_private_metadata(self):
        """Aliases and port details never influence primary or companion DNS."""
        row = {
            "hostname": HOST,
            "ipv4": ADDRESS,
            "ports": [
                {"protocol": "tcp", "port": 6444, "description": "Test control API"},
                {"protocol": "udp", "port": 6444},
                {"port": 8080},
            ],
            "aliases": ["device-web.ygg.nu", "device-alt.ygg.nu"],
        }
        wanted = self.load(inventory([row]))
        self.assertEqual(wanted, {HOST: ADDRESS})
        self.assertEqual(compare_static_dns(wanted, [record()])["counts"]["drift"], 0)
        self.assertEqual(plan_static_dns(wanted, [record()]), [])
        output = str(compare_static_dns(wanted, []))
        self.assertNotIn("device-web", output)
        self.assertNotIn("6444", output)
        self.assertNotIn("Test control API", output)

    def test_ports_reject_invalid_entries_and_duplicates(self):
        """Each port is a unique protocol/number pair or an unknown protocol."""
        invalid = (
            None,
            80,
            "tcp/6444",
            [80],
            [{}],
            [{"protocol": "tcp"}],
            [{"port": 0}],
            [{"port": 65536}],
            [{"port": True}],
            [{"port": 80.0}],
            [{"port": "80"}],
            [{"port": 80, "protocol": "TCP"}],
            [{"port": 80, "protocol": "icmp"}],
            [{"port": 80, "protocol": None}],
            [{"port": 80, "protocol": []}],
            [{"port": 80, "protocol": {}}],
            [{"port": 80, "service": "http"}],
            [{"port": 80, "description": None}],
            [{"port": 80, "description": 5}],
            [{"port": 80, "description": ""}],
            [{"port": 80, "description": " "}],
            [{"port": 80, "description": "line" + chr(10) + "break"}],
            [{"port": 80, "description": "x" * 257}],
            [{"port": 80}, {"port": 80}],
            [{"port": 80, "protocol": "tcp"}, {"port": 80, "protocol": "tcp"}],
        )
        for ports in invalid:
            with self.subTest(ports=ports):
                row = {"hostname": HOST, "ipv4": ADDRESS, "ports": ports}
                with self.assertRaises(ValueError):
                    self.load(inventory([row]))
        for ports in ([], [{"port": 80}], [{"port": 80, "description": "HTTP"}]):
            with self.subTest(ports=ports):
                row = {"hostname": HOST, "ipv4": ADDRESS, "ports": ports}
                self.assertEqual(self.load(inventory([row])), {HOST: ADDRESS})

    def test_aliases_are_unique_single_label_ygg_nu_names(self):
        """Reject malformed aliases before any guarded DNS operations."""
        invalid = (
            None,
            "alias.ygg.nu",
            [None],
            [123],
            ["device.ebi.nu"],
            ["deep.alias.ygg.nu"],
            ["Alias.ygg.nu"],
            [HOST],
            ["alias.ygg.nu", "alias.ygg.nu"],
            [f"alias-{index}.ygg.nu" for index in range(17)],
        )
        for aliases in invalid:
            with self.subTest(aliases=aliases):
                row = {"hostname": HOST, "ipv4": ADDRESS, "aliases": aliases}
                with self.assertRaises(ValueError):
                    self.load(inventory([row]))
        row = {"hostname": HOST, "ipv4": ADDRESS, "aliases": []}
        self.assertEqual(self.load(inventory([row])), {HOST: ADDRESS})

    def test_aliases_cannot_shadow_other_inventory_hosts_or_aliases(self):
        """Reject cross-device collisions, regardless of inventory order."""
        first = {
            "hostname": HOST,
            "ipv4": ADDRESS,
            "aliases": ["shared.ygg.nu"],
        }
        with self.assertRaisesRegex(ValueError, "aliases conflict"):
            self.load(
                inventory(
                    [
                        first,
                        {"hostname": "shared.ygg.nu", "ipv4": "10.4.20.11"},
                    ]
                )
            )
        with self.assertRaisesRegex(ValueError, "aliases conflict"):
            self.load(
                inventory(
                    [
                        first,
                        {
                            "hostname": "second.ygg.nu",
                            "ipv4": "10.4.20.11",
                            "aliases": ["shared.ygg.nu"],
                        },
                    ]
                )
            )

    def test_companion_a_is_validated_but_does_not_replace_primary(self):
        """A second address is explicit DNS metadata, not a primary target."""
        row = {
            "hostname": HOST,
            "ipv4": ADDRESS,
            "additional_ipv4": ["10.4.21.42"],
        }
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "static-hosts.json"
            path.write_text(json.dumps(inventory([row])))
            self.assertEqual(load_inventory(path), {HOST: ADDRESS})
            self.assertEqual(
                load_inventory_details(path),
                ({HOST: ADDRESS}, {HOST: ["10.4.21.42"]}),
            )

    def test_companion_a_rejects_bad_or_unreserved_addresses(self):
        """Protect /27 borders, primary subnet and non-canonical IPs."""
        invalid = (
            "10.4.20.20",
            "10.4.21.0",
            "10.4.21.31",
            "10.4.21.32",
            "10.4.21.63",
            "10.4.22.1",
            "8.8.8.8",
            "10.4.21.099",
        )
        for address in invalid:
            with self.subTest(address=address):
                row = {
                    "hostname": HOST,
                    "ipv4": ADDRESS,
                    "additional_ipv4": [address],
                }
                with self.assertRaises((ValueError, TypeError)):
                    self.load(inventory([row]))
        for values in ("10.4.21.42", [123], ["10.4.21.42"] * 2, [None]):
            with self.subTest(values=values):
                row = {
                    "hostname": HOST,
                    "ipv4": ADDRESS,
                    "additional_ipv4": values,
                }
                with self.assertRaises((ValueError, TypeError)):
                    self.load(inventory([row]))

    def test_optional_missing_file_and_required_missing_file(self):
        """A phased rollout is optional until the private merge is ready."""
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "not-configured.json"
            self.assertIsNone(load_inventory(path))
            with self.assertRaisesRegex(ValueError, "Required"):
                load_inventory(path, required=True)

    def test_duplicate_hostname_refused(self):
        """Never silently override a duplicate inventory entry."""
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self.load(inventory([inventory()["hosts"][0]] * 2))

    def test_invalid_schema_and_ipv4_are_rejected(self):
        """Fail closed on invalid versions, public IPs and Docker addresses."""
        for candidate in (
            {"version": 2, "hosts": inventory()["hosts"]},
            {"version": 1, "hosts": []},
            inventory([{"hostname": HOST, "ipv4": "10.4.21.10"}]),
            inventory([{"hostname": HOST, "ipv4": "8.8.8.8"}]),
            inventory([{"hostname": HOST, "ipv4": "10.4.20.0"}]),
            inventory([{"hostname": "device.ebi.nu", "ipv4": ADDRESS}]),
            inventory([{"hostname": HOST, "ipv4": ADDRESS, "mac": "bad"}]),
            inventory([{"hostname": HOST, "ipv4": ADDRESS, "unknown": 4}]),
            inventory([{"hostname": HOST, "ipv4": "10.4.20.999"}]),
        ):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                self.load(candidate)

    def test_all_planned_27_allocation_boundaries_are_reserved(self):
        """A /23 LAN still reserves network/broadcast offsets for future /27s."""
        for base in range(0, 256, 32):
            for offset in (0, 31):
                address = f"10.4.20.{base + offset}"
                with self.subTest(address=address), self.assertRaises(ValueError):
                    self.load(inventory([{"hostname": HOST, "ipv4": address}]))

    def test_27_allocation_interiors_are_allowed(self):
        """Unassigned /27 segments remain valid for future static devices."""
        for last in (1, 30, 33, 62, 65, 94, 97, 126, 129, 158, 161, 190):
            address = f"10.4.20.{last}"
            with self.subTest(address=address):
                self.assertEqual(
                    self.load(inventory([{"hostname": HOST, "ipv4": address}])),
                    {HOST: address},
                )

    def test_invalid_json_rejected(self):
        """Do not continue the audit with an unreadable source."""
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "static-hosts.json"
            path.write_text("{broken")
            with self.assertRaises(ValueError):
                load_inventory(path)


class StaticDiffTests(unittest.TestCase):
    """No static DNS finding can become an automated write proposal."""

    def test_not_configured(self):
        """The existing controller continues normally before private rollout."""
        report = compare_static_dns(None, [])
        self.assertFalse(report["enabled"])
        self.assertEqual(report["counts"]["drift"], 0)

    def test_matching_unproxied_a_with_aaaa_and_unmanaged_records(self):
        """IPv6 and other non-inventory names remain completely unmanaged."""
        report = compare_static_dns(
            {HOST: ADDRESS},
            [
                record(),
                record(kind="AAAA", address="fd00::1"),
                record(name="other.ygg.nu", address="10.4.20.20"),
            ],
        )
        self.assertTrue(report["enabled"])
        self.assertEqual(report["counts"]["matched"], 1)
        self.assertEqual(report["counts"]["drift"], 0)
        self.assertEqual(report["findings"], [])

    def test_missing_and_wrong_ip(self):
        """Distinguish missing A records from stale IPv4 values."""
        missing = compare_static_dns({HOST: ADDRESS}, [])
        self.assertEqual(missing["findings"][0]["status"], "missing")
        changed = compare_static_dns({HOST: ADDRESS}, [record(address="10.4.20.11")])
        self.assertEqual(changed["findings"][0]["status"], "mismatch")
        self.assertEqual(changed["findings"][0]["actual"], "10.4.20.11")

    def test_conflicting_cname_duplicate_and_proxy(self):
        """Flag unsafe record shapes without changing any of them."""
        for records in (
            [record(kind="CNAME", address="example.com")],
            [record(), record()],
            [record(proxied=True)],
            [record(), record(kind="CNAME", address="example.com")],
        ):
            with self.subTest(records=records):
                report = compare_static_dns({HOST: ADDRESS}, records)
                self.assertEqual(report["findings"][0]["status"], "conflict")
                self.assertEqual(report["counts"]["drift"], 1)


class StaticPlanningTests(unittest.TestCase):
    """Only safely managed A records may become guarded write proposals."""

    def test_create_missing_active_a_without_deleting_other_records(self):
        """Unknown names and AAAA records are left untouched."""
        wanted = {HOST: ADDRESS}
        records = [
            record(name=HOST, address="fd00::1", kind="AAAA"),
            record(name="unmanaged.ygg.nu", address="10.4.20.15"),
        ]
        self.assertEqual(
            plan_static_dns(wanted, records),
            [{"kind": "create_static_dns_a", "hostname": HOST, "content": ADDRESS}],
        )
        self.assertEqual(plan_static_dns(None, records), [])

    def test_update_only_unique_unproxied_static_a(self):
        """A stale, identified A record becomes an IP-only update."""
        existing = record(address="10.4.20.11")
        existing["id"] = "c" * 32
        self.assertEqual(
            plan_static_dns({HOST: ADDRESS}, [existing]),
            [
                {
                    "kind": "update_static_dns_a",
                    "hostname": HOST,
                    "record_id": "c" * 32,
                    "before": "10.4.20.11",
                    "content": ADDRESS,
                }
            ],
        )
        self.assertEqual(plan_static_dns({HOST: ADDRESS}, [record()]), [])

    def test_conflicts_and_outside_subnet_never_generate_writes(self):
        """Never overwrite a CNAME, proxied A, duplicate or Docker IP."""
        for records in (
            [record(address="10.4.20.11", proxied=True)],
            [record(kind="CNAME", address="other.ygg.nu")],
            [record(address="10.4.20.11"), record(address="10.4.20.12")],
            [{**record(address="10.4.21.7"), "id": "c" * 32}],
            [{**record(address="10.4.20.11"), "id": "not-a-cloudflare-id"}],
        ):
            with self.subTest(records=records):
                self.assertEqual(plan_static_dns({HOST: ADDRESS}, records), [])


class CompanionDnsTests(unittest.TestCase):
    """A declared second A record must remain present and untouched."""

    def test_dual_a_is_healthy_only_when_declared(self):
        """Matching primary and declared companion count as one matched host."""
        records = [record(), record(address="10.4.21.42")]
        wanted = {HOST: ADDRESS}
        self.assertEqual(compare_static_dns(wanted, records)["counts"]["drift"], 1)
        actual = compare_static_dns(wanted, records, {HOST: ["10.4.21.42"]})
        self.assertEqual(actual["counts"]["matched"], 1)
        self.assertEqual(actual["counts"]["drift"], 0)
        self.assertEqual(plan_static_dns(wanted, records, {HOST: ["10.4.21.42"]}), [])

    def test_extra_missing_or_unexpected_a_is_conflict(self):
        """A declared companion cannot mask missing or additional records."""
        wanted = {HOST: ADDRESS}
        extras = {HOST: ["10.4.21.42"]}
        for records in (
            [record()],
            [record(), record(address="10.4.21.2")],
            [record(), record(address="10.4.21.42"), record(address="10.4.21.2")],
            [record(), record(address="10.4.21.42", proxied=True)],
            [record(), record(address="10.4.21.42", kind="CNAME")],
        ):
            with self.subTest(records=records):
                result = compare_static_dns(wanted, records, extras)
                self.assertEqual(result["findings"][0]["status"], "conflict")
                self.assertEqual(plan_static_dns(wanted, records, extras), [])

    def test_primary_missing_can_be_created_beside_companion(self):
        """The companion stays protected when only the primary is missing."""
        extras = {HOST: ["10.4.21.42"]}
        records = [record(address="10.4.21.42")]
        self.assertEqual(
            compare_static_dns({HOST: ADDRESS}, records, extras)["findings"][0][
                "status"
            ],
            "missing",
        )
        self.assertEqual(
            plan_static_dns({HOST: ADDRESS}, records, extras),
            [
                {
                    "kind": "create_static_dns_a",
                    "hostname": HOST,
                    "content": ADDRESS,
                    "additional_ipv4": ["10.4.21.42"],
                }
            ],
        )
        self.assertEqual(plan_static_dns({HOST: ADDRESS}, [], extras), [])

    def test_primary_ip_change_updates_only_primary(self):
        """A declared companion does not block an ordinary primary IP change."""
        original = {**record(address="10.4.20.12"), "id": "a" * 32}
        second = {**record(address="10.4.21.42"), "id": "b" * 32}
        extras = {HOST: ["10.4.21.42"]}
        self.assertEqual(
            plan_static_dns({HOST: ADDRESS}, [original, second], extras),
            [
                {
                    "kind": "update_static_dns_a",
                    "hostname": HOST,
                    "record_id": "a" * 32,
                    "before": "10.4.20.12",
                    "content": ADDRESS,
                    "additional_ipv4": ["10.4.21.42"],
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
