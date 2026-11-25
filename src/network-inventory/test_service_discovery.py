"""Optional sources fail independently and never guess SNMP credentials."""

import ipaddress
import unittest
from unittest.mock import patch

from service_discovery import collect


class ServiceTests(unittest.TestCase):
    def test_disabled_sources_do_not_execute(self):
        with (
            patch.dict("os.environ", {}, clear=True),
            patch("service_discovery.execute") as run,
        ):
            collect(["eth0"], lambda a: True, [], lambda *a: None, [])
        run.assert_not_called()

    def test_smb_limit_and_netbios_no_reply_are_explicit(self):
        rows = [{"ip": f"10.0.0.{i}"} for i in range(1, 21)]
        with (
            patch.dict(
                "os.environ",
                {
                    "YGGFLARE_DISCOVERY_NETBIOS": "true",
                    "YGGFLARE_DISCOVERY_SMB": "true",
                    "YGGFLARE_DISCOVERY_SMB_MAX_TARGETS": "16",
                },
                clear=True,
            ),
            patch("service_discovery.shutil.which", return_value="/usr/bin/nmblookup"),
            patch("service_discovery.execute", return_value=""),
            patch("service_discovery.smb_listing", return_value=("success_empty", [])),
        ):
            coverage = collect(
                ["eth0"],
                lambda a: True,
                rows,
                lambda *a: None,
                [],
                observed_ports={row["ip"]: ["tcp/445"] for row in rows},
            )
        self.assertEqual(coverage["netbios"]["attempted"], 20)
        self.assertEqual(coverage["netbios"]["no_reply"], 20)
        self.assertEqual(coverage["smb"]["attempted"], 16)
        self.assertEqual(coverage["smb"]["eligible_targets"], 20)
        self.assertTrue(coverage["smb"]["limited"])
        self.assertEqual(coverage["smb"]["success_empty"], 16)
        self.assertEqual(coverage["smb"]["skipped_target_limit"], 4)

    def test_smb_configurable_limits_and_workers(self):
        from service_discovery import smb_settings

        self.assertEqual(smb_settings({}), (512, 8))
        self.assertEqual(
            smb_settings({"YGGFLARE_DISCOVERY_MAX_TARGETS": "100"}), (100, 8)
        )
        self.assertEqual(
            smb_settings({
                "YGGFLARE_DISCOVERY_SMB_MAX_TARGETS": "200",
                "YGGFLARE_DISCOVERY_SMB_WORKERS": "4",
            }), (200, 4)
        )
        for key, value in (
            ("YGGFLARE_DISCOVERY_SMB_MAX_TARGETS", "0"),
            ("YGGFLARE_DISCOVERY_SMB_MAX_TARGETS", "4097"),
            ("YGGFLARE_DISCOVERY_SMB_WORKERS", "17"),
            ("YGGFLARE_DISCOVERY_SMB_WORKERS", "bad"),
        ):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                smb_settings({key: value})

        rows = [{"ip": f"192.0.2.{i}"} for i in range(1, 206)]
        with (
            patch.dict(
                "os.environ",
                {
                    "YGGFLARE_DISCOVERY_SMB": "true",
                    "YGGFLARE_DISCOVERY_SMB_MAX_TARGETS": "200",
                    "YGGFLARE_DISCOVERY_SMB_WORKERS": "8",
                },
                clear=True,
            ),
            patch("service_discovery.shutil.which", return_value="/usr/bin/smbclient"),
            patch("service_discovery.smb_listing", return_value=("success_empty", [])) as listing,
        ):
            evidence = collect(
                ["eth0"], lambda a: True, rows, lambda *a: None, [],
                observed_ports={row["ip"]: ["tcp/445"] for row in rows},
            )["smb"]
        self.assertEqual(listing.call_count, 200)
        self.assertEqual(evidence["target_limit"], 200)
        self.assertEqual(evidence["workers"], 8)
        self.assertEqual(evidence["effective_workers"], 8)
        self.assertEqual(evidence["completed"], 200)
        self.assertEqual(evidence["skipped_target_limit"], 5)

    def test_invalid_smb_configuration_is_isolated(self):
        warnings = []
        with (
            patch.dict(
                "os.environ",
                {
                    "YGGFLARE_DISCOVERY_SMB": "true",
                    "YGGFLARE_DISCOVERY_SMB_MAX_TARGETS": "-1",
                },
                clear=True,
            ),
            patch("service_discovery.smb_listing") as listing,
        ):
            evidence = collect(
                ["eth0"], lambda a: True, [{"ip": "192.0.2.1"}],
                lambda *a: None, warnings,
                observed_ports={"192.0.2.1": ["tcp/445"]},
            )["smb"]
        listing.assert_not_called()
        self.assertTrue(evidence["unavailable"])
        self.assertEqual(evidence["attempted"], 0)
        self.assertEqual(len(warnings), 1)
        self.assertNotIn("skipped_target_limit", evidence)

    def test_smb_only_uses_observed_ports_and_classifies_outcomes(self):
        from service_discovery import smb_outcome

        rows = [{"ip": f"192.0.2.{i}"} for i in range(1, 5)]
        warnings = []
        with (
            patch.dict(
                "os.environ",
                {
                    "YGGFLARE_DISCOVERY_SMB": "true",
                    "YGGFLARE_DISCOVERY_SMB_WORKERS": "1",
                },
                clear=True,
            ),
            patch("service_discovery.shutil.which", return_value="/usr/bin/smbclient"),
            patch(
                "service_discovery.smb_listing",
                side_effect=[
                    ("access_denied", []),
                    ("remote_timeout", []),
                    ("execution_failed", []),
                ],
            ) as listing,
        ):
            result = collect(
                ["eth0"],
                lambda a: True,
                rows,
                lambda *a: None,
                warnings,
                observed_ports={
                    "192.0.2.2": ["tcp/139"],
                    "192.0.2.3": ["tcp/445"],
                    "192.0.2.4": ["tcp/445"],
                },
            )["smb"]
        self.assertEqual(listing.call_args_list[0].args, ("192.0.2.3", 445))
        self.assertEqual(result["skipped_no_port_evidence"], 1)
        self.assertEqual(result["access_denied"], 1)
        self.assertEqual(result["no_reply"], 1)
        self.assertEqual(result["failed"], 1)
        self.assertEqual(result["completed"], 2)
        self.assertEqual(len(warnings), 1)
        self.assertEqual(smb_outcome(1, "NT_STATUS_LOGON_FAILURE"), "access_denied")
        self.assertEqual(
            smb_outcome(1, "NT_STATUS_CONNECTION_REFUSED"), "connection_refused"
        )
        self.assertEqual(smb_outcome(1, "NT_STATUS_IO_TIMEOUT"), "remote_timeout")
        self.assertEqual(smb_outcome(1, "unknown private error"), "execution_failed")

    def test_netbios_failure_does_not_prevent_smb(self):
        rows = [{"ip": "10.0.0.2"}]
        output, warnings = [], []
        with (
            patch.dict(
                "os.environ",
                {
                    "YGGFLARE_DISCOVERY_NETBIOS": "true",
                    "YGGFLARE_DISCOVERY_SMB": "true",
                },
                clear=True,
            ),
            patch("service_discovery.shutil.which", return_value="/usr/bin/nmblookup"),
            patch(
                "service_discovery.execute",
                side_effect=OSError("private exception"),
            ),
            patch(
                "service_discovery.smb_listing",
                return_value=("success_with_shares", ["media"]),
            ),
        ):
            collect(
                ["eth0"],
                lambda a: a in ipaddress.ip_network("10.0.0.0/24"),
                rows,
                lambda *a: output.append(a),
                warnings,
                observed_ports={"10.0.0.2": ["tcp/445"]},
            )
        self.assertEqual(
            output, [("10.0.0.2", "", "SMB anonymous share listing", "media")]
        )
        self.assertNotIn("private", str(warnings))

    def test_netbios_missing_executable_warns_once(self):
        rows = [{"ip": f"10.0.0.{i}"} for i in range(1, 17)]
        warnings = []
        with (
            patch.dict(
                "os.environ", {"YGGFLARE_DISCOVERY_NETBIOS": "true"}, clear=True
            ),
            patch("service_discovery.shutil.which", return_value=None),
            patch("service_discovery.execute") as execute,
        ):
            collect(["eth0"], lambda a: True, rows, lambda *a: None, warnings)
        execute.assert_not_called()
        self.assertEqual(warnings, ["NetBIOS: nmblookup executable unavailable"])

    def test_netbios_no_response_is_not_warning(self):
        rows = [{"ip": "10.0.0.2"}]
        warnings = []
        with (
            patch.dict(
                "os.environ", {"YGGFLARE_DISCOVERY_NETBIOS": "true"}, clear=True
            ),
            patch("service_discovery.shutil.which", return_value="/usr/bin/nmblookup"),
            patch("service_discovery.execute", return_value="") as execute,
        ):
            collect(["eth0"], lambda a: True, rows, lambda *a: None, warnings)
        execute.assert_called_once_with(
            ["nmblookup", "-A", "10.0.0.2"],
            allow_no_reply=True,
            timeout_seconds=3,
            timeout_is_no_reply=True,
        )
        self.assertEqual(warnings, [])

    def test_netbios_no_reply_exit_code_is_handled_without_masking_failures(self):
        import sys

        from service_discovery import execute

        silent = [sys.executable, "-c", "print('No reply'); raise SystemExit(1)"]
        with self.assertRaises(ValueError):
            execute(silent)
        self.assertIn("No reply", execute(silent, allow_no_reply=True))
        invalid = [sys.executable, "-c", "raise SystemExit(2)"]
        with self.assertRaises(ValueError):
            execute(invalid, allow_no_reply=True)

    def test_netbios_ordinary_timeout_returns_no_evidence(self):
        """A silent UDP/137 device must not produce a collector error."""
        import sys

        from service_discovery import execute

        silent = [sys.executable, "-c", "import time; time.sleep(1)"]
        self.assertEqual(
            execute(
                silent,
                allow_no_reply=True,
                timeout_seconds=0.1,
                timeout_is_no_reply=True,
            ),
            "",
        )
        with self.assertRaisesRegex(ValueError, "bounds"):
            execute(silent, timeout_seconds=0.1)

    def test_netbios_queries_beyond_first_sixteen_observed_addresses(self):
        """Optional NetBIOS scanning covers all scoped observations."""
        rows = [{"ip": f"10.0.0.{i}"} for i in range(1, 21)]
        warnings = []
        with (
            patch.dict(
                "os.environ", {"YGGFLARE_DISCOVERY_NETBIOS": "true"}, clear=True
            ),
            patch("service_discovery.shutil.which", return_value="/usr/bin/nmblookup"),
            patch("service_discovery.execute", return_value="") as execute,
        ):
            collect(
                ["eth0"],
                lambda address: address in ipaddress.ip_network("10.0.0.0/24"),
                rows,
                lambda *args: None,
                warnings,
            )
        self.assertEqual(execute.call_count, 20)
        self.assertEqual(warnings, [])

    def test_snmp_missing_targets_never_queries(self):
        warnings = []
        with (
            patch.dict("os.environ", {"YGGFLARE_DISCOVERY_SNMP": "true"}, clear=True),
            patch("service_discovery.execute") as run,
        ):
            collect(["eth0"], lambda a: True, [], lambda *a: None, warnings)
        run.assert_not_called()
        self.assertTrue(warnings)

    def test_snmp_credentials_use_private_config_and_not_argv(self):
        from pathlib import Path

        for secret in (
            {"version": "2c", "community": "secret-value"},
            {
                "version": "3",
                "username": "monitor",
                "auth_passphrase": "secret-auth",
                "priv_passphrase": "secret-priv",
            },
        ):
            output, warnings = [], []

            def run(args, env=None):
                self.assertEqual(args[0], "snmpget")
                self.assertNotIn("secret-", str(args))
                config = Path(env["SNMPCONFPATH"]) / "snmp.conf"
                # Use open directly because read_text is mocked for the mounted secret.
                with config.open() as handle:
                    text = handle.read()
                self.assertIn("defVersion " + secret["version"], text)
                self.assertEqual(config.stat().st_mode & 0o777, 0o600)
                return "system identity"

            import json
            from types import SimpleNamespace

            original_stat = Path.stat

            def stat(path, **kwargs):
                if str(path) == "/run/secrets/yggflare_snmp":
                    return SimpleNamespace(st_size=100)
                return original_stat(path, **kwargs)

            with (
                patch.dict(
                    "os.environ",
                    {
                        "YGGFLARE_DISCOVERY_SNMP": "true",
                        "YGGFLARE_DISCOVERY_SNMP_TARGETS": "10.0.0.2",
                    },
                    clear=True,
                ),
                patch("service_discovery.Path.stat", stat),
                patch(
                    "service_discovery.Path.read_text", return_value=json.dumps(secret)
                ),
                patch("service_discovery.execute", side_effect=run),
            ):
                collect(
                    ["eth0"], lambda a: True, [], lambda *a: output.append(a), warnings
                )
            self.assertFalse(warnings)
            self.assertEqual(output[0][2], "SNMP system identity")
