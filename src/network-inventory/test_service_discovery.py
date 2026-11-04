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
                side_effect=[
                    OSError("private exception"),
                    "Disk|media|private comment",
                ],
            ),
        ):
            collect(
                ["eth0"],
                lambda a: a in ipaddress.ip_network("10.0.0.0/24"),
                rows,
                lambda *a: output.append(a),
                warnings,
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
