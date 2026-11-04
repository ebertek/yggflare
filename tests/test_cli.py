"""Tests for the container-native Yggflare operator commands."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import cli


class CommandTests(unittest.TestCase):
    def invoke(self, args, *, returncode=0):
        """Run the CLI with a private snapshot and no Docker/Cloudflare calls."""
        with tempfile.TemporaryDirectory() as folder:
            with (
                patch.object(cli.controller, "DATA", Path(folder)),
                patch.object(
                    cli.controller, "snapshot", return_value=Path(folder)
                ) as snapshot,
                patch.object(
                    cli.subprocess,
                    "run",
                    return_value=SimpleNamespace(returncode=returncode),
                ) as run,
            ):
                result = cli.main(args)
            snapshot.assert_called_once()
            return result, run.call_args.args[0]

    def test_version_command_requires_no_component_or_service_access(self):
        with (
            patch.dict(
                "os.environ",
                {
                    "YGGFLARE_BUILD_VERSION": "main",
                    "YGGFLARE_BUILD_REVISION": "a" * 40,
                },
            ),
            patch.object(cli.controller, "snapshot") as snapshot,
            contextlib.redirect_stdout(io.StringIO()) as output,
            self.assertRaises(SystemExit) as result,
        ):
            cli.main(["--version"])
        self.assertEqual(result.exception.code, 0)
        self.assertEqual(
            output.getvalue().strip(),
            "Yggflare main (revision aaaaaaaaaaaa)",
        )
        snapshot.assert_not_called()

    def test_network_status_reads_state_without_snapshot_or_network_scan(self):
        commands = [
            (["network", "status"], []),
            (["network", "status", "--details"], ["--details"]),
            (["network", "status", "--json"], ["--json"]),
        ]
        for arguments, flags in commands:
            with (
                self.subTest(arguments=arguments),
                patch.object(cli.controller, "snapshot") as snapshot,
                patch.object(cli.subprocess, "run") as run,
            ):
                run.return_value = SimpleNamespace(returncode=0)
                self.assertEqual(cli.main(arguments), 0)
                snapshot.assert_not_called()
                run.assert_called_once_with(
                    [cli.sys.executable, "/app/network-inventory/status.py", *flags],
                    check=False,
                )

    def test_network_status_rejects_mutating_or_unexpected_arguments(self):
        bad = [
            ["network", "status", "unexpected"],
            ["network", "status", "--max-operations", "3"],
            ["network", "status", "--details", "--json"],
            ["network", "run", "--details"],
            ["cloudflare", "audit", "--json"],
        ]
        for arguments in bad:
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(
                io.StringIO()
            ):
                with self.assertRaises(SystemExit) as error:
                    cli.main(arguments)
                self.assertEqual(error.exception.code, 2)

    def test_plan_preserves_requested_limit(self):
        result, command = self.invoke(["cloudflare", "plan", "--max-operations", "1"])
        self.assertEqual(result, 0)
        self.assertEqual(command[1], "/app/cloudflare/cloudflare-manage.py")
        self.assertEqual(command[-2:], ["--max-operations", "1"])
        self.assertIn("--root", command)

    def test_large_or_unbounded_reviewed_plan_is_supported(self):
        _, default_plan = self.invoke(["cloudflare", "plan"])
        self.assertEqual(default_plan[-2:], ["--max-operations", "0"])
        _, reviewed_plan = self.invoke(
            ["cloudflare", "plan", "--max-operations", "500"]
        )
        self.assertEqual(reviewed_plan[-2:], ["--max-operations", "500"])

    def test_apply_preserves_approval_and_limit(self):
        token = "da8fce91d8119265"
        result, command = self.invoke(
            ["cloudflare", "apply", token, "--max-operations", "1"]
        )
        self.assertEqual(result, 0)
        self.assertEqual(
            command[-4:],
            ["--max-operations", "1", "--apply", token],
        )

    def test_preflight_and_read_only_audit(self):
        _, command = self.invoke(["cloudflare", "preflight"])
        self.assertEqual(command[-1], "--preflight")
        _, command = self.invoke(["cloudflare", "audit"])
        self.assertEqual(command[1], "/app/cloudflare/cloudflare-live.py")
        self.assertNotIn("--apply", command)

    def test_failed_write_exit_code_propagates(self):
        result, _ = self.invoke(
            ["cloudflare", "apply", "da8fce91d8119265"], returncode=2
        )
        self.assertEqual(result, 2)

    def test_claim_and_orphan_cleanup_dispatch(self):
        _, claim = self.invoke(["cloudflare", "claim", "test.ebi.nu"])
        self.assertEqual(claim[1], "/app/cloudflare/cloudflare-orphans.py")
        self.assertEqual(claim[-4:], ["--action", "claim", "--hostname", "test.ebi.nu"])

        _, plan = self.invoke(["cloudflare", "orphan-plan", "test.ebi.nu"])
        self.assertEqual(plan[-4:], ["--action", "plan", "--hostname", "test.ebi.nu"])

        _, apply = self.invoke(
            ["cloudflare", "orphan-apply", "test.ebi.nu", "da8fce91d8119265"]
        )
        self.assertEqual(
            apply[-6:],
            [
                "--action",
                "apply",
                "--hostname",
                "test.ebi.nu",
                "--approval",
                "da8fce91d8119265",
            ],
        )

    def test_orphan_requires_hostname_and_approval_and_rejects_auto_limit(self):
        for args in (
            ["cloudflare", "claim"],
            ["cloudflare", "orphan-plan"],
            ["cloudflare", "orphan-apply", "test.ebi.nu"],
            ["cloudflare", "orphan-apply", "test.ebi.nu", "bad"],
            ["cloudflare", "claim", "test.ebi.nu", "unexpected"],
            ["cloudflare", "orphan-plan", "test.ebi.nu", "--max-operations", "1"],
        ):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    cli.main(args)
                self.assertEqual(error.exception.code, 2)

    def test_invalid_fingerprint_or_limit_is_rejected(self):
        for args in (
            ["cloudflare", "apply"],
            ["cloudflare", "apply", "not-a-fingerprint"],
            ["cloudflare", "plan", "--max-operations", "-1"],
            ["cloudflare", "plan", "unexpected"],
        ):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    cli.main(args)
                self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
