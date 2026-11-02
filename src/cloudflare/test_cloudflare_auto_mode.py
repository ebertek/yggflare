"""Tests for explicit, private-environment Cloudflare auto-apply authorization."""

import importlib.util
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from cloudflare_guarded import UnsafePlan

SPEC = importlib.util.spec_from_file_location(
    "cloudflare_manage_cli", Path(__file__).with_name("cloudflare-manage.py")
)
if SPEC is None or SPEC.loader is None:
    raise ImportError("Unable to load cloudflare-manage.py")
MANAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MANAGE)


class AutoOptInTests(unittest.TestCase):
    """The CLI cannot apply unattended changes without an exact opt-in."""

    def test_explicit_true_allows_guarded_auto_path(self):
        """Only literal true authorizes --auto."""
        with patch.dict(os.environ, {"CF_AUTO_APPLY": "true"}):
            MANAGE.require_auto_opt_in()

    def test_missing_false_or_malformed_opt_in_is_rejected(self):
        """Old marker values and generic truthy strings must not authorize writes."""
        for value in (None, "", "false", "TRUE", "1", "enabled", "yes"):
            with self.subTest(value=value), patch.dict(os.environ, {}, clear=True):
                if value is not None:
                    os.environ["CF_AUTO_APPLY"] = value
                with self.assertRaises(UnsafePlan):
                    MANAGE.require_auto_opt_in()

    def test_manual_approval_prints_runnable_container_command(self):
        """The approval command must preserve the reviewed operation limit."""
        with patch.dict(os.environ, {"YGGFLARE_CONTAINER_NAME": "yggflare"}):
            command = MANAGE.approval_command("da8fce91d8119265", 1)
        self.assertEqual(
            command,
            "docker exec yggflare yggflare cloudflare apply "
            "da8fce91d8119265 --max-operations 1",
        )
        self.assertNotIn("Scripts/cloudflare/", command)
        self.assertNotIn("python3", command)

    def test_custom_container_name_is_shell_quoted(self):
        """No arbitrary shell text is injected through the container name."""
        with patch.dict(os.environ, {"YGGFLARE_CONTAINER_NAME": "another container"}):
            command = MANAGE.approval_command("da8fce91d8119265", 1)
        self.assertTrue(command.startswith("docker exec 'another container' yggflare "))


if __name__ == "__main__":
    unittest.main()
