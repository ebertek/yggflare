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


if __name__ == "__main__":
    unittest.main()
