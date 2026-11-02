"""Security regression tests for secret-file credential handling."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "cloudflare"))
from cloudflare_credentials import api_token  # noqa: E402


class SecretTests(unittest.TestCase):
    def test_token_comes_from_secret_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            path.write_text("sample-token\n", encoding="utf-8")
            with patch.dict(
                os.environ,
                {
                    "CLOUDFLARE_API_TOKEN_FILE": str(path),
                    "CLOUDFLARE_API_TOKEN": "must-not-be-used",
                },
            ):
                self.assertEqual(api_token(), "sample-token")

    def test_token_environment_alone_cannot_authorize_writes(self):
        with patch.dict(
            os.environ,
            {
                "CLOUDFLARE_API_TOKEN_FILE": "/nonexistent/yggflare-token",
                "CLOUDFLARE_API_TOKEN": "legacy-token",
            },
        ):
            with self.assertRaises(FileNotFoundError):
                api_token()

    def test_empty_secret_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            path.write_text("", encoding="utf-8")
            with patch.dict(os.environ, {"CLOUDFLARE_API_TOKEN_FILE": str(path)}):
                with self.assertRaises(ValueError):
                    api_token()


if __name__ == "__main__":
    unittest.main()
