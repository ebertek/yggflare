"""Offline local MCP HTTP acceptance contract."""

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from mcp_http import settings
from mcp_http_check import check, rpc
from mcp_server import enabled_tools


class MCPHTTPCheckTests(unittest.TestCase):
    def test_checks_denial_and_exact_read_only_tools(self):
        env = {"YGGFLARE_MCP_TOOL_GROUPS": "unifi"}
        names = enabled_tools(env)
        tools = [
            {"name": name, "annotations": {"readOnlyHint": True}} for name in names
        ]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "token"
            path.write_text("a" * 64)
            config = replace(settings(env), token_file=path)
            replies = [
                (401, None),
                (401, None),
                (421, None),
                (403, None),
                (200, {"protocolVersion": "2025-11-25"}),
                (200, {"tools": tools}),
            ]
            with patch("mcp_http_check.rpc", side_effect=replies) as request:
                result = check(config, env, request)
                self.assertEqual(request.call_count, 6)
                self.assertEqual(result["tool_counts"], [len(names)])
                self.assertTrue(result["verified"])
                self.assertNotIn("a" * 64, str(result))
            replies[-1] = (200, {"tools": tools[:-1]})
            with patch("mcp_http_check.rpc", side_effect=replies) as request:
                with self.assertRaisesRegex(ValueError, "scope"):
                    check(config, env, request)

    def test_rejects_nonloopback_before_reading_credentials(self):
        config = settings({"YGGFLARE_MCP_BIND": "192.168.10.2"})
        with patch("mcp_http_check.read_token") as token:
            with self.assertRaisesRegex(ValueError, "loopback"):
                check(config, {})
            token.assert_not_called()

    def test_rpc_does_not_follow_redirects_or_return_response_body(self):
        with patch("mcp_http_check.http.client.HTTPConnection") as connect:
            conn = connect.return_value
            conn.getresponse.return_value.status = 302
            result = rpc(settings({}), "tools/list", b"a" * 64)
            self.assertEqual(result, (302, None))
            connect.assert_called_once_with("127.0.0.1", 8788, timeout=5)
            conn.request.assert_called_once()
            conn.getresponse.return_value.read.assert_not_called()
            conn.close.assert_called_once()
