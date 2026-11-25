"""HTTP transport security and lifecycle regression tests."""

import socket
import tempfile
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from mcp_http import HTTPListener, build_http_app, enabled, read_token, settings

TOKEN = b"a" * 64
HEADERS = {
    "Authorization": "Bearer " + TOKEN.decode("ascii"),
    "Accept": "application/json, text/event-stream",
}
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "1"},
    },
}


class ConfigTests(unittest.TestCase):
    def test_disabled_and_loopback_defaults(self):
        self.assertFalse(enabled({}))
        self.assertTrue(enabled({"YGGFLARE_MCP_ENABLED": "true"}))
        config = settings({})
        self.assertEqual(config.bind, "127.0.0.1")
        self.assertEqual(config.port, 8788)
        self.assertIn("127.0.0.1:8788", config.hosts)
        with self.assertRaises(ValueError):
            enabled({"YGGFLARE_MCP_ENABLED": "yes"})

    def test_valid_ipv4_ipv6_and_explicit_hosts(self):
        ipv4 = settings({})
        self.assertEqual(ipv4.hosts, ("127.0.0.1:8788", "localhost:8788"))
        ipv6 = settings({"YGGFLARE_MCP_BIND": "::1"})
        self.assertEqual(ipv6.hosts, ("[::1]:8788", "localhost:8788"))
        explicit = settings(
            {"YGGFLARE_MCP_ALLOWED_HOSTS": "Yggflare.example.net,localhost:8788"}
        )
        self.assertEqual(explicit.hosts, ("yggflare.example.net", "localhost:8788"))
        for invalid in ("bad/host", r"bad\host", "*.example.net", "a b"):
            with self.subTest(host=invalid), self.assertRaises(ValueError):
                settings({"YGGFLARE_MCP_ALLOWED_HOSTS": invalid})

    def test_reject_wildcards_and_invalid_ports(self):
        for env in (
            {"YGGFLARE_MCP_BIND": "0.0.0.0"},
            {"YGGFLARE_MCP_BIND": "::"},
            {"YGGFLARE_MCP_BIND": "localhost"},
            {"YGGFLARE_MCP_PORT": "0"},
            {"YGGFLARE_MCP_ALLOWED_HOSTS": "*"},
        ):
            with self.subTest(env=env), self.assertRaises(ValueError):
                settings(env)

    def test_token_required_and_never_echoed(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "token"
            with self.assertRaises(ValueError):
                read_token(path)
            path.write_text("invalid-secret", encoding="ascii")
            with self.assertRaises(ValueError) as error:
                read_token(path)
            self.assertNotIn("invalid-secret", str(error.exception))
            path.write_bytes(TOKEN + b"\n")
            self.assertEqual(read_token(path), TOKEN)

    def test_bind_and_shutdown(self):
        with (
            tempfile.TemporaryDirectory() as folder,
            socket.socket() as probe,
        ):
            path = Path(folder) / "token"
            path.write_bytes(TOKEN)
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
            env = {
                "YGGFLARE_MCP_PORT": str(port),
                "YGGFLARE_MCP_TOKEN_FILE": str(path),
            }
            with self.assertRaises(ValueError):
                HTTPListener(settings(env))
            probe.close()
            listener = HTTPListener(settings(env))
            try:
                listener.start()
                self.assertTrue(listener.is_alive())
            finally:
                listener.stop()
            self.assertFalse(listener.is_alive())


class HTTPTests(unittest.TestCase):
    def test_http_protocol_and_auth(self):
        app = build_http_app(settings({}), TOKEN, loader=lambda: {})
        with TestClient(app, base_url="http://127.0.0.1:8788") as client:
            for method in ("GET", "POST", "DELETE"):
                with self.subTest(method=method):
                    response = client.request(method, "/mcp")
                    self.assertEqual(response.status_code, 401)
            response = client.post(
                "/mcp", json=INITIALIZE, headers={"Authorization": "Bearer wrong"}
            )
            self.assertEqual(response.status_code, 401)
            response = client.post(
                "/mcp", json=INITIALIZE, headers={**HEADERS, "Host": "evil.invalid"}
            )
            self.assertEqual(response.status_code, 421)
            response = client.post(
                "/mcp", json=INITIALIZE, headers={**HEADERS, "Origin": "null"}
            )
            self.assertEqual(response.status_code, 403)
            response = client.post("/mcp", json=INITIALIZE, headers=HEADERS)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertIn("result", response.json())
            version = response.json()["result"]["protocolVersion"]
            headers = {**HEADERS, "MCP-Protocol-Version": version}
            response = client.post(
                "/mcp",
                headers=headers,
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            )
            self.assertEqual(response.status_code, 200, response.text)
            tools = response.json()["result"]["tools"]
            self.assertEqual(len(tools), 38)
            self.assertTrue(all(t["annotations"]["readOnlyHint"] for t in tools))
            self.assertTrue(all(t["outputSchema"]["type"] == "object" for t in tools))
            response = client.post(
                "/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "get_inventory_status", "arguments": {}},
                },
            )
            self.assertEqual(response.status_code, 200, response.text)
            result = response.json()["result"]
            self.assertFalse(result.get("isError", False))
            self.assertEqual(result["structuredContent"]["inventory_rows"], 0)


if __name__ == "__main__":
    unittest.main()
