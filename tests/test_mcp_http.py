"""HTTP transport security and lifecycle regression tests."""

import json
import socket
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from starlette.testclient import TestClient

from mcp_http import (
    HTTPListener,
    PrincipalApp,
    build_http_app,
    configured_app,
    enabled,
    read_principals,
    read_token,
    settings,
)

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


class PrincipalTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.manifest = self.root / "mcp-principals.json"
        self.entries = [
            {"name": "ops", "groups": ["operations"]},
            {"name": "routes", "groups": ["traefik"]},
        ]
        self.write_manifest()
        for name, token in (("ops", b"b" * 64), ("routes", b"c" * 64)):
            path = self.root / ("mcp-token-" + name + ".txt")
            path.write_bytes(token)
            path.chmod(0o600)

    def write_manifest(self, entries=None):
        self.manifest.write_text(
            json.dumps(
                {
                    "version": 1,
                    "principals": self.entries if entries is None else entries,
                }
            )
        )
        self.manifest.chmod(0o600)

    def test_private_config_validation_and_ceiling(self):
        self.assertEqual(len(read_principals(self.manifest, {})), 2)
        with self.assertRaises(ValueError):
            read_principals(self.manifest, {"YGGFLARE_MCP_TOOL_GROUPS": "operations"})
        for entries in (
            [],
            [self.entries[0], self.entries[0]],
            [{"name": "../escape", "groups": ["operations"]}],
            [{"name": "ops", "groups": ["all"]}],
            [{"name": "ops", "groups": ["operations", "operations"]}],
            [{"name": "ops", "groups": [["operations"]]}],
            [{"name": "ops", "groups": ["operations"], "token": "raw"}],
        ):
            self.write_manifest(entries)
            with self.assertRaises(ValueError):
                read_principals(self.manifest, {})
        self.write_manifest()
        token = self.root / "mcp-token-routes.txt"
        token.write_bytes(b"b" * 64)
        with self.assertRaises(ValueError):
            read_principals(self.manifest, {})
        token.write_bytes(b"c" * 64)
        token.chmod(0o644)
        with self.assertRaises(ValueError):
            read_principals(self.manifest, {})
        token.unlink()
        token.symlink_to(self.root / "mcp-token-ops.txt")
        with self.assertRaises(ValueError):
            read_principals(self.manifest, {})

    def test_explicit_mode_and_fail_closed(self):
        config = settings(
            {"YGGFLARE_MCP_PRINCIPALS_FILE": "/config/mcp-principals.json"}
        )
        self.assertIsNotNone(config.principals_file)
        for env in (
            {"YGGFLARE_MCP_PRINCIPALS_FILE": "/etc/passwd"},
            {
                "YGGFLARE_MCP_PRINCIPALS_FILE": "/config/mcp-principals.json",
                "YGGFLARE_MCP_BIND": "192.168.1.2",
            },
        ):
            with self.assertRaises(ValueError):
                settings(env)
        config = replace(config, principals_file=self.manifest)
        legacy = self.root / "legacy"
        legacy.write_bytes(TOKEN)
        self.manifest.unlink()
        with self.assertRaises(ValueError):
            configured_app(
                replace(config, token_file=legacy), loader=lambda: {}, env={}
            )

    def test_scoped_tools_resources_and_direct_calls(self):
        app = PrincipalApp(
            settings({}), read_principals(self.manifest, {}), loader=lambda: {}, env={}
        )
        with TestClient(app, base_url="http://127.0.0.1:8788") as client:

            def rpc(token, method, params=None):
                headers = {
                    **HEADERS,
                    "Authorization": "Bearer " + token.decode(),
                    "MCP-Protocol-Version": "2025-11-25",
                }
                payload = {"jsonrpc": "2.0", "id": 1, "method": method}
                if params is not None:
                    payload["params"] = params
                return client.post("/mcp", headers=headers, json=payload)

            for token, allowed, forbidden, resource, denied_resource, prompt in (
                (
                    b"b" * 64,
                    "get_job_status",
                    "get_traefik_status",
                    "yggflare://jobs",
                    "yggflare://traefik",
                    "review_operations",
                ),
                (
                    b"c" * 64,
                    "get_traefik_status",
                    "get_job_status",
                    "yggflare://traefik",
                    "yggflare://jobs",
                    None,
                ),
            ):
                with self.subTest(allowed=allowed):
                    listed = rpc(token, "tools/list").json()["result"]["tools"]
                    names = {row["name"] for row in listed}
                    self.assertIn(allowed, names)
                    self.assertNotIn(forbidden, names)
                    self.assertNotIn("get_ingress_evidence", names)
                    resources = {
                        row["uri"]
                        for row in rpc(token, "resources/list").json()["result"][
                            "resources"
                        ]
                    }
                    self.assertIn(resource, resources)
                    self.assertNotIn(denied_resource, resources)
                    good = rpc(
                        token, "tools/call", {"name": allowed, "arguments": {}}
                    ).json()
                    self.assertFalse(good["result"].get("isError", False))
                    denied = rpc(
                        token, "tools/call", {"name": forbidden, "arguments": {}}
                    ).json()
                    self.assertTrue(
                        "error" in denied or denied.get("result", {}).get("isError")
                    )
                    denied = rpc(
                        token, "resources/read", {"uri": denied_resource}
                    ).json()
                    self.assertIn("error", denied)
                    prompts = {
                        row["name"]
                        for row in rpc(token, "prompts/list").json()["result"][
                            "prompts"
                        ]
                    }
                    self.assertEqual(prompts, {prompt} if prompt else set())
            self.assertEqual(rpc(TOKEN, "tools/list").status_code, 401)
            self.assertEqual(rpc(b"unknown", "tools/list").status_code, 401)
            self.assertEqual(
                client.post(
                    "/mcp",
                    json=INITIALIZE,
                    headers={
                        **HEADERS,
                        "Authorization": "Bearer " + "b" * 64,
                        "Origin": "null",
                    },
                ).status_code,
                403,
            )
            self.assertEqual(
                client.post(
                    "/mcp",
                    json=INITIALIZE,
                    headers={
                        **HEADERS,
                        "Authorization": "Bearer " + "b" * 64,
                        "Host": "evil.invalid",
                    },
                ).status_code,
                421,
            )


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
            self.assertEqual(len(tools), 48)
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
