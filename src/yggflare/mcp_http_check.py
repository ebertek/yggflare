"""Explicit local authorization check of the running MCP HTTP listener."""

import http.client
import ipaddress
import json
import os
import re
import signal
import sys

from mcp_http import enabled, read_principals, read_token, settings
from mcp_server import enabled_tools

MAX_REPLY_BYTES = 2 * 1024 * 1024
VERSION = "2025-11-25"


def rpc(config, method, token=None, *, host=None, origin=None, version=VERSION):
    """POST only to the configured numeric loopback listener; never follow redirects."""
    headers = {
        "Host": host if host is not None else config.hosts[0],
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": version,
    }
    if token is not None:
        headers["Authorization"] = "Bearer " + token.decode("ascii")
    if origin is not None:
        headers["Origin"] = origin
    payload = {"jsonrpc": "2.0", "id": 1, "method": method}
    if method == "initialize":
        payload["params"] = {
            "protocolVersion": VERSION,
            "capabilities": {},
            "clientInfo": {"name": "yggflare-acceptance", "version": "1"},
        }
    conn = http.client.HTTPConnection(config.bind, config.port, timeout=5)
    try:
        conn.request("POST", "/mcp", body=json.dumps(payload), headers=headers)
        response = conn.getresponse()
        if response.status != 200:
            return response.status, None
        raw = response.read(MAX_REPLY_BYTES + 1)
        if len(raw) > MAX_REPLY_BYTES:
            raise ValueError("MCP check response exceeds limit")
        result = json.loads(raw)
        if (
            not isinstance(result, dict)
            or result.get("jsonrpc") != "2.0"
            or result.get("id") != 1
            or not isinstance(result.get("result"), dict)
            or "error" in result
        ):
            raise ValueError("Unexpected MCP check response")
        return response.status, result["result"]
    finally:
        conn.close()


def check(config, env, request=rpc):
    """Validate denial and the exact advertised read-only tool set for each token."""
    if not ipaddress.ip_address(config.bind).is_loopback:
        raise ValueError("MCP acceptance check requires a loopback listener")
    if config.principals_file is None:
        credentials = [(read_token(config.token_file), set(enabled_tools(env)))]
        mode = "legacy"
    else:
        mode = "principals"
        credentials = [
            (
                principal.token,
                set(
                    enabled_tools(
                        {
                            **env,
                            "YGGFLARE_MCP_TOOL_GROUPS": ",".join(principal.groups),
                        }
                    )
                ),
            )
            for principal in read_principals(config.principals_file, env)
        ]
    token = credentials[0][0]
    bad_host = "invalid.example"
    while bad_host in config.hosts:
        bad_host = "x." + bad_host
    for status, kwargs in (
        (401, {}),
        (401, {"token": b"invalid"}),
        (421, {"token": token, "host": bad_host}),
        (403, {"token": token, "origin": "null"}),
    ):
        actual, _ = request(config, "tools/list", **kwargs)
        if actual != status:
            raise ValueError("MCP authorization denial check failed")
    counts = []
    for token, expected in credentials:
        status, result = request(config, "initialize", token=token)
        if status != 200 or not isinstance(result, dict):
            raise ValueError("MCP authenticated initialization failed")
        version = result.get("protocolVersion")
        if not isinstance(version, str) or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}", version
        ):
            raise ValueError("Invalid MCP negotiated version")
        status, result = request(config, "tools/list", token=token, version=version)
        if status != 200 or not isinstance(result, dict):
            raise ValueError("MCP authenticated tool listing failed")
        tools = result.get("tools")
        if (
            not isinstance(tools, list)
            or result.get("nextCursor") is not None
            or len(tools) != len(expected)
            or not all(
                isinstance(tool, dict)
                and isinstance(tool.get("name"), str)
                and isinstance(tool.get("annotations"), dict)
                and tool["annotations"].get("readOnlyHint") is True
                for tool in tools
            )
            or {tool["name"] for tool in tools} != expected
        ):
            raise ValueError("MCP tool scope or read-only annotation mismatch")
        counts.append(len(tools))
    return {
        "mode": mode,
        "authorization_denials_verified": 4,
        "credentials_checked": len(counts),
        "tool_counts": counts,
        "verified": True,
        "scope": "local_listener_only",
    }


def main():
    signal.alarm(120)
    try:
        if not enabled():
            raise ValueError("MCP HTTP listener disabled")
        print(json.dumps(check(settings(), dict(os.environ)), sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, http.client.HTTPException):
        print(
            "MCP HTTP acceptance failed; check local listener and authorization configuration.",
            file=sys.stderr,
        )
        return 2
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    sys.exit(main())
