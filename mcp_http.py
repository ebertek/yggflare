"""Optional authenticated Streamable HTTP transport for Yggflare."""

import hmac
import ipaddress
import os
import re
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import uvicorn
from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import PlainTextResponse

from mcp_server import build_server

TOKEN_PATTERN = re.compile(r"[A-Za-z0-9._~-]{32,256}")
HOST_PATTERN = re.compile(r"[A-Za-z0-9.\\[\\]:-]{1,253}")


def enabled(env=None):
    env = os.environ if env is None else env
    value = env.get("YGGFLARE_MCP_ENABLED", "false")
    if value not in ("true", "false"):
        raise ValueError("YGGFLARE_MCP_ENABLED must be true or false")
    return value == "true"


@dataclass(frozen=True)
class HTTPSettings:
    bind: str
    port: int
    hosts: tuple[str, ...]
    token_file: Path


def settings(env=None):
    env = os.environ if env is None else env
    try:
        address = ipaddress.ip_address(env.get("YGGFLARE_MCP_BIND", "127.0.0.1"))
        if address.is_unspecified or address.is_multicast or "%" in str(address):
            raise ValueError
        port = int(env.get("YGGFLARE_MCP_PORT", "8788"))
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        raise ValueError(
            "MCP requires a specific numeric bind address and port 1-65535"
        ) from None
    host = f"[{address}]" if address.version == 6 else str(address)
    default_hosts = f"{host}:{port}"
    if address.is_loopback:
        default_hosts += f",localhost:{port}"
    hosts = tuple(
        item.strip().lower()
        for item in (env.get("YGGFLARE_MCP_ALLOWED_HOSTS") or default_hosts).split(",")
    )
    if not all(HOST_PATTERN.fullmatch(item) for item in hosts):
        raise ValueError("MCP requires explicit allowed Host values; no wildcards")
    return HTTPSettings(
        str(address),
        port,
        hosts,
        Path(env.get("YGGFLARE_MCP_TOKEN_FILE", "/config/mcp-token.txt")),
    )


def read_token(path):
    """Read only the configured secret, never include it in diagnostics."""
    try:
        with path.open("r", encoding="ascii") as handle:
            raw = handle.read(261)
            if len(raw) > 260:
                raise ValueError("MCP token file exceeds maximum length")
            token = raw.strip()
    except (OSError, UnicodeError):
        raise ValueError("MCP token file is missing or unreadable") from None
    if not TOKEN_PATTERN.fullmatch(token):
        raise ValueError("MCP token must contain 32-256 URL-safe characters")
    return token.encode("ascii")


class ProtectedApp:
    """Reject unauthorized requests before they reach MCP's protocol handler."""

    def __init__(self, app, config, token):
        self.app = app
        self.hosts = {host.encode("ascii") for host in config.hosts}
        self.authorization = b"Bearer " + token

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = scope.get("headers", [])

        def values(name):
            return [value for key, value in headers if key == name]

        hosts = values(b"host")
        auth = values(b"authorization")
        if len(hosts) != 1 or hosts[0].lower() not in self.hosts:
            response = PlainTextResponse("Invalid Host", status_code=421)
        elif values(b"origin"):
            # Native MCP clients do not need CORS. Browser origins are denied.
            response = PlainTextResponse("Origin not permitted", status_code=403)
        elif len(auth) != 1 or not hmac.compare_digest(auth[0], self.authorization):
            response = PlainTextResponse(
                "Unauthorized",
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
        else:
            await self.app(scope, receive, send)
            return
        await response(scope, receive, send)


def build_http_app(config, token, loader=None):
    options = {
        "stateless_http": True,
        "json_response": True,
        "streamable_http_path": "/mcp",
        "transport_security": TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(config.hosts),
            allowed_origins=[],
        ),
    }
    server = (
        build_server(**options) if loader is None else build_server(loader, **options)
    )
    return ProtectedApp(server.streamable_http_app(), config, token)


class HTTPListener:
    """Run one bounded ASGI listener in the controller's background thread."""

    def __init__(self, config):
        self.config = config
        app = build_http_app(config, read_token(config.token_file))
        self.server = uvicorn.Server(
            uvicorn.Config(
                app,
                host=config.bind,
                port=config.port,
                lifespan="on",
                proxy_headers=False,
                access_log=False,
                log_level="warning",
                limit_concurrency=16,
                timeout_keep_alive=5,
                timeout_graceful_shutdown=2,
            )
        )
        family = socket.AF_INET6 if ":" in config.bind else socket.AF_INET
        self.socket = socket.socket(family, socket.SOCK_STREAM)
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((config.bind, config.port))
        except OSError:
            self.socket.close()
            raise ValueError(
                "MCP listener could not bind its configured address"
            ) from None
        self.thread = threading.Thread(
            target=self.server.run,
            kwargs={"sockets": [self.socket]},
            name="yggflare-mcp",
            daemon=True,
        )

    def start(self):
        try:
            self.thread.start()
            deadline = time.monotonic() + 5
            while not self.server.started:
                if not self.thread.is_alive() or time.monotonic() >= deadline:
                    raise RuntimeError("MCP listener did not start")
                time.sleep(0.05)
        except BaseException:
            self.stop()
            raise

    def stop(self):
        self.server.should_exit = True
        if self.thread.is_alive():
            self.thread.join(timeout=3)
        self.socket.close()

    def is_alive(self):
        return self.thread.is_alive()
