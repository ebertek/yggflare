"""Optional authenticated Streamable HTTP transport for Yggflare."""

import hmac
import ipaddress
import json
import os
import re
import socket
import stat
import threading
import time
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

import uvicorn
from mcp.server.transport_security import TransportSecuritySettings
from mcp_server import GROUPS, build_server, enabled_tools
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse

TOKEN_PATTERN = re.compile(r"[A-Za-z0-9._~-]{32,256}")
HOST_PATTERN = re.compile(r"[A-Za-z0-9.:\[\]-]{1,253}")
PRINCIPAL_PATTERN = re.compile(r"[a-z][a-z0-9_-]{0,31}")
MAX_PRINCIPALS = 8
PRINCIPAL_CONFIG = Path("/config/mcp-principals.json")


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
    principals_file: Path | None = None


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
    principals = env.get("YGGFLARE_MCP_PRINCIPALS_FILE", "")
    if principals and principals != str(PRINCIPAL_CONFIG):
        raise ValueError("MCP principals require the fixed private configuration path")
    if principals and not address.is_loopback:
        raise ValueError("MCP principal mode requires loopback binding")
    return HTTPSettings(
        str(address),
        port,
        hosts,
        Path(env.get("YGGFLARE_MCP_TOKEN_FILE", "/config/mcp-token.txt")),
        PRINCIPAL_CONFIG if principals else None,
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


def private_read(path, maximum):
    """Principal manifests and tokens must be bounded private regular files."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_mode & 0o077
                or not 0 < info.st_size <= maximum
            ):
                raise ValueError("Invalid private MCP credential file")
            data = handle.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError("Invalid private MCP credential file")
        return data
    except OSError:
        raise ValueError("Missing or unreadable private MCP credential file") from None


@dataclass(frozen=True, repr=False)
class Principal:
    name: str
    token: bytes
    groups: tuple[str, ...]


def read_principals(path, env=None):
    """Explicit opt-in replaces, rather than supplements, the legacy token."""
    env = os.environ if env is None else env
    enabled_tools(env)  # Validate the server-wide ceiling first.
    raw = env.get("YGGFLARE_MCP_TOOL_GROUPS", "all")
    ceiling = set(GROUPS) if raw == "all" else set(raw.split(","))
    try:
        document = json.loads(private_read(path, 16 * 1024))
    except (UnicodeError, ValueError):
        raise ValueError("Invalid private MCP principal configuration") from None
    if (
        not isinstance(document, dict)
        or set(document) != {"version", "principals"}
        or type(document["version"]) is not int
        or document["version"] != 1
        or not isinstance(document["principals"], list)
        or not 1 <= len(document["principals"]) <= MAX_PRINCIPALS
    ):
        raise ValueError("Invalid private MCP principal configuration")
    principals = []
    names = set()
    for entry in document["principals"]:
        if not isinstance(entry, dict) or set(entry) != {"name", "groups"}:
            raise ValueError("Invalid MCP principal entry")
        name, groups = entry["name"], entry["groups"]
        if (
            not isinstance(name, str)
            or not PRINCIPAL_PATTERN.fullmatch(name)
            or name in names
            or not isinstance(groups, list)
            or not groups
            or not all(isinstance(group, str) for group in groups)
            or len(set(groups)) != len(groups)
            or set(groups) - ceiling
        ):
            raise ValueError("Invalid MCP principal identity or group scope")
        # Fixed sibling filenames; the manifest cannot select arbitrary paths.
        try:
            token = (
                private_read(path.parent / ("mcp-token-" + name + ".txt"), 260)
                .decode("ascii")
                .strip()
            )
        except UnicodeError:
            raise ValueError("Invalid MCP principal token") from None
        if not TOKEN_PATTERN.fullmatch(token):
            raise ValueError("Invalid MCP principal token")
        encoded = token.encode("ascii")
        if any(hmac.compare_digest(encoded, item.token) for item in principals):
            raise ValueError("MCP principal tokens must be distinct")
        names.add(name)
        principals.append(Principal(name, encoded, tuple(groups)))
    return principals


class PrincipalApp:
    """Authenticate each stateless request and dispatch to a scoped MCP server."""

    def __init__(self, config, principals, loader=None, env=None, *, audit_log=None):
        self.hosts = {host.encode("ascii") for host in config.hosts}
        self.routes = []
        env = dict(os.environ if env is None else env)
        slots = threading.BoundedSemaphore(4)
        for principal in principals:
            scoped = {**env, "YGGFLARE_MCP_TOOL_GROUPS": ",".join(principal.groups)}
            server = (
                build_server(env=scoped, slots=slots, audit_log=audit_log)
                if loader is None
                else build_server(loader, env=scoped, slots=slots, audit_log=audit_log)
            )
            self.routes.append(
                (
                    b"Bearer " + principal.token,
                    server.streamable_http_app(**http_options(config)),
                )
            )

        @asynccontextmanager
        async def lifespan(_app):
            async with AsyncExitStack() as stack:
                for _, app in self.routes:
                    await stack.enter_async_context(app.router.lifespan_context(app))
                yield

        # Each SDK app has an independent session manager. Start and stop all
        # of them through one parent ASGI lifespan; never share their scopes.
        self.lifecycle = Starlette(lifespan=lifespan)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.lifecycle(scope, receive, send)
            return
        headers = scope.get("headers", [])
        hosts = [value for key, value in headers if key == b"host"]
        auth = [value for key, value in headers if key == b"authorization"]
        if len(hosts) != 1 or hosts[0].lower() not in self.hosts:
            response = PlainTextResponse("Invalid Host", status_code=421)
        elif any(key == b"origin" for key, _ in headers):
            response = PlainTextResponse("Origin not permitted", status_code=403)
        else:
            selected = None
            if len(auth) == 1:
                # Compare all bounded entries before choosing the matching app.
                for expected, app in self.routes:
                    if hmac.compare_digest(auth[0], expected):
                        selected = app
            if selected is not None:
                await selected(scope, receive, send)
                return
            response = PlainTextResponse(
                "Unauthorized",
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
        await response(scope, receive, send)


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


def http_options(config):
    return {
        "stateless_http": True,
        "json_response": True,
        "streamable_http_path": "/mcp",
        "transport_security": TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(config.hosts),
            allowed_origins=[],
        ),
    }


def build_http_app(config, token, loader=None, *, audit_log=None):
    server = (
        build_server(audit_log=audit_log)
        if loader is None
        else build_server(loader, audit_log=audit_log)
    )
    return ProtectedApp(
        server.streamable_http_app(**http_options(config)), config, token
    )


def configured_app(config, loader=None, env=None, *, audit_log=None):
    if config.principals_file is not None:
        return PrincipalApp(
            config,
            read_principals(config.principals_file, env),
            loader,
            env,
            audit_log=audit_log,
        )
    return build_http_app(
        config, read_token(config.token_file), loader, audit_log=audit_log
    )


class HTTPListener:
    """Run one bounded ASGI listener in the controller's background thread."""

    def __init__(self, config, *, audit_log=None):
        self.config = config
        app = configured_app(config, audit_log=audit_log)
        self.server = uvicorn.Server(
            uvicorn.Config(
                app,
                host=config.bind,
                port=config.port,
                lifespan="on",
                proxy_headers=False,
                access_log=False,
                log_level="warning",
                log_config=None,
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
