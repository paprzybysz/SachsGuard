"""Connections from Aegis to the real MCP servers it proxies (``policy.mcp.upstreams``).

Each upstream gets one long-lived client connection, opened lazily on first use
and owned by its own task (MCP transports must be entered and exited in the same
task). When the upstream section of the policy changes, every connection is
closed and reopened on the next request; a connection that fails is retried on
the next request after ``RETRY_SECONDS``.
"""

from __future__ import annotations

import logging
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import anyio
import mcp_types as types
from anyio.abc import TaskGroup
from mcp import Client, StdioServerParameters
from mcp.client.stdio import get_default_environment

from aegis.policy.models import McpUpstream

logger = logging.getLogger("aegis.mcp")

RETRY_SECONDS = 5.0

Connector = Callable[[McpUpstream], Client]


class UpstreamUnavailable(RuntimeError):
    """No upstream could serve the request."""


def default_connector(cfg: McpUpstream) -> Client:
    if cfg.transport == "streamable_http":
        return Client(str(cfg.url), read_timeout_seconds=cfg.timeout_seconds)
    command = sys.executable if cfg.command in {"python", "python3"} else str(cfg.command)
    env = {**get_default_environment(), **cfg.env} if cfg.env else None
    params = StdioServerParameters(command=command, args=list(cfg.args), env=env)
    return Client(params, read_timeout_seconds=cfg.timeout_seconds)


@dataclass
class _Connection:
    cfg: McpUpstream
    client: Client | None = None
    tools: list[types.Tool] = field(default_factory=list)
    error: str | None = None
    failed_at: float = 0.0
    ready: anyio.Event = field(default_factory=anyio.Event)
    stop: anyio.Event = field(default_factory=anyio.Event)


class UpstreamPool:
    def __init__(self, connector: Connector | None = None) -> None:
        self.connector = connector or default_connector
        self._tg: TaskGroup | None = None
        self._lock: anyio.Lock | None = None
        self._config: tuple[McpUpstream, ...] = ()
        self._connections: dict[str, _Connection] = {}

    # --- lifecycle (bound to the gateway lifespan) ---------------------------
    def attach(self, tg: TaskGroup) -> None:
        self._tg = tg
        self._lock = anyio.Lock()
        self._config = ()
        self._connections = {}

    async def aclose(self) -> None:
        await self.aclose_connections()
        self._tg = None

    # --- public API -----------------------------------------------------------
    async def tools(self, upstreams: list[McpUpstream]) -> dict[str, tuple[str, types.Tool]]:
        """Tool name → (upstream name, tool). The first upstream wins a name clash."""
        await self._sync(upstreams)
        catalog: dict[str, tuple[str, types.Tool]] = {}
        for cfg in upstreams:
            conn = await self._connected(upstreams, cfg.name)
            if conn is None:
                continue
            for tool in conn.tools:
                if tool.name in catalog:
                    logger.warning("mcp tool %r from %r shadowed by %r", tool.name, cfg.name, catalog[tool.name][0])
                    continue
                catalog[tool.name] = (cfg.name, tool)
        return catalog

    async def call(
        self,
        upstreams: list[McpUpstream],
        upstream: str,
        tool: str,
        arguments: dict[str, Any],
        meta: dict[str, Any] | None,
    ) -> types.CallToolResult:
        conn = await self._connected(upstreams, upstream)
        if conn is None or conn.client is None:
            raise UpstreamUnavailable(f"MCP upstream {upstream!r} is unavailable")
        try:
            return await conn.client.call_tool(tool, arguments, meta=meta)
        except Exception as exc:  # transport died: reconnect next time
            self._drop(upstream, f"{type(exc).__name__}: {exc}")
            raise UpstreamUnavailable(f"MCP upstream {upstream!r} failed: {exc}") from exc

    def status(self) -> list[dict[str, Any]]:
        return [
            {
                "name": name,
                "transport": conn.cfg.transport,
                "connected": conn.client is not None,
                "tools": len(conn.tools),
                "error": conn.error,
            }
            for name, conn in self._connections.items()
        ]

    # --- internals ------------------------------------------------------------
    async def _sync(self, upstreams: list[McpUpstream]) -> None:
        """Close every connection when the upstream section of the policy changed."""
        if self._tg is None or self._lock is None:
            raise UpstreamUnavailable("MCP proxy is not running (gateway lifespan not started)")
        async with self._lock:
            config = tuple(upstreams)
            if config != self._config:
                await self.aclose_connections()
                self._config = config

    async def _connected(self, upstreams: list[McpUpstream], name: str) -> _Connection | None:
        await self._sync(upstreams)
        assert self._tg is not None and self._lock is not None
        async with self._lock:
            conn = self._connections.get(name)
            if conn is not None and conn.ready.is_set() and (conn.client is None or conn.stop.is_set()):
                if time.monotonic() - conn.failed_at < RETRY_SECONDS:
                    return None
                self._connections.pop(name, None)
                conn = None
            if conn is None:
                cfg = next((u for u in upstreams if u.name == name), None)
                if cfg is None:
                    return None
                conn = self._connections[name] = _Connection(cfg=cfg)
                self._tg.start_soon(self._run, conn)
        with anyio.move_on_after(conn.cfg.timeout_seconds):
            await conn.ready.wait()
        return conn if conn.client is not None else None

    async def aclose_connections(self) -> None:
        for conn in self._connections.values():
            conn.stop.set()
        self._connections = {}

    def _drop(self, name: str, error: str) -> None:
        """Close a broken connection; it is reopened after RETRY_SECONDS."""
        conn = self._connections.get(name)
        if conn is not None:
            conn.error = error
            conn.failed_at = time.monotonic()
            conn.stop.set()

    async def _run(self, conn: _Connection) -> None:
        try:
            async with self.connector(conn.cfg) as client:
                tools: list[types.Tool] = []
                cursor: str | None = None
                while True:
                    page = await client.list_tools(cursor=cursor)
                    tools.extend(page.tools)
                    cursor = page.next_cursor
                    if not cursor:
                        break
                conn.tools = tools
                conn.client = client
                conn.error = None
                conn.ready.set()
                logger.info("mcp upstream %r connected (%d tools)", conn.cfg.name, len(tools))
                await conn.stop.wait()
        except Exception as exc:  # noqa: BLE001 — surfaced on /health, retried later
            conn.error = f"{type(exc).__name__}: {exc}"[:500]
            conn.failed_at = time.monotonic()
            logger.error("mcp upstream %r failed: %s", conn.cfg.name, conn.error)
        finally:
            conn.client = None
            conn.ready.set()
