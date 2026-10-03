"""stdio ↔ Aegis bridge for agents that only launch MCP servers as subprocesses.

    agent ──stdio──▶ aegis mcp-bridge ──Streamable HTTP + JWT──▶ Aegis /mcp ──▶ upstreams

The bridge holds no policy: it forwards tools/list and tools/call to the gateway,
so every decision, HITL hold and audit event happens in the gateway.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

import anyio
import httpx2
import mcp_types as types
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

logger = logging.getLogger("aegis.mcp_bridge")


def run_bridge(url: str, token: str | Callable[[], str], session: str | None = None) -> None:
    """``token`` is a JWT, or a callable minting one per request (demo principals).

    The bridge starts even when the gateway is down and connects per request (the
    gateway's /mcp is stateless), so starting Aegis after the agent just works.
    """
    headers = {"X-Aegis-Session": session} if session else {}

    async def _authorize(request: httpx2.Request) -> None:
        jwt = token() if callable(token) else token
        request.headers["Authorization"] = f"Bearer {jwt}"

    def _unreachable(exc: BaseException) -> str:
        return f"Aegis gateway at {url} is unreachable ({type(exc).__name__}). Start it with: make serve"

    async def _main() -> None:
        http = httpx2.AsyncClient(
            headers=headers, timeout=httpx2.Timeout(120.0), event_hooks={"request": [_authorize]}
        )

        async def list_tools(ctx: Any, params: types.PaginatedRequestParams | None) -> types.ListToolsResult:
            try:
                async with Client(streamable_http_client(url, http_client=http)) as gateway:
                    return await gateway.list_tools(cursor=params.cursor if params else None)
            except Exception as exc:  # noqa: BLE001 — gateway down: no tools yet
                logger.warning(_unreachable(exc))
                return types.ListToolsResult(tools=[])

        async def call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
            try:
                async with Client(streamable_http_client(url, http_client=http)) as gateway:
                    return await gateway.call_tool(params.name, dict(params.arguments or {}))
            except Exception as exc:  # noqa: BLE001 — reported to the agent as a tool error
                return types.CallToolResult(
                    content=[types.TextContent(type="text", text=_unreachable(exc))], is_error=True
                )

        server = Server("aegis-bridge", version="1.0.0", on_list_tools=list_tools, on_call_tool=call_tool)
        async with http, stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    anyio.run(_main)
