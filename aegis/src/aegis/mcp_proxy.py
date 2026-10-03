"""MCP proxy: Aegis as an MCP server in front of real MCP servers.

    agent ──MCP──▶ Aegis /mcp ──MCP──▶ policy.mcp.upstreams (stdio / Streamable HTTP)

* ``tools/list`` aggregates the upstream catalogs and hides every tool the
  caller's role may not call (``tool_allowlist`` + ``tool_authz``).
* ``tools/call`` runs the same guard as ``/v1/mcp/invoke`` (all controls of the
  caller's profile), forwards the possibly redacted arguments, then screens the
  result (information flow + egress DLP) before the agent sees it.
* A ``hold`` decision does not execute the tool: the call is queued for a human
  and the agent can poll ``aegis_hitl_status``.

Identity is the JWT in ``Authorization: Bearer``; ``X-Aegis-Session`` scopes the
information-flow label to one agent run, as on the REST API.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

import anyio
import mcp_types as types
from anyio.abc import TaskGroup
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.responses import JSONResponse

from aegis.identity import Principal
from aegis.mcp_upstreams import UpstreamPool, UpstreamUnavailable
from aegis.policy.models import McpUpstream

logger = logging.getLogger("aegis.mcp")

# Key under which the caller's identity is forwarded to upstreams in ``_meta``.
AEGIS_META_KEY = "io.aegis/principal"
HITL_STATUS_TOOL = "aegis_hitl_status"

_HITL_STATUS = types.Tool(
    name=HITL_STATUS_TOOL,
    description=(
        "Aegis: status of a tool call held for human approval (pending / approved / denied / "
        "expired) and, once approved, its result."
    ),
    input_schema={
        "type": "object",
        "properties": {"hitl_id": {"type": "string"}},
        "required": ["hitl_id"],
    },
)


@dataclass
class Precheck:
    """Outcome of the policy guard for one tool call, before anything executes."""

    decision: Literal["allow", "block", "hold"]
    arguments: dict[str, Any] = field(default_factory=dict)
    payload: dict[str, Any] = field(default_factory=dict)


class OutputBlocked(Exception):
    """The tool result may not reach the caller (information flow / DLP block)."""

    def __init__(self, detail: dict[str, Any]) -> None:
        super().__init__(detail.get("error", "aegis_output_blocked"))
        self.detail = detail


class GatewayHooks(Protocol):
    """What the proxy needs from the gateway (implemented in ``aegis.gateway``)."""

    def resolve_principal(self, authorization: str | None) -> Principal | None: ...

    def session_key(self, principal: Principal, session_id: str | None) -> str: ...

    def upstreams(self) -> list[McpUpstream]: ...

    def visible_tools(self, principal: Principal, names: list[str]) -> set[str]: ...

    def precheck(
        self, principal: Principal, session: str, tool_name: str, arguments: dict[str, Any], origin: str
    ) -> Precheck: ...

    def screen_output(self, raw: Any, tool_name: str, principal: Principal, session: str) -> Any: ...

    def hitl_status(self, principal: Principal, hitl_id: str) -> dict[str, Any] | None: ...


def _text_result(payload: Any, *, is_error: bool = False) -> types.CallToolResult:
    structured = payload if isinstance(payload, dict) else None
    text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=text)],
        structured_content=structured,
        is_error=is_error,
    )


def result_payload(result: types.CallToolResult) -> Any:
    """The data inside an upstream result: structured content, else the (JSON) text."""
    if result.structured_content is not None:
        return result.structured_content
    texts = [c.text for c in result.content if isinstance(c, types.TextContent)]
    text = "\n".join(texts)
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return text


def _identity_meta(cfg: McpUpstream, principal: Principal) -> dict[str, Any] | None:
    if not cfg.forward_identity:
        return None
    return {AEGIS_META_KEY: {"role": principal.role, "tenant": principal.tenant}}


class McpProxy:
    """Agent-facing MCP server + Streamable HTTP endpoint, bound to the gateway lifespan."""

    def __init__(self, hooks: GatewayHooks, pool: UpstreamPool | None = None) -> None:
        self.hooks = hooks
        self.pool = pool or UpstreamPool()
        self.server: Server[Any] = Server(
            "aegis",
            version="1.0.0",
            instructions=(
                "Aegis AI control layer. Tool calls are checked against the organisation's "
                "policy; a held call returns a hitl_id you can poll with aegis_hitl_status."
            ),
            on_list_tools=self._list_tools,
            on_call_tool=self._call_tool,
        )
        self._manager: StreamableHTTPSessionManager | None = None

    # --- lifecycle --------------------------------------------------------------
    @asynccontextmanager
    async def running(self, tg: TaskGroup) -> AsyncIterator[None]:
        # A fresh manager per lifespan: StreamableHTTPSessionManager.run() is single-use.
        # Stateless: every request carries its own JWT, so no MCP session state is needed.
        self._manager = StreamableHTTPSessionManager(app=self.server, stateless=True, json_response=True)
        self.pool.attach(tg)
        try:
            async with self._manager.run():
                yield
        finally:
            await self.pool.aclose()
            self._manager = None

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        """ASGI endpoint for ``/mcp``: authenticate, then hand over to the MCP transport."""
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        principal = self.hooks.resolve_principal(headers.get("authorization"))
        if principal is None:
            response = JSONResponse(
                {"error": "aegis_auth_required"},
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer realm="aegis"'},
            )
            await response(scope, receive, send)
            return
        if self._manager is None:
            await JSONResponse({"error": "aegis_mcp_not_running"}, status_code=503)(scope, receive, send)
            return
        scope.setdefault("state", {})["aegis_principal"] = principal
        await self._manager.handle_request(scope, receive, send)

    def status(self) -> dict[str, Any]:
        return {"running": self._manager is not None, "upstreams": self.pool.status()}

    # --- handlers -----------------------------------------------------------------
    def _caller(self, ctx: Any) -> tuple[Principal, str]:
        request = ctx.request
        principal: Principal = request.state.aegis_principal
        session = self.hooks.session_key(principal, request.headers.get("x-aegis-session"))
        return principal, session

    async def _list_tools(self, ctx: Any, params: types.PaginatedRequestParams | None) -> types.ListToolsResult:
        principal, _ = self._caller(ctx)
        catalog = await self.pool.tools(self.hooks.upstreams())
        visible = self.hooks.visible_tools(principal, list(catalog))
        tools = [tool for name, (_, tool) in catalog.items() if name in visible]
        return types.ListToolsResult(tools=[*tools, _HITL_STATUS])

    async def _call_tool(self, ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        principal, session = self._caller(ctx)
        name = params.name
        arguments = dict(params.arguments or {})

        if name == HITL_STATUS_TOOL:
            status = self.hooks.hitl_status(principal, str(arguments.get("hitl_id") or ""))
            if status is None:
                return _text_result({"error": "aegis_hitl_not_found"}, is_error=True)
            return _text_result(status)

        upstreams = self.hooks.upstreams()
        catalog = await self.pool.tools(upstreams)
        if name not in catalog:
            return _text_result({"error": "aegis_tool_unknown", "tool_name": name}, is_error=True)
        upstream = catalog[name][0]

        check = await anyio.to_thread.run_sync(
            self.hooks.precheck, principal, session, name, arguments, f"mcp:{upstream}"
        )
        if check.decision != "allow":
            return _text_result(check.payload, is_error=True)

        cfg = next(u for u in upstreams if u.name == upstream)
        try:
            result = await self.pool.call(upstreams, upstream, name, check.arguments, _identity_meta(cfg, principal))
        except UpstreamUnavailable as exc:
            return _text_result({"error": "aegis_upstream_unavailable", "message": str(exc)}, is_error=True)

        try:
            screened = await anyio.to_thread.run_sync(
                self.hooks.screen_output, result_payload(result), name, principal, session
            )
        except OutputBlocked as exc:
            return _text_result(exc.detail, is_error=True)
        return _text_result(screened, is_error=bool(result.is_error))

    # --- HITL ----------------------------------------------------------------------
    async def execute_approved(self, upstream: str, tool_name: str, arguments: dict[str, Any], principal: Principal) -> Any:
        """Run a held MCP call after a human approved it; returns the raw upstream payload."""
        upstreams = self.hooks.upstreams()
        cfg = next((u for u in upstreams if u.name == upstream), None)
        if cfg is None:
            raise UpstreamUnavailable(f"MCP upstream {upstream!r} is no longer configured")
        result = await self.pool.call(upstreams, upstream, tool_name, arguments, _identity_meta(cfg, principal))
        return result_payload(result)
