"""The demo bank as a real MCP server (stdio) — the upstream Aegis sits in front of.

Run it directly (``aegis demo-bank-mcp``) or let the gateway launch it from the
``mcp.upstreams`` section of ``policies/policy.yaml``. It knows nothing about
policy: every guardrail is applied by Aegis before a call reaches it.

The caller's role and tenant arrive in the request ``_meta`` under
``AEGIS_META_KEY`` (set by the Aegis proxy); a client talking to this server
directly is treated as an anonymous teller.
"""

from __future__ import annotations

import json
from typing import Any

import anyio
import mcp_types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from aegis.demo.bank import BankError, BankTools

AEGIS_META_KEY = "io.aegis/principal"


def _schema(**props: str) -> dict[str, Any]:
    return {"type": "object", "properties": {name: {"type": kind} for name, kind in props.items()}}


TOOLS: list[types.Tool] = [
    types.Tool(name="echo", description="Echo the arguments back.", input_schema=_schema(note="string")),
    types.Tool(
        name="get_account_balance",
        description="Balance of the caller's own account.",
        input_schema=_schema(account_id="string"),
    ),
    types.Tool(
        name="get_counterparty_balance",
        description="Balance and KYC data of a business counterparty (restricted).",
        input_schema=_schema(counterparty_id="string"),
    ),
    types.Tool(
        name="list_transactions",
        description="Recent transactions on the caller's account.",
        input_schema=_schema(account_id="string"),
    ),
    types.Tool(
        name="initiate_payment",
        description="Send a payment from the caller's account.",
        input_schema=_schema(amount_pln="number", to_iban="string", title="string"),
    ),
    types.Tool(
        name="get_ticket_from_crm",
        description="Read a customer support ticket from the CRM.",
        input_schema=_schema(ticket_id="string"),
    ),
    types.Tool(
        name="file_github_issue",
        description="Create a PUBLIC GitHub issue.",
        input_schema=_schema(title="string", body="string"),
    ),
    types.Tool(name="send_email", description="Send an internal email.", input_schema=_schema(to="string", subject="string", body="string")),
    types.Tool(name="calculator", description="Evaluate an expression.", input_schema=_schema(expression="string")),
    types.Tool(name="search", description="Search internal docs.", input_schema=_schema(query="string")),
    types.Tool(name="get_weather", description="Weather for a location.", input_schema=_schema(location="string")),
    types.Tool(name="list_files", description="List shared files.", input_schema=_schema()),
    types.Tool(name="read_file", description="Read a shared file.", input_schema=_schema(path="string")),
]


def _caller(meta: Any) -> tuple[str, str]:
    data = meta.model_dump() if hasattr(meta, "model_dump") else dict(meta or {})
    principal = data.get(AEGIS_META_KEY) or {}
    return str(principal.get("role") or "teller"), str(principal.get("tenant") or "default")


def build_server(bank: BankTools | None = None) -> Server[Any]:
    tools_impl = bank or BankTools()

    async def list_tools(ctx: Any, params: types.PaginatedRequestParams | None) -> types.ListToolsResult:
        return types.ListToolsResult(tools=TOOLS)

    async def call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        role, tenant = _caller(params.meta)
        try:
            result = tools_impl.dispatch(params.name, dict(params.arguments or {}), role=role, tenant=tenant)
        except BankError as exc:
            return types.CallToolResult(content=[types.TextContent(type="text", text=str(exc))], is_error=True)
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(result, ensure_ascii=False))],
            structured_content=result,
        )

    return Server("aegis-demo-bank", version="1.0.0", on_list_tools=list_tools, on_call_tool=call_tool)


def main() -> None:
    server = build_server()

    async def _run() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    anyio.run(_run)


if __name__ == "__main__":
    main()
