"""CLI entrypoints for Aegis."""

from __future__ import annotations

import argparse
import os
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(prog="aegis", description="Aegis AI Control Layer")
    sub = parser.add_subparsers(dest="cmd", required=True)

    serve = sub.add_parser("serve", help="Run the control-layer gateway + dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--policy", default=None, help="Path to the policy file (default policies/policy.yaml)")
    serve.add_argument("--profile", default=None, help="Profile to activate (overrides active_profile)")
    serve.add_argument("--reload", action="store_true", help="Uvicorn code reload")

    demo = sub.add_parser("demo-agent", help="Run a tiny agent through the control layer")
    demo.add_argument("--base-url", default="http://127.0.0.1:8080")
    demo.add_argument("--prompt", default="Summarize today's weather in one sentence.")
    demo.add_argument(
        "--scenario",
        default="chat",
        choices=["chat", "bank", "all"],
        help="chat probes, bank MCP/HITL table, or both",
    )

    bridge = sub.add_parser(
        "mcp-bridge",
        help="stdio MCP server that forwards to the Aegis /mcp endpoint (for stdio-only agents)",
    )
    bridge.add_argument("--url", default="http://127.0.0.1:8080/mcp")
    bridge.add_argument("--token", default=None, help="Aegis JWT (default: $AEGIS_TOKEN)")
    bridge.add_argument(
        "--demo-principal",
        choices=["demo", "demo-teller", "demo-admin"],
        default=None,
        help="Dev/demo only: mint a fresh demo JWT for every request instead of --token",
    )
    bridge.add_argument("--session", default=None, help="X-Aegis-Session: information-flow scope of this agent run")

    sub.add_parser("demo-bank-mcp", help="Run the demo bank as a stdio MCP server (an Aegis upstream)")

    token = sub.add_parser("demo-token", help="Print a JWT for a demo principal (demo, demo-teller, demo-admin)")
    token.add_argument("name", choices=["demo", "demo-teller", "demo-admin"])

    hooks = sub.add_parser("claude-hooks", help="Guard Claude Code itself: install / remove the Aegis hooks")
    hooks.add_argument("action", choices=["install", "uninstall"])
    hooks.add_argument("--settings", default=None, help="Claude settings file (default: .claude/settings.local.json)")
    hooks.add_argument("--url", default="http://127.0.0.1:8080/v1/hooks/claude-code")
    hooks.add_argument("--token", default=None, help="Aegis JWT for the hooks (default: a demo token)")
    hooks.add_argument("--demo-principal", choices=["demo", "demo-teller", "demo-admin"], default="demo")
    hooks.add_argument("--ttl-days", type=int, default=30, help="Lifetime of the demo token")
    token = sub.add_parser("token", help="Issue a local JWT for development")
    token.add_argument("--subject", default="demo")
    token.add_argument("--role", choices=["developer", "teller", "admin", "security"], default="developer")
    token.add_argument("--tenant", default="default")
    token.add_argument("--ttl", type=int, default=3600)

    args = parser.parse_args()
    if args.cmd == "serve":
        if args.policy:
            os.environ["AEGIS_POLICY"] = str(Path(args.policy).resolve())
        if args.profile:
            os.environ["AEGIS_PROFILE"] = args.profile
        import uvicorn

        uvicorn.run(
            "aegis.gateway:app",
            host=args.host,
            port=args.port,
            reload=args.reload,
        )
    elif args.cmd == "demo-agent":
        from aegis.demo.agent import run_demo

        run_demo(base_url=args.base_url, prompt=args.prompt, scenario=args.scenario)
    elif args.cmd == "mcp-bridge":
        from aegis.mcp_bridge import run_bridge

        if args.demo_principal:
            from functools import partial

            from aegis.identity import issue_demo_token

            run_bridge(args.url, partial(issue_demo_token, args.demo_principal), args.session)
            return
        jwt_token = args.token or os.environ.get("AEGIS_TOKEN")
        if not jwt_token:
            parser.error("mcp-bridge needs --token, $AEGIS_TOKEN or --demo-principal")
        run_bridge(args.url, jwt_token, args.session)
    elif args.cmd == "demo-bank-mcp":
        from aegis.demo.bank_mcp_server import main as bank_main

        bank_main()
    elif args.cmd == "claude-hooks":
        from aegis.claude_settings import DEFAULT_SETTINGS, install, uninstall

        path = Path(args.settings) if args.settings else DEFAULT_SETTINGS
        if args.action == "uninstall":
            print(f"removed Aegis hooks from {path}" if uninstall(path) else f"no Aegis hooks in {path}")
            return
        if args.token:
            hook_token = args.token
        else:
            from aegis.identity import issue_demo_token

            hook_token = issue_demo_token(args.demo_principal, ttl_seconds=args.ttl_days * 86400)
        install(path, args.url, hook_token)
        print(f"Aegis hooks installed in {path} -> {args.url}. Start a new Claude Code chat to activate them.")
    elif args.cmd == "demo-token":
        from aegis.identity import issue_demo_token

        print(issue_demo_token(args.name))
    elif args.cmd == "token":
        from aegis.identity import issue_token

        print(issue_token(args.subject, args.role, args.tenant, ttl_seconds=args.ttl))


if __name__ == "__main__":
    main()
