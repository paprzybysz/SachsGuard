"""HTTP gateway suite — proves auth, redact, tools, budgets, control-plane locks."""

from __future__ import annotations

import concurrent.futures
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis.controls.budget import BudgetTracker, SqliteBudgetTracker
from aegis.engine import ControlEngine
from aegis.policy.loader import PolicyStore
from aegis.policy.models import Action, BudgetPolicy

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("AEGIS_BUDGET_BACKEND", "memory")
    monkeypatch.setenv("AEGIS_ROOT", str(ROOT))
    monkeypatch.setenv("AEGIS_POLICY", str(ROOT / "policies" / "policy.yaml"))
    monkeypatch.setenv("AEGIS_DEMO_ECHO", "1")
    monkeypatch.setenv(
        "AEGIS_JWT_SECRET",
        "test-secret-for-aegis-jwt-32bytes",
    )

    import aegis.gateway as gateway_mod
    import aegis.identity as identity_mod
    from aegis.audit import AuditStore
    from aegis.identity import TokenRegistry

    identity_mod.REGISTRY = TokenRegistry()
    gateway_mod.policy_store = PolicyStore(ROOT / "policies" / "policy.yaml", profile="balanced")
    gateway_mod.engine = ControlEngine(
        gateway_mod.policy_store,
        root=ROOT,
        budgets=BudgetTracker(),
    )
    gateway_mod.audit = AuditStore(tmp_path / "audit.jsonl")
    gateway_mod.hitl.reset()
    from aegis.demo.bank import BANK

    BANK.reset()

    with TestClient(gateway_mod.app) as test_client:
        yield test_client


def _auth(token: str = "demo") -> dict[str, str]:
    from aegis.identity import issue_demo_token

    return {"Authorization": f"Bearer {issue_demo_token(token)}"}


def test_health_open(client: TestClient) -> None:
    assert client.get("/health").status_code == 200


def test_chat_requires_bearer(client: TestClient) -> None:
    res = client.post(
        "/v1/chat/completions",
        json={"model": "demo-echo", "messages": [{"role": "user", "content": "hi"}]},
    )
    assert res.status_code == 401


def test_evaluate_ignores_client_asserted_admin(client: TestClient) -> None:
    res = client.post(
        "/v1/evaluate",
        json={
            "text": "purge",
            "method": "admin/purge",
            "authenticated": True,
            "role": "admin",
        },
    )
    assert res.status_code == 401

    res = client.post(
        "/v1/evaluate",
        headers=_auth("demo"),
        json={
            "text": "hello",
            "method": "chat.completions",
            "authenticated": True,
            "role": "admin",
        },
    )
    assert res.status_code == 200
    assert res.json()["principal"]["role"] == "developer"


def test_control_plane_requires_admin(client: TestClient) -> None:
    assert client.get("/v1/policy").status_code == 401
    assert client.get("/v1/policy", headers=_auth("demo")).status_code == 403
    assert client.get("/v1/policy", headers=_auth("demo-admin")).status_code == 200

    assert client.post("/v1/demo/reset").status_code == 401
    assert client.post("/v1/demo/reset", headers=_auth("demo")).status_code == 403
    assert client.post("/v1/demo/reset", headers=_auth("demo-admin")).status_code == 200


def test_audit_export_requires_admin(client: TestClient) -> None:
    assert client.get("/v1/audit/export?fmt=jsonl").status_code == 401
    assert client.get("/v1/audit/export?fmt=jsonl", headers=_auth("demo")).status_code == 403
    assert client.get("/v1/audit/export?fmt=jsonl", headers=_auth("demo-admin")).status_code == 200


def test_query_string_token_rejected_on_general_endpoints(client: TestClient) -> None:
    # Tokens in the URL query string must NOT authenticate general endpoints,
    # because URLs leak via access logs, proxies, browser history and Referer.
    assert client.get("/v1/metrics?token=demo").status_code == 401
    assert client.get("/v1/events?token=demo").status_code == 401
    assert client.post("/v1/demo/reset?token=demo-admin").status_code == 401
    # Header auth still works for the same endpoints.
    assert client.get("/v1/metrics", headers=_auth("demo")).status_code == 200


def test_audit_export_allows_query_token_for_download(client: TestClient) -> None:
    # The export download link is the one deliberate exception (an <a> tag cannot
    # set an Authorization header), but it still enforces the admin role.
    from aegis.identity import issue_demo_token

    admin_token = issue_demo_token("demo-admin")
    developer_token = issue_demo_token("demo")
    assert client.get(f"/v1/audit/export?fmt=jsonl&token={admin_token}").status_code == 200
    assert client.get(f"/v1/audit/export?fmt=jsonl&token={developer_token}").status_code == 403
    assert client.get("/v1/audit/export?fmt=jsonl&token=nope").status_code == 401


def test_events_are_tenant_isolated(client: TestClient) -> None:
    import time

    import aegis.gateway as gateway_mod
    from aegis.audit import AuditEvent

    def _seed(tenant: str, preview: str) -> None:
        gateway_mod.audit._recent.appendleft(
            AuditEvent(
                ts=time.time(),
                decision="allow",
                profile="balanced",
                model="demo-echo",
                tenant=tenant,
                method="chat.completions",
                direction="inbound",
                controls_hit=[],
                findings=[],
                tokens=1,
                cost_usd=0.0,
                preview=preview,
            )
        )

    _seed("default", "default-tenant-data")
    _seed("tenant-b", "tenant-b-private-data")

    # Developer in the default tenant must not see another tenant's events/previews.
    dev = client.get("/v1/events", headers=_auth("demo")).json()["events"]
    dev_tenants = {e["tenant"] for e in dev}
    assert "tenant-b" not in dev_tenants
    assert all("tenant-b-private-data" not in e["preview"] for e in dev)

    # Control-plane (admin) may read across all tenants.
    admin = client.get("/v1/events", headers=_auth("demo-admin")).json()["events"]
    admin_tenants = {e["tenant"] for e in admin}
    assert {"default", "tenant-b"} <= admin_tenants


def test_tool_allowlist_checks_all_tools(client: TestClient) -> None:
    res = client.post(
        "/v1/chat/completions",
        headers=_auth("demo"),
        json={
            "model": "demo-echo",
            "messages": [{"role": "user", "content": "use tools"}],
            "tools": [
                {"type": "function", "function": {"name": "calculator"}},
                {"type": "function", "function": {"name": "shell_exec"}},
            ],
        },
    )
    assert res.status_code == 403
    detail = res.json()["detail"]
    assert any(f["control"] == "tool_allowlist" for f in detail["findings"])


def test_mcp_redact_returns_redacted_args(client: TestClient) -> None:
    res = client.post(
        "/v1/mcp/invoke",
        headers=_auth("demo"),
        json={
            "method": "tools/call",
            "tool_name": "echo",
            "arguments": {"email": "alice@example.com"},
        },
    )
    assert res.status_code == 200
    body = res.json()
    assert body["aegis"]["decision"] in {"redact", "degrade"}
    echoed = body["result"]["echo"]
    assert "alice@example.com" not in str(echoed)


def test_mcp_tool_authz_blocks_developer_balance(client: TestClient) -> None:
    res = client.post(
        "/v1/mcp/invoke",
        headers=_auth("demo"),
        json={
            "method": "tools/call",
            "tool_name": "get_counterparty_balance",
            "arguments": {"counterparty_id": "44"},
        },
    )
    assert res.status_code == 403
    findings = res.json()["detail"]["findings"]
    assert any(f["control"] == "tool_authz" for f in findings)


def test_mcp_tool_authz_allows_teller_balance(client: TestClient) -> None:
    res = client.post(
        "/v1/mcp/invoke",
        headers=_auth("demo-teller"),
        json={
            "method": "tools/call",
            "tool_name": "get_counterparty_balance",
            "arguments": {"counterparty_id": "44"},
        },
    )
    assert res.status_code == 200
    assert res.json()["ok"] is True


def test_openappa_blocks_github_after_teller_reads_balance(client: TestClient) -> None:
    assert (
        client.post(
            "/v1/mcp/invoke",
            headers=_auth("demo-teller"),
            json={
                "method": "tools/call",
                "tool_name": "get_counterparty_balance",
                "arguments": {"counterparty_id": "44"},
            },
        ).status_code
        == 200
    )
    res = client.post(
        "/v1/mcp/invoke",
        headers=_auth("demo-teller"),
        json={
            "method": "tools/call",
            "tool_name": "file_github_issue",
            "arguments": {"title": "customer balance"},
        },
    )
    assert res.status_code == 403
    findings = res.json()["detail"]["findings"]
    assert any(f["control"] == "information_flow" for f in findings)


def test_legacy_prometheus_endpoint_removed(client: TestClient) -> None:
    # /metrics was removed: OTEL Collector is now the sole Prometheus scrape target.
    assert client.get("/metrics").status_code == 404


def test_chat_redact_preserves_roles(client: TestClient) -> None:
    res = client.post(
        "/v1/chat/completions",
        headers=_auth("demo"),
        json={
            "model": "demo-echo",
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "Mail me at bob@example.com"},
            ],
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["aegis"]["decision"] == "redact"
    assert data["aegis"]["redacted"] is True


def test_degrade_still_redacts_pii(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_ROOT", str(ROOT))
    monkeypatch.setenv("AEGIS_POLICY", str(ROOT / "policies" / "policy.yaml"))
    monkeypatch.setenv("AEGIS_PROFILE", "permissive")
    monkeypatch.setenv("AEGIS_DEMO_ECHO", "1")
    monkeypatch.setenv("AEGIS_JWT_SECRET", "test-secret-for-aegis-jwt-32bytes")

    import aegis.gateway as gateway_mod
    import aegis.identity as identity_mod
    from aegis.audit import AuditStore
    from aegis.identity import TokenRegistry

    identity_mod.REGISTRY = TokenRegistry()
    gateway_mod.policy_store = PolicyStore(ROOT / "policies" / "policy.yaml", profile="permissive")
    budgets = BudgetTracker()
    gateway_mod.engine = ControlEngine(gateway_mod.policy_store, root=ROOT, budgets=budgets)
    gateway_mod.audit = AuditStore(tmp_path / "audit.jsonl")

    with TestClient(gateway_mod.app) as client:
        pol = gateway_mod.engine.policy.budgets
        for _ in range(pol.max_requests_per_window):
            gateway_mod.engine.budgets.commit("default", pol, tokens=1, cost_usd=0.0)

        res = client.post(
            "/v1/chat/completions",
            headers=_auth("demo"),
            json={
                "model": "demo-echo",
                "messages": [{"role": "user", "content": "email alice@example.com"}],
            },
        )
        assert res.status_code == 200
        data = res.json()
        assert data["aegis"]["decision"] == "degrade"
        assert data["aegis"]["redacted"] is True


def test_tenant_bound_to_token_not_header(client: TestClient) -> None:
    res = client.post(
        "/v1/evaluate",
        headers={**_auth("demo"), "X-Aegis-Tenant": "attacker-tenant"},
        json={"text": "hi", "tenant": "attacker-tenant"},
    )
    assert res.status_code == 200
    assert res.json()["event"]["tenant"] == "default"


def test_budget_atomic_max_requests(tmp_path: Path) -> None:
    tracker = SqliteBudgetTracker(tmp_path / "budgets.db")
    policy = BudgetPolicy(
        max_tokens_per_request=10_000,
        max_tokens_per_window=100_000,
        max_cost_usd_per_window=100,
        max_requests_per_window=1,
        window_seconds=3600,
        on_exceed=Action.BLOCK,
    )

    def once() -> bool:
        findings = tracker.check_and_commit("t", policy, tokens=1, cost_usd=0, commit=True)
        return not any(f.category == "max_requests_per_window" for f in findings)

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(lambda _: once(), range(50)))
    assert sum(results) == 1


def test_sqlite_budget_survives_reopen(tmp_path: Path) -> None:
    path = tmp_path / "budgets.db"
    a = SqliteBudgetTracker(path)
    policy = BudgetPolicy(
        max_tokens_per_request=10_000,
        max_tokens_per_window=100_000,
        max_cost_usd_per_window=100,
        max_requests_per_window=10,
        window_seconds=3600,
        on_exceed=Action.BLOCK,
    )
    a.commit("default", policy, tokens=5, cost_usd=0.01)
    b = SqliteBudgetTracker(path)
    snap = b.snapshot("default")
    assert snap["tokens"] == 5
    assert snap["requests"] == 1


# ---------- Information-flow sessions over HTTP ----------


def _mcp(client: TestClient, token: str, tool: str, args: dict, session: str | None = None):
    headers = _auth(token)
    if session:
        headers["X-Aegis-Session"] = session
    return client.post(
        "/v1/mcp/invoke",
        headers=headers,
        json={"method": "tools/call", "tool_name": tool, "arguments": args},
    )


def test_flow_taint_does_not_leak_across_callers(client: TestClient) -> None:
    assert _mcp(client, "demo-teller", "get_counterparty_balance", {"counterparty_id": "44"}).status_code == 200
    # Same tenant, different caller: untouched by the teller's read.
    assert _mcp(client, "demo-admin", "file_github_issue", {"title": "docs typo"}).status_code == 200
    assert _mcp(client, "demo-teller", "file_github_issue", {"title": "docs typo"}).status_code == 403


def test_flow_session_header_scopes_agent_trajectories(client: TestClient) -> None:
    assert _mcp(client, "demo-teller", "get_counterparty_balance", {"id": "44"}, session="run-1").status_code == 200
    assert _mcp(client, "demo-teller", "file_github_issue", {"title": "typo"}, session="run-2").status_code == 200
    assert _mcp(client, "demo-teller", "file_github_issue", {"title": "typo"}, session="run-1").status_code == 403


def test_plain_chat_never_taints_flow(client: TestClient) -> None:
    res = client.post(
        "/v1/chat/completions",
        headers=_auth("demo-teller"),
        json={"model": "demo-echo", "messages": [{"role": "user", "content": "How do I open an account?"}]},
    )
    assert res.status_code == 200
    assert _mcp(client, "demo-teller", "file_github_issue", {"title": "docs typo"}).status_code == 200


# ---------- Upstream proxy: credentials, compute budget, egress DLP ----------


class _UpstreamResponse:
    status_code = 200

    def json(self) -> dict:
        return {
            "choices": [
                {"message": {"role": "assistant", "content": "Sure: IBAN PL61109010140000071219812874"}}
            ]
        }


def test_upstream_proxy_hides_caller_token_charges_compute_and_filters_output(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    import aegis.gateway as gateway_mod

    seen: dict = {}

    class FakeAsyncClient:
        def __init__(self, *a, **k) -> None:
            pass

        async def __aenter__(self) -> FakeAsyncClient:  # noqa: PYI034
            return self

        async def __aexit__(self, *exc) -> None:
            return None

        async def post(self, url: str, json: dict, headers: dict) -> _UpstreamResponse:
            seen.update(url=url, headers=headers, payload=json)
            return _UpstreamResponse()

    monkeypatch.setattr(gateway_mod, "DEMO_MODE", False)
    monkeypatch.setattr(gateway_mod, "UPSTREAM", "http://ollama.local:11434")
    monkeypatch.setattr(gateway_mod, "UPSTREAM_API_KEY", "")
    monkeypatch.setattr(gateway_mod.httpx, "AsyncClient", FakeAsyncClient)

    res = client.post(
        "/v1/chat/completions",
        headers=_auth("demo"),
        json={"model": "gemma3:4b", "messages": [{"role": "user", "content": "Explain IBAN format"}]},
    )
    assert res.status_code == 200, res.text
    assert seen["url"] == "http://ollama.local:11434/v1/chat/completions"
    assert "Authorization" not in seen["headers"]  # Aegis credential never forwarded
    content = res.json()["choices"][0]["message"]["content"]
    assert "PL61109010140000071219812874" not in content and "[REDACTED_IBAN]" in content

    metrics = client.get("/v1/metrics", headers=_auth("demo")).json()
    assert metrics["upstream_latency"]["count"] == 1
    assert metrics["budget"]["compute_seconds"] >= 0


# ---------- Telemetry & reporting ----------


def test_otel_metrics_not_on_app_port(client: TestClient) -> None:
    # Metrics are scraped from OTEL Collector (:8889), not the app.
    assert client.get("/metrics").status_code == 404


def test_metrics_api_reports_latency_percentiles(client: TestClient) -> None:
    res = client.post("/v1/evaluate", headers=_auth("demo"), json={"text": "hello"})
    assert res.json()["latency_ms"] >= 0
    assert "historical_exploits" in res.json()["timings_ms"]
    metrics = client.get("/v1/metrics", headers=_auth("demo")).json()
    assert metrics["latency"]["count"] == 1
    assert set(metrics["latency"]) >= {"p50_ms", "p95_ms", "p99_ms"}
    assert "prompt_injection" in metrics["control_latency"]


def test_health_reports_semantic_backend_and_feed(client: TestClient) -> None:
    client.post("/v1/evaluate", headers=_auth("demo"), json={"text": "hello"})
    health = client.get("/health").json()
    assert health["semantic"]["prompt_injection"]["backend"] == "ollama"
    assert health["semantic"]["prompt_injection"]["fail_mode"] == "open"
    assert health["historical_feed"]["signatures"] >= 4
    assert health["historical_feed"]["rejected_patterns"] == []
