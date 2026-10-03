"""Bank MCP: real tool dispatch (not echo), AuthZ, egress DLP."""

from __future__ import annotations

from fastapi.testclient import TestClient

from aegis.demo.bank import BANK


def _auth(token: str) -> dict[str, str]:
    from aegis.identity import issue_demo_token

    return {"Authorization": f"Bearer {issue_demo_token(token)}"}


def test_teller_balance_is_real_and_iban_redacted(api_client: TestClient) -> None:
    res = api_client.post(
        "/v1/mcp/invoke",
        headers=_auth("demo-teller"),
        json={"method": "tools/call", "tool_name": "get_account_balance", "arguments": {}},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["ok"] is True
    assert "echo" not in body["result"] or "balance_pln" in body["result"]
    assert body["result"].get("balance_pln") == 42150.55 or "balance_pln" in str(body["result"])
    dumped = str(body)
    assert "PL61109010140000071219812874" not in dumped
    assert "REDACTED_IBAN" in dumped or "REDACTED" in dumped


def test_developer_cannot_read_counterparty(api_client: TestClient) -> None:
    res = api_client.post(
        "/v1/mcp/invoke",
        headers=_auth("demo"),
        json={
            "method": "tools/call",
            "tool_name": "get_counterparty_balance",
            "arguments": {"counterparty_id": "44"},
        },
    )
    assert res.status_code == 403
    assert any(f["control"] == "tool_authz" for f in res.json()["detail"]["findings"])


def test_teller_counterparty_returns_bank_payload(api_client: TestClient) -> None:
    res = api_client.post(
        "/v1/mcp/invoke",
        headers=_auth("demo-teller"),
        json={
            "method": "tools/call",
            "tool_name": "get_counterparty_balance",
            "arguments": {"counterparty_id": "44"},
        },
    )
    assert res.status_code == 200
    result = res.json()["result"]
    assert result.get("counterparty_id") == "44" or result.get("name")
    assert "ACME" in str(result) or "REDACTED" in str(result)


def test_unknown_tool_still_blocked_by_allowlist(api_client: TestClient) -> None:
    res = api_client.post(
        "/v1/mcp/invoke",
        headers=_auth("demo-admin"),
        json={"method": "tools/call", "tool_name": "shell_exec", "arguments": {}},
    )
    assert res.status_code == 403


def test_payment_not_executed_until_approved(api_client: TestClient) -> None:
    before = BANK.payment_count
    res = api_client.post(
        "/v1/mcp/invoke",
        headers=_auth("demo-teller"),
        json={
            "method": "tools/call",
            "tool_name": "initiate_payment",
            "arguments": {
                "from_account": "1001",
                "to_iban": "PL27114020040000300201355387",
                "amount_pln": 5000,
            },
        },
    )
    assert res.status_code == 202
    assert res.json()["decision"] == "hold"
    assert BANK.payment_count == before
