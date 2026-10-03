"""HITL queue: hold does not execute; approve does; deny does not; RBAC."""

from __future__ import annotations

from fastapi.testclient import TestClient

from aegis.demo.bank import BANK


def _auth(token: str) -> dict[str, str]:
    from aegis.identity import issue_demo_token

    return {"Authorization": f"Bearer {issue_demo_token(token)}"}


def _pay(client: TestClient, session: str = "hitl-1") -> object:
    return client.post(
        "/v1/mcp/invoke",
        headers={**_auth("demo-teller"), "X-Aegis-Session": session},
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


def test_hold_then_approve_executes_payment(api_client: TestClient) -> None:
    before = BANK.payment_count
    held = _pay(api_client)
    assert held.status_code == 202
    hitl_id = held.json()["hitl_id"]
    assert BANK.payment_count == before
    approved = api_client.post(f"/v1/hitl/{hitl_id}/approve", headers=_auth("demo-admin"))
    assert approved.status_code == 200
    assert approved.json()["ok"] is True
    assert BANK.payment_count == before + 1
    assert approved.json()["result"]["status"] == "executed"


def test_hold_then_deny_does_not_execute(api_client: TestClient) -> None:
    before = BANK.payment_count
    held = _pay(api_client, session="hitl-deny")
    hitl_id = held.json()["hitl_id"]
    denied = api_client.post(f"/v1/hitl/{hitl_id}/deny", headers=_auth("demo-admin"))
    assert denied.status_code == 200
    assert denied.json()["result"] is None
    assert BANK.payment_count == before


def test_developer_cannot_approve(api_client: TestClient) -> None:
    held = _pay(api_client, session="hitl-rbac")
    hitl_id = held.json()["hitl_id"]
    res = api_client.post(f"/v1/hitl/{hitl_id}/approve", headers=_auth("demo"))
    assert res.status_code == 403
    queue = api_client.get("/v1/hitl/queue", headers=_auth("demo"))
    assert queue.status_code == 403


def test_teller_can_read_queue_admin_sees_items(api_client: TestClient) -> None:
    _pay(api_client, session="hitl-q")
    teller_q = api_client.get("/v1/hitl/queue", headers=_auth("demo-teller"))
    assert teller_q.status_code == 200
    admin_q = api_client.get("/v1/hitl/queue", headers=_auth("demo-admin"))
    assert admin_q.status_code == 200
    assert admin_q.json()["metrics"]["pending"] >= 1
    assert "history" in admin_q.json()


def test_hitl_dashboard_page(api_client: TestClient) -> None:
    res = api_client.get("/hitl")
    assert res.status_code == 200
    assert "Human-in-the-loop" in res.text
    assert "/v1/hitl/queue" in res.text


def test_queue_history_after_deny(api_client: TestClient) -> None:
    held = _pay(api_client, session="hitl-hist")
    hitl_id = held.json()["hitl_id"]
    api_client.post(f"/v1/hitl/{hitl_id}/deny", headers=_auth("demo-admin"))
    admin_q = api_client.get("/v1/hitl/queue", headers=_auth("demo-admin"))
    history = admin_q.json()["history"]
    assert any(row["id"] == hitl_id and row["status"] == "denied" for row in history)
