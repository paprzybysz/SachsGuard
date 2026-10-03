"""System One (JEV analog): typed allow/hold/block with calibrated probabilities."""

from __future__ import annotations

import pytest

from aegis.controls.deterministic import AuthContext
from aegis.controls.semantic import SemanticBackendError
from aegis.controls.system_one import evaluate_system_one, extract_amount_pln, heuristic_route
from aegis.engine import ControlEngine
from aegis.policy.models import Action, ControlConfig, Decision, FailMode, Finding, Strictness


def test_extract_amount_from_json() -> None:
    assert extract_amount_pln('{"amount_pln": 5000}') == 5000.0
    assert extract_amount_pln("kwota 12.5 PLN") == 12.5


def test_positive_system_one_allows_benign_chat(engine: ControlEngine) -> None:
    result = engine.evaluate("What is the capital of France?", model="demo-echo")
    assert result.decision == Decision.ALLOW
    assert not any(f.control == "system_one" for f in result.findings)


def test_negative_system_one_holds_initiate_payment(engine: ControlEngine) -> None:
    result = engine.evaluate(
        '{"from_account": "1001", "amount_pln": 5000}',
        method="tools/call",
        tool_name="initiate_payment",
        auth=AuthContext(authenticated=True, role="teller"),
        session="s1-pay",
    )
    assert result.decision == Decision.HOLD
    assert any(f.control == "system_one" and f.action == Action.HOLD for f in result.findings)
    assert result.metadata.get("system_one", {}).get("verdict") == "hold"


def test_system_one_holds_over_amount_threshold(engine: ControlEngine) -> None:
    result = engine.evaluate(
        '{"amount_pln": 1500, "note": "wire"}',
        method="tools/call",
        tool_name="echo",
        auth=AuthContext(authenticated=True, role="teller"),
        session="s1-amt",
    )
    assert result.decision == Decision.HOLD
    assert "payment" in (result.metadata.get("system_one") or {}).get("labels", [])


def test_system_one_does_not_hold_small_echo_amount(engine: ControlEngine) -> None:
    result = engine.evaluate(
        '{"amount_pln": 20, "note": "ok"}',
        method="tools/call",
        tool_name="echo",
        auth=AuthContext(authenticated=True, role="teller"),
        session="s1-small",
    )
    assert result.decision == Decision.ALLOW, result.findings


def test_strict_holds_counterparty_read(strict_engine: ControlEngine) -> None:
    result = strict_engine.evaluate(
        "show balance for counterparty 44",
        method="tools/call",
        tool_name="get_counterparty_balance",
        auth=AuthContext(authenticated=True, role="teller"),
        session="s1-strict",
    )
    assert result.decision == Decision.HOLD
    assert any(f.control == "system_one" for f in result.findings)


def test_system_one_fail_open(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise SemanticBackendError("down")

    monkeypatch.setattr("aegis.controls.system_one.route_with_ollama", boom)
    cfg = ControlConfig(backend="ollama", fail_mode=FailMode.OPEN, action=Action.HOLD)
    findings, meta = evaluate_system_one(
        text="hello",
        tool_names=[],
        role="developer",
        hop_count=0,
        findings=[],
        cfg=cfg,
    )
    assert findings and findings[0].category == "semantic_unavailable"
    assert findings[0].action == Action.LOG
    assert meta.get("verdict") == "allow"


def test_system_one_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise SemanticBackendError("down")

    monkeypatch.setattr("aegis.controls.system_one.route_with_ollama", boom)
    cfg = ControlConfig(backend="ollama", fail_mode=FailMode.CLOSED, action=Action.HOLD)
    findings, _ = evaluate_system_one(
        text="hello",
        tool_names=[],
        role="developer",
        hop_count=0,
        findings=[],
        cfg=cfg,
    )
    assert findings[0].action == Action.BLOCK


def test_heuristic_block_when_prior_block_findings() -> None:
    cfg = ControlConfig(action=Action.HOLD, hitl_tools=["initiate_payment"], adherence=0.6)
    prior = [
        Finding(
            control="secrets_detector",
            severity=Strictness.HIGH,
            action=Action.BLOCK,
            confidence=1.0,
            message="secret",
        )
    ]
    decision = heuristic_route(
        text="hi",
        tool_names=[],
        role="developer",
        hop_count=0,
        findings=prior,
        cfg=cfg,
    )
    assert decision.verdict == "block"
