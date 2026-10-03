"""Runaway loop guard: max tool hops and identical repeats per session."""

from __future__ import annotations

from aegis.controls.deterministic import AuthContext
from aegis.engine import ControlEngine
from aegis.policy.models import Decision

TELLER = AuthContext(authenticated=True, role="teller")


def test_positive_loop_allows_few_tool_calls(engine: ControlEngine) -> None:
    for i in range(3):
        result = engine.evaluate(
            f'{{"n": {i}}}',
            method="tools/call",
            tool_name="echo",
            auth=TELLER,
            session="loop-ok",
        )
        assert result.decision == Decision.ALLOW, result.findings


def test_negative_loop_blocks_repeated_identical_call(engine: ControlEngine) -> None:
    payload = '{"loop": "same"}'
    last = None
    for _ in range(4):
        last = engine.evaluate(
            payload,
            method="tools/call",
            tool_name="echo",
            auth=TELLER,
            session="loop-rep",
        )
    assert last is not None
    assert last.decision == Decision.BLOCK
    assert any(f.control == "loop_guard" and f.category == "max_repeated_tool" for f in last.findings)


def test_negative_loop_blocks_too_many_tool_calls(engine: ControlEngine) -> None:
    last = None
    for i in range(9):
        last = engine.evaluate(
            f'{{"n": {i}}}',
            method="tools/call",
            tool_name="echo",
            auth=TELLER,
            session="loop-max",
        )
    assert last is not None
    assert last.decision == Decision.BLOCK
    assert any(f.control == "loop_guard" and f.category == "max_tool_calls_per_session" for f in last.findings)


def test_loop_sessions_are_isolated(engine: ControlEngine) -> None:
    payload = '{"loop": "same"}'
    for _ in range(3):
        a = engine.evaluate(payload, method="tools/call", tool_name="echo", auth=TELLER, session="iso-a")
        assert a.decision == Decision.ALLOW
    b = engine.evaluate(payload, method="tools/call", tool_name="echo", auth=TELLER, session="iso-b")
    assert b.decision == Decision.ALLOW
