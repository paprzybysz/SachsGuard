from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Prefer in-memory budgets for unit tests (gateway tests may override).
os.environ.setdefault("AEGIS_BUDGET_BACKEND", "memory")
os.environ.setdefault("AEGIS_JWT_SECRET", "test-secret-for-aegis-jwt-32bytes")
# Never block on a background model warm-up during tests.
os.environ.setdefault("AEGIS_WARMUP", "0")

from aegis.audit import AuditStore
from aegis.controls import semantic
from aegis.controls.budget import BudgetTracker
from aegis.controls.system_one import ROUTE_CACHE
from aegis.demo.bank import BANK
from aegis.engine import ControlEngine
from aegis.hitl import HitlStore
from aegis.policy.loader import PolicyStore

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "policies" / "policy.yaml"


@pytest.fixture(autouse=True)
def offline_llm_judge(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the suite deterministic: the LLM judge answers "safe" unless a test overrides it.

    Tests marked ``live_ollama`` talk to the real local model instead.
    """
    semantic.VERDICT_CACHE.clear()
    ROUTE_CACHE.clear()
    BANK.reset()
    if request.node.get_closest_marker("live_ollama"):
        return
    monkeypatch.setattr(
        semantic, "classify_with_ollama", lambda text, cfg: semantic.Verdict(label="safe", risk=0.0)
    )


@pytest.fixture
def root() -> Path:
    return ROOT


@pytest.fixture
def engine() -> ControlEngine:
    store = PolicyStore(POLICY, profile="balanced")
    budgets = BudgetTracker()
    return ControlEngine(store, root=ROOT, budgets=budgets)


@pytest.fixture
def strict_engine() -> ControlEngine:
    return ControlEngine(
        PolicyStore(POLICY, profile="strict"),
        root=ROOT,
        budgets=BudgetTracker(),
    )


@pytest.fixture
def permissive_engine() -> ControlEngine:
    return ControlEngine(
        PolicyStore(POLICY, profile="permissive"),
        root=ROOT,
        budgets=BudgetTracker(),
    )


@pytest.fixture
def audit(tmp_path: Path) -> AuditStore:
    return AuditStore(tmp_path / "audit.jsonl")


@pytest.fixture()
def api_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("AEGIS_BUDGET_BACKEND", "memory")
    monkeypatch.setenv("AEGIS_ROOT", str(ROOT))
    monkeypatch.setenv("AEGIS_POLICY", str(POLICY))
    monkeypatch.setenv("AEGIS_DEMO_ECHO", "1")
    monkeypatch.setenv(
        "AEGIS_JWT_SECRET",
        "test-secret-for-aegis-jwt-32bytes",
    )

    import aegis.gateway as gateway_mod
    import aegis.identity as identity_mod
    from aegis.identity import TokenRegistry

    identity_mod.REGISTRY = TokenRegistry()
    gateway_mod.policy_store = PolicyStore(POLICY, profile="balanced")
    gateway_mod.engine = ControlEngine(
        gateway_mod.policy_store,
        root=ROOT,
        budgets=BudgetTracker(),
    )
    gateway_mod.audit = AuditStore(tmp_path / "audit.jsonl")
    gateway_mod.hitl = HitlStore()
    BANK.reset()

    with TestClient(gateway_mod.app) as test_client:
        yield test_client
