"""L3: a few business decisions observed through the HTTP API.

The semantic judge is a live Ollama call (``smollm2:135m`` by default, overridable
with ``AEGIS_OLLAMA_MODEL``). Chat completions still use the ``demo-echo`` model;
only the judge talks to Ollama. Skipped when that model is not reachable, so the
offline suite stays green.

Run: ``make test-l3``
"""

from __future__ import annotations

import os
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from policy_helpers import policy_data, write_policy

from aegis.audit import AuditStore
from aegis.controls import semantic
from aegis.controls.budget import BudgetTracker
from aegis.controls.text import normalize_for_matching
from aegis.demo.bank import BANK
from aegis.engine import ControlEngine
from aegis.gateway import ChatMessage, _messages_text
from aegis.hitl import HitlStore
from aegis.policy.loader import PolicyStore
from aegis.policy.models import ControlConfig

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODEL = "smollm2:135m"
OPENAI_KEY = "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCD"
SAVINGS = "What documents do I need to open a savings account?"
EMAIL = "alice.smith@example.com"
PAYMENT = "Pay the supplier invoice."


def _model() -> str:
    return os.environ.get("AEGIS_OLLAMA_MODEL", DEFAULT_MODEL)


def _ollama_ready() -> bool:
    model = _model()
    url = semantic.ollama_url(ControlConfig(backend="ollama", ollama_model=model))
    try:
        tags = httpx.get(f"{url}/api/tags", timeout=2.0).json()
    except (httpx.HTTPError, ValueError):
        return False
    return any(str(item.get("name", "")).startswith(model) for item in tags.get("models", []))


pytestmark = [
    pytest.mark.l3,
    pytest.mark.live_ollama,
    pytest.mark.skipif(
        not _ollama_ready(),
        reason=f"Ollama with {_model()} is not available",
    ),
]


def _auth(who: str) -> dict[str, str]:
    from aegis.identity import issue_demo_token

    return {"Authorization": f"Bearer {issue_demo_token(who)}"}


def _judge_verdict(text: str) -> semantic.Verdict | None:
    model = _model()
    url = semantic.ollama_url(ControlConfig(backend="ollama", ollama_model=model))
    return semantic.VERDICT_CACHE.get((url, model, normalize_for_matching(text)))


def _judge_was_consulted(text: str, findings: list[dict]) -> None:
    """The API path must have called Ollama, not the offline stub.

    A parsed verdict is cached. A tiny model that echoes the schema instead of
    choosing a label raises, and the balanced profile records ``semantic_unavailable``.
    """
    if _judge_verdict(text) is not None:
        return
    consulted = any(finding.get("category") == "semantic_unavailable" for finding in findings)
    assert consulted, "Ollama judge was not consulted"


@pytest.fixture(scope="session", autouse=True)
def _warm_ollama() -> None:
    """Load the weights once so the first API call is not paying for model startup."""
    if not _ollama_ready():
        return
    model = _model()
    url = semantic.ollama_url(ControlConfig(backend="ollama", ollama_model=model))
    httpx.post(
        f"{url}/api/chat",
        json={
            "model": model,
            "messages": [{"role": "user", "content": "Reply with the word ready."}],
            "stream": False,
            "keep_alive": "15m",
            "options": {"temperature": 0, "num_predict": 8},
        },
        timeout=180.0,
    )


@pytest.fixture
def l3_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """Gateway on the balanced policy, with the judge pointed at the small model."""
    data = policy_data()
    model = _model()
    controls = data["profiles"]["balanced"]["controls"]
    for name in ("prompt_injection", "jailbreak_detector"):
        controls[name]["backend"] = "ollama"
        controls[name]["ollama_model"] = model
        controls[name]["timeout_seconds"] = 180
    path = write_policy(tmp_path / "policy.yaml", data)

    monkeypatch.setenv("AEGIS_BUDGET_BACKEND", "memory")
    monkeypatch.setenv("AEGIS_ROOT", str(ROOT))
    monkeypatch.setenv("AEGIS_POLICY", str(path))
    monkeypatch.setenv("AEGIS_DEMO_ECHO", "1")
    monkeypatch.setenv("AEGIS_JWT_SECRET", "test-secret-for-aegis-jwt-32bytes")
    monkeypatch.setenv("AEGIS_WARMUP", "0")

    import aegis.gateway as gateway_mod
    import aegis.identity as identity_mod
    from aegis.identity import TokenRegistry

    identity_mod.REGISTRY = TokenRegistry()
    gateway_mod.policy_store = PolicyStore(path, profile="balanced")
    gateway_mod.engine = ControlEngine(
        gateway_mod.policy_store,
        root=ROOT,
        budgets=BudgetTracker(),
    )
    gateway_mod.audit = AuditStore(tmp_path / "audit.jsonl")
    gateway_mod.hitl = HitlStore()
    BANK.reset()

    with TestClient(gateway_mod.app) as client:
        yield client


def test_l3_savings_question_is_allowed(l3_client: TestClient) -> None:
    scanned = _messages_text([ChatMessage(role="user", content=SAVINGS)])
    res = l3_client.post(
        "/v1/chat/completions",
        headers=_auth("demo"),
        json={"model": "demo-echo", "messages": [{"role": "user", "content": SAVINGS}]},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    _judge_was_consulted(scanned, body["aegis"]["findings"])
    assert body["aegis"]["decision"] == "allow"
    assert body["choices"][0]["message"]["content"].startswith("[aegis:allow]")


def test_l3_openai_key_is_blocked(l3_client: TestClient) -> None:
    content = f"key {OPENAI_KEY}"
    scanned = _messages_text([ChatMessage(role="user", content=content)])
    res = l3_client.post(
        "/v1/chat/completions",
        headers=_auth("demo"),
        json={"model": "demo-echo", "messages": [{"role": "user", "content": content}]},
    )
    assert res.status_code == 403, res.text
    detail = res.json()["detail"]
    _judge_was_consulted(scanned, detail["findings"])
    assert detail["error"] == "aegis_blocked"
    assert detail["decision"] == "block"
    assert any(finding["control"] == "secrets_detector" for finding in detail["findings"])
    assert OPENAI_KEY not in res.text


def test_l3_customer_email_is_redacted(l3_client: TestClient) -> None:
    text = f"Contact {EMAIL} about the invoice."
    res = l3_client.post(
        "/v1/evaluate",
        headers=_auth("demo"),
        json={"text": text, "model": "demo-echo"},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    _judge_was_consulted(text, body["findings"])
    assert body["decision"] == "redact"
    assert body["redacted_text"] is not None
    assert EMAIL not in body["redacted_text"]
    assert any(finding["control"] == "pii_detector" for finding in body["findings"])


def test_l3_developer_payment_is_blocked(l3_client: TestClient) -> None:
    res = l3_client.post(
        "/v1/evaluate",
        headers=_auth("demo"),
        json={
            "text": PAYMENT,
            "model": "demo-echo",
            "method": "tools/call",
            "tool_name": "initiate_payment",
            "role": "admin",
            "authenticated": True,
        },
    )
    assert res.status_code == 200, res.text
    body = res.json()
    _judge_was_consulted(PAYMENT, body["findings"])
    assert body["principal"]["role"] == "developer"
    assert body["decision"] == "block"
    assert any(finding["control"] == "tool_authz" for finding in body["findings"])
