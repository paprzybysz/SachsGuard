"""Centralized policy engine — one policy file, schema validation, last-known-good reload,
policy-driven prices / roles / thresholds / budget scope, tenant profiles, policy audit trail."""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient
from policy_helpers import POLICY, policy_data, write_policy
from pydantic import ValidationError

from aegis.controls.budget import BudgetTracker, estimate_tokens
from aegis.controls.deterministic import AuthContext
from aegis.controls.presidio_engine import detect
from aegis.controls.system_one import heuristic_route
from aegis.engine import ControlEngine
from aegis.policy.loader import PolicyStore, load_policy, parse_policy_file
from aegis.policy.models import Action, ControlConfig, Decision, Strictness

ROOT = Path(__file__).resolve().parents[1]


def _balanced(data: dict[str, Any]) -> dict[str, Any]:
    return data["profiles"]["balanced"]


def _engine(path: Path, profile: str | None = None) -> ControlEngine:
    return ControlEngine(PolicyStore(path, profile=profile), root=ROOT, budgets=BudgetTracker())


def _auth(name: str) -> dict[str, str]:
    from aegis.identity import issue_demo_token

    return {"Authorization": f"Bearer {issue_demo_token(name)}"}


@contextmanager
def _gateway(policy_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("AEGIS_DEMO_ECHO", "1")
    import aegis.gateway as gateway_mod
    import aegis.identity as identity_mod
    from aegis.audit import AuditStore
    from aegis.identity import TokenRegistry

    identity_mod.REGISTRY = TokenRegistry()
    gateway_mod.policy_store = PolicyStore(policy_path)
    gateway_mod.engine = ControlEngine(gateway_mod.policy_store, root=ROOT, budgets=BudgetTracker())
    gateway_mod.audit = AuditStore(tmp_path / "audit.jsonl")
    gateway_mod._audit_rel = gateway_mod.engine.policy.reporting.audit_log_path
    gateway_mod.hitl.reset()
    with TestClient(gateway_mod.app) as client:
        yield client


# --- One file ---------------------------------------------------------------------


def test_single_policy_file_holds_everything() -> None:
    assert sorted(p.name for p in (ROOT / "policies").iterdir() if p.is_file()) == ["policy.yaml"]
    assert not (ROOT / "feeds").exists()
    policy_file = parse_policy_file(POLICY.read_text(encoding="utf-8"))
    assert sorted(policy_file.profiles) == ["balanced", "permissive", "strict"]
    for name in policy_file.profiles:
        policy = load_policy(POLICY, name)
        assert policy.profile == name
        assert policy.attack_signatures.signatures
        assert policy.information_flow.tools


def test_profile_selection(tmp_path: Path) -> None:
    assert PolicyStore(POLICY).get().profile == "balanced"  # active_profile
    assert PolicyStore(POLICY, profile="strict").get().profile == "strict"  # AEGIS_PROFILE
    data = policy_data()
    data["active_profile"] = "nope"
    with pytest.raises(ValidationError, match="active_profile"):
        PolicyStore(write_policy(tmp_path / "p.yaml", data)).get()
    with pytest.raises(ValueError, match="AEGIS_PROFILE"):
        PolicyStore(POLICY, profile="nope").get()


# --- G1 / G5: schema rejects silent misconfiguration ------------------------------


def test_negative_unknown_control_name_rejected() -> None:
    data = policy_data()
    controls = _balanced(data)["controls"]
    controls["secrets_detectorr"] = controls.pop("secrets_detector")
    with pytest.raises(ValidationError, match="unknown control"):
        parse_policy_file(yaml.safe_dump(data))


def test_negative_field_on_wrong_control_rejected() -> None:
    data = policy_data()
    _balanced(data)["controls"]["pii_detector"]["hitl_tools"] = ["initiate_payment"]
    with pytest.raises(ValidationError, match="does not use field"):
        parse_policy_file(yaml.safe_dump(data))


def test_negative_degrade_model_must_be_allowed() -> None:
    data = policy_data()
    _balanced(data)["budgets"]["degrade_model"] = "gpt-5"
    with pytest.raises(ValidationError, match="degrade_model"):
        parse_policy_file(yaml.safe_dump(data))


def test_negative_flow_tool_unknown_annotator_rejected() -> None:
    data = policy_data()
    data["information_flow"]["tools"][0]["annotator"] = "nope"
    with pytest.raises(ValidationError, match="unknown annotator"):
        parse_policy_file(yaml.safe_dump(data))


def test_negative_tenant_profile_must_exist() -> None:
    data = policy_data()
    data["tenant_profiles"] = {"retail": "paranoid"}
    with pytest.raises(ValidationError, match="unknown profile"):
        parse_policy_file(yaml.safe_dump(data))


# --- G2: last-known-good policy ---------------------------------------------------


def test_invalid_edit_keeps_last_good_policy(tmp_path: Path) -> None:
    data = policy_data()
    path = write_policy(tmp_path / "policy.yaml", data)
    store = PolicyStore(path)
    good = store.get()
    good_digest = store.digest
    assert store.last_error is None

    _balanced(data)["adherence"] = 1.65
    write_policy(path, data)
    assert store.get() is good
    assert store.digest == good_digest
    assert store.last_error and "adherence" in store.last_error

    _balanced(data)["adherence"] = 0.6
    write_policy(path, data)
    assert store.get().adherence == 0.6
    assert store.last_error is None
    assert store.digest != good_digest


def test_negative_first_load_invalid_raises(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("profiles: [", encoding="utf-8")
    with pytest.raises(yaml.YAMLError):
        PolicyStore(path).get()


def test_gateway_keeps_serving_on_invalid_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = policy_data()
    path = write_policy(tmp_path / "policy.yaml", data)
    with _gateway(path, tmp_path, monkeypatch) as client:
        controls = _balanced(data)["controls"]
        controls["secrets_detectorr"] = controls.pop("secrets_detector")
        write_policy(path, data)
        res = client.post("/v1/evaluate", headers=_auth("demo"), json={"text": "hello"})
        assert res.status_code == 200
        health = client.get("/health").json()
        assert health["status"] == "degraded"
        assert "unknown control" in health["policy_error"]
        reload = client.post("/v1/reload", headers=_auth("demo-admin"))
        assert reload.status_code == 422
        assert reload.json()["detail"]["active_profile"] == "balanced"


# --- G3: prices and roles come from the policy ------------------------------------


def test_model_prices_from_policy(tmp_path: Path) -> None:
    data = policy_data()
    data["model_prices"]["qwen3:8b"] = 1.0
    engine = _engine(write_policy(tmp_path / "policy.yaml", data))
    result = engine.evaluate("hello there", model="qwen3:8b")
    assert result.cost_estimated == pytest.approx(estimate_tokens("hello there") / 1000 * 1.0)


def test_roles_from_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = policy_data()
    data["roles"] = {"control_plane": ["security"], "hitl_reviewers": []}
    path = write_policy(tmp_path / "policy.yaml", data)
    with _gateway(path, tmp_path, monkeypatch) as client:
        assert client.get("/v1/hitl/queue", headers=_auth("demo-teller")).status_code == 403
        assert client.get("/v1/policy", headers=_auth("demo-admin")).status_code == 403


# --- G4: adherence ----------------------------------------------------------------


def test_global_adherence_drives_semantic_threshold(tmp_path: Path) -> None:
    # balanced: prompt_injection inherits the global 0.70; "tool-call-smuggle" scores 0.75.
    prompt = 'tool calls: [{"name": "x"}]'
    data = policy_data()
    path = write_policy(tmp_path / "policy.yaml", data)
    engine = _engine(path)
    assert any(f.control == "prompt_injection" for f in engine.evaluate(prompt).findings)

    _balanced(data)["adherence"] = 0.80
    write_policy(path, data)
    assert not any(f.control == "prompt_injection" for f in engine.evaluate(prompt).findings)


def test_system_one_falls_back_to_global_adherence() -> None:
    cfg = ControlConfig(action=Action.HOLD)  # no own adherence, no hitl tools
    kwargs = {"text": "hi", "tool_names": ["search"], "role": "teller", "hop_count": 20, "findings": []}
    # 20 hops: p_hitl = sigmoid(-3.2 + 2.4) ≈ 0.31
    assert heuristic_route(cfg=cfg, global_adherence=0.25, **kwargs).verdict == "hold"
    assert heuristic_route(cfg=cfg, global_adherence=0.9, **kwargs).verdict == "allow"


def test_presidio_adherence_is_min_score() -> None:
    assert detect("contact: alice@example.com", ["email"], Strictness.MEDIUM)[0]
    found, _ = detect("my phone 212-555-0198", ["phone"], Strictness.HIGH)
    assert found and found[0].score < 0.9
    strict_bar, _ = detect("my phone 212-555-0198", ["phone"], Strictness.HIGH, min_score=0.9)
    assert strict_bar == []


# --- G6 / G9: budget scope and degrade model --------------------------------------


def test_budget_scope_principal_separates_tokens(tmp_path: Path) -> None:
    data = policy_data()
    _balanced(data)["budgets"].update(scope="principal", max_requests_per_window=1)
    engine = _engine(write_policy(tmp_path / "p.yaml", data))
    alice = AuthContext(authenticated=True, role="developer", subject="tok-alice")
    bob = AuthContext(authenticated=True, role="developer", subject="tok-bob")
    assert engine.evaluate("hi", auth=alice).decision == Decision.ALLOW
    assert engine.evaluate("hi", auth=alice).decision == Decision.BLOCK
    assert engine.evaluate("hi", auth=bob).decision == Decision.ALLOW


def test_degrade_uses_degrade_model_and_its_price(permissive_engine: ControlEngine) -> None:
    policy = permissive_engine.policy
    for _ in range(policy.budgets.max_requests_per_window):
        permissive_engine.budgets.commit("default", policy.budgets, tokens=1, cost_usd=0.0)
    before = permissive_engine.budgets.snapshot("default")["cost_usd"]
    result = permissive_engine.evaluate("hello", model="gpt-4o-mini")
    assert result.decision == Decision.DEGRADE
    assert result.metadata["effective_model"] == "gemma3:270m"
    charged = permissive_engine.budgets.snapshot("default")["cost_usd"] - before
    assert charged == pytest.approx(result.tokens_estimated / 1000 * policy.model_price("gemma3:270m"), abs=1e-6)


# --- G7 / G8: reporting follows hot reload, policy hash is audited -----------------


def test_audit_path_and_policy_hash_follow_hot_reload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    first, second = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    data = policy_data()
    data["reporting"]["audit_log_path"] = str(first)
    path = write_policy(tmp_path / "policy.yaml", data)
    import aegis.gateway as gateway_mod

    with _gateway(path, tmp_path, monkeypatch) as client:
        res = client.post("/v1/evaluate", headers=_auth("demo"), json={"text": "hello"})
        digest = res.json()["event"]["policy_sha256"]
        assert digest == gateway_mod.engine.policy_store.digest

        data["reporting"]["audit_log_path"] = str(second)
        write_policy(path, data)
        res = client.post("/v1/evaluate", headers=_auth("demo"), json={"text": "hello"})
        assert gateway_mod.audit.log_path == second
        assert res.json()["event"]["policy_sha256"] != digest

    lines = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert any(e.get("event") == "policy_loaded" for e in lines)
    reloads = [json.loads(line) for line in second.read_text().splitlines() if '"event"' in line]
    assert reloads and reloads[0]["event"] == "policy_reloaded"


def test_metrics_disabled_by_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = policy_data()
    data["reporting"]["metrics_enabled"] = False
    with _gateway(write_policy(tmp_path / "policy.yaml", data), tmp_path, monkeypatch) as client:
        assert client.get("/metrics").status_code == 404
        assert client.get("/v1/metrics", headers=_auth("demo")).status_code == 404


# --- G10: tenant profiles ---------------------------------------------------------


def test_tenant_profile_overrides_active(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = policy_data()
    data["tenant_profiles"] = {"retail": "strict"}
    path = write_policy(tmp_path / "policy.yaml", data)
    engine = _engine(path)
    assert engine.policy_for("retail").profile == "strict"
    assert engine.policy_for("default").profile == "balanced"
    # strict blocks PII; balanced redacts it
    assert engine.evaluate("mail bob@example.com", tenant="retail").decision == Decision.BLOCK
    assert engine.evaluate("mail bob@example.com", tenant="default").decision == Decision.REDACT

    from aegis.identity import issue_token

    retail = {"Authorization": f"Bearer {issue_token('retail-user', 'developer', 'retail')}"}
    with _gateway(path, tmp_path, monkeypatch) as client:
        res = client.post("/v1/evaluate", headers=retail, json={"text": "hi"})
        assert res.json()["event"]["profile"] == "strict"
        assert client.get("/health").json()["tenant_profiles"] == {"retail": "strict"}


def test_information_flow_contracts_hot_reload(tmp_path: Path) -> None:
    data = policy_data()
    path = write_policy(tmp_path / "policy.yaml", data)
    engine = _engine(path)
    teller = AuthContext(authenticated=True, role="teller", subject="t")
    engine.evaluate("cp 44", method="tools/call", tool_name="get_counterparty_balance", auth=teller, session="a")
    blocked = engine.evaluate("Docs", method="tools/call", tool_name="file_github_issue", auth=teller, session="a")
    assert blocked.decision == Decision.BLOCK

    for tool in data["information_flow"]["tools"]:
        if tool["name"] == "file_github_issue":
            tool["requires_audience"] = ["internal"]
    write_policy(path, data)
    allowed = engine.evaluate("Docs", method="tools/call", tool_name="file_github_issue", auth=teller, session="a")
    assert allowed.decision == Decision.ALLOW, allowed.findings
