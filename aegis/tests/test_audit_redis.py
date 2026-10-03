"""Tests for the Redis audit-log backend and file-export endpoint."""

from __future__ import annotations

import json
import time
from pathlib import Path

import fakeredis
import pytest
from fastapi.testclient import TestClient

from aegis.audit import AuditStore, _RedisAuditLog

# ── helpers ──────────────────────────────────────────────────────────────────

def _fake_redis_log(maxlen: int = 100, ttl_days: int = 7) -> _RedisAuditLog:
    """Return a _RedisAuditLog backed by a fakeredis server."""
    log = _RedisAuditLog.__new__(_RedisAuditLog)
    log._r = fakeredis.FakeRedis(decode_responses=True)
    log._maxlen = maxlen
    log._ttl_s = ttl_days * 86_400
    return log


def _sample_event(tenant: str = "default", decision: str = "allow") -> dict:
    return {
        "ts": time.time(),
        "decision": decision,
        "profile": "balanced",
        "model": "gpt-4o",
        "tenant": tenant,
        "method": "chat.completions",
        "direction": "inbound",
        "controls_hit": [],
        "findings": [],
        "tokens": 10,
        "cost_usd": 0.0001,
        "preview": "hello world",
        "latency_ms": 2.5,
        "timings_ms": {},
        "hitl_id": None,
        "system_one": {},
        "mcp_tool": None,
    }


# ── _RedisAuditLog unit tests ─────────────────────────────────────────────────

class TestRedisAuditLog:
    def test_store_and_recent_all(self) -> None:
        log = _fake_redis_log()
        log.store(_sample_event(decision="allow"))
        log.store(_sample_event(decision="block"))

        events = log.recent(limit=10)
        assert len(events) == 2
        # Newest first (ZREVRANGE)
        assert events[0]["decision"] == "block"
        assert events[1]["decision"] == "allow"

    def test_recent_by_tenant(self) -> None:
        log = _fake_redis_log()
        log.store(_sample_event(tenant="alice", decision="allow"))
        log.store(_sample_event(tenant="bob", decision="block"))
        log.store(_sample_event(tenant="alice", decision="redact"))

        alice = log.recent(limit=10, tenant="alice")
        assert len(alice) == 2
        assert all(e["tenant"] == "alice" for e in alice)

        bob = log.recent(limit=10, tenant="bob")
        assert len(bob) == 1
        assert bob[0]["tenant"] == "bob"

    def test_maxlen_cap(self) -> None:
        log = _fake_redis_log(maxlen=3)
        for i in range(5):
            e = _sample_event()
            e["preview"] = f"msg-{i}"
            log.store(e)

        events = log.recent(limit=100)
        assert len(events) == 3
        # Only the three newest survive
        previews = [e["preview"] for e in events]
        assert "msg-4" in previews
        assert "msg-3" in previews
        assert "msg-2" in previews

    def test_age_pruning(self) -> None:
        log = _fake_redis_log(ttl_days=1)
        old = _sample_event()
        old["ts"] = time.time() - 2 * 86_400  # 2 days ago — should be pruned
        log.store(old)

        fresh = _sample_event(decision="block")
        log.store(fresh)  # triggers pruning of events older than 1 day

        events = log.recent(limit=10)
        assert len(events) == 1
        assert events[0]["decision"] == "block"

    def test_export_jsonl(self) -> None:
        log = _fake_redis_log()
        log.store(_sample_event(decision="allow"))
        log.store(_sample_event(decision="block"))

        jsonl = log.export_jsonl()
        lines = [l for l in jsonl.splitlines() if l]
        assert len(lines) == 2
        for line in lines:
            parsed = json.loads(line)
            assert "decision" in parsed

    def test_flush_to_file(self, tmp_path: Path) -> None:
        log = _fake_redis_log()
        log.store(_sample_event(decision="allow"))
        log.store(_sample_event(decision="block"))

        dest = tmp_path / "export.jsonl"
        count = log.flush_to_file(dest)

        assert dest.exists()
        assert count == 2
        lines = [l for l in dest.read_text().splitlines() if l]
        assert len(lines) == 2

    def test_recent_returns_empty_on_empty_store(self) -> None:
        log = _fake_redis_log()
        assert log.recent() == []

    def test_export_jsonl_empty(self) -> None:
        log = _fake_redis_log()
        assert log.export_jsonl() == ""


# ── AuditStore + Redis integration ───────────────────────────────────────────

def _make_audit_store_with_fake_redis(log_path: Path) -> AuditStore:
    store = AuditStore(log_path)
    store._redis = _fake_redis_log()
    return store


class TestAuditStoreRedis:
    def test_record_writes_to_redis(self, tmp_path: Path) -> None:
        from aegis.policy.models import Decision, EvaluationResult

        store = _make_audit_store_with_fake_redis(tmp_path / "audit.jsonl")
        result = EvaluationResult(
            decision=Decision.ALLOW,
            findings=[],
            original_text="hello",
            model="demo-echo",
            metadata={"tenant": "default", "method": "chat", "direction": "inbound",
                      "profile": "balanced", "latency_ms": 1.0, "timings_ms": {}},
        )
        store.record(result)

        # Recent prefers Redis
        events = store.recent(limit=10)
        assert len(events) == 1
        assert events[0]["decision"] == "allow"

    def test_recent_prefers_redis_over_memory(self, tmp_path: Path) -> None:
        from aegis.policy.models import Decision, EvaluationResult

        store = _make_audit_store_with_fake_redis(tmp_path / "audit.jsonl")
        result = EvaluationResult(
            decision=Decision.BLOCK,
            findings=[],
            original_text="test",
            model="demo-echo",
            metadata={"tenant": "t1", "method": "chat", "direction": "inbound",
                      "profile": "balanced", "latency_ms": 1.0, "timings_ms": {}},
        )
        store.record(result)

        events = store.recent(limit=10, tenant="t1")
        assert len(events) == 1
        assert events[0]["decision"] == "block"

    def test_export_to_file_uses_redis(self, tmp_path: Path) -> None:
        from aegis.policy.models import Decision, EvaluationResult

        store = _make_audit_store_with_fake_redis(tmp_path / "audit.jsonl")
        for _ in range(3):
            store.record(EvaluationResult(
                decision=Decision.ALLOW,
                findings=[],
                original_text="x",
                model="demo-echo",
                metadata={"tenant": "default", "method": "chat", "direction": "inbound",
                          "profile": "balanced", "latency_ms": 1.0, "timings_ms": {}},
            ))

        dest = tmp_path / "export.jsonl"
        count = store.export_to_file(dest)

        assert count == 3
        assert dest.exists()
        lines = [l for l in dest.read_text().splitlines() if l]
        assert len(lines) == 3

    def test_redis_error_falls_back_to_memory(self, tmp_path: Path) -> None:
        """If Redis is unreachable, recent() falls back to in-memory deque."""
        from unittest import mock

        store = _make_audit_store_with_fake_redis(tmp_path / "audit.jsonl")
        # Seed the in-memory deque directly
        from aegis.audit import AuditEvent
        store._recent.appendleft(AuditEvent(
            ts=time.time(), decision="allow", profile="balanced", model="demo-echo",
            tenant="default", method="chat", direction="inbound",
            controls_hit=[], findings=[], tokens=5, cost_usd=0.0,
            preview="fallback test",
        ))
        # Make Redis raise
        store._redis._r = mock.MagicMock()
        store._redis._r.zrevrange.side_effect = Exception("Redis down")

        events = store.recent(limit=10)
        assert len(events) == 1
        assert events[0]["preview"] == "fallback test"


# ── File-export endpoint tests ────────────────────────────────────────────────

ROOT = Path(__file__).resolve().parents[1]


def _admin_auth() -> dict[str, str]:
    from aegis.identity import issue_demo_token
    return {"Authorization": f"Bearer {issue_demo_token('demo-admin')}"}


def _dev_auth() -> dict[str, str]:
    from aegis.identity import issue_demo_token
    return {"Authorization": f"Bearer {issue_demo_token('demo')}"}


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> TestClient:
    monkeypatch.setenv("AEGIS_ROOT", str(ROOT))
    monkeypatch.setenv("AEGIS_POLICY", str(ROOT / "policies" / "policy.yaml"))
    monkeypatch.setenv("AEGIS_DEMO_ECHO", "1")
    monkeypatch.setenv("AEGIS_BUDGET_BACKEND", "memory")
    monkeypatch.setenv("AEGIS_JWT_SECRET", "test-secret-for-aegis-jwt-32bytes")
    monkeypatch.setenv("AEGIS_AUDIT_EXPORT_PATH", str(tmp_path / "export.jsonl"))

    import aegis.gateway as gateway_mod
    import aegis.identity as identity_mod
    from aegis.audit import AuditStore
    from aegis.controls.budget import BudgetTracker
    from aegis.engine import ControlEngine
    from aegis.identity import TokenRegistry
    from aegis.policy.loader import PolicyStore

    identity_mod.REGISTRY = TokenRegistry()
    gateway_mod.policy_store = PolicyStore(ROOT / "policies" / "policy.yaml", profile="balanced")
    gateway_mod.engine = ControlEngine(
        gateway_mod.policy_store, root=ROOT, budgets=BudgetTracker()
    )
    gateway_mod.audit = AuditStore(tmp_path / "audit.jsonl")
    # Default export path must be under ROOT/artifacts/ (path-traversal guard applies to it too).
    gateway_mod._AUDIT_EXPORT_PATH = ROOT / "artifacts" / "test_audit_export.jsonl"

    with TestClient(gateway_mod.app) as test_client:
        yield test_client


class TestExportFileEndpoint:
    def test_requires_admin(self, client: TestClient) -> None:
        res = client.post("/v1/audit/export/file")
        assert res.status_code == 401

        res = client.post("/v1/audit/export/file", headers=_dev_auth())
        assert res.status_code == 403

    def test_exports_to_default_path(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Seed one evaluation so there's something to export
        client.post(
            "/v1/evaluate",
            headers=_admin_auth(),
            json={"text": "hello"},
        )
        res = client.post("/v1/audit/export/file", headers=_admin_auth())
        assert res.status_code == 200
        body = res.json()
        assert body["events"] >= 1
        assert "test_audit_export.jsonl" in body["path"]
        # Cleanup
        p = Path(body["path"])
        if p.exists():
            p.unlink()

    def test_rejects_path_outside_artifacts(self, client: TestClient) -> None:
        res = client.post(
            "/v1/audit/export/file",
            headers=_admin_auth(),
            json={"path": "/etc/passwd"},
        )
        assert res.status_code == 400
        assert res.json()["detail"]["error"] == "invalid_path"

    def test_custom_path_within_artifacts(
        self, client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        dest = ROOT / "artifacts" / "test_custom_export.jsonl"
        client.post("/v1/evaluate", headers=_admin_auth(), json={"text": "hi"})

        res = client.post(
            "/v1/audit/export/file",
            headers=_admin_auth(),
            json={"path": str(dest)},
        )
        assert res.status_code == 200
        assert res.json()["path"] == str(dest)
        # Cleanup
        if dest.exists():
            dest.unlink()
