"""Security reporting — realtime metrics + exportable audit log."""

from __future__ import annotations

import csv
import io
import json
import logging
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

from aegis.policy.models import EvaluationResult


class _RedisAuditLog:
    """Persist audit events in Redis sorted sets (score = Unix timestamp).

    Two keys are maintained:
    - ``aegis:audit:events``          — all tenants, capped at *maxlen*
    - ``aegis:audit:tenant:<name>``   — per-tenant, capped at *maxlen*

    Old entries are pruned on every write (by age AND by count), so the key
    never grows unbounded even under heavy traffic.  The ``redis`` package is
    imported lazily so the rest of the application starts normally when Redis
    is not installed or not configured.
    """

    _KEY_ALL = "aegis:audit:events"
    _KEY_TENANT = "aegis:audit:tenant:{}"

    def __init__(self, url: str, *, maxlen: int = 10_000, ttl_days: int = 7) -> None:
        try:
            import redis as redis_lib
        except ImportError as exc:
            raise RuntimeError(
                "AEGIS_AUDIT_BACKEND=redis requires the redis package. "
                "Install with: pip install 'aegis[redis]'"
            ) from exc
        self._r = redis_lib.Redis.from_url(url, decode_responses=True)
        self._maxlen = maxlen
        self._ttl_s = ttl_days * 86_400

    def store(self, event: dict[str, Any]) -> None:
        ts = float(event.get("ts", time.time()))
        payload = json.dumps(event, ensure_ascii=False, default=str)
        tenant = str(event.get("tenant", "default"))
        cutoff = ts - self._ttl_s

        pipe = self._r.pipeline()
        for key in (self._KEY_ALL, self._KEY_TENANT.format(tenant)):
            pipe.zadd(key, {payload: ts})
            # Prune by age first, then cap by absolute count.
            pipe.zremrangebyscore(key, "-inf", cutoff)
            pipe.zremrangebyrank(key, 0, -(self._maxlen + 1))
        pipe.execute()

    def recent(self, limit: int = 50, tenant: str | None = None) -> list[dict[str, Any]]:
        key = self._KEY_TENANT.format(tenant) if tenant else self._KEY_ALL
        raw: list[str] = self._r.zrevrange(key, 0, limit - 1)
        out: list[dict[str, Any]] = []
        for item in raw:
            try:
                out.append(json.loads(item))
            except json.JSONDecodeError:
                pass
        return out

    def export_jsonl(self) -> str:
        """Return all stored events as a JSONL string (oldest first)."""
        raw: list[str] = self._r.zrange(self._KEY_ALL, 0, -1)
        return "\n".join(raw) + "\n" if raw else ""

    def flush_to_file(self, path: Path) -> int:
        """Write all events to *path* as JSONL; return the number of lines written."""
        content = self.export_jsonl()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return content.count("\n") if content else 0

# Prometheus-style latency buckets (milliseconds).
LATENCY_BUCKETS_MS: tuple[float, ...] = (0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000)


@dataclass
class LatencyHistogram:
    """Cumulative bucket counts for /metrics plus a recent window for percentiles."""

    bucket_counts: list[int] = field(default_factory=lambda: [0] * len(LATENCY_BUCKETS_MS))
    count: int = 0
    sum_ms: float = 0.0
    recent: deque[float] = field(default_factory=lambda: deque(maxlen=2048))

    def observe(self, ms: float) -> None:
        self.count += 1
        self.sum_ms += ms
        self.recent.append(ms)
        for i, bound in enumerate(LATENCY_BUCKETS_MS):
            if ms <= bound:
                self.bucket_counts[i] += 1

    def percentile(self, q: float) -> float:
        if not self.recent:
            return 0.0
        ordered = sorted(self.recent)
        index = min(len(ordered) - 1, max(0, round(q * (len(ordered) - 1))))
        return round(ordered[index], 3)

    def summary(self) -> dict[str, float | int]:
        return {
            "count": self.count,
            "avg_ms": round(self.sum_ms / self.count, 3) if self.count else 0.0,
            "p50_ms": self.percentile(0.50),
            "p95_ms": self.percentile(0.95),
            "p99_ms": self.percentile(0.99),
        }


@dataclass
class AuditEvent:
    ts: float
    decision: str
    profile: str
    model: str | None
    tenant: str
    method: str
    direction: str
    controls_hit: list[str]
    findings: list[dict[str, Any]]
    tokens: int
    cost_usd: float
    preview: str
    latency_ms: float = 0.0
    timings_ms: dict[str, float] = field(default_factory=dict)
    hitl_id: str | None = None
    system_one: dict[str, Any] = field(default_factory=dict)
    mcp_tool: str | None = None
    policy_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": self.ts,
            "decision": self.decision,
            "profile": self.profile,
            "model": self.model,
            "tenant": self.tenant,
            "method": self.method,
            "direction": self.direction,
            "controls_hit": self.controls_hit,
            "findings": self.findings,
            "tokens": self.tokens,
            "cost_usd": self.cost_usd,
            "preview": self.preview,
            "latency_ms": self.latency_ms,
            "timings_ms": self.timings_ms,
            "hitl_id": self.hitl_id,
            "system_one": self.system_one,
            "mcp_tool": self.mcp_tool,
            "policy_sha256": self.policy_sha256,
        }


@dataclass
class Metrics:
    total: int = 0
    allowed: int = 0
    redacted: int = 0
    blocked: int = 0
    degraded: int = 0
    held: int = 0
    tokens: int = 0
    cost_usd: float = 0.0
    by_control: Counter[str] = field(default_factory=Counter)
    by_category: Counter[str] = field(default_factory=Counter)
    # Control-layer overhead per evaluation, per control, and upstream model time.
    latency: LatencyHistogram = field(default_factory=LatencyHistogram)
    control_latency: dict[str, LatencyHistogram] = field(default_factory=dict)
    upstream_latency: LatencyHistogram = field(default_factory=LatencyHistogram)

    def observe_timings(self, total_ms: float, timings_ms: dict[str, float]) -> None:
        self.latency.observe(total_ms)
        for control, ms in timings_ms.items():
            self.control_latency.setdefault(control, LatencyHistogram()).observe(ms)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "allowed": self.allowed,
            "redacted": self.redacted,
            "blocked": self.blocked,
            "degraded": self.degraded,
            "held": self.held,
            "tokens": self.tokens,
            "cost_usd": round(self.cost_usd, 6),
            "block_rate": round(self.blocked / self.total, 4) if self.total else 0.0,
            "by_control": dict(self.by_control),
            "by_category": dict(self.by_category),
            "security_posture": self.posture(),
            "latency": self.latency.summary(),
            "control_latency": {name: h.summary() for name, h in sorted(self.control_latency.items())},
            "upstream_latency": self.upstream_latency.summary(),
        }

    def posture(self) -> str:
        if self.total == 0:
            return "unknown"
        rate = self.blocked / self.total
        if rate >= 0.25:
            return "elevated"
        if rate >= 0.05:
            return "guarded"
        return "stable"


class AuditStore:
    def __init__(
        self,
        log_path: Path,
        *,
        maxlen: int = 500,
        redis_url: str | None = None,
        redis_maxlen: int = 10_000,
        redis_ttl_days: int = 7,
    ) -> None:
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._recent: deque[AuditEvent] = deque(maxlen=maxlen)
        self.metrics = Metrics()
        self._redis: _RedisAuditLog | None = (
            _RedisAuditLog(redis_url, maxlen=redis_maxlen, ttl_days=redis_ttl_days)
            if redis_url
            else None
        )

    def record(self, result: EvaluationResult) -> AuditEvent:
        meta = result.metadata
        event = AuditEvent(
            ts=time.time(),
            decision=result.decision.value,
            profile=str(meta.get("profile", "")),
            model=result.model,
            tenant=str(meta.get("tenant", "default")),
            method=str(meta.get("method", "")),
            direction=str(meta.get("direction", "")),
            controls_hit=sorted({f.control for f in result.findings}),
            findings=[f.model_dump() for f in result.findings],
            tokens=result.tokens_estimated,
            cost_usd=result.cost_estimated,
            preview=(result.redacted_text or result.original_text)[:160],
            latency_ms=float(meta.get("latency_ms", 0.0)),
            timings_ms=dict(meta.get("timings_ms") or {}),
            hitl_id=str(meta["hitl_id"]) if meta.get("hitl_id") else None,
            system_one=dict(meta.get("system_one") or {}),
            mcp_tool=str(meta["tool_name"]) if meta.get("tool_name") else None,
            policy_sha256=str(meta["policy_sha256"]) if meta.get("policy_sha256") else None,
        )
        with self._lock:
            self._recent.appendleft(event)
            m = self.metrics
            m.total += 1
            decision = result.decision.value
            if decision == "allow":
                m.allowed += 1
            elif decision == "redact":
                m.redacted += 1
            elif decision == "block":
                m.blocked += 1
            elif decision == "degrade":
                m.degraded += 1
            elif decision == "hold":
                m.held += 1
            m.tokens += result.tokens_estimated
            m.cost_usd += result.cost_estimated
            m.observe_timings(event.latency_ms, event.timings_ms)
            for finding in result.findings:
                m.by_control[finding.control] += 1
                if finding.category:
                    m.by_category[finding.category] += 1
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
        # Fan out to Redis (if configured) — outside the lock; Redis client is thread-safe.
        if self._redis is not None:
            try:
                self._redis.store(event.to_dict())
            except Exception as exc:  # noqa: BLE001
                _log.warning("audit Redis store failed (falling back to file+memory): %s", exc)
        # Emit structured OTEL audit log outside the lock (logging is thread-safe).
        # Imported lazily to avoid a circular import at module level.
        from aegis.telemetry import emit_audit_log
        emit_audit_log(event.to_dict())
        return event

    def record_policy_change(
        self,
        *,
        event: str,
        path: str,
        profile: str,
        policy_sha256: str | None,
        error: str | None = None,
    ) -> dict[str, Any]:
        """Append a control-plane event (policy_loaded / policy_reloaded / policy_rejected).

        Written to the JSONL trail only; it is not a request decision, so it does not
        count in metrics or the recent-events feed.
        """
        entry = {
            "ts": time.time(),
            "event": event,
            "policy_path": path,
            "profile": profile,
            "policy_sha256": policy_sha256,
            "error": error,
        }
        with self._lock, self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def observe_upstream(self, ms: float) -> None:
        with self._lock:
            self.metrics.upstream_latency.observe(ms)

    def recent(self, limit: int = 50, tenant: str | None = None) -> list[dict[str, Any]]:
        # Prefer Redis when available: it holds the full history across replicas.
        if self._redis is not None:
            try:
                return self._redis.recent(limit, tenant)
            except Exception as exc:  # noqa: BLE001
                _log.warning("audit Redis recent() failed (falling back to memory): %s", exc)
        with self._lock:
            events = list(self._recent)
        if tenant is not None:
            events = [e for e in events if e.tenant == tenant]
        return [e.to_dict() for e in events[:limit]]

    def export_jsonl(self) -> str:
        # Redis holds a larger history than the local file window.
        if self._redis is not None:
            try:
                return self._redis.export_jsonl()
            except Exception as exc:  # noqa: BLE001
                _log.warning("audit Redis export_jsonl() failed (falling back to file): %s", exc)
        if not self.log_path.is_file():
            return ""
        return self.log_path.read_text(encoding="utf-8")

    def export_to_file(self, path: Path) -> int:
        """Write the full audit log to *path* as JSONL; return the number of events written.

        When a Redis backend is active the export pulls from Redis (complete,
        multi-replica history).  Otherwise it re-reads the local JSONL log file.
        """
        if self._redis is not None:
            try:
                return self._redis.flush_to_file(path)
            except Exception as exc:  # noqa: BLE001
                _log.warning("audit Redis flush_to_file() failed (falling back to file): %s", exc)
        content = self.export_jsonl()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return content.count("\n") if content else 0

    @staticmethod
    def _csv_safe(value: str) -> str:
        """Neutralize spreadsheet formula injection on export cells."""
        text = value.replace("\n", " ").replace("\r", " ")
        if text and text[0] in {"=", "+", "-", "@", "\t", "\r"}:
            return "'" + text
        return text

    def export_csv(self) -> str:
        rows = self.recent(limit=10_000)
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf,
            fieldnames=[
                "ts",
                "decision",
                "profile",
                "model",
                "tenant",
                "controls_hit",
                "tokens",
                "cost_usd",
                "latency_ms",
                "policy_sha256",
                "preview",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "ts": row["ts"],
                    "decision": row["decision"],
                    "profile": row["profile"],
                    "model": row["model"],
                    "tenant": row["tenant"],
                    "controls_hit": "|".join(row["controls_hit"]),
                    "tokens": row["tokens"],
                    "cost_usd": row["cost_usd"],
                    "latency_ms": row.get("latency_ms", 0.0),
                    "policy_sha256": row.get("policy_sha256") or "",
                    "preview": self._csv_safe(str(row["preview"])),
                }
            )
        return buf.getvalue()

    def reset_metrics(self) -> None:
        with self._lock:
            self.metrics = Metrics()
            self._recent.clear()
