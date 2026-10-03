"""Budget and resource governance — in-memory, SQLite, or Redis backends.

All backends share one windowing / check / commit implementation
(:class:`_WindowedBudgetTracker`); each backend only implements storage.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from aegis.policy.models import DEFAULT_MODEL_PRICES, Action, BudgetPolicy, Finding, Strictness


@dataclass
class WindowCounters:
    tokens: int = 0
    cost_usd: float = 0.0
    requests: int = 0
    compute_seconds: float = 0.0
    window_start: float = field(default_factory=time.time)

    def add_request(self, *, tokens: int, cost_usd: float) -> None:
        self.tokens += tokens
        self.cost_usd += cost_usd
        self.requests += 1

    def to_dict(self) -> dict[str, float | int]:
        return {
            "tokens": self.tokens,
            "cost_usd": round(self.cost_usd, 6),
            "requests": self.requests,
            "compute_seconds": round(self.compute_seconds, 4),
            "window_start": self.window_start,
        }

    @classmethod
    def from_mapping(cls, row: Any) -> WindowCounters:
        def get(key: str, default: Any) -> Any:
            try:
                value = row[key]
            except (KeyError, IndexError):
                return default
            return default if value is None else value

        return cls(
            tokens=int(get("tokens", 0)),
            cost_usd=float(get("cost_usd", 0.0)),
            requests=int(get("requests", 0)),
            compute_seconds=float(get("compute_seconds", 0.0)),
            window_start=float(get("window_start", time.time())),
        )


class BudgetStore(Protocol):
    def check(self, tenant: str, policy: BudgetPolicy, *, tokens: int, cost_usd: float) -> list[Finding]: ...

    def commit(self, tenant: str, policy: BudgetPolicy, *, tokens: int, cost_usd: float) -> None: ...

    def check_and_commit(
        self,
        tenant: str,
        policy: BudgetPolicy,
        *,
        tokens: int,
        cost_usd: float,
        commit: bool,
        degraded_cost_usd: float | None = None,
    ) -> list[Finding]: ...

    def record_compute(self, tenant: str, policy: BudgetPolicy, seconds: float) -> None: ...

    def snapshot(self, tenant: str = "default") -> dict[str, float | int]: ...

    def snapshot_all(self) -> dict[str, dict[str, float | int]]: ...

    def reset(self, tenant: str | None = None) -> None: ...


def _finding(category: str, message: str, policy: BudgetPolicy) -> Finding:
    return Finding(
        control="budget",
        severity=Strictness.HIGH,
        action=policy.on_exceed,
        confidence=1.0,
        message=message,
        category=category,
    )


def _budget_findings(
    counters: WindowCounters,
    policy: BudgetPolicy,
    *,
    tokens: int,
    cost_usd: float,
) -> list[Finding]:
    checks = [
        (
            tokens > policy.max_tokens_per_request,
            "max_tokens_per_request",
            f"Request tokens {tokens} exceed per-request limit {policy.max_tokens_per_request}",
        ),
        (
            counters.tokens + tokens > policy.max_tokens_per_window,
            "max_tokens_per_window",
            "Window token budget exceeded",
        ),
        (
            counters.cost_usd + cost_usd > policy.max_cost_usd_per_window,
            "max_cost_usd_per_window",
            "Window cost budget exceeded",
        ),
        (
            counters.requests + 1 > policy.max_requests_per_window,
            "max_requests_per_window",
            "Window request budget exceeded",
        ),
        (
            policy.max_compute_seconds_per_window is not None
            and counters.compute_seconds >= policy.max_compute_seconds_per_window,
            "max_compute_seconds_per_window",
            (
                f"Window compute budget exhausted ({counters.compute_seconds:.1f}s of "
                f"{policy.max_compute_seconds_per_window}s model time)"
            ),
        ),
    ]
    return [_finding(category, message, policy) for hit, category, message in checks if hit]


def _would_block(findings: list[Finding]) -> bool:
    return any(f.action == Action.BLOCK for f in findings)


def _would_degrade(findings: list[Finding]) -> bool:
    return any(f.action == Action.DEGRADE for f in findings)


class _WindowedBudgetTracker:
    """Sliding-window budget logic shared by every storage backend.

    Subclasses provide ``_session`` (a transaction handle) plus ``_read``,
    ``_write``, ``_delete`` and ``_tenants``. Every public operation runs as one
    read-modify-write under ``self._lock`` inside one ``_session``, so check and
    commit are atomic per process (and per SQLite transaction).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()

    # --- storage hooks -------------------------------------------------
    @contextmanager
    def _session(self) -> Iterator[Any]:
        yield None

    def _read(self, handle: Any, tenant: str) -> WindowCounters | None:
        raise NotImplementedError

    def _write(self, handle: Any, tenant: str, counters: WindowCounters) -> None:
        raise NotImplementedError

    def _delete(self, handle: Any, tenant: str | None) -> None:
        raise NotImplementedError

    def _tenants(self, handle: Any) -> list[str]:
        raise NotImplementedError

    # --- shared logic --------------------------------------------------
    def _window(self, handle: Any, tenant: str, policy: BudgetPolicy) -> WindowCounters:
        now = time.time()
        counters = self._read(handle, tenant)
        if counters is None or now - counters.window_start >= policy.window_seconds:
            counters = WindowCounters(window_start=now)
        return counters

    def check(self, tenant: str, policy: BudgetPolicy, *, tokens: int, cost_usd: float) -> list[Finding]:
        return self.check_and_commit(tenant, policy, tokens=tokens, cost_usd=cost_usd, commit=False)

    def commit(self, tenant: str, policy: BudgetPolicy, *, tokens: int, cost_usd: float) -> None:
        with self._lock, self._session() as handle:
            counters = self._window(handle, tenant, policy)
            counters.add_request(tokens=tokens, cost_usd=cost_usd)
            self._write(handle, tenant, counters)

    def check_and_commit(
        self,
        tenant: str,
        policy: BudgetPolicy,
        *,
        tokens: int,
        cost_usd: float,
        commit: bool,
        degraded_cost_usd: float | None = None,
    ) -> list[Finding]:
        """Check the window and, unless blocked, commit in the same transaction.

        When the budget itself degrades the request, ``degraded_cost_usd`` (the price
        on the fallback model) is what gets charged.
        """
        with self._lock, self._session() as handle:
            counters = self._window(handle, tenant, policy)
            findings = _budget_findings(counters, policy, tokens=tokens, cost_usd=cost_usd)
            if commit and not _would_block(findings):
                charged = cost_usd
                if degraded_cost_usd is not None and _would_degrade(findings):
                    charged = degraded_cost_usd
                counters.add_request(tokens=tokens, cost_usd=charged)
                self._write(handle, tenant, counters)
            return findings

    def record_compute(self, tenant: str, policy: BudgetPolicy, seconds: float) -> None:
        """Charge measured model wall-clock time (local GPU/CPU or remote API latency)."""
        if seconds <= 0:
            return
        with self._lock, self._session() as handle:
            counters = self._window(handle, tenant, policy)
            counters.compute_seconds += seconds
            self._write(handle, tenant, counters)

    def snapshot(self, tenant: str = "default") -> dict[str, float | int]:
        with self._lock, self._session() as handle:
            return (self._read(handle, tenant) or WindowCounters()).to_dict()

    def snapshot_all(self) -> dict[str, dict[str, float | int]]:
        with self._lock, self._session() as handle:
            return {
                tenant: (self._read(handle, tenant) or WindowCounters()).to_dict()
                for tenant in self._tenants(handle)
            }

    def reset(self, tenant: str | None = None) -> None:
        with self._lock, self._session() as handle:
            self._delete(handle, tenant)


class MemoryBudgetTracker(_WindowedBudgetTracker):
    """Process-local budget tracker (tests / single replica)."""

    def __init__(self) -> None:
        super().__init__()
        self._by_tenant: dict[str, WindowCounters] = {}

    def _read(self, handle: Any, tenant: str) -> WindowCounters | None:
        return self._by_tenant.get(tenant)

    def _write(self, handle: Any, tenant: str, counters: WindowCounters) -> None:
        self._by_tenant[tenant] = counters

    def _delete(self, handle: Any, tenant: str | None) -> None:
        if tenant is None:
            self._by_tenant.clear()
        else:
            self._by_tenant.pop(tenant, None)

    def _tenants(self, handle: Any) -> list[str]:
        return sorted(self._by_tenant)


class SqliteBudgetTracker(_WindowedBudgetTracker):
    """Durable shared budgets via SQLite (default for multi-restart / compose demo)."""

    def __init__(self, path: Path) -> None:
        super().__init__()
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    @contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            with conn:  # commits on success, rolls back on error
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._lock, self._session() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS budgets (
                    tenant TEXT PRIMARY KEY,
                    tokens INTEGER NOT NULL DEFAULT 0,
                    cost_usd REAL NOT NULL DEFAULT 0,
                    requests INTEGER NOT NULL DEFAULT 0,
                    compute_seconds REAL NOT NULL DEFAULT 0,
                    window_start REAL NOT NULL
                )
                """
            )
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(budgets)")}
            if "compute_seconds" not in columns:  # migrate databases from older builds
                conn.execute("ALTER TABLE budgets ADD COLUMN compute_seconds REAL NOT NULL DEFAULT 0")

    def _read(self, handle: sqlite3.Connection, tenant: str) -> WindowCounters | None:
        row = handle.execute("SELECT * FROM budgets WHERE tenant = ?", (tenant,)).fetchone()
        return None if row is None else WindowCounters.from_mapping(row)

    def _write(self, handle: sqlite3.Connection, tenant: str, c: WindowCounters) -> None:
        handle.execute(
            """
            INSERT INTO budgets (tenant, tokens, cost_usd, requests, compute_seconds, window_start)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant) DO UPDATE SET
              tokens=excluded.tokens,
              cost_usd=excluded.cost_usd,
              requests=excluded.requests,
              compute_seconds=excluded.compute_seconds,
              window_start=excluded.window_start
            """,
            (tenant, c.tokens, c.cost_usd, c.requests, c.compute_seconds, c.window_start),
        )

    def _delete(self, handle: sqlite3.Connection, tenant: str | None) -> None:
        if tenant is None:
            handle.execute("DELETE FROM budgets")
        else:
            handle.execute("DELETE FROM budgets WHERE tenant = ?", (tenant,))

    def _tenants(self, handle: sqlite3.Connection) -> list[str]:
        return [row["tenant"] for row in handle.execute("SELECT tenant FROM budgets ORDER BY tenant")]


class RedisBudgetTracker(_WindowedBudgetTracker):
    """Shared budgets via Redis for multi-replica gateway scale-out."""

    _PREFIX = "aegis:budget:"

    def __init__(self, url: str) -> None:
        super().__init__()
        try:
            import redis
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "AEGIS_BUDGET_BACKEND=redis requires the redis package. "
                "Install with: pip install redis"
            ) from exc
        self._redis = redis.Redis.from_url(url, decode_responses=True)

    def _key(self, tenant: str) -> str:
        return f"{self._PREFIX}{tenant}"

    def _read(self, handle: Any, tenant: str) -> WindowCounters | None:
        raw = self._redis.hgetall(self._key(tenant))
        return WindowCounters.from_mapping(raw) if raw else None

    def _write(self, handle: Any, tenant: str, c: WindowCounters) -> None:
        self._redis.hset(
            self._key(tenant),
            mapping={
                "tokens": c.tokens,
                "cost_usd": c.cost_usd,
                "requests": c.requests,
                "compute_seconds": c.compute_seconds,
                "window_start": c.window_start,
            },
        )

    def _delete(self, handle: Any, tenant: str | None) -> None:
        if tenant is not None:
            self._redis.delete(self._key(tenant))
            return
        for key in self._redis.scan_iter(f"{self._PREFIX}*"):
            self._redis.delete(key)

    def _tenants(self, handle: Any) -> list[str]:
        return sorted(key[len(self._PREFIX):] for key in self._redis.scan_iter(f"{self._PREFIX}*"))


def create_budget_tracker(root: Path | None = None) -> _WindowedBudgetTracker:
    backend = os.environ.get("AEGIS_BUDGET_BACKEND", "sqlite").lower()
    if backend == "memory":
        return MemoryBudgetTracker()
    if backend == "redis":
        url = os.environ.get("AEGIS_REDIS_URL", "redis://localhost:6379/0")
        return RedisBudgetTracker(url)
    base = root or Path(os.environ.get("AEGIS_ROOT", "."))
    path = Path(os.environ.get("AEGIS_BUDGET_DB", base / "artifacts" / "budgets.db"))
    return SqliteBudgetTracker(path)


# Back-compat: tests and callers construct BudgetTracker() for in-memory use.
BudgetTracker = MemoryBudgetTracker


def estimate_tokens(text: str, *, max_completion_tokens: int | None = None) -> int:
    prompt = max(1, len(text) // 4)
    completion = max(0, int(max_completion_tokens or 0))
    return prompt + completion


def estimate_cost_usd(
    tokens: int,
    model: str,
    prices: dict[str, float] | None = None,
    default_price: float = 0.0004,
) -> float:
    """USD for ``tokens`` on ``model``; prices (USD per 1k tokens) come from the policy."""
    rate = (prices if prices is not None else DEFAULT_MODEL_PRICES).get(model, default_price)
    return (tokens / 1000.0) * rate


def model_allowed(model: str, allowed: list[str]) -> Finding | None:
    if model in allowed:
        return None
    return Finding(
        control="allowed_models",
        severity=Strictness.HIGH,
        action=Action.BLOCK,
        confidence=1.0,
        message=f"Model {model!r} is not on the allowlist",
        category="model_denied",
        matched=model,
    )
