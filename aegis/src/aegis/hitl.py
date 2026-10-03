"""Human-in-the-loop queue for critical MCP / bank actions."""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Any, Literal

Status = Literal["pending", "approved", "denied", "expired"]


@dataclass
class PendingAction:
    id: str
    tenant: str
    role: str
    tool_name: str
    method: str
    arguments: dict[str, Any]
    session: str
    reasons: list[str]
    system_one: dict[str, Any]
    created_at: float
    status: Status = "pending"
    # Where to execute on approval: "bank" (in-process demo) or "mcp:<upstream name>".
    origin: str = "bank"
    # Who asked; only they (or the control plane) may poll the outcome.
    subject: str | None = None
    resolved_at: float | None = None
    resolved_by: str | None = None
    result: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class HitlStore:
    def __init__(self, *, ttl_seconds: float = 600.0) -> None:
        self.ttl_seconds = ttl_seconds
        self._lock = threading.Lock()
        self._items: dict[str, PendingAction] = {}
        self.approved_total = 0
        self.denied_total = 0
        self.expired_total = 0

    def reset(self) -> None:
        with self._lock:
            self._items.clear()
            self.approved_total = 0
            self.denied_total = 0
            self.expired_total = 0

    def enqueue(
        self,
        *,
        tenant: str,
        role: str,
        tool_name: str,
        method: str,
        arguments: dict[str, Any],
        session: str,
        reasons: list[str],
        system_one: dict[str, Any],
        origin: str = "bank",
        subject: str | None = None,
    ) -> PendingAction:
        self.expire()
        item = PendingAction(
            id=str(uuid.uuid4()),
            tenant=tenant,
            role=role,
            tool_name=tool_name,
            method=method,
            arguments=arguments,
            session=session,
            reasons=reasons,
            system_one=system_one,
            created_at=time.time(),
            origin=origin,
            subject=subject,
        )
        with self._lock:
            self._items[item.id] = item
        return item

    def get(self, action_id: str) -> PendingAction | None:
        self.expire()
        with self._lock:
            item = self._items.get(action_id)
            return item

    def list_pending(self, *, tenant: str | None = None) -> list[PendingAction]:
        self.expire()
        with self._lock:
            items = [i for i in self._items.values() if i.status == "pending"]
        if tenant is not None:
            items = [i for i in items if i.tenant == tenant]
        items.sort(key=lambda i: i.created_at, reverse=True)
        return items

    def list_resolved(self, *, tenant: str | None = None, limit: int = 40) -> list[PendingAction]:
        self.expire()
        with self._lock:
            items = [i for i in self._items.values() if i.status != "pending"]
        if tenant is not None:
            items = [i for i in items if i.tenant == tenant]
        items.sort(key=lambda i: float(i.resolved_at or i.created_at), reverse=True)
        return items[:limit]

    def pending_count(self) -> int:
        return len(self.list_pending())

    def resolve(
        self,
        action_id: str,
        *,
        status: Status,
        resolved_by: str,
        result: dict[str, Any] | None = None,
    ) -> PendingAction | None:
        self.expire()
        with self._lock:
            item = self._items.get(action_id)
            if item is None or item.status != "pending":
                return item
            item.status = status
            item.resolved_at = time.time()
            item.resolved_by = resolved_by
            item.result = result
            if status == "approved":
                self.approved_total += 1
            elif status == "denied":
                self.denied_total += 1
            return item

    def expire(self) -> None:
        now = time.time()
        with self._lock:
            for item in self._items.values():
                if item.status == "pending" and now - item.created_at > self.ttl_seconds:
                    item.status = "expired"
                    item.resolved_at = now
                    self.expired_total += 1

    def snapshot(self) -> dict[str, int]:
        self.expire()
        return {
            "pending": self.pending_count(),
            "approved": self.approved_total,
            "denied": self.denied_total,
            "expired": self.expired_total,
        }
