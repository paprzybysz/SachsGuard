"""Deterministic runaway-loop guard for agent sessions (tool hops / repeats)."""

from __future__ import annotations

import hashlib
import threading
from collections import Counter, defaultdict

from aegis.policy.models import ControlConfig, Finding, Strictness

_TOOL_METHODS = frozenset({"tools/call", "mcp/invoke", "tools.call"})


class LoopTracker:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._steps: dict[str, int] = defaultdict(int)
        self._tools: dict[str, int] = defaultdict(int)
        self._repeats: dict[str, Counter[str]] = defaultdict(Counter)

    def reset(self, session: str | None = None) -> None:
        with self._lock:
            if session is None:
                self._steps.clear()
                self._tools.clear()
                self._repeats.clear()
            else:
                self._steps.pop(session, None)
                self._tools.pop(session, None)
                self._repeats.pop(session, None)

    def hop_count(self, session: str) -> int:
        with self._lock:
            return int(self._tools.get(session, 0))

    def check(
        self,
        session: str,
        tool_names: list[str],
        method: str,
        text: str,
        cfg: ControlConfig,
    ) -> list[Finding]:
        if not cfg.enabled:
            return []
        names = [n for n in tool_names if n]
        is_tool = bool(names) or method in _TOOL_METHODS
        findings: list[Finding] = []
        with self._lock:
            self._steps[session] += 1
            steps = self._steps[session]
            if is_tool:
                self._tools[session] += max(1, len(names) or 1)
            tool_calls = self._tools[session]
            repeat_key = ""
            if names:
                digest = hashlib.sha256(f"{','.join(names)}|{text}".encode()).hexdigest()[:16]
                repeat_key = f"{','.join(names)}:{digest}"
                self._repeats[session][repeat_key] += 1

            max_steps = cfg.max_steps_per_session
            max_tools = cfg.max_tool_calls_per_session
            max_repeat = cfg.max_repeated_tool
            if max_steps is not None and steps > max_steps:
                findings.append(
                    self._finding(
                        cfg,
                        "max_steps_per_session",
                        f"session exceeded max_steps_per_session={max_steps} (now {steps})",
                    )
                )
            if is_tool and max_tools is not None and tool_calls > max_tools:
                findings.append(
                    self._finding(
                        cfg,
                        "max_tool_calls_per_session",
                        f"session exceeded max_tool_calls_per_session={max_tools} (now {tool_calls})",
                    )
                )
            if repeat_key and max_repeat is not None and self._repeats[session][repeat_key] > max_repeat:
                findings.append(
                    self._finding(
                        cfg,
                        "max_repeated_tool",
                        f"identical tool call repeated {self._repeats[session][repeat_key]} times "
                        f"(limit {max_repeat})",
                        matched=repeat_key.split(":", 1)[0],
                    )
                )
        return findings

    @staticmethod
    def _finding(cfg: ControlConfig, category: str, message: str, matched: str | None = None) -> Finding:
        return Finding(
            control="loop_guard",
            severity=Strictness.HIGH,
            action=cfg.action,
            confidence=1.0,
            message=message,
            category=category,
            matched=matched,
        )
