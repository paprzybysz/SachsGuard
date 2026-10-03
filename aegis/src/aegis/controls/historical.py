"""Historical attack mitigation from an externally managed signature feed.

Sources, in order of preference:
1. ``feed_url`` — optional HTTP(S) YAML feed owned by a threat-intel team,
   refreshed every ``feed_refresh_seconds``; the last good copy is kept if a
   refresh fails.
2. ``attack_signatures`` in the central policy file (hot-reloaded with it), used
   when no URL is configured or the URL has never been reachable.

Every pattern is compiled once at load. Invalid patterns, oversized patterns and
catastrophic-backtracking (ReDoS) shapes are rejected and reported via
``FeedStore.status()``: a repeat whose body holds another repeat (``(a+)+``,
``((a+))+``, ``(.*a){20}``) or an alternation (``(a|aa)+``). Python ``re`` has no
match timeout, so shapes are judged on the parsed pattern, not its spelling.
"""

from __future__ import annotations

import re
import re._parser as re_parser  # private CPython module (3.11+); pinned by tests
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import yaml

from aegis.policy.models import AttackFeed, ControlConfig, Finding, Signature

__all__ = ["AttackFeed", "FeedStore", "Signature", "compile_feed", "scan_historical", "unsafe_pattern_reason"]

MAX_PATTERN_LENGTH = 512
_BACKTRACKING_REPEATS = {re_parser.MAX_REPEAT, re_parser.MIN_REPEAT}


@dataclass(frozen=True)
class CompiledSignature:
    signature: Signature
    patterns: tuple[re.Pattern[str], ...]


@dataclass
class CompiledFeed:
    version: str = "empty"
    source: str = "none"
    signatures: list[CompiledSignature] = field(default_factory=list)
    rejected: list[dict[str, str]] = field(default_factory=list)


Node = tuple[object, object]  # (opcode, argument) as produced by re._parser


def _is_multi_repeat(node: Node) -> bool:
    op, arg = node
    return op in _BACKTRACKING_REPEATS and arg[1] > 1  # arg = (min, max, body)


def _subpatterns(arg: object) -> list[re_parser.SubPattern]:
    if isinstance(arg, re_parser.SubPattern):
        return [arg]
    if isinstance(arg, (tuple, list)):
        return [sub for item in arg for sub in _subpatterns(item)]
    return []


def _any_node(sub: re_parser.SubPattern, predicate) -> bool:
    return any(
        predicate(node) or any(_any_node(child, predicate) for child in _subpatterns(node[1]))
        for node in sub
    )


def _redos_shape(sub: re_parser.SubPattern) -> str | None:
    for node in sub:
        if _is_multi_repeat(node):
            body = node[1][2]
            if _any_node(body, _is_multi_repeat):
                return "nested quantifier (ReDoS risk)"
            if _any_node(body, lambda n: n[0] == re_parser.BRANCH):
                return "alternation under a quantifier (ReDoS risk)"
        for child in _subpatterns(node[1]):
            if reason := _redos_shape(child):
                return reason
    return None


def unsafe_pattern_reason(pattern: str) -> str | None:
    if len(pattern) > MAX_PATTERN_LENGTH:
        return f"longer than {MAX_PATTERN_LENGTH} chars"
    try:
        re.compile(pattern)
    except re.error as exc:
        return f"invalid regex: {exc}"
    return _redos_shape(re_parser.parse(pattern))


def compile_feed(feed: AttackFeed, source: str) -> CompiledFeed:
    compiled = CompiledFeed(version=feed.version, source=source)
    for sig in feed.signatures:
        patterns: list[re.Pattern[str]] = []
        for pattern in sig.patterns:
            reason = unsafe_pattern_reason(pattern)
            if reason:
                compiled.rejected.append({"signature": sig.id, "pattern": pattern[:120], "reason": reason})
                continue
            patterns.append(re.compile(pattern))
        if patterns:
            compiled.signatures.append(CompiledSignature(signature=sig, patterns=tuple(patterns)))
    return compiled


class FeedStore:
    def __init__(self, root: Path | None = None, *, http_timeout: float = 3.0) -> None:
        self.root = root
        self.http_timeout = http_timeout
        self._lock = threading.Lock()
        # Compiled inline feed, recompiled only when the policy object changes.
        self._inline: tuple[AttackFeed, CompiledFeed] | None = None
        # url -> (fetched_at, feed); a failed refresh keeps the previous entry.
        self._url_cache: dict[str, tuple[float, CompiledFeed]] = {}
        self._last_error: str | None = None
        self._active: CompiledFeed = CompiledFeed()

    def _load_inline(self, feed: AttackFeed) -> CompiledFeed:
        if self._inline is not None and self._inline[0] is feed:
            return self._inline[1]
        compiled = compile_feed(feed, source="policy:attack_signatures")
        self._inline = (feed, compiled)
        return compiled

    def _load_url(self, url: str, refresh_seconds: int) -> CompiledFeed | None:
        cached = self._url_cache.get(url)
        if cached and time.time() - cached[0] < refresh_seconds:
            return cached[1]
        try:
            response = httpx.get(url, timeout=self.http_timeout)
            response.raise_for_status()
            raw = yaml.safe_load(response.text) or {}
            feed = compile_feed(AttackFeed.model_validate(raw), source=url)
        except Exception as exc:  # noqa: BLE001 — network/YAML/schema error: keep last good copy
            self._last_error = f"{url}: {type(exc).__name__}: {exc}"[:240]
            if cached:
                self._url_cache[url] = (time.time(), cached[1])  # back off until next refresh
                return cached[1]
            return None
        self._last_error = None
        self._url_cache[url] = (time.time(), feed)
        return feed

    def load(self, cfg: ControlConfig, inline: AttackFeed | None = None) -> CompiledFeed:
        with self._lock:
            feed: CompiledFeed | None = None
            if cfg.feed_url:
                feed = self._load_url(cfg.feed_url, cfg.feed_refresh_seconds)
            if feed is None and inline is not None:
                feed = self._load_inline(inline)
            self._active = feed or CompiledFeed()
            return self._active

    def status(self) -> dict[str, object]:
        with self._lock:
            return {
                "source": self._active.source,
                "version": self._active.version,
                "signatures": len(self._active.signatures),
                "rejected_patterns": list(self._active.rejected),
                "last_error": self._last_error,
            }


def scan_historical(
    text: str, cfg: ControlConfig, feed_store: FeedStore, signatures: AttackFeed | None
) -> list[Finding]:
    """Match ``text`` against ``feed_url`` (if set and reachable) or the policy's signatures."""
    if not cfg.enabled:
        return []
    feed = feed_store.load(cfg, signatures)
    allowed = set(cfg.categories) if cfg.categories else None
    findings: list[Finding] = []
    for compiled in feed.signatures:
        sig = compiled.signature
        if allowed is not None and sig.category not in allowed:
            continue
        for pattern in compiled.patterns:
            match = pattern.search(text)
            if match:
                findings.append(
                    Finding(
                        control="historical_exploits",
                        severity=cfg.strictness,
                        action=cfg.action,
                        confidence=0.97,
                        message=f"{sig.id} {sig.name}: {sig.description}",
                        matched=match.group(0)[:80],
                        category=sig.category,
                    )
                )
                break
    return findings
