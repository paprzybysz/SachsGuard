"""Hybrid policy engine — deterministic + semantic + historical + budget."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from functools import partial
from pathlib import Path

from aegis.controls.appa import InformationFlowTracker
from aegis.controls.budget import (
    BudgetStore,
    create_budget_tracker,
    estimate_cost_usd,
    estimate_tokens,
    model_allowed,
)
from aegis.controls.deterministic import (
    AuthContext,
    check_authz,
    check_tool_authz,
    check_tools_allowlist,
    scan_pii,
    scan_secrets,
)
from aegis.controls.dlp import scan_dlp
from aegis.controls.historical import FeedStore, scan_historical
from aegis.controls.loop_guard import LoopTracker
from aegis.controls.semantic import scan_jailbreak, scan_prompt_injection
from aegis.controls.system_one import evaluate_system_one
from aegis.controls.text import normalize_for_matching
from aegis.policy.loader import PolicyStore
from aegis.policy.models import (
    Action,
    ControlConfig,
    Decision,
    EvaluationResult,
    Finding,
    Policy,
)
from aegis.telemetry import (
    allowed_counter,
    blocked_counter,
    cost_counter,
    evaluations_counter,
    findings_counter,
    latency_histogram,
    logger,
    redacted_counter,
    tokens_counter,
    tracer,
)

_KNOWN_DIRECTIONS = frozenset({"inbound", "outbound", "agent_to_mcp"})


def _sanitize_label(value: str, *, limit: int = 120) -> str:
    """Strip CR/LF and control characters and bound length.

    Used for user-controlled values before they reach logs (prevents log
    forging / injection) or span attributes (bounds trace payload size).
    """
    cleaned = "".join(ch for ch in str(value) if ch.isprintable() and ch not in "\r\n\t")
    return cleaned[:limit]


def _bucket_direction(direction: str) -> str:
    """Collapse unknown directions so the metric label stays low-cardinality."""
    return direction if direction in _KNOWN_DIRECTIONS else "other"


def decide(findings: list[Finding], redacted: str, original: str) -> Decision:
    if any(f.action == Action.BLOCK for f in findings):
        return Decision.BLOCK
    if any(f.action == Action.HOLD for f in findings):
        return Decision.HOLD
    needs_redact = redacted != original or any(f.action == Action.REDACT for f in findings)
    has_degrade = any(f.action == Action.DEGRADE for f in findings)
    # Degrade may win as the decision label, but redacted_text is always kept for enforcement.
    if has_degrade:
        return Decision.DEGRADE
    if needs_redact:
        return Decision.REDACT
    return Decision.ALLOW


class _Timer:
    """Per-control wall-clock timings (ms) for performance telemetry."""

    def __init__(self) -> None:
        self.timings_ms: dict[str, float] = {}
        self._start = time.perf_counter()

    def run[T](self, name: str, fn: Callable[..., T], *args: object) -> T:
        start = time.perf_counter()
        try:
            return fn(*args)
        finally:
            self.timings_ms[name] = round((time.perf_counter() - start) * 1000, 3)

    def total_ms(self) -> float:
        return round((time.perf_counter() - self._start) * 1000, 3)


class ControlEngine:
    def __init__(
        self,
        policy_store: PolicyStore,
        *,
        root: Path | None = None,
        budgets: BudgetStore | None = None,
    ) -> None:
        self.policy_store = policy_store
        self.root = root or policy_store.path.parent.parent
        self.feeds = FeedStore(self.root)
        self.budgets: BudgetStore = budgets or create_budget_tracker(self.root)
        self.flow = InformationFlowTracker()
        self.loops = LoopTracker()

    @property
    def policy(self) -> Policy:
        return self.policy_store.get()

    def policy_for(self, tenant: str) -> Policy:
        """Effective policy for ``tenant`` (its ``tenant_profiles`` entry, else the active profile)."""
        return self.policy_store.get_for_tenant(tenant)

    def budget_key(self, tenant: str, auth: AuthContext | None, policy: Policy | None = None) -> str:
        """Budget window key per ``budgets.scope``: tenant, tenant+role or tenant+token."""
        policy = policy or self.policy_for(tenant)
        scope = policy.budgets.scope
        if scope == "role":
            return f"{tenant}:role:{(auth.role if auth else None) or 'anonymous'}"
        if scope == "principal":
            subject = (auth.subject if auth else None) or "anonymous"
            return f"{tenant}:principal:{hashlib.sha256(subject.encode()).hexdigest()[:12]}"
        return tenant

    def _redact(
        self,
        text: str,
        policy: Policy,
        findings: list[Finding] | None,
        timer: _Timer | None,
        *,
        direction: str,
        skip: frozenset[str] = frozenset(),
    ) -> str:
        """Run the redacting controls in order; collect findings when asked."""
        steps = [
            ("pii_detector", lambda t, cfg: scan_pii(t, cfg)),
            ("secrets_detector", lambda t, cfg: scan_secrets(t, cfg)),
            ("dlp_masking", lambda t, cfg: scan_dlp(t, cfg, direction=direction)),
        ]
        if direction == "outbound":
            # Egress path: DLP/masking only — inbound PII/secret policy targets prompts.
            steps = steps[2:]
        working = text
        for name, scan in steps:
            cfg = None if name in skip else policy.control(name)
            if not cfg:
                continue
            step_findings, working = timer.run(name, scan, working, cfg) if timer else scan(working, cfg)
            if findings is not None:
                findings.extend(step_findings)
        return working

    def evaluate(
        self,
        text: str,
        *,
        model: str = "demo-echo",
        method: str = "chat.completions",
        tool_name: str | None = None,
        tool_names: list[str] | None = None,
        auth: AuthContext | None = None,
        tenant: str = "default",
        session: str | None = None,
        commit_budget: bool = True,
        direction: str = "inbound",
        max_tokens: int | None = None,
        skip_controls: frozenset[str] = frozenset(),
        semantic_backend: str | None = None,
    ) -> EvaluationResult:
        with tracer.start_as_current_span(
            "aegis.evaluate",
            attributes={
                "aegis.model": model,
                "aegis.method": method,
                "aegis.tenant": tenant,
                "aegis.direction": direction,
            },
        ) as span:
            result = self._evaluate_inner(
                text,
                model=model,
                method=method,
                tool_name=tool_name,
                tool_names=tool_names,
                auth=auth,
                tenant=tenant,
                session=session,
                commit_budget=commit_budget,
                direction=direction,
                max_tokens=max_tokens,
                skip_controls=skip_controls,
                semantic_backend=semantic_backend,
            )
            elapsed_ms = float(result.metadata.get("latency_ms", 0.0))

            attrs = {
                "aegis.tenant": _sanitize_label(tenant),
                "aegis.direction": _bucket_direction(direction),
                "aegis.model": _sanitize_label(model),
            }
            evaluations_counter.add(1, attrs)
            latency_histogram.record(elapsed_ms, attrs)
            tokens_counter.add(result.tokens_estimated, attrs)
            cost_counter.add(result.cost_estimated, attrs)

            decision_val = result.decision.value
            span.set_attribute("aegis.decision", decision_val)
            span.set_attribute("aegis.findings_count", len(result.findings))
            span.set_attribute("aegis.tokens_estimated", result.tokens_estimated)
            for control, ms in (result.metadata.get("timings_ms") or {}).items():
                span.set_attribute(f"aegis.timing_ms.{_sanitize_label(control)}", ms)

            if result.decision == Decision.BLOCK:
                blocked_counter.add(1, attrs)
                # BLOCK is successful policy enforcement, not a service error.
            elif result.decision in {Decision.REDACT, Decision.DEGRADE, Decision.HOLD}:
                redacted_counter.add(1, attrs)
            else:
                allowed_counter.add(1, attrs)

            # Per-finding metrics — key for security threat analysis.
            # Labels: control (which check fired), category (threat type), decision.
            for finding in result.findings:
                findings_counter.add(
                    1,
                    {
                        "aegis.control": _sanitize_label(finding.control),
                        "aegis.category": _sanitize_label(finding.category or "unknown"),
                        "aegis.decision": decision_val,
                        "aegis.tenant": attrs["aegis.tenant"],
                    },
                )

            logger.info(
                "evaluate decision=%s tenant=%s model=%s direction=%s findings=%d latency_ms=%.1f",
                decision_val,
                tenant,
                model,
                direction,
                len(result.findings),
                elapsed_ms,
            )
            return result

    def _evaluate_inner(
        self,
        text: str,
        *,
        model: str = "demo-echo",
        method: str = "chat.completions",
        tool_name: str | None = None,
        tool_names: list[str] | None = None,
        auth: AuthContext | None = None,
        tenant: str = "default",
        session: str | None = None,
        commit_budget: bool = True,
        direction: str = "inbound",
        max_tokens: int | None = None,
        skip_controls: frozenset[str] = frozenset(),
        semantic_backend: str | None = None,
    ) -> EvaluationResult:
        store = self.policy_store
        policy = store.get_for_tenant(tenant)
        auth = auth or AuthContext()
        budget_key = self.budget_key(tenant, auth, policy)
        session = session or tenant
        timer = _Timer()
        findings: list[Finding] = []

        names = list(tool_names or [])
        if tool_name and tool_name not in names:
            names.append(tool_name)

        metadata = {
            "tenant": tenant,
            "session": session,
            "method": method,
            "tool_name": tool_name,
            "tool_names": names,
            "direction": direction,
            "profile": policy.profile,
            "policy_sha256": store.digest,
            "auth_role": auth.role,
        }

        if direction == "outbound":
            working = self._redact(text, policy, findings, timer, direction=direction, skip=skip_controls)
            metadata["timings_ms"] = timer.timings_ms
            metadata["latency_ms"] = timer.total_ms()
            return EvaluationResult(
                decision=decide(findings, working, text),
                findings=findings,
                redacted_text=working if working != text else None,
                original_text=text,
                model=model,
                metadata=metadata,
            )

        tokens = estimate_tokens(text, max_completion_tokens=max_tokens)
        cost = estimate_cost_usd(tokens, model, policy.model_prices, policy.default_model_price)
        skip = skip_controls
        budget_on = "budget" not in skip
        if budget_on and tokens > policy.budgets.max_tokens_per_request and policy.budgets.on_exceed == Action.BLOCK:
            # Oversized input is rejected before the NLP/LLM controls ever see it, so a
            # huge payload cannot be used to burn CPU (spaCy) or model time.
            findings.extend(
                timer.run(
                    "budget",
                    partial(self.budgets.check, budget_key, policy.budgets, tokens=tokens, cost_usd=cost),
                )
            )
            metadata["timings_ms"] = timer.timings_ms
            metadata["latency_ms"] = timer.total_ms()
            return EvaluationResult(
                decision=Decision.BLOCK,
                findings=findings,
                original_text=text,
                model=model,
                tokens_estimated=tokens,
                cost_estimated=cost,
                metadata=metadata,
            )

        if "allowed_models" not in skip:
            model_finding = timer.run("allowed_models", model_allowed, model, policy.allowed_models)
            if model_finding:
                findings.append(model_finding)

        working = self._redact(text, policy, findings, timer, direction=direction, skip=skip)

        # Signature controls match on a normalized view; the original text is still what
        # is redacted, forwarded and audited.
        scan_text = normalize_for_matching(text)
        adherence = policy.adherence

        def semantic(cfg: ControlConfig) -> ControlConfig:
            # e.g. "heuristic": regex only, no LLM judge, for this one evaluation.
            return cfg.model_copy(update={"backend": semantic_backend}) if semantic_backend else cfg

        checks: list[tuple[str, Callable[..., list[Finding]]]] = [
            ("authz_gate", lambda cfg: check_authz(method, auth, cfg)),
            ("tool_allowlist", lambda cfg: check_tools_allowlist(names, cfg)),
            ("tool_authz", lambda cfg: check_tool_authz(names, auth, cfg)),
            ("information_flow", lambda cfg: self.check_flow(session, text, names, cfg, policy)),
            ("prompt_injection", lambda cfg: scan_prompt_injection(scan_text, semantic(cfg), adherence)),
            ("jailbreak_detector", lambda cfg: scan_jailbreak(scan_text, semantic(cfg), adherence)),
            (
                "historical_exploits",
                lambda cfg: scan_historical(scan_text, cfg, self.feeds, policy.attack_signatures),
            ),
        ]
        for name, check in checks:
            cfg = None if name in skip else policy.control(name)
            if cfg:
                findings.extend(timer.run(name, check, cfg))

        loop_cfg = None if "loop_guard" in skip else policy.control("loop_guard")
        if loop_cfg:
            findings.extend(
                timer.run("loop_guard", self.loops.check, session, names, method, text, loop_cfg)
            )

        s1_cfg = None if "system_one" in skip else policy.control("system_one")
        if s1_cfg:

            def _system_one() -> list[Finding]:
                extra, meta = evaluate_system_one(
                    text=text,
                    tool_names=names,
                    role=auth.role,
                    hop_count=self.loops.hop_count(session),
                    findings=list(findings),
                    cfg=s1_cfg,
                    global_adherence=policy.adherence,
                )
                metadata["system_one"] = meta
                return extra

            findings.extend(timer.run("system_one", _system_one))

        tokens = estimate_tokens(text, max_completion_tokens=max_tokens)
        cost = estimate_cost_usd(tokens, model, policy.model_prices, policy.default_model_price)
        degraded_cost = estimate_cost_usd(
            tokens, policy.degrade_target, policy.model_prices, policy.default_model_price
        )
        preliminary = decide(findings, working, text)
        skip_budget = preliminary in {Decision.BLOCK, Decision.HOLD}
        if preliminary == Decision.DEGRADE:
            cost = degraded_cost  # another control already degraded: charge the fallback model
        budget_check = partial(
            self.budgets.check_and_commit,
            budget_key,
            policy.budgets,
            tokens=tokens,
            cost_usd=cost,
            commit=commit_budget and not skip_budget,
            degraded_cost_usd=degraded_cost,
        )
        if budget_on:
            findings.extend(timer.run("budget", budget_check))
        decision = decide(findings, working, text)
        effective_model = policy.degrade_target if decision == Decision.DEGRADE else model
        if effective_model != model:
            cost = degraded_cost
        metadata["effective_model"] = effective_model
        metadata["budget_key"] = budget_key
        metadata["flow"] = self.flow.snapshot(session)
        metadata["timings_ms"] = timer.timings_ms
        metadata["latency_ms"] = timer.total_ms()

        return EvaluationResult(
            decision=decision,
            findings=findings,
            redacted_text=working if working != text else None,
            original_text=text,
            model=model,
            tokens_estimated=tokens,
            cost_estimated=cost,
            metadata=metadata,
        )

    def check_flow(
        self, session: str, text: str, names: list[str], cfg: ControlConfig, policy: Policy
    ) -> list[Finding]:
        """Information-flow check against the contracts in ``policy.information_flow``."""
        self.flow.use_policy(policy.information_flow)
        return self.flow.check_and_taint(session, text=text, tool_names=names, cfg=cfg)

    def redact_text(self, text: str, tenant: str = "default") -> str:
        """Apply DLP + deterministic redaction (preserve roles / structured fields)."""
        return self._redact(text, self.policy_for(tenant), None, None, direction="inbound")
