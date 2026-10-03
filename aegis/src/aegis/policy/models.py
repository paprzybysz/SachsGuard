"""Centralized policy schema — single source of truth for all controls.

The policy is ONE file (:class:`PolicyFile`): shared settings, information-flow
contracts, attack signatures and named profiles. The engine works on the effective
:class:`Policy` of one profile, produced by :meth:`PolicyFile.resolve`.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Action(StrEnum):
    ALLOW = "allow"
    LOG = "log"
    REDACT = "redact"
    BLOCK = "block"
    DEGRADE = "degrade"
    HOLD = "hold"  # pause for human-in-the-loop; do not execute side effects


class FailMode(StrEnum):
    """What a semantic (AI) control does when its model backend is unavailable."""

    OPEN = "open"  # allow, but record a semantic_unavailable finding
    CLOSED = "closed"  # block the interaction


class Strictness(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class PolicyModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class BudgetPolicy(PolicyModel):
    max_tokens_per_request: int = Field(gt=0)
    max_tokens_per_window: int = Field(gt=0)
    max_cost_usd_per_window: float = Field(gt=0)
    max_requests_per_window: int = Field(gt=0)
    window_seconds: int = Field(gt=0)
    # Measured model wall-clock seconds per window (local GPU/CPU time or API latency).
    max_compute_seconds_per_window: float | None = Field(default=None, gt=0)
    on_exceed: Action = Action.BLOCK
    # Model forced on `on_exceed: degrade`; must be in allowed_models. Defaults to allowed_models[0].
    degrade_model: str | None = None
    # Who shares one budget window: the whole tenant, each role in it, or each API token.
    scope: Literal["tenant", "role", "principal"] = "tenant"


class ControlConfig(PolicyModel):
    enabled: bool = True
    action: Action = Action.BLOCK
    strictness: Strictness = Strictness.MEDIUM
    adherence: float | None = Field(default=None, ge=0, le=1)
    patterns: list[str] = Field(default_factory=list)
    require_auth_for: list[str] = Field(default_factory=list)
    privileged_roles: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    # Role → tools that principal may invoke (tool_authz). "*" = all catalog tools.
    role_tools: dict[str, list[str]] = Field(default_factory=dict)
    # Directions DLP applies to: inbound prompt and/or outbound model/tool output.
    apply_on: list[str] = Field(default_factory=lambda: ["inbound", "outbound"])
    backend: str = "heuristic"
    ollama_model: str = "gemma3:4b"
    # Defaults to $AEGIS_OLLAMA_URL, then http://127.0.0.1:11434.
    ollama_url: str | None = None
    timeout_seconds: float = Field(default=5.0, gt=0)
    fail_mode: FailMode = FailMode.OPEN
    # Optional external signature feed (HTTP/HTTPS YAML), preferred while reachable;
    # the policy's own attack_signatures are the fallback.
    feed_url: str | None = None
    feed_refresh_seconds: int = Field(default=300, gt=0)
    categories: list[str] = Field(default_factory=list)
    # System One / HITL: tools that always pause for a human, and amount threshold (PLN).
    hitl_tools: list[str] = Field(default_factory=list)
    hitl_amount_pln: float | None = Field(default=None, ge=0)
    # Calibrated feature weights for the System One heuristic (logistic).
    weights: dict[str, float] = Field(default_factory=dict)
    # Runaway-loop guard (per agent session).
    max_tool_calls_per_session: int | None = Field(default=None, gt=0)
    max_repeated_tool: int | None = Field(default=None, gt=0)
    max_steps_per_session: int | None = Field(default=None, gt=0)


# Keys each control reads, on top of enabled / action / strictness. A field set on a
# control that does not read it is a configuration mistake and is rejected.
_COMMON_FIELDS = frozenset({"enabled", "action", "strictness"})
_SEMANTIC_FIELDS = frozenset(
    {"adherence", "backend", "ollama_model", "ollama_url", "timeout_seconds", "fail_mode"}
)
CONTROL_FIELDS: dict[str, frozenset[str]] = {
    "pii_detector": frozenset({"patterns", "adherence"}),
    "secrets_detector": frozenset({"patterns", "adherence"}),
    "dlp_masking": frozenset({"patterns", "adherence", "apply_on"}),
    "authz_gate": frozenset({"require_auth_for", "privileged_roles"}),
    "tool_allowlist": frozenset({"allowed_tools"}),
    "tool_authz": frozenset({"role_tools"}),
    "information_flow": frozenset(),
    "prompt_injection": _SEMANTIC_FIELDS,
    "jailbreak_detector": _SEMANTIC_FIELDS,
    "historical_exploits": frozenset({"feed_url", "feed_refresh_seconds", "categories"}),
    "system_one": _SEMANTIC_FIELDS | {"hitl_tools", "hitl_amount_pln", "weights"},
    "loop_guard": frozenset(
        {"max_tool_calls_per_session", "max_repeated_tool", "max_steps_per_session"}
    ),
}

# USD per 1k tokens. Local models carry a notional internal rate so cost caps apply
# to them too; their real constraint is max_compute_seconds_per_window.
DEFAULT_MODEL_PRICES: dict[str, float] = {
    "demo-echo": 0.0001,
    "gemma3:270m": 0.00005,
    "gemma3:4b": 0.0002,
    "qwen3:8b": 0.0003,
    "gpt-4o-mini": 0.0005,
}


class RolesPolicy(PolicyModel):
    """Role names with gateway-level privileges (token → role mapping stays in env)."""

    # May read/reload the policy, export audit, approve/deny HITL, see all tenants.
    control_plane: list[str] = Field(default_factory=lambda: ["admin", "security"])
    # May read the HITL queue of their own tenant.
    hitl_reviewers: list[str] = Field(default_factory=lambda: ["teller"])


class ReportingPolicy(PolicyModel):
    audit_log_path: str = "artifacts/audit.jsonl"
    metrics_enabled: bool = True
    export_formats: list[str] = Field(default_factory=lambda: ["jsonl", "csv"])


class Signature(PolicyModel):
    id: str
    category: str
    name: str
    description: str = ""
    patterns: list[str] = Field(default_factory=list)


class AttackFeed(PolicyModel):
    version: str = "1.0"
    updated: str | None = None
    signatures: list[Signature] = Field(default_factory=list)


class FlowLabel(PolicyModel):
    initial_audience: list[str] = Field(default_factory=lambda: ["public", "internal"])
    initial_trust: Literal["trusted", "untrusted"] = "trusted"


class FlowAnnotator(PolicyModel):
    name: str
    internal_path_markers: list[str] | None = None
    public_path_markers: list[str] | None = None
    internal_content_markers: list[str] | None = None


class FlowTool(PolicyModel):
    name: str
    annotator: str | None = None
    delta_audience: list[str] | None = None
    delta_trust: Literal["trusted", "untrusted"] | None = None
    requires_audience: list[str] | None = None
    requires_trust: Literal["trusted", "untrusted"] | None = None


class InformationFlowPolicy(PolicyModel):
    """OpenAPPA-style tool contracts (sources narrow the session label, sinks check it)."""

    label: FlowLabel = Field(default_factory=FlowLabel)
    annotators: list[FlowAnnotator] = Field(default_factory=list)
    tools: list[FlowTool] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_references(self) -> InformationFlowPolicy:
        names = {a.name for a in self.annotators}
        missing = sorted({t.annotator for t in self.tools if t.annotator and t.annotator not in names})
        if missing:
            raise ValueError(f"information_flow.tools reference unknown annotator(s) {missing}")
        return self


class McpUpstream(PolicyModel):
    """A real MCP server Aegis proxies to (agent → Aegis /mcp → this server)."""

    name: str
    transport: Literal["stdio", "streamable_http"] = "stdio"
    # stdio: command + args (``python`` means the interpreter running Aegis).
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    # streamable_http: the server's MCP endpoint.
    url: str | None = None
    # Send the caller's role / tenant to the server in the request ``_meta``.
    forward_identity: bool = True
    timeout_seconds: float = Field(default=30.0, gt=0)

    @model_validator(mode="after")
    def _check_transport(self) -> McpUpstream:
        if self.transport == "stdio" and not self.command:
            raise ValueError(f"mcp upstream {self.name!r}: transport stdio needs `command`")
        if self.transport == "streamable_http" and not self.url:
            raise ValueError(f"mcp upstream {self.name!r}: transport streamable_http needs `url`")
        return self


class McpPolicy(PolicyModel):
    upstreams: list[McpUpstream] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_names(self) -> McpPolicy:
        names = [u.name for u in self.upstreams]
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            raise ValueError(f"mcp.upstreams names must be unique: {duplicates}")
        return self


# Controls an agent hook may skip: every control plus the two built-in checks.
SKIPPABLE_CONTROLS = frozenset(CONTROL_FIELDS) | {"budget", "allowed_models"}


class AgentHooksPolicy(PolicyModel):
    """Aegis guarding a coding agent's own actions via its hooks (Claude Code)."""

    enabled: bool = True
    # Which agent events are checked.
    prompts: bool = True  # the user's prompt (UserPromptSubmit)
    tool_calls: bool = True  # before a tool call (PreToolUse)
    tool_results: bool = True  # a tool result before the agent reads it (PostToolUse)
    # Agent tools (glob on the tool name) whose calls / results are checked. Default:
    # what executes or reaches outside the machine, not local file reads and edits.
    check_calls_of: list[str] = Field(default_factory=lambda: ["Bash", "WebFetch", "WebSearch", "mcp__*"])
    check_results_of: list[str] = Field(default_factory=lambda: ["Bash", "WebFetch", "WebSearch", "mcp__*"])
    # Where the semantic controls may call the LLM judge (glob on the tool name;
    # "prompt" = the user's prompt). Elsewhere they run regex-only: a small local judge
    # is too noisy on shell commands and too slow to sit on every tool call.
    llm_judge_for: list[str] = Field(default_factory=lambda: ["WebFetch", "WebSearch", "mcp__*"])
    # A prompt with data the policy would redact (PII, secrets): stop it, or let it
    # through with a warning (a hook cannot rewrite the prompt).
    on_sensitive_prompt: Literal["block", "warn"] = "block"
    # Controls that do not fit an agent's own actions (e.g. LLM token budgets on file
    # reads, payment routing on code edits). Everything else in the profile applies.
    skip_controls: list[str] = Field(default_factory=lambda: ["budget", "loop_guard", "system_one"])

    @model_validator(mode="after")
    def _check_skip(self) -> AgentHooksPolicy:
        unknown = sorted(set(self.skip_controls) - SKIPPABLE_CONTROLS)
        if unknown:
            raise ValueError(f"agent_hooks.skip_controls: unknown control(s) {unknown}")
        return self


class ProfilePolicy(PolicyModel):
    """What differs between profiles: models, sensitivity, budgets, controls."""

    allowed_models: list[str]
    adherence: float = Field(ge=0, le=1)
    budgets: BudgetPolicy
    controls: dict[str, ControlConfig]

    @model_validator(mode="after")
    def _check_consistency(self) -> ProfilePolicy:
        unknown = sorted(set(self.controls) - set(CONTROL_FIELDS))
        if unknown:
            raise ValueError(
                f"unknown control(s) {unknown}; known controls: {sorted(CONTROL_FIELDS)}"
            )
        for name, cfg in self.controls.items():
            stray = sorted(cfg.model_fields_set - _COMMON_FIELDS - CONTROL_FIELDS[name])
            if stray:
                raise ValueError(f"control {name!r} does not use field(s) {stray}")
        if not self.allowed_models:
            raise ValueError("allowed_models must list at least one model")
        degrade = self.budgets.degrade_model
        if degrade is not None and degrade not in self.allowed_models:
            raise ValueError(f"budgets.degrade_model {degrade!r} is not in allowed_models")
        return self


class Policy(ProfilePolicy):
    """Effective policy of one profile: the profile plus every shared section."""

    version: str
    profile: str
    reporting: ReportingPolicy = Field(default_factory=ReportingPolicy)
    model_prices: dict[str, float] = Field(default_factory=lambda: dict(DEFAULT_MODEL_PRICES))
    # Price for a model missing from model_prices (USD per 1k tokens).
    default_model_price: float = Field(default=0.0004, ge=0)
    roles: RolesPolicy = Field(default_factory=RolesPolicy)
    information_flow: InformationFlowPolicy = Field(default_factory=InformationFlowPolicy)
    attack_signatures: AttackFeed = Field(default_factory=AttackFeed)
    mcp: McpPolicy = Field(default_factory=McpPolicy)
    agent_hooks: AgentHooksPolicy = Field(default_factory=AgentHooksPolicy)

    def control(self, name: str) -> ControlConfig | None:
        return self.controls.get(name)

    @property
    def degrade_target(self) -> str:
        """Model a degraded request is forced onto."""
        return self.budgets.degrade_model or self.allowed_models[0]

    def model_price(self, model: str) -> float:
        return self.model_prices.get(model, self.default_model_price)


class PolicyFile(PolicyModel):
    """The single policy file: shared sections + named profiles."""

    version: str
    # Profile for every tenant not listed in tenant_profiles.
    active_profile: str
    # Tenant → profile name.
    tenant_profiles: dict[str, str] = Field(default_factory=dict)
    model_prices: dict[str, float] = Field(default_factory=lambda: dict(DEFAULT_MODEL_PRICES))
    default_model_price: float = Field(default=0.0004, ge=0)
    roles: RolesPolicy = Field(default_factory=RolesPolicy)
    reporting: ReportingPolicy = Field(default_factory=ReportingPolicy)
    information_flow: InformationFlowPolicy = Field(default_factory=InformationFlowPolicy)
    attack_signatures: AttackFeed = Field(default_factory=AttackFeed)
    mcp: McpPolicy = Field(default_factory=McpPolicy)
    agent_hooks: AgentHooksPolicy = Field(default_factory=AgentHooksPolicy)
    profiles: dict[str, ProfilePolicy]

    @model_validator(mode="after")
    def _check_references(self) -> PolicyFile:
        if not self.profiles:
            raise ValueError("profiles must define at least one profile")
        known = sorted(self.profiles)
        if self.active_profile not in self.profiles:
            raise ValueError(f"active_profile {self.active_profile!r} is not one of {known}")
        bad = {t: p for t, p in self.tenant_profiles.items() if p not in self.profiles}
        if bad:
            raise ValueError(f"tenant_profiles point to unknown profile(s) {bad}; known: {known}")
        negative = sorted(m for m, price in self.model_prices.items() if price < 0)
        if negative:
            raise ValueError(f"model_prices must be >= 0: {negative}")
        return self

    def resolve(self, profile: str) -> Policy:
        if profile not in self.profiles:
            raise KeyError(f"unknown profile {profile!r}; known: {sorted(self.profiles)}")
        body = self.profiles[profile]
        return Policy(
            version=self.version,
            profile=profile,
            allowed_models=body.allowed_models,
            adherence=body.adherence,
            budgets=body.budgets,
            controls=body.controls,
            reporting=self.reporting,
            model_prices=self.model_prices,
            default_model_price=self.default_model_price,
            roles=self.roles,
            information_flow=self.information_flow,
            attack_signatures=self.attack_signatures,
            mcp=self.mcp,
            agent_hooks=self.agent_hooks,
        )

    def profile_for_tenant(self, tenant: str, default: str | None = None) -> str:
        return self.tenant_profiles.get(tenant) or default or self.active_profile


class Decision(StrEnum):
    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"
    DEGRADE = "degrade"
    HOLD = "hold"


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    control: str
    severity: Strictness
    action: Action
    confidence: float = Field(ge=0, le=1)
    message: str
    matched: str | None = None
    category: str | None = None


class EvaluationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Decision
    findings: list[Finding] = Field(default_factory=list)
    redacted_text: str | None = None
    original_text: str
    model: str | None = None
    tokens_estimated: int = 0
    cost_estimated: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return self.decision == Decision.BLOCK
