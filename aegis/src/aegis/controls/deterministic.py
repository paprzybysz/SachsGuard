"""Deterministic (non-AI) guardrails: PII, secrets, authz, tool allowlist.

PII and secret detection run through Microsoft Presidio (``presidio_engine``).
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch

from aegis.controls.presidio_engine import detect_and_mask
from aegis.policy.models import Action, ControlConfig, Finding, Strictness

PII_CATEGORIES = ["email", "phone", "ssn", "credit_card"]
SECRET_CATEGORIES = [
    "aws_access_key",
    "openai_key",
    "github_token",
    "generic_api_key",
    "private_key",
    "bearer_token",
]
_MASKING_ACTIONS = {Action.REDACT, Action.BLOCK, Action.DEGRADE}


@dataclass
class AuthContext:
    authenticated: bool = False
    role: str | None = None
    subject: str | None = None
    tenant: str | None = None


def _scan(
    text: str,
    cfg: ControlConfig,
    *,
    control: str,
    defaults: list[str],
    label: str,
    severity: Strictness | None = None,
) -> tuple[list[Finding], str]:
    """Detect + mask with Presidio; policy ``patterns`` select the categories."""
    if not cfg.enabled:
        return [], text
    detections, redacted = detect_and_mask(
        text,
        cfg.patterns or defaults,
        cfg.strictness,
        mask=cfg.action in _MASKING_ACTIONS,
        min_score=cfg.adherence,
    )
    findings = [
        Finding(
            control=control,
            severity=severity or cfg.strictness,
            action=cfg.action,
            confidence=min(1.0, d.score),
            message=f"{label} detected (Presidio): {d.category}",
            matched="[REDACTED]",
            category=d.category,
        )
        for d in detections
    ]
    return findings, redacted


def scan_pii(text: str, cfg: ControlConfig) -> tuple[list[Finding], str]:
    return _scan(text, cfg, control="pii_detector", defaults=PII_CATEGORIES, label="PII")


def scan_secrets(text: str, cfg: ControlConfig) -> tuple[list[Finding], str]:
    return _scan(
        text,
        cfg,
        control="secrets_detector",
        defaults=SECRET_CATEGORIES,
        label="Secret",
        severity=Strictness.HIGH,
    )


def check_authz(method: str, auth: AuthContext, cfg: ControlConfig) -> list[Finding]:
    if not cfg.enabled:
        return []
    needs_auth = any(fnmatch(method, pattern) for pattern in cfg.require_auth_for)
    if not needs_auth:
        return []
    if not auth.authenticated:
        return [
            Finding(
                control="authz_gate",
                severity=Strictness.HIGH,
                action=cfg.action,
                confidence=1.0,
                message=f"Authentication required for {method}",
                category="unauthenticated",
            )
        ]
    # Privileged roles apply to every method that requires auth when configured.
    if cfg.privileged_roles and auth.role not in cfg.privileged_roles:
        return [
            Finding(
                control="authz_gate",
                severity=Strictness.HIGH,
                action=cfg.action,
                confidence=1.0,
                message=f"Role {auth.role!r} not privileged for {method}",
                category="forbidden_role",
            )
        ]
    return []


def check_tool_allowlist(tool_name: str | None, cfg: ControlConfig) -> list[Finding]:
    if not cfg.enabled or not tool_name:
        return []
    if not cfg.allowed_tools:
        return []
    if tool_name in cfg.allowed_tools:
        return []
    return [
        Finding(
            control="tool_allowlist",
            severity=cfg.strictness,
            action=cfg.action,
            confidence=1.0,
            message=f"Tool {tool_name!r} is not on the allowlist",
            category="tool_denied",
            matched=tool_name,
        )
    ]


def check_tools_allowlist(tool_names: list[str], cfg: ControlConfig) -> list[Finding]:
    findings: list[Finding] = []
    for name in tool_names:
        findings.extend(check_tool_allowlist(name, cfg))
    return findings


def _role_may_use(role: str | None, tool_name: str, cfg: ControlConfig) -> bool:
    if not cfg.role_tools:
        return True
    allowed = cfg.role_tools.get(role or "", [])
    return "*" in allowed or tool_name in allowed


def check_tool_authz(tool_names: list[str], auth: AuthContext, cfg: ControlConfig) -> list[Finding]:
    """Precise AuthZ: this role may invoke this bank/MCP function — not a global name list."""
    if not cfg.enabled or not tool_names:
        return []
    findings: list[Finding] = []
    for tool_name in tool_names:
        if _role_may_use(auth.role, tool_name, cfg):
            continue
        findings.append(
            Finding(
                control="tool_authz",
                severity=Strictness.HIGH,
                action=cfg.action,
                confidence=1.0,
                message=(
                    f"Role {auth.role!r} is not authorized to invoke {tool_name!r} "
                    "(e.g. counterparty balance is teller/admin only)"
                ),
                category="tool_role_denied",
                matched=tool_name,
            )
        )
    return findings
