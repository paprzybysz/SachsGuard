"""DLP / masking — dedicated data-loss prevention on inbound and egress.

Detects PII, payment identifiers and secrets with Microsoft Presidio
(``presidio_engine``) and replaces them with stable tokens. This is the control
whose only job is protecting customer data.
"""

from __future__ import annotations

from aegis.controls.presidio_engine import detect_and_mask
from aegis.policy.models import Action, ControlConfig, Finding

DEFAULT_PATTERNS = ["email", "phone", "ssn", "pesel", "credit_card", "iban", "account"]


def _applies(cfg: ControlConfig, direction: str) -> bool:
    apply_on = cfg.apply_on or ["inbound", "outbound"]
    return direction in apply_on


def scan_dlp(text: str, cfg: ControlConfig, *, direction: str = "inbound") -> tuple[list[Finding], str]:
    if not cfg.enabled or not _applies(cfg, direction):
        return [], text
    detections, redacted = detect_and_mask(
        text,
        cfg.patterns or DEFAULT_PATTERNS,
        cfg.strictness,
        mask=cfg.action in {Action.REDACT, Action.BLOCK, Action.DEGRADE},
        min_score=cfg.adherence,
    )
    findings = [
        Finding(
            control="dlp_masking",
            severity=cfg.strictness,
            action=cfg.action,
            confidence=min(1.0, d.score),
            message=f"DLP {direction} (Presidio): {d.category}",
            matched="[REDACTED]",
            category=d.category,
        )
        for d in detections
    ]
    return findings, redacted
