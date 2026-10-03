"""OpenAPPA-inspired information-flow control + document annotator.

Tracks a per-session security label (audience + trust) — one label per agent
trajectory, keyed by the authenticated principal plus an optional
``X-Aegis-Session`` id. Reading internal/customer data through a *source* tool
narrows the label; a *sink* tool (e.g. a public GitHub issue) is then blocked if
its required audience is no longer reachable. The outgoing payload of a sink is
classified too, so sensitive data sent straight to a public destination is
blocked even in a fresh session. Plain chat prompts never change the label:
only tool reads do.

This is an in-process subset of APPA (https://github.com/archestra-ai/OpenAPPA),
not the Rust runtime. Tool contracts live in the ``information_flow`` section of
the central policy file.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from aegis.controls.presidio_engine import detect
from aegis.policy.models import ControlConfig, Finding, InformationFlowPolicy, Strictness

TRUST_RANK = {"untrusted": 0, "trusted": 1}

_DEFAULT_INTERNAL_PATHS = ["customer-records", "crm", "kyc", "ticket", "counterparty"]
_DEFAULT_PUBLIC_PATHS = ["public-docs", "marketing", "faq"]
_DEFAULT_INTERNAL_CONTENT = ["iban", "pesel", "ssn", "counterparty", "kyc"]
# Structured identifiers (detected by Presidio) that mark content as customer data.
_SENSITIVE_CATEGORIES = ["iban", "pesel", "account", "ssn", "credit_card"]


@dataclass
class SecurityLabel:
    audiences: set[str] = field(default_factory=lambda: {"public", "internal"})
    trust: str = "trusted"

    def join(self, other: SecurityLabel) -> SecurityLabel:
        """Labels only get more restrictive (OpenAPPA monotonicity)."""
        trust = self.trust if TRUST_RANK[self.trust] <= TRUST_RANK[other.trust] else other.trust
        return SecurityLabel(audiences=self.audiences & other.audiences, trust=trust)


def _markers(cfg: dict[str, Any], key: str, default: list[str]) -> list[str]:
    return [str(x).lower() for x in cfg.get(key) or default]


def classify_document(text: str, *, path: str = "", annotator: dict[str, Any] | None = None) -> SecurityLabel:
    """Deterministic document classifier (OpenAPPA annotator)."""
    blob = f"{path}\n{text}".lower()
    cfg = annotator or {}
    internal_paths = _markers(cfg, "internal_path_markers", _DEFAULT_INTERNAL_PATHS)
    public_paths = _markers(cfg, "public_path_markers", _DEFAULT_PUBLIC_PATHS)
    internal_content = _markers(cfg, "internal_content_markers", _DEFAULT_INTERNAL_CONTENT)

    internal_path_hit = any(m in blob for m in internal_paths)
    detections, _ = detect(f"{path}\n{text}", _SENSITIVE_CATEGORIES, Strictness.MEDIUM)
    sensitive = bool(detections) or any(m in blob for m in internal_content)
    if any(m in blob for m in public_paths) and not internal_path_hit and not sensitive:
        return SecurityLabel(audiences={"public", "internal"}, trust="trusted")
    if internal_path_hit or sensitive:
        return SecurityLabel(audiences={"internal"}, trust="trusted")
    return SecurityLabel(audiences={"public", "internal"}, trust="trusted")


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


class InformationFlowTracker:
    """Per-session trajectory label (OpenAPPA session state)."""

    def __init__(self, policy: InformationFlowPolicy | None = None) -> None:
        self._lock = threading.Lock()
        self._labels: dict[str, SecurityLabel] = {}
        self._source: InformationFlowPolicy | None = None
        self._policy: dict[str, Any] = {}
        if policy is not None:
            self.use_policy(policy)

    def use_policy(self, policy: InformationFlowPolicy) -> None:
        """Follow the central policy's ``information_flow`` section (hot-reloaded with it)."""
        if policy is self._source:
            return
        data = policy.model_dump(exclude_none=True)
        with self._lock:
            self._source = policy
            self._policy = {
                "label": data["label"],
                "annotator": data["annotators"],
                "tool": data["tools"],
            }

    def _initial(self) -> SecurityLabel:
        label = self._policy.get("label") or {}
        audiences = set(_as_list(label.get("initial_audience")) or ["public", "internal"])
        trust = str(label.get("initial_trust") or "trusted")
        return SecurityLabel(audiences=audiences, trust=trust)

    def snapshot(self, session: str) -> dict[str, Any]:
        with self._lock:
            current = self._labels.get(session) or self._initial()
            return {
                "audiences": sorted(current.audiences),
                "trust": current.trust,
            }

    def reset(self, session: str | None = None) -> None:
        with self._lock:
            if session is None:
                self._labels.clear()
            else:
                self._labels.pop(session, None)

    def _named(self, section: str, name: str) -> dict[str, Any]:
        for item in self._policy.get(section) or []:
            if item.get("name") == name:
                return item
        return {}

    def _source_delta(self, contract: dict[str, Any], text: str, current: SecurityLabel) -> SecurityLabel | None:
        """Label of the data a source tool brings into the session, if any."""
        annotator_name = str(contract.get("annotator") or "")
        if annotator_name:
            return classify_document(text, annotator=self._named("annotator", annotator_name))
        if contract.get("delta_audience"):
            return SecurityLabel(
                audiences=set(_as_list(contract.get("delta_audience"))),
                trust=str(contract.get("delta_trust") or current.trust),
            )
        return None

    def _denied(self, tool_name: str, category: str, message: str, cfg: ControlConfig) -> Finding:
        return Finding(
            control="information_flow",
            severity=Strictness.HIGH,
            action=cfg.action,
            confidence=1.0,
            message=f"OpenAPPA: {message}",
            category=category,
            matched=tool_name,
        )

    def check_and_taint(
        self,
        session: str,
        *,
        text: str,
        tool_names: list[str],
        cfg: ControlConfig,
    ) -> list[Finding]:
        if not cfg.enabled or not tool_names:
            return []
        payload_annotator = self._named("annotator", "classify_document")
        findings: list[Finding] = []
        with self._lock:
            current = self._labels.get(session) or self._initial()
            for tool_name in tool_names:
                contract = self._named("tool", tool_name)
                delta = self._source_delta(contract, text, current)
                if delta is not None:
                    current = current.join(delta)

                required = set(_as_list(contract.get("requires_audience")))
                if required:
                    session_ok = not current.audiences.isdisjoint(required)
                    payload = classify_document(text, annotator=payload_annotator)
                    if not session_ok:
                        findings.append(
                            self._denied(
                                tool_name,
                                "audience_denied",
                                f"tool {tool_name!r} requires audience {sorted(required)} but the "
                                f"session label is {sorted(current.audiences)} "
                                "(internal/customer data already read in this session)",
                                cfg,
                            )
                        )
                    elif payload.audiences.isdisjoint(required):
                        findings.append(
                            self._denied(
                                tool_name,
                                "payload_audience_denied",
                                f"payload for {tool_name!r} is classified {sorted(payload.audiences)} "
                                f"but the destination requires {sorted(required)}",
                                cfg,
                            )
                        )
                need_trust = contract.get("requires_trust")
                if need_trust and TRUST_RANK.get(current.trust, 0) < TRUST_RANK.get(str(need_trust), 0):
                    findings.append(
                        self._denied(tool_name, "trust_denied", f"tool {tool_name!r} requires trust={need_trust}", cfg)
                    )
            self._labels[session] = current
        return findings
