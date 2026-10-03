"""AI Control Layer gateway — OpenAI-compatible proxy + evaluate API."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import partial
from pathlib import Path
from typing import Any

import anyio
import httpx
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.metrics import CallbackOptions, Observation
from pydantic import BaseModel, Field
from starlette.routing import Route

from aegis import agent_hooks
from aegis import identity as identity_mod
from aegis.audit import AuditStore
from aegis.controls.budget import create_budget_tracker
from aegis.controls.deterministic import check_tool_authz, check_tools_allowlist
from aegis.controls.presidio_engine import warm_up as presidio_warm_up
from aegis.controls.semantic import SemanticBackendError, classify_with_ollama, ollama_url
from aegis.demo.bank import BANK, BankError
from aegis.engine import ControlEngine
from aegis.hitl import HitlStore
from aegis.identity import Principal
from aegis.mcp_proxy import McpProxy, OutputBlocked, Precheck
from aegis.mcp_upstreams import UpstreamUnavailable
from aegis.policy.loader import PolicyStore
from aegis.policy.models import Action, Decision, EvaluationResult
from aegis.telemetry import logger, meter  # noqa: F401 — logger import ensures OTEL setup runs

ROOT = Path(os.environ.get("AEGIS_ROOT", Path(__file__).resolve().parents[2]))
# The single policy file; AEGIS_PROFILE overrides its active_profile.
POLICY_PATH = Path(os.environ.get("AEGIS_POLICY", ROOT / "policies" / "policy.yaml"))
POLICY_PROFILE = os.environ.get("AEGIS_PROFILE") or None
UPSTREAM = os.environ.get("AEGIS_UPSTREAM_URL", "").rstrip("/")
# Credential for the upstream model API. The caller's Aegis token is never forwarded.
UPSTREAM_API_KEY = os.environ.get("AEGIS_UPSTREAM_API_KEY", "")
DEMO_MODE = os.environ.get("AEGIS_DEMO_ECHO", "1") == "1"

# ── Audit-log backend config ────────────────────────────────────────────
# AEGIS_AUDIT_BACKEND: "memory" (default) | "redis"
# AEGIS_AUDIT_REDIS_URL: Redis URL — falls back to AEGIS_REDIS_URL
# AEGIS_AUDIT_REDIS_MAXLEN: max events kept in Redis per key (default 10 000)
# AEGIS_AUDIT_REDIS_TTL_DAYS: age-based eviction in Redis (default 7 days)
# AEGIS_AUDIT_EXPORT_PATH: default file path for POST /v1/audit/export/file
_AUDIT_BACKEND = os.environ.get("AEGIS_AUDIT_BACKEND", "memory").lower()
_AUDIT_REDIS_URL: str | None = (
    os.environ.get("AEGIS_AUDIT_REDIS_URL")
    or (os.environ.get("AEGIS_REDIS_URL") if _AUDIT_BACKEND == "redis" else None)
)
_AUDIT_REDIS_MAXLEN = int(os.environ.get("AEGIS_AUDIT_REDIS_MAXLEN", "10000"))
_AUDIT_REDIS_TTL_DAYS = int(os.environ.get("AEGIS_AUDIT_REDIS_TTL_DAYS", "7"))
_AUDIT_EXPORT_PATH = Path(
    os.environ.get("AEGIS_AUDIT_EXPORT_PATH", ROOT / "artifacts" / "audit_export.jsonl")
)

policy_store = PolicyStore(POLICY_PATH, profile=POLICY_PROFILE)
engine = ControlEngine(policy_store, root=ROOT, budgets=create_budget_tracker(ROOT))


def _audit_path(rel: str | None = None) -> Path:
    path = Path(rel or engine.policy.reporting.audit_log_path)
    return path if path.is_absolute() else ROOT / path


def _make_audit_store(path: Path) -> AuditStore:
    return AuditStore(
        path,
        redis_url=_AUDIT_REDIS_URL,
        redis_maxlen=_AUDIT_REDIS_MAXLEN,
        redis_ttl_days=_AUDIT_REDIS_TTL_DAYS,
    )


audit = _make_audit_store(_audit_path())
hitl = HitlStore()
# Last audit_log_path value applied, and last (digest, error) seen per policy file.
_audit_rel: str | None = engine.policy.reporting.audit_log_path
_policy_seen: dict[Path, tuple[str | None, str | None]] = {}
_policy_sync_lock = threading.Lock()


def _sync_audit_path() -> None:
    """Honour policy.reporting.audit_log_path whenever the policy changes it."""
    global audit, _audit_rel
    rel = engine.policy.reporting.audit_log_path
    if rel != _audit_rel:
        audit = _make_audit_store(_audit_path(rel))
        _audit_rel = rel


def _sync_policy_state() -> None:
    """Apply hot-reloaded reporting settings and audit every policy load / rejection."""
    with _policy_sync_lock:
        engine.policy  # noqa: B018 — triggers the mtime check / reload
        _sync_audit_path()
        store = engine.policy_store
        state = (store.digest, store.last_error)
        previous = _policy_seen.get(store.path)
        if previous == state:
            return
        _policy_seen[store.path] = state
        profile = store.active_profile
        if store.last_error and (previous is None or previous[1] != store.last_error):
            audit.record_policy_change(
                event="policy_rejected",
                path=str(store.path),
                profile=profile,
                policy_sha256=store.digest,
                error=store.last_error,
            )
        if previous is None or previous[0] != store.digest:
            audit.record_policy_change(
                event="policy_loaded" if previous is None else "policy_reloaded",
                path=str(store.path),
                profile=profile,
                policy_sha256=store.digest,
            )


def _control_plane_roles() -> list[str]:
    return engine.policy.roles.control_plane


def _is_control_plane(principal: Principal | None) -> bool:
    return identity_mod.REGISTRY.is_control_plane(principal, _control_plane_roles())


def _observe_budget_tokens(_options: CallbackOptions) -> list[Observation]:
    try:
        snap = engine.budgets.snapshot()
    except Exception:  # noqa: BLE001 — telemetry must never break the request path
        return []
    return [Observation(int(snap.get("tokens") or 0), {"tenant": "default"})]


def _observe_budget_requests(_options: CallbackOptions) -> list[Observation]:
    try:
        snap = engine.budgets.snapshot()
    except Exception:  # noqa: BLE001 — telemetry must never break the request path
        return []
    return [Observation(int(snap.get("requests") or 0), {"tenant": "default"})]


# Budget state is a live snapshot, so export as OTEL observable gauges
# (callbacks run at metric-export time) rather than push counters.
meter.create_observable_gauge(
    "aegis.budget_tokens",
    callbacks=[_observe_budget_tokens],
    description="Tokens consumed in the current budget window",
    unit="{token}",
)
meter.create_observable_gauge(
    "aegis.budget_requests",
    callbacks=[_observe_budget_requests],
    description="Requests in the current budget window",
    unit="{request}",
)


def _warm_up() -> None:
    """Load spaCy (Presidio) and the LLM judge so the first request is not a cold start."""
    presidio_warm_up()
    for name in ("prompt_injection", "jailbreak_detector"):
        cfg = engine.policy.control(name)
        if cfg and cfg.enabled and cfg.backend == "ollama":
            try:
                classify_with_ollama("warm-up: hello", cfg)
            except SemanticBackendError:
                pass  # surfaced per request via fail_mode + /health
            return


@asynccontextmanager
async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
    if os.environ.get("AEGIS_WARMUP", "1") == "1":
        threading.Thread(target=_warm_up, daemon=True).start()
    # The MCP proxy owns its upstream connections for the lifetime of the app.
    async with anyio.create_task_group() as tg:
        async with mcp_proxy.running(tg):
            yield
        tg.cancel_scope.cancel()


app = FastAPI(title="Aegis AI Control Layer", version="1.0.0", lifespan=_lifespan)

# Auto-instrument FastAPI (traces every request) and outbound httpx calls.
FastAPIInstrumentor.instrument_app(app)


@app.middleware("http")
async def _policy_state_middleware(request: Request, call_next: Any) -> Response:
    _sync_policy_state()
    return await call_next(request)

HTTPXClientInstrumentor().instrument()
static_dir = Path(__file__).parent / "dashboard" / "static"
if static_dir.is_dir():
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


class EvaluateRequest(BaseModel):
    text: str
    model: str = "demo-echo"
    method: str = "chat.completions"
    tool_name: str | None = None
    tool_names: list[str] | None = None
    tenant: str = "default"
    direction: str = "inbound"
    # Client-asserted identity fields are ignored (kept for schema compat).
    role: str | None = None
    authenticated: bool = False


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    model: str = "demo-echo"
    messages: list[ChatMessage]
    max_tokens: int | None = None
    temperature: float | None = None
    stream: bool = False
    tools: list[dict[str, Any]] | None = None
    tool_choice: Any = None


class McpInvokeRequest(BaseModel):
    method: str = "tools/call"
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    tenant: str = "default"


def require_principal(
    authorization: str | None = Header(default=None),
) -> Principal:
    # Identity is resolved ONLY from the Authorization header. Tokens are never
    # accepted from the URL query string on general endpoints, since URLs leak
    # into access logs, proxies, browser history and Referer headers.
    principal = identity_mod.REGISTRY.resolve_bearer(authorization)
    if principal is None:
        raise HTTPException(status_code=401, detail={"error": "aegis_auth_required"})
    return principal


def require_control_plane(principal: Principal = Depends(require_principal)) -> Principal:
    if not _is_control_plane(principal):
        raise HTTPException(status_code=403, detail={"error": "aegis_forbidden"})
    return principal


def require_control_plane_download(
    authorization: str | None = Header(default=None),
    token: str | None = Query(default=None),
) -> Principal:
    # Browser <a> download links cannot set an Authorization header, so the audit
    # export endpoint (and only it) also accepts the admin token via query string.
    # This is a deliberate, scoped trade-off; all other endpoints are header-only.
    principal = identity_mod.REGISTRY.resolve(authorization, token_query=token)
    if principal is None:
        raise HTTPException(status_code=401, detail={"error": "aegis_auth_required"})
    if not _is_control_plane(principal):
        raise HTTPException(status_code=403, detail={"error": "aegis_forbidden"})
    return principal


def _tool_names(tools: list[dict[str, Any]] | None) -> list[str]:
    names: list[str] = []
    for tool in tools or []:
        name = (tool.get("function") or {}).get("name") or tool.get("name")
        if isinstance(name, str) and name:
            names.append(name)
    return names


def _messages_text(messages: list[ChatMessage]) -> str:
    return "\n".join(f"{m.role}: {m.content}" for m in messages)


def _redact_messages(messages: list[ChatMessage], tenant: str) -> list[ChatMessage]:
    return [
        ChatMessage(role=m.role, content=engine.redact_text(m.content, tenant))
        for m in messages
    ]


def _should_redact(decision: Decision) -> bool:
    return decision in {Decision.REDACT, Decision.DEGRADE}


def session_key(principal: Principal, session_id: str | None) -> str:
    """Information-flow session: one per caller identity (+ optional agent session id).

    Keyed by a hash of the token so one caller's reads never taint another caller,
    and the raw credential never appears in state or logs.
    """
    caller = hashlib.sha256(principal.subject.encode()).hexdigest()[:12]
    suffix = (session_id or "default").strip()[:64] or "default"
    return f"{principal.tenant}:{caller}:{suffix}"


def _findings(result: EvaluationResult) -> list[dict[str, Any]]:
    return [f.model_dump() for f in result.findings]


def _envelope(result: EvaluationResult) -> dict[str, Any]:
    return {
        "decision": result.decision.value,
        "findings": _findings(result),
        "redacted": bool(result.redacted_text),
        "latency_ms": result.metadata.get("latency_ms"),
    }


def _blocked(error: str, result: EvaluationResult) -> HTTPException:
    return HTTPException(
        status_code=403,
        detail={"error": error, "decision": "block", "findings": _findings(result)},
    )


def _scan_output(text: str, *, model: str, principal: Principal, session: str) -> str:
    """Egress filter: DLP the model output; raise 403 if policy blocks it."""
    out = engine.evaluate(
        text,
        model=model,
        method="chat.completions",
        auth=principal.to_auth(),
        tenant=principal.tenant,
        session=session,
        direction="outbound",
        commit_budget=False,
    )
    if out.decision != Decision.ALLOW:
        audit.record(out)
    if out.decision == Decision.BLOCK:
        raise _blocked("aegis_output_blocked", out)
    return out.redacted_text if out.redacted_text is not None else text


def _hold_payload(result: EvaluationResult, *, tool_name: str, hitl_id: str) -> dict[str, Any]:
    reasons = [f.message for f in result.findings if f.action == Action.HOLD]
    return {
        "ok": False,
        "decision": "hold",
        "hitl_id": hitl_id,
        "tool_name": tool_name,
        "aegis": {**_envelope(result), "hitl_id": hitl_id},
        "reasons": reasons,
        "system_one": result.metadata.get("system_one") or {},
    }


def _redacted_arguments(body_args: dict[str, Any], result: EvaluationResult) -> dict[str, Any]:
    if result.redacted_text is None:
        return body_args
    try:
        parsed = json.loads(result.redacted_text)
        if isinstance(parsed, dict):
            return parsed
        return {"redacted": result.redacted_text}
    except json.JSONDecodeError:
        return {"redacted": result.redacted_text}


def _mask_structure(value: Any, *, principal: Principal, session: str) -> Any:
    """DLP string leaves of a tool payload so JSON numbers stay valid."""
    if isinstance(value, str):
        return _scan_output(value, model="demo-echo", principal=principal, session=session)
    if isinstance(value, dict):
        return {str(k): _mask_structure(v, principal=principal, session=session) for k, v in value.items()}
    if isinstance(value, list):
        return [_mask_structure(v, principal=principal, session=session) for v in value]
    return value


def _guard_tool_call(
    principal: Principal,
    session: str,
    tool_name: str,
    arguments: dict[str, Any],
    *,
    method: str = "tools/call",
    origin: str = "bank",
) -> tuple[Precheck, EvaluationResult]:
    """All controls for one tool call, before it executes (shared by REST and MCP).

    ``hold`` queues the call for a human (nothing executes); every outcome is audited.
    """
    result = engine.evaluate(
        json.dumps(arguments, ensure_ascii=False),
        model="demo-echo",
        method=method,
        tool_name=tool_name,
        auth=principal.to_auth(),
        tenant=principal.tenant,
        session=session,
        direction="agent_to_mcp",
    )
    args = _redacted_arguments(arguments, result)
    if result.decision == Decision.HOLD:
        item = hitl.enqueue(
            tenant=principal.tenant,
            role=principal.role,
            tool_name=tool_name,
            method=method,
            arguments=args,
            session=session,
            reasons=[f.message for f in result.findings if f.action == Action.HOLD],
            system_one=result.metadata.get("system_one") or {},
            origin=origin,
            subject=principal.subject,
        )
        result.metadata["hitl_id"] = item.id
        audit.record(result)
        return Precheck("hold", args, _hold_payload(result, tool_name=tool_name, hitl_id=item.id)), result
    audit.record(result)
    if result.decision == Decision.BLOCK:
        blocked = {"error": "aegis_blocked", "decision": "block", "findings": _findings(result)}
        return Precheck("block", args, blocked), result
    return Precheck("allow", args, _envelope(result)), result


def _screen_tool_output(raw: Any, tool_name: str, principal: Principal, session: str) -> Any:
    """Tool result → caller: information-flow taint/check, then egress DLP on string leaves.

    Raises OutputBlocked when the result may not reach the caller.
    """
    payload = raw if isinstance(raw, str) else json.dumps(raw, ensure_ascii=False)
    tenant_policy = engine.policy_for(principal.tenant)
    ifc = tenant_policy.control("information_flow")
    if ifc:
        extra = engine.check_flow(session, payload, [tool_name], ifc, tenant_policy)
        if any(f.action == Action.BLOCK for f in extra):
            blocked = engine.evaluate(
                payload,
                model="demo-echo",
                method="tools/call",
                tool_name=tool_name,
                auth=principal.to_auth(),
                tenant=principal.tenant,
                session=session,
                direction="outbound",
                commit_budget=False,
            )
            blocked.findings.extend(extra)
            audit.record(blocked)
            raise OutputBlocked({"error": "aegis_output_blocked", "decision": "block", "findings": _findings(blocked)})
    try:
        return _mask_structure(raw, principal=principal, session=session)
    except HTTPException as exc:  # egress DLP with action block
        raise OutputBlocked(exc.detail) from exc


def _execute_bank_tool(
    tool_name: str,
    arguments: dict[str, Any],
    *,
    principal: Principal,
    session: str,
) -> dict[str, Any]:
    raw = BANK.dispatch(tool_name, arguments, role=principal.role, tenant=principal.tenant)
    try:
        masked = _screen_tool_output(raw, tool_name, principal, session)
    except OutputBlocked as exc:
        raise HTTPException(status_code=403, detail=exc.detail) from exc
    return masked if isinstance(masked, dict) else {"result": masked}


class _GatewayHooks:
    """The gateway side of the MCP proxy (reads module state at call time)."""

    def resolve_principal(self, authorization: str | None) -> Principal | None:
        return identity_mod.REGISTRY.resolve_bearer(authorization)

    def session_key(self, principal: Principal, session_id: str | None) -> str:
        return session_key(principal, session_id)

    def upstreams(self) -> list[Any]:
        return list(engine.policy.mcp.upstreams)

    def visible_tools(self, principal: Principal, names: list[str]) -> set[str]:
        """Tools this caller may call: what tools/list shows (the call is still checked)."""
        policy = engine.policy_for(principal.tenant)
        auth = principal.to_auth()
        allowlist = policy.control("tool_allowlist")
        authz = policy.control("tool_authz")
        return {
            name
            for name in names
            if not (allowlist and check_tools_allowlist([name], allowlist))
            and not (authz and check_tool_authz([name], auth, authz))
        }

    def precheck(
        self, principal: Principal, session: str, tool_name: str, arguments: dict[str, Any], origin: str
    ) -> Precheck:
        return _guard_tool_call(principal, session, tool_name, arguments, origin=origin)[0]

    def screen_output(self, raw: Any, tool_name: str, principal: Principal, session: str) -> Any:
        return _screen_tool_output(raw, tool_name, principal, session)

    def hitl_status(self, principal: Principal, hitl_id: str) -> dict[str, Any] | None:
        item = hitl.get(hitl_id)
        if item is None or item.tenant != principal.tenant:
            return None
        if item.subject and item.subject != principal.subject and not _is_control_plane(principal):
            return None
        return {
            "hitl_id": item.id,
            "status": item.status,
            "tool_name": item.tool_name,
            "reasons": item.reasons,
            "result": item.result if item.status == "approved" else None,
        }


mcp_proxy = McpProxy(_GatewayHooks())
# Agents connect here (MCP Streamable HTTP). An ASGI object, so Starlette passes raw ASGI.
app.router.routes.append(Route("/mcp", endpoint=mcp_proxy, methods=["GET", "POST", "DELETE"]))


@app.get("/health")
def health() -> dict[str, Any]:
    policy = engine.policy
    semantic = {
        name: {"backend": cfg.backend, "model": cfg.ollama_model, "fail_mode": cfg.fail_mode.value,
               "url": ollama_url(cfg) if cfg.backend == "ollama" else None}
        for name in ("prompt_injection", "jailbreak_detector")
        if (cfg := policy.control(name))
    }
    store = engine.policy_store
    return {
        "status": "degraded" if store.last_error else "ok",
        "profile": policy.profile,
        "policy_path": str(store.path),
        "policy_sha256": store.digest,
        "policy_error": store.last_error,
        "profiles": sorted(store.file().profiles),
        "tenant_profiles": dict(store.file().tenant_profiles),
        "controls": {name: cfg.enabled for name, cfg in policy.controls.items()},
        "budget_backend": os.environ.get("AEGIS_BUDGET_BACKEND", "sqlite"),
        "audit_backend": _AUDIT_BACKEND,
        "semantic": semantic,
        "historical_feed": engine.feeds.status(),
        "hitl": hitl.snapshot(),
        "mcp": mcp_proxy.status(),
        "system_one": {
            "backend": (policy.control("system_one").backend if policy.control("system_one") else None),
            "hitl_tools": (policy.control("system_one").hitl_tools if policy.control("system_one") else []),
        },
    }


@app.post("/v1/reload")
def reload_policy(_: Principal = Depends(require_control_plane)) -> dict[str, Any]:
    store = engine.policy_store
    policy = store.reload()
    _sync_policy_state()
    if store.last_error:
        # The file on disk is invalid: the previous policy stays active.
        raise HTTPException(
            status_code=422,
            detail={
                "error": "aegis_policy_invalid",
                "message": store.last_error,
                "active_profile": policy.profile,
                "active_policy_sha256": store.digest,
            },
        )
    return {"status": "reloaded", "profile": policy.profile, "policy_sha256": store.digest}


@app.get("/v1/policy")
def get_policy(_: Principal = Depends(require_control_plane)) -> dict[str, Any]:
    return engine.policy.model_dump()


@app.post("/v1/evaluate")
def evaluate_endpoint(
    body: EvaluateRequest,
    principal: Principal = Depends(require_principal),
    x_aegis_session: str | None = Header(default=None),
) -> dict[str, Any]:
    # Identity comes only from the verified Bearer token — body role/auth ignored.
    result = engine.evaluate(
        body.text,
        model=body.model,
        method=body.method,
        tool_name=body.tool_name,
        tool_names=body.tool_names,
        auth=principal.to_auth(),
        tenant=principal.tenant,
        session=session_key(principal, x_aegis_session),
        direction=body.direction,
    )
    event = audit.record(result)
    return {
        "decision": result.decision.value,
        "findings": _findings(result),
        "redacted_text": result.redacted_text,
        "tokens_estimated": result.tokens_estimated,
        "cost_estimated": result.cost_estimated,
        "latency_ms": result.metadata.get("latency_ms"),
        "timings_ms": result.metadata.get("timings_ms"),
        "event": event.to_dict(),
        "metrics": audit.metrics.to_dict(),
        "principal": {"role": principal.role, "tenant": principal.tenant},
    }


@app.post("/v1/chat/completions", response_model=None)
async def chat_completions(
    body: ChatCompletionRequest,
    principal: Principal = Depends(require_principal),
    x_aegis_session: str | None = Header(default=None),
) -> Any:
    session = session_key(principal, x_aegis_session)
    result = engine.evaluate(
        _messages_text(body.messages),
        model=body.model,
        method="chat.completions",
        tool_names=_tool_names(body.tools),
        auth=principal.to_auth(),
        tenant=principal.tenant,
        session=session,
        direction="inbound",
        max_tokens=body.max_tokens,
    )
    if result.decision == Decision.HOLD:
        item = hitl.enqueue(
            tenant=principal.tenant,
            role=principal.role,
            tool_name="chat.completions",
            method="chat.completions",
            arguments={"messages": [m.model_dump() for m in body.messages]},
            session=session,
            reasons=[f.message for f in result.findings if f.action == Action.HOLD],
            system_one=result.metadata.get("system_one") or {},
        )
        result.metadata["hitl_id"] = item.id
        audit.record(result)
        return JSONResponse(
            status_code=202,
            content=_hold_payload(result, tool_name="chat.completions", hitl_id=item.id),
        )
    audit.record(result)
    if result.decision == Decision.BLOCK:
        raise _blocked("aegis_blocked", result)

    outbound_messages = body.messages
    if _should_redact(result.decision) or result.redacted_text is not None:
        outbound_messages = _redact_messages(body.messages, principal.tenant)

    model = body.model
    if result.decision == Decision.DEGRADE:
        model = engine.policy_for(principal.tenant).degrade_target

    if DEMO_MODE or not UPSTREAM or model == "demo-echo":
        content = (
            f"[aegis:{result.decision.value}] echo ok. "
            f"controls_hit={[f.control for f in result.findings] or ['none']}"
        )
        content = _scan_output(content, model=model, principal=principal, session=session)
        return {
            "id": f"aegis-{int(time.time() * 1000)}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": result.tokens_estimated,
                "completion_tokens": body.max_tokens or 16,
                "total_tokens": result.tokens_estimated + (body.max_tokens or 16),
            },
            "aegis": _envelope(result),
        }

    payload = body.model_dump()
    payload["model"] = model
    payload["messages"] = [m.model_dump() for m in outbound_messages]
    headers = {"Authorization": f"Bearer {UPSTREAM_API_KEY}"} if UPSTREAM_API_KEY else {}
    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(f"{UPSTREAM}/v1/chat/completions", json=payload, headers=headers)
    finally:
        # Charge model wall-clock time against the compute budget (local or remote).
        elapsed = time.perf_counter() - started
        audit.observe_upstream(elapsed * 1000)
        tenant_policy = engine.policy_for(principal.tenant)
        engine.budgets.record_compute(
            engine.budget_key(principal.tenant, principal.to_auth(), tenant_policy),
            tenant_policy.budgets,
            elapsed,
        )
    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail={"error": "aegis_upstream_error", "status": response.status_code})
    data = response.json()
    try:
        upstream_text = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        upstream_text = ""
    if upstream_text:
        data["choices"][0]["message"]["content"] = _scan_output(
            str(upstream_text), model=model, principal=principal, session=session
        )
    data["aegis"] = {**_envelope(result), "upstream_ms": round(elapsed * 1000, 1)}
    return data


def _mask_leaves(value: Any, tenant: str) -> Any:
    """Inbound redaction (PII, secrets, DLP) on every string leaf; keeps the structure."""
    if isinstance(value, str):
        return engine.redact_text(value, tenant)
    if isinstance(value, dict):
        return {k: _mask_leaves(v, tenant) for k, v in value.items()}
    if isinstance(value, list):
        return [_mask_leaves(v, tenant) for v in value]
    return value


@app.post("/v1/hooks/claude-code", response_model=None)
def claude_code_hook(
    payload: dict[str, Any] = Body(...),
    principal: Principal = Depends(require_principal),
) -> Response:
    """Claude Code ``http`` hook: Aegis guards the agent's prompts, tool calls and results.

    Returns 204 (no decision: Claude Code's normal flow) or a hook response JSON.
    """
    cfg = engine.policy_for(principal.tenant).agent_hooks
    session = session_key(principal, f"claude:{payload.get('session_id') or 'default'}")
    skip = frozenset(cfg.skip_controls)

    def run(text: str, method: str, tool_name: str | None) -> EvaluationResult:
        result = engine.evaluate(
            text,
            model="demo-echo",
            method=method,
            auth=principal.to_auth(),
            tenant=principal.tenant,
            session=session,
            commit_budget=False,
            skip_controls=skip,
            semantic_backend=None if agent_hooks.uses_llm_judge(cfg, tool_name) else "heuristic",
        )
        if tool_name:
            result.metadata["tool_name"] = tool_name
        audit.record(result)
        return result

    out = agent_hooks.handle(payload, cfg, run, lambda value: _mask_leaves(value, principal.tenant))
    return JSONResponse(out) if out else Response(status_code=204)


@app.post("/v1/mcp/invoke", response_model=None)
def mcp_invoke(
    body: McpInvokeRequest,
    principal: Principal = Depends(require_principal),
    x_aegis_session: str | None = Header(default=None),
) -> Any:
    session = session_key(principal, x_aegis_session)
    check, result = _guard_tool_call(principal, session, body.tool_name, body.arguments, method=body.method)
    if check.decision == "hold":
        return JSONResponse(status_code=202, content=check.payload)
    if check.decision == "block":
        raise HTTPException(status_code=403, detail=check.payload)
    args = check.arguments
    try:
        dispatched = _execute_bank_tool(body.tool_name, args, principal=principal, session=session)
    except BankError as exc:
        raise HTTPException(status_code=400, detail={"error": "aegis_tool_error", "message": str(exc)}) from exc
    return {
        "ok": True,
        "tool_name": body.tool_name,
        "result": dispatched,
        "aegis": _envelope(result),
    }


@app.get("/v1/metrics")
def metrics(
    principal: Principal = Depends(require_principal),
    x_aegis_session: str | None = Header(default=None),
) -> dict[str, Any]:
    policy = engine.policy_for(principal.tenant)
    if not policy.reporting.metrics_enabled:
        raise HTTPException(status_code=404, detail={"error": "aegis_metrics_disabled"})
    return {
        **audit.metrics.to_dict(),
        "budget": engine.budgets.snapshot(engine.budget_key(principal.tenant, principal.to_auth(), policy)),
        "budget_limits": policy.budgets.model_dump(),
        "profile": policy.profile,
        "flow": engine.flow.snapshot(session_key(principal, x_aegis_session)),
        "hitl": hitl.snapshot(),
    }


@app.get("/v1/events")
def events(
    principal: Principal = Depends(require_principal),
    limit: int = Query(default=50, ge=1, le=500),
) -> dict[str, Any]:
    # Tenant isolation: only control-plane roles (admin/security) may read across
    # all tenants. Everyone else sees only their own tenant's events, which can
    # contain previews of request content.
    scope = None if _is_control_plane(principal) else principal.tenant
    return {"events": audit.recent(limit, tenant=scope)}


@app.get("/v1/audit/export")
def export_audit(
    _: Principal = Depends(require_control_plane_download),
    fmt: str = Query(default="jsonl"),
) -> PlainTextResponse:
    formats = engine.policy.reporting.export_formats
    if fmt not in formats:
        raise HTTPException(status_code=400, detail={"error": "unsupported_format", "allowed": formats})
    if fmt == "csv":
        return PlainTextResponse(audit.export_csv(), media_type="text/csv")
    return PlainTextResponse(audit.export_jsonl(), media_type="application/x-ndjson")


class _ExportFileRequest(BaseModel):
    path: str | None = Field(
        default=None,
        description="Absolute path for the export file.  Must be under AEGIS_ROOT/artifacts/. "
        "Defaults to AEGIS_AUDIT_EXPORT_PATH.",
    )


@app.post("/v1/audit/export/file")
def export_audit_to_file(
    _: Principal = Depends(require_control_plane),
    body: _ExportFileRequest = _ExportFileRequest(),
) -> dict[str, Any]:
    """Write the full audit log to a JSONL file on the server.

    The destination path must resolve under ``{AEGIS_ROOT}/artifacts/`` to
    prevent path-traversal.  When a Redis backend is active the export pulls
    the complete multi-replica history; otherwise the local JSONL log is used.
    """
    artifacts_root = (ROOT / "artifacts").resolve()
    dest = Path(body.path).resolve() if body.path else _AUDIT_EXPORT_PATH.resolve()
    try:
        dest.relative_to(artifacts_root)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_path", "detail": "path must be under AEGIS_ROOT/artifacts/"},
        )

    count = audit.export_to_file(dest)
    return {"path": str(dest), "events": count, "backend": _AUDIT_BACKEND}


def _hitl_reader(principal: Principal) -> Principal:
    if _is_control_plane(principal) or principal.role in engine.policy.roles.hitl_reviewers:
        return principal
    raise HTTPException(status_code=403, detail={"error": "aegis_forbidden"})


@app.get("/v1/hitl/queue")
def hitl_queue(principal: Principal = Depends(require_principal)) -> dict[str, Any]:
    _hitl_reader(principal)
    tenant = None if _is_control_plane(principal) else principal.tenant
    return {
        "items": [i.to_dict() for i in hitl.list_pending(tenant=tenant)],
        "history": [i.to_dict() for i in hitl.list_resolved(tenant=tenant)],
        "metrics": hitl.snapshot(),
    }


@app.post("/v1/hitl/{action_id}/approve")
async def hitl_approve(
    action_id: str,
    principal: Principal = Depends(require_control_plane),
) -> dict[str, Any]:
    item = hitl.get(action_id)
    if item is None or item.status != "pending":
        raise HTTPException(status_code=404, detail={"error": "aegis_hitl_not_found"})
    caller = Principal(
        token=principal.token,
        subject=principal.subject,
        role=item.role,
        tenant=item.tenant,
    )
    try:
        if item.origin.startswith("mcp:"):
            raw = await mcp_proxy.execute_approved(item.origin[4:], item.tool_name, item.arguments, caller)
            dispatched = await anyio.to_thread.run_sync(
                partial(_screen_tool_output, raw, item.tool_name, caller, item.session)
            )
        else:
            dispatched = await anyio.to_thread.run_sync(
                partial(_execute_bank_tool, item.tool_name, item.arguments, principal=caller, session=item.session)
            )
    except BankError as exc:
        raise HTTPException(status_code=400, detail={"error": "aegis_tool_error", "message": str(exc)}) from exc
    except UpstreamUnavailable as exc:
        raise HTTPException(status_code=502, detail={"error": "aegis_upstream_unavailable", "message": str(exc)}) from exc
    except OutputBlocked as exc:
        raise HTTPException(status_code=403, detail=exc.detail) from exc
    resolved = hitl.resolve(action_id, status="approved", resolved_by=principal.role, result=dispatched)
    return {"ok": True, "result": dispatched, "hitl": resolved.to_dict() if resolved else None}


@app.post("/v1/hitl/{action_id}/deny")
def hitl_deny(
    action_id: str,
    principal: Principal = Depends(require_control_plane),
) -> dict[str, Any]:
    item = hitl.get(action_id)
    if item is None or item.status != "pending":
        raise HTTPException(status_code=404, detail={"error": "aegis_hitl_not_found"})
    resolved = hitl.resolve(action_id, status="denied", resolved_by=principal.role)
    return {"ok": True, "result": None, "hitl": resolved.to_dict() if resolved else None}


@app.get("/", response_class=HTMLResponse)
def dashboard() -> HTMLResponse:
    return _serve_dashboard("index.html")


@app.get("/hitl", response_class=HTMLResponse)
def hitl_dashboard() -> HTMLResponse:
    return _serve_dashboard("hitl.html")


def _serve_dashboard(filename: str) -> HTMLResponse:
    html_path = Path(__file__).parent / "dashboard" / filename
    html = html_path.read_text(encoding="utf-8")
    html = html.replace("__AEGIS_TOKEN__", identity_mod.issue_token("demo", "developer"))
    html = html.replace("__AEGIS_TELLER_TOKEN__", identity_mod.issue_token("demo-teller", "teller"))
    html = html.replace("__AEGIS_ADMIN_TOKEN__", identity_mod.issue_token("demo-admin", "admin"))
    return HTMLResponse(html)


@app.post("/v1/demo/reset")
def demo_reset(_: Principal = Depends(require_control_plane)) -> dict[str, str]:
    engine.budgets.reset()
    engine.flow.reset()
    engine.loops.reset()
    hitl.reset()
    BANK.reset()
    audit.reset_metrics()
    return {"status": "reset"}
