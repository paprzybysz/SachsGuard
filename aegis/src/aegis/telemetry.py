"""OpenTelemetry setup — traces, metrics, and structured logs for Aegis."""

from __future__ import annotations

import json
import logging
import os
import socket
from typing import Any
from urllib.parse import urlparse

from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

_OTEL_ENDPOINT = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "")
_SERVICE_NAME = os.environ.get("OTEL_SERVICE_NAME", "aegis")
_ENABLED = os.environ.get("AEGIS_OTEL_ENABLED", "1") == "1"

# Hosts where plaintext OTLP is acceptable (loopback + compose internal service name).
_TRUSTED_PLAINTEXT_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "otel-collector"})


def _is_insecure_endpoint(endpoint: str) -> bool:
    """True when telemetry would cross a non-local network without TLS."""
    parsed = urlparse(endpoint)
    host = (parsed.hostname or "").lower()
    trusted = host in _TRUSTED_PLAINTEXT_HOSTS or host.endswith(".local")
    return parsed.scheme == "http" and not trusted


def _otlp_host_resolves(endpoint: str) -> bool:
    """Skip OTLP export when the collector hostname is not on this network.

    Compose without ``--profile obs`` and local ``aegis serve`` often still have
    ``OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318``. Exporting then
    retries forever and floods logs with NameResolutionError.
    """
    parsed = urlparse(endpoint)
    host = parsed.hostname
    if not host:
        return False
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return False
    return True


# Set AEGIS_OTEL_TEST=1 to enable the in-memory exporter (test introspection only).
_TEST_MODE = os.environ.get("AEGIS_OTEL_TEST", "0") == "1"
_OTLP_READY = bool(_ENABLED and _OTEL_ENDPOINT and _otlp_host_resolves(_OTEL_ENDPOINT))
_OTLP_SKIPPED_DNS = bool(_ENABLED and _OTEL_ENDPOINT and not _OTLP_READY)

_resource = Resource.create({"service.name": _SERVICE_NAME, "service.version": "1.0.0"})

# ── Traces ─────────────────────────────────────────────────────────────────────
_tracer_provider = TracerProvider(resource=_resource)

if _OTLP_READY:
    _tracer_provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{_OTEL_ENDPOINT}/v1/traces"))
    )

# In-memory exporter only in test mode — avoids unbounded memory growth in production.
_test_exporter: InMemorySpanExporter | None = None
if _TEST_MODE:
    _test_exporter = InMemorySpanExporter()
    _tracer_provider.add_span_processor(BatchSpanProcessor(_test_exporter))

trace.set_tracer_provider(_tracer_provider)
tracer = trace.get_tracer("aegis")

# ── Metrics ────────────────────────────────────────────────────────────────────
_readers: list[Any] = []
if _OTLP_READY:
    _readers.append(
        PeriodicExportingMetricReader(
            OTLPMetricExporter(endpoint=f"{_OTEL_ENDPOINT}/v1/metrics"),
            export_interval_millis=15_000,
        )
    )

_meter_provider = MeterProvider(resource=_resource, metric_readers=_readers)
metrics.set_meter_provider(_meter_provider)
meter = metrics.get_meter("aegis")

# ── OTEL-backed metric instruments ────────────────────────────────────────────
evaluations_counter = meter.create_counter(
    "aegis.evaluations",
    description="Total control-layer evaluations",
    unit="{evaluation}",
)
allowed_counter = meter.create_counter(
    "aegis.allowed",
    description="Evaluations that resulted in ALLOW",
    unit="{evaluation}",
)
blocked_counter = meter.create_counter(
    "aegis.blocked",
    description="Evaluations that resulted in BLOCK",
    unit="{evaluation}",
)
redacted_counter = meter.create_counter(
    "aegis.redacted",
    description="Evaluations that resulted in REDACT or DEGRADE",
    unit="{evaluation}",
)
tokens_counter = meter.create_counter(
    "aegis.tokens_estimated",
    description="Estimated prompt tokens processed",
    unit="{token}",
)
cost_counter = meter.create_counter(
    "aegis.cost_usd",
    description="Estimated USD cost of token usage",
    unit="usd",
)
# Unit is milliseconds; intentionally not "s" since this is a custom instrument.
latency_histogram = meter.create_histogram(
    "aegis.evaluation_duration_ms",
    description="Duration of ControlEngine.evaluate() calls",
    unit="ms",
)
# Per-finding breakdown labeled by control, category, and decision.
# Security teams use this to see which threat types fire and at what rate.
findings_counter = meter.create_counter(
    "aegis.findings",
    description="Policy findings broken down by control, threat category, and decision",
    unit="{finding}",
)

# ── Structured logging ─────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] trace_id=%(otelTraceID)s span_id=%(otelSpanID)s %(message)s",
)


class _OtelLogFilter(logging.Filter):
    """Inject active OTEL trace_id / span_id into every log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        span = trace.get_current_span()
        ctx = span.get_span_context()
        record.otelTraceID = format(ctx.trace_id, "032x") if ctx.is_valid else "0" * 32
        record.otelSpanID = format(ctx.span_id, "016x") if ctx.is_valid else "0" * 16
        return True


def configure_logging(target: logging.Logger | None = None) -> None:
    """Attach the OTEL log filter to all handlers on *target* (default: root logger).

    Called at module init; safe to call again after adding new handlers.
    """
    root = logging.getLogger()
    effective = target or root
    # Attach to every existing handler; fall back to root's handlers if target has none.
    handlers = effective.handlers or root.handlers
    for handler in handlers:
        if not any(isinstance(f, _OtelLogFilter) for f in handler.filters):
            handler.addFilter(_OtelLogFilter())


configure_logging()

logger = logging.getLogger("aegis")

if _OTLP_SKIPPED_DNS:
    logger.warning(
        "OTLP endpoint %s is not reachable (collector hostname did not resolve); "
        "spans stay in-process. Unset OTEL_EXPORTER_OTLP_ENDPOINT or start "
        "observability with: docker compose --profile obs up",
        _OTEL_ENDPOINT,
    )
if _OTLP_READY and _is_insecure_endpoint(_OTEL_ENDPOINT):
    logger.warning(
        "OTEL OTLP endpoint %s uses plaintext HTTP to a non-local host; "
        "use an https:// endpoint in production to protect telemetry "
        "(tenant/model/decision metadata) in transit.",
        _OTEL_ENDPOINT,
    )
_audit_logger = logging.getLogger("aegis.audit")


def emit_audit_log(event: dict[str, Any]) -> None:
    """Emit a structured audit event as a JSON log record.

    Every line carries the active trace_id/span_id (injected by _OtelLogFilter),
    making individual audit events correlatable to their OTEL traces.
    Log collectors (Loki, Fluentd, Vector) can forward these to a SIEM as-is.
    """
    _audit_logger.info("AUDIT %s", json.dumps(event, ensure_ascii=False, default=str))
