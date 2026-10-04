# Aegis — AI Control Layer (HackYeah)

HackYeah **AI Control Layer** entry: a Python **modular monolith**. A hybrid gateway enforces YAML policy with deterministic guardrails, a local-LLM semantic judge, a System One router, HITL for bank payments, information-flow control, an external attack-signature feed, durable budgets including compute time (SQLite/Redis), and live security reporting with performance telemetry.

| Doc | Purpose |
|---|---|
| [`aegis/README.md`](aegis/README.md) | Runbook, deliverables, integration |
| [`aegis/docs/architecture.md`](aegis/docs/architecture.md) | Architecture diagram |
| [`aegis/docs/policy-engine.md`](aegis/docs/policy-engine.md) | Centralized policy engine: compliance, diagrams, validation, budgets |


## How to run



```bash
cd aegis

OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318 docker compose --profile obs up --build
```

| Service | URL | Notes |
|---|---|---|
| Aegis dashboard | http://localhost:8080/ | API + live security UI · auth `Bearer demo` / JWT |
| HITL console | http://localhost:8080/hitl | payment approve/deny |
| Grafana | http://localhost:3000/ | dashboards · `admin` / `admin` (anonymous Viewer also on) |
| Prometheus | http://localhost:9090/ | scrapes the OTEL collector |
| OTEL collector | http://127.0.0.1:4318 | OTLP/HTTP (localhost only) |
| Host Ollama | http://127.0.0.1:11434 | semantic judge; start separately

## Test suite

From `aegis/`:

```bash
make test         # local pytest: control pos/neg, gateway, HITL, budgets, exploits, …
make docker-up    # Compose stack + in-container Ollama, then business-requirements suite
make test-l3      # L3 API tests against a live local Ollama judge (host)
```

If Compose fails, swap `docker compose` -> `docker-compose` in `aegis/Makefile` to match your Docker install.

