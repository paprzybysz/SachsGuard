# Aegis — AI Control Layer (HackYeah)

HackYeah **AI Control Layer** entry: a Python **modular monolith**. A hybrid gateway enforces YAML policy with deterministic guardrails, a local-LLM semantic judge, a System One router, HITL for bank payments, information-flow control, an external attack-signature feed, durable budgets including compute time (SQLite/Redis), and live security reporting with performance telemetry.

```bash
cd aegis
python3 -m venv .venv && .venv/bin/pip install -e . pytest
ollama pull gemma3:4b   # LLM judge for semantic controls (optional for tests)
AEGIS_ROOT=$PWD .venv/bin/aegis serve --port 8080
# other terminal:
.venv/bin/pytest -v
open http://127.0.0.1:8080
```

| Doc | Purpose |
|---|---|
| [`aegis/README.md`](aegis/README.md) | Runbook, deliverables, integration |
| [`aegis/docs/architecture.md`](aegis/docs/architecture.md) | Architecture diagram |
| [`aegis/docs/policy-engine.md`](aegis/docs/policy-engine.md) | Centralized policy engine: compliance, diagrams, validation, budgets |
