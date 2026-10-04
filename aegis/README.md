# Aegis — AI Control Layer

Hybrid control layer (gateway + policy engine) that secures **app → agent → MCP → model** traffic with deterministic guardrails, a local-LLM semantic judge, a System One router (JEV analog), HITL for payments, information-flow control, historical exploit signatures and budget governance, plus a live security dashboard, Prometheus/Grafana telemetry and an executable self-test suite.

Built for the HackYeah **AI Control Layer** challenge.



`make sync test serve` does the same and uses `uv` when it is installed.

### Docker (gateway + observability)

```bash
cd aegis
# optional but recommended for the semantic LLM judge — run on the host, not in Compose:
ollama serve                                          # if not already running as a service
ollama pull gemma3:270m                               # model named in policies/policy.yaml

OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318 docker compose --profile obs up --build
```



| Service | URL | Notes |
|---|---|---|
| Aegis dashboard | http://localhost:8080/ | API + live security UI · auth `Bearer demo` / JWT |
| HITL console | http://localhost:8080/hitl | payment approve/deny |
| Grafana | http://localhost:3000/ | dashboards · `admin` / `admin` (anonymous Viewer also on) |
| Prometheus | http://localhost:9090/ | scrapes the OTEL collector |
| OTEL collector | http://127.0.0.1:4318 | OTLP/HTTP (localhost only) |
| Host Ollama | http://127.0.0.1:11434 | semantic judge; start separately |


**Hot reload:** edit `policies/policy.yaml` (the only config file), then send another request. No restart is needed. An invalid edit is rejected and the previous version stays active (`/health` shows the error).

**Without Ollama:** the stack still runs. The test suite stays green because the LLM judge is stubbed, and the one live-model test is skipped. The `balanced` profile fails open: it allows the request and logs `semantic_unavailable`. The `strict` profile fails closed and blocks.

## Deliverables map

| Expected outcome | Where |
|---|---|
| AI Control Layer | `src/aegis/gateway.py`: `/v1/chat/completions` (OpenAI-compatible proxy), `/mcp` (MCP proxy between agents and MCP servers, `src/aegis/mcp_proxy.py`), `/v1/mcp/invoke`, `/v1/evaluate`; `src/aegis/sdk.py` |
| Demo agent | `aegis demo-agent` (`src/aegis/demo/agent.py`) |
| Architecture diagram | [docs/architecture.md](docs/architecture.md) |
| Sample configuration | `policies/policy.yaml`: one file with the `permissive` / `balanced` / `strict` profiles, information-flow contracts and attack signatures |
| Interactive dashboard | http://localhost:8080/ · HITL console http://localhost:8080/hitl · Grafana (`docker compose --profile obs up`) |
| Executable test suite | `tests/`: control pos/neg, HTTP gateway, hardening, System One, HITL, bank MCP, loop guard, agent scenarios |

## Formal requirements

1. **Centralized policy engine.** One YAML file, `policies/policy.yaml`, holds every profile plus information-flow contracts and attack signatures: controls, adherence %, Block/Redact/Log/Degrade, allowlisted models, budgets (tokens, USD with per-model prices, requests, compute seconds; per tenant, role or token), privileged roles, per-tenant overrides and reporting. Strict validation rejects unknown controls and misplaced fields. It is hot-reloaded by mtime; an invalid edit keeps the last good policy active, and every audit event carries the policy's SHA-256. Details: [docs/policy-engine.md](docs/policy-engine.md).
2. **Deterministic controls.** PII, secrets and DLP masking (inbound and egress) run on **Microsoft Presidio**: validated recognizers, spaCy NER (`en_core_web_sm`), and custom PESEL, NRB and credential recognizers. Also token-bound AuthN, method AuthZ, a tool catalog and role-to-tool AuthZ.
3. **Semantic controls (AI-based).** Regex fast path, then a local LLM judge (`gemma3:4b` via Ollama). Rephrased, multilingual and obfuscated injections and jailbreaks reach the judge. Each request makes at most one cached model call. User text is passed to the judge JSON-encoded as data. `fail_mode: open|closed` is set per profile.
4. **System One + HITL.** A typed router (not a chat LLM) returns `{verdict, p_unsafe, p_hitl, labels}` and pauses `initiate_payment` for admin approve/deny (`/v1/hitl/*`).
5. **Information flow (OpenAPPA subset).** Each agent session carries an audience/trust label. Reading internal data blocks public sinks, and sink payloads are classified too. Tool *outputs* also taint the session. Contracts: `information_flow` in `policies/policy.yaml`.
6. **Budget governance.** Per-request and sliding-window caps on tokens, cost, requests and **model compute seconds**. Compute seconds are measured wall-clock time of local or remote models. `on_exceed: block|degrade`. Backends: SQLite (default), Redis or memory.
7. **Loop guard.** Caps tool hops and identical repeats per `X-Aegis-Session` so agents cannot run away.
8. **Historical attack mitigation.** Signatures in `attack_signatures` of `policies/policy.yaml`, optionally overridden by an external feed (`feed_url`, HTTP(S)) while it is reachable, covering code execution, unsafe deserialization, model-repo supply chain and prompt leakage. Patterns are compiled once. ReDoS-prone and invalid patterns are rejected and reported.
9. **Security reporting.** Dashboard with posture, HITL queue, metrics, latency and compute; JSONL/CSV audit export (`/v1/audit/export`); Prometheus `/metrics` with latency histograms; a Grafana dashboard.
10. **Self-testing suite.** Positive and negative cases for every control family, including budgets, exploits, fail-open and fail-closed, information flow, HITL, bank MCP and telemetry.

## Integration

Point any OpenAI-compatible client at Aegis:

```python
from openai import OpenAI
client = OpenAI(base_url="http://127.0.0.1:8080/v1", api_key="demo")
client.chat.completions.create(
    model="demo-echo",
    messages=[{"role": "user", "content": "Hello"}],
)
```

Auth: `Authorization: Bearer <jwt>` (required). JWTs are verified with HS256. Configure:

| Setting | Meaning |
|---|---|---|
| `AEGIS_JWT_SECRET` | Shared HS256 verification secret |
| `AEGIS_JWT_ISSUER` | Required `iss` claim (default `aegis`) |
| `AEGIS_JWT_AUDIENCE` | Required `aud` claim (default `aegis-api`) |

JWTs must contain `sub`, `role`, `tenant`, `iss`, `aud`, `iat`, and `exp` claims. The local dashboard and demo agent issue short-lived demo JWTs using the configured secret. Client-asserted `role`, `authenticated` and `X-Aegis-Tenant` are ignored.

For local development, Docker Compose uses a development-only fallback secret, so no manual secret setup is needed. Set a random secret of at least 32 bytes in any shared or production deployment.

To create a development JWT using the same configured secret:

```bash
.venv/bin/aegis token --subject local-user --role developer
```

Then use the printed value:

```bash
curl http://127.0.0.1:8080/v1/metrics \
  -H "Authorization: Bearer <printed-jwt>"
```

| Setting | Meaning |
|---|---|
| `AEGIS_UPSTREAM_URL` + `AEGIS_DEMO_ECHO=0` | Proxy to a real model after allow/redact. Example: `http://127.0.0.1:11434` for Ollama's OpenAI API. |
| `AEGIS_UPSTREAM_API_KEY` | Credential sent upstream. The caller's Aegis token is **never** forwarded. |
| `AEGIS_OLLAMA_URL` | LLM judge endpoint (default `http://127.0.0.1:11434`) |
| `AEGIS_BUDGET_BACKEND` | `sqlite` (default) · `memory` · `redis` (`AEGIS_REDIS_URL`) |
| `X-Aegis-Session` header | Optional agent-run id. Information-flow state is kept per caller and per session. |

Observability ports and the Compose command are listed under [Docker (gateway + observability)](#docker-gateway--observability) above.

Local `aegis serve` does not need a collector. If `OTEL_EXPORTER_OTLP_ENDPOINT` points at `otel-collector` and that host is not running, export is skipped (no retry spam). Unset the variable or restart the process after this change.

## MCP proxy: Aegis between an agent and MCP servers

Aegis is itself an MCP server. Point the agent at Aegis instead of at its MCP servers; Aegis forwards each allowed call to the real server and screens the result.

```
agent ──MCP──▶ Aegis /mcp ──MCP──▶ real MCP servers (policies/policy.yaml → mcp.upstreams)
                 │
                 ├─ tools/list : only the tools the caller's role may call
                 ├─ tools/call : every control of the caller's profile, before the call
                 │               (allowlist, role AuthZ, DLP, injection/jailbreak, exploits,
                 │                information flow, loop guard, System One / HITL, budgets)
                 └─ result     : information flow + egress DLP before the agent sees it
```

**1. Declare the upstream servers** in `policies/policy.yaml` (hot-reloaded; changed upstreams reconnect on the next request):

```yaml
mcp:
  upstreams:
    - name: bank                       # the demo bank, launched as a subprocess
      transport: stdio
      command: python                  # "python" = the interpreter running Aegis
      args: ["-m", "aegis.demo.bank_mcp_server"]
    - name: remote-tools               # any Streamable HTTP MCP server
      transport: streamable_http
      url: https://tools.example.internal/mcp
```

**2. Connect the agent.** Identity is a JWT (`aegis demo-token demo-teller` prints a demo one).

**Quickest demo: Claude.** Start the gateway, register Aegis in Claude Code with one `claude mcp add` command and open a new chat. Step-by-step guide and demo prompts: [docs/claude-demo.md](docs/claude-demo.md). Step-by-step test procedure (PL): [docs/testowanie-mcp.md](docs/testowanie-mcp.md). Example prompts for Claude, MCP + hooks (PL): [docs/przyklady-claude.md](docs/przyklady-claude.md).

Agents that speak Streamable HTTP (e.g. Claude Code):

```bash
claude mcp add --transport http aegis http://127.0.0.1:8080/mcp \
  --header "Authorization: Bearer $(.venv/bin/aegis demo-token demo-teller)"
```

Agents that only launch stdio servers (e.g. Claude Desktop `claude_desktop_config.json`) use the bridge, which forwards to the gateway and holds no policy itself:

```json
{
  "mcpServers": {
    "aegis": {
      "command": "/path/to/aegis/.venv/bin/aegis",
      "args": ["mcp-bridge", "--url", "http://127.0.0.1:8080/mcp", "--session", "desktop"],
      "env": { "AEGIS_TOKEN": "<jwt from: aegis demo-token demo-teller>" }
    }
  }
}
```

Python (MCP SDK):

```python
import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {jwt}", "X-Aegis-Session": "run-1"})
async with http, Client(streamable_http_client("http://127.0.0.1:8080/mcp", http_client=http)) as aegis:
    print(await aegis.call_tool("get_account_balance", {}))
```

**What the agent sees**

| Situation | Result |
|---|---|
| Allowed | The upstream result, with IBAN / PESEL / card numbers / secrets masked |
| Blocked by policy | `isError: true` with `{"error": "aegis_blocked", "findings": [...]}`; the upstream is never called |
| Held for a human (e.g. `initiate_payment`) | `isError: true` with `{"decision": "hold", "hitl_id": ...}`; an admin approves in the dashboard or via `POST /v1/hitl/{id}/approve`, and the agent polls the built-in `aegis_hitl_status` tool |
| Result may not leave (information flow) | `isError: true` with `aegis_output_blocked` |

`X-Aegis-Session` (header, or `--session` on the bridge) scopes the information-flow label to one agent run. The caller's role and tenant are forwarded to upstreams in the request `_meta` (`io.aegis/principal`); set `forward_identity: false` on an upstream to turn that off. Upstream status is on `/health` under `mcp`.

## Profiles (strictness)

| Profile | Semantic layer | Behaviour |
|---|---|---|
| `permissive` | regex only | Prefer log/redact; large budgets; `degrade` on budget exhaustion |
| `balanced` | regex + LLM judge, fail-open | Default demo |
| `strict` | regex + LLM judge, fail-closed | Block first; small token, cost and compute budgets; narrow model allowlist |

```bash
AEGIS_PROFILE=strict .venv/bin/aegis serve   # or: aegis serve --profile strict · make serve PROFILE=strict
```


