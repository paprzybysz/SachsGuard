# Aegis architecture

Aegis is a Python **modular monolith**: one deployable process for the demo, with logical services that can be split out later (gateway replicas, Redis budgets, a shared policy mount).

Each diagram below answers one question:

| # | Diagram | Question it answers |
|---|---|---|
| 1 | [System overview](#1-system-overview) | What sits where? |
| 2 | [Request lifecycle](#2-request-lifecycle) | What happens to one chat request, step by step? |
| 3 | [Control pipeline](#3-control-pipeline) | In which order do controls run, and how is the decision made? |
| 4 | [Data controls (Presidio)](#4-data-controls-microsoft-presidio) | How are PII, secrets and bank identifiers found and masked? |
| 5 | [Semantic cascade](#5-semantic-cascade) | When is the LLM judge called, and what if it is down? |
| 6 | [Information flow](#6-information-flow-openappa-subset) | Why is a public post blocked after reading customer data? |
| 7 | [Budgets](#7-budgets) | What is limited and where is it stored? |
| 8 | [Observability](#8-observability) | Where do metrics, traces and audit logs go? |
| 9 | [MCP proxy](#9-mcp-proxy) | How does Aegis sit between an agent and its MCP servers? |

The policy file that drives all of these is documented separately in [policy-engine.md](policy-engine.md).

---

## 1. System overview

```mermaid
flowchart TB
  subgraph clients [Clients]
    App[Apps_Agents]
  end

  subgraph edge [Edge]
    GW[Gateway_Proxy]
    AuthN[Identity_Gate]
  end

  subgraph controlPlane [Control_Plane_in_process]
    PE[Policy_Engine]
    DET[Deterministic_Controls]
    DLP[DLP_Masking_Egress]
    TAZ[Tool_AuthZ]
    LOOP[Loop_Guard]
    SEM[Semantic_Regex_fast_path]
    JUDGE[LLM_Judge_gemma3_4b]
    S1[SystemOne_JEV_analog]
    HIST[Historical_Feed]
    APPA[OpenAPPA_InfoFlow]
    BUD[Budget_Governor]
    HITL[HITL_Queue]
  end

  subgraph dataPlane [Shared_State_extractable]
    Redis[(Redis_or_SQLite_budgets)]
    Audit[(Audit_JSONL)]
    PolicyFS[Policy_YAML]
    Prom[(Prometheus)]
    Graf[Grafana]
  end

  subgraph upstream [Upstream]
    LLM[LLM_or_Ollama]
    MCP[Bank_MCP_Tools]
    Intel[Threat_Intel_Feed_URL]
  end

  App --> GW
  GW --> AuthN
  AuthN --> PE
  PE --> DET
  PE --> TAZ
  PE --> SEM
  PE --> LOOP
  SEM -->|no_regex_hit| JUDGE
  PE --> S1
  S1 -->|hold| HITL
  HITL -->|approve| MCP
  PE --> HIST
  Intel -.->|feed_url_refresh| HIST
  PE --> APPA
  PE --> BUD
  BUD --> Redis
  PE --> Audit
  Audit --> Prom
  Prom --> Graf
  PE --> PolicyFS
  GW -->|allow| LLM
  LLM --> DLP
  GW -->|tool_call| TAZ
  TAZ -->|allow_redact| MCP
  MCP --> DLP
  DLP -->|masked| App
  GW -->|block| App
```

| Logical service | Responsibility | Module | Scale-out path |
|---|---|---|---|
| Gateway | OpenAI-compatible + MCP proxy; enforce allow/redact/block | `gateway.py` | N replicas behind LB |
| Identity gate | Bearer API tokens → role + tenant; never trust client-asserted identity | `identity.py` | later IdP / JWT |
| Policy engine | YAML load, mtime hot-reload, hybrid decide | `engine.py`, `policy/` | ConfigMap / policy service |
| Deterministic controls | AuthN/AuthZ gates, tool catalog | `controls/deterministic.py` | in-process |
| **DLP / masking** | Pattern-match PII, IBAN/account, PAN, secrets; **mask inbound and egress** | `controls/dlp.py` | dedicated egress step |
| **Tool AuthZ** | Role → function (e.g. only `teller`/`admin` may call `get_counterparty_balance`) | `controls/deterministic.py` | later OPA / policy service |
| **OpenAPPA IFC** | Per-session audience/trust label (caller + `X-Aegis-Session`); blocks public sinks after internal reads and classifies sink payloads | `controls/appa.py`, `information_flow` in `policies/policy.yaml` | later OpenAPPA sidecar |
| Semantic cascade | Regex fast path, then a local LLM judge (Ollama) with one cached call per request; `fail_mode` open/closed | `controls/semantic.py` | dedicated judge worker / GPU pool |
| **System One** | Typed allow/hold/block + calibrated probabilities (JEV analog). Heuristic logistic first; optional structured Ollama | `controls/system_one.py` | dedicated router |
| **HITL** | Pause `initiate_payment` (and strict counterparty reads) until admin approve/deny | `hitl.py`, dashboard | later workflow engine |
| **Loop guard** | Max tool hops / identical repeats per agent session | `controls/loop_guard.py` | shared session store |
| **Bank MCP** | In-process demo bank tools behind `/v1/mcp/invoke` (balances, CRM, payments) | `demo/bank.py` | real MCP host |
| Historical feed | `attack_signatures` in the policy file; optional external `feed_url` (last good copy kept) takes precedence while reachable; ReDoS-safe compiled patterns | `controls/historical.py` | threat-intel service |
| Budget governor | Token, cost, request and **compute-seconds** windows; one implementation over memory/SQLite/Redis | `controls/budget.py` | Redis (or SQLite) shared state |
| Audit + telemetry | Audit JSONL/CSV, per-control latency, p50/p95/p99, Prometheus histograms | `audit.py`, `observability.py`, `/` | Prometheus `/metrics` + Grafana |

---

## 2. Request lifecycle

One `POST /v1/chat/completions` that is allowed through to a real model:

```mermaid
sequenceDiagram
    autonumber
    participant C as Client / agent
    participant G as Gateway
    participant E as Policy engine
    participant P as Presidio
    participant J as LLM judge (Ollama)
    participant B as Budget store
    participant U as Upstream model
    participant A as Audit

    C->>G: chat request + Bearer token
    G->>G: resolve token → role, tenant
    G->>E: evaluate(prompt, model, tools, session)
    E->>E: oversized? → block before any NLP
    E->>P: detect + mask PII / secrets / bank IDs
    E->>E: AuthZ, tool catalog, information flow
    E->>J: only if no regex hit: classify prompt
    E->>B: atomic check + commit (tokens, cost, requests)
    E-->>G: decision + findings + per-control timings
    G->>A: record event
    alt decision = block
        G-->>C: 403 aegis_blocked + findings
    else allow / redact / degrade
        G->>U: redacted messages (Aegis token NOT forwarded)
        U-->>G: completion
        G->>B: charge model compute seconds
        G->>E: evaluate(output, direction=outbound)
        E->>P: egress DLP (mask leaked identifiers)
        G-->>C: completion + aegis envelope
    end
```

---

## 3. Control pipeline

Controls run in a fixed order. Each one is timed (`timings_ms`). The decision is computed from all findings at the end.

```mermaid
flowchart TD
    start(["inbound text"]) --> size{"tokens &gt;<br/>max_tokens_per_request?"}
    size -- "yes (on_exceed: block)" --> blk
    size -- no --> m["allowed_models"]

    subgraph det["Deterministic (non-AI)"]
        m --> pii["pii_detector · Presidio"]
        pii --> sec["secrets_detector · Presidio"]
        sec --> dlp["dlp_masking · Presidio"]
        dlp --> az["authz_gate"]
        az --> tl["tool_allowlist"]
        tl --> ta["tool_authz"]
        ta --> flow["information_flow"]
    end

    subgraph sem["Semantic (AI)"]
        flow --> pi["prompt_injection"]
        pi --> jb["jailbreak_detector"]
    end

    jb --> hist["historical_exploits"]
    hist --> loop["loop_guard"]
    loop --> s1["system_one"]
    s1 --> bud["budget window check<br/>(commit skipped on block / hold)"]
    bud --> decide{"decide()"}

    decide -- "any finding with action block" --> blk(["BLOCK · 403"])
    decide -- "any hold" --> hold(["HOLD · 202, HITL queue,<br/>no side effects"])
    decide -- "any degrade" --> deg(["DEGRADE · first allowed model,<br/>still redacted"])
    decide -- "text changed / redact" --> red(["REDACT · masked text forwarded"])
    decide -- "nothing" --> ok(["ALLOW"])
```

Decision precedence: **block > hold > degrade > redact > allow**. Redaction still applies when the decision is `degrade`.

Step by step:

1. Authenticate (`Authorization: Bearer <token>` → role + tenant).
2. Load policy (mtime hot-reload from centralized YAML). See [policy-engine.md](policy-engine.md).
3. **Tool AuthZ** on every tool name in the payload (not only the first).
4. Hybrid inbound controls: deterministic + DLP + information flow + semantic (regex, then LLM judge) + historical + **loop guard** + **System One** + budget. Each control is timed.
5. Emit `allow | redact | block | degrade | hold`. **HOLD does not execute MCP.** Redact still applies when the overall decision is degrade.
6. Forward to upstream / bank tools only when not blocked or held, using `AEGIS_UPSTREAM_API_KEY`; the caller's token is never forwarded. Upstream wall-clock time is charged to the compute budget.
7. **Egress DLP** on model/tool output (string leaves) before return; tool results also taint OpenAPPA. Append audit (decision, findings, `latency_ms`, `timings_ms`, System One, HITL id).

---

## 4. Data controls (Microsoft Presidio)

```mermaid
flowchart LR
    text["text"] --> an

    subgraph presidio["Presidio AnalyzerEngine (shared, warmed at startup)"]
        an["analyze(entities = policy patterns + context)"]
        builtin["Built-in recognizers<br/>email · phone · card (Luhn)<br/>IBAN (checksum) · SSN · IP"]
        ner["spaCy NER<br/>person · location (opt-in)"]
        custom["Custom recognizers<br/>PESEL + NRB (checksums)<br/>AWS · OpenAI · GitHub · PEM · Bearer"]
        an --- builtin
        an --- ner
        an --- custom
    end

    an --> thr["score ≥ threshold<br/>(by strictness)"]
    thr --> frag["drop fragments inside<br/>longer numbers"]
    frag --> sel["keep only categories<br/>selected in policy"]
    sel --> anon["Presidio AnonymizerEngine<br/>replace → [REDACTED_IBAN] …"]
    anon --> out["masked text + findings"]
```

| Where it runs | Purpose |
|---|---|
| `pii_detector` | Personal data in prompts |
| `secrets_detector` | Credentials in prompts (always high severity) |
| `dlp_masking` inbound | Customer and payment identifiers going **to** a model |
| `dlp_masking` outbound | The same identifiers leaking **from** a model or tool (egress) |
| `information_flow` | Classifies sink payloads as customer data |

Policy `patterns` choose the categories: `email`, `phone`, `ssn`, `credit_card`, `iban`, `pesel`, `account`, `person`, `location`, `ip_address` and the secret types. The score threshold follows `strictness`: high 0.30, medium 0.35, low 0.50.

---

## 5. Semantic cascade

```mermaid
flowchart TD
    t["prompt text"] --> rx{"regex heuristics<br/>(microseconds)"}
    rx -- hit --> f1["finding<br/>(LLM not called)"]
    rx -- "no hit, backend: heuristic" --> pass["no semantic finding"]
    rx -- "no hit, backend: ollama" --> cache{"verdict cached<br/>for this text?"}
    cache -- yes --> v
    cache -- no --> llm["LLM judge · gemma3:4b<br/>user text JSON-encoded<br/>inside &lt;untrusted_input&gt;"]
    llm -- "JSON verdict" --> v{"label unsafe and<br/>risk ≥ adherence?"}
    llm -- "down / timeout / bad JSON" --> fm{"fail_mode"}
    v -- yes --> f2["finding: llm-injection / llm-jailbreak"]
    v -- no --> pass
    fm -- open --> logf["allow + log semantic_unavailable"]
    fm -- closed --> blockf["block"]
```

At most one model call is made per unique text. Both semantic controls share the cached verdict.

---

## 6. Information flow (OpenAPPA subset)

Each agent session (caller token + optional `X-Aegis-Session`) carries a label. Labels only ever get more restrictive.

```mermaid
stateDiagram-v2
    [*] --> Open: new session
    Open: audience = public + internal
    Internal: audience = internal only

    Open --> Open: plain chat (never taints)
    Open --> Open: public sink, payload has no customer data
    Open --> Internal: source tool read (CRM, balances, customer-records file)
    Open --> Blocked1: public sink, payload contains IBAN / PESEL / NRB
    Internal --> Internal: internal sink (send_email)
    Internal --> Blocked2: public sink (file_github_issue)

    Blocked1: 403 payload_audience_denied
    Blocked2: 403 audience_denied
    Blocked1 --> Open
    Blocked2 --> Internal
```

Tool contracts (sources, sinks, required audience) live in the `information_flow` section of `policies/policy.yaml`.

---

## 7. Budgets

```mermaid
flowchart LR
    req["request"] --> est["estimate tokens + cost"]
    est --> pre{"per-request<br/>token cap"}
    pre -- over --> act
    pre -- ok --> win{"window caps<br/>tokens · cost · requests · compute s"}
    win -- over --> act{"on_exceed"}
    win -- ok --> commit["atomic commit"]
    act -- block --> b403["403"]
    act -- degrade --> cheap["first allowed model"]
    up["upstream call"] -->|"measured wall-clock"| compute["record_compute"]

    commit --> store[("memory · SQLite · Redis")]
    compute --> store
```

All three storage backends share one window/check/commit implementation and differ only in storage. Compute seconds measure the real cost of local models; tokens and USD cover external APIs.

---

## 8. Observability

```mermaid
flowchart LR
    eng["engine.evaluate"] --> ev["audit event<br/>decision · findings<br/>latency_ms · timings_ms"]
    ev --> jsonl[("audit.jsonl")]
    jsonl --> export["/v1/audit/export<br/>JSONL · CSV (admin)"]
    ev --> mem["in-process metrics<br/>p50/p95/p99 histograms"]
    mem --> api["/v1/metrics → dashboard"]
    mem --> prom["/metrics<br/>Prometheus text"]
    prom --> P[("Prometheus")]
    eng --> otel["OpenTelemetry span<br/>aegis.evaluate + counters"]
    otel --> col["OTEL collector"]
    col --> P
    P --> G["Grafana dashboard"]
```

| Audience | Signal |
|---|---|
| Management | Dashboard posture, block rate, cost and compute; Grafana |
| Security team | Audit JSONL/CSV export with findings per event; traces with per-control timings |
| Performance review | `aegis_eval_latency_seconds`, `aegis_control_latency_seconds{control}`, `aegis_upstream_latency_seconds` |

---

## 9. MCP proxy

Aegis speaks MCP on both sides: agents connect to `/mcp` (Streamable HTTP, JWT bearer), or through `aegis mcp-bridge` (stdio), and Aegis connects to the real servers listed in `mcp.upstreams` of `policies/policy.yaml`.

```mermaid
sequenceDiagram
    autonumber
    participant A as Agent
    participant B as aegis mcp-bridge (stdio agents only)
    participant G as Aegis /mcp
    participant E as Policy engine
    participant H as HITL queue
    participant U as Upstream MCP server

    A->>B: tools/call (stdio)
    B->>G: tools/call + Bearer JWT + X-Aegis-Session
    G->>E: guard: allowlist, role AuthZ, DLP, semantic, exploits, info flow, loop guard, System One, budget
    alt block
        G-->>A: isError, aegis_blocked + findings (upstream never called)
    else hold
        G->>H: enqueue (origin mcp:<upstream>)
        G-->>A: isError, decision hold + hitl_id
        Note over H,U: admin approves → Aegis calls the upstream, result stored, agent polls aegis_hitl_status
    else allow / redact
        G->>U: tools/call (redacted args, _meta io.aegis/principal)
        U-->>G: result
        G->>E: information flow taint/check + egress DLP
        G-->>A: masked result (or aegis_output_blocked)
    end
```

| Piece | Module |
|---|---|
| Agent-facing MCP server, `/mcp` endpoint, JWT check | `mcp_proxy.py` (`McpProxy`) |
| Upstream connections (one long-lived client per server, lazy, reconnect on policy change) | `mcp_upstreams.py` (`UpstreamPool`) |
| Shared guard / output screening (also used by `/v1/mcp/invoke`) | `gateway.py` (`_guard_tool_call`, `_screen_tool_output`) |
| stdio bridge | `mcp_bridge.py` |
| Demo bank as a real MCP server | `demo/bank_mcp_server.py` |

---

## Deployment & profiles

- **Demo:** `aegis serve` or `docker compose up --build`. Observability stack: `docker compose --profile obs up --build`, then Grafana at http://localhost:3000.
- **Shared budgets:** `AEGIS_BUDGET_BACKEND=sqlite` (default) or `redis`.
- **Profiles:** all three live in `policies/policy.yaml`; pick one with `active_profile`, `AEGIS_PROFILE` or `aegis serve --profile`, and per tenant with `tenant_profiles`.

| Profile | Semantic layer | Intent |
|---|---|---|
| `permissive` | regex only | Prefer log/redact, high budgets, degrade on exhaustion |
| `balanced` | regex + LLM judge, fail-open | Default demo |
| `strict` | regex + LLM judge, fail-closed | Block first, small budgets |
