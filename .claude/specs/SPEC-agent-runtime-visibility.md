# SPEC: Agent runtime visibility — discover, observe, control

> **Status: proposed, for review** (Ritam, 2026-11-05). Reviewers: Aditya Agarwal
> and his agents. Nothing here is built. Every "today" statement cites the tree at
> `910c491` (origin/authsec-staging) or the collector worktree
> `agent-resilience` (iga-agent 0.4.2); recheck before implementing.
>
> Product context: [SPEC-agentic-access-management.md](SPEC-agentic-access-management.md).
> Policy context: [SPEC-iga-phase3-policy-requirements.md](SPEC-iga-phase3-policy-requirements.md),
> [SPEC-access-policies.md](SPEC-access-policies.md).

## Summary

Agentic IGA today discovers agents and their declared access, and changes that
access in the cloud. It does not see agents as they appear, does not show what
an agent is doing, and has no single action to stop one. This spec adds, for AWS,
Azure and Kubernetes:

1. **one inventory of every AI agent**, platform-declared or inferred, kept
   current within minutes (seconds where the customer enables event streams);
2. **an activity timeline per agent**: model calls, tool calls, cloud actions,
   resources touched, the human it acted for, and what was refused;
3. **the access graph joined to that activity**: what it can reach next to what
   it reached;
4. **control**: a verified kill switch per agent, and per-tool-call allow/deny for
   agents behind a policy enforcement point.

**Inference is the primary discovery mechanism.** Most shadow agents are a
Lambda, a container or a pod in the customer's own estate calling OpenAI,
Anthropic or Gemini directly with an API key: no platform declares them and no
Bedrock or Azure OpenAI log names them. They are recognised from what the
workload carries (key names, images, dependencies), where it connects (model
provider endpoints) and what the provider bills (usage per key), whichever
model provider they use (§5.2).

The promise we can keep, and the one the console states: **every AI agent
running on connected compute (AWS, Azure, Kubernetes), whichever model provider
it calls**. Not agents on laptops or inside SaaS products (§2, out of scope).

## 1. Requirements

| # | Requirement | NIST anchor |
|---|---|---|
| R1 | Inventory every agent per workspace: platform-declared (Bedrock, AgentCore, Foundry, Entra Agent ID, Copilot registry, Teams, Logic Apps, Kubernetes workloads labelled or detected) and **inferred**, the primary path: any workload on connected compute that calls a model of **any** provider (Bedrock, Azure OpenAI, OpenAI, Anthropic, Google, self-hosted), carries a model credential, or behaves like an agent | Design tenet 1; Key Practices "asset inventory" |
| R2 | Flag risky agent credentials: a human's credentials, long-lived keys, model API keys held in secrets (names only) | NCCoE comments summary; IR 8587 |
| R3 | Show the access graph of each agent and the delegation chain (human → agent → sub-agent) where the source states it | Tenet 2 |
| R4 | Show each agent's activity: model calls, tool calls, cloud actions, resources read/written/deleted, on whose behalf, including refused actions | Tenets 9, 10; Key Practices 3.2, 5.1, 5.3 |
| R5 | Near real time: an agent appears and its actions land within minutes by polling, within seconds with event streams | Tenet 9 |
| R6 | Least privilege and time-bound access (built: R1a, R1b, R2, access policies) | Tenets 3, 4 |
| R7 | Kill switch: contain one agent everywhere it has authority, revoke its sessions, verify by re-reading the source, release restores exactly | Key Practices 1.7, 6.2, 6.4; tenet 4 |
| R8 | Per-tool-call allow/deny, decided outside the agent, deterministically | Tenets 7, 8 |
| R9 | Tamper-evident evidence of every decision: who, what, delegation chain, outcome, refusals | Tenet 10 |

NIST references: [Design Tenets for Agent Identity Management Systems](https://www.nist.gov/blogs/cybersecurity-insights/design-tenets-agent-identity-management-systems)
(2026-10-27); [NCCoE summary of comments](https://pages.nist.gov/nccoe-ai-identity/summary-of-comments.html)
(2026-09); [Key Practices for Incident Readiness and Response](https://www.nist.gov/news-events/news/2026/10/key-practices-incident-readiness-and-response-super-intelligence-training)
(CAISSI/NSA/CISA, 2026-10-16); [IR 8587](https://www.nist.gov/news-events/news/2026/09/nist-finalizes-guidelines-protecting-online-identity-and-access-tokens).
NIST now says "Super Intelligence (SI)" for AI (EO 14434, 2026-09-29).

**Decision (Ritam, 2026-11-05): no human-approval step.** R3's `hold` decision
and CIBA are out of scope; R8 is allow/deny only.

## 2. Scope

**In scope:** AWS, Azure, Kubernetes (EKS, AKS, any cluster running
`authsec-iga-agent`), and every agent running on that compute whatever model
provider it calls — including OpenAI, Anthropic and Google called directly
with an API key (§5.2), found from configuration, network and provider-usage
signals. Phases P1–P5 (§6).

**Out of scope (deferred):**
- Agents on laptops (Claude Code, Cursor, desktop MCP clients): needs an
  endpoint integration.
- SaaS agents (Agentforce, ServiceNow) and GCP agents (Agent Engine, Agent
  Registry).
- Human approval (holds, CIBA), signed mandates (NIST tenet 6).
- Effective-access evaluation (conditions, SCPs, boundaries, group inheritance)
  — the graph keeps saying `effective_access_not_evaluated`.
- Prompt and response content. We record that a model was called, by whom, with
  which model and outcome; never the text (the LLM gateway, §5.7, included).

## 3. Today, by cloud

| | AWS | Azure | Kubernetes |
|---|---|---|---|
| Declared agents | Bedrock agents, AgentCore runtimes and gateways → `cloud_workload` (`internal/awsdiscovery/bedrock.go:123,209,302`; `services/cloud_aws_workload_scan.go:457-483`), graph `iga_workload` with `classification='provider_native_agent'` (`internal/igagraph/project.go:553-558`). **Not in `discovered_agents`.** AgentCore workload identities and credential providers are `cloud_observation` evidence only | Entra Agent ID objects, Foundry agents, Copilot registry, Teams bots, Logic Apps (`services/azure_agent_discovery.go`, `azure_agent_sources.go`, `azure_agent_registry.go`) | Admission webhook reports agent-shaped containers (framework tokens, env var **names**, MCP and model endpoints, `authsec.ai/agent` label) as sightings (iga-agent `internal/detect/vocabulary.go:115-223`) |
| Inferred (unregistered) | **None.** CloudTrail `InvokeModel`/`Converse` are read only as generic events. The raw signals partly exist and nothing infers from them: Lambda env var **names** are collected (`internal/awsdiscovery/workloads.go:207`, `EnvVarNames`, never values); Secrets Manager names are read (`resource_policies.go:1402`) | `inferAgents` (`services/azure_agent_inference.go:74`): service principals and managed identities with AI-service sign-ins and machine cadence → `discovered_agents` `evidence_mode=inferred`, rule `azure_agent_v1` | Every sighting lands `status='unregistered'` (`services/discovery_service.go:902`) |
| Activity | CloudTrail `LookupEvents`, 48 h window, ≤10,000 events per region per scan, all management events, no filter (`internal/awsdiscovery/cloudtrail_events.go:77,84-87`); attributed by session issuer (`:228-246`); stored as `cloud_observation` (`cloud_aws_workload_scan.go:752-781`); unmatched events counted, not stored. Access Advisor → `cloud_usage` | Activity Log 7 d (`azure_activity_discovery.go:52`) and Entra sign-ins 7 d (`azure_access_discovery.go:207`) → `cloud_usage` aggregates | **None.** No audit logs (`SPEC-iga-phase3-policy.md:72`). Admission actor on sightings; lifecycle events in `discovered_agent_events` |
| Freshness | Scheduled scan daily or weekly (`cloud_aws_scan_schedule.go:62`), or "Scan now" | `AZURE_DISCOVERY_INTERVAL`, default 12 h (`azure_scheduler.go:31-58`) | Admission push on CREATE/DELETE (real time); resync and RBAC sweep off by default, 6 h when on |
| Access graph | Built | Built (D-114) | Built (RBAC sweep) |
| Control | Access policies (137+), R1a/R1b, R2 session revocation (`internal/igagov/r2.go:79-99`), R3 runtime decisions for AgentCore (062) | Access policies via role assignments (144); no disable of a service principal | Access policies via binding-subject removal (146); legacy quarantine NetworkPolicy (Isolate disposition, `PLAN-existing-policy-code-disposition.md:83`) |

Two inventories exist side by side: `discovered_agents` (sightings: K8s,
Azure inferred, generic ingress; unique `(workspace_id, source, fingerprint)`,
`002:116`) and `iga_workload` classification in the graph. AWS declared agents
reach only the second. P1 resolves this (§5.1).

## 4. Affected repos

| Repo | What changes | Why / why not |
|---|---|---|
| `authsec` | Collectors (AWS Bedrock events, AWS sightings, Azure Key Vault metadata), event-stream ingress, activity store and API, OTLP receiver, kill switch service, PEP decision API; migrations 147+ | All server work |
| `Authsec-ui` | Agents list (declared/inferred/confidence), agent detail with Activity timeline and Access tabs, Contain/Release, event-stream setup wizard | Console is how customers use it |
| `iga-agent` | Azure workload identity annotation, informer watches instead of 6 h list, Kubernetes audit forwarding, kill-switch instruction kinds, sighting sequence numbers, node sensor (eBPF) promoted from `origin/experimental` as an opt-in component | Kubernetes signals come only from the in-cluster agent |
| `sdk-authsec` | none | No SDK caller creates inventory or activity; the PEP (P5) is a gateway, not an SDK |
| `authsec-doc` | Setup pages: event streams (AWS, Azure), CloudTrail data events, tracing (AgentCore, Foundry), iga-agent upgrade | Customers must enable sources |
| Production K3s | OTLP and event ingress hostnames/paths, ingress body limits, retention job | New public ingress |

## 5. Design

### 5.1 One agent inventory

`discovered_agents` becomes the single inventory of agents; the graph's
`iga_workload.classification` stays the graph's view and is kept consistent.

Terms (the schema already distinguishes them; the console must too):
- **declared** — a platform says it is an agent (Bedrock, AgentCore, Foundry,
  Entra Agent ID, registry, `authsec.ai/agent` label): `evidence_mode=declared`.
- **inferred** — AuthSec's rule says it behaves like one: `evidence_mode=inferred`,
  with `metadata.inference_rule`, `confidence`, `signals`.
- **observed** — seen running (admission, resync): `evidence_mode=observed`.
- AuthSec **status** (`unregistered | registered | quarantined | ignored`) is
  the customer's decision about it, independent of the above. "Registered"
  means claimed in AuthSec (client + owner, `registered_chk`), not "declared
  on a platform". The console must not use "registered" for both.

AWS declared agents get sightings: `source='aws'`, fingerprints
`aws:<account>:bedrock_agent:<agentId>` and
`aws:<account>:agentcore_runtime:<runtimeId>`, `evidence_mode=declared`,
written by the workload scan next to `recordWorkload`. `UpsertSighting`
already never touches status, owner or claim fields
(`repository/discovery_repository.go:747-808`).

**Question for review (Q1):** is `discovered_agents` the right single
inventory, or should `iga_agents` / `iga_agent_instances` (004) become it? Today
only the GitHub pipeline writes `iga_agents`; every cloud projector writes none.

### 5.2 Inferred agents — the primary path (P1, P2, P4)

An agent is inferred from the **workload** (the compute) and the **identity**
it runs as, from signals in three families. No single signal decides; the
rule scores them and records every signal it used.

#### 5.2.1 Signals for agents calling any model provider

| Family | Signal | AWS | Azure | Kubernetes | Customer setup | Today |
|---|---|---|---|---|---|---|
| Configuration | env var **names** of model keys and agent frameworks (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`/`GEMINI_API_KEY`, `AZURE_OPENAI_*`, `LANGCHAIN_*`, `LANGSMITH_*`, `MCP_*`, …) | Lambda (collected, `workloads.go:207`), ECS task definitions (new), EC2 launch-template user data **not read** | Function App / App Service / Container Apps app-setting **names** (new; ARM `listApplicationSettings` returns values — keep names, discard values in memory, never log) | collected (`env_marker_keys`) | none | Lambda ✅, K8s ✅, ECS ❌, Azure ❌ |
| Configuration | container image or package of an agent framework or model SDK (langchain, langgraph, crewai, autogen, openai, anthropic, MCP servers) | ECS image names (new), Lambda layers names (new) | Container Apps image (new) | collected (vocabulary) | none | K8s ✅ |
| Configuration | secret **names** that look like model keys (`openai`, `anthropic`, `gemini`, `llm`, `*-api-key`) and which workload reads them | Secrets Manager names (read), which role may `GetSecretValue` (resource policies, graph) | Key Vault secret names (new, §5.3) | `secret_refs` names (collected) | none | partly |
| Configuration | code dependencies (`openai`, `anthropic`, `google-genai`, `langchain`, MCP SDKs) in the repo that deploys the workload | linked through image or function source → GitHub repo (new link) | same | same | GitHub connected | scanner exists; repo↔workload link ❌ |
| Network | DNS lookups / connections to model endpoints (`api.openai.com`, `*.openai.azure.com`, `api.anthropic.com`, `generativelanguage.googleapis.com`, `*.aiplatform.googleapis.com`, `api.mistral.ai`, `api.cohere.com`, `api.groq.com`, `openrouter.ai`, …) mapped to the source ENI / IP → workload | Route 53 Resolver query logs (source VPC, ENI); Network Firewall TLS SNI logs | Azure DNS / Firewall logs (Log Analytics) | node sensor (eBPF, process → destination); on iga-agent `origin/experimental` (`cmd/iga-node-sensor`) | DNS query logging, or sensor install | ❌ |
| Provider usage | usage per API key / project: calls, tokens, models, last use | OpenAI Admin + Usage API, Anthropic Admin + usage report (1-minute buckets, ~5 min lag) | same | same | connect the provider org (admin key, stored per workspace in Vault) | ❌ |
| Cloud model calls | Bedrock `InvokeModel`/`Converse`, Azure OpenAI sign-ins | §5.2.2 | `azure_agent_v1` (built) | via IRSA / workload identity | none | Azure ✅, AWS ❌ |

**Scoring** (rule `workload_agent_v1`; thresholds are review items):
- **high** — a network or provider-usage signal (it *calls* a model) together
  with a configuration signal on the same workload, or a cloud model call by the
  workload's identity;
- **medium** — a network or provider-usage signal alone, or two configuration
  signals of different kinds (key name + framework image);
- **low** — one configuration signal (a key name alone); listed, not alerted.

**Mapping a signal to a workload.** DNS and flow logs name an ENI or IP: map
ENI → Lambda/ECS task/EC2 instance (AWS `DescribeNetworkInterfaces`
attachment), pod IP → pod (iga-agent), Azure NIC/IP → App Service/Container
App/VM. A signal that maps to no known workload is kept as "model traffic from
an unknown source" on the VPC/subnet, itself a finding.

**Provider usage without a workload.** We never see key values, so a provider
key is tied to a workload only by name agreement (secret or env name ↔ key
name / project name) and is marked `weak`. Usage on keys that match nothing is
reported as **unaccounted model usage** per provider project: the shadow-agent
alarm when no workload signal exists.

#### 5.2.2 Cloud model calls on AWS

Rule `aws_agent_v1`, evaluated per IAM role (and IAM user) per scan:

| Signal | Source | Weight |
|---|---|---|
| Calls `bedrock:InvokeModel`, `InvokeModelWithResponseStream`, `Converse`, `ConverseStream` | CloudTrail management events (on by default) | strong |
| Calls `InvokeAgent`, `InvokeInlineAgent`, `Retrieve*`, AgentCore `InvokeAgentRuntime`/`InvokeGateway` | CloudTrail **data** events (only if enabled) | strong |
| Machine cadence (many calls, regular intervals, no console session) | same events | medium |
| Is the execution role of a Lambda/ECS/EC2/EKS workload | `cloud_workload.identity_id`, `cloud_assume_edge` (IRSA, Pod Identity) | context: names the workload |
| Is the role of a declared agent | §5.1 sighting | suppresses: already declared |

Output: a sighting `source='aws'`, fingerprint `aws:<account>:role:<RoleId>`
(the incarnation, never the name), `evidence_mode=inferred`, `confidence`
high/medium, `signals`, and the workloads that run as the role. A workload
inferred by §5.2.1 gets fingerprint `aws:<account>:<runtime_kind>:<native_id>`
(Azure: `azure:<subscription>:<resource id>`; Kubernetes keeps the collector's
fingerprint), and its identity's sighting and its own are linked, not
duplicated: one agent, the workload and the identity it runs as.

**Collection change.** The general `LookupEvents` pass caps at 10,000 events
per region per scan and drops unmatched events; in a busy account Bedrock calls
can be cut off. Add one focused pass per region with
`LookupAttributes: EventSource=bedrock.amazonaws.com` (one attribute per call
is what the API allows), same 48 h window, its own cap, attribution through the
existing `TrailEvent.Attribution`. Aggregate into `cloud_usage`
(`source='cloudtrail'`, already admitted by the check, no writer today) per
identity per model: calls, last call, models, errors.

### 5.3 Risky credentials (P1)

| Finding | AWS | Azure | Kubernetes |
|---|---|---|---|
| Agent runs as a human | IAM user with a console password; assumed-role session from Identity Center | delegated sign-ins of a user from an agent identity | admission actor is a user, not a controller |
| Long-lived key | `cloud_secret` `access_key` older than N days, used by an inferred agent | `entra_client_secret` on the agent's app | ServiceAccount token secret (non-projected) |
| Model key in a secret | Secrets Manager names matching `openai|anthropic|gemini|llm|api[-_]?key` (from `ListSecrets`, already read in `resource_policies.go:1402`) | Key Vault secret **names** (new: data-plane list of secret properties; needs Key Vault Reader or Secrets User — **verify** the minimal role) | env var names already reported (`env_marker_keys`) |

Never a secret value. Findings attach to the agent sighting and the identity.

### 5.4 Real-time ingress (P2)

New authenticated ingress, one per provider, **workspace and connector taken
from the credential, never the body** (CLAUDE.md §4 rule 2; unlike the
Kubernetes ingress today, which accepts a body-asserted `workspace_id` vouched
by the token, `discovery_controller.go:269-309`):

```
POST /authsec/ingest/aws/events        Auth: per-connector ingest secret (EventBridge API destination connection, API-key header)
POST /authsec/ingest/azure/events      Auth: Event Grid webhook, Entra-authenticated delivery or per-connector secret; handles the subscription validation handshake
POST /authsec/ingest/otlp/v1/traces    Auth: per-workspace ingest token (P4)
Response 202; 401 unauthenticated; 413 too large; 429 rate limited
```

- **AWS:** customer deploys a CloudFormation stack (we publish it, as with the
  discovery role): EventBridge rule on `AWS API Call via CloudTrail` for the
  Bedrock, AgentCore, IAM, STS and S3 event sources, state
  `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS` (read-only management events
  need it), target an API destination.
- **Azure:** Bicep: Event Grid system topic on the subscription (ARM writes,
  role assignments) → webhook; diagnostic settings on Entra sign-in logs and
  Azure OpenAI → Event Hubs is **not** pushable to a webhook without a
  function; **Q2:** accept an Azure Function relay we publish, or poll sign-ins
  every 5 min instead?
- **Kubernetes:** iga-agent switches the resync from a 6 h list to informers
  (watch) for workloads and RBAC; admission adds UPDATE; sightings get a
  monotonically increasing sequence per cluster so a replay is refused (K-1
  extended to sightings).
- Each event is idempotent by provider event id; polling stays as the
  backstop and fills gaps; a connector whose stream stops shows "stream
  silent since …" in Connections.

### 5.5 Activity timeline (P4)

New table, append-only (trigger like 108), per workspace, RLS:

```
agent_activity_event(
  id, workspace_id, occurred_at, received_at,
  agent_id (discovered_agents, nullable until attributed), identity_id (cloud_identity / iga_identity_accounts),
  source  -- cloudtrail | cloudtrail_data | azure_activity | entra_sign_in | k8s_audit | agentcore_span | foundry_span | defender | otlp | authsec_decision
  kind    -- model_call | tool_call | cloud_action | data_access | sign_in | decision
  action, resource_ref, outcome (success | denied | error), on_behalf_of (human ref, when stated),
  trace_id, span_id, provider_event_id, attrs jsonb (sanitized; no prompts, no secrets)
)
UNIQUE (workspace_id, source, provider_event_id)
```

Retention: default 90 days, per-workspace setting, daily purge job carrying the
workspace id. Aggregates stay in `cloud_usage` for the graph and R1b.
**Q3:** Postgres with monthly partitions is enough for pilot volumes (estimate
in review); a columnar store is a later decision.

Sources and what each gives:

| Source | Gives | Customer enables |
|---|---|---|
| CloudTrail management (P1 pass, P2 stream) | model calls, IAM/STS, control plane | nothing (on by default) |
| CloudTrail data events | AgentCore invocations, gateway calls, token-vault fetches, S3 object reads | data event selectors (paid) |
| AgentCore observability (`aws/spans`, runtime log groups) | agent → model → tool spans, session ids | Transaction Search, tracing per resource |
| Azure Activity Log / Event Grid | ARM actions, role-assignment changes | nothing / P2 stack |
| Entra sign-ins (agent identities) | token issuance per agent and resource, OBO user | nothing (Graph read) |
| Foundry tracing (App Insights) | runs, tool calls | connect App Insights to the project |
| Defender `CloudAppEvents` (`InvokeAgent`, `ExecuteToolBy*`) | tool calls of Microsoft agents | Agent 365 licence |
| Kubernetes audit (EKS CloudWatch `/aws/eks/<cluster>/cluster`, AKS diagnostic logs) | API calls by ServiceAccount | control-plane audit logging |
| OTLP receiver | any framework emitting OpenTelemetry GenAI spans | point the exporter at AuthSec |
| DNS / egress logs (Route 53 Resolver, Network Firewall, Azure DNS/Firewall) | when and how often a workload reaches which model provider | DNS query logging |
| Kubernetes node sensor (eBPF) | per process: connections to model providers, MCP servers, cloud APIs | install the sensor (iga-agent) |
| Provider usage APIs (OpenAI, Anthropic) | calls, tokens, models per key per minute | connect the provider org |
| AuthSec LLM / MCP gateway (§5.7) | every model call and tool call of an agent routed through it: provider, model, tokens, tool, arguments digest, outcome | point the agent's model base URL / MCP client at the gateway |
| AuthSec decisions (R3, P5 PEP, access policies) | allow/deny, refused actions | nothing |

**What we see of an agent that calls a provider directly**, by what the
customer enables: with nothing, its cloud actions (its identity) and that it is
an agent (configuration signals); with DNS logs or the sensor, when and how
often it calls which provider; with provider usage, tokens and models per key;
**with the gateway, each model and tool call** — the only way to see and
control individual calls of an agent that sends no traces.

**OpenTelemetry.** Accept `gen_ai.*` and `mcp.*` spans
([GenAI semantic conventions](https://github.com/open-telemetry/semantic-conventions-genai),
status *Development*: pin a version, normalize OpenInference/OpenLLMetry on
ingest). The conventions carry no "on whose behalf"; we accept and emit
`authsec.workspace_id`, `authsec.principal`, `authsec.grant_id`.

**Attribution** to an agent: identity → sighting (role, service principal,
ServiceAccount); span → `gen_ai.agent.id` matched to declared agent ids; a
span or event that matches no agent stays unattributed and counts toward
"activity without an agent" (itself a shadow signal).

**API**

```
GET /api/iga/v1/agents/:id/activity?from&to&kind&outcome&cursor   Auth: bearer, discovery:read
GET /api/iga/v1/agents/:id/access                                  (graph walk from the agent's identities, existing /graph underneath)
GET /api/iga/v1/activity?identity_id|resource_id&…                  (who touched this resource)
```

Each activity row links to the graph edge that allowed it when one exists
("reached through Storage Blob Data Reader on stdemo"), and access with no
activity in the window is marked unused (with the coverage caveat: missing
telemetry is not unused access, SPEC-agentic-access-management §9).

**Delegation chain** (R3): from Entra agent sign-ins (OBO user), AgentCore
token-vault events, R3 delegated JWT-SVID, ID-JAG grants we issue. Shown on the
agent and in each activity row as `on_behalf_of`. Graph edge `acts_for`
(human → agent) — **Q4:** a new `iga_relationship` kind, or derived at read?

### 5.6 Kill switch (P3)

`POST /api/iga/v1/agents/:id/contain` and `/release`, `governance:enforce`
(emergency path like R2's `governance:emergency`), audited, one job per
provider, each verified by read-back:

| Provider | Contain | Release |
|---|---|---|
| AWS | AuthSec-owned managed policy denying `*` on every role of the agent (attached like access policies, `/authsec/AuthSecContain-<RoleId>-<id>`), plus an R2 session revocation for sessions issued before contain | detach; session revocation expires as today |
| Azure | remove the agent identity's role assignments in connected subscriptions, recorded exactly as 144's block does, restored on release. Optional (customer opt-in, needs `Application.ReadWrite.All`-class permission): `accountEnabled=false` on the service principal / agent identity | restore assignments; re-enable |
| Kubernetes | remove the ServiceAccount from every binding (146 `remove_binding_subject`), plus NetworkPolicy deny (legacy `quarantine` instruction) | restore subjects; unquarantine |

Status: `containing → contained` only after every provider verified;
`partially_contained` names what failed. The agent sighting moves to
`quarantined` (existing status).

**Q5:** the legacy NetworkPolicy quarantine is "Isolate" pending gate G2 and
R1k must not act on a cluster the legacy reconciler can
(`PLAN-existing-policy-code-disposition.md:83,108-110`). Is reusing it for the
kill switch acceptable, or does contain stop at RBAC removal?

### 5.7 Live control (P5)

One policy decision point for every enforcement point, deterministic, outside
the agent:

- **AgentCore:** the existing R3 runtime (`/authsec/runtime/decide`, Cedar,
  `agentcore/push`; 062) — allow/deny only (holds are out of scope).
- **MCP gateway:** a new AuthSec gateway (or a third-party one: agentgateway,
  Kong) that authorizes each `tools/call` using the `Mcp-Method` / `Mcp-Name`
  headers (MCP spec 2026-07-28), refuses token passthrough, pins tool
  definitions by hash, and asks the PDP.
- **LLM gateway:** the same process proxies model calls for agents that call a
  provider directly. The agent's base URL points at the gateway
  (OpenAI-compatible and Anthropic Messages endpoints); the gateway
  authenticates the agent (workload identity or a per-agent AuthSec key),
  asks the PDP (allowed provider, model, budget), and forwards with the
  provider key, which it holds per workspace in Vault — so the agent no longer
  holds the key. It records metadata per call (provider, model, tokens,
  latency, tool-use names, outcome), never prompt or completion text.
  Redirecting traffic is the customer's change; detection (§5.2) tells them
  which agents still bypass it.
- **Wire format:** OpenID AuthZEN Authorization API 1.0 (Final 2026-01-12),
  so third-party gateways can call us.
- Every decision is an `agent_activity_event` (`source='authsec_decision'`,
  `kind='decision'`, refused ones included).

**Q6:** our own gateway (deploy and operate it) or AuthZEN-only and integrate
third-party gateways first?

### 5.8 Tenancy and safety

- Every new table: `workspace_id NOT NULL`, FK, index, `tenancy_enable_rls`
  (guarded by `to_regprocedure`, as 146:83-84), bootstrap mirror, parity check.
- New Go files listed in `scripts/tenant-rls-files.txt`; ratchet must not rise.
- Ingress derives workspace and connector from the credential; body values are
  never trusted. Per-connector rate limits; payload size limits.
- Isolation tests (`TwoTenants`) for every new read and write route and for each
  ingress (a token of workspace A cannot write activity into B).
- Discovery credentials never write; contain and live control use the
  enforcement/actuation credentials only.
- No secret values, prompts or responses stored.

## 6. Plan

Estimates: backend with tests and docs / until live (UI, real-cloud test,
review). Migration numbers from 147, re-checked at merge.

| Phase | Deliverable | Covers | Backend | Live |
|---|---|---|---|---|
| **P1** | AWS declared agents as sightings (§5.1); inference `workload_agent_v1` from configuration signals on AWS, Azure, Kubernetes (env/app-setting names, images, layers, secret names; §5.2.1) and `aws_agent_v1` with the focused Bedrock pass (§5.2.2); risky-credential findings (§5.3); Azure Key Vault secret names | R1, R2 | 7–8 d | ~2 wk |
| **P2** | Event ingress AWS/Azure + setup templates; iga-agent informers, UPDATE admission, sighting sequence (§5.4); **network signals**: Route 53 Resolver / Network Firewall and Azure DNS/Firewall logs mapped to workloads, iga-agent node sensor promoted from `experimental` (§5.2.1) | R1, R5 | ~2 wk | ~3 wk |
| **P3** | Contain / release (§5.6) | R7 | ~1 wk | ~1.5 wk |
| **P4** | `agent_activity_event`, collectors (CloudTrail data events, AgentCore spans, Foundry, Entra, Defender, K8s audit, DNS/sensor), OTLP receiver, **provider usage (OpenAI, Anthropic) and unaccounted model usage**, repo ↔ workload link, activity and access APIs, delegation chain (§5.5) | R1, R3, R4, R9 | 2.5–3 wk | ~4 wk |
| **P5** | PDP over AuthZEN, R3 allow/deny for AgentCore, MCP gateway **and LLM gateway** (§5.7) | R4, R8, R9 | 3–3.5 wk | ~4.5 wk |

Total ≈ 9–11 weeks backend, 12–14 weeks live. UI for a phase runs alongside the
next phase's backend. iga-agent changes ship as a chart release; customers
upgrade per cluster.

### Acceptance (per phase)

- **P1:** in the lab account (220171243705), a Lambda calling Bedrock with no
  declared agent appears as an inferred agent (confidence high, signals listed,
  the Lambda named) after one scan; a Lambda with `OPENAI_API_KEY` and the
  `openai` package in a layer appears as inferred (medium) without any Bedrock
  call; a Bedrock agent appears as declared; a Secrets Manager secret named
  `openai-api-key` produces a finding with no value read. An Azure Container
  App with `ANTHROPIC_API_KEY` and a pod with a LangGraph image are inferred
  the same way; no app-setting value is stored or logged (test asserts on the
  stored rows and the log output). Cross-workspace test: B sees none of A's
  sightings or findings.
- **P2:** a role assignment created in the Azure portal and an `InvokeModel`
  call in AWS show in AuthSec within 60 s with streams on; a forged or
  cross-workspace event is refused (401/404); stopping the stream shows
  "silent" within one polling interval. With Resolver query logs on, an ECS
  task calling `api.anthropic.com` is raised to high confidence and named as
  the source; traffic from an IP that maps to no workload is reported against
  its VPC.
- **P3:** contain an agent with an AWS role, an Azure identity and a K8s
  ServiceAccount: each provider read back shows no access; release restores
  exactly (diff of before/after equals none); partial failure is reported per
  provider.
- **P4:** an AgentCore agent's tool call and an S3 object read appear on its
  timeline with the human it acted for; an OTLP span from a LangGraph agent
  attaches to its sighting; retention purge removes only the workspace's rows
  past the window.
- **P4 (provider usage):** with an OpenAI org connected, usage on a key that
  matches no workload appears as unaccounted model usage; usage on a key whose
  name matches the inferred Lambda's secret is shown on that agent (weak link).
- **P5:** a denied `tools/call` is refused at the gateway, logged as a refused
  decision, and visible on the timeline; AuthZEN conformance tests pass. An
  agent pointed at the LLM gateway has each model call on its timeline
  (provider, model, tokens) with no prompt text stored; a model outside the
  policy is refused.

## 7. Open questions for review

1. **Q1** Single inventory: `discovered_agents` or `iga_agents`?
2. **Q2** Azure sign-ins in real time: publish an Event Hubs → webhook relay, or poll every 5 min?
3. **Q3** Activity store: Postgres partitions for now?
4. **Q4** Delegation as an `iga_relationship` kind or derived at read?
5. **Q5** Kill switch in Kubernetes: reuse the legacy NetworkPolicy quarantine?
6. **Q6** Own MCP gateway, or AuthZEN PDP first and third-party gateways?
7. **Q7** Order: P3 (kill switch) before P2 (streams) for an earlier demo?
8. **Q8** Azure disable of an agent identity needs a high-privilege Graph permission; offer it at all?
9. **Q9** Azure app settings: the ARM call returns values; reading names and discarding values in memory is the only way. Acceptable, or require a narrower source?
10. **Q10** Promote the iga-agent node sensor (eBPF/Tetragon, `origin/experimental`) to a supported, opt-in component?
11. **Q11** Provider admin keys (OpenAI, Anthropic) are customer secrets we must hold (Vault, per workspace). Accept, or read usage only from exports the customer pushes?
12. **Q12** Inference thresholds (§5.2.1): is "one configuration signal = low, listed but not alerted" right?

## 8. Risks

- Most action-level telemetry is off by default; without it the timeline shows
  only management actions. The console must say which sources are on per
  connector (coverage, never "complete").
- CloudTrail data events cost the customer money; the setup wizard states it.
- OpenTelemetry GenAI conventions may still change (status Development).
- Microsoft gates agent-level Defender and registry data behind Agent 365.
- Inference has false positives (a batch job calling Bedrock is not an agent);
  confidence and the `ignored` status are the release valve.
- DNS logs and the node sensor see traffic metadata of every workload, not only
  agents; we keep only lookups/connections to the model and MCP endpoint list
  and drop the rest on ingest.
- An agent can rename its key variable or bake the key into the image;
  configuration signals then miss it, and only network or provider-usage
  signals find it. The console says which signal families are on.
