# SPEC: Agent runtime gateway — live control of MCP tool calls and model calls

> **Status: revision 1, built 2026-11-05 on `feat/agent-runtime-gateway`**
> (Ritam). Not reviewed. Follows [SPEC-agent-runtime-visibility.md](SPEC-agent-runtime-visibility.md):
> its revision 1 §5.7 ("Live control": MCP gateway, LLM gateway, AuthZEN PDP)
> was deferred by revision 2 §2; this spec builds it with one binding change —
> **the gateway runs in the customer's environment**, so provider keys and MCP
> server credentials never reach AuthSec (revision 1 put them in Vault).
>
> Related: the R3 runtime controls for AgentCore (`internal/igagov/r3.go`,
> migration 062, `/authsec/runtime/*`) stay as they are. This spec borrows R3's
> ideas — a decision is a 200 whose body says allow or deny (R3-18), the
> arguments are bound by an RFC 8785 digest and never stored (R3-4), fail
> closed is the default posture (R3-7) — but not its credential (a delegated
> JWT-SVID per call) or its tables: a gateway is a long-lived PEP, not an agent.

## Summary

A customer runs `authsec/agent-gateway` (one static Go binary, a container or
sidecar) next to their agents. Agents point their MCP client and their
OpenAI/Anthropic base URL at it. For every MCP `tools/call` and every model
call the gateway asks AuthSec — the policy decision point (PDP) — "may this
agent call this tool / this model?" over the OpenID AuthZEN Authorization API,
enforces the answer, forwards allowed calls upstream with the customer's own
credentials, and uploads decision metadata to AuthSec. Admins write tool
policies (allow/deny, per agent, per MCP server and tool or per provider and
model, with a time window and a rate) in AuthSec and see every decision.

## 1. Requirements

| # | Requirement |
|---|---|
| G1 | Decide each MCP `tools/call` and each model call (provider, model) per agent, deterministically, from the workspace's tool policies |
| G2 | Enforce at a gateway in the customer's environment; AuthSec never holds model-provider keys or MCP server credentials, and never sees prompt, completion or tool-argument text |
| G3 | Standard wire format between PEP and PDP: AuthZEN Authorization API 1.0 so third-party gateways can call AuthSec |
| G4 | Detect MCP tool-definition changes (rug pull) and refuse calls to a changed tool until re-approved |
| G5 | Every decision recorded per workspace, append-only, metadata only (agent, tool/model, decision, reason, policy, latency, argument digest, token usage) |
| G6 | Fast: PDP p50 < 20 ms server time; the gateway caches decisions |
| G7 | A defined behaviour when AuthSec is unreachable (fail mode) |
| G8 | Tenant isolation: the gateway credential alone decides workspace and gateway; nothing in a body does |

No human approval (visibility spec §8 Q6, decided): decisions are allow or deny, never hold.

## 2. Scope

**In:** the PDP endpoints, tool-policy model and admin API, gateway
credentials, decision log with retention, the gateway binary (MCP Streamable
HTTP reverse proxy; OpenAI-compatible `/v1/chat/completions`, `/v1/responses`,
`/v1/embeddings`; Anthropic `/v1/messages`), its Dockerfile, a Helm values
example and README.

**Deferred:** the console UI (Authsec-ui); the AuthZEN search APIs (§8 of the
AuthZEN spec) and the `/.well-known/authzen-configuration` metadata document
(it must sit at the host root with the PDP path appended, AuthZEN §9.2, which
is outside the `/authsec` mount); budgets in cost or tokens (only calls per
minute); argument-value policies (only the digest is seen); MCP `resources/read`
and `prompts/get` control (passed through, not decided); stdio MCP servers;
OTLP export from the gateway; writing decisions into `agent_activity_event`
(spec 155, another engineer's table — a follow-up can mirror
`agent_gateway_decision` there with `source='authsec_decision'`).

## 3. Architecture

```
 customer environment                                         AuthSec
 ┌──────────────────────────────────────────────────┐        ┌────────────────────────────┐
 │ agent ──MCP──▶ agent-gateway ──MCP──▶ MCP server │        │ POST /authsec/pdp/access/   │
 │       ──LLM──▶   (PEP)       ──LLM──▶ provider   │──TLS──▶│   v1/evaluation(s)  (PDP)   │
 │                  │  cache, pins, fail mode       │        │ POST /authsec/pdp/v1/decisions│
 │                  │  provider keys, MCP creds     │        │ GET  /authsec/pdp/v1/policy-hints│
 │                  └ never leave this box          │        │ admin: /api/iga/v1/agent-runtime/…│
 └──────────────────────────────────────────────────┘        └────────────────────────────┘
```

- **PEP = gateway** (`cmd/agent-gateway`, logic in `internal/agentgateway/gateway`).
- **PDP = AuthSec** (`services/agent_gateway*.go`, pure evaluation in
  `internal/agentgateway`, shared with the gateway for request mapping).
- What crosses to AuthSec: agent id and selector attributes the gateway
  configured for it, MCP server name/URL and tool name, provider and model,
  the action, an argument digest (`sha256:` of the RFC 8785 form), the tool
  definition hash, latency, HTTP status, token counts. Never: prompts,
  completions, tool arguments or results, provider keys, MCP credentials,
  the agent's own credential.

## 4. Threat model

| Threat | Mitigation |
|---|---|
| Gateway credential stolen | Shown once, stored as sha256; `agw_` prefix for secret scanners; rotate and revoke (`revoked_at`); a stolen credential only reads its own workspace's decisions-for-requests and writes decision logs for its own gateway (it cannot read policies or other gateways' logs; `policy-hints` returns only deny target patterns) |
| Workspace confusion / cross-tenant | Workspace and gateway come from the credential row only (CLAUDE.md §4 rule 2); all SQL after the lookup under `tenancy.InWorkspace` (RLS); decision ids are keyed `(workspace_id, id)` so one workspace's ids cannot collide with another's |
| Forged decision logs from a gateway | Uploaded rows are stamped with the credential's gateway and workspace; `source='pdp'` cannot be uploaded (only AuthSec writes PDP rows); bounded sizes and times; idempotent by id |
| Agent impersonation at the gateway | Per-agent gateway keys (sha256 in the gateway config) or a SPIFFE ID from verified mTLS; a SPIFFE header is trusted only when `trust_spiffe_header` is set behind an mTLS-terminating proxy; the agent credential is stripped before forwarding |
| Token passthrough to MCP servers | The gateway never forwards the agent's `Authorization`; upstream credentials come from the gateway's config/env |
| Header/body mismatch (route on header, execute body) | The gateway processes the body, so it MUST reject a mismatch: 400, JSON-RPC `-32020` HeaderMismatch (MCP Streamable HTTP, "Server Validation"; SEP-2243 as amended by #2907). Decisions use body values |
| Tool rug pull (definition changes after approval) | Tool definitions from `tools/list` are hashed (RFC 8785 sha256) and pinned on first sight (or pre-pinned in config); a changed hash refuses `tools/call` with reason `tool_definition_changed` until re-approved on the gateway's local admin endpoint (`POST /admin/pins/approve`) or by updating the pin file |
| PDP outage | Fail mode (§7) |
| Replay of a cached allow after a policy change | Cache TTL ≤ workspace `cache_ttl_seconds` (default 30, max 300); rate-conditioned decisions are never cached; time-window decisions expire at the next minute boundary |
| DoS of the PDP | Per-gateway token bucket after authentication; the per-IP general limit does not apply to `/authsec/pdp/*` (gateways sit behind NAT), a high per-IP ceiling bounds unauthenticated traffic (`IngestRateLimit` pattern); body limits |
| Prompt/secret leakage into logs | The gateway parses only `method`, `params.name`, `params.arguments` (digested in memory), `model` and `usage`; it logs none of them except tool/model names |

## 5. AuthZEN mapping

Spec: OpenID AuthZEN **Authorization API 1.0**, Final, "Published: 11 January
2026" per the document header (https://openid.net/specs/authorization-api-1_0.html;
the task brief said 2026-01-12 — the published document says the 11th).
Sections used: Subject §5.1, Resource §5.2, Action §5.3, Context §5.4,
Decision §5.5 (`reason_admin`/`reason_user` in context, §5.5.2.1), Access
Evaluation §6, Access Evaluations (batch) §7 with `options.evaluations_semantic`
(`execute_all` default, `deny_on_first_deny`, `permit_on_first_permit`,
§7.1.2.1) and per-evaluation errors as `decision:false` + `context.error`
(§7.2.1), HTTPS binding §10.1 (paths `/access/v1/evaluation`,
`/access/v1/evaluations`; errors 400/401/403/500 with a string body, §10.1.2;
`X-Request-ID` echoed, §10.1.3). Authentication is out of scope of AuthZEN
(§2.4, OAuth RECOMMENDED); AuthSec uses a bearer gateway credential.

| AuthZEN | MCP tool call | Model call |
|---|---|---|
| `subject.type` | `agent` | `agent` |
| `subject.id` | the gateway client id of the agent (its key id) or its SPIFFE ID | same |
| `subject.properties` | `identity_id`, `workload_id` (AuthSec ids, optional), `labels` (strings) | same |
| `action.name` | `tools/call` | `model/invoke` (`properties.operation`: `chat.completions`, `responses`, `embeddings`, `messages`) |
| `resource.type` | `mcp_tool` | `model` |
| `resource.id` | `<server>/<tool>` | `<provider>/<model>` |
| `resource.properties` | `server`, `server_url`, `tool`, `definition_hash` | `provider`, `model` |
| `context` (kept keys only) | `args_digest`, `request_id`, `gateway_version` | `request_id`, `gateway_version`, `stream` |

Response `context`: `decision_id` (the PDP's log row), `reason_admin`
(`{"reason": code, "policy_id", "policy_name"}`), `reason_user`
(`{"reason": code}`), `ttl_seconds` (cache lifetime; 0 = do not cache), `mode`
(`observe`/`enforce`).

Example (single):

```http
POST /authsec/pdp/access/v1/evaluation
Authorization: Bearer agw_…
X-Request-ID: 7d0c…

{"subject":{"type":"agent","id":"billing-agent","properties":{"labels":["prod"]}},
 "action":{"name":"tools/call"},
 "resource":{"type":"mcp_tool","id":"github/create_issue",
             "properties":{"server":"github","server_url":"https://api.githubcopilot.com/mcp/","tool":"create_issue",
                           "definition_hash":"sha256:…"}},
 "context":{"args_digest":"sha256:…"}}

200 OK
X-Request-ID: 7d0c…
{"decision":false,
 "context":{"decision_id":"0b6f…","reason_admin":{"reason":"policy_deny","policy_id":"5e1a…","policy_name":"no-github-writes"},
            "reason_user":{"reason":"policy_deny"},"ttl_seconds":30,"mode":"enforce"}}
```

## 6. Policy model

`agent_tool_policy` (migration 156): `name`, subject selector
(`subject_identity_id`, `subject_workload_id`, `subject_agent_label`,
`subject_client_id` — a pattern on `subject.id`; `gateway_id` restricts to
one gateway; every set field must match, none set = every agent), `effect`
`allow|deny`, `kind` `mcp_tool|model`, target (`mcp_tool`: `target_server`,
`target_server_url`, `target_tool`; `model`: `target_provider`,
`target_model`; patterns where `*` matches any run of characters, empty = any),
`conditions` (`{"time_window": {"days": ["mon",…], "start": "09:00", "end":
"18:00", "timezone": "Europe/Berlin"}, "max_calls_per_minute": 60}`),
`deny_unlisted` (allow policies only: the agents it selects may use only
allowed targets of this kind), `priority` (higher first; only decides which
policy a decision names), `enabled`, `created_by`, `updated_by`, `version`.

**Evaluation** (pure, `internal/agentgateway.Evaluate`), for one request:

1. enabled **deny** policies whose subject, target and time window match →
   deny `policy_deny` (the highest-priority one named; ties by name, then id);
2. enabled **allow** policies whose subject, target and time window match, in
   priority order: the first whose rate bucket has a token → allow
   `policy_allow`; if all matching allows are out of tokens → deny `rate_limited`;
3. an enabled allow policy with `deny_unlisted` of the same kind whose subject
   matches → deny `not_allowlisted` (default deny for listed agents);
4. the workspace default: `observe` → allow `default_allow`, `enforce` → deny
   `default_deny` (`agent_gateway_setting.mode`, default `observe`).

`max_calls_per_minute` is valid on allow policies only; its bucket is
in-memory per (policy, gateway, subject, target) in each AuthSec process
(N per minute, burst N). Several AuthSec replicas each allow N: documented
limit. A dry run (`POST …/tool-policies/evaluate`) never takes a token.

## 7. Gateway behaviour

- **Decision cache**: key (subject id + selector attributes, action, resource
  id + kind); TTL from `context.ttl_seconds`; bounded entries (LRU-ish by
  expiry). A cache hit is logged by the gateway (`source='cache'`,
  `decision_ref` = the PDP decision id).
- **Fail mode** (`fail_mode`): when the PDP is unreachable, times out
  (default 300 ms), or answers 5xx and nothing is cached:
  - `closed` — deny everything;
  - `open` — allow everything;
  - `auto` (**default**) — deny when the target matches a deny policy's
    target (from `GET /authsec/pdp/v1/policy-hints`, refreshed every 60 s), or
    the workspace mode is `enforce`, or no hints were ever fetched; allow
    otherwise (observe mode, no deny policy on that target). So tools with a
    deny policy fail **closed**.
  The decision is logged `source=fail_closed|fail_open`, reason
  `pdp_unavailable`.
- **MCP**: POST bodies are JSON-RPC (an object; an array — pre-2025-06-18
  batching — is decided element by element and refused whole if any call is
  denied). `Mcp-Method`/`Mcp-Name` (base64 sentinel decoded) must match the
  body when present (400, `-32020`); when absent (older protocol versions)
  the body is parsed. `tools/call` → pin check → PDP → forward or JSON-RPC
  error (HTTP 200, code `-31001`, `data: {reason, decision_id, policy_id}`).
  Other methods pass through. `tools/list` responses (JSON or SSE) are teed
  through a parser that pins definitions. GET/DELETE (2025-11-25 sessions and
  standalone streams) pass through. `Mcp-Session-Id`, `MCP-Protocol-Version`,
  `Mcp-Method`, `Mcp-Name`, `Mcp-Param-*`, `Last-Event-ID`, `Accept`,
  `Content-Type` are forwarded; the agent's `Authorization` is not.
- **LLM**: the agent uses its gateway key as its "API key" (`Authorization:
  Bearer agk_…` or `x-api-key: agk_…`) or `X-AuthSec-Agent-Key`. The gateway
  reads `model` from the body, asks the PDP, and on allow forwards the
  untouched body with the provider key from its own env; responses stream
  through (flushed per write). Usage (`prompt/input`, `completion/output`,
  `total` tokens) is read from the JSON body or from SSE events
  (`usage` chunks, `response.completed`, Anthropic `message_start` /
  `message_delta`) and uploaded as an `outcome` record referencing the
  decision. A deny is a 403 in the provider's error shape.
- **Upload**: decisions made by the gateway and outcomes go to
  `POST /authsec/pdp/v1/decisions` in batches (≤ 500 per request, every 2 s),
  retried with backoff; the queue is bounded (50 000) and drops oldest, with a
  counter in the gateway's log.

## 8. API

PDP (no AuthMiddleware; `Authorization: Bearer agw_…` → workspace + gateway):

| Route | |
|---|---|
| `POST /authsec/pdp/access/v1/evaluation` | AuthZEN §6 |
| `POST /authsec/pdp/access/v1/evaluations` | AuthZEN §7 (≤ 100 evaluations) |
| `POST /authsec/pdp/v1/decisions` | gateway decision/outcome upload, 202 `{accepted, duplicates}` |
| `GET /authsec/pdp/v1/policy-hints` | `{mode, deny_targets: [{kind, server, server_url, tool, provider, model}], ttl_seconds}` |

401 unknown/revoked credential, 429 per-gateway limit, 413 body > 1 MB,
400 bad request (string bodies, AuthZEN §10.1.2).

Admin (`/api/iga/v1/agent-runtime`, AuthMiddleware; workspace from the token;
writes need `governance:enforce` and a verified member session; reads
`governance:read`; another workspace's id is 404; every write audited):

| Route | |
|---|---|
| `POST /gateways` `{name}` | 201 `{gateway, credential}` — credential shown once |
| `GET /gateways`, `GET /gateways/:id` | |
| `PATCH /gateways/:id` `{name, version}` | |
| `POST /gateways/:id/rotate` | new credential, old one refused at once |
| `DELETE /gateways/:id` | revoke (the row stays; its decisions stay) |
| `GET/PUT /gateway-settings` | `mode`, `cache_ttl_seconds`, `decision_retention_days` |
| `GET/POST /tool-policies`, `GET/PUT/DELETE /tool-policies/:id` | PUT needs `version` (409 `version_conflict`) |
| `POST /tool-policies/evaluate` | dry run: an AuthZEN evaluation request in, the decision and every policy considered out |
| `GET /gateway-decisions?gateway_id=&decision=&kind=&subject_id=&source=&since=&until=&cursor=&limit=` | newest first, cursor paging |

## 9. Schema (migration 156)

`agent_gateway`, `agent_gateway_setting`, `agent_tool_policy`,
`agent_gateway_decision`: `workspace_id NOT NULL` FK → `workspaces` ON DELETE
CASCADE, workspace-leading indexes, `UNIQUE (workspace_id, id)`,
`tenancy_enable_rls` (guarded as 146), mirrored at the end of
`001_bootstrap.sql`. `agent_gateway_decision` is append-only (trigger): UPDATE
is refused; DELETE only in a workspace purge (`authsec.workspace_purge = on`)
or a retention purge (`authsec.gateway_decision_purge = on`) of rows older
than 7 days. Retention per workspace (`decision_retention_days`, default 30,
7..3650), purged at most hourly per workspace per process.

## 10. Latency budget and limits

PDP server time: credential cache (10 s, invalidated locally on revoke/rotate)
→ per-gateway limiter → policy cache (5 s across replicas, invalidated locally
on change) → evaluation (µs) → async decision write (buffered channel, flushed
every 250 ms or 200 rows; synchronous when the buffer is full). Target p50 <
20 ms server time, typically < 2 ms. Gateway: cache hit adds < 1 ms; a miss
adds one PDP round trip (timeout 300 ms, then fail mode).

Limits: body 1 MB; 100 evaluations per batch; 1 000 records per upload; names
≤ 200 chars, patterns ≤ 512; ≤ 1 000 policies per workspace; per gateway 500
req/s burst 1 000 (`AGENT_GATEWAY_PDP_RPS`, `AGENT_GATEWAY_PDP_BURST`).

## 11. Tenancy and safety

As visibility spec §5.9: new tables under RLS; new Go files in
`scripts/tenant-rls-files.txt`; the only cross-workspace statement is the
credential lookup by hash (TENANT-EXEMPT, as event secrets); isolation tests
(gateway A's credential evaluates only A's policies; A's decisions invisible
to B; B's admin calls on A's ids are 404).

## 12. Affected repos

| Repo | What changes | Why / why not |
|---|---|---|
| `authsec` | migration 156, PDP + admin API, gateway binary, Dockerfile, Helm values | all of it |
| `Authsec-ui` | gateways, tool policies, decisions pages (follow-up) | console |
| `sdk-authsec` | none | agents talk to the gateway with their existing OpenAI/Anthropic/MCP clients; no SDK call is needed |
| `authsec-doc` | gateway deployment guide (from `deploy/agent-gateway/README.md`) | customers deploy it |
| Production K3s | none server-side beyond the `/authsec/pdp/*` ingress path | the gateway runs in the customer's cluster |

## 13. Open questions

1. Q1 Pin re-approval from the console (AuthSec stores pins per gateway) instead of on the gateway?
2. Q2 Mirror decisions into `agent_activity_event` (155) once it lands?
3. Q3 Shared rate buckets across AuthSec replicas (Redis) when a customer needs exact limits?
