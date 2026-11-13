# SPEC: Agent runtime activity timeline (P4, AWS)

> **Status: revision 1, build started 2026-11-05 on `feat/agent-runtime-activity`**
> (Ritam). Reviewer: Aditya Agarwal and his agents.
>
> Parent: [SPEC-agent-runtime-visibility.md](SPEC-agent-runtime-visibility.md)
> (revision 2 deferred P4 to "a separate spec"; this is it). It reuses the
> design of that spec's revision 1, §5.5 (`git show 10e26714:.claude/specs/SPEC-agent-runtime-visibility.md`),
> restricted to AWS and to the sources below. Migration: **155** only.

## Summary

For every AI workload and agent AuthSec knows in a workspace, show **what it
actually did**, newest first, in near real time: its AWS API calls (management
and, when the customer turns them on, data events), its model calls, its own
steps and tool calls from traces, and on whose behalf when the trace says so.
One append-only table per workspace (`agent_activity_event`) is fed by three
sources, read by two APIs, and purged after a per-workspace retention.

## 1. Requirements

| # | Requirement |
|---|---|
| A1 | A per-identity / per-workload timeline of activity rows: kind, action, resource, outcome, time, source |
| A2 | CloudTrail events of every labelled identity (AI workload, suggested agent, agent, and "possible AI workload" when that label exists) become rows, from the poller and the event stream, once |
| A3 | AgentCore observability spans (CloudWatch Logs `aws/spans`) become rows, attributed to the AgentCore runtime workload and its role |
| A4 | Any framework emitting OpenTelemetry traces can post them to AuthSec (OTLP/HTTP); GenAI spans become rows |
| A5 | A trace's spans can be read as a tree |
| A6 | Prompts, completions, messages, tool-argument values and secrets are never stored |
| A7 | Workspace isolation: rows, tokens and cursors are per workspace, under RLS; a token of A cannot write into B; B reads none of A |
| A8 | Rows are append-only; only retention (default 90 days per workspace) and a workspace purge delete them |

## 2. Scope

**In:** the three sources below; `agent_activity_event`, cursors, settings,
OTLP tokens (migration 155); list, trace, coverage, settings and token APIs.

**Out (deferred):** Azure, Kubernetes audit, provider usage APIs, gateways
(other branches); graph-edge links per row ("reached through …") and
"unused access"; `authsec_decision` rows (the source value is reserved, no
writer yet); delegation chain beyond what a span states; runtime log groups
`/aws/bedrock-agentcore/runtimes/*` (spans live in `aws/spans`, §4.2);
partitioning (§3.3); UI (`Authsec-ui`, separate change).

## 3. Data model (migration 155)

### 3.1 `agent_activity_event`

| Column | Type | Notes |
|---|---|---|
| `id` | uuid PK | |
| `workspace_id` | uuid NOT NULL FK `workspaces` ON DELETE CASCADE | RLS |
| `connector_id` | uuid NULL | no FK: a record outlives the inventory row (as `agent_alert`) |
| `identity_id` | uuid NULL | `cloud_identity.id`; no FK (same reason) |
| `workload_id` | uuid NULL | `cloud_workload.id`; no FK |
| `source` | text | `cloudtrail` \| `cloudtrail_data` \| `agentcore_span` \| `otlp` \| `authsec_decision` |
| `kind` | text | `model_call` \| `tool_call` \| `agent_step` \| `cloud_action` \| `data_access` \| `sign_in` \| `decision` |
| `occurred_at` | timestamptz | event time / span start |
| `received_at` | timestamptz default now() | |
| `action` | text ≤ 200 | `s3:GetObject`, `chat`, `execute_tool`, `invoke_agent` |
| `resource_ref` | text ≤ 512 | ARN, model id, tool name, agent name |
| `outcome` | text | `success` \| `denied` \| `error` |
| `on_behalf_of` | text NULL ≤ 256 | the human, only when the source states it |
| `trace_id`, `span_id`, `parent_span_id` | text ≤ 64 | lower-case hex; '' for CloudTrail |
| `provider_event_id` | text ≤ 300 | CloudTrail `eventID`; `<trace_id>:<span_id>` for spans |
| `attrs` | jsonb object ≤ 16 KB | sanitised (§6) |

`UNIQUE (workspace_id, source, provider_event_id)` is the idempotency key: every
writer inserts `ON CONFLICT DO NOTHING`. Indexes: `(workspace_id, occurred_at
DESC, id DESC)` (list), `(workspace_id, identity_id, occurred_at DESC)`,
`(workspace_id, workload_id, occurred_at DESC)`, `(workspace_id, trace_id)`
where `trace_id <> ''`.

**Append-only.** A trigger refuses every UPDATE (as 108) and every DELETE unless
the transaction set `authsec.activity_retention = 'on'` (the purge job) or
`authsec.workspace_purge = 'on'` (workspace deletion,
`database/workspace_repository.go`).

### 3.2 Other tables

- `agent_activity_setting (workspace_id PK, retention_days 1..400 default 90, updated_by, updated_at)`; no row = defaults.
- `agent_activity_cursor (workspace_id, connector_id, region, stream, cursor_at, state, last_error, error_code, last_scan_at, rows_written)`,
  PK `(workspace_id, connector_id, region, stream)`, FK `(workspace_id, connector_id)` → `cloud_connector` ON DELETE CASCADE.
  `stream = 'aws_spans'`; `state` = `reached | partial | permission_missing | not_configured | error`.
- `agent_otlp_token (id, workspace_id, label, token_hash UNIQUE, token_prefix, created_by, created_at, expires_at, revoked_at, last_used_at)`:
  sha256 hex of the token, never the token (the event-stream secret pattern of 149).

All four: `workspace_id NOT NULL` FK, indexed, guarded `tenancy_enable_rls`
(as 146), mirrored by appending the same block at the end of `001_bootstrap.sql`.

### 3.3 Retention and partitioning

Default 90 days per workspace (`agent_activity_setting`). An hourly job lists
the workspaces holding rows (TENANT-EXEMPT: ids only) and, per workspace in
its own `tenancy.InWorkspace` transaction, deletes rows with `occurred_at`
older than the cutoff in batches of 5,000. Writers drop events already older
than the cutoff. **No partitioning in this revision**: pilot volume is small
(polling caps + OTLP rate limits bound it, §8), and a later move to monthly
partitions keeps the same table name and indexes.

## 4. Sources

### 4.1 Source A — CloudTrail (sink `agent_activity`)

An `agentruntime.EventSink` registered at startup; it receives every
normalised event of a connector from the LookupEvents poller and the
EventBridge stream ingest. Per attribution (session issuer / IAM user) it asks
`agentruntime.Resolver()`; it writes rows only for identities labelled
`ai_workload`, `suggested_agent`, `agent` or `possible_ai_workload` (strings,
not constants). Events with `eventType = AwsServiceEvent` (stream-completion
records, counted once by §5.1 of the parent) are skipped.

| Event | source | kind |
|---|---|---|
| Bedrock / mantle inference (`Event.IsModelCall`) | `cloudtrail` or `cloudtrail_data` | `model_call` |
| `eventCategory = Data` | `cloudtrail_data` | `data_access` |
| `ConsoleLogin` | `cloudtrail` | `sign_in` |
| anything else | `cloudtrail` | `cloud_action` |

`action` = `<service>:<eventName>` (service = event source minus
`.amazonaws.com`); `resource_ref` = the model id, else the first resource ARN,
else a request fact (secret, bucket, function, role); `outcome` = `denied` on
an authorization error code, `error` on any other error, else `success`;
`workload_id` = the identity's single workload (none on a shared role).
`on_behalf_of` is empty: the normalised event carries no human principal.
Idempotent by `(workspace, source, eventID)`.

### 4.2 Source B — AgentCore observability spans

Per AWS connector and selected region, during the scan (one call per region
from `scanRegion`, code in its own file): CloudWatch Logs Insights over log
group **`aws/spans`** (where AgentCore and Transaction Search write spans),

```
fields @timestamp, @ingestionTime, @message
| filter @message like /gen_ai|openinference|traceloop|mcp\./
| filter @ingestionTime >= <cursor ms> and @ingestionTime < <until ms>
| sort @ingestionTime asc
| limit 1000
```

from the `aws_spans` cursor (first scan: the last 24 h) to now − 5 min
(ingestion lag); at most one query of 1,000 spans per region per scan. The
cursor is an **arrival time**: the query keeps spans that arrived
(`@ingestionTime`) in `[cursor, now − 5 min)`, sorted by arrival, and searches
event time from `SpanLateArrival` (2 h) before the cursor, so a span that
reaches `aws/spans` up to 2 h after its event time is read once; later ones
are missed. Capped → the cursor moves to the last arrival read and the state
is `partial`. Results are
polled for at most 60 s (then `StopQuery`, state `error`). Each `@message` is
one span record (OTLP shape with `attributes` as a map; parsed tolerantly,
§5). **UNVERIFIED** against a lab account: the record shape, and that
`cloud.resource_id` carries the runtime ARN. Attribution: the runtime ARN
(prefix `arn:…:bedrock-agentcore:<region>:<account>:runtime/<id>`) from
`cloud.resource_id` → `cloud_workload` (`bedrock_agentcore_runtime`, this
connector) → its `identity_id`; else unattributed (connector set).

Coverage: `AccessDeniedException` → `permission_missing`;
`ResourceNotFoundException` (no `aws/spans`: Transaction Search off) →
`not_configured`; anything else → `error`. Recorded on the cursor row, shown by
`GET …/activity/coverage`, and a scan warning; **never** a scan failure, and not
written into the scan's surface coverage (it would mark every scan partial
until the role is updated).

**Discovery role permissions** (granted by discovery template 2026-11-07,
`authsec-aws-discovery-role.yaml`; until 2026-11-06 the template's broad
`logs:StartQuery` covered them by accident):

```yaml
- Sid: AgentActivitySpans
  Effect: Allow
  Action: [logs:StartQuery, logs:StopQuery]
  Resource: !Sub arn:${AWS::Partition}:logs:*:${AWS::AccountId}:log-group:aws/spans:*
- Sid: AgentActivityQueryResults
  Effect: Allow
  Action: logs:GetQueryResults   # no resource-level permissions
  Resource: "*"
```

### 4.3 Source C — OTLP/HTTP receiver

```
POST /authsec/ingest/otlp/v1/traces
Auth: Authorization: Bearer <aot_…> | X-AuthSec-Ingest-Token: <aot_…>
Content-Type: application/x-protobuf | application/json   (Content-Encoding: gzip optional)
200 ExportTraceServiceResponse (partial_success when spans were rejected)
400 undecodable · 401 unknown/revoked/expired token · 413 > 4 MB (compressed or not)
415 other content type · 429 per-token limit (Retry-After) · 503 store failed
```

- No AuthMiddleware. The workspace comes **only** from the token (looked up by
  its sha256 — the one TENANT-EXEMPT statement); nothing in the body or the
  resource attributes can name a workspace. Tokens: created by
  `POST /api/iga/v1/agent-runtime/otlp-tokens` (shown once, `aot_` + 43
  base64url chars), listed, revoked; optional expiry ≤ 365 days; ≤ 25 live
  per workspace.
- Rate limit per token (`AGENT_OTLP_INGEST_RPS`, default 20/s, burst 40; per
  process) after the token check; the path is in the per-IP ingest budget
  (`IngestRateLimit`) like `/ingest/aws/events`.
- Only spans the normaliser recognises as GenAI / agent / MCP spans are stored;
  others are counted (`ignored`) and dropped.
- Attribution from resource attributes, within the token's workspace only
  (asserted by the sender, recorded as `attribution.how`):
  1. `authsec.workload_id` → that `cloud_workload` (and its role);
  2. `authsec.identity_arn` → `cloud_identity` by ARN;
  3. `cloud.resource_id` / `faas.id` / `aws.lambda.invoked_arn` → a workload by ARN (Lambda qualifier stripped; AgentCore runtime prefix);
  4. `cloud.account.id` + `faas.name` (+ `cloud.region`) → the one Lambda of that name in that account;
  5. `cloud.account.id` + `aws.ecs.task.family` + `aws.ecs.task.revision` → the ECS task definition;
  else unattributed (workspace-level). `k8s.pod.name`, `k8s.namespace.name`,
  `aws.ecs.task.arn` are kept as hints only (no pod inventory exists).

## 5. Normalisation (OpenTelemetry GenAI semantic conventions)

Pinned: **open-telemetry/semantic-conventions-genai @ `aa3b7f4394245fec260013898049780975a407a4`**
(2026-11-05; schema `https://opentelemetry.io/schemas/gen-ai-dev/1.42.0-dev`,
on semantic-conventions v1.45.0), https://github.com/open-telemetry/semantic-conventions-genai.
Status **Development**: names may change; the normaliser keeps the aliases below.

**Kind**, first match:

| Signal | kind |
|---|---|
| `gen_ai.operation.name` ∈ chat, generate_content, text_completion, embeddings, realtime_inference | `model_call` |
| `gen_ai.operation.name` = execute_tool; `mcp.method.name` = tools/call | `tool_call` |
| `gen_ai.operation.name` = retrieval, search_memory | `data_access` |
| any other `gen_ai.operation.name` (invoke_agent, create_agent, invoke_workflow, plan, …); other `mcp.method.name` | `agent_step` |
| OpenInference `openinference.span.kind`: LLM/EMBEDDING/RERANKER → model_call, TOOL → tool_call, RETRIEVER → data_access, AGENT/CHAIN/other → agent_step | |
| OpenLLMetry `traceloop.span.kind`: tool → tool_call, agent/workflow/task → agent_step; `llm.request.type` → model_call | |
| none of these | not stored |

**Fields kept** (allowlist; everything else is dropped): `gen_ai.operation.name`,
`gen_ai.provider.name` (alias `gen_ai.system`, `llm.provider`, `llm.system`),
`gen_ai.request.model` / `gen_ai.response.model` (alias `llm.model_name`,
`llm.request.model`, `llm.response.model`), `gen_ai.usage.input_tokens` /
`output_tokens` (alias `gen_ai.usage.prompt_tokens` / `completion_tokens`,
`llm.token_count.prompt` / `completion` / `total`, `llm.usage.total_tokens`), cache
and reasoning token counts, `gen_ai.response.finish_reasons`, `gen_ai.response.id`,
`gen_ai.agent.id` / `name` / `version`, `gen_ai.main_agent.id` / `name`,
`gen_ai.conversation.id` (alias `session.id`), `gen_ai.tool.name` /
`type` / `call.id` (alias `tool.name`), `gen_ai.data_source.id`,
`gen_ai.output.type`, `gen_ai.request.max_tokens` / `temperature` / `stream`,
`mcp.method.name` / `session.id` / `protocol.version`, `error.type`,
`server.address`, `server.port`; span name, span kind, duration, status;
scope name; resource `service.name`, `cloud.*`, `faas.name`, `aws.ecs.task.*`,
`k8s.pod.name`, `k8s.namespace.name`. Strings ≤ 256 chars, ≤ 64 keys.

`action` = the operation (`chat`, `execute_tool`, `invoke_agent`, the MCP
method, else the span name ≤ 200); `resource_ref` = the model, the tool, the
agent or data source; `outcome` = `denied` when `error.type` names a denial
(`AccessDenied*`, `Unauthorized*`, `Forbidden`, `403`, `401`), `error` when the
status is ERROR or `error.type` is set, else `success`; `on_behalf_of` =
`authsec.principal`, else `enduser.id`, else `user.id` (span, then resource).

## 6. Never stored

- Prompt, completion and message content: `gen_ai.input.messages`,
  `gen_ai.output.messages`, `gen_ai.system_instructions`, `gen_ai.prompt*`,
  `gen_ai.completion*`, `*_ref` pointers, `gen_ai.retrieval.*` text,
  `gen_ai.memory.*` text and records, `gen_ai.tool.definitions`,
  `gen_ai.tool.call.result`, OpenInference `input.*`, `output.*`,
  `llm.input_messages*`, `llm.output_messages*`, `llm.prompts*`,
  OpenLLMetry `traceloop.entity.input/output`, span events and their attributes,
  span status messages. (Allowlist: anything not in §5 is dropped.)
- Tool-call argument values: `gen_ai.tool.call.arguments` and OpenInference
  `tool_call.function.arguments` become `tool_arguments_sha256` (sha256 hex of
  the value as sent). A digest lets a reviewer match equal calls; it is not
  secrecy for low-entropy arguments.
- Secrets: OTLP tokens (sha256 only), request/response bodies, CloudTrail
  `requestParameters` beyond the parent spec's sanitised facts.

## 7. APIs

Workspace from the token (AuthMiddleware); another workspace's rows read as
absent (empty list, 404 trace). Governance error envelope.

```
GET    /api/iga/v1/agent-runtime/activity                        discovery:read
       ?identity_id=&workload_id=&kind=&outcome=&source=&from=&to=&cursor=&limit= (1..200, default 50)
       newest first (occurred_at, id); meta.next_cursor
GET    /api/iga/v1/agent-runtime/activity/traces/:trace_id       discovery:read
       {trace_id, spans: [...roots with children], count, truncated}; ≤ 2,000 spans; 404 when none
GET    /api/iga/v1/agent-runtime/activity/coverage               discovery:read   span cursors per connector/region
GET    /api/iga/v1/agent-runtime/activity/settings               discovery:read
PUT    /api/iga/v1/agent-runtime/activity/settings               discovery:admin  {retention_days}
POST   /api/iga/v1/agent-runtime/otlp-tokens                     discovery:admin  {label, expires_in_days?} → token once
GET    /api/iga/v1/agent-runtime/otlp-tokens                     discovery:read
DELETE /api/iga/v1/agent-runtime/otlp-tokens/:id                 discovery:admin
```

Writes need a verified workspace member (humanActor) and write `audit_events`.

## 8. Limits

| | |
|---|---|
| OTLP request | 4 MB compressed and decompressed; ≤ 10,000 spans |
| OTLP rate | 20 req/s per token, burst 40 (env) |
| Row | action 200, resource_ref 512, on_behalf_of 256, attrs 64 keys / 256-char strings / 16 KB |
| AgentCore scan | 1 query × 1,000 spans per region per scan; 60 s poll |
| Trace read | 2,000 spans |
| Event age | dropped when older than retention or > 1 h in the future |

## 9. Tenancy and safety

New tables RLS-enabled with `workspace_id` FK; every statement under
`tenancy.InWorkspace` / `InWorkspaceRead` except the token-hash lookup and the
retention job's workspace listing (TENANT-EXEMPT, ids only). New Go files in
`scripts/tenant-rls-files.txt`; the ratchet stays at 72. Tests: sink writes
labelled identities only and is idempotent; OTLP token of A cannot write into
B; timeline and trace APIs isolated; the trigger refuses UPDATE and an
unflagged DELETE.

## 10. Affected repos

| Repo | What changes | Why |
|---|---|---|
| `authsec` | migration 155, sink, span scan, OTLP receiver, APIs, retention | server work |
| `Authsec-ui` | Activity tab on agent / AI-workload detail, trace tree, OTLP token page | later change |
| `sdk-authsec` | none | agents send standard OTLP; no SDK method needed |
| `authsec-doc` | OTLP exporter setup, AgentCore Transaction Search, role permissions | customer setup |
| Production K3s | ingress path `/authsec/ingest/otlp/v1/traces`, body limit ≥ 4 MB | new public ingest |

## 11. Open questions

1. **Q1** Should OTLP attribution by resource attributes (asserted by the
   sender) be allowed to name an identity, or only a workload? (Built: both,
   recorded as `asserted`.)
2. **Q2** Should spans the normaliser does not recognise be kept as `agent_step`
   rows when they belong to a trace that has GenAI spans? (Built: dropped.)
3. **Q3** Keyed digest (HMAC with a per-workspace key) instead of plain sha256
   for tool arguments?
