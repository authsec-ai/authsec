# P0 — Complete schema, functions & API contracts (all phases) · v4.2.1 · Step 1 locked

**v4.2 (consistency):** watermark workspace-scoped + filter-independent scan + start-at-creation (in T24 + inventory); `activity_alert_status_history` full DDL + `workspace_id`; `OBS_CONSOLE`→`OBS_MONITOR`+`OBS_ALERTS`; `telemetry_enabled` config endpoint (`PUT /monitor/applications/:id/telemetry`); SDK reporting = bounded best-effort + Hydra introspect-once; SDK `at-least-once` mislabels fixed.

**v4.1 deltas:** `token.validation_denied` event + emit; `?token_key=` filter; ingest per-event rejection + `session_id`/`operation_id` + `tool.*`-only restriction + heartbeat empty-report + JSON-RPC-id canonicalization; `tokens.active`→`unexpired_known_tokens`; `DeliveryConfig`/`AlertRuleSetting` DTOs; webhook SSRF + replay-safe signature + `activity_delivery_watermark`; coverage terminal set incl. denied/not_executed; retention/alerts on `received_at`.

**Companion to** [`p0-observability-spec.md`](./p0-observability-spec.md) (design) and [`p0.1-tickets.md`](./p0.1-tickets.md) (P0.1 execution).
**Purpose:** the fixed, buildable contract for **P0.1→P0.5** — data model, Go surface, exact DTOs, per-phase tickets, dependency graph, flags, rollout, failure/recovery — so the mock UI and the backend implement identical meanings.
**v4 fixes:** application_telemetry→P0.2 (config-driven, real health fields); valid rollup PK; token model (`token_kind`, `token_key`, `token_expires_at`, `delegation.issued` for ID-JAG); per-token receipt envelope; exact DTOs + monitor metric semantics; per-endpoint cursor keys; durable delivery queue; alert ack storage; P0.2–P0.5 tickets; dependency graph; feature flags; empty-state; failure/recovery.
**Conventions:** single-state bootstrap (inline `CREATE TABLE`, wipe+re-bootstrap, never `ALTER`); `controllers/platform/*`→`services/*` (`db` from `config.DB`); `register*Routes(r gin.IRouter)` under `/authsec`. **Guards:** *console* = `AuthMiddleware + RequireWorkspaceRole("owner","admin") + ValidateWorkspaceFromToken`; *ingest* = RS Basic auth (`rs_id:introspection_secret`). All new `workspace_id` are `uuid`.

---

# 1. Data model

New tables, phase-tagged:

| Table | Phase | Role |
|---|---|---|
| `agent_activity_events` | P0.1 | correlated event spine |
| `application_telemetry` | **P0.2** | per-application ingest health / coverage (moved from P0.3 — health begins when ingest begins) |
| `activity_alerts` + `activity_alert_status_history` | P0.4 | detection output + ack/resolve audit |
| `alert_rule_settings` | P0.4 | per-workspace rule thresholds |
| `activity_daily_rollup` | P0.3 (optional) | monitor pre-aggregation |
| `activity_delivery_config` | P0.5 | delivery destinations |
| `activity_delivery_queue` | P0.5 | durable delivery + dead-letter |
| `activity_delivery_watermark` | P0.5 | per-destination fan-out cursor (workspace-scoped) |

### 1.1 `agent_activity_events` (P0.1)
Full DDL in spec §3.1, with these **v4 column changes:**
```sql
    token_kind      text,                    -- access_token | id_jag
    token_key       text GENERATED ALWAYS AS (COALESCE(token_jti, token_ref)) STORED,  -- canonical token id
    token_expires_at timestamptz,            -- for tokens.unexpired_known (Hydra + native)
```
Idempotency unchanged: `UNIQUE (workspace_id, reporter_id, source_event_id, event_type)`. Extra index `idx_aae_ws_tokenkey ON (workspace_id, token_key)` for token metrics. Metrics/joins use `token_key`, never bare `token_jti`.

### 1.2 `application_telemetry` (P0.2) — ingest health (not delivery health)
`telemetry_enabled` is **application configuration**, never the SDK payload. 24h completeness is **recomputed** (not lifetime counters).
```sql
CREATE TABLE public.application_telemetry (
    workspace_id       uuid NOT NULL,
    application_id     uuid NOT NULL,           -- resource_server_id
    telemetry_enabled  bool NOT NULL DEFAULT false,   -- SET FROM APPLICATION CONFIG, not ingest
    reporting_config_source text,               -- P0: 'admin' is the only writer (the PUT endpoint, T8); 'manifest'/'default' reserved for later
    telemetry_started_at timestamptz,           -- first ingest observed
    last_heartbeat_at  timestamptz,             -- last ingest of any kind
    last_event_at      timestamptz,
    last_ingest_error_at timestamptz, last_ingest_error text,
    last_sdk           text, last_sdk_version text,
    -- 24h completeness recomputed by the coverage job (NOT monotonic counters):
    window_start       timestamptz,             -- start of the current observation window
    requested_in_window bigint NOT NULL DEFAULT 0,
    terminal_in_window  bigint NOT NULL DEFAULT 0,
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT application_telemetry_pkey PRIMARY KEY (workspace_id, application_id)
);
```
`telemetry_enabled` is written by the application-config path (admin toggling telemetry on an RS), read at ingest; the SDK's `telemetry_enabled` in the payload is advisory only and ignored for coverage. Completeness columns are refreshed from events by the coverage job on a rolling window; ingest updates only `last_*`/`telemetry_started_at`.

### 1.3 `activity_daily_rollup` (P0.3, optional) — valid PK (no expressions)
Sentinel-non-null columns → plain composite PK.
```sql
CREATE TABLE public.activity_daily_rollup (
    workspace_id uuid NOT NULL, day date NOT NULL,
    application_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    oauth_client_id text NOT NULL DEFAULT '',
    tool_name text NOT NULL DEFAULT '',
    allow bigint NOT NULL DEFAULT 0, deny bigint NOT NULL DEFAULT 0,
    success bigint NOT NULL DEFAULT 0, error bigint NOT NULL DEFAULT 0,
    tokens_issued bigint NOT NULL DEFAULT 0,
    p50_latency_ms int, p95_latency_ms int,
    CONSTRAINT activity_daily_rollup_pkey PRIMARY KEY
      (workspace_id, day, application_id, oauth_client_id, tool_name)
);
```

### 1.4 `activity_alerts` (P0.4) — with ack storage
Spec §8.1 DDL **plus**:
```sql
    note text, acknowledged_by text, acknowledged_at timestamptz, resolved_by text, resolved_at timestamptz,
```
Status transitions append to:
```sql
CREATE TABLE public.activity_alert_status_history (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    alert_id uuid NOT NULL,
    from_status text, to_status text NOT NULL,
    actor text, note text,
    at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT activity_alert_status_history_pkey PRIMARY KEY (id)
);
CREATE INDEX idx_aash_alert ON public.activity_alert_status_history (workspace_id, alert_id, at DESC);
```

### 1.5 `alert_rule_settings` (P0.4)
```sql
CREATE TABLE public.alert_rule_settings (
    workspace_id uuid NOT NULL,
    rule_key text NOT NULL,             -- revoked_token_use | repeated_denials | repeated_tool_failures | access_after_suspension
    enabled bool NOT NULL DEFAULT true,
    threshold_n int, window_seconds int, severity text,   -- NULL → platform default for that rule
    updated_by text, updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT alert_rule_settings_pkey PRIMARY KEY (workspace_id, rule_key)
);
```
Absent row → platform default for that rule.
**Dedup / active-incident:** the `activity_alerts` fingerprint index covers `status IN ('open','ack')` (spec §8.1) — `ack` keeps one active incident (no duplicate spawned on acknowledge); `resolved`/`muted` close it and a later recurrence opens a new incident.

### 1.6 `activity_delivery_config` (P0.5) — destinations only (spec §8.2).

### 1.7 `activity_delivery_queue` (P0.5) — durable, with worker lease + payload snapshot
Snapshots the redacted outbound payload so retention deleting the source event never breaks delivery.
```sql
CREATE TABLE public.activity_delivery_queue (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    delivery_config_id uuid NOT NULL,        -- ON DELETE the worker drops pending rows for it
    event_id uuid NOT NULL,
    payload jsonb NOT NULL,                  -- redacted snapshot; delivery does not re-read the event
    status text NOT NULL DEFAULT 'pending',  -- pending | delivering | delivered | dead_letter
    attempts int NOT NULL DEFAULT 0, max_attempts int NOT NULL DEFAULT 8,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    locked_by text, locked_until timestamptz, -- worker lease; recover rows where locked_until < now()
    last_error text, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT activity_delivery_queue_pkey PRIMARY KEY (id),
    CONSTRAINT uq_adq_once UNIQUE (delivery_config_id, event_id)   -- fan-out dedup: one row per (destination,event)
);
CREATE INDEX idx_adq_due ON public.activity_delivery_queue (status, next_attempt_at)
  WHERE status IN ('pending','delivering');
```
Durable per-destination fan-out watermark (resumable, exactly-enqueues-once):
```sql
CREATE TABLE public.activity_delivery_watermark (
    workspace_id       uuid NOT NULL,
    delivery_config_id uuid NOT NULL,
    last_received_at   timestamptz NOT NULL,   -- initialized to the config's created_at (NOT epoch — no 90-day backfill)
    last_event_id      uuid,
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT activity_delivery_watermark_pkey PRIMARY KEY (workspace_id, delivery_config_id)
);
```
**Enqueue worker (fan-out), per enabled config, in one tx:** scan events **independently of the filter** with the tuple cursor `(received_at, event_id) > (last_received_at, last_event_id)` up to a batch bound; insert `activity_delivery_queue` rows **only for events matching `event_filter`** (snapshot redacted payload; `uq_adq_once` makes re-runs idempotent); then **advance the watermark to the last *scanned* event** (not the last *matched* one) — otherwise a destination whose filter matches nothing re-scans the same range forever. A new config starts at its `created_at`, so enabling delivery never dumps the 90-day history. Not on the enforcement path.
**Delivery worker:** `SELECT … WHERE status='pending' AND next_attempt_at<=now() FOR UPDATE SKIP LOCKED LIMIT n`; set `status='delivering', locked_by, locked_until=now()+lease`; on success→`delivered`; on failure→`attempts++`, backoff `next_attempt_at`, `dead_letter` at `max_attempts`. A recovery sweep resets `delivering` rows with `locked_until<now()` to `pending`. Webhook POST is SSRF-guarded + replay-safe-signed (§4.5). Deleting a `delivery_config` drops its pending rows + watermark; retention deleting a source event is safe (payload snapshotted).

---

# 2. Shared Go packages
`internal/activity` — `Event` struct (see tickets T2), `RecordTx` / `RecordBestEffort` / `RecordBatchBestEffort` (short-timeout), `DeriveSessionID`, `SourceEventIDFromJTI` / `SourceEventIDFromAudit`.
`internal/activity/receipt` (P0.2) — `Mint` / `Verify` / `TokenRef(raw)→(ref,refKID)` (spec §5.5).

---

# 3. Common contracts (apply to every endpoint)

- **Timestamps:** RFC 3339 UTC strings, `Z` suffix, ms precision — e.g. `"2026-07-19T16:40:11.482Z"`.
- **Nullability:** `field?: T | null` — explicit; UI must handle null.
- **Pagination:** cursor-based. Response carries `next_cursor: string | null` (opaque base64). `has_more = next_cursor != null`. **Per-endpoint sort key** (there is no universal cursor):
  | Endpoint | sort key (cursor encodes) |
  |---|---|
  | events / timeline | `occurred_at DESC, event_id` |
  | alerts | `last_seen DESC, id` |
  | applications | `name ASC, application_id` |
  | delivery configs | `created_at DESC, id` |
- **Errors:** `{ "error": ErrorCode, "error_description"?: string }`. `ErrorCode ∈ unauthorized(401) | forbidden(403) | invalid_request(400) | not_found(404) | rate_limited(429) | conflict(409) | internal(500)`.
- **Empty state:** list endpoints return `{ <items>: [], next_cursor: null }` (never 404). Monitor returns zeroed counters + `coverage.status` reflecting instrumentation.
- **Enums (fixed):**
  - `Category = token | authz | tool | admin`
  - `EventType = token.issued | token.revoked | delegation.issued | token.validation_denied | authz.allowed | authz.denied | tool.requested | tool.allowed | tool.denied | tool.completed | tool.failed | tool.not_executed | admin.role_changed | admin.scope_changed | admin.policy_changed | admin.client_disabled | admin.identity_suspended | admin.token_revoked`
  - `Outcome = allow | deny | success | error | not_executed | null`
  - `ValidationReason = revoked | suspended | rbac_revoked | registration_revoked | inactive` (on `token.validation_denied`, in `reason`)
  - `TokenKind = access_token | id_jag`
  - `GrantType = client_credentials | jwt-bearer | token-exchange | ciba | authorization_code | refresh_token`
  - `Transport = http | sse | streamable`
  - `CoverageStatus = complete | partial | not_instrumented | reporting_delayed`
  - `AlertStatus = open | ack | resolved | muted` · `Severity = low | medium | high | critical`
  - `RuleKey = revoked_token_use | repeated_denials | repeated_tool_failures | access_after_suspension` (P0.4)

---

# 4. DTOs & endpoints, per phase

### 4.1 P0.1 — Events
```ts
interface ActivityEvent {
  event_id: string; workspace_id: string;
  occurred_at: string; received_at: string;
  producer: string; category: Category; event_type: EventType; outcome: Outcome | null;
  tool_call_id: string | null; mcp_request_id: string | null; operation_id: string | null;
  request_id: string | null; session_id: string | null;
  token_jti: string | null; token_ref: string | null; token_key: string | null;
  token_ref_verified: boolean; token_engine: "native" | "hydra" | null;
  token_family: "m2m" | "xaa" | "ciba" | null; grant_type: GrantType | null;
  token_kind: TokenKind | null; token_expires_at: string | null; source_grant_jti: string | null;
  oauth_client_id: string | null; actor_client_id: string | null; actor_spiffe_id: string | null;
  subject_type: "user" | "service_account" | null; subject_id: string | null;
  owner_email: string | null; owner_team: string | null;
  application_id: string | null; connector_id: string | null; tool_name: string | null;
  scopes_requested: string[] | null; scopes_granted: string[] | null;
  transport: Transport | null; http_status: number | null; jsonrpc_error_code: number | null;
  mcp_is_error: boolean | null; latency_ms: number | null;
  error_category: string | null; reason: string | null; attributes: Record<string, unknown>;
}
```
`GET /authsec/activity/events` (console) — query `from,to,event_type,category,outcome,client_id,application_id,tool_call_id,token_key,token_jti,reason,cursor,limit` → `{ events: ActivityEvent[], next_cursor: string | null }`. Use `token_key` to filter across both native + Hydra (bare `token_jti` is native-only). `from/to` filter on `received_at`.

### 4.2 P0.2 — Ingest (per-token report envelope)
```ts
interface ToolEventsRequest {
  reporter: { sdk: string; sdk_version: string };   // rs_id from Basic auth
  reports: Array<{                                   // ONE observed token per report
    activity_receipt?: string;                       // Hydra: signed JWT (SDK never sends token_ref)
    token_jti?: string;                              // native: the jti
    events: Array<{
      source_event_id: string; tool_call_id: string;
      mcp_request_id: string | null;     // TYPE-PRESERVING canonical id: "n:3" (number) | "s:3" (string) | "null:<tool_call_id>" (JSON-RPC null). Numeric 3 and string "3" must NOT collide.
      event_type: "tool.requested" | "tool.allowed" | "tool.denied" | "tool.completed" | "tool.failed" | "tool.not_executed";  // tool.* ONLY — token/authz/admin rejected
      tool_name: string; session_id?: string; operation_id?: string;
      scopes_requested?: string[]; transport?: Transport;
      http_status?: number; jsonrpc_error_code?: number; mcp_is_error?: boolean;
      latency_ms?: number; error_category?: string; reason?: string;
      occurred_at: string; arguments_meta?: Record<string, unknown>; result_meta?: Record<string, unknown>;
    }>;
  }>;
}
interface ToolEventsResponse { accepted: number; duplicates: number; rejected: number;
  rejections: Array<{ source_event_id: string; reason: string }>;   // per-event; partial success
  refs_verified: Record<string, boolean>; }   // keyed by token_key
```
`POST /authsec/activity/tool-events` (RS Basic auth). **Atomicity is per-event, not per-batch:** a malformed/duplicate event is rejected individually (listed in `rejections`) while the rest are accepted; but a **failed receipt/token-ref verification rejects that whole *report*** (all its events). Each report supplies exactly one of `activity_receipt` | `token_jti`; AuthSec derives `token_ref`/identity from it and **ignores any identity/workspace/application on the events**. Only `tool.*` types are accepted (server-side event types can't be injected by an RS). **Heartbeat:** an empty request `{"reporter":{…},"reports":[]}` is a valid liveness ping — it refreshes `application_telemetry.last_heartbeat_at` and returns `{accepted:0,…}`. `POST /oauth/introspect` (existing) gains `activity_receipt` on active+authorized responses.

### 4.3 P0.3 — Monitor / Timeline / Access / Coverage
```ts
interface ApplicationSummary { application_id: string; name: string; application_type: string;
  active_agents_24h: number; requests_24h: { allow: number; deny: number };
  open_alerts: number; coverage: CoverageStatus; }
interface ApplicationMonitor {
  application: { id: string; name: string; application_type: string };
  window: "24h" | "7d";
  active_agents: number; active_users: number;
  tokens: { issued: number; delegations: number; revoked: number; unexpired_known: number };  // NOT "active": Hydra revocation may be unknown locally (§5)
  requests: { allow: number; deny: number };
  top_tools: Array<{ tool_name: string; calls: number; deny: number; errors: number; p95_ms: number | null }>;
  failed_tools: Array<{ tool_name: string; errors: number; top_error_category: string | null }>;
  unused_scopes: string[]; open_alerts: number; coverage: CoverageStatus;
}
interface TimelineResponse { identity: { type: "user"|"agent"|"service_account"; id: string; owner_email: string | null };
  events: ActivityEvent[]; next_cursor: string | null; }
interface GrantedVsUsed { identity: string; coverage: CoverageStatus;
  rows: Array<{ scope: string; tools: string[]; used: boolean; denied_attempts: number;
    finding: "keep" | "review" | "remove" | "investigate" | "insufficient_coverage" }>; }
interface CoverageRow { application_id: string; status: CoverageStatus;
  telemetry_enabled: boolean; last_event_at: string | null; last_sdk_version: string | null; }
```
Endpoints (console): `GET /monitor/applications`→`{applications:ApplicationSummary[], next_cursor}`; `GET /monitor/applications/:id`→`ApplicationMonitor`; `GET /activity/timeline?subject=|client=`→`TimelineResponse`; `GET /access/granted-vs-used?identity=`→`GrantedVsUsed`; `GET /monitor/coverage`→`{applications: CoverageRow[]}`.
> `open_alerts` **returns a documented `0`** until P0.4 lands `activity_alerts` (gated by `OBS_ALERTS`/P0.4); the field is present from P0.3 so the UI contract doesn't change when alerts arrive. Timeline honors the XAA cross-workspace visibility rule (spec §4): it shows only the queried workspace's events.

### 4.4 P0.4 — Alerts
```ts
interface Alert { id: string; rule_key: RuleKey; severity: Severity; status: AlertStatus;
  identity_type: string | null; identity_id: string | null; application_id: string | null;
  tool_name: string | null; token_key: string | null;
  first_seen: string; last_seen: string; event_count: number;
  summary: string; suggested_action: string | null; related_event_ids: string[];
  note: string | null; acknowledged_by: string | null; acknowledged_at: string | null;
  resolved_by: string | null; resolved_at: string | null; }   // token_key (not token_jti) — see field above
```
```ts
interface AlertRuleSetting { rule_key: RuleKey; enabled: boolean;
  threshold_n: number | null; window_seconds: number | null; severity: Severity | null; }  // null → platform default
```
`GET /monitor/alerts?status,severity,cursor`→`{alerts:Alert[], next_cursor}`; `POST /monitor/alerts/:id/ack` body `{status:"ack"|"resolved"|"muted", note?}`→`{updated:true}` (writes ack fields + status history); `GET /monitor/alert-rules`→`{rules:AlertRuleSetting[]}`; `PUT /monitor/alert-rules/:rule_key` body `AlertRuleSetting`→`{updated:true}`.

### 4.5 P0.5 — Export / Delivery
```ts
interface DeliveryConfig { id: string; kind: "webhook"; endpoint_url: string;   // secret write-only → Vault, never returned
  event_filter: { event_type?: EventType[]; category?: Category[]; outcome?: Outcome[] };
  enabled: boolean; created_at: string; }
interface DeliveryConfigCreate { kind: "webhook"; endpoint_url: string; secret: string;   // secret goes straight to Vault
  event_filter?: DeliveryConfig["event_filter"]; enabled?: boolean; }
```
`GET /authsec/activity/events?format=csv|json` (console, same filters, streamed). `GET /activity/delivery`→`{configs:DeliveryConfig[]}`; `POST /activity/delivery` (`DeliveryConfigCreate`); `PUT/DELETE /activity/delivery/:id`.
**Outbound webhook (SSRF- & replay-safe):** `POST {endpoint_url}` — **HTTPS only**, destination host resolved and **blocked if private/link-local/metadata** (127/8, ::1, RFC1918, 169.254.0.0/16 incl. 169.254.169.254, fc00::/7) with a DNS-rebind pin. Headers: `X-AuthSec-Timestamp`, `X-AuthSec-Delivery-Id`, `X-AuthSec-Signature: sha256=HMAC(secret, timestamp + "." + body)`; receiver rejects stale timestamps + replayed delivery-ids. Body = the redacted queued payload snapshot.

---

# 5. Monitor metric semantics (fixed definitions — no ambiguity)

- **`requests.allow` / `requests.deny`:** count **tool decisions** only — `event_type ∈ {tool.allowed, tool.denied}` (not `authz.*` mint-time, and not `token.validation_denied` which is a token rejection, surfaced separately as a security signal). One decision per `tool_call_id`.
- **A "call":** identified by `tool_call_id`; "calls" counts `DISTINCT tool_call_id` with a `tool.requested`. Terminal per call ∈ `{tool.completed, tool.failed, tool.denied, tool.not_executed}`.
- **`active_agents`:** `DISTINCT oauth_client_id` with any event in the window (default 24h, by `received_at`).
- **`tokens.issued`:** `DISTINCT token_key WHERE token_kind='access_token'` in window. **`tokens.delegations`:** `DISTINCT token_key WHERE token_kind='id_jag'`. **`tokens.unexpired_known`** (not "active"): access tokens whose `token_expires_at > now()` and not in `revoked_tokens` — honest naming because **Hydra revocation may not be locally known** (`revoked_tokens` is native-only); it counts tokens AuthSec has *no local reason to believe are dead*. **`tokens.revoked`:** `token.revoked` count.
- **`top_tools` window:** same window as the monitor (24h default, 7d toggle); ranked by `calls`.
- **Hydra + native combined** everywhere via `token_key = COALESCE(token_jti, token_ref)`.

---

# 6. Per-phase tickets

**P0.1** — see [`p0.1-tickets.md`](./p0.1-tickets.md) (T1–T7, v4-corrected).

**P0.2 — RS-authenticated SDK reporting + Hydra receipt + telemetry health**
- T8 Schema: `application_telemetry` (§1.2) **+ the config write path** — `PUT /authsec/monitor/applications/:id/telemetry` body `{enabled: boolean}` (console guard) sets `telemetry_enabled` + `reporting_config_source='admin'`. This is the **only** writer of `telemetry_enabled`; the SDK payload never sets it. T9 `internal/activity/receipt` (Mint/Verify/TokenRef). T10 `Introspect` change: return `activity_receipt` on active+authorized only, **and emit `token.validation_denied` on the reject path** (reason from the failure). T11 `ActivityIngestService`/`ActivityIngestController` (`POST /activity/tool-events`, per-token envelope, per-event rejection, `tool.*`-only, heartbeat, idempotent, updates telemetry `last_*`/`last_heartbeat_at`). T12 Hydra `token.issued` emitters at authcode+refresh grant success — **best-effort/outbox, NOT in-tx** (receipt = introspection, not issuance; Hydra already minted). T13 SDK reporting in Go/Python/TS (emit requested/allowed/denied + MCP-classified completed/failed; canonicalize `mcp_request_id`; **bounded best-effort + idempotent retry**, and for Hydra introspect-once to obtain + retain `activity_receipt` from `Principal.Claims`, else mark coverage `partial`). T14 ingest metrics (`activity_ingest_accepted_total`, `_duplicates_total`, `_rejected_total`).
- Exit: an SDK-enforced (non-broker) tool call — allowed and denied — appears with verified native `token_jti` and Hydra `token_ref`; telemetry health rows populate.

**P0.3 — Application Monitor + Timeline + Granted-vs-used + Coverage**
- T15 `MonitorService` + `MonitorController` (`/monitor/applications*`). T16 `Timeline` (`/activity/timeline`). T17 `AccessAnalysisService` (`/access/granted-vs-used`) gated on coverage. T18 coverage job (rolling recompute of `application_telemetry` completeness) + `/monitor/coverage`. **Two coverage sources by application type:** SDK-instrumented apps (mcp_server/ai_agent) use SDK version + `last_heartbeat_at` + lifecycle completeness; the **managed connector broker** (`application_type='connector_broker'`) emits **server-side** and never sends an SDK heartbeat — its coverage is derived from `OBS_CAPTURE` being on + recent broker activity + `activity_emit_failures_total{producer="broker"}` (emitter-drop health), so it is `complete` when capture is healthy, never `not_instrumented`. T19 (optional) `activity_daily_rollup` + populate job when raw-scan latency shows up.
- Exit: monitor + timeline + granted-vs-used render from real data; findings suppressed when `coverage≠complete`.

**P0.4 — Deterministic alerts**
- T20 Schema `activity_alerts` (+ack fields) + `activity_alert_status_history` + `alert_rule_settings`. T21 `AlertEvaluator` worker (4 time-gated rules, dedup, honors settings). T22 `AlertService`/`AlertsController` (list/ack/rules). T23 `activity_alerts_open` gauge.
- Exit: revoked-token-use / repeated-denials / repeated-failures / access-after-suspension fire correctly (time-gated), ack persists + audits.

**P0.5 — Export + durable webhook**
- T24 Schema `activity_delivery_config` + `activity_delivery_queue` + **`activity_delivery_watermark`** (workspace-scoped). T25 `DeliveryWorker` (filter-independent scan + tuple-cursor watermark advance to last *scanned*, fan-out enqueue, SKIP LOCKED, lease recovery, backoff, dead-letter, SSRF-guarded + replay-safe HMAC sign). T26 `DeliveryService`/`DeliveryController` CRUD (new config watermark starts at `created_at`). T27 export endpoint (csv/json stream). T28 retention sweep (platform-wide scheduled delete keyed on `received_at`) + delivery metrics.
- Exit: an event matching a webhook filter is delivered at-least-once with signature, survives source-event deletion (payload snapshot), retries + dead-letters; CSV/JSON export works.

---

# 7. Dependency graph & phase exit gates
```
P0.1 (spine + capture + events API)
  └─ P0.2 (ingest + receipt + telemetry health)   [needs: Event contract, receipt pkg]
       └─ P0.3 (monitor/timeline/access/coverage)  [needs: full capture incl SDK, application_telemetry]
            ├─ P0.4 (alerts)                        [needs: complete event stream + revoked/suspension state]
            └─ P0.5 (export + delivery)             [needs: event stream; independent of P0.4]
```
Each phase is merged only when its **Exit** (above) passes on stage after wipe+re-bootstrap. P0.4 and P0.5 can proceed in parallel after P0.3.

# 8. Feature flags & rollout order
- `OBS_CAPTURE` (P0.1): master switch for server-side emit. Default on in stage, staged in prod. Emit is best-effort/in-tx per producer; flag off = no rows written, enforcement unaffected.
- `OBS_INGEST` (P0.2): enables `/activity/tool-events` + `activity_receipt` in introspection. Off = SDK reports rejected `404`/`disabled`, native/broker capture continues.
- `OBS_MONITOR` (P0.3): exposes monitor/timeline/coverage/granted-vs-used read APIs + UI nav.
- `OBS_ALERTS` (P0.4): exposes alert routes — **gated separately** so alert endpoints cannot be hit before the `activity_alerts` schema exists (splitting the old single `OBS_CONSOLE`).
- `OBS_DELIVERY` (P0.5): enables the delivery worker + config CRUD.
Rollout: enable `OBS_CAPTURE` on stage → dogfood mcpauthz → prod. Then per-phase flags in dependency order. Flags are per-deployment (env), not per-workspace, in P0.

# 9. Empty-state & backfill
- **No backfill.** The spine starts empty at `OBS_CAPTURE` enable; historical `connector_action_audit`/`native_tokens` are **not** replayed in P0 (possible later as a one-off importer). Monitor/timeline show honest "no activity yet" until events accrue.
- Coverage for an app with no telemetry = `not_instrumented`; granted-vs-used returns `finding:"insufficient_coverage"` until a complete window exists.
- Every list endpoint returns `[]` + `next_cursor:null` when empty.

# 10. Operational failure & recovery
- **Emit failure (best-effort producers):** counted in `activity_emit_failures_total{producer}`; alert on rate. No enforcement impact. Gap is visible (coverage `partial`).
- **Ingest down / SDK retries:** **bounded best-effort + idempotency** — SDK retries within limits then drops + counts (NFR); no durable SDK-local queue in P0, so it is not at-least-once. Duplicate submissions are no-ops.
- **Coverage job lag:** `reporting_delayed` status; findings withheld.
- **Delivery:** stuck `delivering` rows recovered by lease expiry sweep; permanent failures → `dead_letter` + metric; deleting a `delivery_config` drops its pending rows; retention deleting a source event is safe (payload snapshotted).
- **Receipt key compromise:** rotate `activity_token_ref_key` (new `ref_kid`); old Hydra tokens split old/new `token_ref` (accepted, spec §5.5).

# 11. Open items (before the owning phase; none block UI/UX)
- P0.2: `activity_token_ref_key` rotation cadence; SSE/streamable terminal-state details (spec §5.4); redaction allowlist (NFR).
- P0.3: `session_id` precedence (derived vs SDK-supplied); whether `activity_daily_rollup` is needed at expected volume.
- **Resolved (removed from open):** same-tx vs outbox — decided per producer (spec §6): issuance in-tx, broker/admin best-effort.
