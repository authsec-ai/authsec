# SPEC: Agent runtime — model provider usage (OpenAI, Anthropic)

> **Status: built 2026-11-05 on `feat/agent-runtime-provider-usage`** (migration
> 154). Opt-in per workspace. Pending Aditya's review (decision record below).
>
> Context: [SPEC-agent-runtime-visibility.md](SPEC-agent-runtime-visibility.md)
> (rev 2 + §10; this spec is one of the sources §2 deferred: "OpenAI/Anthropic
> admin APIs"), migration 148 (`agent_finding`).

## Summary

A workspace may connect its OpenAI and Anthropic organisations with an
organisation **admin key**. AuthSec then reads, hourly, the organisation's API
keys (with their project / workspace and owner) and the model usage per API
key, project and model in one-hour buckets, and flags usage nobody can account
for: an API key that used models in the last 7 days and that no AWS workload
of the workspace can be tied to, even weakly. That is the shadow agent the AWS
sources cannot see — a program calling a model provider directly with a key
that appears nowhere in the workspace's discovered configuration.

AuthSec never reads prompts or completions (the provider usage APIs carry
none), never calls a write endpoint of the provider, and never returns or logs
the admin key.

## Decision record

- **Ritam 2026-11-05: build opt-in despite the review-2 concern; pending
  Aditya.** Review 2 of SPEC-agent-runtime-visibility.md said "holding
  customers' OpenAI and Anthropic admin keys makes AuthSec a high-value
  target; leave out of the AWS pilot". The product owner decided to build it
  as an **opt-in** feature with the mitigations of §2. Nothing runs for a
  workspace until one of its administrators connects an organisation.
  Aditya's sign-off is pending; until then the feature stays out of the pilot
  scope of SPEC-agent-runtime-visibility.md and its findings are labelled
  with their weak basis (§5).

## 1. Requirements

| # | Requirement |
|---|---|
| U1 | An administrator connects an OpenAI or Anthropic organisation with an admin key; the key is validated with one read call before anything is stored |
| U2 | AuthSec lists the organisation's API keys: id, name, project / workspace, owner (user or service account), created, last used, status |
| U3 | AuthSec stores hourly usage per (key, project, model): requests (OpenAI only), input and output tokens |
| U4 | A key is tied to AWS workloads only weakly, by name agreement (§5), never by a value |
| U5 | Usage on a key with no such tie in the last 7 days raises `unaccounted_model_usage`; it resolves when usage stops for 30 days or a tie appears |
| U6 | The admin key is write-only: stored in Vault per workspace, never returned, never logged; rotation and revocation are audited |

## 2. Threat model and mitigations

**Asset:** an organisation admin key. With it an attacker can create and
delete API keys, invite users and read usage of the customer's provider
organisation. AuthSec holding many such keys makes it a target (review 2).

| Threat | Mitigation (built) |
|---|---|
| AuthSec's database is read (SQL injection, backup leak) | The key is not in the database: only its Vault path (`secret_ref`) and a **fingerprint** (`...<last 4> sha256:<12 hex>`) are. Vault path `kv/data/secret/workspaces/<ws>/agent-runtime/model-provider-<connection>-<nonce>`, per workspace, as the SIEM secrets (`agent_runtime_alert_siem.go`) |
| The key leaks through the API | Write-only: `admin_key` is accepted by connect and rotate only; no response contains it, nor any part beyond the fingerprint |
| The key leaks through logs or errors | The key is never formatted into a log line or an error; provider error bodies are truncated and scrubbed of anything shaped like a key (`sk-…`) before they are stored in `last_error` or logged |
| A workspace uses another workspace's key or reads its data | Workspace from the token only (AuthMiddleware); every statement under RLS for that workspace (`tenancy.InWorkspace` / `InWorkspaceRead`); another workspace's connection is 404 |
| AuthSec is made to send the key elsewhere (SSRF, redirect) | Fixed provider hosts (`https://api.openai.com`, `https://api.anthropic.com`) compiled in; no tenant-supplied URL; **redirects are refused** (Go forwards custom headers such as `x-api-key` across hosts on redirect) |
| AuthSec misuses the key (writes to the customer's organisation) | The clients have one HTTP method, GET, and only the read endpoints of §6; a unit test fails on any other method or path |
| Over-collection / provider rate limits | Minimum polling: one sync per connection per hour; a manual sync at most every 5 minutes; usage re-read only from the last high-water mark (2 h overlap for late data), at most 30 days the first time; 429 honoured with `Retry-After` |
| A revoked or rotated key lingers | Revoke (DELETE) marks the connection revoked and destroys the Vault secret (all versions, `vault.Destroy`) after the commit; rotate writes the new key at a new path and destroys the old path; a connection whose key the provider refuses (401/403) stops syncing (`status=error`) until rotated or synced by hand |
| An insider or a compromised admin connects or revokes silently | Every connect, rotate, revoke and manual sync writes an `audit_events` row (`auditAdminMutation`) with the connection id, provider, organisation and fingerprint — never the key |
| A stale key keeps working after the customer leaves | Revocation is the customer's and AuthSec's: the console states that the customer should also revoke the key at the provider |

**Customer guidance** (shown in the console and the docs): create a
**dedicated** admin key named for AuthSec, use it nowhere else, rotate it
regularly (rotate endpoint), revoke it at the provider when disconnecting.

**Not mitigated:** neither provider offers a read-only admin key today (the
Admin API keys are organisation-wide); an AuthSec process with Vault access can
read the key. Both are the reason for opt-in.

## 3. Scope

**In:** OpenAI organisations (Admin API), Anthropic organisations (Admin API);
keys, usage, OpenAI key audit events; weak attribution to AWS workloads; the
`unaccounted_model_usage` finding; the routes of §7.

**Out:** cost (USD) reports; Google, Azure OpenAI, Bedrock (Bedrock is covered
by CloudTrail, SPEC-agent-runtime-visibility.md §5.1); reading request
contents; acting on keys (revoking a customer's provider key); attribution to
Azure or Kubernetes workloads; alerts on unaccounted usage (the finding is the
signal; D-rules may consume it later).

## 4. Data model (migration 154)

All three tables: `workspace_id NOT NULL` with FK to `workspaces` (cascade),
composite `(workspace_id, id)` keys for child FKs, workspace-leading indexes,
and `public.tenancy_enable_rls` (guarded, as 146). Mirrored at the end of
`001_bootstrap.sql`.

- **`model_provider_connection`** — one connected organisation: `provider`
  (`openai|anthropic`), `display_name`, `secret_ref` (Vault path; `''` once
  revoked), `key_fingerprint`, `org_id` / `org_name` as read from the provider
  (OpenAI: the `openai-organization` response header; Anthropic:
  `GET /v1/organizations/me`), `status` (`active|error|revoked`),
  `last_sync_at`, `last_sync_attempt_at`, `next_sync_at`, `sync_lease_until`,
  `usage_cursor` (high-water mark of usage read), `last_error`, `created_by`,
  `created_at`, `revoked_at`, `revoked_by`. **One live connection per
  (workspace, provider, org)** (partial unique index, `status <> 'revoked'`);
  an organisation the provider does not name is `org_id = ''`, so at most one
  such connection per provider.
- **`model_provider_key`** — one provider API key as last listed:
  `provider_key_id`, `name`, `key_hint` (the provider's own redacted hint),
  `project_id` / `project_name` (OpenAI project; Anthropic workspace),
  `owner_type` (`user|service_account|''`), `owner_id`, `owner_name`,
  `created_at_provider`, `last_used_at` (OpenAI's value, else the newest usage
  bucket), `status` (`active|inactive|archived|expired|deleted|unknown`;
  `unknown` = seen in usage but never listed), `links` (weak attribution, §5),
  `first_seen`, `last_seen`. Unique `(workspace_id, connection_id,
  provider_key_id)`.
- **`model_provider_usage`** — one hour of one key on one model:
  `provider_key_id` (`''` for usage without a key, e.g. the Anthropic
  console), `project_id`, `model`, `bucket_start` (hour, UTC), `requests`
  (NULL when the provider does not report a count — Anthropic), `input_tokens`
  (OpenAI: `input_tokens`; Anthropic: uncached + cache read + cache creation),
  `cached_input_tokens`, `output_tokens`. Unique `(workspace_id,
  connection_id, provider_key_id, project_id, model, bucket_start)` (the
  project is in the key so key-less usage of two projects does not collide).
  Rows are **replaced** on re-read (provider totals are final values, not
  increments). Retention 180 days.
- **`agent_finding`** (148) is widened: kind CHECK admits all of
  `shared_role, human_credentials, long_lived_key, model_key_secret,
  ai_config_hint, ai_network_traffic, unaccounted_model_usage` (152 and 153
  add the middle two on other branches; listing all keeps any merge order
  safe); `connector_id` becomes nullable and `provider_connection_id`
  (FK → `model_provider_connection`) is added, with a CHECK that a finding
  names one or the other.

## 5. Attribution (weak) and the finding

A provider key is tied to an AWS identity / workload **only by name
agreement**, never by a value (no secret is read):

1. **Secret name** — a Secrets Manager secret of a connected AWS account
   (the names the resource-policy collector listed, and the secrets grants
   name — the readers logic of `agent_runtime_findings.go`) whose name
   contains the key's name or its project name; the link names the
   identities whose declared allow grants cover `GetSecretValue` on it, and
   the workloads that run as them. A secret no identity may read (as far as
   the declared grants show) ties nothing.
2. **Lambda environment variable name** — a Lambda (newest generation of its
   connector) one of whose env-var NAMES contains the key's name or project
   name.

Matching: both sides lower-cased with everything but `[a-z0-9]` removed;
the key/project name must keep ≥ 4 characters after removing generic words
(`default`, `project`, `workspace`, `openai`, `anthropic`, `claude`, `api`,
`key`, `secret`, `token`, `prod`, `dev`, `test`, `staging`, `admin`), so
"Default project" or "OPENAI_API_KEY" match nothing. Every link is
`strength: weak` with what matched (`key_name|project_name`) and where
(`secret_name|env_var_name`). Links are recomputed on every sync.

**`unaccounted_model_usage`**, per connection and key (subject key
`model_provider:<connection>:<provider_key_id>`):

- **opens** when the key has usage (any tokens or requests) in the last 7
  days and no link; evidence: requests, input/output tokens, models, last
  used, project, owner, window — never a value;
- **stays open** while it has no link and was used in the last 30 days;
- **resolves** when a link appears, when the key has had no usage for 30
  days, or when the connection is revoked.

Usage with no key (`provider_key_id = ''`, console / playground) is never a
finding. A link is weak: the finding means "nothing in the workspace names
this key", not "a shadow agent exists".

## 6. Provider endpoints used (read only)

Verified against the official references on 2026-11-05.

**OpenAI** — `https://api.openai.com/v1`, `Authorization: Bearer <admin key>`:

| Purpose | Endpoint | Reference |
|---|---|---|
| Validate; organisation id from the `openai-organization` response header | `GET /organization/projects?limit=1` | [list projects](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/projects/methods/list), [response headers](https://developers.openai.com/api/reference/overview) |
| Projects (`limit=100`, `after`) | `GET /organization/projects` | as above |
| Project API keys with owner (user or service account) (`limit=100`, `after`) | `GET /organization/projects/{project_id}/api_keys` | [list project API keys](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/projects/subresources/api_keys/methods/list) |
| Text usage (completions, incl. the Responses API) | `GET /organization/usage/completions?start_time&end_time&bucket_width=1h&group_by=api_key_id&group_by=project_id&group_by=model&limit=168&page` | [completions usage](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/usage/methods/completions) |
| Embeddings usage | `GET /organization/usage/embeddings` (same parameters) | [usage](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/usage) |
| Key created / deleted events | `GET /organization/audit_logs?event_types[]=api_key.created&event_types[]=api_key.deleted&effective_at[gte]&limit=100&after` | [audit logs](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/audit_logs/methods/list) |

Notes: OpenAI has **no separate "responses" usage endpoint**; Responses API
text generation is reported by the completions usage endpoint (whose
`api_source` grouping only separates `agents_api` from `unlabeled`). Service
accounts are read from each key's `owner` object, not from the
service-accounts list (one call fewer per project). Audit logs must be
enabled by the organisation; when they are not (the call fails), the sync
continues without them and records nothing about it as an error.

**Anthropic** — `https://api.anthropic.com/v1`, `x-api-key: <admin key>`,
`anthropic-version: 2026-10-21`:

| Purpose | Endpoint | Reference |
|---|---|---|
| Validate; organisation id and name | `GET /organizations/me` | [get current organization](https://platform.claude.com/docs/en/api/admin/organizations) |
| Workspaces (names for `scope.workspace_id`) (`limit=1000`, `after_id`, `include_default=true`) | `GET /organizations/workspaces` | [list workspaces](https://platform.claude.com/docs/en/api/organization/workspaces/list) |
| API keys (`limit=1000`, `after_id`) | `GET /organizations/api_keys` | [list API keys](https://platform.claude.com/docs/en/api/organization/api_keys/list) |
| Messages usage | `GET /organizations/usage_report/messages?starting_at&ending_at&bucket_width=1h&group_by[]=api_key_id&group_by[]=workspace_id&group_by[]=model&limit=168&page` | [usage report](https://platform.claude.com/docs/en/api/beta/organization/usage_report/retrieve_messages), [guide](https://platform.claude.com/docs/en/manage-claude/usage-cost-api) |

Notes: the messages usage report is marked **legacy** but "remains
supported"; its replacement, `GET /v1/organizations/analytics/usage`, is a
follow-up. It reports tokens only (no request count) and `api_key_id = null`
for console usage; the default workspace's `workspace_id` is `null`.
Anthropic recommends at most one poll per minute sustained; we poll hourly.
API keys carry no last-used time; it is taken from usage. API version
2026-10-21 returns the key's workspace in `scope.workspace_id` only.

**Both:** 30 s timeout per request, 16 MiB response cap, 429 / 5xx retried up
to 4 times (Retry-After honoured, capped at 60 s; otherwise 2, 4, 8, 16 s);
401 / 403 → the connection becomes `error` ("the provider refused the admin
key") and stops syncing until rotated or synced by hand.

## 7. API (under `/api/iga/v1/agent-runtime`)

Workspace from the token; another workspace's connection is 404 like an
unknown one; writes need a verified workspace member session and
`governance:enforce`; reads need `discovery:read`. Errors use the governance
`{"error": {code, message, detail}}` envelope.

| Route | Permission | Body / query | Result |
|---|---|---|---|
| `POST /model-providers` | governance:enforce | `{provider, admin_key, display_name}` | 201 connection (no key). 400 bad input; 422 `provider_rejected_key` (the validation call failed); 409 `model_provider_exists` (one live per provider and organisation) or `model_provider_limit` (5 live per workspace); 503 secrets store unavailable |
| `GET /model-providers` | discovery:read | — | connections, newest first (revoked included, `status=revoked`) |
| `GET /model-providers/:id` | discovery:read | — | one connection |
| `POST /model-providers/:id/rotate` | governance:enforce | `{admin_key}` | 200 connection; the new key must read the same organisation (409 `organization_mismatch`) |
| `DELETE /model-providers/:id` | governance:enforce | — | 200 connection (`revoked`); Vault secret destroyed; open findings resolved |
| `POST /model-providers/:id/sync` | governance:enforce | — | 202 `{queued, next_sync_at}` (not before 5 minutes after the last attempt); 409 if revoked |
| `GET /model-providers/:id/keys` | discovery:read | — | keys with links, 7-day usage and `unaccounted` |
| `GET /model-providers/:id/usage` | discovery:read | `from`, `to` (RFC 3339; default last 7 days; ≤ 90 days), `group_by=key|model|project` (default key) | totals per group: requests (null when not reported), input / output tokens, first / last bucket |

Connect, rotate, revoke and sync write `audit_events` (`model_provider.*`).
Findings appear in the existing `GET /agent-runtime/findings?kind=unaccounted_model_usage`
(`connector_id` null; the connection is `subject.connection_id`, and
`agent_finding.provider_connection_id` in the table).

## 8. Sync

A small worker (`RunModelProviderSyncWorker`, cmd/main.go; off with
`AUTHSEC_DISABLE_MODEL_PROVIDER_SYNC=true`) wakes every minute, lists due
connections across workspaces (the one `TENANT-EXEMPT` statement: ids only),
and for each: claims it under RLS (a 15-minute lease, safe on every replica),
reads the key from Vault, calls the provider outside any transaction, then in
one `tenancy.InWorkspace` transaction upserts keys (absent ones become
`deleted`), replaces the usage buckets read, purges usage older than 180 days,
recomputes links and the findings, and schedules the next sync one hour later.
Usage is read from `usage_cursor − 2 h` (late data) to now; the first sync
reads 30 days.

## 9. Limits

5 live connections per workspace; 5,000 keys per connection (the rest are not
stored and the sync says so in `last_error`); usage window 30 days first time;
usage reads ≤ 90 days; `display_name` ≤ 200 characters; admin key 20–512
characters, no whitespace.

## 10. Affected repos

| Repo | What changes |
|---|---|
| `authsec` | migration 154, `internal/modelprovider`, `services/model_provider_*.go`, controller, routes, worker |
| `Authsec-ui` | Connect organisation dialog (write-only key field, fingerprint shown), keys and usage views, the new finding kind — not built here |
| `authsec-doc` | Customer guidance of §2 — not built here |
| `sdk-authsec`, `iga-agent` | none |

## 11. Open questions

1. **Aditya:** sign off the opt-in build (decision record).
2. Move Anthropic to the Usage and Cost Analytics API before the legacy
   endpoint is retired.
3. Should `unaccounted_model_usage` raise an alert (Slack / SIEM)?
