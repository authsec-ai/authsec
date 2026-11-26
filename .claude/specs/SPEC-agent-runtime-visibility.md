# SPEC: Agent runtime visibility on AWS — discover, detect, contain

> **Status: revision 2, build started 2026-11-05 on `feat/agent-runtime-aws`** (Q1–Q4 answered in review 2, §10; Q6 decided; Q5, Q7 at the build defaults in §10) (Ritam, 2026-11-05). Reviewer:
> Aditya Agarwal and his agents. Revision 1 (AWS, Azure, Kubernetes, gateways)
> was reviewed the same day; this revision is **AWS only** and answers that
> review point by point (§9). Nothing here is built.
>
> "Today" statements cite `origin/authsec-staging` at `910c491`. Read them with
> `git show 910c491:<path>`; a local branch older than that lacks some files.
>
> Context: [SPEC-iga-phase2-graph.md](SPEC-iga-phase2-graph.md) (the graph, and
> the classification decision this spec amends, §3),
> [SPEC-agentic-access-management.md](SPEC-agentic-access-management.md),
> [SPEC-access-policies.md](SPEC-access-policies.md).

## Summary

For a connected AWS account, AuthSec should show which workloads use AI models
and which of them are agents, keep that current, raise an alert when an agent
does something dangerous, and contain an agent safely. Today it discovers
platform-declared agents (Bedrock agents, AgentCore runtimes) and the access of
every identity, reads CloudTrail management events during scans, and changes
access in IAM. It does not use the model calls it already reads, has no
alerting, and has no single containment action.

**Coverage, per source** (what the console states; never "all agents"):

| A workload is found if… | Needs from the customer | Misses |
|---|---|---|
| a platform declares it (Bedrock agent, AgentCore runtime) | nothing | — |
| it calls Bedrock through the Bedrock Runtime API (`InvokeModel`, `Converse`, …) | nothing (management events) | — |
| it calls Bedrock through the OpenAI/Anthropic-compatible endpoint (`bedrock-mantle`) | a trail with data events for it (P2) | without data events |
| it carries model-key names or reads a model-key secret | nothing | a renamed variable, a key baked into the image |
| it is refused by the tag-gated model access template (§5.4) | apply the template | accounts that do not apply it |

Not found: an agent calling a non-AWS provider (OpenAI, Anthropic, Google)
directly with nothing in its configuration that names it, and self-hosted
models. Revision 1's network, provider-usage and gateway sources are deferred
(§2).

## 1. Requirements

| # | Requirement |
|---|---|
| R1 | Show every **AI workload** in the account: a workload or identity seen calling a model, with the evidence |
| R2 | Show every **agent**: declared by a platform, or confirmed by a person; suggest likely agents with their evidence |
| R3 | Flag risky agent credentials and identities: IAM users and access keys used by AI workloads, model-key secrets, roles shared by several workloads |
| R4 | Keep this current: within one scan interval by polling; within about a minute with the event stream (P2) |
| R5 | **Detect and alert** on dangerous actions by an AI workload or agent, to Slack and to a SIEM |
| R6 | **Contain** an agent: show the blast radius first, stop it at the narrowest level AWS allows, verify, release exactly |
| R7 | Every suggestion, confirmation, alert and containment is recorded per workspace, append-only |

**Labels** (the console uses exactly these; NIST's NCCoE concept paper keeps
LLM-only and retrieval-only applications out of "agent"):

- **AI workload** — seen calling a model. Evidence only; not an agent.
- **Suggested agent** — an AI workload that, in the same window, also acted on
  other resources under its own identity (read a secret, wrote S3, invoked a
  Lambda, called an API). A suggestion, never a classification.
- **Agent** — provider-native (`provider_native_agent`, set by the projector),
  or classified by a person (`classified_agent`, the existing action).

## 2. Scope

**In:** one or more connected AWS accounts; Bedrock (both endpoints), IAM, STS,
Lambda, ECS, EC2, EKS identities as collected today; P1–P3 (§7).

**Deferred:** Azure and Kubernetes (their discovery and inference stay as
built); egress and node-sensor signals (AWS DNS query logs: built, §11); OpenAI/Anthropic admin APIs;
LLM and MCP gateways; OpenTelemetry ingest; per-tool-call control; the activity
timeline from AgentCore spans (P4, later); human approval (§8, Q6).

## 3. Amendment to a recorded decision

[SPEC-iga-phase2-graph.md §2.14.3](SPEC-iga-phase2-graph.md) keeps "automatic
inference from names, tags, env vars or dependencies" out, because inference
from names or tags is unreliable, and says classification is provider-native or
a person's decision. This spec **keeps that rule** and adds one thing:

- AuthSec may **suggest** that a workload is an agent, from **observed
  behaviour** (model calls attributed by CloudTrail's session issuer, then
  actions on other resources) with names and env-var names as supporting
  evidence only. A suggestion never sets `classification`; only the existing
  **Classify as agent** action does (`POST /workloads/:id/classification`,
  `iga:review`, audited). Rejecting a suggestion is recorded and suppresses it
  for that workload incarnation.

**Needs Aditya's sign-off** (Q1). If accepted, §2.14.3 gets a line pointing
here; if not, P1 ships "AI workload" only and no suggestions.

## 4. Today (AWS)

| | Fact | Where |
|---|---|---|
| Declared agents | Bedrock agents, AgentCore runtimes and gateways → `cloud_workload`; graph `iga_workload.classification='provider_native_agent'`, set on insert | `internal/awsdiscovery/bedrock.go:123,209,302`; `internal/igagraph/project.go:553-558` |
| Agents list | AWS declared agents are **not** in `discovered_agents` (the Agents page) | `UpsertSighting` callers: Azure inference, ingress |
| CloudTrail | `LookupEvents`, 48 h window, ≤200 pages × 50 = 10,000 events per region per scan, all management events, no filter; attribution by session issuer; stored as `cloud_observation`; unmatched events counted, not stored | `internal/awsdiscovery/cloudtrail_events.go:77,84-87,228-246`; `services/cloud_aws_workload_scan.go:654-695,752-781` |
| Usage aggregates | `cloud_usage` admits `source='cloudtrail'`; nothing writes it | `016_cloud_usage.sql` |
| Env var names | Lambda `EnvVarNames` (names only; `EnvVarsUnread` when KMS refuses) | `internal/awsdiscovery/workloads.go:207-250` |
| Secrets | Secrets Manager names from `ListSecrets` (resource-policy collector) | `internal/awsdiscovery/resource_policies.go:1402` |
| Schedule | daily or weekly | `services/cloud_aws_scan_schedule.go:62` |
| Classification | `POST /workloads/:id/classification` (manual); `iga_classification_candidates` exists (004) with decisions route | phase-2 spec §2.14.3; `routes/iga_routes.go:96` |
| Control | access policies (managed policy per role), R2 session revocation (`aws:TokenIssueTime` cutoff), R3 for AgentCore | `internal/igagov/r2.go:79-99`; 062 |
| Alerting | none for discovery; policy notifications go to Slack through `iga_gov_notify` | `services/iga_gov_notify.go` |

## 5. Design

### 5.1 Model-call evidence (P1)

**Event sources and kinds.**

| Endpoint | Calls | CloudTrail | Read by |
|---|---|---|---|
| Bedrock Runtime (`bedrock.amazonaws.com`) | `InvokeModel`, `InvokeModelWithResponseStream`, `Converse`, `ConverseStream` | management events, on by default | `LookupEvents` (P1) |
| Bedrock agents runtime | `InvokeAgent`, `InvokeInlineAgent`, `Retrieve`, `RetrieveAndGenerate`, `InvokeFlow` | data events, opt-in | stream only (P2) |
| `bedrock-mantle` (OpenAI/Anthropic-compatible SDK endpoint) | inference | data events, its own event source, opt-in ([doc](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-cloudtrail-mantle.html)) | stream only (P2); **verify the exact `eventSource` value against a lab call** |
| AgentCore | `InvokeAgentRuntime`, `InvokeGateway`, token-vault calls | data events, opt-in | stream only (P2) |

`LookupEvents` returns management events only
([API](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html)),
so P1 sees Bedrock Runtime calls and nothing on the data-event rows.

**Counting.** `ConverseStream` and `InvokeModelWithResponseStream` write an
additional stream-completion record with the same event name
(`eventType = AwsServiceEvent`). Count only `eventType = AwsApiCall`; read token
counts from the completion record when present.

**Window.** Read from the last successful scan's high-water mark (per
connector, per region), bounded by AWS's 90-day lookup limit; first scan reads
the full 90 days up to its cap. A weekly connector then covers all seven days.
If a cap is hit the window is marked partial with the time reached, and "no
calls seen" is never shown for an uncovered interval.

**Focused pass.** One extra `LookupEvents` per region with
`LookupAttributes: EventSource=bedrock.amazonaws.com` (one attribute per call
is what the API allows), its own page cap, attribution through the existing
`TrailEvent.Attribution`. The general pass is unchanged.

**Storage.** Per identity (incarnation) per model per day in `cloud_usage`
(`source='cloudtrail'`, `service='bedrock'`, attrs: calls, errors, denied,
models, first/last call, session names seen). Refused calls (`AccessDenied`)
are kept: they are evidence for §5.4.

### 5.2 From identity to workload (P1)

CloudTrail names the role, not the Lambda. Attribution:

1. Role → workloads that run as it (`cloud_workload.identity_id`; IRSA and Pod
   Identity edges for EKS).
2. One workload on the role → the AI workload is that workload.
3. Several workloads on the role → **shared-role finding**; the role is the
   AI workload, listing the candidates. The session name narrows it where AWS
   sets it predictably (Lambda's session name is the function name; ECS tasks
   use the task id): recorded as `weak` evidence on the candidate, never as
   attribution of the call (the phase-2 rule "never by name" holds for
   attribution).
4. An IAM user or a root/human session calling a model → R3 finding (agent on
   human or long-lived credentials).

### 5.3 Suggestions (P1)

Rule `aws_agent_suggest_v1`, per AI workload per window:

| Evidence | Role in the rule |
|---|---|
| model calls by its identity (§5.1) | required |
| in the same window, its identity also called other services (S3, Secrets Manager, Lambda Invoke, DynamoDB, SQS/SNS, STS AssumeRole, external API through API Gateway…) | required for "suggested agent" |
| machine cadence (calls spread over the day, no console sign-in) | supporting |
| env-var names of agent frameworks or model keys (`LANGCHAIN_*`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `MCP_*`), Lambda layer names | supporting only |
| a model-key secret it may read | supporting only |

Output: an `iga_classification_candidates` row (pending) per workload
incarnation with the evidence, shown as **Suggested agent**; the person uses
**Classify as agent** (confirm) or **Dismiss** (records a rejection). AWS
provider-native agents and classified agents are mirrored into
`discovered_agents` (`source='aws'`, `evidence_mode` declared or inferred) so
the Agents page lists them; the graph stays authoritative for classification.
**Q2:** is `iga_classification_candidates` the right store, or a new table?

### 5.4 Tag-gated model access template (P1)

The one certain way to tell declared agents from everything else:

- The customer tags agent roles `authsec:agent=<name>`.
- A template we publish denies `bedrock:InvokeModel*` / `bedrock:Converse*`
  unless `aws:PrincipalTag/authsec:agent` is present — as an **SCP** for
  Organizations customers, or as an AuthSec-owned permissions boundary on
  chosen roles otherwise (weaker: covers only those roles).
- The refusals are management events: §5.1 already reads them, so every
  untagged AI workload shows up as "refused model call" with its identity.
- Shipped in **audit mode first**: a variant that only tags-and-reports (no
  deny), so the customer sees what the deny would break before applying it.

### 5.5 Risky credentials and identities (P1)

| Finding | Evidence |
|---|---|
| AI workload on an IAM user / access key | model calls attributed to an IAM user; key age from `cloud_secret` / credential report |
| AI workload on a human session | Identity Center or federated session calling a model |
| Model-key secret | Secrets Manager names matching `openai|anthropic|gemini|llm|api[-_]?key`, and which roles may read them (graph) — names only, no `GetSecretValue` |
| Shared role | §5.2 step 3 |

### 5.6 Event stream (P2)

```
POST /authsec/ingest/aws/events
Auth: per-connector secret (EventBridge connection, API-key header); workspace
      and connector come from the secret, never the body
Body: EventBridge envelope (≤256 KB), batched
Response 202; 401 unknown secret; 413; 429 per-connector limit
```

- **Requires a CloudTrail trail** logging in the region. Read-only management
  events (`Converse`, `InvokeModel`, `Get*`) reach EventBridge only with rule
  state `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`
  ([doc](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-event-cloudtrail-management.html));
  data events (mantle, agents runtime, AgentCore) only if the trail's selectors
  include them ([doc](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)),
  which the customer pays for.
- We publish a CloudFormation stack: optional trail (or reuse), data-event
  selectors (opt-in per kind, with the cost stated), EventBridge rule, API
  destination to the endpoint above.
- Idempotent by CloudTrail `eventID`; polling (§5.1) stays as the backstop; the
  connector shows "stream silent since …" after a configurable gap.
- **Delivery is best effort and its latency is measured, not promised.** AWS
  delivers service events to CloudTrail, and CloudTrail events to EventBridge,
  on a best-effort basis ([doc](https://docs.aws.amazon.com/eventbridge/latest/ref/events-ref-bedrock.html)).
  The connector reports `last_event_time` and silence; the lab measured 10–30 s.
- **Durable acceptance (migration 161).** Each accepted eventID is recorded in
  `agent_event_seen` with `dispatched_at` NULL, and `dispatched_at` is set only
  after every consumer has returned. A delivery whose eventIDs are present but
  undispatched (a dispatch error, or a process that died after the insert) is
  dispatched again; EventBridge retries the delivery for up to 24 h (185
  attempts in the event-stream template). Every consumer is idempotent by
  eventID, so a second dispatch changes nothing. Before 161 the row was
  committed before dispatch and only a normal error removed it, so a crash in
  between lost the event for the live consumers.

### 5.7 Detections and alerts (P2)

Evaluated on every event (stream) and every scan (poll), for identities that
are AI workloads or agents:

| ID | Detection | Events |
|---|---|---|
| D1 | Reads a secret | `secretsmanager:GetSecretValue`, `ssm:GetParameter*` with decryption, `kms:Decrypt` on a secret's key |
| D2 | Creates credentials | `iam:CreateAccessKey`, `CreateLoginProfile`, `sts:GetFederationToken` |
| D3 | Changes IAM | `Attach*Policy`, `Put*Policy`, `UpdateAssumeRolePolicy`, `CreateRole`, `PassRole` to a new service |
| D4 | Weakens logging | `cloudtrail:StopLogging`, `DeleteTrail`, `PutEventSelectors`, `UpdateTrail`; `bedrock:DeleteModelInvocationLoggingConfiguration` |
| D5 | Acts outside its grant | a burst of `AccessDenied` / `UnauthorizedOperation` (N in M minutes) |
| D6 | New model or volume spike | first call to a model id, or calls > k × its 7-day baseline |
| D7 | New role assumption | `sts:AssumeRole` into a role it has not assumed before |
| D8 | Model call from an unexpected place | source IP / region never seen for that identity |

- Each alert: workspace, identity, workload/agent, detection, events, first/last
  seen, severity; deduplicated per (identity, detection) per window.
- Delivered to **Slack** (the existing governance Slack channel) and to a
  **SIEM webhook** (per-workspace URL and HMAC secret, through
  `internal/safehttp`; JSON; retries; delivery audited).
- Thresholds per workspace; each detection can be turned off.
- **Q3:** alerts as a new table, or as `iga_gov_event` kinds in the Logs view?

### 5.8 Containment (P3)

`POST /api/iga/v1/agents/:id/contain` (preview), `…/contain/confirm`,
`…/release`; `governance:enforce` (emergency: `governance:emergency`, as R2).

**Preview — blast radius first.** Lists every workload that runs as each
identity the agent uses, the services they call (from §5.1/activity), and what
each containment level would stop. A shared role shows "this also stops: …".

| Level | Action | Stops | Notes |
|---|---|---|---|
| Workload | Lambda `PutFunctionConcurrency` = 0; ECS `UpdateService` desiredCount = 0 | that workload only | preferred when the role is shared; needs new enforcement-template permissions (**template v3**, Q4) |
| Identity | AuthSec-owned managed policy denying `*` on the role (`/authsec/AuthSecContain-<RoleId>-<id>`), plus an R2 session revocation for sessions issued before contain | every workload on the role | service-linked roles cannot take it → refused with the reason; IAM user: deactivate its keys |
| Model | deny `bedrock:*` on the role | its model use only | lighter option |

**Verification.** (1) Read back the change (policy attached, concurrency 0,
desired count 0). (2) **Behavioural:** no successful CloudTrail call by the
identity after the containment time, beyond CloudTrail's delivery delay;
successful calls after it mark the containment **not effective** with the
events. **Release** restores exactly what was changed (recorded before-state).
Status: `previewed → containing → contained | partially_contained | failed →
released`.

### 5.9 Tenancy and safety

- New tables: `workspace_id NOT NULL`, FK, index, `tenancy_enable_rls`
  (guarded, as 146:83-84), bootstrap mirror, parity check; next migration 147.
- New Go files in `scripts/tenant-rls-files.txt`; the ratchet does not rise.
- The ingest endpoint derives workspace and connector from the secret; body
  values are never trusted; isolation tests (`TwoTenants`) for every route and
  for the ingest (A's secret cannot write B's events).
- Discovery credentials never write; containment and the template use the
  enforcement credential.
- No secret values, prompts or responses are read or stored.

## 6. Affected repos

| Repo | What changes | Why / why not |
|---|---|---|
| `authsec` | CloudTrail window and focused pass, model-call aggregates, suggestions, findings, mirror to agents list, ingest endpoint, detections, alerts (Slack, SIEM), containment; migrations 147+; discovery role unchanged for P1; enforcement template v3 for P3 | All server work |
| `Authsec-ui` | AI workloads and Suggested agents on the Agents page with evidence and Classify/Dismiss; findings; alert settings (Slack, SIEM, thresholds); Contain preview/confirm/release | Console |
| `iga-agent` | none | Kubernetes deferred |
| `sdk-authsec` | none | No SDK caller needs discovery or containment |
| `authsec-doc` | Stream stack, data-event costs, tag-gated template, SIEM payload | Customer setup |
| Production K3s | ingest path and body limit on the API ingress | New public ingress |

## 7. Plan

Backend estimates include tests and docs; "live" adds UI, lab-account testing
(220171243705) and review.

| Phase | Deliverable | Covers | Backend | Live |
|---|---|---|---|---|
| **P1** | Model-call evidence (§5.1: window to last scan ≤90 d, focused pass, stream-completion filter, aggregates); identity → workload (§5.2); suggestions with Classify/Dismiss (§5.3); AWS agents in the Agents list; tag-gated template with audit mode (§5.4); risky-credential and shared-role findings (§5.5) | R1, R2, R3, R7 | 2–2.5 wk | ~3.5 wk |
| **P2** | Ingest endpoint and CloudFormation stack (§5.6), data events incl. mantle; detections D1–D8 and alerts to Slack and SIEM (§5.7) | R4, R5, R7 | 2–2.5 wk | ~3.5 wk |
| **P3** | Containment with blast-radius preview, three levels, behavioural verification, release (§5.8); enforcement template v3 | R6, R7 | 1.5–2 wk | ~3 wk |
| P4 (later) | Activity timeline per agent from data events and AgentCore spans; delegation chain | — | separate spec | |

P1–P3 ≈ 6–7 weeks backend, ~10 weeks live. P2 and P3 can run in parallel after
P1.

### Acceptance

- **P1** (lab account):
  - a Lambda calling `Converse` appears as an **AI workload** after one scan,
    with calls, model and the Lambda named; it is **not** called an agent;
  - the same Lambda also reading S3 and a secret in the window appears as a
    **Suggested agent**; Classify sets `classified_agent` with the decision
    record; Dismiss records the rejection and it is not suggested again for
    that incarnation;
  - five Lambdas on one role produce one shared-role finding listing all five;
  - `ConverseStream` calls are counted once;
  - on a weekly connector, calls from six days ago are counted;
  - with the template in deny mode, an untagged role's `InvokeModel` shows as a
    refused model call;
  - a secret named `openai-api-key` produces a finding with no value read;
  - workspace B sees none of A's evidence, suggestions or findings.
- **P2:** with the stack deployed, a `Converse` call shows in AuthSec within
  60 s; a mantle call shows when its data events are on and the console says
  it is missing when they are off; an AI workload calling `GetSecretValue`
  raises D1 in Slack and in the SIEM webhook (signed); a forged or
  cross-workspace post is refused; a silent stream is reported.
- **P3:** containing a Lambda on a shared role offers workload level and shows
  the other workloads; identity-level containment of a dedicated role stops
  its calls (no successful CloudTrail call after contain + delay); a
  service-linked role is refused with the reason; release restores the exact
  before-state.

## 8. Open questions

1. **Q1** Sign off the amendment in §3 (suggestions from observed behaviour; classification stays human)?
2. **Q2** Suggestions in `iga_classification_candidates`, or a new table?
3. **Q3** Alerts: new table, or `iga_gov_event` kinds in Logs?
4. **Q4** Enforcement template v3 (Lambda concurrency, ECS desired count): acceptable widening of the enforcement role?
5. **Q5** Single agent inventory long term: graph classification plus a mirror into `discovered_agents` (this spec), or one of them only?
6. **Q6 — decided (Ritam, 2026-11-05): no human approval** in this scope, containment included. NIST design tenet 5 noted; revisit only on a customer requirement.
7. **Q7** Detection thresholds (D5, D6) defaults.

## 9. Review of revision 1 (Aditya, 2026-11-05) and what changed

| Review point | Revision 2 |
|---|---|
| Reverses the recorded classification decision silently | §3: kept; suggestions only, from observed behaviour; sign-off asked (Q1) |
| Scope too big (three clouds, gateways, sensor, provider keys, OTLP) | AWS only; the rest deferred (§2) |
| Headline promise cannot be kept | Replaced by a per-source coverage table (Summary) |
| A model call alone made a "high-confidence agent" | Labels: AI workload / Suggested agent / Agent (§1); P1 acceptance changed |
| No detection or alerting | R5, §5.7 (D1–D8, Slack, SIEM), P2 |
| `bedrock-mantle` missing | §5.1: data events, stream only; event source to verify |
| Streaming calls double-counted | §5.1: count `AwsApiCall` only |
| Weekly scans with a 48 h window | §5.1: window to the last successful scan, ≤90 days, partial marked |
| Stream needs a trail and the special rule state | §5.6 |
| Inferred agents keyed by role; shared roles | §5.2: shared-role finding; session name as weak evidence only |
| Kill switch breaks shared roles, SLRs; verification only by read-back | §5.8: blast-radius preview, workload level, SLR refusal, behavioural verification |
| Human approval is a product call | Q6 |
| Tag-gated model access as the certain confirmation path | §5.4, P1, with audit mode |
| Provider admin keys, LLM gateway with provider keys | Admin keys: opt-in, signed off 2026-11-06 (SPEC-agent-runtime-provider-usage.md). Gateway: runs in the customer's environment, AuthSec never holds the provider keys (SPEC-agent-runtime-gateway.md) |
| Unverified MCP header and AuthZEN dates, EO naming | Removed (not needed for AWS) |
| "Only GitHub writes `iga_agents`" unverified | Removed |
| Kubernetes ingress described too harshly | Removed (Kubernetes deferred) |
| 9–11 weeks optimistic | Smaller scope; P1–P3 6–7 weeks backend, stated as estimates |

## 10. Decisions from review 2 (Aditya, 2026-11-05) — binding for the build

These override §3–§8 where they differ.

**Q1 — signed off, with conditions.** Suggestions are allowed; a suggestion
never sets classification (phase-2 §2.14.3 gets a pointer line when this
merges). Measure suggestion precision on the lab account and record it in the
P1 acceptance results (a fixed pipeline — read S3, summarise, write S3 — also
matches the rule; false positives are expected). **No suggestion on a shared
role:** classification lives on `iga_workload`, so when several workloads share
the role, show only the shared-role finding until the role is split.

**Q2 — a new table keyed to `iga_workload`.** `agent_suggestion` keyed
`(workspace_id, workload_id)` → `iga_workload` (each row is one incarnation, so
suppression per incarnation is free): rule id and version, evidence references
(the `cloud_usage` / `cloud_observation` rows), state `pending | confirmed |
dismissed | superseded`, deciding user, time, reason, version. **Confirm** calls
the existing classify transaction (`POST /workloads/:id/classification`, same
`operation_id` and version contract) and closes the suggestion in the same
transaction. Workspace FK, index, RLS, bootstrap mirror, parity check.
`iga_classification_candidates` is not used (GitHub-only, promotes to
`iga_agents`, uniqueness only while pending).

**Q3 — new tables plus log entries.** `agent_alert` (detection, identity,
workload, severity, dedupe key, first/last seen, count, state `open |
acknowledged | resolved`, evidence references — never secret values) and
`agent_alert_delivery` (channel, attempt, status, time). Write "alert opened" and
"alert resolved" into `iga_gov_event` with the alert id in the payload so they
appear in Logs and the audit trail stays append-only (R7). Slack through
`services/iga_gov_notify.go` (`GovChannelSlack`). Alerts have their own default
retention, separate from the log.

**Q4 — widen the enforcement role only as an opt-in stack parameter**, following
`EnableLambdaSplit` in template v2 (no new template file). Identity- and
model-level containment need no widening (v2's `ManageAuthSecPolicies` and
`AttachOnlyAuthSecPolicies`). Workload containment, behind the parameter:
Lambda `GetFunctionConcurrency`, `PutFunctionConcurrency`,
`DeleteFunctionConcurrency`; ECS `DescribeServices`, `UpdateService`;
Application Auto Scaling describe and register scalable target (to suspend
scaling, otherwise it raises `desiredCount` again); `iam:ListAccessKeys`,
`iam:UpdateAccessKey` (IAM user keys). Deny all of these on resources tagged
`authsec:protected=true`, as v2 does for roles (verify Lambda and ECS honour
`aws:ResourceTag` on these actions). Bindings without the parameter report
workload containment unavailable, with the reason, in `/api/iga/v1/capabilities`.

**§5.4 changes.** No permissions-boundary variant: a role has one boundary and
R1a already writes AuthSec boundaries (`internal/awsenforce/deploy.go`). Without
Organizations, the template is a **deny policy** attached to chosen roles,
under `/authsec-gate/` so the enforcement role's `/authsec/` policy rights
cannot rewrite or detach it. The gate must not be bypassable through session
tags: also deny setting the `authsec:agent` tag key through `sts:TagSession`,
`sts:AssumeRole*` (with tags) and `iam:TagRole` / `iam:UntagRole`, except for
named administrator principals (a template parameter). A policy on the gated
role never sees the assumer's call, so tags set by the assumer are stopped
only by the SCP (in-organization callers) and a **resource control policy**
form (`form=rcp`, any caller); an empty `authsec:agent` value counts as
untagged. The deny list covers Bedrock Runtime, agents, flows, batch
inference, AgentCore runtime invocation and `bedrock-mantle:CreateInference`.
Bedrock's own service roles (agent, knowledge base, flow, batch, AgentCore
runtime) must be tagged too.

**§5.2 change.** The session-name claims (Lambda = function name, ECS = task id)
are unverified: both go into the P1 lab acceptance; until verified, session
names are shown as unverified weak evidence only.

**§5.8 change.** The preview states side effects: zero Lambda concurrency does
not stop event source mappings (queue messages are retried and may dead-letter);
ECS `desiredCount = 0` does not stop tasks started with `RunTask`. Workload
containment selects ECS services running the workload's exact task-definition
revision, and one target is held by one live containment at a time (159).
**Verified** needs evidence: CloudTrail events from after contained-at plus the
grace were received (stream or scan cursor) and none was a successful call by
the identity (calls a deny cannot block, such as `sts:GetCallerIdentity`, and
calls made by an AWS service do not count). Without such events within 24 h,
or when no event can be attributed to the contained workloads, the
containment is recorded **unverifiable** with the reason, never verified.

**§5.7 change.** D1 on `kms:Decrypt` would duplicate every `GetSecretValue`
alert (Secrets Manager decrypts on the caller's behalf): drop `kms:Decrypt`
calls made on a principal's behalf by Secrets Manager or SSM (`invokedBy`), and
check in the lab.

Q5 and Q7 remain open; the build uses: Q5 graph classification authoritative +
mirror into `discovered_agents`; Q7 defaults D5 N=10/M=5 min, D6 k=5.

## 11. DNS-based detection of direct model-provider calls

> Built 2026-11-05 on `feat/agent-runtime-dns` (Ritam). This section takes the
> **AWS DNS part** of revision 1's deferred network signals (§2) into scope;
> egress flow logs, node sensors and non-AWS resolvers stay deferred.

**Why.** A workload that calls OpenAI, Anthropic, Google… directly leaves
nothing in CloudTrail (§5.1 sees Bedrock only). It does look up the provider's
API host, and Route 53 Resolver query logging records every lookup a VPC makes
through the Amazon-provided resolver, with the source address and — for an EC2
instance — the instance id.

### 11.1 Discovery (per region)

- `route53resolver:ListResolverQueryLogConfigs` and
  `ListResolverQueryLogConfigAssociations`: which VPCs of this account are
  logged (associations in state `ACTIVE`) and to which destination.
- **CloudWatch Logs** destination in this account and region: read (§11.2).
- **S3 or Firehose** destination, a log group in **another account** (a shared
  configuration) or another region: listed, **not read**, reported on
  `dns-query-logs-unread:<region>` (state `unsupported`) naming the
  configuration, its VPCs, the destination and why.
- Kill switch: `AUTHSEC_AWS_DNS_QUERY_LOGS=off` skips the read
  (`dns-query-logs:<region>` = `not_selected`).

### 11.2 Query: only model hosts are ever read

The domain list (`awsdiscovery.ModelEndpoints`; exact and suffix match, case
insensitive, trailing dot optional):

| Provider | Hosts |
|---|---|
| openai | `api.openai.com` |
| azure_openai | `*.openai.azure.com` |
| anthropic | `api.anthropic.com` |
| google_gemini | `generativelanguage.googleapis.com` |
| google_vertex | `aiplatform.googleapis.com`, `*.aiplatform.googleapis.com`, `<region>-aiplatform.googleapis.com` (Vertex's regional hosts are not subdomains) |
| mistral | `api.mistral.ai` |
| cohere | `api.cohere.com`, `api.cohere.ai` |
| groq | `api.groq.com` |
| openrouter | `openrouter.ai` |
| huggingface | `api-inference.huggingface.co`, `router.huggingface.co` |
| together | `api.together.xyz` |
| fireworks | `api.fireworks.ai` |
| deepseek | `api.deepseek.com` |
| xai | `api.x.ai` |
| aws_bedrock (**control**) | `bedrock-runtime.<region>.amazonaws.com`, `bedrock-runtime-fips.<region>.amazonaws.com` |

One Logs Insights query per log group (`logs:StartQuery` over the log group
ARN, polled with `GetQueryResults`, stopped with `StopQuery` past a 2-minute
deadline):

```
fields @timestamp, query_name, coalesce(srcaddr, "-") as srcaddr,
       coalesce(srcids.instance, "-") as src_instance, coalesce(vpc_id, "-") as vpc
| filter query_name like /(?i)^(<the list as one regex>)\.?$/
| stats count(*) as queries, min(@timestamp) as first_seen, max(@timestamp) as last_seen
        by srcaddr, src_instance, vpc, query_name
| limit 10000
```

The filter runs inside the customer's account, so no other DNS data is
returned; every returned row is checked against the same list again and a
non-matching row is dropped, never stored or named (`coalesce` keeps the
lookups of Lambdas and Fargate tasks, which carry no `srcids.instance`).

**Window and cost.** Logs Insights is charged per GB scanned. Per (connector,
region, log group) a cursor (`cloud_dns_cursor`, migration 153, stream `dns`)
records the window read. Windows are cut by **arrival time** (`@ingestionTime`,
when CloudWatch Logs received the line), not by event time: the query keeps
only lines that arrived in `[read_to, now − 10 min)` and searches event time
from `DNSLateArrival` (2 h) before the window. Consecutive windows never
overlap, so a line is counted once, and a line that arrives after a read has
passed its event time is still read by the read whose window holds its
arrival. A line arriving more than 2 h after its event time is missed (the
late-data policy; AWS states no maximum delivery delay). The first read covers
24 h; later reads are capped at **7 days**. An older mark is read for its last 7
days and the cursor marks the read `partial` (`lapsed`); a read that reaches
the 10,000-row limit is `partial` (`truncated`). At most 10 log groups per
region per scan (more: `partial`, the rest named). `records_scanned` and
`bytes_scanned` are kept per read so the cost is visible. A failed read moves
nothing and records `last_error`.

**What a count means.** The Resolver logs only *unique* queries: a lookup it
answers from its cache within the record's TTL is not logged
([doc](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs.html)),
and the workload's own resolver cache answers repeats before they reach it.
`queries` is therefore evidence of **resolution activity** (the workload looked
the host up), never a count of model requests.

### 11.3 Attribution

`srcids.instance` in the query log record is recorded at lookup time and
decides first when it is one of the account's inventoried instances. Lambda in
a VPC resolves through AWS-owned hosts whose instance ids also appear there
(observed in the lab, 2026-11-06), so an id not in the inventory does not
decide: the network interface does, and the id is used only when no
interface holds the address. Otherwise, for each (VPC, source address), the network
interface holding the address **now** (`ec2:DescribeNetworkInterfaces`,
filtered by private address and VPC). An interface whose attachment time is
after the last lookup did not make it (the address changed hands) and is not
used.

| Evidence (in this order) | Subject | Confidence |
|---|---|---|
| `srcids.instance` in the record | the EC2 instance (and its instance-profile role) | `query_time` |
| interface `AWS Lambda VPC ENI-<name>` / type `lambda` | Lambda shares one interface across every function with the same subnet and security groups ([doc](https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html#configuration-vpc-enis)). The candidates are the inventoried functions whose VPC subnets include the interface's subnet and whose security groups equal its groups (`vpc_subnet_ids`, `vpc_security_group_ids` in `cloud_workload.attrs`). One candidate: that function. Several: subject `workload_set` keyed `lambda_eni:<region>:<eni>` listing every candidate, **unresolved**, with `identity_id` only when they all run as one role. Until a scan has recorded VPC settings, the function the description names, with a note that sharing was not checked | `scan_time` (`eni_lambda`, or `eni_lambda_shared` for a set) |
| interface described by an ECS attachment ARN | the running task holding the interface (`ecs:ListClusters/ListTasks/DescribeTasks`), then its task definition | `scan_time` |
| interface attached to an instance | the instance | `scan_time` |
| a secondary address on an instance, or a VPC CNI interface (`aws-K8S-...`) | the instance (EKS node), **pod level unresolved** (`subject.pod_level = "unresolved"`) | as above |
| none of these | **the VPC**: "model traffic from an unknown source in VPC X" | `none` |

Subjects resolve to `cloud_workload` (and `identity_id`, the role it runs as).
A workload the interface names but the inventory lacks is still the subject
(`in_inventory: false`).

### 11.4 Output: `agent_finding` kind `ai_network_traffic`

- One row per subject: `subject_key` `workload:<runtime_kind>:<region>:<native_id>`
  or `vpc:<region>:<vpc_id>`; `identity_id` the workload's role when known;
  `subject` {kind workload|vpc, cloud_workload_id, runtime_kind, native_id,
  name, region, identity_id, identity_arn, in_inventory, pod_level}.
- `evidence`: providers, `control_only` (only `bedrock-runtime` lookups),
  queries, first/last seen, per domain {domain, provider, control, queries,
  first/last seen}, source refs {srcaddr, instance_id, vpc_id, eni_id,
  eni_kind, queries, last_seen} (at most 50), log groups and their VPCs,
  attribution {how, confidence, note, pod_level}, `partial`, limitations.
  Model hosts only, never another domain.
- `first_seen` / `last_seen` are the first and last **lookup**. Counts add
  across scans (windows never overlap).
- **Resolved** when the last lookup is at least 30 days old **and** every log
  group it was seen in has been read without a gap and without a failure since
  then (`covered_from <= last lookup`, `read_to >= last lookup + 30 d`). A log
  group no longer read keeps the finding open: unknown is not "no traffic".
- The inference pass (`applyFindings`) neither opens nor resolves this kind.
  Only a `query_time` attribution is `ai_workload` evidence; a `scan_time` or
  `none` one makes a possible AI workload, which raises no detections and
  gets no suggestion or credential findings (§5.7).

### 11.5 Coverage and limits

| Surface | Meaning |
|---|---|
| `dns-query-logs:<region>` | `reached` (every log group read whole), `partial` (failed, truncated, lapsed or above the cap, each named), `denied` / `throttled` with the call and AWS's code; `unsupported` when no VPC logs to CloudWatch Logs here |
| `dns-query-logs-unread:<region>` | `unsupported`: configurations not read (S3, Firehose, other account or region) |
| `dns_blind_spots` | `unsupported`, fixed: what DNS detection never sees |

**Not visible**, whatever is read: **Lambda functions not attached to a VPC**;
anything using a resolver **other than the Route 53 Resolver** (a custom DNS
server, DNS over HTTPS/TLS in the application); VPCs without query logging to
CloudWatch Logs; lookups answered from a cache. Attribution by address names
the interface holding the address **at scan time** (a short-lived task's
address may since have been released or reused). A lookup is not a call.

Nothing here fails the scan: every failure is coverage and a scan warning, and
none of these surfaces gates reconciliation.

### 11.6 Permissions: discovery template 2026-11-05, scoped in 2026-11-06

Statements `DnsQueryLogConfigs` (`route53resolver:ListResolverQueryLogConfigs`,
`route53resolver:ListResolverQueryLogConfigAssociations`,
`ec2:DescribeNetworkInterfaces`), `DnsQueryLogInsights` (`logs:StartQuery`
only on the log-group ARNs the customer lists in the `DnsQueryLogGroupArns`
parameter; omitted when the list is empty, since template 2026-11-06 — IAM,
not AuthSec's query filter, keeps every other log group out of reach) and
`DnsQueryLogInsightsResults` (`logs:GetQueryResults`, `logs:StopQuery`; no
resource scoping exists for them). The ECS task reads are already granted
(MigrationEvidence). `TemplateVersion` and `PermissionsVersion` move to
2026-11-05; the template must be published to
`<base>/aws/2026-11-05/authsec-aws-discovery-role.yaml` before release. A
stack on an older version keeps working: `dns-query-logs:<region>` is
`denied` with the call, AWS's code and the fact "template 2026-11-05 is the
first to grant the DNS query-log reads; this connector's stack reports ...".
Deliberately **not** granted: `route53resolver:Get*` and
`logs:DescribeLogGroups` (never called).
Template 2026-11-06 changes only that scope; 2026-11-07 adds `AgentActivitySpans`
(the activity timeline's `aws/spans` reads), and `PermissionsVersion` is 2026-11-07. A query refused on a 2026-11-06 stack says to add the log group's
ARN to `DnsQueryLogGroupArns`. A 2026-11-05 stack still grants `StartQuery`
on every log group until the customer updates it. The 2026-11-06 template
must be published to `<base>/aws/2026-11-06/authsec-aws-discovery-role.yaml`
before release.

### 11.7 Customer setup

1. Update the AuthSec discovery stack to template 2026-11-05.
2. In each region, create a Route 53 Resolver **query logging configuration**
   whose destination is a **CloudWatch Logs log group** in the same account
   (Route 53 > Resolver > Query logging), and associate every VPC whose
   workloads should be covered. S3 and Firehose destinations are not read.
3. Keep workloads on the Amazon-provided resolver (the VPC `.2` address or
   Route 53 Resolver endpoints); attach Lambdas that must be covered to a VPC.
4. Cost: Logs Insights bills per GB scanned (24 h on the first read, then only
   the new interval, at most 7 days, per log group per scan); the bytes
   scanned per read are kept in `cloud_dns_cursor`.

## 12. Review 3 (2026-11-11): verified defects, fixes, and a PROPOSED product direction

An external design review of the system-design document and code. Its factual
claims were checked against the code and AWS's documentation on 2026-11-11.

### 12.1 Verified and fixed (branch `fix/agent-runtime-review-3`)

| Claim | Verified | Fix |
|---|---|---|
| A crash between committing `agent_event_seen` and dispatching loses the event for the live consumers | yes (`agent_runtime_ingest.go`: insert, then dispatch; only a normal error deleted the row) | migration 161 `dispatched_at`; undispatched rows are redispatched on EventBridge's retry (§5.6) |
| A Lambda interface does not identify one function | yes; AWS shares an interface across functions with the same subnet and security groups | candidate set from recorded Lambda VPC settings; unresolved `workload_set` when several (§11.3) |
| Non-overlapping event-time windows miss late log lines | yes (`StartQuery` on event time from the previous `read_to`) | windows cut by `@ingestionTime` with a 2 h late-arrival search (§11.2; activity spec, span reader). The ingestion filter was run against the lab log group: it selected the window's arrivals and excluded older ones |
| Resolver logs are not one line per question | yes; cached answers are not logged | counts described as resolution activity, not requests (§11.2) |
| EventBridge delivery "within seconds" is not a guarantee | yes; best effort per AWS | latency stated as measured, health shown (§5.6) |
| "CloudTrail records every call; scans count every model call exactly" | the system-design PDF overstated it; this spec (§5.1) already scopes coverage to management events, with data events seen only through the stream | PDF corrected |

### 12.2 Verified, not changed (needs a product decision)

- **Detections run only for labelled identities** (`AgentAlertLabels`,
  `agent_runtime_alerts.go`): an unlabelled or newly seen identity raises
  nothing until a scan labels it.
- **Containment success is configuration, not effect.** `contained` means the
  steps were applied; behavioural verification is separate (`effective`, late
  events). Lambda concurrency 0 stops **new invocations** only; restricting an
  IAM role does not revoke an external provider key the workload holds.

### 12.3 PROPOSED direction (not decided; for Aditya)

1. **A governed run as the central object.** Application and version, run id
   and parent run id, requester, owner and environment, task type, approved
   tools and resource scope, time/call/spend limits, progress checkpoints and
   state, and the interventions available. Supplied by trusted application or
   orchestration context (existing OpenTelemetry instrumentation plus a small
   run-context integration), never inferred from an IAM role or a DNS lookup.
2. **Four separate dimensions instead of one label ladder:** classification
   (agent, AI application, unknown), visibility (which sources report on it),
   attribution (run, workload, or shared identity only), control (what AuthSec
   can actually block or stop).
3. **Intervention contracts that state their real scope:** reject a tool call
   (gateway), stop further model calls (model gateway or provider control),
   cancel one run (orchestrator integration), restrict an AWS identity (IAM),
   disable new Lambda invocations (concurrency). Success reads requested →
   applied → independently checked → effect observed, with what remains
   unobservable; the UI names what happened ("New Lambda invocations disabled").
4. **Detection scope set by the customer** (monitored applications and
   infrastructure scopes), with detections running regardless of
   classification inside it; classification only adds context and priority.
5. **An approved behaviour envelope per application** (tools, resource
   scopes, destinations, budgets, deadlines, approval points), with findings
   phrased as departures from it ("accessed a production credential outside its
   approved scope; previous runs touched only the document store").
6. **Onboarding in three independent steps:** Connect (read-only AWS),
   Observe (traces and run context), Control (gateway or runtime integration).
   DNS logging, provider admin keys and classification review are optional,
   never prerequisites.
7. **Hard budget limits need admission control** (reservations at the request
   boundary, defined handling of in-flight requests); hourly provider
   reconciliation is accounting, not enforcement.
8. **Five demonstrations before expanding:** (a) two runs share a role, one
   misbehaves, the intervention leaves the other running; (b) a new workload
   acts suspiciously before classification and stays visible; (c) an agent
   holding an external provider key, with the UI stating which intervention can
   stop those calls; (d) events arriving late, twice, and across a processing
   crash, preserved without invented completeness; (e) a control applied but
   not behaviourally verifiable, shown as such.

What exists toward this: OTLP spans with trace and parent ids (activity
timeline), the request-time gateway (AuthZEN policy decision point), the
containment preview and separate enforcement role. What does not: run identity
and context, budgets with admission control, run-level cancellation, scoped
detection, behaviour envelopes.
