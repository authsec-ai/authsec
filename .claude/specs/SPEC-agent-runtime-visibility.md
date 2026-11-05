# SPEC: Agent runtime visibility on AWS — discover, detect, contain

> **Status: proposed, revision 2, for review** (Ritam, 2026-11-05). Reviewer:
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
built); DNS/egress and node-sensor signals; OpenAI/Anthropic admin APIs;
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
6. **Q6** Human approval: Ritam decided against it for this scope; NIST design tenet 5 is human-in-the-loop for sensitive actions. Keep it out, or require approval for identity-level containment?
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
| Provider admin keys, LLM gateway with provider keys | Out of the AWS pilot (§2) |
| Unverified MCP header and AuthZEN dates, EO naming | Removed (not needed for AWS) |
| "Only GitHub writes `iga_agents`" unverified | Removed |
| Kubernetes ingress described too harshly | Removed (Kubernetes deferred) |
| 9–11 weeks optimistic | Smaller scope; P1–P3 6–7 weeks backend, stated as estimates |
