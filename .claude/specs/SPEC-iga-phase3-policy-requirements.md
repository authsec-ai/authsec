# Phase 3 — policy creation and enforcement requirements

Updated: 1 October 2026.

**Outcome:** remove unnecessary standing access while preserving application behavior. AuthSec owns policy lifecycle; AWS enforces native controls. This brief defines requirements for the forthcoming canonical implementation spec. All acceptance gates remain to be executed; numeric targets are planning estimates unless explicitly sourced. Existing Kubernetes code is review input, not design authority. Preserve existing integrations and runtime behavior.

## 1. Customers and day one

| Persona | Job | Day-one experience | Success |
|---|---|---|---|
| Security engineer | Reduce excessive privilege | Prioritized service-access, broad-grant, shared-role and expiry findings with owners and evidence | Approved, verified access reduction |
| Platform engineer | Protect uptime and infrastructure ownership | Diff, dependencies, known consumers, canary and direct/IaC delivery choice | Recoverable deployment through normal workflows |
| Agent developer / workload owner | Preserve the agent's required operations | Notification before proposal observation/canary: exact diff, retain-with-reason action and response deadline | Required jobs keep working; exceptions are reviewed |
| Auditor | Trace authorization and outcome | Read-only chain: finding, policy version, owner response, approval, deployment and verification | Exportable control evidence and visible gaps |
| CISO | Measure exposure and operational cost | Verified reductions, conversions, approval delays, rollbacks and coverage | Demonstrable improvement without hidden outages |

Start with **Review access recommendations**. Current service activity supplies the initial candidates; missing collection links to the existing collection-gaps surface. Write access is separately enabled.

## 2. Top ten customer requirements

1. **Prioritize my work:** explain each finding's risk, affected workload, owner and next action.
2. **Generate a tighter policy:** retain dependencies and justified infrequent operations.
3. **Show impact:** exact diff and consumers in R1a; historical request what-if in R1b.
4. **Consult the owners:** notify every known consumer, collect retain requests, then observe and canary.
5. **Fit approvals:** UI and Slack review of one immutable proposal, with separation of duties.
6. **Fit delivery:** direct apply or Terraform/CloudFormation PR against the customer's source of truth.
7. **Verify results:** distinguish applied, verified-for-scope and drifted, with recoverable changes.
8. **Bound standing privilege:** time-bound access and existing-session revocation in R2.
9. **Resolve shared roles:** disclose blast radius and propose dedicated identities where needed.
10. **Keep one workflow:** findings, templates, graph edges and identity pages lead into Agent policies and its existing operational screens.

## 3. Success measures

**Provenance:** the customer requested these metrics, but supplied no numerical targets. Every number below and in Appendix A is an author estimate for pilot validation, not customer research or a measured baseline.

| Metric | Counting rule | Planning target |
|---|---|---|
| Unused candidates removed | Deduplicate principal/service changes in R1a; action/resource/condition units in R1b. Count boundary-constrained access separately from removed grants | 20–40% of owner-approved eligible candidates in 30 days |
| Roles right-sized | Unique role incarnations with verified artifact and accepted operational evidence / eligible roles | 10–25% in 30 days |
| Standing access converted | Standing path closed and time-bound replacement/expiry verified / approved conversion candidates | 10–20% during pilot |
| Request to approval | Submission to authorized decision; p50/p95 plus pending, rejected and expired requests | Routine p50 15–60 minutes, p95 one business day; emergency 5–15 minutes |
| Apply to verified | Separate artifact readback and behavioral evidence clocks; pending/overdue remain visible | Artifact p95 1–5 minutes; behavior 15–60 minutes after qualifying evidence arrives |
| Safety | Unexpected denials, application-health changes and rollbacks per deployment | Critical attributable outage stops rollout; zero unapproved widening |

Show denominators, coverage and lower bounds. A statement or wildcard is not an exact action count. Correct metrics after rollback; adding an expiring grant beside unchanged standing access does not count as conversion.

## 4. Release 1 journey

**Findings → Generate proposal → Owner review → Observe → Approve → Canary → Verify → Expand → Monitor drift.**

### R1a: service-level right-sizing

Ship with the existing Access Advisor service reports, graph/inventory, policy documents and owner review. CloudTrail ingestion upgrades are not a dependency. An eligible example is: “No DynamoDB attempt reported in the reviewed 90-day interval; remove this role's DynamoDB permissions.” Use 90 days only when the evidence supports that interval. Null last-use, unread services or an identity younger than the interval cannot establish that history. Otherwise show the actual available period. [AWS last-accessed information](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html)

Generate a service-wide reduction for supported roles. Preserve unrelated actions, conditions, negations, trust and dependencies. A mixed-service statement must be transformed safely, not deleted wholesale; wildcard/NotAction cases outside the compiler's supported subset go to expert review. Removing one attachment does not remove independent grants.

R1a observation periodically refreshes service activity and collects owner/application-health feedback without mutating IAM. Respect source latency; this is not request-level shadow evaluation. Preview the native diff, known consumers and retained dependencies. Verify artifact readback, graph reconciliation and required application operations using existing health signals or customer-approved safe checks. Keep behavioral restrictions unobserved when there is no qualifying evidence. No production probe is required.

### R1b: action-level right-sizing

Add the CloudTrail pipeline: sufficient history, role-session attribution, resource/context preservation and relevant data events. Evaluate recorded events against the candidate without reissuing operations. Present retained, would-block and indeterminate results with observation range and coverage. Candidate evaluation and full AWS authorization evaluation remain distinct.

Use native Access Analyzer recommendations/generation where compatible. Its CloudTrail policy generation has a 90-day maximum window, omits action-level data events and PassRole, and includes denied events; review output before application. S3 GetObject action-level recommendations require appropriate data-event evidence, not just management history. [AWS policy generation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-generation.html)

### Owner gate, sharing and rollout

Before **proposal observation or canary**, send the role owner and every known consuming-workload owner the versioned diff, impact, retain-with-reason action and deadline. Record recipients, delivery, responses and retained requirements. Existing passive discovery continues normally. Missing ownership, delivery failure or silence blocks progression until resolved or an authorized reviewer records an explicit exception; silence never becomes consent. Material proposal/consumer changes reopen review. Owner acknowledgement and deployment approval are separate decisions.

A canary is an isolated principal with named consumers. Changing a shared role affects every consumer. Offer broader reviewed scope, supported session isolation, or **Propose dedicated identity**. A split includes trust/policy, workload-binding migration, adoption checks, old-access cleanup and rollback. Initial automated binding migration targets Lambda; preserve ECS task-role versus task-execution-role semantics. Never remove old access before required consumers adopt the replacement.

### Verification and four policy families

Track artifact verification, required operations observed and restriction observed/attributed separately. A generic AccessDenied proves that request failed, not which policy caused it; preserve attribution and distinguish authorization failures from throttling. No denial is expected when removed access was genuinely unused. [AWS denial diagnostics](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_access-denied.html)

| Family | Outcome |
|---|---|
| Governance | Ownership, review/expiry rules, findings and remediation workflow |
| Cloud access | Supported AWS-native restrictions and least-privilege ceilings |
| Time-bound access | Approved interval and verified old/new-session expiry behavior |
| Runtime/business | Tool allow-lists, human approval for risky operations and session budgets at a mandatory boundary |

Families share lifecycle, not interchangeable semantics. Kubernetes, AuthSec runtime and AWS remain separate deployment arms with per-target results.

## 5. UX and one inbox

**Findings are about the estate; Policy warnings are about a policy's execution; collection gaps stay on the existing coverage/collection-gaps surface.**

Estate findings cover unused-access candidates, broad/admin grants, shared-role review and missing customer-required expiry. Collection failures have one canonical gap record. Findings and policy details link to it; Policy warnings can say “deployment blocked by collection gap” without creating another collection incident. Resolution and deduplication use stable source IDs. An inherently permanent service role is not automatically a finding.

Keep **Agent policies** with Findings, Policies and Templates. Keep Scheduled actions, Policy warnings and Enforcement queue. Default rows show subject, reason, owner, interval, impact and next action. Reuse ConsolePage, AdaptiveTable and shared filters; collapse secondary columns to available width and reveal raw evidence on demand.

The authoring flow is:

1. **Recommendation:** retain/remove/unknown groups; R1a service or R1b action rationale.
2. **Impact and owners:** native diff, consumers, retain requests and response status; R1b adds historical what-if.
3. **Rollout:** observation, isolated canary, delivery mode, health gates and reversal plan.
4. **Approval:** exact plan in UI/Slack, with expiry and control mapping.
5. **Deployment:** per-target progress, verification dimensions, drift and next action.

Graph **Create policy** is the expert shortcut into the same flow. Resolve the holder/path before prefilling scope; keep View evidence and return to the original selection. Offer only supported restriction, right-sizing, time-bound or runtime actions.

Templates cover service/action right-sizing, document read access, secrets, bounded jobs, identity splits and later gateway/approval/budget controls. Every template has explicit actions, required evidence, parameters and version; updates cannot silently widen deployed policies.

Slack carries the immutable proposal and authenticated detail link. Verify signature/timestamp, active workspace membership, authorization, replay protection and separation of duties. Retain requests revise the proposal; approvals bind its hash. IaC mode links source file, PR, reviewed commit, plan/change-set and actual deployed artifact. Merge is not application. Direct mode respects IaC ownership. Automatic rollback needs a still-valid, pre-approved inverse plan.

Policy details lead with purpose, consumers, outcome and next action; ARNs, conditions, JSON and history are progressive details. Require keyboard access, text alongside color, back-navigation, saved filters and distinct loading/empty/partial/error states.

## 6. Requirements register

MUST gates the named release; deferring a SHOULD requires an owner and recorded exception. R1a ships service-level right-sizing; R1b adds action-level history/replay and inherits R1a's gates. R2 covers time-bound access; R3 covers runtime controls. All are increments within Phase 3.

### Policy meaning and evidence

| ID | Weight / increment | Requirement |
|---|---|---|
| P-01 | MUST R1a | Stable policy IDs, immutable versions, purpose, accountable owner, actor and timestamps |
| P-02 | MUST R1a | Four families; typed subjects, actions, resources, conditions, duration and exceptions; per-arm capability/results |
| P-03 | MUST R1a | Authenticated workspace scoping on reads, joins, approvals, jobs, callbacks and exports |
| P-04 | MUST R1a | RoleId/incarnation binding; recreation invalidates pending approvals and requires re-evaluation |
| P-05 | MUST R1a | Shared-role consumer impact and reviewed split proposal, with supported binding migration or explicit prerequisite |
| P-06 | MUST R1a | Explicit targets initially; selector expansion frozen in approval; future members require bounded standing authorization or new review |
| P-08 | MUST R1a | Defined conflict/default behavior per family; trace matching rules; exceptions cannot override independent AWS deny |
| P-09 | MUST R1a | Unknown/stale evidence blocks unsupported conclusions and offers a concrete next step |
| P-10 | MUST R1a | Separate author, approver, executor and emergency privileges; validate active membership and anti-self-approval policy |
| P-11 | MUST R1a | Findings-first entry and explainable recommendation lifecycle for unused access, broad grants, shared roles and expiry requirements |
| P-12 | MUST R1a | Generate tightened policy with retained dependencies, owner exceptions and a service-level rationale; R1b adds action-level rationale |
| P-13 | MUST R1a | Use current service activity, coverage and identity incarnation for R1a; qualify the observation period and exclude unread services |
| P-14 | MUST R1a | Customer success metrics with deduplication, cohort/coverage denominators, pending outcomes and rollback corrections |
| P-15 | MUST R1b | Upgrade CloudTrail history, session attribution and relevant data events; retain unmatched events, coverage, resources/context and correct authorization-error classification |

### Provider capability and policy interpretation

| ID | Weight / increment | Requirement |
|---|---|---|
| C-01 | MUST R1a | Expand Appendix C into exact per-release action/resource/condition, artifact, verification and reversal contracts |
| C-02 | MUST R1a | Validate native documents and service dependencies; surface quotas, size/version limits and unrepresentable scope |
| C-03 | MUST R1a | Versioned templates with explicit actions and parameters; no silently broadened upgrades |
| C-04 | MUST R1a | Lossless resource/selector/existence distinctions, conditions, negations and independent grants; graph edge is evidence, not a complete scope; removing one grant does not establish revocation |
| C-05 | MUST R1a | Evaluate relevant identity/resource policies, boundaries, organization/session constraints, trust and ownership for each supported change; preserve indeterminate results |
| C-06 | MUST R1a | Separate workload runtime identity from infrastructure execution identity and initiating human/session |
| C-07 | MUST R1a | State existing/future session, role-chain, alternate-route and service-mediated effects for each capability |
| C-08 | SHOULD R2 | Additional account/provider adapters preserve semantics through demonstrated support, not approximate translation |
| C-09 | MUST R1a | Tagged AuthSec-owned ceiling artifact for eligible roles, existing-boundary handling and authorized attachment changes |
| C-10 | MUST R2 | Native outage-independent expiry where supported and a separately authorized role-session cutoff action |

### Preview, approvals and ownership

| ID | Weight / increment | Requirement |
|---|---|---|
| L-01 | MUST R1a | Static impact preview names identities/workloads, independent grants and unknown consumers; R1a does not require historical replay |
| L-02 | MUST R1a | Human-readable proposal and exact native/IaC diff, including security-relevant conditions |
| L-03 | MUST R1a | Approval bound to version, targets, plan, observation revision and expiry; semantic changes require fresh approval |
| L-04 | MUST R1a | Audited, scoped, expiring exceptions and an explicit break-glass workflow |
| L-05 | MUST R1a | Separate discovery and opt-in enforcement credentials with least write privilege and protected administration roles |
| L-06 | MUST R1a | Ownership ledger plus provider tags where supported; Direct apply and Terraform/CloudFormation PR routes; no mutation outside authorized artifact/attachment scope |
| L-07 | MUST R1a | Self-lockout protection and explicit handling of customer boundaries, shared managed policies and IaC reconciliation |
| L-08 | MUST R1a | Reject unsupported document/attachment/quota combinations before apply; give the customer a viable alternative |
| L-09 | MUST R1a | Separate pause, disable, remove deployment and archive; retain visibility of deployed controls |
| L-11 | MUST R1a | Authenticated, replay-resistant Slack approval and UI approval use the same authorization/decision contract |
| L-12 | MUST R1a | Observe-to-canary-to-expansion rollout, explicit health gates and identity-isolated canary |
| L-13 | SHOULD R1a | Versioned compliance mapping and export, initially NIST least-privilege/access controls, SOC 2 logical-access criteria and ISO 27001 access-rights controls |
| L-14 | MUST R1a | Before proposal observation or canary, notify the role owner and every known consuming-workload owner with the exact diff, retain-with-reason action and deadline; record delivery/response. Silence is not consent; missing owners or nonresponse require resolution or an explicit authorized exception |
| L-15 | MUST R1b | Historical what-if evaluates recorded requests without executing them; show retained/would-block/unknown outcomes and missing context |
| L-16 | MUST R1a | Findings own estate issues; Policy warnings own policy-execution issues; collection gaps remain on the existing collection surface, linked without duplicate inbox items |

### Execution, verification and recovery

| ID | Weight / increment | Requirement |
|---|---|---|
| E-01 | MUST R1a | Separate authoring, evaluation, approval and deployment state |
| E-02 | MUST R1a | Per-target queued/applying/applied-unverified/verified-for-scope/partial/failed/drifted/rollback state and next action |
| E-03 | MUST R1a | Durable jobs, version fencing, bounded retries, idempotency and safe crash replay |
| E-04 | MUST R1a | Live target, ownership and artifact precondition validation before every write |
| E-05 | MUST R1a | Explicit multi-target partial result and compensation policy; no cross-account atomicity claim |
| E-06 | MUST R1a | Single change-verification-reversal contract: readback/hash, scoped operational evidence, graph reconciliation, and rollback that rechecks ownership/drift and preserves intervening edits |
| E-07 | MUST R1a | Propagation, telemetry and verification deadlines with separate awaiting-evidence/overdue outcomes |
| E-08 | MUST R1a | Drift detection and authorized report/reapprove/reconcile behavior without fighting customer tooling |
| E-09 | MUST R2 | Expiry and revocation across old/new sessions, outage, missed housekeeping and re-grant attempts |
| E-10 | MUST R1a | Append-only, redacted chain of finding, proposal, approval, artifact, attempt, verification, exception and rollback |
| E-11 | MUST R1a | Qualify Appendix A targets and §3 metrics; retain their provenance and distinguish AuthSec processing from provider latency |

### Runtime and agent-specific controls

| ID | Weight / increment | Requirement |
|---|---|---|
| R-01 | MUST R3 | Supported AgentCore gateway/tool allow-list at a mandatory enforcement boundary; document routing and alternate direct credentials |
| R-02 | MUST R3 | Authenticated workload, initiating human/delegation, tool/action, target and trusted request context |
| R-03 | MUST R3 | Decision binds operation arguments, policy version, approval and expiry; prevent substitution, replay and check/execute races |
| R-04 | MUST R3 | Block bypass or expose partial coverage; an optional SDK is not mandatory enforcement |
| R-05 | MUST R3 | Explicit outage/caching/revocation posture, latency and availability budgets; no silent fail-open |
| R-06 | MUST R3 | Human-in-the-loop for designated risky tools; durable hold, bounded approval, safe resumption, cancellation and no duplicate business operation |
| R-07 | MUST R3 | Distinguish AuthSec/gateway decisions from actual tool/AWS execution outcomes |
| R-08 | MUST R2 | Scoped temporary sessions with authenticated attribution; no credential values in evidence |
| R-09 | MUST R3 | Per-session budgets with atomic reservation, concurrent calls, retry idempotency, settlement/refunds and overshoot rules; specify count/cost/token units and metering source |
| R-10 | SHOULD R3 | Natural-language drafting produces typed reviewable proposals, never silent authorization; evaluate errors before relying on inferred intent |
| R-11 | MUST R3 | Minimize prompt/argument/response collection; customer-controlled redaction, retention, residency and access |

Retired IDs: P-07 → C-04; L-10 → E-06. C-01 has one matrix in Appendix C.

## 7. Acceptance table

Shared gates apply from R1a; rows marked R1b, R2 or R3 apply when that capability ships.

| Scenario | Required evidence |
|---|---|
| R1a end to end | CloudTrail disconnected: eligible service candidate → service-wide proposal → owner review → observation/approval/canary → readback → expected application operations; no action-history dependency |
| R1b end to end | Attributable history and data events support action-level generation/replay, followed by the same rollout and verification |
| Owner response | Every known owner receives the bound diff; retain requests change the proposal; delivery failure/nonresponse blocks transition unless an authorized exception is recorded; no timeout auto-approval |
| One inbox | A collection failure has one canonical gap record; affected findings/policies link it; policy warnings track blocked execution without duplicating the collection incident |
| Access Advisor period | An old last-attempt time supports the stated interval; null/unread/recently created cases cannot invent 90 days or removable action counts |
| R1b — incomplete/data-plane history | S3/other missing data events and ingestion gaps produce indeterminate preview and useful setup action |
| R1b — historical what-if | Known events produce retained/would-block/unknown results; no actual cloud operation is replayed |
| Native restriction | Dedicated fixture: formerly successful matching request is denied by the intended control; positive control still succeeds |
| R1b — passive CloudTrail verification | Attributable live denial supports only its scope; generic denial and non-authorization errors do not become proof; no traffic stays awaiting evidence |
| Duplicate grants / resource-policy route | One detached grant is not counted as complete removal; boundary implicit-deny exceptions are handled |
| Shared role / canary | Other consumers named; no false workload isolation; dedicated-role migration proves adoption before removing old access |
| Existing customer boundary | No silent replacement/widening; approved composition or alternate route, with reversible ownership plan |
| Role recreation | Same ARN/new RoleId cannot inherit approval or silently receive a previously approved mutation |
| Cross-account / workspace | Account ownership and native rights verified; foreign workspace cannot read, approve, apply or export |
| Slack approval | Forged, replayed, stale, self-disallowed or departed-member decisions rejected; legitimate approval binds exact plan |
| IaC PR | Correct source diff; reviewed revision matches deployment; merge alone remains pending; out-of-band change is detected |
| Concurrent edit / drift / rollback | Customer edit preserved; stale plan re-approved; reversal touches only authorized current artifact/attachment state |
| Worker crash / stale worker | Resume safely; obsolete lease cannot publish or apply a newer plan; idempotent effects and auditable outcomes |
| Multi-target partial rollout | Applied and failed targets distinct; stop/compensation is explicit and never falsely global success |
| Propagation and no traffic | Appropriate pending/overdue status, separately timed artifact and behavioral verification |
| R2 — expiry / AuthSec outage | Deployed native expiry holds at its supported boundary with AuthSec stopped; old/new sessions and cleanup verified |
| R2 — session revocation | Pre-cutoff role-session requests constrained; post-cutoff reacquisition behavior disclosed and separately controlled |
| R3 — runtime bypass / substitution | Unapproved direct path either blocked or out-of-coverage; altered arguments cannot reuse approval |
| R3 — human approval / budget concurrency | Pending/denied tool action does not execute; concurrent/retried operations cannot double-spend reservation or duplicate side effect |
| Graph and UX | Graph evidence retained, controls overlaid, status and coverage truthful; responsive tables and complete keyboard journey |
| Metrics and audit | Duplicate grants/wildcards/lower bounds handled; rolled-back removals corrected; export traces actor through provider evidence |

## 8. Delivery and spec handoff

Phase 2 includes entitlements, traversal and the complete graph console. Phase 3 delivers **R1a service-level right-sizing**, **R1b action-level right-sizing**, **R2 time-bound access/session response**, then **R3 runtime controls**. R1b inherits R1a's workflow, not a second policy product.

The spec must select exact supported transformations/artifacts, source ownership, migration/API contracts, attribution, approvals, job fencing, verification and rollback. Map each MUST to implementation and acceptance evidence. Design all families now while assigning delivery to these increments. Preserve existing K8s behavior and track its independent repairs.

## Appendix A. Operating envelope

All values here are author estimates; validate with pilot customers and benchmarks. Customer-supplied numerical targets: **none**.

| Area | Qualification range / rule |
|---|---|
| Scale | Pilot 1–10 accounts/workspace, 1,000 roles/account, 10 concurrent deployments/workspace; later qualify 10–100 accounts and 10,000 roles/account |
| Responsiveness | Ready list/preview p95 1–3 seconds; bounded analysis 1–5 minutes; larger jobs asynchronous |
| Execution | Start direct apply within 1–5 minutes outside maintenance windows; propagation checks over 1–15 minutes, then overdue/unverified |
| Drift | Check every 5–15 minutes; notify p95 within 15–30 minutes; show quota degradation |
| Retries | 3–5 jittered attempts over 10–15 minutes; terminal errors require intervention |
| Observation | Default 30 days, selectable 7–90 where evidence supports it; seasonal jobs need retained exceptions or longer supplied evidence; canary 24–72 hours plus relevant job cycle |
| Expiry | Deploy native cutoff ahead of deadline; housekeeping/display within 1–5 minutes; broker sessions initially 15–60 minutes where supported |
| Retention | 90 days searchable, 1 year retained; contractual archive 1–7 years; redact credentials and sensitive payloads |

Separate AuthSec latency from provider propagation and telemetry delivery. No traffic remains awaiting evidence; elapsed time alone does not pass a canary. Owner review deadlines are customer-configured and never an automatic approval timer.

## Appendix B. Existing-code reuse and repair map

Backend paths are relative to this repository; UI paths are relative to the sibling Authsec-ui checkout. Source inspection: backend `f166f78`, UI `4325889`.

| Existing code | Reuse / required extension |
|---|---|
| `models/agent_policy.go` | Retain policy/workspace identity and legacy targets; add versions, families, typed AWS targets and per-arm state |
| `services/agent_policy_service.go` | Keep orchestration, lookahead and reconciliation entry point; add AWS dispatch, owner review and plan-bound approval; repair empty-versus-absent ceilings and missing-evidence handling |
| `services/agent_policy_enforce.go` | Retain AuthSec role-binding narrowing/grant lapse; add separate AWS arm. Scope ceilings currently report excess rather than narrow arbitrary scopes |
| `services/governance_policy_worker.go` | Reuse scheduling responsibility; AWS work needs durable jobs and fencing |
| `services/policy_warning_service.go`, `services/policy_warning_senders.go` | Keep delivery lifecycle; add policy-execution notices. Slack approval needs authenticated callbacks, not just outbound warnings |
| `services/actuation_service.go`, `models/governance.go` | Preserve cluster transport; repair stale-worker report handling. AWS uses its own executor with shared queue presentation |
| UI `src/features/governance/AgentPoliciesPage.tsx`, `AgentPolicyDialogs.tsx` | Retain entry and authoring; add findings/templates and right-sizing workflow |
| UI `src/features/governance/UpcomingActionsPage.tsx` | Keep Scheduled actions; add AWS expiry, canary and session operations |
| UI `src/features/governance/PolicyWarningsPage.tsx` | Policy execution only; link canonical collection gaps |
| UI `src/features/governance/InstructionsPage.tsx` | Extend Enforcement queue with provider/job kinds and apply/verify states |
| `internal/awsdiscovery/activity.go` | R1a service-level recommendation input; tracked action details are not ingested |
| `internal/awsdiscovery/cloudtrail_events.go`, `services/cloud_aws_workload_scan.go` | R1b upgrade: current reader is 48 hours/10,000 management events, name-match attribution capped at 500 identities; any extracted error becomes denied. Add session attribution, correct error parsing/classification, context, data events and history |

Kubernetes quarantine targeting, policy-name collision, verification and lease defects remain separate repair gates; UI reuse does not certify that enforcement implementation.

## Appendix C. AWS contracts and capability matrix (C-01)

Use a tagged customer-managed permissions boundary as the preferred AuthSec-owned ceiling for eligible roles. Existing customer boundaries require approved composition/migration, never silent replacement. Same-account resource grants directly to role sessions can escape an implicit boundary deny; select a supported explicit restriction or reject the guarantee. Boundary removal can widen access. [AWS boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)

Tags identify managed-by, workspace reference, policy, target, version and change. Require an ownership ledger, native ID/hash and live preconditions too. Untaggable inline statements/attachments need parent/statement ownership or the customer IaC route. Attachment changes require explicit authority. [IAM tagging](https://docs.aws.amazon.com/IAM/latest/APIReference/API_TagPolicy.html)

R2 embeds UTC expiry using `aws:CurrentTime` where supported. Distinguish ending a grant from ending a restriction; an expiring Allow does not defeat alternate grants. “Stop at T” requires an applicable cutoff restriction, already deployed and propagated. Revoke existing role sessions through the supported `aws:TokenIssueTime` cutoff mechanism; reacquisition after the cutoff is separately controlled. [Time conditions](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_aws-dates.html), [session revocation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html)

| Capability | Release / design requirement |
|---|---|
| Named IAM roles | R1a service-wide reductions/ceilings for supported customer roles; RoleId, quotas, other grants and existing boundaries; exclude service-linked-role mutation |
| Mixed-service/wildcard documents | R1a exact supported transformation or expert review; preserve unrelated permissions, negations and conditions |
| S3 / DynamoDB | R1a whole-service candidate; R1b specific actions/resources require relevant data events, dependent permissions and policy context |
| SSM / Secrets Manager / KMS | Preserve parameter/secret scope and encryption dependencies; key policies/grants require dedicated analysis; no secret values |
| Lambda / STS | Invocation versus administration, caller versus execution identity, trust, PassRole and session effects |
| AgentCore / business tools | R3 mandatory tool boundary, trusted arguments, approval and atomic budget accounting |

Each supported row must specify actions/resource forms, conditions, dependencies, history, native artifact, old/new-session behavior, delivery, verification and reversal. AWS grants retained in the graph remain visible beneath control overlays.

## Appendix D. Research and design choices

| Source | Product implication |
|---|---|
| [Wiz CIEM](https://www.wiz.io/solutions/ciem) | Excess-access findings, remediation and contextual graph are category expectations |
| [Veza](https://veza.com/identity-security/) and [AI-agent security](https://veza.com/wp-content/uploads/2026/02/AI-Agent-Security-Veza-Feb-2026-.pdf) | Right-sizing and agent graphs already exist; demonstrate our workflow quality rather than claim uniqueness |
| [Sonrai recommendations](https://docs.sonraisecurity.com/cpf-public/cpf-interface/controls/services/services-intro/) and [approvals](https://docs.sonraisecurity.com/cpf-public/cpf-interface/workflow/requests/how-to-action-pod-requests/) | Used/unused-service controls and Slack workflows; approval does not create missing AWS permission |
| [AWS unused access](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-concepts.html) | Native findings support service/action refinement; integrate compatible analysis |
| [Astrix policies](https://astrix.security/learn/blog/set-access-policy-for-ai-agents/) | Allow/flag/block and hook integration inform runtime UX |
| [Oasis AAM](https://www.oasis.security/agentic-access-management) | Scoped sessions and escalation inform identity lifecycle |

AuthSec's intended emphasis by feature: findings tie to consuming workloads; templates retain agent-job dependencies; what-if explains affected paths; canaries isolate identities; Slack binds graph impact to the plan; IaC links policy version to deployment; ownership explains exact mutable artifacts; expiry exposes session effects; compliance exports the decision-to-evidence chain; runtime controls correlate tool sessions with cloud identity.

Choose OPA, Cedar/Verified Permissions or custom evaluation only after comparing a shared policy corpus, missing context, explainability, Go integration, latency, distribution, licensing and operating cost. Native AWS remains the enforcer for AWS controls; SDKs require a mandatory boundary. AgentCore Policy is scoped to configured Gateway traffic; approval orchestration and budgets need additional state. [OPA](https://www.openpolicyagent.org/docs), [Cedar](https://docs.cedarpolicy.com/), [Verified Permissions](https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/what-is-avp.html), [AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html)

Compliance exports record framework edition, control reference, rationale, evidence and gaps. Initial mappings: NIST AC-2/AC-3/AC-6, SOC 2 logical access and ISO 27001 access rights. Validate exact customer/licensed criteria before badges; mappings support audits, not certification. [NIST](https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r5/SP_800-53_v5_1-derived-OSCAL.pdf), [AICPA](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022), [ISO](https://www.iso.org/standard/27001)

CloudTrail Event history has management events independently of configured trails; data events need appropriate collection. Keep this distinction in R1b coverage. Simulations remain separate from live verification. [CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/how-cloudtrail-works.html), [data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events-console.html), [simulator](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html)
