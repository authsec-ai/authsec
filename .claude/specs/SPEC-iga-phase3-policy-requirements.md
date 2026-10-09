# Phase 3 — policy creation and enforcement requirements

Updated: 7 October 2026.

**Outcome:** remove unnecessary standing access while preserving application
behavior. AuthSec owns the policy lifecycle; each provider enforces its own
native controls. This brief defines what Phase 3 must do for customers. The
implementation design is [SPEC-iga-phase3-policy.md](SPEC-iga-phase3-policy.md)
(draft for review). The disposition of the existing agent-policy code is
[PLAN-existing-policy-code-disposition.md](PLAN-existing-policy-code-disposition.md).
All acceptance gates remain to be executed; numeric targets are planning
estimates unless explicitly sourced.

## 1. Architectural decision

Phase 3 is an **independent policy product**. It is designed from the
customer outcome, not from the code that happens to exist.

- It does not inherit the existing Kubernetes agent-lifecycle policy model:
  not the `agent_policies` root, its reconciliation service, the
  `provisioning_instructions` queue, the warning worker or the retired
  governance screens. That feature is assessed separately in the disposition
  plan and is retained, isolated, migrated or retired there, on its own
  gates.
- Independence does not mean duplicating sound shared infrastructure.
  Workspace authorization and permissions, Vault credential storage, the
  `audit_events` trail, notification transport and console primitives are
  reused **only through explicit, verified contracts** named in the
  implementation spec.
- Four domains stay distinct and are never converted into one another
  automatically:

| Domain | What it is | Example |
|---|---|---|
| Discovered provider policies and grants | Evidence of the customer's estate | An AWS managed policy, a Kubernetes Role and RoleBinding, as collected |
| AuthSec governance policies | Customer intent and its lifecycle | "Remove unused services from `RefundTaskRole`" |
| Provider artifacts | What AuthSec deploys to enforce that intent | An AuthSec-owned AWS permissions boundary |
| AuthSec's own runtime authorization | The shipped OAuth/OIDC, RBAC, token and Action Connector behavior | Workspace roles, client grants |

A discovered Kubernetes Role or AWS policy is never automatically an
AuthSec-managed policy. Phase 3 never edits AuthSec's own runtime
authorization as a side effect of a governance policy.

## 2. Customers and day one

| Persona | Job | Day-one experience | Success |
|---|---|---|---|
| Security engineer | Reduce excessive privilege | Prioritized findings with owners, evidence and its limits | Approved, verified access reduction |
| Platform engineer | Protect uptime and infrastructure ownership | Exact native diff, dependencies, known and unknown consumers, canary, direct or IaC delivery | Recoverable change through normal workflows |
| Workload owner | Preserve required operations | Notification before observation or canary: exact diff, retain-with-reason action, deadline | Required jobs keep working; exceptions are reviewed |
| Auditor | Trace authorization and outcome | Read-only chain: finding, evidence, policy version, owner response, approval, deployment, verification | Exportable control evidence with visible gaps |
| CISO | Measure exposure and operational cost | Verified reductions, approval delays, rollbacks and coverage | Demonstrable improvement without hidden outages |

Start with **Review access recommendations** in the Policy destination.
Collection problems stay in Connections and are linked, not copied. Write
access to a provider is separately enabled.

## 3. Top customer requirements

1. **Prioritize my work:** each finding explains the risk, affected workload,
   owner, evidence and its limits, and the next action.
2. **Generate a tighter change:** keep dependencies and justified infrequent
   operations; never remove access nobody selected.
3. **Show impact:** exact native diff, known and unknown consumers, and
   alternate grants that keep access.
4. **Consult the owners:** every known owner is asked before observation or
   canary; silence is not consent.
5. **Fit approvals:** UI and Slack review of one immutable proposal, with
   separation of duties.
6. **Fit delivery:** direct apply, Terraform/CloudFormation PR, or export
   for the customer to apply.
7. **Verify results:** distinguish applied, verified, drifted and unknown,
   with recoverable changes.
8. **Bound standing privilege:** time-bound access and session revocation
   (R2).
9. **Resolve shared identities:** disclose blast radius and propose
   dedicated identities.
10. **Keep one console:** Connections → Discovery → Policy → Logs. A finding
    or a discovered object leads into the same Policy workflow.

## 4. Success measures

**Provenance:** the customer requested these metrics but supplied no
numerical targets. Every number here and in Appendix A is an author estimate
for pilot validation.

| Metric | Counting rule | Planning target |
|---|---|---|
| Unused candidates removed | Deduplicate principal/service pairs; count only established removals, never exclusions with remaining or unknown routes | 20–40% of owner-approved eligible candidates in 30 days |
| Identities right-sized | Unique identity incarnations with a verified change and accepted operational evidence / eligible identities | 10–25% in 30 days |
| Standing access converted | Standing path closed and time-bound replacement verified / approved candidates (R2) | 10–20% during pilot |
| Request to approval | Submission to decision; p50/p95 plus pending, rejected and expired | Routine p50 15–60 minutes, p95 one business day |
| Apply to verified | Separate artifact readback and behavioral evidence clocks; pending and overdue stay visible | Artifact p95 1–5 minutes |
| Safety | Unexpected denials, health changes and rollbacks per deployment | A critical attributable outage stops rollout; zero unapproved widening |

Show denominators, coverage and lower bounds. Correct metrics after rollback.

## 5. Release scope and provider capabilities

Phase 3 releases are increments of one product. **R1a** is the first
release. The Kubernetes increment is a separate, later release (**R1k**)
because three prerequisites are not met today, and Kubernetes graph
availability alone does not meet them (§5.2).

### 5.1 Capability matrix

S = supported, B = prerequisite-blocked (named), D = deferred (named release),
— = not applicable.

| Capability | AWS IAM roles | Kubernetes RBAC (ServiceAccounts) | Kubernetes network containment | Runtime tool controls (AgentCore) |
|---|---|---|---|---|
| Discovery and declared relationships | S (published graph) | S, unrevisioned, from an unauthenticated ingress today → B for any policy use until K-1 | Legacy quarantine only (disposition plan) | D R3 |
| Activity evidence | S at service level (Access Advisor, identity-policy scope only); R1b adds CloudTrail history | **None collected.** No usage history exists; "unused" findings are impossible until audit-log evidence is designed (D, later than R1k) | — | D R3 |
| Recommendation generation | S R1a: unused services; broad grants; shared roles; ownership | D R1k: broad grants, shared ServiceAccounts, alternate bindings, ownership — **not** unused-permission removal | D | D R3 |
| Static impact preview | S R1a | D R1k | D | D R3 |
| Historical what-if | D R1b (CloudTrail) | Not planned without activity evidence | — | D R3 |
| Direct apply | S R1a: AuthSec-owned permissions boundary | D after R1k (needs a separate least-privilege actuation credential; K-3) | Retained legacy only | D R3 |
| IaC change proposal | S R1a: Terraform/CloudFormation PR | D R1k: GitOps manifest PR / export | — | — |
| Verification | S R1a: readback, graph, scoped behavioral evidence | D R1k: authenticated sweep readback | — | D R3 |
| Rollback | S R1a: undo to recorded before-state; remove-control restores baseline | D R1k | — | D R3 |
| Expiry / session behavior | D R2: `aws:CurrentTime`, `aws:TokenIssueTime` cutoff | D: RBAC changes apply to the next request; ServiceAccount tokens are not revoked by an RBAC change | — | D R3 |

**Enforcement mechanisms, named.** AWS R1a: a tagged, AuthSec-owned
customer-managed policy attached as the role's permissions boundary, whose
only content excludes the removed services
([boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)).
Kubernetes R1k: removal of a ServiceAccount subject from a RoleBinding or
ClusterRoleBinding, or replacement of a shared binding by a narrower
dedicated Role and binding — never a "deny", because RBAC "permissions are
purely additive (there are no 'deny' rules)"
([RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)).
Admission policies cannot restrict reads: "Admission controllers do not
(and cannot) block requests to read (get, watch or list) objects"
([admission](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)),
so admission is not an access-reduction mechanism. Network containment uses
NetworkPolicies, which "are implemented by the network plugin" and are
additive ([network policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/));
it is containment, not least privilege, and is not part of R1a or R1k.

### 5.2 Kubernetes prerequisites (block R1k)

| ID | Prerequisite | Why |
|---|---|---|
| K-1 | **Authenticated, ordered evidence.** Every discovery ingress call is authenticated by a workspace-bound, revocable collector credential; the workspace and cluster come from the credential, not the body; a snapshot carries the cluster UID and a collector sequence, and an older or replayed snapshot is rejected rather than projected as the newest generation | Today the RBAC snapshot route accepts a body-asserted workspace that is only checked for existence, and a replayed old snapshot ends newer grants. Evidence that anyone can forge cannot authorize a change |
| K-2 | **Server-side object identity.** A detail-by-identity read for ServiceAccounts, Roles and bindings, independent of list caps | Kubernetes lists cap at 500 with no cursor; a policy target cannot be found by scanning a page |
| K-3 | **Separate actuation authority.** A cluster credential distinct from the collector's, with only the RBAC verbs the supported mutations need, and an explicit decision on `bind` / `escalate` | Discovery credentials never authorize writes |

Until K-1 holds for a cluster, no Kubernetes finding, recommendation or
operation may be produced from that cluster's evidence; the UI says which
condition is missing and links to the Connections remedy.

### 5.3 Four policy families

Families share a lifecycle (draft, review, approval, deployment,
verification, drift, rollback, audit), not semantics.

| Family | Outcome | First release |
|---|---|---|
| Governance | Ownership, review and expiry rules, findings and remediation workflow | R1a |
| Cloud access | Provider-native restrictions and least-privilege ceilings | R1a (AWS), R1k (Kubernetes RBAC) |
| Time-bound access | Approved interval and verified old/new-session expiry | R2 |
| Runtime/business | Tool allow-lists, human approval for risky operations, session budgets at a mandatory boundary | R3 |

**Rules engine.** None is needed for R1a: the decisions are compilation of a
reviewed intent into one native artifact, and evaluation of collected
evidence against fixed finding rules. A rules engine does not change AWS or
Kubernetes permissions. R3 (runtime decisions on live requests) is where an
engine — Cedar, OPA or a custom evaluator — must be selected, against a
shared corpus, latency, explainability, Go integration and licensing.

## 6. Evidence and approval binding

The graph is not uniformly revisioned: AWS data is published with a
revision, Kubernetes and GitHub rows are written directly by sweeps and
scans, and the graph reader serves only the latest revision. Phase 3 must
not fabricate one global revision.

- **Evidence bundle.** Every proposal is evaluated against an immutable
  evidence bundle that copies the facts it relies on, or references content
  that is itself immutable (content-addressed documents, per-scan
  observations). A bundle records, per source: workspace; connection and
  estate scope; provider-native identity and incarnation; the publication,
  run, sweep or scan it came from; collection interval, freshness and
  coverage; source authentication and trust; native policy and binding
  versions or content hashes; known and unresolved consumers; constraints
  and evidence gaps.
- **Trust.** A source that is not authenticated, not ordered, stale or
  incomplete for the facts needed cannot support a removal; the proposal
  states which operation is blocked and the customer remedy.
- **Approval binding.** An approval binds immutable intent, resolved targets,
  the exact plan and its evidence bundle. Live target identity and the
  relevant native state are re-read before every mutation. A later scan is
  recorded as a **revalidation** against the approved evidence, which is never
  rewritten: if nothing material changed (targets, native change, live
  preconditions, consumers, owners, removed-service evidence, routes,
  unanalysed items, evidence gaps) the approval stands; otherwise the change
  is blocked with the diff and needs a new approval.
- **Accepted uncertainty is recorded.** Every evidence gap, unanalysed item
  or unavailable gate a person accepts is stored per item with its evidence
  binding, actor, reason and time.
- **Collection is never blocked indefinitely.** Evaluation runs within a
  bounded budget and fails safe; publication and collection continue.

## 7. Lifecycle

**Finding or selected object → policy draft → complete server-side target
resolution → impact preview → owner consultation → approval → rollout →
provider write → readback → behavioral verification where supported →
reconciliation → ongoing drift monitoring.**

A graph selection is context for a proposal, not its complete scope or
permission to mutate.

### 7.1 AWS R1a: service-level right-sizing

Use Access Advisor service reports, which cover only access "allowed by an
IAM identity's policies" and exclude resource-based policies
([last accessed](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html)).
An eligible example: "No DynamoDB attempt reported in the reviewed 90-day
interval through this role's IAM policies." Null last-use, unread services or
an unverified grant age cannot establish a longer history. Resource-policy
routes to the role are reported as known, absent or unknown and need owner
confirmation when they exist.

The change preserves every unselected permission by construction, keeps
dependencies, and distinguishes workload runtime roles from infrastructure
execution roles. In plain terms, R1a **restricts whole AWS services for
selected roles**; it does not produce action- or resource-level least
privilege (R1b), and the product says so wherever it describes a change.

### 7.2 Owner gate, sharing and rollout

Before **observation or canary**, send the identity owner and every known
consuming-workload owner the versioned diff, impact, retain-with-reason
action and deadline. Missing ownership, delivery failure or silence blocks
progression until resolved or an authorized reviewer records an exception.
Material changes reopen review. Owner acknowledgement and deployment approval
are separate decisions.

A canary is an isolated identity with named consumers. A shared identity
affects every consumer; offer broader reviewed scope or **Propose dedicated
identity** (trust/policy, binding migration, adoption check, old-access
cleanup, rollback). Never remove old access before consumers adopt the
replacement. Isolation and reduction are **separate changes with separate
approvals**: the dedicated identity first receives the source identity's
identity policies; it is narrowed later only from its own qualified
evidence or owner-reviewed requirements. Observing one consumer use a service
never establishes that another does not need it. The move is proven by live
evidence that the workload's running instances (tasks, function versions and
aliases, instances) use the new identity — not by the new identity existing —
and access granted to the old identity by name elsewhere is listed, updated or
explicitly accepted.

### 7.3 Verification

Track artifact verification, required operations and restriction observed
separately. A generic denial does not prove which policy caused it. No
denial is expected when removed access was genuinely unused.

## 8. Console experience

The console has four destinations: **Connections, Discovery, Policy,
Logs**. Phase 3 does not restore Agent policies, Scheduled actions, Policy
warnings or the Enforcement queue as sidebar entries.

- **Policy** holds the workflow, in secondary views: Findings, Policies,
  Approvals and Deployments, plus a Setup view for enforcement access, IaC
  sources and notification channels.
- **Logs** is the audit and event experience for policy and discovery events.
  It shows only recorded events; an event category without a source is shown
  as unavailable, never filled with sample data. Demonstrations use a
  separate, labelled preview mode.
- **Readiness before effort.** Policy shows, from the server, how many roles
  are eligible for direct apply, need IaC, need owner review, are blocked by
  collection gaps, or need no change — mutually exclusive categories with the
  reason per role — before a customer starts a proposal.
- **Connections** keeps collection problems; a blocked proposal links to the
  exact connection and coverage gap.
- Entrypoints: a finding that explains an actionable problem, or **Create
  policy** from a discovered object or graph relationship, with supported
  context prefilled and unsupported context explained.
- Targets are resolved by a server-side identity lookup, never from the rows
  a table happened to load, a truncated graph or frontend filtering.
- Each screen leads with the decision and next action; native documents and
  detailed evidence are available on demand. The current "Who / Can do / On
  / Where" preview is a visual starting point, not the policy schema; a
  policy also carries effect, conditions, duration, exceptions and provider
  limitations.
- Old bookmarks of retired screens reach an intentional replacement or the
  retirement state.

## 9. Requirements register

MUST gates the named release; deferring a SHOULD needs an owner and a
recorded exception.

### Policy meaning and evidence

| ID | Weight / release | Requirement |
|---|---|---|
| P-01 | MUST R1a | Stable policy IDs, immutable versions, purpose, accountable owner, actor and timestamps, in the independent policy model (§1) |
| P-02 | MUST R1a | Four families with distinct semantics; typed subjects, actions, resources, conditions, duration and exceptions; per-provider capability and results |
| P-03 | MUST R1a | Authenticated workspace scoping on reads, joins, approvals, jobs, callbacks and exports |
| P-04 | MUST R1a | Native identity and incarnation binding (AWS RoleId; Kubernetes object UID in R1k); recreation invalidates pending approvals |
| P-05 | MUST R1a | Shared-identity consumer impact and reviewed split proposal |
| P-06 | MUST R1a | Explicit targets resolved server-side by identity; selector expansion frozen in approval |
| P-08 | MUST R1a | Defined conflict and default behavior per family; exceptions cannot override an independent provider deny |
| P-09 | MUST R1a | Unknown, stale or untrusted evidence blocks unsupported conclusions and offers a concrete next step |
| P-10 | MUST R1a | Separate author, approver, executor and emergency privileges; active membership; no self-approval |
| P-11 | MUST R1a | Findings-first entry with an explainable lifecycle for unused access, broad grants, shared identities and ownership |
| P-12 | MUST R1a | Generated change keeps dependencies and owner exceptions, with a service-level rationale |
| P-13 | MUST R1a | Qualify the observation period, grant age and evidence scope; exclude unread services |
| P-14 | MUST R1a | Metrics with deduplication, coverage denominators, pending outcomes and rollback corrections |
| P-15 | MUST R1b | CloudTrail history, session attribution and relevant data events with honest coverage |
| P-16 | MUST R1a | Immutable evidence bundle per proposal, per-source trust and freshness, no fabricated global revision (§6) |
| P-17 | MUST R1k | Kubernetes prerequisites K-1 to K-3 hold for a cluster before any finding or operation uses its evidence |

### Provider capability and interpretation

| ID | Weight / release | Requirement |
|---|---|---|
| C-01 | MUST R1a | Exact per-release contracts for every supported mutation: native object changed, permissions required, scope of effect, propagation, verification evidence and reversal limits (§5.1, Appendix C) |
| C-02 | MUST R1a | Validate native documents and dependencies; surface quotas, size limits and unrepresentable scope |
| C-03 | MUST R1a | Versioned templates; no silently broadened upgrades |
| C-04 | MUST R1a | Preserve conditions, negations and independent grants; a graph edge is evidence, not complete scope; removing one grant is not revocation |
| C-05 | MUST R1a | Account for resource policies, boundaries, organization and session constraints for each supported change; keep indeterminate results |
| C-06 | MUST R1a | Separate workload runtime identity from infrastructure execution identity |
| C-07 | MUST R1a | State existing/future session, alternate-route and propagation effects per capability |
| C-08 | SHOULD R2 | Further adapters only through demonstrated provider support |
| C-09 | MUST R1a | AuthSec-owned, tagged ceiling artifact; customer boundaries handled without silent replacement |
| C-10 | MUST R2 | Native expiry and a separately authorized session cutoff |
| C-11 | MUST R1k | Kubernetes changes act on bindings and roles, account for every alternate binding and aggregated ClusterRole, and never claim a "deny" |

### Preview, approvals and ownership

| ID | Weight / release | Requirement |
|---|---|---|
| L-01 | MUST R1a | Static impact preview names identities, workloads, independent grants and unknown consumers |
| L-02 | MUST R1a | Human-readable proposal and exact native or IaC diff |
| L-03 | MUST R1a | Approval bound to version, targets, plan, evidence bundle and expiry; material changes need fresh approval |
| L-04 | MUST R1a | Audited, scoped, expiring exceptions and break-glass |
| L-05 | MUST R1a | Separate discovery and enforcement credentials, least write privilege, protected administration roles |
| L-06 | MUST R1a | Ownership ledger plus provider tags; direct, IaC PR and export routes; no mutation outside the authorized artifact |
| L-07 | MUST R1a | Self-lockout protection; customer boundaries, shared managed policies and IaC reconciliation handled explicitly |
| L-08 | MUST R1a | Reject unsupported combinations before apply, with a viable alternative |
| L-09 | MUST R1a | Separate pause, remove control and archive; deployed controls stay visible |
| L-11 | MUST R1a | Authenticated, replay-resistant Slack and UI approval on one decision contract |
| L-12 | MUST R1a | Observe → canary → expansion with explicit health gates |
| L-13 | SHOULD R1a | Versioned compliance mapping and export |
| L-14 | MUST R1a | Owner notification before observation or canary; silence is not consent |
| L-15 | MUST R1b | Historical what-if over recorded requests, without executing them |
| L-16 | MUST R1a | Findings own estate issues; a deployment's problems show on that deployment in Policy; collection gaps stay in Connections, linked, never duplicated |
| L-17 | MUST R1a | Targets and impact resolved server-side by identity, independent of list caps and graph truncation |

### Execution, verification and recovery

| ID | Weight / release | Requirement |
|---|---|---|
| E-01 | MUST R1a | Separate authoring, evaluation, approval and deployment state |
| E-02 | MUST R1a | Per-target queued / applying / applied-unverified / verified / partial / failed / drifted / undone state and next action |
| E-03 | MUST R1a | Durable jobs, fencing, bounded retries, idempotency and safe crash replay; a provider mutation whose outcome cannot be established is an explicit state that blocks conflicting operations until resolved |
| E-04 | MUST R1a | Live identity, ownership and artifact preconditions before every write |
| E-05 | MUST R1a | Explicit multi-target partial result; no cross-account atomicity claim |
| E-06 | MUST R1a | One change-verification-reversal contract; rollback rechecks ownership and preserves intervening customer edits |
| E-07 | MUST R1a | Propagation and verification deadlines with awaiting-evidence and overdue outcomes |
| E-08 | MUST R1a | Drift detection without fighting customer tooling |
| E-09 | MUST R2 | Expiry and revocation across sessions, outages and missed housekeeping |
| E-10 | MUST R1a | Append-only, redacted chain from finding to rollback, readable in Logs |
| E-11 | MUST R1a | Qualify Appendix A targets; separate AuthSec processing from provider latency |
| E-12 | MUST R1a | Legacy coexistence: no two systems own the same provider artifact or operation; legacy controls stay visible and manageable until their retirement gate (disposition plan) |

### Runtime and agent-specific controls

| ID | Weight / release | Requirement |
|---|---|---|
| R-01 | MUST R3 | Supported AgentCore gateway/tool allow-list at a mandatory boundary; document alternate direct credentials |
| R-02 | MUST R3 | Authenticated workload, initiating human, tool/action, target and trusted context |
| R-03 | MUST R3 | Decision binds operation arguments, policy version, approval and expiry; no substitution or replay |
| R-04 | MUST R3 | Block bypass or expose partial coverage; an optional SDK is not mandatory enforcement |
| R-05 | MUST R3 | Explicit outage, caching and revocation posture; no silent fail-open |
| R-06 | MUST R3 | Human-in-the-loop for designated risky tools with durable hold and no duplicate operation |
| R-07 | MUST R3 | Distinguish AuthSec decisions from actual tool and AWS outcomes |
| R-08 | MUST R2 | Scoped temporary sessions with authenticated attribution (conflict with R2 scope recorded in the implementation spec) |
| R-09 | MUST R3 | Per-session budgets with atomic reservation and settlement |
| R-10 | SHOULD R3 | Natural-language drafting produces typed reviewable proposals only |
| R-11 | MUST R3 | Minimize prompt and argument collection; customer-controlled redaction and retention |

Retired IDs: P-07 → C-04; L-10 → E-06.

## 10. Acceptance

Each scenario requires the stated evidence. The implementation spec records
whether its proof is a written walkthrough, an executed SQL probe, a fixture
test, or a real producer-to-provider run; only the last proves behavior.

| # | Scenario | Required evidence |
|---|---|---|
| 1 | AWS right-sizing end to end | Finding → proposal → owner review → approval → native change → scoped verification, on a real lab account |
| 2 | A selected graph edge has an independent grant | Preview names the other grant; removing the edge's grant is not reported as revocation |
| 3 | A shared identity affects several workloads | Every consumer named and asked; no false isolation; split proposal available |
| 4 | Role or ServiceAccount recreated under the same name | New incarnation cannot inherit approval or receive the mutation |
| 5 | Collection incomplete, stale or unauthenticated | Unsupported conclusions blocked with the remedy; nothing is compiled from untrusted evidence |
| 6 | Target beyond an inventory page cap | Resolved and opened by identity |
| 7 | Evidence changes after approval | Approval invalidated or the change blocked with the diff |
| 8 | Worker crash before and after a provider write | Safe resume; idempotent effect; auditable outcome |
| 9 | Customer edits the native artifact before rollback | Edit preserved; rollback blocked or role-scoped |
| 10 | Provider update succeeds, verification stays unknown | Applied-unverified then overdue; never verified by elapsed time |
| 11 | Legacy and new workers coexist during cutover | No artifact owned by both; legacy controls visible and manageable |
| 12 | Kubernetes alternate binding preserves access after one binding changes (R1k) | Preview and verification name the remaining binding |
| 13 | Retired screen bookmark | Lands on the intentional replacement or retirement state |
| 14 | One target fails in a multi-target rollout | Partial result explicit; never global success |
| 15 | Owner response | Delivery failure or nonresponse blocks; retain requests change the proposal |
| 16 | Slack approval | Forged, replayed, stale, self or departed-member decisions rejected |
| 17 | IaC PR | Merge alone stays pending; applied state matched to the reviewed plan |
| 18 | Metrics and audit | Exclusions with remaining routes not counted as removals; rollback corrections; Logs export traces actor to provider evidence |
| 19 | R1b, R2, R3 rows | As in each increment's own spec |

## 11. Delivery

R1a (AWS service-level right-sizing, governance findings) → R1b (action-level
AWS) and R1k (Kubernetes RBAC, after K-1 to K-3) → R2 (time-bound access) →
R3 (runtime controls). Each increment beyond R1a needs its own approved
implementation spec. The legacy agent-lifecycle feature follows the
disposition plan's gates; Phase 3 neither extends nor silently removes it.

## Appendix A. Operating envelope

All values are author estimates; validate with pilot customers.

| Area | Qualification range / rule |
|---|---|
| Scale | Pilot 1–10 accounts per workspace, 1,000 roles per account, 10 concurrent deployments per workspace |
| Responsiveness | List and preview p95 1–3 s; bounded analysis 1–5 min; larger jobs asynchronous |
| Execution | Direct apply starts within 1–5 min; propagation checks 1–15 min, then overdue |
| Drift | Check every 5–15 min; notify p95 within 15–30 min |
| Retries | 3–5 jittered attempts over 10–15 min; terminal errors need intervention |
| Observation | Default 30 days, 7–90 where evidence supports it; canary 24–72 h plus the job cycle |
| Retention | 90 days searchable, 1 year retained; redact credentials and sensitive payloads |

Elapsed time alone never passes a canary; owner deadlines never auto-approve.

## Appendix B. Existing code

The existing Kubernetes agent-lifecycle policy stack is not a starting point
for Phase 3 (§1). Its traced inventory, consumers and retain / reimplement /
isolate / migrate / retire decisions are in
[PLAN-existing-policy-code-disposition.md](PLAN-existing-policy-code-disposition.md).
Shared infrastructure reused by Phase 3 is named, with its contract, in the
implementation spec's baseline section.

## Appendix C. AWS contracts (C-01)

Use a tagged customer-managed permissions boundary as the AuthSec-owned
ceiling for eligible roles. A boundary limits resource-policy grants to the
role ARN but not same-account grants to a role session, and a resource-policy
`Deny` with `NotPrincipal` "will always deny any IAM principal that has a
permissions boundary policy attached"
([boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)).
Existing customer boundaries are never silently replaced. Removing a boundary
can widen access.

| Capability | Release / requirement |
|---|---|
| Named IAM roles | R1a service-level exclusion; RoleId incarnation; exclude service-linked roles |
| Mixed-service and wildcard documents | R1a preservation by construction (exclusion-only ceiling) |
| S3 / DynamoDB actions | R1b, with data events |
| SSM / Secrets Manager / KMS | Preserve scope and encryption dependencies; key policies and grants need dedicated analysis |
| Time-bound access | R2: `aws:CurrentTime`, session cutoff via `aws:TokenIssueTime` ([dates](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_aws-dates.html), [revocation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html)) |
| AgentCore / business tools | R3 mandatory tool boundary |

## Appendix D. Research

| Source | Use |
|---|---|
| [Wiz CIEM](https://www.wiz.io/solutions/ciem), [Veza](https://veza.com/identity-security/) | Excess-access findings and graphs are category expectations; compete on workflow quality, not claimed uniqueness |
| [Sonrai](https://docs.sonraisecurity.com/cpf-public/cpf-interface/controls/services/services-intro/) | Unused-service controls and Slack approval flows challenge our customer workflow |
| [AWS unused access](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-concepts.html) | Native findings to integrate where compatible |
| [Astrix](https://astrix.security/learn/blog/set-access-policy-for-ai-agents/), [Oasis](https://www.oasis.security/agentic-access-management) | Runtime allow/flag/block and scoped sessions inform R3 UX |

Competitor material challenges our workflows; it is not evidence of their
internal architecture.
