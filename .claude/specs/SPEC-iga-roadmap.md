# SPEC: IGA roadmap — discovery, identity graph, policy enforcement

> **Phase numbering updated 1 October 2026.** Phase 1 is connect and collect;
> Phase 2 is the complete scanning-to-declared-access-graph journey, including
> entitlement relationships, traversal APIs and console; Phase 3 is policy
> creation and enforcement. Phase 3 R1a/R1b/R2/R3 are release increments, not separate
> numbered phases. Renumbering does not certify implementation or deployment.
>
> Phase 1 contracts: [SPEC-iga-phase1-collect.md](SPEC-iga-phase1-collect.md).
> Phase 2 target: [SPEC-iga-phase2-graph.md](SPEC-iga-phase2-graph.md).
> Phase 3 proposed customer requirements:
> [Phase 3 policy requirements](SPEC-iga-phase3-policy-requirements.md).
> Phase 3 R1a implementation spec (draft for review):
> [SPEC-iga-phase3-policy.md](SPEC-iga-phase3-policy.md); R1b, R2 and R3 need
> their own specs. Existing Kubernetes policy code is review input, not its
> design authority.
>
> Product context: [SPEC-agentic-access-management.md](SPEC-agentic-access-management.md).
> Sections 1–3 retain the earlier graph planning/reference material; dated source
> claims there are not a current implementation audit. Where contracts conflict,
> the active Phase 2 spec governs graph delivery, and each approved Phase 3
> increment spec governs its policy enforcement.

---

## 1. Historical implementation snapshot (15 September 2026)

### 1.1 Reported built and serving in that snapshot

AWS discovery is wired end to end at a basic level. `routes/routes.go:1647–1683`
serves onboarding, connector create/list/get/verify/revoke, `POST
/aws/connectors/:id/scan`, and reads for identities, secrets, assume-edges,
permissions, resources, workloads and usage. Collectors live in
`internal/awsdiscovery/{onboarding,iam,workloads,bedrock,eks,activity}.go` and
`services/cloud_aws_*_scan.go`.

**List endpoints paginate and scope to one connector** (PR #54, `a09362e`).
`CloudSecretFilter`, `CloudPermissionFilter` and `CloudWorkloadFilter` each carry
`IdentityID`, `ConnectorID`, `Limit` and `Offset` through a shared `clampLimit`.
Before this, six of seven list endpoints returned every row in the workspace and
five could not be scoped, so a workspace with two connected accounts mixed both
accounts' rows together.

**Coverage reflects the whole scan, not just IAM** (PR #54, `4615d9d`). The
permission and workload scans now fold their outcomes into connector coverage
before it commits.

Two other sources exist and are **not** part of this roadmap's scope:
the GitHub IGA provider (`services/iga_github_provider.go`) and the
`authsec-iga-agent` Kubernetes collector running in `authsec-system`.

### 1.2 Reported gaps in that snapshot; recheck before implementation

| Defect | Where | Consequence |
|---|---|---|
| Scan execution is not durable | `controllers/platform/cloud_aws_controller.go:408` launches a `go func()` | worker death loses the run; nothing resumes it |
| No evidence written | cloud collectors | no relationship can cite an observation, so nothing is explicable |
| Ingestion is insert-only **on the GitHub/IGA path** | `repository/iga_repository.go:616–629` — `UpsertIdentityAccount`, `UpsertCredential`, `UpsertResource`, `UpsertEntitlement`, `UpsertAccessEdge` call `Create`; reached from `services/iga_service.go` | that path duplicates on rescan. **The AWS path does not**: the `cloud_*` repositories use `ON CONFLICT … DO UPDATE` on natural keys throughout |
| `AgentDetail` returns `Instances: []` | `services/iga_service.go` | the deployment half of an agent has no read path |
| No `cloudtrail` client | — | no observed usage; activity is Access-Advisor *attempts*, which include denied ones |
| No resource-policy reads | no S3 client | a bucket policy that denies an action is invisible, so a grant it blocks still reads as access |
| **Frontend ignores pagination** | `Authsec-ui/src/app/api/cloudDiscoveryApi.ts:924` | its comment still says these routes are "UNPAGINATED … the server has no limit/offset", which PR #54 made false. `clampLimit` returns **100** when none is sent, so an account with 250 workloads renders 100 and counts, filters and summarises over that subset as though it were everything |
| **Frontend does not render constraints** | `Authsec-ui/.../AWSIdentityTabs.tsx:163` | no types for `condition`, `not_actions`, `not_resources`, `constraint_state` or `derivation='boundary'`, so a boundary statement appears beside granting policies and a conditional grant appears without its condition |
| Role identity keyed on ARN alone | `repository/cloud_identity_repository.go:93` | a role deleted and recreated under the same name keeps its row and overwrites `attrs`, losing the `RoleId` change that is the only evidence it is a different principal |
| Statement identity is positional | `services/cloud_aws_permission_scan.go:523` — `native_id` is `<source>#s<index>` | inserting or reordering a statement in AWS still repoints an existing permission row. Parser-skip renumbering is fixed; author edits are not. Needs `Sid` where present, else a versioned semantic fingerprint |
| Wildcard resource selectors collapse | `services/cloud_aws_permission_scan.go` | two different partial-wildcard resources in one statement become the single `resource_id IS NULL` row, so their exact targets are lost at persistence |
| Reconciliation deletes rather than ending | `ReconcileGeneration` | rows are removed instead of retaining an ended period, so "what changed since yesterday" is unanswerable |

**Fixed 2026-09-15, migration `019`.** Policy parsing was discarding every element
that narrows a statement, which made permissions read broader than they are:

- `Condition` was not in the parser struct at all — a tag-gated grant rendered as
  unconditional.
- A statement written with `NotAction` **vanished entirely**, because the parser
  required a non-empty `Action`. A `Deny` expressed that way left no trace.
- `NotResource` was recognised, then widened to `*` by the writer — turning a
  bounded exclusion into an account-wide grant.
- A malformed document returned zero statements and no error, so a broken policy
  was indistinguishable from one that grants nothing.
- The permissions boundary was never read, though it sits in the `GetRole`
  response already being parsed for tags.
- The **trust** parser took the first `:sub` condition across every operator, so
  `StringNotEquals` produced the same principal as `StringEquals` — recording a
  trust relationship the policy exists to forbid. A negative condition now
  yields no subject, and the federation is recorded as unscoped rather than
  confidently wrong.

All are recorded rather than evaluated: `cloud_permission` gained
`not_actions`, `not_resources`, `condition` and `constraint_state`, and identity
attrs gained `permissions_boundary_arn`. **`constraint_state` is the load-bearing
column** — only `unconstrained` may be rendered as plain access, and database
checks refuse a conditional or negated row that claims otherwise. Boundary
documents are stored with `derivation = 'boundary'` so no query counts a ceiling
as a grant.

Rows that existed before this migration are backfilled to `constraint_state =
'unknown'`, **not** `unconstrained`. They were collected by a scanner that
discarded conditions; calling them unconstrained would stamp "we checked and
found nothing" onto rows nobody checked. They leave `unknown` on the next scan.

**Reconciliation is gated on read completeness — for documents and statements.** `ScanFromSnapshot` deletes rows from
older generations when it reports `Complete`, and `Complete` ignored parse
failures — so a trust document that would not parse deleted that role's real
edges. Reproduced: **assume edges went from 1 to 0** on a scan whose only fault
was an unreadable document. `Complete` now requires `ParseFailures == 0` **and** `StatementsSkipped == 0`,
and a partially-read surface reports `partial`, which `Complete()` rejects. Both
were reproduced as data loss — trust edges 1→0, permissions 1→0 — and both are
held by regression tests that fail with the gate removed.

**This closes two specific deletion defects and nothing more.** Safety under
overlapping scans, worker crashes and expired workers publishing stale results is
durable execution's job (Phase 1, P1-2) and is not addressed here.

**Statement identity no longer shifts on a parser skip.** `native_id` was
`<source>#s<index>` over the *parsed* slice, so one unusable statement renumbered
every statement after it. The index is now the position in the original document.
**This is a partial fix and the issue stays open** — the key still changes when
someone inserts or reorders statements in AWS. A stable key needs a
policy-scoped `Sid` where the author set one, and a versioned semantic
fingerprint with defined duplicate handling where they did not. Document position
remains useful evidence; it is not an identity.

**An unknown boundary is not an absent one.** A failed `GetRole` leaves the
boundary unknown; classifying that as `unconstrained` erased a ceiling we never
checked for. Boundary state is now three-valued, and unknown yields
`constraint_state = 'unknown'`.

Earlier attempts at these fixes stopped short and were caught in review:
`UpsertPermission` rejected any statement with no `Action`, and its conflict
clause refreshed none of the new columns — so a `NotAction` Deny still never
reached the database, and a statement that gained a `Condition` in AWS kept its
old unconditional row across a rescan. Both are fixed, with end-to-end tests that
scan, mutate the policy, and rescan
(`tests/integration/cloud_aws_constraints_test.go`). **Parser tests could not
have caught either.**

**No new AWS permission was needed.** The boundary ARN comes from the `GetRole`
response already being read, and the boundary document through the same
`GetPolicy`/`GetPolicyVersion` pair used for attached policies. The
CloudFormation template is unchanged.

**Also fixed:** `cloud_workload`, `cloud_usage` and `cloud_scan_checkpoint` were
created by migrations `015`–`017` but missing from `001_bootstrap.sql`, so a
fresh install and a migrated database disagreed — a new install failed scans with
`relation "cloud_scan_checkpoint" does not exist`. Bootstrap now mirrors them.

### 1.3 Security findings recorded in that snapshot, independent of phases

| ID | Defect | Gate |
|---|---|---|
| A3 | Cross-tenant references accepted by the database; polymorphic `subject_id` is not a foreign key | cross-tenant insert fails at the database |
| A4 | `Decide` never checks the actor against the assigned reviewer; delegation ignores a failed membership lookup; decision, item update and counters are not atomic | wrong reviewer rejected; concurrent keep and revoke converge to one outcome |
| A5 | Certification's fallback stamps `revocation_executed_at` without removing the entitlement; actuation accepts a report with no current lease | no path records "executed" or "verified" without a confirming source re-read |
| — | `iam:GetAccountAuthorizationDetails` granted but never called; `iam.go` performs the per-identity walk its own justification says it avoids | collect it, or correct the grant and its justification together |

A1 (GitHub binding accepted caller-supplied proof) and A2 (a denied scope was
emptied by another scope's success) are fixed at `3e93618` and `3a45b07`.

---

## 2. Foundations

Settled. They do not change between phases, and no phase may reopen them.

### 2.1 Deployment and isolation

IGA is a package in the AuthSec binary, served from the `prod-authsec` pod on
`prod.api.authsec.ai`, against the single `authprod` database and `public` schema.

| Item | Rule |
|---|---|
| Table naming | `iga_*` in `public` |
| Connection | the existing single `GetMasterDB()` pool; no second role or DSN |
| Migration line | `migrations/master`, continuing at `019` |
| Legacy coupling | only through a named bridge table carrying its own state, evidence and decision record |
| Ad-hoc joins | prohibited; CI fails an IGA file naming a non-`iga_` table outside a short allowlist |

A database privilege boundary is not available: `discovered_agent_iga_links`
(`migrations/deltas/governance_iga_bridge.sql`) carries foreign keys to both
`public.discovered_agents` and `public.iga_agents`, because linking the runtime
channel to the correlated estate is the product feature. A role without a grant
on `public` would forbid that join along with every careless one.

The allowlist is empty today — `repository/iga_repository.go`,
`services/iga_*.go` and `controllers/platform/iga_controller.go` reference no
legacy table.

**Not covered.** One database, one pool, one process, one node. This stops
coupling growing unreviewed; it gives no protection against a legacy incident.
Physical separation is a cutover prerequisite, not an MVP one.

### 2.2 Membership authority

IGA reads membership through a Go interface, never by querying a legacy table.

```go
type MembershipAuthority interface {
    Members(ctx context.Context, workspaceID uuid.UUID) (MembershipSnapshot, error)
    Member(ctx context.Context, workspaceID, subjectID uuid.UUID) (Member, error)
}
```

| Question | Rule |
|---|---|
| Shape | injected at construction, as `InstallationVerifier` is into `NewIGAManager` |
| Authority | legacy is authoritative; IGA never creates a member |
| Freshness | 5-minute cache; a revocation invalidates it directly |
| Unavailable | mutations fail closed; reads serve from cache with a staleness banner |
| Stale ceiling | a snapshot older than 60 minutes blocks mutations entirely |

**External identity is never login membership.** Discovering `priya@acme.com` as
an IAM user creates an identity account. It does not create an AuthSec member,
grant console access, or make her selectable as a reviewer. Joining a discovered
identity to a member is an explicit evidenced decision, never an email match.

### 2.3 AWS coverage manifest

Enumerated from the SDK clients imported in non-test code: `iam`, `sts`,
`lambda`, `ecs`, `ec2`, `eks`, `bedrockagent`, `bedrockagentcorecontrol`.

| Surface | Calls | Scope |
|---|---|---|
| Caller identity | `sts:GetCallerIdentity` | global |
| IAM roles / users | `ListRoles`, `GetRole`, `ListUsers` | global |
| Access keys | `ListAccessKeys`, `GetAccessKeyLastUsed` | global |
| Role / user policies | `ListAttachedRolePolicies`, `ListRolePolicies`, `GetRolePolicy`, and the user equivalents | global |
| Managed policies | `GetPolicy`, `GetPolicyVersion` | global |
| OIDC providers | `ListOpenIDConnectProviders` | global |
| Activity | `GenerateServiceLastAccessedDetails`, `GetServiceLastAccessedDetails` | global |
| Lambda | `ListFunctions` | per region |
| ECS | `ListTaskDefinitions`, `DescribeTaskDefinition` | per region |
| EC2 | `DescribeInstances`, `iam:GetInstanceProfile` | per region |
| Bedrock | `ListAgents`, `GetAgent` | per region |
| AgentCore | `ListAgentRuntimes`, `GetAgentRuntime` | per region |
| EKS | `ListClusters`, `DescribeCluster`, `ListPodIdentityAssociations`, `DescribePodIdentityAssociation` | per region |

**Historical collection-gap list; not current coverage authority.** The earlier
review listed the following calls as granted but uncollected. Current source now
contains `internal/awsdiscovery/cloudtrail_events.go`, with a bounded management-
event reader; Phase 3 requires deeper history and attribution. Recheck every
remaining entry against the active collectors and coverage manifest:
`cloudtrail:LookupEvents`/`DescribeTrails`/`GetTrailStatus`;
`bedrock-agentcore:ListGateways`/`ListGatewayTargets`/`ListWorkloadIdentities`/
`ListOauth2CredentialProviders`/`ListApiKeyCredentialProviders`;
`iam:GenerateCredentialReport`/`GetCredentialReport`/`GetAccountAuthorizationDetails`.
Collect them or remove them from the template — an over-grant nobody uses is a
finding in the customer's security review.

**Coverage states — two levels, not one.** The implementation already models
this correctly and the spec follows it: per-surface reachability and overall scan
outcome answer different questions and must not be collapsed.

*Per surface*, written into `CloudConnector.Coverage` — `models/cloud_discovery.go`:

| State | Meaning | Whose problem |
|---|---|---|
| `reached` | read successfully | — |
| `denied` | the role lacks the permission | the customer's to fix |
| `throttled` | AWS rate-limited us; incomplete | ours to retry |
| `not_configured` | the customer has not set this up | the customer's choice |
| `unsupported` | **to add** — we have built no collector | ours to build |
| `not_selected` | **to add** — excluded from the selected scope | a deliberate choice |

*Per scan run*: `running`, `complete`, `partial`, `failed`. **`complete` is the
only state in which reconciliation may age a row out** — every surface reached.
`partial` means it finished with at least one surface denied or throttled;
`failed` means it could not start or died before any surface completed.

`unsupported` and `not_selected` are the two surface states the code does not yet
carry, and Phase 1 adds them. Without them, a surface with no collector is
indistinguishable from one the customer declined.

**Never a percentage.** Averaging these says nothing, because they have different
owners: a denied surface is fixed by the customer, an unsupported one by us, and
a not-selected one by neither. A surface that was not reached preserves prior
facts as stale and never ends a relationship.

### 2.4 Query budgets

| Budget | Value |
|---|---|
| max nodes per traversal | 500 |
| max edges per traversal | 2,000 |
| max depth | 6 — workload → identity → assume → identity → grant → resource |
| wall clock | 3 s |
| page size | 100, max 500 |

A depth limit alone does not bound a hub node such as a shared role. **Cursors
bind to a graph publication**, not only to a sort key: a stable sort cannot keep
pages consistent while a scan publishes underneath. A request against a retired
publication returns `410` with the current publication id.

Every response carries `truncated` with its reason, plus per-edge `basis`,
`state`, `last_confirmed_at` and evidence references, and coverage caveats. A
budget stop returns `incomplete`. It never returns "no further access".

### 2.5 Concurrency and time

- All upserts use `INSERT … ON CONFLICT … DO UPDATE` on the natural key. No
  read-then-write — that is the race behind the duplicate-on-rescan defect.
- A scan writes in a fixed order: object registry → typed record → relationships
  → evidence. Consistent ordering is what stops two scans deadlocking.
- Typed relationship checks are deferred to commit, because an edge and its
  endpoints are written in one transaction.
- **Publication is a single transaction**: coverage, generation and
  reconciliation commit together or not at all. A half-published scan is what
  lets one scope's success license another scope's deletion.
- Three times, never conflated: `observed_at` (when the provider's data was
  true), `ingested_at` (when we stored it), `published_at` (when a scan became
  authoritative). Reconciliation orders by scan generation, never wall-clock.

---

## 3. Invariants

Every phase honours these. They are the reason the graph is worth building.

### 3.1 What an edge may claim

| Edge | Claim | Does NOT mean |
|---|---|---|
| workload → identity | configured execution identity | that it ran, or ran as that |
| gateway → lambda | configured tool target | that an invocation succeeded |
| identity → grant | a policy assigns this | that a request would be allowed |
| grant → resource | a selector names this | that the resource exists |
| identity → identity | trust permits assumption | that assumption succeeds |
| person → agent | accepted accountability | any cloud permission |

Priya owning the assistant does not let her assume its role. That is why `basis`
is a column and not a display detail:

```
declared   provider configuration says so
observed   we saw it happen, with attribution
derived    we computed it, naming the rule and its inputs
asserted   a human decided it, with authority recorded
```

**The console never labels a configured path "can access", and never labels an
inventory sighting "usage".**

### 3.2 Identity and continuity

A bare native id is never unique. Every key is namespaced by
**(provider, partition-or-host, account-or-project, region-if-regional)**, in both
uniqueness indexes.

| Type | Recognition key | Continuity | Immutable key |
|---|---|---|---|
| IAM role | ARN | immutable | `RoleId` (`AROA…`) |
| IAM user | ARN | immutable | `UserId` (`AIDA…`) |
| Lambda | function ARN | recognition_only | — the ARN embeds the name, not a creation boundary |
| ECS task def | `family:revision`, namespaced | recognition_only | — |
| EC2 instance | instance id | immutable | instance id |
| S3 bucket | ARN | recognition_only | — |

`recognition_only` is recorded on the object so a reviewer knows "same name" is
the strongest claim available, and so a future creation-boundary signal can
upgrade it.

**Delete-and-recreate** applies only where an immutable key exists: same
recognition key with a different immutable key is a **new object**, and the old
one retires with reason `recreated`. Merging them would carry ownership decisions
and review history onto an unrelated principal.

**An integration is a route, not an identity.** Two integrations observing one
role produce one object with two observation streams. Reconnecting must not mint
a new object. Equal display names across accounts never merge.

**A text kind beside a bare UUID is not a foreign key — that is how cross-tenant
references got in (A3).** Every relationship endpoint is a typed, nullable column
with its own composite foreign key on `(workspace_id, id)`, and an
"exactly one is set" `CHECK` across the set. `022_cloud_observation.sql` is the
reference implementation; Phase 2 applies the same pattern to
`iga_access_edges`.

### 3.3 Relationship lifecycle

Every relationship carries validity:

```sql
    state             text NOT NULL DEFAULT 'current',
    valid_from        timestamptz NOT NULL DEFAULT now(),
    valid_to          timestamptz,           -- NULL while current
    last_confirmed_at timestamptz NOT NULL DEFAULT now(),
    last_confirmed_by uuid,                  -- the scan run that last saw it
    ended_reason      text NOT NULL DEFAULT '',
    CONSTRAINT rel_state_chk CHECK (state IN ('current','stale','ended')),
    CONSTRAINT rel_ended_chk CHECK ((state = 'ended') = (valid_to IS NOT NULL))
```

- **current** — a recent authoritative read confirmed it.
- **stale** — we could not look. Still believed, with its last confirmation time
  shown. A failed or denied scan produces this and never `ended`.
- **ended** — an authoritative read of the owning scope and class did not see it.

**Collapsing `stale` into `ended` lets a permissions outage read as a cleanup.**
That single distinction is why reconciliation is per `(scope, object class,
relationship type)` and driven by scan generation.

A relationship may be ended only when all of these hold: the scan published
successfully; coverage for the owning `(scope, class)` is complete; the
relationship's own source surface was among what that scan read; and the run owns
the publication generation for that surface.

Ended rows are never deleted — a review decision made last quarter must remain
explicable against the access that existed then.

| Case | Expected |
|---|---|
| Lambda moves `RoleA` → `RoleB` | old edge `ended` with `valid_to`; new edge `current`; both in history |
| managed policy detached | grant `ended`; the entitlement and its document survive |
| statement removed from a policy | that entitlement's grants end; other statements untouched |
| scan of that scope denied | edges become `stale`, never `ended` |
| one of two integrations loses visibility | edge stays `current`; the losing stream is stale |
| policy re-attached later | a **new** grant period; the previous one stays closed |

### 3.4 Evidence

Configuration reads **are** evidence. Every relationship has at least one
supporting observation, through a junction so several can support one edge, with
both endpoints workspace-scoped by composite foreign keys.

Two bases need more than an observation:

- **derived** — records rule id, rule version and the input relationship ids in
  `derivation jsonb`. A derived edge whose inputs have ended is recomputed, not
  left standing.
- **asserted** — records the decision id, the deciding principal and their
  authority. Asserted evidence uses an authenticated decision observation, never
  a fabricated scan.

Retained evidence is not cascade-deleted while a retained edge depends on it.
Retention and redaction are explicit policy with an auditable
evidence-unavailable state.

Redaction happens **before** hashing: AWS response → sensitive-field deletion →
normalized → hash. No secret values, Kubernetes Secret contents or source-code
secrets are ingested.

### 3.5 Policy versioning, and the revocable unit

Three levels, never collapsed: a **stable policy** identity (fully namespaced and
owned — two roles can each have an inline policy called `s3-read`, and they are
different policies), **immutable document versions**, and **stable statements**
with revisions. A policy edit must not reset statement identity, or last
quarter's review becomes unexplainable.

`ACCESS_GRANT` is the revocable unit and names the **role-policy attachment**,
not just a statement. Detaching a managed policy from one role ends that
attachment's grants for that role and leaves other roles untouched; editing the
shared document affects every attached principal. A review item must disclose the
revocable unit and its other consumers.

One current grant per assignment, enforced by a partial unique index
`WHERE state <> 'ended'`, so re-attachment opens a new period instead of
colliding with the closed one.

### 3.5a Declared-graph constraints and policy evaluation are separate

A permission row says what a document grants. Four things narrow that, and each
is stored rather than applied: a `Condition`, a `NotAction`, a `NotResource`, and
the identity's permissions boundary.

`constraint_state` carries the result — `unconstrained | conditional | negated |
bounded`. These describe collected constraints, not effective authorization.
Even an unconstrained declared statement is not proof of successful access.
Database checks must preserve constraint information. Phase 3 adds separately
scoped evaluation and verification; it does not relabel declared graph edges as
effective access. A boundary's own statements are stored with `derivation = 'boundary'`:
they never grant, they cap.

This is the line between this milestone and effective access. We can say "this
policy grants `s3:GetObject` on `reports/*` when `PrincipalTag/Team` is
`operations`". We cannot say whether a given request succeeds, and the schema is
built so nothing can quietly start claiming that.

### 3.6 Selectors: preservation vs resolution

Two different things.

- **Preservation** — `iga_entitlement_revision.resource_selector` holds the
  selector verbatim whether or not any resource is known. Never lossy.
- **Resolution** — `iga_grant_resource`, one row per *matched* resource. Zero
  rows is a legitimate answer.

The attempt is recorded on the grant: `resolution_state ∈ complete | partial |
unsupported | not_performed`. `complete` means evaluated against a named
supported inventory snapshot and scope — **zero matches never proves no access
outside that coverage**. Unresolved selectors are displayed even when no resource
node exists.

### 3.7 Provider-neutral boundary

AWS is the implementation scope; the product is multi-provider. A GCP role
definition, a conditional resource binding and an Entra app-role assignment each
need provider-specific mapping. Binding conditions and assignment scope need a
contract separate from statement conditions.

Record the extension point; do not build unvalidated integrations or a generic
policy language in order to finish the AWS graph. Provider-native documents stay
available for reparsing.

---

## 4. The phases

Each phase ends with a customer-visible outcome and executed acceptance evidence.
The former entitlement, traversal and console phases are consolidated into Phase 2;
there is no separate Phase 3 “Entitlement graph” or deferred Phase 4/5 graph UI.

| Phase | Delivers | Depends on | Exit gate |
|---|---|---|---|
| **0 · Foundations** | Topology, tenant/membership authority, scope/coverage and lifecycle contracts | — | Approved contracts and reproducible baseline checks; no assumed isolation |
| **1 · Connect and collect** | AWS onboarding, durable scanning, evidence, pagination, coverage and stable inventory | 0 | Real-account scan and recovery; failed reads cannot masquerade as complete; superseded work cannot publish |
| **2 · End-to-end identity and declared-access graph** | Objects, entitlement/statement/assignment history, typed evidenced relationships, publication/reconciliation, bounded traversal APIs, inventories and usable console | 1 | Customer follows a real workload through identity and declared permissions to resources, examines evidence, changes the source and sees a safe rescan; parser (§5), workspace, lifecycle and UI gates pass |
| **3 · Policy creation and enforcement** | Findings-driven right-sizing, policy lifecycle and AWS arm, preview, approval, rollout, verification, drift/reversal; later time-bound and runtime increments | 2 plus each capability's evidence prerequisites | Actual supported policy outcome traced from finding/UI to provider artifact and scoped operational evidence, including failure/recovery; relevant MUST gates in the approved Phase 3 spec pass |

**Phase 3 increments:** R1a delivers service-level right-sizing using existing
Access Advisor evidence, generated proposals, owner review before observation or
canary, static impact preview, Slack/UI approval, direct or Terraform/CloudFormation
PR delivery and scoped verification. It does not depend on upgraded CloudTrail.
R1b adds action-level right-sizing with attributable history, relevant data events
and historical what-if, reusing the same workflow. R2 adds broader time-bound
access, native expiry, session revocation and expanded identity-split support;
R1a already includes shared-role impact and a supported split path. R3 adds
mandatory gateway/tool controls, human approval and session budgets. These labels
reserve no automatic completion status.

Phase 2 re-proves per-scope reconciliation and publication invariants on its own
code path. Native-agent claims require a real supported provider agent; a fixture
labelled registered/simulated does not establish provider-native discovery.

### API and console contract

`/api/iga/v1`, served by the existing binary — a route prefix, not a separate
deployment. Required surfaces: integration create/verify, scan enqueue/status,
coverage, paginated identities/workloads/agents/resources, agent instances,
bounded relationships and access paths, and object/relationship evidence.

The server takes the authorized workspace from the authenticated context, never
from a query parameter. View permissions and integration mutations are separate.

Every list, graph and evidence read accepts and echoes a **published revision**
(`rev`), so one investigation cannot mix revisions. A newer publication is
offered, never applied silently. A revision is **current-only** in Phase 2:
the client pins it in memory, links never carry it, and a shared link
reproduces the object, view and filters as they are now.

The console uses `ConsolePage` and existing API/state conventions, and shows
source scope, identity continuity, basis, state, observation time, evidence and
unresolved selectors. Loading, empty, partial, failed, stale, unconnected and
truncated states must look different from one another — in particular a failed
request must never render as an empty list.

The entry point is the **estate** — agents and workloads across every connected
provider — not a graph and not a per-provider inventory tree. Estate-wide
identity and resource lists stay first-class, because an investigation often
starts from a shared role or a sensitive resource.
[SPEC-iga-phase2-graph.md](SPEC-iga-phase2-graph.md) §2.14 specifies the
experience, §2.15 the contracts behind it, and §2.16 traces one path end to
end.

---

## 5. Parser acceptance

Required before Phase 2 closes and before Phase 3 relies on parsed policy
semantics. These are acceptance requirements, not reported test results.

| Case | Expected |
|---|---|
| `Deny` + `NotAction` | the statement appears at all, with `not_actions` populated |
| `Allow` + `Condition` | condition stored verbatim; `constraint_state = conditional`; no effectiveness claimed |
| `NotResource` | preserved in `not_resources`; never widened to `*`; `constraint_state = negated` |
| trust with `StringNotEquals` on `:sub` | never yields the same principal as `StringEquals` |
| trust with multiple operators | every operator read, not just the first |
| malformed document | `ErrMalformedPolicy`, counted as a parse failure, never an empty result |
| managed policy at non-default version | the operative version is the one recorded |

---

## 6. Boundaries between graph delivery and policy enforcement

- **Phase 2 is a declared-access graph.** A configured path is evidence of a
  grant or relationship, never universal proof that a request succeeds. Phase 3
  adds capability-scoped evaluation, native changes and verification separately.
- **Activity has a source and coverage.** Access Advisor reports attempts at its
  supported grain. Current source also contains bounded CloudTrail management-
  event collection; that is not complete data-plane history or reliable role-
  session attribution. Phase 3 R1a qualifies service-level evidence; R1b supplies
  the upgraded history required for action-level recommendations and replay.
- **Resource selectors are not resource enumeration.** Phase 3 must collect or
  explicitly qualify the resource and policy context required by each supported
  operation; graph presence alone cannot authorize mutation.
- **Runtime enforcement is a distinct capability.** Gateway discovery does not
  prove that requests traverse a mandatory enforcement boundary. Phase 3 R3 must
  prove routing, identity, approval, budget and bypass behavior.
- **Discovery credentials never write.** Phase 3 adds separate opt-in enforcement
  authority and respects customer-owned Terraform/CloudFormation workflows.
- **Preserve existing integrations.** Kubernetes, GitHub and legacy runtime
  functionality remain intact. AWS is the first end-to-end enforcement focus,
  not the entire product or permission to remove other providers.
- **No name-based identity merging or speculative graph database requirement.**
  Preserve immutable incarnation, evidence, ownership and measured scale.

The graph remains useful independently of enforcement. Policy deployment does
not erase the collected grants; the UI overlays desired controls, observed
artifacts and scoped verification with distinct states. Certification and other
broader governance work retain their own explicit scope and future acceptance
gates rather than being implied by completion of Phase 3 R1a or R1b.
