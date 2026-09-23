# SPEC: AWS discovery to a working identity graph

> The phase after [SPEC-iga-phase1-collect.md](SPEC-iga-phase1-collect.md).
> Product context is
> [SPEC-agentic-access-management.md](SPEC-agentic-access-management.md); the
> invariants this work must honour are [SPEC-iga-roadmap.md](SPEC-iga-roadmap.md) §3.
>
> **Inspected, 2026-09-23.** Every claim about current behaviour below was
> traced in code at these commits, not taken from names, comments or earlier
> reports:
>
> | Tree | Commit | What it is |
> |---|---|---|
> | Backend, production | `authsec` `0e75ad7` (`origin/authsec-staging`) | What customers run. Migrations `001`–`026` |
> | Backend, implementation branch | `authsec` `7eb8bed` (`origin/graph`) | Ritam's work against an earlier, incomplete version of this spec. Migrations `027`–`034`, **unshipped** |
> | Console | `Authsec-ui` `c74fcf7` (`authsec-staging`) | What customers run |
>
> "**Staging**" below means `0e75ad7` / `c74fcf7`. "**Graph branch**" means
> `7eb8bed`. The two are always distinguished; nothing on the graph branch is
> described as current behaviour.

## 0. The completion promise

**When the implementation of this document is finished, a customer can do
this, in the product, against their own AWS accounts:**

```
connect AWS → choose regions → scan → see collection progress and coverage
  → the identity graph publishes
  → browse agents and workloads, identities and resource references
  → open one, follow workload → execution identity → policy statements → resource
  → explore the same paths visually
  → inspect the evidence behind any claim, and what it cannot establish
  → change something in AWS → rescan → see exactly what changed, and what did not
```

That working journey is the milestone. **A stored graph, a single inspection
endpoint, fixtures, or screenshots are not completion.** P2-0 and the first
read path (§6) are intermediate milestones on the way to it.

"End to end" means **complete through the supported evidence pipeline** in
§1.4. It does not mean every AWS resource is discovered, and it does not mean
AWS authorization is evaluated. Every screen says which.

**How to read this document.**

| Question | Section |
|---|---|
| What ships, in what order, and what is deliberately not in it | §1.1–§1.2 |
| What exists today, what the graph branch built, what must change | §1.3 |
| What an AWS scan collects, surface by surface | §1.4 |
| What the change does to GitHub, Kubernetes, GCP and legacy consumers | §1.5 |
| The canonical model and its identity rules | §2 |
| The customer experience | §2.14 |
| Schema | §3 |
| Projection, reconciliation, publication | §4 |
| Read APIs, traversal and read consistency | §5 |
| Implementation handoff: tasks, and the requirement → task → proof map | §6 |
| Acceptance, including the end-to-end gate | §7 |

---

## 1. What this milestone delivers

### 1.1 Delivery stages

Everything the journey in §0 depends on is in this milestone. It is built in
eight stages, in dependency order. The stages are **internal sequencing, not
separate deliverables**: nothing is complete until S8 passes.

| Stage | Delivers | Why it comes here | Detail |
|---|---|---|---|
| **S1 · Pipeline safety** | Every inventory write and delete fenced to the run that owns it; one generation per run; the workspace barrier that hands over cleanly; the projector started by one explicit switch; recovery that frees stuck workspaces; no busy loops | Every later stage writes through this pipeline. The graph branch shows what happens without it: after the first scan, a workspace can never scan again (§1.3) | §2.8, §2.10, §4.11, T1.x |
| **S2 · Connect, configure, observe** | AWS connection and verification (exist); region selection **after** onboarding; scan history per account; one pipeline status for the workspace: queued, collecting, projecting, published, failed | The first screen of the journey. Today regions are fixed at onboarding and a scan's outcome is never shown (§1.3) | §1.4, §5.3, T2.x |
| **S3 · Complete, honest collection** | Groups and memberships; user permissions boundaries; policies as objects with their documents; trust documents with conditions and Deny; per-document parse isolation; the workload fixes; a coverage vocabulary that says `unsupported` when it means it | The graph can only be as true as what is collected. §1.4 lists the gaps that make today's data wrong, not merely incomplete | §1.4, §3 `035`, T3.x |
| **S4 · Canonical model and projection** | Stable objects; policies, statements, assignments and grants as separate identities; structural relationships; external principals; per-source support; evidence links | The model the product ships. No later rewrite is planned (§2.6) | §2, §3 `027`–`036`, §4, T4.x |
| **S5 · Reconciliation, publication and history** | Trustworthy absence checks; `current`/`stale`/`ended`; atomic publication with a workspace revision; statement revisions and assignment periods for the Changes view | "Rescan and see the correct changes" is this stage | §2.7, §4.10, T5.x |
| **S6 · Read APIs and traversal** | Every API the console needs, with one read-consistency contract, typed references and bounded traversal | The console reads only through these | §5, T6.x |
| **S7 · Console** | Agents & workloads, Identities, Resources, object detail tabs, the graph, evidence, changes, coverage, scan states | The customer-facing product | §2.14, T7.x |
| **S8 · Integrated acceptance** | The end-to-end gate against real AWS lab accounts, through the real backend and console | The only stage that proves the milestone | §7.1 |

**Intermediate milestones**, each a checkpoint, never a stopping point:

| Milestone | Proves | Gate |
|---|---|---|
| **M0 · P2-0** | One narrow slice through the real pipeline: scan → projection → publication, with S1's safety properties | §6, P2-0 gate |
| **M1 · First read path** | The Agents & workloads list and one workload's Identities and Resources tabs, over §5's contracts | §7.2 UI1–UI4 on those screens |
| **M2 · Full console** | Every screen in §2.14, including the graph, against fixtures and a real scan | §7.2 in full |
| **M3 · Milestone complete** | The journey in §0 | §7.1, all sixteen scenarios |

### 1.2 Deferred capabilities

A **stage** is work in this milestone. A **deferred capability** is not built
here, and nothing in the product may imply it exists. The two are never
mixed: nothing below is a dependency of §0's journey.

| Deferred | Why it is safe to defer | What the product says instead |
|---|---|---|
| **Effective-access evaluation** (conditions, SCPs, boundaries, session policies, resource policies combined into "would this request succeed") | The journey explains *declared* access. Evaluation is a separate engine with its own correctness burden | Every grant reads "declared"; effective access is always "not evaluated" (§2.14.9) |
| **Resource-policy grants** (bucket and key policies as grants to principals) | Bucket and KMS key policies are read (§1.4), but their statements are not projected into grants | The resource's Overview says whether a resource policy was read and whether it contains a Deny |
| **Comprehensive resource inventory** (ListBuckets, ListKeys, …) | Resources in this milestone are what policy statements name | Every resource is labelled "exact reference" or "selector"; never "discovered resource" (§2.14.12) |
| **Broader telemetry** (CloudTrail-attributed "observed" relationships, data events) | CloudTrail lookups exist as evidence only, matched by user name; they cannot attribute role sessions | Activity is Access Advisor with its documented limits (§2.14.8); nothing has `basis = observed` |
| **Historical graph reconstruction** ("the graph as of 1 March") | Retained history is per relationship and per statement (§2.7, §5.1) | Changes are shown; past graphs are not |
| **Logical-agent grouping and agent instances** for AWS | Bedrock aliases are not collected; grouping is a correlation claim (§2.12) | Each workload stands alone. A Bedrock agent shows "instances not collected" |
| **Automatic classification** | Inference from names or tags is unreliable | Classification is provider-native or a person's decision |
| **Ownership, certification, remediation** for AWS objects | Existing governance features are preserved as they are (§1.5); this milestone does not feed them AWS data | Owner reads "Not assigned" |
| **AgentCore gateway → tool relationships** | Targets are listed with name, status and type; their backing Lambda, OpenAPI or MCP server is not collected (`GetGatewayTarget` is never called) | A gateway's Overview lists its targets and says their backing tools are not collected |
| **Organizations and SCPs** | Not collected | Coverage reports `organizations: unsupported` |
| **Scheduled scans** | Rescans are started by a person; nothing in the journey needs a schedule | The scan button, and the last scan's time |
| **Additional providers in the graph** (GitHub, GCP, Kubernetes) | Their existing features keep working unchanged (§1.5). The model is provider-neutral so they can project into it later | They appear where they appear today, not in the new AWS graph screens |

### 1.3 Starting point: implementation map

What exists, what the graph branch built, and what this milestone changes.
"Proof" names the acceptance scenario in §7.1 (`E#`) or §7.2 (`UI#`) that
fails if the change is missing.

**Collection and pipeline**

| Requirement | Staging (`0e75ad7`) | Graph branch (`7eb8bed`) | Required change | Proof |
|---|---|---|---|---|
| Connect and verify an AWS account | **Built.** CloudFormation package, `POST /aws/connectors`, `…/verify` (`cloud_aws_onboarding.go:108-233`) | Unchanged | Reuse | E1 |
| Choose regions | Fixed at onboarding; no update route (`routes.go:1664-1710`) | Unchanged | `PATCH /aws/connectors/:id` plus the account's enabled regions (§5.3) | E1 |
| Start a scan; see its outcome | Enqueue only; `GET /aws/scan-runs/:id` exists; no list of runs; the console never shows published/failed (`AWSConnectorDrawer.tsx:186-199`) | Unchanged | Scan-run list, pipeline status, console states (§2.14.7) | E1, E9 |
| Superseded worker cannot change data | **Not true.** Upserts and deletions run before the fenced `Publish` (`cloud_aws_scan_worker.go:185`) | Upserts fenced (`scan_fence.go`); **deletions (`ReconcileGeneration`) not fenced** | Fence deletions too | E13 |
| One generation per run | A re-claimed run keeps its generation while the IAM scan computes `scan_generation + 1` again (`cloud_scan_run_repository.go:123-127`, `cloud_aws_iam_scan.go:182`) | Unchanged | Scanners use `run.Generation`, never recompute | E13 |
| Publication, coverage and projection job in one transaction | Coverage best-effort after publish | **Built** (`PublishWithCoverage`) | Reuse | E13 |
| Workspace barrier | None | Built, with three defects: nothing starts the projector; the barrier stays in the scan worker's name so projection waits ~15 min; a busy barrier makes the worker requeue in a tight loop | §2.10A as corrected: job-held barrier, explicit switch, backoff | E13 |
| Schema-presence check | n/a | Caches "absent" on a transient error for the process lifetime, silently disabling the barrier | Fail closed; decided by the switch, verified at startup (§4.11) | E13 |
| Recovery of stuck workspaces | n/a | `RecoverStalled`, phase-aware; sound | Reuse, started with the projector | E13 |

**Collection completeness** (the full contract is §1.4)

| Requirement | Staging | Graph branch | Required change | Proof |
|---|---|---|---|---|
| IAM groups and membership | **None.** No API call, no identity kind | Unchanged | `GetAccountAuthorizationDetails` (already granted, never called) | E3 |
| User permissions boundaries | **Never read**; every user statement stored `unconstrained` (`cloud_aws_permission_scan.go:438-446`) | Unchanged | Read from authorization details | E4 |
| Policies as objects | **None.** Only per-holder statement rows; version, AWS-managed flag and name dropped | Unchanged | `cloud_policy` + `cloud_policy_attachment` with the document | E6, E7 |
| Statement identity survives reorder | `native_id = <source>#s<index>` | Same key | Sid, else content hash (§2.6) | E7 |
| One malformed document | **Aborts the whole permission scan** and reports only `permission_scan: denied` (`cloud_aws_permission_scan.go:587-595`) | Unchanged | Isolate per document; `policy_documents: partial` names it | E9 |
| Trust policies | Allow only; conditions discarded; no evidence (`trust_policy.go:186-188`) | Unchanged | Store the document; parse Allow and Deny with conditions; evidence | E4, E11 |
| Role details survive a failed `GetRole` | `attrs` replaced wholesale, losing tags and boundary (`cloud_identity_repository.go:73-127`) | Unchanged | Authorization details replace `GetRole`; attrs merge, never blank | E9 |
| Silent detail failures | `DescribeTaskDefinition`, `GetAgent`, `GetAgentRuntime`, `GetGateway`, `GetInstanceProfile` failures leave the surface `reached`, so rows can be deleted | Unchanged | Surface becomes `partial`; `partial` blocks deletion | E9 |
| Service not offered in a region | Recorded `denied`, which blocks workload reconciliation for the connector on every run | Unchanged | `unsupported` for "not available in region" | E9 |
| Bedrock agent key | ARN, or bare agent id when `GetAgent` fails, so the object's key changes | Unchanged | Construct the ARN deterministically | E7 |
| AgentCore gateway | Row kept; its evidence labelled `aws:unknown`; `GetGateway` not in the role template | **Projector crashes the process** on gateways (`project.go:710`) | Fix the label; add `GetGateway`; project gateways as workloads | E1 |
| ECS execution role | Stored in attrs, never linked | Unchanged | Its own relationship (§2.2) | E3 |
| Access Advisor | Silently stops after 500 identities; a throttle reports `denied` | Unchanged | `partial` above the cap; `throttled` on throttle | E4 |
| Resource-policy coverage | `reached` even when every read was denied | Unchanged | Count per-resource failures | E4 |

**Model, projection, reconciliation**

| Requirement | Staging | Graph branch | Required change | Proof |
|---|---|---|---|---|
| Stable identities across rescans | Canonical upserts are bare `Create` | Keys and real upserts for AWS objects; sound | Reuse for AWS; extend to policies, statements, assignments | E1 |
| Workload vs agent vs instance | n/a | Writes AWS rows into `iga_agents` and `iga_agent_instances`, which GitHub lists and the Kubernetes bridge read | **Do not** write agents or instances for AWS (§2.2, §1.5) | E16 |
| Independent grants | n/a | One entitlement per (policy, statement index, resource) | Policy, statement, assignment and grant as separate identities (§2.6) | E6 |
| Deny and boundaries | n/a | Projected as ordinary outbound grants | Never grants (§2.6) | E4 |
| Shared resources across accounts | n/a | `Load` reads resources by the last scanner's `connector_id`, so the other account's grant becomes `*` | Targets derived from the statement text, not from the shared `cloud_resource` row (§4.7) | E10 |
| External principals | n/a | Table only; nothing creates rows | Created from trust principals and pod-identity associations (§4.7) | E11 |
| Recreate, restore, suspend | n/a | Built for identities; sound | Reuse; extend to policies | E8 |
| Reconciliation, support | n/a | Built; sound | Reuse, with the new partitions | E9, E10 |
| Publication, replay | n/a | Built; `AlreadyPublished` verified by mutation | Reuse | E13 |

**Read path and console**

| Requirement | Staging | Graph branch | Required change | Proof |
|---|---|---|---|---|
| Graph read APIs | None. The console reads `cloud_*` through `/authsec/discovery/aws/*` with offset paging clamped at 500 (a limit above 500 silently becomes 100) | One route: `GET /workloads/:id/access-path` (no revision, no expansion, rights serialized as base64) | §5's catalogue replaces it | E3 |
| Classification | n/a | `POST /estate/:id/classification`, `discovery:admin`, no idempotency, a retry after success returns `409` | `POST /workloads/:id/classification` with an operation id, `iga:review`, audit record (§5.5) | E12 |
| Human actor rule | n/a | Built; seven cases pass | Reuse | E12 |
| Console IA | `/iga/cloud/*` raw inventory; `/iga/identities` is a static "not available yet" card (`IdentitiesPage.tsx:16-41`) | Unchanged | §2.14: Agents & workloads, Identities, Resources; every existing destination kept | E16 |
| Refresh after a scan | Broken: inventories never refetch when a run publishes (`cloudDiscoveryApi.ts:1141-1170`) | Unchanged | Revision-driven refresh (§2.14.5) | E1 |
| Paging, sorting | Client-side over one 500-row page; sorting reorders only the visible page (`responsive-data-table.tsx:531-562`) | Unchanged | Server-side, cursor, stable order (§5.2) | E2 |
| Cache isolation | Not keyed by workspace; never reset, not even on logout (`authSlice.ts:69`) | Unchanged | §2.14.14 | E14 |
| Keyboard, narrow screens | Rows not focusable; no card layout | Unchanged | §2.14.14 | E15 |
| Graph rendering | None | None | React Flow + ELK (§2.14.15) | UI9 |

**The graph branch is implementation evidence, not validation.** Its passing
tests (54 graph, 159 integration, re-run and reproduced on 23 Sep) prove what
they exercise, and several of its most consequential behaviours are not
exercised: two consecutive scans through the worker, the scan → projector
handoff, gateway projection, and `Load` over a resource two accounts share.
Each of those is broken (§1.3 rows above), and each now has an acceptance
scenario.

### 1.4 AWS coverage contract

What a completed scan supports, surface by surface. **Supported** means
collected, persisted with evidence, projected, served and shown. Anything
else is one of the states below, and the product says which.

| State | Meaning | Blocks ending relationships? |
|---|---|---|
| `reached` | Read completely | No |
| `partial` | Read, but some items failed or were skipped; the report names how many | **Yes**, for that surface |
| `denied` | The role lacks permission, or the call failed | **Yes** |
| `throttled` | AWS throttled the calls past the retry budget | **Yes** |
| `not_selected` | The customer did not select this region | No — nothing there is claimed |
| `unsupported` | The service is not offered in that region, or AuthSec does not collect it | No — nothing there is claimed |

A surface in `denied`, `throttled` or `partial` keeps every relationship it
last confirmed, as `stale`. **Absence is only ever inferred from `reached`.**

**IAM (global)**

| Surface | AWS API | Captured | Persisted, with evidence | Graph | Shown |
|---|---|---|---|---|---|
| `iam_roles` | `GetAccountAuthorizationDetails` (`Filter: Role`), paginated | ARN, RoleId, path, tags, max session, last used, permissions-boundary ARN, trust document, instance profiles, attached and inline policies | `cloud_identity` (`iam_role`), `trust_document`; observation per role | Identity (`immutable` on RoleId) | Identities list, Overview, Used by, Permissions |
| `iam_users` | Same call, `Filter: User` | ARN, UserId, path, tags, **permissions boundary**, **group list**, attached and inline policies | `cloud_identity` (`iam_user`) | Identity (`immutable` on UserId) | Same |
| `iam_groups` | Same call, `Filter: Group` | ARN, GroupId, path, attached and inline policies | `cloud_identity` (`iam_group`), `cloud_group_membership` | Identity; `member_of` relationship | Identity › Used by lists members |
| `iam_policies` | Same call, `Filter: LocalManagedPolicy` (customer-managed, with default version document); `GetPolicy` + `GetPolicyVersion` for each **attached** AWS-managed policy, cached per scan | ARN, PolicyId, name, default version id, document, AWS-managed flag | `cloud_policy`, `cloud_policy_attachment` (`attached`, `inline`, `boundary`); observation per policy version | Policy, statements, assignments, grants (§2.6) | Identity › Permissions; evidence |

`iam_policies` is `reached` when the authorization-details listing completed.
A failure to fetch **one** policy's document does not make it partial — that
would veto every policy partition in the account — but is recorded on that
policy (`document_error`) and reported under `policy_documents`, so only what
that document declared is protected (§4.10).

| `policy_documents` | — (fetch and parse) | Every statement: Sid, effect, Action/NotAction, Resource/NotResource, Condition, verbatim | A document that could not be fetched or parsed is recorded per policy (`cloud_policy.document_error`); skipped statements are counted per document; the rest of the scan continues | An unreadable document contributes no statements this run; what it declared before — its statements, grants, and the support of resources only it names — goes `stale`, never `ended` (§4.10). Its assignments stay current: attachment lists are read independently of documents | Coverage: *"1 policy could not be read: TicketRead v3 (parse)"* |
| `iam_access_keys` | `ListAccessKeys`, `GetAccessKeyLastUsed` | Key id, status, created, last used | `cloud_secret`; **observation added** | Credential (`iga_credentials`) | Identity › Overview |
| `iam_credential_report` | `GenerateCredentialReport`, `GetCredentialReport` | Password enabled, MFA active, key rotation and last use | Observation per user | Evidence on the identity | Identity › Overview, as evidence |
| `activity` | `GenerateServiceLastAccessedDetails`, `GetServiceLastAccessedDetails` | Per service: last authenticated attempt | `cloud_usage`; `partial` when the 500-identity cap applies; `throttled` on throttle | Not a relationship | Identity › Permissions, with §2.14.8 wording |
| `oidc_providers` | `ListOpenIDConnectProviders` | Provider ARNs | Gate only | Resolves OIDC issuers to "connected provider" wording | Evidence |
| `organizations` | — | — | Reported **`unsupported`** | — | Coverage: *"SCPs are not collected"* |

**Trust and cross-account**

| Surface | Source | Captured | Graph | Shown |
|---|---|---|---|---|
| Trust policies (inside `iam_roles`) | The role's trust document | Every statement, **Allow and Deny**, with principals, actions and conditions verbatim; `NotPrincipal` recorded as unsupported for resolution | `can_assume` from each Allow principal to the role (§2.2); the principal is an identity in the workspace, or an **external principal** (another account, a service, an OIDC or SAML issuer and subject). Deny statements are restrictions on the role, never relationships | Identity › Used by ("may assume"), graph, evidence with conditions |
| `eks_pod_identity` (per selected region) | `eks:ListClusters`, `DescribeCluster`, `ListPodIdentityAssociations`, `DescribePodIdentityAssociation` | Cluster, namespace, service account, role | `can_assume` from an external principal (`k8s_service_account` + cluster issuer) to the role; **observation added** | Same |

A trust declaration is **never** proof that assumption succeeds: it needs the
caller's own permission and passes conditions we do not evaluate. The edge
label is *"may assume"*, and its evidence lists the conditions.

**Workloads (per selected region)**

| Surface | AWS API | Captured | Execution identity | Graph | Shown |
|---|---|---|---|---|---|
| `lambda:<region>` | `lambda:ListFunctions` | ARN, name, state, env var **names** | `Role` | Workload `lambda_function`; `executes_as` | Agents & workloads |
| `ecs:<region>` | `ListTaskDefinitions`, `DescribeTaskDefinition` | ARN (with revision), family, status | Task role → `executes_as`; execution role → `task_execution_role` | Workload `ecs_task_definition` | Same |
| `ec2:<region>` | `DescribeInstances`, `iam:GetInstanceProfile` | Instance id (projected with a constructed ARN), name tag, state, instance profile | Instance profile's role | Workload `ec2_instance` | Same |
| `bedrock-agents:<region>` | `ListAgents`, `GetAgent` | ARN (constructed if `GetAgent` fails), name, status, foundation model | `AgentResourceRoleArn` | Workload `bedrock_agent`, classification `provider_native_agent` | Same; "instances not collected" |
| `bedrock-agentcore:<region>` | `ListAgentRuntimes`, `GetAgentRuntime` | ARN, name, **status** | `RoleArn` | Workload `bedrock_agentcore_runtime`, `provider_native_agent` | Same |
| `agentcore-gateways:<region>` | `ListGateways`, `GetGateway` (**added to the role template**), `ListGatewayTargets` | ARN, name, status; each target's id, name, status and **type** | `RoleArn` | Workload `bedrock_agentcore_gateway`; targets are attributes, not objects | Gateway Overview lists targets; *"backing tools not collected"* |
| `agentcore-workload-identities:<region>`, `agentcore-credential-providers:<region>` | List calls | Name, ARN | — | Not projected | Cloud Inventory (existing) |
| `cloudtrail-events:<region>`, `cloudtrail-status:<region>` | `LookupEvents` (48 h), `DescribeTrails`, `GetTrailStatus` | Events matched by IAM user name | — | Not projected (§1.2) | Cloud Inventory (existing) |
| `compute:<region>` | — | Stand-in written only when the region is not selected or its session cannot be created | — | Blocks that region's workload partitions | Coverage |

A failed **detail** call (`GetAgent`, `DescribeTaskDefinition`, …) makes its
surface `partial`, never silently `reached`.

**Resources**

| Kind | Source | Graph | Shown |
|---|---|---|---|
| **Exact reference** | A statement's Resource names one ARN | Resource node, keyed by the ARN; `existence: not_verified` | "Named exactly by a policy statement. We have not confirmed it exists" |
| **Selector** | A statement's Resource contains `*` or `?` | Resource node of kind `selector`, keyed by the pattern | "A selector, not a resource. It may match nothing" |
| **External reference** | The ARN's account is not a connected account | As above, plus `account_connected: false` | "Account 905418271234 is not connected" |
| **Discovered resource** | — | Not produced (§1.2) | Never shown |

Account and region come from the ARN **when the ARN carries them**. S3 ARNs
carry neither, so an S3 reference has *account not stated* and *region not
stated*. It is never assigned the scanning account (§2.14.10).

### 1.5 Compatibility with existing consumers

Verified by tracing every reader and writer of the tables this milestone
touches, at `0e75ad7` and `7eb8bed`.

| Consumer | What it reads and writes | Effect of this milestone | Required |
|---|---|---|---|
| **GitHub IGA** (`/api/iga/v1/*`, `iga_service.go`) | Writes `iga_identity_accounts`, `iga_resources`, `iga_entitlements`, `iga_credentials`, `iga_access_edges`; lists them without a provider filter | AWS rows land in the same tables | Every GitHub reader filters `provider = 'github'` (`028` adds the column and backfills existing rows as `github`). The GitHub writer changes **only** where the shared schema forces it: typed subject and provider. GitHub recognition keys are **not** introduced here — the graph branch's GitHub key change would duplicate every GitHub row once on upgrade (no retirement exists for the legacy rows), so it is reverted |
| **GitHub access paths** (`GET /api/iga/v1/agents/:id/access-paths`) | `iga_access_edges.subject_kind` / `subject_id` | `030` would drop both, and the graph branch hard-codes `subject_agent_id` in `ListAccessPaths` | `030` is **expand only**: typed columns added, legacy columns kept and still written, until the contract migration (`037`) after the rollback window. `ListAccessPaths` keeps base semantics |
| **Kubernetes collector** (`authsec-iga-agent`) | Posts to `/authsec/discovery/*`; writes `discovered_*` only | None, **provided AWS writes no `iga_agents`**: the bridge (`iga_bridge_service.go:93-101`) matches every sighting against all active `iga_agents` by name | AWS projects no agents (§2.2) |
| **Governance, certification, enforcement** | Reach canonical tables only through the bridge | None | — |
| **GCP discovery** | `cloud_connector`, `cloud_identity`, `cloud_secret` through shared repositories | Fence wrappers are no-ops without a fence; GCP sets none | None. GCP is not projected; the barrier does not coordinate GCP scans, which is harmless while GCP is not in the graph |
| **Legacy AWS discovery APIs and Cloud Inventory** (`/authsec/discovery/aws/*`, `/iga/cloud/*`) | `cloud_*` | New columns and tables only; `cloud_permission` keeps being written | Preserved as the raw collection view. The permission observation's `subject_native_id` becomes the qualified key (graph branch); the console reads it only for other observation kinds |
| **Rollback to `0e75ad7`** after deploy | — | Supported: every `027`–`036` change is additive for the old binary once `030` keeps the legacy columns | `037` (contract) ships only after the rollback window |
| **Migration runner** | Applies pending files; **continues past a failure, then refuses to boot** (`runner.go:213-259`, `cmd/main.go:96-97`) | A failing `027` pre-flight would leave `028`–`029` applied and the pod down | The production-schema rehearsal (§9) is a merge gate, and `027`'s pre-flight count is run against production **before** the release |

### 1.6 What `024` closed

Four defects blocked any graph: coverage was not per-run, evidence was deleted by
inventory churn, content dedupe erased run confirmation, and the completeness
gate was unclear. Migration `024` closed all four.

| | Closed by | Note |
|---|---|---|
| **D1** coverage not per-run | `cloud_scan_run.coverage` jsonb, stamped at publish | One column on the existing per-run anchor |
| **D2** completeness gate | Composition, not a new counter | Parse failures are folded into a surface **state** before `Complete()` runs, so `Complete()` stays a pure function of surface states. **Do not add a counter check to `Complete()`** |
| **D3** evidence deleted by churn | Subject FKs `CASCADE` → `SET NULL`, plus `subject_native_id` | An orphaned observation still says what it was evidence for |
| **D4** dedupe erased confirmation | `last_confirmed_run_id`, `last_confirmed_at`, `confirmation_count` on `cloud_observation` | Stamped on the dedupe path (`cloud_observation_writer.go:246-248`); answers "did **this** run confirm it", which `canEnd()` needs |

What `024` did not close is §2.9: cross-workspace provenance. `027` closes it.

## 2. The model

### 2.1 One authoritative model, one projection

```
AWS ──collect──▶ cloud_* ──project──▶ iga_* ──read──▶ console
               authoritative        canonical,
               per-connector        provider-neutral,
               evidence + coverage  rebuildable, published by revision
```

`cloud_*` is what we read, per connector, with evidence and per-run coverage.
`iga_*` is the provider-neutral graph, **projected one way** from it. Nothing
writes `cloud_*` from `iga_*`. Deleting every graph-projected `iga_*` row for a
workspace and re-projecting reproduces the graph exactly, except human-owned
state: classification decisions and asserted resolutions.

**Extend the existing tables, do not build a registry.** Roadmap §3.2 sketches
an `iga_object` parent table; it exists in no migration and is not built.
Typed endpoints use nullable typed FK columns plus an exactly-one `CHECK`, the
pattern `022_cloud_observation.sql` already proves. A new endpoint type costs
one migration that adds a column and widens the constraints.

**Graph-projected rows are marked.** Every shared node table gains `provider`
(`028`). The AWS projector writes `aws`; existing GitHub rows are backfilled
`github`; every existing reader filters on it (§1.5). The graph read APIs (§5)
read only rows the projector owns: `provider = 'aws'` with at least one support
row.

### 2.2 Objects and relationships

**Nodes**

| Object | Table | What it is | Recognition key (§2.4) |
|---|---|---|---|
| Workload | `iga_workload` | One provider-native runtime object: a Lambda function, an ECS task definition revision, an EC2 instance, a Bedrock agent, an AgentCore runtime or gateway | Its ARN |
| Identity account | `iga_identity_accounts` | An IAM role, user or group | Its ARN; immutable key RoleId / UserId / GroupId |
| External principal | `iga_external_principal` | A principal a trust policy names that is not an identity in the workspace: another account, a service, an OIDC or SAML subject, a Kubernetes service account | Issuer + subject |
| Policy | `iga_policy` | A managed policy (AWS- or customer-managed), or one holder's inline policy | Policy ARN; inline: holder ARN + name. Immutable key: PolicyId (managed) |
| Statement | `iga_entitlements` | One statement of one policy document | Policy key + Sid, else content hash (§2.6) |
| Resource reference | `iga_resources` | An exact ARN or a selector pattern a statement names | The ARN or pattern |
| Credential | `iga_credentials` | An IAM user's access key | Key id, namespaced by its user |

**Workload, logical agent, instance.** A *workload* is one runtime object the
provider returns. A *logical agent* is a persistent purpose that may span
workloads and versions; an *instance* is one deployed realization of it. In
this milestone **only workloads are materialized for AWS.** A workload whose
provider API calls it an agent (Bedrock agent, AgentCore runtime) is
classified `provider_native_agent`; a person may classify any other workload as
an agent (§2.14.3). No AWS row is written to `iga_agents` or
`iga_agent_instances`: those tables are GitHub-confirmed agents, read by GitHub
lists and by the Kubernetes bridge's name matching (§1.5), and grouping
workloads into one agent is a correlation claim this milestone does not make
(§1.2).

**Edges**

| Edge | Table | Source → target | Declared by | Claim |
|---|---|---|---|---|
| `executes_as` | `iga_relationship` | workload → identity | The workload's configured role (Lambda `Role`, ECS task role, instance profile role, Bedrock `AgentResourceRoleArn`, AgentCore `RoleArn`) | Configured to run as. Not that it ran |
| `task_execution_role` | `iga_relationship` | workload → identity | ECS `ExecutionRoleArn` | ECS itself uses this role to pull images and fetch secrets for the task. Not the task's own identity |
| `member_of` | `iga_relationship` | identity (user) → identity (group) | Group membership | The user is a member, so the group's policies apply to it |
| `can_assume` | `iga_relationship` | identity or external principal → identity (role) | An Allow statement in the role's trust policy, or an EKS pod-identity association | The trust policy permits it. Not that assumption succeeds |
| Assignment | `iga_policy_assignment` | policy → holder identity | Attachment, inline embedding, or permissions-boundary setting | This policy applies to this holder, as a grant source or as a boundary |
| Grant | `iga_access_edges` | holder identity → statement, **through one assignment** | An Allow statement in an attached or inline policy | This statement is declared for this holder. Not that a request would succeed |
| Target | `iga_entitlement_target` | statement → resource reference | The statement's Resource or NotResource | The statement names this |

`iga_relationship`'s legal `(source, type, target)` triples are a `CHECK` with
an `ELSE false` arm (`031`), so a new type cannot be inserted until someone
widens it deliberately.

**What is never an edge.** A Deny statement is never a grant. A
permissions-boundary statement is never a grant. A trust Deny is never a
`can_assume`. Each is recorded, attached to what it restricts, and shown as a
restriction or limitation (§2.6, §2.14.7).

### 2.3 What an edge may claim

Roadmap §3.1, non-negotiable:

| Edge | Claim | Does NOT mean |
|---|---|---|
| workload → identity | configured execution identity | that it ran, or ran as that |
| identity → identity (`can_assume`) | trust permits assumption | that assumption succeeds |
| identity → group (`member_of`) | membership, so the group's policies apply | anything about the user's own policies |
| policy → identity (assignment) | the policy is attached, embedded, or set as boundary | that any statement in it grants anything |
| identity → statement (grant) | an Allow statement is declared for this holder | that a request would be allowed |
| statement → resource (target) | the statement names this | that the resource exists |

`basis` is a column on every edge:

```
declared   provider configuration says so
observed   we saw it happen, with attribution
derived    we computed it, naming the rule and its inputs
asserted   a human decided it, with authority recorded
```

Everything this milestone projects from AWS is `declared`, except external
principal resolutions, which are `derived` (an exact ARN match, rule recorded)
or `asserted`. Nothing produces `observed` (§1.2). `derived` requires a
non-empty `derivation_rule`, enforced by `CHECK`.

### 2.4 Node identity and continuity

**`source_key` is namespaced, always.** A bare native id is never unique:

```
provider ␟ kind-or-namespace ␟ native-id [␟ qualifier …]
```

joined with `\x1f` (unit separator — cannot occur in an ARN). An ARN already
carries partition, account and region, so an IAM role is
`aws␟arn:aws:iam::123456789012:role/foo`. Keys are built in exactly one place,
`internal/igagraph/sourcekey.go`; formatting one inline is a review failure,
because two spellings of a key is the duplication bug in a new costume.

| Object | Recognition key | Continuity | Immutable key |
|---|---|---|---|
| IAM role / user / group | ARN | `immutable` | RoleId (`AROA…`) / UserId (`AIDA…`) / GroupId (`AGPA…`) |
| Managed policy | Policy ARN | `immutable` | PolicyId (`ANPA…`) |
| Inline policy | `inline ␟ <holder ARN> ␟ <name>` | `immutable` when its holder is (always, for IAM) | The holder's immutable key |
| Statement | policy **incarnation** key `␟ stmt ␟` `sid:<Sid>`, else `h:<content hash>[#n]` | inherits the policy's | — |
| Assignment | policy incarnation key `␟` holder endpoint key `␟` kind | — | — |
| Grant | assignment key `␟` statement key | — | — |
| Workload | ARN (EC2 and a failed `GetAgent`: constructed ARN) | `recognition_only` | — (no provider creation id; stored so the console can say so) |
| Resource reference | ARN or selector pattern | `recognition_only` | — |
| External principal | issuer `␟` subject | `recognition_only` | — |
| Credential | holder ARN `␟` key id | `recognition_only` | — |

An **endpoint key** — how an edge key names an identity — is the identity's
immutable key when it has one, and its source key otherwise.

A **policy incarnation key** is the same idea for policies, and every key
below a policy is built from it, never from the ARN:

| Policy | Incarnation key |
|---|---|
| Managed | `aws ␟ policy ␟ <PolicyId>` |
| Inline | `aws ␟ inline ␟ <holder endpoint key> ␟ <name>` |

So a customer-managed policy deleted and recreated under the same ARN (new
PolicyId), or a role recreated with an inline policy of the same name (new
RoleId), yields a **new policy object whose statements, assignments and grants
all have new keys**. Nothing of the old incarnation can be matched, reused or
revived by the new one. So a role deleted
and recreated under the same ARN yields different edge keys: its old
relationships end and the new role does not inherit them.

**Recreation.** Same recognition key, different non-empty immutable key: a new
object. The old row retires `recreated`, its edges end `subject_recreated`,
and human decisions about it stay with it (§2.12).

**Restoration.** No live row, but a row retired as `unsupported` with the same
recognition **and** immutable key: the same object returns — same id, same
`first_seen_at` — and asserted decisions about it come back
`pending_reconfirmation`. A `recognition_only` object is never restored after
a confirmed absence: without a creation boundary we cannot prove the returning
Lambda is the one that left, so it returns as a new object and `continuity`
says why.

### 2.5 Credentials: what rotation does and does not prove

**IAM roles do not hold long-lived access keys; IAM users do**, so a rotation
test framed around a role tests nothing. And AWS's documented rotation procedure
has *two active keys at once*, deliberately, so the application can be moved
over before the old key is disabled.

Therefore: **observing a new key never implies the old one was replaced.**

- A new key appears ⇒ insert an `iga_credentials` row, `lifecycle = 'active'`.
  The other key stays `active`. Two active keys is a correct, common state, not
  a conflict to resolve.
- A key disappears from an authoritative read ⇒ `lifecycle = 'revoked'`, under
  the same four conditions that let a relationship end (§2.7). Never `rotated`,
  because we did not observe a replacement.
- `rotated` is only written when a human records it, `basis = 'asserted'`.

In every case the identity account keeps its `id`, its `first_seen_at` and every
relationship. `004:614` already constrains
`lifecycle IN ('active','expired','revoked','rotated')` — use it, and never
delete the row.

### 2.6 The permission model: policy, statement, assignment, grant

This is the model the product ships. It replaces the earlier "one
entitlement per grant occurrence" design, which the graph branch built and
which cannot support independent grants, policy edits or detach/reattach
history.

```
iga_policy ──1:n──▶ iga_entitlements (statement) ──1:n──▶ iga_entitlement_target ──▶ iga_resources
    │                         ▲
    │ 1:n                     │ n:1
    ▼                         │
iga_policy_assignment ──1:n──▶ iga_access_edges (grant) ◀── subject: iga_identity_accounts
 (attached | inline | boundary)   (Allow statements only)
```

**Four identities, because four things change independently.**

| Identity | Changes when | Stays the same when |
|---|---|---|
| **Policy** | A different managed policy (new PolicyId), or a new inline policy name on a holder | Its document is edited; it is attached to more or fewer holders |
| **Statement** | Its Sid changes, or — without a Sid — its content changes | The statements around it are reordered; the policy is attached elsewhere |
| **Assignment** | The policy is attached to, or detached from, a holder | The policy's content changes |
| **Grant** | Its assignment or its statement changes | Anything else |

**Statement identity.** The key is the policy key plus:

- **`sid:<Sid>`** when the statement has a `Sid` that is unique within the
  document. A reorder keeps it; an edit keeps it and records a **revision**
  (`iga_statement_revision`: content hash, verbatim statement, policy version,
  `valid_from`/`valid_to`).
- **`h:<hash>`** otherwise, where the hash is SHA-256 over the canonical JSON
  of `Effect`, `Action`, `NotAction`, `Resource`, `NotResource`, `Condition`.
  Identical statements without a Sid in one document are disambiguated by
  their order among equals (`#1`, `#2`). A reorder keeps them; **an edit ends
  the old statement and creates a new one**, and the Changes view says so
  plainly: *"A statement without a Sid changed. AWS gives it no stable name,
  so this is shown as one statement ending and another beginning."*

The statement's position (`statement_index`) is stored as a descriptive field
and never used as identity.

**Shared versus holder-scoped.** A managed policy is one object: two roles
attached to `ToolboxRead` have **one** policy, **one** set of statements, **two**
assignments and **two** grants per Allow statement. Detaching it from one role
ends that role's assignment and grants; the policy, its statements and the other
role's grants are untouched. An inline policy is keyed by its holder, so two
roles each with an inline `ReadData` are two policies. An AWS-managed policy
attached in two connected accounts is still one policy, with one support row
per account (§2.10B).

**Multiple statements, one resource.** `TicketRead` statement 2 and
`ToolboxRead` statement 1 both declare `s3:GetObject` on
`support-tickets/*`. They are **two statements, two grants**. The canvas may
draw one line; the Resources tab, the evidence panel and the Changes view list
both, each with its own lifecycle (§2.14.11). Detaching `TicketRead` ends one
grant; the path survives because the other is current.

**Effects, negations, conditions.**

| Statement | Stored | Grant? | Shown |
|---|---|---|---|
| `Allow` + `Action` | verbatim | **yes** | "declared" |
| `Allow` + `NotAction` | verbatim, `negated` | **yes** — the broad form is a real grant (`019` relaxed the constraint for it) | "all actions except …" |
| `Allow` + `NotResource` | verbatim; target mode `not_resource`, plus the implicit `*` selector | **yes** | "all resources except …" |
| any `Condition` | verbatim, never evaluated | as the statement says | "conditional — not evaluated" and the condition keys |
| `Deny` | verbatim, `effect = 'deny'` | **never** | Under Permissions as a restriction; on every path from the same holder as the limitation *"This identity has N Deny statements. Their effect on this grant is not evaluated"* |
| Permissions-boundary statements | as a policy with an assignment of kind `boundary` | **never** | Under Permissions › Permissions boundary; on every path from the holder: *"A permissions boundary applies. Effective access is not evaluated"* |

Effect is stored lowercase (`policy_statements.go:135`); every comparison is
against the lowercase constant, covered by a test that fails on the
capitalised form.

**Groups.** A user's access through a group is **not** copied onto the user.
The path is user → `member_of` → group → grant → statement → target. Two hops
are the truth, and a copy would have to be kept in step with every membership
change.

**Policy versions.** Only the default version is read (§1.4). The policy row
records its `version_id`; a change of default version is a policy change event
in the Changes view, and the statement revisions it causes are listed under it.

**Assignment periods.** An assignment is a row with `valid_from`/`valid_to`.
Detach ends it; reattaching later creates a **new** row. So "was this policy
attached on 1 March?" is answerable from retained rows, and a reattach never
rewrites the earlier period.

**Stability promise.** Policy, statement, assignment and grant ids are stable
under the rules above, from the first publication. No later re-keying is
planned. Review decisions may reference them once certification is built
(§1.2).

### 2.7 Relationship lifecycle

- **`current`** — the latest authoritative read confirmed it.
- **`stale`** — we could not look. Still believed, with its last confirmation
  time. A failed, denied, throttled or partial read produces this and
  **never** `ended`.
- **`ended`** — an authoritative read of the owning scope did not see it.
  `valid_to` and `ended_reason` are set; the row is never deleted.

A relationship, assignment, grant or support row may move to `ended` only when
**all four** hold:

1. the run reached `status = 'published'` (the `cloud_scan_run` CHECK is
   `queued|running|published|failed|abandoned`; there is no `complete`);
2. that run's own `cloud_scan_run.coverage` records every surface the
   partition requires as `reached` — not `cloud_connector.coverage`, which a
   later scan has overwritten;
3. the partition's source surface was read by **that run**, proven by
   `cloud_observation.last_confirmed_run_id`, because content dedupe means the
   absence of a fresh observation row proves nothing;
4. the projection job owns the partition's generation (§2.8).

**Collapsing `stale` into `ended` lets a permissions outage read as a
cleanup.**

| Case | Expected |
|---|---|
| Lambda moves `RoleA` → `RoleB` | Old `executes_as` `ended` with `valid_to`; new one `current`; both readable |
| Managed policy detached from one of two roles | That role's assignment and its grants `ended`; the policy, its statements and the other role's assignment untouched |
| Policy re-attached a week later | A **new** assignment and new grants; the ended period stays as it was |
| Statement with a Sid edited | Same statement id; a new revision; grants unchanged |
| Statement without a Sid edited | Old statement's support ends and it retires; its grants `ended` (`statement_retired`); a new statement with new grants |
| Two policies grant the same action; one detached | One grant `ended`, the other `current`; the path stays |
| User added to a group | New `member_of`; the group's grants now reach the user by traversal; nothing copied |
| Second access key added | New credential `active`; the user and every relationship unchanged |
| Access key disappears | Credential `revoked`, only under the four conditions |
| Role deleted and recreated, same name | Old identity retired `recreated`; new id, new `first_seen_at`; old edges `ended` |
| Customer-managed policy deleted and recreated, same ARN and Sids | Old policy retired `recreated`, its statements retired `policy_recreated`, its assignments and grants `ended` `policy_recreated`; new policy, statements, assignments and grants with new ids |
| Role recreated with a same-named inline policy | The old inline policy retires with the old role's incarnation; the new role's inline policy is a new object with new statements |
| IAM read denied | Everything under IAM `stale`; zero rows `ended` |
| One of two accounts stops naming a shared bucket | That account's support ends; the bucket stays active; the other account's grants unchanged |
| A policy document fails to parse | Its assignments and statements `stale`; the rest of the account reconciles normally |

### 2.8 Projection execution: durable, separately fenced, explicitly enabled

**The projector cannot run under the scan lease.** `Publish()` clears the
lease, so any fenced call after publication affects zero rows. Projection is
therefore **its own durable, leased work item**, `iga_projection_job`,
mirroring `cloud_scan_run`'s proven pattern: `Enqueue/Claim/Renew/Complete/Fail`,
`lease_owner` + `lease_version`, fenced updates that consult no clock.

- **Enqueued in the publication transaction.** Coverage, `published`, the job
  and the barrier hand-off commit together (`PublishWithCoverage`, built on the
  graph branch). A published run always has a job.
- **Inputs are the published run's artefacts**: `cloud_*` rows at the run's
  generation, the run's own coverage, and the observations it confirmed.
- **Crash recovery.** A job whose lease expires is reclaimed; projection is
  idempotent; a replay after commit is recognised by its publication row
  (§4.6).
- **Atomic visibility.** Projection and reconciliation are one transaction,
  and it inserts the workspace publication row (§5.1). Readers see the
  previous revision or the next, never the gap.

**One explicit switch: `IGA_GRAPH_PROJECTION`.** The graph branch decided
whether to use the barrier and enqueue jobs by probing for tables. With no
projector wired into the binary, that meant the first scan in a workspace
queued a job nobody would ever claim, and no scan could run there again. The
decision is now a single configuration value, read once at startup:

| `IGA_GRAPH_PROJECTION` | Scan worker | Projector | Supported at schema |
|---|---|---|---|
| `off` (default) | Exactly the Phase 1 behaviour: no barrier, no job | Not started | any |
| `on` | Barrier, job enqueue, hand-off | Started; runs `RecoverStalled` | head ≥ `036`, verified at startup |

With `on` and the schema verification **failing or erroring**, both
components **fail closed**: the worker does not claim scans and the projector
does not start, and `/api/iga/v1/capabilities` reports
`graph_projection: "misconfigured"` with the reason. A transient database error
during verification is retried, never cached as an answer.

### 2.9 Every provenance reference is workspace-qualified

A single-column `FOREIGN KEY (last_confirmed_by) REFERENCES cloud_scan_run (id)`
admits **another workspace's** scan run — the A3 class of defect, easy to
reintroduce two lines below the fix.

**Rule: no single-column foreign key to a workspace-scoped table.** Every
reference is `(workspace_id, id)` against a `UNIQUE (workspace_id, id)`.
`cloud_connector`, `cloud_scan_run` and `cloud_observation` lack that unique
constraint today; `027` adds it and converts the three existing single-column
references.

### 2.10 Two mechanisms the rest of the design rests on

#### A. The pipeline barrier — durable, workspace-wide

A published run's inventory must not change while its projection reads it.
Three writers can change it:

| Writer | Why per-connector locking misses it |
|---|---|
| Another connector's scan | `cloud_resource` and `cloud_workload` are unique on `(workspace_id, native_id)` with no connector, and their upserts reassign `connector_id`. Two connectors never contend for one lock, yet both write the row |
| A superseded worker still running | It holds no lock to lose |
| The next scan of the same connector | The only one a per-connector rule catches |

An advisory lock cannot express this: it is released when its transaction
commits, and publication and projection are different transactions. So the
barrier is a **row**, `iga_pipeline_lease`, one per workspace (`027`):

| Transition | Guard | Effect |
|---|---|---|
| scan claim | `state='idle'`, or `collecting` for **this run** with an expired lease | `collecting`, `version+1`, holder = the scan worker |
| heartbeat (collecting) | holder, run and version match | `expires_at` extended, **version unchanged** |
| publish | `state='collecting' AND version=?`, same run | `projecting`, `version+1`, **holder = `job:<projection job id>`**, in the publication transaction |
| projection claim | `state='projecting'`, holder = `job:<id>` of the claimed job | the worker proceeds under the barrier version; the **job lease** is its fence |
| heartbeat (projecting) | holder, run and version match | `expires_at` extended, version unchanged |
| projection done | `state='projecting' AND version=?` | `idle`, `version+1`, in the same transaction as job completion |
| recover `collecting` | expired, and the run is still claimable | left for the run's own reclaim |
| recover `projecting` | expired, and the job is still claimable | left for the job's own reclaim |
| **abandon** | expired, and the run or job can no longer make progress | terminalize run and job **first**, then `idle`, `version+1`, one transaction |

**The barrier is held by the job, not by a worker.** The graph branch left the
scan worker's name on it after publication, and the projector refuses a live
barrier held by anyone else, so every projection waited out the full
15-minute lease. Holding it as `job:<id>` means whichever worker holds that
job's lease may proceed at once, and a worker that lost the job lease is fenced
out by the job, not by a timer.

**Expiry alone never returns the barrier to `idle`.** A `projecting` barrier
whose worker died still guards a published run's inventory. Recovery either
leaves it for the run's or job's own reclaim, or abandons it after
terminalizing both — decided by phase (`RecoverStalled`, built on the graph
branch and correct).

**A refused claim backs off.** A run that meets a busy barrier is returned to
the queue with `requested_at = now()`, and the worker sleeps its poll interval
before claiming again. Without both, a refused run stays the oldest claimable
row and is re-claimed in a tight loop that starves every other workspace's
scans, and its attempt refund means the retry ceiling never trips.

> **Cost, stated plainly: scanning is serialized per workspace.** A customer
> with five AWS accounts scans them one at a time. The shared-resource writer
> crosses connectors, so nothing narrower is sound. Revisit only by removing
> the sharing, not by narrowing the barrier. The console shows the queue
> (§2.14.7).

**Cancellation is not a fence.** Every inventory write **and every inventory
delete** validates the run's fence in the same transaction as the write
(`ScanFence`). The graph branch fenced the upserts; `ReconcileGeneration`'s
deletes must be fenced too, or a superseded worker can still delete rows the
current owner just wrote.

#### B. Per-source support — a shared node has no single owner

A resource, a managed policy and its statements can be supported by
**several** connectors at once: accounts A and B both attach the AWS-managed
`ReadOnlyAccess`, both name the same bucket. Recording one `connector_id` on
the node makes the last scanner its apparent owner, and then B's cleanup
retires what A still holds.

**Object identity and source support are separate rows** (`iga_object_support`,
`032`, widened in `036`):

- **Projection** upserts one support row per `(object, connector, partition)`
  it observed, stamping `last_confirmed_run_id`.
- **Reconciliation** acts on **support rows**, never on nodes directly.
- **A node's lifecycle is derived** in the same transaction: `active` while any
  support is `current` or `stale`; `retired` (`unsupported`) only when **every**
  support is `ended`.

**Edges keep a single membership.** An assignment, grant, `executes_as`,
`member_of` or `can_assume` is declared by one account's configuration, so
`connector_id` + `partition_key` on the row is correct for them.

### 2.11 ERD

```
                                   workspaces
                                        │
   ┌──────────────── collection (cloud_*) ─────────────────┐
   │ cloud_connector ──▶ cloud_scan_run (coverage, published)│
   │   │                    │                               │
   │   ├─ cloud_identity (role|user|group, trust_document)   │
   │   ├─ cloud_group_membership   user ─▶ group            │
   │   ├─ cloud_policy (document, policy_id, version_id)    │
   │   ├─ cloud_policy_attachment  policy ─▶ principal       │
   │   │                           kind attached|inline|boundary
   │   ├─ cloud_workload (identity_id, attrs)               │
   │   ├─ cloud_assume_edge (eks pod identity)              │
   │   ├─ cloud_secret, cloud_usage                         │
   │   └─ cloud_observation (typed subject incl. policy_id,  │
   │                          last_confirmed_run_id)        │
   └────────────────────────────┬──────────────────────────┘
                                │ project (one way, one transaction, one revision)
   ┌──────────────── graph (iga_*) ─────────────────────────┐
   │  iga_workload ─executes_as / task_execution_role─▶ iga_identity_accounts
   │                                                  ▲   │ member_of
   │  iga_external_principal ──can_assume────────────┘   ▼
   │                                           (role)  (group)
   │  iga_policy ──▶ iga_policy_assignment ──▶ holder identity
   │     │                 │
   │     ▼                 ▼
   │  iga_entitlements ◀── iga_access_edges (grant; Allow only)
   │  (statement)
   │     │  ──▶ iga_statement_revision
   │     ▼
   │  iga_entitlement_target ──▶ iga_resources (exact | selector)
   │
   │  every node ── iga_object_support (connector, partition, state)
   │  every edge ── *_evidence ──▶ cloud_observation
   │
   │  iga_publication (rev)   iga_projection_job   iga_projection_state
   │  iga_pipeline_lease (one per workspace)   iga_workload_classification
   └────────────────────────────────────────────────────────┘
```

`iga_relationship` holds `executes_as`, `task_execution_role`, `member_of` and
`can_assume`. Assignments and grants have their own tables because they carry
columns relationships do not (assignment kind; the statement a grant points
at).

### 2.12 Multi-account and multi-provider boundaries

One workspace holds many connectors, and one graph spans them. That is the
product, not an edge case — a customer's real question is "can anything in
sandbox reach production", which no single-account console can answer. These
are the rules that make it tractable.

#### One object, or two?

Every hard case reduces to §2.4's rule: **an object is identified by what the
provider calls it, namespaced by provider, partition, account and region.**
Never by what it looks like.

| Situation | Result | Because |
|---|---|---|
| Accounts A and B both name `s3:::refunds-bucket` | **one** object | The ARN is globally unique — it is the same bucket. Two `iga_object_support` rows (§2.10B), one object |
| Role `deploy` in A, role `deploy` in B | **two** | ARNs differ in the account segment. Equal display names never merge |
| One role seen through two connectors | **one** | An integration is a route, not an identity. Two observation streams, one object; reconnecting must not mint a new one |
| Role deleted, recreated with the same name | **two** | `RoleId` is the creation boundary; the old one retires `recreated` |
| Lambda `refund-processor` in two regions | **two** | Region is in the ARN |
| IAM user `priya`, GitHub `priya`, k8s SA `priya` | **three, never merged** | Three authorities. Correlation is a separate evidenced act — below |

#### Cross-provider access, with one provider connected

A GitHub Action assuming an AWS role is **fully visible from the AWS scan
alone**: the trust policy names the issuer and the subject claim, and
`cloud_assume_edge` already carries `SubjectKind`, `Subject`, `Issuer` and
`Mechanism`.

**Rule: every edge is recorded by the side that declares it, and the far
endpoint may be unresolved.**

```
external principal            identity account        entitlement      resource
repo:authsec-ai/authsec  ──▶  role/gha-deploy    ──▶  s3:PutObject ──▶ artifacts/*
:ref:refs/heads/main       can_assume              granted            names
   (unresolved)
```

The far end is a **node**, not a string on the edge:

Its DDL is migration `034` (§3); it is not repeated here.

`iga_relationship` gains `source_external_principal_id` as a fourth typed
source, with the legal-pair CHECK widened so `can_assume` accepts it.

> **Why a node and not a string.** When the far provider connects later,
> resolution **upgrades the existing node** and the edge keeps its identity
> and its whole history. A string endpoint would force delete-and-recreate,
> destroying "this access has existed since March" — which is precisely the
> fact a reviewer needs and the one hardest to recover.

**The lifecycle of a resolution follows its basis.** A `derived` resolution
is a mechanical fact about current evidence and is simply re-derived. An
`asserted` one is a person's decision, and restoring its target's *record*
must not silently renew it:

| Situation | `derived` | `asserted` |
|---|---|---|
| Collection becomes incomplete | Kept; its supporting evidence shown stale | Kept; evidence shown stale. **Still `active`** — we could not look, which proves nothing |
| Target confirmed absent and retired | Re-derived against current evidence; usually becomes unresolved | **`suspended`.** The decision is preserved and still points at the retired row, so it stays explicable; it is not in force |
| Same immutable identity returns (restored) | Re-derived | **`pending_reconfirmation`.** The record is restored; the person's association is *offered back*, not reinstated. Nothing grants on it until someone confirms |
| A different identity appears under the same name (recreated) | Re-derived — an exact ARN match now points at the new object, which is correct for a mechanical fact | **Stays `suspended` on the old object. Never transferred.** The person decided about X, not about whatever now wears X's name |

`suspended` and `pending_reconfirmation` are both **not in force**: no path is
drawn through them as current, and the UI shows them as a decision awaiting a
person. `SuspendAssertions` and `MarkAssertionsPendingReconfirm` in
`projectIdentities` (§4.6, branches a and c) are the two writes that implement
the retire and restore rows; they touch `asserted` rows only.

**Resolution is a claim, not a fact.** `repo:org/repo:*` matches every branch
and tag in that repository. So it carries the same `basis` discipline as
everything else: an exact unambiguous match is `derived` with its rule
recorded; anything wildcarded stays unresolved and is shown as unresolved; a
human confirming it is `asserted` with the deciding authority stored.

#### Identity correlation: candidates only

The tempting feature is "Priya has an AWS user, a GitHub account and a
Kubernetes service account — show me Priya."

**Auto-correlating on name or email is how a review that says "revoke Priya's
access" revokes a service account belonging to someone else.** Name collisions
across providers are ordinary, service accounts borrow human names, and
contractors share mailbox aliases. A wrong merge is not a display bug: it
silently changes the scope of every decision made about that identity.

This milestone therefore performs **no cross-provider correlation**. It may:

- record **candidates with their evidence** in `iga_correlations` and
  `iga_classification_candidates`, which exist from `004` for this;
- never let a candidate affect a graph query, a path, a finding or a
  certification until a human confirms it;
- record confirmation as `asserted` basis with the deciding authority, so it
  is explicable and reversible.

#### What this milestone deliberately will not do

Stated as product limits now, rather than discovered as gaps later. Each is
cheap to state and expensive to walk back.

| Not built | Why not |
|---|---|
| Automatic cross-provider identity merging | Above |
| Unbounded transitive traversal | Bounded by §5.4's budgets — display defaults and hard server limits, stated separately. Role-assumption chaining starts at two hops and expands on request |
| Resolving every external principal | Exact matches only; wildcards stay unresolved and visible |
| Effective access | Conditions recorded, never evaluated; boundaries and Deny statements shown as restrictions, not applied. Every conclusion reads `unknown` (roadmap §3.5a) |
| Blast-radius or risk scoring | Needs effective access to mean anything. A score over declared grants is a number that looks like analysis |
| A node-link diagram as primary navigation | 107 identities × 461 permissions is a hairball that answers no question. The graph is a focused view of one object's paths, reached from that object (§2.14.11) |

### 2.13 Why these boundaries, in product terms

The decisions above are schema decisions, but they are really positioning
decisions. This is the reasoning a PM or architect should be able to challenge
without reading a migration.

#### The four categories we are standing between

| Category | Examples | Strong at | Blind spot |
|---|---|---|---|
| **Classic IGA** | SailPoint, Saviynt, Okta IGA | Certification campaigns, access requests, SoD, auditor-ready evidence | Human joiner/mover/leaver. Non-human identity is a bolt-on; an agent is just another service account |
| **NHI security** | Oasis, Astrix, Entro, Natoma | Discovery of service accounts, keys, OAuth grants; ownership inference; usage context | Ends at inventory and findings. No certification, no proven revocation, thin history |
| **Authorization graph** | Veza | Cross-system effective-permission model, "who can do what" queries | Normalization is lossy and customers argue with it; heavy deployment |
| **CNAPP graph** | Wiz, Orca | The best graph UX in security; exposure and attack paths | Point-in-time posture. Cannot answer "what did access look like last quarter when this was approved" |

**The gap we are aiming at is the join: agent-aware discovery wired to real
IGA workflow.** NHI vendors discover and stop; IGA vendors govern things they
cannot see. Neither models an agent as distinct from the credential it uses.

#### Three bets the schema has already placed

**1. Keep the provider's own words.** Veza's bet is normalizing permissions
into a canonical verb set. It makes cross-system queries elegant and it is
lossy — and the argument a customer has with your normalization is an argument
about whether your product is telling the truth. `iga_entitlements` stores
`native_rights` *and* `normalized_rights` for exactly this reason: the
reviewer can always see what AWS actually said. Normalization becomes a
convenience layer, never the record.

**2. History is the moat, not the graph.** A graph of current access is a
commodity — Wiz has a better-looking one. What almost nobody keeps is the
*shape of access at the moment a decision was made*. `current | stale | ended`
with `valid_from`/`valid_to`, rows never deleted, evidence pinned per edge, is
what lets a customer answer an auditor a year later. It is also the least
demoable feature in the product, which is why it has to be built into the
model now rather than added when someone asks for it.

**3. Coverage honesty is a feature, not a caveat.** Every competitor's demo
shows a full dashboard. Ours will sometimes say *"we could not read IAM in
this account since Tuesday."* That reads as weakness in a bake-off and as
credibility in a procurement review, and it is the only defensible position
once a customer discovers a gap themselves. **Zero objects is never reported
as complete coverage** is a product promise before it is a constraint.

#### What the competition teaches about the graph UI

BloodHound made attack-path graphs the reference UX in security, and the
lesson generalizes badly. Its paths are *exploitable* — each edge is something
an attacker can actually do, so a path is a finding. Our paths are
*authorization* paths: a granted path is not a finding, it is usually the
intended design. Presenting them in the same visual language invites the
reader to treat normal access as an alert.

So the graph view is **a focused explanation of one object**, never an
estate-wide canvas: it opens on the selected workload, identity or resource,
draws one declared path, and expands only when asked (§2.14.11). A
force-directed view of 107 identities against 461 permissions is a hairball
that answers no question; governance work is reading one path, deciding on it,
and explaining the decision later. The canvas is visually distinct from
attack-path tools — edges read *configured to run as*, *granted by*, *names*,
never *can access* — and the path list says the same thing as text.

#### Sequencing, and the temptations at each step

The order is forced by what each stage needs from the one before, and every
stage has a plausible-looking shortcut that breaks the next one:

| Stage | Needs | The temptation to refuse |
|---|---|---|
| Discovery | — | Shipping a connector count. Ten shallow integrations are worth less than one that is complete and says so |
| **Graph** | Stable objects, history | A risk score. It needs effective access to mean anything, and a score over declared grants is a number that looks like analysis |
| Certification | Trustworthy inventory, owners | Certifying against an inventory that duplicates on rescan — reviews nobody can explain |
| Remediation | Reviewed targets, source re-read | Trusting a ticket close or a 200 response as removal |

**No second provider until AWS is end to end.** A second integration
multiplies the surface of every unfinished contract — coverage, keys,
reconciliation — and the model cannot be validated by a provider that has not
yet met a real estate. The canonical model should be *checked* against a
second provider's payloads as a design exercise (roadmap §7), which is
different from building the integration.

### 2.14 The product experience

Stage S7 builds this, over the read APIs in §5. Several decisions below
constrain the schema and the API, not just the pixels.

**Status.** Nothing in §2.14 exists today except Cloud Inventory
(`/iga/cloud/*`) and the AWS connection flow under Integrations, both of which
this milestone keeps.

#### 2.14.1 The journey, and what the current IA does to it

The intended journey:

```
connect an integration → see agents and workloads → pick one you recognise
    → explore it → inspect the evidence for one relationship → see what changed
```

The customer never has to know our entity names, and never starts at a graph.

**Verified against `c74fcf7`, the console today does not support this.** The
IGA area has these destinations, backed by different pipelines:

| Route | Backed by | Pipeline |
|---|---|---|
| `/iga/agents` | `/authsec/discovery/agents` → `discovered_agents` (`models/discovery.go:343`) | Legacy discovery — **not** the IGA graph |
| `/iga/identities` | Nothing: a static *"Identity inventory is not available yet"* card (`IdentitiesPage.tsx:16-41`); no page calls `/api/iga/v1` at all | — |
| `/iga/cloud/identities` | `cloud_identity` | AWS collection path |
| `/iga/cloud/compute` | `cloud_workload` | AWS collection path |
| `/iga/cloud/resources` | `cloud_permission` resource references | AWS collection path |

The older `/iga/cloud/aws/*` paths already redirect to these (`App.tsx`,
`CloudInventoryRedirect`). None of these URLs carries an object id; detail
drawers are local state, so only filters (`account`, `kind`, `view`) are
bookmarkable today.

So a customer sees an **Identities page that shows nothing**, a Cloud
Inventory with its own Identities tab, and an **Agents page that never shows a
Bedrock agent** — Bedrock agents land in `cloud_workload` and surface under
*Compute*, which is the one tab that sounds least like an agent.

There are also three distinct "agent" concepts in the tree: `discovered_agents`
(legacy), `iga_agents` (`models/iga.go:421`, canonical), and Bedrock/AgentCore
rows in `cloud_workload`. The IA exposes all three without distinguishing them.

#### 2.14.2 Where it lives: the IGA sidebar

The IGA sidebar today (`IgaSidebar.tsx:48-75`) is **Integrations, Discovered
Agents, Identities, Cloud Inventory, Detection Rules**, then the governance
group. GitHub and Kubernetes have no pages of their own; they are rows in
Integrations and open at `/iga/integrations/:id`. **Every one of these
destinations is kept.**

| Item | Route | Change |
|---|---|---|
| Integrations | `/iga/integrations` | Kept. The AWS connector drawer gains scan history and outcome (§2.14.7) |
| **Agents & workloads** | `/iga/estate` | **New**, second in the list. The entry point of the journey |
| Discovered Agents | `/iga/agents` | **Kept as it is.** It is the Kubernetes/runtime discovery pipeline (`discovered_agents`). Its rows never appear in the graph, and graph rows never appear in it |
| **Identities** | `/iga/identities` | The existing route, today a static "not available yet" card (`IdentitiesPage.tsx:16-41`), becomes the graph's identity list |
| **Resources** | `/iga/resources` | **New**. Resource references and selectors |
| Cloud Inventory | `/iga/cloud/*` | **Kept** as the raw collection view: every `cloud_*` row, including surfaces the graph does not project (CloudTrail events, workload identities, credential providers). Linked from each account's drawer as *"Raw inventory"* |
| Detection Rules, governance group | unchanged | Unchanged |

"Estate" is the route segment only; the customer sees *Agents & workloads*,
and breadcrumbs use it. Identities and Resources are estate-wide lists because
an investigation often starts from a shared role or a sensitive bucket rather
than from a workload.

#### 2.14.3 Classification: what we may call an agent

**Not every Lambda is an agent.** The column is *Classification*, never a
badge reading "AI".

| State | Meaning | Evidence | This milestone |
|---|---|---|---|
| **Provider-native agent** | The provider's own API calls it an agent | The observation: `bedrock:GetAgent`, `bedrock-agentcore:GetAgentRuntime` | **Automatic.** Derived from `runtime_kind` (`bedrock_agent`, `bedrock_agentcore_runtime`) |
| **Classified as agent** | A person said so, for a custom agent on Lambda/ECS/EC2 | A decision record: who, when, why | **In — as one narrow, audited action.** See below |
| **Unclassified workload** | We found it; nobody has said what it is | Discovery evidence for the workload itself | The default |

**Decision: manual classification is in this milestone.** The journey this
product exists for — *"select the customer support agent"* — is unreachable
for any customer whose support agent is a Lambda, which is most of them,
because it would stay "Unclassified workload" indefinitely. The column and the
decision record are `029`.

What is in, and what stays out:

| In | Out |
|---|---|
| A **Classify as agent** action on a workload's Overview | Automatic inference from names, tags, env vars or dependencies (§1.2) |
| An optional free-text purpose ("Customer support triage") | Grouping several workloads into one logical agent |
| Undo, which records its own decision rather than deleting the first | Bulk classification |
| The decision shown on Overview: *"Classified as agent by priya@ · 22 Sep · 'handles tier-1 tickets'"* | Classification affecting any access conclusion |

Grouping is the one to hold the line on. Deciding that `cs-handler-a` and
`cs-handler-b` are one agent is a correlation claim, and §2.12's rule applies:
no merging on names, ever, without evidence.

**Schema** is in migration `029` (§3), with `iga_workload`.

Two rules the projector must honour:

- **`provider_native_agent` is set by the projector; `classified_agent` never
  is.** The projector writes the former from `runtime_kind` and must not
  overwrite the latter — classification is human-owned state, and §3's "never
  `UpdateAll`" rule protects it.
- **Recreation does not carry classification.** A workload retired as
  `recreated` keeps its decisions on the old row; the new object starts
  `unclassified`. A human classified *that* workload, not whatever now wears
  its name.

#### The classification contract

A human decision in a security product needs these pinned down, and each is a
place this goes wrong quietly.

| Concern | Contract |
|---|---|
| **Who may** | Classify and undo require `iga:review` — the permission every other IGA decision route uses (`/classification-candidates/:id/decisions`, `/agents/:id/iga-link/decisions`). The graph branch used `discovery:admin`; that is changed. `iga:review` is seeded (`004`) and backfilled to admin roles (`005`), so no permission migration is needed. Viewing a decision needs `iga:read` |
| **Who did** | A **verified human workspace member**, recorded by **stable user id** (§ rule below). The response returns the id and, separately, a display name resolved at read time |
| **Atomic** | One transaction: insert the decision row, update `iga_workload.classification`, bump `classification_version`, bump the workspace's `iga_classification_clock.seq`. Either all land or none does |
| **Concurrent edits** | Optimistic. The request carries `expected_version`; a mismatch is `409` with the current decision, so the second person sees the first person's decision instead of overwriting it |
| **Retries** | The request carries a client-generated **`operation_id`** (UUID), one per intent, reused on every retry of that intent. The operation is **bound to its request**: workload, actor and every request field are hashed into `request_hash`. A retry of an operation that already committed returns the **stored outcome** with `200` and `replayed: true`, even if the version has since moved; the same id with a different workload, actor or content is `422 operation_id_reused`. The check runs **after** the workload row is locked (§5.5), so two concurrent retries cannot both miss it |
| **Deliberate replacement** | Replacing someone else's decision after a `409` is a **new operation** with a new `operation_id` and the version returned in the `409` |
| **Undo** | A new decision (`unclassified`) with `undoes_decision_id` set, recorded, never a deletion. Only `classified_agent → unclassified` |
| **Provider-native** | Not human-editable. The action is not offered; the endpoint returns `422 provider_native` |
| **Audit** | The decision table is the audit record: operation id, actor user id, decision, previous classification, reason, purpose, time, and the version it was made against |

**Identifying the human** — verified against the token code, because every
shortcut here is wrong:

| Tempting check | Why it fails |
|---|---|
| Reject if `client_id` is present | The human console session carries **both** `UserID` and `ClientID` (`GenerateWorkspaceToken`, `authmanager_token_service.go:71`); this rejects every legitimate user |
| Accept if a `user_id` is present | `GenerateEndUserToken`, `GenerateAdminToken`, `GenerateCIBAToken`, `GenerateDeviceAuthToken` and others set `UserID`. An end user of a customer's application would pass |
| `ResolveUserID(c)` | Falls back to `sub`, then email. A machine token's `sub` is the client |
| `IGAController.workspace()` | Falls back to `client_id`, then to the workspace id itself (`iga_controller.go:114-122`) |

**The rule.** Only `GenerateWorkspaceToken` sets `WorkspaceMembershipID`; it
is the discriminator for a human console session, and it is checked against
the record because a membership can be revoked after the token was issued:

```go
func requireWorkspaceHuman(c *gin.Context, db *gorm.DB) (userID uuid.UUID, err error) {
    membershipID := c.GetString("workspace_membership_id")
    uid          := c.GetString("user_id")
    ws           := c.GetString("workspace_id")
    if membershipID == "" || uid == "" || ws == "" {
        return uuid.Nil, errNotWorkspaceHuman // 403
    }
    var n int64
    if err := db.Model(&models.WorkspaceMembership{}).
        Where("id = ? AND workspace_id = ? AND user_id = ? AND status = 'active'",
            membershipID, ws, uid).Count(&n).Error; err != nil {
        return uuid.Nil, err
    }
    if n != 1 {
        return uuid.Nil, errNotWorkspaceHuman // 403: invited, suspended, left, or another workspace's membership
    }
    return uuid.Parse(uid)
}
```

Built on the graph branch (`humanActor`), and all seven cases of
`TestClassifyActorRule` pass. The endpoint, request, response and transaction are in §5.5.

(On the graph branch nothing sets `provider_native_agent`; T4.4 fixes it,
per the two projector rules above.)

**`Unclassified` does not mean "not an agent"** and is never rendered as a
negative or filtered away by default.

#### 2.14.4 Logical agent versus deployed instance

A logical agent persists across versions and deployments; an instance is one
source-native realization. **The product only shows instances it has evidence
for.** Production and staging are two instances of one agent only when the
provider says so — never because their names look alike.

**What the collector actually gathers — verified, `internal/awsdiscovery/bedrock.go`:**

| Provider object | Called | Collected | Gives us |
|---|---|---|---|
| Bedrock agent | `ListAgents`, `GetAgent` | yes | The logical agent, its execution role |
| Bedrock agent **alias** | `ListAgentAliases` | **no** | Nothing — no instances |
| AgentCore runtime | `ListAgentRuntimes`, `GetAgentRuntime` | yes | One deployed runtime per row |
| AgentCore gateway | `ListGateways`, `ListGatewayTargets` | yes | A gateway; its targets recorded as evidence under it |

So **a Bedrock agent has no known instances.** Aliases are what
separate `live` from `canary`, and nothing reads them. The Agents & workloads list
therefore shows the agent with its instance state stated honestly:

```
  customer-support-agent     Provider-native agent    bedrock    22 min ago
                             instances: not collected
  cs-runtime-prod            Provider-native agent    agentcore  22 min ago
  cs-runtime-staging         Provider-native agent    agentcore  22 min ago
```

The two AgentCore runtimes are **two rows**, not one agent with two instances.
Their names suggest they belong together; nothing the provider returns says so,
and grouping on names is the correlation §2.12 forbids.

**Instances are a deferred capability (§1.2).** Showing them needs
`bedrock-agent:ListAgentAliases` per agent and an instance model this
milestone does not build. Until then "instances: not collected" is the correct
display — not a count of zero, and not a guess.

#### 2.14.5 Navigation model

One selected object, a fixed set of views, shared filters. The views are
**alternate lenses on one investigation**, not separate pages that forget each
other.

**Sidebar.** §2.14.2. The object views below are reached from the Agents &
workloads, Identities and Resources lists, from links inside other views, and
from coverage banners.

##### Routes and views

Every object type gets the tabs that answer its own questions. An identity is
not a workload, so it does not borrow the workload's tabs.

| Object | URL | Tabs | What each tab answers |
|---|---|---|---|
| Agent or workload | `/iga/estate/:id/{overview,identities,resources,graph,changes}` | **Overview · Identities · Resources · Graph · Changes** | What it is · what it runs as and who else does · what its declared access names · the path, drawn · what changed |
| Identity (role, user, group) | `/iga/identities/:id/{overview,used-by,permissions,graph,changes}` | **Overview · Used by · Permissions · Graph · Changes** | What it is and where · which workloads run as it and which principals may assume it · which policies grant what, each statement separately · the path, drawn · what changed |
| Resource or selector | `/iga/resources/:id/{overview,access,graph,changes}` | **Overview · Access · Graph · Changes** | Its kind (§2.14.12) and what we know about it · which identities are granted what on it, by which statement · the path, drawn · what changed |
| External principal | `/iga/external-principals/:id/{overview,referenced-by}` | **Overview · Referenced by** | Which account it belongs to and why it is unresolved · what names it. No Graph tab: there is nothing on the far side we could read |

`/iga/estate/:id` with no tab segment is Overview. The **Evidence panel** is
not a tab. It is `?evidence=<claim id>` on whichever view opened it.

##### What a URL carries, and what it promises

| In the URL | In history state only | Never in the URL |
|---|---|---|
| Object id, tab, `provider`, `account`, `region`, `integration`, `q` (search), `sort`, `evidence`, `node` (graph selection), `target` (*View in graph*), `as=paths`, `via` (originating object), `from` (when a link was shared) | Page cursor, scroll position, expanded graph nodes | `rev` |

**`rev` is not in the URL.** A revision is current-only (§5.1), so a `rev` in a shared link would promise a snapshot the server
cannot serve. The client pins `rev` **in memory** for the life of an
investigation and sends it on every request. A pasted link therefore
reproduces **the same object, the same view and the same filters, as they are
now**. It does not reproduce the same revision, and nothing on screen may say
it does.

What a link recipient sees when the graph has changed:

| Case | Shown |
|---|---|
| The object still exists | The current state, and, **only if** the link carries `from=<published_at>` (the "Copy link" action adds it), a one-line notice: *"Shared 22 Sep 14:02. The graph has been rescanned since, so this shows it as it is now."* |
| The object has retired | *"`ticket-tools` is no longer in the latest scan. It was last confirmed 18 Sep."* Overview still renders from the retired row. Other tabs say they have no current data rather than rendering empty |
| The object never existed in this workspace, or belongs to another | *"Not found in this workspace."* The page must not reveal whether it exists elsewhere |
| The `evidence` claim has ended | The panel opens on the ended claim with its `valid_to` and `ended_reason` |

##### When the revision moves mid-investigation

The server answers a stale `rev` with `409 revision_stale` (§5.1). The client must not lose
the investigation to it:

1. **Keep what is on screen.** The rendered data stays, marked with a banner:
   *"A newer scan published at 14:31. You are viewing the previous result.
   [Refresh]"*. It never swaps automatically.
2. **Pause, don't break, further reads.** Anything that would need a new read
   at the old `rev` (the next page, a graph expansion, a different evidence
   claim) shows the same banner inline in place of its result. It must not
   show an empty list or an error.
3. **Refresh keeps the investigation.** Refresh re-pins to the current `rev`
   and reloads the **same object, tab, filters, search, sort and open evidence
   claim**. Pagination restarts at page one, because cursors are
   revision-bound. Graph expansions are re-requested in the order they were
   made.
4. **Say what did not survive.** If the open evidence claim, a selected node
   or an expanded node no longer exists at the new revision, say so in
   place: *"This grant ended in the newer scan. [See the change]"*. Never
   silently close the panel or drop the node.

##### Rows, panels and returning

- **Rows are links.** Clicking a row opens that object's Overview. Rows are
  real anchors, so middle-click and Cmd/Ctrl-click open a new tab. Row
  actions (a menu at the end of the row) are **Open graph**, **Open
  identities** (workloads) / **Open permissions** (identities) / **Open
  access** (resources), and **Copy ARN**.
- **Tabs are routes.** Switching tab pushes one history entry and keeps every
  query parameter except `evidence` and `node`, which belong to the view that
  set them.
- **Evidence panel — one rule for every way in and out.** The panel is a
  query parameter, `evidence=<claim ref>`, on the view that opened it.

  | Action | History | Result |
  |---|---|---|
  | Open, from a closed panel | **push** an entry marked `panel: opened-here` | Panel opens; focus moves into it |
  | Open a different claim while open | **replace** | Panel shows the new claim; Back does not step through claims |
  | **Close** (×) or **Escape** | If the current entry is marked `opened-here`: **go back one entry**. Otherwise (arrived by a direct link, or the marked entry was replaced by a reload): **replace** with the same URL minus `evidence` | Panel closes; focus returns to the opener, or to the view's heading when there is no opener |
  | Browser **Back** while open | The browser pops the entry | Panel closes, because the previous entry has no `evidence` |
  | Direct link with `evidence=` | none | The view renders with the panel open. There is no `opened-here` mark, so Close replaces rather than leaving the page |

  Closing never leaves a duplicate history entry, and Back never reopens a
  panel the customer just closed. The panel never opens a second panel; a link
  inside it navigates the page and closes the panel.
- **Filter, search and sort edits replace**, not push. Back does not walk a
  filter one keystroke at a time.
- **Returning to a list restores it.** Back from an object restores the list's
  filters, search and sort (from the URL) and its page and scroll position
  (from history state). If the revision moved in between, the list reloads at
  the current revision from page one and says why: *"The list was refreshed
  because a newer scan published."*
- **Breadcrumbs name the investigation**, not the schema:
  `Agents & workloads › customer-support-agent › Identities`. Never
  `iga_agents › iga_relationship`.
- **The originating object persists** across detours. Following
  `SharedToolRole` from `ticket-tools`' Identities tab shows *"← Back to
  ticket-tools"* on the role's page. It is carried as `via=<id>`, and is
  dropped when the customer navigates from the sidebar or dismisses it.

##### Existing routes

No existing IGA route is removed or redirected in this milestone.

| Route | Disposition |
|---|---|
| `/iga/cloud`, `/iga/cloud/{identities,compute,resources}` | **Kept** as Cloud Inventory, the raw collection view. The existing `/iga/cloud/aws/*` redirects stay |
| `/iga/identities` | The same route; the placeholder card is replaced by the graph identity list |
| `/iga/agents`, `/iga/integrations`, `/iga/integrations/:id`, `/iga/detection-rules`, governance routes, `/discovery/*` redirects, the Google OAuth callback | Unchanged |

**Links between the two views, not redirects.** Cloud Inventory rows gain an
*"Open in graph"* action where the row has a projected counterpart; graph
objects gain *"Raw inventory"* on Overview. The mapping is a server lookup
(`GET /api/iga/v1/lookup?cloud_ref=…`, §5.3) — never a match by name, because
names repeat across accounts. No current URL carries an object id, so no
id-bearing bookmark exists to break.

#### 2.14.6 Wireframes

**Agents & workloads list.** The entry point. Filters at the top apply everywhere.
Two rows named `ticket-tools` are two workloads in two accounts, so the
account is always a column, never a tooltip.

```
┌────────────────────────────────────────────────────────────────────────────────┐
│ Agents & workloads                                    as of 22 Sep, 14:02      │
│ 3 integrations · 2 complete · 1 partial                                        │
│ [Search name, ARN or account id] [AWS ▾] [All accounts ▾] [All regions ▾]      │
├────────────────────────────────────────────────────────────────────────────────┤
│ ⚠ sandbox (905418271234): iam_users denied. Identity lists for that account    │
│   are incomplete.                                                  [Coverage]  │
├────────────────────────────────────────────────────────────────────────────────┤
│ NAME                    CLASSIFICATION ▾       RUNTIME    ACCOUNT    CONFIRMED │
│ customer-support-agent  Provider-native agent  Bedrock    production 22 min ago│
│   instances not collected                                                      │
│ cs-runtime-prod         Provider-native agent  AgentCore  production 22 min ago│
│ refund-tools            Classified as agent    Lambda     production 22 min ago│
│ ticket-tools            Unclassified workload  Lambda     production 22 min ago│
│ ticket-tools            Unclassified workload  Lambda     sandbox    22 min ago│
│ nightly-etl             Unclassified workload  ECS        production 6 days ago│
│   stale: eu-west-1 compute not read since 15 Sep                               │
├────────────────────────────────────────────────────────────────────────────────┤
│ 1–100 of 412 found · sandbox incomplete                      [‹ Prev] [Next ›] │
└────────────────────────────────────────────────────────────────────────────────┘
```

**Overview.** Answers "what is this and how much do we know?" Plain words
first; the ARN and the raw evidence are one click away, not the headline.

```
┌────────────────────────────────────────────────────────────────────────────────┐
│ Agents & workloads › ticket-tools             AWS · production · eu-central-1  │
│ [Overview] Identities  Resources  Graph  Changes                               │
├────────────────────────────────────────────────────────────────────────────────┤
│ ticket-tools                                             [Classify as agent]   │
│ Lambda function · production (220171243705) · eu-central-1                     │
│ arn:aws:lambda:eu-central-1:220171243705:function:ticket-tools        [Copy]   │
│                                                                                │
│ Classification   Unclassified workload                                         │
│                  Nobody has recorded what this is for.                         │
│ Runs as          SharedToolRole  (shared with 1 other workload)                │
│ Owner            Not assigned                                                  │
│ First seen       12 Mar 2026          Last confirmed   22 min ago              │
│ Identity         Same name only. AWS gives a function no creation id, so a     │
│ continuity       function deleted and recreated under this name looks the      │
│                  same to us.                                          [why?]   │
│ Found by         lambda:ListFunctions in eu-central-1               [evidence] │
└────────────────────────────────────────────────────────────────────────────────┘
```

**Identities.** The execution identity, and who else uses it.

```
│ EXECUTION IDENTITY                                                          │
│ SharedToolRole              arn:aws:iam::220171243705:role/SharedToolRole   │
│ Relationship  executes_as · declared · current · confirmed 22 min ago       │
│ Basis         Configuration. The function is configured to run as this      │
│               role. We have not observed it run.                     [why?] │
│                                                                             │
│ ALSO USES THIS IDENTITY                                                     │
│ refund-tools        lambda · eu-central-1 · confirmed 22 min ago            │
│                                                                             │
│ ⓘ Two workloads share this role. Changing the role affects both.           │
```

**Resources.** Honest about what a selector is.

```
│ NAMED BY DECLARED ACCESS                                                    │
│                                                                             │
│ arn:aws:s3:::support-tickets/*                        Prefix selector       │
│   s3:GetObject · via SharedToolRole                                         │
│   ⓘ A selector, not a resource. It names objects under a prefix; we have   │
│     not enumerated them and do not know whether any exist.                  │
│                                                                             │
│ arn:aws:s3:::support-tickets                          Exact reference       │
│   s3:ListBucket · via SharedToolRole                                        │
│   ⓘ Named exactly by a policy statement. Not independently discovered —     │
│     we have not confirmed this bucket exists.                               │
│                                                                             │
│ arn:aws:kms:eu-central-1:905418271234:key/abcd        External reference    │
│   kms:Decrypt · via SharedToolRole                                          │
│   ⚠ Account 905418271234 is connected but its KMS surface was not read.    │
```

**Changes.** Configuration changes and visibility changes never share a list.

```
│ ┌ Configuration changes ┬ Coverage changes ┐                               │
│                                                                             │
│ 21 Sep 14:02  Grant ended    s3:PutObject on support-tickets/*             │
│               Policy TicketWrite detached from SharedToolRole.              │
│               One other policy still grants s3:GetObject — the path to      │
│               support-tickets/* remains.                          [evidence]│
│                                                                             │
│ 12 Mar 09:41  First seen     ticket-tools                                   │
│                                                                             │
│ ── Coverage changes ──                                                      │
│ 15 Sep 03:10  Became stale   eu-west-1 compute not read since this date.   │
│               No relationship ended. This is a visibility change.           │
```

##### Interaction contract per screen

**Rules every list follows:**

| Concern | Contract |
|---|---|
| **Primary text** | The name the customer recognises. The ARN, account id and provider id are always one step away: a secondary line where it disambiguates, **Copy** on Overview, and the full raw record in the Evidence panel. Search matches them. They are never the headline |
| **Account is always visible** | Names repeat across accounts, so every list row shows its account, by name where the connector has one, and the id on hover and in search. Two rows that differ only by account must look different at a glance |
| **Search** | Server-side, over the **whole inventory** at the pinned revision, never a filter over the loaded page. Matches name (substring, case-insensitive), full ARN, account id, and provider id (exact). Debounced 250 ms; in the URL as `q`; a new search restarts pagination. The empty result names the query and the active filters: *"No workloads match 'ticket' in production. [Clear filters]"* |
| **Ordering** | Every sort has a stable tiebreaker (name, then account, then object id), so paging never repeats or skips a row. The sort is in the URL; only the columns listed as sortable below are |
| **Pagination** | Cursor-based, 100 per page, **Prev / Next**. There are no page numbers, because a cursor cannot jump. Cursors are bound to the pinned revision; a cursor from another revision is refused (§2.14.5). Pages from different revisions are never shown together |
| **Totals** | Two different numbers, never merged. **Found**: how many rows we hold that match, shown only when the server returns `total_known: true`: *"1–100 of 412 found"*. When it cannot count cheaply: *"1–100 · more available"*, never a guessed number. **Completeness** is a separate claim from coverage: if any account in scope is partial, the footer adds *"sandbox incomplete"* and links to Coverage. *"412 found"* is never written as *"412 total"* |
| **Row click** | Opens the object's Overview (§2.14.5, *Rows are links*) |

**Columns and default order:**

| List | Columns (default) | Sortable | Default order | Available, off by default |
|---|---|---|---|---|
| **Agents & workloads** | Name · Classification · Runtime · Account · Last confirmed | Name, Classification, Account, Last confirmed | Name, then account (classification is a filter, §below) | Region · Runs as · Integration · First seen · ARN |
| **Identities** | Name · Type · Account · Used by · Last confirmed | Name, Type, Account, Last confirmed | Name | Region (`global` for IAM) · Trust (may be assumed by) · Integration · ARN |
| **Resources** | Name or pattern · Kind (§2.14.12) · Service · Account · Named by · Last confirmed | Name, Kind, Service, Account | Kind (exact reference, selector, external), then name | Region · ARN |

*Used by* and *Named by* are counts of **declared** relationships, shown as
*"3 workloads"* or *"2 statements"*, and follow the totals rule: if the count
is not known, it reads *"3+"*, not a number that looks exact.

**Detail tabs:**

| Tab | Rows | Grouping | Order |
|---|---|---|---|
| Workload › Identities | Execution identity first, in its own section, then other identity relationships | By relationship kind | Execution identity, then name |
| Workload › Resources | One row per target; under it, **one line per declaring statement** (policy, Sid, actions) | By target; **never** merge two statements into one line | Kind, then name |
| Identity › Used by | Workloads that run as it, then principals that may assume it | Two sections | Name, then account |
| Identity › Permissions | One row per statement: policy · Sid · effect · actions · targets | By policy | Policy name, then statement index |
| Resource › Access | One row per (identity, statement) | By identity | Identity name |

Each tab paginates on its own at 100, with the same totals rule, and says so:
*"20 of 63 statements"*.

**Classification: save, conflict, undo.** The flow the §2.14.3 contract
implies:

| Step | Behaviour |
|---|---|
| **Offered** | **Classify as agent** on Overview, for workloads that are not provider-native, and only when the object's `capabilities.can_classify` is true (§5.2). Otherwise the button is absent, not disabled without a reason. Provider-native agents show why there is no action: *"AWS reports this as an agent."* |
| **Dialog** | Decision (preselected), purpose (optional), reason (**required**, because it is the audit record). Save is enabled once there is a reason |
| **Saving** | **Not optimistic.** The dialog shows *Saving…* and the page does not change until the server answers. A human decision in a security record must not appear to have landed when it has not |
| **200** | Dialog closes; Overview shows the decision line (*"Classified as agent by Priya Shah · 22 Sep · 'handles tier-1 tickets'"*); the list row updates on return. A toast offers **Undo** for 10 seconds |
| **Undo** | A new decision (`unclassified`) with `expected_version` set to the version just returned, and reason *"Undo of the decision at 14:02"*. It is recorded, not a deletion. After the toast is gone, the same action is the **Undo classification** button on Overview, which asks for a reason |
| **409** | Only when a *different* operation changed the classification. The dialog **stays open, with the customer's input kept**, and shows who decided what and when: *"Alex Kim classified this as an agent at 14:01: 'owns refunds'."* Two choices: **Keep theirs** (closes) or **Replace with mine** (a **new** operation, against the version the `409` returned — a deliberate second act). Never auto-retry |
| **403** | *"You need the IGA review permission to classify workloads."* The input is kept |
| **422** | Only reachable if the object became provider-native since load: the dialog closes and Overview reloads |
| **Network failure** | The input is kept and the outcome is **unknown**. The client retries **with the same `operation_id`**: if the first attempt committed, the server returns its stored outcome (`replayed: true`) and the dialog closes as a success; if it did not, the retry applies it. The customer never has to guess |

Classification is **human-owned current state, not part of a revision**: a
decision shows immediately on every screen and does not trigger the *revision
moved* banner. Lists are therefore **not sorted by classification by
default**; the default order is name, then account. The Agents & workloads list
offers classification as filter chips — *All*, *Agents* (provider-native or
classified), *Unclassified* — and as an optional sort. A list request that
filters or sorts on classification binds its cursor to the workspace's
classification clock (§5.5); if a decision lands between two pages, the next
page returns `409 listing_changed`, and the list restarts at page one with
*"The list was refreshed because a classification changed."* Pages that
neither filter nor sort on classification are unaffected by decisions.

#### 2.14.7 Screen and state table

##### Pipeline and first-run states

Shown on Agents & workloads, Identities and Resources, and per account in
Integrations. Driven by `GET /api/iga/v1/pipeline` (§5.3).

| State | Condition | Shown |
|---|---|---|
| **No integration** | No active AWS connector | *"Connect an AWS account to discover its agents and workloads."* **Connect AWS** opens the existing wizard. No table, no zeros |
| **Connected, never scanned** | Connector active, no run | *"production is connected. Start the first scan."* **Scan now** (for people with `discovery:admin`) |
| **Queued** | Run `queued`, or waiting on the workspace barrier | Per account: *"Queued behind the scan of sandbox, which started 4 min ago."* |
| **Collecting** | Run `running` | *"Scanning production · started 3 min ago."* No progress bar: the scanners report no percentage, and one that implied progress would lie |
| **Projecting** | Run `published`, its projection job `queued` or `running` | *"Scan finished. Building the graph…"* |
| **Published** | A publication exists | The lists; the header shows *"as of <published_at>"* |
| **Failed** | Run `failed` or `abandoned`, or projection job `abandoned` | Per account: the error, what was kept (*"Earlier results are still shown and marked stale where affected"*), **View details** into the connector drawer, and **Retry scan** |
| **First publication pending** | Connector scanned, no publication yet | *"The first scan of production finished. The graph is being built."* No empty table |

A published graph stays on screen while a later scan runs, fails or projects.
Only a new publication changes what is shown (§2.14.5).

##### Per-screen states

Every screen defines every row below. **A failed request must never render as
an empty list**: "No identities" and "we could not ask" are different answers,
and conflating them is the failure the whole coverage model exists to prevent.

| State | Agents & workloads list | Overview | Identities | Resources | Graph | Changes |
|---|---|---|---|---|---|---|
| **Loading** | skeleton rows, filters interactive | skeleton | skeleton | skeleton | spinner on canvas, no partial graph | skeleton |
| **Empty** | "No agents or workloads in this scope" + which filters are narrowing it | n/a | Read from `execution_role_state`, never inferred from the absence of an edge: `none` → "No execution role configured" (a real finding); `not_in_inventory` → "Runs as `<arn>` — matches no identity we hold"; `not_in_scan` → "Runs as `<arn>` — not read in the latest scan", plus the coverage reason | "No declared access names any resource" | "No relationships at this depth" + expand control | "No changes recorded since first seen" |
| **Partial** | banner naming the account and surface, rows still shown | per-field "not collected" | "Identities for sandbox are incomplete (`iam_users` denied)" | same | truncation chip on canvas | "History begins 12 Mar — earlier changes predate collection" |
| **Failed** | **error with retry — never "no results"** | error per panel, others still render | error | error | error, canvas stays blank | error |
| **Stale** | age on each row + banner | "Last confirmed 6 days ago" | relationship rows show `stale` and their last confirmation | same | stale edges dashed, legend explains | coverage-change entry |
| **Unconnected** | "No integrations connected" + Connect AWS | n/a | n/a | n/a | n/a | n/a |
| **Truncated** | "100 of 412 shown" + Load more | n/a | "20 of 63 shown" | "20 of 148 shown" | "Showing 87 of 210 nodes at this depth" + Expand | "50 of 900" |
| **Revision moved** | banner: *"A newer scan published at 14:31. You are viewing the previous result. [Refresh]"*. Data stays on screen; never auto-swaps (§2.14.5) | same | same | same | same, and expansion pauses | same |
| **Next page failed** | loaded rows **stay**; the footer shows the error and **Retry** | n/a | same | same | expansion failed: the node shows *"Could not load. Retry"*; the canvas stays | same |
| **Unavailable** | the backend for this view is not deployed: *"Changes will show configuration and coverage history. Not available yet."* Neither an error nor empty | same | same | same | same | same |
| **Not authorized** | `403`: *"You need the IGA read permission to view the identity graph."* Never an empty list, never "not found" | same | same | same | same | same |
| **Refresh failed** | A reload after data was shown failed: the **previous data stays**, dimmed, with *"Could not refresh — showing results from 14:02. [Retry]"* | same | same | same | same | same |
| **Scan queued** | per-account: *"Queued behind the scan of sandbox — started 4 min ago"* | freshness shows the queue, not just the age | same | same | same | same |

**Queued is a real state, because the barrier serializes per workspace.** A
customer with five accounts will see scans wait. That is the price of §2.10A's
guarantee, and the honest response is to show it — which scan is running,
which are waiting, since when — rather than a spinner that implies progress.
**Measure the wait** (p50/p95 time from enqueue to claim, per workspace)
before optimizing; the serialization is correct, and only its cost is
negotiable.

##### Four answers that must never look alike

| Answer | What it means | Where it is shown | Copy |
|---|---|---|---|
| **Empty** | We looked, completely, and there is nothing | In place of the rows | *"No declared access names any resource."* |
| **Partial collection** | We could not look at some surface, so some rows may be missing | A coverage banner above the rows, per account and surface. Rows we do have still render | *"sandbox: iam_users denied. Identities for that account are incomplete."* |
| **Truncated** | We have more rows than this page, or more nodes than this canvas | The table footer or the canvas chip. Always continuable | *"1–100 · more available [Next ›]"* / *"Showing 87 of 210 nodes. [Expand]"* |
| **Failed** | We could not ask this time | In place of the rows, with Retry. Previously loaded rows stay | *"Could not load identities. [Retry]"* |

Partial and truncated **can both be true** at once, and then both show, in
their own places. A truncated list is never described as incomplete
coverage, and a coverage gap is never described as "more available".

##### The Evidence panel

The panel answers one question: **why does the product claim this?** It
opens for a relationship, a grant, a node's existence, or a coverage claim,
and always has the same five parts, in this order:

| Part | Contents | Example |
|---|---|---|
| **Claim** | One sentence in the §2.14.8 wording | *"SharedToolRole is granted s3:GetObject on support-tickets/\* by 2 statements."* |
| **Status** | The four dimensions (§2.14.9) as four separate facts | *declared · current · collection complete · effective access unknown* |
| **Supporting facts** | Each fact on its own line: the source API call, account, region, the scan and time it was collected, and for a grant the **policy, Sid, statement index and the statement excerpt**. Two declaring statements are two entries, each with its own status | *TicketRead (managed) · statement 2 "ReadTickets" · current* / *ToolboxRead (managed) · statement 1 · current* |
| **Freshness** | First seen, last confirmed, and if stale, why and since when | *"Last confirmed 22 min ago by the scan of production."* |
| **Limitations** | What this claim does **not** establish, and any coverage gap that bears on it | *"Conditions, SCPs, permission boundaries and resource policies were not evaluated. We have not confirmed any object exists under this prefix."* |

The **Limitations** part is never empty and never generic boilerplate. It
lists the specific gaps that apply to this claim: an unread surface, an
unevaluated condition key present in the statement, an unresolved external
account. A **Show raw record** control at the bottom reveals the stored
observation JSON, for the engineer who needs it.

#### 2.14.8 Terminology

Wording the UI is **forbidden** to use, and what replaces it:

| Never | Because | Say |
|---|---|---|
| "Can access" / "Allowed" | We evaluate nothing. Conditions, SCPs, boundaries and session policies are all unevaluated | "Declared access" / "A policy grants this" |
| "Never used" | Absence is bounded by a tracking period that varies by Region, and excludes whole policy types | "No attempt reported in the available tracking period" |
| "Last used" | It reports *authenticated attempts*, which include requests that were then denied | "Last authenticated attempt" |
| "Unused permission" | Same, and it invites deletion on absent evidence | "No recorded attempt in the tracking period" |
| "Verified" | Nothing is verified in this phase | "Confirmed by the scan on <date>" |
| "Risk: High" | Needs effective access to mean anything | Nothing. There is no score |
| "Removed" | We saw it stop being declared | "Grant ended" |
| "Agent" for any workload | Most workloads are not agents | "Workload", until classification says otherwise |

**AWS activity semantics, stated once.** Activity comes from
`iam:GenerateServiceLastAccessedDetails` / `GetServiceLastAccessedDetails`
(`internal/awsdiscovery/activity.go`). Verified against the AWS documentation
(*Refine permissions in AWS using last accessed information*, IAM User Guide),
not paraphrased from memory:

1. **Attempts, not outcomes.** AWS: *"includes all attempts to access an AWS
   API, not just the successful attempts."* A request that was then denied
   still sets the timestamp. Unauthenticated attempts are excluded.
2. **The window varies.** Service tracking is *"at least 400 days, or less if
   your Region began tracking this feature within the last 400 days."* So
   there is no universal "400 days". The Region's own tracking start date
   bounds what absence can mean.
3. **Only identity-based policies count.** AWS excludes access allowed by
   *"resource-based policies, access control lists, AWS Organizations SCPs, IAM
   permissions boundaries, and session policies."* A role that reads a bucket
   **only through the bucket's own policy never appears in this report at
   all.** Absence says nothing about access granted from the resource side.
4. **Action-level data is management-plane only.** AWS: *"Action last accessed
   information is not available for any data plane event."* `s3:GetObject` —
   the action in this spec's own worked example — can never be reported at
   action level. Only "touched S3" at service level.
5. **Not authoritative.** AWS directs readers to *"your CloudTrail logs as the
   authoritative source"* for whether calls happened and succeeded.

So the only honest negative is **"No attempt reported in the available
tracking period"**, shown with the verified interval where we have it
(*"tracking since 1 Oct 2015 in eu-central-1"*), and it is **never presented
as a reason to revoke** — point 3 alone means a genuinely used permission can
read as absent.

#### 2.14.9 Four dimensions, never one badge

These are independent and a single status pill cannot carry them. The UI shows
them as separate, individually explainable facts:

| Dimension | Values | Answers |
|---|---|---|
| **Basis** | `declared` · `observed` · `derived` · `asserted` | Where did this claim come from? |
| **Lifecycle** | `current` · `stale` · `ended` | Is it believed now, and how old is that belief? |
| **Collection** | `complete` · `partial` · `stale` per surface | Could we look? |
| **Effective access** | `unknown` — always, this phase | Would a request succeed? |

A row may legitimately read *declared · current · collection partial ·
effective unknown*. Compressing that into amber tells the customer nothing
about which of four different problems they have, and each has a different
owner and a different fix.

#### 2.14.10 Filter semantics

| Filter | Means | On an object with no value |
|---|---|---|
| Provider | Objects collected from this provider | An object with relationships from two providers appears under **both**, and its detail names both |
| Account | Objects whose **own** estate scope is this account | Shown as **Unknown account**. See the rules below |
| Region | Objects whose ARN carries this region | Global services (IAM) are labelled `global` and always shown; a region choice never filters them out. An object whose ARN carries **no** region (every S3 ARN) is **Region not stated**, never `global`, and follows the same rules as an unknown account |
| Integration | Objects supported by this connector | A shared object supported by two connectors appears under both, and its detail lists every supporting source |

**Scoping to Production, precisely:**

- **Starting objects** respect the scope — the Agents & workloads list shows production's
  agents and workloads.
- **Paths leaving the scope stay visible and are labelled.** Filtering to
  production must not hide that production's Lambda can assume sandbox's role.
  The far node renders as out-of-scope with its account named.
- **Coverage for the far segment stays visible.** If sandbox was not read, the
  path says so — otherwise the filter has quietly converted "we could not look"
  into "nothing there".
- **Switching views preserves the investigation.** The filter is in the query
  string; Identities → Graph carries it unchanged.
**Where the account comes from, and when it is unknown:**

| Object | Its own account | Unknown when |
|---|---|---|
| Workload | The account of the connector that collected it. **Always known** | Never. An unresolved *execution identity* (`not_in_scan`, `not_in_inventory`) is a fact about the role, not about the workload, and must not blank the workload's account or drop it from an account filter. In the graph lists the workload's account is its connector's account, so the account filter applies to it. (Cloud Inventory's Compute page, kept unchanged, deliberately shows every account at once.) |
| Identity | From its ARN | Never for a collected identity |
| External principal | From its ARN | The ARN is malformed or a service principal (`lambda.amazonaws.com`) |
| Resource or selector | From its ARN | The ARN has no account field: **every S3 ARN** (`arn:aws:s3:::bucket`), and wildcards such as `*` or `arn:aws:s3:::*`. The parser sets no account for S3 (`policy_statements.go`), which is correct. Guessing the grantor's account would be wrong for cross-account buckets |

**Filtering rules for unknown scope:**

- **"All accounts" includes Unknown account.** The default view hides
  nothing. Unattributed objects are often the ones that need attention.
- **Unknown account is an option in the account filter**, alongside each
  connected account, with its own count. It can be chosen alone.
- **Choosing a specific account excludes unknowns, and says so.** The filter
  bar then reads *"production · 23 with unknown account not shown [Show]"*.
  Selecting production must not look like the complete answer for production
  when a bucket production's roles are granted on has no account in its ARN.
- **An account filter applies to the starting objects, not to paths**: the
  scoping rules above still hold. Filtering Resources to production hides the
  S3 selector row; opening production's `ticket-tools` still shows the path to
  it.
- Unknown renders as **Unknown account**, never blank and never defaulted to
  the connector's account.

#### 2.14.11 The graph

The graph opens **on the selected object**, showing one full declared path,
and expands only when the customer asks. It is not an estate-wide canvas.

The questions it exists to answer, and where each is read:

| Question | Where |
|---|---|
| Which identity is this workload configured to use? | The `executes_as` edge, labelled *configured to run as* |
| Which other workloads share that identity? | A count on the identity node; expanding lists them |
| Which policies declare its permissions? | Each grant edge names its policy; two policies declaring the same grant are **two edges** |
| Which resources or selectors do those statements name? | Terminal nodes, typed by §2.14.12 |
| Where does this cross accounts or providers? | Edges crossing a boundary are marked and the far node names its account |
| Why is this relationship shown? | Every edge opens evidence |
| What is unavailable or stale? | Stale edges are dashed; unread surfaces appear as a coverage note on the affected edge |

**The worked example.** This is the teaching case, and the shape the first
implementation must reproduce:

```
                        ┌─ 2 policies declare this grant ─┐
                        │                                  │
  ticket-tools ──▶ SharedToolRole ══▶ s3:GetObject ──▶ s3:::support-tickets/*
   (workload)    │   (identity)    │   (entitlement)      (prefix selector)
                 │                 │
  refund-tools ──┘                 └─ TicketRead   (managed)  current
   (workload)                      └─ ToolboxRead  (managed)  current
      also uses this identity
                                   ┌──▶ arn:aws:iam::9054:role/data-reader
  SharedToolRole ──can_assume──────┘     ⚠ account 9054 not connected
                                          external principal, unresolved

  ─── stale ───  nightly-etl ┄┄▶ EtlRole
                 eu-west-1 compute not read since 15 Sep.
                 This is a visibility change, not a removal.
```

Five things this single picture has to get right:

1. **Two workloads, one identity.** `refund-tools` is a second source edge
   into the same node, not a duplicate path.
2. **Two policies, one grant.** `TicketRead` and `ToolboxRead` both declare
   `s3:GetObject`. The canvas may draw **one** connection for legibility, but
   **the evidence panel and the change history must preserve both
   independently** — otherwise detaching one looks like losing the access.
3. **Detach one, the path survives.** When `TicketRead` is detached, that
   grant ends; the edge remains because `ToolboxRead` still declares it. The
   change entry says exactly that, and the graph does not flicker.
4. **The external role is unresolved.** Account 9054 is not connected, so the
   far end is an `iga_external_principal` node, drawn distinctly, and the UI
   says the account is not connected rather than implying the role is absent.
5. **Stale is dashed, not missing.** A failed refresh makes an edge stale. It
   stays on the canvas with its last-confirmed time.

**Wording.** Edge labels are `configured to run as`, `may assume`, `granted
by`, `names`. Never `can access`, never `uses`. Configuration is not observed
activity, and a declared grant is not proof an AWS request succeeds.

##### Budgets

The graph has **display defaults**, which decide what is drawn first, and
**hard server budgets**, which bound any single request. They are defined once,
in §5.4. The canvas never implies more than the response establishes:

- Truncation is always explicit and continuable: *"Showing 87 nodes; more are
  available at this depth. [Expand]"*.
- When any budget binds, **every completeness claim is suppressed** — no
  counts presented as totals, no "this workload names 3 resources".
- A node at the assume-hop default reads *"may assume more roles — expand"*
  (with the count only when the server counted it exactly); it never looks
  like the chain ends there.
- *No path found* has two forms, and they are never merged: *"No declared
  path exists"* (the search finished) and *"No path found within the limits"*
  (a budget stopped it — the answer is unknown).

##### The graph and the lists must agree

The graph is bounded and a list is paginated, so **they will not show the same
set of objects**, and nothing may suggest they do. What must hold is narrower
and testable:

- **Same revision, same claims.** Both read the pinned revision (§2.14.5) with
  the same filters. Any fact shown on both — an object's name and kind, a
  relationship's basis and lifecycle, the list of statements declaring a
  grant, a coverage gap — is identical on both. A disagreement at the same
  revision is a bug, not a view difference.
- **Absence on the canvas is never a claim.** An object missing from the
  canvas is *not drawn*, not *not there*. When any limit binds, the canvas
  shows its truncation chip and suppresses every count presented as a total
  (see *Limits*).
- **"View in graph" must find the thing it was asked for.** From a list row
  (for example a resource under `ticket-tools` › Resources), it opens the Graph
  tab rooted at the current object with `target=<id>`. The server returns the
  declared paths from the root to that target within the limits, and the
  canvas draws and highlights them. If no path fits within the limits, the
  canvas says which of the two it is, per §5.4: *"No declared path from
  ticket-tools to support-tickets/\*."* when the search finished, or *"No
  path found within the search limits — one may still exist. [Search
  deeper]"* when a budget stopped it. It never opens a canvas that silently
  lacks the target, and never states a distance it did not measure.

##### Controls

| Concern | Behaviour |
|---|---|
| **Select vs open** | One click (or Enter on a focused element) **selects**: a node shows its summary, an edge shows its evidence, in the side panel. Selection is `node=` / `evidence=` in the URL and **replaces** history. **Open** (double-click, or the panel's **Open** button) **navigates** to that object's own page and pushes history. **Focus here** re-roots the graph on the selected node, as a new history entry |
| **Expand** | A node with unshown neighbours carries a count: *"+3 roles"* (or *"+3 or more"* when the count is not known). Expanding adds exactly those neighbours, one step. `max_assume_hops` is a starting depth, never a ceiling on expansion |
| **Collapse** | Collapsing removes what that expansion added **unless** the same node is also reached by another expanded path. Nodes are reference-counted by expansion, so collapsing one path never breaks another |
| **Shared paths** | A node reached by several paths is drawn **once**. Many workloads sharing one identity collapse into one group node, *"Used by 14 workloads"*, which expands into its members |
| **Grouped edges** | Several grants between the same two nodes may be drawn as **one line with a count badge** (*"2 statements"*) for legibility. The grouping is visual only. The evidence panel lists every grant separately, each with its own status. Line style follows the most-current member: solid if **any** grant is current, dashed only if **all** are stale, and the badge carries the mix (*"1 current · 1 ended"*). Ending one grant never restyles the line while another is current |
| **Exclusions** | A `NotResource` statement is drawn with an *"except finance/\*"* chip on its statement node and a positive edge only to the `*` selector. An excluded resource is **never** drawn as the end of a path, and the Paths list reads *"all resources except finance/\*"* |
| **Cycles** | Role A may assume B, and B may assume A. Each node is drawn once; the edge back to an already-drawn node is drawn to it and marked *cycle*. Expansion never re-adds a visited node. The server de-duplicates too (§5.4) |
| **Loading and failure** | The first load is all-or-nothing: an error with Retry, never a partial canvas presented as the answer (§2.14.7). An **expansion** failure is local: that node shows *"Could not load. Retry"*, and everything already drawn stays. A truncated response is not a failure and is never shown as one |
| **Layout stability** | A deterministic left-to-right layered layout: workload → identity → statement → resource or selector, with external principals in the identity column's upper band. Expanding and collapsing **never moves nodes already on screen**; new nodes take free positions by the placement rule in §2.14.15. Only a refresh to a new revision may re-lay out, and it says so (*"Layout updated for the newer scan"*). Transitions are 200 ms at most and are removed under `prefers-reduced-motion` |
| **Legend** | Always visible: node kinds, edge labels (§2.14.11 *Wording*), dashed = stale, the cycle marker, the out-of-scope marker, the truncation chip |

##### The path list, the accessible equivalent

The Graph tab has two presentations of **the same response**: **Canvas** and
**Paths**. Paths is a nested list: each declared path is an ordered list of
steps, each step naming the node, its kind and account, and the edge label
into it (*"ticket-tools — configured to run as → SharedToolRole — granted by
TicketRead, ToolboxRead → s3:GetObject — names → support-tickets/\*
(prefix selector)"*).

- It is **complete for what was loaded**. Anything drawn on the canvas is in
  the list, and expansion and truncation work the same way in both.
- Grouped edges are **never** grouped in the list. Each statement is its own
  item.
- It is the **default below 768 px**, with the canvas available but not
  imposed.
- Selecting a step opens the same Evidence panel as selecting the edge on the
  canvas. The toggle's state is in the URL (`as=paths`).

The canvas itself supports the keyboard (§2.14.15), but the path list is how
a screen-reader user, or anyone who prefers text, gets the whole answer.
Neither presentation may know something the other does not.

#### 2.14.12 Resources: four kinds, never conflated

An ARN in a policy is not proof a resource exists. The UI types every resource
row, and this milestone produces three of the four:

| Kind | Meaning | This milestone |
|---|---|---|
| **Discovered resource** | Independently enumerated from the provider; we know it exists | **No.** Nothing enumerates resources this phase |
| **Exact reference** | A statement names this exact ARN. Existence unconfirmed | Yes |
| **Prefix / wildcard selector** | A statement names a pattern. It may match nothing | Yes |
| **External / unresolved** | The ARN belongs to an account or provider we cannot read | Yes |

**An S3 object selector is never rendered as a bucket.** `s3:::tickets/*` and
`s3:::tickets` are different grant targets with different blast radius, and
`TypeResourceARN` already distinguishes `s3_object` from `s3_bucket`
(`internal/awsdiscovery/policy_statements.go`). The UI must carry that through
rather than collapsing to "bucket: tickets".

Counts follow the same rule: *"names 3 selectors and 1 exact reference"*, never
*"has access to 4 resources"*.

#### 2.14.13 Coverage UX

Coverage explains **what is missing and which conclusion it prevents** — that
second half is what makes it actionable rather than a complaint.

```
┌─ Coverage · sandbox (905418271234) ──────────────────────────────────────────┐
│ iam_users            denied                                                   │
│   AWS returned AccessDenied for iam:GetAccountAuthorizationDetails (Users).   │
│   Prevents: listing IAM users in this account, and any path that starts at    │
│             one. Role-based paths are unaffected.                             │
│                                                                               │
│ compute:eu-west-1    not selected                                             │
│   The region is not in this account's scan scope.       [Change regions]     │
│   Prevents: nothing is claimed about eu-west-1. Earlier results from it are   │
│             kept and marked stale.                                            │
│                                                                               │
│ policy_documents     partial · 1 policy could not be parsed                   │
│   TicketRead (v3): unexpected value in Condition.                             │
│   Prevents: ending or changing anything granted by TicketRead. Its statements │
│             are shown stale. Other policies are unaffected.                   │
└───────────────────────────────────────────────────────────────────────────────┘
```

**Name the call, not a guess at the fix.** An `AccessDenied` response says
which API call failed; it does not say which permission is missing, and an
SCP, a permissions boundary on the discovery role or a region opt-out can all
produce it. So coverage names the failed call and the error code, and offers a
fix only when the evidence supports one: *"not selected"* has **Change
regions**; a template version older than the current one has *"Update the
CloudFormation stack"*. Each surface states its own cause and consequence;
there is never one "grant these permissions" button for everything.

#### 2.14.14 Console primitives and frontend handoff

Verified against `Authsec-ui` on `authsec-staging`. Nothing here needs a new
layout system; every screen composes from what exists, with two exceptions
named below.

| Screen | Composition |
|---|---|
| Agents & workloads, Identities, Resources lists | `ConsolePage` (title, description, actions) → `ConsoleFilterBar` (`console/iam-console.tsx`) → `TableCard` (`theme/components/cards.tsx`) → `AdaptiveTable` (`ui/adaptive-table.tsx`), with `ui/table-skeleton` for the loading state. **Pagination needs a cursor variant**: `ui/table-pagination` takes `currentPage`, `totalPages` and `totalItems`, none of which a cursor list has. Add a Prev/Next control that renders *"1–100 of 412 found"* or *"1–100 · more available"* from `total_known` |
| Object detail header + tabs | `ConsolePage` with `ui/breadcrumb` in the title slot and `ui/tabs` for each object type's tabs (§2.14.5). **Tabs are routes**, not local state, so Back and deep links work |
| Overview body | `console/detail.tsx`: `DetailGrid` + `DetailRow`, `CopyField` for ARNs |
| Relationship and evidence rows | `AdaptiveTable` rows; lifecycle via `console/status.tsx` `StatusBadge` — **one badge per dimension**, never a combined tone (§2.14.9) |
| Coverage and partial banners | `console/status.tsx` `DecisionBanner`, per affected account |
| Evidence panel | `ui/sheet` — a single side panel with its own URL. **Not** `ui/drawer` stacked on a drawer (§2.14.5 forbids nesting) |
| Graph canvas | The one genuinely new component. Sits in the Graph tab's `TableCard` slot; its legend and truncation chip reuse `StatusBadge` |

The graph canvas is the only surface with no existing primitive, and it
is built after the lists (§6) — the list views answer every question in §2.14.11
except the visual one, and they can ship first. The library decision is §2.14.15.

##### What every IGA response must carry

The UI depends on these on **every** list and detail response. They are defined in §5.2:

| Field | Used for |
|---|---|
| `rev`, `published_at` | Pinning (§2.14.5); the *"as of 14:02"* label; the shared-link notice |
| `data[].ref` (typed, §5.2), `name`, `arn`, `account` (`{id, label, connected}`, or `null` = Unknown account), `region` (or `global`, or `null` = not stated) | Rows, disambiguation, search display |
| `next_cursor` | Next page. **Prev is client-side**: the client keeps the stack of cursors it has used, so the server needs no backward cursor |
| `total_known`, `total` | The totals rule (§2.14.6). `total` is present only when `total_known` is true |
| `meta.coverage[]`: `{account_id, surface, state, affects}` for every gap that bears on this result | Partial banners (§2.14.7). Computed by the server, never inferred client-side from row counts |
| `meta.capabilities` on detail responses (`can_classify`) | Offering actions (§2.14.6). The client never infers permissions from role names |

##### Contracts behind every screen

Every contract the console uses is specified in §5. There is no
"to be decided by backend" item; this table is the index.

| Screen or behaviour | Contract (§5.3) |
|---|---|
| Pipeline and first-run states | `GET /pipeline`, `GET /aws/connectors/:id/scan-runs` |
| Agents & workloads list and Overview | `GET /workloads`, `GET /workloads/:id` |
| Workload › Identities | `GET /workloads/:id/identities` |
| Workload › Resources | `GET /workloads/:id/resources` |
| Identities list, Overview, Used by, Permissions | `GET /identities`, `/identities/:id`, `/used-by`, `/permissions` |
| Resources list, Overview, Access | `GET /resources`, `/resources/:id`, `/access` |
| External principal | `GET /external-principals/:id`, `/referenced-by` |
| Graph, expansion, re-rooting, *View in graph* | `GET /graph`, `GET /graph/expand`, `GET /graph/path` |
| Evidence panel | `GET /evidence?claim=…` |
| Changes | `GET /{workloads,identities,resources}/:id/changes` |
| Coverage | `GET /coverage` |
| Classification | `POST /workloads/:id/classification`, `GET /workloads/:id/classification` |
| Search, sort, facets, totals | Every list: `q`, `sort`, `facets`, `total_known` (§5.2) |
| Retired objects | Every detail route returns retired objects with `lifecycle` (§5.2) |
| Unavailable features | `GET /capabilities` |
| Cloud Inventory ↔ graph links | `GET /lookup` |

The console must not work around a contract: no client-side search over a
loaded page, no totals computed by paging to the end, no name-based matching,
no evidence assembled by joining lists.

##### Development fixtures

The UI is built against fixtures first, so screens can be designed and tested
before the backend ships, and fixtures double as the acceptance data in §7.2.
**Tooling decision:** MSW for request mocking in development and component
tests, and Playwright with `@axe-core/playwright` for the browser-level UI
gates (§7.2). None is a dependency today (`package.json` has Vitest and
Testing Library only); all three are added as dev dependencies in T7.1. Fixtures are typed from the same TypeScript contract types
the API slice uses, so a contract change breaks the fixture build rather than
drifting silently.

| Fixture | Contents | Exercises |
|---|---|---|
| `worked-example` | §2.14.11's picture: `ticket-tools`, `refund-tools`, `SharedToolRole`, `TicketRead` + `ToolboxRead` on `support-tickets/*`, the unresolved role in 9054, stale `nightly-etl` | Every screen's primary story; U1–U5 |
| `grant-detached` | `worked-example` at the next revision, with `TicketRead` detached | Independent grants; revision moved; Changes |
| `large-inventory` | 5,000 workloads, 3 accounts, 40 duplicate names across accounts, one account partial | Search, paging, totals, duplicate names |
| `unknown-scope` | S3 selectors, a service principal, a `*` resource | Unknown account and Region not stated |
| `partial-and-truncated` | A result that is both coverage-partial and paginated | *Four answers that must never look alike* |
| `classification-conflict` | An object whose `classification_version` moves between read and save | The `409` flow, including our own lost-response retry |
| `cycles` | A may assume B, B may assume A, and a 6-hop chain | Cycle marker; expansion past `max_assume_hops`; *not within limits* |
| `failures` | Each endpoint failing: `500`, network drop, `409` stale revision, route not deployed | Failed, Next page failed, Unavailable |
| `retired-object` | A shared link to a workload no longer in the latest scan | Retired-object notice |

##### Unavailable features

The UI and the backend release separately, so a UI build may be live against
a backend that lacks a view. The rule: **a view whose backend is not deployed
is not shown in navigation**, driven by the capabilities contract above. A
view reached anyway, through an old link or a race, renders the *Unavailable*
state (§2.14.7). It is never an error and never empty. Views planned for a
later phase are **not** shown as greyed-out teasers: nothing in the product
claims a capability that is not live.

##### Cache isolation: workspace and revision

- **Workspace.** Every IGA cache entry is keyed by workspace. Switching
  workspace resets the IGA API state and discards in-flight responses for the
  previous workspace. Nothing in `src/` calls `resetApiState` today (checked),
  so this has to be built, not assumed.
- **Revision.** Every IGA cache entry is keyed by the pinned `rev`. A response
  whose echoed `rev` differs from the pinned one is never merged into the
  pinned entries. It triggers the *revision moved* banner (§2.14.5). Pages from
  different revisions are never concatenated.
- **Classification** is not revision-bound. A successful save invalidates that
  object and the lists containing it, at the same `rev`.

##### Responsive layouts

| Width | Lists | Detail | Evidence panel | Graph |
|---|---|---|---|---|
| ≥ 1280 px | Full table | Tabs across the top | Side panel **beside** the view; the view stays usable | Canvas + side panel |
| 768–1279 px | Table; off-by-default columns stay off | Same | Sheet **over** the view | Canvas; panel as a sheet |
| < 768 px | `AdaptiveTable` card layout: name, account and classification on every card | Tabs become a select | Full-screen sheet with a back arrow | **Paths** by default (§2.14.11); canvas on request |

##### Keyboard

| Where | Keys |
|---|---|
| Anywhere in IGA | `/` focuses search. `Esc` closes the Evidence panel, then clears a selection |
| Lists | `↑` / `↓` move between rows; `Enter` opens; `Cmd/Ctrl+Enter` opens in a new tab; `.` opens the row's action menu |
| Tabs | `←` / `→` between tabs (the `ui/tabs` default); `Enter` activates |
| Evidence panel | Focus moves into the panel on open and returns to the opener on close; `Tab` is trapped only on the full-screen sheet |
| Graph canvas | `Tab` moves through nodes in path order; arrow keys follow edges from the focused node; `Enter` selects; `Shift+Enter` opens; `+` / `-` expand and collapse |
| Paths | A standard nested list: arrow keys, `Enter` selects a step |

Every interactive element has a visible focus state, and every state in
§2.14.7 is announced to screen readers through a live region (*"Showing 100 of
412 found"*, *"Could not load. Retry"*, *"A newer scan published"*).

#### 2.14.15 Graph rendering: React Flow and ELK

**Decision: `@xyflow/react` 12 (React Flow) renders and interacts; `elkjs`
0.12 computes the initial layered layout.** The backend decision against a
second graph *datastore* (§4.1) is unaffected; this is a rendering library.

**What was verified** (23 Sep, in a scratch project outside the product
repos, against representative graphs):

| Check | Result |
|---|---|
| Compatibility | `@xyflow/react` 12.11.6 declares `react >=17`; rendered correctly under React 19.1 (the console runs 19.2) |
| Licences | React Flow **MIT**. ELK **EPL-2.0 OR GPL-3.0-or-later**; we take it under EPL-2.0, shipped unmodified in the bundle. EPL-2.0's obligations attach to modifications of ELK itself; confirm with legal before release (a release checklist item, not a design blocker). The fallback, if legal declines, is `@dagrejs/dagre` (MIT), with the column assignment done by us |
| Worked example (9 nodes, 8 edges) | Layout 44 ms first run, 10 ms after; identical positions on every rerun |
| Cycle plus a six-hop assume chain | Deterministic; the cycle edge is the only one drawn right-to-left |
| Display maximum (150 nodes, 300 edges) | ~400 ms, deterministic. Acceptable only off the main thread — ELK runs in a Web Worker (`elk-worker.min.js`) |
| Bundle | ELK 1.4 MB minified, React Flow 126 KB plus 52 KB of d3. **The graph is a lazy-loaded chunk**, fetched only when the Graph tab first opens |
| Keyboard | React Flow makes every node focusable with a role and a description, and Tab follows node order. **Enter did not select a node, and there is no live region** — both are ours to build |
| Layout stability | **Neither re-layout nor ELK's interactive mode preserves positions.** A full re-layout after expanding four nodes moved 3 of 9 existing nodes; interactive mode with position hints moved 7 of 9, and with fixed columns it exhausted memory |

**Layout stability, therefore, is ours.** ELK computes the layout **once**, on
first load, and again only on an explicit **Tidy layout** action or when a
refresh moves to a new revision (announced, §2.14.11). Expansion does not call
ELK. New nodes are placed by our own deterministic rule, with every existing
node pinned:

1. Columns are fixed by node kind: workload · identity · statement · resource,
   with external principals in the identity column's upper band.
2. A new node goes in its kind's column, in the first free slot below the
   lowest existing node connected to the node that was expanded, at the
   standard vertical spacing.
3. Slots are claimed in the order the server returned the nodes, which is
   stable (§5.4), so the same expansion always lands the same way.
4. Collapsing frees slots but does not move the remaining nodes.

**Components.**

| Element | Built as |
|---|---|
| Node | A custom node per kind, composed from existing console primitives (`StatusBadge` per dimension, `EntityCell`). Shows name, kind, account, and the lifecycle badge. External principals and selectors have their own visual treatment |
| Grouped-grants edge | A custom edge whose label is a button: *"granted by · 2 statements"*, `aria-label` included. Selecting it opens the evidence panel listing every grant separately |
| Expand / collapse | A control on the node: *"+3 roles"*, or *"+ more"* when the count is not exact |
| Re-root | **Focus here**, in the node's panel; a new history entry |
| Cycle marker, out-of-scope marker, truncation chip, legend | React Flow overlays using `StatusBadge` |
| Zoom | React Flow's controls; zoom level is not in the URL |
| Keyboard | Our `onKeyDown` on the node component: Enter selects, Shift+Enter opens, arrow keys move to the connected node in that direction, `+`/`-` expand and collapse. A polite live region announces selection, expansion, truncation and errors |
| Paths | The accessible equivalent (§2.14.11), from the same response; no React Flow involved |
| Attribution | React Flow's attribution stays visible unless the company subscribes to React Flow Pro; the MIT licence permits hiding it, the project asks that commercial users who hide it subscribe. A product decision, not a technical one |
### 2.15 One path, traced end to end

The spec's own coherence check. If a step cannot be followed through §3, §4
and §5, the spec is incomplete regardless of which terms appear in it.

**Subject:** `ticket-tools`, a Lambda in `eu-central-1` of account
`220171243705`, running as `SharedToolRole`. Two managed policies,
`TicketRead` (statement `ReadTickets`) and `ToolboxRead` (a statement with no
Sid), each allow `s3:GetObject` on `arn:aws:s3:::support-tickets/*`.

#### The happy path

| # | Step | Where | What becomes true |
|---|---|---|---|
| 1 | Scan requested | `POST /aws/connectors/:id/scan` → `cloud_scan_run` `queued` | `GET /pipeline` shows the account *Queued* |
| 2 | Claimed, barrier taken | `cloud_scan_run` `running`, generation 8 fixed on the run; `iga_pipeline_lease` `idle → collecting`, `v7` | No other scan in this workspace; *Collecting* |
| 3 | IAM read | `GetAccountAuthorizationDetails`: `cloud_identity` for the role (`unique_id AROA5XK…`, trust document), `cloud_policy` ×2 with documents, `cloud_policy_attachment` ×2 | `iam_roles`, `iam_users`, `iam_groups`, `iam_policies`: `reached` |
| 4 | Compute read | `cloud_workload` for `ticket-tools`, `identity_id →` the role | `lambda:eu-central-1: reached` |
| 5 | Evidence | An observation per role, policy version and workload, `last_confirmed_run_id = run` | Every later claim can name its source |
| 6 | **Publish** | One transaction: coverage stamped; run `published`; `iga_projection_job` enqueued; barrier `collecting → projecting`, holder `job:<id>`, `v8` | *Building the graph…* |
| 7 | Job claimed | Its own lease; the barrier's holder names this job, so it proceeds at once | |
| 8 | Snapshot | `REPEATABLE READ`; rows at generation 8; the run's own coverage; observations it confirmed | Inputs fixed for the pass |
| 9 | Fence, replay, order | Job lease and barrier `(workspace, projecting, run, v8)` asserted `FOR UPDATE`; no publication for this run yet; every partition's watermark below 8 | A superseded job commits nothing |
| 10 | Nodes | Identity, workload, 2 policies, 2 statements (`sid:ReadTickets`; `h:3f9c…`), 1 selector resource — each with its support row | Stable ids; `first_seen_at` kept on rescans |
| 11 | Edges | `executes_as`; 2 assignments (`attached`); **2 grants** (one per statement, each through its own assignment); 2 targets | Independent grants |
| 12 | Evidence linked | Each edge to the observations this run confirmed | Every edge has evidence (§4.8 gate) |
| 13 | Reconcile | Same transaction; nothing to end on a first run | |
| 14 | Commit | Graph + watermarks + `iga_publication` `rev = N`, one commit; job `complete` and barrier `idle` in the next transaction, together | *as of 14:02* |
| 15 | **API** | `GET /workloads/<id>/identities` in one read-only snapshot at `rev N`: `SharedToolRole`, `executes_as`, `declared`, `current`; `used_by_count: 2` | §5.3 |
| 16 | **API** | `GET /workloads/<id>/resources`: one target, `support-tickets/*`, kind `selector`, **two** statement lines | Independent grants visible |
| 17 | **Customer** | Agents & workloads → `ticket-tools` (production) → Identities → Resources → evidence | E3 |

#### Change: `TicketRead` is detached, then the scan repeats

The next run reads `SharedToolRole` with one attachment. `canEnd` passes for
the assignment and grant partitions; the `TicketRead` assignment and its grant
end with `valid_to` and `ended_reason = 'not_seen'`. `TicketRead` itself —
still a policy in the account, attached elsewhere or not — keeps its row while
its support holds. `ToolboxRead`'s grant is confirmed and stays `current`. The
Changes view: *"21 Sep 14:02 — TicketRead detached from SharedToolRole. The
path to support-tickets/\* remains through ToolboxRead."* (E6)

#### Change: `ToolboxRead`'s statement is edited

It has no Sid, so its content hash changes: statement `h:3f9c…` loses support
and retires; its grant ends `statement_retired`; statement `h:a41e…` appears
with a new grant. The Changes view says a statement without a Sid changed and
is shown as one ending and another beginning. Had it carried a Sid, the same
statement would have gained a revision instead. (E7)

#### Failure: the role disappears, then returns

A clean scan does not see `SharedToolRole`; its support ends, it retires
`unsupported`, and every edge on it ends `subject_retired`. If it returns with
the **same** `RoleId`, it is restored: same id, same `first_seen_at`; its
relationships are new rows, because we did not observe them in the gap; an
asserted association comes back `pending_reconfirmation`. If it returns with a
**different** `RoleId`, it is a new object and nothing transfers. (E8)

#### Failure: IAM is denied on a rescan

No IAM surface is `reached`. Every IAM partition goes `stale`; zero rows end;
`last_confirmed_at` keeps its old value. The graph looks unchanged except for
stale markers, and coverage says what was denied and what that prevents. (E9)

#### Failure: the projection worker dies at step 11

Its job lease expires; the barrier stays `projecting`, held by the job. The
job is reclaimed; the new worker proceeds because it now holds that job's
lease; projection is idempotent and converges. The dead worker's fenced
writes fail. (E13)

#### Failure: crash after commit, before the job completes

The graph and its publication row are committed; the job still reads
`running`. The reclaimed replay finds the publication for its run at step 9
and returns `AlreadyPublished` **before any write**; the job completes and the
barrier is released. It does not re-project: after a committed pass the
watermark equals this generation, and a guard that treated that as stale would
fail the job forever. (E13)


---

## 3. Schema

**Numbering, verified.** Production (`0e75ad7`) ends at
`026_governance_schema_parity.sql`; no duplicate version exists on either
branch. The graph branch's `027`–`034` have **never shipped**, so they are
**edited in place** to match this section rather than followed by corrective
migrations. `035`–`036` are new. `037` is the contract step, released after
the rollback window.

| # | File | Status on the graph branch | Change |
|---|---|---|---|
| `027` | `workspace_qualified_provenance` | Built | None |
| `028` | `iga_recognition_keys` | Built | Drop the `iga_agents` block; add `provider` to the shared node tables with the `github` backfill |
| `029` | `iga_workload` | Built | Add `provider`, `provider_attrs`; classification operation id, actor columns and the classification clock |
| `030` | `iga_access_edges_typed` | Built — **drops** `subject_kind`/`subject_id` | **Expand only**: keep both legacy columns |
| `031` | `iga_relationship` | Built | Types become `executes_as`, `task_execution_role`, `member_of`, `can_assume` (no `realizes`, no agent-instance endpoint); trust statement columns |
| `032` | `iga_evidence_and_support` | Built | Drop `agent_id` from support |
| `033` | `iga_projection_job_state` | Built | Drop the `iga_agents` / `iga_agent_instances` ALTERs |
| `034` | `iga_external_principal` | Built | None |
| `035` | `aws_collection_model` | — | **New**: groups, policies, attachments, trust documents, policy evidence |
| `036` | `iga_permission_model` | — | **New**: policies, statements, revisions, targets, assignments; grants reference assignments |
| `037` | `iga_access_edges_contract` | — | **New, later release**: drop the legacy subject columns once rollback to a pre-`030` binary is no longer supported |

**Rollout.** `027`–`036` ship in **one release** with `IGA_GRAPH_PROJECTION=off`
(§2.8). They are additive for the previous binary, so rolling back to
`0e75ad7` is supported until `037`. Projection is switched on separately, after
the release is verified.

**The runner continues past a failed file and then refuses to boot**
(`runner.go:213-259`, `cmd/main.go:96-97`). A migration that fails in
production therefore takes the service down with some later files applied. Two
gates follow: the production-schema rehearsal (§9) passes before merge, and
`027`'s cross-workspace pre-flight count is run against production **before**
the release.

**`001_bootstrap.sql` is not extended with `027`+.** The repository rule
"bootstrap = end state" conflicts with the runner, which re-applies every
numbered file after `001` on a fresh database, and several of these files
contain statements that cannot run twice. The bootstrap already stops before
`024`. Every migration from `027` is written to apply cleanly on a fresh
`001`–`026` database and on a production dump; the conflict is reported separately for the repository rules to settle.

### 027 — workspace-qualified provenance, and the pipeline barrier

**The pipeline barrier (§2.10A) lands here**, in the foundation migration:
everything downstream assumes a workspace cannot collect and project at
once, and the barrier is the row that makes that true.

```sql
CREATE TABLE IF NOT EXISTS public.iga_pipeline_lease (
    workspace_id uuid NOT NULL,
    -- idle -> collecting -> projecting -> idle
    state        text NOT NULL DEFAULT 'idle',
    holder       text NOT NULL DEFAULT '',   -- worker identity
    scan_run_id  uuid,
    expires_at   timestamptz,
    -- Fence token. Every transition demands the version it read, so a
    -- worker that slept past its expiry is refused because the version
    -- moved on -- never because a clock was consulted.
    version      bigint NOT NULL DEFAULT 0,
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_pipeline_lease_pkey PRIMARY KEY (workspace_id),
    CONSTRAINT iga_pipeline_lease_state_chk CHECK (
        state IN ('idle', 'collecting', 'projecting')),
    CONSTRAINT iga_pipeline_lease_busy_chk CHECK (
        (state = 'idle') = (holder = '' AND scan_run_id IS NULL))
);
```

```sql
-- Every composite FK below needs this target, and it does not exist:
-- 010 gives cloud_connector only a primary key on id and
-- uq_cloud_connector_scope. Without it, every
-- REFERENCES cloud_connector (workspace_id, id) in 030–033 fails to apply.
ALTER TABLE public.cloud_connector
    ADD CONSTRAINT cloud_connector_workspace_id_key UNIQUE (workspace_id, id);
```

`024` (shipped, `b47adeb`) closed D1–D4. It did **not** close §2.9, and in
closing D4 it added a third instance of the same gap.

Three foreign keys reference `cloud_scan_run` by `id` alone, so a row in one
workspace can point at another workspace's scan run:

| Where | Column |
|---|---|
| `001_bootstrap.sql:6880` | `cloud_observation.scan_run_id` |
| `022_cloud_observation.sql:43` | same constraint, as re-declared |
| `024_scan_evidence_durability.sql:130` | `cloud_observation.last_confirmed_run_id` |

Neither `cloud_scan_run` nor `cloud_observation` has `UNIQUE (workspace_id, id)`,
which is why the composite form was not available to write. This migration adds
the targets and converts the references.

```sql
ALTER TABLE public.cloud_scan_run
    ADD CONSTRAINT cloud_scan_run_workspace_id_key UNIQUE (workspace_id, id);
ALTER TABLE public.cloud_observation
    ADD CONSTRAINT cloud_observation_workspace_id_key UNIQUE (workspace_id, id);

-- Verify the real constraint names against \d+ cloud_observation in the
-- rehearsal database before running this: these are PostgreSQL's defaults for
-- inline column references and a wrong name fails the migration.
ALTER TABLE public.cloud_observation
    DROP CONSTRAINT cloud_observation_scan_run_id_fkey,
    ADD CONSTRAINT cloud_observation_run_fkey
        FOREIGN KEY (workspace_id, scan_run_id)
        REFERENCES public.cloud_scan_run (workspace_id, id) ON DELETE RESTRICT,

    DROP CONSTRAINT cloud_observation_last_confirmed_run_id_fkey,
    ADD CONSTRAINT cloud_observation_last_confirmed_fkey
        FOREIGN KEY (workspace_id, last_confirmed_run_id)
        REFERENCES public.cloud_scan_run (workspace_id, id)
        ON DELETE SET NULL (last_confirmed_run_id);
```

`ON DELETE SET NULL (last_confirmed_run_id)` nulls only that column and keeps
`workspace_id` — the reason the column-list form of `SET NULL` exists. It needs
PostgreSQL 15+; this repo runs 16.

**Rows that already violate this cannot be converted.** Before adding the
constraints, count them — a non-zero result is a real cross-tenant reference
and a finding in its own right, not a migration inconvenience:

```sql
SELECT count(*) FROM cloud_observation o
  JOIN cloud_scan_run r ON r.id = o.scan_run_id
 WHERE r.workspace_id <> o.workspace_id;
```

This is why §2.9 is a rule rather than a one-off fix: **no single-column foreign
key to a workspace-scoped table.** Every migration from here adds its references
in the composite form, and `027` exists because three were written before the
rule was.

The graph branch's `027` also converts `cloud_observation.connector_id` and
`cloud_scan_run.connector_id` to composite references, and its pre-flight
raises if any cross-workspace reference exists. Both stay. The pre-flight is
run against production as a count **before** the release (§3 intro), so a
non-zero result is investigated rather than discovered as a failed boot.


### 028 — recognition keys, continuity, provider

The AWS projector writes `iga_identity_accounts`, `iga_resources`,
`iga_entitlements` and `iga_credentials`, which the GitHub path also writes and
lists. **`provider` separates them.** The only writer of these four tables at
`0e75ad7` is the GitHub path (`iga_service.go:863,876,886,897,1090`), so every
existing row is GitHub's.

`iga_agents` is **not** altered: this milestone writes no AWS agents (§2.2).

Written out for each table. "Repeat for the others" applies cleanly and leaves
the others without the columns.

```sql
-- iga_entitlements has no lifecycle column (004); the partial index needs one.
ALTER TABLE public.iga_entitlements
    ADD COLUMN IF NOT EXISTS lifecycle text NOT NULL DEFAULT 'active';
ALTER TABLE public.iga_entitlements
    DROP CONSTRAINT IF EXISTS iga_entitlements_lifecycle_chk,
    ADD CONSTRAINT iga_entitlements_lifecycle_chk CHECK (
        lifecycle IN ('active','retired','tombstoned'));

-- iga_identity_accounts
ALTER TABLE public.iga_identity_accounts
    ADD COLUMN IF NOT EXISTS provider       text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS source_key     text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS continuity     text NOT NULL DEFAULT 'recognition_only',
    ADD COLUMN IF NOT EXISTS immutable_key  text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS first_seen_at  timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_seen_at   timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS retired_reason text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS provider_attrs jsonb NOT NULL DEFAULT '{}'::jsonb;
UPDATE public.iga_identity_accounts SET provider = 'github' WHERE provider = '';
ALTER TABLE public.iga_identity_accounts
    DROP CONSTRAINT IF EXISTS iga_identity_accounts_continuity_chk,
    ADD CONSTRAINT iga_identity_accounts_continuity_chk CHECK (continuity IN ('immutable','recognition_only')),
    DROP CONSTRAINT IF EXISTS iga_identity_accounts_immutable_chk,
    ADD CONSTRAINT iga_identity_accounts_immutable_chk CHECK (continuity <> 'immutable' OR immutable_key <> '');
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_identity_accounts_source_key
    ON public.iga_identity_accounts (workspace_id, source_key)
    WHERE source_key <> '' AND lifecycle <> 'retired';
CREATE INDEX IF NOT EXISTS idx_iga_identity_accounts_provider
    ON public.iga_identity_accounts (workspace_id, provider, lifecycle);

-- iga_resources
ALTER TABLE public.iga_resources
    ADD COLUMN IF NOT EXISTS provider       text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS source_key     text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS continuity     text NOT NULL DEFAULT 'recognition_only',
    ADD COLUMN IF NOT EXISTS immutable_key  text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS first_seen_at  timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_seen_at   timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS retired_reason text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS provider_attrs jsonb NOT NULL DEFAULT '{}'::jsonb;
UPDATE public.iga_resources SET provider = 'github' WHERE provider = '';
ALTER TABLE public.iga_resources
    DROP CONSTRAINT IF EXISTS iga_resources_continuity_chk,
    ADD CONSTRAINT iga_resources_continuity_chk CHECK (continuity IN ('immutable','recognition_only')),
    DROP CONSTRAINT IF EXISTS iga_resources_immutable_chk,
    ADD CONSTRAINT iga_resources_immutable_chk CHECK (continuity <> 'immutable' OR immutable_key <> '');
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_resources_source_key
    ON public.iga_resources (workspace_id, source_key)
    WHERE source_key <> '' AND lifecycle <> 'retired';
CREATE INDEX IF NOT EXISTS idx_iga_resources_provider
    ON public.iga_resources (workspace_id, provider, lifecycle);

-- iga_entitlements
ALTER TABLE public.iga_entitlements
    ADD COLUMN IF NOT EXISTS provider       text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS source_key     text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS continuity     text NOT NULL DEFAULT 'recognition_only',
    ADD COLUMN IF NOT EXISTS immutable_key  text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS first_seen_at  timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_seen_at   timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS retired_reason text NOT NULL DEFAULT '';
UPDATE public.iga_entitlements SET provider = 'github' WHERE provider = '';
ALTER TABLE public.iga_entitlements
    DROP CONSTRAINT IF EXISTS iga_entitlements_continuity_chk,
    ADD CONSTRAINT iga_entitlements_continuity_chk CHECK (continuity IN ('immutable','recognition_only')),
    DROP CONSTRAINT IF EXISTS iga_entitlements_immutable_chk,
    ADD CONSTRAINT iga_entitlements_immutable_chk CHECK (continuity <> 'immutable' OR immutable_key <> '');
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_entitlements_source_key
    ON public.iga_entitlements (workspace_id, source_key)
    WHERE source_key <> '' AND lifecycle <> 'retired';

-- iga_credentials: a credential's key is "gone" when revoked or expired, not retired.
ALTER TABLE public.iga_credentials
    ADD COLUMN IF NOT EXISTS provider       text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS source_key     text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS continuity     text NOT NULL DEFAULT 'recognition_only',
    ADD COLUMN IF NOT EXISTS immutable_key  text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS first_seen_at  timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_seen_at   timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS retired_reason text NOT NULL DEFAULT '';
UPDATE public.iga_credentials SET provider = 'github' WHERE provider = '';
ALTER TABLE public.iga_credentials
    DROP CONSTRAINT IF EXISTS iga_credentials_continuity_chk,
    ADD CONSTRAINT iga_credentials_continuity_chk CHECK (continuity IN ('immutable','recognition_only')),
    DROP CONSTRAINT IF EXISTS iga_credentials_immutable_chk,
    ADD CONSTRAINT iga_credentials_immutable_chk CHECK (continuity <> 'immutable' OR immutable_key <> '');
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_credentials_source_key
    ON public.iga_credentials (workspace_id, source_key)
    WHERE source_key <> '' AND lifecycle NOT IN ('revoked','expired');

-- iga_estate_scopes: nothing populates it today; the projector does (§4.8).
ALTER TABLE public.iga_estate_scopes
    ADD COLUMN IF NOT EXISTS source_key text NOT NULL DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_estate_scopes_source_key
    ON public.iga_estate_scopes (workspace_id, source_key) WHERE source_key <> '';
```

- **`DEFAULT ''` plus a partial unique index.** GitHub rows keep
  `source_key = ''` and stay outside every unique index; the GitHub writer is
  not keyed in this milestone (§1.5), so nothing ever conflicts with them.
- **`lifecycle <> 'retired'` in the predicate** makes recreation expressible:
  the retired row keeps its key, the new row takes it, only one is live.
- **`provider` is filtered by every existing reader** of these tables
  (`ListIdentityAccounts`, the entitlement and resource joins of
  `ListAccessPaths`, `ListCredentialsFor`): `provider = 'github'`. Without that,
  AWS identities appear in the GitHub `GET /api/iga/v1/identity-accounts` list.
- **`provider_attrs`** holds display-only provider facts — tags, path,
  permissions-boundary ARN, whether the trust policy contains a Deny — so the
  read APIs never read `cloud_*`. Never used as identity, never filtered on
  except by documented list filters.

### 029 — `iga_workload`, execution-role state, classification

```sql
CREATE TABLE IF NOT EXISTS public.iga_workload (
    id              uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id    uuid NOT NULL,
    estate_scope_id uuid,
    provider        text NOT NULL DEFAULT 'aws',
    runtime_kind    text NOT NULL,
    display_name    text NOT NULL DEFAULT '',
    region          text NOT NULL DEFAULT '',
    stage           text NOT NULL DEFAULT 'unknown',
    lifecycle       text NOT NULL DEFAULT 'active',
    retired_reason  text NOT NULL DEFAULT '',
    source_key      text NOT NULL,
    continuity      text NOT NULL DEFAULT 'recognition_only',
    immutable_key   text NOT NULL DEFAULT '',
    provider_attrs  jsonb NOT NULL DEFAULT '{}'::jsonb,
    first_seen_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    -- What we know about the role the workload runs as, when there is no
    -- executes_as edge to say it. Written on every pass (§4.6).
    execution_role_state text NOT NULL DEFAULT 'none',
    execution_role_arn   text NOT NULL DEFAULT '',

    -- Human-owned; the projector writes provider_native_agent on insert only.
    classification         text   NOT NULL DEFAULT 'unclassified',
    classification_version bigint NOT NULL DEFAULT 0,

    CONSTRAINT iga_workload_pkey PRIMARY KEY (id),
    CONSTRAINT iga_workload_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_workload_scope_fkey FOREIGN KEY (workspace_id, estate_scope_id)
        REFERENCES public.iga_estate_scopes (workspace_id, id) ON DELETE SET NULL (estate_scope_id),
    CONSTRAINT iga_workload_stage_chk CHECK (stage IN ('production','non_production','unknown')),
    CONSTRAINT iga_workload_lifecycle_chk CHECK (lifecycle IN ('active','retired','tombstoned')),
    CONSTRAINT iga_workload_retired_chk CHECK ((lifecycle = 'retired') = (retired_reason <> '')),
    CONSTRAINT iga_workload_continuity_chk CHECK (continuity IN ('immutable','recognition_only')),
    CONSTRAINT iga_workload_immutable_chk CHECK (continuity <> 'immutable' OR immutable_key <> ''),
    CONSTRAINT iga_workload_source_key_chk CHECK (source_key <> ''),
    CONSTRAINT iga_workload_exec_role_state_chk CHECK (execution_role_state IN
        ('resolved','not_in_scan','not_in_inventory','none')),
    CONSTRAINT iga_workload_exec_role_arn_chk CHECK (
        (execution_role_state IN ('not_in_scan','not_in_inventory')) = (execution_role_arn <> '')),
    CONSTRAINT iga_workload_classification_chk CHECK (
        classification IN ('unclassified','provider_native_agent','classified_agent')),
    CONSTRAINT iga_workload_workspace_id_key UNIQUE (workspace_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_workload_source_key
    ON public.iga_workload (workspace_id, source_key) WHERE lifecycle <> 'retired';
-- Default list order (§5.3) and the classification filter.
CREATE INDEX IF NOT EXISTS idx_iga_workload_list
    ON public.iga_workload (workspace_id, lifecycle, lower(display_name), id);
CREATE INDEX IF NOT EXISTS idx_iga_workload_classification
    ON public.iga_workload (workspace_id, classification, lower(display_name), id);

-- The decision record. Human decisions are never rows the projector writes.
CREATE TABLE IF NOT EXISTS public.iga_workload_classification (
    id                    uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id          uuid NOT NULL,
    workload_id           uuid NOT NULL,
    operation_id          uuid NOT NULL,   -- client-generated, one per intent (§5.5)
    decision              text NOT NULL,   -- classified_agent | unclassified
    previous              text NOT NULL,
    purpose               text NOT NULL DEFAULT '',
    reason                text NOT NULL,
    decided_by_user_id    uuid NOT NULL,   -- stable identity; never an email
    against_version       bigint NOT NULL, -- the classification_version it was made against
    request_hash          text NOT NULL,   -- sha256(workload, actor, decision, purpose, reason, expected_version, undoes)
    result_version        bigint NOT NULL,
    undoes_decision_id    uuid,
    decided_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_workload_classification_pkey PRIMARY KEY (id),
    CONSTRAINT iga_wc_workload_fkey FOREIGN KEY (workspace_id, workload_id)
        REFERENCES public.iga_workload (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_wc_decision_chk CHECK (decision IN ('classified_agent','unclassified')),
    CONSTRAINT iga_wc_reason_chk CHECK (reason <> ''),
    CONSTRAINT iga_wc_operation_key UNIQUE (workspace_id, operation_id),
    CONSTRAINT iga_wc_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT iga_wc_undoes_fkey FOREIGN KEY (workspace_id, undoes_decision_id)
        REFERENCES public.iga_workload_classification (workspace_id, id)
);
CREATE INDEX IF NOT EXISTS idx_iga_wc_workload
    ON public.iga_workload_classification (workspace_id, workload_id, decided_at DESC);

-- One counter per workspace, bumped in every decision transaction. List
-- cursors that filter or sort on classification bind to it (§5.5).
CREATE TABLE IF NOT EXISTS public.iga_classification_clock (
    workspace_id uuid NOT NULL,
    seq          bigint NOT NULL DEFAULT 0,
    CONSTRAINT iga_classification_clock_pkey PRIMARY KEY (workspace_id),
    CONSTRAINT iga_classification_clock_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE
);
```

`region` is the workload's **collected** region (`cloud_workload.region`), not
parsed from the ARN — EC2 instance ids carry none.

### 030 — `iga_access_edges`: typed subject, lifecycle — expand only

```sql
ALTER TABLE public.iga_access_edges
    ADD COLUMN IF NOT EXISTS subject_identity_account_id uuid,
    ADD COLUMN IF NOT EXISTS provider          text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS basis             text NOT NULL DEFAULT 'declared',
    ADD COLUMN IF NOT EXISTS derivation_rule   text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS state             text NOT NULL DEFAULT 'current',
    ADD COLUMN IF NOT EXISTS valid_from        timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS valid_to          timestamptz,
    ADD COLUMN IF NOT EXISTS last_confirmed_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_confirmed_by uuid,
    ADD COLUMN IF NOT EXISTS ended_reason      text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS source_key        text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS partition_key     text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS connector_id      uuid;

-- The only writer ever set subject_kind = 'identity_account' (iga_service.go:918).
UPDATE public.iga_access_edges
   SET subject_identity_account_id = subject_id, provider = 'github'
 WHERE subject_kind = 'identity_account' AND subject_identity_account_id IS NULL;

ALTER TABLE public.iga_access_edges
    ADD CONSTRAINT iga_access_edges_subject_identity_fkey
        FOREIGN KEY (workspace_id, subject_identity_account_id)
        REFERENCES public.iga_identity_accounts (workspace_id, id) ON DELETE CASCADE,
    ADD CONSTRAINT iga_access_edges_connector_fkey
        FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE SET NULL (connector_id),
    ADD CONSTRAINT iga_access_edges_run_fkey
        FOREIGN KEY (workspace_id, last_confirmed_by)
        REFERENCES public.cloud_scan_run (workspace_id, id) ON DELETE SET NULL (last_confirmed_by),
    -- The typed column and the legacy pair agree whenever both are set.
    ADD CONSTRAINT iga_access_edges_subject_agree_chk CHECK (
        subject_identity_account_id IS NULL
        OR (subject_kind = 'identity_account' AND subject_id = subject_identity_account_id)),
    ADD CONSTRAINT iga_access_edges_basis_chk CHECK (basis IN ('declared','observed','derived','asserted')),
    ADD CONSTRAINT iga_access_edges_derivation_chk CHECK (basis <> 'derived' OR derivation_rule <> ''),
    ADD CONSTRAINT iga_access_edges_state_chk CHECK (state IN ('current','stale','ended')),
    ADD CONSTRAINT iga_access_edges_ended_chk CHECK ((state = 'ended') = (valid_to IS NOT NULL)),
    ADD CONSTRAINT iga_access_edges_ended_reason_chk CHECK ((state = 'ended') = (ended_reason <> ''));

CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_access_edges_live
    ON public.iga_access_edges (workspace_id, source_key)
    WHERE source_key <> '' AND state <> 'ended';
CREATE INDEX IF NOT EXISTS idx_iga_access_edges_subject_identity
    ON public.iga_access_edges (workspace_id, subject_identity_account_id)
    WHERE subject_identity_account_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_iga_access_edges_partition
    ON public.iga_access_edges (workspace_id, connector_id, partition_key)
    WHERE state <> 'ended';
```

- **Nothing is dropped and nothing is deleted.** The graph branch's `030`
  dropped `subject_kind`/`subject_id` and deleted untypeable rows, which breaks
  the `0e75ad7` binary's GitHub writer and `GET /api/iga/v1/agents/:id/access-paths`
  on rollback. Every writer — GitHub and AWS — sets the typed column **and**
  the legacy pair until `037`.
- `entitlement_id` stays nullable here; `036`'s check requires it for AWS rows.
- **`iga_access_edges_honesty_chk` from `004` survives**; the migration test
  asserts it.
- No `subject_workload_id`: a workload holds nothing, it runs as an identity
  that does.

### 031 — `iga_relationship`

```sql
CREATE TABLE IF NOT EXISTS public.iga_relationship (
    id                uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id      uuid NOT NULL,
    relationship_type text NOT NULL,

    source_identity_account_id uuid,
    source_workload_id         uuid,
    -- source_external_principal_id: added by 034 (its table does not exist yet).

    target_identity_account_id uuid,

    basis             text NOT NULL DEFAULT 'declared',
    derivation_rule   text NOT NULL DEFAULT '',
    state             text NOT NULL DEFAULT 'current',
    valid_from        timestamptz NOT NULL DEFAULT now(),
    valid_to          timestamptz,
    last_confirmed_at timestamptz NOT NULL DEFAULT now(),
    last_confirmed_by uuid,
    ended_reason      text NOT NULL DEFAULT '',
    source_key        text NOT NULL,
    partition_key     text NOT NULL DEFAULT '',
    connector_id      uuid,

    -- can_assume only: the trust statement that declared it, verbatim facts.
    statement_key     text  NOT NULL DEFAULT '',
    conditions        jsonb,          -- NULL = the statement had no Condition
    mechanism         text  NOT NULL DEFAULT '',  -- sts_assume_role | oidc_federation | saml_federation | eks_pod_identity

    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT iga_relationship_pkey PRIMARY KEY (id),
    CONSTRAINT iga_relationship_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_relationship_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT iga_relationship_connector_fkey FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE SET NULL (connector_id),
    CONSTRAINT iga_rel_src_identity_fkey FOREIGN KEY (workspace_id, source_identity_account_id)
        REFERENCES public.iga_identity_accounts (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_rel_src_workload_fkey FOREIGN KEY (workspace_id, source_workload_id)
        REFERENCES public.iga_workload (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_rel_tgt_identity_fkey FOREIGN KEY (workspace_id, target_identity_account_id)
        REFERENCES public.iga_identity_accounts (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_relationship_run_fkey FOREIGN KEY (workspace_id, last_confirmed_by)
        REFERENCES public.cloud_scan_run (workspace_id, id) ON DELETE SET NULL (last_confirmed_by),

    CONSTRAINT iga_relationship_source_chk CHECK (
        (source_identity_account_id IS NOT NULL)::int
      + (source_workload_id         IS NOT NULL)::int = 1),
    CONSTRAINT iga_relationship_target_chk CHECK (target_identity_account_id IS NOT NULL),

    -- The legal (source, type, target) triples. ELSE false is load-bearing.
    CONSTRAINT iga_relationship_pair_chk CHECK (
        CASE relationship_type
            WHEN 'executes_as'         THEN source_workload_id IS NOT NULL
            WHEN 'task_execution_role' THEN source_workload_id IS NOT NULL
            WHEN 'member_of'           THEN source_identity_account_id IS NOT NULL
            WHEN 'can_assume'          THEN source_identity_account_id IS NOT NULL
            ELSE false
        END),

    CONSTRAINT iga_relationship_basis_chk CHECK (basis IN ('declared','observed','derived','asserted')),
    CONSTRAINT iga_relationship_derivation_chk CHECK (basis <> 'derived' OR derivation_rule <> ''),
    CONSTRAINT iga_relationship_state_chk CHECK (state IN ('current','stale','ended')),
    CONSTRAINT iga_relationship_ended_chk CHECK ((state = 'ended') = (valid_to IS NOT NULL)),
    CONSTRAINT iga_relationship_ended_reason_chk CHECK ((state = 'ended') = (ended_reason <> '')),
    CONSTRAINT iga_relationship_source_key_chk CHECK (source_key <> ''),
    CONSTRAINT iga_relationship_trust_chk CHECK (
        (relationship_type = 'can_assume') = (mechanism <> ''))
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_relationship_live
    ON public.iga_relationship (workspace_id, source_key) WHERE state <> 'ended';
CREATE INDEX IF NOT EXISTS idx_iga_relationship_source
    ON public.iga_relationship (workspace_id, relationship_type,
        COALESCE(source_identity_account_id, source_workload_id));
CREATE INDEX IF NOT EXISTS idx_iga_relationship_target
    ON public.iga_relationship (workspace_id, relationship_type, target_identity_account_id);
CREATE INDEX IF NOT EXISTS idx_iga_relationship_partition
    ON public.iga_relationship (workspace_id, connector_id, partition_key) WHERE state <> 'ended';
```

Every relationship in this milestone targets an identity account, so the
target is one column. A future type with another target adds a column and
widens the checks, deliberately.

### 032 — evidence junctions and object support

**Object support first**: the evidence junctions and every node
reconciliation path depend on it, and §2.10B explains why a shared node
cannot carry a single owning connector.

```sql
CREATE TABLE IF NOT EXISTS public.iga_object_support (
    id            uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id  uuid NOT NULL,
    -- TYPED, not (object_type, object_id).
    --
    -- A text kind beside a bare uuid is not a foreign key -- it is the exact
    -- A3 pattern §2.9 exists to eliminate, and putting it back here would let
    -- a support row in workspace A claim to support workspace B's object, or
    -- an object that no longer exists. The endpoint set is small and fixed,
    -- so the same nullable-typed-columns pattern used everywhere else applies.
    identity_account_id uuid,
    workload_id         uuid,
    resource_id         uuid,
    entitlement_id      uuid,

    connector_id  uuid NOT NULL,
    partition_key text NOT NULL,

    state         text NOT NULL DEFAULT 'current',  -- current|stale|ended
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_confirmed_run_id uuid,
    last_confirmed_at     timestamptz,
    ended_reason  text NOT NULL DEFAULT '',

    CONSTRAINT iga_object_support_pkey PRIMARY KEY (id),
    CONSTRAINT iga_object_support_connector_fkey
        FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE CASCADE,

    CONSTRAINT iga_os_identity_fkey FOREIGN KEY (workspace_id, identity_account_id)
        REFERENCES public.iga_identity_accounts (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_os_workload_fkey FOREIGN KEY (workspace_id, workload_id)
        REFERENCES public.iga_workload (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_os_resource_fkey FOREIGN KEY (workspace_id, resource_id)
        REFERENCES public.iga_resources (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_os_entitlement_fkey FOREIGN KEY (workspace_id, entitlement_id)
        REFERENCES public.iga_entitlements (workspace_id, id) ON DELETE CASCADE,

    -- The confirming run is workspace-qualified too (§2.9).
    CONSTRAINT iga_os_run_fkey FOREIGN KEY (workspace_id, last_confirmed_run_id)
        REFERENCES public.cloud_scan_run (workspace_id, id)
        ON DELETE SET NULL (last_confirmed_run_id),

    CONSTRAINT iga_object_support_one_chk CHECK (
        (identity_account_id IS NOT NULL)::int + (workload_id    IS NOT NULL)::int
      + (resource_id         IS NOT NULL)::int + (entitlement_id IS NOT NULL)::int = 1),
    CONSTRAINT iga_object_support_state_chk CHECK (state IN ('current','stale','ended')),
    CONSTRAINT iga_object_support_ended_chk CHECK ((state = 'ended') = (ended_reason <> ''))
);
```

```sql
-- One live support row per (object, connector, partition), per type. Partial
-- indexes rather than one composite key, because the discriminating column
-- differs per type.
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_os_identity
    ON public.iga_object_support (workspace_id, identity_account_id, connector_id, partition_key)
    WHERE identity_account_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_os_workload
    ON public.iga_object_support (workspace_id, workload_id, connector_id, partition_key)
    WHERE workload_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_os_resource
    ON public.iga_object_support (workspace_id, resource_id, connector_id, partition_key)
    WHERE resource_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_os_entitlement
    ON public.iga_object_support (workspace_id, entitlement_id, connector_id, partition_key)
    WHERE entitlement_id IS NOT NULL;
```

These indexes are the conflict targets for every support upsert, so they
ship **with** the table, in the same migration as the table they index.

Then the evidence junctions.

```sql
CREATE TABLE IF NOT EXISTS public.iga_access_edge_evidence (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL,
    access_edge_id uuid NOT NULL,
    observation_id uuid NOT NULL,
    relation       text NOT NULL DEFAULT 'supports',
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_access_edge_evidence_pkey PRIMARY KEY (id),
    CONSTRAINT iga_access_edge_evidence_edge_fkey
        FOREIGN KEY (workspace_id, access_edge_id)
        REFERENCES public.iga_access_edges (workspace_id, id) ON DELETE CASCADE,
    -- RESTRICT is now safe: 024 stopped inventory deletion from cascading into
    -- cloud_observation, so this can no longer block reconciliation. Before
    -- 024 this same constraint deadlocked it.
    CONSTRAINT iga_access_edge_evidence_obs_fkey
        FOREIGN KEY (workspace_id, observation_id)
        REFERENCES public.cloud_observation (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT iga_access_edge_evidence_relation_chk CHECK (
        relation IN ('supports','contradicts','supersedes','previously_supported')),
    CONSTRAINT iga_access_edge_evidence_key
        UNIQUE (workspace_id, access_edge_id, observation_id, relation)
);
```

```sql
-- The same shape against iga_relationship. Written out rather than described
-- as "the same table again": a migration author cannot apply prose, and the
-- FK target and cascade differ.
CREATE TABLE IF NOT EXISTS public.iga_relationship_evidence (
    id              uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id    uuid NOT NULL,
    relationship_id uuid NOT NULL,
    observation_id  uuid NOT NULL,
    relation        text NOT NULL DEFAULT 'supports',
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_relationship_evidence_pkey PRIMARY KEY (id),
    CONSTRAINT iga_relationship_evidence_rel_fkey
        FOREIGN KEY (workspace_id, relationship_id)
        REFERENCES public.iga_relationship (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_relationship_evidence_obs_fkey
        FOREIGN KEY (workspace_id, observation_id)
        REFERENCES public.cloud_observation (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT iga_relationship_evidence_relation_chk CHECK (
        relation IN ('supports','contradicts','supersedes','previously_supported')),
    CONSTRAINT iga_relationship_evidence_key
        UNIQUE (workspace_id, relationship_id, observation_id, relation)
);
```

Both junctions have typed, workspace-qualified endpoints on both sides.
`iga_observation_links` keeps its polymorphic `target_kind`/`target_id` for the
GitHub path; the CI isolation check (`scripts/ci-iga-isolation-check.sh`) forbids new writers to it.

`036` adds `policy_id` to support and widens the exactly-one check.


### 033 — projection job, projection state, publication

```sql
-- Mirrors cloud_scan_run's lease pattern. Enqueued in the SAME transaction as
-- Publish(), because the scan lease is released there (§2.8) and a job that is
-- not enqueued atomically can be lost to a crash.
CREATE TABLE IF NOT EXISTS public.iga_projection_job (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL,
    scan_run_id    uuid NOT NULL,
    connector_id   uuid NOT NULL,
    generation     integer NOT NULL,
    status         text NOT NULL DEFAULT 'queued',
    lease_owner    text NOT NULL DEFAULT '',
    lease_expires_at timestamptz,
    lease_version  bigint NOT NULL DEFAULT 0,
    attempts       integer NOT NULL DEFAULT 0,
    last_error     text NOT NULL DEFAULT '',
    requested_at   timestamptz NOT NULL DEFAULT now(),
    completed_at   timestamptz,
    CONSTRAINT iga_projection_job_pkey PRIMARY KEY (id),
    CONSTRAINT iga_projection_job_run_fkey FOREIGN KEY (workspace_id, scan_run_id)
        REFERENCES public.cloud_scan_run (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_projection_job_status_chk CHECK (
        status IN ('queued','running','complete','failed','abandoned')),
    CONSTRAINT iga_projection_job_generation_chk CHECK (generation > 0),
    CONSTRAINT iga_projection_job_run_key UNIQUE (scan_run_id)
);

CREATE INDEX IF NOT EXISTS idx_iga_projection_job_claimable
    ON public.iga_projection_job (status, lease_expires_at, requested_at)
    WHERE status IN ('queued','running');

CREATE TABLE IF NOT EXISTS public.iga_projection_state (
    id                uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id      uuid NOT NULL,
    estate_scope_id   uuid NOT NULL,
    connector_id      uuid NOT NULL,
    object_class      text NOT NULL DEFAULT '',
    relationship_type text NOT NULL DEFAULT '',
    -- The partition's full identity (Partition.Key()): scope, connector,
    -- class, relationship type, target and required surfaces.
    --
    -- Keying on (scope, class, relationship_type) alone merges partitions that
    -- must stay separate -- roles with users, every region's Lambda with every
    -- other's -- and one partition's watermark then overwrites another's,
    -- which licenses closing relationships nothing in this run looked at.
    partition_key     text NOT NULL,
    last_run_id       uuid NOT NULL,
    last_generation   bigint NOT NULL,
    coverage_state    text NOT NULL,
    reconciled        boolean NOT NULL DEFAULT false,
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_projection_state_pkey PRIMARY KEY (id),
    CONSTRAINT iga_projection_state_scope_fkey
        FOREIGN KEY (workspace_id, estate_scope_id)
        REFERENCES public.iga_estate_scopes (workspace_id, id) ON DELETE CASCADE,
    -- §2.9: workspace-qualified, not a bare FK to cloud_scan_run(id).
    CONSTRAINT iga_projection_state_run_fkey FOREIGN KEY (workspace_id, last_run_id)
        REFERENCES public.cloud_scan_run (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_projection_state_generation_chk CHECK (last_generation >= 0),
    -- (workspace_id, connector_id), never connector_id alone: a bare FK
    -- lets a row in workspace A reference workspace B's integration, which
    -- is the §2.9 defect this phase exists to close. 027 adds the
    -- UNIQUE (workspace_id, id) on cloud_connector that this needs.
    CONSTRAINT iga_projection_state_connector_fkey
        FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_projection_state_key
        UNIQUE (workspace_id, connector_id, partition_key)
);
```

`reconciled = false` against a complete coverage state signals a pass
interrupted between projection and reconciliation; the next job re-reconciles
that partition rather than assuming it settled.

No agent or agent-instance columns are added: this milestone writes neither for AWS (§2.2).

#### Publication revisions (§5.1)

```sql
-- One row per projection commit.
CREATE TABLE IF NOT EXISTS public.iga_publication (
    workspace_id  uuid   NOT NULL,
    rev           bigint NOT NULL,       -- per-workspace, monotonic, no gaps
    published_at  timestamptz NOT NULL,
    scan_run_id   uuid   NOT NULL,       -- the run whose projection this was
    -- The manifest: every partition's watermark AS OF this revision, so a
    -- reader can see exactly which run each part of the graph came from.
    manifest      jsonb  NOT NULL,       -- {partition_key: run_id, ...}
    CONSTRAINT iga_publication_pkey PRIMARY KEY (workspace_id, rev),
    -- One publication per run, ever. This is what lets a replayed job
    -- recognise "I already committed" (§4.6 step 2) instead of republishing.
    CONSTRAINT iga_publication_run_key UNIQUE (workspace_id, scan_run_id),
    CONSTRAINT iga_publication_run_fkey FOREIGN KEY (workspace_id, scan_run_id)
        REFERENCES public.cloud_scan_run (workspace_id, id) ON DELETE RESTRICT
);
```


### 034 — external principals

The node for a far endpoint we may never resolve (§2.12).

```sql
CREATE TABLE IF NOT EXISTS public.iga_external_principal (
    id            uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id  uuid NOT NULL,
    issuer        text NOT NULL,   -- token.actions.githubusercontent.com
    subject_claim text NOT NULL,   -- repo:org/repo:ref:refs/heads/main
    mechanism     text NOT NULL,   -- aws_account | aws_principal | aws_service | oidc | saml | k8s_service_account
    source_key    text NOT NULL,

    -- Filled when the far provider connects AND the claim resolves to exactly
    -- one object. Nullable forever otherwise, which is an honest state.
    --
    -- TYPED, for the same reason iga_object_support is: a text kind beside a
    -- bare uuid would let a principal in workspace A "resolve" to workspace
    -- B's identity, or to an id that no longer exists. A trust policy names
    -- an identity or a workload -- nothing else can be assumed -- so two
    -- typed columns cover the domain.
    resolved_identity_account_id uuid,
    resolved_workload_id         uuid,
    resolution_basis     text NOT NULL DEFAULT '',   -- derived | asserted
    resolution_rule      text NOT NULL DEFAULT '',
    -- Who asserted it, when basis = 'asserted'. A resolution a human made
    -- must be explicable and reversible.
    resolved_by          text NOT NULL DEFAULT '',
    -- Whether the resolution currently APPLIES. Separate from whether it
    -- exists: a human's decision is preserved when its target is retired,
    -- but it stops being in force until someone reconfirms it.
    resolution_state     text NOT NULL DEFAULT 'active',

    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_external_principal_pkey PRIMARY KEY (id),
    CONSTRAINT iga_external_principal_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_external_principal_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT iga_ep_resolved_identity_fkey
        FOREIGN KEY (workspace_id, resolved_identity_account_id)
        REFERENCES public.iga_identity_accounts (workspace_id, id)
        ON DELETE SET NULL (resolved_identity_account_id),
    CONSTRAINT iga_ep_resolved_workload_fkey
        FOREIGN KEY (workspace_id, resolved_workload_id)
        REFERENCES public.iga_workload (workspace_id, id)
        ON DELETE SET NULL (resolved_workload_id),
    -- At most one target, and a basis exactly when there is a target.
    CONSTRAINT iga_external_principal_resolution_chk CHECK (
        (resolved_identity_account_id IS NOT NULL)::int
      + (resolved_workload_id         IS NOT NULL)::int <= 1
        AND ((resolved_identity_account_id IS NULL AND resolved_workload_id IS NULL)
             = (resolution_basis = ''))),
    CONSTRAINT iga_external_principal_asserted_chk CHECK (
        resolution_basis <> 'asserted' OR resolved_by <> ''),
    CONSTRAINT iga_external_principal_state_chk CHECK (
        resolution_state IN ('active', 'suspended', 'pending_reconfirmation')),
    CONSTRAINT iga_external_principal_derived_chk CHECK (
        resolution_basis <> 'derived' OR resolution_rule <> '')
);

-- Deleting a resolved target cannot leave "resolved" with no target:
-- SET NULL would violate the CHECK above. So a target is never hard-deleted
-- while resolved -- nodes are RETIRED, not deleted (§2.7). Retirement does NOT
-- clear the resolution: it SUSPENDS it (resolution_state below), keeping the
-- FK pointed at the retired row so the decision stays explicable. The FK is
-- the backstop, not the mechanism.
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_external_principal_key
    ON public.iga_external_principal (workspace_id, source_key);
```

The table in §2.12, and then — because 031 could not forward-reference it —
the three `ALTER`s that wire it in:

```sql
ALTER TABLE public.iga_relationship
    ADD COLUMN IF NOT EXISTS source_external_principal_id uuid,
    ADD CONSTRAINT iga_rel_src_external_fkey
        FOREIGN KEY (workspace_id, source_external_principal_id)
        REFERENCES public.iga_external_principal (workspace_id, id) ON DELETE CASCADE,

    DROP CONSTRAINT iga_relationship_source_chk,
    ADD CONSTRAINT iga_relationship_source_chk CHECK (
        (source_identity_account_id   IS NOT NULL)::int
      + (source_workload_id           IS NOT NULL)::int
      + (source_external_principal_id IS NOT NULL)::int = 1),

    DROP CONSTRAINT iga_relationship_pair_chk,
    ADD CONSTRAINT iga_relationship_pair_chk CHECK (
        CASE relationship_type
            WHEN 'executes_as'         THEN source_workload_id IS NOT NULL
            WHEN 'task_execution_role' THEN source_workload_id IS NOT NULL
            WHEN 'member_of'           THEN source_identity_account_id IS NOT NULL
            WHEN 'can_assume'          THEN source_identity_account_id IS NOT NULL
                                         OR source_external_principal_id IS NOT NULL
            ELSE false
        END);
CREATE INDEX IF NOT EXISTS idx_iga_relationship_source_external
    ON public.iga_relationship (workspace_id, source_external_principal_id)
    WHERE source_external_principal_id IS NOT NULL;
```

**`034` is part of the core rollout, not an optional extra.** Core
reconciliation writes this table — `retireUnsupported` suspends asserted
resolutions and re-derives derived ones — and the projector's recreation and
restoration branches call `SuspendAssertions` and
`MarkAssertionsPendingReconfirm`. With `027`–`033` applied and `034` not, the
reconciler fails with `relation "iga_external_principal" does not exist` on
**every** run: the error is raised at plan time, so it fires even when no row
could match. (Verified by applying exactly that intermediate state.)

The table is populated in this milestone: the projector creates an external
principal for every trust-policy principal that is not an identity in the
workspace, and for every EKS pod-identity association (§4.7). An exact ARN
match to an identity in another connected account is a `derived` resolution
with its rule recorded; wildcards stay unresolved and visible.


### 035 — AWS collection model

Phase 1 collection gains what §1.4 requires. These are `cloud_*` tables:
authoritative, per connector, written by the scanners under the run fence.

**Every reference is workspace- and integration-qualified.** These rows are
facts one integration collected about its own account, so a membership, an
inline policy's holder and an attachment's principal and policy must all belong
to **the same workspace and the same integration** as the row. A foreign key to
`cloud_identity (id)` alone admits another workspace's identity (§2.9); the
composite keys below make the database refuse it.

```sql
-- Targets for integration-qualified references. id is already the primary
-- key, so both are always satisfiable.
ALTER TABLE public.cloud_identity
    ADD CONSTRAINT cloud_identity_scope_key UNIQUE (workspace_id, connector_id, id);

-- Groups are identities: kind 'iam_group' (cloud_identity_kind_chk only
-- requires kind <> '', so no constraint change).

-- The role's trust document, verbatim, so the projector parses Allow AND Deny
-- statements with their conditions. trust_parse_error is non-empty when the
-- document could not be parsed: that role's trust edges go stale (§4.10).
ALTER TABLE public.cloud_identity
    ADD COLUMN IF NOT EXISTS trust_document jsonb,
    ADD COLUMN IF NOT EXISTS trust_document_hash text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS trust_parse_error  text NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS public.cloud_group_membership (
    id                   uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id         uuid NOT NULL,
    connector_id         uuid NOT NULL,
    user_identity_id     uuid NOT NULL,
    group_identity_id    uuid NOT NULL,
    last_seen_generation integer NOT NULL,
    first_seen_at        timestamptz NOT NULL DEFAULT now(),
    last_seen_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT cloud_group_membership_pkey PRIMARY KEY (id),
    CONSTRAINT cloud_gm_connector_fkey FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT cloud_gm_user_fkey FOREIGN KEY (workspace_id, connector_id, user_identity_id)
        REFERENCES public.cloud_identity (workspace_id, connector_id, id) ON DELETE CASCADE,
    CONSTRAINT cloud_gm_group_fkey FOREIGN KEY (workspace_id, connector_id, group_identity_id)
        REFERENCES public.cloud_identity (workspace_id, connector_id, id) ON DELETE CASCADE,
    CONSTRAINT cloud_gm_key UNIQUE (user_identity_id, group_identity_id)
);

-- A policy AS READ BY ONE CONNECTOR. Keyed per connector, unlike
-- cloud_resource: an AWS-managed policy attached in two accounts is two rows
-- here and ONE iga_policy, and no scanner ever reassigns another's row.
CREATE TABLE IF NOT EXISTS public.cloud_policy (
    id                   uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id         uuid NOT NULL,
    connector_id         uuid NOT NULL,
    policy_kind          text NOT NULL,     -- managed | inline
    native_id            text NOT NULL,     -- managed: ARN; inline: 'inline:' || holder ARN || ':' || name
    holder_identity_id   uuid,              -- inline only
    name                 text NOT NULL,
    policy_id            text NOT NULL DEFAULT '',  -- AWS PolicyId (ANPA…), managed only
    aws_managed          boolean NOT NULL DEFAULT false,
    version_id           text NOT NULL DEFAULT '',  -- default version, managed only
    document             jsonb,             -- NULL when the document could not be fetched
    document_hash        text NOT NULL DEFAULT '',
    -- Non-empty when the document is UNREADABLE this run: it could not be
    -- fetched ("fetch: AccessDenied") or did not parse ("parse: …"). Such a
    -- policy's statements, grants and the resources only it names go stale,
    -- never ended (§4.10).
    document_error       text NOT NULL DEFAULT '',
    last_seen_generation integer NOT NULL,
    first_seen_at        timestamptz NOT NULL DEFAULT now(),
    last_seen_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT cloud_policy_pkey PRIMARY KEY (id),
    CONSTRAINT cloud_policy_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT cloud_policy_scope_key UNIQUE (workspace_id, connector_id, id),
    CONSTRAINT cloud_policy_connector_fkey FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT cloud_policy_holder_fkey FOREIGN KEY (workspace_id, connector_id, holder_identity_id)
        REFERENCES public.cloud_identity (workspace_id, connector_id, id) ON DELETE CASCADE,
    CONSTRAINT cloud_policy_kind_chk CHECK (policy_kind IN ('managed','inline')),
    CONSTRAINT cloud_policy_inline_chk CHECK ((policy_kind = 'inline') = (holder_identity_id IS NOT NULL)),
    CONSTRAINT cloud_policy_readable_chk CHECK (document IS NOT NULL OR document_error <> ''),
    CONSTRAINT cloud_policy_key UNIQUE (connector_id, native_id)
);

CREATE TABLE IF NOT EXISTS public.cloud_policy_attachment (
    id                    uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id          uuid NOT NULL,
    connector_id          uuid NOT NULL,
    policy_row_id         uuid NOT NULL,
    principal_identity_id uuid NOT NULL,   -- role, user or group
    attachment_kind       text NOT NULL,   -- attached | inline | boundary
    last_seen_generation  integer NOT NULL,
    first_seen_at         timestamptz NOT NULL DEFAULT now(),
    last_seen_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT cloud_policy_attachment_pkey PRIMARY KEY (id),
    CONSTRAINT cloud_pa_connector_fkey FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE CASCADE,
    -- Same workspace AND same integration: an attachment is one account's fact
    -- about its own policy and its own principal.
    CONSTRAINT cloud_pa_policy_fkey FOREIGN KEY (workspace_id, connector_id, policy_row_id)
        REFERENCES public.cloud_policy (workspace_id, connector_id, id) ON DELETE CASCADE,
    CONSTRAINT cloud_pa_principal_fkey FOREIGN KEY (workspace_id, connector_id, principal_identity_id)
        REFERENCES public.cloud_identity (workspace_id, connector_id, id) ON DELETE CASCADE,
    CONSTRAINT cloud_pa_kind_chk CHECK (attachment_kind IN ('attached','inline','boundary')),
    CONSTRAINT cloud_pa_key UNIQUE (policy_row_id, principal_identity_id, attachment_kind)
);

-- Policy versions as evidence subjects, integration-qualified like the rest.
-- Widening the subject columns means widening the at-most-one check AND both
-- dedupe indexes, or a policy observation dedupes against the wrong key.
ALTER TABLE public.cloud_observation
    ADD COLUMN IF NOT EXISTS policy_id uuid,
    ADD CONSTRAINT cloud_observation_policy_fkey FOREIGN KEY (workspace_id, connector_id, policy_id)
        REFERENCES public.cloud_policy (workspace_id, connector_id, id) ON DELETE SET NULL (policy_id);
ALTER TABLE public.cloud_observation DROP CONSTRAINT IF EXISTS cloud_observation_subject_chk;
ALTER TABLE public.cloud_observation ADD CONSTRAINT cloud_observation_subject_chk CHECK (
      (identity_id IS NOT NULL)::int + (permission_id IS NOT NULL)::int
    + (resource_id IS NOT NULL)::int + (workload_id IS NOT NULL)::int
    + (policy_id   IS NOT NULL)::int <= 1);
DROP INDEX IF EXISTS public.uq_cloud_observation_dedupe;
CREATE UNIQUE INDEX uq_cloud_observation_dedupe ON public.cloud_observation (
    workspace_id, COALESCE(identity_id, permission_id, resource_id, workload_id, policy_id),
    source_api, content_hash);
DROP INDEX IF EXISTS public.uq_cloud_observation_dedupe_no_subject;
CREATE UNIQUE INDEX uq_cloud_observation_dedupe_no_subject
    ON public.cloud_observation (workspace_id, source_api, content_hash)
    WHERE identity_id IS NULL AND permission_id IS NULL AND resource_id IS NULL
      AND workload_id IS NULL AND policy_id IS NULL;

-- A refused claim is re-queued with a fresh requested_at (§2.10A). The
-- oldest-first claim is already indexed by 020's idx_cloud_scan_run_claimable.
```

The observation writer's `ON CONFLICT` target (`services/cloud_observation_writer.go:248-254`)
is updated in the same commit to name `policy_id` in the `COALESCE`; a
mismatch fails every write at runtime, which the rehearsal catches.

`cloud_permission` keeps being written, from the same parse, for Cloud
Inventory. The projector does not read it.

### 036 — the IGA permission model

```sql
CREATE TABLE IF NOT EXISTS public.iga_policy (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL,
    provider       text NOT NULL,
    policy_kind    text NOT NULL,     -- aws_managed | customer_managed | inline
    display_name   text NOT NULL,
    native_ref     text NOT NULL DEFAULT '',  -- ARN for managed
    source_key     text NOT NULL,
    continuity     text NOT NULL,
    immutable_key  text NOT NULL DEFAULT '',  -- PolicyId
    version_id     text NOT NULL DEFAULT '',
    document_hash  text NOT NULL DEFAULT '',
    lifecycle      text NOT NULL DEFAULT 'active',
    retired_reason text NOT NULL DEFAULT '',
    first_seen_at  timestamptz NOT NULL DEFAULT now(),
    last_seen_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_policy_pkey PRIMARY KEY (id),
    CONSTRAINT iga_policy_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_policy_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT iga_policy_kind_chk CHECK (policy_kind IN ('aws_managed','customer_managed','inline')),
    CONSTRAINT iga_policy_continuity_chk CHECK (continuity IN ('immutable','recognition_only')),
    CONSTRAINT iga_policy_immutable_chk CHECK (continuity <> 'immutable' OR immutable_key <> ''),
    CONSTRAINT iga_policy_lifecycle_chk CHECK (lifecycle IN ('active','retired')),
    CONSTRAINT iga_policy_retired_chk CHECK ((lifecycle = 'retired') = (retired_reason <> ''))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_policy_source_key
    ON public.iga_policy (workspace_id, source_key) WHERE lifecycle <> 'retired';

-- A statement is an entitlement row. Existing GitHub entitlements have
-- provider = 'github' and leave every column below at its default.
ALTER TABLE public.iga_entitlements
    ADD COLUMN IF NOT EXISTS policy_id       uuid,
    ADD COLUMN IF NOT EXISTS statement_key   text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS sid             text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS statement_index integer,
    ADD COLUMN IF NOT EXISTS effect          text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS content_hash    text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS negated         boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS conditional     boolean NOT NULL DEFAULT false;
ALTER TABLE public.iga_entitlements
    ADD CONSTRAINT iga_entitlements_policy_fkey FOREIGN KEY (workspace_id, policy_id)
        REFERENCES public.iga_policy (workspace_id, id) ON DELETE CASCADE,
    ADD CONSTRAINT iga_entitlements_aws_statement_chk CHECK (
        provider <> 'aws'
        OR (policy_id IS NOT NULL AND statement_key <> '' AND effect IN ('allow','deny')
            AND content_hash <> ''));
CREATE INDEX IF NOT EXISTS idx_iga_entitlements_policy
    ON public.iga_entitlements (workspace_id, policy_id) WHERE policy_id IS NOT NULL;

-- Content history for Sid-keyed statements (§2.6). One live revision each.
CREATE TABLE IF NOT EXISTS public.iga_statement_revision (
    id                 uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id       uuid NOT NULL,
    entitlement_id     uuid NOT NULL,
    content_hash       text NOT NULL,
    statement          jsonb NOT NULL,     -- verbatim, as AWS returned it
    policy_version_id  text NOT NULL DEFAULT '',
    valid_from         timestamptz NOT NULL,
    valid_to           timestamptz,
    first_seen_run_id  uuid NOT NULL,
    CONSTRAINT iga_statement_revision_pkey PRIMARY KEY (id),
    CONSTRAINT iga_sr_entitlement_fkey FOREIGN KEY (workspace_id, entitlement_id)
        REFERENCES public.iga_entitlements (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_sr_run_fkey FOREIGN KEY (workspace_id, first_seen_run_id)
        REFERENCES public.cloud_scan_run (workspace_id, id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_statement_revision_live
    ON public.iga_statement_revision (workspace_id, entitlement_id) WHERE valid_to IS NULL;

CREATE TABLE IF NOT EXISTS public.iga_entitlement_target (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL,
    entitlement_id uuid NOT NULL,
    resource_id    uuid NOT NULL,
    target_mode    text NOT NULL,     -- resource | not_resource
    ordinal        integer NOT NULL,  -- position in the statement's list
    CONSTRAINT iga_entitlement_target_pkey PRIMARY KEY (id),
    CONSTRAINT iga_et_entitlement_fkey FOREIGN KEY (workspace_id, entitlement_id)
        REFERENCES public.iga_entitlements (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_et_resource_fkey FOREIGN KEY (workspace_id, resource_id)
        REFERENCES public.iga_resources (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_et_mode_chk CHECK (target_mode IN ('resource','not_resource')),
    CONSTRAINT iga_et_key UNIQUE (workspace_id, entitlement_id, resource_id, target_mode)
);
CREATE INDEX IF NOT EXISTS idx_iga_et_resource
    ON public.iga_entitlement_target (workspace_id, resource_id);

CREATE TABLE IF NOT EXISTS public.iga_policy_assignment (
    id                         uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id               uuid NOT NULL,
    policy_id                  uuid NOT NULL,
    holder_identity_account_id uuid NOT NULL,
    assignment_kind            text NOT NULL,   -- attached | inline | boundary
    basis             text NOT NULL DEFAULT 'declared',
    state             text NOT NULL DEFAULT 'current',
    valid_from        timestamptz NOT NULL DEFAULT now(),
    valid_to          timestamptz,
    last_confirmed_at timestamptz NOT NULL DEFAULT now(),
    last_confirmed_by uuid,
    ended_reason      text NOT NULL DEFAULT '',
    source_key        text NOT NULL,
    partition_key     text NOT NULL,
    connector_id      uuid,
    CONSTRAINT iga_policy_assignment_pkey PRIMARY KEY (id),
    CONSTRAINT iga_pa_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT iga_pa_policy_fkey FOREIGN KEY (workspace_id, policy_id)
        REFERENCES public.iga_policy (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_pa_holder_fkey FOREIGN KEY (workspace_id, holder_identity_account_id)
        REFERENCES public.iga_identity_accounts (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_pa_connector_fkey FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE SET NULL (connector_id),
    CONSTRAINT iga_pa_run_fkey FOREIGN KEY (workspace_id, last_confirmed_by)
        REFERENCES public.cloud_scan_run (workspace_id, id) ON DELETE SET NULL (last_confirmed_by),
    CONSTRAINT iga_pa_kind_chk CHECK (assignment_kind IN ('attached','inline','boundary')),
    CONSTRAINT iga_pa_basis_chk CHECK (basis IN ('declared','asserted')),
    CONSTRAINT iga_pa_state_chk CHECK (state IN ('current','stale','ended')),
    CONSTRAINT iga_pa_ended_chk CHECK ((state = 'ended') = (valid_to IS NOT NULL)),
    CONSTRAINT iga_pa_ended_reason_chk CHECK ((state = 'ended') = (ended_reason <> '')),
    CONSTRAINT iga_pa_source_key_chk CHECK (source_key <> '')
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_policy_assignment_live
    ON public.iga_policy_assignment (workspace_id, source_key) WHERE state <> 'ended';
CREATE INDEX IF NOT EXISTS idx_iga_pa_holder
    ON public.iga_policy_assignment (workspace_id, holder_identity_account_id, state);
CREATE INDEX IF NOT EXISTS idx_iga_pa_partition
    ON public.iga_policy_assignment (workspace_id, connector_id, partition_key) WHERE state <> 'ended';

CREATE TABLE IF NOT EXISTS public.iga_assignment_evidence (
    id             uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   uuid NOT NULL,
    assignment_id  uuid NOT NULL,
    observation_id uuid NOT NULL,
    relation       text NOT NULL DEFAULT 'supports',
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_assignment_evidence_pkey PRIMARY KEY (id),
    CONSTRAINT iga_ae_assignment_fkey FOREIGN KEY (workspace_id, assignment_id)
        REFERENCES public.iga_policy_assignment (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_ae_obs_fkey FOREIGN KEY (workspace_id, observation_id)
        REFERENCES public.cloud_observation (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT iga_ae_relation_chk CHECK (relation IN ('supports','contradicts','supersedes','previously_supported')),
    CONSTRAINT iga_ae_key UNIQUE (workspace_id, assignment_id, observation_id, relation)
);

-- A grant is reached through exactly one assignment, and only Allow statements
-- are grants. Enforced for AWS rows; GitHub rows (provider = 'github') are exempt.
ALTER TABLE public.iga_access_edges
    ADD COLUMN IF NOT EXISTS assignment_id uuid,
    ADD CONSTRAINT iga_access_edges_assignment_fkey FOREIGN KEY (workspace_id, assignment_id)
        REFERENCES public.iga_policy_assignment (workspace_id, id) ON DELETE CASCADE,
    ADD CONSTRAINT iga_access_edges_aws_grant_chk CHECK (
        provider <> 'aws'
        OR (assignment_id IS NOT NULL AND entitlement_id IS NOT NULL
            AND subject_identity_account_id IS NOT NULL AND resource_id IS NULL));
CREATE INDEX IF NOT EXISTS idx_iga_access_edges_entitlement
    ON public.iga_access_edges (workspace_id, entitlement_id) WHERE state <> 'ended';

-- Policies are nodes with multi-source support (§2.10B).
ALTER TABLE public.iga_object_support
    ADD COLUMN IF NOT EXISTS policy_id uuid,
    ADD CONSTRAINT iga_os_policy_fkey FOREIGN KEY (workspace_id, policy_id)
        REFERENCES public.iga_policy (workspace_id, id) ON DELETE CASCADE;
ALTER TABLE public.iga_object_support DROP CONSTRAINT iga_object_support_one_chk;
ALTER TABLE public.iga_object_support ADD CONSTRAINT iga_object_support_one_chk CHECK (
    (identity_account_id IS NOT NULL)::int + (workload_id    IS NOT NULL)::int
  + (resource_id         IS NOT NULL)::int + (entitlement_id IS NOT NULL)::int
  + (policy_id           IS NOT NULL)::int = 1);
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_os_policy
    ON public.iga_object_support (workspace_id, policy_id, connector_id, partition_key)
    WHERE policy_id IS NOT NULL;
```

```sql
-- Durable node lifecycle history for the Changes view (§5.3). Written in the
-- projection transaction; the FK to the publication is DEFERRED because the
-- publication row is inserted at the end of the same transaction, so an event
-- can exist only together with the publication it belongs to.
CREATE TABLE IF NOT EXISTS public.iga_lifecycle_event (
    id                  uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id        uuid NOT NULL,
    rev                 bigint NOT NULL,
    scan_run_id         uuid NOT NULL,
    occurred_at         timestamptz NOT NULL,
    event               text NOT NULL,   -- first_seen | retired | restored
    reason              text NOT NULL DEFAULT '',  -- retired: unsupported | recreated | policy_recreated
    identity_account_id uuid,
    workload_id         uuid,
    resource_id         uuid,
    entitlement_id      uuid,
    policy_id           uuid,
    CONSTRAINT iga_lifecycle_event_pkey PRIMARY KEY (id),
    CONSTRAINT iga_le_publication_fkey FOREIGN KEY (workspace_id, rev)
        REFERENCES public.iga_publication (workspace_id, rev) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT iga_le_run_fkey FOREIGN KEY (workspace_id, scan_run_id)
        REFERENCES public.cloud_scan_run (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT iga_le_identity_fkey FOREIGN KEY (workspace_id, identity_account_id)
        REFERENCES public.iga_identity_accounts (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_le_workload_fkey FOREIGN KEY (workspace_id, workload_id)
        REFERENCES public.iga_workload (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_le_resource_fkey FOREIGN KEY (workspace_id, resource_id)
        REFERENCES public.iga_resources (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_le_entitlement_fkey FOREIGN KEY (workspace_id, entitlement_id)
        REFERENCES public.iga_entitlements (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_le_policy_fkey FOREIGN KEY (workspace_id, policy_id)
        REFERENCES public.iga_policy (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_le_event_chk CHECK (event IN ('first_seen','retired','restored')),
    CONSTRAINT iga_le_reason_chk CHECK ((event = 'retired') = (reason <> '')),
    CONSTRAINT iga_le_one_chk CHECK (
        (identity_account_id IS NOT NULL)::int + (workload_id IS NOT NULL)::int
      + (resource_id IS NOT NULL)::int + (entitlement_id IS NOT NULL)::int
      + (policy_id IS NOT NULL)::int = 1)
);
CREATE INDEX IF NOT EXISTS idx_iga_le_identity ON public.iga_lifecycle_event (workspace_id, identity_account_id, occurred_at DESC) WHERE identity_account_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_iga_le_workload ON public.iga_lifecycle_event (workspace_id, workload_id, occurred_at DESC) WHERE workload_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_iga_le_resource ON public.iga_lifecycle_event (workspace_id, resource_id, occurred_at DESC) WHERE resource_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_iga_le_policy   ON public.iga_lifecycle_event (workspace_id, policy_id, occurred_at DESC) WHERE policy_id IS NOT NULL;
```

**Lifecycle history is an append-only log, not the node row.** Node and support
updates overwrite `lifecycle`, and a restoration clears `retired_reason`, so
the row alone cannot answer "when was this retired, and why". Every transition
— insert (`first_seen`), retirement (with its reason) and restoration — appends
an event stamped with the revision and run, in the transaction that makes the
transition. A recreation writes `retired`/`recreated` on the old object and
`first_seen` on the new one.

**The Deny rule is structural.** `iga_access_edges_aws_grant_chk` cannot see
the statement's effect, so the rule "only Allow statements are grants" is
enforced by the projector and by a test that seeds a Deny statement and
asserts zero grants for it (§7.3). It is also enforced at read time: every
grant query joins its statement with `effect = 'allow'`, so a projector defect
cannot surface a Deny as access.

**`resource_id IS NULL` on AWS grants.** A statement names several targets;
the grant points at the statement, and targets are read through
`iga_entitlement_target`. The denormalized `resource_id` stays for the GitHub
path, whose grants name one resource.

### 037 — contract (a later release)

```sql
ALTER TABLE public.iga_access_edges
    DROP CONSTRAINT IF EXISTS iga_access_edges_subject_agree_chk,
    DROP CONSTRAINT IF EXISTS iga_access_edges_subject_chk,
    DROP COLUMN IF EXISTS subject_kind,
    DROP COLUMN IF EXISTS subject_id;
DROP INDEX IF EXISTS public.idx_iga_access_edges_subject;
```

Released only after the rollback window of the release that shipped `030`
closes, and after the GitHub writer and readers stop referencing the legacy
columns. It is not required for the working product.

### Rules the DDL cannot express

1. **One-way projection.** No path writes `cloud_*` from `iga_*`. Enforced by `scripts/ci-iga-isolation-check.sh`.
2. **Generation ordering.** A projection job may only advance
   `last_generation`; a replayed or out-of-order job is a no-op. The job lease
   is the fence — `lease_version`, never a clock.
3. **`ended` requires all four conditions of §2.7.** No SQL constraint can see
   coverage. This is `Reconciler.canEnd()`, the single most important function
   in the phase to test.
4. **Retired objects keep their `source_key`**; the partial unique indexes
   depend on it.
5. **Human-owned columns are never overwritten by the projector.**
   `classification` (once a person has decided) and asserted resolutions. Every
   `ON CONFLICT DO UPDATE` names its columns — never `UpdateAll`.
6. **The observation writer records run membership even on the deduped path**
   (D4).
7. **Only Allow statements become grants**, and every grant query joins its
   statement with `effect = 'allow'` (§3 `036`).
8. **Every inventory write and delete is fenced** to the run that owns it
   (§2.10A).



---

## 4. The machinery

§3 says what must be in the database. This says what code puts it there.
Names follow the graph branch where its code is reused; everything new is
marked NEW in §4.2.

### 4.1 No graph database, and why

A graph database (Neo4j, Dgraph, an embedded Cayley) would be a **second
datastore holding the same facts**, with a sync problem between it and
Postgres — exactly the class of bug §2.1's one-authoritative-source rule
exists to remove. What the product needs is: store typed edges, walk them a
bounded number of steps, filter by state and time. Postgres does all three,
and bounded traversal over ~10⁴–10⁵ edges per workspace (§5.4) does not
justify a second database.

**No new backend dependencies.** Everything uses what is in `go.mod`:
`gorm.io/gorm`, `github.com/lib/pq`, `github.com/google/uuid`, the AWS SDK
already vendored, stdlib. The console's rendering library (§2.14.15) is a
separate, frontend decision.

### 4.2 Package layout

```
internal/awsdiscovery/      collection (existing): readers, parsers
    authdetails.go          NEW: GetAccountAuthorizationDetails, paginated
    policy_statements.go    existing parser, now also used by the projector
    trust_policy.go         parser extended: Allow AND Deny, conditions kept

internal/igagraph/          pure logic, no database handle of its own
    sourcekey.go            keys, continuity, immutable keys, statement keys
    load.go                 one run's cloud_* rows -> Snapshot; existing graph prefetch
    snapshot.go             Snapshot, Partition, Partitions(), lookups
    project.go              Snapshot -> node and edge writes
    permissions.go          NEW: policy -> statements -> targets; assignments; grants
    trust.go                NEW: trust statements -> can_assume + external principals
    reconcile.go            what this run did not see, and whether to close it

internal/igaread/           NEW: the read path (§5), no writes
    snapshot.go             read transaction, revision check, statement timeout
    refs.go                 typed references
    cursor.go               signed cursors
    lists.go                workloads, identities, resources
    detail.go               object detail and tabs
    traverse.go             bounded traversal (§5.4)
    evidence.go             claim -> facts, freshness, limitations

repository/
    iga_graph_repository.go          node and edge upserts, retire, end (graph branch)
    iga_projection_job_repository.go claim/renew/complete, fenced (graph branch)
    iga_pipeline_lease_repository.go barrier transitions (graph branch, corrected §2.10A)
    cloud_policy_repository.go       NEW: policies, attachments, memberships (fenced)

services/
    iga_projection_service.go   claims a job, loads, projects, reconciles (graph branch)
    iga_classification_service.go  NEW: decisions (§5.5)

controllers/platform/
    iga_graph_read_controller.go   NEW: §5.3 routes
```

`internal/igagraph` takes a `Snapshot` and returns decisions, so key
collisions, recreation, statement identity and the `ended`-vs-`stale` call are
testable as pure functions. `internal/igaread` owns every read query, so the
consistency contract (§5.1) lives in one place.

### 4.3 The two data structures

```go
// Snapshot is one published run's collected state, loaded once.
type Snapshot struct {
    Run        models.CloudScanRun
    Connector  models.CloudConnector
    Generation int

    Identities   []models.CloudIdentity        // roles, users, groups; roles carry TrustDocument
    Memberships  []models.CloudGroupMembership // user -> group
    Policies     []models.CloudPolicy          // managed (AWS and customer) and inline, with Document
    Attachments  []models.CloudPolicyAttachment// policy -> principal, attached|inline|boundary
    Workloads    []models.CloudWorkload
    PodIdentity  []models.CloudAssumeEdge      // mechanism = eks_pod_identity only
    Secrets      []models.CloudSecret          // access keys

    // Per-run coverage, keyed by surface. From this run's own
    // cloud_scan_run.coverage, NEVER cloud_connector.coverage.
    Coverage map[string]models.SurfaceCoverage

    // Documents that were UNREADABLE this run: a policy whose document could
    // not be fetched or parsed (cloud_policy.document_error <> ''), and a role
    // whose trust document did not parse (cloud_identity.trust_parse_error <> '').
    // What they declare goes stale instead of ending (§4.10).
    UnreadablePolicy map[uuid.UUID]bool // cloud_policy.id
    UnreadableTrust  map[uuid.UUID]bool // cloud_identity.id

    // Observation ids this run CONFIRMED, keyed by subject.
    ConfirmedBy map[SubjectRef][]uuid.UUID
}

// SubjectRef keys observations by what survives inventory deletion: the
// typed subject kind and subject_native_id, verbatim.
type SubjectRef struct {
    Kind     string // identity | policy | workload | pod_identity
    NativeID string
}
```

**Resources are not loaded from `cloud_resource`.** That table is unique on
`(workspace_id, native_id)` and its upsert reassigns `connector_id` to the
last scanner, so on the graph branch a bucket both accounts name vanished
from the other account's snapshot and its grant was projected as `*`.
Resource references are derived from **this run's own statement text**
(§4.7), so no other connector's scan can remove them.

```go
// resolved maps collected rows to the graph objects they projected to, so
// edges resolve endpoints without a query.
type resolved struct {
    identity   map[uuid.UUID]uuid.UUID // cloud_identity.id -> iga_identity_accounts.id
    workload   map[uuid.UUID]uuid.UUID // cloud_workload.id -> iga_workload.id
    policy     map[uuid.UUID]uuid.UUID // cloud_policy.id   -> iga_policy.id
    statements map[uuid.UUID][]projectedStatement // cloud_policy.id -> its statements
    resource   map[string]uuid.UUID    // resource source_key -> iga_resources.id
    assignment map[uuid.UUID]uuid.UUID // cloud_policy_attachment.id -> iga_policy_assignment.id

    existing *existing // the workspace's live graph, prefetched once (§4.5)
}

type projectedStatement struct {
    ID     uuid.UUID
    Key    string
    Effect string // "allow" | "deny"
}
```

### 4.4 `sourcekey.go`

```go
package igagraph

// Unit separator. Cannot occur in an ARN, a policy name or a Kubernetes
// reference, so no join is ambiguous and no key needs escaping.
const Sep = "\x1f"

func Key(provider string, parts ...string) string {
    return provider + Sep + strings.Join(parts, Sep)
}

func IdentityKey(i models.CloudIdentity) string { return Key("aws", i.NativeID) }
func WorkloadKey(w models.CloudWorkload) string { return Key("aws", workloadARN(w)) }

// PolicyKey is the RECOGNITION key: what the policy is called. Managed
// policies are one object across holders and accounts; inline policies belong
// to their holder. Used only to find the live object and detect recreation.
func PolicyKey(p models.CloudPolicy, holder *models.CloudIdentity) string {
    if p.PolicyKind == "inline" {
        return Key("aws", "inline", holder.NativeID, p.Name)
    }
    return Key("aws", p.NativeID) // the policy ARN
}

// PolicyImmutableKey is the policy's creation boundary: the PolicyId for a
// managed policy; the holder's immutable key for an inline policy, because an
// inline policy lives and dies with its holder.
func PolicyImmutableKey(p models.CloudPolicy, holder *models.CloudIdentity) string {
    if p.PolicyKind == "inline" {
        return ImmutableKey(*holder)
    }
    return p.PolicyID
}

// PolicyIncarnationKey names ONE incarnation of a policy. Every descendant key
// -- statements, assignments, grants -- is built from this, never from the
// ARN, so a recreated policy shares no key with its predecessor.
func PolicyIncarnationKey(p models.CloudPolicy, holder *models.CloudIdentity) string {
    if p.PolicyKind == "inline" {
        return Key("aws", "inline", EndpointKey(*holder), p.Name)
    }
    return Key("aws", "policy", p.PolicyID)
}

// StatementKey implements §2.6. `sids` counts Sid occurrences in the
// document; `hashSeen` counts identical content hashes seen so far, in
// document order.
func StatementKey(policyIncarnation string, st awsdiscovery.PolicyStatement,
    sids map[string]int, hashSeen map[string]int) (key, hash string) {
    hash = ContentHash(st) // sha256 of canonical JSON: Effect, Action, NotAction,
                           // Resource, NotResource, Condition
    if st.Sid != "" && sids[st.Sid] == 1 {
        return Key("aws", policyIncarnation, "stmt", "sid:"+st.Sid), hash
    }
    hashSeen[hash]++
    return Key("aws", policyIncarnation, "stmt", fmt.Sprintf("h:%s#%d", hash, hashSeen[hash])), hash
}

// ResourceRefKey keys a resource reference by the text the statement used.
// An exact ARN and a pattern are different objects; "*" is one workspace-wide
// selector node, supported per connector.
func ResourceRefKey(resource string) string { return Key("aws", "ref", resource) }

func AssignmentKey(policyIncarnation, holderEndpoint, kind string) string {
    return Key("aws", "assign", policyIncarnation, holderEndpoint, kind)
}
func GrantKey(assignmentKey, statementKey string) string {
    return Key("aws", "grant", assignmentKey, statementKey)
}
func ExternalPrincipalKey(issuer, subject string) string {
    return Key("aws", "ext", issuer, subject)
}

// EndpointKey names an identity inside an edge key: its immutable key when it
// has one, so a role recreated under the same ARN yields different edges.
func EndpointKey(ci models.CloudIdentity) string {
    if imm := ImmutableKey(ci); imm != "" {
        return Key("aws", "uid", imm)
    }
    return IdentityKey(ci)
}
```

`workloadARN` returns the collected ARN, or constructs one where the
collector stores a bare id: EC2 (`arn:aws:ec2:<region>:<account>:instance/<id>`)
and a Bedrock agent whose `GetAgent` failed
(`arn:aws:bedrock:<region>:<account>:agent/<id>`), so the key never changes
with a transient failure.

```go
func Continuity(kind string) string {
    switch kind {
    case "iam_role", "iam_user", "iam_group", "managed_policy", "inline_policy":
        return models.ContinuityImmutable
    default:
        // Workloads, resource references, external
        // principals: the name is the strongest claim available.
        return models.ContinuityRecognitionOnly
    }
}
```

`ImmutableKey` reads `AWSIdentityAttrs.UniqueID` (RoleId / UserId / GroupId,
written by the collector); `PolicyImmutableKey` reads `cloud_policy.policy_id`,
or the holder's immutable key for an inline policy. Continuity and the
immutable key must agree: `028`'s check rejects `immutable` with an empty key,
and that loud failure is correct — fix the mapping, never relax the check.

### 4.5 Loading the snapshot

`internal/igagraph/load.go`. One read-only snapshot per job, and one decision
that determines whether this scales.

```go
func Load(ctx context.Context, db *gorm.DB, runID uuid.UUID) (*Snapshot, error) {
    tx := db.WithContext(ctx).Begin(&sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
    defer tx.Rollback()

    var run models.CloudScanRun
    if err := tx.First(&run, "id = ?", runID).Error; err != nil {
        return nil, err
    }
    var conn models.CloudConnector
    if err := tx.First(&conn, "workspace_id = ? AND id = ?", run.WorkspaceID, run.ConnectorID).Error; err != nil {
        return nil, err
    }
    snap := &Snapshot{Run: run, Connector: conn, Generation: run.Generation}

    // Rows AT THIS RUN'S GENERATION, for THIS connector. Every table below is
    // written per connector (cloud_policy and its attachments are keyed by
    // connector), so no other account's scan can move a row out of this set.
    at := func(dst any) error {
        return tx.Where("workspace_id = ? AND connector_id = ? AND last_seen_generation = ?",
            run.WorkspaceID, run.ConnectorID, run.Generation).Find(dst).Error
    }
    for _, dst := range []any{&snap.Identities, &snap.Memberships, &snap.Policies,
        &snap.Attachments, &snap.Workloads, &snap.Secrets} {
        if err := at(dst); err != nil {
            return nil, err
        }
    }
    if err := tx.Where("workspace_id = ? AND connector_id = ? AND last_seen_generation = ? AND mechanism = ?",
        run.WorkspaceID, run.ConnectorID, run.Generation, models.MechanismEKSPodIdentity).
        Find(&snap.PodIdentity).Error; err != nil {
        return nil, err
    }

    snap.Coverage = models.DecodeScanCoverage(run.Coverage).Surfaces
    snap.UnreadablePolicy = unreadablePolicies(snap.Policies)   // document_error <> ''
    snap.UnreadableTrust = unreadableTrust(snap.Identities)     // trust_parse_error <> ''

    var obs []models.CloudObservation
    if err := tx.Select("id", "subject_native_id", "identity_id", "policy_id", "workload_id").
        Where("workspace_id = ? AND last_confirmed_run_id = ?", run.WorkspaceID, run.ID).
        Find(&obs).Error; err != nil {
        return nil, err
    }
    snap.ConfirmedBy = indexObservations(obs)

    var fresh models.CloudConnector
    if err := tx.First(&fresh, "id = ?", run.ConnectorID).Error; err != nil {
        return nil, err
    }
    if fresh.ScanGeneration > run.Generation {
        return nil, ErrSuperseded
    }
    return snap, tx.Commit().Error
}
```

`cloud_assume_edge` rows other than pod identity are **not** loaded: trust
relationships come from the trust documents themselves (§4.7), which keep
Deny statements and conditions that `cloud_assume_edge` drops.

#### Why isolation alone cannot fix this

`cloud_aws_iam_scan.go:182` computes `generation := connector.ScanGeneration + 1`
**at scan start** and writes every row at that number, while `commitScan`
(`:711`) advances `cloud_connector.scan_generation` **only at the end, on
success**. So a scan in flight has already moved rows to generation N+1 while
the connector still reports N:

```
1. run at generation 7 publishes; its projection job is queued
2. scan 8 starts; generation := 7 + 1 = 8
3. scan 8 rewrites one identity  -> last_seen_generation = 8
4. connector.scan_generation is STILL 7 -- commitScan has not run
5. the loader selects last_seen_generation = 7 and silently omits that identity
6. the connector check sees 7 > 7 = false and accepts the snapshot
```

The row was already gone before the snapshot opened, so no isolation level
helps: this is a **missing** read, not a torn one. The graph loses an identity,
every edge that needed it is skipped, and reconciliation — believing the
partition was fully read — closes them.

The guarantee is **§2.10(A), the pipeline barrier** — a durable
`iga_pipeline_lease` row, not an advisory lock, because publication and
projection are different transactions and a session lock cannot span them.
A scan claim collides with `state='projecting'`; inventory mutations validate
the run's fence in the same transaction as the write.

#### Publication is one transaction

Built on the graph branch (`PublishWithCoverage`) and kept: coverage is
computed first, then **one transaction**, fenced on the scan lease, stamps the
run's coverage, flips it to `published`, enqueues the projection job and hands
the barrier to the job (§2.10A). A scan whose coverage cannot be stored has not
published.

`cloud_scan_run`'s `Claim` gains the projection predicate, alongside the
existing `uq_cloud_scan_run_live` partial index:

```sql
AND NOT EXISTS (
    SELECT 1 FROM iga_projection_job j
     WHERE j.connector_id = cloud_scan_run.connector_id
       AND j.status IN ('queued', 'running'))
```

Two consequences to accept deliberately:

- **A wedged projection blocks scanning for that connector.** That is why
  `iga_projection_job` has an attempts ceiling and terminal `failed` /
  `abandoned` states (§4.11): a job must always reach a terminal state, or it
  becomes an outage. Alert on `queued`/`running` jobs older than one lease.
- **Scan throughput is bounded by projection.** Acceptable at one connector per
  customer and a projection measured in seconds.

> **If overlap is ever required**, membership alone does not solve it. A
> `(scan_run_id, row_id)` table still points at mutable rows, so another
> writer can change the content underneath a stable id — the projector would
> read the right *set* with the wrong *values*. Versioned inputs would have to
> capture content, not references: either project entirely from
> `cloud_observation` (already append-only and run-stamped) or copy the
> collected facts into per-run rows. Both are real work; do not adopt either
> speculatively. Serialization is cheaper and the throughput ceiling is far
> away.

**The decision that matters: prefetch the existing graph, do not query per row.**

Recreate detection needs the current object for every incoming row. Doing that
as a `SELECT … WHERE source_key = ?` per row is one round trip per identity —
107 today, thousands on a real estate, all inside one transaction holding
locks. Load the workspace's live objects once, before the transaction, and
match in memory:

```go
// existing holds the workspace's live graph objects, keyed by source_key, so
// the projection does zero per-row SELECTs.
type existing struct {
    identity    map[string]*models.IGAIdentityAccount
    workload    map[string]*models.IGAWorkload
    resource    map[string]*models.IGAResource
    policy      map[string]*models.IGAPolicy
    entitlement map[string]*models.IGAEntitlement // statements, with their live revision hash
}

// Two maps per type, because there are two different questions.
//
//   live     -- lifecycle <> 'retired', keyed by source_key. Matches the
//               partial unique index, so it is exactly what an upsert can hit.
//   retired  -- lifecycle = 'retired' AND retired_reason = 'unsupported',
//               keyed by (source_key, immutable_key). Candidates for
//               RESTORATION when an object comes back.
//
// Without the second map, reappearance after retirement silently mints a new
// object: X is retired as unsupported, drops out of `live`, the next scan
// sees it again, finds no live match, and inserts Y. Every review decision
// and first_seen_at attached to X is orphaned.
//
// Retired-as-RECREATED rows are deliberately NOT candidates. They were
// replaced by a different principal wearing the same name; restoring one
// would carry the old history onto the new principal, which is exactly what
// the recreate rule exists to prevent.
func loadExisting(ctx context.Context, db *gorm.DB, ws uuid.UUID) (*existing, error) { … }
```

§4.6's node passes then read `r.existing.live.identity[key]` — a map lookup, no
query. The transaction still sees its own writes, because the upserts go
through `tx`; `existing` is only the *pre-transaction* baseline, which is all
the recreate-detection comparison needs.

**Memory.** A workspace's whole graph is tens of thousands of rows of a few
hundred bytes — single-digit MB. If an estate ever makes that untrue, partition
the projection by `estate_scope_id` and load one scope at a time; the algorithm
does not change, because reconciliation is already per-scope.

### 4.6 The projection algorithm

One transaction per job: every node, every edge, reconciliation and the
publication. Nodes first, edges second.

`projectAndReconcile` runs `Project`, then `Reconcile` with the exclusions
`Project` computed, then flushes the lifecycle event log — all in one
transaction (graph branch, kept and extended). `Project`:

```go
func (p *Projector) Project(tx *gorm.DB, snap *Snapshot) error {
    // 1. OWNERSHIP, inside the transaction: the job lease and the barrier
    //    (workspace, phase=projecting, holder=job:<id>, run, version), both
    //    FOR UPDATE. A reclaimed worker fails here and writes nothing.
    if err := p.fence.AssertOwnedTx(tx, p.jobID, p.owner, p.leaseVersion); err != nil {
        return err
    }
    if err := p.fence.AssertHeldTx(tx, snap.Run.WorkspaceID, snap.Run.ID, p.pipelineVersion); err != nil {
        return err
    }

    // 2. ALREADY PUBLISHED? Before the generation guard: a replay after commit
    //    is success, and only the publication row can tell it from supersession.
    if pub, err := p.repo.PublicationForRun(tx, snap.Run.WorkspaceID, snap.Run.ID); err != nil {
        return err
    } else if pub != nil {
        return &AlreadyPublished{Rev: pub.Rev}
    }

    // 3. SUPERSEDED? Only a strictly newer generation. Equality without a
    //    publication is an inconsistency and fails loudly.
    if err := p.guardWatermarks(tx, snap); err != nil {
        return err
    }

    // 4. THE REVISION, allocated now: max(rev)+1 is safe because step 1 holds
    //    the barrier row FOR UPDATE. Every lifecycle event is stamped with
    //    it, and the publication row at step 6 carries it.
    rev, err := p.repo.NextRevision(tx, snap.Run.WorkspaceID)
    if err != nil {
        return err
    }
    p.events = newEventLog(snap.Run.WorkspaceID, rev, snap.Run.ID, p.now())

    r := newResolved(p.existing)
    scope, err := p.upsertEstateScope(tx, snap) // aws␟account␟<account id>
    if err != nil {
        return err
    }

    // Nodes, in dependency order. Each writes its support row (§4.10 contract).
    steps := []func(*gorm.DB, *Snapshot, *resolved) error{
        p.projectIdentities, // roles, users, groups: recreate / continue / restore / new
        p.projectWorkloads,  // + provider_native_agent on insert for Bedrock and AgentCore runtimes
        p.projectPolicies,   // §4.7
        p.projectStatements, // §4.7: statements, revisions, resource references, targets
        p.projectCredentials,
    }
    // Edges. Every endpoint is in r by now.
    steps = append(steps,
        p.projectAssignments,   // §4.7
        p.projectGrants,        // §4.7: Allow statements only
        p.projectMemberships,   // member_of
        p.projectExecution,     // executes_as, task_execution_role, execution_role_state
        p.projectTrust,         // can_assume + external principals (§4.7)
        p.attachEvidence,       // every edge, counted per edge (§4.8)
    )
    for _, step := range steps {
        if err := step(tx, snap, r); err != nil {
            return err
        }
    }
    if err := p.recordState(tx, snap, scope, false); err != nil {
        return err
    }

    // 5. LIFECYCLE EVENTS: every first_seen / retired / restored transition
    //    the node passes made is in p.events. Reconciliation, which runs next
    //    in this same transaction, appends its retirements to the same log,
    //    and projectAndReconcile flushes it before commit.

    // 6. PUBLICATION, in the same transaction as every write above.
    return p.repo.InsertPublication(tx, snap.Run.WorkspaceID, rev, snap.Run.ID, p.now(), manifestOf(snap))
}
```

One node pass in full — `projectWorkloads` and `projectPolicies` are the same
shape:

```go
func (p *Projector) projectIdentities(tx *gorm.DB, snap *Snapshot, r *resolved) error {
    now := p.now()
    for _, ci := range snap.Identities {
        key  := IdentityKey(ci)
        cont := Continuity(ci.Kind)
        imm  := ImmutableKey(ci)
        // The partition this row is evidenced by -- looked up from the same
        // list Partitions() builds, so the key written here is the key
        // reconciliation filters on (roles and users are separate).
        part := snap.PartitionFor(models.ObjectIdentity, ci.Kind, "")

        // Descriptive fields, applied on every path below: insert, update
        // and restore all refresh them from what this run read.
        desc := models.IGAIdentityAccount{
            WorkspaceID: snap.Run.WorkspaceID, SourceKey: key,
            Continuity: cont, ImmutableKey: imm,
            DisplayName: ci.Name, AccountKind: ci.Kind,
            IdentityBacking: "provider_native", LastSeenAt: now,
        }

        var id uuid.UUID
        live := r.existing.live.identity[key]   // prefetched once, §4.5

        switch {
        // (a) RECREATION. Same recognition key, different non-empty creation
        //     boundary: a different principal wearing the old name. Retire the
        //     old object, end its edges, and fall through to a fresh insert.
        case live != nil && cont == models.ContinuityImmutable &&
            imm != "" && live.ImmutableKey != "" && live.ImmutableKey != imm:

            if err := p.repo.RetireIdentity(tx, live.ID, models.RetiredRecreated, now); err != nil {
                return fmt.Errorf("retire recreated %s: %w", key, err)
            }
            if err := p.repo.EndEdgesOnSubject(tx, snap.Run.WorkspaceID, live.ID,
                models.EndedSubjectRecreated, now, snap.Run.ID); err != nil {
                return fmt.Errorf("end edges of recreated %s: %w", key, err)
            }
            if err := p.repo.SuspendAssertions(tx, snap.Run.WorkspaceID, live.ID, "recreated"); err != nil {
                return err // §2.12: a human's decision about X never transfers to Y
            }
            row := desc
            row.FirstSeenAt = now
            var err error
            if id, err = p.repo.InsertIdentity(tx, &row); err != nil {
                return fmt.Errorf("insert recreated %s: %w", key, err)
            }

        // (b) CONTINUING. The object is live; refresh descriptive fields only.
        //     first_seen_at, lifecycle and human-owned columns are untouched.
        case live != nil:
            var err error
            if id, err = p.repo.UpsertIdentity(tx, &desc); err != nil {
                return fmt.Errorf("upsert %s: %w", key, err)
            }

        // (c) RESTORATION. No live row, but the same provider identity was
        //     retired as UNSUPPORTED. Same id, same first_seen_at. Requires a
        //     non-empty, equal immutable key -- a recognition_only object is
        //     never restored, because without a creation boundary we cannot
        //     prove the returning one is the one that left.
        case imm != "" && r.existing.retired.identity[retiredKey(key, imm)] != nil:
            prev := r.existing.retired.identity[retiredKey(key, imm)]
            var err error
            // Guarded UPDATE: only a row still retired as 'unsupported' with
            // this immutable key. Zero rows -> ErrNotRestorable, and the pass
            // fails rather than silently inserting a duplicate.
            if id, err = p.repo.RestoreIdentity(tx, prev.ID, imm, &desc); err != nil {
                return fmt.Errorf("restore %s: %w", key, err)
            }
            // Restoring the RECORD does not reactivate a human's decision about
            // it. Asserted associations come back as pending reconfirmation.
            if err := p.repo.MarkAssertionsPendingReconfirm(tx, snap.Run.WorkspaceID, id); err != nil {
                return err
            }

        // (d) NEW.
        default:
            row := desc
            row.FirstSeenAt = now
            var err error
            if id, err = p.repo.InsertIdentity(tx, &row); err != nil {
                return fmt.Errorf("insert %s: %w", key, err)
            }
        }

        // Step 2 of the contract, on EVERY path above -- including restore.
        // A node without a current support row is never reconciled.
        if err := p.repo.UpsertSupport(tx, &models.IGAObjectSupport{
            WorkspaceID:        snap.Run.WorkspaceID,
            IdentityAccountID:  &id,
            ConnectorID:        snap.Run.ConnectorID,
            PartitionKey:       part.Key(),
            State:              models.RelCurrent,
            LastConfirmedRunID: &snap.Run.ID,
            LastConfirmedAt:    &now,
            EndedReason:        "", // clears a previous 'not_seen' on reappearance
        }); err != nil {
            return fmt.Errorf("support %s: %w", key, err)
        }

        r.identity[ci.ID] = id
    }
    return nil
}
```

**Reappearance is not recreation, and the difference is the immutable key.**

| What changed | Recognition key | Immutable key | Result |
|---|---|---|---|
| A source stops reporting an object, then reports it again | same | same, **non-empty** | **Reappearance.** Same object id, same `first_seen_at` — restored from `retired` if it had been retired as unsupported (below). Its support row flips `ended → current` and `ended_reason` clears. Relationships ended by the gap are *not* revived — they are re-projected as new rows, because we did not observe them in between and cannot claim continuity we lack |
| The object is deleted and remade under the same name | same | **different**, both non-empty | **Recreation.** New object id, fresh `first_seen_at`, old object retired `recreated`, its relationships ended `subject_recreated` |
| Same name, no immutable key, **continuously present** | same | both empty | **Continues as one object.** `continuity = 'recognition_only'` is stored and surfaced so a reviewer knows "same name" is the strongest claim available |
| Same name, no immutable key, **returns after a confirmed absence** | same | both empty | **New object.** Retirement only happens after `canEnd` passed — an authoritative read said it was gone — so a same-name return is more likely a recreation than a continuation, and we have no creation boundary to tell. Assuming continuity would hand the old object's history to what is probably a different workload |

**Restoration** is branch (c) of `projectIdentities` above; there is no
separate algorithm.

Restoration requires a **non-empty, equal** immutable key. A
`recognition_only` object (Lambda, S3 bucket) has none, so a retired one is
never restored — it returns as a new object, and its `continuity` says why.
That is the honest outcome: without a creation boundary we cannot prove the
returning Lambda is the one that left.

Restoring requires the partial unique index to admit it: the live row's slot
is free because the retired row is excluded by `WHERE lifecycle <> 'retired'`,
and a restore flips that same row back into the index. There is never a moment
with two live rows for one key.

Rows two and four are the only ones that split an object, and they differ in what licenses it: row two has proof (a changed immutable key); row four has a confirmed absence and no way to prove continuity. A *failed* read never reaches either — it makes support `stale`, never `ended`, so nothing is retired and nothing splits. Where the provider
gives no creation boundary we cannot tell the first case from the second, and
the honest answer is to continue the object and say why.

```go
// The support upsert's ON CONFLICT names ended_reason and state explicitly:
DoUpdates: clause.AssignmentColumns([]string{
    "state", "ended_reason", "last_confirmed_run_id", "last_confirmed_at",
}),
// NOT first_seen_at -- a reappearing object kept existing as far as we know;
// we simply stopped being able to see it.
```

Edges, where `resolved` pays for itself:

```go
// projectExecution writes the configured execution identity of every workload.
func (p *Projector) projectExecution(tx *gorm.DB, snap *Snapshot, r *resolved) error {
    for _, w := range snap.Workloads {
        src, ok := r.workload[w.ID]
        if !ok {
            continue
        }
        // DETERMINE THE ENDPOINT FIRST, then record what we know. The role is
        // the one the workload ACTS AS (RoleARN), never ECS's
        // ExecutionRoleARN, which is written separately below.
        state, arn, dst := executionRole(snap, r, w) // resolved | not_in_scan | not_in_inventory | none
        if err := p.repo.SetExecutionRoleState(tx, src, state, arn); err != nil {
            return err // written every pass, so no earlier state survives
        }
        if state == models.ExecRoleResolved {
            if err := p.upsertRel(tx, snap, "executes_as", w, &src, nil, dst); err != nil {
                return err
            }
        }
        // ECS only: the role ECS uses to pull the image and fetch secrets.
        if w.RuntimeKind == models.WorkloadECSTaskDefinition {
            if dst, ok := resolveRole(snap, r, w.AWSAttrs().ExecutionRoleARN); ok {
                if err := p.upsertRel(tx, snap, "task_execution_role", w, &src, nil, dst); err != nil {
                    return err
                }
            }
        }
    }
    return nil
}
```

The four execution-role states are each a different sentence on the
Identities tab (§2.14.7): `resolved` (the edge exists); `not_in_scan` (the
collector linked a role this run's snapshot does not contain — a partial IAM
read); `not_in_inventory` (a role ARN that matches no identity in the
workspace: another account, or IAM never read); `none` (no role configured).
A prior edge is never deleted by this pass; reconciliation decides.

Every relationship key names **both** endpoints with their endpoint keys
(§4.4): a Lambda moved from `RoleA` to `RoleB` computes a new key, so the old
edge ends instead of being overwritten in place.

`projectWorkloads` is the same shape as `projectIdentities` — **including
the support upsert**, with `part := snap.PartitionFor(models.ObjectWorkload,
w.RuntimeKind, w.Region)`, because workload partitions are per service per
region (`lambda:eu-central-1` is not `ecs:eu-central-1`). A description by
reference is only safe if it carries the step that is easy to omit.

`projectWorkloads` also writes `classification = 'provider_native_agent'` **on
insert** for `bedrock_agent` and `bedrock_agentcore_runtime`, and never updates
the column afterwards. `Continuity()` returns `recognition_only` for every
runtime kind this milestone collects — so a Lambda that is deleted and recreated under the same name
continues as one object, and the console says `recognition_only` rather than
implying we checked.

### 4.7 The permission graph and trust

This is the part that makes the graph an access graph, and the one place the
provider's shape and ours genuinely differ. It implements §2.6 exactly.

#### Policies

```go
func (p *Projector) projectPolicies(tx *gorm.DB, snap *Snapshot, r *resolved) error {
    for _, cp := range snap.Policies {
        holder := snap.IdentityByID(cp.HolderIdentityID) // nil for managed
        key := PolicyKey(cp, holder)
        kind := policyKind(cp)                          // aws_managed | customer_managed | inline
        id, err := p.repo.UpsertPolicy(tx, &models.IGAPolicy{
            WorkspaceID: snap.Run.WorkspaceID, Provider: "aws", PolicyKind: kind,
            DisplayName: cp.Name, NativeRef: cp.NativeID, SourceKey: key,
            Continuity: Continuity(policyContinuityKind(cp)),
            ImmutableKey: PolicyImmutableKey(cp, holder),
            VersionID: cp.VersionID, DocumentHash: cp.DocumentHash, LastSeenAt: p.now(),
        }, r.existing) // same recreate / continue / restore / new branches as identities
        if err != nil {
            return fmt.Errorf("policy %s: %w", key, err)
        }
        if err := p.support(tx, snap, models.ObjectPolicy, id, snap.PartitionFor(models.ObjectPolicy, "", "")); err != nil {
            return err
        }
        r.policy[cp.ID] = id
    }
    return nil
}
```

**Recreation is decided here, and cascades in the same transaction.** When a
live policy has the same recognition key but a different non-empty immutable
key — a customer-managed policy recreated under the same ARN, or an inline
policy whose holder was recreated — the old policy retires `recreated`, and in
the same transaction:

| Old incarnation's | Becomes | `ended_reason` / `retired_reason` |
|---|---|---|
| Statements | retired, support ended | `policy_recreated` |
| Assignments | `ended` | `policy_recreated` |
| Grants | `ended` | `policy_recreated` |
| Statement revisions | closed (`valid_to`) | — |

The new incarnation is then inserted with its own id, and `projectStatements`
builds its statements from `PolicyIncarnationKey`, so none of the old rows can
be matched or reused. A **restored** policy (same recognition and immutable key
after retirement as `unsupported`) keeps its incarnation key, so its statements
are matched by key and continue.

#### Statements, revisions, resource references, targets

```go
func (p *Projector) projectStatements(tx *gorm.DB, snap *Snapshot, r *resolved) error {
    for _, cp := range snap.Policies {
        if snap.UnreadablePolicy[cp.ID] {
            continue // its existing statements are protected by reconciliation (§4.10)
        }
        stmts, _, err := awsdiscovery.ParsePolicyDocument(cp.Document) // the collector's own parser
        if err != nil {
            return fmt.Errorf("policy %s parsed at collection, failed now: %w", cp.NativeID, err)
        }
        polKey := PolicyIncarnationKey(cp, snap.IdentityByID(cp.HolderIdentityID))
        sids, seen := countSids(stmts), map[string]int{}
        for _, st := range stmts {
            key, hash := StatementKey(polKey, st, sids, seen)
            id, err := p.repo.UpsertStatement(tx, &models.IGAEntitlement{
                WorkspaceID: snap.Run.WorkspaceID, Provider: "aws",
                PolicyID: ptr(r.policy[cp.ID]), SourceKey: key, StatementKey: key,
                Sid: st.Sid, StatementIndex: &st.Index, Effect: st.Effect, // lowercase
                ContentHash: hash, Negated: len(st.NotActions) > 0 || len(st.NotResources) > 0,
                Conditional: st.Condition != nil,
                NativeGrantKind: "aws_statement",
                NativeRights:     verbatim(st),        // exactly what AWS returned
                NormalizedRights: normalizedRights(st), // our reading; never the record
                LastSeenAt: p.now(),
            })
            if err != nil {
                return err
            }
            // A Sid-keyed statement whose content changed gains a revision;
            // the live revision closes and a new one opens, same transaction.
            if err := p.repo.RecordRevision(tx, snap, id, hash, verbatim(st), cp.VersionID); err != nil {
                return err
            }
            if err := p.projectTargets(tx, snap, r, id, st); err != nil {
                return err
            }
            if err := p.support(tx, snap, models.ObjectEntitlement, id, snap.PartitionFor(models.ObjectEntitlement, "", "")); err != nil {
                return err
            }
            r.statements[cp.ID] = append(r.statements[cp.ID], projectedStatement{id, key, st.Effect})
        }
    }
    return nil
}

// projectTargets replaces the statement's target set with the one its
// CURRENT content names. Targets are derived from content; the content's
// history is the revision rows, so replacing targets loses nothing.
func (p *Projector) projectTargets(tx *gorm.DB, snap *Snapshot, r *resolved,
    stmtID uuid.UUID, st awsdiscovery.PolicyStatement) error {
    var rows []models.IGAEntitlementTarget
    add := func(resource, mode string, ord int) error {
        id, err := p.resourceRef(tx, snap, r, resource) // exact | selector | external, typed via awsdiscovery.TypeResourceARN
        if err != nil {
            return err
        }
        rows = append(rows, models.IGAEntitlementTarget{EntitlementID: stmtID, ResourceID: id, TargetMode: mode, Ordinal: ord})
        return nil
    }
    for i, res := range st.Resources {
        if err := add(res, "resource", i); err != nil {
            return err
        }
    }
    for i, res := range st.NotResources {
        if err := add(res, "not_resource", i); err != nil {
            return err
        }
    }
    if len(st.NotResources) > 0 && len(st.Resources) == 0 {
        if err := add("*", "resource", 0); err != nil { // "everything except" is scoped by "*"
            return err
        }
    }
    return p.repo.ReplaceTargets(tx, snap.Run.WorkspaceID, stmtID, rows)
}
```

`resourceRef` upserts one `iga_resources` row per distinct resource text:
kind from `awsdiscovery.TypeResourceARN` (`s3_bucket` and `s3_object` stay
distinct), account and region **only when the ARN carries them**, a `selector`
kind for `*`/`?` patterns, and `provider_attrs.account_connected` computed from
the workspace's connectors. Each gets a support row for this connector, so a
bucket named by two accounts has two support rows and survives either one
dropping it.

#### Assignments and grants

```go
func (p *Projector) projectAssignments(tx *gorm.DB, snap *Snapshot, r *resolved) error {
    for _, at := range snap.Attachments {
        holder, ok := r.identity[at.PrincipalIdentityID]
        if !ok {
            continue // the holder was not projected; nothing to attach to
        }
        pol := snap.PolicyByID(at.PolicyRowID)
        key := AssignmentKey(PolicyIncarnationKey(pol, snap.IdentityByID(pol.HolderIdentityID)),
            EndpointKey(snap.IdentityByID(at.PrincipalIdentityID)), at.AttachmentKind)
        id, err := p.repo.UpsertAssignment(tx, &models.IGAPolicyAssignment{
            WorkspaceID: snap.Run.WorkspaceID, PolicyID: r.policy[pol.ID],
            HolderIdentityAccountID: holder, AssignmentKind: at.AttachmentKind,
            Basis: models.BasisDeclared, State: models.RelCurrent,
            SourceKey: key, ConnectorID: &snap.Run.ConnectorID,
            PartitionKey: snap.EdgePartitionFor("assignment", "", "").Key(),
            LastConfirmedAt: p.now(), LastConfirmedBy: &snap.Run.ID,
        })
        if err != nil {
            return err
        }
        r.assignment[at.ID] = id
    }
    return nil
}

func (p *Projector) projectGrants(tx *gorm.DB, snap *Snapshot, r *resolved) error {
    for _, at := range snap.Attachments {
        asg, ok := r.assignment[at.ID]
        if !ok || at.AttachmentKind == "boundary" {
            continue // a boundary limits; it never grants
        }
        holder := r.identity[at.PrincipalIdentityID]
        for _, st := range r.statements[at.PolicyRowID] {
            if st.Effect != "allow" {
                continue // a Deny statement is a restriction, never a grant
            }
            if err := p.repo.UpsertGrant(tx, &models.IGAAccessEdge{
                WorkspaceID: snap.Run.WorkspaceID, Provider: "aws",
                SubjectIdentityAccountID: &holder,
                SubjectKind: "identity_account", SubjectID: holder, // legacy pair, until 037
                EntitlementID: &st.ID, AssignmentID: &asg,
                Direction: "outbound", PathKind: "aws_policy",
                Basis: models.BasisDeclared, State: models.RelCurrent,
                // Nothing is evaluated: the honesty check (004) requires unknown
                // unless the calculation is complete, and it never is.
                CalculationState: models.CalcPartial, EffectiveConclusion: models.ConclusionUnknown,
                SourceKey: GrantKey(assignmentKeyOf(snap, at), st.Key),
                ConnectorID: &snap.Run.ConnectorID,
                PartitionKey: snap.EdgePartitionFor("access_edge", "", "").Key(),
                LastConfirmedAt: p.now(), LastConfirmedBy: &snap.Run.ID,
            }); err != nil {
                return err
            }
        }
    }
    return nil
}
```

**Two roles on one managed policy:** one policy, one statement set, two
assignments, two grants per Allow statement. **Two policies declaring the same
action:** two statements, two grants. **Detach one:** its assignment is not
confirmed by the next run, so the assignment and its grants end; nothing else
moves.

#### Trust and external principals

```go
func (p *Projector) projectTrust(tx *gorm.DB, snap *Snapshot, r *resolved) error {
    for _, role := range snap.Roles() {
        target := r.identity[role.ID]
        if snap.UnreadableTrust[role.ID] {
            continue // its existing trust edges are protected by reconciliation (§4.10)
        }
        stmts, err := awsdiscovery.ParseTrustPolicy(role.TrustDocument) // Allow and Deny, conditions kept
        if err != nil {
            return fmt.Errorf("trust document of %s parsed at collection, failed now: %w", role.NativeID, err)
        }
        for _, st := range stmts {
            if st.Effect == "deny" {
                continue // recorded on the role (provider_attrs.trust_has_deny), never an edge
            }
            for _, pr := range st.Principals {
                src, ext, err := p.trustSource(tx, snap, r, pr) // an identity in the workspace, or an external principal
                if err != nil {
                    return err
                }
                if err := p.upsertTrust(tx, snap, role, target, src, ext, st, pr.Mechanism); err != nil {
                    return err
                }
            }
        }
    }
    for _, pi := range snap.PodIdentity { // EKS: k8s service account -> role
        ext, err := p.upsertExternal(tx, snap, pi.Issuer, pi.Subject, "k8s_service_account")
        if err != nil {
            return err
        }
        if err := p.upsertTrust(tx, snap, snap.IdentityByID(pi.IdentityID), r.identity[pi.IdentityID],
            nil, &ext, podIdentityStatement(pi), models.MechanismEKSPodIdentity); err != nil {
            return err
        }
    }
    return nil
}
```

`trustSource` resolves a principal in this order, and records which rule
applied:

| Principal | Result |
|---|---|
| An exact role or user ARN of an identity **in any connected account of the workspace** | That identity; `basis = declared` on the edge |
| An exact ARN in an account that is **not connected** | External principal (`aws_principal`), unresolved |
| An account (`123456789012`, `arn:aws:iam::123456789012:root`) | External principal (`aws_account`): "any principal in that account the account permits" |
| `*` | External principal (`aws_account`, subject `*`), shown as *"any AWS principal"* |
| A service (`lambda.amazonaws.com`) | External principal (`aws_service`) |
| Federated OIDC or SAML | External principal (`oidc` / `saml`) with issuer and the `sub` condition values; wildcarded subjects stay unresolved and are shown as wildcards |
| `NotPrincipal` | Not projected; the role records `trust_has_not_principal` and every path to it carries the limitation *"The trust policy uses NotPrincipal, which is not resolved"* |

The edge key names the trust statement (`statement_key`: Sid, else content
hash, as §2.6), the source and the target, so two statements naming the same
principal under different conditions are two edges, each with its own
conditions.

### 4.8 Evidence, and the watermark

`attachEvidence` links every projected edge to the observations **this run**
confirmed, joined on the typed subject and `subject_native_id`, never on a
`cloud_*` row id (an observation outlives the row it describes, `024`).

**Evidence per edge type:**

| Edge | Supporting observation |
|---|---|
| Grant | The observation of the policy's default version (subject `policy_id`) **and** of the holder (whose authorization-details entry lists the attachment) |
| Assignment | The holder's observation (it lists the attachment) and the policy version's |
| `executes_as`, `task_execution_role` | The workload's own observation |
| `member_of` | The user's observation (it lists the group) |
| `can_assume` | The role's observation (it carries the trust document); pod identity: the association's observation |
| Target | The policy version's observation |


**Every projected edge needs evidence — counted per edge, not per class.** A
non-zero count per *class* passes with one evidenced edge and ten thousand
bare ones, which is exactly the shape of the bug this section had: the access
pass never retained its edge ids, so the map was empty and the pipeline wrote
nothing while appearing to work. T4.9's gate asserts
`count(edges without evidence) == 0` for every projected edge type.

**Every projected edge has evidence, or the pass fails its gate.** An edge
whose supporting observation cannot be found is still written — the
configuration was read — and is counted; the P2-0 gate and T4.9 assert the count
is zero on the lab accounts.

```go
// recordState writes the per-partition watermark. reconciled=false until the
// Reconciler commits, so a pass interrupted between projection and
// reconciliation is visible as exactly that and gets redone (§2.8).
func (p *Projector) recordState(tx *gorm.DB, snap *Snapshot, reconciled bool) error {
    for _, part := range Partitions(snap) {
        if err := p.repo.UpsertProjectionState(tx, &models.IGAProjectionState{
            WorkspaceID:      snap.Run.WorkspaceID,
            EstateScopeID:    part.ScopeID,
            ConnectorID:      part.ConnectorID,
            ObjectClass:      part.Class,
            RelationshipType: part.RelationshipType,
            // The partition's full identity. A partition can depend on
            // several surfaces, so no single one of them can key it.
            PartitionKey:   part.Key(),
            LastRunID:      snap.Run.ID,
            LastGeneration: int64(snap.Generation),
            CoverageState:  part.CoverageSummary(snap),
            Reconciled:     reconciled,
        }); err != nil {
            return err
        }
    }
    return nil
}

// Key is the partition's stable identity: scope, connector, class,
// relationship type, target and its required surfaces, joined. It is the
// unique key on iga_projection_state (033) and the value lastGenerationFor
// looks up -- so two partitions that differ only by region or by service get
// separate watermark rows instead of overwriting each other's progress.
func (p Partition) Key() string
```

#### Estate scopes, which nothing creates yet

Every canonical node has `estate_scope_id`, and **no code populates
`iga_estate_scopes`** — checked. The projector must create the scope before the
nodes that reference it, or every object lands with a NULL scope and
reconciliation has no partition to work in.

For AWS the scope is the connected account: `cloud_connector.ScopeKind` /
`ScopeID` already hold `("account", "220171243705")` — `models.CloudScopeAccount`,
constrained by `cloud_connector_scope_kind_chk` to
`account | project | folder | org | subscription`, with the provider carried
separately in `provider`. One upsert per run,
before the node passes, keyed the same way as everything else:

```go
scopeKey := Key("aws", "account", snap.Connector.ScopeID)
```

Region is deliberately **not** a sub-scope. It would multiply
partitions without changing any authorization boundary — IAM is global, and a
denied region is a coverage fact, not a containment one.

### 4.9 The upsert, and the one thing that will bite

Every node upsert targets a **partial** unique index (`… WHERE source_key <> ''
AND lifecycle <> 'retired'`). Postgres will not infer a partial index from a
bare `ON CONFLICT (cols)` — the predicate must be restated, and in GORM that is
`TargetWhere`, not `Where`. `Where` emits the `DO UPDATE … WHERE` condition,
which is a different clause and silently does not help inference.

```go
func (r *igaGraphRepository) UpsertIdentity(tx *gorm.DB, a *models.IGAIdentityAccount) (uuid.UUID, error) {
    err := tx.Clauses(clause.OnConflict{
        Columns: []clause.Column{{Name: "workspace_id"}, {Name: "source_key"}},
        // Must match uq_iga_identity_accounts_source_key's predicate EXACTLY.
        TargetWhere: clause.Where{Exprs: []clause.Expression{
            clause.Expr{SQL: "source_key <> '' AND lifecycle <> 'retired'"},
        }},
        // Named columns only. UpdateAll would reset first_seen_at and clobber
        // human-owned state -- ownership, review status, classification -- which
        // is precisely what the exit gate tests for.
        DoUpdates: clause.AssignmentColumns([]string{
            "display_name", "account_kind", "identity_backing",
            "last_seen_at", "updated_at",
        }),
    }).Create(a).Error
    return a.ID, err
}
```

Two traps, both of which have to be covered by a test against real Postgres:

- **`a.ID` after a conflict.** GORM returns the id it generated, not the
  surviving row's. Add `Returning{Columns: []clause.Column{{Name: "id"}}}` and
  read it back, or every rescan silently points edges at ids that do not exist.
- **SQLite accepts all of this.** It does not enforce partial-index inference,
  so the suite will pass and production will not. These tests need Postgres.

### 4.10 Reconciliation

Projection writes what the run saw. Reconciliation decides what to do about
what it did not — and this is the function to get right.

```go
// Reconcile closes what this run SHOULD have seen and did not.
//
// The naive version -- "end everything older than this generation" -- is wrong
// and dangerous: a denied surface produces no rows, so every relationship
// behind it looks absent, and a credential outage reads as a successful
// cleanup. Hence canEnd().
// Reconcile runs in the caller's transaction -- see projectAndReconcile.
//
// Node partitions act on SUPPORT rows; edge partitions act on the edge tables.
// Routing on part.Target matters: a node partition sent through the edge
// helpers matches nothing (its relationship_type is empty) and silently
// reconciles nothing.
func (rc *Reconciler) Reconcile(tx *gorm.DB, snap *Snapshot, ex Exclusions) error {
    for _, part := range Partitions(snap) {
        stale := !rc.canEnd(snap, part)
        var err error
        if part.Target == "" {
            err = rc.reconcileNodes(tx, part, snap, ex, stale) // identity|workload|policy|entitlement|resource
        } else {
            err = rc.reconcileEdges(tx, part, snap, ex, stale) // relationship|assignment|access_edge
        }
        if err != nil {
            return err
        }
    }
    // Only now, with every partition's support settled, is it safe to ask
    // which objects have no support left (§2.10B).
    if err := rc.retireUnsupported(tx, snap); err != nil {
        return err
    }
    return rc.markReconciled(tx, snap)
}

// canEnd gates every close. Its corrected body, the partition contract it
// depends on, and why the obvious version is wrong are below.
func (rc *Reconciler) canEnd(snap *Snapshot, part Partition) bool // see "canEnd, corrected"
```

`markStale` moves `current` rows to `stale` and leaves `last_confirmed_at`
untouched — that timestamp is the honest answer to "how old is this?" and
refreshing it would launder an outage into a confirmation.

`endOlderThan` sets `state='ended'`, `valid_to=now()`, `ended_reason='not_seen'`
on rows in the partition whose `last_confirmed_by` generation predates this run.
It never deletes.

#### The partition contract

A Partition is the unit reconciliation reasons about, and getting its
definition wrong is how a scan of one account deletes another account's graph.

```go
type Partition struct {
    // The evidence boundary. Reconciliation NEVER crosses it: one AWS account
    // confirming its own relationships says nothing about another account's.
    ScopeID     uuid.UUID
    ConnectorID uuid.UUID

    Class            string // identity | workload | resource | entitlement
    RelationshipType string // "" for node classes and for access edges
    Target           string // "relationship" | "access_edge"

    // Every surface that must be good before this partition may close
    // anything. Plural, because completeness is composed: a statement's grants
    // depend on the IAM read AND on the policy documents parsing.
    RequiredSurfaces []string

    // Scanner-level failure markers that veto this partition if PRESENT.
    // FinalizeCoverage writes these only when a scanner died before producing
    // a snapshot, so presence proves failure and absence proves nothing on its
    // own -- which is exactly why they are a separate list from the surfaces
    // above, whose absence DOES mean "did not look".
    RequiredScanners []string // "permission_scan", "workload_scan"
}
```

**The surface names are `models.Surface*` constants, not invented strings.**
The vocabulary after S3 (§1.4):

| Emitted by | Keys |
|---|---|
| IAM scan (authorization details) | `iam_roles`, `iam_users`, `iam_groups` (new), `iam_policies`, `iam_access_keys` |
| `cloud_aws_permission_scan.go` | `oidc_providers`, `eks_pod_identity`, `resource_policies`, and `policy_documents` **only when something failed to parse** |
| `cloud_aws_workload_scan.go` | On success, one key **per service per region**: `lambda:<region>`, `ecs:<region>`, `ec2:<region>`, `bedrock-agents:<region>`, `bedrock-agentcore:<region>` (`:268-295`). `compute:<region>` is **only** the stand-in written when the region's client config fails (`denied`, `:255`) or the region was never selected (`not_selected`, `:166`) |
| `FinalizeCoverage` | `iam_credential_report`, `permission_scan`, `workload_scan`, `activity` |

```go
func Partitions(snap *Snapshot) []Partition {
    sc, cn := snap.ScopeID, snap.Run.ConnectorID
    iam := []string{models.SurfaceIAMRoles, models.SurfaceIAMUsers, models.SurfaceIAMGroups, models.SurfaceIAMPolicies}
    // policy_documents is deliberately absent: unparsed documents are excluded
    // row by row (below), not by vetoing the whole account.
    perm := iam
    veto := []string{models.SurfacePermissionScan}

    ps := []Partition{
        // Identities, one partition per kind: a denied users read must not
        // block role reconciliation, nor a good roles read license closing users.
        {ScopeID: sc, ConnectorID: cn, Class: "identity", Kind: "iam_role",  RequiredSurfaces: []string{models.SurfaceIAMRoles}},
        {ScopeID: sc, ConnectorID: cn, Class: "identity", Kind: "iam_user",  RequiredSurfaces: []string{models.SurfaceIAMUsers}},
        {ScopeID: sc, ConnectorID: cn, Class: "identity", Kind: "iam_group", RequiredSurfaces: []string{models.SurfaceIAMGroups}},

        // Policies, statements and resource references come from the same
        // read and reconcile on the same evidence.
        {ScopeID: sc, ConnectorID: cn, Class: "policy",      RequiredSurfaces: iam, RequiredScanners: veto},
        {ScopeID: sc, ConnectorID: cn, Class: "entitlement", RequiredSurfaces: perm, RequiredScanners: veto},
        {ScopeID: sc, ConnectorID: cn, Class: "resource",    RequiredSurfaces: perm, RequiredScanners: veto},

        {ScopeID: sc, ConnectorID: cn, Target: "assignment",  RequiredSurfaces: iam,  RequiredScanners: veto},
        {ScopeID: sc, ConnectorID: cn, Target: "access_edge", RequiredSurfaces: perm, RequiredScanners: veto},
        {ScopeID: sc, ConnectorID: cn, Target: "relationship", RelationshipType: "member_of",
            RequiredSurfaces: []string{models.SurfaceIAMUsers, models.SurfaceIAMGroups}},
        {ScopeID: sc, ConnectorID: cn, Target: "relationship", RelationshipType: "can_assume", Kind: "trust",
            RequiredSurfaces: []string{models.SurfaceIAMRoles}, RequiredScanners: veto},
        {ScopeID: sc, ConnectorID: cn, Target: "relationship", RelationshipType: "can_assume", Kind: "eks_pod_identity",
            RequiredSurfaces: []string{models.SurfaceEKSPodIdentity, models.SurfaceIAMRoles}, RequiredScanners: veto},
    }

    // Workloads: per SERVICE per REGION — the grain the scanner reports at.
    // compute:<region> appears only on failure or not_selected, so it is a
    // veto (presence = failure), never a required surface.
    for _, region := range snap.RegionsAttempted() {
        gate := []string{models.SurfaceWorkloadScan, models.SurfaceCompute + ":" + region}
        for _, svc := range workloadServices { // lambda, ecs, ec2, bedrock-agents, bedrock-agentcore, agentcore-gateways
            surf := svc + ":" + region
            ps = append(ps,
                Partition{ScopeID: sc, ConnectorID: cn, Class: "workload", Kind: svc, Region: region,
                    RequiredSurfaces: []string{surf}, RequiredScanners: gate},
                Partition{ScopeID: sc, ConnectorID: cn, Target: "relationship", RelationshipType: "executes_as",
                    Kind: svc, Region: region,
                    RequiredSurfaces: []string{surf, models.SurfaceIAMRoles}, RequiredScanners: gate})
        }
        ps = append(ps, Partition{ScopeID: sc, ConnectorID: cn, Target: "relationship",
            RelationshipType: "task_execution_role", Kind: "ecs", Region: region,
            RequiredSurfaces: []string{"ecs:" + region, models.SurfaceIAMRoles}, RequiredScanners: gate})
    }
    return ps
}
```

**Unreadable documents are protected row by row.** A partition's `canEnd`
decides for the whole partition, and treating one unreadable document as a
veto would freeze every statement and grant in the account. That is too
coarse — a statement in a policy that was read is fully known — so
`policy_documents` is **not** a required surface of the policy, statement,
resource, assignment, grant or trust partitions. But the projector skips an
unreadable document's statements, so without protection its unconfirmed rows
would look absent to a partition that *can* end. **Protection is therefore
explicit, and applied inside every reconciliation update:**

```go
// Exclusions are computed by the projector, in graph ids, and passed to
// Reconcile in the same transaction. They name what an unreadable document
// declared, so reconciliation can never end it.
type Exclusions struct {
    UnreadablePolicies []uuid.UUID // iga_policy ids whose document was unreadable this run
    UnreadableTrust    []uuid.UUID // iga_identity_accounts ids of roles whose trust document did not parse
}

// protected returns the predicate for rows of this partition that an
// unreadable document declared. Exhaustive: every partition answers.
func protected(part Partition, ex Exclusions) (sql string, args []any, ok bool) {
    pol := ex.UnreadablePolicies
    switch {
    case part.Target == "access_edge":
        return `entitlement_id IN (SELECT id FROM iga_entitlements
                  WHERE workspace_id = iga_access_edges.workspace_id AND policy_id = ANY(?))`,
            []any{pq.Array(pol)}, len(pol) > 0
    case part.Target == "relationship" && part.RelationshipType == "can_assume" && part.Kind == "trust":
        return `target_identity_account_id = ANY(?)`, []any{pq.Array(ex.UnreadableTrust)}, len(ex.UnreadableTrust) > 0
    case part.Class == models.ObjectEntitlement:
        return `entitlement_id IN (SELECT id FROM iga_entitlements
                  WHERE workspace_id = iga_object_support.workspace_id AND policy_id = ANY(?))`,
            []any{pq.Array(pol)}, len(pol) > 0
    case part.Class == models.ObjectResource:
        // A resource another statement still names is confirmed anyway; one
        // named ONLY by an unreadable policy must not lose this source's support.
        return `resource_id IN (SELECT t.resource_id FROM iga_entitlement_target t
                  JOIN iga_entitlements e ON e.workspace_id = t.workspace_id AND e.id = t.entitlement_id
                  WHERE t.workspace_id = iga_object_support.workspace_id AND e.policy_id = ANY(?))`,
            []any{pq.Array(pol)}, len(pol) > 0
    default:
        // identities, workloads, policies (still listed by authorization
        // details), assignments (attachment lists are read independently of
        // documents), member_of, executes_as, pod-identity can_assume
        return "", nil, false
    }
}
```

Both update paths apply it. When a partition **can** end, protected rows that
this run did not confirm are moved `current → stale` (last confirmation kept)
**before** the end statement runs, and the end statement excludes them. When it
cannot end, everything unconfirmed goes stale anyway. So an unreadable
document's grants, statements, and the support of resources only it names are
never ended; a genuinely detached policy in the same account still ends. A
`policy_documents` failure the scanner could **not** attribute to a document
(the scanner died) remains a partition veto through `permission_scan`.

**Trace the gate against these definitions, not against the struct.** The
fixture below must close nothing, and it only does so because the entitlement
and access-edge partitions name `permission_scan` in `RequiredScanners`:

| Surface | State | Effect |
|---|---|---|
| `iam_roles` | `reached` | identity partitions may close |
| `iam_policies` | `reached` | — |
| `permission_scan` | `denied` | **vetoes** entitlement, `can_assume`, access-edge |
| `policy_documents` | absent | would otherwise read as "nothing was dropped" |

```go
// PartitionFor returns the Partition that evidences a row of this class, from
// the SAME list Partitions() builds -- looked up, never reconstructed. That is
// the property that matters: the partition_key the projector stamps on a row
// and the one reconciliation filters by are the same value by construction,
// so a row cannot be written under one key and reconciled under another.
//
//   identity  -> by kind:          iam_role -> iam_roles, iam_user -> iam_users
//   workload  -> by kind + region: lambda_function + eu-central-1
//                -> lambda:eu-central-1, via workloadSurfacePrefix
//   resource, entitlement -> the single permission-scan partition
//
// A class/kind/region with no partition is a programming error and panics in
// tests. It must never fall back to a default partition: a row filed under
// the wrong partition is reconciled against the wrong surface, and a clean
// read of one surface would then license ending rows another surface owns.
func (s *Snapshot) PartitionFor(class, kind, region string) Partition {
    for _, p := range s.partitions { // built once, by Partitions(s), in Load
        if p.Matches(class, kind, region) {
            return p
        }
    }
    panic(fmt.Sprintf("no partition for class=%q kind=%q region=%q", class, kind, region))
}
```

```go
// EdgePartitionFor is PartitionFor's counterpart for edges, over the same
// list. Nodes key on Class; edges on RelationshipType or Target.
func (s *Snapshot) EdgePartitionFor(relOrTarget, kind, region string) Partition

// Matches is the membership predicate both lookups use. It is the ONLY place
// that decides which partition a row belongs to.
func (p Partition) Matches(class, kind, region string) bool {
    if p.Class != class {
        return false
    }
    switch class {
    case models.ObjectIdentity:
        // iam_role -> iam_roles, iam_user -> iam_users
        return len(p.RequiredSurfaces) > 0 && p.RequiredSurfaces[0] == identitySurface(kind)
    case models.ObjectWorkload:
        // NOT kind+":"+region. RuntimeKind and the surface prefix are
        // different vocabularies -- lambda_function vs lambda: -- so string
        // concatenation never matches and every workload would panic here.
        prefix, ok := workloadSurfacePrefix[kind]
        return ok && len(p.RequiredSurfaces) > 0 && p.RequiredSurfaces[0] == prefix+":"+region
    default:
        return true // resource, entitlement: one partition per connector
    }
}

// workloadSurfacePrefix maps cloud_workload.RuntimeKind to the prefix its
// coverage surface is reported under. Verified against the collector at
// 0e75ad7: cloud_aws_workload_scan.go:268-298 (scanRegion, scanGateways).
//
// Keep it exhaustive. A RuntimeKind missing here makes PartitionFor panic in
// tests, which is the point -- a new runtime kind must be given a partition
// deliberately, not fall into a default that reconciles it against the
// wrong surface.
var workloadSurfacePrefix = map[string]string{
    "lambda_function":           "lambda",
    "ecs_task_definition":       "ecs",
    "ec2_instance":              "ec2",
    "bedrock_agent":             "bedrock-agents",
    "bedrock_agentcore_runtime": "bedrock-agentcore",
    "bedrock_agentcore_gateway": "agentcore-gateways",
}

// Key is the partition's stable identity and the value stamped on every row.
// Deterministic from the struct: scope, connector, class, relationship type,
// target, and the SORTED required surfaces, joined with Sep.
func (p Partition) Key() string

// retiredKey is the restoration lookup: (source_key, immutable_key). Both,
// because the recognition key alone would restore a RECREATED object.
func retiredKey(sourceKey, immutableKey string) string {
    return sourceKey + Sep + immutableKey
}

// endpointKey is what edge source_keys use for an identity endpoint: the
// immutable key when the identity has one, the source key otherwise. This is
// what makes a recreated role under the same ARN produce a DIFFERENT edge key.
func endpointKey(snap *Snapshot, cloudIdentityID uuid.UUID) string {
    ci := snap.IdentityByID(cloudIdentityID)
    if imm := ImmutableKey(ci); imm != "" {
        return Key("aws", "uid", imm)
    }
    return IdentityKey(ci)
}
```

**Repository contracts named but not written out.** These share one shape,
given in full by `UpsertIdentity` in §4.9 — `ON CONFLICT` on the partial
unique index with `TargetWhere`, `DoUpdates` naming only descriptive columns,
`Returning("id")` so the surviving row's id comes back:
`UpsertResource`, `UpsertPolicy`, `UpsertStatement`, `UpsertAssignment`,
`UpsertGrant`, `UpsertRelationship`, `UpsertExternalPrincipal`,
`UpsertProjectionState`, and the `Link*Evidence` functions.

Three are **not** that shape, and are specified here because each carries a
guard that is easy to lose:

| Contract | Guard it must carry |
|---|---|
| `UpsertSupport` | Conflict target is the **typed** partial index for the row's class. `DoUpdates` sets `state='current'`, `ended_reason=''`, `last_confirmed_run_id`, `last_confirmed_at` — clearing `ended_reason` is what makes reappearance correct. Never `first_seen_at` |
| `RestoreIdentity` | `UPDATE … SET lifecycle='active', retired_reason='', display_name=?, account_kind=?, last_seen_at=? WHERE id=? AND lifecycle='retired' AND retired_reason='unsupported' AND immutable_key=? RETURNING id`. **Zero rows is `ErrNotRestorable`**, never a fallback insert — a concurrent restore or a recreated row must not be silently restored. Refreshes descriptive fields; never touches `first_seen_at` or classification |
| `AssertOwnedTx` | `SELECT … FOR UPDATE FROM iga_pipeline_lease WHERE workspace_id=? AND state=? AND version=?` plus the job row `WHERE id=? AND lease_version=?`. Zero rows on either is `ErrLeaseLost`. **Phase, job and version, all four** |
| `PublicationForRun` | `SELECT rev FROM iga_publication WHERE workspace_id=? AND scan_run_id=?`, **inside** the graph transaction after `AssertOwnedTx`. Its answer is only trustworthy because `InsertPublication` commits in the same transaction as the graph |
| `InsertPublication` | `rev = max(rev)+1` for the workspace, computed while `AssertOwnedTx` holds the barrier row `FOR UPDATE`. `UNIQUE (workspace_id, scan_run_id)` backstops a double publish |
| `CompleteTx` / `ReleaseTx` | Always called together, in that order, in one transaction (`completeAndRelease`). Each is fenced; each returns `ErrLeaseLost` on zero rows |
| `SuspendAssertions` | `UPDATE iga_external_principal SET resolution_state='suspended' WHERE resolution_basis='asserted' AND resolution_state='active' AND resolved_…_id=?`. **Asserted rows only** — derived rows are re-derived, never suspended |
| `MarkAssertionsPendingReconfirm` | Same predicate, from `suspended` to `pending_reconfirmation`. Never to `active`: restoring a record never renews a person's decision |
| `RecordRevision` | Only for Sid-keyed statements. If the live revision's hash equals the new hash, touch nothing; otherwise close it (`valid_to = now`) and insert the new one, same transaction. Never rewrites a closed revision |
| `ReplaceTargets` | Deletes and re-inserts the statement's targets **only when its content hash changed**; an unchanged statement's targets are not touched, so evidence and ids stay stable |
| `UpsertGrant` | Refuses (returns an error, the pass fails) if the statement's effect is not `allow` — the projector's rule, checked again at the write |
| `SetExecutionRoleState` | Called for **every projected** workload on every pass, **after** the endpoint is determined. Writes the state and the ARN together, so the `CHECK` pairing them can never be violated mid-update. Never skipped, so no earlier run's state survives |
| `Snapshot.IdentityNativeID` | Native id of any `cloud_identity` a workload references, **regardless of generation** — loaded in `Load` by one `WHERE id IN (…)` over the snapshot's workload identity ids. It is how `not_in_scan` still names the role |

Everything else called in §4 without a body (`orStar`, `keyOf`, `byIDOf`,
`resourceKeyOf`, `nativeRightsOf`, `normalizeRights`, `now`, `stop`) is
mechanical and has no correctness property beyond its name.

> **Assert the vocabulary at startup.** Every `RequiredSurfaces` entry except
> `policy_documents` must appear in the AWS coverage manifest (roadmap §2.3).
> A partition naming a surface no report ever contains can never satisfy
> `canEnd`, so its relationships stay `stale` **forever** — silent, and it
> looks like working caution. Fail loudly on a typo.

#### `canEnd`, corrected

```go
func (rc *Reconciler) canEnd(snap *Snapshot, part Partition) bool {
    if snap.Run.Status != models.CloudScanRunPublished {
        return false
    }

    // POSITIVE EVIDENCE THAT THE SCANNER RAN, FIRST.
    //
    // policy_documents is written ONLY when parsing dropped something
    // (cloud_aws_permission_scan.go:226), so its absence is ambiguous: either
    // parsing was clean, or parsing never happened. This fixture must NOT
    // license closing anything, and a bare "absent means clean" rule lets it:
    //
    //     iam_roles        reached
    //     iam_policies     reached
    //     permission_scan  denied      <- the scanner died before parsing
    //     policy_documents absent
    //
    // permission_scan / workload_scan are written by FinalizeCoverage only
    // when a scanner failed before producing a snapshot at all
    // (cloud_aws_iam_scan.go:795, :803). Their PRESENCE is therefore proof of
    // failure, and must veto every partition that depends on that scanner.
    for _, gate := range part.RequiredScanners { // e.g. "permission_scan"
        if cov, ok := snap.Coverage[gate]; ok && cov.State != models.CloudCoverageReached {
            return false
        }
    }

    for _, name := range part.RequiredSurfaces {
        cov, ok := snap.Coverage[name]

        if name == models.SurfacePolicyDocuments {
            // Only meaningful once RequiredScanners has established that the
            // permission scanner actually ran. Present => something was
            // dropped; absent => nothing was.
            if ok && cov.State != models.CloudCoverageReached {
                return false
            }
            continue
        }

        // Every other surface: absent report == did not look.
        if !ok || cov.State != models.CloudCoverageReached {
            return false
        }
    }
    return true
}
```

**`SurfaceCoverage` has exactly three fields — `State`, `Count`, `Error`.**
There is no `ParseFailures` and no `StatementsSkipped` on it; those counters
live on the permission scanner's own result and are folded into the
`policy_documents` surface before publish. Reading them off a surface struct
does not compile, and reading only `iam_roles: reached` misses the failure
entirely.

**Generations are per connector.** `snap.Generation` is
`cloud_scan_run.Generation` for one connector's run. Two connectors in one
workspace advance independently, so a generation number is only comparable
within `part.ConnectorID`. Never order two integrations' generations against
each other.

#### The updates, scoped to the partition

```go
// reconcileEdges is the edge half of Reconcile: stale when we could not look,
// ended when we could and it was not there.
func (rc *Reconciler) reconcileEdges(tx *gorm.DB, part Partition, snap *Snapshot, ex Exclusions, stale bool) error {
    if stale {
        return rc.markStale(tx, part, snap, "")
    }
    // Protected rows first: stale, never ended (§4.10, unreadable documents).
    if p, args, ok := protected(part, ex); ok {
        if err := rc.markStale(tx, part, snap, p, args...); err != nil {
            return err
        }
        return rc.endOlderThan(tx, part, snap, "not_seen", "NOT ("+p+")", args...)
    }
    return rc.endOlderThan(tx, part, snap, "not_seen", "")
}

// markStale: we could not look at THIS partition.
//
// Two rules, both learned the hard way:
//   - Rows this run DID confirm are excluded. Without that, a denied
//     us-west partition marks us-east's freshly-confirmed relationships
//     stale as well, because the update matched on partition membership
//     alone.
//   - last_confirmed_at is NOT touched. It is the honest answer to "how old
//     is this?", and refreshing it would launder an outage into a
//     confirmation.
func (rc *Reconciler) markStale(tx *gorm.DB, part Partition, snap *Snapshot, extra string, args ...any) error {
    q, err := rc.scope(tx, part, snap)
    if err != nil {
        return err
    }
    q = q.Where("state = ?", models.RelCurrent).
        Where("last_confirmed_by IS DISTINCT FROM ?", snap.Run.ID)
    if extra != "" {
        q = q.Where(extra, args...)
    }
    return q.Update("state", models.RelStale).Error
}

// endOlderThan: we looked properly at this partition and it was not there.
func (rc *Reconciler) endOlderThan(tx *gorm.DB, part Partition, snap *Snapshot, reason, extra string, args ...any) error {
    q, err := rc.scope(tx, part, snap)
    if err != nil {
        return err
    }
    if extra != "" {
        q = q.Where(extra, args...) // "NOT (<protected>)"
    }
    return q.
        Where("state <> ?", models.RelEnded).
        // IS DISTINCT FROM, never <>. last_confirmed_by is nullable, and
        // NULL <> uuid evaluates to NULL rather than true -- a plain <> would
        // silently skip every row that never carried a run id and leave
        // pre-graph rows `current` forever.
        Where("last_confirmed_by IS DISTINCT FROM ?", snap.Run.ID).
        Updates(map[string]any{
            "state":        models.RelEnded,
            "valid_to":     snap.CompletedAt,
            "ended_reason": reason, // never empty: 031's CHECK enforces it
        }).Error
}
```

#### Partition membership is stored, not inferred

`scope()` cannot be a join through endpoint tables. Three reasons:

- Filtering on `(workspace_id, relationship_type)` ends **another account's**
  relationships, because a scan of account A does not confirm account B's.
- Adding only `estate_scope_id` still crosses **regions and connectors**: a
  clean `lambda:us-east-1` read would license closing `lambda:eu-west-1`
  relationships in the same account.
- The endpoint union has to enumerate every source type, and missing one
  silently excludes it — `can_assume` can start at an external principal,
  which a union of workloads and identities does not contain, so those rows
  would never reconcile at all.

So membership is **written at projection time and queried directly**. Each
relationship, assignment and grant records the partition that produced it:

The columns are created in migrations `030` (`iga_access_edges`), `031`
(`iga_relationship`) and `036` (`iga_policy_assignment`); the fragment below
shows their shape only. A unit test asserts every `Target` that `Partitions()`
emits resolves in `scope()`.

```sql
-- EDGES ONLY: 030 (iga_access_edges) and 031 (iga_relationship).
--
-- Nodes deliberately do NOT get these columns. A resource or managed-policy
-- entitlement can be supported by several connectors at once, so a single
-- connector_id on the node makes the last scanner its apparent owner and lets
-- that scanner retire an object another account still holds (§2.10B). Node
-- membership lives in iga_object_support, one row per supporting source.
partition_key   text NOT NULL DEFAULT '',
connector_id    uuid,
CONSTRAINT …_connector_fkey FOREIGN KEY (workspace_id, connector_id)
    REFERENCES public.cloud_connector (workspace_id, id) ON DELETE SET NULL (connector_id),
```

```go
// scope selects exactly the rows this partition is responsible for, by the
// membership the projector stamped on them. No joins, no endpoint union, no
// type it can silently omit.
func (rc *Reconciler) scope(tx *gorm.DB, part Partition, snap *Snapshot) (*gorm.DB, error) {
    // EXHAUSTIVE. A default that fell through to iga_relationship would send
    // an assignment partition to the wrong table: grants would end, their
    // assignment would stay current, and a reattach would revive the old period.
    var model any
    switch part.Target {
    case "relationship":
        model = &models.IGARelationship{}
    case "assignment":
        model = &models.IGAPolicyAssignment{}
    case "access_edge":
        model = &models.IGAAccessEdge{}
    default:
        return nil, fmt.Errorf("partition %s: no edge table for target %q", part.Key(), part.Target)
    }
    return tx.Model(model).
        Where("workspace_id = ? AND connector_id = ? AND partition_key = ?",
            snap.Run.WorkspaceID, part.ConnectorID, part.Key()), nil
}
```

`partition_key` is `Partition.Key()` — the same value `iga_projection_state`
is keyed on — so "what this run reconciles" and "what this run recorded a
watermark for" are the same set by construction, rather than two predicates
that have to be kept in agreement.

**Node classes reconcile nodes.** A partition whose `Class` is `identity`,
`workload` or `resource` and whose `Target` is empty acts on that node table's
`lifecycle`, retiring rows the run did not confirm — it must not fall through
to `iga_relationship` with an empty relationship type, which matches nothing
and silently reconciles nothing:

**Nodes reconcile through their support rows, in two steps.** Never directly:
a node touched by this partition may still be held by another account.

```go
// supportColumn maps a node class to its typed column on iga_object_support.
// The single place that mapping lives: the projector's upsert, the conflict
// target, reconcileNodes and retireUnsupported all go through it.
func supportColumn(class string) (string, error) {
    switch class {
    case models.ObjectIdentity:    return "identity_account_id", nil
    case models.ObjectWorkload:    return "workload_id", nil
    case models.ObjectResource:    return "resource_id", nil
    case models.ObjectEntitlement: return "entitlement_id", nil
    case models.ObjectPolicy:      return "policy_id", nil
    }
    return "", fmt.Errorf("no support column for node class %q", class)
}

// externalResolutionColumn names the iga_external_principal column that can
// point at a node of this class. Only identities and workloads can be the
// target of a trust relationship, so only they appear.
var externalResolutionColumn = map[string]string{
    models.ObjectIdentity: "resolved_identity_account_id",
    models.ObjectWorkload: "resolved_workload_id",
}

// nodeTable is supportColumn's partner. Both switch on the same class set, so
// adding a node class is one edit in two adjacent functions -- and a unit
// test asserts every entry in models.NodeClasses resolves in both.
func nodeTable(class string) string {
    switch class {
    case models.ObjectIdentity:    return "iga_identity_accounts"
    case models.ObjectWorkload:    return "iga_workload"
    case models.ObjectResource:    return "iga_resources"
    case models.ObjectEntitlement: return "iga_entitlements"
    case models.ObjectPolicy:      return "iga_policy"
    }
    panic("unmapped node class " + class)
}

// Step 1 -- end this partition's SUPPORT, not the object.
func (rc *Reconciler) reconcileNodes(tx *gorm.DB, part Partition, snap *Snapshot, ex Exclusions, stale bool) error {
    // The partition's class selects WHICH typed column is populated. There is
    // no object_type to compare against -- the typed column's non-nullness is
    // the type, and the database enforces that exactly one is set.
    col, err := supportColumn(part.Class) // "identity_account_id", "workload_id", ...
    if err != nil {
        return err // an unmapped class is a programming error, never a no-op
    }
    q := tx.Model(&models.IGAObjectSupport{}).
        Where("workspace_id = ? AND connector_id = ? AND partition_key = ?",
            snap.Run.WorkspaceID, part.ConnectorID, part.Key()).
        Where(col + " IS NOT NULL").
        Where("state <> ?", models.RelEnded).
        Where("last_confirmed_run_id IS DISTINCT FROM ?", snap.Run.ID)

    if stale {
        return q.Where("state = ?", models.RelCurrent).
            Update("state", models.RelStale).Error
    }
    // Support declared only by an unreadable document: stale, never ended.
    if p, args, ok := protected(part, ex); ok {
        if err := q.Session(&gorm.Session{}).Where("state = ?", models.RelCurrent).Where(p, args...).
            Update("state", models.RelStale).Error; err != nil {
            return err
        }
        q = q.Where("NOT ("+p+")", args...)
    }
    return q.Updates(map[string]any{
        "state": models.RelEnded, "ended_reason": "not_seen",
    }).Error
}

// Step 2 -- derive each object's lifecycle from what support REMAINS.
// Same transaction, after every partition's support has been reconciled, so
// an object is retired only when no source anywhere still holds it.
func (rc *Reconciler) retireUnsupported(tx *gorm.DB, snap *Snapshot) error {
    // One statement per node table, each joined on ITS OWN typed support
    // column. There is no object_type/object_id to switch on -- 032 made
    // support typed precisely so a support row cannot point at a missing or
    // foreign-workspace object -- so the join column is fixed per table.
    for _, class := range models.NodeClasses { // identity, workload, resource, entitlement, policy
        col, err := supportColumn(class)
        if err != nil {
            return err
        }
        t := struct{ table, col string }{nodeTable(class), col}
        // The first EXISTS matters: an object with NO support rows at all is
        // pre-graph, not unsupported, and must not be retired by this pass --
        // 035 handles those deliberately.
        stmt := fmt.Sprintf(`
            UPDATE %[1]s n
               SET lifecycle = 'retired', retired_reason = 'unsupported', updated_at = now()
             WHERE n.workspace_id = $1
               AND n.lifecycle = 'active'
               AND EXISTS (SELECT 1 FROM iga_object_support s
                            WHERE s.workspace_id = n.workspace_id AND s.%[2]s = n.id)
               AND NOT EXISTS (SELECT 1 FROM iga_object_support s
                                WHERE s.workspace_id = n.workspace_id AND s.%[2]s = n.id
                                  AND s.state <> 'ended')
            RETURNING n.id`, t.table, t.col)
        var retired []uuid.UUID
        if err := tx.Raw(stmt, snap.Run.WorkspaceID).Scan(&retired).Error; err != nil {
            return fmt.Errorf("retire unsupported %s: %w", t.table, err)
        }

        // A person's association with an object that just retired is
        // SUSPENDED, not left active and not cleared (§2.12). This is the
        // reconciler-side twin of the projector's recreation branch: two
        // paths retire nodes, and both must suspend, or a human assertion
        // stays in force pointing at a row that is gone.
        if epCol, ok := externalResolutionColumn[class]; ok && len(retired) > 0 {
            if err := tx.Exec(`
                UPDATE iga_external_principal
                   SET resolution_state = 'suspended'
                 WHERE workspace_id = ? AND resolution_basis = 'asserted'
                   AND resolution_state = 'active' AND `+epCol+` IN ?`,
                snap.Run.WorkspaceID, retired).Error; err != nil {
                return fmt.Errorf("suspend assertions on retired %s: %w", t.table, err)
            }
            // DERIVED resolutions to a retired target are re-derived HERE,
            // not left for the next projection. The resolution pass runs
            // during projection, BEFORE this reconcile step, so without this
            // a derived resolution would stay in force pointing at a retired
            // row for a whole scan cycle. Re-deriving against current evidence
            // -- the target no longer exists -- means unresolved.
            if err := tx.Exec(`
                UPDATE iga_external_principal
                   SET `+epCol+` = NULL, resolution_basis = '', resolution_rule = ''
                 WHERE workspace_id = ? AND resolution_basis = 'derived'
                   AND `+epCol+` IN ?`,
                snap.Run.WorkspaceID, retired).Error; err != nil {
                return fmt.Errorf("re-derive resolutions on retired %s: %w", t.table, err)
            }
        }
    }
    return nil
}
```

Retiring a node ends what depends on it, in the same transaction:

| Retired | Ends | `ended_reason` |
|---|---|---|
| Identity | Its relationships, assignments and grants | `subject_retired` |
| Workload | Its `executes_as` / `task_execution_role` | `subject_retired` |
| Policy | Its assignments, and their grants | `policy_retired` |
| Statement | Its grants | `statement_retired` |
| Resource reference | Nothing: targets are statement content, and a resource retires only when no statement anywhere names it |  |

Every retirement here, and every restoration and first insert in the node
passes, appends to the projection's lifecycle event log (`iga_lifecycle_event`,
`036`), so the Changes view can say when and why after the node row itself has
been overwritten.

#### The node write contract, stated once

Every node pass — identities, workloads, resources, entitlements — does
exactly this, and the examples in §4.6 and §4.7 are instances of it:

1. **Upsert the node** on `(workspace_id, source_key)`. `DoUpdates` names only
   descriptive columns and `last_seen_at`. It never touches `first_seen_at`,
   `lifecycle`, or human-owned state.
2. **Upsert its support row** on
   the typed conflict target for its class — e.g.
   `(workspace_id, identity_account_id, connector_id, partition_key) WHERE
   identity_account_id IS NOT NULL` — which must be passed as GORM's
   `TargetWhere`, because the unique index is partial (§4.9),
   setting `state='current'`, `last_confirmed_run_id = run.ID`,
   `last_confirmed_at = now`. **This is the step that makes the node visible
   to reconciliation** — a node written without it is never reconciled, and a
   support row written without the run id is treated as unseen on the next
   pass.
3. **Return the node id** into `resolved`, so edges can reference it.

A node pass that does 1 and 3 but not 2 compiles, passes an unchanged-rescan
test, and silently never reconciles. It is the single easiest thing to get
wrong here, which is why it is a numbered contract and not a comment.



**Access edges are reconciled, not just relationships.** The `access_edge`
partition is what makes *"detach a managed policy from one of two roles and
only that role's grant ends"* actually happen: the detached role's edge is not
confirmed by this run, the surviving role's is, and the shared entitlement is
untouched because entitlements are reconciled on their own partition.

```go
func (rc *Reconciler) lastGenerationFor(tx *gorm.DB, part Partition, ws uuid.UUID) (int64, error) {
    var st models.IGAProjectionState
    // Keyed exactly as 033 keys the table, and exactly as scope() filters
    // rows -- one value, three call sites, no predicate to keep in agreement.
    err := tx.Where("workspace_id = ? AND connector_id = ? AND partition_key = ?",
        ws, part.ConnectorID, part.Key()).First(&st).Error
    if errors.Is(err, gorm.ErrRecordNotFound) {
        return 0, nil
    }
    return st.LastGeneration, err
}
```

`iga_projection_state`'s unique key (033) must include the partition's surface
key, not just `(scope, class, relationship_type)` — otherwise roles and users
share one watermark row, as do every region's workloads, and one partition's
progress overwrites another's.

### 4.11 The service loop

`services/iga_projection_service.go`, built on the graph branch and kept, with
the corrections below. It mirrors `AWSScanWorker` (`Run` / `RunOnce` /
`heartbeat`) so there is one worker shape in the codebase.

```go
func (s *ProjectionService) RunOnce(ctx context.Context) (bool, error) {
    job, err := s.jobs.Claim(s.owner, s.lease)   // fenced exactly like cloud_scan_run
    if err != nil || job == nil {
        return false, err
    }
    stop := s.heartbeat(ctx, job)                 // Renew on a ticker
    defer stop()

    // Staleness is NOT checked here. A check before the read is stale by the
    // time the read runs; Load performs it inside the same repeatable-read
    // snapshot as the inventory queries and returns ErrSuperseded.

    snap, err := igagraph.Load(ctx, s.db, job.ScanRunID)
    if errors.Is(err, igagraph.ErrSuperseded) {
        // Detected inside the snapshot, which is the only place it can be
        // detected reliably. Recorded, not silent: a permanently-losing job
        // must not look like one that never ran.
        return true, s.abandonAndRelease(ctx, job, "superseded during load")
    }
    if err != nil {
        return true, s.failKeepBarrier(ctx, job, err)
    }

    // Project AND reconcile in ONE transaction. Committing projection first
    // publishes a graph in which nothing has been closed yet -- every stale
    // edge still reads `current` -- and a crash in between leaves it that way
    // until the next run. One transaction means readers see the before state
    // or the after state, never the gap.
    err = s.projectAndReconcile(ctx, snap, job)

    // A replay of a run that already committed is SUCCESS, not failure.
    // The graph transaction wrote nothing on this attempt (§4.6 step 2), so
    // there is nothing to undo -- only the job and the barrier to settle,
    // in the same order and transaction as a normal completion.
    var done *igagraph.AlreadyPublished
    if errors.As(err, &done) {
        return true, s.completeAndRelease(ctx, job, done.Rev)
    }
    if errors.Is(err, igagraph.ErrSuperseded) {
        return true, s.abandonAndRelease(ctx, job, "superseded by a newer publication")
    }
    if err != nil {
        // Fail, do not Complete. The lease expires, the job is reclaimed, and
        // projection is idempotent -- so a retry converges. A job marked
        // complete after a partial write is unrecoverable without a manual
        // rebuild.
        return true, s.failKeepBarrier(ctx, job, err)
    }
    return true, s.completeAndRelease(ctx, job, 0)
}

// completeAndRelease is the ONLY way a projection leaves the `projecting`
// phase successfully. One transaction, fenced, in this order:
//
//   1. job           running  -> complete   (fenced on job lease_version)
//   2. barrier       projecting -> idle     (fenced on phase + version)
//
// Job first, barrier second, both in one transaction: there is no committed
// state in which the barrier is idle while the job could still commit. A
// crash BEFORE this commits leaves both as they were, and recovery reclaims
// `projecting`; its replay then hits AlreadyPublished and lands here again.
// Idempotent by construction, because every step is fenced.
//
// There are exactly three exits from a claimed projection job, and each has
// ONE implementation. No path terminalizes a job or moves the barrier except
// through these:
//
//   completeAndRelease  job complete  + barrier idle      (success, or replay)
//   abandonAndRelease   job abandoned + barrier idle      (superseded, or past the ceiling)
//   failKeepBarrier     job failed    + barrier UNCHANGED (transient; will be retried)
//
// FENCING IS WHAT MAKES "never release someone else's barrier" TRUE. Both
// writes in a *AndRelease are fenced -- the job on its lease_version, the
// barrier on (workspace, phase, job, version) -- and they share one
// transaction. If recovery has already reclaimed either one, that fence
// matches zero rows, the transaction rolls back, and THIS worker changes
// nothing. The current owner decides the outcome. A superseded worker never
// terminalizes a job or releases a barrier it no longer holds.

func (s *ProjectionService) abandonAndRelease(ctx context.Context,
    job *models.IGAProjectionJob, reason string) error {
    return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
        if err := s.jobs.AbandonTx(tx, job.ID, s.owner, job.LeaseVersion, reason); err != nil {
            return err // ErrLeaseLost: not ours any more -- change nothing
        }
        return s.pipeline.ReleaseTx(tx, PipelineFence{
            WorkspaceID: job.WorkspaceID, Phase: models.PipelineProjecting,
            JobID: job.ID, Version: s.pipelineVersion,
        })
    })
}

// failKeepBarrier records a TRANSIENT failure and deliberately leaves the
// barrier `projecting`. The job is not terminal: it is reclaimed and retried,
// and its inventory must stay frozen until it succeeds -- releasing here would
// admit a scan while this projection is still pending, which is the overwrite
// the barrier exists to prevent.
//
// Past the attempts ceiling it is no longer transient, and escalates to
// abandonAndRelease: the job becomes terminal and the workspace is unblocked,
// with the failure recorded and alerting on it.
func (s *ProjectionService) failKeepBarrier(ctx context.Context,
    job *models.IGAProjectionJob, cause error) error {
    if job.Attempts >= s.maxAttempts {
        return s.abandonAndRelease(ctx, job,
            fmt.Sprintf("gave up after %d attempts: %v", job.Attempts, cause))
    }
    return s.jobs.Fail(job, s.owner, job.LeaseVersion, cause.Error()) // fenced; barrier untouched
}

func (s *ProjectionService) completeAndRelease(ctx context.Context,
    job *models.IGAProjectionJob, rev int64) error {
    return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
        if err := s.jobs.CompleteTx(tx, job.ID, s.owner, job.LeaseVersion); err != nil {
            return err
        }
        return s.pipeline.ReleaseTx(tx, PipelineFence{
            WorkspaceID: job.WorkspaceID, Phase: models.PipelineProjecting,
            JobID: job.ID, Version: s.pipelineVersion,
        })
    })
}
```

```go
// holdBarrier: the barrier must be projecting THIS run and held by THIS job.
// Whoever holds the job's lease may proceed; there is no worker name to match.
func (s *ProjectionService) holdBarrier(job *models.IGAProjectionJob) (int64, error) {
    lease, err := s.pipeline.Get(job.WorkspaceID)
    if err != nil {
        return 0, err
    }
    if lease.State != models.PipelineProjecting ||
        lease.ScanRunID == nil || *lease.ScanRunID != job.ScanRunID ||
        lease.Holder != "job:"+job.ID.String() {
        return 0, fmt.Errorf("%w: barrier is %s/%s for run %v, not this job", repositories.ErrPipelineLost,
            lease.State, lease.Holder, lease.ScanRunID)
    }
    return lease.Version, nil
}
```

**Starting it.** `cmd/main.go` reads `IGA_GRAPH_PROJECTION` once (§2.8). When
`on`, it verifies the schema by the presence of the `036` relations, retrying
on error; only after a **successful** check does it start both the AWS scan
worker in pipeline mode and `ProjectionService.Run`, which claims jobs and runs
`RecoverStalled` on its ticker. When the check keeps failing, neither claims
work and `/capabilities` reports why.

**The heartbeat renews both leases on one tick**, the job's and the
barrier's (`RenewHeld`, without bumping the barrier version), so a long
projection never looks stalled to recovery. The scan worker's heartbeat
likewise renews its `collecting` barrier.

**What readers may see.** Projection, reconciliation and publication commit
together, so the graph moves from one publication to the next with no visible
gap. Readers use the single read contract in §5.1; nothing reads by partition
run ids.

**Failure semantics, stated once:**

| Situation | Behaviour | Why |
|---|---|---|
| Projection errors midway | transaction rolls back, job `failed`, lease expires, reclaimed | Idempotent, so the retry converges. Nothing half-written is visible. |
| Worker is killed | no `Fail` call; lease simply expires | Same recovery path. Fencing on `lease_version` means the dead worker cannot later commit. |
| Lease lost mid-projection | next fenced write returns `ErrLeaseLost`; abort, write nothing further | A superseded worker must not publish. Identical rule to `cloud_scan_run`. |
| Connector generation advanced | `abandoned` with a reason, detected inside the load snapshot | The newer run's job does the work with better data. |
| Lease lost while the graph transaction is open | `AssertOwnedTx` fails, transaction rolls back | A reclaimed worker cannot commit graph mutations. Rejecting `Complete()` afterwards would be too late — the writes would already be visible. |
| One partition's coverage is bad | that partition goes `stale`; others still reconcile | Per-partition is the whole point — a denied Lambda surface must not freeze IAM. |

**Retry is not unbounded.** `attempts` increments on every claim; past a small
ceiling the job stops being claimed and stays `failed` with its last error. A
job that fails deterministically — a bad `source_key`, a CHECK it cannot satisfy
— must stop and be visible, not spin against production forever.

### 4.12 One Lambda, end to end

Concretely, with the values a real scan produces.

**Collected:**

```
cloud_identity   c1a2  kind=iam_role  native_id=arn:aws:iam::1234:role/refund-lambda-role
                 attrs.unique_id=AROA5XK7QEXAMPLE  trust_document={…lambda.amazonaws.com…}
cloud_policy     p9d0  managed  native_id=arn:aws:iam::1234:policy/RefundS3Access
                 policy_id=ANPA7QEXAMPLE  version_id=v2
                 document={"Statement":[{"Sid":"ReadRefunds","Effect":"Allow",
                           "Action":"s3:GetObject","Resource":"arn:aws:s3:::refunds-bucket/*"}]}
cloud_policy_attachment  p9d0 -> c1a2  attached
cloud_workload   b7f0  runtime_kind=lambda_function  identity_id=c1a2
                 native_id=arn:aws:lambda:eu-central-1:1234:function:refund-processor
```

**Projected** (keys shown without the provider prefix):

| Row | `source_key` | Notes |
|---|---|---|
| `iga_identity_accounts` | `arn:aws:iam::1234:role/refund-lambda-role` | `immutable`, `AROA5XK7QEXAMPLE` |
| `iga_workload` | `arn:aws:lambda:eu-central-1:1234:function:refund-processor` | `recognition_only` |
| `iga_policy` | `arn:aws:iam::1234:policy/RefundS3Access` | `customer_managed`, `immutable` on `ANPA7QEXAMPLE` |
| `iga_entitlements` | `…RefundS3Access␟stmt␟sid:ReadRefunds` | `effect=allow`; one revision |
| `iga_resources` | `ref␟arn:aws:s3:::refunds-bucket/*` | `selector`, account and region not stated |
| `iga_entitlement_target` | statement → resource | `mode=resource` |
| `iga_policy_assignment` | `assign␟…RefundS3Access␟uid␟AROA5XK7QEXAMPLE␟attached` | `current` |
| `iga_access_edges` | `grant␟<assignment key>␟<statement key>` | `partial` / `unknown` |
| `iga_relationship` | `executes_as` workload → role | `declared` |
| `iga_relationship` | `can_assume` from external principal `aws_service lambda.amazonaws.com` | `mechanism=sts_assume_role` |

**Rescan, nothing changed.** Every key matches; every upsert takes the
`DO UPDATE` branch; `last_seen_at` advances; `first_seen_at` and every id are
untouched; row counts identical; no revision added.

**The `Sid` statement's action becomes `s3:*`.** Same statement id; its live
revision closes, a new one opens; the grant and its id are unchanged; Changes
shows the before and after.

**The policy is detached.** The assignment and its grant end; the policy, its
statement and resource reference stay while any support holds.

**IAM is denied.** Every IAM partition goes `stale`; zero rows end.

**The role is deleted and recreated with the same name.** A different RoleId:
the old identity retires `recreated`, its edges end `subject_recreated`; a new
identity, with new assignment and grant keys because the endpoint key is the
immutable key.

---

## 5. Read APIs, traversal and read consistency

Everything the console shows comes through this section's contracts. They live
under `/api/iga/v1`, behind `AuthMiddleware`, and every handler takes the
workspace from the token (`c.GetString("workspace_id")`), never from a
parameter. The graph branch's `GET /workloads/:id/access-path` and
`POST /estate/:id/classification` are replaced by the routes below.

### 5.1 The read-consistency contract

One contract, used by every read. There is no other way to read the graph.

**A revision is a workspace publication.** Projection is serialized per
workspace by the barrier, and each projection commit inserts one
`iga_publication` row with `rev = max(rev) + 1`, in the same transaction as
its graph writes (`033`). So `rev` names exactly one committed state of the
workspace's graph. (The per-partition run ids in `iga_publication.manifest`
record which scan each part came from; they are provenance for the Changes and
Coverage views, never a way to read the graph.)

**Every read request runs as one read-only snapshot, under one deadline:**

```go
const requestBudget = 3 * time.Second

func (r *Reader) read(ctx context.Context, ws uuid.UUID, requested *int64,
    fn func(q *Query, rev Revision) error) error {
    // ONE deadline for the whole request, as a context. Every query runs with
    // it, and the driver cancels the in-flight statement when it passes.
    // statement_timeout alone cannot do this: it bounds each statement
    // separately, so ten statements could each take the full allowance.
    ctx, cancel := context.WithTimeout(ctx, requestBudget)
    defer cancel()
    return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
        tx.Exec("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        cur, err := currentRevision(tx, ws) // max(rev), published_at; nil if none
        if err != nil {
            return err
        }
        if requested != nil && (cur == nil || cur.Rev != *requested) {
            return ErrRevisionStale{Requested: *requested, Current: cur}
        }
        return fn(&Query{tx: tx, deadline: deadlineOf(ctx)}, rev(cur))
    })
}

// Optional runs work whose absence the response can state honestly (a total,
// a facet, a neighbour count) inside a SAVEPOINT, with a local statement
// timeout of at most half the remaining budget. If it times out, the
// savepoint is rolled back and the transaction continues in the same
// snapshot. Without the savepoint, a timed-out statement aborts the whole
// transaction and every later query fails.
func (q *Query) Optional(fn func(tx *gorm.DB) error) (ok bool, err error)
```

Verified on PostgreSQL 16 (23 Sep): without a savepoint, a timed-out statement
leaves the transaction aborted and the next query fails; with one, `ROLLBACK
TO SAVEPOINT` recovers and the next query runs in the same snapshot, and the
`SET LOCAL statement_timeout` made inside the savepoint is undone with it.

**What each kind of read does when time or the database fails** — one
contract per response type, so the console never has to guess:

| Situation | Lists and details | Graph (`/graph`, `/graph/expand`, `/graph/path`) |
|---|---|---|
| An **optional** query (total, facet, neighbour count) times out | `200`; `total_known: false` / the facet or count `null` | `200`; that `more.count` is `null`, `exact: false` |
| The **budget runs low** between steps | — (a list page is one mandatory query) | `200` with what was traversed; `truncated.bound_by: "time"`. The traverser checks the remaining deadline before each level and stops while it still has time to answer. Each level's query runs in a savepoint, so a level that times out is rolled back and the previous levels are returned the same way |
| A **mandatory** query fails or the deadline passes | `504 query_timeout`, nothing partial | `504 query_timeout` only if even the root could not be read |
| Any other database error | `500 internal`, nothing partial | `500 internal`, nothing partial |

A truncated graph is a **controlled** answer: it is correct for what it
contains and says where it stopped. A `504` or `500` is a **failure**: the
console shows *Failed* (§2.14.7), never an empty or partial result.

Because the revision check and every data query run in the same
`REPEATABLE READ` snapshot, and a publication commits atomically with its
graph, **a response cannot straddle two publications.** A projection that
commits while a request is in flight is simply not visible to it.

| Request | Response |
|---|---|
| No `rev` | The current revision, echoed as `meta.rev` and `meta.published_at`. The client pins it for the rest of the investigation (§2.14.5) |
| `rev=N`, N current | `200`, `meta.rev = N` |
| `rev=N`, N no longer current | **`409 revision_stale`** — the one stale-revision status and payload, on every route |
| No publication exists yet | `200`, `data` empty, `meta.rev = null`, `meta.graph_state = "not_published"` — a distinct state the console renders as §2.14.7's first-run states, never as "no results" |

```json
HTTP/1.1 409 Conflict
{ "error": { "code": "revision_stale",
             "message": "A newer scan was published.",
             "requested_rev": 41,
             "current_rev": 42,
             "current_published_at": "2026-09-23T14:31:07Z" } }
```

**Cursors bind to what produced them.** A cursor is an opaque, HMAC-signed
token over `{workspace_id, rev, route, filter hash, sort, last sort key and
id}`, plus `classification_seq` when the list filters or sorts on
classification (§5.5). The signing key is the server secret
`IGA_CURSOR_SECRET`.

| Cursor presented with | Response |
|---|---|
| A different workspace, route, filter set or sort | `400 cursor_invalid` |
| A revision that is no longer current | `409 revision_stale` |
| A classification clock that has moved (classification lists only) | `409 listing_changed`, `reason: "classification_changed"` |

**Refresh preserves context without combining revisions.** On `409`, the
console keeps what it shows, offers Refresh, and on Refresh re-requests the
same routes, filters and selections **without** `rev`, so it pins the new
revision and starts every list from its first page (§2.14.5). No response from
one revision is ever merged with another's.

**What history is retained, and what is not.** Relationships, assignments and
grants keep `valid_from`/`valid_to`/`ended_reason` and are never deleted;
statement revisions keep content history; `iga_lifecycle_event` keeps every
node's first seen, retirement (with reason) and restoration, stamped with the
revision; every run keeps its coverage. From these the
Changes view answers *"what changed, and when"*. What is **not** retained: a
relationship's `current`↔`stale` transitions (state is updated in place), node
display attributes over time, and evidence associations over time. So the
product does not reconstruct *"the whole graph as of 1 March"* (§1.2), and no
API accepts a past revision.

### 5.2 References, envelopes and common list behaviour

**Typed references.** A bare UUID never identifies an object on its own. Every
object and claim in a response is a typed reference, `"<type>:<uuid>"`:

| Type | Table | Detail route |
|---|---|---|
| `workload` | `iga_workload` | `/workloads/:id` |
| `identity` | `iga_identity_accounts` (role, user, group) | `/identities/:id` |
| `external_principal` | `iga_external_principal` | `/external-principals/:id` |
| `resource` | `iga_resources` | `/resources/:id` |
| `policy` | `iga_policy` | (shown within identity Permissions) |
| `statement` | `iga_entitlements` (`provider = 'aws'`) | (shown within Permissions and Access) |

| Claim type | Row | What it claims |
|---|---|---|
| `relationship` | `iga_relationship` | `executes_as`, `task_execution_role`, `member_of`, `can_assume` |
| `assignment` | `iga_policy_assignment` | policy applies to holder |
| `grant` | `iga_access_edges` | Allow statement declared for holder |
| `target` | `iga_entitlement_target` | statement names resource |
| `presence` | an object's support rows | the object exists in the named sources |
| `coverage` | `coverage:<run id>:<surface>` | what a run could read |

Route parameters are type-specific (`/identities/:id`), and every handler
checks the id exists **in that table and this workspace**; anything else is
`404 not_found`, with no hint whether it exists elsewhere.

**List envelope**

```json
{ "data": [ … ],
  "meta": {
    "rev": 42, "published_at": "2026-09-23T14:02:11Z", "graph_state": "published",
    "next_cursor": "eyJ2IjoxLC…", "limit": 100,
    "total_known": true, "total": 412,
    "facets": { "account": [ { "value": "220171243705", "label": "production", "count": 301 },
                             { "value": "unknown", "label": "Unknown account", "count": 23 } ] },
    "coverage": [ { "account_id": "905418271234", "surface": "iam_users",
                    "state": "denied", "affects": "identities of kind iam_user" } ] } }
```

**Detail envelope** — distinct, never a one-row list:

```json
{ "data": { "ref": "workload:6f1e…", … },
  "meta": { "rev": 42, "published_at": "…", "capabilities": { "can_classify": true } } }
```

**Common list parameters**

| Parameter | Contract |
|---|---|
| `q` | Case-insensitive substring over display name (LIKE metacharacters escaped); exact match over full ARN or pattern, account id and provider id. Minimum 2 characters. Server-side over the whole inventory at the revision |
| `sort` | Route-specific allowed keys, `-` prefix for descending. Every sort ends with `id`, so keyset paging is stable |
| `limit` | 1–200, default 100 |
| `cursor` | §5.1 |
| `facets` | Comma list of facet names; each facet's counts apply every **other** active filter, so a chip shows what choosing it would give |
| `lifecycle` | `active` (default), `retired`, `all` |
| `account` | An account id, repeatable; `unknown` selects objects with no stated account (§2.14.10). Absent means all accounts **including unknown** |

**Totals.** Counted in the same snapshot with `LIMIT 10001`, as an
**optional** query (§5.1): up to 10 000, `total_known: true` and `total`;
beyond, `total_known: false` and `total_at_least: 10000`. A count that times out
is rolled back to its savepoint and reported as `total_known: false`, never
guessed; the page itself is unaffected.

**Retired objects.** Every detail route returns retired objects with
`lifecycle`, `retired_reason` and `last_confirmed_at`. Lists exclude them
unless `lifecycle` asks.

**Errors, on every route**

| Status | `code` | When |
|---|---|---|
| `400` | `invalid_parameter`, `cursor_invalid` | A malformed or disallowed parameter; a cursor from another context |
| `401` | `unauthenticated` | No valid token |
| `403` | `forbidden` | Missing `iga:read` (or `iga:review` for classification); not a verified human for decisions |
| `404` | `not_found` | Not in this table in this workspace |
| `409` | `revision_stale`, `listing_changed`, `classification_conflict` | §5.1, §5.5 |
| `422` | `provider_native`, `invalid_decision`, `operation_id_reused` | Classification rules |
| `503` | `graph_unavailable` | `IGA_GRAPH_PROJECTION` off or misconfigured (§2.8), with `reason` |
| `500` | `internal` | A database error; nothing partial is returned |
| `504` | `query_timeout` | A mandatory query did not finish within the request deadline (§5.1); nothing partial is returned. A graph that ran out of time returns `200` with `truncated` instead |

### 5.3 The API catalogue

Authorization: every read needs **`iga:read`**; classification needs
**`iga:review`** and a verified human (§2.14.3). Connector and scan operations
stay on the existing `/authsec/discovery/aws/*` routes with `discovery:read` /
`discovery:admin`. No new permission is introduced.

#### Integration, scan and pipeline

| Method, path | Auth | Purpose | Status |
|---|---|---|---|
| `POST /authsec/discovery/aws/connectors` | `discovery:admin` | Connect | Exists |
| `POST /authsec/discovery/aws/connectors/:id/verify` | `discovery:admin` | Verify | Exists |
| `GET /authsec/discovery/aws/connectors/:id/regions` | `discovery:read` | Regions enabled in the account (`ec2:DescribeRegions` through the discovery role), with which are selected | **New** |
| `PATCH /authsec/discovery/aws/connectors/:id` | `discovery:admin` | `{ "regions": ["eu-central-1","us-east-1"] }`. Validated against the enabled list; applies from the next scan; `422 invalid_region` names the offender | **New** |
| `POST /authsec/discovery/aws/connectors/:id/scan` | `discovery:admin` | Queue a scan | Exists |
| `GET /authsec/discovery/aws/connectors/:id/scan-runs` | `discovery:read` | Run history, newest first, cursor-paged: status, times, coverage summary, projection job status, publication `rev` | **New** |
| `GET /authsec/discovery/aws/scan-runs/:id` | `discovery:read` | One run; gains `projection: { status, rev }` | Exists, extended |
| `GET /api/iga/v1/pipeline` | `iga:read` | The workspace's state (below) | **New** |
| `GET /api/iga/v1/capabilities` | authenticated | What this deployment supports | **New** |
| `GET /api/iga/v1/coverage` | `iga:read` | Per account and surface, from the runs the current revision was built from | **New** |

```json
GET /api/iga/v1/pipeline
{ "data": {
    "barrier": { "state": "collecting", "scan_run": "cloud_scan_run:9a3…", "since": "2026-09-23T14:28:02Z" },
    "accounts": [
      { "integration": "cloud_connector:51c…", "account_id": "220171243705", "label": "production",
        "latest_run": { "ref": "cloud_scan_run:9a3…", "status": "running", "started_at": "…" },
        "projection": null, "last_published_rev": 41 },
      { "integration": "cloud_connector:7e2…", "account_id": "905418271234", "label": "sandbox",
        "latest_run": { "ref": "cloud_scan_run:b10…", "status": "queued", "queued_at": "…",
                        "waiting_on": "cloud_scan_run:9a3…" },
        "projection": null, "last_published_rev": 41 } ],
    "current_rev": 41, "current_published_at": "…" } }
```

```json
GET /api/iga/v1/capabilities
{ "data": { "graph_projection": "on",          // on | off | misconfigured
            "reason": null,
            "features": { "workloads": true, "identities": true, "resources": true,
                          "graph": true, "evidence": true, "changes": true,
                          "classification": true, "coverage": true },
            "schema_head": "036" } }
```

`GET /coverage?account=<id>` returns, for each surface: `state`, `count`,
`error_code` (the AWS error code when one was returned), `api` (the call that
failed), `since` (first run in the current state), `prevents` (a code from
§5.4's limitations vocabulary) and `run`. It **never** returns a guessed
missing permission (§2.14.13).

#### Agents & workloads

`GET /api/iga/v1/workloads`

| Filter | Values |
|---|---|
| `q`, `account`, `lifecycle` | §5.2 |
| `region` | a region; `not_stated` |
| `integration` | a connector ref |
| `runtime_kind` | `lambda_function`, `ecs_task_definition`, `ec2_instance`, `bedrock_agent`, `bedrock_agentcore_runtime`, `bedrock_agentcore_gateway` |
| `classification` | `agent` (provider-native or classified), `provider_native_agent`, `classified_agent`, `unclassified` |
| `execution_role_state` | `resolved`, `not_in_scan`, `not_in_inventory`, `none` |
| `sort` | `name` (default), `-name`, `account`, `last_confirmed`, `classification` |
| `facets` | `account`, `runtime_kind`, `classification`, `region` |

```json
{ "ref": "workload:6f1e…", "name": "ticket-tools", "runtime_kind": "lambda_function",
  "arn": "arn:aws:lambda:eu-central-1:220171243705:function:ticket-tools",
  "account": { "id": "220171243705", "label": "production", "connected": true },
  "region": "eu-central-1",
  "classification": "unclassified", "classification_version": 0,
  "execution_role": { "state": "resolved", "identity": "identity:c41…", "name": "SharedToolRole" },
  "lifecycle": "active", "state": "current",
  "first_seen_at": "2026-03-12T09:41:00Z", "last_confirmed_at": "2026-09-23T14:02:11Z",
  "instances": { "state": "not_collected" } }
```

Query: one statement over `iga_workload` joined to its estate scope for the
account, keyset-paged on `(lower(display_name), id)`
(`idx_iga_workload_list`); `execution_role` from the live `executes_as` row,
or `execution_role_state`/`_arn` when unresolved.

`GET /api/iga/v1/workloads/:id` — the list fields plus `continuity`,
`provider_attrs` (status, foundation model, env var names, gateway targets
`[{id, name, status, type}]`), `sources` (the connectors whose support rows
hold it, with state), and the latest classification decision
`{ decision, purpose, reason, decided_by: { user_id, display }, decided_at }`.

`GET /api/iga/v1/workloads/:id/identities`

```json
{ "data": {
    "execution": [
      { "claim": "relationship:88a…", "type": "executes_as",
        "identity": { "ref": "identity:c41…", "name": "SharedToolRole", "kind": "iam_role",
                      "arn": "arn:aws:iam::220171243705:role/SharedToolRole", "account": { … } },
        "basis": "declared", "state": "current", "valid_from": "…", "last_confirmed_at": "…",
        "used_by_count": { "value": 2, "exact": true } } ],
    "execution_role_state": "resolved",
    "other": [ { "claim": "relationship:9c0…", "type": "task_execution_role", … } ],
    "groups": [ ],
    "may_assume": [ { "claim": "relationship:1d7…", "type": "can_assume",
                      "target": { "ref": "identity:e02…", "name": "data-reader", … },
                      "conditions": null, "state": "current" } ] },
  "meta": { "rev": 42, … } }
```

`execution_role_state` other than `resolved` carries `execution_role_arn`, so
the tab says *"Runs as `<arn>` — not read in the latest scan"* rather than
showing nothing.

`GET /api/iga/v1/workloads/:id/resources` — for every resource the workload's
execution identities (and their groups) have a **grant** to — positive
targets only; a `NotResource` statement contributes its `*` row, with its
exclusions listed on the grant line — one row per target, and under it **one
line per grant**:

```json
{ "resource": { "ref": "resource:0b9…", "text": "arn:aws:s3:::support-tickets/*",
                "kind": "selector", "service": "s3", "account": null, "region": null },
  "grants": [
    { "claim": "grant:a11…", "via_identity": "identity:c41…",
      "policy": { "ref": "policy:3f0…", "name": "TicketRead", "kind": "customer_managed" },
      "statement": { "ref": "statement:77e…", "sid": "ReadTickets", "index": 2,
                     "actions": ["s3:GetObject"], "not_actions": [], "conditional": false },
      "target_mode": "resource", "state": "current", "valid_from": "…" },
    { "claim": "grant:a12…", "policy": { "name": "ToolboxRead", … }, "statement": { "sid": "", "index": 1, … }, … } ],
  "restrictions": { "deny_statements": 0, "permissions_boundary": false } }
```

Paged by resource (`sort`: `kind`, `name`), 100 per page; grants per resource
are not paged (the Resources tab shows at most the statements naming it, which
is bounded by the policies attached).

`GET /api/iga/v1/workloads/:id/changes?kind=configuration|coverage&cursor=` —
§5.3 *Changes*.

#### Identities

`GET /api/iga/v1/identities` — filters `q`, `account`, `kind`
(`iam_role`, `iam_user`, `iam_group`), `used_by` (`workloads` = identities
some workload runs as), `lifecycle`; sort `name`, `kind`, `account`,
`last_confirmed`; facets `account`, `kind`. Rows: name, kind, ARN, account,
`used_by_count` (`{value, exact}`), `last_confirmed_at`.

`GET /api/iga/v1/identities/:id` — list fields plus `continuity`,
`immutable_key`, `provider_attrs` (path, tags, permissions-boundary ARN,
`trust_has_deny`, `trust_has_not_principal`), credentials
(`[{ key_id, status, created_at, last_used_at }]` for users), sources.

`GET /api/iga/v1/identities/:id/used-by` — two sections, each paged:
`workloads` (via `executes_as` and `task_execution_role`, with the relationship
type) and `principals` (sources of `can_assume` into this role: identities and
external principals, with mechanism and conditions); for a group, `members`
(`member_of`).

`GET /api/iga/v1/identities/:id/permissions` — grouped by policy:

```json
{ "policies": [
    { "ref": "policy:3f0…", "name": "TicketRead", "kind": "customer_managed",
      "assignment": { "claim": "assignment:5aa…", "kind": "attached", "via_group": null,
                      "state": "current", "valid_from": "…" },
      "statements": [
        { "ref": "statement:77e…", "sid": "ReadTickets", "index": 2, "effect": "allow",
          "actions": ["s3:GetObject"], "not_actions": [],
          "targets": [ { "ref": "resource:0b9…", "text": "arn:aws:s3:::support-tickets/*",
                         "kind": "selector", "mode": "resource" } ],
          "condition": null, "grant": "grant:a11…", "revision_count": 1 } ] } ],
  "boundary": { "policy": null },
  "inherited": [ { "group": "identity:g77…", "policies": [ … ] } ],
  "activity": { "source": "access_advisor", "tracking_note": "…",
                "services": [ { "namespace": "s3", "last_authenticated_attempt": "2026-09-20T…" } ] } }
```

Deny statements appear under their policy with `"effect": "deny"` and no
`grant`. Boundary policies appear under `boundary`, never as grants. Access
Advisor data is labelled per §2.14.8.

#### External principals

`GET /api/iga/v1/external-principals/:id` — mechanism, issuer, subject,
account (when parseable), `account_connected`, resolution
`{ state, basis, rule, resolved_to, resolved_by }`.

`GET /api/iga/v1/external-principals/:id/referenced-by` — the `can_assume`
edges from it, with target roles, statements and conditions.

#### Resources

`GET /api/iga/v1/resources` — filters `q`, `account` (incl. `unknown`),
`region` (incl. `not_stated`), `kind` (`exact`, `selector`, `external`),
`service`, `lifecycle`; sort `kind` (default), `name`, `service`, `account`;
facets `kind`, `service`, `account`. Rows: text (the ARN or pattern), kind,
service, account, region, `named_by_count` (`{value, exact}` — statements naming it as a positive target; exclusions are counted separately as `excluded_by_count`),
`last_confirmed_at`.

`GET /api/iga/v1/resources/:id` — list fields plus
`existence: "not_verified"`, `resource_policy`
(`{ read: true|false, has_deny: true|false|null }` from the existing
resource-policy observations), sources.

`GET /api/iga/v1/resources/:id/access` — `access`: one row per (holder,
grant) whose statement names this resource as a **positive** target
(`mode = resource`): holder identity, via group (if any), policy, statement,
state; paged by holder. Separately, never mixed into `access` or its counts:
`excluded_by` (Allow statements that name it in `NotResource` — they exclude
it, they do not grant it) and `deny_statements_naming` (Deny statements
targeting it). Both are restrictions, shown as such.

#### Graph

| Route | Purpose |
|---|---|
| `GET /api/iga/v1/graph?root=<ref>&direction=forward\|reverse&assume_hops=2` | The initial neighbourhood of an object (§5.4) |
| `GET /api/iga/v1/graph/expand?node=<ref>&edge=<kind>&direction=…&cursor=` | One node's next neighbours of one kind |
| `GET /api/iga/v1/graph/path?from=<ref>&to=<ref>` | Declared paths between two objects, bounded (§5.4) |

```json
{ "data": {
    "root": "workload:6f1e…",
    "nodes": [ { "ref": "workload:6f1e…", "kind": "workload", "label": "ticket-tools", "account": { … }, "state": "current" },
               { "ref": "identity:c41…", "kind": "iam_role", "label": "SharedToolRole", "restrictions": { "deny_statements": 0 } },
               { "ref": "statement:77e…", "kind": "statement", "label": "s3:GetObject", "policy": "TicketRead",
                 "group_key": "s3:GetObject→resource:0b9…" },
               { "ref": "statement:91b…", "kind": "statement", "label": "s3:GetObject", "policy": "ToolboxRead",
                 "group_key": "s3:GetObject→resource:0b9…" },
               { "ref": "resource:0b9…", "kind": "selector", "label": "support-tickets/*" } ],
    "edges": [ { "claim": "relationship:88a…", "kind": "executes_as", "from": "workload:6f1e…", "to": "identity:c41…", "state": "current" },
               { "claim": "grant:a11…", "kind": "grant", "from": "identity:c41…", "to": "statement:77e…", "state": "current" },
               { "claim": "grant:a12…", "kind": "grant", "from": "identity:c41…", "to": "statement:91b…", "state": "current" },
               { "claim": "target:c20…", "kind": "target", "mode": "resource", "from": "statement:77e…", "to": "resource:0b9…" },
               { "claim": "target:c21…", "kind": "target", "mode": "resource", "from": "statement:91b…", "to": "resource:0b9…" } ],
    "frontier": [ { "node": "identity:c41…", "edge": "can_assume", "direction": "forward",
                    "more": { "count": 3, "exact": true },
                    "expand": "/api/iga/v1/graph/expand?node=identity:c41…&edge=can_assume&direction=forward" } ],
    "truncated": null },
  "meta": { "rev": 42, "budgets": { "nodes": 500, "edges": 2000, "assume_hops": 4, "timeout_ms": 3000 } } }
```

`group_key` lets the canvas draw statements with the same actions and target
as one line (§2.14.11); the response always lists each statement and grant
separately.

#### Evidence

`GET /api/iga/v1/evidence?claim=<claim ref>` — any claim or object ref:

```json
{ "data": {
    "claim": { "ref": "grant:a11…", "sentence": "SharedToolRole is granted s3:GetObject on support-tickets/* by TicketRead (statement ReadTickets)." },
    "status": { "basis": "declared", "lifecycle": "current", "collection": "complete", "effective_access": "not_evaluated" },
    "facts": [
      { "source_api": "iam:GetAccountAuthorizationDetails", "account_id": "220171243705", "region": null,
        "observed_in_run": "cloud_scan_run:9a3…", "last_confirmed_at": "…",
        "fact": "SharedToolRole has TicketRead attached" },
      { "source_api": "iam:GetPolicyVersion", "policy_version": "v3",
        "fact": "Statement ReadTickets allows s3:GetObject on arn:aws:s3:::support-tickets/*",
        "statement_excerpt": { "Sid": "ReadTickets", "Effect": "Allow", "Action": "s3:GetObject",
                               "Resource": "arn:aws:s3:::support-tickets/*" } } ],
    "freshness": { "first_seen_at": "…", "last_confirmed_at": "…", "stale_since": null },
    "limitations": [
      { "code": "effective_access_not_evaluated" },
      { "code": "selector_may_match_nothing" },
      { "code": "resource_existence_not_verified" },
      { "code": "organizations_not_collected" } ],
    "raw": null },
  "meta": { "rev": 42 } }
```

`include=raw` adds the stored observation `sanitized_facts`. Those are
redacted **at write time** by the observation writer (`cloud_observation_writer.go:34-49`)
and are returned only through this authorized route; nothing else exposes
them. The **limitations vocabulary**, with the exact condition for each, is:

| Code | Present when |
|---|---|
| `effective_access_not_evaluated` | Always, on grants and paths |
| `conditions_not_evaluated` | The statement or trust statement has a Condition (the keys are listed) |
| `negated_statement` | NotAction or NotResource |
| `deny_statements_present` | The holder (or its groups) has Deny statements; count and refs |
| `permissions_boundary_present` | The holder has a boundary assignment |
| `organizations_not_collected` | Always, for AWS |
| `resource_policy_not_projected` | The target has a resource policy that was read |
| `resource_existence_not_verified` | Exact references |
| `selector_may_match_nothing` | Selectors |
| `account_not_connected` | An endpoint's account is not a connected account |
| `caller_permission_not_evaluated` | `can_assume`: the caller also needs `sts:AssumeRole` permission, which is not checked |
| `not_principal_unresolved` | The trust policy uses NotPrincipal |
| `surface_stale` / `surface_partial` / `surface_denied` | A required surface for this claim is not `reached`, with the surface, state and since |
| `activity_attempts_not_outcomes` | Access Advisor facts (§2.14.8) |

#### Changes

`GET /api/iga/v1/{workloads|identities|resources}/:id/changes?kind=configuration|coverage&cursor=`
— events, newest first, 50 per page:

| Event | Source |
|---|---|
| `first_seen`, `retired` (with reason: `unsupported`, `recreated`, `policy_recreated`), `restored` | `iga_lifecycle_event` (`036`) |
| `relationship_started` / `relationship_ended` | `iga_relationship` `valid_from` / `valid_to`, `ended_reason` |
| `policy_attached` / `policy_detached` | Assignment periods |
| `grant_started` / `grant_ended` | Grants |
| `statement_revised` | `iga_statement_revision` (before and after) |
| `statement_replaced` | A Sid-less statement ended and another began in the same policy in the same run |
| `coverage_changed` | Consecutive runs' coverage for the object's account and surfaces |

Each event carries its time, run, the claim refs involved, and for
grant/assignment ends the grants that **remain** on the same path, so the view
can say *"the path remains through ToolboxRead"*.

#### Classification

`POST /api/iga/v1/workloads/:id/classification` — §5.5.
`GET /api/iga/v1/workloads/:id/classification` — the decision history, newest
first.

#### Lookup

`GET /api/iga/v1/lookup?cloud_ref=cloud_identity:<id>|cloud_workload:<id>` —
the graph object projected from a Cloud Inventory row, by source key through
the row's own connector; `404` when none. Never by name.

### 5.4 Traversal

**The traversal graph.** Nodes: workloads, identities (roles, users, groups),
external principals, statements, resource references. Edges, each with a
direction:

| Edge | Forward (from → to) | Reverse | Filtered by |
|---|---|---|---|
| `executes_as`, `task_execution_role` | workload → identity | identity → workloads | lifecycle |
| `member_of` | user → group | group → members | lifecycle |
| `can_assume` | principal → role (who may assume it → the role) | role → its principals | lifecycle |
| `grant` | identity → statement (Allow only) | statement → holders | lifecycle |
| `target` (`mode = resource`) | statement → resource | resource → statements | statement lifecycle |
| exclusion (`mode = not_resource`) | **not an edge** | **not an edge** | — |

A **path** is a sequence of these edges. The forward path of the product's
teaching case is workload → `executes_as` → role → `grant` → statement →
`target` → resource; with groups, user → `member_of` → group → `grant` → …;
with assumption, role A → `can_assume` → role B → `grant` → …, where the
edge exists because B's trust policy names A as a principal ("A may assume
B").

**Forward** answers "what can this reach, declared"; **reverse** answers "what
reaches this" (Resource › Access, Identity › Used by, *View in graph* from a
resource). **A `NotResource` entry is an exclusion, not a destination** (AWS
defines `NotResource` as "every resource except these"): it is never traversed,
in either direction, and never counts toward a declared-access path or a
`named_by` count. It is returned on its statement node as `exclusions`, so the
canvas and the path list can say *"all resources except finance/\*"*. The
statement's positive target is the implicit `*` selector (§4.7). Deny
statements and boundaries are **not edges** either: each node carries
`restrictions` (§5.3), and every path through a restricted node carries the
matching limitation.

**Lifecycle.** Default `current` and `stale`; `ended` only when a Changes
view asks. A stale edge is traversed and marked, because it is still believed.

**Cycles and shared nodes.** Traversal keeps a visited set per request. An edge
to an already-visited node is returned, marked `closes_cycle: true` when its
target is on the path that reached it, and never re-expanded. A node reached by
several paths is returned once; the edges say how.

**External endpoints and account boundaries.** An external principal is a
terminal node (it has no outgoing edges we can read). An edge whose endpoints
are in different accounts is returned normally and marked
`crosses_account: true`; the far account's coverage appears as limitations on
the edge. An `account` filter applies to **starting objects**, never to
traversal (§2.14.10).

**Budgets — display defaults and hard limits, separately.**

| | Display default (console) | Hard server budget (per request) |
|---|---|---|
| Assume hops | 2, then expand on request | 4 per request; a further hop is a new expand from the frontier |
| Nodes | 150 drawn, then a truncation chip | 500 |
| Edges | 300 drawn | 2 000 |
| Paths (`/graph/path`) | 50 listed | 200 |
| Neighbours per expansion | 100 per page | 100 per page, cursor for the rest |
| Time | — | 3 s request deadline (§5.1); a graph that reaches it returns what it has, `truncated.bound_by: "time"` |

**Continuation.** When a budget binds, the response returns what it has,
`truncated: { bound_by: "nodes" | "edges" | "assume_hops" | "time" }`, and a
`frontier` of nodes with unexpanded neighbours. Each frontier entry has an
`expand` call and a `more` count that is **exact only when counted within the
budget** (`{ "count": 3, "exact": true }`); otherwise `{ "count": null,
"exact": false }`. The server never states a hidden-node count, a distance, or
a completeness it did not establish.

**`/graph/path` outcomes.** A bidirectional breadth-first search from both
ends within the budgets:

| Outcome | Meaning | Console |
|---|---|---|
| `found` | One or more declared paths, shortest first; `more_paths: true` if the path budget bound | Draws them |
| `none_exists` | The search **exhausted** both frontiers before any budget bound: no declared path exists among current and stale edges | *"No declared path from X to Y."* |
| `not_found_within_budget` | A budget bound first; `bound_by` names it | *"No path found within the search limits — one may still exist."* |

**Algorithm and queries.** Iterative breadth-first search in Go inside the
read snapshot (§5.1). Each level issues **one query per edge kind** for the
whole frontier (`WHERE source_id = ANY($1)` on the typed columns, using the
source and target indexes of `030`, `031` and `036`), ordered by
`(edge kind, target source_key, id)` so the same request returns the same
result. Node rows are fetched in one query per node type per level. Levels
stop at the budgets. There is no recursive CTE: per-level batching keeps each
query simple, lets the server stop exactly at a budget, and returns a frontier
it can describe.

**Independent grants.** Each grant is its own edge to its own statement, so two
policies declaring the same action are two edges and two statement nodes. The
server supplies `group_key` (actions + target set) so the console may draw one
line; nothing in the response merges them.

### 5.5 Classification: writes and list consistency

```
POST /api/iga/v1/workloads/:id/classification          iga:review + verified human
{ "operation_id": "b8f1c2de-…",       // client-generated, one per intent, reused on retry
  "decision": "classified_agent",      // or "unclassified" (undo)
  "purpose": "Customer support triage",
  "reason": "Owns tier-1 ticket routing",
  "expected_version": 3,
  "undoes_decision_id": null }

200 { "data": { "classification": "classified_agent", "classification_version": 4,
                "decision": { "id": "…", "operation_id": "b8f1c2de-…",
                              "decided_by": { "user_id": "2c9…", "display": "Priya Shah" },
                              "decided_at": "…", "reason": "…", "purpose": "…" },
                "replayed": false } }
409 { "error": { "code": "classification_conflict",
                 "current": { "classification": "classified_agent", "classification_version": 4,
                              "decided_by": { "user_id": "…", "display": "Alex Kim" },
                              "decided_at": "…", "reason": "owns refunds" } } }
422 provider_native | invalid_decision | operation_id_reused     403 forbidden     404 not_found
```

**The transaction** — `READ COMMITTED`, so a statement after the lock sees
rows another transaction committed while this one waited:

1. `SELECT … FROM iga_workload WHERE workspace_id = ? AND id = ? FOR UPDATE`.
   Missing → `404`. **The lock comes first**: every request for this workload
   now serializes behind it.
2. `SELECT … FROM iga_workload_classification WHERE workspace_id = ? AND
   operation_id = ?`, **after** the lock. Found with the same `request_hash` →
   return its stored outcome, `replayed: true`, `200`. Found with a different
   hash (another workload, actor or content) → `422 operation_id_reused`.
3. Provider-native → `422`. `classification_version <> expected_version` →
   `409 classification_conflict` with the current decision.
4. Insert the decision row (operation id, request hash, actor user id,
   decision, previous, reason, purpose, `against_version`, `result_version`).
5. Update `iga_workload` classification and version; increment
   `iga_classification_clock.seq` (upsert).
6. Commit. A unique violation on `operation_id` at step 4 can only come from
   the same id used concurrently on a **different** workload (the lock
   serializes one workload): it rolls back and returns `422
   operation_id_reused`.

Verified with two sessions (23 Sep): the retry, blocked on the lock while the
original committed, found no operation before the lock and found it after, and
took the replay branch.

**Display names** are resolved at read time from the user record, falling back
to the user id; the stable `user_id` is always returned beside them.

**List consistency.** Classification is not part of a graph revision. A list
whose filter or sort involves classification binds its cursor to the clock's
`seq` at the first page; if a decision lands before the next page,
`409 listing_changed`. Lists that do not involve classification show each
row's classification as of the request and are unaffected. The default
Agents & workloads order is by name for this reason (§2.14.6).

### 5.6 Query strategy and performance

| Read | Strategy | Index | Target (p95, 10 000 objects per workspace) |
|---|---|---|---|
| Lists | One keyset-paged statement per page, filters in SQL, account via the estate scope | `idx_iga_workload_list`, `idx_iga_*_provider`, the source-key indexes | 400 ms |
| Totals and facets | Separate `COUNT` queries in the same snapshot, `LIMIT 10001` | as above | within the 3 s timeout, counted in the page budget |
| Detail tabs | Targeted joins from the object's typed FK columns | `idx_iga_relationship_source`/`_target`, `idx_iga_pa_holder`, `idx_iga_access_edges_entitlement`, `idx_iga_et_resource` | 300 ms |
| Graph | §5.4 per-level batches | as above | 1.5 s for the display defaults |
| Evidence | Junction → observation, one query per edge type | the `*_evidence` keys | 300 ms |
| Changes | Union of dated rows for the object, keyset on `(at, id)` | lifecycle and validity columns | 500 ms |

T6.10 load-tests these on a generated 10 000-workload fixture; a target missed
is a defect, not a note.

## 6. Implementation handoff

### 6.1 Starting from the graph branch

`origin/graph` (`7eb8bed`) is the base for the backend work. It is correct
in most of what it built, and the corrections are specific:

| On the graph branch | Disposition |
|---|---|
| `027`, `032`–`034`, the barrier table, job/state/publication, `PublishWithCoverage`, fenced upserts, `RecoverStalled`, the three projection exits, `AlreadyPublished` replay, restoration, suspension, `canEnd`, support rows, `retireUnsupported`, the actor rule, the schema-gate tests, the S0 fallback tests | **Keep** |
| `028`–`031` | **Edit in place** per §3 |
| `ToProjectingTx` leaving the scan worker as holder; `holdBarrier` matching worker names | **Correct**: job-held barrier (§2.10A) |
| `phase2Available()` / `hasProjectionJobs()` probing tables and caching errors as "absent" | **Replace** with the `IGA_GRAPH_PROJECTION` switch and fail-closed verification (§2.8) |
| Nothing starts `ProjectionService` | **Wire** in `cmd/main.go` (§4.11) |
| `Requeue` then immediate re-claim | **Correct**: fresh `requested_at` and a poll sleep (§2.10A) |
| Unfenced `ReconcileGeneration` deletes | **Fence** |
| One entitlement per (policy, statement index, resource); Deny and boundary statements as grants | **Replace** with §2.6 (`036`, §4.7) |
| `Load` reading `cloud_resource` by connector | **Remove**: resources derive from statement text (§4.3) |
| `projectAgents`, `realizes`, AWS writes to `iga_agents` / `iga_agent_instances` | **Remove** (§2.2) |
| `can_assume` from `cloud_assume_edge`, same-snapshot identities only; no external principals | **Replace** with §4.7 *Trust* |
| GitHub `ingestGrant` recognition keys | **Revert**; keep the typed subject and set `provider` (§1.5) |
| `ListAccessPaths` hard-coding `subject_agent_id` | **Restore** base semantics |
| `GET /workloads/:id/access-path`, `POST /estate/:id/classification` | **Replace** with §5.3 |
| `.claude/specs/P2-0-EVIDENCE.md` on the branch | Superseded by the P2-0 evidence report against this document; remove it when the new report lands |

**Branch hygiene.** Rebase `graph` onto the current `authsec-staging` before
starting, so this document and `026` are in the tree. Migrations `027`–`034`
are edited in place (never shipped); `035`–`037` are added. `graph` is **not**
merged into `authsec-staging` until M3 — pushing `authsec-staging` deploys
production (§1.5), and the switch defaults to `off` for exactly that reason.

### 6.2 Tasks

Each task names its files, what it changes, and the gate someone else can
check. `Proof` is the §7 scenario that fails without it.

**S1 · Pipeline safety**

| Task | Files | Change | Gate |
|---|---|---|---|
| T1.1 | `services/cloud_aws_scan_worker.go`, `cmd/main.go`, `internal/config` | `IGA_GRAPH_PROJECTION` switch; fail-closed schema verification with retry; start `ProjectionService.Run` when on | Two consecutive worker scans at `036`, switch off: both publish, no job, no barrier row changes. Switch on: scan → projection → scan completes. E13 |
| T1.2 | `repository/iga_pipeline_lease_repository.go`, `services/iga_projection_service.go` | Job-held barrier; `holdBarrier` by holder `job:<id>`; `RenewHeld` for both phases | Scan worker and projector with **different** owner names: projection completes on its **first** pass. E13 |
| T1.3 | `repository/cloud_scan_run_repository.go`, `services/cloud_aws_scan_worker.go` | Refused claim: `requested_at = now()`, worker sleeps its poll interval | Two workspaces, one blocked: the other's scan is claimed within one poll interval. E13 |
| T1.4 | `repository/cloud_*_repository.go` | Fence `ReconcileGeneration` deletes | A superseded worker's reconcile deletes nothing. E13 |
| T1.5 | `services/cloud_aws_iam_scan.go`, workload and permission scanners | Use `run.Generation`; never recompute from the connector | Reclaimed run after a crash post-commitScan writes rows and evidence at one generation. E13 |

**S2 · Connect, configure, observe**

| Task | Files | Change | Gate |
|---|---|---|---|
| T2.1 | `controllers/platform/cloud_aws_controller.go`, `services/cloud_aws_onboarding.go` | `GET …/regions`, `PATCH …/connectors/:id` | Region change applies to the next scan; invalid region `422`. E1 |
| T2.2 | same | `GET …/connectors/:id/scan-runs`; `projection` on `GET …/scan-runs/:id` | History shows published, failed and abandoned runs with rev. E1, E9 |
| T2.3 | `controllers/platform/iga_graph_read_controller.go` | `GET /pipeline`, `GET /capabilities`, `GET /coverage` | Pipeline reports queued-behind, collecting, projecting. E1 |
| T2.4 | `internal/awsdiscovery/permissions.go`, `authsec-aws-discovery-role.yaml` | Add `bedrock-agentcore:GetGateway`; template version bump | Gateway gets its ARN and role in the lab. E1 |

**S3 · Complete, honest collection**

| Task | Files | Change | Gate |
|---|---|---|---|
| T3.1 | `internal/awsdiscovery/authdetails.go` (new), `services/cloud_aws_iam_scan.go` | `GetAccountAuthorizationDetails` replaces the per-role/per-user calls; roles, users, groups, memberships, boundaries, tags, attachments, inline and customer-managed documents; AWS-managed documents for attached policies via `GetPolicy`/`GetPolicyVersion` | Lab: a user in a group with a boundary appears with membership, boundary and inherited policies. E3, E4 |
| T3.2 | `035`, `repository/cloud_policy_repository.go` | `cloud_policy`, `cloud_policy_attachment`, `cloud_group_membership`, `trust_document`; fenced upserts; per-connector keys; composite (workspace, integration) references | An AWS-managed policy in two accounts is two `cloud_policy` rows; a membership, holder or attachment across workspaces or integrations is rejected by the database (B20). E10, E14 |
| T3.3 | `internal/awsdiscovery/policy_statements.go`, `services/cloud_aws_permission_scan.go` | Per-document fetch and parse isolation; `document_error` (policies) and `trust_parse_error` (roles); `policy_documents: partial` names the documents; the scan continues | One unreadable document: every other policy's statements written. E9 |
| T3.4 | `internal/awsdiscovery/trust_policy.go` | Parse Allow and Deny, all principals, conditions verbatim; `NotPrincipal` recorded; per-statement failure isolation | Trust statement with a non-string condition value no longer fails the document. E11 |
| T3.5 | `services/cloud_observation_writer.go`, scanners | Evidence for policies (`policy_id` subject), access keys, pod-identity associations; gateway `source_api` fixed; conflict target names `policy_id` | Every surface in §1.4 writes evidence. E4 |
| T3.6 | `services/cloud_aws_workload_scan.go`, `internal/awsdiscovery/{workloads,bedrock}.go` | Detail-call failures make the surface `partial`; "not available in region" → `unsupported`; Bedrock ARN constructed; AgentCore runtime status; gateway target type | A failed `GetAgent` keeps the same key and blocks deletion. E7, E9 |
| T3.7 | `services/cloud_aws_workload_scan.go` | Access Advisor: `partial` above the cap, `throttled` on throttle; resource-policy failures counted | Coverage matches reality in the lab's throttling fixture. E4 |
| T3.8 | `models/cloud_discovery.go`, scanners | Coverage vocabulary: `unsupported` for `organizations` and unoffered services; `iam_groups` surface | Coverage shows `organizations: unsupported`. E4 |

**S4 · Canonical model and projection**

| Task | Files | Change | Gate |
|---|---|---|---|
| T4.1 | `028`–`034` (edit), `036` (new), `models/iga*.go` | Schema per §3 | All migrations apply to a fresh `001`–`026` and to the production schema dump (§9) |
| T4.2 | `internal/igagraph/sourcekey.go` | Keys per §4.4, incl. statement keys | Unit tests: Sid, hash, duplicates, reorder. E7 |
| T4.3 | `internal/igagraph/load.go`, `snapshot.go` | Snapshot per §4.3; no `cloud_resource` | Shared bucket across two accounts survives in both snapshots. E10 |
| T4.4 | `internal/igagraph/project.go` | Identities (incl. groups), workloads (`provider_native_agent`), credentials; no agents | Rescan keeps ids. E1 |
| T4.5 | `internal/igagraph/permissions.go` | Policies (incarnation keys, recreation cascade), statements, revisions, targets with `mode`, assignments, grants per §4.7 | Two policies same action → two grants; Deny → zero grants; recreated policy shares no key with its predecessor (B21). E6, E7, E8 |
| T4.6 | `internal/igagraph/project.go` | `executes_as`, `task_execution_role`, `member_of`, execution-role state | Role switch ends the old edge. E5, E8 |
| T4.7 | `internal/igagraph/trust.go` | `can_assume` and external principals per §4.7 | Cross-account, service and OIDC principals appear. E11 |
| T4.8 | `services/iga_service.go`, `repository/iga_repository.go` | GitHub: revert keys, keep typed subject, set `provider`; readers filter `provider = 'github'`; `ListAccessPaths` base semantics | GitHub suites pass; AWS rows absent from `/api/iga/v1/identity-accounts`. E16 |
| T4.9 | `internal/igagraph/evidence.go` | Evidence per §4.8 | Zero edges without evidence on the lab accounts. E4 |

**S5 · Reconciliation, publication, history**

| Task | Files | Change | Gate |
|---|---|---|---|
| T5.1 | `internal/igagraph/snapshot.go`, `reconcile.go` | Partitions per §4.10; `Exclusions` and `protected()` applied in every edge and support update; exhaustive `scope()` | B12 and B18. E9 |
| T5.2 | `reconcile.go` | Retirement cascade table (§4.10); policy recreation | Policy retired → assignments end `policy_retired`. E7 |
| T5.3 | `repository/iga_graph_repository.go` | Revisions and target replacement (§4.10 contracts) | Sid edit → one new revision, same grant id. E7 |
| T5.4 | `internal/igagraph` (event log), `internal/igaread` | `iga_lifecycle_event` written in the projection transaction; Changes events (§5.3) | Detach → `policy_detached` with remaining grants; retire → restore → both events present after later updates (B24). E6, E8 |

**S6 · Read APIs and traversal**

| Task | Files | Change | Gate |
|---|---|---|---|
| T6.1 | `internal/igaread/snapshot.go`, `refs.go`, `cursor.go` | §5.1–§5.2 contract: request deadline, optional queries in savepoints | Revision advanced between pages → `409 revision_stale`; tampered cursor → `400`; B23. E12 |
| T6.2 | `internal/igaread/lists.go` | Workloads, identities, resources lists | Search finds a row beyond page one; facets include `unknown`. E2 |
| T6.3 | `internal/igaread/detail.go` | Every detail and tab route | Execution role states each worded; retired object readable. E3, E8 |
| T6.4 | `internal/igaread/traverse.go` | §5.4 | Cycle, budget and exhaustion outcomes distinguished. E11 |
| T6.5 | `internal/igaread/evidence.go` | §5.3 *Evidence*, limitations vocabulary | Each limitation code has a fixture that produces it and one that does not. E4 |
| T6.6 | `services/iga_classification_service.go` | §5.5: lock, then operation lookup, then version; request hash | Concurrent retries (B22); same id, different content → `422 operation_id_reused`; different operation, stale version → `409`. E12 |
| T6.7 | `controllers/platform/iga_graph_read_controller.go`, `routes/routes.go` | Routes, `iga:read` / `iga:review`; remove the graph branch's two routes | Cross-workspace ids → `404`. E14 |
| T6.8 | same | `GET /lookup` | Cloud Inventory row → graph object. E16 |
| T6.9 | `controllers/platform/iga_graph_read_controller.go` | `503 graph_unavailable` when the switch is off or misconfigured | Console shows *Unavailable*, never empty. E1 |
| T6.10 | `tests/load/` | 10 000-workload fixture, §5.6 targets | Targets met, recorded |

**S7 · Console** (`Authsec-ui`)

| Task | Files | Change | Gate |
|---|---|---|---|
| T7.1 | `package.json` | Add `@xyflow/react`, `elkjs`; dev: `msw`, `@playwright/test`, `@axe-core/playwright` | `tsc --noEmit`, lint ratchets hold |
| T7.2 | `src/app/api/igaGraphApi.ts` (new) | RTK Query slice for §5.3; cache keyed by workspace and `rev`; `resetApiState` on workspace change and logout | UI11. E14 |
| T7.3 | `src/components/ui/responsive-data-table.tsx`, `table-pagination.tsx` | Keyboard row navigation, card layout under 768 px, server-side sort, cursor pagination control | UI10. E15 |
| T7.4 | `src/features/iga/estate/*` (new), `IgaSidebar.tsx`, `App.tsx` | Agents & workloads list, Overview, Identities, Resources, Changes; sidebar per §2.14.2 | UI1–UI6. E2, E3 |
| T7.5 | `src/features/iga/identities/*`, `IdentitiesPage.tsx` | Identities list and tabs; replaces the placeholder | E5 |
| T7.6 | `src/features/iga/resources/*` | Resources list and tabs | E3 |
| T7.7 | `src/features/iga/evidence/*` | Evidence panel with §2.14.5 history rules | UI3. E4 |
| T7.8 | `src/features/iga/graph/*` | §2.14.11, §2.14.15; lazy chunk; ELK in a worker; placement rule; Paths | UI9. E11 |
| T7.9 | `src/features/discovery/cloud/aws/AWSConnectorDrawer.tsx`, `AWSOnboardingWizard.tsx` | Region editing, scan history, run outcome, error on failed scan start; revision-driven refresh | E1, E9 |
| T7.10 | `src/features/iga/pipeline/*` | §2.14.7 pipeline and first-run states | E1 |
| T7.11 | `src/features/iga/classification/*` | §2.14.6 flow with operation ids | UI7. E12 |
| T7.12 | Cloud Inventory pages | *Open in graph* via `/lookup` | E16 |
| T7.13 | `src/mocks/*` | MSW fixtures per §2.14.14 | Fixture build breaks on contract drift |

**S8 · Integrated acceptance**

| Task | Change | Gate |
|---|---|---|
| T8.1 | The lab (§7.1 *Lab*), provisioned by Terraform in the lab accounts | Every §7.1 scenario's setup is reproducible from a clean lab |
| T8.2 | Playwright scenarios E1–E16 against the real backend and console | §7.1 passes; recorded per §7.4 |
| T8.3 | Production-schema rehearsal (§9) | Passes before merge |

### 6.3 The P2-0 slice (M0)

P2-0 proves the pipeline before the model widens: **one Lambda → its role →
one attached managed policy → its statements → grants → resource references**,
with evidence, reconciliation and publication, through the **real** worker and
projector, with the switch on. It includes T1.1–T1.5, T4.2–T4.5 (managed
policies only) and T4.9.

It must survive, each verified by removing its fix and observing the failure:

| Scenario | Catches |
|---|---|
| Unchanged rescan | ids, `first_seen_at` stable; no duplicate rows; no new revision |
| Lambda switches `RoleA` → `RoleB` | the old `executes_as` ends |
| Two policies grant the same action; one detached | one grant ends, the other stays current |
| One previously collected policy becomes unreadable **and** another is genuinely detached, same account and run | the unreadable one's statements, grants and the support of resources only it names go stale; the detached one's assignment and grants end |
| Attach → detach → reattach | the first assignment period ends with `valid_to`; reattach creates a second row; grants follow; Permissions and Changes agree |
| A `NotResource` statement | produces a grant to the `*` selector and no path to the excluded resource |
| A customer-managed policy recreated under the same ARN and Sid | new policy, statements, assignments and grants; the old ones retired or ended `policy_recreated` |
| A Deny statement | produces no grant |
| One region denied, another clean | per-region partitions independent |
| Two accounts naming one bucket | both keep the reference; neither becomes `*` |
| Two consecutive scans through the worker, switch **off** | both publish; no job; no barrier change |
| Two consecutive scans through the worker, switch **on**, different worker names | each projection completes on its first pass; the second scan starts |
| A superseded scan worker | its writes and deletes are refused |
| A crash after the graph commit | the replay returns `AlreadyPublished`, writes nothing, completes |
| Schema verification error at startup | the worker claims nothing and `/capabilities` says `misconfigured` |

**The evidence report** has one row per scenario: commit, exact command
(including environment variables and skip counts), fixture, expected,
observed, and the safeguard removed with its observed failure. A row without
*Observed* is a plan; a row whose safeguard removal still passes fails the
gate.

### 6.4 Requirement → implementation → proof

| Requirement | Collector / model | Backend API | UI | Tasks | Proof |
|---|---|---|---|---|---|
| Connect, verify, choose regions | existing onboarding; `attrs.regions` | `…/regions`, `PATCH …/connectors/:id` | Connector drawer | T2.1, T7.9 | E1 |
| Scan and see its state | `cloud_scan_run`, barrier, job | `…/scan-runs`, `/pipeline` | Pipeline states | T2.2, T2.3, T7.10 | E1, E9 |
| Complete IAM collection | authorization details, `035` | — | — | T3.1–T3.3 | E3, E4 |
| Trust and cross-account | trust documents, pod identity, `iga_external_principal` | `/identities/:id/used-by`, `/external-principals/*` | Used by, graph | T3.4, T4.7 | E11 |
| Workloads and execution identity | `cloud_workload`, `executes_as`, `task_execution_role` | `/workloads/*` | Agents & workloads, Identities tab | T3.6, T4.4, T4.6, T7.4 | E3, E5 |
| Duplicate names across accounts | account on every object | `account` filter, facets | Account column | T6.2, T7.4 | E2 |
| Independent grants | `036` policy / statement / assignment / grant | `/workloads/:id/resources`, `/identities/:id/permissions` | Resources tab, grouped edge | T4.5, T6.3, T7.4, T7.8 | E6 |
| Policy edits and reattach | statement keys, revisions, assignment periods | `/…/changes` | Changes | T4.2, T5.3, T5.4 | E7 |
| Role replacement | immutable keys, endpoint keys | detail routes | Overview, Changes | T4.4, T6.3 | E8 |
| Collection failure keeps the graph | coverage, `canEnd`, stale | `/coverage`, limitations | Coverage, stale markers | T3.3, T5.1, T6.5 | E9 |
| Shared objects | support rows, per-connector collection | `sources` on detail | Overview sources | T3.2, T4.3 | E10 |
| External accounts, cycles, limits | external principals | `/graph*` outcomes | Graph, Paths | T4.7, T6.4, T7.8 | E11 |
| Consistency while exploring | publication, snapshot reads, cursors, classification clock | §5.1, §5.5 | Revision banner, list restart | T6.1, T6.6, T7.2 | E12 |
| Recovery from interruption | barrier, job, replay | — | Pipeline states | T1.1–T1.5 | E13 |
| Workspace isolation | composite FKs | workspace from token | cache keyed by workspace | T6.7, T7.2 | E14 |
| Keyboard and narrow screens | — | — | §2.14.14 | T7.3, T7.8 | E15 |
| Existing products unchanged | `provider`, expand-only `030`, no AWS agents | GitHub readers filtered | Existing routes kept | T4.8, T7.12 | E16 |
| Evidence and limitations | observations, junctions | `/evidence` | Evidence panel | T3.5, T4.9, T6.5, T7.7 | E4 |
| Classification | `029` | §5.5 | §2.14.6 | T6.6, T7.11 | E12 |

## 7. Acceptance

**Nothing in this section has been executed against the design in this
document.** These are gates, not results. What has been demonstrated, and what
it does and does not show, is §7.6.

### 7.1 The end-to-end gate (M3)

Run through the **real backend and the real console**, against real AWS lab
accounts, by Playwright (T8.2) with a person reviewing the recorded runs.
Fixtures support development and failure-state checks (§7.2); they do not
substitute for this gate.

**The lab** (T8.1, Terraform, in AuthSec-owned AWS accounts):

| Account | Role in the lab | Contents |
|---|---|---|
| **A `production`** | Connected | Lambdas `ticket-tools` and `refund-tools` sharing `SharedToolRole`; managed policies `TicketRead` (statement `ReadTickets`) and `ToolboxRead` (no Sid), both allowing `s3:GetObject` on `arn:aws:s3:::support-tickets/*`; an ECS task definition with task and execution roles; an EC2 instance with an instance profile; a Bedrock agent and an AgentCore runtime and gateway (in a region that offers them); IAM group `ops` with user `priya` (with a permissions boundary) as a member; a role trusting account B's `data-reader`; a role with a Deny statement; a role trusting GitHub OIDC for `repo:authsec-ai/authsec:*` |
| **B `sandbox`** | Connected | A Lambda also named `ticket-tools`; role `data-reader`; a policy naming the same `support-tickets` bucket; roles `loop-a` and `loop-b` that trust each other |
| **C `partner`** | **Not** connected | A role trusted by A |

The discovery role in each connected account is the current CloudFormation
template. Scenarios that remove permissions do so by modifying that role and
restoring it afterwards.

| # | Scenario | Setup | Action | Expected — database | Expected — API | Expected — console | Fails if |
|---|---|---|---|---|---|---|---|
| **E1** | Connect and publish the first graph | Clean workspace | Connect A with regions `eu-central-1`, `us-east-1`; scan | One published run; one job `complete`; barrier `idle`; one `iga_publication` `rev 1`; no AWS rows in `iga_agents` | `/pipeline` moves queued → collecting → projecting → published; `/workloads` lists A's workloads at `rev 1` | First-run states in order; the list appears without a reload; *as of* shows the publication time | Any state is skipped or shown as empty; a reload is needed; the second scan cannot start |
| **E2** | The right workload among duplicates | A and B connected and scanned | Search `ticket` | Two workloads named `ticket-tools`, different accounts | `q=ticket` returns both with distinct `account`; facet counts per account | Both rows, each with its account; opening B's shows B's ARN and account throughout | Rows indistinguishable; search misses rows beyond page one; one opens the other's data |
| **E3** | Workload → identity → statements → resource | E1 | Open A's `ticket-tools`; Identities; Resources | `executes_as` to `SharedToolRole`; two grants; two statements; one selector | `/identities` returns the execution identity; `/resources` returns `support-tickets/*` with **two** grant lines | Identities names the role as execution identity; Resources shows the selector with two statement lines; the Graph draws the same path | Any hop missing; one grant line; "can access" wording anywhere |
| **E4** | Evidence and limitations | E3, plus a lab policy allowing `s3:*` with `NotResource: arn:aws:s3:::finance/*` | Open evidence on each grant, on the selector, on `priya`'s group grant; open `finance/*` › Access | Evidence junction rows for every edge | `/evidence` returns claim, status, facts (policy version, Sid, excerpt), freshness, limitations incl. `selector_may_match_nothing`, `effective_access_not_evaluated`, `permissions_boundary_present` for `priya`, `negated_statement` for the `NotResource` grant; `finance/*` › Access lists the statement under `excluded_by`, not `access` | Five parts, in order; raw record only on request; the `NotResource` statement drawn as *except finance/\** with no edge to it | A generic limitation; a missing fact; a limitation that does not apply; any path or access row ending at `finance/*` |
| **E5** | Two workloads share one role | E1 | Open `SharedToolRole` › Used by | Two `executes_as` rows to one identity | `/used-by` lists both | Both listed; Overview says *shared with 1 other workload* | One missing; the role shown twice |
| **E6** | Detach one of two equivalent grants | E3 | Detach `TicketRead` from `SharedToolRole`; rescan | `TicketRead` assignment and grant `ended`, `valid_to` set; `ToolboxRead` grant `current` | Resources shows one current grant line; Changes has `policy_detached` naming the remaining grant | *"The path remains through ToolboxRead"*; the canvas line stays solid | The path disappears; both grants end; the line turns dashed |
| **E7** | Policy edits and detach/reattach | E6 | (a) Edit `ReadTickets` actions; rescan. (b) Edit `ToolboxRead`'s statement; rescan. (c) Reattach `TicketRead`; rescan | (a) Same statement id; a new revision. (b) Old statement retired, new statement and grant. (c) A **new** assignment row; the ended period unchanged | Changes returns `statement_revised` with before/after, `statement_replaced`, `policy_attached` | Each event worded per §2.6 | (a) creates a new statement; (b) is shown as an edit; (c) reopens the old assignment row |
| **E8** | Replace a role, and a policy | E3, with an inline policy `ToolsInline` on `SharedToolRole` | (a) Delete and recreate `SharedToolRole` under the same name, with the same inline policy; rescan. (b) Delete and recreate `TicketRead` under the same ARN and Sid; rescan | (a) Old identity `retired` `recreated`; its edges `ended` `subject_recreated`; the old inline policy retired with its statements; new identity **and new inline policy**, new ids. (b) Old `TicketRead` `retired` `recreated`; its statements, assignments and grants retired or ended `policy_recreated`; new ones with new ids. Lifecycle events for every transition | Old objects readable with `lifecycle: retired`; new ones current | Changes: old role and policy ended, new ones started; nothing of the old history on the new objects | Any new object reuses an old id or key, or inherits history |
| **E9** | Collection fails and relationships are retained | E3 | (a) Remove IAM permissions from the discovery role; rescan; restore. (b) Deny `iam:GetPolicyVersion` on `TicketRead` only, and in the same change detach `ToolboxRead`; rescan | (a) Zero rows `ended`; IAM partitions `stale`; `last_confirmed_at` unchanged. (b) `TicketRead`'s grants and statements `stale`; `ToolboxRead`'s assignment and grants `ended` | `/coverage` reports the denied surfaces or the unreadable document with the failed API call; affected grants `state: stale` | Graph unchanged with stale markers; coverage names the call and what it prevents; no guessed missing permission | Anything unreadable ends; the detached policy stays current; coverage invents a permission name |
| **E10** | A shared object survives one source dropping it | A and B scanned | Remove B's policy naming `support-tickets`; rescan B | B's support row for the bucket reference `ended`; A's `current`; the resource `active`; A's grants unchanged | Resource detail `sources` shows A current, B ended | Resource still listed; Access shows A's grants | The resource retires; A's grant becomes `*` |
| **E11** | External accounts, cycles and limits | A and B scanned | Open A's role trusting C; open `loop-a`'s graph; expand past the display default; search a path to an unreachable resource | External principal for C, unresolved; `can_assume` edges both ways between `loop-a`/`loop-b` | `/graph` marks `closes_cycle`; `crosses_account`; frontier `more` counts exact or `null`; `/graph/path` returns `none_exists` or `not_found_within_budget` correctly | *Account not connected*; each loop node drawn once; truncation chip; the two not-found messages distinct | A cycle duplicates nodes; an unreachable search claims a distance; "none exists" when a budget bound |
| **E12** | Changes during paging and exploration | A scanned, > 200 workloads (lab fixture generator) | Page the list; mid-way, trigger a new publication; separately, classify a workload between pages of the *Agents* filter; retry a classification after dropping its response | — | `409 revision_stale` on the next page; `409 listing_changed` on the classification list; the retry returns `200 replayed: true` | Banner, data kept, Refresh restores view and filters; list restarts with notice; the retried save closes as success | Pages from two revisions combined; a retried save shows a conflict; a conflict shows success |
| **E13** | Interruption, lease loss and replay | A connected | Kill the scan worker mid-collection; kill the projector mid-projection; kill it after commit before completion; start a second worker while the first is paused | Exactly one publication per run; no rows written by a superseded worker; job `complete`; barrier `idle`; the next scan starts | `/pipeline` recovers without intervention | Pipeline states recover; the graph never shows a partial publication | A second publication for one run; a stuck workspace; a superseded write lands |
| **E14** | Cross-workspace access and cache isolation | Two workspaces, each with an account | Request the other workspace's object ids; switch workspace in the console mid-load | — | `404 not_found` for every foreign id on every route | No row from the previous workspace ever appears | Any foreign data returned or shown |
| **E15** | Keyboard and narrow screens | E3 | Complete E3's investigation keyboard-only, and at 375 px wide | — | — | Every step reachable; focus visible; Paths default on narrow screens; axe reports no serious or critical issues | Any step needs a mouse; a critical axe violation |
| **E16** | Existing products unchanged | A workspace with GitHub and Kubernetes integrations, plus AWS | Run the existing GitHub scan and Kubernetes collector; open Integrations, Discovered Agents, Cloud Inventory, governance pages; call `GET /api/iga/v1/identity-accounts` and `…/agents/:id/access-paths` | No AWS rows with `provider <> 'aws'`; no AWS rows in `iga_agents`; GitHub rows unchanged in shape | GitHub endpoints return only GitHub rows, same JSON fields as before plus additive ones | Every existing page behaves as before; Cloud Inventory rows link to the graph | Any existing flow changes behaviour; AWS rows appear in GitHub lists or the Kubernetes bridge |

### 7.2 UI gates

Three gates, deliberately separate. Passing one says nothing about the others.

| Gate | Who | Passes when | Recorded |
|---|---|---|---|
| **A. Design approved** | The product owner and the engineer who will build it | Every screen in §2.14 has every §2.14.7 state specified; every contract it uses exists in §5 | Date, commit of this spec, names |
| **B. Behaviour implemented** | Automated, against the §2.14.14 fixtures | Every scenario below passes **and** fails when its safeguard is removed | Test name, command, fixture, expected, observed, safeguard removed |
| **C. Usability observed** | Sessions with at least five people from the buyer's security or platform team who have not seen the product | At least four of five complete each task unaided in under two minutes | Per task: completed or not, time, what they said |

**B. Behaviour scenarios** (fixtures, MSW, Playwright)

| # | Scenario | Passes when |
|---|---|---|
| UI1 | Large inventory | Search finds rows beyond page one and the request carries `q`; paging never repeats or skips; *"of N found"* only when `total_known` |
| UI2 | Duplicate names across accounts | Two `ticket-tools` distinguishable in list, search, breadcrumb and canvas; never mixed from cache |
| UI3 | Deep links and the evidence panel | Every route, tab, filter set and `evidence` claim opens cold; Close/Escape/Back follow §2.14.5 exactly, never leaving a duplicate history entry |
| UI4 | Partial, truncated, failed, unauthorized, unsupported | Each renders its own §2.14.7 state; a failed refresh keeps the previous data with a warning |
| UI5 | Independent grants | Two statement lines; one grouped canvas line with *2 statements*; after detach, solid line, *1 current · 1 ended* |
| UI6 | Revision changes | Banner, data kept, paused reads, Refresh keeps context; no page mixing |
| UI7 | Classification | Not optimistic; `409` keeps input; *Replace with mine* is a new operation; a network failure retries with the same `operation_id` |
| UI8 | Unknown scope | *All accounts* includes unknown; a specific account shows *N with unknown account not shown*; an unresolved role keeps its workload's account |
| UI9 | Graph controls | *View in graph* highlights the target or shows the correct not-found form; collapse is reference-counted; cycles drawn once; **expansion moves no existing node** (positions asserted); Paths equals the canvas |
| UI10 | Accessibility | No serious/critical axe violation in any state; U1–U5 keyboard-only; live region announcements; reduced motion honoured |
| UI11 | Workspace isolation | A workspace switch mid-load shows nothing from the previous workspace |

**C. Usability tasks**

| # | Task | Fails if |
|---|---|---|
| U1 | Find which identity `ticket-tools` runs as | They cannot tell the execution identity from other identity relationships |
| U2 | Say what else uses that identity, and what that implies | The shared role is not visible from the identity |
| U3 | Explain why the path to `support-tickets/*` exists | They cannot name the statements, or say "it can access it" |
| U4 | Say what we could not see, and what that prevents | Coverage reads as a complaint rather than a bounded conclusion |
| U5 | Explain why removing one grant did not remove the path | The UI merged two grants |
| U6 | In 5 000 workloads, open the `ticket-tools` in **sandbox** | They open production's, or page instead of searching |
| U7 | A newer scan publishes mid-task: say what changed, then carry on | They lose their place, or believe the old result is current |
| U8 | Say which of production's resources cannot be attributed to an account, and why | Unknown account reads as an error, or is not found |
| U9 | Classify a Lambda, then explain the conflict when a colleague got there first | They overwrite without reading the other decision |

### 7.3 Backend scenarios

Executed against real PostgreSQL through the implementation; each counts only
once removing its safeguard makes it fail.

| # | Scenario | Passes when | Catches |
|---|---|---|---|
| B1 | Two workloads share one role | Two `executes_as`, one identity | A relationship key missing an endpoint |
| B2 | Two policies grant the same action; one detached | One grant ended, one current | Merged grants |
| B3 | A resource named by two accounts; one stops | One resource, two supports, one ended, resource active | Single-owner nodes; `cloud_resource` reassignment |
| B4 | IAM denied on rescan | Zero rows ended; non-vacuity: the same fixture with `reached` does end them | `canEnd` trusting the wrong signal |
| B5 | Scan → projection hand-off with different worker names | Projection completes on the first pass | A worker-held barrier |
| B6 | Crash after commit | Replay `AlreadyPublished`, no writes, job complete, barrier idle | A `<=` generation guard |
| B7 | Recreated role, same ARN | Two identities; old retired `recreated`; edges ended | ARN-only endpoint keys |
| B21 | Recreated policy, same ARN and Sid; recreated role with a same-named inline policy | New policy and statements with new keys; old ones retired `policy_recreated` / `recreated`; no statement id reused | ARN-based statement and assignment keys |
| B8 | Support ends then reappears, same immutable key | Restored: same id and `first_seen_at` | Reappearance treated as recreation |
| B9 | Cross-workspace references | Every composite FK rejects a foreign row; one test per FK | The A3 pattern |
| B10 | Deny and boundary statements | Zero grants; restrictions present | A Deny as access |
| B11 | Statement identity | Reorder keeps ids; Sid edit keeps id with a revision; Sid-less edit replaces | Index-keyed statements |
| B12 | One unreadable document and one genuinely detached policy, one run | Unreadable: statements, grants and sole-named resource support stale. Detached: assignment and grants ended | An account-wide veto, or ending what could not be read |
| B13 | Switch off at `036` | Two consecutive scans publish; no job, no barrier change | Table-probing enablement |
| B14 | Schema verification error | Worker claims nothing; `/capabilities` `misconfigured` | Fail-open caching |
| B15 | Busy barrier | The refused run does not starve another workspace | The requeue hot loop |
| B16 | Reads straddling a publication | A read in flight when a publication commits returns only the old revision | Non-snapshot reads |
| B18 | Attach → detach → reattach | Assignment period 1 ended; period 2 a new row; grants follow each; `scope()` rejects an unknown target | A default table in `scope()` |
| B19 | `NotResource` | Grant to `*` only; no traversal edge, path or `access` row to the excluded resource; `excluded_by` lists it | Exclusions as destinations |
| B20 | Cross-workspace and cross-integration collection facts | Membership, inline holder, attachment principal and attachment policy from another workspace or integration rejected; same-integration controls accepted | Single-column references to `cloud_identity` |
| B22 | Two concurrent retries of one classification operation | The second replays (`200`, `replayed: true`) | Operation lookup before the lock |
| B23 | Deadlines | An optional count that times out → `total_known: false`, page returned; graph at the deadline → `200` with `truncated.bound_by: "time"`; a mandatory query past the deadline → `504` | Timeouts poisoning the transaction; incompatible outcomes |
| B24 | Lifecycle history | Retire → restore → further upserts: both events remain, with rev, run and reason | Lifecycle read from the overwritten node row |
| B17 | Limits suppress completeness | Any bound budget → `total_known: false` / `truncated` / `not_found_within_budget` | Truncation presented as an answer |

### 7.4 Recording results

Every gate result — P2-0, §7.1, §7.2 B, §7.3 — is recorded with: commit,
exact command **including environment variables** (for example
`TEST_DATABASE_URL`, `IGA_TEST_DSN`, `S0_DSN`), pass / **skip** / fail counts,
fixture or lab state, expected, observed, and the safeguard removed with its
observed failure. **A run with skipped tests is not a pass for those tests**:
the graph branch's integration suite skips 130 of 145 tests without
`IGA_TEST_DSN`, and green output then proved nothing about them.

### 7.5 Supported deployment states

Migrations run on boot, so a rollout passes through intermediate states in
production. Only these are supported:

| State | Schema | `IGA_GRAPH_PROJECTION` | Must hold |
|---|---|---|---|
| **S0** | `001`–`026` | — | Today |
| **S1** | `001`–`036` | `off` | Phase 1 scanning exactly as today, any number of consecutive scans; nothing written to graph tables; GitHub and Kubernetes unchanged; rollback to `0e75ad7` works |
| **S2** | `001`–`036` | `on` | The full pipeline; §7.1 |
| **S3** | `001`–`037` | `on` | After the rollback window; GitHub no longer references the legacy subject columns |

`027`–`036` ship in one release in S1. Switching to S2 is a configuration
change after the release is verified, and switching back to `off` returns to
S1 behaviour immediately.

### 7.6 What has actually been demonstrated

Results as of 23 Sep 2026. **None of them validates the design in this
document**; they are what exists to build on.

| What | Observed | What it shows | What it does not |
|---|---|---|---|
| Graph branch `7eb8bed` suites, rerun independently | Graph 54 pass / 0 skip / 0 fail; integration (at `034`, `IGA_TEST_DSN` set) 159 / 0 / 0; build, vet and isolation check clean; `001`–`026` byte-identical to production | Its tests are genuine and reproducible | Anything about two consecutive worker scans, the hand-off, gateways, or shared resources through `Load` — none is exercised |
| Proof 4 mutation, rerun | Disabling the publication check makes the replay fail with *watermark equals generation* | The replay logic is load-bearing and tested | — |
| Probe: first scan with no projector wired (`TestProbeFirstScanWedgesWithoutAProjector`) | After one publish, neither the account's next scan nor another account's can start, a day later | The wiring defect (§1.3) | — |
| Probe: hand-off (`TestProbeProjectorWaitsForBarrierExpiry`) | Projector refused three times while the barrier was held in the scan worker's name; completed only after expiry | The hand-off defect (§2.10A) | — |
| Earlier mutations on `5bc5809` | Five safeguards each shown load-bearing (canEnd, retireUnsupported, scope, attachEvidence, unqualified evidence) | Those mechanisms, which this design keeps | — |
| This document's SQL, `028`–`037` (23 Sep) | Extracted from §3 and applied in order on a fresh PostgreSQL 16 with the shipped `001`–`026` and the graph branch's `027`: **all apply**. 27 constraint probes on a database at `036`, each rejection paired with a control that must succeed: **27 of 27 as expected**, including a GitHub-shaped legacy edge accepted (the rollback case), the Deny-statement and grant checks, the observation subject and dedupe widening, revision uniqueness, reattach-as-new-row, operation-id uniqueness and cross-workspace FKs; `iga_access_edges_honesty_chk` present | That the DDL is internally consistent and enforces what §3 says it enforces | Anything about production: the **production-schema rehearsal (§9) has not been run** (it needs a dump from someone with production access). Nothing about the Go control flow, which does not exist yet |
| The previous revision's `027`–`034` SQL | Applied on `001`–`025` with state-transition probes | The transitions `027`, `032`–`034` keep | — |
| Review fixes (23 Sep, second round) | **Composite collection keys:** with the revised `035` on the real `001`–`034` schema, the four cross-workspace / cross-integration inserts the review found accepted are now rejected (membership, inline holder, attachment principal, attachment policy) plus a second-integration holder; four controls accepted — 10 of 10. **Classification race:** two sessions, the retry blocked on the workload lock while the original committed; before the lock it found no operation, after it found it and took the replay branch. **Timeouts:** without a savepoint a timed-out statement aborts the transaction; with one, `ROLLBACK TO SAVEPOINT` recovers in the same snapshot | The DDL and the transaction orderings the fixes rely on | The Go reconciler, projector and reader, which do not exist yet |
| Graph rendering (§2.14.15) | Measured in a scratch project | Compatibility, layout timing, bundle size, keyboard, stability | The console integration |

## 8. Known-failing tests and ratchets

At `0e75ad7`, with `IGA_TEST_DSN` pointing at a database migrated to `026`,
the integration suite passes in full (run 23 Sep). Without the variable most
of it **skips**, which is why §7.4 requires skip counts.

On the graph branch the suites pass as recorded in §7.6; its
`TestIGACheckpointsAndSurvivorship` regression (`RETURNING id` on a table with
no id) was fixed in `4504426`.

Console ratchets that must not rise, re-counted before T7.1 and recorded in
the T7.1 change: TypeScript errors (`tsc --noEmit -p tsconfig.app.json`,
counted with `grep -c "error TS"`) and ESLint errors (`-f json`, summing
`errorCount`; the human formatter reports zero regardless, and a parse error
reports as one and masks everything behind it).

## 9. Verification

**Execute the spec, not just read it.** For the schema, extract each migration
section's SQL and apply it, one file per transaction, on top of the shipped
migrations — and then on top of a **production schema dump**:

```bash
# Fresh: 001–026 as shipped, then this document's 027–036 in order.
for f in $(ls migrations/master/0*.sql | sort); do
  psql "$DB" -v ON_ERROR_STOP=1 --single-transaction -q -f "$f"
done

# Production: the schema only, no rows, restored into a scratch database.
# Someone with production access takes the dump; nothing is run against production.
pg_dump --schema-only "$PROD_URL" > prod-schema.sql
createdb iga_rehearsal && psql iga_rehearsal < prod-schema.sql
psql iga_rehearsal -c "SELECT count(*) FROM cloud_observation o JOIN cloud_scan_run r
                       ON r.id = o.scan_run_id WHERE r.workspace_id <> o.workspace_id"
# expected: 0  (027's pre-flight; also run against production itself before the release)
for m in migrations/master/0{27,28,29,30,31,32,33,34,35,36}_*.sql; do
  psql iga_rehearsal -v ON_ERROR_STOP=1 --single-transaction -f "$m" || { echo "FAILED: $m"; break; }
done
```

Then check the resulting schema has **every column the code uses**, not only
that the SQL applied — an applied, incomplete migration is the failure this
catches. And run probes, each with a control row that must succeed so a
rejection cannot pass because the seed was broken:

| Probe | Expected |
|---|---|
| AWS statement row without `policy_id` | rejected, `iga_entitlements_aws_statement_chk` |
| AWS grant without `assignment_id`, or with `resource_id` set | rejected, `iga_access_edges_aws_grant_chk` |
| GitHub-shaped access edge (legacy pair, no typed subject) | **accepted** — `030` is expand only |
| Typed subject disagreeing with the legacy pair | rejected, `iga_access_edges_subject_agree_chk` |
| `can_assume` without a mechanism | rejected, `iga_relationship_trust_chk` |
| `executes_as` whose source is an identity | rejected, `iga_relationship_pair_chk` |
| An observation with two subjects (`policy_id` and `identity_id`) | rejected, `cloud_observation_subject_chk` |
| Duplicate policy observation (same subject, API, hash) | conflicts on `uq_cloud_observation_dedupe` |
| Two live revisions for one statement | rejected, `uq_iga_statement_revision_live` |
| Assignment reattached after ending | a second row accepted; the ended row unchanged |
| Classification decision reusing an `operation_id` | rejected, `iga_wc_operation_key` |
| Support row with two typed columns, or none | rejected, `iga_object_support_one_chk` |
| Any composite FK given another workspace's row | rejected, one probe per FK |
| `iga_access_edges_honesty_chk` from `004` | still present |
| Group membership, inline-policy holder, attachment principal or attachment policy from another workspace **or another integration** | rejected by the composite FKs (`cloud_gm_*`, `cloud_policy_holder_fkey`, `cloud_pa_*`); same-integration controls accepted |
| A policy with neither a document nor a `document_error` | rejected, `cloud_policy_readable_chk` |
| A lifecycle event whose revision has no publication, at commit | rejected (deferred `iga_le_publication_fkey`); inserting the publication in the same transaction commits both |

Then the code:

```bash
go build ./... && go vet ./...
bash scripts/ci-iga-isolation-check.sh
TEST_DATABASE_URL=… IGA_TEST_DSN=… S0_DSN=… S1_DSN=… \
  go test -count=1 -p 1 -v ./... 2>&1 | tee test.txt
grep -cE '^\s*--- PASS' test.txt; grep -cE '^\s*--- SKIP' test.txt; grep -cE '^\s*--- FAIL' test.txt
```

Every acceptance item needs a named test. **An item verified only by reading
code is not verified**, and a test that passes for the wrong reason is worse
than none: check each by removing the fix and confirming the test fails.
