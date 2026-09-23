# SPEC: Phase 2 — objects and the identity graph

> The phase after [SPEC-iga-phase1-collect.md](SPEC-iga-phase1-collect.md).
> Product context is
> [SPEC-agentic-access-management.md](SPEC-agentic-access-management.md); the
> invariants this phase must honour are [SPEC-iga-roadmap.md](SPEC-iga-roadmap.md) §3.
>
> **Verified 2026-09-21** against backend `efb67b2`, migrations `001`–`025`; `026` (governance schema parity)
> is written and precedes this phase — see §3.
> Every table, column, file and line cited below was read. Claims that a
> function or constraint *does* something were checked against its body, not
> against its name.

**Exit gate (roadmap §4).** Repeat scan keeps IDs and `first_seen_at`; role
replacement closes the old edge; key rotation preserves the account; recreation
is recorded; a registered agent is distinguished from native discovery.

**Achievable outcome.** A trustworthy stored identity graph the team can inspect
and explain, plus the one read path in P2-11. Customer-facing traversal and
visualization are Phases 4 and 5 and are not attempted here.

---

## 1. What this phase is

Phase 1 made collection durable and evidenced. Everything it collects lands in
`cloud_*`, keyed by AWS native ids, scoped to one connector. That is a
**per-provider record of what we read**.

Phase 2 builds the **provider-neutral graph** on top of it: stable objects that
survive rescans, typed relationships that carry lifecycle and evidence, and a
projection that can be rebuilt from evidence at any time.

### In scope

- Four Phase 1 defects that block any graph (§1.2). They are fixed here because
  Phase 2 is the first consumer that needs evidence to be durable.
- Recognition keys and continuity on the canonical node tables.
- `iga_workload` — the runtime, missing from the canonical model.
- Typed, workspace-scoped, FK-enforced endpoints on **both** ends of every
  relationship, with an enumerated set of legal source/target pairs.
- Relationship lifecycle: `current | stale | ended`, with `basis`, validity
  window, last-confirmation and evidence.
- A **durable, separately-fenced projector** running `cloud_* → iga_*`.
- Reconciliation per `(scope, object class, relationship type)`, gated on a
  persisted per-run coverage report.
- Agent origin (`registered` vs `discovered`) and a real instance read path.

### Out of scope

- **Statement identity.** Phase 2 projects one entitlement per collected grant
  occurrence (§2.6). Statement revisions, operative policy versions and
  selector resolution are Phase 3.
- **Effective access.** Conditions are recorded, never evaluated (roadmap §3.5a).
- **Traversal API and console.** Phases 4 and 5. §2.14 specifies the
  experience and §2.15 the contracts it needs, so neither is invented twice; P2-11 builds only the first read
  path.
- **Migrating the GitHub path.** GitHub keeps writing through `ingestGrant`;
  P2-4 makes that write path correct rather than replacing it.
- **Physical IGA isolation.** Settled: `iga_*` stays in `public`, enforced by a
  CI check, not a privilege boundary — `discovered_agent_iga_links`
  deliberately foreign-keys IGA to the legacy runtime channel, so a grant
  boundary would break a designed feature. See [roadmap §2.1](SPEC-iga-roadmap.md)
  and the cutover gate in the product doc §8. Reopening this is a cutover
  decision, not a Phase 2 one.

### 1.1 Starting state — the canonical tables

**The canonical tables have no recognition key. At all.** `iga_agents`
(`004_agentic_iga.sql:532`) is `id, workspace_id, estate_scope_id, display_name,
classification, status, rollup_state, lifecycle, version, created_at,
updated_at` — that is the whole table. Same for identity accounts, resources and
entitlements. **There is no column a rescan could match on**, so "repeat scan
keeps IDs" is not a bug in the code; it is impossible in the current schema.

**Every canonical upsert is a bare `Create`** (`repository/iga_repository.go:616-629`).
All five are named `Upsert*` and none upserts. The caller assigns
`ID: uuid.New()` before each call (`services/iga_service.go:863,885,899,918`).

**`iga_access_edges` has an untyped subject and no lifecycle.** Its entitlement
and resource ends are correctly composite-FK'd to `(workspace_id, id)`; the
subject end is `subject_kind text` + `subject_id uuid` with **no foreign key of
any kind**. That is A3, and `004:694` is its location.
`iga_observation_links:793` repeats the pattern.

**Blast radius is asymmetric.**

| Table | Non-test Go files | Meaning |
|---|---|---|
| `iga_resources` | 49 | load-bearing for governance |
| `iga_agents` | 44 | load-bearing for governance |
| `iga_entitlements` | 18 | load-bearing for governance |
| `iga_identity_accounts` | 2 | projection only |
| `iga_access_edges` | 1 writer, 1 reader | projection only |
| `iga_agent_instances` | **0** | declared, never written |

Nothing foreign-keys `iga_access_edges` — the only references in the migrations
are two of its own indexes. It can be rewritten in place.
`services/iga_service.go:1300` returns `Instances: []models.IGAAgentInstance{}`
unconditionally: the instance concept is in the schema and not in the product.

### 1.2 What `024` closed, and the one gap it left

Four defects blocked any graph: coverage was not per-run, evidence was deleted by
inventory churn, content dedupe erased run confirmation, and the completeness
gate was unclear. Migration `024` (`b47adeb`, merged) closed **all four**.

| | Closed by | Note |
|---|---|---|
| **D1** coverage not per-run | `cloud_scan_run.coverage` jsonb, stamped at publish | One column on the existing per-run anchor, rather than a separate `cloud_scan_coverage` table. Same guarantee, less schema |
| **D2** completeness gate | Composition, not a new counter | See below — this one is easy to misread |
| **D3** evidence deleted by churn | Subject FKs `CASCADE` → `SET NULL`, plus `subject_native_id` | **Better than proposed.** The ARN is captured at write time, so an orphaned observation still says what it was evidence *for*. The subject CHECK relaxes from "exactly one" to "at most one" to permit that state |
| **D4** dedupe erased confirmation | `last_confirmed_run_id`, `last_confirmed_at`, `confirmation_count` on `cloud_observation` | Stamped in the `OnConflict → DoUpdates` at `services/cloud_observation_writer.go:246-248`, i.e. exactly on the dedupe path. A column rather than a junction table: it answers "did **this** run confirm it", which is what `canEnd()` needs, but holds only the latest run rather than every one |

**D2 is the one to read carefully, because `Complete()` looks broken in
isolation and is not.** `models.ScanCoverage.Complete()` iterates surface states
and consults no counter — which invites the conclusion that
`ParseFailures`/`StatementsSkipped` never gate anything. They do, one level up:

```
cloud_aws_permission_scan.go:226   ParseFailures or StatementsSkipped > 0
                                     → Surfaces["policy_documents"] = surfacePartial(…)
cloud_aws_iam_scan.go:765          FinalizeCoverage merges permSurfaces into merged.Surfaces
models/cloud_discovery.go          Complete() sees state `partial` → default: return false
```

The counters are folded into a surface **state** before `Complete()` ever runs.
That keeps `Complete()` a pure function of surface states and makes each scanner
responsible for encoding its own failure modes as coverage — which is the better
design. **Do not "fix" this by adding a counter check to `Complete()`.** It would
duplicate a gate that already holds, and the second copy is the one that drifts.

#### What is still open

**§2.9 — cross-workspace provenance.** `024` added no `UNIQUE (workspace_id, id)`
and, in closing D4, introduced a third single-column foreign key to
`cloud_scan_run`. Migration `027` closes it. This is the only Phase 1-adjacent
item left, and it belongs before the projector: if the projector's foreign keys
are written single-column they have to be redone.

## 2. The model

### 2.1 Three models were in play. This resolves them.

The tree currently contains all three:

1. the `iga_*` tables from `004`, with the defects in §1.1;
2. `cloud_*` as authoritative collected model, with
   [SPEC-aws-discovery.md](SPEC-aws-discovery.md) describing `iga_*` as a
   *"projection, one-way, rebuildable"*;
3. a typed object registry sketched in roadmap §3.2 — `iga_object` with a
   `GENERATED ALWAYS AS (…) STORED` discriminator — **which exists in no
   migration**.

**Decision: (2), implemented by extending the tables from (1) in place. The
registry in (3) is not built.**

```
AWS ──collect──▶ cloud_* ──project──▶ iga_* ──read──▶ governance, console
               authoritative        canonical,
               per-connector        provider-neutral,
               evidence + coverage  rebuildable
```

`cloud_*` is never derived from `iga_*`. Deleting all `iga_*` rows for a
workspace and re-projecting must reproduce the graph exactly, except
human-owned columns (ownership, review state, classification, confirmed origin).

**Why not the registry.** It satisfies the same invariant at much higher cost:
every canonical node would need a parent row, changing the insert path across
the ~110 non-test files touching `iga_agents`, `iga_resources` and
`iga_entitlements`. The cheaper mechanism is already proven here —
`022_cloud_observation.sql:74` enforces typed endpoints with nullable typed FK
columns plus an exactly-one `CHECK`. Adding a further endpoint type later costs
one migration that adds a column and widens the constraints.

> **Roadmap §3.2's mechanism paragraph was updated to match.** The invariant
> (typed endpoints, no `(kind, uuid)` pairs) stands unchanged.

### 2.2 Relationships: two shapes, both fully typed

A single edge table with typed subjects but fixed entitlement/resource targets
cannot express workload→identity, identity→identity or instance→workload — there
are no endpoint columns for them — and it permits an edge with no target at all.
These are two genuinely different shapes and are kept apart:

**`iga_access_edges` — the access-grant triple.** `identity account → entitlement`,
with the resource denormalized for the reverse query. Ternary. Carries
`calculation_state`/`effective_conclusion`. `entitlement_id` becomes
`NOT NULL`: an access edge that grants nothing is not a fact about access.

**`iga_relationship` — binary structural edges.** Source and target are each one
of four typed FK columns, and `relationship_type` determines which pair is
legal. Three types in Phase 2:

| `relationship_type` | Source | Target | Projected from |
|---|---|---|---|
| `executes_as` | workload | identity account | `cloud_workload.identity_id` |
| `can_assume` | identity account | identity account | `cloud_assume_edge` |
| `realizes` | agent instance | workload | `cloud_workload` where Bedrock/AgentCore |

The legal pairs are a `CHECK` with an `ELSE false` arm (§3.5), so a fourth
relationship type cannot be inserted until someone widens the constraint
deliberately. `entitlement → resource` is **not** a relationship: it is
`iga_entitlements.resource_id`, which already exists and is already FK'd.

Both tables carry the same lifecycle columns and both have an evidence junction.

### 2.3 What an edge may claim

Roadmap §3.1, non-negotiable:

| Edge | Claim | Does NOT mean |
|---|---|---|
| workload → identity | configured execution identity | that it ran, or ran as that |
| identity → identity | trust permits assumption | that assumption succeeds |
| identity → entitlement | a policy assigns this | that a request would be allowed |
| entitlement → resource | a selector names this | that the resource exists |
| person → agent | accepted accountability | any cloud permission |

`basis` is a column:

```
declared   provider configuration says so
observed   we saw it happen, with attribution
derived    we computed it, naming the rule and its inputs
asserted   a human decided it, with authority recorded
```

Everything Phase 2 projects is `declared`. Nothing produces `observed` — no
CloudTrail collector exists. `derived` requires a non-empty `derivation_rule`,
enforced by CHECK.

### 2.4 Node identity and continuity

**`source_key` is namespaced, always.** A bare native id is never unique. The
stored form is

```
provider | partition | account-or-project | region-if-regional | native-id
```

joined with `\x1f` (unit separator — cannot occur in an ARN). An ARN already
carries partition, account and region, so for AWS the key is
`aws\x1farn:aws:iam::123456789012:role/foo`. The generalised form exists so
GitHub and Kubernetes keys cannot collide with AWS or each other.

Build it in exactly one place — `internal/igagraph/sourcekey.go`, one exported
function — and never format it inline. Two spellings of the key is the same
duplication bug in a new costume.

| Node | Table | Projected from | Recognition key |
|---|---|---|---|
| Identity account | `iga_identity_accounts` | `cloud_identity` | role/user ARN |
| Workload | `iga_workload` *(new)* | `cloud_workload` | function / task-def / instance ARN |
| Resource | `iga_resources` | `cloud_resource` | resource ARN, or the selector when unresolved |
| Entitlement | `iga_entitlements` | `cloud_permission` | see §2.6 |
| Credential | `iga_credentials` | `cloud_secret` | key id, namespaced by its identity |
| Agent | `iga_agents` | `cloud_workload` where Bedrock/AgentCore, or registered | agent ARN, or the registration id |

Continuity columns on all six:

```sql
source_key    text        NOT NULL,
continuity    text        NOT NULL DEFAULT 'recognition_only',
immutable_key text        NOT NULL DEFAULT '',
first_seen_at timestamptz NOT NULL DEFAULT now(),
last_seen_at  timestamptz NOT NULL DEFAULT now(),
```

with a unique index on `(workspace_id, source_key)`. `continuity` is `immutable`
only where the provider gives a creation-boundary id: IAM role (`RoleId`,
`AROA…`), IAM user (`UserId`, `AIDA…`), EC2 instance. Lambda, ECS task
definition and S3 bucket are `recognition_only` — storing it lets the console
say *"same name is the strongest claim available here"* rather than implying
more.

**Delete-and-recreate** applies only where `continuity = 'immutable'`: same
`source_key`, different non-empty `immutable_key` ⇒ **new object**. The old row
retires with `retired_reason = 'recreated'`; the new row gets its own `id` and
its own `first_seen_at`. Merging them would carry last quarter's ownership
decision and review history onto an unrelated principal.

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

### 2.6 Entitlement grain — the collision, and the decision

`uq_cloud_permission_grant` is `ON cloud_permission (identity_id, native_id,
resource_id) NULLS NOT DISTINCT` (`013:178`). So a `cloud_permission` row's
grain is **(identity, statement, resource)**: one statement naming three
resources produces **three rows**. And inline policies are named
`"inline:" + p.Name` (`services/cloud_aws_permission_scan.go:410`), which is
unique only *within an identity* — two roles can each have an inline policy
called `ReadData`.

Keying entitlements by "policy ARN + statement index" therefore collides three
ways at once: across the resources of one statement, across identities sharing
an inline policy name, and on any statement reorder. Deferring statement-order
stability to Phase 3 fixes none of them.

**Decision: one entitlement per grant occurrence, keyed by its policy scope.**

```
managed policy:  aws | <policy ARN>   | <native_id> | <resource key or '*'>
inline policy:   aws | <identity ARN> | <native_id> | <resource key or '*'>
```

The policy scope is what makes this correct. A **managed** policy is genuinely shared: two roles attached to it get
**one** entitlement and **two** access edges — which is what makes *"managed
policy detached ⇒ the grant ends, the entitlement and its document survive"*
(§2.7) true rather than aspirational. An **inline** policy is not shared, so its
key is namespaced by the identity that owns it and the `ReadData` collision
disappears.

`cloud_aws_permission_scan.go:496` already discriminates on the `inline:`
prefix; reuse that, do not re-parse.

> **Entitlement ids are not stable across Phase 3.** Phase 3 collapses the
> three resource-rows of one statement into a single statement entitlement plus
> three grant-resource rows, which re-keys them. **Attach no review decision,
> no ownership and no certification to an entitlement id in Phase 2.** Put this
> in the migration comment, not only here.

### 2.7 Relationship lifecycle

- **`current`** — a recent authoritative read confirmed it.
- **`stale`** — we could not look. Still believed, with its last confirmation
  time shown. A failed, denied or throttled scan produces this and **never**
  `ended`.
- **`ended`** — an authoritative read of the owning scope and class did not see
  it.

A relationship may move to `ended` only when **all four** hold:

1. the run reached `status = 'published'` — **the value is `published`**; the
   `cloud_scan_run` CHECK is `('queued','running','published','failed','abandoned')`
   (`020:71`) and there is no `complete`;
2. that run's own `cloud_scan_run.coverage` report (`024`) records the owning
   `(scope, surface)` as `reached` — not `cloud_connector.coverage`, which a
   later scan has overwritten. Read the stored report; do **not** re-derive it.
   Parse failures already turned the surface `partial` upstream (§1.2), so a
   `reached` surface in the persisted report has passed that gate;
3. the relationship's own source surface was among what **that run** read,
   proven by `cloud_observation.last_confirmed_run_id` naming this run (`024`),
   because content dedupe means the absence of a *fresh* observation row proves
   nothing;
4. the projection job owns the generation for that partition (§2.8).

**Collapsing `stale` into `ended` lets a permissions outage read as a cleanup.**
Ended rows are never deleted: a review decision made last quarter must remain
explicable against the access that existed then.

| Case | Expected |
|---|---|
| Lambda moves `RoleA` → `RoleB` | old `executes_as` `ended` with `valid_to`; new `current`; both in history |
| managed policy detached from one of two roles | that role's access edge `ended`; the entitlement and the other role's edge untouched |
| second access key added to a user | second credential `active`; identity id, `first_seen_at` and every relationship unchanged |
| access key disappears | credential `revoked` — only under the four conditions above |
| role deleted and recreated, same name | old object retired `recreated`; new object, new `first_seen_at`; old relationships `ended` |
| scan of that scope denied | relationships `stale`, never `ended` |
| one of two integrations loses visibility | relationship stays `current`; the losing stream is stale |

### 2.8 Projection execution: durable, separately fenced

**The projector cannot run under the scan lease.** `Publish()` sets
`lease_owner: ""` and `lease_expires_at: nil`
(`repository/cloud_scan_run_repository.go:152`), and `fenced()` requires
`lease_owner = ?` — so any fenced call after publication returns `ErrLeaseLost`
and affects zero rows. Projecting "after publication, under the same lease" is
therefore not implementable, and simply moving the call earlier would make a
projection failure fail the scan.

**Design: projection is its own durable, leased work item.**

- `iga_projection_job` mirrors `cloud_scan_run`'s proven pattern:
  `Enqueue/Claim/Renew/Complete/Fail`, `lease_owner` + `lease_version`, fenced
  updates that **consult no clock**. Do not invent a second ownership notion;
  copy the one that already works.
- **Enqueue is in the same transaction as `Publish()`.** A published run always
  has a job; a crash between the two is impossible rather than recovered.
- **Inputs are the published run's immutable artefacts**: `cloud_observation`
  (append-only, generation-stamped) and `cloud_scan_run.coverage` (stamped once,
  at publish). `cloud_*` inventory rows are read only at the job's own
  generation.
- **Staleness resolution.** `cloud_*` rows are mutable and a newer scan can
  change them. If a claimed job finds `cloud_connector.scan_generation` has
  advanced past its own, it **abandons** — the newer run's job will do the work,
  with better data. Abandoning is recorded, not silent.
- **Crash recovery.** The job lease expires and the job is reclaimed. Projection
  is idempotent (an acceptance criterion), so re-running is safe.
- **Atomic visibility.** One transaction per `(scope, class)` partition, which
  flips `iga_projection_state.reconciled` at commit. A partition is never
  half-visible.

### 2.9 Every provenance reference is workspace-qualified

A single-column `FOREIGN KEY (last_confirmed_by) REFERENCES cloud_scan_run (id)`
admits **another workspace's** scan run. That is the same A3 class of defect
these migrations exist to close, and it is easy to reintroduce two lines below
the fix.

**Rule for this phase: no single-column foreign key to a workspace-scoped
table.** Every reference is `(workspace_id, id)` against a
`UNIQUE (workspace_id, id)`. `cloud_scan_run` and `cloud_observation` lack that
unique constraint today; `027` adds it. This applies to `last_confirmed_by`,
`iga_projection_state.last_run_id`, `iga_projection_job.scan_run_id` and every
evidence junction.

`cloud_observation.scan_run_id` (`022:42`) is itself a single-column FK to
`cloud_scan_run(id)` — the same gap, in Phase 1 code. `027` qualifies it.

### 2.10 Two mechanisms the rest of the design rests on

Everything about correctness under concurrency and sharing reduces to these
two. They are stated here, once, and §4 implements exactly them.

#### A. The pipeline barrier — durable, workspace-wide

A published run's inventory must not change while its projection reads it.
Three writers can change it, and the first two defeat any per-connector rule:

| Writer | Why per-connector locking misses it |
|---|---|
| Another connector's scan | `uq_cloud_resource_native` is `(workspace_id, native_id)` with no connector (`013:86`), and `UpsertResource` reassigns `connector_id` (`cloud_permission_repository.go:111`). Two connectors never contend for the same lock, yet both write the row |
| A superseded worker still running | It holds no lock to lose |
| The next scan of the same connector | The only one a per-connector rule catches |

**An advisory lock cannot express this.** `pg_advisory_xact_lock` is released
when its transaction commits, and publication and projection are necessarily
*different* transactions — projection is a durable job claimed later. The
window between them is exactly where the overwrite happens.

So the barrier is a **row**, not a lock:

Its DDL is migration `027` (§3); it is not repeated here.

Every transition is one conditional `UPDATE`, atomic and recoverable:

| Transition | Guard | Effect |
|---|---|---|
| scan claim | `state='idle' AND version=?` | `collecting`, `version+1`, new `holder` |
| publish | `state='collecting' AND version=?` | `projecting`, **in the publish transaction**, job enqueued |
| projection done | `state='projecting' AND version=?` | `idle`, `version+1` |
| **recover `collecting`** | `state='collecting' AND expires_at < now()` | `collecting`, `version+1`, new `holder` — **same run, same phase** |
| **recover `projecting`** | `state='projecting' AND expires_at < now()` | `projecting`, `version+1`, new `holder` — **same phase** |
| **abandon** | expired, past the attempts ceiling | terminalize the scan run **and** its projection job, *then* `idle`, `version+1` |

**Expiry alone must never return the barrier to `idle`.** A `projecting`
lease whose worker died still has a published run whose inventory is being
read; releasing the barrier lets the next scan rewrite a shared resource
underneath it, which is the exact overwrite §2.10A exists to prevent. Recovery
therefore **reclaims the same phase under a new fencing version** — the dead
worker is fenced out by the version, and the phase invariant holds throughout.

Only `abandon` returns to `idle`, and it is not a timeout: it fires past the
attempts ceiling and **first drives both the scan run and the projection job
to a terminal state in the same transaction**. Nothing is admitted while
either could still commit.

```
                 expired                    expired
        ┌───────────────────────┐  ┌──────────────────────────┐
        ▼                       │  ▼                          │
     collecting ──publish──▶ projecting ──done──▶ idle ──claim─┘
        │                       │                  ▲
        └──── abandon ──────────┴──────────────────┘
              (terminalize run + job first)
```

Every ownership check binds **(workspace, phase, run-or-job id, version)** —
not the version alone. A worker holding `collecting@v7` cannot perform a
`projecting` transition even if the version happens to match, because the
phase is part of the predicate.

`state='projecting'` is what a later scan's claim collides with, and because
it is a committed row rather than a session lock, it survives the gap between
the two transactions. Recovery is the expiry sweep, so a dead worker cannot
wedge a workspace permanently.

> **Cost, stated plainly: scanning is serialized per workspace, not per
> connector.** A customer with five AWS accounts scans them one at a time.
> That is a real throughput ceiling and it is the price of the guarantee —
> the shared-resource writer crosses connectors, so nothing narrower is
> sound. Revisit only by removing the sharing (per-connector resource rows)
> or by projecting from immutable inputs, not by narrowing the barrier.

**Cancellation is not a fence.** Cancelling a superseded scanner's context is
necessary — it stops work promptly — but it cannot *establish* that the
worker has stopped: `UpsertIdentity(i *models.CloudIdentity)` takes no context
and writes through `r.db` (`cloud_identity_repository.go:73`), and even a
context-aware write can be in flight when cancellation is observed. So
inventory mutations must also **validate ownership in the same transaction as
the write**, against the same row `reclaim` updates:

```go
// P2-2: every inventory upsert takes the run's fence and checks it.
func (r *cloudIdentityRepository) UpsertIdentity(
    ctx context.Context, fence ScanFence, i *models.CloudIdentity,
) (*models.CloudIdentity, bool, error)
```

Cancellation for promptness, the fence for correctness. Neither substitutes
for the other.

#### B. Per-source support — a shared node has no single owner

A resource, and a managed-policy entitlement, can be supported by **several**
connectors at once: accounts A and B both attach `RefundS3Access`, both name
the same bucket. Recording one `connector_id` and one `last_confirmed_run_id`
on the node makes the most recent scanner its apparent owner, and then:

```
A and B both support entitlement E
B scans last, so E records B as its membership
B detaches the policy
B's reconciliation retires E -- while A still holds it
```

Serialization does not help; this happens sequentially and is still wrong.

**Object identity and source support are separate rows.**

Its DDL is migration `032` (§3); it is not repeated here.

- **Projection** upserts one support row per `(object, connector, partition)`
  it observed, stamping `last_confirmed_run_id`.
- **Reconciliation** acts on **support rows**, never on nodes directly. B's
  scan ends B's support and touches nothing of A's.
- **A node's lifecycle is derived**, in the same transaction, after support
  reconciliation: `active` while any support is `current` or `stale`;
  `retired` with `retired_reason = 'unsupported'` only when **every** support
  is `ended`.

`iga_object_support` is therefore the node-side analogue of a partition
membership column — and the reason nodes cannot simply carry one.

**Edges keep a single membership.** An access edge's subject is an identity in
one account; `executes_as` joins a workload and identity in one account; a
`can_assume` edge is evidenced by exactly one trust policy. None is
multiply-supported, so `connector_id` + `partition_key` on the row is correct
for them and a support table would be ceremony. If a future edge type *is*
shared, it moves to support rows rather than growing a second rule.

### 2.11 ERD

```
                          workspaces
                               │
        ┌──────────────────────┼────────────────────────┐
        ▼                      ▼                        ▼
 iga_estate_scopes      cloud_connector             iga_agents
        ▲                      │                    origin: registered|discovered
        │                      ▼                         │
        │              cloud_scan_run ◀──┐               ▼
        │                 (published)    │        iga_agent_instances
        │                      │         │               │
        │         ┌────────────┼─────────┤               │
        │         ▼            ▼         │               │
        │  cloud_scan_    cloud_observation              │
        │   coverage       (+ subject_native_id,         │
        │   NEW 024         durable)  NEW 024            │
        │   immutable            │                       │
        │                        ▼                       │
        │         last_confirmed_run_id on the           │
        │           observation itself  (024)            │
        │                                                │
   ┌────┴─────────┬──────────────────┬──────────────┐    │
   ▼              ▼                  ▼              ▼    ▼
iga_identity_  iga_workload      iga_resources   iga_credentials
  accounts      NEW 029               ▲             │
   │  source_key ✦  source_key ✦      │   source_key ✦
   │                                  │
   │              iga_entitlements ───┘  source_key ✦ (§2.6)
   │                     ▲
   │                     │ NOT NULL
   └──────┬──────────────┘
          ▼
   iga_access_edges          iga_relationship  NEW 031
   identity → entitlement    typed source AND typed target
   basis/state/validity      legal (source,type,target) CHECK
   last_confirmed_by ────▶ cloud_scan_run (workspace-qualified)
          │                         │
          ▼                         ▼
   iga_access_edge_evidence   iga_relationship_evidence
          └──────────┬──────────────┘
                     ▼
              cloud_observation

✦ = UNIQUE (workspace_id, source_key) WHERE lifecycle <> 'retired'

Two tables carry the mechanisms of §2.10 and sit beside this graph rather than
inside it:

    iga_pipeline_lease      one row per WORKSPACE. idle -> collecting ->
      (027)                 projecting -> idle, fenced by `version`. A durable
                            row, not a session lock, because publication and
                            projection are different transactions.

    iga_object_support      one row per (object, connector, partition).
      (032)                 Reconciliation ends SUPPORT; a node retires only
                            when every support of it has ended. This is why
                            nodes carry no connector_id and edges do.
```

---

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

Phase 2 therefore performs **no cross-provider correlation**. It may:

- record **candidates with their evidence** in `iga_correlations` and
  `iga_classification_candidates`, which exist from `004` for this;
- never let a candidate affect a graph query, a path, a finding or a
  certification until a human confirms it;
- record confirmation as `asserted` basis with the deciding authority, so it
  is explicable and reversible.

#### What this phase deliberately will not do

Stated as product limits now, rather than discovered as gaps later. Each is
cheap to state and expensive to walk back.

| Not built | Why not |
|---|---|
| Automatic cross-provider identity merging | Above |
| Unbounded transitive traversal | Bounded by **four separate limits** (§2.14.11), not one hop count: a blanket two-hop cap makes the product's own workload→identity→entitlement→resource example untraversable. Role-assumption chaining is the one capped at 2, because each hop multiplies the chance a link is `stale` |
| Resolving every external principal | Exact matches only; wildcards stay unresolved and visible |
| Effective access | Conditions recorded, never evaluated. No SCPs, boundaries or session policies. Every conclusion reads `unknown` (roadmap §3.5a) |
| Blast-radius or risk scoring | Needs effective access to mean anything. A score over declared grants is a number that looks like analysis |
| A node-link diagram as primary navigation | 107 identities × 461 permissions is a hairball that answers no question. See P2-11 |

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

So: **paths as rows, not a node-link canvas.** A force-directed view of 107
identities against 461 permissions is a hairball that answers no question, and
governance work is reading one path, deciding on it, and explaining the
decision later. The diagram earns its place only for a single expanded path of
four to six nodes — legible, printable, pasteable into a ticket.

If a demo needs a picture, the honest version is a filtered path list with
counts. A picture that looks like insight and is not is the most expensive
thing to ship, because customers make decisions from it.

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

Phases 4 and 5 build this. It is specified here because P2-11 builds the first
read path and the shape must not be invented twice — and because several
decisions below constrain the schema and the API, not just the pixels.

**Status of this section.** Everything here is **proposed** unless a row says
*built*. Nothing in §2.14 exists today beyond the three inventory tabs.

#### 2.14.1 The journey, and what the current IA does to it

The intended journey:

```
connect an integration → see agents and workloads → pick one you recognise
    → explore it → inspect the evidence for one relationship → see what changed
```

The customer never has to know our entity names, and never starts at a graph.

**Verified against `authsec-staging`, the console today does not support this.**
Three separate trees claim overlapping territory, backed by three different
pipelines:

| Route | Backed by | Pipeline |
|---|---|---|
| `/iga/agents` | `/authsec/discovery/agents` → `discovered_agents` (`models/discovery.go:343`) | Legacy discovery — **not** the IGA graph |
| `/iga/identities` | `iga_identity_accounts` via `/api/iga/v1/identity-accounts` | GitHub IGA path |
| `/iga/cloud/identities` | `cloud_identity` | AWS collection path |
| `/iga/cloud/compute` | `cloud_workload` | AWS collection path |
| `/iga/cloud/resources` | `cloud_permission` resource references | AWS collection path |

The older `/iga/cloud/aws/*` paths already redirect to these (`App.tsx`,
`CloudInventoryRedirect`). None of these URLs carries an object id; detail
drawers are local state, so only filters (`account`, `kind`, `view`) are
bookmarkable today.

So a customer sees **two pages called Identities** fed by different pipelines,
and an **Agents page that never shows a Bedrock agent** — Bedrock agents land
in `cloud_workload` and surface under *Compute*, which is the one tab that
sounds least like an agent.

There are also three distinct "agent" concepts in the tree: `discovered_agents`
(legacy), `iga_agents` (`models/iga.go:421`, canonical), and Bedrock/AgentCore
rows in `cloud_workload`. The IA exposes all three without distinguishing them.

#### 2.14.2 One entry point: Agents & workloads

The sidebar item is **Agents & workloads**. It lists the things that *run* —
logical agents and workloads — across every connected provider. "Estate" stays
an architectural term and the route segment (`/iga/estate`), because the list
spans two object types and needs one URL namespace; the customer sees the
label, and breadcrumbs use it.

`/iga/cloud/*` stops being its own tree and becomes **provider filters** on
this list.

Two estate-wide lists stay first-class, because an investigation often starts
from a shared role or a sensitive bucket rather than from an agent:

- **Identities** → `/iga/identities` — every identity account, all providers,
  replacing the two pipeline-specific pages
- **Resources** → `/iga/resources` — every resource and selector

**The legacy Agents page leaves the navigation, not the product.**
`/iga/agents` is backed by `discovered_agents` — a separate pipeline with its
own semantics — and leaving it in the sidebar beside *Agents & workloads*
would give the customer two competing "agents" destinations that disagree.

| | During transition |
|---|---|
| Route `/iga/agents` | **Stays live.** Existing links and bookmarks keep working |
| Sidebar | **Removed.** No second agents destination in IGA navigation |
| Reachable from | *Integrations → Runtime discovery (legacy)*, labelled as a separate pipeline |
| Excluded from | Agents & workloads, the graph, every count, every coverage claim. Its rows never appear as graph nodes |
| Retirement | A separate decision, outside this phase |

#### 2.14.3 Classification: what we may call an agent

**Not every Lambda is an agent.** The column is *Classification*, never a
badge reading "AI".

| State | Meaning | Evidence | Phase 2 |
|---|---|---|---|
| **Provider-native agent** | The provider's own API calls it an agent | The observation: `bedrock:GetAgent`, `bedrock-agentcore:GetAgentRuntime` | **Automatic.** Derived from `runtime_kind` (`bedrock_agent`, `bedrock_agentcore_runtime`) |
| **Classified as agent** | A person said so, for a custom agent on Lambda/ECS/EC2 | A decision record: who, when, why | **In — as one narrow, audited action.** See below |
| **Unclassified workload** | We found it; nobody has said what it is | Discovery evidence for the workload itself | The default |

**Decision (proposed — confirm before build): manual classification is in
this phase.** `cloud_workload` has no classification column, but a missing
column is a migration, not a reason to cut scope. The journey this product exists for — *"select the customer support
agent"* — is unreachable for any customer whose support agent is a Lambda,
which is most of them, because it would stay "Unclassified workload"
indefinitely. A missing column is a migration, not a reason.

What is in, and what stays out:

| In | Out |
|---|---|
| A **Classify as agent** action on a workload's Overview | Automatic inference from names, tags, env vars or dependencies |
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

A human decision in a security product needs five things pinned down, and
each is a place this goes wrong quietly.

| Concern | Contract |
|---|---|
| **Who may** | Classify and undo require `middlewares.Require("discovery", "admin")` — the same gate as connecting an integration. Viewing a decision needs `discovery:read`. A narrower `discovery:classify` action is a later refinement, not a Phase 2 dependency |
| **Who did** | A **verified human workspace member**, and the actor recorded is their **stable user id**. See the rule below — the obvious checks are all wrong in this codebase |
| **Atomic** | One transaction: insert the `iga_workload_classification` row, then update `iga_workload.classification` and bump `classification_version`. Either both land or neither does; there is never a classification with no decision behind it |
| **Concurrent edits** | Optimistic. The request carries `expected_version`; the update is `… WHERE id=? AND classification_version=?`. Zero rows → `409` with the current classification, who set it and when, so the second person sees the first person's decision instead of overwriting it |
| **Provider-native** | Not human-editable. The action is not offered on a `provider_native_agent`, and the endpoint returns `422` if called. The provider's own API says it is an agent; a person cannot overrule the evidence, only add context to it. **Undo** reverts only `classified_agent → unclassified`, and records its own decision row rather than deleting the first |

**Identifying the human — verified against the token code, because every
shortcut here is wrong:**

| Tempting check | Why it fails |
|---|---|
| Reject if `client_id` is present | The human console session carries **both** `UserID` and `ClientID` (`GenerateWorkspaceToken`, `authmanager_token_service.go:71`), and the middleware sets both into context (`auth.go:864-868`). This would reject every legitimate user |
| Accept if a `user_id` is present | `GenerateEndUserToken`, `GenerateAdminToken`, `GenerateCIBAToken`, `GenerateDeviceAuthToken` and others all set `UserID`. An **end-user of a customer's application** would pass |
| `ResolveUserID(c)` | Falls back to `sub`, then email. A machine token's `sub` is the client |
| `IGAController.workspace()` | Falls back to `client_id`, then to the workspace id itself (`iga_controller.go:114-122`) |

**The rule.** Of the eleven token generators, **only `GenerateWorkspaceToken`
sets `WorkspaceMembershipID`** — it is the discriminator for a human console
session. But a claim is not a fact: the membership may have been revoked since
the token was issued, so it is checked against the record.

```go
func requireWorkspaceHuman(c *gin.Context, db *gorm.DB) (userID uuid.UUID, err error) {
    membershipID := c.GetString("workspace_membership_id") // only workspace sessions carry it
    uid          := c.GetString("user_id")
    ws           := c.GetString("workspace_id")
    if membershipID == "" || uid == "" || ws == "" {
        return uuid.Nil, errNotWorkspaceHuman // 403: machine, SDK, end-user, admin or CIBA token
    }
    // All three must agree with the RECORD, and the membership must be live.
    // status is CHECKed to active|invited|suspended|left (001_bootstrap.sql:1668),
    // so 'active' refuses an invitee who never accepted, a suspended member,
    // and someone who has left.
    // A token naming a membership that belongs to another user or workspace,
    // or one revoked after issuance, is refused here.
    var n int64
    if err := db.Model(&models.WorkspaceMembership{}).
        Where("id = ? AND workspace_id = ? AND user_id = ? AND status = 'active'",
            membershipID, ws, uid).Count(&n).Error; err != nil {
        return uuid.Nil, err
    }
    if n != 1 {
        return uuid.Nil, errNotWorkspaceHuman // 403
    }
    return uuid.Parse(uid)
}
```

Then `middlewares.Require("discovery", "admin")` applies as usual. `decided_by`
stores the **user id**, never the email: an email can be reassigned, and the
decision must stay attributable to the person who made it.

```
POST /api/iga/v1/estate/:id/classification
  { "decision": "classified_agent" | "unclassified",
    "purpose":  "Customer support triage",       // optional
    "reason":   "Owns tier-1 ticket routing",
    "expected_version": 3 }

  200  { "classification": "classified_agent", "classification_version": 4,
         "decided_by": "priya@acme.com", "decided_at": "…" }
  403  not a live workspace member, or lacks discovery:admin
  409  { "current": { classification, version, decided_by, decided_at } }
  422  workload is provider_native_agent
```

**The projector never writes `classified_agent`,** and never overwrites it.
It sets `provider_native_agent` from `runtime_kind` on insert and leaves the
column alone otherwise — classification is human-owned state, protected by
§3's rule that every `ON CONFLICT DO UPDATE` names its columns and never uses
`UpdateAll`.

**`Unclassified` does not mean "not an agent"** and is never rendered as a
negative or filtered away by default. An ordinary workload stays discoverable
whether or not anyone ever classifies it.

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

So in Phase 2 **a Bedrock agent has no known instances.** Aliases are what
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

**To show instances, one piece of collection work is required and is not yet
scheduled**: `bedrock-agent:ListAgentAliases` per agent, written as
`iga_agent_instances` rows with `origin = 'discovered'`, linked to the agent by
the provider's own agent id. That is a Phase 1 collector change plus a P2-10
projection change. Until it lands, "instances: not collected" is the correct
display — not a count of zero, and not a guess.

#### 2.14.5 Navigation model

One selected object, a fixed set of views, shared filters. The views are
**alternate lenses on one investigation**, not separate pages that forget each
other.

**Sidebar.** Under IGA: **Agents & workloads**, **Identities**, **Resources**.
Nothing else in this area; coverage is reached from banners and from each
integration, not from its own nav item.

##### Routes and views

Every object type gets the tabs that answer its own questions. An identity is
not a workload, so it does not borrow the workload's tabs.

| Object | URL | Tabs | What each tab answers |
|---|---|---|---|
| Agent or workload | `/iga/estate/:id/{overview,identities,resources,graph,changes}` | **Overview · Identities · Resources · Graph · Changes** | What it is · what it runs as and who else does · what its declared access names · the path, drawn · what changed |
| Identity (role, user) | `/iga/identities/:id/{overview,used-by,permissions,graph,changes}` | **Overview · Used by · Permissions · Graph · Changes** | What it is and where · which workloads run as it and which principals may assume it · which policies grant what, each statement separately · the path, drawn · what changed |
| Resource or selector | `/iga/resources/:id/{overview,access,graph,changes}` | **Overview · Access · Graph · Changes** | Its kind (§2.14.12) and what we know about it · which identities are granted what on it, by which statement · the path, drawn · what changed |
| External principal | `/iga/identities/:id/{overview,referenced-by}` | **Overview · Referenced by** | Which account it belongs to and why it is unresolved · what names it. No Graph tab: there is nothing on the far side we could read |

`/iga/estate/:id` with no tab segment is Overview. The **Evidence panel** is
not a tab. It is `?evidence=<claim id>` on whichever view opened it.

##### What a URL carries, and what it promises

| In the URL | In history state only | Never in the URL |
|---|---|---|
| Object id, tab, `provider`, `account`, `region`, `integration`, `q` (search), `sort`, `evidence`, `node` (graph selection), `target` (*View in graph*), `as=paths`, `via` (originating object), `from` (when a link was shared) | Page cursor, scroll position, expanded graph nodes | `rev` |

**`rev` is not in the URL.** A revision is current-only (§2.15 *Revision
pinning*), so a `rev` in a shared link would promise a snapshot the server
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

The server answers a stale `rev` with `409` (§2.15). The client must not lose
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
- **Evidence panel.** Opening it from a closed state **pushes**, so browser
  Back closes it. Opening a different claim while it is open **replaces**, so
  Back does not step through every claim viewed. **Close** (×, or Esc)
  **replaces** the URL without `evidence`. Focus returns to the control that
  opened it. The panel never opens a second panel; a link inside it navigates
  the page and closes the panel.
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

##### Old routes

Old cloud URLs redirect **only once the replacement list has shipped**. Until
then they stay as they are. Redirects translate filters and must never guess
an object:

| Old | New | Filter translation |
|---|---|---|
| `/iga/cloud/identities?account=A&kind=K` | `/iga/identities?provider=aws&account=A&kind=K` | `kind` values must be mapped by a table checked against both enums in code review. An unmapped value is dropped **and** the page says a filter could not be carried over |
| `/iga/cloud/compute?account=A` | `/iga/estate?provider=aws&account=A` | `view=workload-identities` → `/iga/identities?provider=aws&used_by=workloads` |
| `/iga/cloud/resources?account=A&kind=K` | `/iga/resources?provider=aws&account=A` | Same `kind` rule |
| `/iga/identities` (GitHub path today) | Same path, now all providers | None needed |

**No object-level redirects in this phase.** No current URL carries an object
id (verified), so none is needed. Graph objects have no column pointing back
to a `cloud_*` row; they are keyed by `source_key`. So a future id redirect
needs a server lookup (`cloud_* id → iga id`), flagged in §2.14.14. It must
never be approximated by name, because names repeat across accounts.

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
| **Agents & workloads** | Name · Classification · Runtime · Account · Last confirmed | Name, Classification, Account, Last confirmed | Classification (provider-native, classified, unclassified), then name | Region · Runs as · Integration · First seen · ARN |
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
| **Offered** | **Classify as agent** on Overview, for workloads that are not provider-native, and only when the server says this user may (a capability flag on the object, §2.14.14). Otherwise the button is absent, not disabled without a reason. Provider-native agents show why there is no action: *"AWS reports this as an agent."* |
| **Dialog** | Decision (preselected), purpose (optional), reason (**required**, because it is the audit record). Save is enabled once there is a reason |
| **Saving** | **Not optimistic.** The dialog shows *Saving…* and the page does not change until the server answers. A human decision in a security record must not appear to have landed when it has not |
| **200** | Dialog closes; Overview shows the decision line (*"Classified as agent by Priya Shah · 22 Sep · 'handles tier-1 tickets'"*); the list row updates on return. A toast offers **Undo** for 10 seconds |
| **Undo** | A new decision (`unclassified`) with `expected_version` set to the version just returned, and reason *"Undo of the decision at 14:02"*. It is recorded, not a deletion. After the toast is gone, the same action is the **Undo classification** button on Overview, which asks for a reason |
| **409** | The dialog **stays open, with the customer's input kept**, and shows who decided what and when: *"Alex Kim classified this as an agent at 14:01: 'owns refunds'."* Two choices: **Keep theirs** (closes) or **Replace with mine** (resubmits against the new version, as a deliberate second act). Never auto-retry |
| **409 that is our own write** | A retry after a lost response can return `409` with `decided_by` = this user and the same decision. The client treats that as success, not as a conflict |
| **403** | *"You need discovery admin to classify workloads."* The input is kept |
| **422** | Only reachable if the object became provider-native since load: the dialog closes and Overview reloads |
| **Network failure** | The input is kept and the outcome is **unknown**, so the client re-reads the object before allowing a retry. `expected_version` makes a blind retry safe, but the customer should see which state they are in |

Classification is **human-owned current state, not part of a revision**: a
decision shows immediately on every screen, and it does not trigger the
*revision moved* banner.

#### 2.14.7 Screen and state table

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
| Workload | The account of the connector that collected it. **Always known** | Never. An unresolved *execution identity* (`not_in_scan`, `not_in_inventory`) is a fact about the role, not about the workload, and must not blank the workload's account or drop it from an account filter. The AWS Compute page ignores the account filter today; the fix is to attribute the workload to its connector's account, not to hide the filter |
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

##### Limits — four, not one

The blanket "two hops" was wrong: the basic workload → identity → entitlement
→ resource path is already three edges, so a two-hop cap makes the product's
own teaching example untraversable. The limits are separate because they bound
different risks:

| Limit | Default | Bounds |
|---|---|---|
| `max_semantic_paths` | 1 | How many complete workload→resource paths are expanded at once. One by default; expansion adds more |
| `max_assume_hops` | 2, **then expandable** | Role-assumption chaining shown initially. Each hop multiplies the chance a link is stale, so two is the default — but the customer can expand further, one hop at a time, and the limit is always visible. A node at the limit reads *"may assume 3 more roles — expand"*; it must never look like the chain ends there |
| `max_nodes` | 150 | Canvas legibility |
| `max_edges` | 300 | Canvas legibility |
| `page_size` | 100 | Every list, everywhere |

**Truncation is always explicit and always continuable.** "Showing 87 of 210
nodes at this depth" with an Expand control; never a silently clipped canvas.
When any limit binds, **every completeness claim on the screen is suppressed**
— no counts presented as totals, no "this workload reaches 3 resources".

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
  canvas says so and offers what does work: *"support-tickets/\* is 5 steps
  from ticket-tools; the graph shows up to 4 here. [Show the path as a list]
  [Expand one more step]"*. It never opens a canvas that silently lacks the
  target.

##### Controls

| Concern | Behaviour |
|---|---|
| **Select vs open** | One click (or Enter on a focused element) **selects**: a node shows its summary, an edge shows its evidence, in the side panel. Selection is `node=` / `evidence=` in the URL and **replaces** history. **Open** (double-click, or the panel's **Open** button) **navigates** to that object's own page and pushes history. **Focus here** re-roots the graph on the selected node, as a new history entry |
| **Expand** | A node with unshown neighbours carries a count: *"+3 roles"* (or *"+3 or more"* when the count is not known). Expanding adds exactly those neighbours, one step. `max_assume_hops` is a starting depth, never a ceiling on expansion |
| **Collapse** | Collapsing removes what that expansion added **unless** the same node is also reached by another expanded path. Nodes are reference-counted by expansion, so collapsing one path never breaks another |
| **Shared paths** | A node reached by several paths is drawn **once**. Many workloads sharing one identity collapse into one group node, *"Used by 14 workloads"*, which expands into its members |
| **Grouped edges** | Several grants between the same two nodes may be drawn as **one line with a count badge** (*"2 statements"*) for legibility. The grouping is visual only. The evidence panel lists every grant separately, each with its own status. Line style follows the most-current member: solid if **any** grant is current, dashed only if **all** are stale, and the badge carries the mix (*"1 current · 1 ended"*). Ending one grant never restyles the line while another is current |
| **Cycles** | Role A may assume B, and B may assume A. Each node is drawn once; the edge back to an already-drawn node is drawn to it and marked *cycle*. Expansion never re-adds a visited node. The server de-duplicates too (§2.14.14) |
| **Loading and failure** | The first load is all-or-nothing: an error with Retry, never a partial canvas presented as the answer (§2.14.7). An **expansion** failure is local: that node shows *"Could not load. Retry"*, and everything already drawn stays. A truncated response is not a failure and is never shown as one |
| **Layout stability** | A deterministic left-to-right layered layout: workload → identity → entitlement → resource or selector, with external principals in their own lane. Expanding and collapsing **never moves nodes already on screen**; new nodes take free positions. Only a refresh to a new revision may re-lay out, and it says so (*"Layout updated for the newer scan"*). Transitions are 200 ms at most and are removed under `prefers-reduced-motion` |
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

The canvas itself supports the keyboard (§2.14.14), but the path list is how
a screen-reader user, or anyone who prefers text, gets the whole answer.
Neither presentation may know something the other does not.

#### 2.14.12 Resources: four kinds, never conflated

An ARN in a policy is not proof a resource exists. The UI types every resource
row, and Phase 2 can only produce three of the four:

| Kind | Meaning | Phase 2 |
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
┌─ Coverage · sandbox (905418271234) ────────────────────────────────────────┐
│ iam_users            denied                                                 │
│   Missing: iam:ListUsers on the discovery role.                             │
│   Prevents: listing IAM users in this account, and any path that starts at  │
│             one. Role-based paths are unaffected.                           │
│                                                                             │
│ compute:eu-west-1    not read since 15 Sep                                  │
│   Cause: region removed from the connector's selected scope.                │
│   Prevents: ending anything in eu-west-1. Six relationships are stale and   │
│             will not be closed while this persists.                         │
│                                                                             │
│ policy_documents     partial · 3 statements skipped                         │
│   Cause: documents that could not be parsed.                                │
│   Prevents: ending ANY grant in this account — a statement we could not     │
│             read may be the one still granting access.                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Never promise that one permission fixes everything.** Each surface states
its own cause and its own blast radius. `iam_users denied` and
`compute:eu-west-1 not selected` have different owners and different fixes,
and a single "grant these permissions" call-to-action would be wrong for at
least one of them. Where the cause is genuinely a missing permission, name
that permission; where it is a configuration choice or a parse failure, say so
instead.

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
should be built last (§6.3) — the list views answer every question in §2.14.11
except the visual one, and they can ship first. No graph or layout library is
a dependency today (checked: `package.json`); choosing one is part of that
work, judged against *Layout stability* in §2.14.11.

##### What every IGA response must carry

The UI depends on these on **every** list and detail response. They belong in
§2.15's contracts, not in per-screen special cases:

| Field | Used for |
|---|---|
| `rev`, `published_at` | Pinning (§2.14.5); the *"as of 14:02"* label; the shared-link notice |
| `items[].id`, `name`, `arn`, `account_id`, `account_name` (or `null` = Unknown account), `region` (or `global`, or `null` = not stated), `provider` | Rows, disambiguation, search display |
| `next_cursor` | Next page. **Prev is client-side**: the client keeps the stack of cursors it has used, so the server needs no backward cursor |
| `total_known`, `total` | The totals rule (§2.14.6). `total` is present only when `total_known` is true |
| `coverage[]`: `{account_id, surface, state, prevents}` for every gap that bears on this result | Partial banners (§2.14.7). Computed by the server, never inferred client-side from row counts |
| `capabilities` on objects (`can_classify`) | Offering actions (§2.14.6). The client never infers permissions from role names |

##### Contracts the UI needs that §2.15 does not yet define

**These are flagged for backend coordination, not designed here.** Each needs
a backend decision before the screen that depends on it is built. The frontend
must not work around a missing one — no client-side search over a loaded page,
no totals computed by paging to the end, no name-based matching, no evidence
assembled by joining lists.

| Need | Screen | Why the client cannot supply it |
|---|---|---|
| `q` search on every list, over the whole inventory at `rev` | All lists | Only the server holds the whole inventory |
| `sort` with a stable tiebreaker | All lists | Cursor paging is only stable if the server orders deterministically |
| Account facet counts, including Unknown | Account filter; *"23 with unknown account not shown"* | Same |
| Graph `target=<id>`: paths from root to target within limits, or a `not_within_limits` reason with the distance | *View in graph* (§2.14.11) | Path finding over data the client does not have |
| Neighbour counts per node, with known/unknown | Expand affordance (*"+3 roles"*) | Same |
| Server-side de-duplication of visited nodes in traversal and expansion | Cycles | A client-side guard alone would still download cycles |
| `/identities/:id/used-by` (workloads **and** principals that may assume it), `/identities/:id/permissions` (per statement) | Identity tabs | §2.15 has only `/identities/:id/workloads` |
| `/resources/:id/access` (per identity and statement) | Resource tabs | Missing |
| `/identities/:id/referenced-by` for external principals | External principal tabs | Missing |
| Evidence as **structured** parts: facts, freshness, and `limitations[]` as codes (`condition_not_evaluated`, `surface_unread`, `account_not_connected`, …) | Evidence panel (§2.14.7) | Which limitations apply depends on stored conditions and coverage; the client would have to reproduce the server's logic |
| `409` body including `current_published_at` | Revision banner time | §2.15's body has `current_rev` and `changed_since` only |
| Retired objects readable by id, with `lifecycle` and `last_confirmed_at` | Shared links to retired objects (§2.14.5) | A `404` would be indistinguishable from "never existed" |
| Classification response with `decided_by_user_id` and a display name | Decision line; recognising our own write on `409` | §2.14.3 returns `decided_by` as an email |
| A way to tell "this route is not deployed" from "this object does not exist", e.g. `GET /api/iga/v1/capabilities` listing enabled views | The *Unavailable* state | Both are `404` today. The UI and the backend deploy separately, so skew is a normal state, not an edge case |
| `cloud_* id → iga id` lookup | Object-level redirects from old routes | **Not needed this phase** (§2.14.5, *Old routes*) |

##### Development fixtures

The UI is built against fixtures first, so screens can be designed and tested
before the backend ships, and fixtures double as the acceptance data in §6.2.
**Proposed tooling:** MSW for request mocking in development and tests. It is
not a dependency today (checked: `package.json` has Vitest and Testing Library,
no mock server). Fixtures are typed from the same TypeScript contract types
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

### 2.15 The API contracts this experience needs

Every screen in §2.14 mapped to the contract behind it, and whether it exists.
**Verified against `routes.go` and `iga_controller.go` on `authsec-staging`.**

| Screen / interaction | Contract | Today |
|---|---|---|
| Agents & workloads list | `GET /api/iga/v1/estate` — agents + workloads, one page, filters, cursor | **Missing.** `GET /agents` exists but is the GitHub path over `iga_agents`; cloud workloads are only under the AWS connector routes |
| Classification + provenance | `classification`, `classification_version` and the latest decision (who, when, why) on the estate row | **Missing — in this phase** (P2-G). Provider-native derived from `runtime_kind`; manual classification per §2.14.3 |
| Classify / undo | `POST /api/iga/v1/estate/:id/classification` — contract below | **Missing — in this phase** (P2-G) |
| Agent → instances | `GET /api/iga/v1/agents/:id/instances` | **Missing.** `AgentDetail` returns `Instances: []` unconditionally (`iga_service.go:1300`) — P2-10 |
| Object overview | `GET /api/iga/v1/estate/:id` | **Missing** |
| Identities view | `GET /api/iga/v1/estate/:id/identities` — execution identity + relationships, each with basis/state/evidence | **Missing** |
| Shared-role workloads | `GET /api/iga/v1/identities/:id/workloads` | **Missing.** The reverse edge is the point of the shared-role story |
| Resources view | `GET /api/iga/v1/estate/:id/resources` — typed per §2.14.12, with the grants naming each | **Missing** |
| Independent grant evidence | Each resource row carries **every** declaring statement, not a merged one | **Missing**, and the one most likely to be lost to "simplification" |
| Graph | `GET /api/iga/v1/graph?root=:id&depth=…` | **Missing.** `GET /agents/:id/access-paths` exists (`iga_controller.go:725`) and is the closest thing — GitHub path, no expansion, no truncation contract |
| Graph expansion | `GET /api/iga/v1/graph/expand?node=:id&rev=…` returning added nodes/edges plus `truncated` | **Missing** |
| Evidence | `GET /api/iga/v1/edges/:id/evidence` | **Partial.** `GET /agents/:id/evidence` exists, agent-scoped, not per-edge |
| Coverage for a scope | `GET /api/iga/v1/coverage?account=…` with per-surface cause **and prevented conclusion** | **Partial.** `GET /integrations/:id/coverage` exists; it reports state, not what the gap prevents |
| Changes | `GET /api/iga/v1/estate/:id/changes?kind=configuration\|coverage` | **Missing.** Requires the lifecycle history 030/031 add |
| Pagination + totals | Cursor + `total_known: bool` on every list | **Partial.** AWS lists clamp at 500 with no cursor (P1-8 unbuilt) |

#### Revision pinning

**A revision is a workspace publication, not a run.** An investigation into a
cross-account path touches partitions last projected by different runs, so a
single `last_run_id` cannot name what the customer is looking at. But the
pipeline barrier (§2.10A) serializes projection per workspace, so every
projection commit is a totally ordered event — and that gives a well-defined
revision for free.

Its DDL is migration `033` (§3), with `iga_projection_state`.

`rev` is assigned **inside the projection transaction**, as
`max(rev) + 1` under the barrier row's lock — so two publications can never
share a number and there is never a gap a reader could mistake for a lost one.

**What a revision can promise in Phase 2: consistency, not history.**

A revision pins an investigation to *the current* publication so that the
list, the graph expansion and the evidence a customer is looking at all come
from one commit. It does **not** let an old link reproduce an old graph, and
the API must not imply it can. Two things are not preserved:

- **Relationship state is overwritten in place.** A relationship can go
  `current → stale → current` without its validity interval changing — the
  reconciler updates `state`, and `valid_from`/`valid_to` only record when it
  began and ended. So "what state was this in at revision N" cannot be read
  back from those columns.
- **Node attributes and evidence links are current-only.** Display names are
  refreshed on every upsert; evidence junctions carry no validity interval.

Historical reads would need a state-transition log per relationship and
versioned evidence associations. That is real work, deferred, and named in
§6.3 rather than assumed. The manifest in `iga_publication` records *which run
each partition came from* — useful for the Changes view and for explaining a
result — but a manifest of run ids is not a graph.

| The request | Response |
|---|---|
| No `rev` | Latest. The response **echoes** the `rev` it resolved to, and the client pins it for the rest of the investigation |
| `rev=N`, N is current | `200`, `rev: N` |
| `rev=N`, N is no longer current | `409 Conflict` with `current_rev` and `changed_since: <published_at of N>` |

One conflict response, two presentations, chosen by the client from context:

- **Mid-investigation** (the customer has been navigating under `rev=N`): the
  rendered data stays, with *"A newer scan published at 14:31. You are viewing
  the previous result. [Refresh]"*. It is never swapped automatically: they may
  be halfway through explaining a path. Refresh keeps the object, tab, filters
  and open evidence (§2.14.5, *When the revision moves mid-investigation*).
- **Opening a shared link**: links never carry `rev` (§2.14.5), so this is not
  a conflict at all. The page loads current. If the link carries `from=`, it
  says *"Shared 22 Sep 14:02. The graph has been rescanned since, so this shows
  it as it is now."* It does not pretend to show the graph as it was.

**What the Changes view reads, given this.** Configuration changes come from
what *is* retained: `valid_from`, `valid_to` and `ended_reason` on
relationships and access edges, which are never overwritten once set, and
per-run coverage on `cloud_scan_run.coverage`. Coverage changes are derived by
comparing consecutive runs' coverage, not from relationship `state`. Neither
needs a state log.

**Omitting `rev` means latest**, and the response always echoes which `rev` it
resolved to, so the client can pin from its first read.

`total_known: false` is returned whenever any limit bound, and the UI then
suppresses every completeness claim (§2.14.11).

#### Phase dependencies, stated rather than implied

| Experience | Needs | Phase |
|---|---|---|
| Agents & workloads list, Overview, Identities, Resources | The graph tables and projector | **2** |
| Graph view with expansion | Traversal API with bounded depth and truncation | **4** |
| Changes view | Relationship lifecycle history | **2** (schema) + **4** (read path) |
| Manual classification as agent | `029` classification columns + decision record; the endpoint below | **2** (P2-G) |
| Inferred classification, grouping | Rules, evidence, review surface | **Not this phase** |
| Ownership on Overview | Ownership attestation | **Post-graph** — shows "Not assigned" until then |
| Activity on any screen | A CloudTrail collector for observed use | **Not this phase.** Access Advisor only, with §2.14.8 wording |

P2-11 builds **one** read path — the Identities and Resources views for a
selected workload, at a pinned revision, with evidence. Everything else here
is Phase 4/5 and must not be presented as current.

### 2.16 One path, traced end to end

The spec's own coherence check. If any step below cannot be followed in §3 and
§4, the spec is incomplete regardless of which terms appear in it.

**Subject:** `ticket-tools`, a Lambda in `eu-central-1` of account
`220171243705`, running as `SharedToolRole`, granted `s3:GetObject` on
`s3:::support-tickets/*` by two managed policies.

#### The happy path

| # | Step | Where | What becomes true |
|---|---|---|---|
| 1 | Barrier claimed | `iga_pipeline_lease`: `idle → collecting`, `v7` | No other scan in this workspace |
| 2 | Generation allocated | `generation := connector.ScanGeneration + 1` = 8 | Rows will be written at 8; the connector still reads 7 |
| 3 | IAM read | `cloud_identity` row for `SharedToolRole`, `attrs.unique_id = AROA5XK…` | Surface `iam_roles: reached` |
| 4 | Compute read | `cloud_workload` for `ticket-tools`, `identity_id →` the role | Surface `lambda:eu-central-1: reached` |
| 5 | Policies parsed | Two `cloud_permission` rows, same statement, same resource, different policy ARNs | `policy_documents` **absent** = nothing dropped |
| 6 | Evidence written | `cloud_observation` rows; permission subjects keyed `<holder>␟<native_id>␟<resource>` | `last_confirmed_run_id = run` |
| 7 | **Publish** | One transaction: coverage stamped on `cloud_scan_run`, status `published`, `iga_projection_job` enqueued, barrier `collecting → projecting` | A published run always has a job and a coverage report |
| 8 | Job claimed | Own lease, own fencing version | |
| 9 | Snapshot loaded | `REPEATABLE READ`; rows at generation 8; coverage from the **run's** column; confirmed observations by `last_confirmed_run_id` | Inputs immutable for the pass — the barrier holds `projecting` |
| 10 | Fence + ordering | `AssertOwnedTx` on **(workspace, phase=`projecting`, job, version)**, then every partition's watermark | A superseded job — or a `collecting` holder — commits nothing |
| 11 | Scope | `iga_estate_scopes` row for the account | Partitions have somewhere to live |
| 12 | Nodes | Each looked up in `existing.live`, then `existing.retired` for restoration; upserted on `(workspace_id, source_key)`; **each with its typed `iga_object_support` row**, partition from `snap.PartitionFor` | `first_seen_at` preserved; a returning object with the same `UniqueID` is restored, not duplicated |
| 13 | Entitlements | **Two** — both managed, both keyed by policy ARN, so shared not merged | Detaching one later cannot end the other |
| 14 | Edges | `executes_as` keyed on **both** endpoints with the identity's immutable key; two access edges, `partial`/`unknown` | No evaluation is claimed |
| 15 | Evidence linked | `iga_access_edge_evidence` per edge, via qualified subject keys | Unqualified legacy rows skipped, never guessed |
| 16 | Reconcile | Same transaction. `canEnd` → `published` ✓, `iam_roles`/`iam_policies` `reached` ✓, `policy_documents` absent with `permission_scan` absent ✓ | Nothing to end on a first run |
| 17 | Commit, complete, release | Graph + watermark + **`iga_publication` row `rev = N`** commit together; job `complete`; barrier `projecting → idle`, `v8` | The customer's next read resolves to `rev = N` |
| 18 | **API** | `GET /estate/:id/identities` → resolves and echoes `rev: N`; `SharedToolRole`, `executes_as`, `declared`, `current`, 2 evidence ids, `refund-tools` as a co-user. Every later view carries `rev=N` | §2.15 |
| 19 | **Customer** | Overview → Identities: *"runs as SharedToolRole; refund-tools uses it too"* → Resources: *"names a prefix selector, via two policies"* → evidence | U1, U2, U3 |

#### Failure and recovery: the role disappears, then returns

A later scan reads IAM cleanly and `SharedToolRole` is absent — deleted in AWS.
`canEnd` passes for the `iam_roles` partition, so its support ends; with no
other source supporting it, `retireUnsupported` retires it
(`retired_reason = 'unsupported'`) and its edges end `subject_retired`. The
customer's Changes view shows *"Role no longer present — confirmed by the
scan on 23 Sep."*

Two days later the role is back. What happens depends on **one field**:

- **`UniqueID` is `AROA5XK…`, the same as before.** It was never deleted —
  perhaps a permissions blip that still read as `reached`, or a restored
  backup. `existing.retired` matches on `(source_key, immutable_key)`, so
  `RestoreIdentity` flips the **same row** back to `active`: same object id,
  same `first_seen_at`, same classification. Its relationships are
  re-projected as **new** rows — we did not observe them in the gap, so we do
  not claim they were continuous. A person's association with it was
  `suspended` at retirement and now becomes **`pending_reconfirmation`**: the
  record is back, the decision is offered back, and nothing grants on it until
  someone confirms.
- **`UniqueID` is `AROA9ZZ…`, different.** Someone recreated it. The retired
  row stays retired; a new object is inserted with a new id and a fresh
  `first_seen_at`, and it starts `unclassified`. Last quarter's decisions stay
  with the principal they were made about: an asserted association stays
  `suspended` on the old row and is never transferred.

#### Failure: a policy fails to parse

At step 5 one document is unparseable. `policy_documents: partial` appears.
Everything through 15 is unchanged — we still write what we read. At 16,
`canEnd` sees `policy_documents` present and **not** `reached`, so the
entitlement and access-edge partitions go **`stale`**, not `ended`. The API
returns the relationships with `state: stale`; Coverage says *"3 statements
skipped — prevents ending ANY grant in this account, because the statement we
could not read may be the one still granting access."* The customer sees an
unchanged graph with a stale marker, which is the truth.

#### Failure: the projection worker dies at step 12

Its job lease expires. The barrier is `projecting` and **stays `projecting`**
— recovery reclaims the same phase under `v+1`. No scan is admitted, so the
shared bucket row cannot be reassigned to another connector underneath the
pending pass. The new worker reloads the snapshot, and because projection is
idempotent it converges. The dead worker's `AssertOwnedTx` fails on the
version and it commits nothing.

#### Failure: crash between commit (17a) and job completion (17b)

The graph and its `iga_publication` row are committed; the job still reads
`running`. Recovery reclaims `projecting` under a new version. The replay
passes step 1 (ownership), and at step 2 finds a publication for this run —
so it returns `AlreadyPublished` **before any write**, and the service calls
`completeAndRelease`. The job ends `complete`.

It does not re-project. Re-projection cannot be relied on to converge here:
after a committed pass the watermark equals this generation, so any
generation guard sees the replay as stale, and a job that fails on every
retry wedges the workspace behind a barrier that never releases. The
publication row is what tells a replay from a supersession.

#### Why there is no crash between job completion and barrier release

They are one transaction (`completeAndRelease`). A crash either precedes its
commit — the case above — or follows it, in which case both have moved. There
is no committed state with a terminal job and a `projecting` barrier, so
recovery never has to infer one from the other.

#### The path that is not yet traceable

**Step 19's Agents & workloads list does not exist**, and neither does the Graph view's
expansion contract. §2.15 marks both missing. The customer journey is
traceable end to end **only as far as P2-11's single read path**; the rest is
Phase 4/5 and is specified, not built.

---

## 3. Schema

Nine migrations, `027`–`035`, in `authsec/migrations/master/`. **`024` and
`025` have shipped** — `024_scan_evidence_durability.sql` closed D1–D4 and
`025_observation_subjectless_dedupe.sql` followed it; §1.2 says what they did.

**`026_governance_schema_parity.sql` ships first, on its own, and is not a
Phase 2 migration.** The production schema rehearsal (restored production
against a fresh `001`–`025`) found production missing six governance tables
and two `CHECK`s that exist only in `001_bootstrap.sql` — the same defect as
`023`, in a part of the schema `023` did not reach. It is live today: the
deployed binary serves `/governance/agent-policies` and
`/actuation/enforcement-plan` against tables production does not have, and
production's `provisioning_instructions_kind_chk` rejects every eviction,
delete and force-delete instruction. `026` copies the six tables verbatim from
the bootstrap, widens `kind_chk`, and adds `force_chk`. Verified: after `026`,
production is identical to a fresh install in tables, columns, indexes and
constraint behaviour. Phase 2 therefore starts at `027`.

> **Rehearse against a production schema dump before merging.** Migration `023`
> exists only because that rehearsal caught seven columns added to
> `001_bootstrap.sql` with no numbered migration: new installs had them,
> production never would, and pods would have come up healthy and failed at
> first customer use. Dump the schema (no rows), restore locally, apply
> `027`–`034`, run the suite between each. **A green run on a fresh bootstrap
> proves nothing about production.**

### 027 — close the cross-workspace provenance gap

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

### 028 — recognition keys and continuity

Written out for **all five tables**. "Repeat the block for the others" is not
something a migration can apply: it runs cleanly and leaves the other tables
without `source_key`, so every upsert on them targets a column that does not
exist. Executing the extracted SQL and checking the resulting columns (§8) is
the check that catches an incomplete migration; reading does not.

`iga_entitlements` has no `lifecycle` column (`004:667`), so it gets one first
— the partial index below needs it.

```sql
ALTER TABLE public.iga_entitlements
    ADD COLUMN IF NOT EXISTS lifecycle text NOT NULL DEFAULT 'active',
    ADD CONSTRAINT iga_entitlements_lifecycle_chk CHECK (
        lifecycle IN ('active','retired','tombstoned'));


ALTER TABLE public.iga_identity_accounts
    ADD COLUMN IF NOT EXISTS source_key     text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS continuity     text NOT NULL DEFAULT 'recognition_only',
    ADD COLUMN IF NOT EXISTS immutable_key  text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS first_seen_at  timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_seen_at   timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS retired_reason text NOT NULL DEFAULT '';
ALTER TABLE public.iga_identity_accounts
    ADD CONSTRAINT iga_identity_accounts_continuity_chk CHECK (continuity IN ('immutable','recognition_only')),
    ADD CONSTRAINT iga_identity_accounts_immutable_chk  CHECK (continuity <> 'immutable' OR immutable_key <> '');
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_identity_accounts_source_key
    ON public.iga_identity_accounts (workspace_id, source_key)
    WHERE source_key <> '' AND lifecycle <> 'retired';

ALTER TABLE public.iga_resources
    ADD COLUMN IF NOT EXISTS source_key     text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS continuity     text NOT NULL DEFAULT 'recognition_only',
    ADD COLUMN IF NOT EXISTS immutable_key  text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS first_seen_at  timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_seen_at   timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS retired_reason text NOT NULL DEFAULT '';
ALTER TABLE public.iga_resources
    ADD CONSTRAINT iga_resources_continuity_chk CHECK (continuity IN ('immutable','recognition_only')),
    ADD CONSTRAINT iga_resources_immutable_chk  CHECK (continuity <> 'immutable' OR immutable_key <> '');
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_resources_source_key
    ON public.iga_resources (workspace_id, source_key)
    WHERE source_key <> '' AND lifecycle <> 'retired';

ALTER TABLE public.iga_entitlements
    ADD COLUMN IF NOT EXISTS source_key     text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS continuity     text NOT NULL DEFAULT 'recognition_only',
    ADD COLUMN IF NOT EXISTS immutable_key  text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS first_seen_at  timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_seen_at   timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS retired_reason text NOT NULL DEFAULT '';
ALTER TABLE public.iga_entitlements
    ADD CONSTRAINT iga_entitlements_continuity_chk CHECK (continuity IN ('immutable','recognition_only')),
    ADD CONSTRAINT iga_entitlements_immutable_chk  CHECK (continuity <> 'immutable' OR immutable_key <> '');
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_entitlements_source_key
    ON public.iga_entitlements (workspace_id, source_key)
    WHERE source_key <> '' AND lifecycle <> 'retired';

ALTER TABLE public.iga_agents
    ADD COLUMN IF NOT EXISTS source_key     text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS continuity     text NOT NULL DEFAULT 'recognition_only',
    ADD COLUMN IF NOT EXISTS immutable_key  text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS first_seen_at  timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_seen_at   timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS retired_reason text NOT NULL DEFAULT '';
ALTER TABLE public.iga_agents
    ADD CONSTRAINT iga_agents_continuity_chk CHECK (continuity IN ('immutable','recognition_only')),
    ADD CONSTRAINT iga_agents_immutable_chk  CHECK (continuity <> 'immutable' OR immutable_key <> '');
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_agents_source_key
    ON public.iga_agents (workspace_id, source_key)
    WHERE source_key <> '' AND lifecycle <> 'retired';

ALTER TABLE public.iga_credentials
    ADD COLUMN IF NOT EXISTS source_key     text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS continuity     text NOT NULL DEFAULT 'recognition_only',
    ADD COLUMN IF NOT EXISTS immutable_key  text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS first_seen_at  timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_seen_at   timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS retired_reason text NOT NULL DEFAULT '';
ALTER TABLE public.iga_credentials
    ADD CONSTRAINT iga_credentials_continuity_chk CHECK (continuity IN ('immutable','recognition_only')),
    ADD CONSTRAINT iga_credentials_immutable_chk  CHECK (continuity <> 'immutable' OR immutable_key <> '');
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_credentials_source_key
    ON public.iga_credentials (workspace_id, source_key)
    WHERE source_key <> '' AND lifecycle <> 'retired';
```


Three notes, each a decision:

- **`DEFAULT ''` plus a partial unique index.** Existing production rows have no
  recognition key and cannot be given one — they were minted by `uuid.New()`
  from GitHub scans and nothing records their origin. A total unique index would
  collapse them into one row. The partial index lets legacy rows coexist while
  constraining every new one. `035` retires them.
- **`lifecycle <> 'retired'` in the predicate** is what makes
  delete-and-recreate expressible: the retired row keeps its `source_key`, the
  new row takes the same key, only one is live.
- **`iga_credentials` is included** because P2-4 gives all five upsert methods a
  conflict target, and `UpsertCredential` is one of them. Its key is the
  credential's own id namespaced by its identity's `source_key`.

Put the Phase 3 warning from §2.6 in `iga_entitlements`' migration comment.

### 029 — `iga_workload`

```sql
CREATE TABLE IF NOT EXISTS public.iga_workload (
    id              uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id    uuid NOT NULL,
    estate_scope_id uuid,
    runtime_kind    text NOT NULL,
    display_name    text NOT NULL DEFAULT '',
    stage           text NOT NULL DEFAULT 'unknown',
    lifecycle       text NOT NULL DEFAULT 'active',
    retired_reason  text NOT NULL DEFAULT '',
    source_key      text NOT NULL,
    continuity      text NOT NULL DEFAULT 'recognition_only',
    immutable_key   text NOT NULL DEFAULT '',
    first_seen_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_workload_pkey PRIMARY KEY (id),
    CONSTRAINT iga_workload_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_workload_scope_fkey FOREIGN KEY (workspace_id, estate_scope_id)
        REFERENCES public.iga_estate_scopes (workspace_id, id) ON DELETE SET NULL (estate_scope_id),
    CONSTRAINT iga_workload_stage_chk CHECK (stage IN ('production','non_production','unknown')),
    CONSTRAINT iga_workload_lifecycle_chk CHECK (lifecycle IN ('active','retired','tombstoned')),
    CONSTRAINT iga_workload_continuity_chk CHECK (continuity IN ('immutable','recognition_only')),
    CONSTRAINT iga_workload_immutable_chk CHECK (continuity <> 'immutable' OR immutable_key <> ''),
    CONSTRAINT iga_workload_source_key_chk CHECK (source_key <> ''),
    CONSTRAINT iga_workload_workspace_id_key UNIQUE (workspace_id, id)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_workload_source_key
    ON public.iga_workload (workspace_id, source_key) WHERE lifecycle <> 'retired';
```

New table, so `source_key` is `NOT NULL` with a non-empty CHECK from the start.
The `UNIQUE (workspace_id, id)` is not decoration — it is the target every
composite FK needs.

**A workload is not an agent instance.** An instance may not be compute at all
(a published SaaS agent, a Bedrock alias). Where a Bedrock agent *is* the
runtime, the projector writes both rows and links them with a `realizes`
relationship.

#### Unresolved execution role (§4.7)

```sql
-- What we know about the role a workload acts as, when there is no
-- executes_as edge to say it. A bare "ARN or empty" cannot distinguish the
-- four cases the Identities view has to word differently.
ALTER TABLE public.iga_workload
    ADD COLUMN IF NOT EXISTS execution_role_state text NOT NULL DEFAULT 'none',
    ADD COLUMN IF NOT EXISTS execution_role_arn   text NOT NULL DEFAULT '',
    ADD CONSTRAINT iga_workload_exec_role_state_chk CHECK (execution_role_state IN
        ('resolved',          -- an executes_as edge exists; the ARN is on the edge
         'not_in_scan',       -- configured and known; its identity absent from this run
         'not_in_inventory',  -- configured; matches no identity we hold
         'none')),            -- no role configured
    -- The ARN is present exactly when it is the only place the role is recorded.
    ADD CONSTRAINT iga_workload_exec_role_arn_chk CHECK (
        (execution_role_state IN ('not_in_scan','not_in_inventory')) = (execution_role_arn <> ''));
```

#### Classification (§2.14.3)

```sql
ALTER TABLE public.iga_workload
    ADD COLUMN IF NOT EXISTS classification text NOT NULL DEFAULT 'unclassified',
    -- Optimistic-concurrency token for the classify endpoint (§2.14.3).
    ADD COLUMN IF NOT EXISTS classification_version bigint NOT NULL DEFAULT 0,
    ADD CONSTRAINT iga_workload_classification_chk CHECK (
        classification IN ('unclassified', 'provider_native_agent', 'classified_agent'));

-- The decision record. Same pattern as iga_classification_candidates (004),
-- which cannot be reused directly: its subject FKs to iga_source_objects, the
-- GitHub path's entity, not to a workload.
CREATE TABLE IF NOT EXISTS public.iga_workload_classification (
    id            uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id  uuid NOT NULL,
    workload_id   uuid NOT NULL,
    decision      text NOT NULL,   -- classified_agent | unclassified (an undo)
    purpose       text NOT NULL DEFAULT '',
    decided_by    text NOT NULL,
    decided_at    timestamptz NOT NULL DEFAULT now(),
    reason        text NOT NULL DEFAULT '',
    CONSTRAINT iga_workload_classification_pkey PRIMARY KEY (id),
    CONSTRAINT iga_wc_workload_fkey FOREIGN KEY (workspace_id, workload_id)
        REFERENCES public.iga_workload (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_wc_decision_chk CHECK (decision IN ('classified_agent', 'unclassified')),
    CONSTRAINT iga_wc_decided_by_chk CHECK (decided_by <> '')
);
```

### 030 — `iga_access_edges`: typed subject, required entitlement, lifecycle

```sql
ALTER TABLE public.iga_access_edges
    ADD COLUMN IF NOT EXISTS subject_identity_account_id uuid,
    ADD COLUMN IF NOT EXISTS subject_agent_id            uuid,
    ADD COLUMN IF NOT EXISTS subject_agent_instance_id   uuid,

    ADD COLUMN IF NOT EXISTS basis             text NOT NULL DEFAULT 'declared',
    ADD COLUMN IF NOT EXISTS derivation_rule   text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS state             text NOT NULL DEFAULT 'current',
    ADD COLUMN IF NOT EXISTS valid_from        timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS valid_to          timestamptz,
    ADD COLUMN IF NOT EXISTS last_confirmed_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_confirmed_by uuid,
    ADD COLUMN IF NOT EXISTS ended_reason      text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS source_key        text NOT NULL DEFAULT '',
    -- PARTITION MEMBERSHIP (§4.10). scope() selects the rows a partition owns
    -- by these two columns and nothing else, and the projector stamps both on
    -- every edge it writes. Without them every edge insert and every
    -- reconciliation fails on a missing column.
    ADD COLUMN IF NOT EXISTS partition_key     text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS connector_id      uuid;

-- Backfill: the only writer ever set subject_kind = 'identity_account'
-- (services/iga_service.go:918).
UPDATE public.iga_access_edges
   SET subject_identity_account_id = subject_id
 WHERE subject_kind = 'identity_account';

-- Rows that cannot satisfy the new shape are rebuildable projection rows with
-- no review decisions attached and nothing foreign-keying to them, so deleting
-- is safe -- but the counts must be reported, not swallowed.
DO $$
DECLARE n bigint;
BEGIN
    DELETE FROM public.iga_access_edges e
     WHERE e.subject_identity_account_id IS NULL
        OR e.entitlement_id IS NULL
        OR NOT EXISTS (SELECT 1 FROM public.iga_identity_accounts a
                        WHERE a.workspace_id = e.workspace_id
                          AND a.id = e.subject_identity_account_id);
    GET DIAGNOSTICS n = ROW_COUNT;
    RAISE NOTICE 'iga_access_edges: deleted % rows that cannot be typed', n;
END $$;

ALTER TABLE public.iga_access_edges
    ALTER COLUMN entitlement_id SET NOT NULL,

    ADD CONSTRAINT iga_access_edges_subject_identity_fkey
        FOREIGN KEY (workspace_id, subject_identity_account_id)
        REFERENCES public.iga_identity_accounts (workspace_id, id) ON DELETE CASCADE,
    ADD CONSTRAINT iga_access_edges_subject_agent_fkey
        FOREIGN KEY (workspace_id, subject_agent_id)
        REFERENCES public.iga_agents (workspace_id, id) ON DELETE CASCADE,
    ADD CONSTRAINT iga_access_edges_subject_instance_fkey
        FOREIGN KEY (workspace_id, subject_agent_instance_id)
        REFERENCES public.iga_agent_instances (workspace_id, id) ON DELETE CASCADE,
    -- §2.9: workspace-qualified, against the UNIQUE added in 027.
    ADD CONSTRAINT iga_access_edges_connector_fkey
        FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id)
        ON DELETE SET NULL (connector_id),
    ADD CONSTRAINT iga_access_edges_run_fkey
        FOREIGN KEY (workspace_id, last_confirmed_by)
        REFERENCES public.cloud_scan_run (workspace_id, id) ON DELETE SET NULL (last_confirmed_by),

    ADD CONSTRAINT iga_access_edges_subject_chk2 CHECK (
        (subject_identity_account_id IS NOT NULL)::int
      + (subject_agent_id            IS NOT NULL)::int
      + (subject_agent_instance_id   IS NOT NULL)::int = 1),

    ADD CONSTRAINT iga_access_edges_basis_chk CHECK (
        basis IN ('declared','observed','derived','asserted')),
    ADD CONSTRAINT iga_access_edges_derivation_chk CHECK (
        basis <> 'derived' OR derivation_rule <> ''),
    ADD CONSTRAINT iga_access_edges_state_chk CHECK (
        state IN ('current','stale','ended')),
    ADD CONSTRAINT iga_access_edges_ended_chk CHECK (
        (state = 'ended') = (valid_to IS NOT NULL)),
    ADD CONSTRAINT iga_access_edges_ended_reason_chk CHECK (
        (state = 'ended') = (ended_reason <> ''));

DROP INDEX IF EXISTS public.idx_iga_access_edges_subject;
ALTER TABLE public.iga_access_edges
    DROP CONSTRAINT IF EXISTS iga_access_edges_subject_chk,
    DROP COLUMN IF EXISTS subject_kind,
    DROP COLUMN IF EXISTS subject_id;

CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_access_edges_live
    ON public.iga_access_edges (workspace_id, source_key)
    WHERE source_key <> '' AND state <> 'ended';

CREATE INDEX IF NOT EXISTS idx_iga_access_edges_subject_identity
    ON public.iga_access_edges (workspace_id, subject_identity_account_id, direction)
    WHERE subject_identity_account_id IS NOT NULL;
```

- There is no `subject_workload_id`: a workload does not hold an entitlement,
  it executes *as* an identity that does. That path is
  `iga_relationship(executes_as)` then `iga_access_edges`, and keeping it two
  hops is the point — an inbound permission never implies an outbound one.
- `resource_id` stays, denormalized from the entitlement for the reverse query
  (`idx_iga_access_edges_resource`). The projector sets it from the entitlement.
- **`iga_access_edges_honesty_chk` from `004` must survive.** `ADD`/`DROP
  COLUMN` leaves it intact; assert its presence in the migration test.
- `uq_iga_access_edges_live` is partial on `state <> 'ended'` so history
  accumulates while only one edge per grant is live.
- `DROP COLUMN subject_kind` removes a column the Go model still has: `030` and
  the `models/iga.go` change land in the same commit.

### 031 — `iga_relationship`

```sql
CREATE TABLE IF NOT EXISTS public.iga_relationship (
    id                uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id      uuid NOT NULL,
    relationship_type text NOT NULL,

    source_identity_account_id uuid,
    source_workload_id         uuid,
    source_agent_instance_id   uuid,
    -- source_external_principal_id is added by 034, NOT here: its table does
    -- not exist yet and a forward reference makes 031 fail to apply. 034 adds
    -- the column, its composite FK, and widens both CHECKs below.


    target_identity_account_id uuid,
    target_workload_id         uuid,
    target_agent_id            uuid,

    basis             text NOT NULL DEFAULT 'declared',
    derivation_rule   text NOT NULL DEFAULT '',
    state             text NOT NULL DEFAULT 'current',
    valid_from        timestamptz NOT NULL DEFAULT now(),
    valid_to          timestamptz,
    last_confirmed_at timestamptz NOT NULL DEFAULT now(),
    last_confirmed_by uuid,
    ended_reason      text NOT NULL DEFAULT '',
    source_key        text NOT NULL,
    -- PARTITION MEMBERSHIP (§4.10), as on iga_access_edges.
    partition_key     text NOT NULL DEFAULT '',
    connector_id      uuid,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT iga_relationship_pkey PRIMARY KEY (id),
    CONSTRAINT iga_relationship_connector_fkey
        FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id)
        ON DELETE SET NULL (connector_id),
    CONSTRAINT iga_relationship_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_relationship_workspace_id_key UNIQUE (workspace_id, id),

    CONSTRAINT iga_rel_src_identity_fkey FOREIGN KEY (workspace_id, source_identity_account_id)
        REFERENCES public.iga_identity_accounts (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_rel_src_workload_fkey FOREIGN KEY (workspace_id, source_workload_id)
        REFERENCES public.iga_workload (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_rel_src_instance_fkey FOREIGN KEY (workspace_id, source_agent_instance_id)
        REFERENCES public.iga_agent_instances (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_rel_tgt_identity_fkey FOREIGN KEY (workspace_id, target_identity_account_id)
        REFERENCES public.iga_identity_accounts (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_rel_tgt_workload_fkey FOREIGN KEY (workspace_id, target_workload_id)
        REFERENCES public.iga_workload (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_rel_tgt_agent_fkey FOREIGN KEY (workspace_id, target_agent_id)
        REFERENCES public.iga_agents (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_relationship_run_fkey FOREIGN KEY (workspace_id, last_confirmed_by)
        REFERENCES public.cloud_scan_run (workspace_id, id) ON DELETE SET NULL (last_confirmed_by),

    -- Exactly one source and exactly one target, always.
    -- Widened by 034 to admit source_external_principal_id.
    CONSTRAINT iga_relationship_source_chk CHECK (
        (source_identity_account_id   IS NOT NULL)::int
      + (source_workload_id           IS NOT NULL)::int
      + (source_agent_instance_id     IS NOT NULL)::int = 1),
    CONSTRAINT iga_relationship_target_chk CHECK (
        (target_identity_account_id IS NOT NULL)::int
      + (target_workload_id         IS NOT NULL)::int
      + (target_agent_id            IS NOT NULL)::int = 1),

    -- The legal (source, type, target) triples, enumerated. The ELSE arm is
    -- load-bearing: a new relationship_type cannot be inserted until someone
    -- widens this constraint deliberately, which is the review point.
    CONSTRAINT iga_relationship_pair_chk CHECK (
        CASE relationship_type
            WHEN 'executes_as' THEN
                source_workload_id IS NOT NULL AND target_identity_account_id IS NOT NULL
            WHEN 'can_assume' THEN
                -- 034 widens this to also admit source_external_principal_id,
                -- once that table exists.
                source_identity_account_id IS NOT NULL
                AND target_identity_account_id IS NOT NULL
            WHEN 'realizes' THEN
                source_agent_instance_id IS NOT NULL AND target_workload_id IS NOT NULL
            ELSE false
        END),

    CONSTRAINT iga_relationship_basis_chk CHECK (
        basis IN ('declared','observed','derived','asserted')),
    CONSTRAINT iga_relationship_derivation_chk CHECK (
        basis <> 'derived' OR derivation_rule <> ''),
    CONSTRAINT iga_relationship_state_chk CHECK (state IN ('current','stale','ended')),
    CONSTRAINT iga_relationship_ended_chk CHECK ((state = 'ended') = (valid_to IS NOT NULL)),
    CONSTRAINT iga_relationship_ended_reason_chk CHECK ((state = 'ended') = (ended_reason <> '')),
    CONSTRAINT iga_relationship_source_key_chk CHECK (source_key <> '')
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_relationship_live
    ON public.iga_relationship (workspace_id, source_key) WHERE state <> 'ended';

CREATE INDEX IF NOT EXISTS idx_iga_relationship_source
    ON public.iga_relationship (workspace_id, relationship_type,
        COALESCE(source_identity_account_id, source_workload_id, source_agent_instance_id));
CREATE INDEX IF NOT EXISTS idx_iga_relationship_target
    ON public.iga_relationship (workspace_id, relationship_type,
        COALESCE(target_identity_account_id, target_workload_id, target_agent_id));
```

The source/target exactly-one CHECKs and the pair CHECK are redundant with each
other for the three current types. Keep both: the pair CHECK's `ELSE false` is
the gate on new types, and the exactly-one CHECKs stay correct no matter how the
pair CHECK is later widened.

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
    agent_id            uuid,

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
    CONSTRAINT iga_os_agent_fkey FOREIGN KEY (workspace_id, agent_id)
        REFERENCES public.iga_agents (workspace_id, id) ON DELETE CASCADE,

    -- The confirming run is workspace-qualified too (§2.9).
    CONSTRAINT iga_os_run_fkey FOREIGN KEY (workspace_id, last_confirmed_run_id)
        REFERENCES public.cloud_scan_run (workspace_id, id)
        ON DELETE SET NULL (last_confirmed_run_id),

    CONSTRAINT iga_object_support_one_chk CHECK (
        (identity_account_id IS NOT NULL)::int + (workload_id    IS NOT NULL)::int
      + (resource_id         IS NOT NULL)::int + (entitlement_id IS NOT NULL)::int
      + (agent_id            IS NOT NULL)::int = 1),
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
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_os_agent
    ON public.iga_object_support (workspace_id, agent_id, connector_id, partition_key)
    WHERE agent_id IS NOT NULL;
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
GitHub path; P2-1's CI check forbids new writers to it.

### 033 — projection job, projection state, agent origin

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

ALTER TABLE public.iga_agents
    ADD COLUMN IF NOT EXISTS origin text NOT NULL DEFAULT 'discovered',
    ADD CONSTRAINT iga_agents_origin_chk CHECK (origin IN ('registered','discovered'));

ALTER TABLE public.iga_agent_instances
    ADD COLUMN IF NOT EXISTS workload_id    uuid,
    ADD COLUMN IF NOT EXISTS source_key     text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS origin         text NOT NULL DEFAULT 'discovered',
    ADD COLUMN IF NOT EXISTS retired_reason text NOT NULL DEFAULT '',
    ADD CONSTRAINT iga_agent_instances_workload_fkey
        FOREIGN KEY (workspace_id, workload_id)
        REFERENCES public.iga_workload (workspace_id, id) ON DELETE SET NULL (workload_id),
    ADD CONSTRAINT iga_agent_instances_origin_chk CHECK (origin IN ('registered','discovered'));

CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_agent_instances_source_key
    ON public.iga_agent_instances (workspace_id, source_key)
    WHERE source_key <> '' AND lifecycle <> 'retired';
```

`reconciled = false` against a complete coverage state signals a pass
interrupted between projection and reconciliation; the next job re-reconciles
that partition rather than assuming it settled.

`iga_agent_instances` already has `first_seen_at`/`last_seen_at` and
`native_workload_id` from `004:563` — it needs the key, the origin and the typed
link, not a rebuild. **`origin` is the exit gate's "registered agent
distinguished from native discovery":** they get different review treatment and
must never silently merge. A discovered object a human later registers keeps its
id and flips `origin`, with the decision recorded.

#### Publication revisions (§2.15)

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
    mechanism     text NOT NULL,   -- oidc | saml | aws_account | service_principal
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
      + (source_agent_instance_id     IS NOT NULL)::int
      + (source_external_principal_id IS NOT NULL)::int = 1),

    DROP CONSTRAINT iga_relationship_pair_chk,
    ADD CONSTRAINT iga_relationship_pair_chk CHECK (
        CASE relationship_type
            WHEN 'executes_as' THEN
                source_workload_id IS NOT NULL AND target_identity_account_id IS NOT NULL
            WHEN 'can_assume' THEN
                (source_identity_account_id IS NOT NULL
                 OR source_external_principal_id IS NOT NULL)
                AND target_identity_account_id IS NOT NULL
            WHEN 'realizes' THEN
                source_agent_instance_id IS NOT NULL AND target_workload_id IS NOT NULL
            ELSE false
        END);
```

**`034` is part of the core rollout, not an optional extra.** Core
reconciliation writes this table — `retireUnsupported` suspends asserted
resolutions and re-derives derived ones — and the projector's recreation and
restoration branches call `SuspendAssertions` and
`MarkAssertionsPendingReconfirm`. With `027`–`033` applied and `034` not, the
reconciler fails with `relation "iga_external_principal" does not exist` on
**every** run: the error is raised at plan time, so it fires even when no row
could match. (Verified by applying exactly that intermediate state.)

What *is* staged is the feature, not the schema. The table ships empty; the
**resolution pass** — turning trust-policy principals into
`iga_external_principal` rows and drawing `can_assume` edges from them — is
P2-E and can be enabled later. An empty table makes every core write against
it a no-op, which is the correct behaviour before that pass exists.

### 035 — retire the legacy unkeyed rows (deferred)

`028`'s partial indexes let `source_key = ''` rows coexist. That is a transition
allowance. Once P2-4 and P2-6 own the write path and **one clean production scan
has run on the new path**, mark the remaining unkeyed rows
`lifecycle = 'retired'`, `retired_reason = 'pre_graph'`, and tighten the CHECK
to require a non-empty `source_key` on active rows. Ship as a separate PR, after 034. Never
tighten a constraint in the same release that introduces its column.

### Rules the DDL cannot express

1. **One-way projection.** No path writes `cloud_*` from `iga_*`. CI check, P2-1.
2. **Generation ordering.** A projection job may only advance
   `last_generation`; a replayed or out-of-order job is a no-op. The job lease
   is the fence — `lease_version`, never a clock.
3. **`ended` requires all four conditions of §2.7.** No SQL constraint can see
   coverage. This is `Reconciler.canEnd()`, the single most important function
   in the phase to test.
4. **Retired objects keep their `source_key`**; the partial unique indexes
   depend on it.
5. **Human-owned columns are never overwritten by the projector.** Ownership,
   review state, `classification`, and `origin` once `registered`. Every
   `ON CONFLICT DO UPDATE` names its columns — never `UpdateAll`.
6. **The observation writer records run membership even on the deduped path**
   (D4).

---

## 4. The machinery

§3 says what must be in the database. This says what code puts it there. Every
type and field below is from the tree at `eedabaa`.

### 4.1 No graph library, and why

A graph database (Neo4j, Dgraph, an embedded Cayley) is the obvious reach and
the wrong one here. It would be a **second datastore holding the same facts**,
which means a sync problem between it and Postgres — and the entire point of
§2.1 is that there is one authoritative source and one rebuildable projection.
A sync layer would reintroduce exactly the class of bug this phase exists to
remove.

What we actually need from "a graph" is: store edges, walk them a bounded number
of hops, and filter by state and time. Postgres does all three. Traversal in
Phase 4 is a recursive CTE over `iga_relationship`, depth-capped per §2.4 of the
roadmap. Bounded traversal over ~10⁴ edges per workspace is not a workload that
justifies a second database.

**No new dependencies.** Everything below uses what is already in `go.mod`:
`gorm.io/gorm`, `github.com/lib/pq`, `github.com/google/uuid`, stdlib.

### 4.2 Package layout

```
internal/igagraph/          pure logic, no database handle
    sourcekey.go            recognition keys, continuity, immutable keys
    load.go                 one run's cloud_* rows -> Snapshot, plus the
                            prefetch that keeps projection off N+1
    snapshot.go             the Snapshot type and its lookups
    project.go              Snapshot -> the writes to make
    reconcile.go            what this run did not see, and whether to close it

repository/
    iga_graph_repository.go        node and edge upserts, retire, end
    iga_projection_job_repository.go   claim/renew/complete, fenced like scans

services/
    iga_projection_service.go   claims a job, loads, projects, reconciles
```

The split matters for testing: `internal/igagraph` takes a `Snapshot` and
returns decisions, so the hard logic — key collisions, recreate detection, the
`ended`-vs-`stale` call — is testable as pure functions with no Postgres. The
repository layer is where `ON CONFLICT` lives.

### 4.3 The two data structures

Everything hinges on these.

```go
// Snapshot is one published run's collected state, loaded once.
//
// Loaded, not streamed: a run's output is thousands of rows, not millions, and
// the projection needs random access across all of it (an access edge needs its
// identity, its resource and its entitlement resolved at once). Streaming would
// buy nothing and cost a query per edge.
type Snapshot struct {
    Run        models.CloudScanRun
    Connector  models.CloudConnector
    Generation int

    Identities  []models.CloudIdentity
    Workloads   []models.CloudWorkload
    Resources   []models.CloudResource
    Permissions []models.CloudPermission
    AssumeEdges []models.CloudAssumeEdge

    // Per-run coverage, keyed by surface. Decoded from this run's own
    // cloud_scan_run.coverage (024), NEVER from cloud_connector.coverage,
    // which a later scan has overwritten.
    Coverage map[string]models.SurfaceCoverage

    // Observation ids this run CONFIRMED, keyed by subject. Selected on
    // last_confirmed_run_id = this run (024) -- because content dedupe means
    // an unchanged fact writes no new observation, so the observation's own
    // scan_run_id may name an older run.
    ConfirmedBy map[SubjectRef][]uuid.UUID
}

// SubjectRef keys observations by what SURVIVES inventory deletion.
//
// Not the cloud_* row id: 024 made cloud_observation's subject FKs
// ON DELETE SET NULL, so an observation outlives its subject row and the id
// goes NULL. subject_native_id is what remains.
//
// The key is ONE string, and it must be the one the collector wrote.
//
// A permission's native id alone is ambiguous: one statement produces one
// cloud_permission row per resource, and two holders of the same managed
// policy produce more. Carrying holder and resource as extra struct fields
// does not help, because they are not persisted -- the observation stores a
// single subject_native_id and the FK, and 024 makes that FK NULL once the
// inventory row is reconciled away.
//
// PHASE 1 CHANGE, IN P2-2: make the permission observation's
// subject_native_id fully qualifying at write time --
// "<holder ARN>\x1f<native_id>\x1f<resource ARN or *>" -- so the evidence
// carries its own unambiguous identity and survives the FK going NULL. This
// is a change to what goes INTO the existing column, not a new column.
type SubjectRef struct {
    Kind     string // identity | permission | resource | workload
    NativeID string // cloud_observation.subject_native_id, verbatim
}
```

```go
// resolved maps a cloud_* row id to the iga_* object id it projected to.
//
// This is the whole trick of the projection. Nodes are projected before the
// edges that reference them, so by the time an edge is written both of its
// endpoints are already in here and need no lookup. Without it, every edge
// costs two SELECTs by source_key.
type resolved struct {
    identity    map[uuid.UUID]uuid.UUID // cloud_identity.id   -> iga_identity_accounts.id
    workload    map[uuid.UUID]uuid.UUID // cloud_workload.id   -> iga_workload.id
    resource    map[uuid.UUID]uuid.UUID // cloud_resource.id   -> iga_resources.id
    entitlement map[uuid.UUID]uuid.UUID // cloud_permission.id -> iga_entitlements.id

    // cloud_permission.id -> iga_access_edges.id. Populated by
    // projectAccessEdges and consumed by attachEvidence, which has to know
    // which edge an observation is evidence for.
    accessEdge map[uuid.UUID]uuid.UUID

    // Live iga_* objects by source_key, loaded ONCE before the transaction
    // (§4.5). Recreate detection compares against this instead of issuing a
    // SELECT per row.
    existing *existing
}

func newResolved(ex *existing) *resolved {
    return &resolved{
        identity:    map[uuid.UUID]uuid.UUID{},
        workload:    map[uuid.UUID]uuid.UUID{},
        resource:    map[uuid.UUID]uuid.UUID{},
        entitlement: map[uuid.UUID]uuid.UUID{},
        accessEdge:  map[uuid.UUID]uuid.UUID{},
        existing:    ex,
    }
}
```

### 4.4 `sourcekey.go`

```go
package igagraph

// Unit separator. Cannot occur in an ARN, a policy name or a Kubernetes
// reference, so no join is ambiguous and no key needs escaping.
const sep = "\x1f"

func Key(provider string, parts ...string) string {
    return provider + sep + strings.Join(parts, sep)
}

// An IAM ARN already carries partition, account and (where regional) region,
// so it satisfies the roadmap §3.2 namespacing on its own. The provider prefix
// is what stops a GitHub or Kubernetes key colliding with it.
func IdentityKey(i models.CloudIdentity) string { return Key("aws", i.NativeID) }
func WorkloadKey(w models.CloudWorkload) string { return Key("aws", w.NativeID) }
func ResourceKey(r models.CloudResource) string { return Key("aws", r.NativeID) }
```

The entitlement key is the one with real logic in it (§2.6):

```go
// cloud_permission.native_id is "<source>#s<n>", where <source> is a managed
// policy ARN or "inline:<name>" (cloud_aws_permission_scan.go:410), and the
// row's grain is (identity, statement, resource) per uq_cloud_permission_grant.
func EntitlementKey(p models.CloudPermission, holder models.CloudIdentity, resourceKey string) string {
    if resourceKey == "" {
        resourceKey = "*" // an unresolved selector is still a distinct grant
    }
    return Key("aws", policyScope(p, holder), p.NativeID, resourceKey)
}

// policyScope decides whether an entitlement is SHARED.
//
// A managed policy is one object two roles can both attach, so both must
// resolve to ONE entitlement -- that is what makes "detach from one role ends
// that grant, the entitlement survives" true rather than aspirational.
//
// An inline policy is not shared. Two roles can each have one named ReadData,
// and they are different grants. Scoping by the holder's ARN keeps them apart.
func policyScope(p models.CloudPermission, holder models.CloudIdentity) string {
    source, _, _ := strings.Cut(p.NativeID, "#")
    if strings.HasPrefix(source, "inline:") {
        return holder.NativeID
    }
    return source
}
```

Continuity, per the roadmap §3.2 table:

```go
func Continuity(kind string) string {
    switch kind {
    case "iam_role", "iam_user", "ec2_instance":
        return models.ContinuityImmutable
    default:
        // lambda, ecs_task_definition, s3_bucket: the name is the strongest
        // claim available. Stored so the console can say so.
        return models.ContinuityRecognitionOnly
    }
}

// ImmutableKey reads the provider's creation-boundary id out of the collected
// attrs. Returns "" when the provider exposes none.
//
// Continuity() and ImmutableKey() must agree: 028's CHECK rejects a row
// claiming 'immutable' with an empty immutable_key, which is deliberate -- a
// silent disagreement here disables delete-and-recreate detection entirely.
func ImmutableKey(ci models.CloudIdentity) string {
    // The collector ALREADY stores this, as AWSIdentityAttrs.UniqueID
    // (`unique_id`), written at cloud_aws_iam_scan.go:452 from role.UniqueID.
    // models/cloud_discovery.go:418 documents it as "AROA... for a role,
    // AIDA... for a user" -- exactly the creation-boundary id needed here.
    //
    // Use the typed accessor, never a hand-rolled json.Unmarshal of a guessed
    // field name: a wrong key returns "" silently, Continuity() still says
    // 'immutable', and 028's CHECK then rejects every IAM identity.
    attrs, err := ci.AWSAttrs()
    if err != nil {
        return ""
    }
    return attrs.UniqueID
}
```

> **Verify the attrs mapping separately for every object kind before relying on
> it.** IAM roles and users are confirmed (`UniqueID`). EC2 instances,
> Lambda, ECS task definitions and S3 buckets are **not** — each needs its own
> check of what the collector actually writes, because `Continuity()` claiming
> `immutable` while `ImmutableKey()` returns `""` makes 028's CHECK reject the
> row. That loud failure is correct; do not relax the CHECK to get past it,
> fix the mapping or downgrade the kind to `recognition_only`.

### 4.5 Loading the snapshot

`internal/igagraph/load.go`. One function, five queries, and one decision that
determines whether this scales.

```go
func Load(ctx context.Context, db *gorm.DB, jobRunID uuid.UUID) (*Snapshot, error) {
    var run models.CloudScanRun
    if err := db.WithContext(ctx).First(&run, "id = ?", jobRunID).Error; err != nil {
        return nil, err
    }
    var conn models.CloudConnector
    if err := db.WithContext(ctx).First(&conn, "id = ?", run.ConnectorID).Error; err != nil {
        return nil, err
    }

    snap := &Snapshot{Run: run, Connector: conn, Generation: run.Generation}

    // Rows AT THIS RUN'S GENERATION. Not "all rows for the connector": a later
    // scan may already have written generation+1 rows, and projecting those
    // under this job's generation would attribute another run's findings to
    // this one -- and then reconcile against the wrong baseline.
    // REPEATABLE READ makes the five reads one consistent view, which is
    // necessary and NOT sufficient. See "Why isolation alone cannot fix this"
    // below: the inputs must also be guaranteed not to have moved before the
    // snapshot opened, and that is a coordination property, not an isolation
    // one.
    tx := db.WithContext(ctx).Begin(&sql.TxOptions{Isolation: sql.LevelRepeatableRead})
    defer tx.Rollback()

    gen := run.Generation
    cid := run.ConnectorID
    q := func(dst any) error {
        return tx.Where("connector_id = ? AND last_seen_generation = ?", cid, gen).
            Find(dst).Error
    }
    if err := q(&snap.Identities);  err != nil { return nil, err }
    if err := q(&snap.Workloads);   err != nil { return nil, err }
    if err := q(&snap.Resources);   err != nil { return nil, err }
    if err := q(&snap.Permissions); err != nil { return nil, err }
    if err := q(&snap.AssumeEdges); err != nil { return nil, err }

    // Coverage is the run's OWN report (024), decoded from the jsonb column
    // stamped at publish. Never cloud_connector.coverage, which a later scan
    // has overwritten -- that was D1.
    snap.Coverage = models.DecodeScanCoverage(run.Coverage).Surfaces

    // Which observations THIS run confirmed. Content dedupe means a re-read of
    // unchanged data writes no row, so the question cannot be answered by
    // scan_run_id; 024 added last_confirmed_run_id for exactly this (D4).
    var obs []models.CloudObservation
    if err := tx.
        Select("id", "subject_native_id", "identity_id", "permission_id",
               "resource_id", "workload_id").
        Where("workspace_id = ? AND last_confirmed_run_id = ?", run.WorkspaceID, run.ID).
        Find(&obs).Error; err != nil {
        return nil, err
    }
    snap.ConfirmedBy = indexObservations(obs)

    // A defence in depth, not the guarantee. The connector's generation only
    // moves at commitScan, so this catches a NEXT scan that already finished
    // -- it cannot catch one still in flight. The guarantee is the
    // coordination rule below.
    var fresh models.CloudConnector
    if err := tx.First(&fresh, "id = ?", cid).Error; err != nil {
        return nil, err
    }
    if fresh.ScanGeneration > gen {
        return nil, ErrSuperseded
    }
    return snap, tx.Commit().Error
}
```

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

#### Publication must be one transaction

`AWSScanWorker.execute` currently runs `Publish` → `FinalizeCoverage` →
`SetCoverage` (best effort, `cloud_aws_scan_worker.go:185-199`). Enqueuing the
projection job inside `Publish()` therefore creates a job that can be claimed
**before its coverage exists**, and a crash in the gap makes that permanent —
the job then reads absent coverage, `canEnd` refuses every partition, and the
graph silently never closes anything.

**Required worker change, in P2-2:** compute coverage first, then in **one
transaction** persist per-run coverage, flip the run to `published`, and
enqueue the projection job — all under the existing lease fence.

```go
merged := scanner.FinalizeCoverage(...)          // no writes
err := w.runs.PublishWithCoverage(run.ID, w.owner, run.LeaseVersion, merged)
// one tx: SetCoverage + Publish + enqueue iga_projection_job, fenced on
// (lease_owner, lease_version). Coverage stops being best-effort: a scan
// whose coverage cannot be stored has not published.
```

This reverses the current ordering deliberately. The existing comment argues
publication must come first so a superseded worker cannot overwrite the
winner's coverage — the fence already guarantees that, and inside one
transaction the ordering of the two writes is not observable.

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
```go
// (loader continues)
```

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
    entitlement map[string]*models.IGAEntitlement
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

One transaction per `(scope, class)` partition. Nodes first, edges second.

```go
// projectAndReconcile is the ONE transaction. Project and Reconcile below are
// its two halves and take a *gorm.DB they must not commit -- separate
// transactions would publish a graph in which nothing has been closed yet,
// and a crash between them leaves it that way until the next run.
func (s *ProjectionService) projectAndReconcile(
    ctx context.Context, snap *Snapshot, job *models.IGAProjectionJob,
) error {
    return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
        if err := s.projector.Project(tx, snap, job); err != nil {
            return err
        }
        return s.reconciler.Reconcile(tx, snap)
    })
}

func (p *Projector) Project(tx *gorm.DB, snap *Snapshot, job *models.IGAProjectionJob) error {
    return func(tx *gorm.DB) error {
        // FENCE FIRST, INSIDE THE TRANSACTION.
        //
        // Checking the lease before the transaction proves nothing: the lease
        // can be lost while the writes are in flight, and a Complete() that
        // is rejected afterwards cannot un-commit a graph mutation. This
        // locks the job row and asserts the caller still owns the claimed
        // lease version; a reclaimed worker fails here and commits nothing.
        //
        // The row stays locked for the transaction's life, so the reclaiming
        // worker blocks rather than writing concurrently.
        if err := p.jobs.AssertOwnedTx(tx, p.jobID, p.owner, p.leaseVersion); err != nil {
            return err // ErrLeaseLost -> rollback, write nothing
        }

        // 1. OWNERSHIP. Binds workspace, phase, job and version (§2.10A): a
        //    worker holding collecting@v7 cannot pass even if the version
        //    matches, because phase and job are in the predicate. Locks the
        //    barrier row FOR UPDATE for the rest of the transaction.
        if err := p.pipeline.AssertOwnedTx(tx, PipelineFence{
            WorkspaceID: snap.Run.WorkspaceID,
            Phase:       models.PipelineProjecting,
            JobID:       p.jobID,
            Version:     p.pipelineVersion,
        }); err != nil {
            return err // ErrLeaseLost -> rollback, write nothing
        }

        // 2. ALREADY PUBLISHED? Checked BEFORE the generation guard, because
        //    the two outcomes it separates are opposite:
        //
        //      this run's projection already committed, then the worker died
        //      before completing the job  -> SUCCESS: finish the job
        //      a newer run already published over these partitions
        //                                 -> SUPERSEDED: abandon
        //
        //    A generation comparison alone cannot tell them apart -- after a
        //    committed pass the watermark EQUALS this generation, so a `<=`
        //    guard reports the replay as obsolete and the job fails on every
        //    retry, forever. The durable fact that separates them is the
        //    publication row, which commits atomically with the graph (step 6).
        if pub, err := p.repo.PublicationForRun(tx, snap.Run.WorkspaceID, snap.Run.ID); err != nil {
            return err
        } else if pub != nil {
            return &AlreadyPublished{Rev: pub.Rev} // no writes; caller completes the job
        }

        // 3. SUPERSEDED? Only a STRICTLY newer generation. Under the barrier
        //    this should be unreachable -- a newer run cannot project while
        //    this job holds `projecting` -- so reaching it means an abandon
        //    raced a reclaim, and the correct response is to stop, not to
        //    overwrite. Equality without a publication row for this run is an
        //    inconsistency, not a replay, and fails loudly.
        for _, part := range Partitions(snap) {
            have, err := p.reconciler.lastGenerationFor(tx, part, snap.Run.WorkspaceID)
            if err != nil {
                return err
            }
            switch {
            case int64(snap.Generation) < have:
                return ErrSuperseded
            case int64(snap.Generation) == have:
                return fmt.Errorf("partition %s at generation %d with no publication for run %s: %w",
                    part.Key(), have, snap.Run.ID, ErrInconsistentWatermark)
            }
        }

        r := newResolved(p.existing) // prefetched once, §4.5

        // Nodes, in dependency order. Each populates `r` so later passes can
        // resolve endpoints without a query.
        if err := p.projectIdentities(tx, snap, r); err != nil { return err }
        if err := p.projectResources(tx, snap, r); err != nil { return err }
        if err := p.projectWorkloads(tx, snap, r); err != nil { return err }
        if err := p.projectEntitlements(tx, snap, r); err != nil { return err }

        // Edges. Every endpoint is in `r` by now.
        if err := p.projectAccessEdges(tx, snap, r); err != nil { return err }
        if err := p.projectRelationships(tx, snap, r); err != nil { return err }

        // Evidence, then the watermark. reconciled=false until the
        // Reconciler commits; see §2.8 on interrupted passes.
        if err := p.attachEvidence(tx, snap, r); err != nil { return err }
        // reconciled=false here; Reconcile flips it in the same transaction.
        if err := p.recordState(tx, snap, false); err != nil {
            return err
        }

        // 6. PUBLICATION. Same transaction as every graph write above, so
        //    "the graph changed" and "a publication exists for this run" can
        //    never disagree -- which is exactly what step 2 relies on to tell
        //    a replay from a supersession.
        //
        //    rev = max(rev)+1 is safe here: step 1 holds the barrier row FOR
        //    UPDATE, and the barrier serializes projection per workspace.
        //    UNIQUE (workspace_id, scan_run_id) makes a double publish of one
        //    run impossible even if that reasoning were ever wrong.
        return p.repo.InsertPublication(tx, &models.IGAPublication{
            WorkspaceID: snap.Run.WorkspaceID,
            ScanRunID:   snap.Run.ID,
            PublishedAt: p.now(),
            Manifest:    manifestOf(snap), // {partition_key: run_id}
        })
    }(tx)
}
```

One node pass in full — the others are the same shape:

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
func (p *Projector) projectRelationships(tx *gorm.DB, snap *Snapshot, r *resolved) error {
    now := p.now()

    // workload --executes_as--> identity
    for _, w := range snap.Workloads {
        src, ok := r.workload[w.ID]
        if !ok {
            continue // the workload itself was not projected; nothing to annotate
        }

        // DETERMINE THE ENDPOINT FIRST, then record what we know. Clearing a
        // warning before the edge is known to exist is how a configured role
        // silently disappears from the customer's view.
        //
        // Four outcomes, and each is a different sentence on the Identities
        // view. The ARN is the role the workload ACTS AS -- RoleARN in the
        // collector -- never attrs.ExecutionRoleARN, which for ECS is the
        // image-pull role ECS itself uses (workloads.go:82), not the task's.
        var dst uuid.UUID
        state, arn := models.ExecRoleNone, ""
        switch {
        case w.IdentityID != nil:
            if id, ok := r.identity[*w.IdentityID]; ok {
                dst, state = id, models.ExecRoleResolved
            } else {
                // The collector resolved the role against an inventory row,
                // but that row is not in THIS run's snapshot (a partial IAM
                // read, or a row still at an older generation). The role is
                // configured and known; we just cannot draw the edge now.
                state, arn = models.ExecRoleNotInScan, snap.IdentityNativeID(*w.IdentityID)
            }
        case w.AWSAttrs().UnresolvedRoleARN != "":
            // A role is configured but matches nothing in inventory -- another
            // account, or iam_roles never read.
            state, arn = models.ExecRoleNotInInventory, w.AWSAttrs().UnresolvedRoleARN
        }

        // Written on EVERY pass, for every projected workload, so a state from
        // an earlier run cannot survive: resolved clears the ARN, the others
        // set it, none clears both.
        if err := p.repo.SetExecutionRoleState(tx, src, state, arn); err != nil {
            return err
        }
        if state != models.ExecRoleResolved {
            continue // no edge: there is no projected endpoint to point it at
        }

        if err := p.repo.UpsertRelationship(tx, &models.IGARelationship{
            WorkspaceID:             snap.Run.WorkspaceID,
            RelationshipType:        "executes_as",
            // MEMBERSHIP. scope() finds rows by (workspace, connector,
            // partition_key) and nothing else -- an edge written without
            // these is invisible to reconciliation and never ends, ever.
            // The partition is chosen by the surface that produced the row,
            // so a Lambda edge lands in lambda:<region>, not in ECS's.
            ConnectorID:             &snap.Run.ConnectorID,
            PartitionKey:            snap.EdgePartitionFor("executes_as", w.RuntimeKind, w.Region).Key(),
            SourceWorkloadID:        &src,
            TargetIdentityAccountID: &dst,
            Basis:                   "declared", // configuration says so; we did not see it run
            State:                   "current",
            LastConfirmedAt:         now,
            LastConfirmedBy:         &snap.Run.ID,
            // BOTH endpoints. A key naming only the workload means a Lambda
            // moved from RoleA to RoleB computes the SAME key, so the upsert
            // overwrites the target in place -- no ended RoleA edge, no
            // history, and the exit gate's "role replacement closes the old
            // edge" silently fails. The identity's source_key also carries
            // its recreate boundary, so a recreated role cannot inherit the
            // old relationship's history.
            // Both endpoints, and the TARGET'S IMMUTABLE KEY -- not its ARN.
            //
            // A role deleted and recreated under the same name has the same
            // ARN, so an ARN-keyed endpoint produces the same relationship
            // key and the new role silently inherits the old one's history.
            // The immutable key (AROA…) is the creation boundary, so a
            // recreate yields a different relationship key and the old one is
            // ended rather than adopted.
            //
            // recognition_only targets have no immutable key; those fall back
            // to the source key and cannot detect recreation, which is what
            // `continuity` on the node exists to tell the reader.
            SourceKey: Key("aws", "executes_as", w.NativeID, endpointKey(snap, *w.IdentityID)),
        }); err != nil {
            return err
        }
    }

    // identity --can_assume--> identity, from cloud_assume_edge.
    // CloudAssumeEdge.Subject is a STRING, not a row id: the trust policy names
    // a principal that may not exist in this account, or at all. Resolve it by
    // source key and skip when unknown -- a trust statement naming a principal
    // we have never seen is not evidence that principal exists (roadmap §3.1).
    for _, ae := range snap.AssumeEdges {
        dst, ok := r.identity[ae.IdentityID]
        if !ok { continue }
        src, ok := snap.IdentityIDByKey(Key("aws", ae.Subject))
        if !ok { continue }
        ...
    }
    return nil
}
```

`projectWorkloads` is the same shape as `projectIdentities` — **including
the support upsert**, with `part := snap.PartitionFor(models.ObjectWorkload,
w.RuntimeKind, w.Region)`, because workload partitions are per service per
region (`lambda:eu-central-1` is not `ecs:eu-central-1`). A description by
reference is only safe if it carries the step that is easy to omit.

`projectResources` above follows the same contract. Both are the same shape as
`projectIdentities` above, differing only in which model they write and in
`Continuity()` returning `recognition_only` for every runtime kind Phase 2
collects — so a Lambda that is deleted and recreated under the same name
continues as one object, and the console says `recognition_only` rather than
implying we checked.

`snap.IdentityIDByKey(key)` is a lookup over an index built in `Load`, used for
the assume-edge target: `cloud_assume_edge.Subject` is a *string* naming a
principal that may not exist in this account or at all, so it resolves by
source key and returns `false` when unknown.

### 4.7 The access graph

The previous section projects nodes and the structural edges between them. This
is the part that makes it an *access* graph, and it is the one path where the
provider's shape and ours genuinely differ.

**The shape mismatch.** One `cloud_permission` row is
`(identity, statement, resource)` — that is `uq_cloud_permission_grant`
(`013:178`). The canonical model splits that into two things:

```
cloud_permission (identity, statement, resource)
        │
        ├──▶ iga_entitlements   (statement, resource)   — WHAT may be done
        │                         keyed by policy scope; SHARED across holders
        │
        └──▶ iga_access_edges   (identity → entitlement) — WHO holds it
```

Splitting them is what makes *"detach a managed policy from one of two roles and
that role's grant ends while the entitlement and the other role's grant
survive"* expressible. Keep them fused and detaching from one role either
deletes a grant the other still has, or leaves a dangling row nobody can
explain.

#### Resources first — entitlements point at them

```go
func (p *Projector) projectResources(tx *gorm.DB, snap *Snapshot, r *resolved) error {
    now := p.now()
    for _, cr := range snap.Resources {
        key := ResourceKey(cr)
        id, err := p.repo.UpsertResource(tx, &models.IGAResource{
            WorkspaceID: snap.Run.WorkspaceID,
            SourceKey:   key,
            // A selector is not proof the resource exists (roadmap §3.1), and
            // Phase 2 does not enumerate. `kind` carries what the ARN claims;
            // existence is Phase 3's problem.
            ResourceKind: cr.Kind,
            DisplayName:  cr.Name,
            Continuity:   Continuity(cr.Kind),
            Stage:        "unknown",
            LastSeenAt:   now,
        }, r.existing.live.resource[key] == nil /* isNew */)
        if err != nil {
            return fmt.Errorf("upsert resource %s: %w", key, err)
        }

        // Step 2, identical in shape to projectIdentities. A resource named by
        // two accounts gets TWO support rows -- one per connector -- and that
        // is the whole mechanism by which account B dropping it leaves account
        // A's support, and the resource, intact (§2.10B, scenario 3).
        part := snap.PartitionFor(models.ObjectResource, "", "")
        if err := p.repo.UpsertSupport(tx, &models.IGAObjectSupport{
            WorkspaceID:        snap.Run.WorkspaceID,
            ResourceID:         &id,
            ConnectorID:        snap.Run.ConnectorID,
            PartitionKey:       part.Key(),
            State:              models.RelCurrent,
            LastConfirmedRunID: &snap.Run.ID,
            LastConfirmedAt:    &now,
            EndedReason:        "",
        }); err != nil {
            return fmt.Errorf("upsert resource support %s: %w", key, err)
        }

        r.resource[cr.ID] = id
    }
    return nil
}
```

#### Entitlements — where sharing is decided

```go
func (p *Projector) projectEntitlements(tx *gorm.DB, snap *Snapshot, r *resolved) error {
    now := p.now()

    // The holder is needed to key an INLINE policy (§2.6), so index identities
    // by their cloud id first.
    byID := make(map[uuid.UUID]models.CloudIdentity, len(snap.Identities))
    for _, ci := range snap.Identities {
        byID[ci.ID] = ci
    }

    for _, cp := range snap.Permissions {
        holder, ok := byID[cp.IdentityID]
        if !ok {
            // The permission's identity was not read by this run. Skip: an
            // entitlement we cannot key correctly is worse than a missing one,
            // because the wrong key silently merges two different grants.
            continue
        }

        resourceKey := ""
        if cp.ResourceID != nil {
            if rid, ok := r.resource[*cp.ResourceID]; ok {
                resourceKey = p.keyOf(rid)
            }
        }
        // resourceKey stays "" for an account-wide or wildcard grant; the key
        // builder substitutes "*". NULLS NOT DISTINCT on the collector's side
        // means those already collapse to one cloud_permission row per
        // statement, so they collapse to one entitlement here too.

        key := EntitlementKey(cp, holder, resourceKey)

        var resID *uuid.UUID
        if cp.ResourceID != nil {
            if rid, ok := r.resource[*cp.ResourceID]; ok { resID = &rid }
        }

        id, err := p.repo.UpsertEntitlement(tx, &models.IGAEntitlement{
            WorkspaceID: snap.Run.WorkspaceID,
            SourceKey:   key,
            ResourceID:  resID,
            NativeGrantKind: cp.NativeID,
            // Both representations, always. native_rights is what AWS said;
            // normalized_rights is our reading. A reviewer must be able to see
            // the provider's own wording -- that is why 004 has both columns.
            NativeRights:     mustJSON(nativeRightsOf(cp)),
            NormalizedRights: mustJSON(normalizeRights(cp)),
            NativeScope:      cp.ScopeKind,
            // Revocable through a supported path. Phase 2 has no remediation,
            // so this is a statement about the grant's shape, not a promise.
            Remediable: !strings.HasPrefix(cp.NativeID, "boundary:"),
            LastSeenAt: now,
        }, r.existing.live.entitlement[key] == nil)
        if err != nil {
            return fmt.Errorf("upsert entitlement %s: %w", key, err)
        }

        // Step 2. This is the row that makes "two policies declare the same
        // grant; detach one; the other survives" true at the node level: a
        // managed-policy entitlement shared by two holders in two accounts
        // carries one support row per connector, and ending one leaves it
        // active while the other holds.
        part := snap.PartitionFor(models.ObjectEntitlement, "", "")
        if err := p.repo.UpsertSupport(tx, &models.IGAObjectSupport{
            WorkspaceID:        snap.Run.WorkspaceID,
            EntitlementID:      &id,
            ConnectorID:        snap.Run.ConnectorID,
            PartitionKey:       part.Key(),
            State:              models.RelCurrent,
            LastConfirmedRunID: &snap.Run.ID,
            LastConfirmedAt:    &now,
            EndedReason:        "",
        }); err != nil {
            return fmt.Errorf("upsert entitlement support %s: %w", key, err)
        }

        r.entitlement[cp.ID] = id
    }
    return nil
}
```

`nativeRightsOf` preserves `Actions`, `NotActions`, `NotResources`, `Condition`
and `Effect` verbatim.

**`Effect` is lowercase.** The parser stores `strings.ToLower(stmt.Effect)`
(`internal/awsdiscovery/policy_statements.go:135`), so it is `"allow"` /
`"deny"`, never `"Allow"`. Any comparison against the capitalised form is
always false — which, in a branch that decides whether access is effective,
inverts the answer for every Allow statement in the account. Compare
case-insensitively, or against the lowercase constant, and cover it with a
test that would fail on the capitalised form.

The statement's allow/deny is preserved **on the entitlement**, as the
provider's own wording, and is never promoted into an access-edge conclusion:
"this statement says Deny" is a fact about the policy; "this request would be
denied" is an evaluation Phase 2 does not perform.

**It must not drop `NotActions`/`NotResources`** — a
NotAction-only statement is a real grant shape (`019` relaxed
`cloud_permission_actions_chk` precisely to allow it), and an entitlement that
silently loses the negation reads as broader access than exists.

#### Access edges — who holds what

```go
func (p *Projector) projectAccessEdges(tx *gorm.DB, snap *Snapshot, r *resolved) error {
    now := p.now()
    for _, cp := range snap.Permissions {
        subj, ok := r.identity[cp.IdentityID]
        if !ok { continue }
        ent, ok := r.entitlement[cp.ID]
        if !ok { continue } // entitlement was skipped above; no edge without one

        var resID *uuid.UUID
        if cp.ResourceID != nil {
            if rid, ok := r.resource[*cp.ResourceID]; ok { resID = &rid }
        }

        // calculation_state / effective_conclusion carry the SAME honesty rule
        // the GitHub path already uses (iga_service.go:913) and that 004's
        // iga_access_edges_honesty_chk enforces: a decided conclusion requires
        // a complete calculation.
        //
        // Phase 2 evaluates NOTHING. Conditions are recorded, never evaluated
        // (roadmap §3.5a), so any grant carrying a constraint is 'partial' and
        // 'unknown'. Writing 'effective' here would claim an evaluation we did
        // not perform.
        // Phase 2 runs no evaluator, so the conclusion is ALWAYS unknown and
        // the calculation is ALWAYS partial. There is no branch that promotes
        // a grant to 'effective': doing so would claim an evaluation nobody
        // performed, which is the one thing roadmap §3.5a forbids.
        //
        // What IS recorded is the statement's own allow/deny, on the
        // entitlement, as evidence of what the policy says. That is a
        // different claim from "a request would succeed", and conflating the
        // two is how a dashboard starts lying.
        calc, conclusion := models.CalcPartial, models.ConclusionUnknown

        edgeID, err := p.repo.UpsertAccessEdge(tx, &models.IGAAccessEdge{
            WorkspaceID:              snap.Run.WorkspaceID,
            ConnectorID:              &snap.Run.ConnectorID,
            PartitionKey:             snap.EdgePartitionFor("access_edge", "", "").Key(),
            SubjectIdentityAccountID: &subj,
            EntitlementID:            ent,          // NOT NULL since 030
            ResourceID:               resID,        // denormalized for the reverse query
            Direction:                "outbound",
            PathKind:                 cp.NativeID,
            Basis:                    models.BasisDeclared,
            State:                    models.RelCurrent,
            CalculationState:         calc,
            EffectiveConclusion:      conclusion,
            NativeScope:              cp.ScopeKind,
            LastConfirmedAt:          now,
            LastConfirmedBy:          &snap.Run.ID,
            SourceKey: Key("aws", IdentityKey(byIDOf(snap, cp.IdentityID)),
                cp.NativeID, orStar(resourceKeyOf(r, cp))),
        })
        if err != nil {
            return fmt.Errorf("upsert access edge %s: %w", cp.NativeID, err)
        }
        // Retained so attachEvidence can link observations to THIS edge.
        // Without this line the evidence pass reads an empty map and silently
        // writes nothing -- a broken pipeline that looks like a working one.
        r.accessEdge[cp.ID] = edgeID
    }
    return nil
}
```

**Two roles on one managed policy, concretely.** Both produce a
`cloud_permission` row. Both compute the *same* `EntitlementKey`, because the
policy ARN is the scope — so the second upsert conflicts and updates rather than
inserting. Each produces a *different* access-edge `source_key`, because that
key leads with the identity. Result: **one entitlement, two edges.** Detach the
policy from one role and only that edge ends.

Swap the managed policy for two inline policies both named `ReadData`, and
`policyScope` returns each holder's ARN instead: **two entitlements, two edges**,
correctly unshared.

### 4.8 Evidence, and the watermark

```go
// attachEvidence links each projected object to the observations THIS run
// confirmed. The join is on subject_native_id, not on a cloud_* row id, because
// 024 made the subject FKs ON DELETE SET NULL -- an observation outlives the
// inventory row it describes, and the native id is what survives.
func (p *Projector) attachEvidence(tx *gorm.DB, snap *Snapshot, r *resolved) error {
    for _, cp := range snap.Permissions {
        edgeID, ok := r.accessEdge[cp.ID]
        if !ok { continue }
        // Built with the SAME function the observation writer uses, so the
        // two cannot drift. One shared helper, never two spellings.
        ref := SubjectRef{Kind: "permission", NativeID: igagraph.PermissionSubjectKey(cp, holder, resKey)}
        for _, obsID := range snap.ConfirmedBy[ref] {
            if err := p.repo.LinkAccessEdgeEvidence(tx, snap.Run.WorkspaceID,
                edgeID, obsID, "supports"); err != nil {
                return err
            }
        }
    }
    return nil // same shape for relationships, against iga_relationship_evidence
}
```

**Derived relationships still get evidence.** `executes_as` comes from a field
on the workload, so its supporting observation is the *workload's* — link that,
with `relation = 'supports'`, rather than leaving the edge bare. The same holds
for `can_assume` (the role's trust-policy observation) and `realizes`.

**Every projected edge needs evidence — counted per edge, not per class.** A
non-zero count per *class* passes with one evidenced edge and ten thousand
bare ones, which is exactly the shape of the bug this section had: the access
pass never retained its edge ids, so the map was empty and the pipeline wrote
nothing while appearing to work. P2-6's gate asserts
`count(edges without evidence) == 0` for every projected class.

**Changing what the writer supplies is not enough — the dedupe path must
upgrade the stored key.** `cloud_observation_writer.go:241` updates only
`last_confirmed_run_id`, `last_confirmed_at` and `confirmation_count` on
conflict, so an unchanged rescan keeps the old unqualified
`subject_native_id` even when the caller passes the new one. Every
already-collected observation would stay un-upgradable for as long as its
content does not change, which for stable IAM is indefinitely.

P2-2 adds the upgrade to the same `DoUpdates`, guarded so it can only ever
add qualification:

```go
"subject_native_id": gorm.Expr(
    // Upgrade only while the subject is still resolvable, and only from an
    // unqualified key to a qualified one. Never overwrite a qualified key,
    // and never write a placeholder over a real value.
    `CASE WHEN cloud_observation.subject_native_id NOT LIKE '%' || ? || '%'
               AND ? <> '(unknown)'
          THEN ? ELSE cloud_observation.subject_native_id END`,
    sep, subjectNativeID, subjectNativeID),
```

**Observations already orphaned cannot be upgraded**, because their subject FK
is NULL and the holder and resource were never persisted separately.

**They are therefore never attached as `supports`.** Matching them on the bare
native id would be a guess: two holders of the same managed policy share a
statement identifier, so the orphan could belong to either, and attaching it
to one — or to both — manufactures evidence. Worse, it would let ambiguous
history satisfy the "every projected edge has evidence" gate, turning the
gate from a check into a rubber stamp.

`indexObservations` skips any observation whose key lacks the qualifying
separator. Those rows stay queryable as history and are surfaced by the read
path as **unattributed evidence** — "this was observed, we cannot say for
which grant" — which is a true statement and a useful one. What they must
never be is a `supports` row on an edge.

The "evidence survives deletion as a reconstructable graph input" guarantee
therefore applies **from P2-2 forward only**, and the read path must label
pre-P2-2 evidence as such rather than implying the same precision.

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

Region is deliberately **not** a sub-scope in Phase 2. It would multiply
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
func (rc *Reconciler) Reconcile(tx *gorm.DB, snap *Snapshot) error {
    for _, part := range Partitions(snap) {
        stale := !rc.canEnd(snap, part)
        var err error
        if part.Target == "" {
            err = rc.reconcileNodes(tx, part, snap, stale) // identity|workload|resource|entitlement
        } else {
            err = rc.reconcileEdges(tx, part, snap, stale) // relationship|access_edge
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
Checked against the scanners at `efb67b2`, the real vocabulary is:

| Emitted by | Keys |
|---|---|
| `cloud_aws_iam_scan.go` | `iam_roles`, `iam_users`, `iam_access_keys`, `iam_policies` |
| `cloud_aws_permission_scan.go` | `oidc_providers`, `eks_pod_identity`, `resource_policies`, and `policy_documents` **only when something failed to parse** |
| `cloud_aws_workload_scan.go` | On success, one key **per service per region**: `lambda:<region>`, `ecs:<region>`, `ec2:<region>`, `bedrock-agents:<region>`, `bedrock-agentcore:<region>` (`:268-295`). `compute:<region>` is **only** the stand-in written when the region's client config fails (`denied`, `:255`) or the region was never selected (`not_selected`, `:166`) |
| `FinalizeCoverage` | `iam_credential_report`, `permission_scan`, `workload_scan`, `activity` |

```go
func Partitions(snap *Snapshot) []Partition {
    sc, cn := snap.ScopeID, snap.Run.ConnectorID

    // NAMED FIELDS, ALWAYS. Positional literals silently mis-assign the
    // moment a field is added, and RequiredScanners was added after this
    // list was first written -- every positional literal here compiled
    // fine with the veto list empty, which disables the gate entirely.
    ps := []Partition{
        // Roles and users are SEPARATE partitions. Merged, a denied
        // iam_users read blocks role reconciliation, or a good roles read
        // licenses closing users.
        {ScopeID: sc, ConnectorID: cn, Class: "identity",
            RequiredSurfaces: []string{models.SurfaceIAMRoles}},
        {ScopeID: sc, ConnectorID: cn, Class: "identity",
            RequiredSurfaces: []string{models.SurfaceIAMUsers}},

        // Resources come from the SAME read as entitlements -- the permission
        // scanner writes cloud_resource for every ARN a statement names -- so
        // they reconcile on the same evidence. Without this partition resources
        // never reconcile at all, and a bucket two accounts share cannot show
        // one account's support ending while the other's holds.
        {ScopeID: sc, ConnectorID: cn, Class: "resource",
            RequiredSurfaces: []string{
                models.SurfaceIAMRoles, models.SurfaceIAMPolicies, models.SurfacePolicyDocuments},
            RequiredScanners: []string{models.SurfacePermissionScan}},

        {ScopeID: sc, ConnectorID: cn, Class: "entitlement",
            RequiredSurfaces: []string{
                models.SurfaceIAMRoles, models.SurfaceIAMPolicies, models.SurfacePolicyDocuments},
            // The permission scanner produces both the statements and the
            // parse report. If it died before producing a snapshot at all,
            // policy_documents is absent for the WRONG reason.
            RequiredScanners: []string{models.SurfacePermissionScan}},

        {ScopeID: sc, ConnectorID: cn, RelationshipType: "can_assume", Target: "relationship",
            RequiredSurfaces: []string{models.SurfaceIAMRoles, models.SurfacePolicyDocuments},
            RequiredScanners: []string{models.SurfacePermissionScan}},

        // Access edges reconcile on the same evidence as the entitlements
        // they point at, and are NOT covered by the relationship partitions.
        {ScopeID: sc, ConnectorID: cn, Target: "access_edge",
            RequiredSurfaces: []string{
                models.SurfaceIAMRoles, models.SurfaceIAMPolicies, models.SurfacePolicyDocuments},
            RequiredScanners: []string{models.SurfacePermissionScan}},
    }

    // Per SERVICE per REGION, because that is the grain the scanner reports
    // at. Keyed only on region, a clean ECS read would license closing
    // Lambda workloads in the same region.
    //
    // compute:<region> is NOT a success key -- it appears only when the
    // region was unselected or its client config failed, standing in for the
    // five per-service surfaces that never ran. So it belongs in
    // RequiredScanners (presence = failure), never in RequiredSurfaces.
    for _, region := range snap.RegionsAttempted() {
        computeGate := []string{models.SurfaceWorkloadScan, "compute:" + region}
        // Every workload surface gets a WORKLOAD partition -- Bedrock and
        // AgentCore included. They previously had only a `realizes` edge
        // partition, so a Bedrock agent's own node had nowhere to be
        // reconciled and PartitionFor panicked on it.
        for _, svc := range []string{"lambda", "ecs", "ec2",
            "bedrock-agents", "bedrock-agentcore", "agentcore-gateways"} {
            ps = append(ps, Partition{ScopeID: sc, ConnectorID: cn, Class: "workload",
                RequiredSurfaces: []string{svc + ":" + region},
                RequiredScanners: computeGate})
        }
        // executes_as for EVERY workload kind the collector attaches an
        // execution role to -- verified: Lambda/ECS/EC2 (workloads.go),
        // Bedrock AgentResourceRoleArn (bedrock.go:156), AgentCore runtime
        // and gateway RoleArn (bedrock.go:191, :262). Covering only the first
        // three meant a customer could select an AWS agent and never see the
        // identity it runs as -- the one relationship this experience exists
        // to explain.
        for _, svc := range []string{"lambda", "ecs", "ec2",
            "bedrock-agents", "bedrock-agentcore", "agentcore-gateways"} {
            ps = append(ps,
                Partition{ScopeID: sc, ConnectorID: cn,
                    RelationshipType: "executes_as", Target: "relationship",
                    RequiredSurfaces: []string{svc + ":" + region, models.SurfaceIAMRoles},
                    RequiredScanners: computeGate})
        }
        for _, svc := range []string{"bedrock-agents", "bedrock-agentcore"} {
            ps = append(ps, Partition{ScopeID: sc, ConnectorID: cn,
                RelationshipType: "realizes", Target: "relationship",
                RequiredSurfaces: []string{svc + ":" + region},
                RequiredScanners: computeGate})
        }
    }
    return ps
}
```

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
// efb67b2: cloud_aws_workload_scan.go:268-295 and scanGateways.
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
`UpsertResource`, `UpsertEntitlement`, `UpsertAccessEdge`,
`UpsertRelationship`, `UpsertProjectionState`, `LinkAccessEdgeEvidence`.

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
| `SetExecutionRoleState` | Called for **every projected** workload on every pass, **after** the endpoint is determined. Writes the state and the ARN together, so the `CHECK` pairing them can never be violated mid-update. Never skipped, so no earlier run's state survives |
| `Snapshot.IdentityNativeID` | Native id of any `cloud_identity` a workload references, **regardless of generation** — loaded in `Load` by one `WHERE id IN (…)` over the snapshot's workload identity ids. It is how `not_in_scan` still names the role |

Everything else called in §4 without a body (`orStar`, `keyOf`, `byIDOf`,
`resourceKeyOf`, `nativeRightsOf`, `normalizeRights`, `now`, `stop`) is
mechanical and has no correctness property beyond its name.

> **`permission_scan` and `workload_scan` are not constants yet.** They are
> string literals in `FinalizeCoverage` (`cloud_aws_iam_scan.go:795`, `:803`),
> unlike the `models.Surface*` values. P2-2 promotes them to
> `models.SurfacePermissionScan` / `SurfaceWorkloadScan` and switches
> `FinalizeCoverage` to use them, so the partition table and the writer cannot
> drift by a typo. Do not reference them as constants before that lands.

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
func (rc *Reconciler) reconcileEdges(tx *gorm.DB, part Partition, snap *Snapshot, stale bool) error {
    if stale {
        return rc.markStale(tx, part, snap)
    }
    return rc.endOlderThan(tx, part, snap, "not_seen")
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
func (rc *Reconciler) markStale(tx *gorm.DB, part Partition, snap *Snapshot) error {
    return rc.scope(tx, part, snap).
        Where("state = ?", models.RelCurrent).
        Where("last_confirmed_by IS DISTINCT FROM ?", snap.Run.ID).
        Update("state", models.RelStale).Error
}

// endOlderThan: we looked properly at this partition and it was not there.
func (rc *Reconciler) endOlderThan(tx *gorm.DB, part Partition, snap *Snapshot, reason string) error {
    return rc.scope(tx, part, snap).
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
  silently excludes it — `realizes` starts at an `agent_instance`, which a
  union of workloads and identities does not contain, so those rows would
  never reconcile at all.

So membership is **written at projection time and queried directly**. Each
relationship and access edge records the partition that produced it:

The columns are created in migrations `030` (`iga_access_edges`) and `031`
(`iga_relationship`); the fragment below shows their shape only.

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
func (rc *Reconciler) scope(tx *gorm.DB, part Partition, snap *Snapshot) *gorm.DB {
    model := any(&models.IGARelationship{})
    if part.Target == "access_edge" {
        model = &models.IGAAccessEdge{}
    }
    return tx.Model(model).
        Where("workspace_id = ? AND connector_id = ? AND partition_key = ?",
            snap.Run.WorkspaceID, part.ConnectorID, part.Key())
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
    case models.ObjectAgent:       return "agent_id", nil
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
    case models.ObjectAgent:       return "iga_agents"
    }
    panic("unmapped node class " + class)
}

// Step 1 -- end this partition's SUPPORT, not the object.
func (rc *Reconciler) reconcileNodes(tx *gorm.DB, part Partition, snap *Snapshot, stale bool) error {
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
    for _, class := range models.NodeClasses { // identity, workload, resource, entitlement, agent
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

Retiring a node ends its incident relationships with
`ended_reason = 'subject_retired'`, in the same transaction.

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

`services/iga_projection_service.go`. Mirrors `AWSScanWorker` (`Run` /
`RunOnce` / `execute` / `heartbeat`) so there is one worker shape in the
codebase, not two.

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

**Failure semantics, stated once:**

| Situation | Behaviour | Why |
|---|---|---|
| Projection errors midway | transaction rolls back, job `failed`, lease expires, reclaimed | Idempotent, so the retry converges. Nothing half-written is visible. |
| Worker is killed | no `Fail` call; lease simply expires | Same recovery path. Fencing on `lease_version` means the dead worker cannot later commit. |
| Lease lost mid-projection | next fenced write returns `ErrLeaseLost`; abort, write nothing further | A superseded worker must not publish. Identical rule to `cloud_scan_run`. |
| Connector generation advanced | `abandoned` with a reason, detected inside the load snapshot | The newer run's job does the work with better data. |
| Lease lost while the graph transaction is open | `AssertOwnedTx` fails, transaction rolls back | A reclaimed worker cannot commit graph mutations. Rejecting `Complete()` afterwards would be too late — the writes would already be visible. |
| One partition's coverage is bad | that partition goes `stale`; others still reconcile | Per-partition is the whole point — a denied Lambda surface must not freeze IAM. |

**What readers may see.** Projection and reconciliation commit together, so
the graph moves from one published state to the next with no visible gap. A
reader that must not straddle versions pins
`iga_projection_state.last_run_id` for the partitions it reads and filters on
it; Phase 4's traversal API makes that pinning explicit, which is why its exit
gate says "current and history reads pin a publication".

**Retry is not unbounded.** `attempts` increments on every claim; past a small
ceiling the job stops being claimed and stays `failed` with its last error. A
job that fails deterministically — a bad `source_key`, a CHECK it cannot satisfy
— must stop and be visible, not spin against production forever.

### 4.12 One Lambda, end to end

Concretely, with the values a real scan produces.

**Collected** (Phase 1, already working):

```
cloud_identity   id=c1a2  kind=iam_role  native_id=arn:aws:iam::1234:role/refund-lambda-role
                 attrs={"role_id":"AROA5XK7QEXAMPLE"}
cloud_workload   id=b7f0  runtime_kind=lambda  identity_id=c1a2
                 native_id=arn:aws:lambda:eu-central-1:1234:function:refund-processor
cloud_resource   id=d3e1  native_id=arn:aws:s3:::refunds-bucket/*
cloud_permission id=e5c9  identity_id=c1a2  resource_id=d3e1
                 native_id=arn:aws:iam::1234:policy/RefundS3Access#s0
                 actions={s3:GetObject}  effect=Allow  constraint_state=unconstrained
```

**Projected** (Phase 2):

| iga row | `source_key` | notes |
|---|---|---|
| `iga_identity_accounts` | `aws␟arn:aws:iam::1234:role/refund-lambda-role` | `continuity=immutable`, `immutable_key=AROA5XK7QEXAMPLE` |
| `iga_workload` | `aws␟arn:aws:lambda:eu-central-1:1234:function:refund-processor` | `continuity=recognition_only` — the ARN embeds the name, not a creation boundary |
| `iga_resources` | `aws␟arn:aws:s3:::refunds-bucket/*` | still a selector; Phase 3 resolves it |
| `iga_entitlements` | `aws␟arn:aws:iam::1234:policy/RefundS3Access#s0␟arn:aws:s3:::refunds-bucket/*` | managed policy ⇒ **shared**; a second role attaching it adds an edge, not an entitlement |
| `iga_relationship` | `aws␟executes_as␟arn:aws:lambda:…:refund-processor` | `executes_as`, source=workload, target=identity, `basis=declared` |
| `iga_access_edges` | `aws␟arn:aws:iam::1234:role/refund-lambda-role␟…#s0␟…refunds-bucket/*` | subject=identity, entitlement NOT NULL, `state=current` |

**Rescan, nothing changed.** Every `source_key` matches, every upsert takes the
`DO UPDATE` branch, `last_seen_at` advances, `first_seen_at` and every `id` are
untouched. Row counts identical. That is acceptance item 1.

**The Lambda is repointed to `RoleB`.** `cloud_workload.identity_id` now
resolves elsewhere, so `projectRelationships` writes an `executes_as` to the new
identity — a different `source_key`, hence a new row. The old row is not in this
run's output; `canEnd` passes (published, surface `reached`, no parse failures,
generation owned), so reconciliation sets it `ended` with `valid_to`. Both are
readable. Acceptance item 2.

**IAM is denied on the next scan.** No identities, no workloads, no permissions.
`canEnd` returns false at condition 2 — the surface is `denied`, not `reached` —
so everything moves to `stale` with its last confirmation time intact. **Zero
rows end.** Acceptance item 8, and the reason `canEnd` exists.

**The role is deleted and recreated with the same name.** Same `source_key`,
`immutable_key` is now `AROA9ZZ…`. `projectIdentities` retires the old row
(`retired_reason='recreated'`), ends its edges (`subject_recreated`), and
inserts a new object with a new `id` and a fresh `first_seen_at`. Acceptance
item 4.

---

## 5. Tasks

Eleven tasks. Each names its files and one gate checkable by someone who did not
write it. **P2-2 must land before anything else** — the rest is built on it.

### P2-0 · One narrow slice, end to end, before anything widens

Build exactly one path and prove it: **Lambda → IAM role → declared
entitlement → resource reference**, with evidence and reconciliation. **Build
the happy path first, then introduce the failure cases one at a time.**

Also in the slice, because they are the highest-risk contracts to get wrong:
the manual-classification endpoint (the one human write, and the only way to
exercise the actor rule), and the reconciler's handling of asserted
associations — exercised against **seeded** `iga_external_principal` rows,
not a resolution pass.

Out of the slice: the graph canvas and every UI beyond the one read path,
automatic classification, grouping, Bedrock/AgentCore, `can_assume` edges, the
external-principal resolution pass, credentials, and traversal beyond one
workload's declared path.

Nine scenarios it must survive. Each maps to a defect this document has
already had to correct, which is why they are the gate and not a later
hardening pass:

| Scenario | What it catches |
|---|---|
| Unchanged rescan | ids and `first_seen_at` stable; no duplicate rows |
| Lambda switches `RoleA` → `RoleB` | the relationship key names both endpoints, so the old edge ends instead of being overwritten |
| A policy that fails to parse | `policy_documents` appears as `partial`, and **nothing closes** in the entitlement or access-edge partitions |
| One region denied, another clean | `eu-central-1` reports `compute:eu-central-1: denied` (the failure stand-in) and its workloads go stale; `us-east-1` reports `lambda:us-east-1: reached` and closes — per-region partitions really are independent |
| Two AWS accounts in one workspace | a scan of A closes nothing in B |
| An obsolete worker | a reclaimed job cannot commit; the graph is unchanged and the job reads `abandoned` |
| **Two accounts naming the same bucket** | B's scan reassigns `cloud_resource.connector_id`; A's projection must not silently lose the resource or the edges needing it |
| **A superseded scan worker that keeps running** | its writes stop at lease loss; its replacement's projection sees a stable input set |
| **Crash between publication and coverage** | impossible — one transaction. Kill the worker mid-publish and the run is either fully published with coverage and a queued job, or not published at all |

> **Exit gate — all nine scenarios above, plus these five.** The five
> supplement the table; they do not replace it. Executed through the
> implementation, not the pseudocode, against real Postgres, each verified
> non-vacuous by removing its fix and observing the failure:
>
> 1. **A normal human session** classifies a workload: a real workspace token
>    — which carries **both** `user_id` and `client_id` — **succeeds**. A
>    machine-only token, an end-user token, and a member with `invited` or
>    `suspended` status are each **refused**.
> 2. **A workload whose configured role is not in the current scan** shows
>    `not_in_scan` with the role's ARN, and **no newly confirmed**
>    `executes_as` edge. If a relationship was discovered in an earlier run,
>    it is **preserved**: `stale`, with its last confirmation time, while
>    coverage for its partition is incomplete; `ended` with `valid_to` — still
>    readable, never deleted — only when coverage is complete and the role is
>    genuinely absent. A workload with no role configured shows `none`. None of
>    these is confused with another, and **no case deletes a prior edge**.
>    The fixture must include the prior edge; a fixture starting empty cannot
>    tell preservation from deletion.
> 3. **Retirement and restoration**: a role confirmed absent retires and a
>    person's association with it — a **seeded** asserted
>    `iga_external_principal` row — is `suspended`; the same `UniqueID`
>    returns and is restored — same id — with the association
>    `pending_reconfirmation`, not active.
> 4. **A crash after publication**: the graph transaction commits, the worker
>    is killed before `completeAndRelease`; the replay finds `AlreadyPublished`,
>    writes nothing, and completes the job. The job is `complete`, not
>    `failed`, and the barrier is `idle`.
> 5. **Deployment states S0–S2, in an isolated environment**: deploy into
>    each and confirm what the table says must hold — in particular that
>    Phase 1 scanning still works in S1, and that the projector declines to
>    start below `034`.
>
> **S3 is not part of this gate.** It includes `035`, which depends on
> evidence from a real rollout (one clean S2 production scan) and is a
> separate cleanup gate. It must not block starting the first slice.
>
> The graph widens only after all nine scenarios and all five proofs pass.

**Evidence report.** P2-0's deliverable is running behaviour plus a short
report, one row per scenario and proof:

| Field | Content |
|---|---|
| Commit | The implementation commit the result was observed on |
| Command | The exact test invocation, reproducible by someone else |
| Fixture | Starting state — the rows seeded, the coverage report, the token used |
| Expected | The database state and, where there is one, the API/UI result |
| Observed | What actually happened |
| Safeguard removed | Where meaningful: the specific fix removed, and the failure then observed |

A row without *Observed* is a plan, not evidence. A row whose *Safeguard
removed* result is "still passes" is a test that proves nothing, and fails
the gate.

### P2-1 · Extend the CI boundary check

`scripts/ci-iga-isolation-check.sh` exists and is bash-3.2 portable. Add: no
file under `internal/igagraph/` or matching `*projector*.go` may reference a
`cloud_*` table in a write position (`INSERT`/`UPDATE`/`DELETE`/`Create`/`Save`/
`Updates`), and no file outside the GitHub path may add a writer to
`iga_observation_links`.

Keep it a grep. A privilege boundary cannot tell a designed join from a careless
one — recorded in roadmap §2.1, and the same reasoning applies here.

> **Gate:** a deliberately added `db.Create(&models.CloudIdentity{})` under
> `internal/igagraph/` fails CI. Prove it by adding the line, running the
> script, seeing the failure, reverting.

### P2-2 · Close the cross-workspace provenance gap

Migration `027` alone: the two `UNIQUE (workspace_id, id)` targets and the three
single-column references converted to composite form (§3, `027`).

`024` already closed D1–D4. **Verify them, do not redo them** (§1.2), and in
particular leave `models.ScanCoverage.Complete()` alone — the parse-failure gate
lives upstream in `cloud_aws_permission_scan.go:226`, which turns the surface
`partial` before `Complete()` runs. Adding a counter check inside `Complete()`
duplicates a gate that already holds, and the duplicate is the copy that drifts.

Then wire the projection job enqueue: `repository/cloud_scan_run_repository.go`
`Publish()` also enqueues `iga_projection_job` in the same transaction. That is a
forward reference — land `027` now and wire the enqueue when `033` exists.

> **Gate:** a `cloud_observation` row whose `scan_run_id` belongs to another
> workspace is rejected by the database, proven by a test that fails without
> `027`. Then re-assert what `024` delivers, so a later change cannot quietly
> undo it: deleting a `cloud_permission` leaves its observations alive with
> `subject_native_id` intact; a second unchanged read advances
> `last_confirmed_run_id` without growing the table; a surface with one parse
> failure never reads `reached`.

### P2-3 · `internal/igagraph/sourcekey.go`

*Implementation: §4.4.*

One exported function producing the namespaced key of §2.4; `Continuity(kind)`
returning `immutable` or `recognition_only` per the roadmap §3.2 table;
`ImmutableKey` extraction for roles (`RoleId`), users (`UserId`) and EC2
instances; and `EntitlementKey` implementing the managed-vs-inline scoping of
§2.6.

Reuse the ARN parsing in `internal/awsdiscovery/policy_statements.go`
(`TypedResource` carries `Account`, `ObjectKey`, `BucketName`) and the
`inline:` discrimination at `cloud_aws_permission_scan.go:496`. Do not write a
second ARN parser.

> **Gate:** table test over every row of roadmap §3.2. Two accounts with the
> same role name produce different keys. The same role through two connectors
> produces the same key. **Two roles each with an inline policy named
> `ReadData` produce different entitlement keys; two roles attached to the same
> managed policy produce the same one.** One statement naming three resources
> produces three distinct entitlement keys.

### P2-4 · Make the canonical upserts actually upsert

Replace the five bare `Create` calls at `repository/iga_repository.go:616-629`.

**The conflict target is a partial index, and GORM's `Where` is the wrong
field.** `clause.OnConflict{Where: ...}` emits the `DO UPDATE … WHERE` condition;
index inference against a partial unique index needs the index predicate, which
is `TargetWhere`. PostgreSQL's `INSERT` reference documents the distinction.

```go
func (r *igaRepository) UpsertIdentityAccount(a *models.IGAIdentityAccount) error {
	return r.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "workspace_id"}, {Name: "source_key"}},
		// Must match uq_iga_identity_accounts_source_key's predicate exactly,
		// or Postgres cannot infer the index and the statement errors.
		TargetWhere: clause.Where{Exprs: []clause.Expression{
			clause.Expr{SQL: "source_key <> '' AND lifecycle <> 'retired'"},
		}},
		// Named columns only. UpdateAll would clobber human-owned state and
		// reset first_seen_at -- the exact thing the exit gate tests.
		DoUpdates: clause.AssignmentColumns([]string{
			"display_name", "account_kind", "identity_backing",
			"last_seen_at", "updated_at",
		}),
	}).Create(a).Error
}
```

Then fix the caller: `services/iga_service.go:863,885,899,918` assigns
`ID: uuid.New()` on every scan and must instead read back the resolved id for
the edge it writes. All five methods — including `UpsertCredential`, whose
`source_key` `028` adds.

Test against **real Postgres**. SQLite accepts the wrong thing silently.

> **Gate:** run the same GitHub scan twice against real Postgres. Row counts in
> `iga_identity_accounts`, `iga_resources`, `iga_entitlements`,
> `iga_credentials` and `iga_access_edges` are identical after the second run,
> every `id` is unchanged, every `first_seen_at` is unchanged, `last_seen_at`
> advanced. This is the exit gate's first clause and is testable before any AWS
> projection exists.

### P2-5 · Models and migrations for the graph

*The upsert trap that will bite: §4.9.*

`028`–`032`, plus `models/iga.go`: `IGAAccessEdge` loses `SubjectKind`/
`SubjectID`, gains the three typed subject pointers and the lifecycle columns;
new `models.IGAWorkload` and `models.IGARelationship`. `ListAccessEdges`
(`repository/iga_repository.go:632`) filters on the dropped column and must take
a typed subject.

A `Subject()` helper returning `(kind, id)` keeps the multi-column awkwardness
out of read call sites. Writes name the column.

> **Gate:** `go build ./... && go vet ./...` clean. Four database rejections,
> each as a test: two subject columns set; a subject from another workspace; an
> `iga_relationship` with a source but no target; an `iga_relationship` with
> `relationship_type = 'executes_as'` whose source is an identity rather than a
> workload. Also: an edge whose `last_confirmed_by` is another workspace's run
> is rejected (§2.9).

### P2-6 · The projector

*Implementation: §4.3 (structures), §4.5 (loading), §4.6 (nodes), §4.7 (the access graph), §4.8 (evidence), §4.11 (the worker). Worked example: §4.12.*

`internal/igagraph/projector.go`, `services/iga_projection_service.go`,
`repository/iga_projection_job_repository.go`.

Claim a job; verify `cloud_connector.scan_generation` has not advanced past it
(abandon if it has); then per `(scope, class)`, in one transaction:

1. read `cloud_*` rows at the job's generation, plus that run's
   `cloud_scan_run.coverage`;
2. compute `source_key` and continuity;
3. detect delete-and-recreate where `continuity = 'immutable'`;
4. upsert nodes, advancing `last_seen_at`, never `first_seen_at`;
5. upsert `iga_access_edges` and `iga_relationship` rows, `basis = 'declared'`,
   `state = 'current'`, `last_confirmed_by = run.ID`;
6. write evidence junction rows against the `cloud_observation` rows confirmed
   by this run (`last_confirmed_run_id = run.ID`);
7. record `iga_projection_state` with `reconciled = false`.

Renew the job lease on a heartbeat. **If the job lease is lost mid-projection,
stop and write nothing further** — reuse the `fenced()` pattern rather than
adding a second ownership notion.

> **Gate:** projecting the same published run twice produces byte-identical
> `iga_*` state. Deleting all `iga_*` rows for a workspace and re-projecting
> reproduces the graph exactly, except human-owned columns. Killing the worker
> mid-projection and letting the lease expire produces the same final state as
> an uninterrupted run. A job whose connector generation has advanced records
> `abandoned` and writes nothing.

### P2-7 · Reconciliation

*Implementation: §4.10, including `Partitions`, `markStale` and `endOlderThan`.*

`internal/igagraph/reconcile.go`. For each `(scope, class, relationship_type)`
with `reconciled = false`: rows last confirmed at an older generation become
`ended` **only when `canEnd()` returns true** for all four conditions of §2.7;
otherwise `stale`.

`canEnd()` reads `cloud_scan_run.coverage` for **this run**, checks
`status = 'published'`, and requires `last_confirmed_run_id` to name this run. It does **not** call `ScanCoverage.Complete()`
and does not read `cloud_connector.coverage`.

> **Gate:** five tests. Denied scan ⇒ `stale`, zero `ended`. Clean scan that no
> longer sees a relationship ⇒ `ended` with `valid_to` and `ended_reason`.
> Throttled surface ⇒ `stale`. **One parse failure in the owning scope ⇒
> `stale`** — the parse failure turns `policy_documents` `partial` upstream, so
> the persisted report never says `reached`. Deduped unchanged evidence in
> run 2 ⇒ `current`, not `stale`,
> because `last_confirmed_run_id` names run 2.
>
> **Check each for vacuity:** assert the same fixture *with* coverage complete
> does produce `ended`. The Phase 1 deletion test passed with its fix removed
> because EKS was denied and `Complete()` was already false.

### P2-8 · Delete-and-recreate

Same `source_key`, different non-empty `immutable_key` ⇒ retire the old row
(`lifecycle = 'retired'`, `retired_reason = 'recreated'`), insert a new one with
a new `id` and fresh `first_seen_at`. All relationships on the old object `ended`
with `ended_reason = 'subject_recreated'`.

> **Gate:** fixture scan; delete the role in the fake AWS and recreate it with
> the same name and a new `RoleId`; rescan. Two `iga_identity_accounts` rows,
> the old retired `recreated`, the new with a later `first_seen_at`, old
> relationships `ended`.

### P2-9 · Credentials

Per §2.5. Two active keys on an IAM user is a correct state. A disappeared key
becomes `revoked` only under the four conditions; `rotated` only from a human
assertion.

> **Gate:** an IAM user with two active access keys yields two `iga_credentials`
> rows both `active`, with the identity's `id`, `first_seen_at` and every
> relationship unchanged. Disable one key and rescan under complete coverage ⇒
> that credential `revoked`, the other untouched. Rescan under **denied**
> coverage ⇒ neither changes state.

### P2-10 · Agent instances become real

Replace `services/iga_service.go:1300`'s unconditional
`Instances: []models.IGAAgentInstance{}` with a real read. The projector writes
instances for Bedrock agents and AgentCore runtimes, linked to `iga_workload` by
a `realizes` relationship. `AgentDetail` surfaces `origin`.

> **Gate:** a Bedrock agent in the fixture appears as `iga_agents` with
> `origin = 'discovered'` plus an `iga_agent_instances` row and a `realizes`
> relationship to its `iga_workload`; an agent registered through the product
> appears with `origin = 'registered'`; the two are distinguishable in
> `AgentDetail` and never merge even when display names match.

### P2-11 · One read-only path-and-evidence view

*Shape: §2.14.5 (navigation), §2.14.6 (wireframes), §2.14.7 (states).
Contracts: §2.15. Do not invent a second shape.*

Not the console. One authenticated endpoint under `/api/iga/v1` that returns,
for a given workload: its `executes_as` identity, that identity's access edges
with entitlement and resource, each row's `basis`, `state`, `last_confirmed_at`,
and the evidence ids behind it — plus any surface whose coverage was not
`reached`.

This exists so the team can inspect and explain the graph before Phase 4 builds
traversal on it. The workspace comes from the authenticated context, never a
query parameter.

> **Gate:** a reviewer who did not build the projector can take one workload id
> and explain, from the response alone, why the system believes each grant and
> when it was last confirmed. A foreign-workspace workload id returns 404, not
> another tenant's graph.

---

## 6. Acceptance

Twelve executable backend scenarios (§6.1) and the UI acceptance gates
(§6.2). Each names what it breaks if removed — a scenario that cannot fail is
not a gate.

**Status: these are planned acceptance gates, not results.** None has been run
against the contracts in this document. What *has* been demonstrated is listed
in §6.4, with why it does not transfer.

### 6.1 Executable scenarios

| # | Scenario | Passes when | Catches |
|---|---|---|---|
| 1 | **Two workloads share one role.** `ticket-tools` and `refund-tools` both `executes_as` `SharedToolRole` | Two `executes_as` rows, one identity object. The identity's workload list returns both. Neither edge's key collides | A relationship key that omits an endpoint |
| 2 | **Duplicate grants, one removed.** `TicketRead` and `ToolboxRead` both declare `s3:GetObject`; detach `TicketRead` | Two entitlements before; after, one `ended` and one `current`; **the access edge survives**; the change entry names which policy went and which remains | Merging independent grants into one row |
| 3 | **A resource supported by two integrations.** Accounts A and B both name the same bucket; B stops | One resource object, two support rows; B's `ended`, A's `current`; **the resource stays `active`** | Single-owner node membership |
| 4 | **Collection failure preserves prior relationships.** IAM denied on rescan | Everything becomes `stale` with last-confirmation intact. **Zero rows `ended`.** Non-vacuity: the same fixture with coverage `reached` **does** end them | `canEnd` trusting the wrong signal |
| 5 | **Lease expiry after publication, before projection** | The barrier recovers **into `projecting`**, same phase, new version. No scan is admitted. The old worker's fenced write is refused | Expiry returning the barrier to `idle` |
| 6 | **Crash around graph commit and barrier release** | **(a)** Kill after the graph transaction commits, before `completeAndRelease`: recovery reclaims `projecting`, the replay hits `AlreadyPublished` in step 2, **writes nothing**, and completes. The job ends `complete`, not `failed`; `iga_publication` has exactly one row for the run. **(b)** Kill inside `completeAndRelease`: it is one transaction, so either both job and barrier moved or neither did — case (a) again. **(c)** No state admits a scan while a projection could still commit | A `<=` generation guard that makes every replay fail forever; a non-atomic complete/release |
| 7 | **Recreated role, same ARN, new `UniqueID`** | Two identity objects; old retired `recreated` with its edges `subject_recreated`; new one has a later `first_seen_at` | ARN-only endpoint keys |
| 8 | **Support ends, then reappears.** Same recognition *and* immutable key | Support flips `ended → current`, `ended_reason` cleared, **object id and `first_seen_at` unchanged**. Relationships are re-projected as new rows, not revived | Treating reappearance as recreation, and stale `ended_reason` |
| 9 | **Cross-workspace reference rejected** | Inserting a support row, an edge endpoint, a `last_confirmed_run_id` or a `connector_id` from another workspace is refused **by the database**. One test per FK | The A3 pattern reappearing |
| 10 | **Cross-account navigation, unconnected endpoint** | A `can_assume` into an unconnected account renders as an unresolved external principal naming the account; filtering to production **keeps it visible and labelled** | A filter converting "could not look" into "nothing there" |
| 11 | **Consistent filtering** | The same `rev` + filters give the same object set in list, detail, resources and graph. A region filter does not drop `global` IAM objects | The graph and list disagreeing |
| 12 | **Limits suppress completeness claims** | With any limit bound, the response sets `total_known: false` and **no screen shows a total or a "reaches N resources" claim** | Truncation presented as an answer |

A scenario **counts as passing only once it has been mutation-tested**: break
the fix, confirm the scenario fails, restore it, confirm it passes. Record the
test name, the command, and the observed failure. A test that passes with its
fix removed is worse than no test, because it is believed.

### 6.2 UI acceptance

Three gates, deliberately separate. Passing one says nothing about the others:
an approved design can be built wrong, and a correctly built screen can still
confuse the person using it.

| Gate | Who | Passes when | Recorded |
|---|---|---|---|
| **A. Design approved** | The product owner and the engineer who will build it | Every screen in §2.14 has every state in §2.14.7 drawn or specified; every contract flagged in §2.14.14 has a backend decision and an owner; the fixtures in §2.14.14 exist | Date, commit of this spec, names |
| **B. Behaviour implemented** | Automated, against the §2.14.14 fixtures | Every scenario below passes **and** fails when its safeguard is removed, the same rule as §6.1 | Test name, command, fixture, expected, observed, safeguard removed |
| **C. Usability observed** | Sessions with at least five people who have not seen the product, from the buyer's security or platform team | At least four of five complete each task unaided in under two minutes | Per task: completed or not, time, what they said, where they hesitated |

**B. Behaviour scenarios**

| # | Scenario | Fixture | Passes when | Catches |
|---|---|---|---|---|
| UI1 | **Large inventory** | `large-inventory` | Searching `ticket` finds rows that are not on the first page, and the request carries `q`; paging Next through every page never repeats or skips a row; *"of N found"* appears only when `total_known` is true | Client-side search over the loaded page; an unstable sort |
| UI2 | **Duplicate names across accounts** | `large-inventory` | Two `ticket-tools` rows are distinguishable in the list, in search results, in the breadcrumb and on the canvas; opening one never shows the other's data, even from cache | Name-keyed routing or caching |
| UI3 | **Deep links** | `worked-example`, `retired-object` | Every route, tab, filter set and `evidence` claim, opened cold in a new session, renders the same object, view and filters; a retired object shows its notice; another workspace's id reads *"Not found in this workspace"*; `from=` shows the shared-link notice | State held only in memory; a link that claims a revision |
| UI4 | **Partial scans** | `partial-and-truncated`, `failures` | The coverage banner and *"more available"* both show, each in its own place; a failed request renders an error with Retry, never an empty list; a failed next page keeps the rows already loaded; an undeployed route renders *Unavailable* | A failure rendered as empty; partial and truncated merged |
| UI5 | **Independent grants** | `worked-example`, `grant-detached` | Resources lists two statement lines under `support-tickets/*`; the canvas line reads *"2 statements"*; evidence lists both. After the detach: the line stays solid, the badge reads *"1 current · 1 ended"*, and the change entry names both policies | Merging two grants into one |
| UI6 | **Revision changes mid-investigation** | `worked-example` → `grant-detached` | The banner appears and the data stays; the next page and any expansion show the paused state, not empty; Refresh keeps object, tab, filters and evidence; an evidence claim that ended says so in place; no list ever combines pages from two revisions | Auto-swap; a lost investigation; mixed-revision cache |
| UI7 | **Classification conflicts** | `classification-conflict`, `failures` | Saving is not optimistic; a `409` keeps the input and shows the other decision; *Replace with mine* resubmits against the new version; a `409` for our own lost write is treated as success; after a network failure the object is re-read before retry | Overwriting a colleague's decision; a phantom save |
| UI8 | **Unknown scope** | `unknown-scope` | *All accounts* includes Unknown account; choosing production shows *"N with unknown account not shown"*; a workload whose role is `not_in_scan` keeps its account and stays in the production filter | A default filter hiding unattributed objects |
| UI9 | **Graph controls** | `worked-example`, `cycles` | *View in graph* highlights the target or states the distance and the limit; collapsing one path leaves a node another path still needs; a cycle draws each node once with the marker; expanding does not move any node already on screen (positions asserted); the Paths list contains exactly what the canvas draws | A canvas that silently lacks the target; layout jumps; a text view that knows less |
| UI10 | **Accessibility** | Every fixture | Zero serious or critical violations from an automated checker on every screen in every §2.14.7 state (proposed: axe, not a dependency today); U1–U5's routes completed keyboard-only; state changes announced by the live region; no motion under `prefers-reduced-motion` | An interface only a mouse user can finish |
| UI11 | **Workspace isolation** | Two workspaces | Switching workspace while a list is loading never shows a row from the previous workspace | A shared cache across workspaces |

**C. Usability tasks**

Each is pass/fail on whether the participant can say the answer out loud,
unaided, in under two minutes.

| # | Task | Fails if |
|---|---|---|
| U1 | Find which identity `ticket-tools` runs as | They cannot tell the execution identity from other identity relationships |
| U2 | Say what else uses that identity, and what that implies | The shared-role relationship is not visible from the identity |
| U3 | Explain why the path to `support-tickets/*` exists | They cannot name the policy statements, or they say "it can access it" — the wording failed |
| U4 | Say what we could not see, and what that prevents | Coverage reads as a complaint rather than a bounded conclusion |
| U5 | Explain why removing one grant did not remove the path | The UI merged two independent grants |
| U6 | In an inventory of 5,000, open the `ticket-tools` in **sandbox** | They open the production one, or page instead of searching |
| U7 | A newer scan publishes mid-task: say what changed, then carry on | They lose their place, or believe the old result is current |
| U8 | Say which of production's resources we cannot attribute to an account, and why | Unknown account reads as an error, or they do not find it |
| U9 | Classify a Lambda as an agent, then explain the conflict when a colleague got there first | They overwrite without reading the other decision |

U3 and U5 are the ones that fail most designs. U3 fails when the interface
lets a reader say *"can access"*; U5 fails when the canvas merged two edges
and the evidence panel did not keep them apart.

### 6.3 Phased sequence and gates

| Stage | Delivers | Gate |
|---|---|---|
| **P2-A** Foundation | `027` (workspace-qualified provenance) + P2-1 CI check + P2-3 `sourcekey.go` | `027` applies to a **production schema dump**, not a fresh bootstrap. Key table tests pass |
| **P2-B** Objects | `028`–`029`, real upserts, support rows | Scenarios 1, 3, 7, 8, 9 |
| **P2-C** Edges and evidence | `030`–`032`, projector, evidence | Scenarios 2, 11 |
| **P2-D** Lifecycle | Reconciliation, barrier, job | Scenarios 4, 5, 6 |
| **P2-E** External | The **resolution pass** that populates `iga_external_principal`. The table itself ships with the core rollout (see below) | Scenario 10 |
| **P2-F** One read path | P2-11: Identities + Resources for one workload, pinned `rev` via `iga_publication`, with evidence | Scenario 12; §6.2 gate A for these views; UI1–UI6, UI8, UI10, UI11; tasks U1–U8 |
| **P2-G** Classification | `classification` + `iga_workload_classification` (029), the Classify-as-agent action on Overview | A classified Lambda appears as *Classified as agent* with its decision record; undo records its own decision; recreation starts `unclassified`; UI7; task U9 |
| **Graph canvas** | The one new UI component (§2.14.14) | Built **last**. The list views answer every §2.14.11 question except the visual one. UI9, and UI5/UI10 re-run on the canvas |
| **Not scheduled** | Bedrock alias collection (`ListAgentAliases`) | Required before any instance count is shown. Until then the UI says *"instances not collected"* |
| **Deferred** | `035` retirement of legacy unkeyed rows | After one clean production scan on the new path. **Not in the initial rollout** |

#### Supported deployment states

Migrations run on boot, so a rollout split across releases passes through
intermediate schemas in production. Only these are supported, and each is a
state P2-0 must deploy into and check:

| State | Schema | Projector | Must hold |
|---|---|---|---|
| **S0** | `001`–`026` (today, once `026` ships) | not present | Phase 1 scanning unchanged; governance routes work |
| **S1** | `001`–`034` | **disabled** | Phase 1 scanning still works against the migrated schema; nothing writes `iga_*` graph tables |
| **S2** | `001`–`034` | enabled | The P2-0 slice end to end |
| **S3** | `001`–`035` | enabled | After one clean S2 production scan |

**`027`–`034` ship in one release.** Any other split is unsupported, because
core code references tables across that whole range.

As a backstop against a partial rollout anyway, **the projector refuses to
start below schema head `034`**: `ProjectionService.Run` reads the migration
head and, if it is lower, logs and exits without claiming a job. A partial
schema therefore degrades to *"graph not projecting"* — visible, and fixed by
finishing the rollout — rather than to a reconciler that fails on every run.

### 6.4 What has actually been demonstrated

Five mutations were run against real PostgreSQL 16 on **`origin/graph` at
`5bc5809`** — a separate implementation branch, not `authsec-staging`. Each
was introduced, the named test observed to fail, and the fix restored:

| Mutation | Test | Observed |
|---|---|---|
| `canEnd` returns `true` unconditionally | `TestDeniedScanEndsNothing` | FAIL |
| `retireUnsupported` retires when *any* support ends | `TestSharedResourceSurvivesOneAccountDroppingIt` | FAIL |
| `scope()` drops `connector_id` | `TestScanOfOneAccountClosesNothingInAnother` | FAIL |
| `attachEvidence` made a no-op | `TestEvidenceIsAttachedThroughLoad` | FAIL |
| Unqualified observations no longer skipped | `TestUnqualifiedObservationAttachesNoEvidence` | FAIL |

Command, for each: `TEST_DATABASE_URL=postgres://… go test ./tests/igagraph/... -run '<Test>'`.

**Against this document's own SQL** (run 2026-09-23, PostgreSQL 16, on top of
the shipped `001`–`025`): every `027`–`034` section's SQL was extracted and
applied in order, **all eight apply**, and ten constraint probes were run with
a seed that includes one insert that *must succeed* — so a rejection cannot
pass merely because the seed was broken:

| Probe | Expected | Rejected by |
|---|---|---|
| Support row, one typed column, own workspace | **accepted** | — |
| Support with two typed columns | rejected | `iga_object_support_one_chk` |
| Support with none | rejected | `iga_object_support_one_chk` |
| Support in A → identity in B | rejected | `iga_os_identity_fkey` |
| Support in A using B's connector | rejected | `iga_object_support_connector_fkey` |
| Support → nonexistent identity | rejected | `iga_os_identity_fkey` |
| Duplicate live support | rejected | `uq_iga_os_identity` |
| External principal in A resolving to B's identity | rejected | `iga_ep_resolved_identity_fkey` |
| Resolution `asserted` with no `resolved_by` | rejected | `iga_external_principal_asserted_chk` |
| `executes_as` whose source is an identity | rejected | `iga_relationship_pair_chk` |
| Unknown classification value | rejected | `iga_workload_classification_chk` |

`retireUnsupported`'s statement was also **executed** against all five node
tables. This is what caught that `028` altered only one of its five tables —
it applied cleanly and left four without `source_key`. A reading review and a
static forward-reference check both missed it.

**State-transition probes** (same environment, each with a control row that
must *not* change, so a pass cannot be vacuous):

| Probe | Observed |
|---|---|
| Publish run R once | accepted |
| Publish run R again | rejected, `iga_publication_run_key` |
| The replay check (`publication for run R?`) | finds `rev 1` — the fact §4.6 step 2 relies on exists |
| Retire an identity whose only support ended; its sibling stays supported | ended one `retired`, control `active` |
| …an `asserted` resolution to the retired identity | `suspended`, still pointing at the retired row |
| …a `derived` resolution to it | re-derived to unresolved in the same transaction |
| …an `asserted` resolution to the control | unchanged, `active` |
| Restore with the **same** `UniqueID` | 1 row |
| Restore with a **different** `UniqueID` (recreation) | 0 rows |
| Restore a row retired as `recreated` | 0 rows |

The derived-resolution row was a real defect found by this probe: the
resolution pass runs during projection, *before* reconciliation retires
anything, so without the re-derive in `retireUnsupported` a derived resolution
stayed in force for a full scan cycle pointing at a retired row.

These exercise the SQL of each transition in isolation. **They do not exercise
the Go control flow** — the projector's branch selection, the service loop's
`AlreadyPublished` handling, or crash timing — which exist only as pseudocode
here and are what P2-0 has to prove.

**The graph branch results above do not validate this document.** That branch
implements the earlier design: polymorphic `iga_object_support`, recovery that
returns an expired lease to `idle`, no restoration of retired objects, no
workload classification, no publication revision. The five results show that
branch's tests are genuine; they say nothing about scenarios 5, 6 or 8, which
test behaviour the branch does not have.

## 7. Known-failing tests, carried in

Seven `TestIGA*` GitHub-path tests fail today with `source_objects=0,
observations=0`. A Phase 1 carry-over, not caused by this work.

**P2-4 touches the code they exercise.** Re-run and record the count before
starting it, so a Phase 2 regression is distinguishable from the existing
failure. If P2-4 fixes them incidentally — plausible, since GitHub's ingestion
is what changes — say so rather than leaving the ratchet stale.

CI ratchets that must not rise: **198** TypeScript errors, **17** ESLint errors.
Count TS errors with `grep -c`, not `wc -l`; ESLint with `-f json` summing
`errorCount`, because the human formatter reports zero regardless. A parse error
reports as 1 and masks everything behind it.

## 8. Verification

**Execute the spec, not just read it.** Extract each migration section's SQL
and apply it on top of the shipped migrations. Apply each file as **one
transaction** — `006` depends on it (`CREATE TEMP TABLE … ON COMMIT DROP`):

```bash
for f in $(ls migrations/master/0*.sql | sort); do
  psql "$DB" -v ON_ERROR_STOP=1 --single-transaction -q -f "$f"
done
# then each spec section 027..034 the same way; 035 is deferred
```

Then check the resulting schema has **every column the pseudocode uses**, not
only that the SQL applied. A migration that applies and is incomplete is the
failure mode this catches.

```bash
# Migrations apply in order against a PRODUCTION schema dump, not a fresh bootstrap.
pg_dump --schema-only "$PROD_URL" > /tmp/prod-schema.sql   # no rows
createdb iga_rehearsal && psql iga_rehearsal < /tmp/prod-schema.sql
# 035 is deferred (§6.3) and is NOT part of the initial rollout.
for m in migrations/master/0{27,28,29,30,31,32,33,34}_*.sql; do
  psql iga_rehearsal -v ON_ERROR_STOP=1 -f "$m" || { echo "FAILED: $m"; break; }
done

# Confirm the FK constraint names 027 drops actually exist first.
psql iga_rehearsal -c "\d cloud_observation" | grep "Foreign-key"

# A relationship with no target is rejected.
psql iga_rehearsal -c "INSERT INTO iga_relationship
  (workspace_id, relationship_type, source_workload_id, source_key)
  VALUES (gen_random_uuid(), 'executes_as', gen_random_uuid(), 'k');"
# expected: ERROR ... iga_relationship_target_chk

# An illegal pair is rejected.
psql iga_rehearsal -c "INSERT INTO iga_relationship
  (workspace_id, relationship_type, source_identity_account_id,
   target_workload_id, source_key)
  VALUES (gen_random_uuid(), 'executes_as', gen_random_uuid(), gen_random_uuid(), 'k');"
# expected: ERROR ... iga_relationship_pair_chk

# The polymorphic pair is gone.
psql iga_rehearsal -c "\d iga_access_edges" | grep -E "subject_kind|subject_id\b"
# expected: no output

# The honesty constraint from 004 survived.
psql iga_rehearsal -c "\d iga_access_edges" | grep honesty_chk
# expected: one line

go build ./... && go vet ./...
bash scripts/ci-iga-isolation-check.sh
go test ./... 2>&1 | tee /tmp/p2.txt; grep -c "^--- FAIL" /tmp/p2.txt
```

Every acceptance item needs a named test. **An item verified only by reading the
code is not verified** — and a test that passes for the wrong reason is worse
than none. Check each by removing the fix and confirming the test fails.
