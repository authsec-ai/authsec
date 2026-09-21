# SPEC: Phase 2 — objects and the identity graph

> The phase after [SPEC-iga-phase1-collect.md](SPEC-iga-phase1-collect.md).
> Product context is
> [SPEC-agentic-access-management.md](SPEC-agentic-access-management.md); the
> invariants this phase must honour are [SPEC-iga-roadmap.md](SPEC-iga-roadmap.md) §3.
>
> **Verified 2026-09-21** against backend `efb67b2`, migrations `001`–`025`.
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
  screens so they are not invented twice; P2-11 builds only the first read
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
gate was unclear. Migration `024` (`b47adeb`, merged) closed **all four**, two of
them by better mechanisms than this document originally proposed.

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
`cloud_scan_run`. Migration `026` closes it. This is the only Phase 1-adjacent
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
unique constraint today; `024` adds it. This applies to `last_confirmed_by`,
`iga_projection_state.last_run_id`, `iga_projection_job.scan_run_id` and every
evidence junction.

`cloud_observation.scan_run_id` (`022:42`) is itself a single-column FK to
`cloud_scan_run(id)` — the same gap, in Phase 1 code. `024` qualifies it.

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

```sql
-- 026
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

Every transition is one conditional `UPDATE`, atomic and recoverable:

| Transition | Guard | Effect |
|---|---|---|
| scan claim | `state='idle'` **or** expired | `collecting`, `version+1` |
| publish | `state='collecting' AND version=?` | `projecting`, in the publish transaction |
| projection done | `state='projecting' AND version=?` | `idle` |
| recovery | `expires_at < now()` | any state → `idle`, `version+1` |

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

```sql
-- 031
CREATE TABLE IF NOT EXISTS public.iga_object_support (
    id            uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id  uuid NOT NULL,
    object_type   text NOT NULL,  -- identity|workload|resource|entitlement|agent
    object_id     uuid NOT NULL,
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
    CONSTRAINT iga_object_support_state_chk CHECK (state IN ('current','stale','ended')),
    CONSTRAINT iga_object_support_ended_chk CHECK ((state = 'ended') = (ended_reason <> '')),
    CONSTRAINT iga_object_support_key
        UNIQUE (workspace_id, object_type, object_id, connector_id, partition_key)
);
```

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
  accounts      NEW 026               ▲             │
   │  source_key ✦  source_key ✦      │   source_key ✦
   │                                  │
   │              iga_entitlements ───┘  source_key ✦ (§2.6)
   │                     ▲
   │                     │ NOT NULL
   └──────┬──────────────┘
          ▼
   iga_access_edges          iga_relationship  NEW 028
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
      (026)                 projecting -> idle, fenced by `version`. A durable
                            row, not a session lock, because publication and
                            projection are different transactions.

    iga_object_support      one row per (object, connector, partition).
      (031)                 Reconciliation ends SUPPORT; a node retires only
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

```sql
-- 034
CREATE TABLE IF NOT EXISTS public.iga_external_principal (
    id            uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id  uuid NOT NULL,
    issuer        text NOT NULL,   -- token.actions.githubusercontent.com
    subject_claim text NOT NULL,   -- repo:org/repo:ref:refs/heads/main
    mechanism     text NOT NULL,   -- oidc | saml | aws_account | service_principal
    source_key    text NOT NULL,

    -- Filled when the far provider connects AND the claim resolves to exactly
    -- one object. Nullable forever otherwise, which is an honest state.
    resolved_object_type text NOT NULL DEFAULT '',
    resolved_object_id   uuid,
    resolution_basis     text NOT NULL DEFAULT '',   -- derived | asserted
    resolution_rule      text NOT NULL DEFAULT '',

    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_external_principal_pkey PRIMARY KEY (id),
    CONSTRAINT iga_external_principal_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT iga_external_principal_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT iga_external_principal_resolution_chk CHECK (
        (resolved_object_id IS NULL) = (resolution_basis = '')),
    CONSTRAINT iga_external_principal_derived_chk CHECK (
        resolution_basis <> 'derived' OR resolution_rule <> '')
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_external_principal_key
    ON public.iga_external_principal (workspace_id, source_key);
```

`iga_relationship` gains `source_external_principal_id` as a fourth typed
source, with the legal-pair CHECK widened so `can_assume` accepts it.

> **Why a node and not a string.** When the far provider connects later,
> resolution **upgrades the existing node** and the edge keeps its identity
> and its whole history. A string endpoint would force delete-and-recreate,
> destroying "this access has existed since March" — which is precisely the
> fact a reviewer needs and the one hardest to recover.

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
| Unbounded transitive traversal | **Capped at two hops** from any start. Depth three yields paths nobody can verify, and each hop multiplies the chance one link is `stale` |
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

### 2.14 The console — screens, states, and what is deliberately not a screen

Phases 4 and 5 build this. It is specified here because P2-11 builds the first
read path, and the shape must not be invented twice.

#### The jobs, in order

A customer does four things, and each is a screen. Anything that is not one of
these four is a candidate for cutting.

1. **Connect an estate and find out what we can actually see.**
2. **Look up a thing** — an identity, a workload, a resource.
3. **Answer a reach question** — what can this reach, who can reach this.
4. **Challenge an answer** — why do you believe this, and when did you last check?

Job 3 is the graph's entire purpose and is the screen that does not exist
today. Job 4 is what separates this from a dashboard.

---

#### A · Accounts and coverage

The first screen, and the one that makes every number on every other screen
trustworthy. Per connected account: what was read, what was refused and why,
and when it was last confirmed.

```
  ┌─ Accounts ──────────────────────────────────────────────────────┐
  │                                                                  │
  │  220171243705 · production                          [complete]   │
  │  14 surfaces read · last scan 22 min ago                         │
  │                                                                  │
  │  905418271234 · sandbox                             [partial]    │
  │  iam_users denied — role lacks iam:ListUsers                     │
  │  11 of 14 surfaces read                                          │
  │                                                                  │
  │  551209887761 · data-eu                             [stale]      │
  │  Last confirmed 6 days ago. Nothing deleted — we could not look. │
  └──────────────────────────────────────────────────────────────────┘
```

**Never a percentage.** "78% covered" averages a denied IAM read with an
unselected region, and those have different owners and different fixes. The
per-surface state is the answer, and the account rolls up to
`complete | partial | stale` only.

Each refused surface states **the permission that would fix it**. A coverage
gap the customer cannot act on is a complaint, not a finding.

---

#### B · Inventory — three provider-neutral tabs

Identities · Compute · Resources. Built. A second provider filters into these
tabs rather than adding `GCP Identities` beside `AWS Identities` — the tab set
is about *what kind of thing*, never *which vendor*.

```
  Identities | Compute | Resources          [All accounts ▾] 3 connected

  ┌──────────────────────────────────────────────────────────────────┐
  │ arn:aws:iam::1234:role/refund-lambda-role            [current]   │
  │ production · immutable · first seen 12 Mar                       │
  ├──────────────────────────────────────────────────────────────────┤
  │ arn:aws:iam::9054:role/deploy                        [current]   │
  │ sandbox · immutable · distinct from production/deploy            │
  └──────────────────────────────────────────────────────────────────┘
```

Two rules the list must honour:

- **Show the account on every row whenever more than one is connected.** Two
  roles named `deploy` are different objects (§2.12) and a list that hides
  which account they came from makes them look like a duplicate bug.
- **Say `immutable` or `recognition_only`.** For a Lambda, "same name" is the
  strongest claim available, and the console should say so rather than
  implying we verified continuity we cannot verify.

---

#### C · Access paths — the missing screen

Pick a start, pick a direction, read paths as rows. This is job 3.

```
  ○ What can this reach?   ● Who can reach this?
  Start: refund-processor (lambda · eu-central-1)

  ┌──────────────────────────────────────────────────────────────────┐
  │ refund-processor ─executes_as→ refund-lambda-role                │
  │        ─granted→ s3:GetObject ─names→ refunds-bucket/*           │
  │                                                                   │
  │ current · declared · confirmed 22 min ago · 4 observations       │
  ├──────────────────────────────────────────────────────────────────┤
  │ refund-lambda-role ─can_assume→ arn:aws:iam::9054:role/          │
  │                                 data-reader                       │
  │                                                                   │
  │ ⚠ CROSSES ACCOUNTS · stale 6 days                                │
  │ sandbox not read since 15 Sep — this is not a removal            │
  └──────────────────────────────────────────────────────────────────┘
```

That second row is most of the product's value in one line. One account's
console shows one account's roles; nothing today shows that production's
Lambda can assume sandbox's reader. **It is also why account is a filter and
never a mode** — a mode makes the cross-account path unrepresentable, because
the path has no single account to live in.

Every row carries four things, and a row missing any of them is not shippable:

| | Why it is on the row and not behind a click |
|---|---|
| `basis` | `declared` vs `observed` is the difference between "a policy says so" and "we saw it happen". Hiding it invites the reader to assume the stronger one |
| `state` | `stale` must be visually distinct from `current`, or an outage reads as a clean result |
| last confirmed | The honest age of the claim |
| evidence count | A link into screen D. Zero is a defect, not a display state (§4.8) |

**Two hops, and the cap is visible.** When a path is truncated the row says so
— "2 of 2 hops shown; this identity can assume 3 more roles" — rather than
silently ending. An invisible limit is indistinguishable from an absence.

---

#### D · Evidence drawer

Opens from any path row or object. Job 4: *why do you believe this?*

```
  ┌─ Evidence · refund-lambda-role → s3:GetObject ──────────────────┐
  │ iam:GetRole · 22 min ago                          [supports]    │
  │ surface iam_roles · coverage reached at collection              │
  │ confirmed by 14 runs                                             │
  ├──────────────────────────────────────────────────────────────────┤
  │ lambda:ListFunctions · 22 min ago                 [supports]    │
  │ surface lambda:eu-central-1 · coverage reached                  │
  ├──────────────────────────────────────────────────────────────────┤
  │ iam:GetRole · 4 Aug                            [unattributed]   │
  │ Subject no longer in inventory. Cannot be tied to one grant.    │
  └──────────────────────────────────────────────────────────────────┘
```

Each row shows the API call, the surface, **the coverage that surface had at
collection time**, and the redacted response. A fact collected during a
degraded scan must still read as such a year later — that is what
`cloud_observation.surface_state` is for.

The third row is the rule from §4.8 made visible: pre-P2-2 observations cannot
be tied to one grant without guessing, so they appear as history and are never
counted toward the evidence gate.

---

#### The account filter, precisely

- **Multi-select, defaults to all.** The default view is the whole estate,
  because cross-account reach is the thing being bought.
- **Filtering also filters the coverage banner.** Otherwise a partial read in
  a hidden account silently licenses a clean-looking list — the exact failure
  the coverage model exists to prevent.
- **Compute ignores the filter, deliberately.** Already true in
  `cloudInventoryNav.ts`: workloads nobody can attribute must not hide behind
  an account filter.
- **A path that crosses the filter is shown, marked.** Filtering to
  production and hiding a path into sandbox would answer the customer's
  question wrongly.

#### Not a screen

| Not built | Instead |
|---|---|
| A node-link graph canvas | Path rows (C). The diagram earns its place only for one expanded path of 4–6 nodes: legible, printable, pasteable into a ticket |
| A risk score or posture dial | Nothing. It needs effective access to mean anything (§2.13) |
| A "Priya" unified person view | Correlation candidates with evidence, on their own review surface, affecting nothing until confirmed (§2.12) |
| A remediation button | Phase 6 at the earliest, behind a separate credential and separate consent. The discovery role can never write |

---

## 3. Schema

Nine migrations, `026`–`034`, in `authsec/migrations/master/`. **`024` and
`025` have shipped** — `024_scan_evidence_durability.sql` closed D1–D4 and
`025_observation_subjectless_dedupe.sql` followed it; §1.2 says what they did
and how the shipped shape differs from what this document first proposed.

> **Rehearse against a production schema dump before merging.** Migration `023`
> exists only because that rehearsal caught seven columns added to
> `001_bootstrap.sql` with no numbered migration: new installs had them,
> production never would, and pods would have come up healthy and failed at
> first customer use. Dump the schema (no rows), restore locally, apply
> `026`–`033`, run the suite between each. **A green run on a fresh bootstrap
> proves nothing about production.**

### 026 — close the cross-workspace provenance gap

```sql
-- Every composite FK below needs this target, and it does not exist:
-- 010 gives cloud_connector only a primary key on id and
-- uq_cloud_connector_scope. Without it, every
-- REFERENCES cloud_connector (workspace_id, id) in 029-032 fails to apply.
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
in the composite form, and `026` exists because three were written before the
rule was.

### 027 — recognition keys and continuity

For each of `iga_identity_accounts`, `iga_resources`, `iga_entitlements`,
`iga_agents`, `iga_credentials`:

```sql
ALTER TABLE public.iga_identity_accounts
    ADD COLUMN IF NOT EXISTS source_key     text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS continuity     text NOT NULL DEFAULT 'recognition_only',
    ADD COLUMN IF NOT EXISTS immutable_key  text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS first_seen_at  timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_seen_at   timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS retired_reason text NOT NULL DEFAULT '';

ALTER TABLE public.iga_identity_accounts
    ADD CONSTRAINT iga_identity_accounts_continuity_chk CHECK (
        continuity IN ('immutable', 'recognition_only')),
    ADD CONSTRAINT iga_identity_accounts_immutable_chk CHECK (
        continuity <> 'immutable' OR immutable_key <> '');

CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_identity_accounts_source_key
    ON public.iga_identity_accounts (workspace_id, source_key)
    WHERE source_key <> '' AND lifecycle <> 'retired';
```

**`iga_entitlements` has no `lifecycle` column.** Checked: `004:667` is
`id, workspace_id, resource_id, native_grant_kind, native_rights,
normalized_rights, native_scope, remediable, created_at, updated_at`. The index
predicate above therefore fails with `column "lifecycle" does not exist`. Add
it, matching the other three tables rather than special-casing the index:

```sql
ALTER TABLE public.iga_entitlements
    ADD COLUMN IF NOT EXISTS lifecycle text NOT NULL DEFAULT 'active',
    ADD CONSTRAINT iga_entitlements_lifecycle_chk CHECK (
        lifecycle IN ('active','retired','tombstoned'));
```

Three notes, each a decision:

- **`DEFAULT ''` plus a partial unique index.** Existing production rows have no
  recognition key and cannot be given one — they were minted by `uuid.New()`
  from GitHub scans and nothing records their origin. A total unique index would
  collapse them into one row. The partial index lets legacy rows coexist while
  constraining every new one. `033` retires them.
- **`lifecycle <> 'retired'` in the predicate** is what makes
  delete-and-recreate expressible: the retired row keeps its `source_key`, the
  new row takes the same key, only one is live.
- **`iga_credentials` is included** because P2-4 gives all five upsert methods a
  conflict target, and `UpsertCredential` is one of them. Its key is the
  credential's own id namespaced by its identity's `source_key`.

Put the Phase 3 warning from §2.6 in `iga_entitlements`' migration comment.

### 028 — `iga_workload`

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

### 029 — `iga_access_edges`: typed subject, required entitlement, lifecycle

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
    ADD COLUMN IF NOT EXISTS source_key        text NOT NULL DEFAULT '';

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
    -- §2.9: workspace-qualified, against the UNIQUE added in 024.
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
- `DROP COLUMN subject_kind` removes a column the Go model still has: `029` and
  the `models/iga.go` change land in the same commit.

### 030 — `iga_relationship`

```sql
CREATE TABLE IF NOT EXISTS public.iga_relationship (
    id                uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id      uuid NOT NULL,
    relationship_type text NOT NULL,

    source_identity_account_id uuid,
    source_workload_id         uuid,
    source_agent_instance_id   uuid,
    -- A trust policy names a principal from another provider, which may never
    -- resolve to an object we hold (§2.12). Typed and FK'd like every other
    -- endpoint -- an unresolved far end is still a real endpoint, not a string.
    source_external_principal_id uuid,

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
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT iga_relationship_pkey PRIMARY KEY (id),
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
    CONSTRAINT iga_rel_src_external_fkey
        FOREIGN KEY (workspace_id, source_external_principal_id)
        REFERENCES public.iga_external_principal (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT iga_relationship_source_chk CHECK (
        (source_identity_account_id   IS NOT NULL)::int
      + (source_workload_id           IS NOT NULL)::int
      + (source_agent_instance_id     IS NOT NULL)::int
      + (source_external_principal_id IS NOT NULL)::int = 1),
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
                -- Either one of our identities, or an external principal a
                -- trust policy names. Both are legitimate assumption sources.
                (source_identity_account_id IS NOT NULL
                 OR source_external_principal_id IS NOT NULL)
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

### 031 — evidence junctions

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

`iga_relationship_evidence` is the same table against
`iga_relationship (workspace_id, id)`. Both endpoints typed and FK'd.
`iga_observation_links` keeps its polymorphic `target_kind`/`target_id` for the
GitHub path; P2-1's CI check forbids new writers to it.

### 032 — projection job, projection state, agent origin

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
    -- is the §2.9 defect this phase exists to close. 026 adds the
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

### 033 — external principals

The table in §2.12, plus `iga_relationship.source_external_principal_id`, its
composite FK and the widened `can_assume` arm of the legal-pair CHECK.

Last in the sequence deliberately: the graph is correct without it — a trust
policy naming an unconnected provider simply produces no edge — and shipping
it after the core path is proven keeps P2-0's slice narrow.

### 034 — retire the legacy unkeyed rows (deferred)

`027`'s partial indexes let `source_key = ''` rows coexist. That is a transition
allowance. Once P2-4 and P2-6 own the write path and **one clean production scan
has run on the new path**, mark the remaining unkeyed rows
`lifecycle = 'retired'`, `retired_reason = 'pre_graph'`, and tighten the CHECK
to require a non-empty `source_key` on active rows. Ship as a separate PR, after 033. Never
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
// Continuity() and ImmutableKey() must agree: 027's CHECK rejects a row
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
    // 'immutable', and 027's CHECK then rejects every IAM identity.
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
> `immutable` while `ImmutableKey()` returns `""` makes 027's CHECK reject the
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

// One query per type, WHERE lifecycle <> 'retired' -- matching the partial
// unique indexes, so what is loaded is exactly what a conflict could hit.
func loadExisting(ctx context.Context, db *gorm.DB, ws uuid.UUID) (*existing, error) { … }
```

§4.6's node passes then read `r.existing.identity[key]` — a map lookup, no
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

        // ORDERED PUBLICATION, separate from job ownership.
        //
        // AssertOwnedTx protects this job's row. It does NOT order two
        // DIFFERENT jobs: generation 7 and generation 8 hold different job
        // rows, both legitimately own their leases, and nothing stops 7 from
        // committing after 8 and overwriting the newer graph with an older
        // one.
        //
        // Take a per-connector advisory lock so only one projection publishes
        // at a time, then refuse to write if this generation is not ahead of
        // what the partitions already hold. Both inside the transaction, both
        // before any graph mutation.
        // The workspace barrier (§2.10A) already excludes concurrent
        // collection; this asserts THIS job still holds the projecting
        // state, so a reclaimed pipeline cannot have its old job commit.
        if err := p.pipeline.AssertProjectingTx(tx,
            snap.Run.WorkspaceID, p.pipelineVersion); err != nil {
            return err
        }
        for _, part := range Partitions(snap) {
            have, err := p.reconciler.lastGenerationFor(tx, part, snap.Run.WorkspaceID)
            if err != nil {
                return err
            }
            if int64(snap.Generation) <= have {
                // Not an error the operator must act on: the newer job
                // already did this work. Recorded and skipped.
                return ErrObsoleteGeneration
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
        return p.recordState(tx, snap, false)
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

        // Map lookup, not a query. The workspace's live objects were loaded
        // once before the transaction (§4.5); a SELECT per identity here is
        // one round trip per row, inside a transaction holding locks.
        existing := r.existing.identity[key]

        // DELETE-AND-RECREATE. Same recognition key, different creation
        // boundary => a different principal wearing the old name. Carrying
        // the old row forward would carry last quarter's review decisions
        // onto a stranger.
        //
        // Both immutable keys must be non-empty: one empty side means we
        // could not tell, and "could not tell" is never "recreated".
        if existing != nil && cont == models.ContinuityImmutable &&
            imm != "" && existing.ImmutableKey != "" && existing.ImmutableKey != imm {

            if err := p.repo.RetireIdentity(tx, existing.ID, "recreated", now); err != nil {
                return err
            }
            if err := p.repo.EndEdgesOnSubject(tx, snap.Run.WorkspaceID,
                existing.ID, "subject_recreated", now, snap.Run.ID); err != nil {
                return err
            }
            existing = nil // fall through to INSERT, with a fresh first_seen_at
        }

        row := &models.IGAIdentityAccount{
            WorkspaceID: snap.Run.WorkspaceID,
            SourceKey:   key,
            Continuity:  cont,
            ImmutableKey: imm,
            DisplayName: ci.Name,
            AccountKind: ci.Kind,
            IdentityBacking: "provider_native",
            LastSeenAt:  now,
        }
        if existing == nil {
            row.FirstSeenAt = now
        }

        id, err := p.repo.UpsertIdentity(tx, row)
        if err != nil {
            return fmt.Errorf("upsert identity %s: %w", key, err)
        }
        r.identity[ci.ID] = id
    }
    return nil
}
```

Edges, where `resolved` pays for itself:

```go
func (p *Projector) projectRelationships(tx *gorm.DB, snap *Snapshot, r *resolved) error {
    now := p.now()

    // workload --executes_as--> identity
    for _, w := range snap.Workloads {
        if w.IdentityID == nil {
            continue // no configured execution identity; not an edge we can claim
        }
        src, ok := r.workload[w.ID]
        if !ok { continue }
        dst, ok := r.identity[*w.IdentityID]
        if !ok {
            // The identity was not in this run's snapshot -- a partial scan.
            // Skipping is right: an edge whose endpoint we did not read this
            // run must not be written as `current`.
            continue
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
            PartitionKey:            partitionFor(snap, "executes_as", w.RuntimeKind, w.Region).Key(),
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

`projectWorkloads` and `projectResources` are the same shape as
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
        }, p.existing.resource[key] == nil /* isNew */)
        if err != nil {
            return fmt.Errorf("upsert resource %s: %w", key, err)
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
        }, p.existing.entitlement[key] == nil)
        if err != nil {
            return fmt.Errorf("upsert entitlement %s: %w", key, err)
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
            PartitionKey:             accessEdgePartition(snap).Key(),
            SubjectIdentityAccountID: &subj,
            EntitlementID:            ent,          // NOT NULL since 029
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
// unique key on iga_projection_state (032) and the value lastGenerationFor
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
`ScopeID` already hold `("aws_account", "220171243705")`. One upsert per run,
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
        for _, svc := range []string{"lambda", "ecs", "ec2"} {
            ps = append(ps,
                Partition{ScopeID: sc, ConnectorID: cn, Class: "workload",
                    RequiredSurfaces: []string{svc + ":" + region},
                    RequiredScanners: computeGate},
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
            "ended_reason": reason, // never empty: 030's CHECK enforces it
        }).Error
}
```

#### Partition membership is stored, not inferred

`scope()` cannot be a join through endpoint tables. Three reasons, each of
which was a defect in an earlier draft of this section:

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

```sql
-- EDGES ONLY: 029 (iga_access_edges) and 030 (iga_relationship).
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
// Step 1 -- end this partition's SUPPORT, not the object.
func (rc *Reconciler) reconcileNodes(tx *gorm.DB, part Partition, snap *Snapshot, stale bool) error {
    q := tx.Model(&models.IGAObjectSupport{}).
        Where("workspace_id = ? AND object_type = ? AND connector_id = ? AND partition_key = ?",
            snap.Run.WorkspaceID, part.Class, part.ConnectorID, part.Key()).
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
    return tx.Exec(`
        UPDATE iga_identity_accounts n
           SET lifecycle = 'retired', retired_reason = 'unsupported', updated_at = now()
         WHERE n.workspace_id = ?
           AND n.lifecycle = 'active'
           AND EXISTS (SELECT 1 FROM iga_object_support s
                        WHERE s.workspace_id = n.workspace_id
                          AND s.object_type = 'identity' AND s.object_id = n.id)
           AND NOT EXISTS (SELECT 1 FROM iga_object_support s
                            WHERE s.workspace_id = n.workspace_id
                              AND s.object_type = 'identity' AND s.object_id = n.id
                              AND s.state <> 'ended')`, snap.Run.WorkspaceID).Error
    // ...repeated per node table. The first EXISTS matters: an object with no
    // support rows at all is pre-graph, not unsupported, and must not be
    // retired by this pass -- 033 handles those deliberately.
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
   `(workspace_id, object_type, object_id, connector_id, partition_key)`,
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
    // Keyed exactly as 032 keys the table, and exactly as scope() filters
    // rows -- one value, three call sites, no predicate to keep in agreement.
    err := tx.Where("workspace_id = ? AND connector_id = ? AND partition_key = ?",
        ws, part.ConnectorID, part.Key()).First(&st).Error
    if errors.Is(err, gorm.ErrRecordNotFound) {
        return 0, nil
    }
    return st.LastGeneration, err
}
```

`iga_projection_state`'s unique key (032) must include the partition's surface
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
        return true, s.jobs.Abandon(job, s.owner, job.LeaseVersion, "superseded during load")
    }
    if err != nil {
        return true, s.jobs.Fail(job, s.owner, job.LeaseVersion, err.Error())
    }

    // Project AND reconcile in ONE transaction. Committing projection first
    // publishes a graph in which nothing has been closed yet -- every stale
    // edge still reads `current` -- and a crash in between leaves it that way
    // until the next run. One transaction means readers see the before state
    // or the after state, never the gap.
    if err := s.projectAndReconcile(ctx, snap, job); err != nil {
        // Fail, do not Complete. The lease expires, the job is reclaimed, and
        // projection is idempotent -- so a retry converges. A job marked
        // complete after a partial write is unrecoverable without a manual
        // rebuild.
        return true, s.jobs.Fail(job, s.owner, job.LeaseVersion, err.Error())
    }
    return true, s.jobs.Complete(job, s.owner, job.LeaseVersion)
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
entitlement → resource reference**, with evidence and reconciliation. Nothing
else — no agents, no assume edges, no credentials.

Six scenarios it must survive before the graph widens. Each maps to a defect
this document has already had to correct, which is why they are the gate and
not a later hardening pass:

| Scenario | What it catches |
|---|---|
| Unchanged rescan | ids and `first_seen_at` stable; no duplicate rows |
| Lambda switches `RoleA` → `RoleB` | the relationship key names both endpoints, so the old edge ends instead of being overwritten |
| A policy that fails to parse | `policy_documents` appears as `partial`, and **nothing closes** in the entitlement or access-edge partitions |
| One region denied, another clean | `compute:eu-central-1` stale while `compute:us-east-1` closes — per-region partitions really are independent |
| Two AWS accounts in one workspace | a scan of A closes nothing in B |
| An obsolete worker | a reclaimed job cannot commit; the graph is unchanged and the job reads `abandoned` |
| **Two accounts naming the same bucket** | B's scan reassigns `cloud_resource.connector_id`; A's projection must not silently lose the resource or the edges needing it |
| **A superseded scan worker that keeps running** | its writes stop at lease loss; its replacement's projection sees a stable input set |
| **Crash between publication and coverage** | impossible — one transaction. Kill the worker mid-publish and the run is either fully published with coverage and a queued job, or not published at all |

> **Gate:** all six, against real Postgres, with each verified non-vacuous by
> removing the fix and confirming the test fails.

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

Migration `026` alone: the two `UNIQUE (workspace_id, id)` targets and the three
single-column references converted to composite form (§3, `026`).

`024` already closed D1–D4. **Verify them, do not redo them** (§1.2), and in
particular leave `models.ScanCoverage.Complete()` alone — the parse-failure gate
lives upstream in `cloud_aws_permission_scan.go:226`, which turns the surface
`partial` before `Complete()` runs. Adding a counter check inside `Complete()`
duplicates a gate that already holds, and the duplicate is the copy that drifts.

Then wire the projection job enqueue: `repository/cloud_scan_run_repository.go`
`Publish()` also enqueues `iga_projection_job` in the same transaction. That is a
forward reference — land `026` now and wire the enqueue when `032` exists.

> **Gate:** a `cloud_observation` row whose `scan_run_id` belongs to another
> workspace is rejected by the database, proven by a test that fails without
> `026`. Then re-assert what `024` delivers, so a later change cannot quietly
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
`source_key` `027` adds.

Test against **real Postgres**. SQLite accepts the wrong thing silently.

> **Gate:** run the same GitHub scan twice against real Postgres. Row counts in
> `iga_identity_accounts`, `iga_resources`, `iga_entitlements`,
> `iga_credentials` and `iga_access_edges` are identical after the second run,
> every `id` is unchanged, every `first_seen_at` is unchanged, `last_seen_at`
> advanced. This is the exit gate's first clause and is testable before any AWS
> projection exists.

### P2-5 · Models and migrations for the graph

*The upsert trap that will bite: §4.9.*

`027`–`031`, plus `models/iga.go`: `IGAAccessEdge` loses `SubjectKind`/
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

*Shape: §2.14, screen C. Do not invent a second one.*

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

1. **Repeat scan keeps IDs.** Two consecutive scans of an unchanged account
   leave every `id` and `first_seen_at` unchanged, advance `last_seen_at`, and
   leave row counts equal.
2. **Role replacement closes the old edge.** Lambda moved `RoleA` → `RoleB`:
   old `executes_as` `ended` with `valid_to`, new `current`, both readable.
3. **Credential change preserves the account**, and two active keys is not
   treated as a conflict (§2.5).
4. **Recreation is recorded.** Same name, new `RoleId` ⇒ two objects, old
   retired `recreated`.
5. **A registered agent is distinguished from native discovery**, surfaced in
   `AgentDetail`; equal display names never merge.
6. **A3 is closed on both ends.** Every relationship endpoint *and* every
   provenance reference is a composite FK. Cross-workspace subject, target and
   `last_confirmed_by` are all rejected, each proven by a test that fails
   without the constraint.
7. **Illegal relationship shapes are rejected**: no target, two sources, or a
   source/target pair not in §2.2's table.
8. **A denied scan never ends anything**, and neither does a scan with one parse
   failure in the owning scope. Both non-vacuous.
9. **Evidence survives inventory deletion**, and a deduped re-read still
   records run confirmation. Both shipped in `024` — assert them, do not
   rebuild them.
10. **Projection is durable.** Killing the worker mid-projection yields the same
    final state; a job for a superseded generation abandons and writes nothing.
11. **Projection is rebuildable and one-way.** Drop-and-re-project reproduces
    the graph; CI fails on a write to `cloud_*` from the graph package, proven
    by a deliberate failure.
12. **Migrations rehearse cleanly against a production schema dump**, and the
    suite's failure count does not rise above the known set below.

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

```bash
# Migrations apply in order against a PRODUCTION schema dump, not a fresh bootstrap.
pg_dump --schema-only "$PROD_URL" > /tmp/prod-schema.sql   # no rows
createdb iga_rehearsal && psql iga_rehearsal < /tmp/prod-schema.sql
for m in migrations/master/0{26,27,28,29,30,31,32,33,34}_*.sql; do
  psql iga_rehearsal -v ON_ERROR_STOP=1 -f "$m" || { echo "FAILED: $m"; break; }
done

# Confirm the FK constraint names 024 drops actually exist first.
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
