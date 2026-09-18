# SPEC: Phase 2 — objects and the identity graph

> The phase after [SPEC-iga-phase1-collect.md](SPEC-iga-phase1-collect.md).
> Product context is
> [SPEC-agentic-access-management.md](SPEC-agentic-access-management.md); the
> invariants this phase must honour are [SPEC-iga-roadmap.md](SPEC-iga-roadmap.md) §3.
>
> **Verified 2026-09-18** against backend `eedabaa`, migrations `001`–`024`.
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
- **Traversal API and console.** Phases 4 and 5.
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
`cloud_scan_run`. Migration `025` closes it. This is the only Phase 1-adjacent
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

### 2.10 ERD

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
```

---

## 3. Schema

Eight migrations, `025`–`032`, in `authsec/migrations/master/`. `024` has
shipped; §1.2 says what it did.

> **Rehearse against a production schema dump before merging.** Migration `023`
> exists only because that rehearsal caught seven columns added to
> `001_bootstrap.sql` with no numbered migration: new installs had them,
> production never would, and pods would have come up healthy and failed at
> first customer use. Dump the schema (no rows), restore locally, apply
> `025`–`032`, run the suite between each. **A green run on a fresh bootstrap
> proves nothing about production.**

### 025 — close the cross-workspace provenance gap

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
in the composite form, and `025` exists because three were written before the
rule was.

### 026 — recognition keys and continuity

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
  constraining every new one. `032` retires them.
- **`lifecycle <> 'retired'` in the predicate** is what makes
  delete-and-recreate expressible: the retired row keeps its `source_key`, the
  new row takes the same key, only one is live.
- **`iga_credentials` is included** because P2-4 gives all five upsert methods a
  conflict target, and `UpsertCredential` is one of them. Its key is the
  credential's own id namespaced by its identity's `source_key`.

Put the Phase 3 warning from §2.6 in `iga_entitlements`' migration comment.

### 027 — `iga_workload`

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

### 028 — `iga_access_edges`: typed subject, required entitlement, lifecycle

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
- `DROP COLUMN subject_kind` removes a column the Go model still has: `028` and
  the `models/iga.go` change land in the same commit.

### 029 — `iga_relationship`

```sql
CREATE TABLE IF NOT EXISTS public.iga_relationship (
    id                uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id      uuid NOT NULL,
    relationship_type text NOT NULL,

    source_identity_account_id uuid,
    source_workload_id         uuid,
    source_agent_instance_id   uuid,

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
    CONSTRAINT iga_relationship_source_chk CHECK (
        (source_identity_account_id IS NOT NULL)::int
      + (source_workload_id         IS NOT NULL)::int
      + (source_agent_instance_id   IS NOT NULL)::int = 1),
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
                source_identity_account_id IS NOT NULL AND target_identity_account_id IS NOT NULL
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

### 030 — evidence junctions

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

### 031 — projection job, projection state, agent origin

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
    object_class      text NOT NULL,
    relationship_type text NOT NULL DEFAULT '',
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
    CONSTRAINT iga_projection_state_key
        UNIQUE (workspace_id, estate_scope_id, object_class, relationship_type)
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

### 032 — retire the legacy unkeyed rows (deferred)

`026`'s partial indexes let `source_key = ''` rows coexist. That is a transition
allowance. Once P2-4 and P2-6 own the write path and **one clean production scan
has run on the new path**, mark the remaining unkeyed rows
`lifecycle = 'retired'`, `retired_reason = 'pre_graph'`, and tighten the CHECK
to require a non-empty `source_key` on active rows. Ship as a separate PR. Never
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

type SubjectRef struct {
    Kind string // identity | permission | resource | workload
    ID   uuid.UUID
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
    identity    map[uuid.UUID]uuid.UUID
    workload    map[uuid.UUID]uuid.UUID
    resource    map[uuid.UUID]uuid.UUID
    entitlement map[uuid.UUID]uuid.UUID
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
// Continuity() and ImmutableKey() must agree: 025's CHECK rejects a row
// claiming 'immutable' with an empty immutable_key, which is deliberate -- a
// silent disagreement here disables delete-and-recreate detection entirely.
func ImmutableKey(kind string, attrs json.RawMessage) string {
    var a struct {
        RoleID     string `json:"role_id"`
        UserID     string `json:"user_id"`
        InstanceID string `json:"instance_id"`
    }
    if err := json.Unmarshal(attrs, &a); err != nil {
        return ""
    }
    switch kind {
    case "iam_role":     return a.RoleID
    case "iam_user":     return a.UserID
    case "ec2_instance": return a.InstanceID
    }
    return ""
}
```

> **First task for whoever picks this up:** confirm the IAM collector actually
> writes `role_id` / `user_id` into `cloud_identity.attrs`. `internal/awsdiscovery/iam.go`
> collects the detail; whether `RoleId` survives into `Attrs` was not verified
> when this was written. **If it does not, that is a Phase 1 collector gap and
> it must be fixed in P2-2, not worked around here** — without it,
> `Continuity()` returns `immutable` and `ImmutableKey()` returns `""`, the
> CHECK rejects the row, and the projection fails loudly. That failure is the
> correct behaviour; do not relax the CHECK to get past it.

### 4.5 The projection algorithm

One transaction per `(scope, class)` partition. Nodes first, edges second.

```go
func (p *Projector) Project(ctx context.Context, snap *Snapshot) error {
    return p.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
        r := newResolved()

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
        return p.recordState(tx, snap, false)
    })
}
```

One node pass in full — the others are the same shape:

```go
func (p *Projector) projectIdentities(tx *gorm.DB, snap *Snapshot, r *resolved) error {
    now := p.now()
    for _, ci := range snap.Identities {
        key  := IdentityKey(ci)
        cont := Continuity(ci.Kind)
        imm  := ImmutableKey(ci.Kind, ci.Attrs)

        existing, err := p.repo.FindIdentityByKey(tx, snap.Run.WorkspaceID, key)
        if err != nil {
            return fmt.Errorf("lookup identity %s: %w", key, err)
        }

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
            SourceWorkloadID:        &src,
            TargetIdentityAccountID: &dst,
            Basis:                   "declared", // configuration says so; we did not see it run
            State:                   "current",
            LastConfirmedAt:         now,
            LastConfirmedBy:         &snap.Run.ID,
            SourceKey:               Key("aws", "executes_as", w.NativeID),
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

### 4.6 The upsert, and the one thing that will bite

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

### 4.7 Reconciliation

Projection writes what the run saw. Reconciliation decides what to do about
what it did not — and this is the function to get right.

```go
// Reconcile closes what this run SHOULD have seen and did not.
//
// The naive version -- "end everything older than this generation" -- is wrong
// and dangerous: a denied surface produces no rows, so every relationship
// behind it looks absent, and a credential outage reads as a successful
// cleanup. Hence canEnd().
func (rc *Reconciler) Reconcile(ctx context.Context, snap *Snapshot) error {
    return rc.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
        for _, part := range Partitions(snap) { // (scope, class, relationship_type)
            if !rc.canEnd(snap, part) {
                // We could not look. Still believed, with its last confirmation
                // time shown. NEVER ended.
                if err := rc.markStale(tx, part, snap); err != nil { return err }
                continue
            }
            if err := rc.endOlderThan(tx, part, snap.Generation, "not_seen", snap); err != nil {
                return err
            }
        }
        return rc.markReconciled(tx, snap)
    })
}

// canEnd is the four conditions of §2.7, in order of cheapness.
func (rc *Reconciler) canEnd(snap *Snapshot, part Partition) bool {
    // 1. The run published. Note the value is 'published' -- cloud_scan_run has
    //    no 'complete' state (020:71).
    if snap.Run.Status != models.CloudScanRunPublished {
        return false
    }
    // 2. This run's own coverage for the owning surface. Absent report ==
    //    did not look, which is not the same as looked and found nothing.
    cov, ok := snap.Coverage[part.Surface]
    if !ok || cov.State != models.CloudCoverageReached {
        return false
    }
    // 3. Nothing was dropped reading it. ScanCoverage.Complete() does NOT
    //    check these -- that gate lives in the permission scanner
    //    (cloud_aws_permission_scan.go:188). 024 persists them per run so this
    //    does not have to re-derive them.
    if cov.ParseFailures > 0 || cov.StatementsSkipped > 0 {
        return false
    }
    // 4. This run owns the partition's generation. An out-of-order or replayed
    //    job must not close anything.
    return snap.Generation >= rc.lastGenerationFor(part)
}
```

`markStale` moves `current` rows to `stale` and leaves `last_confirmed_at`
untouched — that timestamp is the honest answer to "how old is this?" and
refreshing it would launder an outage into a confirmation.

`endOlderThan` sets `state='ended'`, `valid_to=now()`, `ended_reason='not_seen'`
on rows in the partition whose `last_confirmed_by` generation predates this run.
It never deletes.

### 4.8 One Lambda, end to end

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

Migration `025` alone: the two `UNIQUE (workspace_id, id)` targets and the three
single-column references converted to composite form (§3, `025`).

`024` already closed D1–D4. **Verify them, do not redo them** (§1.2), and in
particular leave `models.ScanCoverage.Complete()` alone — the parse-failure gate
lives upstream in `cloud_aws_permission_scan.go:226`, which turns the surface
`partial` before `Complete()` runs. Adding a counter check inside `Complete()`
duplicates a gate that already holds, and the duplicate is the copy that drifts.

Then wire the projection job enqueue: `repository/cloud_scan_run_repository.go`
`Publish()` also enqueues `iga_projection_job` in the same transaction. That is a
forward reference — land `025` now and wire the enqueue when `031` exists.

> **Gate:** a `cloud_observation` row whose `scan_run_id` belongs to another
> workspace is rejected by the database, proven by a test that fails without
> `025`. Then re-assert what `024` delivers, so a later change cannot quietly
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
`source_key` `026` adds.

Test against **real Postgres**. SQLite accepts the wrong thing silently.

> **Gate:** run the same GitHub scan twice against real Postgres. Row counts in
> `iga_identity_accounts`, `iga_resources`, `iga_entitlements`,
> `iga_credentials` and `iga_access_edges` are identical after the second run,
> every `id` is unchanged, every `first_seen_at` is unchanged, `last_seen_at`
> advanced. This is the exit gate's first clause and is testable before any AWS
> projection exists.

### P2-5 · Models and migrations for the graph

*The upsert trap that will bite: §4.6.*

`026`–`030`, plus `models/iga.go`: `IGAAccessEdge` loses `SubjectKind`/
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

*Implementation: §4.3, §4.5, §4.6. Worked example: §4.8.*

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

*Implementation: §4.7.*

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
for m in migrations/master/0{25,26,27,28,29,30,31}_*.sql; do
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
