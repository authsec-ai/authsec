# Onboarding prompt — AuthSec Agentic IGA

*Paste this as your first message. The spec files referenced below will be in the
repo — find them before you start (try `.claude/specs/`, then the repo root).*

---

You are picking up work on **AuthSec Agentic IGA**. Before writing any code, read
the specs in the order given in §2. Do not skip to the phase documents — they
assume the invariants in §4, and code that violates those is worse than no code.

Everything below is current as of **2026-09-18**: backend `eedabaa`, UI
`efb67b2`, migrations `001`–`025` applied in production. Re-verify before
trusting any line number here — this drifts.

## 1. What you are building

AuthSec is building identity governance for **AI agents** rather than people. An
agent shows up in a cloud account as a Lambda with an execution role, in Bedrock
as an agent definition, in a repo as a workflow identity. Each platform exposes a
fragment. The product joins those fragments into one evidence-backed record per
agent — its instances, owners, the identities and permissions it holds, who can
invoke it — then runs real IGA workflows on it: certify the access, remove it,
prove the removal happened.

The piece under construction is the **identity graph** everything hangs off. AWS
discovery is built and deployed. The graph is not.

## 2. Read these, in this order

| # | File | Lines | Why |
|---|---|---|---|
| 1 | `SPEC-agentic-access-management.md` | 246 | What the product is and its non-goals. §6 "As built today" is the honest state — read it before trusting any other document's present tense |
| 2 | `SPEC-iga-roadmap.md` | 570 | **The load-bearing document.** Current state (§1), foundations (§2), **invariants (§3)**, six phases with exit gates (§4). If you read one thing, read §3 |
| 3 | `SPEC-aws-discovery.md` | 893 | What an IAM role, trust policy, instance profile and permissions boundary actually mean. Nothing else documents this, and the graph is wrong if you get it wrong |
| 4 | `SPEC-iga-phase1-collect.md` | 532 | The phase that is **done**: how collection works, what it writes, what it deliberately does not promise |
| 5 | `SPEC-iga-phase2-graph.md` | 1890 | The phase **in flight** — likely your work. Migrations `025`–`032`, eleven tasks, each with a gate |

Then read `AGENTS.md` at the workspace root and in each repo. Those are the
canonical engineering conventions; each `CLAUDE.md` just points at them.

Read when relevant, not now: `AuthSec-AWS-Discovery-Lab-Team-Brief.md` (AWS test
fixtures, exercises lettered A–D so they never read as delivery phases),
`SPEC-github-discovery.md` (dormant source, has a known defect),
`SPEC-deployment-k3s.md` (how it ships).

**One boundary to know without reading anything:** AuthSec already ships *Action
Connectors*, an outbound broker that executes typed provider actions on behalf of
agents. That is a **different product** with a different credential. A discovery
integration reads an estate to build inventory and evidence; Slack or GitHub
support in the connector framework provides no Slack or GitHub *estate
discovery*. **Agentic IGA must not depend on the connector framework.**
Remediation is a third category again, with its own credential and its own
consent.

## 3. Where things stand

| Phase | State |
|---|---|
| 0 · Foundations | **Closed** |
| 1 · Connect and collect | **Built and deployed.** AWS onboarding, connector lifecycle, scan, reads for identities/secrets/assume-edges/permissions/resources/workloads/usage. Durable leased execution, evidence, idempotent upserts |
| 2 · Objects and identity graph | **Started.** Migration `024` landed (`b47adeb`), closing four durability defects in scan coverage and evidence. `025` onward remain |
| 3–5 · Entitlements, traversal API, console | Sketched in the roadmap only |

Production holds real scanned data — roughly 107 identities, 461 permissions —
collected through pre-Phase-1 code. Real, but not evidence-backed.

> ### Read this before you push anything
>
> **Any commit landing on `authsec-staging` in either repo deploys to live
> production in about four minutes.** There is no approval gate. The backend
> deploy runs migrations against the customer database.
>
> The pipeline is safe mechanically — it backs up the database, verifies that the
> running service reports the expected commit, and reverts if not — but nothing
> asks a human first. **Work on a branch and open a PR.** Do not push to
> `authsec-staging` unless you intend to deploy.

## 4. Invariants — do not violate these

These are not style preferences. Each exists because the alternative makes the
product lie to a customer. Full text in `SPEC-iga-roadmap.md` §3.

**Coverage is a state, never a percentage.** Per surface: `reached | partial |
denied | throttled | not_configured | constrained | stale | unsupported |
not_selected | unknown`. "68% covered" averages a permissions error together with
a deliberate exclusion, and those have different owners. **Zero objects returned
is never complete coverage.**

**`stale` is not `ended`.** A relationship we could not look at is `stale` — still
believed, with its last confirmation time shown. `ended` means an authoritative
read of the owning scope did not see it. Collapse them and a credentials outage
renders as a successful access cleanup. This drives the whole reconciliation
design.

**A configured path is not proven access.** `basis ∈ declared | observed |
derived | asserted`. Everything collected today is `declared` — there is no
CloudTrail collector, so nothing is `observed`. Never label a configured path
"can access", nor an inventory sighting "usage".

**Conditions are recorded, never evaluated.** `constraint_state ∈ unconstrained |
conditional | negated | bounded | unknown`. Only `unconstrained` may render as
plain access. We do not compute effective access and must not imply we do.

**Redact, then hash.** `AWS response → delete sensitive fields → canonical form →
hash`. Hashing first retains a deterministic derivative of material we refused to
store.

**`(kind, uuid)` is not a foreign key.** A text discriminator beside a bare UUID
is how cross-tenant references got in — defect A3. Every relationship endpoint
and every provenance reference is a typed column with a composite FK on
`(workspace_id, id)`. `022_cloud_observation.sql` is the reference
implementation. **Never a single-column foreign key to a workspace-scoped
table.**

**Leases fence with a version, never a clock.** `cloud_scan_run.lease_version` is
a fence token; publication requires the row still carries the claimed version, so
two hosts with skewed clocks cannot both publish. See `fenced()` in
`repository/cloud_scan_run_repository.go`.

**Generation is assigned at claim, not enqueue.** Reconciliation reads generations
as evidence a pass actually happened.

**No secrets, ever.** Existence, age and last use of a credential — never its
value. ExternalId is not a secret; the system must stay secure if it leaks.

**The discovery role can never write.** Remediation is a separate credential with
separate consent.

## 5. Traps that will each cost you a day

**The canonical `iga_*` tables have no recognition key at all.** `iga_agents`,
`iga_identity_accounts`, `iga_resources` and `iga_entitlements` carry no native
id and no source key. There is no column a rescan could match on, so "repeat scan
keeps IDs" is not a bug in the code — it is impossible in the current schema.
Migration `026` fixes it. Assume no `iga_*` row is stable yet.

**All five `Upsert*` methods are bare `Create`.** `repository/iga_repository.go:616-629`.
Named `Upsert*`, none upserts. Every GitHub scan duplicates everything.

**`ScanCoverage.Complete()` looks broken and is not — do not "fix" it.** Its
body iterates surface states and consults no counter, which invites the
conclusion that `ParseFailures`/`StatementsSkipped` gate nothing. They gate it one
level up: `cloud_aws_permission_scan.go:226` turns the `policy_documents` surface
`partial` when either is non-zero, `FinalizeCoverage` merges that surface in, and
`Complete()` then returns false on `partial`. Adding a counter check inside
`Complete()` duplicates a gate that already holds, and the duplicate is the copy
that drifts. Two independent reviewers have now misread this; read the chain
before touching it.

**Provenance is not workspace-scoped.** Three foreign keys reference
`cloud_scan_run` by `id` alone — `001:6880`, `022:43`, and `024:130` — so a row
in one workspace can point at another workspace's scan run. Neither
`cloud_scan_run` nor `cloud_observation` has `UNIQUE (workspace_id, id)`, which
is why the composite form was unavailable. Migration `025` closes it. **Never
write a single-column foreign key to a workspace-scoped table.**

**Scan run status is `published`, not `complete`.** The CHECK is
`('queued','running','published','failed','abandoned')`.

**One `cloud_permission` row is (identity, statement, resource).** A statement
naming three resources produces three rows. Inline policies are keyed
`"inline:" + name`, unique only *within* an identity — two roles can each have a
`ReadData`.

`SPEC-iga-phase2-graph.md` §1.2 covers what `024` closed and how — including two
mechanisms better than the spec originally proposed.

## 6. Conventions

- **Migrations** are numbered files in `authsec/migrations/master/`, applied on
  deploy, forward-only. No deployed database is ever wiped. Head is `024`;
  Phase 2 continues at `025`.
- **Rehearse migrations against a production schema dump**, never a fresh
  bootstrap. Migration `023` exists only because that rehearsal caught seven
  columns added to `001_bootstrap.sql` with no numbered migration — new installs
  had them, production never would, and pods would have come up healthy then
  failed at first customer use.
- **IGA lives in the `public` schema** with an `iga_*` prefix: one database, one
  pool, one process. Isolation is enforced by
  `scripts/ci-iga-isolation-check.sh`, not a privilege boundary —
  `discovered_agent_iga_links` deliberately foreign-keys IGA to the legacy
  runtime channel, so a grant boundary would break a designed feature. A grant
  cannot tell a designed join from a careless one; a CI check can.
- **CI ratchets, which must not rise:** 198 TypeScript errors, 17 ESLint errors.
  Count TS with `grep -c`, not `wc -l`; ESLint with `-f json` summing
  `errorCount`, because the human formatter reports zero regardless. A *parse*
  error reports as 1 and hides every other diagnostic — a low count is not good
  news.
- **`npx tsc --noEmit` at the UI root checks nothing** — the root `tsconfig.json`
  has `"files": []`. Use `-p tsconfig.app.json`.
- **Known-failing, tracked, not caused by you:** 7 × `TestIGA*` in
  `tests/integration` fail with `source_objects=0, observations=0` — a real
  GitHub-path defect. `TestMasterMigrations_Flow` needs a local postgres role
  `kloudone`. Record the counts before you start so your regressions are
  distinguishable from inherited ones.
- **Legacy AuthSec Production is release-locked** — security, data-integrity,
  availability and critical customer fixes only. IGA work must not mutate legacy
  production data, credentials, deployments or artifacts.

## 7. Start here

If you are picking up Phase 2, the task order in `SPEC-iga-phase2-graph.md` §4 is
deliberate and the dependencies are real:

1. **P2-2 first** — migration `025`, closing the provenance gap above. Small now
   that `024` has landed, and it belongs before the projector: foreign keys
   written single-column have to be redone.
2. **P2-4** is testable immediately, before any AWS projection exists: make the
   five `Upsert*` methods actually upsert, then run the same GitHub scan twice
   against real Postgres and assert nothing duplicated. That is the exit gate's
   first clause. Test against real Postgres — SQLite accepts the wrong thing
   silently.
3. Then the graph proper — migrations `026`–`031`, tasks P2-3 and P2-5 onward.

Two habits that matter more than anything above:

**Verify before asserting.** Check the cluster, the build and the migrations
before writing a claim into a document as fact. A table headed "Decision" reads
as a description of a real system; make sure it is one.

**Check every test for vacuity.** Remove the fix and confirm the test fails. A
Phase 1 deletion test passed with its fix removed, because the fixture had EKS
denied and the coverage check was already false for an unrelated reason. A test
that passes for the wrong reason is worse than no test at all.
