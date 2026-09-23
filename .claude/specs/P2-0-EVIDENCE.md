# P2-0 evidence report

**Commit:** `6b8efeb` on `graph` (parent `4504426`, rebased onto `0e75ad7`)
**Date run:** 2026-09-23
**Database:** PostgreSQL 16, `postgres:16` container, migrations `001`–`034`
applied in order unless a row says otherwise.

Every row below was executed. A row's **Observed** is what the run printed, not
what the code is expected to do. **Safeguard removed** is a mutation applied to
the implementation, the resulting failure observed, and the mutation reverted —
a row whose mutation still passes proves nothing and is marked as such.

## Environment

```bash
docker run -d --name p2pg -e POSTGRES_USER=authsec -e POSTGRES_PASSWORD=pw \
  -e POSTGRES_DB=iga_test -p 55433:5432 postgres:16

# Staged databases, migrated with psql -1 per file, in order:
#   iga_test  001-034   (graph suite; self-rebuilds its own schema)
#   iga_int   001-034   (integration suite)
#   s0        001-026   (S0: Phase 1 state)
#   s1        001-034   (S1/S2)

export TEST_DATABASE_URL="postgres://authsec:pw@localhost:55433/iga_test?sslmode=disable"
export IGA_TEST_DSN="postgres://authsec:pw@localhost:55433/iga_int?sslmode=disable"
export S0_DSN="postgres://authsec:pw@localhost:55433/s0?sslmode=disable"
export S1_DSN="postgres://authsec:pw@localhost:55433/s1?sslmode=disable"
```

## Suite totals, with skips

A count that hides skips is how the previous rounds reported green on tests
that never ran, so the skip column is mandatory.

| Suite | Command | Pass | Skip | Fail |
|---|---|---|---|---|
| Graph | `go test -count=1 -p 1 -v ./internal/igagraph/... ./tests/igagraph/` | **53** | **0** | **0** |
| Integration | `go test -count=1 -p 1 -v ./tests/integration/` | **155** | **0** | **0** |
| Build / vet | `go build ./... && go vet ./...` | clean | — | — |
| Isolation | `bash scripts/ci-iga-isolation-check.sh` | passed (3 rules) | — | — |
| Migrations | `001`–`034` applied in order to a fresh database | applied | — | — |

## The nine scenarios

| # | Scenario | Test | Fixture | Expected | Observed | Safeguard removed |
|---|---|---|---|---|---|---|
| 1 | Unchanged rescan | `TestRepeatScanKeepsIDs` | One Lambda → role → grant → resource; projected twice, clock +24h | Every `id` and `first_seen_at` unchanged, `last_seen_at` advanced, row counts equal, nothing ended | PASS | — (covered by the upsert conflict target; a bare `Create` duplicates rows) |
| 2 | Lambda switches RoleA → RoleB | `TestRoleReplacementClosesOldEdge` | Same workload repointed; RoleA absent from run 2 | Old `executes_as` `ended` with `valid_to` + reason, new one `current`, both readable | PASS — 1 ended / 1 current, both rows retained | — |
| 3 | A policy that fails to parse | `TestCanEndRefusesParseFailure` | `policy_documents` = `partial` | Entitlement + access-edge partitions close **nothing** | PASS | Pair `TestCanEndAllowsCleanParse` proves non-vacuity: absent `policy_documents` **does** close |
| 4 | One region denied, another clean | `TestRegionPartitionsAreIndependent` | `lambda:us-east-1` reached, `compute:eu-central-1` denied | Clean region closes, denied region does not, keys distinct | PASS | — |
| 5 | Two accounts, one workspace | `TestScanOfOneAccountClosesNothingInAnother` | Two connectors, each with its own role/resource | A scan of A changes nothing of B's | PASS — B's live edges unchanged, 0 ended | `scope()` dropping `connector_id` → this test FAILS (verified in an earlier round) |
| 6 | An obsolete worker | `TestExitsRefuseASupersededWorker` | Barrier recovered by `w2`; `w1` still holds the old version | `w1` changes **nothing** — not the job, not the barrier | PASS (both sub-cases) | — |
| 7 | Two accounts naming the same bucket | `TestSharedResourceSurvivesOneAccountDroppingIt` | A and B both name one ARN; B stops | One object, two support rows; B's support ends, A's untouched, object survives | PASS | `retireUnsupported` retiring when **any** support ends → FAILS (verified earlier) |
| 8 | A superseded scan worker that keeps running | `TestSupersededWorkerInventoryWriteIsRefused` (integration) | `w1` claims, `w2` reclaims the run, `w1` writes | `ErrScanFenceLost`; the row does **not** land | PASS | Neutralising `assertScanFence` → "the superseded write LANDED" |
| 9 | Crash between publication and coverage | `PublishWithCoverage` | Coverage + publish + job enqueue in one transaction | Either fully published with coverage and a queued job, or not published | **Structural, not executed.** One transaction by construction; no test kills the process mid-commit |

## The five proofs

| # | Proof | Test | Fixture | Expected | Observed | Safeguard removed |
|---|---|---|---|---|---|---|
| 1 | Actor rule | `TestClassifyActorRule` (integration) | 7 token shapes; **every** case sets `client_id`, because a real session has one | Human workspace session succeeds; machine-only, end-user, invited, suspended, cross-workspace, mismatched-user all refused; the **user id** is recorded | PASS, 7/7 | Accept-on-`user_id` → end-user case FAILS. Dropping `status='active'` → invited **and** suspended FAIL |
| 2 | `not_in_scan` with a prior edge | `TestProof2NotInScanPreservesPriorEdge` | Real `cloud_*` rows through the real `igagraph.Load`; workload at gen 2, its role left at gen 1; IAM denied | `not_in_scan` + the role's ARN; prior edge **preserved** as `stale`, no `valid_to`, `last_confirmed_at` unmoved | PASS | Deleting the prior edge in the non-resolved branch → "the prior edge was DELETED; it must be preserved" |
| 2b | No role configured | `TestProof2NoRoleConfiguredIsNone` | Workload with `IdentityID = nil` | `none`, empty ARN — never confused with `not_in_scan` | PASS | — |
| 3 | Retire → suspend → restore → reconfirm | `TestProof3RetirementSuspensionRestoration` | Role + **seeded asserted** external principal; role vanishes under clean coverage; same `UniqueID` returns | Retired `unsupported`; assertion `suspended` still pointing at the retired row; restored **same id, same `first_seen_at`**; assertion `pending_reconfirmation` | PASS | Skipping `settleResolutionsOnRetired` → `resolution_state = "active"` at both checkpoints |
| 4 | Kill after commit | `TestProof4KillAfterCommitReplaysAsAlreadyPublished` | Graph committed, worker dies before `completeAndRelease`; replay same run/generation | `AlreadyPublished` naming the rev; **no** writes; one publication row; job `complete`, barrier `idle` | PASS | Disabling the publication check → replay hits the generation guard and fails `ErrInconsistentWatermark` — i.e. the `<=` behaviour that failed a successful run forever |
| 5 | Wedge recovery (added this round) | `TestTransientFailureIsRetriedThenRecovered`, `TestCrashOnLastAttemptIsRecovered`, `TestScanGiveUpIsRecovered`, `TestRecoveryLeavesClaimableWorkAlone` | The reviewer's three wedge paths, plus a still-claimable run | Each wedged workspace is freed and admits a new scan; a claimable run is **left alone** | PASS, 4/4 | These began as probes asserting the **bug** and passed in that form; inverted, they fail without the recovery loop |

## The three exits

| Exit | Test | Expected | Observed | Safeguard removed |
|---|---|---|---|---|
| `completeAndRelease` | `TestExitCompleteAndRelease` | Job `complete`, barrier `idle`, workspace accepts the next scan | PASS | — |
| `abandonAndRelease` | `TestExitAbandonAndRelease` | Job `abandoned`, barrier `idle` | PASS | — |
| `failKeepBarrier` (below ceiling) | `TestExitFailKeepBarrierBelowCeiling` | Job `failed`, barrier **still projecting**, job reclaimable after backoff | PASS | Releasing the barrier here → `barrier = "idle", want projecting` |
| `failKeepBarrier` (at ceiling) | `TestExitFailKeepBarrierAtCeilingEscalates` | Escalates: job `abandoned`, barrier `idle` | PASS | — |
| Fencing | `TestExitsRefuseASupersededWorker` | A superseded worker changes nothing | PASS | — |

## S0 / S1 / S2

| Stage | Schema | Command | Expected | Observed |
|---|---|---|---|---|
| S0 | `001`–`026` (`s0`) | `go test ./tests/igagraph/ -run TestSchemaGateRefusesBelow034` | Projector **declines to start**; governance tables present | PASS — refused with *"projector requires migration 034 (relation iga_external_principal is missing…)"*; 153 tables; `agent_policies` present; `iga_external_principal` absent |
| S1 | `001`–`034`, projector disabled (`s1`) | `go test ./tests/integration/` | Phase 1 scanning unaffected | PASS — 155 pass / 0 skip / 0 fail |
| S2 | `001`–`034`, projector enabled (`s1`) | `go test ./tests/igagraph/ -run TestSchemaGateAcceptsAt034` + graph suite | Projector starts; the slice works end to end | PASS — accepted at head 034; graph suite 53/0/0 |

## What this report does NOT cover

Stated plainly, because a gate that overclaims is worse than one with holes.

1. **Scenario 9 is structural, not executed.** Publication, coverage and job
   enqueue share one transaction by construction, but no test kills the process
   mid-commit to observe it.
2. **S0/S1/S2 are migration states, not deployments.** They prove the schema
   gate and that each state's suites pass. They are not deploys into an
   isolated environment, and say nothing about pod startup, config or rollout.
3. **The §8 production rehearsal is still outstanding.** Everything here runs
   against a schema built from `001`–`034` on a fresh database. The spec is
   explicit that this proves nothing about production drift — `023` and `026`
   both exist because production had diverged from `001_bootstrap.sql`. This
   needs a `pg_dump --schema-only` of production restored into a scratch
   database, with `027`–`034` applied on top. That requires production access
   and has not been done.
4. **The projection heartbeat's barrier renewal** is implemented and reasoned
   about, but no test runs a projection long enough to observe a renewal.
5. **`can_assume`, credentials, agent instances and the read path** are
   implemented and covered by the graph suite, but are out of P2-0's slice and
   have no dedicated scenario row here.
