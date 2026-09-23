# P2 evidence — checkpoint M0 (P2-0)

| | |
|---|---|
| **Spec** | `SPEC-iga-phase2-graph.md` at `d9741e7` (`authsec-staging`), merged into `graph` |
| **Results observed on** | `graph` @ **`4593476`** (this report is committed on top of it) |
| **Date** | 2026-09-23 |
| **Database** | PostgreSQL 16 (`postgres:16`), migrations `001`–`036` applied in order, one transaction per file |
| **Status** | M0 complete as far as this report says. **Stopping here for review**, per the handoff |

Every row below was executed. *Observed* is what the run printed. *Safeguard
removed* is a mutation applied to the implementation, the failure then
observed, and the file restored byte for byte — a row whose mutation still
passes fails the gate, and two did on the first attempt (see *Scenarios that
initially passed for the wrong reason*).

---

## 1. Reproduce

```bash
docker run -d --name p2pg -e POSTGRES_USER=authsec -e POSTGRES_PASSWORD=pw \
  -e POSTGRES_DB=iga_test -p 55433:5432 postgres:16

# Staged databases, built from migrations/master with psql -1 per file:
#   s0       001-026   (the shipped schema)
#   s1       001-036   (switch verification)
#   iga_int  001-036   (integration suite, P2-0 lab)
#   iga_test (empty)   (graph suite drops and rebuilds public itself)

export TEST_DATABASE_URL="postgres://authsec:pw@localhost:55433/iga_test?sslmode=disable"
export IGA_TEST_DSN="postgres://authsec:pw@localhost:55433/iga_int?sslmode=disable"
export S0_DSN="postgres://authsec:pw@localhost:55433/s0?sslmode=disable"
export S1_DSN="postgres://authsec:pw@localhost:55433/s1?sslmode=disable"

go build ./... && go vet ./...
bash scripts/ci-iga-isolation-check.sh
go test -count=1 -p 1 -v ./... 2>&1 | tee test.txt
grep -cE '^\s*--- PASS' test.txt; grep -cE '^\s*--- SKIP' test.txt; grep -cE '^\s*--- FAIL' test.txt

# The P2-0 scenarios alone:
go test -count=1 -p 1 -v -run 'TestP2' ./tests/integration/
```

## 2. Suite totals (at `4593476`, every DSN set)

| Package | Pass | **Skip** | Fail |
|---|---|---|---|
| `internal/igagraph` (unit) | 24 | **0** | 0 |
| `internal/awsdiscovery` (unit) | 23 | **0** | 0 |
| `tests/igagraph` (graph suite, real Postgres) | 22 | **0** | 0 |
| `tests/integration` (at `036`; includes the 18 `TestP2*`) | 177 | **0** | 0 |
| **IGA total** | **246** | **0** | **0** |
| Whole repository, `go test ./...` | 1063 | 12 | 22 |

The whole-repository failures are **not** from this branch. The same six
packages were run at base `0e75ad7` with the same environment, and they fail
the **identical set** of 18 tests (22 counting subtests):
`controllers/admin`, `controllers/enduser`, `controllers/shared`,
`internal/migration` (`TestMasterMigrations_Flow`), `internal/tokens`,
`services`. The 12 skips are AD / Entra ID / admin-controller tests that need
external services; none is in an IGA package.

`go build ./...` and `go vet ./...` clean. `ci-iga-isolation-check.sh`
passes all three rules. `001`–`036` apply in order to a fresh database; `026`
alone is the `s0` state.

## 3. The fifteen P2-0 scenarios (§6.3)

All through the **real** `AWSScanWorker.RunOnce` and
`ProjectionService.RunOnce`, **with a different owner name on each side**, the
switch on and verified, and every AWS call answered by a fake
(`tests/integration/p2_0_lab_test.go`). Each projection is required to
**complete on its first pass**.

| # | Scenario | Test | Fixture | Expected | Observed | Safeguard removed → observed failure |
|---|---|---|---|---|---|---|
| 1 | Unchanged rescan | `TestP2UnchangedRescan` | Lambda → role → `TicketRead` (Sid `ReadTickets`); two full cycles | Every id and `first_seen_at` stable; row counts equal; no new revision; no new lifecycle event; `last_seen_at` advances; 2 publications | PASS | **M1** `RecordRevision` without its equal-hash early return → *"revisions 1 -> 2: an unchanged statement gained a revision"*. **M1b** the evidence pass removed → *"1 grant edges have no evidence (T4.9 requires zero)"* |
| 2 | Lambda switches `RoleA` → `RoleB` | `TestP2RoleSwitchEndsOldExecutesAs` | One Lambda repointed | Old `executes_as` `ended` with `valid_to` and a reason; new one `current` | PASS | **M2** relationship key without the target endpoint → *"executes_as rows = 1, want 2 … RoleA current"* (overwritten in place) |
| 3 | Two policies grant the same action; one detached | `TestP2TwoPoliciesOneDetached` | `TicketRead` + `ToolboxRead` on `SharedToolRole`; `TicketRead` **also on `OtherRole`** so only the assignment partition can end it | Detached role's `TicketRead` grant `ended` `not_seen`; `OtherRole`'s current; `ToolboxRead` current | PASS | **M3** statement key by content only (drops Sid and incarnation) → grants merged. **M5b** `scope()` sends assignments to `iga_relationship` → *"TicketRead assignments ended = [] …"* |
| 4 | One policy becomes unreadable **and** another is detached, same run | `TestP2UnreadableAndDetachedInOneRun` | `GetPolicyVersion` denied on `TicketRead` only; `OtherPolicy` detached | `policy_documents` partial naming `TicketRead`; its statement, grant and the support of `ticket-archive/*` (named only by it) **stale**; its assignment **current**; `OtherPolicy` assignment + grant **ended**, `other-bucket/*` retired; `support-tickets/*` current | PASS | **M4** `protected()` disabled → *"unreadable policy's grant = … State:ended"* |
| 5 | Attach → detach → reattach | `TestP2AttachDetachReattach` | `TicketRead` kept alive by `OtherRole` | Period 1 `ended` `not_seen` with `valid_to`; reattach is a **new** row; period 1 unchanged; one grant per period | PASS | **M5** `scope()` default table → *"after detach: … State:current … want one period, ended not_seen"* |
| 6 | A `NotResource` statement | `TestP2NotResourceIsAnExclusion` | `s3:*` `NotResource: finance/*` | A grant; targets `*` (`resource`) and `finance/*` (`not_resource`); statement `negated` | PASS | **M6** NotResource entries written as `resource` targets → *"targets = [{finance/* resource} …]"* |
| 7 | Customer-managed policy recreated, same ARN and Sid | `TestP2RecreatedPolicySharesNothing` | `PolicyId` `ANPAOLD…` → `ANPANEW…` | Old policy retired `recreated`; old statement retired `policy_recreated`; old assignment and grant ended `policy_recreated`; new ones with new ids and keys; `retired/recreated` lifecycle event | PASS | **M7** incarnation key from the ARN → statements share a key |
| 8 | A Deny statement | `TestP2DenyIsNeverAGrant` | Allow + Deny in one policy | Both statements stored with their effect; exactly one grant (Allow) | PASS | **M8a** projector's Allow check removed → the write-time check refuses: *"only Allow statements are grants: effect deny"*. **M8b** both removed → a grant on the Deny statement |
| 9 | One region denied, another clean | `TestP2RegionPartitionsIndependent` | Lambdas in `us-east-1` and `eu-west-1`; east **changes role**, west's `ListFunctions` denied | East old edge `ended`, new `current`; west edge `stale`, workload active | PASS | **M9** executes_as partition ignores region → *"east-fn->RoleA: stale … want ended"* |
| 10 | Two accounts naming one bucket | `TestP2TwoAccountsOneBucket` | Accounts A and B, each a policy on `support-tickets/*`; then B detaches | One resource, two supports; no `*` resource; after B: B's support ended, A's current, resource active, A's grant current | PASS | **M10** retire when **any** support ended → *"shared resource … (retired) … want one active resource supported by both"* |
| 11 | Two scans, switch **off** | `TestP2SwitchOffTwoScans` | Gate off | Both publish; no job, barrier, publication, policy, grant or workload rows | PASS | **M11** worker ignores the switch → *"scan worker scan-worker-off-2: worked=false"* (job left the connector blocked) |
| 12 | Two scans, switch **on**, different worker names | `TestP2SwitchOnHandOffDifferentOwners` | `scan-worker-A` → `projector-X` → `scan-worker-B` → `projector-Y` | Holder after publish `job:<id>`; each projection completes on its first pass; second scan runs | PASS | **M12** barrier left in the scan worker's name → *"barrier holder after publish = scan-worker-A, want job:<id>"* |
| 13 | A superseded scan worker | `TestP2SupersededWorkerDeletesRefused` (+ the kept `TestSupersededWorkerInventoryWriteIsRefused` for writes) | `w1` claims, `w2` reclaims, `w1` reconciles | Identity and policy deletes → `ErrScanFenceLost`; the row survives | PASS | **M13** `runFencedTx` without the fence → *"superseded identity delete: err = <nil>"* |
| 14 | A crash after the graph commit | `TestP2CrashAfterCommitReplays` | Real cycle, then the job restored to *running, lease expired* and the barrier to *projecting, held by the job* | Replay completes on its first pass; one publication; no graph or lifecycle rows written | PASS | **M14** publication check skipped → *"partition … at generation 1 with no publication"* (the old `<=` failure) |
| 15 | Schema verification error at startup | `TestP2SchemaVerificationErrorFailsClosed` | Switch on, verification against a closed pool | Worker claims nothing, run stays queued; `/capabilities` → `misconfigured` + reason, eight feature keys | PASS | **M15** `ClaimAllowed` fails open → *"worker with an unverified switch: worked=true"* |

### Also in this checkpoint

| Check | Test | Safeguard removed → failure |
|---|---|---|
| **B15 / T1.3** a refused claim backs off and goes to the back of the queue; another workspace's scan is claimed next | `TestP2BusyBarrierDoesNotStarveAnotherWorkspace` | **M16a** no fresh `requested_at` → *"second pass: worked=false"*; **M16b** refusal reported as work → *"refused claim: worked=true … want false (back off)"* |
| **T1.5** a reclaimed run keeps its generation; rows and evidence at one generation | `TestP2ReclaimedRunKeepsItsGeneration` | **M17** scanner recomputes → *"identity rows at generations [2], want only the run's own 1"* |
| **T4.9** zero edges without evidence (per edge) | inside `TestP2UnchangedRescan` | **M1b** above |
| **E16 / T4.8** AWS identities never in GitHub's `/identity-accounts`; GitHub writer stamps `provider` | `TestP2AWSRowsAbsentFromGitHubReaders` | **M18** provider filter dropped → *"would return 2 rows"* |
| **B13/B14, T1.1** the switch: fails closed below `036`, verifies at `036`, a transient error is **retried, not cached**, a typo is misconfigured | `TestGraphSwitch*` (5, graph suite) | — (the fail-open cache is M15) |
| The three exits, fenced, with the **job-held** barrier; a reclaiming worker settles at once | `TestExit*`, `TestBarrierHeartbeatRenewsWithoutBreakingTheFence` | kept from the graph branch, adapted |
| not_in_scan, retire → suspend → restore → reconfirm (**now with B24 lifecycle events**), AlreadyPublished replay | `TestProof2*`, `TestProof3*`, `TestProof4*` | kept |
| Wedge recovery | `TestTransientFailureIsRetriedThenRecovered` and 4 more | kept |

**23 mutations, 23 caught** (M1, M1b, M2, M3, M4, M5, M5b, M6, M7, M8a, M8b,
M9, M10–M15, M16a, M16b, M17, M18), re-run as one batch on `4593476` after the
last test change.

### Scenarios that initially passed for the wrong reason

Two mutations **still passed** on the first run, and both exposed the same
flaw in the test, not the code:

- **M5 (scope)**: detaching a policy from its **only** holder retires the
  policy, and the retirement cascade ends the assignment — so the assignment
  partition was never exercised. Fixed by keeping the policy attached to a
  second role (scenarios 3 and 5) and asserting `ended_reason = not_seen`.
- **M9 (regions)**: removing the Lambda in the clean region retired the
  workload, and the cascade ended its edge. Fixed by having the Lambda
  **change role** instead, so only its region's `executes_as` partition can
  end the old edge.

## 4. The §6.1 dispositions

| On the graph branch | Done |
|---|---|
| Keep: `027`, `032`–`034` machinery, barrier, jobs, publication, `PublishWithCoverage`, fenced upserts, `RecoverStalled`, three exits, replay, restoration, suspension, `canEnd`, support, `retireUnsupported`, actor rule, gate and S0 tests | Kept. `032`/`033` edited per §3's table (see §6 below) |
| `028`–`031` edit in place per §3 | Generated from §3's own SQL, verbatim |
| Job-held barrier | Done: holder `job:<id>` at publish; every fence matches holder; `RecoverProjecting` removed |
| `phase2Available()` probing → switch + fail-closed | Done: `services/iga_graph_projection.go`; probe deleted |
| Nothing starts `ProjectionService` | Wired in `cmd/main.go`, only after verification |
| `Requeue` then immediate re-claim | Fresh `requested_at` (scan run **and** projection job) + back-off |
| Unfenced `ReconcileGeneration` deletes | Fenced (`runFencedTx`), identity / permission / workload / policy |
| One entitlement per (policy, index, resource); Deny as grants | Replaced by §2.6: policy / statement / assignment / grant (`036`, `internal/igagraph/permissions.go`) |
| `Load` from `cloud_resource` | Removed; references derive from statement text |
| `projectAgents`, `realizes`, AWS agent writes | Removed; models restored to base shape |
| `can_assume` from `cloud_assume_edge` | **Removed**, not yet replaced (T4.7 is M1) |
| GitHub recognition keys | Reverted: GitHub writer is base + `provider` + typed subject |
| `ListAccessPaths` hard-coding the agent column | Base semantics restored, filtered `provider = 'github'` |
| The two old routes | Removed; `/capabilities` added |
| `P2-0-EVIDENCE.md` | Removed by the commit adding this report |

## 5. Deviations from the spec, and why

1. **M0 includes work the spec files under S2, S3 and S5.** §6.3's task list
   is T1.1–T1.5, T4.2–T4.5, T4.9, but its scenarios and §4's machinery need
   more, so this checkpoint also contains:
   - **T3.2 (partial)**: `035`, and `cloud_policy` / attachments /
     memberships written by the scanners, fenced. `Load` reads nothing else.
   - **T3.3 (partial)**: per-document isolation, `document_error`, and
     `policy_documents` naming the document (scenario 4).
   - **T3.1 (groups only)**: `GetAccountAuthorizationDetails` for groups and
     memberships. §4.10 makes `iam_groups` a required surface of every policy,
     statement, assignment and grant partition, so without it nothing in the
     permission graph could ever end. Roles and users still use the per-role
     calls.
   - **T3.5 (partial)**: policy versions as evidence subjects (grant and
     assignment evidence).
   - **T5.1–T5.4 (partial)**: `Exclusions` and `protected()`, the recreation
     cascade, revisions, and lifecycle events written. Their *read* side is M1.
   - **T2.3 (partial)**: `/capabilities` only.
   - **T4.8**: done, because `028` adds `provider` and GitHub's lists would
     otherwise show AWS rows the moment the projector runs.
2. **`/capabilities` reports every `features` flag `false`.** No §5.3 read
   route exists yet. A feature reported available with no route behind it
   would render empty rather than *Unavailable*, which §2.14.7 forbids.
3. **Statement continuity.** §2.4 says a statement "inherits the policy's"
   continuity with no immutable key, but `028`'s
   `iga_entitlements_immutable_chk` requires one whenever continuity is
   `immutable`. Statements carry the **policy's** immutable key.
4. **An unreadable policy whose `GetPolicy` failed** has no `PolicyId` that
   run. It keeps the incarnation already in the graph for its ARN rather
   than minting an empty key. With no prior object it is not projected: there
   is nothing to protect and nothing to key it by.
5. **Test seams added**: `AWSScanWorker.WithScannerHook`,
   `AWSWorkloadScanner.WithRegionalAPIs`. Production does not use them.
6. **`037`** is written to `migrations/contract/`, which the runner does not
   read. It ships only after the rollback window.

## 6. Found wrong in the spec

**6.1 — `035` breaks rollback to `0e75ad7` (evidence writes).** `035`
replaces `uq_cloud_observation_dedupe` with a five-column `COALESCE(…,
policy_id)`. The `0e75ad7` writer's `ON CONFLICT` names the four-column
expression, which no longer matches any index. Run against a `036` database:

```
ON CONFLICT (workspace_id, COALESCE(identity_id, permission_id, resource_id, workload_id), source_api, content_hash)
ERROR:  there is no unique or exclusion constraint matching the ON CONFLICT specification
```

The old writer logs and continues, so a rolled-back deployment keeps
scanning **and records no evidence at all** — silently. The same applies to
`uq_cloud_observation_dedupe_no_subject`, whose predicate `035` also widens.
§1.5 and §7.5 promise rollback works. *Proposed*: keep the four-column index
(and the old partial one) alongside the new ones until `037`. Not changed
here — it is the spec's DDL and its probes name these indexes.

**6.2 — `028`'s `provider DEFAULT ''` loses GitHub rows across a rollback.**
Rows the `0e75ad7` binary writes during a rollback get `provider = ''`. After
rolling forward, `028` has already run, so nothing backfills them, and every
GitHub reader filters `provider = 'github'` — those rows disappear from
GitHub's lists. *Proposed*: `DEFAULT 'github'` in `028`, since the AWS
projector always sets `provider` explicitly. Not changed here, for the same
reason.

**6.3 — §6.1 and §3 disagree on `032`/`033`.** §6.1's table (and the handoff)
say keep `032`–`034` as they are; §3's table says drop `agent_id` from
support (`032`) and the agent ALTERs (`033`). §3 agrees with §2.2 (no AWS
agents), so §3 was followed. `034`'s relationship checks also had to change:
they re-declared `realizes` and the agent-instance source, which `031` no
longer has.

**6.4 — The handoff says "twelve P2-0 scenarios"; §6.3 lists fifteen.** All
fifteen are above.

**6.5 — The retirement cascade's reasons are mostly unreachable.** §4.10's
`Reconcile` ends edge partitions (`not_seen`) *before* `retireUnsupported`
runs, so a grant of a detached policy, or of a Sid-less statement that
changed, is already `ended not_seen` when the cascade would have written
`policy_retired` / `statement_retired`. The cascade reasons appear only when
the partition could not end the edge. Harmless, but the Changes wording in
§2.6 assumes the cascade reason.

**6.6 — Credential revocation has no partition.** §2.5 says a key that
disappears becomes `revoked` "under the four conditions", but §4.10's
`Partitions()` has no credential partition, so it cannot be implemented as
written. Credentials are projected; provider-reported `Inactive` maps to
`revoked`; absence revokes nothing.

**6.7 — Every unselected region gets partitions.** `RegionsAttempted` counts
`compute:<region>` stand-ins, which the workload scanner writes for **every
unselected** region, so a two-region connector gets ~200 partitions per
projection. Correct, but relevant to T6.10's load target.

## 7. Not done (M1 and later)

- **T4.7 trust**: `can_assume`, external principals, trust documents parsed
  with Deny and conditions (T3.4). The old `can_assume` projection is
  removed, so **no `can_assume` edges exist today**.
- **T3.1 in full** (roles, users, boundaries and customer-managed documents
  through authorization details), **T3.6–T3.8**, **T2.1–T2.4**.
- **T4.4** workloads and credentials are projected; groups and `member_of`
  are projected, but the membership path has no dedicated scenario.
  **T4.6** `task_execution_role` is projected, with no dedicated scenario.
- **All of S6**: the §5.3 read API, `internal/igaread`, traversal,
  classification (§5.5, T6.6), the T6.10 load test. The classification
  write route was **removed** per §6.1; there is none until T6.6.
- **The §9 production-schema rehearsal** — needs the dump from you.
- **B1–B24** as a set; those covered here are B2, B5, B6, B7-equivalent
  (`TestRecreatedRole…` moved to M1 with the old projection tests), B10,
  B12, B13, B14, B15, B18, B19, B21, B24.
- Deploys: none; not in scope.

## 8. Corrections to earlier reports

- An earlier revision of `P2-0-EVIDENCE.md` (`b704729`) said P2-11's read
  path "does not exist". **It did**: `GET /workloads/:workload_id/access-path`
  was on the branch; a truncated search missed it. It is removed now, per
  §6.1.
- The graph branch's own report called P2-6 done. The spec's review was right
  that **nothing started the projector**, the barrier stayed in the scan
  worker's name, the S0 probe failed open, and Deny statements were grants.
  All four are fixed and each has a scenario above that fails without the fix.

## 9. Questions for review

1. §6.1/§6.2: keep the old observation indexes and default `provider` to
   `github`, or another fix? Either is a small, additive change to `028`/`035`.
2. Is pulling T3.1 (groups), T3.2, T3.3, T3.5 and T5.1–T5.4 forward into M0
   acceptable, or should the checkpoint be cut differently?
3. §2.5: should credential revocation get a partition (`iam_access_keys`), or
   is provider-reported status enough for this milestone?
