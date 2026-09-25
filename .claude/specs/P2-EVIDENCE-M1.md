# P2 evidence — checkpoint M1

| | |
|---|---|
| **Spec** | `SPEC-iga-phase2-graph.md`: §6.2 S2–S6 (l.6279–6337), §7.1 (l.6429–6465), §7.3 (l.6507–6537), §7.4 (l.6539–6547) |
| **Code** | `graph` @ **`9248549`**, on M0 `7bdee07`. `graph` has since gained one commit, `e63dfa7`, which adds only an `igaDB(t)` DSN guard at the top of `TestP2BdbIAMDeniedEndsNothing` (3 lines, `git show e63dfa7`); no assertion cited below changes with it (§11 below) |
| **History** | `git log --first-parent 7bdee07..9248549`: 17 merges `Merge branch 'm1/<key>' into graph`, 5 commits before the waves, 4 commits after merges |
| **Migrations** | Unchanged since M0. `git diff --name-only 7bdee07 9248549 -- migrations/` is empty, so `027`–`036` are exactly as the M0 report left them, and every DDL below is a proposal |
| **Results** | Run for this report on the build machine, 2026-09-25: suite totals §2 below (at `9248549`, and the test-only `e63dfa7`), the load suite on the merged code §3 below (at `9248549`), the whole-repository comparison against `0e75ad7` §11 below (at `e63dfa7`). Mutation results were not re-run (§6.2 below) |
| **Date** | 2026-09-25 |
| **Status** | `origin/graph` (re-fetched 2026-09-25) is at `3ea0244`, the end of Wave A. Nothing after it is pushed: `graph` (at `e63dfa7`) is 66 commits ahead, 65 of them up to `9248549`. Every D-n is provisional. **Stopping here for review** |

M1 is the backend of the spec's S2–S6 and the §7 proofs (B1–B24, and the backend halves of E1–E16), built on the local branch `graph`. Each work item was built on its own branch `m1/<key>` and merged into `graph`; the non-merge first-parent commits are fixes made on `graph` after a merge. In merge order:

- **Before the waves:** `56df9e1`, `e665834`, `944cc5e`, `76003e1`, `33c8df7`.
- **Wave A:** `s3a`, `trust`, `s3b`, `s2`, `class`, `lists`; then `6f9b3ff`, `ac7519d`, `3ea0244` on `graph`.
- **Wave B:** `changes`, `wdetail`, `idetail`, `rdetail`, `graph`, `evidence`.
- **Wave C:** `bdb`, `bfk`, `contract`, `egates`, `load`; then `9248549` on `graph`.

The console (S7), the real-AWS lab (S8), Playwright, the §9 production rehearsal and deploys are not part of M1 (§11 below).

**How to read this.** The suite totals, the load run and the whole-repository comparison were executed for this report (§2, §3 and §11 below); nothing else was. Each test named was checked to exist with `git grep '^func Test…' 9248549`, except `TestScanResumesPastIdentitiesAlreadyDone`, M0's name for a renamed test, checked at `7bdee07`. What a test asserts beyond its name, and every mutation result, come from the agent reports in `m1-wt/_shared/`, cited as `impl:<key>`, `review:<key>` and `fix:<key>`:

- `wave_reports.md` has the implement, review and fix report for each item in Waves A and B.
- `wave_c_reports.md` has the Wave C JSON reports.
- `egates_fix_report.md`, `load_fix_report.md` and `tests/load/RESULTS.md` cover the E-gates and load fix passes.

A claim that rests on one report or commit message alone says so ("reported, not re-verified"). `SP` = `C:/Users/RITAMK~1/AppData/Local/Temp/claude/c--Users-Ritam-Kumarb-Kundu-Desktop-Broadcom-authsec-authsec/c2e9868c-f8e8-444c-9916-18d7cb9be499/scratchpad`, where the mutation logs are. `m1-wt/_shared/` and `SP` are on the build machine, not in the repository (about 10 MB of logs); they are available on request. A `p2_*_test.go` with no directory is in `tests/integration/`; the prefixes are `tg/` = `tests/igagraph/`, `ig/` = `internal/igagraph/`, `ir/` = `internal/igaread/`, `svc/` = `services/`. A bare § is the spec's; this report's own sections are cited "above" or "below"; M0's are cited "M0 §n".

---

## 1. Reproduce

§2, §3 and §11 below ran these commands. §2's first run did not set `S0_DSN`/`S1_DSN`, so its three schema-gate tests skipped there.

```bash
docker run -d --name p2pg -e POSTGRES_USER=authsec -e POSTGRES_PASSWORD=pw \
  -e POSTGRES_DB=iga_test -p 55433:5432 postgres:16

# Built from migrations/master, psql --single-transaction per file
# (m1-wt/_shared/mkdbs.sh: s0, s1, iga_int, iga_test; mkagentdbs.sh: iga_tpl):
#   s0            001-026    schema-gate tests; they SKIP without S0_DSN (tests/igagraph/schema_gate_test.go)
#   s1            001-036    schema-gate tests; they SKIP without S1_DSN
#   iga_tpl       001-036    the 036 template
#   iga_int       001-036    integration suite (IGA_TEST_DSN)
#   iga_test      empty      tests/igagraph drops and rebuilds public itself (TEST_DATABASE_URL)
#   iga_w_loadfx  = iga_tpl  load suite only (IGA_LOAD_DSN); loadEnvFor refuses the other two
docker exec p2pg psql -U authsec -d postgres \
  -c 'DROP DATABASE IF EXISTS iga_w_loadfx WITH (FORCE)' -c 'CREATE DATABASE iga_w_loadfx TEMPLATE iga_tpl'

export TEST_DATABASE_URL="postgres://authsec:pw@localhost:55433/iga_test?sslmode=disable"
export IGA_TEST_DSN="postgres://authsec:pw@localhost:55433/iga_int?sslmode=disable"
export S0_DSN="postgres://authsec:pw@localhost:55433/s0?sslmode=disable"
export S1_DSN="postgres://authsec:pw@localhost:55433/s1?sslmode=disable"
# IGA_CURSOR_SECRET: no test reads it. The integration harness signs cursors with
# readTestCursorKey (tests/integration/p2_read_harness_test.go:42); production falls back
# to a per-process random key with a warning (D-8).

go build ./... && go vet ./...
bash scripts/ci-iga-isolation-check.sh
go test -count=1 -p 1 -timeout 60m -v -run 'TestP2' ./tests/integration/ 2>&1 | tee p2.txt
# M1 also edited three older files in this package (cloud_aws_iam_scan_test.go and
# cloud_aws_workload_test.go, which hold the AWS fakes, and cloud_aws_resume_test.go, whose
# TestLeftoverCheckpointSkipsNoIdentity replaces a resume test). Their non-TestP2 tests run only
# without -run, i.e. in the whole-repo comparison (§11 below).
go test -count=1 -p 1 -timeout 60m -v ./tests/igagraph/... ./internal/igagraph/... ./internal/igaread/... 2>&1 | tee graph.txt
go test -count=1 -v ./internal/awsdiscovery/... 2>&1 | tee awsd.txt           # TestTrust*, TestS2*, TestS3a*, TestS3b*, TestP2Wdetail*
go test -count=1 -v -run 'TestS3a|TestEgates|TestP2Class' ./services/ 2>&1 | tee svc.txt  # the rest of services fails for environment reasons (§11 below)
go test -count=1 -v -run 'TestP2Class' ./internal/authz/ 2>&1 | tee authz.txt  # TestP2ClassAllows
for f in p2.txt graph.txt awsd.txt svc.txt authz.txt; do
  echo "$f pass=$(grep -cE '^\s*--- PASS' $f) skip=$(grep -cE '^\s*--- SKIP' $f) fail=$(grep -cE '^\s*--- FAIL' $f)"
done

# Load (T6.10), after tests/load/RESULTS.md §1. The recorded run also set IGA_LOAD_KEEP=1 and
# IGA_LOAD_SQL_DIR, for the §7 index measurement on the same rows; neither changes the targets.
export IGA_LOAD_DSN="postgres://authsec:pw@localhost:55433/iga_w_loadfx?sslmode=disable"
export GOFLAGS=-p=2
export IGA_LOAD_REPORT="$SCRATCH/report.md"   # optional: the §5 tables
go test -count=1 -timeout 60m -v ./tests/load/
```

## 2. Suite totals

Run on the build machine on 2026-09-25, after this report was drafted: Docker `p2pg` as in §1 above, `iga_int` recreated from `iga_tpl` and `iga_test` recreated empty before each run.

**At `9248549`** (the merged code):

| Suite | Command | Result |
|---|---|---|
| Build and vet | `go build ./...`; `go vet` on the IGA packages | ok |
| Isolation | `bash scripts/ci-iga-isolation-check.sh` | `IGA isolation passed.` |
| Integration | `go test -count=1 -p 1 -timeout 60m -v -run 'TestP2' ./tests/integration/` | `ok 719.0s`: **332 top-level tests passed, 0 failed, 0 skipped**; 203 subtests passed, 1 skipped (D-94's "under 036 as shipped", by design) |
| Graph and read packages | `go test -count=1 -p 1 -v ./tests/igagraph/... ./internal/igagraph/... ./internal/igaread/...` | `ok` (82.1 s, 0.2 s, 1.2 s): 118 top-level tests passed, 0 failed; 23 skipped: the 20 by-design D-95 subtests of the Skips list below, and the three schema-gate tests, because this run did not set `S0_DSN`/`S1_DSN` |
| services | `go test -count=1 -p 1 -v ./services/ -run 'Egates\|P2'` | `ok`, 2 passed |

How `9248549` got there: the first full run after the last merge (`0f9d850`) failed 4 of 332 -- E1, E2, E3 and E10, whose assertions predated D-96 (publication time to the second) and D-98(b) (a source's account as an object). `9248549` changed only those assertions; all 18 `TestP2Egates*` then passed, and the full run above followed.

**At `e63dfa7`** (the one test-only commit after it): `TestP2BdbIAMDeniedEndsNothing` passed with `IGA_TEST_DSN` set (both halves, 4.6 s) and skipped as a whole without it.

A full re-run of these commands at `e63dfa7`, together with a run that sets `S0_DSN`/`S1_DSN` and runs the whole `tests/integration` package without `-run`, was in progress when this report was committed; its results follow in the next commit.

**Skips.**
- **Without a DSN.** `tests/igagraph`'s graph tests skip without `TEST_DATABASE_URL` (`setupSchema`, `tests/igagraph/harness_test.go`), and its schema-gate tests without `S0_DSN`/`S1_DSN`. `internal/igaread`'s `TestP2GraphLevelRearmsEveryStatement` skips without `IGA_TEST_DSN`. Most of `tests/integration` skips without `IGA_TEST_DSN`. `tests/load`'s database tests skip without `IGA_LOAD_DSN`.
- **By design, with every DSN set.** Read from the code (the `t.Skip` sites and the `bfkLegacy` entries); not observed in a run. They are the only `t.Skip` calls in `tests/integration` and `tests/igagraph` that are not DSN guards; the unrelated skips in the `tests/integration/flows` and `tests/integration/onboarding` packages are not counted. Under §7.4 none of these 21 subtests is a pass:
  - 19 `known_gap_foreign_workspace_admitted` subtests, one per `bfkLegacy` case; there are 19 `kind: bfkLegacy` entries in `tg/p2_bfk_fk_cases_test.go` (D-95);
  - 1 `known_gap_open_section_2_9_exemptions` subtest, in `TestB9ForeignKeyCatalogGuard` (D-95);
  - 1 subtest of `TestP2BdbWorkspaceDeletionAfterProjection`, "under 036 as shipped" (D-94).

## 3. Load results (T6.10; §5.6 l.6219)

**On the merged code.** Run at `9248549` on 2026-09-25 with nothing else running, on `iga_w_loadfx` recreated from `iga_tpl` (and dropped again after): `IGA_LOAD_DSN=…/iga_w_loadfx IGA_TEST_DSN=…/iga_int TEST_DATABASE_URL=…/iga_test GOFLAGS=-p=2 go test -count=1 -timeout 60m -v ./tests/load/` → `ok 754.0s`. **All 12 tests passed** (`TestP2LoadTargets` 544.4 s, 50 iterations per read). **83 timed rows, every one within its §5.6 target** (the rows RESULTS.md's tables hold; its text counts them as 77 reads, with page-2 and variant rows folded in). Closest to target:

| Read | Group | p50 ms | p95 ms | Target ms | p95 / target |
|---|---|---:|---:|---:|---:|
| GET /resources/:id/access ("*") | Detail tabs | 198.0 | 268.5 | 300 | 90% |
| GET /resources/:id/access page 2 ("*") | Detail tabs | 199.3 | 251.8 | 300 | 84% |
| GET /resources/:id/changes ("*") | Changes | 297.9 | 381.8 | 500 | 76% |
| GET /resources facets=kind,service,account | Lists | 188.8 | 249.6 | 400 | 62% |
| GET /graph/path workload -> a resource its role reaches | Graph | 417.6 | 893.3 | 1500 | 60% |
| GET /resources/:id/changes (most-named bucket) | Changes | 228.4 | 278.6 | 500 | 56% |

Against run 2 below, the p95s are higher on the same generator: `/resources/:id/access ("*")` 219.8 → 268.5 ms, leaving 10% headroom. The cause was not investigated; the code between `3a80c78` and `9248549` adds the E-gates fix pass and the contract pass's D-98 limitations. The full tables are in Appendix A below.

**Before the merge: measured on `m1/load` @ `3a80c78`.** `tests/load/RESULTS.md`, run 2, on `iga_w_loadfx` (reported by the load agent, not re-run):
- 12 tests (40 with subtests): 40 passed, 0 skipped, 0 failed.
- 77 reads through the real route table, interleaved round-robin, 50 iterations each; every §5.6 target met.
- Closest to target: `/resources/:id/access ("*")` p95 219.8 ms of 300, `/resources/:id/changes ("*")` p95 305.7 ms of 500, `/resources` facets p95 193.7 ms of 400.
- Run 1, at `555a821` under shared load, failed with four p95 misses (`RESULTS.md` §5.1).
- The fixture has 10 000 workloads (9 823 active), 10 000 resource references, 3 550 identities and 2 000 policies. Every number comes from PostgreSQL defaults on a shared laptop.

What the fixture and harness are is in §4.18 below; the questions the numbers raise (the unapplied D-106 indexes, per-transaction plan settings, the reference environment, the hub path, and what "10 000 objects" means) are §9 entries 60–67 and 73 below.

## 4. What M1 delivered

Each item gives what it built, its branch head and merge, its principal tests, its mutation counts, and what its fix pass or merge changed. "Mutations *n*/*n*" is the count in the implement report's header, and "fix *n*/*n*" the count the fix pass reports; the rows, and what each count leaves out, are in §6 below.

### 4.0 Before the waves (5 commits on `graph`)

- **`56df9e1`, the §5.1 foundation.**
  - `internal/igaread` owns the read contract: one REPEATABLE READ, READ ONLY snapshot per request under a 3 s deadline, optional work in savepoints with a local statement timeout, the `rev` pin (`409 revision_stale`), HMAC-signed cursors, typed refs, the list and detail envelopes, and the §5.2 errors.
  - Every §5.3 route is registered as a 501 stub behind the 503 gate.
- **`e665834`, one route table.** Production and tests share `RegisterIGAGraphReadRoutes`.
- **`944cc5e`, the decisions file.** It adds `P2-DECISIONS.md` and the `ValidateTrustDocument` seam between T3.1 and T3.4.
- **`76003e1`, corrections.** D-41, D-55 and D-57 corrected; D-60–D-67 added.
- **`33c8df7`, the adversarial audit** (`audit.md`): 32 corrections and 26 new entries, D-68–D-93.
- **Tests**, all in `tests/integration/p2_read_snapshot_test.go`: `TestP2ReadDoesNotStraddleAPublication` (B16), `TestP2ReadRevisionStale`, `TestP2ReadCursorBinding`, `TestP2ReadOptionalTimeoutKeepsTheSnapshot` (B23, first clause), `TestP2ReadMandatoryTimeoutIs504` (B23, third clause), `TestP2ReadGraphUnavailable` (T6.9, added by `e665834`).

### Wave A

#### 4.1 `trust`: trust parser and trust projection (T3.4 l.6295, T4.7 l.6311; §4.7 *Trust* l.4364)

**What it built.**
- **Parser.** It reads Allow and Deny statements, every principal form, conditions verbatim (non-string values included) and `NotPrincipal`, and it isolates each statement. A skipped statement makes the whole document unreadable (D-45).
- **Projection.** It writes `can_assume` edges and external principals under D-41–D-47 and D-88:
  - Keys are the trust statement key plus the source and target endpoint keys. No edge is re-pointed in place.
  - A live external principal stays the source. When its account connects, it gains a derived `exact_arn_match` resolution.
  - Pod identity is a separate `k8s_service_account` node, with a `pod:` subject.
- **Role attributes.** Roles carry `trust_has_deny`, `trust_has_not_principal` and `trust_negated_statements`.

**Branch.** `m1/trust` (head `2b92e8f`), merged as **`c7b6692`**.

**Principal tests.**
- `internal/awsdiscovery/p2_trust_parse_test.go`: `TestTrustNonStringConditionValueParses` (the T3.4 gate), `TestTrustMalformedStatementIsolated`, `TestTrustPrincipalForms`, `TestTrustContentHash`.
- `internal/igagraph/p2_trust_keys_test.go`: `TestTrustEdgeKeyNamesItsEndpoints`.
- `tests/igagraph/p2_trust_projection_test.go`: `TestTrustWholeDocumentUnreadableNowFailsThePass`, `TestTrustLiveExternalPrincipalsAreThisWorkspaces`, `TestTrustRetiredRoleEndsItsExternalEdges`.
- `tests/integration/p2_trust_lab_test.go`: `TestP2TrustPrincipalsAppear` (the T4.7 gate; E11), `TestP2TrustUnreadableDocumentKeepsItsEdges`, `TestP2TrustFarAccountConnectsLater`, `TestP2TrustLoopProjectsBothEdges`, `TestP2TrustRecreatedTrustedRole`, `TestP2TrustRecreatedRoleInheritsNoTrustFlags`.
- `tests/integration/p2_trust_pod_test.go`: `TestP2TrustPodIdentityEvidenceRatchet`.

**Mutations.** 48/48; the summary's "52 in total" also counts four first attempts that only broke the build (§6.3 below).

**Fixed by the fix pass or at merge.**
- **Fix pass `2b92e8f`** (7 fixed, 1 rejected):
  - A failed `DescribePodIdentityAssociation` now makes `eks_pod_identity` partial. Before, the binding ended.
  - Three safeguards the review found uncovered now have tests that catch its mutants M1–M3 (workspace scoping of live external principals, the recreated-role flag check, the whole-document hard error). The pod-identity evidence gap got a §8 ratchet (`TestP2TrustPodIdentityEvidenceRatchet`) and a byte pin of `PodIdentitySubjectKey` (`TestTrustEdgeKeyNamesItsEndpoints`).
  - A `"Principal": "*"` statement yields an edge for any assume action.
  - Rejected: writing the pod-identity observation. That is T3.5's writer, and it landed in `m1/s3b`.
- **Merge `c7b6692`.** One conflict, in `services/cloud_aws_iam_scan.go`.
- **Merge `1728342`.** The s3b merge replaced trust's `PodIdentityDetailFailures` with s3b's `ItemFailures` and flipped the evidence ratchet (`trustPodEvidenceWriterLanded = true`, `tests/integration/p2_trust_lab_test.go:218`).
- **Change to an M0 expectation.** `TestP2UnchangedRescan` now expects 2 relationships and 1 external principal. The lab role's Lambda trust is now projected (§4.12).

#### 4.2 `s3a`: IAM collection (T3.1 l.6292, T3.3 l.6294, the policy half of T3.5 l.6296; §1.4 l.187)

**What it built.**
- **Collection.** `GetAccountAuthorizationDetails` replaces the per-role and per-user calls. It makes one paginated call per filter, and each filter has its own surface state (D-48).
  - Customer-managed documents come from the LocalManagedPolicy listing at their default version.
  - AWS-managed attached and boundary policies are fetched through `GetPolicy`/`GetPolicyVersion` and cached per scan (D-50).
  - Memberships are resolved against the same read. Users get tags and boundaries, and roles get instance profiles in `attrs` (D-52).
- **Per-document isolation.**
  - A failed call names the call and AWS's error code (`APICallError`).
  - An unusable statement makes its document unreadable (D-49).
  - `policy_documents` becomes partial and names each document as bounded items (D-71).
  - Policy-version observations use the `policy_id` subject.

**Branch.** `m1/s3a` (head `aa0d594`), merged as **`13e47f0`**.

**Principal tests.**
- `tests/integration/p2_s3a_authdetails_test.go`: `TestP2S3aUserInGroupWithBoundary` (the T3.1 gate; E3, E4), `TestP2S3aOneUnreadableDocumentIsolated` (the T3.3 gate), `TestP2S3aAWSManagedPolicyInTwoAccounts`, `TestP2S3aUnusableStatementMarksDocumentUnreadable`, `TestP2S3aPerFilterSurfaceStates`, `TestP2S3aPaginationAcrossPages`, `TestP2S3aRescanReplacesListedAttrsKeepsUnlisted`, `TestP2S3aTrustDocumentStoredAndJudged`.
- `p2_s3a_malformed_documents_test.go`: `TestP2S3aMalformedDocumentsIsolated`.
- `p2_s3a_orphaned_evidence_test.go`: `TestP2S3aDeletedPolicyEvidenceNeverBlocksReconcile`.
- `internal/awsdiscovery/p2_s3a_authdetails_test.go`: `TestS3aAuthorizationDetailsOneCallPerFilterAcrossPages`, `TestS3aAuthorizationDetailsFailuresArePerFilter`.

**Mutations.** 42/42 (§6.3 below).

**Changes to M0 tests.**
- `TestP2UnreadableAndDetachedInOneRun` (M0 scenario 4, B12) is re-expressed under D-51: the `GetPolicyVersion` denial is now on an attached AWS-managed `TicketRead`.
- In `TestP2TwoAccountsOneBucket`, account B's policy is now removed (detached and deleted), not merely detached, because a detached customer-managed policy is still listed.
- `TestScanResumesPastIdentitiesAlreadyDone` became `TestLeftoverCheckpointSkipsNoIdentity`, because authorization details leave no per-identity phase to resume.

**Fixed by the fix pass or at merge.**
- **Fix pass `aa0d594`** (4 fixed, 1 rejected):
  - **Orphaned observations.** Two orphaned observations with equal facts collided on `uq_cloud_observation_dedupe_no_subject`, and that failed `ReconcileGeneration` on the first detach of a two-resource statement. Facts are now stamped with their subject row before hashing.
  - **New tests** for malformed and absent documents.
  - **D-48 keep-merge.** It now applies only when `unique_id` matches, so a recreated role inherits nothing.
  - Rejected: surfacing a `ReconcilePolicies` failure in coverage. §4.10 defines no surface key for it.
- **After merge, `ac7519d`.** The lists tests were re-staged through T3.1's calls (see §4.6 below).

#### 4.3 `s3b`: workload collection (T3.5 l.6296, T3.6 l.6297, T3.7 l.6298, T3.8 l.6299)

**What it built.**
- **Evidence (T3.5).** Access-key observations are keyed by key id and CloudTrail events by event, so neither is edge evidence. Pod-identity observations are keyed by association; after merge `12b0a23` each is evidence on exactly its own pod-identity `can_assume` edge and on no other edge of the role (`TestP2S3bPodIdentityEvidenceIsTheAssociations`). Gateways get a real `source_api`.
- **Detail-call failures (T3.6).** A failed `GetAgent`, `GetGateway`, `ListGatewayTargets`, `DescribeTaskDefinition`, `GetInstanceProfile` or `GetAgentRuntime` keeps the item; Bedrock agents and gateways are keyed by an ARN constructed in the connector's partition, and an ECS task definition stays under its listed ARN. The surface becomes partial, and the execution role is left as it was (D-53).
- **Activity (T3.7).** Activity is partial above the 500-identity cap, sampled by ARN (D-86), and throttled on a throttle. Resource-policy reads follow D-93.
- **Coverage (T3.8).** `organizations` is reported `unsupported`, and so is a service whose regional endpoint does not resolve, unless an earlier scan found that kind of workload there (then `denied`; D-93).

**Branch.** `m1/s3b` (head `5060774`), merged as **`1728342`**.

**Principal tests.**
- `tests/integration/p2_s3b_workload_detail_test.go`: `TestP2S3bFailedGetAgentKeepsKeyAndBlocksDeletion` (the T3.6 gate; E7, E9), `TestP2S3bFailedGetGatewayIsPartialAndKeepsTheKey`, `TestP2S3bNewAgentWithFailedDetailIsNotProjectedAsNone`.
- `p2_s3b_evidence_test.go`: `TestP2S3bEverySurfaceWritesEvidence` (the T3.5 gate), `TestP2S3bAccessKeyEvidenceAttachesToTheCredentialAndDedupes`, `TestP2S3bCloudTrailEventIsNotEdgeEvidence`, `TestP2S3bPodIdentityEvidenceIsTheAssociations`.
- `p2_s3b_coverage_test.go`: `TestP2S3bOrganizationsIsReportedUnsupported` (the T3.8 gate), `TestP2S3bActivityIsPartialAboveTheCap`, `TestP2S3bActivityThrottledOnThrottle`, `TestP2S3bResourcePolicyFailuresAreCounted`.
- `p2_s3b_surface_reconcile_test.go`: `TestP2S3bWorkloadDeletionIsPerSurface`, `TestP2S3bConstructedARNUsesTheConnectorPartition`.
- `internal/igagraph/sourcekey_test.go`: `TestWorkloadKeyUsesTheConnectorPartition`.

**Mutations.** 40/40, fix pass 23/23 (§6.3 below).

**Fixed by the fix pass or at merge.**
- **Fix pass `5060774`** (10 fixed, 3 rejected):
  - Workload deletion is scoped to each `<svc>:<region>` surface. Before, one partial surface blocked deletion for the whole connector.
  - Bare-id rows are adopted by their ARN.
  - `eks_pod_identity` counts every failure.
  - Rejected (finding 9): projecting a never-seen workload whose first detail call fails. 029 has no `unknown` state (D-53).
- **Merge `1728342`**, conflicts with s3a and trust:
  - s3b's `ItemFailures` supersede trust's type.
  - `SurfaceCoverage` becomes the union of s3a's and s3b's fields.
- **After merge, `6f9b3ff`.** `WorkloadKey` is now partition-aware, and `/lookup` did not compile against it (see §4.6 below).

#### 4.4 `s2`: connect, configure, observe (T2.1–T2.4 l.6283–6286; §5.3 *Integration* l.5750, §2.14.7 l.1490)

**What it built.**
- **Regions (T2.1).** `GET …/regions` calls `ec2:DescribeRegions` and marks each region selected or not. `PATCH …/connectors/:id` validates against the enabled regions (`422 invalid_region`, `422 regions_unavailable`; D-54, D-90), and a run keeps the regions it was claimed with.
- **Scan-run history (T2.2).** `GET …/connectors/:id/scan-runs` lists runs, and `GET …/scan-runs/:id` gains a `projection` object (D-91).
- **Pipeline and coverage (T2.3).** `/pipeline` reports queued-behind, collecting, projecting and published (D-55, D-56, D-59, D-92). `/coverage` is built from the runs the revision stands on (D-58, D-72).
- **Template (T2.4).** It adds `bedrock-agentcore:GetGateway` and `ec2:DescribeRegions`, and `TemplateVersion` becomes `"2026-09-23"`.
- **Refused calls.** A call refused under the assumed role (other than STS) is `ErrCallDenied` and names the call.

**Branch.** `m1/s2` (head `230535e`), merged as **`12b0a23`**.

**Principal tests.**
- `tests/integration/p2_s2_regions_test.go`: `TestP2S2RegionPatchNamesTheOffenders`, `TestP2S2RegionChangeAppliesFromTheNextScan` (the T2.1 gate; E1), `TestP2S2DeniedDescribeRegionsIsAClearError`, `TestP2S2SigningRegionIsNeverAnOptInSortedFirst`.
- `p2_s2_scan_runs_test.go`: `TestP2S2ScanRunHistoryShowsEveryEnding` (the T2.2 gate).
- `p2_s2_pipeline_test.go`: `TestP2S2PipelineQueuedBehindCollectingProjecting` (the T2.3 gate), `TestP2S2PipelineAccountsAtTheCurrentRevision`.
- `p2_s2_coverage_test.go`: `TestP2S2CoverageFromTheCurrentRevision`.
- `p2_s2_coverage_merge_test.go`: `TestP2S2CoverageMergesTheRunsTheRevisionStandsOn`.
- `p2_s2_pod_identity_test.go`: `TestP2S2DeselectedRegionKeepsPodIdentityBindings`.
- `internal/awsdiscovery/p2_s2_regions_test.go`: `TestS2TemplateVersionDeclaredConsistently`.
- `internal/igaread/p2_s2_pipeline_state_test.go`: `TestS2PreventsMapping`.

**Mutations.** 38/38. The fix pass reports the reviewer's A (M2a), B (M3a) and D (M5a, M5b) caught, and one equivalent mutant, M7e, not caught (§6.3 below).

**Fixed by the fix pass or at merge.**
- **Fix pass `230535e`** (10 fixed, 0 rejected):
  - Deselecting a region deleted its EKS pod-identity bindings. They now stay stale.
  - `regions_ever_selected` keeps a `not_selected` stand-in for every region deselected earlier.
  - `/coverage` takes older runs only for the partitions still standing on them.
  - `/pipeline` reads a fixed amount per connector (`TestP2S2PipelineReadsAFixedAmountPerConnector`).
  - The signing region is never an opt-in region that sorts first.
- **Merge `12b0a23`.** The failed-call naming of s3a, s3b and s2 is chained in `surfaceResult`, and the pod-identity region handling of s2 and s3b is joined.

#### 4.5 `class`: classification (T6.6 l.6333; §5.5 l.6161, §2.14.3)

**What it built.** `POST /workloads/:id/classification` runs §5.5's transaction at READ COMMITTED with `SET LOCAL lock_timeout '3s'` (D-31). The order is:
1. `FOR UPDATE` on the workspace's supported AWS row.
2. Operation lookup: a replay answers `200 replayed:true`; the same id with a different D-29 hash answers `422 operation_id_reused`.
3. Provider-native: `422`.
4. Version check: `409 classification_conflict` with the current decision.
5. The D-30 rules.

`GET …/classification` returns the history. `igaread` adds `ClassificationSeq`/`CheckClassificationSeq` (`409 listing_changed`), `CanClassify` (D-83) and display names (D-32).

**Branch.** `m1/class` (head `fcfe33e`), merged as **`df6769b`**.

**Principal tests**, all in `tests/integration/p2_class_decision_test.go`:
- B22 and E12: `TestP2ClassConcurrentRetriesReplay` (B22), `TestP2ClassRetryStormReplays`, `TestP2ClassRetryAfterVersionMovedReplays` (E12).
- Error codes: `TestP2ClassOperationReusedIs422`, `TestP2ClassStaleVersionIs409WithCurrentDecision`, `TestP2ClassDecisionRulesComeAfterTheVersion`.
- Guards: `TestP2ClassRequiresAVerifiedHuman`, `TestP2ClassCrossWorkspaceIs404` (E14), `TestP2ClassClockAndListingChanged`, `TestP2ClassLockWaitIsBounded`.
- Added by the fix pass: `TestP2ClassOperationIdIsPerWorkspace`, `TestP2ClassLockTimeoutIsTransactionScoped`.

**Mutations.** 35/36 in the header; the one not caught, #37a, is an equivalent mutant (§6.3 below).

**Fixed by the fix pass or at merge.**
- **Fix pass `fcfe33e`** (6 fixed):
  - The operation lookup is proven workspace-scoped.
  - `SET LOCAL` is proven transaction-scoped.
  - A NUL in `reason` or `purpose` is now `400`, not `500`.
  - `features.classification` follows the switch.
- **Merge `df6769b`.** `graphFeatures` becomes one table gated on the switch (D-11).
- **Wave C, in `m1/egates` `d0f716c`.** The `TestP2ClassConcurrentRetriesReplay` flake is fixed. Its waiter gave up 2 s after it started, by wall-clock time. The staging waits are now bounded at 1 min and count only the staged statement (`egates_fix_report.md`).

#### 4.6 `lists`: lists and lookup (T6.2 l.6329, T6.8 l.6335, route permissions T6.7 l.6334; §5.2, §5.3)

**What it built.**
- **Lists.** `/workloads`, `/identities` and `/resources` each run one keyset-paged statement per page.
  - Cursors are signed and bound to the workspace, revision, route, filter hash and sort, and to the classification clock when the list filters or sorts on classification.
  - The lists support `q` (D-76), the D-13 sorts, D-14 facets, `CountUpTo` totals (D-15), `meta.coverage` (D-73), `stale_reason` (D-74) and the D-75 filters.
- **Lookup.** `GET /lookup` matches a Cloud Inventory row on the source key and immutable key and requires a support row from the row's own connector (D-81). It never matches by name.
- **Route test.** A table-driven test checks the permission and the cross-workspace `404` of every registered route.

**Branch.** `m1/lists` (head `a89ee8d`), merged as **`bca9963`**.

**Principal tests.**
- `tests/integration/p2_lists_test.go`: `TestP2ListsSearchFindsRowBeyondPageOne` (the T6.2 gate), `TestP2ListsDuplicateNamesAcrossAccounts` (E2), `TestP2ListsResourcesKindsAccountsAndFacets`, `TestP2ListsCursorBinding`, `TestP2ListsClassificationChangeBetweenPages`, `TestP2ListsIntegrationNeedsLiveSupport`.
- `p2_lists_coverage_test.go`: `TestP2ListsCoverageAndStaleRows`, `TestP2ListsResourceCoverageKeepsOtherScannersGaps`.
- `p2_lists_lookup_test.go`: `TestP2ListsLookupByKeyNeverByName` (E16), `TestP2ListsLookupSameNameInOneAccount`.
- `p2_lists_routes_test.go`: `TestP2ListsRoutesPermissionsAndCrossWorkspace` (T6.7, E14).
- `p2_lists_usedby_test.go`: `TestP2ListsUsedByCountsDistinctWorkloads`.

**Mutations.** 47/47 (§6.3 below).

**Fixed by the fix pass or at merge.**
- **Fix pass `a89ee8d`** (4 fixed): `/resources` coverage is no longer narrowed by the scanning connector's account (D-3). Three untested safeguards now have tests.
- **Merge `bca9963`.** One conflict, in `internal/igagraph/load.go`. The merge message names only the file; both the trust and the lists reports record a one-line D-61 filter there.
- **After merge, `6f9b3ff`.** `/lookup` builds the workload key in the connector's partition. The merge did not compile after s3b changed `WorkloadKey`.
- **After merge, `ac7519d`.** The lists tests now stage their gaps through T3.1's calls:
  - they deny the User filter;
  - they use AWS-managed policies for unreadable documents (D-51);
  - "stops naming" now deletes the policy.

#### 4.7 After Wave A: `3ea0244`, D-57 partition keys and the cumulative manifest (033 l.2888–2890, §4.8, §4.10)

**What it changed.**
- `Partition.Key()` now begins with the estate scope and the connector. The scope is resolved right after the replay check, before any key is computed.
- `manifestOf` overlays this run's partitions on the previous publication's manifest (`LatestManifest`). Before, two accounts' keys collided, and a revision's manifest named only one run.
- No migration was needed: no key had been persisted outside test databases. D-60 freezes the key format from the first deployment.

**Tests.** `tests/integration/p2_manifest_test.go`: `TestP2ManifestIsCumulativeAcrossAccounts`, `TestP2PartitionKeysCarryTheRealScope`. The commit message reports three mutation checks; they were not re-verified (§6.4 below).

### Wave B

#### 4.8 `changes`: Changes, and the D-26 single clock (T5.4 l.6322; §5.3 *Changes* l.6038)

**What it built.**
- **D-26.** The projector reads its clock once per pass (`Projector.At`, normalised by `igagraph.PassTime`). Every `valid_from`, `valid_to`, `last_confirmed_at`, `first_seen_at`/`last_seen_at` and lifecycle `occurred_at` the pass writes equals the publication's `published_at`, and the graph repository refuses a write without it (`ErrNoPassTime`).
- **Changes routes.** `GET /{workloads|identities|resources}/:id/changes` returns:
  - lifecycle events, read only from `iga_lifecycle_event` (B24);
  - relationship, assignment and grant starts and ends;
  - `statement_revised` and `statement_replaced`, and `coverage_changed`;
  - `remaining` and `paths` on ends (D-28).
- **Scope and paging.** Scope follows D-68. Paging is keyset on `(at, event, id)` (D-27, D-27a–g).

**Branch.** `m1/changes` (head `068847a`), merged as **`68e2a36`**.

**Principal tests.**
- `tests/integration/p2_changes_test.go`: `TestP2ChangesDetachNamesRemainingGrant` (the T5.4 gate; E6), `TestP2ChangesRemainingStaleGrant`, `TestP2ChangesDetachOwnStaleGrantIsNoPath`.
- `p2_changes_history_test.go`: `TestP2ChangesPolicyEdits` (E7), `TestP2ChangesRecreatedRoleAndPolicy` (E8), `TestP2ChangesLifecycleSurvivesNodeRewrites` (B24), `TestP2ChangesWorkloadWindowOnItsRole`, `TestP2ChangesRestoredStatementIsNotARevision`.
- `p2_changes_d26_test.go`: `TestP2ChangesOnePassOneTimestamp`.
- `p2_changes_paging_test.go`: `TestP2ChangesPaging`, `TestP2ChangesCoverageKind`.
- `p2_changes_effect_test.go`: `TestP2ChangesAllowEditedToDeny`.
- `p2_changes_replaced_test.go`: `TestP2ChangesReplacementVersionsAndIDs`.

**Mutations.** 15/15, fix pass 17/17 (§6.4 below).

**Fixed by the fix pass or at merge.**
- **Fix pass `068847a`** (11 fixed, 0 rejected):
  - `statement_replaced` carries D-69's `policy_version_id`.
  - Grant history is judged by the statement revision in force at `valid_from` (new D-27g).
  - A replacement's id is derived from (policy, run).
  - `history_begins` is `null`, not `500`, when there is no `first_seen` event.
  - The cross-workspace probe now reaches the workspace predicate.
- **Wave C, in `m1/load`.** The Changes union was rewritten for T6.10 (§4.18 below).

#### 4.9 `wdetail`: workload detail and tabs (T6.3 l.6330; §5.3 *Agents & workloads* l.5796)

**What it built.**
- **`/workloads/:id`** is built from the list's own row builder. It adds `continuity`, D-85's `provider_attrs`, `sources`, the latest `decision` and `meta.capabilities.can_classify` (D-83).
- **`/workloads/:id/identities`** has the sections `execution`, `other`, `groups` and `may_assume`, each paged (D-77, D-62).
- **`/workloads/:id/resources`** has one line per grant, joined to an Allow statement through an attached or inline assignment with `mode = resource` targets. Holders follow D-78, and restrictions are holder-level.
- **Projector.** It now writes the workload's `provider_attrs` from `cloud_workload` attrs.

**Branch.** `m1/wdetail` (head `3fe1433`), merged as **`a070111`**.

**Principal tests.**
- `tests/integration/p2_wdetail_detail_test.go`: `TestP2WdetailDetailShape`, `TestP2WdetailRetiredWorkloadReadable` (E8), `TestP2WdetailNotFound` (E14), `TestP2WdetailCanClassifyAndDecision`.
- `p2_wdetail_identities_test.go`: `TestP2WdetailIdentitiesSharedRoleAndMayAssume` (B1, E5), `TestP2WdetailExecutionRoleStates`, `TestP2WdetailECSTaskExecutionRoleIsOther`.
- `p2_wdetail_resources_test.go`: `TestP2WdetailResourcesTwoLinesThenDetach` (E3, E6), `TestP2WdetailResourcesNotResource` (B19), `TestP2WdetailResourcesDenyAndBoundaryAreRestrictions` (B10).

**Mutations.** 34/34 (§6.4 below).

**Fixed by the fix pass or at merge.**
- **Fix pass `3fe1433`** (8 fixed):
  - Section totals follow the list rule.
  - An unread Lambda environment is `null`, not `[]` (`internal/awsdiscovery/p2_wdetail_env_test.go`: `TestP2WdetailLambdaEnvironmentUnreadIsNotEmpty`).
  - Gateway targets are written only when the list was read in full.
  - `may_assume` coverage names the trusting accounts.
  - One surviving mutant was a redundant gate, which was removed.
- **Merge `a070111`.** One conflict, in `iga_graph_read_controller.go`.

#### 4.10 `idetail`: identity and external-principal detail (T6.3 l.6330; §5.3 *Identities* l.5883, *External principals* l.5925)

**What it built.**
- **`/identities/:id`** adds `continuity`, `immutable_key`, `sources`, D-85's `provider_attrs` and credentials (D-86).
- **`/identities/:id/used-by`** has workload, principal and member sections, one row per claim.
- **`/identities/:id/permissions`** is grouped by policy:
  - Statements are 1-based (D-84) and verbatim.
  - The grant is looked up only for Allow statements.
  - The boundary gets its own section, and the user's groups are listed under `inherited`.
  - Access Advisor activity is keyed to the revision's run.
  - The response is capped at 1000 statements.
- **`/external-principals/:id` and `/referenced-by`** follow D-87, with state derived from the principal's edges (D-47).

**Branch.** `m1/idetail` (head `ba3377e`), merged as **`f76c1b2`**.

**Principal tests.**
- `tests/integration/p2_idetail_identity_test.go`: `TestP2IdetailIdentityOverview`, `TestP2IdetailRetiredIdentityReadable` (E8), `TestP2IdetailNotFound`.
- `p2_idetail_usedby_test.go`: `TestP2IdetailUsedBySharedRole` (E5).
- `p2_idetail_permissions_test.go`: `TestP2IdetailPermissionsUserGroupBoundary` (E4), `TestP2IdetailPermissionsNeverGrantBoundaryOrDeny`.
- `p2_idetail_external_test.go`: `TestP2IdetailExternalPrincipals` (E11), `TestP2IdetailExternalResolvedAndRetired`, `TestP2IdetailExternalConnectedAsOfRevision`.
- `p2_idetail_history_test.go`: `TestP2IdetailPermissionsLeftGroup`, `TestP2IdetailActivityNewerScanNotMixed`.

**Mutations.** 42/42, fix pass 22/22, run as `go test -overlay` builds (§6.4 below).

**Fixed by the fix pass or at merge.**
- **Fix pass `ba3377e`** (11 fixed):
  - A user inherits only through a live `member_of`.
  - `account_connected` is computed as of the revision, not from live connector state.
  - Retired statements appear only with `include_ended`.
  - Access Advisor rows must be from the run's exact generation (`newer_scan_not_published`).
  - Credential status is AWS's `Active`/`Inactive`.
- **Wave C, contract `2e89004`.** `provider_attrs` has one shape for every kind (D-102(d)).

#### 4.11 `rdetail`: resource detail and Access (T6.3 l.6330; §5.3 *Resources* l.5934)

**What it built.**
- **`/resources/:id`** is the list row plus `existence: "not_verified"`, `resource_policy {read, has_deny}` scoped to the revision (D-19), and `sources`, one per support row.
- **`/resources/:id/access`:**
  - It returns one row per (holder, grant), and group-held grants are expanded to members (D-18).
  - `excluded_by` and `deny_statements_naming` are capped lists.
  - Pages are cut on holders (later D-99).

**Branch.** `m1/rdetail` (head `69cfb22`), merged as **`6d0bb0a`**.

**Principal tests.**
- `tests/integration/p2_rdetail_access_test.go`: `TestP2RDetailAccessTwoStatementsOneHolder` (E3, E6), `TestP2RDetailNotResourceExcludes` (E4, B19), `TestP2RDetailDenyIsARestrictionNotAccess` (B10), `TestP2RDetailGroupHeldGrantExpandsToMembers`.
- `p2_rdetail_detail_test.go`: `TestP2RDetailSourcesTwoAccounts` (B3, E10), `TestP2RDetailResourcePolicy`, `TestP2RDetailResourcePolicyConfirmations`, `TestP2RDetailCoverageEveryGapThatBears`, `TestP2RDetailNotFoundRetiredAndParameters`.

**Mutations.** 38/38, fix pass 15/15; two implement-stage "catches" were compile errors (§6.4 below).

**Fixed by the fix pass or at merge.**
- **Fix pass `69cfb22`** (8 fixed, 2 rejected):
  - `resource_policy` failed on deduplicated re-reads: the query trusted the first recorder's publication.
  - Detail coverage now includes every gap that bears on the resource.
  - The `cloud_observation` workspace filter is now tested.
  - Rejected: an index for the `resource_policy` read, and the `*` Access build. Both were measured and neither missed a §5.6 target. The `*` page was reworked in T6.10 anyway (§4.18 below).
- **Merge `c445404`.** `/evidence`'s `resource_policy_not_projected` now reads through `ResourcePolicyOf`, so there is one D-19 rule.

#### 4.12 `graph`: traversal (T6.4 l.6331; §5.3 *Graph* l.5956, §5.4 l.6069)

**What it built.** `/graph`, `/graph/expand` and `/graph/path` walk breadth-first inside the §5.1 snapshot, with one query per edge kind per level and each level in a savepoint.
- **Edge rules.** A grant reaches only Allow statements. Targets are `mode = resource` only; NotResource entries become `exclusions`. Deny statements and boundaries are restrictions.
- **Cycles.** One visited set per request. `closes_cycle` marks the edge back onto the path.
- **Terminals and budgets.** External principals are terminal. The budgets are nodes 500, edges 2000, `assume_hops` 4 and paths 200, with D-40's time reserve.
- **`none_exists`** only when both frontiers are exhausted before any budget binds (D-38).

**Branch.** `m1/graph` (head `a4c2205`), merged as **`4cf0596`**.

**Principal tests.**
- `tests/integration/p2_graph_teaching_test.go`: `TestP2GraphTeachingPathForward` (E3).
- `p2_graph_exclusions_test.go`: `TestP2GraphNotResourceIsNeverAnEdge` (B19), `TestP2GraphDenyAndBoundaryAreRestrictions` (B10).
- `p2_graph_trust_test.go`: `TestP2GraphCycleClosesAndIsNotReexpanded`, `TestP2GraphCrossAccountEdge`, `TestP2GraphExternalPrincipalIsTerminal` (all E11).
- `p2_graph_budgets_test.go`: `TestP2GraphNodeAndEdgeBudgets` (B17), `TestP2GraphPathNoneExistsOnlyWhenExhausted`, `TestP2GraphTimeBudgetTruncates` (B23, second clause), `TestP2GraphRootTimeoutIs504`.
- `p2_graph_orientation_test.go`: `TestP2GraphPathEitherOrientation`.
- `p2_graph_lifecycle_test.go`: `TestP2GraphEndedEdgesOnlyWhenAsked`.

**Mutations.** 29/29, fix pass 29/29 (§6.4 below).

**Fixed by the fix pass or at merge.**
- **Fix pass `a4c2205`** (10 fixed, 1 rejected):
  - A reverse-orientation `/graph/path` gave a definitive `none_exists`. The search now also runs the other way.
  - The lifecycle filters on reverse grants, reverse targets and frontier counts had no test that failed without them; they now do (review findings 2, 3 and 5).
  - Group grants now carry D-22's member boundary.
  - Stale targets and principals now have a `stale_reason`.
  - `/graph/expand` now checks D-40's reserve.
  - Nested reads are re-armed per level (`traverse_level.go`).
  - Rejected: `200 not_published` for the graph routes. D-4 keeps them at `404`.
- **Merge `4cf0596`.** One conflict, in `iga_graph_read_controller.go`.
- **Wave C.** Contract (D-98(a)) moved node and edge limitations onto `/evidence`'s computation. egates (D-105) took `resolution_not_followed` out of `/graph`'s `truncated`.

#### 4.13 `evidence`: `/evidence` (T6.5 l.6332; §5.3 *Evidence* l.5990)

**What it built.**
- **Claims.** It accepts grant, assignment, relationship, target, presence and `coverage:<run>:<surface>` claims, and object refs (D-65). A request may repeat `claim` 1–50 times (D-79).
- **Response parts.** Each claim returns:
  - a sentence composed from the claim rows;
  - a status (D-20, D-80);
  - facts from `supports` junction rows, keeping only sources that bear on the claim type (D-24);
  - freshness (D-23, D-80);
  - the §5.3 limitation vocabulary, each code only when its condition holds (D-21, D-22, D-58, D-88).
- **For the graph routes.** `Query.ClaimLimitations` exposes the same computation (D-35).

**Branch.** `m1/evidence` (head `7b978c7`), merged as **`c445404`**.

**Principal tests.**
- `tests/integration/p2_evidence_limitations_test.go`: `TestP2EvidenceLimitationVocabulary` (the T6.5 gate; E4), `TestP2EvidencePlainGrantCarriesOnlyWhatApplies`, `TestP2EvidenceDenyOnlyWhileAssignedAndMember`.
- `p2_evidence_route_test.go`: `TestP2EvidenceGrantFactsAndShape`, `TestP2EvidenceNotResourceGrant` (B19), `TestP2EvidenceClaimLimitationsMatchTheRoute`, `TestP2EvidenceErrors` (E14).
- `p2_evidence_asof_test.go`: `TestP2EvidenceFactsIgnoreAnUnprojectedRun`, `TestP2EvidenceEndedGrantKeepsItsContent`.
- `p2_evidence_guards_test.go`: `TestP2EvidenceDenyIsNeverAGrant`.

**Mutations.** 41/41, fix pass 15/15 (§6.4 below).

**Fixed by the fix pass or at merge.**
- **Fix pass `7b978c7`** (11 fixed):
  - Facts could come from an unprojected run.
  - Ended and stale claims are now described by the content as of their own run (`contentAsOf`).
  - The Deny-statement filters are now tested.
- **Merge `c445404`.** Duplicate symbols from parallel items were resolved (`ExternalPrincipalAccount` / `ExternalPrincipalAccountID`, one `ResourcePolicySourceAPIs`, one `stringOrList`). All eight `/capabilities` features are `true` when the switch is on.

### Wave C

#### 4.14 `bdb`: the §7.3 B-proofs against PostgreSQL (§7.3 l.6507)

**What it built.**
- **Proofs through the pipeline:** B1, B4 (with its `reached` non-vacuity half), B8 (identity, policy and statements, and a returning workload that is a new object), the B10 database half, B11, B13, B21's inline half, B24 and E1.
- **Unit tests for §4.10:** B18's `scope()` half (its attach → detach → reattach half is M0's `TestP2AttachDetachReattach`) and node classes, on a gorm DryRun handle with no database.
- **Proofs for T4.4 and T4.9:** `member_of` and `task_execution_role` over five cycles, and an evidence audit of every edge kind.
- **D-61 through the pipeline:** a revoked account is not connected, for trust resolution and for `account_connected`.
- **One production fix, D-64.** `UpsertCredential` updates a key's existing row regardless of lifecycle. Before, every pass inserted another `revoked` row.

**Branch.** `m1/bdb` (head `98d75d9`), merged as **`9acf2d1`**.

**Principal tests** (`tests/integration/p2_bdb_*_test.go`): `TestP2BdbTwoWorkloadsShareOneRole` (B1), `TestP2BdbIAMDeniedEndsNothing` (B4), `TestP2BdbRestoredIdentityKeepsItsIdentity` / `TestP2BdbRestoredPolicyKeepsItsStatements` / `TestP2BdbReturningWorkloadIsANewObject` (B8), `TestP2BdbBoundaryAndDenyGrantNothing` (B10), `TestP2BdbStatementIdentity` (B11), `TestP2BdbSwitchOffLeavesTheIdleBarrier` (B13), `TestP2BdbRecreatedRoleInlinePolicyIsANewIncarnation` (B21), `TestP2BdbLifecycleHistorySurvivesRewrites` (B24), `TestP2BdbFirstPublication` (E1), `TestP2BdbMemberOfAndTaskExecutionRole` (T4.4), `TestP2BdbEveryEdgeHasEvidence` (T4.9), `TestP2BdbRevokedAccountIsNotConnected` (D-61), `TestP2BdbInactiveKeyKeepsOneRow` (D-64), `TestP2BdbWorkspaceDeletionAfterProjection` (D-94). Also `internal/igagraph/p2_bdb_scope_test.go`: `TestP2BdbEveryPartitionTargetResolvesInScope` (B18, `scope()` half), `TestP2BdbEveryNodeClassResolves`.

**Mutations.** 30/30; the fix pass re-ran 29 of them at `1046c1a`, all caught (§6.2 and §6.5 below).

**Fixed by the fix pass or at merge.**
- **Review.** It found no code defect and raised 3 minors.
- **Fix `1046c1a`:**
  - The deletion test no longer pins the defect. Under the proposed DDL it asserts the correct delete; under `036` as shipped it skips, naming D-94.
  - D-67 now covers a replaced Sid-less statement: its grant ends `not_seen`.
- **Fix `98d75d9`.** The B21 header is corrected, and the B11(c) message prints values instead of pointers.
- **Merge `9acf2d1`.** The merge commit has no message body.
- **After HEAD, `e63dfa7`.** `TestP2BdbIAMDeniedEndsNothing` now skips as a whole without `IGA_TEST_DSN`. Before, its `reached` half failed when `denied` had skipped.

#### 4.15 `bfk`: B9 and B20 foreign keys (§2.9 l.654, B9 l.6523, B20 l.6533)

**What it built.** Two tests in `tests/igagraph/p2_bfk_fk_test.go`:

- **`TestB9B20ForeignKeysRejectForeignRows`** has one subtest per foreign key, each with an accepted same-workspace, same-integration control. The negatives are:
  - `foreign_workspace`, and `foreign_integration` for the integration-qualified keys (B20);
  - `absent_workspace` for the workspaces anchor, and `absent_parent` for each legacy single-column key;
  - each must fail with SQLSTATE 23503 from the expected constraint.
  - Each legacy key also gets `known_gap_foreign_workspace_admitted`, which SKIPs while the key admits another workspace's parent and FAILs once it does not.

  The deferred `iga_le_publication_fkey` must accept the INSERT and reject at COMMIT.
- **`TestB9ForeignKeyCatalogGuard`** reads `pg_constraint`. Every key on an `iga_*` or `cloud_*` table, and every key into one, must have exactly one case, and every `cloud_*` table must be classified as Phase 1 or Phase 2.

**Branch.** `m1/bfk` (head `21436d4`), merged as **`393dc32`**.

**Principal tests.** The two above, with cases in `p2_bfk_fk_cases_test.go` (19 `kind: bfkLegacy` entries). The pinned list is `bfkLegacySingleColumn`.

**Counts as implemented, at `a986178`** (reported): 116 FK subtests, 88 `foreign_workspace`, 6 `foreign_integration`, 22 `absent_workspace`, and 6 legacy keys.

**Mutations.** 16/16 for the implementation (its summary says 15). The review's MUT-3 and MUT-3b were not caught at `a986178`, and were caught after the scope change (§6.5 below).

**Fixed by the fix pass or at merge.**
- **Fix pass `21436d4`:**
  - Review major: the guard's scope was defined by a key's form and missed the A3 pattern outside `iga_*` tables. It is now defined by table name.
  - Phase 1's 13 single-column keys are pinned, which brings the list to 19.
  - Each known gap now SKIPs instead of passing.
- **Merge `393dc32`.** The bfk entry was numbered D-95.

#### 4.16 `contract`: frozen-contract conformance (T6.7 l.6334; §5.1–§5.4)

**What it built.** A field-by-field test of every §5.3 route and of the Phase 2 discovery routes, against closed shapes, on one estate built by the real worker and projector. The report counts 141 cases and 42 malformed parameters (reported, not re-verified). Its decisions are D-96–D-103. The implementation changes are D-96–D-100, plus D-102(d)'s identity `provider_attrs` shape from the fix pass:
- one `published_at` rendering (`igaread.PublicationTime`; D-96);
- `meta.capabilities` on every detail envelope (D-97);
- one shape per concept, with graph limitations taken from `/evidence` (D-98(a));
- Access paged by holder (D-99);
- D-9 wired through `routes.SetupIGARoutes` and `GraphEnvelope` (D-100).

D-101 and D-102(a)–(c) record `bound_by` values and shapes the code already had; D-103 records the discovery routes' 401/403 as unchanged.

**Branch.** `m1/contract` (head `2e89004`), merged as **`3a7e4d6`**.

**Principal tests.**
- `tests/integration/p2_contract_routes_test.go`: `TestP2ContractEveryRouteFieldByField`, `TestP2ContractGraphLimitationsAreEvidences`.
- `p2_contract_errors_test.go`: `TestP2ContractErrorEnvelopes`, `TestP2ContractAuthEnvelopes`, `TestP2ContractNotPublished`, `TestP2ContractClassificationPost`.
- `p2_contract_discovery_test.go`: `TestP2ContractDiscoveryRoutes`.
- `p2_contract_notprincipal_test.go`: `TestP2ContractGraphNotPrincipalUnresolved`.

**Mutations.** 25/25 (§6.5 below).

**Fixed by the fix pass or at merge.**
- **Review.** Two rounds; the first said "not ready".
- **Fix pass `2e89004`:**
  - The production auth wiring was untested. The `/api/iga/v1` block moved into `routes.SetupIGARoutes`, which the test mounts.
  - D-44's `not_principal_unresolved` on graph nodes is now tested.
  - Identity `provider_attrs` has one shape for every kind.
  - Rejected: wrapping the discovery routes' 401/403 in the envelope (D-103).
- **Merge `3a7e4d6`.** The contract branch had numbered from D-94, which bdb and bfk had taken; its entries became D-96–D-103.
- **Merge `6398b72`.** `p2_contract_schemas_test.go` follows D-105.

#### 4.17 `egates`: the backend halves of §7.1 E1–E16 (§7.1 l.6429–6465)

**What it built.**
- **Tests.** 18 `TestP2Egates*` tests in 8 of the 9 files `tests/integration/p2_egates_*_test.go` (the ninth, `p2_egates_lab_test.go`, is the harness). The implementation had 17; the fix pass added `TestP2EgatesE13SupersededScannersWriteNothing` in `p2_egates_supersede_test.go`. Every scan goes through the real `AWSScanWorker`, every projection through the real `ProjectionService`, and every read through the route table. E15 is console-only (`p2_egates_isolation_test.go` header).
- **Production changes from the fix pass:**
  - The IAM scanner's connector-row coverage and generation write is now fenced (`repositories.RunFenced`), so a superseded worker cannot overwrite the current owner's report.
  - D-104 names the first failing call on `policy_documents`.
  - D-105: `/graph` `truncated` names only a budget that bound, and the new `data.resolution_not_followed` carries an unfollowed resolution.
  - `ProjectionService.WithBeforeGraphTx` is a seam for tests only.

**Branch.** `m1/egates` (head `d0f716c`), merged as **`6398b72`**.

**Principal tests.**
- `TestP2EgatesE1ConnectAndPublishFirstGraph`, `E2RightWorkloadAmongDuplicates`, `E3WorkloadIdentityStatementsResource`, `E4EvidenceAndLimitations`, `E5TwoWorkloadsShareOneRole`.
- `E6DetachOneOfTwoEquivalentGrants`, `E7PolicyEditsAndReattach`, `E8ReplaceRoleAndPolicy`.
- `E9aIAMDeniedRetainsEverything`, `E9bUnreadableDocumentAndDetachInOneRun`, `E10SharedObjectSurvivesOneSource`.
- `E11ExternalAccountsCyclesAndLimits`, `E11HardBudgetsThroughTheRoutes`, `E12ChangesDuringPagingAndExploration`.
- `E13InterruptionLeaseLossReplay`, `E13SupersededScannersWriteNothing`, `E14CrossWorkspaceAccess`, `E16ExistingProductsUnchanged`.
- `services/p2_egates_coverage_test.go`: `TestEgatesPolicyDocumentsNamesTheFirstFailedCall`.

**Mutations.** 49/49, fix pass 22/22 (§6.5 below).

**Fixed by the fix pass or at merge.**
- **Fix pass `d0f716c`** (all 7 review findings fixed):
  - E13 now runs through the real `ProjectionService` and `AWSScanWorker`.
  - E9(a)'s kinds are derived from `igagraph.Partitions`.
  - E9(b) asserts the structured `api` and `error_code`.
  - The E11 path through `/graph/path` is tested.
  - E16 has a positive control.
- **Merge `6398b72`.** The branch's entry became D-105, which supersedes D-101's `/graph` half.
- **After merge, `9248549`.** E1, E2, E3 and E10 had been written before D-96 (`published_at` to the second) and D-98(b) (a source's `account` as `{id, label, connected}`). Their assertions now follow both; the product is unchanged. `load_fix_report.md` records the 4 failures at `0f9d850` and all 18 passing after the fix.

#### 4.18 `load`: the 10 000-workload fixture and §5.6 targets (T6.10 l.6337; §5.6 l.6219)

**What it built.**
- **Fixture.** A deterministic generator writes 492 743 rows with COPY, using the projector's own key and parsing helpers, into a dedicated database. `loadEnvFor` refuses an `IGA_LOAD_DSN` that names the integration or graph database.
- **Harness.** It measures 77 reads through the real route table, interleaved round-robin, 50 iterations each.
- **Production changes to meet the targets:**
  - an identity-first Access page for heavily named references;
  - `jit = off` and `plan_cache_mode = force_custom_plan` per read transaction (`snapshotSettingsSQL`);
  - the Changes union rewrite;
  - batched resource-policy reads.

**Branch.** `m1/load` (head `ad721a7`), merged as **`0f9d850`**.

**Principal tests.**
- `tests/load/p2_load_measure_test.go`: `TestP2LoadTargets`.
- `p2_load_fixture_integrity_test.go`: `TestP2LoadFixtureIntegrity`.
- `p2_load_access_test.go`: `TestP2LoadAccessStrategiesAgree`.
- `p2_load_env_guard_test.go`: `TestP2LoadRefusesASharedDatabase`, `TestP2LoadRefusalStopsTheFixture`.
- `p2_load_harness_test.go`: `TestP2LoadGraphShape`, `TestP2LoadHonest`.
- In `tests/integration`: `TestP2LoadAccessStrategiesAgreeOnTheLab`, `TestP2LoadChangesReplacementStaysInItsPolicy`, `TestP2LoadChangesReplacementReachesTheNewTarget`, `TestP2LoadChangesTotalCountsEachEventOnce`, `TestP2LoadChangesPagesKeepEveryRepeatedEvent`, and in `p2_load_reads_test.go` `TestP2LoadReadPlansWithBindValuesOnlyInsideTheRead` (the `jit`/`plan_cache_mode` settings, S1–S3), `TestP2LoadWorkloadQMatchesTheWholeProviderID` (L1, L2), `TestP2LoadGroupedEvidenceReadsEachTargetsOwnResourcePolicy` (batched resource policies, R1).

**Mutations.** 32 entries, 31 caught; C4 was caught only by a test added for it (§6.5 below). `RESULTS.md` §8 lists the safeguards.

**Recorded result.** §3 above: run 2 at `m1/load` `3a80c78`, and the run on the merged code.

**Fixed by the fix pass or at merge.**
- **Fix pass `555a821`, `3a80c78`, `ad721a7`** (7 of 7 review findings fixed):
  - The fixture had been left in the integration database. The suite now refuses to run there.
  - The same-policy half of `statement_replaced` is tested, and so is a replacement reaching its new target.
  - The Access state filter is tested.
  - Graph response sizes are recorded.
  - The §7.4 record was re-run at a clean commit.
  - The missing Changes indexes are proposed as D-106, measured and not applied.
- **`3a80c78`.** Fixes a harness defect: the measured "hub role" was an `ecsTaskExecutionRole`, so its expand measured an empty page.
- **Merge `0f9d850`.** The branch's entry became D-106.

## 5. B1–B24 and E1–E16 traceability

§7.3 counts a scenario only once removing its safeguard makes it fail (l.6509–6510), so each row names the safeguard removal the reports record. The mutation results in these tables were not re-run for this report (§6.2 below). The tests they name passed in the runs of §2 and §11 above and below, apart from the by-design skips listed in §2.

- **Mutation labels** follow §6 below. An unqualified label is the implement stage's (`bdb b4a`, `rdetail M21`, `lists M21`); `egfix` is the egates fix pass, and the bdb fix pass's mutants are capitalised (`W1`–`W4`, `B11e`, `B11r`). A label marked "(M0)" is M0's (M0 §3, observed at `4593476`; M19 at `7bdee07`). Whether each result still holds at HEAD is §6.2 below.
- **Status values.**
  - *proven*: the tests assert the row's "Passes when" against real PostgreSQL through the implementation, and a recorded safeguard removal makes them fail.
  - *proven, D-n*: the same, for the row as D-n restates it.
  - *not proven*: the reason is stated in the row.
- The 21 subtests that skip by design with every DSN set are listed in §2 above. None counts as a pass.

### 5.1 §7.3 backend scenarios

| # | Spec (line): scenario → passes when | Test(s) and what they assert | Safeguard removed → caught | Status |
|---|---|---|---|---|
| B1 | l.6514: *Two workloads share one role → Two `executes_as`, one identity* | `TestP2BdbTwoWorkloadsShareOneRole` (`p2_bdb_shared_role_test.go`): two Lambdas in one region on one role give one identity and two `executes_as` rows, with distinct ids, sources and keys and the same target. An unchanged rescan keeps both ids. Read side: `TestP2WdetailIdentitiesSharedRoleAndMayAssume`, `TestP2IdetailUsedBySharedRole`, `TestP2EgatesE5TwoWorkloadsShareOneRole` | `RelationshipKey` without the source endpoint → *"executes_as rows = 1, want TWO"* (bdb `b1`). Also caught through E5 (egates) | proven |
| B2 | l.6515: *Two policies grant the same action; one detached → One grant ended, one current* | `TestP2TwoPoliciesOneDetached` (`p2_0_scenarios_more_test.go`). `TicketRead` is also held by `OtherRole`, so only the assignment partition can end the grant. After the detach, of the two TicketRead grants exactly one is ended `not_seen` with `valid_to` and one is current, and exactly one TicketRead assignment is ended `not_seen`. `ToolboxRead`'s one grant is current. The test counts the grants by state. It does not check which holder each belongs to. Read side: `TestP2WdetailResourcesTwoLinesThenDetach`, `TestP2RDetailAccessTwoStatementsOneHolder`, `TestP2EgatesE6DetachOneOfTwoEquivalentGrants` | M3 (statement key by content only) and M5b (`scope()` → `iga_relationship`), both M0. E3's "two statements … two grant lines" (egates) | proven |
| B3 | l.6516: *A resource named by two accounts; one stops → One resource, two supports, one ended, resource active* | `TestP2TwoAccountsOneBucket`: one resource, two supports, no `*`. Changed in M1 (s3a, `3ca551f`): B's policy is now detached and also deleted from the account, because a detached customer-managed policy is still listed (§2.15). Afterwards B's support is ended, A's is current, the resource is active and A's grant is current. Also `TestP2RDetailSourcesTwoAccounts` and `TestP2EgatesE10SharedObjectSurvivesOneSource` | M10 (M0, on the pre-M1 version of the test). On E10 (egates): "a node retires only when no support row is left" and "a pass ends only its own connector's support rows". rdetail M21 | proven |
| B4 | l.6517: *IAM denied on rescan → Zero rows ended; non-vacuity: the same fixture with `reached` does end them* | `TestP2BdbIAMDeniedEndsNothing` (`p2_bdb_iam_denied_test.go`). `/denied`: every `GetAccountAuthorizationDetails` filter is refused, no edge or support ends, no node retires, and every IAM-partition row moves current → stale with `last_confirmed_at` unchanged. Edges also keep their confirming run. The workload is re-confirmed. `/reached`: the same fixture with the objects gone. Every edge current before ends `not_seen` at the pass's `published_at`, the IAM supports end, and the IAM nodes retire `unsupported`. The ended set equals the kept-stale set, compared as counts per kind, not by id. Also `TestP2EgatesE9aIAMDeniedRetainsEverything` | `canEnd` trusts a present-but-denied surface → `/denied` fails. `canEnd` always false → `/reached` fails (bdb `b4a`, `b4b`). egfix F3 ×3 on E9a | proven |
| B5 | l.6518: *Scan → projection hand-off with different worker names → Projection completes on the first pass* | `TestP2SwitchOnHandOffDifferentOwners`: `scan-worker-A` → `projector-X` → `scan-worker-B` → `projector-Y`, with the barrier holder `job:<id>` after publish. The lab's `project()` (`p2_0_lab_test.go:224`) fails unless the first `RunOnce` leaves the job complete and the barrier idle | M12, barrier left in the scan worker's name (M0; not re-run in M1) | proven |
| B6 | l.6519: *Crash after commit → Replay `AlreadyPublished`, no writes, job complete, barrier idle* | `TestP2CrashAfterCommitReplays`, through the real service: the replay completes on its first pass, there is one publication, and the graph row count and lifecycle event count are unchanged. Both are compared as counts, not row contents. `tg/proofs_test.go` `TestProof4KillAfterCommitReplaysAsAlreadyPublished` asserts the `AlreadyPublished` error and its rev, then job complete and barrier idle. E13 step 3 | M14 (M0). "A replay after commit publishes nothing twice" on E13 (egates) | proven |
| B7 | l.6520: *Recreated role, same ARN → Two identities; old retired `recreated`; edges ended* | `TestP2RecreatedRoleIsANewObject`: two identities, the old one retired `recreated`, and its `executes_as`, assignments and grants ended `subject_recreated`. The Lambda's current edge goes to the new role. Trust analogue: `TestP2TrustRecreatedTrustedRole`. Key level: `ig/sourcekey_test.go` `TestEndpointKeyUsesImmutableKey`, `ig/p2_trust_keys_test.go` `TestTrustEdgeKeyNamesItsEndpoints`. Also `TestP2EgatesE8ReplaceRoleAndPolicy` | M19 (M0). E8 "a role recreated under the same ARN is a new object" (egates) | proven |
| B8 | l.6522: *Support ends then reappears, same immutable key → Restored: same id and `first_seen_at`* | `TestP2BdbRestoredIdentityKeepsItsIdentity` (same RoleId): same id, same `first_seen_at` and the same support row current again. Edges ended in the gap stay ended, and the edges on its return are new rows. `TestP2BdbRestoredPolicyKeepsItsStatements`: policy and statement ids kept, a `restored` event, and a new assignment period. `TestP2BdbReturningWorkloadIsANewObject`: a workload is `recognition_only` (§2.4 l.424, l.455), so it comes back as a new row. Also `tg/` `TestProof3RetirementSuspensionRestoration` | bdb `b8a`–`b8d` (restoration branches in `project.go` and `permissions.go`; `LoadExisting` live-only in `load.go`) | proven |
| B9 | l.6523: *Cross-workspace references → Every composite FK rejects a foreign row; one test per FK* | `tg/p2_bfk_fk_test.go` `TestB9B20ForeignKeysRejectForeignRows`. There is one subtest per key on any `iga_*` or `cloud_*` table and per key into one; `bfkCases` has 130 cases per the fix-pass logs at `21436d4` (not re-counted at HEAD; §6.2 below). In each: the control is accepted; `foreign_workspace` gets 23503 from the named constraint, with sibling keys dropped inside the rolled-back transaction; the deferred `iga_le_publication_fkey` is checked at COMMIT. `TestB9ForeignKeyCatalogGuard` reads `pg_constraint` and fails on a key without a case, a case of the wrong shape, an unlisted single-column reference or an unclassified `cloud_*` table. Planted violations in rolled-back transactions show each check can fail. **D-95**: 19 single-column keys still admit a foreign-workspace parent: `iga_observations_delivery_fkey`, 5 keys on Phase 2 `cloud_*` tables and 13 Phase 1 keys, all named in §10.3 below. Each one's gap subtest SKIPs, and the guard's `known_gap_open_section_2_9_exemptions` SKIPs with the list. Once a key is converted, its gap subtest fails, and the guard fails on the stale exemption ("exemption … no longer matches the schema"; bfk impl T4) | bfk impl: M1–M7b and T1–T8 caught. In review, MUT-3 and MUT-3b were NOT caught at `a986178` (a new `cloud_*` table with only single-column references; a Phase 1 → `cloud_policy(id)` reference). The fix pass widened the guard (`77da653`, `39a728f`, finished in `21436d4`), and both were then caught at `77da653`: 133 and 131 keys in scope against 130 cases. Fix pass at `21436d4`: M1–M10 caught. M1b, the same mutation without the new plant, passes, which is why the plant was added | proven, **D-95** (not for the 19) |
| B10 | l.6524: *Deny and boundary statements → Zero grants; restrictions present* | DB side. `TestP2BdbBoundaryAndDenyGrantNothing`: the boundary is stored as a current `boundary` assignment with its 2 statements and gives zero grants. The Deny is stored with effect `deny` and gives zero grants. The only grant is the Allow. Also `TestP2DenyIsNeverAGrant`. Restrictions side: `TestP2WdetailResourcesDenyAndBoundaryAreRestrictions` asserts `restrictions {deny_statements: 1, permissions_boundary: true}`, and grant rows inserted directly as defects never surface. `TestP2GraphDenyAndBoundaryAreRestrictions` and `TestP2RDetailDenyIsARestrictionNotAccess` (`deny_statements_naming`) cover the graph and resource access. `TestP2IdetailPermissionsNeverGrantBoundaryOrDeny` covers identity permissions | bdb `b10a` (the boundary skip in `projectGrants`) and `b10b` (the effect check and the `UpsertGrant` refusal, both removed). M8a/M8b (M0). rdetail M02. graph "Rule 7 at read time" | proven |
| B11 | l.6525: *Statement identity → Reorder keeps ids; Sid edit keeps id with a revision; Sid-less edit replaces* | `TestP2BdbStatementIdentity`. (a) The reversed document keeps ids and grants and writes no revision. (b) A Sid edit keeps the id, makes exactly two revisions (the new one at v4) and keeps the same grant current. (c) A Sid-less edit retires the old statement and ends its grant `not_seen`, and a new statement and grant begin. Unit: `ig/sourcekey_test.go` `TestStatementKeySidSurvivesReorderAndEdit`, `TestStatementKeyHashReorderKeepsEditReplaces`. **D-67**: the grant in (c) ends `not_seen`, not the `statement_retired` of §2.7 l.605 | bdb `b11`, `b11a`, `b11b` (index-keyed statement keys), `B11e` (no retired event for statements), `B11r` (grant partitions skipped) | proven, **D-67** (reason only) |
| B12 | l.6526: *One unreadable document and one genuinely detached policy, one run → Unreadable: statements, grants and sole-named resource support stale. Detached: assignment and grants ended* | `TestP2UnreadableAndDetachedInOneRun`, re-expressed in M1 per **D-51**: the `GetPolicyVersion` denial is on an attached AWS-managed `TicketRead`. `policy_documents` is partial and names TicketRead and the call; `iam_policies` stays reached. The unreadable grant is stale, the statement support stale and active, and the `ticket-archive/*` support stale. `OtherPolicy`'s assignment is ended `not_seen`, its grant ended, and `other-bucket/*` retired. Also `TestP2EgatesE9bUnreadableDocumentAndDetachInOneRun`, and the trust analogue `TestP2TrustUnreadableDocumentKeepsItsEdges` | M4 (M0, on the pre-D-51 version of the test). M21 `protected()` on the re-expressed test (s3a). egates: "an unreadable document's grants go stale" and "one unreadable document does not veto the account" | proven, **D-51** |
| B13 | l.6527: *Switch off at `036` → Two consecutive scans publish; no job, no barrier change* | `TestP2SwitchOffTwoScans`: 2 published runs; no job, barrier, publication, policy, grant or workload rows. `TestP2BdbSwitchOffLeavesTheIdleBarrier`: after an *on* period, two *off* scans leave the barrier row byte-identical, with no new job or publication. Enablement by switch, not by table probing: `tg/schema_gate_test.go` `TestGraphSwitchFailsClosedBelow036`, `TestGraphSwitchVerifiesAt036`, `TestGraphSwitchOffIsPhaseOne` | M11 (M0). bdb `b13` (worker takes the pipeline path regardless) | proven |
| B14 | l.6528: *Schema verification error → Worker claims nothing; `/capabilities` `misconfigured`* | `TestP2SchemaVerificationErrorFailsClosed`: verification runs against a closed pool; the worker claims nothing and the run stays queued. `/capabilities` returns `misconfigured` with a reason and 8 feature keys. `tg/` `TestGraphSwitchTransientErrorIsNotCached`: an error is retried, never cached | M15, `ClaimAllowed` fails open (M0; not re-run in M1) | proven |
| B15 | l.6529: *Busy barrier → The refused run does not starve another workspace* | `TestP2BusyBarrierDoesNotStarveAnotherWorkspace` | M16a, M16b (M0; not re-run in M1) | proven |
| B16 | l.6530: *Reads straddling a publication → A read in flight when a publication commits returns only the old revision* | `TestP2ReadDoesNotStraddleAPublication` (`p2_read_snapshot_test.go`). Inside one `igaread.Reader.Read`, a scan and projection publish; the open snapshot sees neither the new `iga_publication` row nor the new role, and after the read the role exists. The follow-up `rev=N` → 409 is `TestP2ReadRevisionStale`. The test runs at the Reader level, not through a route, and asserts no response `meta.rev`. It failed once in each of two agents' full runs under machine load, and passed alone and on rerun (impl:evidence in `wave_reports.md`; impl:contract in `wave_c_reports.md`). Both put it down to timing. impl:evidence calls it a timing flake; impl:contract notes that the scan and projection run inside the read's 3 s budget | **None found.** No report and no mutation log records removing the snapshot (for example, reads outside the REPEATABLE READ transaction). impl:load's S1, "Reader.Read applies no snapshot settings", is a different safeguard. It removed the planner settings (`snapshotSettingsSQL`: `plan_cache_mode`, `jit`), not the isolation level, and was caught by `TestP2LoadReadPlansWithBindValuesOnlyInsideTheRead` | **not proven**: the behaviour is asserted but the safeguard removal §7.3 requires is not recorded |
| B17 | l.6537: *Limits suppress completeness → Any bound budget → `total_known: false` / `truncated` / `not_found_within_budget`* | `p2_graph_budgets_test.go`: `TestP2GraphNodeAndEdgeBudgets`, `TestP2GraphPathBudget`, `TestP2GraphPathNoneExistsOnlyWhenExhausted`, `TestP2GraphPathHopLimit`, `TestP2GraphTimeBudgetTruncates`, `TestP2GraphPathRediscoveredEdgesCostNoRows`. Budgets are injected through `Reader.TraversalWith` on small fixtures. The exception is `TestP2GraphTimeBudgetTruncates`, which runs through the route under the production budget with a table locked. Through the routes with production budgets: `TestP2EgatesE11HardBudgetsThroughTheRoutes` (510 workloads, bound at 500 nodes), and `TestP2EgatesE11ExternalAccountsCyclesAndLimits` (chain-1 → chain-6, `bound_by: assume_hops`). List totals: `ir/` `TestP2ListsTotalsBeyondTheCap` and `TestP2WdetailSectionTotalsFollowTheListRule` (unit), `TestP2WdetailIdentitiesSectionTotalAboveTheCap` (real PostgreSQL, rows inserted), `TestP2ListsNoTimeForOptionalWork` | graph: node, edge, path and hop budgets; D-38 `none_exists`; "no exact frontier counts after the time bind". egates: hard node and neighbour budgets. egfix F6 (a hop-bound path read as `none_exists`). lists M21 | proven. A list route above 10 000 rows is not exercised (§5.3 below) |
| B18 | l.6531: *Attach → detach → reattach → Assignment period 1 ended; period 2 a new row; grants follow each; `scope()` rejects an unknown target* | `TestP2AttachDetachReattach`: `OtherRole` keeps the policy alive, so period 1 ends `not_seen` through the partition; period 2 is a new row; there is one grant per period. `ig/p2_bdb_scope_test.go` `TestP2BdbEveryPartitionTargetResolvesInScope` and `TestP2BdbEveryNodeClassResolves`: gorm DryRun, **no database**. Also E7(c), `TestP2EgatesE7PolicyEditsAndReattach` | M5, `scope()` default table (M0). bdb `s1` (default → `iga_relationship`). bdb `s2` (`SupportColumn` maps entitlement to `policy_id`) and `s3` (`NodeTable` loses `policy`) are node-class resolution, not the `scope()` default | proven. The `scope()` half is not run against PostgreSQL |
| B19 | l.6532: *`NotResource` → Grant to `*` only; no traversal edge, path or `access` row to the excluded resource; `excluded_by` lists it* | `TestP2NotResourceIsAnExclusion` (DB: one grant; targets `*` in mode `resource` and `finance/*` in mode `not_resource`; statement negated). `TestP2GraphNotResourceIsNeverAnEdge`: no node or edge in either direction, the expansion is empty, the path is `none_exists`, and the control path to `*` is found. `TestP2RDetailNotResourceExcludes`: no access row, `total` 0, `excluded_by` lists the Allow. Also `TestP2WdetailResourcesNotResource`, `TestP2EvidenceNotResourceGrant`, `TestP2EgatesE4EvidenceAndLimitations` | M6 (M0). graph: target mode `resource` only, forward and reverse. rdetail M01. egates: "a NotResource entry is never a traversal edge" and "Resource › Access lists positive targets only" | proven |
| B20 | l.6533: *Cross-workspace and cross-integration collection facts → Membership, inline holder, attachment principal and attachment policy from another workspace or integration rejected; same-integration controls accepted* | `tg/` `TestB9B20ForeignKeysRejectForeignRows`. The six integration-qualified keys (`cloud_gm_user_fkey`, `cloud_gm_group_fkey`, `cloud_policy_holder_fkey`, `cloud_pa_policy_fkey`, `cloud_pa_principal_fkey`, `cloud_observation_policy_fkey`) each have a control (same workspace and integration, accepted) plus `foreign_workspace` and `foreign_integration`, each 23503 from that constraint. `tg/` `TestB9ForeignKeyCatalogGuard` requires every reference to `cloud_identity` or `cloud_policy` to be `(workspace_id, connector_id, id)`, with a planted workspace-only reference. **D-95**: the row's *Catches* ("single-column references to `cloud_identity`") is still open for 6 keys: `cloud_observation_identity_id_fkey` and the five Phase 1 `*_identity_id_fkey`. All six SKIP | bfk impl: M1 (`cloud_pa_principal_fkey` single-column), M3 (`cloud_gm_user_fkey` workspace-only, caught only by `foreign_integration`), T8. review MUT-2. Fix pass M10 | proven for the four named facts, **D-95** |
| B21 | l.6521: *Recreated policy, same ARN and Sid; recreated role with a same-named inline policy → New policy and statements with new keys; old ones retired `policy_recreated` / `recreated`; no statement id reused* | `TestP2RecreatedPolicySharesNothing`: old policy retired `recreated`, old statement retired `policy_recreated`, new key and id, old assignment and grant ended `policy_recreated`, plus a retired event. `TestP2RecreatedRoleIsANewObject`: no statement key shared across the inline incarnations. `TestP2BdbRecreatedRoleInlinePolicyIsANewIncarnation`: old inline policy retired `recreated`; statements retired `policy_recreated` with events; new statements are new rows with `first_seen` events. The old inline assignment and grants end `subject_recreated`; the spec does not say which reason, and no D-n records this (§5.3 below). Unit: `ig/sourcekey_test.go` `TestRecreatedPolicySharesNoKey`, `TestInlinePolicyIsHolderScoped` | M7 (M0). bdb `b21` and `b21b`, one mutation (inline incarnation key from the holder's ARN): `b21` on the bdb test, `b21b` on `TestP2RecreatedRoleIsANewObject` | proven |
| B22 | l.6534: *Two concurrent retries of one classification operation → The second replays (`200`, `replayed: true`)* | `TestP2ClassConcurrentRetriesReplay`: request 1 is held at commit (`WithBeforeCommit`) and request 2 is parked on `FOR UPDATE OF w`. They return 200 `replayed:false` and 200 `replayed:true`, with one decision id, version 1 and no publication. `TestP2ClassRetryStormReplays`: 8 overlapping retries give exactly one `replayed:false` and one decision id. The lock-wait helper's flake was fixed in the egates fix pass (`egates_fix_report.md`) | egfix C1 (lookup before the lock), C2 (no `FOR UPDATE`), C4 (REPEATABLE READ). C3 is on `TestP2ClassSameOperationTwoWorkloadsConcurrently`. The same safeguards were first caught in impl:class, including the lookup-before-lock mutation under the free-running storm, which survived round 1 and was caught after the test was strengthened | proven |
| B23 | l.6535: *Deadlines → An optional count that times out → `total_known: false`, page returned; graph at the deadline → `200` with `truncated.bound_by: "time"`; a mandatory query past the deadline → `504`* | Optional count: `TestP2ListsOptionalCountTimesOutPageStillReturned` (a real lock), `TestP2ListsNoTimeForOptionalWork`, `TestP2ListsCountUpToTimesOut`, `TestP2ReadOptionalTimeoutKeepsTheSnapshot`, `TestP2IdetailOptionalCountsTimeOut`. Graph at the deadline: `TestP2GraphTimeBudgetTruncates` (lock on `iga_entitlement_target`, through the route, production 3 s), `TestP2GraphTimeReserve`, `TestP2GraphExpandTimeReserve`, `TestP2GraphNestedOptionalsFitTheirLevel`, `ir/` `TestP2GraphLevelRearmsEveryStatement`. Mandatory query: `TestP2ReadMandatoryTimeoutIs504` (Reader), `TestP2GraphRootTimeoutIs504` (the traversal on a Reader with an 800 ms budget via `graphDirect`, not the route). No route test times out a list's own total: the route test times out a per-row count (`used_by_count` → `{value: null, exact: false}`, total still known). `total_known: false` is shown at the Reader only: `CountUpTo` timing out, and Optional skipped under a 39 ms budget | lists M21–M24 (timed-out total, facet and counts). graph: "each level inside a savepoint → 200 truncated time, not 504", and the D-40 reserve | proven |
| B24 | l.6536: *Lifecycle history → Retire → restore → further upserts: both events remain, with rev, run and reason* | `TestP2BdbLifecycleHistorySurvivesRewrites`: after two passes rewrite `provider_attrs`, the events are exactly `first_seen`, `retired:unsupported`, `restored`, each with its own run's rev and pass time. `tg/` `TestProof3RetirementSuspensionRestoration`: events stamped with their run. `TestP2ChangesLifecycleSurvivesNodeRewrites`: Changes shows both while the node row reads `active` | bdb `b24` (`EventLog.Restored`). changes: "lifecycle events come from `iga_lifecycle_event`, never the node row" | proven |

**Count:** 19 proven (B17, B18 and B23 each with a stated gap, §5.3 below), 4 proven with a stated deviation (B9 and B20 under D-95, B11 under D-67, B12 under D-51), and 1 not proven (B16).

### 5.2 §7.1 end-to-end gates: backend halves

§7.1 is an M3 gate: *"real backend and the real console, against real AWS lab accounts, by Playwright (T8.2)"* (l.6431–6432). Every backend half below uses the P2-0 lab, not real AWS:

- scans go through the real `AWSScanWorker`, with AWS answered by fakes;
- projections go through the real `ProjectionService`;
- reads go through the real route table.

So every row still needs the **S8** real-AWS run (T8.1/T8.2) and the **S7** console half. The "Left" columns name the specific part that remains. All E-gate tests are in `p2_egates_*_test.go`. The fix-pass report says all 18 `TestP2Egates*` pass at `9248549` (`load_fix_report.md`, last line). The egates mutations ran before the merge (impl up to `3dfa4b0`, fix pass up to `d0f716c`). After it, `9248549` changed E1, E2, E3 and E10 in only two ways: `published_at` is now expected to the second (D-96), and a source names its account as an object (D-98(b)). No assertion was removed.

**Safeguard removals per gate** (§7.4 records "the safeguard removed with its observed failure"; each mutant's text and failure are in §6.5 below, egates).
- **impl:egates at `3dfa4b0`**: 49 of 49 caught, in the `wave_c_reports.md` list. By gate: E1 4, E2 3, E3 1, E4 4, E5 1, E6 2, E7 3, E8 1, E9(a) 5, E9(b) 2, E10 2, E11 6 (4 on the cycles test, 2 on the hard budgets), E12 4, E13 5, E14 4, E16 2.
- **review:egates at `3dfa4b0`**: ran five mutations and found four NOT caught: M1 (E13), M2 (E13, E1), M3 (E9) and M5 (E9(b)). It also found E16 without a positive control and E11's bound path only on the Reader.
- **The fix pass up to `d0f716c`** (egfix, `SP/egfix/mutations.jsonl`) re-ran each class and caught all 22:
  - E13: F1 ×2 and F2 ×4 (one on the lease-loss test, three on `TestP2EgatesE13SupersededScannersWriteNothing`);
  - E9(a): F3 ×3;
  - E9(b): F4 ×3;
  - E11: F5 ×3 (with `TestP2GraphExternalPrincipalIsTerminal`) and F6 through the route;
  - E16: F7 ×2 (the positive control);
  - C1–C4 on B22's class tests (E12's retried save; E12 itself cites only `TestP2ClassConcurrentRetriesReplay` of them).
- **E15**: none. It has no backend half.

| # | Spec (line) | Backend test(s) | What the backend half asserts | Left for S7 (console) | Left for S8 (real AWS) | Status |
|---|---|---|---|---|---|---|
| E1 | l.6450: Connect and publish the first graph | `TestP2EgatesE1ConnectAndPublishFirstGraph`. Parts in `TestP2BdbFirstPublication`, `TestP2S2PipelineQueuedBehindCollectingProjecting`, `TestP2S2RegionsListedWithSelection`, `TestP2SwitchOnHandOffDifferentOwners` | Connect A with `eu-central-1` and `us-east-1` and queue a scan through the discovery route. `/pipeline` account state goes `never_scanned` → `queued` → `collecting` (read from inside the worker) → `projecting` → `published`. Lists are `not_published` until rev 1; then `/workloads` lists A's workloads at rev 1. DB: one published run, one complete job, barrier idle, one publication at rev 1, and no `iga_agents` or `iga_agent_instances` rows. The second scan publishes rev 2, and `?rev=1` then returns 409. The per-account `state` field is additive to §5.3's `/pipeline` example; no D-n records it | First-run states drawn in order; the list appears without a reload; *as of* | Account A connected for real | backend half proven |
| E2 | l.6451: The right workload among duplicates | `TestP2EgatesE2RightWorkloadAmongDuplicates`. Also `TestP2ListsDuplicateNamesAcrossAccounts`, `TestP2ListsSearchFindsRowBeyondPageOne` | 120 filler functions, so neither `ticket-tools` is on page one. `q=ticket` (in any case) returns both, with distinct account and ARN. The account facet counts per account with every other filter applied. B's detail and tabs carry B's ARN and account and none of A's ids | Rows distinguishable in list, search, breadcrumb and canvas; never mixed from cache (UI2) | A and B for real | backend half proven |
| E3 | l.6452: Workload → identity → statements → resource | `TestP2EgatesE3WorkloadIdentityStatementsResource`. Also `TestP2WdetailIdentitiesSharedRoleAndMayAssume`, `TestP2WdetailResourcesTwoLinesThenDetach`, `TestP2RDetailAccessTwoStatementsOneHolder`, `TestP2GraphTeachingPathForward` | The execution identity is `SharedToolRole`. Resources shows `support-tickets/*` as one selector with **two** grant lines (ReadTickets, and ToolboxRead's Sid-less statement). The graph's edges match the tabs claim for claim; the path search finds two paths; no response says "can access"; the ECS execution role is listed under *other* | Identities and Resources wording; the graph drawing | Real lab | backend half proven |
| E4 | l.6453: Evidence and limitations | `TestP2EgatesE4EvidenceAndLimitations`. Also `TestP2EvidenceGrantFactsAndShape`, `TestP2EvidenceNotResourceGrant`, `TestP2EvidenceLimitationVocabulary`, `TestP2RDetailNotResourceExcludes`, `TestP2BdbEveryEdgeHasEvidence` | No grant, relationship or assignment lacks a junction row. For each grant: the claim sentence, status, facts (v3, Sid, excerpt), freshness, and the exact set of limitations that apply: `selector_may_match_nothing`, `effective_access_not_evaluated`, `organizations_not_collected`; `negated_statement` on the NotResource grant; `permissions_boundary_present` for priya on the `ops` grant (D-22, D-21). `raw` appears only with `include=raw`. `finance/*` appears only in `excluded_by`: never an access row, graph node or edge, and the path is `none_exists`. **D-66**: target edges have no junction table; a target's facts come from its statement's policy-version observation | The five parts in order; the NotResource statement drawn as *except finance/\** | Real lab policy | backend half proven, **D-66** for target edges |
| E5 | l.6454: Two workloads share one role | `TestP2EgatesE5TwoWorkloadsShareOneRole`. Also `TestP2BdbTwoWorkloadsShareOneRole`, `TestP2IdetailUsedBySharedRole`, `TestP2ListsUsedByCountsDistinctWorkloads` | Two current `executes_as` edges to one identity. Used by lists both workloads. The role is one row, used by 2, in the list, the detail and both workloads' tabs. The reverse graph draws both workloads | Overview's *shared with 1 other workload* | Real lab | backend half proven |
| E6 | l.6455: Detach one of two equivalent grants | `TestP2EgatesE6DetachOneOfTwoEquivalentGrants`. Also `TestP2TwoPoliciesOneDetached`, `TestP2ChangesDetachNamesRemainingGrant`, `TestP2WdetailResourcesTwoLinesThenDetach` | TicketRead's assignment is ended `not_seen` and its grant ended, both with `valid_to`. The grant's `not_seen` is asserted through the API, on its `include_ended` Resources line and in its evidence `freshness.ended_reason`, not on the row. ToolboxRead's are current. Resources shows one current line, plus the ended one with `include_ended`. Changes `policy_detached` names the remaining ToolboxRead grant (D-28), also through the workload. The graph keeps a current grant (1 current · 1 ended) and the path is still found | *"The path remains through ToolboxRead"*; the line stays solid | Real detach | backend half proven |
| E7 | l.6456: Policy edits and detach/reattach | `TestP2EgatesE7PolicyEditsAndReattach`. Also `TestP2BdbStatementIdentity`, `TestP2AttachDetachReattach`, `TestP2ChangesPolicyEdits` | (a) Same statement, 2 revisions, `statement_revised` with before and after, v3 → v4; it appears on the resource's Changes but not on the role's or the workload's (D-27d). (b) The old statement retires, a new statement and grant begin, and Changes shows `statement_replaced`. (c) A **new** assignment row, the ended period unchanged, and `policy_attached` | Each event worded per §2.6 | Real edits | backend half proven |
| E8 | l.6457: Replace a role, and a policy | `TestP2EgatesE8ReplaceRoleAndPolicy`. Also `TestP2RecreatedRoleIsANewObject`, `TestP2RecreatedPolicySharesNothing`, `TestP2BdbRecreatedRoleInlinePolicyIsANewIncarnation`, `TestP2ChangesRecreatedRoleAndPolicy` | (a) New ids and keys, and no edge key reused. The old role is retired `recreated`; its edges end `subject_recreated`; the old inline policy and statements retire. (b) A new policy and statement; the old ones retire `recreated` / `policy_recreated`; the grants end `policy_recreated`. There is a lifecycle event for every transition; old objects stay readable as retired; the new role's Changes carry no old history | Changes rendering | Real delete and recreate | backend half proven |
| E9 | l.6458: Collection fails and relationships are retained | `TestP2EgatesE9aIAMDeniedRetainsEverything`, `TestP2EgatesE9bUnreadableDocumentAndDetachInOneRun`, `svc/p2_egates_coverage_test.go` `TestEgatesPolicyDocumentsNamesTheFirstFailedCall`. Also `TestP2BdbIAMDeniedEndsNothing`, `TestP2UnreadableAndDetachedInOneRun`, `TestP2S2FailedCallsNamedOnEveryDeniedSurface` | (a) Zero rows end. Every row whose partition requires an IAM surface goes stale with `last_confirmed_at` unchanged; the kinds are taken from `igagraph.Partitions` and include `executes_as`, `can_assume`, `task_execution_role` and resource support. `/coverage` names each refused call with AWS's code and `surface_denied`, offers no fix and has no guessed-permission key. `meta.coverage` follows D-73 and rows carry a `stale_reason`. After the restore, every row is back in its pre-denial state under the same id, and no row is added. (b) Per **D-51**: the customer-managed TicketRead stays current. An attached AWS-managed policy with `GetPolicyVersion` denied has its grants, statement and sole-named resource support stale. ToolboxRead's assignment and grants end. `policy_documents` is partial with `api` `iam:GetPolicyVersion` and `error_code` `AccessDenied` (**D-104**) | Graph unchanged with stale markers; coverage wording | Removing permissions from the real discovery role; here the fakes answer `AccessDenied` | backend half proven, **D-51**, **D-104** |
| E10 | l.6459: A shared object survives one source dropping it | `TestP2EgatesE10SharedObjectSurvivesOneSource`. Also `TestP2TwoAccountsOneBucket`, `TestP2RDetailSourcesTwoAccounts` | B's support is ended and A's current; the resource stays active and listed. A's grants and their `last_confirmed_at` are untouched and still name the selector, never `*`. Sources show A current and B ended `not_seen`. Access shows A's grants, and B's ended one only with `include_ended` | Resource still listed; Access view | A and B for real | backend half proven |
| E11 | l.6460: External accounts, cycles and limits | `TestP2EgatesE11ExternalAccountsCyclesAndLimits`, `TestP2EgatesE11HardBudgetsThroughTheRoutes`. Also `TestP2GraphCycleClosesAndIsNotReexpanded`, `TestP2GraphExternalPrincipalIsTerminal`, `TestP2GraphCrossAccountEdge`, `TestP2GraphPathNoneExistsOnlyWhenExhausted`, `TestP2TrustPrincipalsAppear`, `TestP2TrustLoopProjectsBothEdges` | The principal for C is unresolved, account not connected, on a `crosses_account` edge, and terminal. `loop-a` and `loop-b` have `can_assume` both ways, each node once, and `closes_cycle`. Frontier `more` is exact (`{count 1, exact}` past the display default; `{count 510 − drawn workloads, exact}` at the 500-node bind), and expand walks the next hop. The E-gate tests do not assert `{count: null, exact: false}` after a time bind. `TestP2GraphTimeBudgetTruncates` asserts it through the route, under the production budget, on the teaching fixture with `iga_entitlement_target` locked. The path is `none_exists` when nothing bound. `not_found_within_budget` with `bound_by: assume_hops` is shown through the route (chain-1 → chain-6); with `bound_by: nodes` only on the Reader, with an injected budget. No distance is claimed. `data.resolution_not_followed` is true, false or null (**D-105**; `/graph/path` keeps D-101's `bound_by`). 510 workloads truncate at 500 nodes, and expand pages 100 at a time. The fixture adds chain-1…chain-6 and 510 fillers, which T8.1's lab lacks | *Account not connected*; each loop node drawn once; the truncation chip; the two not-found messages kept distinct | Real B, C and loops; T8.1 needs a deeper chain | backend half proven, **D-105**, D-38, D-101 |
| E12 | l.6461: Changes during paging and exploration | `TestP2EgatesE12ChangesDuringPagingAndExploration`. Also `TestP2ReadRevisionStale`, `TestP2ListsClassificationChangeBetweenPages`, `TestP2ClassClockAndListingChanged`, `TestP2ClassConcurrentRetriesReplay` | 217 workloads (210 fillers). After a publication mid-walk, each of these returns 409 `revision_stale`: the next list page, `?rev=1`, the expand continuation, the used-by section continuation, the pinned evidence and the pinned graph. A fresh walk is whole. A decision between pages of the Agents filter or the classification sort returns 409 `listing_changed`. A retried operation returns 200 `replayed` and writes nothing. A real conflict returns 409; the same operation id with other content returns 422 | Banner; data kept; Refresh restores the view; list restart notice; the retried save closes as success | The lab fixture generator (T8.1) | backend half proven |
| E13 | l.6462: Interruption, lease loss and replay | `TestP2EgatesE13InterruptionLeaseLossReplay` (`p2_egates_pipeline_test.go`), `TestP2EgatesE13SupersededScannersWriteNothing` (`p2_egates_supersede_test.go`). Also `TestP2CrashAfterCommitReplays`, `TestP2SupersededWorkerDeletesRefused`, `tg/` `TestProof4KillAfterCommitReplaysAsAlreadyPublished`, `tg/` `TestExitsRefuseASupersededWorker` | The real worker is paused inside its first IAM listing through the scanner hook. A second worker claims nothing while the lease is live; the run is then reclaimed and published. The stalled worker's first write is refused with `ErrScanFenceLost`, and nothing lands, from any of the three scanners or `commitScan`. The projector is paused through `WithBeforeGraphTx`. A second projector claims nothing; after the reclaim, the first pass is refused inside its graph transaction with zero writes. The crash after commit is replayed. Each run has one publication, the job completes, the barrier is idle, and the next scan publishes rev 3. All of this is followed through `/pipeline` | Pipeline states; never a partial publication shown | A real process kill. Here the "kills" are in-process pauses and lease expiries, and the crash after commit is staged by resetting the job and barrier rows with SQL after a whole pass | backend half proven |
| E14 | l.6463: Cross-workspace access and cache isolation | `TestP2EgatesE14CrossWorkspaceAccess`. Also `TestP2GraphWorkspaceAndGates`, `TestP2ListsRoutesPermissionsAndCrossWorkspace`, `TestP2ClassCrossWorkspaceIs404`. Discovery routes: `TestP2S2RegionsListedWithSelection`, `TestP2S2RegionPatchNamesTheOffenders`, `TestP2S2ScanRunHistoryShowsEveryEnding`. DB (§6.4 l.6417, composite FKs): `tg/` `TestB9B20ForeignKeysRejectForeignRows` | Two workspaces hold the identical lab. Every route in `RegisterIGAGraphReadRoutes`, taken from the engine's route table with bare and typed ids, returns 404 `not_found` for the other workspace's ids. This includes `POST /workloads/:id/classification`, sent with a classify body. The same GET path from the owning workspace returns 200; the POST probe has no owner-side control. No id leaks either way. Lists, totals and facets count only the workspace's own rows. Another workspace's cursor returns 400 | Workspace switch mid-load; cache keyed by workspace (UI11) | Two real workspaces | backend half proven (DB side subject to D-95) |
| E15 | l.6464: Keyboard and narrow screens | None. It is console-only, as stated in the header of `p2_egates_isolation_test.go` | No backend half | Keyboard-only E3, 375 px, focus, axe | Runs on E3's real lab (§7.1 is run against real AWS, l.6431) | console half is S7 |
| E16 | l.6465: Existing products unchanged | `TestP2EgatesE16ExistingProductsUnchanged`. Also `TestP2AWSRowsAbsentFromGitHubReaders` | GitHub rows are byte-identical across the AWS scans and projections, and AWS rows across a GitHub rescan. No row carries another provider. `iga_agents` and `iga_agent_instances` hold no AWS object. The 13 existing GitHub routes the test lists answer the same JSON, ids and times aside, as a GitHub-only control workspace on the **same binary**. They are `/integrations`, `/integrations/:id` with `/coverage` and `/source-health`, `/scan-runs/:id`, `/agents`, `/agents/:id` with `/evidence` and `/access-paths`, `/identity-accounts`, `/classification-candidates`, and `/authsec/discovery/agents` and `/coverage`. The Kubernetes bridge proposes for the GitHub-named sighting (positive control) and nothing for the AWS-named one. Cloud Inventory rows `/lookup` to their own account | Existing pages behave as before; the Cloud Inventory link | A real Kubernetes collector (the test reports each sighting through the webhook's write path, `DiscoveryManager.ReportSighting`, which runs the real bridge). The comparison with pre-Phase-2 `0e75ad7` is not made by this test; for the whole repository see §11 below | backend half proven, same-binary |

**Count:** 15 backend halves proven (E1–E14, E16). E4 carries D-66 for target edges and E9(b) runs per D-51/D-104. E15 has no backend half. All 16 console halves are S7, and all 16 need the S8 real-AWS run.

### 5.3 What a proof or gate asks that no test shows

1. **B16.** No safeguard removal is recorded. The test asserts snapshot isolation at the `igaread.Reader` level, not through a route's `meta.rev`. It was reported failing twice under machine load (timing; see the B16 row) and is unchanged.
2. **B9 and B20 (D-95).** The rejection does not hold for 19 single-column keys. The tests show each one ADMITS another workspace's parent, and that result is reported as SKIP. B20's *Catches* class (single-column references to `cloud_identity`) is still open for 6 of them. Separately, `bfkNoForeignKey` lists uuid columns with no key at all. Three of them are marked SPEC QUESTION in the test but are not in D-95's list: `iga_pipeline_lease.scan_run_id`, `iga_source_objects.integration_scope_id` and `iga_webhook_deliveries.integration_id`. The decisions are §9 entries 5 and 6 below.
3. **B17.** No list route is exercised above 10 000 rows through the database. The cap is shown for the envelope (unit tests) and for one detail section through PostgreSQL, with the rows inserted directly. The T6.10 load fixture has 10 000 workloads (9 823 active; `tests/load/RESULTS.md`), which is at the cap, not above it.
4. **B18.** The `scope()` half runs on gorm DryRun, not "against real PostgreSQL" (l.6509).
5. **B23.** No route test times out a list's own total. `total_known: false` from a timed-out optional count is shown at the Reader (`TestP2ListsCountUpToTimesOut`; `TestP2ListsNoTimeForOptionalWork`, where Optional is skipped under a 39 ms budget rather than timing out). The route test (`TestP2ListsOptionalCountTimesOutPageStillReturned`) times out a per-row count while the total stays known. The 504 for a graph root is shown on a Reader with an 800 ms budget, not through the route.
6. **B21, inline.** The old inline assignment and grants end `subject_recreated`. The spec does not name the reason, and no D-n records it; it was raised only in the bdb implement report's `spec_questions` (§9 entry 53 below).
7. **M0 mutations not repeated in M1:**
   - B5 (M12), B14 (M15) and B15 (M16a/b) were observed at `4593476` and never re-run after M1's production changes. Their tests are unchanged since `7bdee07`.
   - M10 (B3) ran on the pre-M1 version of `TestP2TwoAccountsOneBucket`. The E10 mutations cover the same mechanism.
   - M4 (B12) ran on the pre-D-51 version of `TestP2UnreadableAndDetachedInOneRun`. s3a's M21 is the same removal on the re-expressed test.
8. **E gates.** Nothing is proven for the console halves (S7) or real AWS (S8). What the backend halves put in place of the lab:
   - E9 simulates the permission removal with fake `AccessDenied` answers.
   - E13 simulates process kills with pauses and lease expiries, and stages the crash after commit by resetting the job and barrier rows.
   - E16 compares 13 listed GitHub routes against a control workspace, not the `0e75ad7` binary. It reports a Kubernetes sighting through the webhook's write path rather than running the collector.
9. **Gates the backend cannot meet as the spec writes them**: E9(b), E4 on target edges, E1's per-account pipeline state, and the E2, E11 and E12 fixtures. They are listed in §8.2 below.
10. **§7.4 record.** Commands with environment variables and pass/skip/fail counts at HEAD are in §2 above. These tables record the 21 design skips as not passing.

### 5.4 Where each cited test is

All 130 test functions named above, by file, each found in the file listed with `git grep -n '^func <Name>(' 9248549` and again at `e63dfa7`. Prefixes are as in the conventions; a file with no prefix is in `tests/integration/`.

| File | Functions |
|---|---|
| `p2_0_scenarios_more_test.go` | `TestP2AWSRowsAbsentFromGitHubReaders`, `TestP2AttachDetachReattach`, `TestP2BusyBarrierDoesNotStarveAnotherWorkspace`, `TestP2CrashAfterCommitReplays`, `TestP2DenyIsNeverAGrant`, `TestP2NotResourceIsAnExclusion`, `TestP2RecreatedPolicySharesNothing`, `TestP2RecreatedRoleIsANewObject`, `TestP2SchemaVerificationErrorFailsClosed`, `TestP2SupersededWorkerDeletesRefused`, `TestP2SwitchOffTwoScans`, `TestP2SwitchOnHandOffDifferentOwners`, `TestP2TwoAccountsOneBucket`, `TestP2TwoPoliciesOneDetached`, `TestP2UnreadableAndDetachedInOneRun` |
| `p2_bdb_deletion_test.go` | `TestP2BdbWorkspaceDeletionAfterProjection` |
| `p2_bdb_evidence_test.go` | `TestP2BdbEveryEdgeHasEvidence` |
| `p2_bdb_iam_denied_test.go` | `TestP2BdbIAMDeniedEndsNothing` |
| `p2_bdb_pipeline_test.go` | `TestP2BdbFirstPublication`, `TestP2BdbSwitchOffLeavesTheIdleBarrier` |
| `p2_bdb_recreated_inline_test.go` | `TestP2BdbRecreatedRoleInlinePolicyIsANewIncarnation` |
| `p2_bdb_restore_test.go` | `TestP2BdbLifecycleHistorySurvivesRewrites`, `TestP2BdbRestoredIdentityKeepsItsIdentity`, `TestP2BdbRestoredPolicyKeepsItsStatements`, `TestP2BdbReturningWorkloadIsANewObject` |
| `p2_bdb_restrictions_test.go` | `TestP2BdbBoundaryAndDenyGrantNothing` |
| `p2_bdb_shared_role_test.go` | `TestP2BdbTwoWorkloadsShareOneRole` |
| `p2_bdb_statements_test.go` | `TestP2BdbStatementIdentity` |
| `p2_changes_history_test.go` | `TestP2ChangesLifecycleSurvivesNodeRewrites`, `TestP2ChangesPolicyEdits`, `TestP2ChangesRecreatedRoleAndPolicy` |
| `p2_changes_test.go` | `TestP2ChangesDetachNamesRemainingGrant` |
| `p2_class_decision_test.go` | `TestP2ClassClockAndListingChanged`, `TestP2ClassConcurrentRetriesReplay`, `TestP2ClassCrossWorkspaceIs404`, `TestP2ClassRetryStormReplays`, `TestP2ClassSameOperationTwoWorkloadsConcurrently` |
| `p2_egates_failure_test.go` | `TestP2EgatesE10SharedObjectSurvivesOneSource`, `TestP2EgatesE9aIAMDeniedRetainsEverything`, `TestP2EgatesE9bUnreadableDocumentAndDetachInOneRun` |
| `p2_egates_isolation_test.go` | `TestP2EgatesE14CrossWorkspaceAccess`, `TestP2EgatesE16ExistingProductsUnchanged` |
| `p2_egates_journey_test.go` | `TestP2EgatesE2RightWorkloadAmongDuplicates`, `TestP2EgatesE3WorkloadIdentityStatementsResource`, `TestP2EgatesE4EvidenceAndLimitations`, `TestP2EgatesE5TwoWorkloadsShareOneRole` |
| `p2_egates_lifecycle_test.go` | `TestP2EgatesE6DetachOneOfTwoEquivalentGrants`, `TestP2EgatesE7PolicyEditsAndReattach`, `TestP2EgatesE8ReplaceRoleAndPolicy` |
| `p2_egates_paging_test.go` | `TestP2EgatesE12ChangesDuringPagingAndExploration` |
| `p2_egates_pipeline_test.go` | `TestP2EgatesE13InterruptionLeaseLossReplay`, `TestP2EgatesE1ConnectAndPublishFirstGraph` |
| `p2_egates_supersede_test.go` | `TestP2EgatesE13SupersededScannersWriteNothing` |
| `p2_egates_traversal_test.go` | `TestP2EgatesE11ExternalAccountsCyclesAndLimits`, `TestP2EgatesE11HardBudgetsThroughTheRoutes` |
| `p2_evidence_limitations_test.go` | `TestP2EvidenceLimitationVocabulary` |
| `p2_evidence_route_test.go` | `TestP2EvidenceGrantFactsAndShape`, `TestP2EvidenceNotResourceGrant` |
| `p2_graph_budgets_test.go` | `TestP2GraphExpandTimeReserve`, `TestP2GraphNodeAndEdgeBudgets`, `TestP2GraphPathBudget`, `TestP2GraphPathHopLimit`, `TestP2GraphPathNoneExistsOnlyWhenExhausted`, `TestP2GraphPathRediscoveredEdgesCostNoRows`, `TestP2GraphRootTimeoutIs504`, `TestP2GraphTimeBudgetTruncates`, `TestP2GraphTimeReserve` |
| `p2_graph_exclusions_test.go` | `TestP2GraphDenyAndBoundaryAreRestrictions`, `TestP2GraphNotResourceIsNeverAnEdge` |
| `p2_graph_nested_test.go` | `TestP2GraphNestedOptionalsFitTheirLevel` |
| `p2_graph_params_test.go` | `TestP2GraphWorkspaceAndGates` |
| `p2_graph_teaching_test.go` | `TestP2GraphTeachingPathForward` |
| `p2_graph_trust_test.go` | `TestP2GraphCrossAccountEdge`, `TestP2GraphCycleClosesAndIsNotReexpanded`, `TestP2GraphExternalPrincipalIsTerminal` |
| `p2_idetail_optional_test.go` | `TestP2IdetailOptionalCountsTimeOut` |
| `p2_idetail_permissions_test.go` | `TestP2IdetailPermissionsNeverGrantBoundaryOrDeny` |
| `p2_idetail_usedby_test.go` | `TestP2IdetailUsedBySharedRole` |
| `p2_lists_optional_test.go` | `TestP2ListsCountUpToTimesOut`, `TestP2ListsNoTimeForOptionalWork`, `TestP2ListsOptionalCountTimesOutPageStillReturned` |
| `p2_lists_routes_test.go` | `TestP2ListsRoutesPermissionsAndCrossWorkspace` |
| `p2_lists_test.go` | `TestP2ListsClassificationChangeBetweenPages`, `TestP2ListsDuplicateNamesAcrossAccounts`, `TestP2ListsSearchFindsRowBeyondPageOne` |
| `p2_lists_usedby_test.go` | `TestP2ListsUsedByCountsDistinctWorkloads` |
| `p2_load_reads_test.go` | `TestP2LoadReadPlansWithBindValuesOnlyInsideTheRead` |
| `p2_rdetail_access_test.go` | `TestP2RDetailAccessTwoStatementsOneHolder`, `TestP2RDetailDenyIsARestrictionNotAccess`, `TestP2RDetailNotResourceExcludes` |
| `p2_rdetail_detail_test.go` | `TestP2RDetailSourcesTwoAccounts` |
| `p2_read_snapshot_test.go` | `TestP2ReadDoesNotStraddleAPublication`, `TestP2ReadMandatoryTimeoutIs504`, `TestP2ReadOptionalTimeoutKeepsTheSnapshot`, `TestP2ReadRevisionStale` |
| `p2_s2_coverage_merge_test.go` | `TestP2S2FailedCallsNamedOnEveryDeniedSurface` |
| `p2_s2_pipeline_test.go` | `TestP2S2PipelineQueuedBehindCollectingProjecting` |
| `p2_s2_regions_test.go` | `TestP2S2RegionPatchNamesTheOffenders`, `TestP2S2RegionsListedWithSelection` |
| `p2_s2_scan_runs_test.go` | `TestP2S2ScanRunHistoryShowsEveryEnding` |
| `p2_trust_lab_test.go` | `TestP2TrustLoopProjectsBothEdges`, `TestP2TrustPrincipalsAppear`, `TestP2TrustRecreatedTrustedRole`, `TestP2TrustUnreadableDocumentKeepsItsEdges` |
| `p2_wdetail_identities_test.go` | `TestP2WdetailIdentitiesSectionTotalAboveTheCap`, `TestP2WdetailIdentitiesSharedRoleAndMayAssume` |
| `p2_wdetail_resources_test.go` | `TestP2WdetailResourcesDenyAndBoundaryAreRestrictions`, `TestP2WdetailResourcesNotResource`, `TestP2WdetailResourcesTwoLinesThenDetach` |
| `ig/p2_bdb_scope_test.go` | `TestP2BdbEveryNodeClassResolves`, `TestP2BdbEveryPartitionTargetResolvesInScope` |
| `ig/p2_trust_keys_test.go` | `TestTrustEdgeKeyNamesItsEndpoints` |
| `ig/sourcekey_test.go` | `TestEndpointKeyUsesImmutableKey`, `TestInlinePolicyIsHolderScoped`, `TestRecreatedPolicySharesNoKey`, `TestStatementKeyHashReorderKeepsEditReplaces`, `TestStatementKeySidSurvivesReorderAndEdit` |
| `ir/p2_graph_level_test.go` | `TestP2GraphLevelRearmsEveryStatement` |
| `ir/p2_lists_unit_test.go` | `TestP2ListsTotalsBeyondTheCap` |
| `ir/p2_wdetail_unit_test.go` | `TestP2WdetailSectionTotalsFollowTheListRule` |
| `svc/p2_egates_coverage_test.go` | `TestEgatesPolicyDocumentsNamesTheFirstFailedCall` |
| `tg/exits_test.go` | `TestExitsRefuseASupersededWorker` |
| `tg/p2_bfk_fk_test.go` | `TestB9B20ForeignKeysRejectForeignRows`, `TestB9ForeignKeyCatalogGuard` |
| `tg/proofs_test.go` | `TestProof3RetirementSuspensionRestoration`, `TestProof4KillAfterCommitReplaysAsAlreadyPublished` |
| `tg/schema_gate_test.go` | `TestGraphSwitchFailsClosedBelow036`, `TestGraphSwitchOffIsPhaseOne`, `TestGraphSwitchTransientErrorIsNotCached`, `TestGraphSwitchVerifiesAt036` |

## 6. Mutation evidence

| | |
|---|---|
| **Rule** | §7.3 (l.6509–6510): a scenario "counts only once removing its safeguard makes it fail". §7.4 (l.6541–6545): every result records "the safeguard removed with its observed failure" |
| **Where** | Mutations ran in the `m1/<key>` worktrees before each merge, never on `graph` (§6.2 below) |
| **Sources** | The agent reports, commit messages, and the mutation logs under `SP`. Short file names in the tables are expanded in each table's heading |
| **Re-run** | Nothing. Every row is read from a report or a log |
| **Totals** | **968 checks: 908 caught, 53 missed then fixed, 5 missed and left (3 accepted, 2 open), 2 unverified** |

**Result.**
- **CAUGHT**: the first run of a mutant that compiled failed a test.
- **MISSED→FIXED**: that run passed. A test was then added or strengthened, and the same mutant was re-run and failed. The row says what changed.
- **MISSED**: it passed and was left that way. The row gives the reason.
- **UNVERIFIED**: the log records "caught", but the failure was a compile error, and no compiling variant was ever run.

**Src.**
- **L**: the outcome is in a log. The path is in the table heading.
- **R**: the outcome is only in a report or commit message, not re-verified.
- **R+b**: the outcome is only reported, but `SP` holds the mutant's spec or backup file. That shows the mutant was prepared, not what it did.

**What is counted.** A check is one mutant against one safeguard in one stage (implement, review or fix).
- A mutant whose first attempt did not compile counts once, as its compiling variant.
- A reviewer's missed mutant appears twice: as MISSED→FIXED in the review stage, and as CAUGHT in the fix pass that re-ran it.
- Not counted, but listed under each item:
  - runs by agents that stopped and were later superseded;
  - controls, which are expected to pass;
  - mutants a reviewer reasoned about but never ran.

### 6.1 Counts

| Item | Checks | Caught | Missed→fixed | Missed | Unverified | Where the outcomes are |
|---|---:|---:|---:|---:|---:|---|
| trust | 59 | 56 | 3 | 0 | 0 | impl, fix: L. review: R+b |
| s3a | 53 | 49 | 4 | 0 | 0 | impl: L. review: R+b. fix: 7 L, 2 R+b |
| s3b | 66 | 63 | 3 | 0 | 0 | impl, fix: L. review: R+b |
| s2 | 87 | 83 | 3 | 1 | 0 | impl, fix: L. review: R+b |
| lists | 55 | 51 | 4 | 0 | 0 | impl, fix: L. review: R+b |
| class | 78 | 73 | 4 | 1 | 0 | impl: L. review: R+b. fix: 6 L, 2 R |
| rdetail | 53 | 51 | 0 | 0 | 2 | impl, fix: L |
| changes | 35 | 32 | 3 | 0 | 0 | impl, fix: L. review: R+b |
| idetail | 66 | 63 | 3 | 0 | 0 | impl, fix: L. review: R+b |
| wdetail | 56 | 51 | 4 | 1 | 0 | impl: R+b. review: 4 L, 1 R+b. fix: L |
| graph | 61 | 57 | 4 | 0 | 0 | impl: R+b. review: R+b. fix: L |
| evidence | 60 | 58 | 2 | 0 | 0 | impl, review: L. fix: R+b |
| D-57 commit `3ea0244` | 3 | 3 | 0 | 0 | 0 | R+b |
| **Waves A–B** | **732** | **690** | **37** | **3** | **2** | |
| bfk | 31 | 28 | 3 | 0 | 0 | impl, fix: L. review: R+b; the MUT-3/3b re-runs L |
| bdb | 37 | 37 | 0 | 0 | 0 | impl: R+b, 29 of 31 re-run L. review: R+b. fix: L |
| contract | 40 | 38 | 2 | 0 | 0 | impl, fix: L. review: R+b |
| egates | 79 | 74 | 5 | 0 | 0 | impl, fix, review: L (review: 5 in `SP/egmut`, 3 from an earlier run) |
| load | 49 | 41 | 6 | 2 | 0 | all L, except one fix-stage miss (R) |
| **Wave C** | **236** | **218** | **16** | **2** | **0** | |
| **Total** | **968** | **908** | **53** | **5** | **2** | |

The five missed:
- Accepted:
  - s2 fix M7e and class #37a are equivalent mutants.
  - wdetail fix F5-trust-retired hit a redundant gate, which was deleted.
- Open: load LR-M1 and LR-M3, from an earlier load review, were never re-run after the fix pass.

The two unverified:
- rdetail impl M08 and M38. Their "catch" was a compile error.

Three other gaps a reviewer should know about:
- The only records of the graph implementation's 29 mutations are reports, plus the 29 specs in `SP/mut/specs.json`.
- The only records of the wdetail implementation's 34 mutations are reports, plus spec files and a backup per mutant.
- The only records of the evidence fix pass's 15 mutations are reports, plus backup files.

### 6.2 Whether the results hold at HEAD

Every mutation ran before its item's merge. What changed afterwards:

- **bdb.** The 35 runs in `SP/bdbfix3/results_1046c1a.jsonl` were at `1046c1a`: 29 implement-stage production mutants, their specs identical to `SP/bdb_mut`, and the fix pass's `W1`–`W4`, `B11e` and `B11r` (§6.5 below). 34 were CAUGHT and `W2`, a control, passed. Every file was restored and checked by sha256. The last bdb commit, `98d75d9`, changed only a header comment and one failure message, plus the helper that formats it (`git diff 1046c1a 98d75d9`). At HEAD the bdb tests differ from `98d75d9` only by `e63dfa7`'s DSN guard, so the results apply to the merged tests. Every mutated safeguard's text is still present verbatim at HEAD, in the file each spec names (string match on the specs' `old` text; not re-run). The runs predate the `contract`, `egates` and `load` merges, which changed production code; the behaviour was not re-run after them.
- **bfk.** Sources: `wave_c_reports.md` impl:bfk and review:bfk, plus the fix pass in `SP/bfk_mut/*.out`. Their pre-mutation sha256 (`SP/bfk_mut/pre.sha`) matches both test files at `21436d4`; the merge `393dc32` changed only `D-bfk` → `D-95`, in three comments and one skip message. No migration changed after `21436d4` (`git diff 21436d4 HEAD -- migrations/` is empty), so the logs' "130 foreign keys in scope" describes HEAD's schema too; the case count was not re-derived at HEAD. The review's MUT-3 and MUT-3b were re-run by the first, stopped fixer on its uncommitted guard, which WIP `77da653` (09:37) captured. The logs record no commit, but they print the guard's log line at l.682, where `77da653` has it.
- **egates.** The implementation's mutations ran up to `3dfa4b0` and the fix pass's up to `d0f716c`. After the merge, `9248549` changed only what E1, E2, E3 and E10 expect of D-96 and D-98(b), and removed no assertion (§5.2 above).
- **M0.** B5, B14 and B15's M0 mutations were observed only at `4593476`; M10 and M4 ran on the pre-M1 versions of their tests (§5.3 above, item 7).

### 6.3 Wave A

#### trust (T3.4/T4.7): impl `ab2f7994`, fix `2b92e8f7`

59 checks: 56 caught, 3 missed→fixed.

**Implement.** Source: L, `SP/trust3/results.json`. It holds 64 records: the 48 mutants, 12 second-test records, and 4 first attempts that only broke the build (P13, G3, G15, G23, each logged `caught: True` on the build failure). The agent discarded those four and ran compiling variants. Files: `tp` = internal/awsdiscovery/trust_policy.go, `tr` = internal/igagraph/trust.go, plus the others named.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| P1 | `tp`: a skipped statement no longer makes the document unreadable (D-45) | TestTrustMalformedStatementIsolated; TestP2TrustUnreadableDocumentKeepsItsEdges | CAUGHT | L |
| P2 | `tp`: per-statement failure isolation removed | TestTrustMalformedStatementIsolated | CAUGHT | L |
| P3 | `tp`: a non-string condition value fails the document | TestTrustNonStringConditionValueParses; TestP2TrustPrincipalsAppear | CAUGHT | L |
| P4+G5 | `tp` + `tr`: NotPrincipal becomes an edge (parser and projector removed together) | TestP2TrustPrincipalsAppear | CAUGHT | L |
| P4 | `tp`: NotPrincipal entries returned as principals (parser alone) | TestTrustNotPrincipalRecordedNeverEmitted | CAUGHT | L |
| P5 | `tp`: sub-claim order not sorted | TestTrustSubjectsAreDeterministic | CAUGHT | L |
| P6 | `tp`: content hash leaves out Principal (D-46) | TestTrustContentHash | CAUGHT | L |
| P7 | `tp`: a statement with no assume action still yields an edge (D-43) | TestTrustActionDecidesMechanism | CAUGHT | L |
| P8 | `tp`: a negated sub names the principal it excludes | TestTrustPrincipalForms | CAUGHT | L |
| P9 | `tp`: OIDC issuer taken from the provider ARN, not host+path (D-42) | TestTrustPrincipalForms; TestP2TrustPrincipalsAppear | CAUGHT | L |
| P10 | `tp`: `:root` ARN and bare account id become two nodes (D-42) | TestTrustPrincipalForms; TestP2TrustPrincipalsAppear | CAUGHT | L |
| P11 | `tp`: session ARNs resolve to an identity | TestTrustPrincipalForms | CAUGHT | L |
| P12 | `tp`: a Null/Bool operator value becomes a subject | TestTrustPrincipalForms | CAUGHT | L |
| P13b | `tp`: another issuer's sub key taken as this principal's subject (P13 did not build) | TestTrustPrincipalForms | CAUGHT | L |
| P14 | `tp`: an absent trust document read as "trusts nobody" | TestTrustReadTrustDocument | CAUGHT | L |
| G1 | `tr`: projectTrust writes edges for an unreadable role | TestP2TrustUnreadableDocumentKeepsItsEdges | CAUGHT | L |
| G2 | `tr`: Exclusions.UnreadableTrust not filled | TestP2TrustUnreadableDocumentKeepsItsEdges | CAUGHT | L |
| G3b | internal/igagraph/load.go: a missing document with no error is not unreadable (G3 did not build) | TestTrustUnreadableIncludesAMissingDocument | CAUGHT | L |
| G4 | `tr`: a Deny statement becomes an edge (D-44) | TestP2TrustPrincipalsAppear | CAUGHT | L |
| G6 | internal/igagraph/project.go: trust flags not written to provider_attrs | TestP2TrustPrincipalsAppear | CAUGHT | L |
| G7 | `tr`: an unreadable document drops the incarnation's flags | TestP2TrustUnreadableDocumentKeepsItsEdges | CAUGHT | L |
| G8 | `tr`: NotAction statement keys not recorded (D-88) | TestP2TrustNotActionMarksItsStatement | CAUGHT | L |
| G9 | `tr`: D-88 marker not carried across an unreadable document | TestP2TrustNotActionMarksItsStatement | CAUGHT | L |
| G10 | `tr`: an association with no cluster issuer no longer protects the pod edges | TestP2TrustIRSAAndPodIdentity; TestTrustPodIdentityWithoutAnIssuerIsUnresolved | CAUGHT | L |
| G11 | internal/igagraph/reconcile.go: protected() leaves out the pod-identity partition | TestTrustProtectedPartitions; TestTrustPodIdentityWithoutAnIssuerIsUnresolved | CAUGHT | L |
| G12 | `tr`: an issuer-less k8s_service_account node is created (D-42) | TestTrustPodIdentityWithoutAnIssuerIsUnresolved; TestP2TrustIRSAAndPodIdentity | CAUGHT | L |
| G13 | `tr`: derived exact_arn_match resolution pass removed (D-41 rule 1) | TestP2TrustFarAccountConnectsLater | CAUGHT | L |
| G14 | `tr`: this run's own identities not preferred | TestP2TrustRecreatedTrustedRole; TestP2TrustLoopProjectsBothEdges | CAUGHT | L |
| G15b | `tr`: a pod association whose role is outside the snapshot is not skipped (G15 did not build; G15b fails by a nil-pointer panic) | TestTrustPodIdentityRoleOutsideTheSnapshotIsSkipped | CAUGHT | L |
| G16 | internal/igagraph/evidence.go: can_assume evidence not linked per edge | TestP2TrustPrincipalsAppear; TestP2TrustIRSAAndPodIdentity | CAUGHT | L |
| G17 | `tr`: a live external principal stops being the source once the far account connects (D-41) | TestP2TrustFarAccountConnectsLater | CAUGHT | L |
| G18 | `tr`: identity source keyed by ARN instead of endpoint key | TestP2TrustRecreatedTrustedRole | CAUGHT | L |
| G19 | internal/igagraph/sourcekey.go: CanAssumeKey leaves out the source endpoint | TestTrustEdgeKeyNamesItsEndpoints; TestP2TrustPrincipalsAppear | CAUGHT | L |
| G20 | `tr`: an identity in an unconnected account used as source | TestP2TrustRevokedAccountIsNotConnected | CAUGHT | L |
| G21 | load.go: ConnectedAccounts includes revoked connectors (D-61) | TestP2TrustRevokedAccountIsNotConnected | CAUGHT | L |
| G22 | `tr`: an own-account principal a complete listing no longer names stays the source | TestP2TrustUnlistedOwnPrincipalIsNotTheSource | CAUGHT | L |
| G23b | `tr`: a denied listing taken as proof a principal is gone (G23 did not build) | TestTrustUnlistedPrincipalOfADeniedListingStaysTheSource | CAUGHT | L |
| G24 | repository/iga_graph_repository.go: SetDerivedResolution overwrites an asserted row | TestP2TrustAssertedResolutionUntouched | CAUGHT | L |
| G25 | iga_graph_repository.go: UpsertExternalPrincipal writes the resolution columns | TestP2TrustAssertedResolutionUntouched | CAUGHT | L |
| G27 | services/cloud_aws_iam_scan.go: the IAM scanner stops writing the trust columns | TestP2TrustPrincipalsAppear | CAUGHT | L |
| G28 | repository/cloud_identity_repository.go: fenced upsert does not refresh the trust columns | TestP2TrustUnreadableDocumentKeepsItsEdges | CAUGHT | L |
| G29 | reconcile.go: retirement cascade does not end external-principal edges into a retired role | TestTrustRetiredRoleEndsItsExternalEdges | CAUGHT | L |
| G30 | `tr`: a can_assume row written without its partition key | TestP2TrustUnreadableDocumentKeepsItsEdges | CAUGHT | L |
| G31 | `tr`: pod-identity edges reconciled outside their own partition | TestP2TrustIRSAAndPodIdentity | CAUGHT | L |
| G32 | sourcekey.go: a unique Sid no longer keys the trust statement | TestTrustStatementKeys; TestP2TrustUnreadableDocumentKeepsItsEdges | CAUGHT | L |
| G33 | sourcekey.go: a duplicated Sid used as identity | TestTrustStatementKeys | CAUGHT | L |
| G34 | sourcekey.go: `pod:` prefix dropped, so the node collides with the IRSA oidc node | TestTrustEdgeKeyNamesItsEndpoints; TestP2TrustIRSAAndPodIdentity | CAUGHT | L |
| G36 | `tr`: "readable at collection, unreadable now" no longer a hard error (per-statement branch) | TestTrustReadableAtCollectionUnreadableNowFailsThePass | CAUGHT | L |

**Review.** Source: R+b. The only record is `SP/review_mut/trust.go.orig`, a backup of the mutated file. What each mutant passed, per the review: RV-M3 passed -run TestP2 on tests/integration, all of tests/igagraph and internal/igagraph; RV-M1 passed "every trust test"; RV-M2 passed "every test".

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| RV-M3 | `tr` ~l.413: the whole-document "parsed at collection, failed now" error replaced by an empty document | none | MISSED→FIXED. TestTrustWholeDocumentUnreadableNowFailsThePass added; the fix's D is caught | R+b |
| RV-M1 | `tr` ~l.211: liveExternalPrincipals `WHERE (ep.workspace_id = ? OR TRUE)` | none | MISSED→FIXED. TestTrustLiveExternalPrincipalsAreThisWorkspaces added; the fix's E is caught | R+b |
| RV-M2 | `tr` ~l.440: incarnation check removed (`live == nil`) | none | MISSED→FIXED. TestP2TrustRecreatedRoleInheritsNoTrustFlags added; the fix's F is caught | R+b |

**Fix.** Source: L, `SP/trustfix_mut/results.json`, with a restored sha256 on every record.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| A | internal/awsdiscovery/eks.go: a failed DescribePodIdentityAssociation silently skipped | TestP2TrustPodIdentityDescribeFailureKeepsTheEdge | CAUGHT | L |
| B | services/cloud_aws_permission_scan.go: the scanner drops the rows it read | TestP2TrustPodIdentityDescribeFailureKeepsTheEdge | CAUGHT | L |
| C | cloud_aws_permission_scan.go: partial reported as another state. The report says "as surfaceResult"; the backup is named `C_scan_partial_as_denied` | TestP2TrustPodIdentityDescribeFailureKeepsTheEdge | CAUGHT | L |
| D | `tr`: the whole-document error replaced by an empty document (reviewer M3) | TestTrustWholeDocumentUnreadableNowFailsThePass | CAUGHT | L |
| E | `tr`: live external principals of any workspace (reviewer M1) | TestTrustLiveExternalPrincipalsAreThisWorkspaces | CAUGHT | L |
| F | `tr`: a recreated role inherits the trust flags (reviewer M2) | TestP2TrustRecreatedRoleInheritsNoTrustFlags | CAUGHT | L |
| G | `tp`: anyoneMechanism reverted to AssumeRole-only | TestTrustActionDecidesMechanism; TestTrustAnyoneByWebIdentityIsAnEdge | CAUGHT | L |
| H | `tr`: a pod edge linked to the role's own observation | TestP2TrustPodIdentityEvidenceRatchet | CAUGHT | L |

A–C tested the trust fix's PodIdentityDetailFailures and its podIdentityCoverage. The merge took s3b's side (ItemFailures), as the trust fix's merge note directs: `git grep PodIdentityDetailFailures e63dfa7` finds nothing, and the podIdentityCoverage on graph is s3b's (services/cloud_aws_collection_coverage.go:205), not the trust fix's. The replacement's tally is mutation-checked by s3b fix M13–M15 and M20. H's ratchet flag `trustPodEvidenceWriterLanded` is now `true` (tests/integration/p2_trust_lab_test.go:218), so the test now asserts zero bare pod edges.

#### s3a (T3.1/T3.3, policy half of T3.5): impl `0615e8da`, fix `aa0d5944`

53 checks: 49 caught, 4 missed→fixed.

**Implement.** Source: L. `SP/s3a_mut3.log` holds the first 41 runs, where M20 and M32 show NOT. `SP/s3a_mutation_results3.json` holds 42 records: the first run's 39 catches, the re-runs of M20 and M32, and the extra M20b. That is 44 runs in all, matching the report's "44 mutation checks". Files: `ad` = internal/awsdiscovery/authdetails.go, `ps` = services/cloud_aws_permission_scan.go, `is` = services/cloud_aws_iam_scan.go, `ow` = services/cloud_observation_writer.go.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| M1 | `ps`: one unreadable managed document aborts the scan | TestP2S3aOneUnreadableDocumentIsolated | CAUGHT | L |
| M2 | `is`: one fetch failure makes iam_policies denied | TestP2S3aOneUnreadableDocumentIsolated | CAUGHT | L |
| M3 | internal/awsdiscovery/policy_statements.go: D-49 skip check removed | TestP2S3aUnusableStatementMarksDocumentUnreadable | CAUGHT | L |
| M4 | `is`: iam_roles takes the Group listing's error | TestP2S3aPerFilterSurfaceStates | CAUGHT | L |
| M5 | `ad`: one call names all four filters | TestP2S3aPerFilterSurfaceStates | CAUGHT | L |
| M6 | `ad`: pagination stops after page 1 | TestP2S3aPaginationAcrossPages | CAUGHT | L |
| M7 | `is`: D-48 keep list dropped | TestP2S3aRescanReplacesListedAttrsKeepsUnlisted | CAUGHT | L |
| M8 | repository/cloud_identity_repository.go: attrs merged wholesale | TestP2S3aRescanReplacesListedAttrsKeepsUnlisted | CAUGHT | L |
| M9 | cloud_identity_repository.go: trust columns missing from ON CONFLICT | TestP2S3aTrustDocumentStoredAndJudged | CAUGHT | L |
| M10 | `is`: trust_parse_error not taken from ValidateTrustDocument | TestP2S3aTrustDocumentStoredAndJudged | CAUGHT | L |
| M11 | `ps`: unreadable trust documents not named under policy_documents | TestP2S3aTrustDocumentStoredAndJudged | CAUGHT | L |
| M12 | `ow`: observation conflict target without policy_id | TestP2S3aPolicyObservationPerVersion | CAUGHT | L |
| M13 | `ad`: customer-managed policies fetched with GetPolicy/GetPolicyVersion | TestP2S3aCustomerPoliciesFromTheListing | CAUGHT | L |
| M14 | `ad`: first listed version read, not the default | TestP2S3aCustomerPoliciesFromTheListing | CAUGHT | L |
| M15 | `ps`: unattached customer-managed policies get no row | TestP2S3aCustomerPoliciesFromTheListing | CAUGHT | L |
| M16 | `ad`: user permissions boundary not read | TestP2S3aUserInGroupWithBoundary | CAUGHT | L |
| M17 | `ad`: membership to an unlisted group guessed into an ARN | TestS3aAuthorizationDetailsOneCallPerFilterAcrossPages | CAUGHT | L |
| M18 | `ps`: cloud_policy reconcile vetoed by one unreadable document | TestP2S3aOneUnreadableDocumentIsolated | CAUGHT | L |
| M19 | `ps`: cloud_policy reconcile runs although a listing failed | TestP2S3aPerFilterSurfaceStates | CAUGHT | L |
| M20 | `ad`: call errors use classify()'s text, with no call name and no AWS code | TestP2UnreadableAndDetachedInOneRun | MISSED→FIXED. The first run passed because the fake's message already contained the call and the code. `0615e8d` now requires "AWS returned AccessDenied for iam:GetPolicyVersion" and rejects the assume-role wording; the re-run was caught | L |
| M20b | the same mutant, run against the isolation test | TestP2S3aOneUnreadableDocumentIsolated | CAUGHT (after `0615e8d`) | L |
| M21 | internal/igagraph/reconcile.go: protected() disabled, on the re-expressed scenario 4 | TestP2UnreadableAndDetachedInOneRun | CAUGHT | L |
| M22 | reconcile.go: protected() disabled, on the isolation gate | TestP2S3aOneUnreadableDocumentIsolated | CAUGHT | L |
| M23 | `is`: instance profiles kept by the merge (D-52) | TestP2S3aInstanceProfilesInAttrs | CAUGHT | L |
| M24 | `is`: instance profiles not stored | TestP2S3aInstanceProfilesInAttrs | CAUGHT | L |
| M25 | `is`: surfaceResult does not stamp api/error_code (D-71) | TestP2S3aPerFilterSurfaceStates | CAUGHT | L |
| M26 | `ps`: policy_documents items not written | TestP2S3aOneUnreadableDocumentIsolated | CAUGHT | L |
| M27 | `ps`: policy_documents items unbounded | TestS3aPolicyDocumentsItemsAreBounded | CAUGHT | L |
| M28 | `ow`: subject-less conflict predicate without policy_id | TestP2S3aObservationDedupeWithPolicySubject | CAUGHT | L |
| M29 | `ow`: a policy subject not counted as a subject | TestP2S3aObservationDedupeWithPolicySubject | CAUGHT | L |
| M30 | internal/awsdiscovery/iam.go: a ListAccessKeys failure falls back to classify() | TestP2S3aPerFilterSurfaceStates | CAUGHT | L |
| M31 | `is`: the role observation leaves out the trust document | TestP2S3aTrustDocumentStoredAndJudged | CAUGHT | L |
| M32 | `is`: the user observation does not list its groups | TestP2S3aUserInGroupWithBoundary | MISSED→FIXED. Evidence links by subject, so the dropped list went unnoticed. `0615e8d` makes the E3 test check the listed group; the re-run was caught | L |
| M33 | `ad`: an AWS-managed boundary not fetched (D-50) | TestP2S3aUserInGroupWithBoundary | CAUGHT | L |
| M34 | `ps`: an AWS-managed policy in two accounts collapses to one row | TestP2S3aAWSManagedPolicyInTwoAccounts | CAUGHT | L |
| M35 | `ad`: user tags not read | TestP2S3aUserInGroupWithBoundary | CAUGHT | L |
| M36 | `is`: tags treated as not returned by the listing | TestP2S3aRescanReplacesListedAttrsKeepsUnlisted | CAUGHT | L |
| M37 | `ps`: policy_documents written although nothing failed | TestP2S3aTrustDocumentStoredAndJudged | CAUGHT | L |
| M38 | `ad`: group names never resolved to ARNs | TestP2S3aUserInGroupWithBoundary | CAUGHT | L |
| M39 | `ad`: an attachment under a failed listing blamed on absence | TestS3aAuthorizationDetailsFailuresArePerFilter | CAUGHT | L |
| M40 | `ps`: documentError ignores the skip count (D-49) | TestP2S3aUnusableStatementMarksDocumentUnreadable | CAUGHT | L |
| M41 | `ps`: an unreadable policy's row and attachment skipped | TestP2S3aOneUnreadableDocumentIsolated | CAUGHT | L |

**Review.** Source: R+b, backups in `SP/rev_s3a_bak/`. Both mutants passed the whole integration package; MUT-2 also passed tests/igagraph.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| MUT-1 | `ps` ~l.953: the inline noteUnreadable replaced by `_ = docErr` | none | MISSED→FIXED. TestP2S3aMalformedDocumentsIsolated added; the fix's MUT-B is caught | R+b |
| MUT-2 | `is` ~l.510: validation skipped for an absent trust document | none | MISSED→FIXED. TestP2S3aTrustDocumentStoredAndJudged gains a nil AssumeRolePolicyDocument; the fix's MUT-C is caught | R+b |

**Fix.** Source: `SP/mut/MUT-*.log` for the rows marked L. MUT-E and MUT-F left only `.orig` backups.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| MUT-A | `ow`: the observed_subject stamp removed | TestP2S3aDeletedPolicyEvidenceNeverBlocksReconcile; TestP2S3aIdenticalFactsOnDeletedSubjectsKeepBothObservations | CAUGHT | L |
| MUT-A2 | `ow`: every subject stamped except policy subjects | TestP2S3aDeletedPolicyEvidenceNeverBlocksReconcile ("B detached", "detached again") | CAUGHT | L |
| MUT-E | `ow`: the caller's map stamped in place | unit tests in services/p2_s3a_evidence_test.go | CAUGHT | R+b |
| MUT-F | `ow`: the null-object guard dropped (the test panics) | the same unit tests | CAUGHT | R+b |
| MUT-B | reviewer MUT-1 | TestP2S3aMalformedDocumentsIsolated | CAUGHT | L |
| MUT-B2 | `ps`: the same mutation, on the managed noteUnreadable | TestP2S3aMalformedDocumentsIsolated | CAUGHT | L |
| MUT-C | reviewer MUT-2 | TestP2S3aTrustDocumentStoredAndJudged | CAUGHT | L |
| MUT-D | cloud_identity_repository.go: incarnation `CASE WHEN true` | TestP2S3aRescanReplacesListedAttrsKeepsUnlisted (recreated role) | CAUGHT | L |
| MUT-D2 | cloud_identity_repository.go: `CASE WHEN false` | TestP2S3aRescanReplacesListedAttrsKeepsUnlisted (same role, "KEPT") | CAUGHT | L |

#### s3b (T3.5–T3.8): impl `63c66e60`, fix `50607742`

66 checks: 63 caught, 3 missed→fixed.

**Implement.** Source: L, `SP/s3b_mut_log.jsonl`. It holds 42 records: M17 and M36 first failed to build (logged `caught: False, build_failed: True`), and their compiling variants M17b and M36b were caught. Files: `bd` = internal/awsdiscovery/bedrock.go, `wr` = repository/cloud_workload_repository.go, `ws` = services/cloud_aws_workload_scan.go, `cc` = services/cloud_aws_collection_coverage.go, `if` = internal/awsdiscovery/item_failures.go.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| M01 | `bd`: no constructed agent ARN on a GetAgent failure | TestP2S3bFailedGetAgentKeepsKeyAndBlocksDeletion | CAUGHT | L |
| M02 | `bd`: a GetAgent failure not counted | TestP2S3bFailedGetAgentKeepsKeyAndBlocksDeletion | CAUGHT | L |
| M03 | internal/igagraph/project.go: projectExecution skip for detail-incomplete workloads removed (D-53) | TestP2S3bFailedGetAgentKeepsKeyAndBlocksDeletion | CAUGHT | L |
| M04 | project.go: a new detail-incomplete workload projected as none (D-53) | TestP2S3bNewAgentWithFailedDetailIsNotProjectedAsNone | CAUGHT | L |
| M05 | `wr`: identity_id not kept on a detail failure | TestP2S3bFailedGetAgentKeepsKeyAndBlocksDeletion | CAUGHT | L |
| M06 | `wr`: attrs blanked on a detail failure | TestP2S3bFailedGetAgentKeepsKeyAndBlocksDeletion | CAUGHT | L |
| M07 | `bd`: no constructed gateway ARN | TestP2S3bFailedGetGatewayIsPartialAndKeepsTheKey | CAUGHT | L |
| M08 | `bd`: a GetGateway failure not counted | TestP2S3bFailedGetGatewayIsPartialAndKeepsTheKey | CAUGHT | L |
| M09 | `bd`: a ListGatewayTargets failure not counted | TestP2S3bFailedGetGatewayIsPartialAndKeepsTheKey | CAUGHT | L |
| M10 | `wr`: the previous target list not kept | TestP2S3bFailedGetGatewayIsPartialAndKeepsTheKey | CAUGHT | L |
| M11 | internal/awsdiscovery/workloads.go: an ECS describe failure not kept or counted | TestP2S3bECSDescribeAndInstanceProfileFailuresArePartial | CAUGHT | L |
| M12 | workloads.go: a GetInstanceProfile failure not counted | TestP2S3bECSDescribeAndInstanceProfileFailuresArePartial | CAUGHT | L |
| M13 | `bd`: runtime status not taken from the list item | TestP2S3bAgentCoreRuntimeStatusIsCollected | CAUGHT | L |
| M14 | `bd`: gateway target type not collected | TestP2S3bFailedGetGatewayIsPartialAndKeepsTheKey | CAUGHT | L |
| M15 | services/cloud_aws_collection_evidence.go: access-key evidence keyed by user ARN | TestP2S3bAccessKeyEvidenceAttachesToTheCredentialAndDedupes | CAUGHT | L |
| M16 | cloud_aws_collection_evidence.go: last_used_at hashed | TestP2S3bAccessKeyEvidenceAttachesToTheCredentialAndDedupes | CAUGHT | L |
| M17b | cloud_aws_collection_evidence.go: pod-identity evidence keyed by role ARN (M17 did not build) | TestP2S3bPodIdentityEvidenceIsTheAssociations | CAUGHT | L |
| M18 | `ws`: activity not partial above the cap | TestP2S3bActivityIsPartialAboveTheCap | CAUGHT | L |
| M19 | `cc`: a throttle not reported throttled | TestP2S3bActivityThrottledOnThrottle | CAUGHT | L |
| M20 | `wr`: activity sample not ordered by `native_id COLLATE "C"` | TestP2S3bActivitySampleIsTheFirstByARN | CAUGHT | L |
| M21 | `ws`: capped_after not stamped | TestP2S3bActivitySampleIsTheFirstByARN | CAUGHT | L |
| M22 | `ws`: workload reconcile vetoed by activity | TestP2S3bActivityIsPartialAboveTheCap | CAUGHT | L |
| M23 | `ws`: usage reconcile not gated on activity being reached | TestP2S3bActivityIsPartialAboveTheCap | CAUGHT | L |
| M24 | services/cloud_aws_permission_scan.go: per-resource resource-policy failures not counted | TestP2S3bResourcePolicyFailuresAreCounted | CAUGHT | L |
| M25 | `cc`: resource_policies not denied when every read failed | TestP2S3bResourcePolicyFailuresAreCounted | CAUGHT | L |
| M26 | `cc`: resource_policies count is not the failures (D-93) | TestP2S3bResourcePolicyFailuresAreCounted | CAUGHT | L |
| M27 | services/cloud_aws_iam_scan.go: organizations not reported unsupported | TestP2S3bOrganizationsIsReportedUnsupported | CAUGHT | L |
| M28 | `if`: NXDOMAIN not mapped to ErrServiceNotInRegion | TestP2S3bServiceNotOfferedInRegionIsUnsupported | CAUGHT | L |
| M29 | `ws`: prior rows no longer veto unsupported | TestP2S3bServiceNotOfferedInRegionIsUnsupported | CAUGHT | L |
| M30 | `ws`: a partial compute surface no longer blocks ReconcileWorkloads | TestP2S3bFailedGetAgentKeepsKeyAndBlocksDeletion | CAUGHT | L |
| M31 | internal/awsdiscovery/eks.go: a pod-identity describe failure not counted | TestP2S3bPodIdentityDescribeFailureIsPartialAndKeepsTheEdge | CAUGHT | L |
| M32 | eks.go: a failed DescribeCluster kept, with an empty issuer | TestP2S3bPodIdentityDescribeFailureIsPartialAndKeepsTheEdge | CAUGHT | L |
| M33 | workloads.go: partition missing from WorkloadARN | TestWorkloadKeyUsesTheConnectorPartition | CAUGHT | L |
| M34 | `bd` + `ws`: gateway source_api becomes aws:unknown | TestP2S3bFailedGetGatewayIsPartialAndKeepsTheKey | CAUGHT | L |
| M35 | cloud_aws_permission_scan.go: readable associations not written when others fail | TestP2S3bPodIdentityPartialStillWritesWhatWasRead | CAUGHT | L |
| M36b | `ws`: CloudTrail event evidence keyed by identity ARN (M36 did not build) | TestP2S3bCloudTrailEventIsNotEdgeEvidence | CAUGHT | L |
| M37 | `if`: listing failures do not name the call | TestP2S3bListingFailureNamesTheCall | CAUGHT | L |
| M38 | models/cloud_discovery.go: gateway_targets not stored under the D-85 keys | TestP2S3bFailedGetGatewayIsPartialAndKeepsTheKey | CAUGHT | L |
| M39 | services/cloud_observation_writer.go: policy_id missing from the conflict target | TestP2S3bPolicyAndSubjectlessObservationsDedupe | CAUGHT | L |
| M40 | `if`: an empty tally returned as a non-nil error | TestS3bItemFailuresCountsItemsOnceAndNamesEachCall | CAUGHT | L |

**Review.** Source: R+b. No reviewer log was found; the backups are `SP/mutA_backup.go` (services/cloud_aws_workload_scan.go, 20:44), `SP/mutB_backup.go` (internal/awsdiscovery/workloads.go, 20:46) and `SP/mutC_backup.go` (cloud_aws_workload_scan.go, 20:48), matched to M-A, M-B and M-C by file and time. Every mutant passed all TestP2 tests and the older AWS integration tests (81, per the M-A finding); M-B and M-C passed the unit suites too.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| M-A | `ws` ~l.264: the gateways prefix removed from computeSurfacePrefixes | none | MISSED→FIXED. TestP2S3bWorkloadDeletionIsPerSurface added; the fix's M3 is caught | R+b |
| M-B | workloads.go ~l.400: the cached GetInstanceProfile failure returns `ans.role, nil` | none | MISSED→FIXED. Two instances per profile, plus TestS3bEveryInstanceBehindAnUnreadableProfileIsIncomplete; the fix's M5 is caught | R+b |
| M-C | `ws` ~l.182: scope partition hard-coded to `""` | none | MISSED→FIXED. TestP2S3bConstructedARNUsesTheConnectorPartition added; the fix's M6 is caught | R+b |

**Fix.** Source: L, `SP/s3bfix_mut_log.jsonl`, 24 records with a restored sha on each. M1 was first logged `caught: True` on a broken build and then re-run as a compiling mutant. The log has no M12; the report's "M1–M21 plus M3b, M8b, M8c" is 24 names, but it says 23 mutants, which matches the log.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| M1 | `ws`: reached-only scope removed (compiling re-run) | TestP2S3bFailedGetAgentKeepsKeyAndBlocksDeletion; TestP2S3bWorkloadDeletionIsPerSurface | CAUGHT | L |
| M2 | `wr`: the ReconcileWorkloads scope clause removed | TestP2S3bWorkloadDeletionIsPerSurface | CAUGHT | L |
| M3 | `ws`: gateways dropped from computeSurfaceKinds (reviewer M-A) | TestP2S3bWorkloadDeletionIsPerSurface | CAUGHT | L |
| M3b | `ws`: agents dropped from computeSurfaceKinds | TestP2S3bWorkloadDeletionIsPerSurface | CAUGHT | L |
| M4 | `ws`: connector-wide veto restored | TestP2S3bFailedGetAgentKeepsKeyAndBlocksDeletion; TestP2S3bWorkloadDeletionIsPerSurface | CAUGHT | L |
| M5 | workloads.go: the cached profile failure read as "no role" (reviewer M-B) | TestP2S3bECSDescribeAndInstanceProfileFailuresArePartial; TestS3bEveryInstanceBehindAnUnreadableProfileIsIncomplete | CAUGHT | L |
| M6 | `ws`: partition not passed to the scope (reviewer M-C) | TestP2S3bConstructedARNUsesTheConnectorPartition | CAUGHT | L |
| M7 | `wr`: the targets arm restored in the detail branch | TestP2S3bGatewayTargetsMergeWhileGetGatewayFails | CAUGHT | L |
| M8 | `wr`: the old targets and flag not dropped | TestP2S3bGatewayTargetsMergeWhileGetGatewayFails | CAUGHT | L |
| M8b | `wr`: the old targets not dropped | TestP2S3bGatewayTargetsMergeWhileGetGatewayFails | CAUGHT | L |
| M8c | `wr`: the old flag not dropped | TestP2S3bGatewayTargetsMergeWhileGetGatewayFails | CAUGHT | L |
| M9 | models/cloud_discovery.go: target omitempty restored | TestP2S3bGatewayTargetsMergeWhileGetGatewayFails | CAUGHT | L |
| M10 | `wr`: adoptBareIDRow update removed | TestP2S3bBareIDRowsAreAdoptedByTheirARN | CAUGHT | L |
| M11 | `wr`: adoptBareIDRow delete removed | TestP2S3bBareIDRowsAreAdoptedByTheirARN | CAUGHT | L |
| M13 | `cc`: reader tallies not merged | TestP2S3bPodIdentityCoverageNamesEveryFailure | CAUGHT | L |
| M14 | `cc`: a listing failure no longer outranks partial | TestP2S3bPodIdentityCoverageNamesEveryFailure | CAUGHT | L |
| M15 | `cc`: a denial no longer outranks throttle | TestP2S3bPodIdentityCoverageNamesEveryFailure | CAUGHT | L |
| M16 | eks.go: ListClusters not through listErr | TestP2S3bPodIdentityRegionWithoutEKSIsSkipped | CAUGHT | L |
| M17 | cloud_aws_permission_scan.go: prior-binding guard removed | TestP2S3bPodIdentityRegionWithoutEKSIsSkipped | CAUGHT | L |
| M18 | repository/cloud_permission_repository.go: region-less edges not counted | TestP2S3bPodIdentityRegionWithoutEKSIsSkipped | CAUGHT | L |
| M19 | cloud_aws_permission_scan.go: edge region attrs not written | TestP2S3bPodIdentityRegionWithoutEKSIsSkipped | CAUGHT | L |
| M20 | `if`: Merge does not sum Failed | TestP2S3bPodIdentityCoverageNamesEveryFailure; TestS3bItemFailuresMergeSumsEveryReader | CAUGHT | L |
| M21 | cloud_aws_permission_scan.go: a region that listed clusters is skipped as not offered | TestP2S3bPodIdentityRegionThatListedIsNeverNotOffered | CAUGHT | L |

#### s2 (T2.1–T2.4): impl `0bb7ab58`, fix `230535ec`

87 checks: 83 caught, 3 missed→fixed, 1 missed (equivalent).

**Implement.** Source: L. `SP/s2_mutation_results.json` has 53 records; `SP/s2_mutations.log` holds the same runs plus M14's first attempt, which failed to build (`caught=False build_failed=True`) and was re-run. The report's 38 rows group these 53 mutants. Files: `ob` = services/cloud_aws_onboarding.go, `rg` = internal/awsdiscovery/regions.go, `cv` = internal/igaread/coverage.go, `pl` = internal/igaread/pipeline.go, `cp` = controllers/platform/cloud_aws_controller_p2.go, `sr` = repository/cloud_scan_run_repository.go.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| M1 | `sr`: Requeue keeps the started_at that a refused claim set (D-55) | TestP2S2PipelineQueuedBehindCollectingProjecting | CAUGHT | L |
| M1b | `sr`: Requeue drops the start of a run that really collected | TestP2S2RefusedReclaimKeepsItsStart | CAUGHT | L |
| M2 | services/cloud_aws_scan_worker.go: the worker stops pinning the connector per run | TestP2S2RegionChangeAppliesFromTheNextScan | CAUGHT | L |
| M3 | `ob`: PATCH validated against more than the enabled regions | TestP2S2RegionPatchNamesTheOffenders | CAUGHT | L |
| M4 | `ob`: PATCH writes an unvalidated selection (D-90) | TestP2S2DeniedDescribeRegionsIsAClearError | CAUGHT | L |
| M5a | `rg`: a refused DescribeRegions not classified as that call's denial (unit) | TestS2DeniedDescribeRegionsIsNotAnAssumeFailure | CAUGHT | L |
| M5b | `rg`: the same, through the route | TestP2S2DeniedDescribeRegionsIsAClearError | CAUGHT | L |
| M5c | `rg`: an assume failure under DescribeRegions not ErrNotAssumable | TestS2AssumeFailureUnderDescribeRegionsIsNotAssumable | CAUGHT | L |
| M5d | `cp`: GET regions answers an AWS failure with an error status, not 200 plus the selection | TestP2S2DeniedDescribeRegionsIsAClearError | CAUGHT | L |
| M6 | `cv`: coverage read only from the publishing run, not every run the revision stands on | TestP2S2CoverageFromTheCurrentRevision | CAUGHT | L |
| M7 | `cv`: denied not mapped to surface_denied (D-58) | TestP2S2CoverageFromTheCurrentRevision | CAUGHT | L |
| M7b | `cv`: not_selected not mapped to surface_stale (D-58) | TestP2S2CoverageFromTheCurrentRevision | CAUGHT | L |
| M7c | `cv`: partial not mapped to surface_partial (D-58) | TestP2S2CoverageFromTheCurrentRevision | CAUGHT | L |
| M8 | `cv`: a reached surface renders a call, code or error | TestP2S2CoverageFromTheCurrentRevision | CAUGHT | L |
| M9 | `cv`: count given when the surface is not reached (D-72) | TestP2S2CoverageFromTheCurrentRevision | CAUGHT | L |
| M10 | `pl`: waiting_on does not name the barrier's run | TestP2S2PipelineQueuedBehindCollectingProjecting | CAUGHT | L |
| M11a | `pl`: barrier.since while collecting taken from the lease's updated_at (D-92) | TestP2S2PipelineQueuedBehindCollectingProjecting | CAUGHT | L |
| M11b | `pl`: barrier.since while projecting taken from the lease's updated_at (D-92) | TestP2S2PipelineQueuedBehindCollectingProjecting | CAUGHT | L |
| M12 | `cp`: history cursor not bound to its connector (D-62) | TestP2S2ScanRunHistoryShowsEveryEnding | CAUGHT | L |
| M13 | `ob`: verify writes the whole pre-probe attrs blob | TestP2S2VerifyDoesNotUndoARegionChange | CAUGHT | L |
| M14 | services/cloud_aws_workload_scan.go: no not_selected stand-in for a deselected region outside the built-in list (first attempt did not build) | TestP2S2DeselectedRegionIsKeptStale | CAUGHT | L |
| M15 | controllers/platform/iga_graph_read_controller.go: features.coverage true while the switch is off (D-11) | TestP2S2PipelineAndCoverageUnavailableWhenOff | CAUGHT | L |
| M16 | `pl`: a job failed below its ceiling not shown as projecting/retrying (D-59) | TestP2S2PipelineQueuedBehindCollectingProjecting | CAUGHT | L |
| M17 | `sr`: GET scan-runs/:id not workspace-qualified | TestP2S2ScanRunHistoryShowsEveryEnding | CAUGHT | L |
| M18 | `cv`: since does not stop at the first run in another state (D-72) | TestP2S2CoverageFromTheCurrentRevision | CAUGHT | L |
| M19 | `cp`: PATCH accepts unknown body fields | TestP2S2RegionPatchNamesTheOffenders | CAUGHT | L |
| M20 | `pl`: a revoked connector not listed revoked (D-89) | TestP2S2PipelineAccountsAtTheCurrentRevision | CAUGHT | L |
| M21 | `pl`: last_published_rev not the current rev (D-56) | TestP2S2PipelineAccountsAtTheCurrentRevision | CAUGHT | L |
| M22 | `pl`: latest_run not the live run (D-92) | TestP2S2PipelineAccountsAtTheCurrentRevision | CAUGHT | L |
| M24 | internal/awsdiscovery/onboarding.go: template "outdated" not recorded < current | TestP2S2DeniedDescribeRegionsIsAClearError | CAUGHT | L |
| M25a | internal/awsdiscovery/authsec-aws-discovery-role.yaml: GetGateway grant removed | TestS2TemplateVersionDeclaredConsistently | CAUGHT | L |
| M25b | the same template: DescribeRegions grant removed | TestS2TemplateVersionDeclaredConsistently | CAUGHT | L |
| M25c | the same template: Metadata version changed | TestS2TemplateVersionDeclaredConsistently | CAUGHT | L |
| M25d | the same template: Outputs version changed | TestS2TemplateVersionDeclaredConsistently | CAUGHT | L |
| M25e | internal/awsdiscovery/permissions.go: GetGateway not advertised | TestS2TemplateVersionDeclaredConsistently | CAUGHT | L |
| M26a | internal/awsdiscovery/failed_call.go: classify drops the SDK error chain (unit) | TestS2ClassifyKeepsTheFailedCall | CAUGHT | L |
| M26b | failed_call.go: the same, seen through coverage api/error_code | TestP2S2CoverageFromTheCurrentRevision | CAUGHT | L |
| M27 | `ob`: malformed region codes not refused on shape before AWS is asked | TestP2S2RegionPatchNamesTheOffenders | CAUGHT | L |
| M28 | `ob`: an empty selection not 422 (D-90) | TestP2S2RegionPatchNamesTheOffenders | CAUGHT | L |
| M29 | `ob`: an over-cap selection not 400 | TestP2S2RegionPatchNamesTheOffenders | CAUGHT | L |
| M30 | `ob`: the write accepts a connector revoked since it was read | TestP2S2RegionPatchNamesTheOffenders | CAUGHT | L |
| M31 | `cp`: a selected-but-disabled region not listed `enabled:false` | TestP2S2RegionsListedWithSelection | CAUGHT | L |
| M32 | `rg`: DescribeRegions asks with AllRegions=true | TestS2EnabledRegionsOverTheWire | CAUGHT | L |
| M33 | `cv`: `?account=` does not narrow /coverage | TestP2S2CoverageFromTheCurrentRevision | CAUGHT | L |
| M35 | `cp`: history limit above 100 accepted (D-91) | TestP2S2ScanRunHistoryShowsEveryEnding | CAUGHT | L |
| M36 | `cp`: history accepts unknown parameters | TestP2S2ScanRunHistoryShowsEveryEnding | CAUGHT | L |
| M37 | controllers/platform/iga_graph_read_pipeline.go: /pipeline accepts rev and parameters (D-82) | TestP2S2PipelineAccountsAtTheCurrentRevision | CAUGHT | L |
| M39a | internal/awsdiscovery/onboarding.go: a call refused to the assumed role not ErrCallDenied (unit) | TestS2ClassifyKeepsTheFailedCall | CAUGHT | L |
| M39b | onboarding.go: the same, seen in coverage prose | TestP2S2CoverageFromTheCurrentRevision | CAUGHT | L |
| M39c | onboarding.go: an STS refusal under another call not ErrNotAssumable | TestS2ClassifyKeepsTheFailedCall | CAUGHT | L |
| M40 | `cv`: the prevents table maps not_selected to nil (unit) | TestS2PreventsMapping | CAUGHT | L |
| M41 | `pl`: published with no job reported published (unit) | TestS2AccountStateTable | CAUGHT | L |
| M42 | `pl`: an unknown job status reported published (unit) | TestS2AccountStateTable | CAUGHT | L |

**Review.** Source: R+b. No reviewer log was found; `SP/mut/A.orig` (repository/cloud_scan_run_repository.go, 20:40), `B.orig` and `D.orig` (internal/igaread/coverage.go, 20:42 and 20:45) are the backups, each with a `.sha`, matched to A, B and D by file and time. A fourth backup, `SP/mut/C.orig` (services/cloud_aws_onboarding.go, 20:44), has no outcome in the review; like idetail's m1 it is not counted. Every mutant passed every TestP2 test.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| A | `sr` ~l.535: history query's connector filter removed | none | MISSED→FIXED. TestP2S2ScanRunHistoryShowsEveryEnding now scans B between A's runs; the fix's M2a is caught | R+b |
| B | `cv` ~l.239: newest-run-first merge reversed | none | MISSED→FIXED. TestP2S2CoverageMergesTheRunsTheRevisionStandsOn added; the fix's M3a is caught | R+b |
| D | `cv` ~l.412: the D-72 "streak longer than the walk is null" rule removed | none | MISSED→FIXED. TestP2S2CoverageSinceIsNullPastTheWalk added; the fix's M5a is caught | R+b |

**Fix.** Source: L, `SP/s2fix_mutations.log`, 33 lines, each "restored sha ok". M1a and M1c were first logged CAUGHT on `[build failed]`; their compiling re-runs are the next lines. Files are in `SP/s2fix_mut_backup/`: regions.go, coverage.go, pipeline.go, cloud_permission_repository.go, cloud_scan_run_repository.go, cloud_aws_iam_scan.go, cloud_aws_onboarding.go, cloud_aws_permission_scan.go and cloud_aws_workload_scan.go.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| M1a | keep list not passed to reconcile (compiling re-run) | TestP2S2DeselectedRegionKeepsPodIdentityBindings | CAUGHT | L |
| M1b | surface reported reached although bindings went unread | TestP2S2DeselectedRegionKeepsPodIdentityBindings | CAUGHT | L |
| M1c | an unknown-region edge always treated as gone (compiling re-run) | TestP2S2DeselectedRegionKeepsPodIdentityBindings | CAUGHT | L |
| M1d | deselection history ignored | TestP2S2DeselectedRegionKeepsPodIdentityBindings | CAUGHT | L |
| M1e | issuer fallback removed | TestP2S2DeselectedRegionKeepsPodIdentityBindings | CAUGHT | L |
| M1f | region not stamped on the edge | TestP2S2DeselectedRegionKeepsPodIdentityBindings | CAUGHT | L |
| M1g | a read region not treated as gone | TestP2S2DeselectedRegionKeepsPodIdentityBindings | CAUGHT | L |
| M1h | repository ignores the keep list | TestP2S2DeselectedRegionKeepsPodIdentityBindings | CAUGHT | L |
| M1i | held-over query ignores mechanism | TestP2S2DeselectedRegionKeepsPodIdentityBindings | CAUGHT | L |
| M1j | a failed read masked as not_selected | TestP2S2DeselectedRegionKeepsPodIdentityBindings | CAUGHT | L |
| M4a | stand-ins ignore the selection history | TestP2S2DeselectedRegionIsKeptStale | CAUGHT | L |
| M4b | history not carried forward | TestP2S2RegionHistoryOnlyGrows | CAUGHT | L |
| M4c | the replaced selection not recorded | TestP2S2DeselectedRegionKeepsPodIdentityBindings | CAUGHT | L |
| M3a | coverage merge oldest-first (reviewer B) | TestP2S2CoverageMergesTheRunsTheRevisionStandsOn | CAUGHT | L |
| M3b | the older run not scoped | TestP2S2CoverageMergesTheRunsTheRevisionStandsOn | CAUGHT | L |
| M3c | an unknown watermark scoped anyway | TestP2S2CoverageMergesTheRunsTheRevisionStandsOn | CAUGHT | L |
| M3d | the newest run scoped too | TestP2S2CoverageMergesTheRunsTheRevisionStandsOn | CAUGHT | L |
| M5a | a streak past the walk not nulled (reviewer D) | TestP2S2CoverageSinceIsNullPastTheWalk | CAUGHT | L |
| M5b | the walk one short | TestP2S2CoverageSinceIsNullPastTheWalk | CAUGHT | L |
| M2a | history not filtered by connector (reviewer A) | TestP2S2ScanRunHistoryShowsEveryEnding | CAUGHT | L |
| M6a | the activity surface drops its failed call | TestP2S2FailedCallsNamedOnEveryDeniedSurface | CAUGHT | L |
| M6b | the permission_scan stand-in drops its failed call | TestP2S2FailedCallsNamedOnEveryDeniedSurface | CAUGHT | L |
| M6c | the workload_scan stand-in drops its failed call | TestP2S2FailedCallsNamedOnEveryDeniedSurface | CAUGHT | L |
| M6d | the per-identity activity error value dropped | TestP2S2FailedCallsNamedOnEveryDeniedSurface | CAUGHT | L |
| M7a | pipeline: newest branch unbounded | TestP2S2PipelineReadsAFixedAmountPerConnector | CAUGHT | L |
| M7b | pipeline: newest branch unordered | TestP2S2PipelineReadsAFixedAmountPerConnector | CAUGHT | L |
| M7c | pipeline: the live run not preferred | TestP2S2PipelineReadsAFixedAmountPerConnector | CAUGHT | L |
| M7d | pipeline: ever_published always false | TestP2S2PipelineReadsAFixedAmountPerConnector | CAUGHT | L |
| M7e | pipeline: LIMIT dropped on the live branch | none | MISSED, accepted as equivalent: uq_cloud_scan_run_live allows at most one live run per connector, so that LIMIT can never bind | L |
| M8a | STS signed for the sorted first region | TestP2S2SigningRegionIsNeverAnOptInSortedFirst | CAUGHT | L |
| M8b | SigningRegion ignores the regions that cannot be disabled | TestS2SigningRegionPrefersARegionThatCannotBeDisabled | CAUGHT | L |

#### lists (T6.2/T6.8): impl `3876f78c`, fix `a89ee8d2`

55 checks: 51 caught, 4 missed→fixed.

**Implement.** Source: L, `SP/lists3_mutations.log`, 52 records with a restored sha256 on each. The first attempts at M10, M21, M22 and M47 did not build (`build_failed: true`) and were rewritten; the rewrites are the rows below. The report mentions M10, M21 and M22, not M47. An earlier agent's `SP/lists_mutate.log` holds a single run of M1 (caught) and is superseded. Files: `li` = internal/igaread/lists.go (M01–M33), `nd` = internal/igaread/nodes.go (M34–M41), `lk` = internal/igaread/lookup.go (M42–M45, M47), plus internal/igagraph/load.go (M46).

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| M01 | `li`: q's LIKE metacharacters not escaped | TestP2ListsWorkloadRowsSearchAndPaging | CAUGHT | L |
| M02 | `li`: a facet's counts apply its own filter | TestP2ListsResourcesKindsAccountsAndFacets | CAUGHT | L |
| M03 | `li`: the account facet stops offering unknown | TestP2ListsDuplicateNamesAcrossAccounts | CAUGHT | L |
| M04 | `li`: cursor not bound to the filter hash | TestP2ListsCursorBinding | CAUGHT | L |
| M05 | `li`: cursor revision not pinned (409 revision_stale) | TestP2ListsCursorBinding | CAUGHT | L |
| M06 | `li`: classification clock not checked between pages | TestP2ListsClassificationChangeBetweenPages | CAUGHT | L |
| M07 | `li`: a classification sort does not bind the clock | TestP2ListsClassificationChangeBetweenPages | CAUGHT | L |
| M08 | `li`: a classification filter does not bind the clock | TestP2ListsClassificationChangeBetweenPages | CAUGHT | L |
| M09 | `li`: retired objects listed by default | TestP2ListsLifecycle | CAUGHT | L |
| M10 | `li`: choosing an account keeps unknowns (`true \|\| unknown`; the first attempt did not build) | TestP2ListsResourcesKindsAccountsAndFacets | CAUGHT | L |
| M11 | `li`: graph rows not restricted to provider aws (D-6) | TestP2ListsIdentities; TestP2ListsResourcesKindsAccountsAndFacets | CAUGHT | L |
| M12 | `li`: graph rows without a projection-pass support row (D-6) | TestP2ListsIdentities; TestP2ListsResourcesKindsAccountsAndFacets | CAUGHT | L |
| M13 | `li`: sorts no longer end with id | TestP2ListsDuplicateNamesAcrossAccounts | CAUGHT | L |
| M14 | `li`: `-` does not reverse the keyset comparison | TestP2ListsWorkloadRowsSearchAndPaging | CAUGHT | L |
| M15 | `li`: no-value flags reversed under `-` | TestP2ListsResourcesKindsAccountsAndFacets; TestP2ListsWorkloadAndIdentitySorts | CAUGHT | L |
| M16 | `li`: integration filter not "supported by that connector" | TestP2ListsDuplicateNamesAcrossAccounts | CAUGHT | L |
| M17 | `li`: unknown parameter accepted | TestP2ListsInvalidParameters | CAUGHT | L |
| M18 | `li`: provider accepts other than aws (D-75) | TestP2ListsInvalidParameters | CAUGHT | L |
| M19 | `li`: nothing published not 200 empty with not_published | TestP2ListsNotPublished | CAUGHT | L |
| M20 | `li`: region not_stated does not select region-less rows | TestP2ListsResourcesKindsAccountsAndFacets | CAUGHT | L |
| M21 | `li`: a timed-out total reported known (first attempt did not build) | TestP2ListsNoTimeForOptionalWork | CAUGHT | L |
| M22 | `li`: a timed-out facet not null (first attempt did not build) | TestP2ListsNoTimeForOptionalWork | CAUGHT | L |
| M23 | `li`: a timed-out used_by_count reported exact | TestP2ListsOptionalCountTimesOutPageStillReturned | CAUGHT | L |
| M24 | `li`: timed-out named_by/excluded_by reported | TestP2ListsOptionalCountTimesOutPageStillReturned | CAUGHT | L |
| M25 | `li`: used_by filter counts ended edges | TestP2ListsIdentities | CAUGHT | L |
| M26 | `li`: coverage not narrowed to the account filter | TestP2ListsCoverageAndStaleRows | CAUGHT | L |
| M27 | `li`: coverage names surfaces that do not bear on the list (D-73) | TestP2ListsCoverageAndStaleRows | CAUGHT | L |
| M28 | `li`: coverage treats reached as a gap | TestP2ListsCoverageAndStaleRows | CAUGHT | L |
| M29 | `li`: not_selected not reported stale | TestP2ListsCoverageAndStaleRows | CAUGHT | L |
| M30 | `li`: coverage not decided by the newest reporting run | TestP2ListsCoverageAndStaleRows | CAUGHT | L |
| M31 | `li`: coverage reads runs of other object types | TestP2ListsCoverageAndStaleRows | CAUGHT | L |
| M32 | `li`: a revoked account not named `*` | TestP2ListsCoverageAndStaleRows | CAUGHT | L |
| M33 | `li`: cursor key count not checked against the sort | TestP2ListsDecodeCursorKey | CAUGHT | L |
| M34 | `nd`: resource account taken from the scanning account (D-3) | TestP2ListsResourcesKindsAccountsAndFacets | CAUGHT | L |
| M35 | `nd`: external kind removed (D-16) | TestP2ListsResourcesKindsAccountsAndFacets | CAUGHT | L |
| M36 | `nd`: connected taken from live connectors, not the projected value | TestP2ListsResourcesKindsAccountsAndFacets | CAUGHT | L |
| M37 | `nd`: named_by counts Deny statements (D-17) | TestP2ListsResourcesKindsAccountsAndFacets | CAUGHT | L |
| M38 | `nd`: used_by_count counts ended edges (D-17) | TestP2ListsIdentities | CAUGHT | L |
| M39 | `nd`: a stale support row does not make a stale node (D-1) | TestP2ListsCoverageAndStaleRows | CAUGHT | L |
| M40 | `nd`: a current support row does not make a current node (D-1) | TestP2ListsCoverageAndStaleRows | CAUGHT | L |
| M41 | `nd`: stale_reason on non-stale rows (D-74) | TestP2ListsCoverageAndStaleRows | CAUGHT | L |
| M42 | `lk`: lookup accepts a recreated principal | TestP2ListsLookupByKeyNeverByName | CAUGHT | L |
| M43 | `lk`: identity lookup not through the row's own connector | TestP2ListsLookupByKeyNeverByName | CAUGHT | L |
| M44 | `lk`: workload lookup not through the row's own connector | TestP2ListsLookupByKeyNeverByName | CAUGHT | L |
| M45 | `lk`: identity looked up by name, not source key | TestP2ListsLookupByKeyNeverByName, then TestP2ListsLookupSameNameInOneAccount | MISSED→FIXED. The first run passed; TestP2ListsLookupSameNameInOneAccount (two principals of one name in one account) was added and the re-run was caught | L |
| M46 | internal/igagraph/load.go: connected accounts include revoked connectors (D-61) | TestP2ListsRevokedAccountReferenceIsExternal | CAUGHT | L |
| M47 | `lk`: workload looked up by name (the first attempt did not build) | TestP2ListsLookupByKeyNeverByName; TestP2ListsLookupSameNameInOneAccount | CAUGHT | L |

**Review.** Source: R+b, backups of lists.go and nodes.go in `SP/rv_lists_bak/`. RV-1 passed every TestP2Lists test and every igaread unit test; RV-2 and M-D passed every TestP2 test. The review's first finding, /resources coverage narrowed by the scanning account, came from reading; the fix's M1 checks it.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| RV-1 | `li` ~l.697: `AND os.state <> 'ended'` removed from the integration filter | none | MISSED→FIXED. TestP2ListsIntegrationNeedsLiveSupport added; the fix's M2 is caught | R+b |
| RV-2 | `nd` ~l.355: DISTINCT removed from used_by_count | none | MISSED→FIXED. TestP2ListsUsedByCountsDistinctWorkloads added; the fix's M3 is caught | R+b |
| M-D | `li` ~l.475: workspace predicate removed from listsClassificationSeq | none | MISSED→FIXED. TestP2ListsClassificationChangeBetweenPages now has a second workspace; the fix's M4 is caught | R+b |

**Fix.** Source: L, `SP/mut-M1-resource-account-narrowing.log` through `SP/mut-M4b-clock-workspace-any.log`, with `.orig` backups; the script restores each and compares sha256.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| M1 | `li`: `sc := listsScope{accounts: p.Accounts}` restored | TestP2ListsResourceCoverageKeepsOtherScannersGaps | CAUGHT | L |
| M2 | `li`: `AND os.state <> 'ended'` removed | TestP2ListsIntegrationNeedsLiveSupport | CAUGHT | L |
| M3 | `nd`: DISTINCT dropped | TestP2ListsUsedByCountsDistinctWorkloads | CAUGHT ("value 3") | L |
| M4 | `li`: the clock read without its workspace; the report names it the reviewer's M-D, `WHERE ?::uuid IS NOT NULL ORDER BY seq`, and the log name is clock-workspace-min | TestP2ListsClassificationChangeBetweenPages | CAUGHT (409 on both cursors) | L |
| M4b | `li`: a variant; the report gives `ORDER BY seq DESC`, and the log name is clock-workspace-any | TestP2ListsClassificationChangeBetweenPages | CAUGHT | L |

#### class (T6.6): impl `1415a219`, fix `fcfe33ee`

78 checks: 73 caught, 4 missed→fixed, 1 missed (equivalent).

**Implement.** Source: L, `SP/class3_mutations_part1.log` through `part4.log`, backups in `SP/class3_orig/` with `SP/class3_pre.sha`. The runner numbers the mutants #0–#65; the report's "66 safeguards" is that range. Two indices were used twice: #16 in part 1 is a different mutant from #16 in part 2, and #37 was redefined in part 3. That makes 68 distinct mutants.
- #16a deadlocked, and the killed run dirtied iga_w_class, so part 2 re-ran #16–#65 against a database reset from iga_tpl.
- The report's 36 rows count 67 mutants by their own counts. The 68th is #16a, which the report mentions only inside the row for #16b ("round 1's insert-outside-tx variant also failed, by deadlocking to the timeout").

Files: services/iga_classification_service.go, controllers/platform/iga_graph_read_classification.go, controllers/platform/iga_classification_controller.go, internal/igaread/classification.go and internal/authz/allowed.go.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| #0 | operation lookup moved before the row lock (B22) | TestP2ClassConcurrentRetriesReplay | CAUGHT (parts 1 and 4) | L |
| #1 | READ COMMITTED made REPEATABLE READ | TestP2ClassConcurrentRetriesReplay | CAUGHT | L |
| #2 | request-hash comparison on a found operation removed | TestP2ClassOperationReusedIs422 | CAUGHT | L |
| #3 | replay renders the current state, not the stored outcome | TestP2ClassRetryAfterVersionMovedReplays | CAUGHT | L |
| #4 | provider-native refusal removed | TestP2ClassProviderNativeIs422 | CAUGHT | L |
| #5 | expected_version check (409) removed | TestP2ClassStaleVersionIs409WithCurrentDecision | CAUGHT | L |
| #6 | D-30 decision rules moved before the version check | TestP2ClassDecisionRulesComeAfterTheVersion | CAUGHT | L |
| #7 | classified→classified replacement refused | TestP2ClassReplacementIsANewDecision | CAUGHT | L |
| #8 | retired-workload refusal removed | TestP2ClassDecisionRulesComeAfterTheVersion | CAUGHT | L |
| #9 | a classify naming a decision to undo accepted | TestP2ClassDecisionRulesComeAfterTheVersion | CAUGHT | L |
| #10 | unclassified accepted on a workload that is not classified_agent | TestP2ClassDecisionRulesComeAfterTheVersion | CAUGHT | L |
| #11 | an undo need not name a decision | TestP2ClassDecisionRulesComeAfterTheVersion | CAUGHT | L |
| #12 | an undo need not name this workload's latest decision | TestP2ClassUndoIsANewDecision | CAUGHT | L |
| #13 | SET LOCAL lock_timeout removed (D-31) | TestP2ClassLockWaitIsBounded | CAUGHT | L |
| #14 | 23505 on iga_wc_operation_key not mapped to 422 | TestP2ClassSameOperationTwoWorkloadsConcurrently | CAUGHT | L |
| #15 | clock bump removed from the decision transaction | TestP2ClassClockAndListingChanged | CAUGHT | L |
| #16a | decision row written outside the transaction | TestP2ClassDecisionIsAtomic | CAUGHT, but only through a deadlock that hit go test's 10-minute timeout (part 1), not an assertion | L |
| #16b | clock bump moved after the commit | TestP2ClassDecisionIsAtomic | CAUGHT (part 2) | L |
| #17 | lock SELECT not scoped to the workspace | TestP2ClassCrossWorkspaceIs404 | CAUGHT (parts 1–3) | L |
| #18 | lock SELECT without a support row (D-6) | TestP2ClassUnreadableWorkloadIs404 | CAUGHT | L |
| #19 | lock SELECT without provider aws (D-6) | TestP2ClassUnreadableWorkloadIs404 | CAUGHT | L |
| #20 | reason length bound removed | TestP2ClassValidation | CAUGHT | L |
| #21 | reason bound counted in bytes, not characters | TestP2ClassValidation | CAUGHT | L |
| #22 | purpose length bound removed | TestP2ClassValidation | CAUGHT | L |
| #23 | blank reason accepted (not trimmed) | TestP2ClassValidation | CAUGHT | L |
| #24 | negative expected_version accepted | TestP2ClassValidation | CAUGHT | L |
| #25 | missing expected_version accepted | TestP2ClassValidation | CAUGHT (the test panicked on a nil dereference) | L |
| #26 | request hash ignores the actor | TestP2ClassRequestHash | CAUGHT | L |
| #27 | an actor-rule refusal no longer 403, a database error no longer 500 | TestP2ClassMembershipCheckFailureIs500 | CAUGHT | L |
| #28 | a can_classify database error read as false | TestP2ClassMembershipCheckFailureIs500 | CAUGHT | L |
| #29 | can_classify checks iga:read, not iga:review | TestP2ClassCanClassifyCaller | CAUGHT | L |
| #30 | can_classify true on a retired workload | TestP2ClassCanClassifyCaller | CAUGHT | L |
| #31 | can_classify true for a token that is not a verified human | TestP2ClassCanClassifyCaller | CAUGHT | L |
| #32 | can_classify true on a provider-native agent | TestP2ClassCanClassifyCaller | CAUGHT | L |
| #33 | authz.Allows true without claims | TestP2ClassAllows | CAUGHT | L |
| #34 | membership need not be active | TestP2ClassRequiresAVerifiedHuman | CAUGHT | L |
| #35 | membership need not be this workspace's | TestP2ClassRequiresAVerifiedHuman | CAUGHT | L |
| #36 | membership need not be this user's | TestP2ClassRequiresAVerifiedHuman | CAUGHT | L |
| #37a | the empty-membership check alone removed | none | MISSED, accepted as equivalent: `uuid.Parse("")` and the SQL id binding still refuse | L |
| #37b | all three layers of the membership-claim check removed | TestP2ClassRequiresAVerifiedHuman | CAUGHT (part 3) | L |
| #38 | a non-UUID user id reaches PostgreSQL (500, not a refusal) | TestP2ClassRequiresAVerifiedHuman | CAUGHT | L |
| #39 | history rev not pinned | TestP2ClassHistoryIsRevisionBound | CAUGHT | L |
| #40 | history cursor's rev not pinned | TestP2ClassHistoryIsRevisionBound | CAUGHT | L |
| #41 | history accepts unknown parameters | TestP2ClassHistoryIsRevisionBound | CAUGHT | L |
| #42 | history not 404 when nothing is published (D-4) | TestP2ClassHistoryNothingPublishedIs404 | CAUGHT | L |
| #43 | history cursor does not carry the revision | TestP2ClassHistoryPages | CAUGHT | L |
| #44 | history cursor not bound to its workload (D-62) | TestP2ClassHistoryPages | CAUGHT | L |
| #45 | history readable without workspace scoping | TestP2ClassCrossWorkspaceIs404 | MISSED→FIXED. Part 2 passed because D-4's 404 fired first, the other workspace having nothing published. The test now publishes it; caught in part 3 | L |
| #46 | history readable without a support row | TestP2ClassUnreadableWorkloadIs404 | CAUGHT | L |
| #47 | latest decision ordered by decided_at, not result_version | TestP2ClassLatestDecisionForTheDetail | CAUGHT | L |
| #48 | history ordered by decided_at, not result_version | TestP2ClassLatestDecisionForTheDetail | CAUGHT | L |
| #49 | no listing_changed when the clock moved (part 2 did not build: `seq` unused) | TestP2ClassClockAndListingChanged | CAUGHT (part 3) | L |
| #50 | a classification cursor without a clock not cursor_invalid | TestP2ClassClockAndListingChanged | CAUGHT | L |
| #51 | display name does not skip the "Not Provided" default (D-32) | TestP2ClassDisplayNames | CAUGHT | L |
| #52 | retry storm: lookup before the lock | TestP2ClassRetryStormReplays | MISSED→FIXED. In part 2 the retries ran one after another. Each commit now waits 50 ms; caught 3 of 3 times (parts 3 and 4) | L |
| #53 | FOR UPDATE removed from the workload row | TestP2ClassConcurrentRetriesReplay | CAUGHT | L |
| #54 | request hash taken over untrimmed strings | TestP2ClassRequestHash | CAUGHT | L |
| #55 | the membership row need not exist | TestP2ClassRequiresAVerifiedHuman | CAUGHT | L |
| #56 | unknown body fields accepted | TestP2ClassValidation | CAUGHT | L |
| #57 | a wrong-typed field not named | TestP2ClassValidation | CAUGHT | L |
| #58 | a null body accepted as an object | TestP2ClassValidation | CAUGHT | L |
| #59 | 64 KiB size bound removed | TestP2ClassValidation | CAUGHT | L |
| #60 | more than one JSON object accepted | TestP2ClassValidation | CAUGHT | L |
| #61 | an absent purpose renders `""`, not null | TestP2ClassReplacementIsANewDecision | CAUGHT | L |
| #62 | display name has no user-id fallback | TestP2ClassDisplayNames | CAUGHT | L |
| #63 | display name has no email fallback | TestP2ClassDisplayPrecedence | CAUGHT | L |
| #64 | the 409's current decision does not name the latest decider | TestP2ClassStaleVersionIs409WithCurrentDecision | CAUGHT | L |
| #65 | history not keyset-paged after the cursor | TestP2ClassHistoryPages | CAUGHT | L |

**Review.** Source: R+b, backup `SP/revclass/svc.orig`. Both mutants passed every TestP2Class test; RV-1 also passed the services tests.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| RV-1 | iga_classification_service.go ~l.242: `workspace_id = ?` removed from the step-2 operation lookup | none | MISSED→FIXED. TestP2ClassOperationIdIsPerWorkspace added; the fix's M2 is caught | R+b |
| RV-2 | ~l.206: `SET LOCAL` changed to `SET` | none | MISSED→FIXED. TestP2ClassLockTimeoutIsTransactionScoped added; the fix's M3 is caught | R+b |

**Fix.** Source: L, `SP/classfix/*.log` with `.orig` backups; `mut.sh` compares sha256.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| M2 | the operation lookup reduced to `WHERE operation_id = ?` | TestP2ClassOperationIdIsPerWorkspace (422 at p2_class_decision_test.go:982 as of `fcfe33e`) | CAUGHT | L |
| M3 | `SET LOCAL` changed to `SET` | TestP2ClassLockTimeoutIsTransactionScoped ("1234ms, want the session's 0") | CAUGHT | L |
| M5 | the NUL check on reason disabled | TestP2ClassValidation (500, want 400) | CAUGHT | L |
| M6 | the NUL check on purpose disabled | TestP2ClassValidation | CAUGHT | L |
| M7 | graphFeatures classification `on && false` | TestP2ClassCapabilitiesFeature/on | CAUGHT | L |
| M8 | graphFeatures classification `on \|\| true` | TestP2ClassCapabilitiesFeature/off, /misconfigured | CAUGHT | L |
| M1, M4 | "the reviewer's M1 and M4 are still caught". The review text numbers no mutations, so these two are not identifiable | not named | CAUGHT | R |

The egates fix pass re-checked four class safeguards (`SP/egfix/mut_C1`–`C4`); see egates.

**Earlier runs, superseded and not counted.**
- `SP/class_mutations.json`: 26 runs, M1–M25 plus M13u, all caught. This was the first class agent, before `93ed668`.
- `SP/class2_mutations.log`: #0 (B22) caught. The agent then died while applying #1, which flipped READ COMMITTED to REPEATABLE READ; see §6.6 below.

### 6.4 Wave B

#### rdetail (T6.3 resource tabs): impl `52673ac`, fix `69cfb22c`

53 checks: 51 caught, 2 unverified.

**Implement.** Source: L, `SP/rdetail_mut/results.txt` (38 lines). Files: `ra` = internal/igaread/resource_access.go, for M01–M20, M32 and M38 (restored sha `ec406879165d`); `rd` = internal/igaread/resource_detail.go, for the rest (restored sha `2c0fb92208a2`).

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| M01 | `ra`: NotResource targets grant access | TestP2RDetailNotResourceExcludes | CAUGHT | L |
| M02 | `ra`: `effect = 'allow'` dropped from the grant join | TestP2RDetailDenyIsARestrictionNotAccess | CAUGHT | L |
| M03 | `ra`: grant state filter removed (D-12) | TestP2RDetailAccessTwoStatementsOneHolder | CAUGHT | L |
| M04 | `ra`: group-held grant not expanded to members (D-18) | TestP2RDetailGroupHeldGrantExpandsToMembers | CAUGHT | L |
| M05 | `ra`: membership state filter removed | TestP2RDetailGroupHeldGrantExpandsToMembers | CAUGHT | L |
| M06 | `ra`: membership and grant periods need not overlap | TestP2RDetailGroupHeldGrantExpandsToMembers | CAUGHT | L |
| M07 | `ra`: member row state not the worse of grant and membership | TestP2RDetailGroupHeldGrantExpandsToMembers | CAUGHT | L |
| M08 | `ra`: page cut on rows, not holders | TestP2RDetailAccessTwoStatementsOneHolder | UNVERIFIED. The logged "catch" is `resource_access.go:419:6: declared and not used: prev`, a compile error, and no compiling variant was run. The report lists it caught | L |
| M09 | `ra`: cursor route does not carry the resource id (D-62) | TestP2RDetailAccessTwoStatementsOneHolder | CAUGHT | L |
| M10 | `ra`: keyset `>` changed to `>=` | TestP2RDetailAccessTwoStatementsOneHolder | CAUGHT | L |
| M11 | `ra`: total counts rows, not holders | TestP2RDetailAccessTwoStatementsOneHolder | CAUGHT | L |
| M12 | `ra`: ended rows listed without include_ended | TestP2RDetailAccessTwoStatementsOneHolder | CAUGHT | L |
| M13 | `ra`: restriction sections not filtered by effect | TestP2RDetailNotResourceExcludes | CAUGHT | L |
| M14 | `ra`: deny_statements_naming includes non-positive targets | TestP2RDetailNotResourceExcludes | CAUGHT | L |
| M15 | `ra`: restrictions list inactive statements | TestP2RDetailNotResourceExcludes | CAUGHT | L |
| M16 | `ra`: restriction holders not filtered by assignment state | TestP2RDetailDenyIsARestrictionNotAccess | CAUGHT | L |
| M17 | `ra`: statement cap of 100 removed | TestP2RDetailRestrictionCaps | CAUGHT | L |
| M18 | `ra`: holders cap of 100 removed | TestP2RDetailRestrictionCaps | CAUGHT | L |
| M19 | `ra`: 0-based statement index (D-84) | TestP2RDetailStatementActions | CAUGHT | L |
| M20 | `ra`: NotAction not read back into not_actions | TestP2RDetailNotResourceExcludes | CAUGHT | L |
| M21 | `rd`: sources leave out ended supports | TestP2RDetailSourcesTwoAccounts | CAUGHT | L |
| M22 | `rd`: D-19 observation from a run not published at or below the rev | TestP2RDetailResourcePolicy | CAUGHT | L |
| M23 | `rd`: D-19 `ingested_at <= published_at` removed | TestP2RDetailResourcePolicy | CAUGHT | L |
| M24 | `rd`: D-19 the latest qualifying observation no longer decides | TestP2RDetailResourcePolicy | CAUGHT | L |
| M25 | `rd`: D-19 a parse_failed policy gives has_deny | TestP2RDetailResourcePolicy | CAUGHT | L |
| M26 | `rd`: D-19 not limited to the exact ARN | TestP2RDetailResourcePolicy | CAUGHT | L |
| M27 | `rd`: D-19 not limited to resource-policy APIs | TestP2RDetailResourcePolicy | CAUGHT | L |
| M28 | `rd`: rows without a support row (D-6) | TestP2RDetailNotFoundRetiredAndParameters | CAUGHT | L |
| M29 | `rd`: provider not limited to aws (D-6) | TestP2RDetailNotFoundRetiredAndParameters | CAUGHT | L |
| M30 | `rd`: workspace filter removed from the resource lookup (E14) | TestP2RDetailNotFoundRetiredAndParameters | CAUGHT | L |
| M31 | `rd`: detail not 404 before the first publication (D-4) | TestP2RDetailNotFoundRetiredAndParameters | CAUGHT | L |
| M32 | `ra`: access not 404 before the first publication (D-4) | TestP2RDetailNotFoundRetiredAndParameters | CAUGHT | L |
| M33 | `rd`: unknown parameters accepted | TestP2RDetailNotFoundRetiredAndParameters | CAUGHT | L |
| M34 | `rd`: meta.coverage removed | TestP2RDetailStaleReferenceAndCoverage | CAUGHT | L |
| M35 | `rd`: no stale_reason on a stale reference | TestP2RDetailStaleReferenceAndCoverage | CAUGHT | L |
| M36 | `rd`: named/excluded counts cross-wired | TestP2RDetailNotResourceExcludes | CAUGHT | L |
| M37 | `rd`: timed-out counts rendered as 0 | TestP2RDetailOptionalWork | CAUGHT | L |
| M38 | `ra`: access total not optional work | TestP2RDetailOptionalWork | UNVERIFIED. The logged "catch" is `resource_access.go:256:3: declared and not used: ok`, a compile error, and no compiling variant was run | L |

**Review.** Nothing counted.
- The reviewer's two checks, RA (`effect = 'allow'` removed from grants) and RB (`target_mode = 'resource'` removed), are blocked. Every test failed at setup with `clear observations: ... violates foreign key constraint "iga_relationship_evidence_obs_fkey"` (`SP/rdetail_mut_effect_allow.txt`), so the failures say nothing about the mutants. The fixer re-ran both; see RA and RB below.
- Finding 4 (the cloud_observation workspace filter) is stated from reading. The fixer's M2 checks it.

**Fix.** Source: L, `SP/rdfix2/results.json` and `SP/rdfix2/mutations.log`, each restore checked against `SP/rdfix2/pre_mutation.sha`.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| M1 | `rd`: last_in keyed on scan_run_id | TestP2RDetailResourcePolicyConfirmations | CAUGHT | L |
| M2 | `rd`: `o.workspace_id` filter removed | TestP2RDetailResourcePolicy (the new E14 assertion) | CAUGHT | L |
| M3 | `rd`: last_in ignored | TestP2RDetailResourcePolicyState; TestP2RDetailResourcePolicyConfirmations | CAUGHT | L |
| M4 | `rd`: the undecidable-null check removed | TestP2RDetailResourcePolicyState; TestP2RDetailResourcePolicyConfirmations | CAUGHT | L |
| M5 | `rd`: latest read ordered by first recorder | TestP2RDetailResourcePolicyState; TestP2RDetailResourcePolicyConfirmations | CAUGHT | L |
| M6 | `rd`: unnamed reads ignored | TestP2RDetailResourcePolicyState; TestP2RDetailResourcePolicyConfirmations | CAUGHT | L |
| M7 | `rd`: resource_policies gaps from every connector | TestP2RDetailCoverageEveryGapThatBears | CAUGHT | L |
| M8 | `rd`: identity gaps narrowed to own partitions | TestP2RDetailCoverageEveryGapThatBears | CAUGHT | L |
| M9 | `rd`: the detail never adds resource_policies | TestP2RDetailCoverageEveryGapThatBears | CAUGHT | L |
| M10 | `rd`: every resource kind adds resource_policies | TestP2RDetailCoverageEveryGapThatBears | CAUGHT | L |
| M11 | `ra`: /access uses the detail's coverage | TestP2RDetailCoverageEveryGapThatBears | CAUGHT | L |
| M12 | `rd`: names_it counts ended supports | TestP2RDetailCoverageEveryGapThatBears | CAUGHT | L |
| M13 | `rd`: `ingested_at <= published_at` removed | TestP2RDetailResourcePolicy | CAUGHT | L |
| RA | `ra`: `effect = 'allow'` removed from grants (the reviewer's blocked check) | TestP2RDetailDenyIsARestrictionNotAccess | CAUGHT | L |
| RB | `ra`: `target_mode = 'resource'` removed (the reviewer's blocked check) | TestP2RDetailNotResourceExcludes | CAUGHT | L |

Nothing re-ran M08 or M38 after this pass.

#### changes (T5.4, D-26): impl `514efc77`, fix `068847ac`

35 checks: 32 caught, 3 missed→fixed.

**Implement.** Source: L, `SP/changes_mut/results.txt`. Each record shows "restored byte-for-byte: True". Files: `ch` = internal/igaread/changes.go (MC1–MC10). MW1 mutates internal/igagraph/reconcile.go; MW2 and MW5 mutate project.go; MW3 and MW4 mutate permissions.go; MW3 and MW5 also mutate repository/iga_graph_repository.go.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| MC1 | `ch`: D-28 remaining grants pooled from every holder | TestP2ChangesDetachNamesRemainingGrant | CAUGHT | L |
| MC2 | `ch`: D-28 the named[] target check removed | TestP2ChangesDetachNamesRemainingGrant | CAUGHT | L |
| MC3 | `ch`: D-28 candidates include ended grants | TestP2ChangesDetachNamesRemainingGrant | CAUGHT | L |
| MC4 | `ch`: lifecycle events derived from the node row, not iga_lifecycle_event (B24) | TestP2ChangesLifecycleSurvivesNodeRewrites | CAUGHT | L |
| MC5 | `ch`: a workload's via events not limited to the executes_as window (D-68) | TestP2ChangesWorkloadWindowOnItsRole | CAUGHT | L |
| MC6 | `ch`: cursor route does not carry the object id (D-62) | TestP2ChangesPaging | CAUGHT | L |
| MC7 | `ch`: cursor filter hash does not carry the effective kind | TestP2ChangesPaging | CAUGHT | L |
| MC8 | `ch`: rev/run join from published_at disabled | TestP2ChangesDetachNamesRemainingGrant | CAUGHT | L |
| MC9 | `ch`: statement_revised without the content-differs condition (D-27b) | TestP2ChangesRestoredStatementIsNotARevision | CAUGHT | L |
| MC10 | `ch`: statement_replaced without the same-run condition (D-27c) | TestP2ChangesPolicyEdits | CAUGHT | L |
| MW1 | reconcile.go: ends take a fresh clock read (D-26) | TestP2ChangesOnePassOneTimestamp | CAUGHT | L |
| MW2 | project.go: published_at takes a fresh clock read (D-26) | TestP2ChangesOnePassOneTimestamp | CAUGHT | L |
| MW3 | permissions.go + iga_graph_repository.go: grant valid_from left to the DB default; the repository guard also removed | TestP2ChangesOnePassOneTimestamp | CAUGHT | L |
| MW4 | permissions.go: ValidFrom removed with the guard kept, so ErrNoPassTime must refuse | TestP2ChangesOnePassOneTimestamp | CAUGHT | L |
| MW5 | project.go + iga_graph_repository.go: support first_seen_at left to the DB default | TestP2ChangesOnePassOneTimestamp | CAUGHT | L |

**Review.** Source: R+b, backup `SP/review_changes/changes.go.orig`. Every Changes test passed each mutant.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| RV-3 | `ch` ~l.1519: D-28 keep predicate made `return true` | none | MISSED→FIXED. TestP2ChangesDetachOwnStaleGrantIsNoPath added; the fix's R1 is caught | R+b |
| RV-5 | `ch` ~l.700: `AND e.sid = ''` removed from the replacement branch | none | MISSED→FIXED. TestP2ChangesPolicyEdits gains case (e); the fix's S1–S3 are caught | R+b |
| RV-7 | `ch`: workspace filter removed from changesLoadObject | only TestP2ListsRoutesPermissionsAndCrossWorkspace, which failed with a 500. All 11 TestP2Changes tests passed | MISSED→FIXED. The Changes test's foreign workspace had nothing published, so D-4's 404 fired first. TestP2ChangesParametersAndNotFound now probes from a published second workspace; the fix's W1 is caught | R+b |

**Fix.** Source: L, `SP/changesfix2/mut/results.txt`. The report says all 17 restores matched the pre-mutation manifest.

| ID | Mutation (all in `ch`) | Caught by | Result | Src |
|---|---|---|---|---|
| V1 | statement_replaced's after not taken from the replacing run | TestP2ChangesReplacementVersionsAndIDs | CAUGHT | L |
| V2 | before counts confirmations not published earlier | TestP2ChangesReplacementVersionsAndIDs | CAUGHT | L |
| V3 | before not read from the confirming runs | TestP2ChangesReplacementVersionsAndIDs | CAUGHT | L |
| V4 | an inline policy gets versions | TestP2ChangesReplacementVersionsAndIDs | CAUGHT | L |
| V5 | event id is the policy id, not md5(policy, run) | TestP2ChangesReplacementVersionsAndIDs | CAUGHT | L |
| E1 | holders' branch judges effect now, not at grant start (D-27g) | TestP2ChangesAllowEditedToDeny | CAUGHT | L |
| E2 | resource branch judges effect now, not at grant start | TestP2ChangesAllowEditedToDeny | CAUGHT | L |
| E3 | loader judges effect now, not at grant start | TestP2ChangesAllowEditedToDeny | CAUGHT | L |
| E4 | detached targets judged now, not at grant start | TestP2ChangesAllowEditedToDeny | CAUGHT | L |
| E5a | the candidates' Allow filter dropped | TestP2ChangesAllowEditedToDeny | CAUGHT | L |
| E5b | candidates judged at grant start | TestP2ChangesAllowEditedToDeny | CAUGHT. The report says it is caught only with the second seeded row, which the fixer added | L |
| R1 | a grant through the detached assignment counted as another path (reviewer RV-3) | TestP2ChangesDetachOwnStaleGrantIsNoPath | CAUGHT | L |
| H1 | history_begins scanned into `[]*time.Time`, so a missing first_seen gives 500 | TestP2ChangesParametersAndNotFound | CAUGHT | L |
| S1 | holders' replacement needs no Sid-less ended statement (reviewer RV-5) | TestP2ChangesPolicyEdits | CAUGHT | L |
| S2 | resource branch: the ended statement need not be Sid-less | TestP2ChangesPolicyEdits | CAUGHT | L |
| S3 | resource branch: the begun statement need not be Sid-less | TestP2ChangesPolicyEdits | CAUGHT | L |
| W1 | `t.workspace_id` dropped in changesLoadObject (reviewer RV-7) | TestP2ChangesParametersAndNotFound (200, not 404) | CAUGHT | L |

#### idetail (T6.3 identity tabs): impl `e9261e1`, fix `ba3377e4`

66 checks: 63 caught, 3 missed→fixed.

**Implement.** Source: L. `SP/idetail_mutation_results.json` has 42 records, all caught. The mutants were built as `go test -overlay` binaries; `SP/idetail_mutation_slots_log.txt` says each one built ("ok"). Files: `pm` = internal/igaread/idetail_permissions.go, `hp` = idetail_helpers.go, `ex` = idetail_external.go, `id` = idetail_identity.go, `ub` = idetail_usedby.go.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| boundary-never-a-grant | `pm`: boundary assignments grant | TestP2IdetailPermissionsNeverGrantBoundaryOrDeny | CAUGHT | L |
| boundary-only-under-boundary | `pm`: boundary listed under policies | TestP2IdetailPermissionsUserGroupBoundary | CAUGHT | L |
| deny-never-a-grant | `pm`: rule-7 join `e.effect = 'allow'` removed | TestP2IdetailPermissionsNeverGrantBoundaryOrDeny | CAUGHT | L |
| group-policies-not-copied-onto-user | `pm`: group policies copied onto the user | TestP2IdetailPermissionsUserGroupBoundary | CAUGHT | L |
| inherited-via-group | `pm`: via_group not set | TestP2IdetailPermissionsUserGroupBoundary | CAUGHT | L |
| grant-keyed-by-assignment | `pm`: grant keyed by statement alone | TestP2IdetailPermissionsNeverGrantBoundaryOrDeny | CAUGHT | L |
| statement-cap-truncated | `pm`: statement cap does not set truncated | TestP2IdetailPermissionsStatementCap | CAUGHT | L |
| d84-statement-index-1-based | `hp`: 0-based index | TestP2IdetailPermissionsUserGroupBoundary | CAUGHT | L |
| d6-provider-aws | `hp`: provider not limited to aws (a GitHub row gives 200) | TestP2IdetailNotFound | CAUGHT | L |
| d6-supported | `hp`: no support row required | TestP2IdetailNotFound | CAUGHT | L |
| identity-workspace-scope | `hp`: identity load not workspace-scoped | TestP2IdetailNotFound | CAUGHT | L |
| retired-identity-readable | `hp`: lifecycle filter on load | TestP2IdetailRetiredIdentityReadable | CAUGHT | L |
| external-workspace-scope | `ex`: external principal not workspace-scoped | TestP2IdetailNotFound | CAUGHT | L |
| credential-one-entry-per-key | `id`: DISTINCT ON source_key removed | TestP2IdetailCredentialTurnsInactive | CAUGHT | L |
| credential-inactive-status | `id`: revoked not mapped to inactive | TestP2IdetailIdentityOverview | CAUGHT | L |
| provider-attrs-allowlist | `id`: raw jsonb rendered, not the D-85 allowlist | TestP2IdetailIdentityOverview | CAUGHT | L |
| trust-flag-unknown-is-null | `id`: an unwritten trust flag rendered false | TestIdetailIdentityProviderAttrs | CAUGHT | L |
| activity-outside-sample | `pm`: activity outside the capped sample is collected | TestP2IdetailActivityNotCollected | CAUGHT | L |
| activity-run-generation | `pm`: activity rows not limited to the run's generation | TestP2IdetailActivityNotCollected | CAUGHT | L |
| activity-same-principal | `pm`: no unique_id match | TestP2IdetailActivityNotCollected | CAUGHT | L |
| activity-retired-not-collected | `pm`: a retired identity's activity collected | TestP2IdetailRetiredIdentityReadable | CAUGHT | L |
| include-ended-default-off | `hp`: include_ended on by default | TestP2IdetailUsedByPaging | CAUGHT | L |
| cursor-route-carries-section | `ub`: cursor route does not carry the section (D-62) | TestP2IdetailUsedByPaging | CAUGHT | L |
| cursor-filter-binds-include-ended | `hp`: cursor filter does not bind include_ended | TestP2IdetailUsedByPaging | CAUGHT | L |
| keyset-strictly-after | `hp`: keyset `>=` | TestP2IdetailUsedByPaging | CAUGHT | L |
| usedby-task-execution-role | `ub`: workloads section drops task_execution_role | TestP2IdetailUsedBySharedRole | CAUGHT | L |
| usedby-section-applies | `ub`: a section that does not apply to the kind accepted | TestP2IdetailUsedBySharedRole | CAUGHT | L |
| usedby-group-sections | `ub`: a group gets more than members | TestP2IdetailUsedBySharedRole | CAUGHT | L |
| claim-stale-reason-partition-match | `hp`: partition matched by something other than key equality | TestP2IdetailUsedByStaleMembers | CAUGHT | L |
| detail-coverage-access-keys | `id`: user coverage drops iam_access_keys | TestP2IdetailDetailCoverage | CAUGHT | L |
| detail-coverage-only-bearing | `id`: coverage for surfaces that do not bear | TestP2IdetailDetailCoverage | CAUGHT | L |
| unresolved-account-not-connected | `ex`: unresolved_reason account_not_connected removed | TestP2IdetailExternalPrincipals | CAUGHT | L |
| account-connected-null-without-account | `ex`: account_connected false with no account | TestP2IdetailExternalPrincipals | CAUGHT | L |
| resolution-null-without-basis | `ex`: resolution rendered without a basis (D-87) | TestP2IdetailExternalPrincipals | CAUGHT | L |
| referenced-by-negated | `ex`: negated not read from trust_negated_statements (D-88) | TestP2IdetailExternalPrincipals | CAUGHT | L |
| external-derived-lifecycle | `ex`: lifecycle not derived (D-47) | TestP2IdetailExternalResolvedAndRetired | CAUGHT | L |
| external-star-label | `ex`: `*` not labelled "any AWS principal" | TestP2IdetailExternalPrincipals | CAUGHT | L |
| used-by-count-optional | `id`: used_by_count not optional work | TestP2IdetailOptionalCountsTimeOut | CAUGHT | L |
| revision-count-optional | `pm`: revision_count not optional work | TestP2IdetailOptionalCountsTimeOut | CAUGHT | L |
| statement-stale-reason | `pm`: stale statements lack stale_reason (D-74) | TestP2IdetailPermissionsStaleStatements | CAUGHT | L |
| notprincipal-limitation | `ub`: NotPrincipal role's principals lack not_principal_unresolved | TestP2IdetailUsedByNotPrincipalLimitation | CAUGHT | L |
| external-k8s-label | `ex`: k8s_service_account not labelled ns/sa | TestP2IdetailExternalLabels | CAUGHT | L |

An earlier in-place run was stopped partway and left `pm` mutated; see §6.6 below. `SP/idetail_mutation_results.txt` holds its four CAUGHT lines; the report says five. It is superseded and not counted.

**Review.** Source: R+b. The reviewer's overlays are in `SP/idmut/`: `m1`–`m3_permissions.go`, with `orig_permissions.go` beside them. Both counted mutants passed all 19 TestP2Idetail* tests.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| m2 | `pm` l.274: `(r.state IN ? OR true)` in the groups query | none | MISSED→FIXED. TestP2IdetailPermissionsLeftGroup added; the fix's M1 is caught | R+b |
| m3 | `pm` l.495: `e.lifecycle = 'active'` removed | none | MISSED→FIXED. TestP2IdetailPermissionsReplacedAndRecreated added; the fix's M3 is caught | R+b |
| m1 | `pm` l.547: `AND e.effect = 'allow'` removed | not reported | The overlay was prepared and the review reports no outcome. Not counted | R+b |

**Fix.** Source: L, `SP/idfix2/mut_all.txt` and `SP/idfix2/mut_m15.txt`. The mutants were run as overlays, and all five source files kept their sha256 (listed in mut_m15.txt).

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| M1 | inheritance not limited to a live membership (reviewer m2) | TestP2IdetailPermissionsLeftGroup | CAUGHT | L |
| M2 | include_ended does not show the ended membership | TestP2IdetailPermissionsLeftGroup | CAUGHT | L |
| M3 | the default shows inactive statements (reviewer m3) | TestP2IdetailPermissionsReplacedAndRecreated | CAUGHT | L |
| M4 | include_ended does not read retired statements | TestP2IdetailPermissionsReplacedAndRecreated | CAUGHT | L |
| M5 | live statements no longer sorted before history | TestP2IdetailPermissionsReplacedAndRecreated | CAUGHT | L |
| M6 | grant_stale_reason not rendered | TestP2IdetailPermissionsStaleStatements | CAUGHT | L |
| M7 | stale grants not sent to ClaimStaleReasons | TestP2IdetailPermissionsStaleStatements | CAUGHT | L |
| M8 | a document-protected claim does not name policy_documents (idetail_helpers.go) | TestP2IdetailPermissionsStaleStatements | CAUGHT | L |
| M9 | newer-generation row probe removed | TestP2IdetailActivityNewerPartialScanNotMixed | CAUGHT | L |
| M10 | newer-run coverage probe removed | TestP2IdetailActivityNewerScanDeletedEverything | CAUGHT | L |
| M11 | a newer scan does not answer not_collected | TestP2IdetailActivityNewerScanNotMixed | CAUGHT | L |
| M12 | `=` generation changed to `<=` | TestP2IdetailActivityNotCollected | CAUGHT | L |
| M13 | inRevision forced true | TestP2IdetailExternalConnectedAsOfRevision | CAUGHT | L |
| M14 | used-by chip from live state | TestP2IdetailExternalConnectedAsOfRevision | CAUGHT | L |
| M15 | detail account from live state (mut_all: BUILD-ERROR; the corrected mutant is caught in mut_m15) | TestP2IdetailExternalConnectedAsOfRevision | CAUGHT | L |
| M16 | a revoked connector counted as connected | TestIdetailExternalPrincipalAccount | MISSED→FIXED. The log shows only the catch. The report says it was not caught at first and was caught once the reconnected-account case was added | L; first run R |
| M17 | account_principal reason removed (unit) | TestIdetailUnresolvedReasonOf | CAUGHT | L |
| M18 | account_principal reason removed (integration) | TestP2IdetailExternalConnectedAsOfRevision | CAUGHT | L |
| M19 | no retired_reason on a retired principal | TestP2IdetailExternalResolvedAndRetired; TestP2IdetailExternalLabels | CAUGHT | L |
| M20 | retired_reason emitted when not retired | TestP2IdetailExternalPrincipals | CAUGHT | L |
| M21 | credential status not in AWS spelling (unit) | TestIdetailCredentialStatusOf | CAUGHT | L |
| M22 | credential status not in AWS spelling (integration) | TestP2IdetailIdentityOverview; TestP2IdetailCredentialTurnsInactive | CAUGHT | L |

#### wdetail (T6.3 workload tabs): impl `d0cd854`, fix `3fe14333`

56 checks: 51 caught, 4 missed→fixed, 1 missed (the gate was removed).

**Implement.** Source: R+b. `SP/wdetail-mut/batch1.json`–`batch4.json` hold the 35 mutant specs (the 34 below plus `detail-decision`), and each has its `<name>.orig` backup beside them; no outcome log exists. batch1b re-runs three batch1 mutants after the test change. `detail-decision` did not build and was replaced by `detail-decision-v2`. Files: `wr` = internal/igaread/workload_resources.go, `wd` = workload_detail.go, `wi` = workload_identities.go, `wp` = workload_partitions.go, `pj` = internal/igagraph/project.go.

| ID (spec name) | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| res-target-mode | `wr`: `t.target_mode = 'resource'` changed to `true` (B19) | TestP2WdetailResourcesNotResource | CAUGHT | R+b |
| res-effect-allow | `wr`: `e.effect = 'allow'` dropped (rule 7) | TestP2WdetailResourcesDenyAndBoundaryAreRestrictions | CAUGHT | R+b |
| res-no-boundary-grant | `wr`: `a.assignment_kind <> 'boundary'` dropped | TestP2WdetailResourcesDenyAndBoundaryAreRestrictions | CAUGHT | R+b |
| res-holders-exclude-task-exec | `wr`: holders include task_execution_role (D-78) | TestP2WdetailECSTaskExecutionRoleIsOther | CAUGHT | R+b |
| res-deny-count | `wr`: deny_statements counts `effect = 'allow'` | TestP2WdetailResourcesDenyAndBoundaryAreRestrictions | MISSED→FIXED. The fixture had one Allow and one Deny statement, so the counts matched. A second Allow policy was added; the batch1b re-run was caught | R+b |
| res-boundary-flag | `wr`: permissions_boundary reads the attached kind | TestP2WdetailResourcesTwoLinesThenDetach | CAUGHT | R+b |
| res-group-deny | `wr`: a group's Deny statements not counted for its member (D-22) | TestP2WdetailGroupsAndGroupHeldGrants | CAUGHT | R+b |
| res-cursor-route | `wr`: cursor route drops the workload id (D-62) | TestP2WdetailResourcesPaging | CAUGHT | R+b |
| proj-provider-attrs | `pj`: provider_attrs written as `{}` | TestP2WdetailProviderAttrsFollowRescan; TestP2WdetailDetailShape | CAUGHT | R+b |
| proj-lambda-empty-list | `pj`: env_var_names nil, not `[]` | TestP2WdetailDetailShape | CAUGHT | R+b |
| proj-unread-targets | `pj`: an unread gateway target list written | TestP2WdetailWorkloadProviderAttrs | CAUGHT | R+b |
| detail-null-not-empty | `wd`: an uncollected fact rendered `""` | TestP2WdetailDetailShape | CAUGHT | R+b |
| detail-workspace-scope | `wd`: `(w.workspace_id = ? OR true)` | TestP2WdetailNotFound | CAUGHT | R+b |
| detail-provider-aws | `wd`: `provider <> ''` in place of `= 'aws'` (D-6) | TestP2WdetailNotFound | CAUGHT | R+b |
| detail-supported | `wd`: support row not required (D-6) | TestP2WdetailNotFound | CAUGHT | R+b |
| detail-published | `wd`: D-4 404 disabled | TestP2WdetailNotFound | CAUGHT | R+b |
| ids-published | `wi`: D-4 404 disabled | TestP2WdetailNotFound | CAUGHT | R+b |
| res-published | `wr`: D-4 404 disabled | TestP2WdetailNotFound | CAUGHT | R+b |
| detail-sources-ended | `wd`: ended support rows dropped from sources | TestP2WdetailRetiredWorkloadReadable | CAUGHT | R+b |
| detail-decision-v2 | `wd`: latest decision set to nil (v1 did not build) | TestP2WdetailCanClassifyAndDecision | CAUGHT | R+b |
| detail-can-classify | controllers/platform/iga_graph_read_workloads.go: `SetCanClassify(true \|\| can)` | TestP2WdetailDetailShape; TestP2WdetailCanClassifyAndDecision | CAUGHT | R+b |
| tabs-default-states | `wd`: default states include ended (D-12) | TestP2WdetailRetiredWorkloadReadable; TestP2WdetailResourcesTwoLinesThenDetach | CAUGHT | R+b |
| ids-may-assume-sources | `wi`: may_assume sources not the execution identities | TestP2WdetailIdentitiesSharedRoleAndMayAssume | CAUGHT | R+b |
| ids-cursor-route-section | `wi`: cursor route drops the section (D-62) | TestP2WdetailIdentitiesSectionPaging | CAUGHT | R+b |
| ids-filter-hash-section | `wi`: section included in the filter hash | TestP2WdetailIdentitiesSectionPaging | CAUGHT | R+b |
| ids-keyset-strict | `wi`: keyset `>=` | TestP2WdetailIdentitiesSectionPaging | CAUGHT | R+b |
| ids-arn-middle-states | `wi`: execution_role_arn shown in every state | TestP2WdetailIdentitiesSharedRoleAndMayAssume; TestP2WdetailExecutionRoleStates | CAUGHT | R+b |
| edge-stale-reasons | `wp`: partition gaps dropped from EdgeStaleReasons (D-74) | TestP2WdetailExecutionRoleStates | CAUGHT | R+b |
| coverage-execution-partition | `wp`: executes_as partition left out of meta.coverage | TestP2WdetailExecutionRoleStates | CAUGHT | R+b |
| coverage-gaps-unsupported | `wp`: unsupported surfaces reported as gaps | TestP2WdetailCoverageGaps | CAUGHT | R+b |
| statement-actions-verbatim | `wd`: actions not parsed from native_rights | TestP2WdetailResourcesTwoLinesThenDetach | CAUGHT | R+b |
| statement-index-one-based | `wd`: 0-based index (D-84) | TestP2WdetailResourcesTwoLinesThenDetach | CAUGHT | R+b |
| coverage-revoked-note | `wp`: revoked `*` note dropped | TestP2WdetailRevokedConnector | CAUGHT | R+b |
| features-workloads | controllers/platform/iga_graph_read_controller.go: features.workloads false (D-11) | TestP2S2PipelineAndCoverageUnavailableWhenOff | CAUGHT | R+b |

**Review.** Source: L, `SP/wdetail_mutate.log`, for A–D, each "restored: sha256 ok". E is only reported; its backup is `SP/wdetail_wr_E.bak` (01:27).

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| A | `wr` l.146: rule-7 `effect = allow` changed to `true` | TestP2WdetailResourcesDenyAndBoundaryAreRestrictions | CAUGHT | L |
| B | `wr` l.152: `target_mode = resource` changed to `true` (B19) | TestP2WdetailResourcesNotResource | CAUGHT | L |
| C | `wr` l.179: holders include ended executes_as | TestP2WdetailRetiredWorkloadReadable | CAUGHT | L |
| D | `wr` l.431: deny count ignores assignment state | none (tests/integration ok) | MISSED→FIXED. The test detaches NoDeletes and rescans; the fix's F4-deny is caught | L |
| E | `wr`: permissions_boundary ignores assignment state | none | MISSED→FIXED. The test removes the boundary and rescans; the fix's F4-boundary is caught | R+b |

**Fix.** Source: L. `SP/wdetailfix/results_run1.json` holds 17 records and `results.json` 7 F5 re-runs, each `restored_ok`. Also in `pj`: internal/awsdiscovery/workloads.go and services/cloud_aws_workload_scan.go.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| F1-total-omitempty | `wi`: `json:"total"` restored | TestP2WdetailSectionTotalsFollowTheListRule | CAUGHT | L |
| F1-drop-total-at-least | `wi`: TotalAtLeast dropped from SetTotal | TestP2WdetailSectionTotalsFollowTheListRule | CAUGHT | L |
| F1-callsite-old-rule | `wi`: `ok && n <= TotalCap` restored | TestP2WdetailIdentitiesSectionTotalAboveTheCap | CAUGHT | L |
| F2-projector-ignores-unread | `pj`: `false && a.EnvVarsUnread` | TestP2WdetailWorkloadProviderAttrs | CAUGHT | L |
| F2-collector-never-unread | workloads.go: lambdaEnvVarsUnread returns false | TestP2WdetailLambdaEnvironmentUnreadIsNotEmpty | CAUGHT | L |
| F2-scan-drops-flag | cloud_aws_workload_scan.go: EnvVarsUnread not copied | TestP2WdetailProviderAttrsFollowRescan | CAUGHT | L |
| F3-kept-targets-shown | `pj`: kept targets shown when incomplete | TestP2WdetailWorkloadProviderAttrs | CAUGHT | L |
| F4-deny-ended-assignment | `wr`: reviewer D | TestP2WdetailResourcesDenyAndBoundaryAreRestrictions | CAUGHT | L |
| F4-boundary-ended-assignment | `wr`: reviewer E | TestP2WdetailResourcesDenyAndBoundaryAreRestrictions | CAUGHT | L |
| F5-no-trust-scope | `wp`: the trust loop over nothing. In run 1, placed in `wi`, it failed to build (`declared and not used: trust`) and was logged `caught: True`; the re-run compiled and was caught | TestP2WdetailMayAssumeCoverageNamesTrustingAccounts | CAUGHT | L |
| F5-trust-any-section | `wi`: trust coverage for any section | TestP2WdetailMayAssumeCoverageNamesTrustingAccounts | CAUGHT | L |
| F5-trust-without-exec | `wi`: execution-identity gate removed | TestP2WdetailMayAssumeCoverageNamesTrustingAccounts | CAUGHT | L |
| F5-trust-revoked-note | `wp`: revoked note dropped | TestP2WdetailMayAssumeCoverageNamesTrustingAccounts | CAUGHT | L |
| F5-trust-edge-partitions-only | `wp`: only connectors that already have edges | TestP2WdetailMayAssumeCoverageNamesTrustingAccounts | CAUGHT | L |
| F5-want-nil-drops-all | `wp`: the resolveWatermarks nil filter | TestP2WdetailMayAssumeCoverageNamesTrustingAccounts | CAUGHT | L |
| F5-trust-kind-filter | `wp`: `MatchesEdge(can_assume, "trust")` filter removed | TestP2WdetailMayAssumeCoverageNamesTrustingAccounts | MISSED→FIXED. It passed in run 1 and was caught in the final run, after the test gained assertions (p2_wdetail_identities_test.go:500). The report does not mention the first pass | L |
| F5-trust-retired | `wi`: a gate the log names "trust-retired" | TestP2WdetailRetiredWorkloadReadable passed | MISSED, resolved by deleting the gate. It is in run 1 only, and the final mutation list no longer has it. The report says one survivor, "a redundant len(nodes)>0 gate", was removed rather than kept as dead code. That this is that gate is confirmed by the files, though the mutation text was not saved: the run's backup `SP/wdetailfix/F5-trust-retired.orig` (sha256 `b28554ee…`, the run's recorded sha_before) has `if len(exec) > 0 && len(nodes) > 0 && contains(wanted, …)` at l.510, commented "a retired workload (no node partitions) reports no coverage", and `3fe1433` has `if len(exec) > 0 && contains(wanted, …)` | L |

#### graph (T6.4 traversal): impl `86099f4`, fix `a4c22054`

61 checks: 57 caught, 4 missed→fixed.

**Implement.** Source: R+b. No outcome log for this item was found. `SP/mut/specs.json` (00:45, generated by `SP/mut/specs.py`) holds the 29 mutant specs, in the report's order, each naming the same test as its row below: g1 `target_mode_forward`, g2 `target_mode_reverse`, g3 `none_exists_requires_no_bound`, g4 `closes_cycle`, g5 `visited_set`, g6 `crosses_account_differ`, g7 `far_coverage`, g8 `assume_hops_limit`, g9 `node_budget`, g10 `edge_budget`, g11 `frontier_zero_suppressed`, g12 `level_in_savepoint`, g13 `no_counts_after_time`, g14 `time_reserve`, g15 `grant_allow_only`, g16 `target_allow_only`, g17 `lifecycle_filter`, g18 `root_workspace`, g19 `root_types`, g20 `exclusions`, g21 `group_key_digest`, g22 `deny_through_groups`, g23 `edge_stale_reason`, g24 `unfollowed_resolution`, g25 `rediscover_rows`, g26 `edge_order`, g27 `cursor_filter`, g28 `path_budget`, g29 `path_hop_limit`. The g-numbers are this report's labels.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| g1 | forward target query not limited to `mode = 'resource'` | TestP2GraphNotResourceIsNeverAnEdge | CAUGHT | R+b |
| g2 | reverse target query not limited to `mode = 'resource'` | TestP2GraphNotResourceIsNeverAnEdge | CAUGHT | R+b |
| g3 | none_exists without requiring that no budget bound (D-38) | TestP2GraphPathNoneExistsOnlyWhenExhausted | CAUGHT | R+b |
| g4 | closes_cycle not set on the edge back to the source | TestP2GraphCycleClosesAndIsNotReexpanded | CAUGHT | R+b |
| g5 | visited set removed | TestP2GraphCycleClosesAndIsNotReexpanded | CAUGHT | R+b |
| g6 | crosses_account true whenever both accounts are known, same or not (`from.acct != to.acct` dropped; D-36) | TestP2GraphCrossAccountEdge | MISSED→FIXED. The first run passed. The test gained a same-account executes_as edge, and the re-run was caught | R+b |
| g7 | no far-account coverage on a crossing edge | TestP2GraphCrossAccountEdge | CAUGHT | R+b |
| g8 | assume_hops limit removed | TestP2GraphAssumeHopsFrontier | CAUGHT | R+b |
| g9 | node budget removed | TestP2GraphNodeAndEdgeBudgets | CAUGHT | R+b |
| g10 | edge budget removed | TestP2GraphNodeAndEdgeBudgets | CAUGHT | R+b |
| g11 | a frontier pair counted at zero listed | TestP2GraphNodeAndEdgeBudgets | CAUGHT | R+b |
| g12 | a level outside its savepoint (504, not 200 truncated time) | TestP2GraphTimeBudgetTruncates | CAUGHT | R+b |
| g13 | exact frontier counts after the time budget bound | TestP2GraphTimeBudgetTruncates | CAUGHT | R+b |
| g14 | D-40 reserve check removed | TestP2GraphTimeReserve | CAUGHT | R+b |
| g15 | grants read for Deny statements (rule 7) | TestP2GraphDenyAndBoundaryAreRestrictions | CAUGHT | R+b |
| g16 | targets read through Deny statements | TestP2GraphDenyAndBoundaryAreRestrictions | CAUGHT | R+b |
| g17 | lifecycle filter removed | TestP2GraphEndedEdgesOnlyWhenAsked | CAUGHT | R+b |
| g18 | root read without the workspace predicate (E14) | TestP2GraphWorkspaceAndGates | CAUGHT | R+b |
| g19 | a policy or claim root accepted (D-39) | TestP2GraphParametersAndRoots | CAUGHT | R+b |
| g20 | NotResource entries not on the statement node | TestP2GraphNotResourceIsNeverAnEdge | CAUGHT | R+b |
| g21 | group_key leaves out condition, exclusions or effect (D-37) | TestP2GraphConditionSplitsGroupKey | CAUGHT | R+b |
| g22 | group-held Deny statements not counted against members | TestP2GraphMembershipCarriesRestrictions | CAUGHT | R+b |
| g23 | stale edges without their partition's gaps (D-74) | TestP2GraphStaleEdgesAreMarked | CAUGHT | R+b |
| g24 | an unfollowed resolution reported none_exists | TestP2GraphExternalPrincipalIsTerminal | CAUGHT | R+b |
| g25 | re-discovered edges not added to the LIMIT | TestP2GraphPathRediscoveredEdgesCostNoRows | CAUGHT | R+b |
| g26 | ORDER BY (target source_key, id) removed | TestP2GraphTeachingPathReverse | CAUGHT | R+b |
| g27 | expansion cursor not bound to the filter hash | TestP2GraphExpandPagesAndCursor | CAUGHT | R+b |
| g28 | path budget removed | TestP2GraphPathBudget | CAUGHT | R+b |
| g29 | hop limit on enumerated paths removed | TestP2GraphPathHopLimit | CAUGHT | R+b |

**Review.** Source: R+b, backup `SP/graphmut/traverse_edges.go.orig`. No test caught any of the three.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| RV-1 | traverse_edges.go ~l.243: reverse grant lifecycle `e0.state <> 'ended'` removed | none | MISSED→FIXED. TestP2GraphEndedEdgesOnlyWhenAsked now checks reverse traversal; the fix's M1 is caught | R+b |
| RV-2 | ~l.361: lifecycle filter removed from countNeighbours | none; the test's "not a hidden frontier neighbour" assertion was vacuous, because no budget bound | MISSED→FIXED. The same test now binds a budget next to the ended grant; the fix's M3 is caught | R+b |
| RV-3 | ~l.254: reverse target `far.lifecycle = 'active'` removed | none | MISSED→FIXED. TestP2GraphRetiredStatementOnlyWhenAsked added; the fix's M2 is caught | R+b |

**Fix.** Source: L, `SP/mut.log`, 29 lines, each "restored sha256 … match=True clean=True". The catching test comes from the file:line in each log line, looked up in `a4c2205`.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| M1 | reverse grant lifecycle filter (reviewer RV-1) | TestP2GraphEndedEdgesOnlyWhenAsked | CAUGHT | L |
| M2 | reverse target statement-lifecycle filter (reviewer RV-3) | TestP2GraphRetiredStatementOnlyWhenAsked | CAUGHT | L |
| M2b | forward target statement-lifecycle filter | TestP2GraphRetiredStatementOnlyWhenAsked | CAUGHT | L |
| M3 | frontier-count lifecycle filter (reviewer RV-2) | TestP2GraphEndedEdgesOnlyWhenAsked | CAUGHT | L |
| M4 | reverse orientation never searched | TestP2GraphPathEitherOrientation | CAUGHT | L |
| M4b | reverse paths not reported | TestP2GraphPathEitherOrientation | CAUGHT | L |
| M5 | none_exists on one orientation | TestP2GraphPathEitherOrientation | CAUGHT | L |
| M5u | none_exists on one orientation (unit) | TestP2GraphPathDecide | CAUGHT | L |
| M6 | reverse path node order | TestP2GraphPathEitherOrientation | CAUGHT | L |
| M6b | reverse list ignores an unfinished forward search | TestP2GraphPathDecide | CAUGHT | L |
| M7 | member boundary not emitted (D-22) | TestP2GraphMembershipCarriesRestrictions | CAUGHT | L |
| M8 | member boundary existence ignored | TestP2GraphMembershipCarriesRestrictions | CAUGHT | L |
| M9 | ended membership counted | TestP2GraphMembershipCarriesRestrictions | CAUGHT | L |
| M10 | ended boundary assignment counted | TestP2GraphMembershipCarriesRestrictions | CAUGHT | L |
| M11 | /graph resolution check skipped | TestP2GraphExternalPrincipalIsTerminal | CAUGHT | L |
| M12 | forward resolution query skipped | TestP2GraphExternalPrincipalIsTerminal | CAUGHT | L |
| M13 | a held principal's resolution ignored | TestP2GraphExternalPrincipalIsTerminal | CAUGHT | L |
| M14 | the path's forward-side principal link ignored | TestP2GraphExternalPrincipalIsTerminal | CAUGHT | L |
| M15 | stale target without its statement's reason | TestP2GraphStaleTargetsCarryTheirStatementsReason | CAUGHT | L |
| M16 | stale principal without a reason | TestP2GraphStaleEdgesAreMarked | CAUGHT | L |
| M17 | expand page started under the reserve (D-40) | TestP2GraphExpandTimeReserve | CAUGHT | L |
| M18 | level statements not re-armed | TestP2GraphLevelRearmsEveryStatement | CAUGHT | L |
| M19 | level copy keeps the request deadline | TestP2GraphLevelRearmsEveryStatement | CAUGHT | L |
| M19i | the same, end to end | TestP2GraphNestedOptionalsFitTheirLevel | CAUGHT | L |
| M20 | nested Optional re-armed to the whole remainder | TestP2GraphLevelRearmsEveryStatement | CAUGHT | L |
| M21 | savepoint numbering not handed back | TestP2GraphLevelRearmsEveryStatement | CAUGHT | L |
| M22 | NodeStaleReasons run on the request query | TestP2GraphNestedOptionalsFitTheirLevel | CAUGHT | L |
| M23 | edge run history run on the request query | TestP2GraphNestedOptionalsFitTheirLevel | CAUGHT | L |
| M24 | far coverage run on the request query | TestP2GraphNestedCoverageFitsItsLevel | CAUGHT | L |

#### evidence (T6.5): impl `a3442b4`, fix `7b978c7d`

60 checks: 58 caught, 2 missed→fixed.

**Implement.** Source: L, `SP/evidence_mut/mutations.log`; every record is `"result": "CAUGHT"`. Files: `lm` = internal/igaread/limitations.go (L1–L21, U2), `ef` = evidence_facts.go (F1–F6, U1), `ev` = evidence.go (E1–E12).

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| L1 | `lm`: effective_access_not_evaluated on every claim, not only grants | TestP2EvidenceLimitationVocabulary | CAUGHT | L |
| L2 | `lm`: conditions_not_evaluated without a statement Condition | TestP2EvidenceLimitationVocabulary | CAUGHT | L |
| L3 | `lm`: conditions_not_evaluated on can_assume without a trust Condition | TestP2EvidenceLimitationVocabulary | CAUGHT | L |
| L4 | `lm`: negated_statement dropped | TestP2EvidenceLimitationVocabulary | CAUGHT | L |
| L5 | `lm`: trust negated_statement not keyed on trust_negated_statements (D-88) | TestP2EvidenceLimitationVocabulary | CAUGHT | L |
| L6 | `lm`: deny_statements_present ignores the holder's groups | TestP2EvidenceLimitationVocabulary | CAUGHT | L |
| L7 | `lm`: deny query effect inverted | TestP2EvidenceLimitationVocabulary | CAUGHT | L |
| L8 | `lm`: group members' boundaries ignored on group-held grants (D-22) | TestP2EvidenceLimitationVocabulary | CAUGHT | L |
| L9 | `lm`: boundary query kind inverted | TestP2EvidenceLimitationVocabulary | CAUGHT | L |
| L10 | `lm`: organizations_not_collected removed | TestP2EvidenceLimitationVocabulary | CAUGHT | L |
| L11 | `lm`: resource_policy_not_projected on any target | TestP2EvidenceLimitationVocabulary | CAUGHT | L |
| L12 | `lm`: resource policy not scoped to published runs at or below the rev (D-19) | TestP2EvidenceResourcePolicyOfAnUnpublishedRun | CAUGHT | L |
| L13 | `lm`: a selector counted as an exact reference (D-21) | TestP2EvidenceLimitationVocabulary | CAUGHT | L |
| L14 | `lm`: caller_permission_not_evaluated on every relationship | TestP2EvidenceLimitationVocabulary | CAUGHT | L |
| L15 | `lm`: not_principal_unresolved always | TestP2EvidenceLimitationVocabulary | CAUGHT | L |
| L16 | `lm`: policy_documents fallback on current claims | TestP2EvidenceStaleGrantOnUnreadablePolicy | CAUGHT | L |
| L17 | `lm`: surface code flattened (denied/partial/stale) | TestP2EvidenceSurfaceLimitations | CAUGHT | L |
| L18 | `lm`: collection always complete | TestP2EvidenceSurfaceLimitations | CAUGHT | L |
| L19 | `lm`: a claim with no nameable partition reported complete | TestP2EvidenceUnrecordedPartitionIsNotComplete | CAUGHT | L |
| L20 | `lm`: activity_attempts_not_outcomes never emitted | TestP2EvidenceActivityAttemptsNotOutcomes | CAUGHT | L |
| L21 | `lm`: partition surface gaps ignored | TestP2EvidenceSurfaceLimitations | CAUGHT | L |
| F1 | `ef`: junction links not filtered by generation (D-24) | TestP2EvidenceFactsDropSupersededVersions | CAUGHT | L |
| F2 | `ef`: grant facts from any source | TestP2EvidenceFactsKeepOnlyBearingSources | CAUGHT | L |
| F3 | `ef`: any junction relation, not only supports | TestP2EvidenceOnlySupportingLinks | CAUGHT | L |
| F4 | `ef`: presence anchors not filtered by generation | TestP2EvidenceFactsDropSupersededVersions | CAUGHT | L |
| F5 | `ef`: Access Advisor rows not limited to the support run (D-25) | TestP2EvidenceActivityAttemptsNotOutcomes | CAUGHT | L |
| F6 | `ef`: stale_since off by one (D-23) | TestP2EvidenceSurfaceLimitations | CAUGHT | L |
| E1 | `ev`: grant read without `effect = allow` (rule 7) | TestP2EvidenceDenyIsNeverAGrant | CAUGHT | L |
| E2 | `ev`: grant read without workspace_id | TestP2EvidenceErrors | CAUGHT | L |
| E3 | `ev`: identity presence not limited to provider aws (D-6) | TestP2EvidenceOnlyProjectorRows | CAUGHT | L |
| E4 | `ev`: presence without a support row (D-6) | TestP2EvidenceOnlyProjectorRows | CAUGHT | L |
| E5 | `ev`: coverage claim run not one the revision stands on (D-80) | TestP2EvidenceCoverageClaim | CAUGHT | L |
| E6 | `ev`: summary ignores group_key (D-79) | TestP2EvidenceGroupedGrants | CAUGHT | L |
| E7 | `ev`: claim cap raised above 50 (D-79) | TestP2EvidenceErrors | CAUGHT | L |
| E8 | `ev`: 0-based statement index (D-84) | TestP2EvidenceGrantFactsAndShape | CAUGHT | L |
| E9 | `ev`: raw always included | TestP2EvidenceGrantFactsAndShape | CAUGHT | L |
| E10 | `ev`: a revoked connector reported connected (D-89) | TestP2EvidenceRevokedConnector | CAUGHT | L |
| E11 | `ev`: resource endpoint connected from the projected value alone (D-3) | TestP2EvidenceLimitationVocabulary | CAUGHT | L |
| E12 | `ev`: external principal account connected not read against live connectors | TestP2EvidenceLimitationVocabulary | CAUGHT | L |
| U1 | `ef`: user-entry classification ignores the call (unit) | TestP2EvidenceClassifyObservation | CAUGHT | L |
| U2 | `lm`: condition keys from the first operator only (unit) | TestP2EvidenceConditionKeys | CAUGHT | L |

**Review.** Source: L, `SP/evrev/M1`–`M4-*.log`. The review report mentions only M2 and M4.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| M1 | `ev`: relationship read without the workspace filter | TestP2EvidenceErrors (another workspace's relationship answered 200) | CAUGHT | L |
| M2 | `lm` ~l.602: `pa.state <> ended` removed from the Deny query | none (tests/integration ok) | MISSED→FIXED. TestP2EvidenceDenyOnlyWhileAssignedAndMember added; the fix's I is caught | L |
| M3 | `ef`: D-24 junction generation filter removed | TestP2EvidenceFactsDropSupersededVersions | CAUGHT | L |
| M4 | `lm` ~l.585: `r.state <> ended` removed from the member_of group collection | none (tests/integration ok) | MISSED→FIXED. The same new test covers it; the fix's J is caught | L |

**Fix.** Source: R+b. The 15 `.bak` backups in `SP/evidence-fix-mut/` show each mutant was applied; the outcomes went to stdout and exist only in the report. The report names new tests but does not say which one catches each of C–H3, K, L and N; it ties A, B, I and J to their tests.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| A | `ef`: anchor lower bound (first recorder) removed | TestP2EvidenceFactsIgnoreAnUnprojectedRun | CAUGHT | R+b |
| B | `ef`: junction lower bound removed | TestP2EvidenceJunctionNeverLinksALaterRead | CAUGHT | R+b |
| C | `ev`: grant content-as-of override off | one of TestP2EvidenceEndedGrantKeepsItsContent, TestP2EvidenceSharedPolicyFactsAsOfEachAccount, TestP2EvidenceEndedSentences, TestP2EvidenceContentTargets, TestP2EvidenceContentApply | CAUGHT | R+b |
| D | `ef`: names-drop off | one of those tests | CAUGHT | R+b |
| E | `ef`: anchor content-as-of off | one of those tests | CAUGHT | R+b |
| F | `ef`: policy version from the observation replaced by `''` | one of those tests | CAUGHT | R+b |
| G | evidence_content.go: `Index = nil` removed | one of those tests | CAUGHT | R+b |
| H | `ev`: ended grant stated in the present tense | one of those tests | CAUGHT | R+b |
| H2 | `ev`: ended assignment stated in the present tense | one of those tests | CAUGHT | R+b |
| H3 | `ev`: ended relationship stated in the present tense | one of those tests | CAUGHT | R+b |
| I | `lm`: Deny of an ended assignment counted (reviewer M2) | TestP2EvidenceDenyOnlyWhileAssignedAndMember | CAUGHT | R+b |
| J | `lm`: Deny of a group the holder left counted (reviewer M4) | TestP2EvidenceDenyOnlyWhileAssignedAndMember | CAUGHT | R+b |
| K | evidence_content.go: revision chosen by `true`, not by publication rev | one of the content tests | CAUGHT | R+b |
| L | evidence_content.go: differs-from-current filter removed | one of the content tests | CAUGHT | R+b |
| N | `ev`: historical targets not applied | one of the content tests | CAUGHT | R+b |

#### D-57 on `graph`: commit `3ea0244`

3 checks, all caught. Source: R+b. The commit message says TestP2ManifestIsCumulativeAcrossAccounts and TestP2PartitionKeysCarryTheRealScope are "each mutation-checked" against three mutants: the manifest not cumulative, a key without scope and connector, and keys computed before the scope. It does not say which test catches which. Backups: `SP/d57bak/project.go`, `project2.go`, `snapshot.go`.

### 6.5 Wave C

#### bfk (B9/B20 foreign keys): impl `a986178`, fix `21436d4`

31 checks: 28 caught, 3 missed→fixed. The mutants are DDL applied to the test database (never to migrations) or edits to the test harness. The catching tests are the two test functions and their subtests, as the report names them.

**Implement.** Source: L, `SP/bfkmut/M*.out` and `T*.out`, one per mutant. Every counted row shows `--- FAIL`. The JSON report lists 16 mutants; its summary says "15 recorded".

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| M1 | cloud_pa_principal_fkey made single-column on (principal_identity_id) | TestB9B20ForeignKeysRejectForeignRows/cloud_pa_principal_fkey; TestB9ForeignKeyCatalogGuard | CAUGHT | L |
| M2 | iga_access_edges_run_fkey made single-column on (last_confirmed_by), the A3 pattern | TestB9B20ForeignKeysRejectForeignRows/iga_access_edges_run_fkey/foreign_workspace (row accepted) | CAUGHT | L |
| M3 | cloud_gm_user_fkey made workspace-only (B20) | .../cloud_gm_user_fkey/foreign_integration | CAUGHT | L |
| M4 | iga_le_publication_fkey made NOT DEFERRABLE | .../iga_le_publication_fkey; guard every_foreign_key_has_a_subtest | CAUGHT | L |
| M5 | iga_le_publication_fkey over (rev) alone, so B's revision commits | .../iga_le_publication_fkey/foreign_workspace (accepted at COMMIT) | CAUGHT | L |
| M6 | control broken: iga_pa_holder_fkey pointed at iga_workload (NOT VALID) | .../iga_pa_holder_fkey/control | CAUGHT | L |
| M7 | cloud_gm_connector_fkey made single-column | .../cloud_gm_connector_fkey/foreign_workspace | CAUGHT | L |
| M7b | M7 with sibling-constraint dropping disabled | the same subtest (23503 came from cloud_gm_user_fkey, the wrong constraint) | CAUGHT | L |
| T1 | iga_os_policy_fkey removed from bfkCases | TestB9ForeignKeyCatalogGuard/every_foreign_key_has_a_subtest | CAUGHT | L |
| T2 | cloud_gm_user_fkey's case loses kind bfkIntegration | the shape check; guard every_foreign_key_has_a_subtest | CAUGHT | L |
| T3 | the guard's catalog query drops bfkPhase2CloudTables | TestB9ForeignKeyCatalogGuard/every_foreign_key_has_a_subtest | CAUGHT | L |
| T4 | a stale exemption (cloud_pa_principal_fkey) added to bfkLegacySingleColumn | guard no_single_column_reference_to_a_workspace_scoped_table; a_planted_single_column_reference_is_caught | CAUGHT | L |
| T5 | the §2.9 single-column rule disabled | guard a_planted_single_column_reference_is_caught | CAUGHT | L |
| T6 | the table-scope check disabled | guard a_planted_single_column_reference_is_caught | CAUGHT | L |
| T7 | the deferred negative rolls back instead of committing | .../iga_le_publication_fkey/foreign_workspace | CAUGHT | L |
| T8 | the B20 qualification rule disabled | guard a_planted_workspace_only_collection_reference_is_caught | CAUGHT | L |

Control, not counted: `SP/bfkmut/M7c.out` (08:12), in which cloud_gm_connector_fkey's control and foreign_workspace subtests both pass. It is not in the report, and its mutation text was not saved; that it is M7 with further harness checks disabled is inferred from its name and output.

**Review.** Source: R+b. The reviewer edited migration files in place, with backups in `SP/bfkrev_bak/`. The re-runs of the two missed plants are logged, `SP/bfk_mut/MUT3.txt` and `MUT3b.txt` (09:19–09:20), but they were made by the first, stopped fixer against its uncommitted guard (captured in WIP `77da653`, 09:37), not against `21436d4`. The final fixer did not re-run MUT-3 or MUT-3b; `21436d4` instead builds the pattern into the guard's permanent non-vacuity plant (a new cloud_* table with single-column references only), which the fix's M1 checks.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| MUT-1 | cloud_policy_holder_fkey made single-column | foreign_workspace, foreign_integration, and three guard checks | CAUGHT | R+b |
| MUT-2 | cloud_pa_policy_fkey made workspace-only | foreign_integration (row accepted); the guard's shape and B20 checks | CAUGHT | R+b |
| MUT-4 | iga_access_edge_evidence_obs_fkey made single-column | not named | CAUGHT | R+b |
| MUT-3 | 036 gains cloud_role_session, with single-column FKs to cloud_connector, cloud_identity and cloud_policy | none. Both tests passed, and the guard logged "116 foreign keys in scope, 116 cases" | MISSED→FIXED. `21436d4` scopes the guard by name. Re-run (on the stopped fixer's WIP) `SP/bfk_mut/MUT3.txt`, 6 FAIL lines: TestB9ForeignKeyCatalogGuard fails with "cloud_role_session_connector_id_fkey ... has no subtest" | R+b; re-run L |
| MUT-3b | a single-column cloud_workload.policy_row_id → cloud_policy(id) | none | MISSED→FIXED. Re-run (on the stopped fixer's WIP) `SP/bfk_mut/MUT3b.txt`, 4 FAIL lines: the guard fails with "a single-column reference ... cloud_policy is workspace-scoped" | R+b; re-run L |

**Fix.** Source: L, `SP/bfk_mut/M1_*.out`–`M10_*.out`, driven by `run.sh` with sha256-verified restores. There is no written fix report; commit `21436d4` describes the pass.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| M1 | the child-side `r.relname LIKE 'cloud\_%'` dropped from bfkForeignKeys | TestB9ForeignKeyCatalogGuard | MISSED→FIXED. M1b is the same mutant without the new planted table, and it passes. `21436d4` adds the `cloud_bfk_planted` → discovered_agents(id) plant; with it, M1 fails | L |
| M2 | parent-side scope narrowed | TestB9B20ForeignKeysRejectForeignRows; TestB9ForeignKeyCatalogGuard | CAUGHT | L |
| M3 | an unclassified cloud_* table allowed | TestB9ForeignKeyCatalogGuard | CAUGHT | L |
| M4 | the known-gap statement drops the B20 group | TestB9ForeignKeyCatalogGuard | CAUGHT | L |
| M5 | a Phase 1 exemption removed | TestB9ForeignKeyCatalogGuard | CAUGHT | L |
| M6 | the known-gap probe names an absent key | TestB9B20ForeignKeysRejectForeignRows | CAUGHT | L |
| M7 | a Phase 1 case removed | TestB9ForeignKeyCatalogGuard ("130 foreign keys in scope, 129 cases") | CAUGHT | L |
| M8 | the gap group drops Phase 1 | TestB9ForeignKeyCatalogGuard | CAUGHT | L |
| M9 | a Phase 1 bare workspace_id left unlisted | TestB9ForeignKeyCatalogGuard | CAUGHT | L |
| M10 | the B20 check skips cloud_policy | TestB9ForeignKeyCatalogGuard | CAUGHT | L |

**Earlier runs, superseded and not counted.** These are logs only. None of them saved its mutation text, so each is described from its failure output.
- `SP/mut_M0.txt`–`mut_M2.txt` (06:42, the WIP `8e420bc` agent): cloud_observation_run_fkey, cloud_pa_principal_fkey and iga_os_identity_fkey each made single-column. All 3 failed the tests (caught).
- `SP/bfk_mut/MUT3`, `MUT3b`, `MUT5`–`MUT10` (09:19–09:27, a stopped fixer): the reviewer's two plants (MUT3 and MUT3b, cited above as the review's re-runs and counted there); an outside reference to cloud_identity; cloud_observation_identity_id_fkey converted, which closes a known gap; cloud_secret keys removed; discovered_agent_iga_links_iga_fkey removed; cloud tables missing from the schema; bare workspace_id columns keyed. All 8 FAIL.
- `SP/bfkmut/mut1`–`mut8c` (09:51–09:57, a stopped fixer): the cloud_role_session and cloud_workload.policy_row_id plants; the cloud_assume_edge keys; an unclassified table; an out-of-scope outside reference; cloud_usage → cloud_identity single-column; the known-gap statement omitting a group; cloud_usage key and harness variants. All 10 FAIL.

#### bdb (B-proofs against the database): impl `2b67d69`, fix `1046c1a` / `98d75d9`

37 checks, all caught.

**Implement.** Source: R+b, with a later log. `SP/bdb_mut/*.json` holds 31 mutant specs; the implementer's outcomes were not logged. The fix pass re-ran 28 of the 30 reported mutants, plus b11a (29 records), at `1046c1a`: every one is `"verdict": "CAUGHT"` in `SP/bdbfix3/results_1046c1a.jsonl`. w1 and w2 were not re-run, because `1046c1a` rewrote the deletion test. b11a is a spec file only; it is not in the report's list. Files: `sk` = internal/igagraph/sourcekey.go, `rc` = reconcile.go, `pr` = permissions.go, `pj` = project.go, `ld` = load.go, `ev` = evidence.go, `gr` = repository/iga_graph_repository.go.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| b1 | `sk`: RelationshipKey without the source endpoint | TestP2BdbTwoWorkloadsShareOneRole | CAUGHT | R; re-run L |
| b4a | `rc`: canEnd trusts a present surface, reached or not | TestP2BdbIAMDeniedEndsNothing | CAUGHT | R; re-run L |
| b4b | `rc`: canEnd always false (non-vacuity) | TestP2BdbIAMDeniedEndsNothing/reached | CAUGHT | R; re-run L |
| b8a | `pj`: identity restoration case (c) disabled | TestP2BdbRestoredIdentityKeepsItsIdentity | CAUGHT | R; re-run L |
| b8b | `pr`: policy restoration branch disabled | TestP2BdbRestoredPolicyKeepsItsStatements | CAUGHT | R; re-run L |
| b8c | `pr`: statement restoration (RestoreStatement) disabled | TestP2BdbRestoredPolicyKeepsItsStatements | CAUGHT | R; re-run L |
| b8d | `ld`: LoadExisting includes retired workloads | TestP2BdbReturningWorkloadIsANewObject | CAUGHT | R; re-run L |
| b24 | `ev`: EventLog.Restored records nothing | TestP2BdbLifecycleHistorySurvivesRewrites | CAUGHT | R; re-run L |
| b10a | `pr`: boundary attachments grant | TestP2BdbBoundaryAndDenyGrantNothing | CAUGHT | R; re-run L |
| b10b | `pr` + `gr`: the Deny effect check and the UpsertGrant refusal both removed | TestP2BdbBoundaryAndDenyGrantNothing | CAUGHT | R; re-run L |
| b11 | `sk`: every statement index-keyed | TestP2BdbStatementIdentity | CAUGHT | R; re-run L |
| b11b | `sk`: Sid-less statements index-keyed | TestP2BdbStatementIdentity | CAUGHT | R; re-run L |
| b11a | `sk`: Sid-keyed statements index-keyed (not in the report's list) | TestP2BdbStatementIdentity | CAUGHT | re-run L |
| b13 | services/cloud_aws_scan_worker.go: `pipeline := gate.PipelineMode() \|\| true` | TestP2BdbSwitchOffLeavesTheIdleBarrier | CAUGHT | R; re-run L |
| e1a | `gr`: NextRevision `COALESCE(max, 1) + 1` | TestP2BdbFirstPublication | CAUGHT | R; re-run L |
| e1b | `pj`: an INSERT into iga_agents for provider-native agents | TestP2BdbFirstPublication | CAUGHT | R; re-run L |
| s1 | `rc`: scope() default returns iga_relationship | TestP2BdbEveryPartitionTargetResolvesInScope | CAUGHT | R; re-run L |
| s2 | models/iga_graph.go: SupportColumn maps entitlement to policy_id | TestP2BdbEveryNodeClassResolves | CAUGHT | R; re-run L |
| s3 | models/iga_graph.go: NodeTable's policy mapping removed | TestP2BdbEveryNodeClassResolves | CAUGHT | R; re-run L |
| b21 | `sk`: inline incarnation key from holder.NativeID | TestP2BdbRecreatedRoleInlinePolicyIsANewIncarnation | CAUGHT | R; re-run L |
| b21b | the same mutant | TestP2RecreatedRoleIsANewObject | CAUGHT | R; re-run L |
| t44a | `pj`: task_execution_role targets the task role | TestP2BdbMemberOfAndTaskExecutionRole | CAUGHT | R; re-run L |
| t44b | snapshot.go: member_of partition no longer requires iam_groups | TestP2BdbMemberOfAndTaskExecutionRole | CAUGHT | R; re-run L |
| t44c | snapshot.go: task_execution_role partition no longer requires `ecs:<region>` | TestP2BdbMemberOfAndTaskExecutionRole | CAUGHT | R; re-run L |
| t44d | `pj`: the task_execution_role edge not handed to attachEvidence | TestP2BdbMemberOfAndTaskExecutionRole | CAUGHT | R; re-run L |
| t49a | `ev`: member_of dropped from the attachEvidence map | TestP2BdbEveryEdgeHasEvidence | CAUGHT | R; re-run L |
| t49b | `ev`: can_assume dropped from the attachEvidence map | TestP2BdbEveryEdgeHasEvidence | CAUGHT | R; re-run L |
| d61 | `ld`: ConnectedAccounts includes revoked connectors | TestP2BdbRevokedAccountIsNotConnected | CAUGHT | R; re-run L |
| d64 | `gr`: the UpsertCredential update path disabled | TestP2BdbInactiveKeyKeepsOneRow | CAUGHT | R; re-run L |
| w1 | tests/integration/p2_bdb_deletion_test.go: the proposed-DDL application removed (a test-side mutant) | TestP2BdbWorkspaceDeletionAfterProjection | CAUGHT | R+b |
| w2 | the same test file: proposed DDL applied before the "blocked today" check (test-side) | TestP2BdbWorkspaceDeletionAfterProjection | CAUGHT | R+b |

**Review.** Source: R+b. One mutant was executed; the reviewer restored the file and verified it with `cmp`. `SP/reconcile.go.orig` (09:58) and `SP/reconcile.go.orig2` (10:02), both sha256 `4a1a07a0…` (the unmutated reconcile.go), fit the review's two reconcile.go runs (scope(), then canEnd); the attribution is by file and time only.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| RV-1 | `rc`: scope() given a default table (B18) | TestP2BdbEveryPartitionTargetResolvesInScope (node-partition and unknown-target assertions) | CAUGHT | R+b |

Not counted:
- The reviewer's canEnd (B4) run failed at setup. A timed-out run had left workspace 99f0885d… in iga_w_bdb, and the report says the run "proves nothing".
- B1, B4 and B8 were reasoned about and never run. The fix pass's run at `1046c1a` covers them (b1, b4a, b4b, b8a–b8d above).

**Fix.** Source: L. `SP/bdbfix3/results_1046c1a.jsonl` holds the run at `1046c1a`; `SP/bdbfix3/results.jsonl` holds a re-run at 11:23–11:26, after `98d75d9`. The mutated file is tests/integration/p2_bdb_deletion_test.go (W1–W4) or `rc` (B11e, B11r).

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| W1 | the proposed DDL not applied in the "under the proposed DDL" subtest | TestP2BdbWorkspaceDeletionAfterProjection/after_a_projection/under_the_proposed_DDL_the_delete_cascades_to_every_graph_row | CAUGHT at `1046c1a`. The later re-run records "ERROR (no test failure seen: build or setup problem)" | L |
| W3 | the "as shipped" delete no-oped under the proposed DDL | TestP2BdbWorkspaceDeletionAfterProjection/after_a_projection/under_036_as_shipped_the_delete_cascades_to_every_graph_row ("graph rows left after the workspace delete") | CAUGHT | L |
| W4 | the RESTRICT keys cascaded before the connector hard delete | TestP2BdbWorkspaceDeletionAfterProjection/after_a_projection:_a_connector_hard_delete_never_strips_an_edge_of_its_evidence ("relationship edge ... survived"; the log's -run pattern is `…/connector_hard_delete`) | CAUGHT | L |
| B11e | `rc`: no retired event for entitlements | TestP2BdbStatementIdentity | CAUGHT | L |
| B11r | `rc`: the access_edge partition returns before protected() | TestP2BdbStatementIdentity (grant ended statement_retired, want not_seen) | CAUGHT | L |

Control, not counted: W2 (`SP/bdbfix3/specs/W2.json` has `expect_pass: true`) is recorded "PASSES AS EXPECTED" in both runs. It applies the proposed DDL inside the "under 036 as shipped" subtest, which then runs instead of skipping, and it passed.

Earlier runs, superseded: `SP/bdb/mutations.jsonl` (06:37, the WIP `24de5ef` agent). B1 is caught. B4's first attempt found its old text 0 times; the applied B4 is caught.

#### contract (T6.7 frozen contract): impl `8b65055`, fix `2e89004`

40 checks: 38 caught, 2 missed→fixed. Decision numbers below are graph's. The branch's D-94..D-101 became D-96..D-103 at merge `3a7e4d6`; the branch number is in brackets where the report used it.

**Implement.** Source: L, `SP/contract/c2_mutations.log` (first run) and `SP/contract/c2_rerun.log` (re-run). The report says three mutants did not compile: edges-claim-limitations, node-evidence-limitations and envelope-passthrough. The first run logs each as caught with empty evidence; `c2_rerun.log` records them `caught: false`. Their `-v2` compiling versions are the rows below.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| edges-claim-limitations-v2 | internal/igaread/traverse_limits.go: an edge no longer carries /evidence's fact-free limitations (D-35, D-98(a) [D-96a]) | TestP2ContractGraphLimitationsAreEvidences | CAUGHT | L |
| node-restriction-limitations | traverse_limits.go: a restricted node loses its restrictions' limitations | TestP2ContractGraphLimitationsAreEvidences | CAUGHT | L |
| node-evidence-limitations-v2 | traverse_limits.go: a node loses /evidence's presence limitations | TestP2ContractGraphLimitationsAreEvidences | CAUGHT | L |
| far-coverage | traverse_limits.go: a crosses_account edge loses the far account's coverage | TestP2ContractGraphLimitationsAreEvidences | CAUGHT | L |
| holder-restrictions-groups | loadRestrictions denyOf ignores group statements | TestP2GraphMembershipCarriesRestrictions | CAUGHT | L |
| publication-time-rendering | meta.published_at not rendered to the second (D-96 [D-94]) | TestP2ContractEveryRouteFieldByField | CAUGHT | L |
| capabilities-always | detail meta.capabilities omitted (D-97 [D-95]) | TestP2ContractEveryRouteFieldByField | CAUGHT | L |
| support-source-presence | sources do not name their support row (D-98(b)) | TestP2ContractEveryRouteFieldByField | CAUGHT | L |
| workload-sources-shared | workload detail does not list its support rows (D-98(b)) | TestP2ContractEveryRouteFieldByField | CAUGHT | L |
| may-assume-trust-sid | may_assume without {key, sid, negated} (D-98(c)) | TestP2ContractEveryRouteFieldByField | CAUGHT | L |
| identity-retired-reason-present | identity detail omits retired_reason (D-98(d)) | TestP2ContractEveryRouteFieldByField | CAUGHT | L |
| resource-retired-reason-present | resource detail omits retired_reason (D-98(d)) | TestP2ContractEveryRouteFieldByField | CAUGHT | L |
| external-retired-reason-present | external-principal detail omits retired_reason (D-98(d)) | TestP2ContractEveryRouteFieldByField | CAUGHT | L |
| statement-node-sid | statement node omits sid (D-98(e)) | TestP2ContractEveryRouteFieldByField | CAUGHT | L |
| principal-node-lifecycle | external-principal node omits lifecycle (D-98(e)) | TestP2ContractEveryRouteFieldByField | CAUGHT | L |
| mount-wraps-auth | the AuthMiddleware 401 not rewritten to the §5.2 envelope (D-100 [D-98]) | TestP2ContractAuthEnvelopes | CAUGHT | L |
| mount-wraps-require | GraphRequire not wrapped per route (D-100 [D-98]) | TestP2ContractAuthEnvelopes | MISSED→FIXED. AuthMiddleware runs the rest of the chain itself, so the outer wrapper had already rewritten the 403. The returning-authenticator case was added; caught in c2_rerun.log | L |
| envelope-passthrough-v2 | graphIsEnvelope inverted | TestP2ContractAuthEnvelopes | CAUGHT | L |
| capabilities-rejects-rev | /capabilities accepts rev and unknown parameters (D-82) | TestP2ContractErrorEnvelopes | CAUGHT | L |
| q-minimum-length | q shorter than 2 characters accepted (§5.2) | TestP2ContractErrorEnvelopes | CAUGHT | L |
| expand-carries-include-ended | frontier expand link drops include_ended (D-12) | TestP2ContractEveryRouteFieldByField | CAUGHT | L |
| access-via-group | a member's access row does not name the group (D-18) | TestP2ContractEveryRouteFieldByField | CAUGHT | L |
| ended-assignment-valid-to | an ended assignment lacks valid_to/ended_reason (§5.1) | TestP2ContractEveryRouteFieldByField | CAUGHT | L |
| section-alone | `?section=` returns more than that section (D-77) | TestP2ContractEveryRouteFieldByField | CAUGHT | L |
| statement-label-actions | statement node not labelled by its actions (§5.3 example) | TestP2ContractEveryRouteFieldByField | CAUGHT | L |

**Review 1** (wf_4d2f68bd). Source: R+b, backups in `SP/contractrev_mut/`: routes.go.orig, traverse_limits.go.orig, workload_detail.go.orig.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| M1 | routes/routes.go l.335: the old `RegisterIGAGraphReadRoutes(iga, igaGraphRead, middlewares.Require)` call restored | none (TestP2Contract* ok 71.1 s); no test imported the routes package | MISSED→FIXED. `2e89004` extracts routes.SetupIGARoutes and tests it, with a source check on SetupRoutes; the fix's M6a and M6b are caught | R+b |
| M2 | internal/igaread/workload_detail.go: LoadWorkload `WHERE (w.workspace_id = ? OR true)` | TestP2ListsRoutesPermissionsAndCrossWorkspace (200, want 404) | CAUGHT, but only by that older test. TestP2ContractErrorEnvelopes passed: its foreign workspace has nothing published, so D-4's 404 answers first. The contract fix report does not address it. The same filter is caught by TestP2EgatesE14CrossWorkspaceAccess (egates E14-detail-workspace) | R+b |
| M3 | traverse_limits.go: a crossing edge keeps its own /evidence limitations | not named | CAUGHT | R+b |

**Review 2** (wf_2c6c2a42): not executed and not counted. The reviewer's run hit go test's 10-minute default timeout and left iga_w_contract dirty, and the permission check refused the cleanup. The reviewer reasoned about six mutants; `SP/crv_mutate.py` holds them. Predicted caught: M1 (graphDenyWriter holds only 401), M2 (far coverage dropped), M4 (PublicationTime not truncated), M5 (HolderRestrictions ignores group Deny). Predicted missed: M3 (node not_principal_unresolved dropped) and M6 (routes.go reverted). The fix pass ran all six in some form, below.

**Fix.** Source: L, `SP/cfix/mut/*.log` with `.bak` backups; mutate.py compares sha256.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| M6a | graph routes mounted on the shared iga group via RegisterIGAGraphReadRoutes | TestP2ContractAuthEnvelopes (the structural check and the 401/403 envelopes) | CAUGHT | L |
| M6b | SetupRoutes inlines the old wiring instead of calling SetupIGARoutes | TestP2ContractAuthEnvelopes (structural check) | CAUGHT | L |
| M3a | the role node's not_principal_unresolved branch deleted (D-44) | TestP2ContractGraphNotPrincipalUnresolved | CAUGHT | L |
| M3b | the flag not read in fetchIdentities | TestP2ContractGraphNotPrincipalUnresolved | CAUGHT | L |
| M3c | the condition inverted | TestP2ContractGraphLimitationsAreEvidences | CAUGHT | L |
| F4a | trust flags on roles only (the old shape) | TestIdetailIdentityProviderAttrs; TestP2ContractEveryRouteFieldByField; TestP2IdetailIdentityOverview | CAUGHT | L |
| F4b | false instead of null | TestIdetailIdentityProviderAttrs; TestP2ContractEveryRouteFieldByField | CAUGHT | L |
| F4c | flags read from the jsonb for any kind | TestIdetailIdentityProviderAttrs | CAUGHT | L |
| R1 | reviewer-2 M1: a 403 escapes the envelope | TestP2ContractAuthEnvelopes | CAUGHT | L |
| R2 | reviewer-2 M2: far coverage dropped | TestP2ContractGraphLimitationsAreEvidences | CAUGHT | L |
| R4 | reviewer-2 M4: publication time to the microsecond | TestP2ContractEveryRouteFieldByField | CAUGHT | L |
| R5 | reviewer-2 M5: group Deny dropped | TestP2GraphMembershipCarriesRestrictions | CAUGHT | L |

#### egates (§7.1 E1–E16 backend halves): impl `3dfa4b0`, fix `d0f716c`

79 checks: 74 caught, 5 missed→fixed. The implementation changed no production file (`git diff --stat c445404 3dfa4b0` over internal, services, repository, controllers, models, routes and migrations is empty), so every implementation mutant is of production code the earlier items wrote.

**Implement.** Source: L. `SP/egates_mut4_log.jsonl` holds 51 records: 47 mutants, plus four re-runs of the three E7 mutants after the E7 flake fix. `SP/egates_mut5_log.jsonl` holds 2. `egates_mut4_pre.sha` covers 478 production files. Files: `pl` = internal/igaread/pipeline.go, `li` = lists.go, `rc` = internal/igagraph/reconcile.go, `tv` = internal/igaread/traverse.go, `sk` = internal/igagraph/sourcekey.go.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| E13-scan-fence-write | repository/scan_fence.go: a superseded worker's single write (runFenced) accepted | TestP2EgatesE13InterruptionLeaseLossReplay | CAUGHT | L |
| E13-projector-live-lease | repository/iga_projection_job_repository.go: a live-leased job claimed by a second projector | TestP2EgatesE13InterruptionLeaseLossReplay | CAUGHT | L |
| E10-own-source-support | `rc`: a pass ends other connectors' support rows | TestP2EgatesE10SharedObjectSurvivesOneSource | CAUGHT | L |
| E1-collecting | `pl`: a running run not reported collecting | TestP2EgatesE1ConnectAndPublishFirstGraph | CAUGHT | L |
| E1-barrier | `pl`: barrier state not the lease's | TestP2EgatesE1ConnectAndPublishFirstGraph | CAUGHT | L |
| E1-not-published | internal/igaread/envelope.go: a list before the first publication not not_published | TestP2EgatesE1ConnectAndPublishFirstGraph | CAUGHT | L |
| E1-capabilities | controllers/platform/iga_graph_read_controller.go: features false while the switch is on (D-11) | TestP2EgatesE1ConnectAndPublishFirstGraph | CAUGHT | L |
| E2-facet-other-filters | `li`: a facet applies its own filter | TestP2EgatesE2RightWorkloadAmongDuplicates | CAUGHT | L |
| E2-q-case-insensitive | `li`: q case-sensitive | TestP2EgatesE2RightWorkloadAmongDuplicates | CAUGHT | L |
| E2-tab-scoped-to-id | internal/igaread/workload_identities.go: a tab reads another workload | TestP2EgatesE2RightWorkloadAmongDuplicates | CAUGHT | L |
| E3-merged-statements | `sk`: two statements granting one action merged | TestP2EgatesE3WorkloadIdentityStatementsResource | CAUGHT | L |
| E4-selector-limitation | internal/igaread/limitations.go: a selector gets resource_existence_not_verified (D-21) | TestP2EgatesE4EvidenceAndLimitations | CAUGHT | L |
| E4-member-boundary | limitations.go: a group grant lacks the member's boundary (D-22) | TestP2EgatesE4EvidenceAndLimitations | CAUGHT | L |
| E4-exclusion-not-edge | internal/igaread/traverse_edges.go: a NotResource entry becomes an edge | TestP2EgatesE4EvidenceAndLimitations | CAUGHT | L |
| E4-exclusion-not-access | internal/igaread/resource_access.go: Access lists non-positive targets | TestP2EgatesE4EvidenceAndLimitations | CAUGHT | L |
| E5-relationship-key-source | `sk`: relationship key without its source workload | TestP2EgatesE5TwoWorkloadsShareOneRole | CAUGHT | L |
| E6-ended-lines-hidden | internal/igaread/workload_detail.go: ended grant lines listed by default (D-12) | TestP2EgatesE6DetachOneOfTwoEquivalentGrants | CAUGHT | L |
| E6-remaining | internal/igaread/changes.go: policy_detached without the remaining grants (D-28) | TestP2EgatesE6DetachOneOfTwoEquivalentGrants | CAUGHT | L |
| E7-remaining-non-ended | changes.go: remaining grants include ended ones (D-28) | TestP2EgatesE7PolicyEditsAndReattach | CAUGHT (re-run after the flake fix) | L |
| E7-sid-keyed-statement | `sk`: a Sid-keyed edit replaces the statement | TestP2EgatesE7PolicyEditsAndReattach | CAUGHT (re-run) | L |
| E7-reattach-new-row | repository/iga_graph_repository.go: a reattach reopens the ended assignment | TestP2EgatesE7PolicyEditsAndReattach | CAUGHT (re-run twice) | L |
| E8-recreation | internal/igagraph/project.go: a role recreated under the same ARN reuses its object | TestP2EgatesE8ReplaceRoleAndPolicy | CAUGHT | L |
| E9a-canEnd | `rc`: a partition whose surface was not reached is ended | TestP2EgatesE9aIAMDeniedRetainsEverything | CAUGHT | L |
| E9a-last-confirmed | `rc`: a stale row's last_confirmed_at moved | TestP2EgatesE9aIAMDeniedRetainsEverything | CAUGHT | L |
| E9a-list-coverage | `li`: meta.coverage drops the gaps that bear on the list (D-73) | TestP2EgatesE9aIAMDeniedRetainsEverything | CAUGHT | L |
| E9a-failed-call | internal/igaread/coverage.go: /coverage drops the refused call's api | TestP2EgatesE9aIAMDeniedRetainsEverything | CAUGHT | L (mut5) |
| E9a-no-invented-fix | coverage.go: a denied surface offered a remedy | TestP2EgatesE9aIAMDeniedRetainsEverything | CAUGHT | L (mut5) |
| E9b-protected | `rc`: an unreadable document's grants end | TestP2EgatesE9bUnreadableDocumentAndDetachInOneRun | CAUGHT | L |
| E9b-no-account-veto | `rc`: one unreadable document vetoes the account | TestP2EgatesE9bUnreadableDocumentAndDetachInOneRun | CAUGHT | L |
| E10-retire-when-unsupported | `rc`: a node retires while a support row is left | TestP2EgatesE10SharedObjectSurvivesOneSource | CAUGHT | L |
| E11-closes-cycle | `tv`: closes_cycle not set | TestP2EgatesE11ExternalAccountsCyclesAndLimits | CAUGHT | L |
| E11-visited-set | `tv`: the visited set removed | TestP2EgatesE11ExternalAccountsCyclesAndLimits | CAUGHT | L |
| E11-none-exists | internal/igaread/graph_path.go: none_exists after a budget bound (D-38) | TestP2EgatesE11ExternalAccountsCyclesAndLimits | CAUGHT | L |
| E11-crosses-account | internal/igaread/traverse_limits.go: crosses_account wrong (D-36) | TestP2EgatesE11ExternalAccountsCyclesAndLimits | CAUGHT | L |
| E11-hard-node-budget | `tv`: the §5.4 hard node budget not applied | TestP2EgatesE11HardBudgetsThroughTheRoutes | CAUGHT | L |
| E11-hard-neighbour-budget | `tv`: /graph/expand does not page 100 per cursor | TestP2EgatesE11HardBudgetsThroughTheRoutes | CAUGHT | L |
| E12-cursor-rev | internal/igaread/snapshot.go: cursor revision not checked | TestP2EgatesE12ChangesDuringPagingAndExploration | CAUGHT | L |
| E12-class-clock | `li`: a classification cursor not checked against the clock | TestP2EgatesE12ChangesDuringPagingAndExploration | CAUGHT | L |
| E12-class-sort-binds | `li`: a classification sort does not bind the clock | TestP2EgatesE12ChangesDuringPagingAndExploration | CAUGHT | L |
| E12-replay | services/iga_classification_service.go: a retried operation writes again | TestP2EgatesE12ChangesDuringPagingAndExploration | CAUGHT | L |
| E13-scan-fence | repository/scan_fence.go: a superseded worker's reconcile deletes accepted (runFencedTx) | TestP2EgatesE13InterruptionLeaseLossReplay | CAUGHT | L |
| E13-live-lease | repository/cloud_scan_run_repository.go: a live-leased run claimed by a second worker | TestP2EgatesE13InterruptionLeaseLossReplay | CAUGHT | L |
| E13-replay | internal/igagraph/project.go: the AlreadyPublished replay check disabled (`pub != nil && false`) | TestP2EgatesE13InterruptionLeaseLossReplay | CAUGHT | L |
| E14-detail-workspace | workload_detail.go: detail lookup not workspace-filtered | TestP2EgatesE14CrossWorkspaceAccess | CAUGHT | L |
| E14-list-workspace | `li`: a list not workspace-filtered | TestP2EgatesE14CrossWorkspaceAccess | CAUGHT | L |
| E14-cursor-workspace | internal/igaread/cursor.go: cursor not bound to its workspace | TestP2EgatesE14CrossWorkspaceAccess | CAUGHT | L |
| E14-facet-workspace | `li`: facet counts drop the workspace filter | TestP2EgatesE14CrossWorkspaceAccess | CAUGHT | L |
| E16-github-reader | repository/iga_repository.go: GET /identity-accounts not limited to github | TestP2EgatesE16ExistingProductsUnchanged | CAUGHT | L |
| E16-github-writer | iga_repository.go: the GitHub writer does not stamp github | TestP2EgatesE16ExistingProductsUnchanged | CAUGHT | L |

**Earlier runs, superseded and not counted.** Earlier agents ran the same mutants three times before the final run, using `SP/egates_mutate.py`, `egates_mutate2.py` and `egates_mutate3.py`.
- `SP/egates_mut_log.jsonl` (08:58–09:26): 39 records; 38 caught, and E11-closes-cycle `build_failed: true`.
- `SP/egates_mut2_log.jsonl` (09:57–10:19): 38 caught. It stops after E13-live-lease; the next mutant was E13-replay, the project.go incident.
- `SP/egates_mut3_log.jsonl` (11:04–11:13): 7 caught, starting with E13-replay.

**Review.** Source: L. The report's five are logged in `SP/egmut/m1.log`–`m5.log` (19:02–19:06), each with its `.orig` backup and the `.old`/`.new` text, run by `SP/egmut/mutate.py` and `mutate2.py`, which restore the backup and compare sha256; the logged times and outcomes match the report (M1: E13 passed in 4.67 s; M3: E9a passed in 3.74 s). `SP/rv_egates_mut_log.jsonl` (12:59–13:05, `SP/rv_egates_*.txt`) is an earlier review run with no report of its own; its three mutants the later run did not repeat are listed as rv-M2 to rv-M4. Every restore is sha256-verified.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| RV-M1 | services/iga_projection_service.go l.81: `f.jobs.AssertOwnedTx(...)` made `return nil` | none (E13 passed, `SP/egmut/m1.log`; the earlier run's M1 also passed E13, and its M1b passed tests/igagraph and -run `TestP2Egates\|TestP2SwitchOn\|TestP2CrashAfterCommit\|TestP2Reclaimed\|TestP2Superseded\|TestP2Busy`) | MISSED→FIXED. E13 now drives the real ProjectionService through the WithBeforeGraphTx seam; the fix's F1_projection_job_fence is caught ("graph rows 0 -> 63") | L |
| RV-M2 | services/cloud_aws_scan_worker.go l.294: `.WithFence(fence)` removed from NewAWSIAMScanner | none (E1 and E13 passed, `SP/egmut/m2.log`) | MISSED→FIXED. A real AWSScanWorker is now superseded mid-scan; the fix's F2_iam_scanner_unfenced is caught | L |
| RV-M3 | `rc`: the reconcileEdges stale branch returns nil for relationship partitions other than member_of | none (E9a and E9b passed, `SP/egmut/m3.log`) | MISSED→FIXED. E9a derives its kinds from igagraph.Partitions; the fix's F3_relationships_not_staled is caught | L |
| RV-M4 | `rc`: canEnd trusts a denied surface | TestP2EgatesE9aIAMDeniedRetainsEverything (`SP/egmut/m4.log`) | CAUGHT | L |
| RV-M5 | internal/awsdiscovery/authdetails.go l.367: the error format no longer names the call | none (E9b passed on the fixture's own "GetPolicyVersion" message, `SP/egmut/m5.log`) | MISSED→FIXED. The fixture message names no call, and structured api/error_code are asserted (D-104); the fix's F4_* are caught | L |
| rv-M2 | internal/igaread/evidence.go: evidence grant read without the workspace | TestP2EgatesE14CrossWorkspaceAccess | CAUGHT | L |
| rv-M3 | services/cloud_aws_iam_scan.go: iam_roles denied reported as reached | TestP2EgatesE9aIAMDeniedRetainsEverything | CAUGHT | L |
| rv-M4 | internal/awsdiscovery/iam.go: an unreadable document names the wrong call | none (E9b) | MISSED→FIXED, by a related mutant. This exact mutant was not re-run; the fix's F4_fetch_call_not_recorded also mutates iam.go's call recording and is caught | L |

**Fix.** Source: L, `SP/egfix/mutations.jsonl` (22 records, each `restored_sha256_ok`) and `SP/egfix/mut_*.log`.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| F1_projection_job_fence | iga_projection_service.go: fencer no-op (reviewer M1) | TestP2EgatesE13InterruptionLeaseLossReplay | CAUGHT | L |
| F1_before_graph_tx_seam_unused | iga_projection_service.go: the WithBeforeGraphTx seam never called | TestP2EgatesE13InterruptionLeaseLossReplay | CAUGHT | L |
| F2_iam_scanner_unfenced | cloud_aws_scan_worker.go: the IAM scanner built without WithFence (reviewer M2) | TestP2EgatesE13InterruptionLeaseLossReplay | CAUGHT | L |
| F2_permission_scanner_unfenced | cloud_aws_scan_worker.go: the permission scanner unfenced | TestP2EgatesE13SupersededScannersWriteNothing | CAUGHT | L |
| F2_workload_scanner_unfenced | cloud_aws_scan_worker.go: the workload scanner unfenced | TestP2EgatesE13SupersededScannersWriteNothing | CAUGHT | L |
| F2_commitscan_unfenced | cloud_aws_iam_scan.go: commitScan unfenced | TestP2EgatesE13SupersededScannersWriteNothing | CAUGHT | L |
| F3_executes_as_not_under_iam | internal/igagraph/snapshot.go: executes_as partition without iam_roles | TestP2EgatesE9aIAMDeniedRetainsEverything | CAUGHT | L |
| F3_relationships_not_staled | `rc`: stale skipped for executes_as, task_execution_role and can_assume (reviewer M3) | TestP2EgatesE9aIAMDeniedRetainsEverything | CAUGHT | L |
| F3_resource_support_not_staled | `rc`: resource support not staled | TestP2EgatesE9aIAMDeniedRetainsEverything | CAUGHT | L |
| F4_fetch_call_not_recorded | internal/awsdiscovery/iam.go: fetchFailed does not record the call | TestP2EgatesE9bUnreadableDocumentAndDetachInOneRun | CAUGHT | L |
| F4_first_call_not_noted | services/cloud_aws_permission_scan.go: noteUnreadablePolicy does not note the call | TestP2EgatesE9bUnreadableDocumentAndDetachInOneRun | CAUGHT | L |
| F4_surface_names_no_call | cloud_aws_permission_scan.go: the surface does not set api | TestP2EgatesE9bUnreadableDocumentAndDetachInOneRun | CAUGHT | L |
| F5_resolution_in_truncated | `tv`: resolution_not_followed put back in truncated | TestP2EgatesE11ExternalAccountsCyclesAndLimits; TestP2GraphExternalPrincipalIsTerminal | CAUGHT | L |
| F5_field_only_when_unbound | `tv`: data.resolution_not_followed set only when unbound | TestP2EgatesE11ExternalAccountsCyclesAndLimits | CAUGHT | L |
| F5_time_bound_says_false | `tv`: false, not null, when time bound first | TestP2EgatesE11ExternalAccountsCyclesAndLimits | CAUGHT | L |
| F6_hop_bound_reads_none | graph_path.go: a hop-bound search reported none_exists (chain-6 through the route) | TestP2EgatesE11ExternalAccountsCyclesAndLimits | CAUGHT | L |
| F7_bridge_proposes_nothing | services/iga_bridge_service.go: the bridge proposes nothing (positive control) | TestP2EgatesE16ExistingProductsUnchanged | CAUGHT | L |
| F7_bridge_matches_aws_workloads | iga_bridge_service.go: the bridge also matches iga_workload names | TestP2EgatesE16ExistingProductsUnchanged | CAUGHT | L |
| C1_lookup_before_lock | iga_classification_service.go: lookup before the lock (class flake re-check) | TestP2ClassConcurrentRetriesReplay; TestP2ClassRetryStormReplays | CAUGHT | L |
| C2_no_for_update | iga_classification_service.go: FOR UPDATE removed | TestP2ClassConcurrentRetriesReplay | CAUGHT | L |
| C3_23505_unmapped | iga_classification_service.go: 23505 not mapped to 422 | TestP2ClassSameOperationTwoWorkloadsConcurrently | CAUGHT | L |
| C4_repeatable_read | iga_classification_service.go: REPEATABLE READ | TestP2ClassConcurrentRetriesReplay | CAUGHT | L |

**Stopped fixers, superseded and not counted.**
- Fixer 1 (`SP/egates-fix/`, 19:22–19:51, WIP `fe2e552`): 11 scripts (m1, m2, m2b–m2e, m3, m3b, m4a–m4c). Each run overwrote `mut_out.txt`, so only the last run's output survives, and that output is a failure of TestP2EgatesE13SupersededScannersWriteNothing. The outcomes are otherwise unrecorded.
- Fixer 2 (`SP/mutation_results.txt` and `SP/mut_*.txt`, 20:09–20:24, WIP `96fca84`; texts in `SP/m/`, backups in `SP/orig/`): 16 runs, every one a test failure. One more prepared text, `SP/m/cursor-mac-not-checked` (20:36), has no output:
  - d94-truncated, route-hop-budget and d94-field-inverted: E11;
  - bridge-never-proposes and bridge-matches-aws-workloads: E16;
  - projection-job-fence and iam-scanner-fence: E13;
  - permission-, workload-, commitscan- and persistcoverage-fence: TestP2EgatesE13SupersededScannersWriteNothing;
  - stale-relationships- and stale-resource-support-left-current: E9a;
  - item-api-not-stamped, fetch-call-not-recorded and coverage-items-not-rendered: E9b.

#### load (T6.10, §5.6): impl `54b48f5`, fix `ad721a7` (last code `3a80c78`)

49 checks: 41 caught, 6 missed→fixed, 2 missed (open). The fix pass changed no production file: `git diff --stat 54b48f5 ad721a7` over internal, services, repository, controllers, models and routes is empty.

**Implement.** Source: L, `SP/loadd/mut/log.jsonl`: 33 records, every one `restored: True`. The report's JSON lists 32 entries, with H2 and H2b in one; its summary says "all 30 safeguards". C4b re-runs C4 against a new test, so it counts once. Files: `sn` = internal/igaread/snapshot.go, `ra` = resource_access.go, `ch` = changes.go, `me` = tests/load/p2_load_measure_test.go.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| S1 | `sn`: Reader.Read applies no snapshot settings | TestP2LoadReadPlansWithBindValuesOnlyInsideTheRead | CAUGHT | L |
| S2 | `sn`: jit=off dropped | TestP2LoadReadPlansWithBindValuesOnlyInsideTheRead | CAUGHT | L |
| S3 | `sn`: settings made session-wide (`is_local` false) | TestP2LoadReadPlansWithBindValuesOnlyInsideTheRead | CAUGHT | L |
| LM1 | `sn`: plan_cache_mode not forced | TestP2LoadTargets (IGA_LOAD_ONLY=changes) | CAUGHT. A 504 query_timeout on /resources/:id/changes was logged a minute in (13:07:57). The run then ended with go test's "Test killed: ran too long (1h6m0s)" after 19 757 s of wall clock (19 792.6 s in the record); the report says the machine slept and gives the 60 m test timeout | L |
| LM2 | `ra`: the identity-first page never chosen | TestP2LoadTargets (IGA_LOAD_ONLY=access) | CAUGHT | L |
| D1 | `ra`: identity-first direct-grant probe never hits | TestP2LoadAccessStrategiesAgreeOnTheLab | CAUGHT | L |
| D2 | `ra`: identity-first member probe never hits | TestP2LoadAccessStrategiesAgreeOnTheLab | CAUGHT | L |
| D3 | `ra`: member rows ignore the membership/grant overlap | TestP2LoadAccessStrategiesAgreeOnTheLab | CAUGHT | L |
| D4 | `ra`: member probe ignores the overlap | TestP2LoadAccessStrategiesAgreeOnTheLab | CAUGHT | L |
| D5 | `ra`: identity-first cursor `>` changed to `>=` | TestP2LoadAccessStrategiesAgreeOnTheLab | CAUGHT | L |
| D6 | `ra`: member probe counts ended memberships by default | TestP2LoadAccessStrategiesAgreeOnTheLab | CAUGHT | L |
| L1 | internal/igaread/lists.go: provider-id suffix pre-test uses left(), not right() | TestP2LoadWorkloadQMatchesTheWholeProviderID | CAUGHT | L |
| L2 | lists.go: full provider-id equality dropped after the pre-test | TestP2LoadWorkloadQMatchesTheWholeProviderID | CAUGHT | L |
| R1 | internal/igaread/resource_detail.go: batched resource policies not split by subject | TestP2LoadGroupedEvidenceReadsEachTargetsOwnResourcePolicy | CAUGHT | L |
| C1 | `ch`: the workload statement_revised branch counted as unique | TestP2LoadChangesTotalCountsEachEventOnce | CAUGHT | L |
| C2 | `ch`: the holders' statement_replaced branch counted as unique | TestP2LoadChangesTotalCountsEachEventOnce | CAUGHT | L |
| C3 | `ch`: the resource's statement_replaced branch counted as unique | TestP2LoadChangesTotalCountsEachEventOnce | CAUGHT | L |
| C4 | `ch`: repeatable arms not deduplicated before the per-branch cut | TestP2LoadChangesTotalCountsEachEventOnce (exit 0), then TestP2LoadChangesPagesKeepEveryRepeatedEvent | MISSED→FIXED. TestP2LoadChangesPagesKeepEveryRepeatedEvent added; the re-run C4b was caught (an event was skipped) | L |
| C5 | `ch`: per-branch cursor `<` changed to `<=` | TestP2LoadChangesTotalCountsEachEventOnce | CAUGHT | L |
| C6 | `ch`: total without DISTINCT over repeatable branches | TestP2LoadChangesTotalCountsEachEventOnce | CAUGHT | L |
| C7 | `ch`: the holders' edited revisions include a first revision | TestP2Changes\|TestP2LoadChangesTotalCountsEachEventOnce | CAUGHT | L |
| C8 | `ch`: the resource's statement_revised includes a first revision | TestP2Changes\|TestP2LoadChangesTotalCountsEachEventOnce | CAUGHT | L |
| C9 | `ch`: the before/after loader takes the wrong predecessor | TestP2Changes\|TestP2LoadChangesTotalCountsEachEventOnce | CAUGHT | L |
| H1 | `me`: a timed-out total not flagged | TestP2LoadHonest | CAUGHT | L |
| H2 | `me`: a non-200 not a failure | TestP2LoadMeasureFailsWhatIsNotAnAnswer | CAUGHT | L |
| H2b | `me`: the same safeguard after the loadMeasureAll refactor | TestP2LoadMeasureFailsWhatIsNotAnAnswer | CAUGHT | L |
| H3 | `me`: a p95 over target not a miss | TestP2LoadVerdictJudgesEveryRow | CAUGHT | L |
| H4 | `me`: nearest rank off by one | TestP2LoadRank | CAUGHT | L |
| H5 | `me`: facet counts not detected as COUNT work | TestP2LoadIsCount | CAUGHT | L |
| H6 | `me`: a time-bound traversal not flagged | TestP2LoadHonest | CAUGHT | L |
| H7 | `me`: a null facet not flagged | TestP2LoadHonest | CAUGHT | L |
| I1 | `me`: reads measured one after another, not round-robin | TestP2LoadInterleaves | CAUGHT | L |

**Review.** Source: L, `SP/loadrev_M1.out`, `M2.out`, `M2b.out`, `M3.out` and `M3load.out` (20:31–20:41), driven by `SP/loadrev_mutate.sh`, which checks sha256 and a clean git diff. M1, M2 and M2b each passed the 16 `TestP2Changes|TestP2LoadChanges` tests. M3 was run against `TestP2LoadAccess` only (1 test, passed) and against the opt-in load suite (`M3load.out`, failed).

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| RV-M1 | `ch` l.946: the holders' pairs subquery yields the outer e.policy_id | none | MISSED→FIXED. TestP2LoadChangesReplacementStaysInItsPolicy added; the fix's MA is caught | L |
| RV-M2 | `ch` l.1032: `PARTITION BY n.scan_run_id` | none | MISSED→FIXED. The same test (resource subtest); the fix's MB is caught | L |
| RV-M2b | `ch` l.1034: `(w.names OR w.begun_naming)` changed to `(w.names)` | none | MISSED→FIXED. TestP2LoadChangesReplacementReachesTheNewTarget added; the fix's MC is caught | L |
| RV-M3 | `ra` l.491: `(g.state IN ? OR true)` on the identity-first direct rows | integration: none. Opt-in load suite: TestP2LoadAccessStrategiesAgree fails ("page 1 differs") | MISSED→FIXED in the integration suite. A role with an ended and a current grant on `*` was added; the fix's MD is caught | L |

**Earlier review attempt,** with no report and not superseded. Source: L, `SP/loadrev_mut/` (19:18–19:31, before the wf_3cb17bac review). The mutants were built as overlays from `mkmut.py`, and the outcomes are in `summary.txt` and `M*_run.txt`. The line numbers are at `54b48f5`.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| LR-M1 | `ch` l.1034: `(w.names OR w.begun_naming)` changed to `(w.names OR w.begun)` | none (`TestP2Changes\|TestP2LoadChanges`: PASS) | MISSED, **open**. Never re-run after the fix pass. RV-M2b and MC drop the term instead of widening it | L |
| LR-M2 | `ch` l.682: per-branch keyset `ORDER BY b.at DESC` only, without the tie-breakers | TestP2LoadChangesTotalCountsEachEventOnce; TestP2LoadChangesPagesKeepEveryRepeatedEvent | CAUGHT | L |
| LR-M3 | `ra` l.474: `(g.state IN ? OR true)` in the identity-first page's **member probe** (the holders CTE's membership lateral, not the access rows) | none (`TestP2LoadAccess\|TestP2RDetail`: PASS) | MISSED, **open**. Never re-run after the fix pass. The fix's MD mutates the direct-grant rows, not this line | L |

**Fix.** Source: L, `SP/mut-MA.log`–`SP/mut-MJ.log` with `.orig` backups.

| ID | Mutation | Caught by | Result | Src |
|---|---|---|---|---|
| MA | `ch`: the holders' correlation reduced to the run (reviewer M1) | TestP2LoadChangesReplacementStaysInItsPolicy (identity, workload subtests) | CAUGHT | L |
| MB | `ch`: the resource PARTITION BY reduced to the run (reviewer M2) | TestP2LoadChangesReplacementStaysInItsPolicy (resource subtest) | CAUGHT | L |
| MC | `ch`: `OR w.begun_naming` dropped (reviewer M2b) | TestP2LoadChangesReplacementReachesTheNewTarget ("move-to/* = 0 events, want 1") | CAUGHT | L |
| MD | `ra`: `(g.state IN ? OR true)` (reviewer M3) | TestP2LoadAccessStrategiesAgreeOnTheLab | CAUGHT | L |
| ME | tests/load/p2_load_env_test.go: the loadDSNRefusal call dropped | TestP2LoadRefusalStopsTheFixture | CAUGHT | L |
| MF | p2_load_env_test.go: the DSN comparison disabled | TestP2LoadRefusesASharedDatabase (the report says 7 of 13 cases) | CAUGHT | L |
| MG | `me`: graph-shape maxima taken from one body | TestP2LoadGraphShape | CAUGHT | L |
| MH | `me`: path shape counted wrong | TestP2LoadGraphShape | CAUGHT | L |
| MI | `me`: graph and path shape both wrong | TestP2LoadGraphShape | CAUGHT | L |
| MJ | tests/load/p2_load_workloads_test.go: the old hub-role selection restored | TestP2LoadFixtureIntegrity ("0 nodes ... want a full page of 100") | CAUGHT | L |

One of MG, MH and MI was caught only "after strengthening the test", according to the report. The logs keep only the final runs, so the first miss is counted as missed→fixed (R) and cannot be attributed to a particular one.

Control, not counted: `SP/mut-MD-old.log`. The same mutant as MD, run against the test at `54b48f5`, passes. That confirms nothing protected the filter before the fix.

**Stopped fixer, superseded and not counted.** Source: L, `SP/mut/G1`–`G3`, `A1`, `A1b`, `M2a`, `M2b` and `M3`, with `.json` specs, from before WIP `8fc488f`. All 8 are test failures:
- G1 refusal disabled, and G2 and G3 comparison and env-list variants: the p2_load_env guard tests;
- A1 and A1b, `ra` l.491: TestP2LoadAccessStrategiesAgreeOnTheLab;
- M2a and M2b, the holders' correlation and the resource window: TestP2LoadChangesReplacementStaysInItsPolicy;
- M3, begun_naming dropped: TestP2LoadChangesReplacementReachesTheNewTarget.

### 6.6 Mutation-safety incidents

An agent that stops mid-mutation leaves a production file mutated. Three such incidents were reported; the table says what each record shows. After the first, the common prompt required every original to be copied to disk before editing and restored by sha256 (`_shared/common_egates.md` l.13: "an agent in an earlier wave died mid-mutation and left a safeguard inverted").

| Where | What was left applied | Evidence that it happened | Evidence it was restored before merge |
|---|---|---|---|
| m1/class, `services/iga_classification_service.go` | READ COMMITTED flipped to REPEATABLE READ | `SP/class2_mutate.py` l.70–71 applies `LevelReadCommitted` → `LevelRepeatableRead` as mutant #1. `SP/class2_mutations.log` records only #0. WIP `cfbf1f1`: "the agent died mid-mutation with the transaction isolation flipped to REPEATABLE READ" | `cfbf1f1` restored the file from its pre-mutation backup. `SP/class2_bak_iga_classification_service.go` has sha256 `845377ff…`, the value in `SP/class2_pre.sha`, and the final class agent matched it byte for byte (`wave_reports.md` l.678). `git show cfbf1f1:services/iga_classification_service.go` has `sql.LevelReadCommitted` (l.340); graph HEAD has it at l.354 |
| m1/egates, `internal/igagraph/project.go` | `} else if pub != nil && false { // MUTANT`: the AlreadyPublished replay check disabled | `SP/egates_mutate2.py` l.171–172. `SP/egates_mut2_log.jsonl` stops at E13-live-lease. `SP/egates_mut2_backup/E13-replay__internal__igagraph__project.go` (10:19) is the next mutant's backup | The WIP snapshots `872122e` (m1/egates), `bc921d2` (m1/bdb), `39a728f` (m1/bfk) and `5bae74a` (m1/load), all 10:23–10:24, each record that project.go "was left MUTATED ... restored from the branch before this snapshot". `git log c445404..d0f716c -- internal/igagraph/project.go` is empty. graph HEAD project.go:193 reads `} else if pub != nil {` |
| m1/bdb, a mutation loop over `internal/igagraph/reconcile.go` | reported by the orchestrator. **No written account was found** in `wave_reports.md`, `wave_c_reports.md`, the fix reports or any commit message | What the logs show: `SP/bdbfix/` (10:19) holds specs B11e and B11r, both reconcile.go mutants, with W1–W4 and a `pre.sha` that includes reconcile.go, but no results. Its agent stopped at the fourth spend-limit stop (WIP `bc921d2`, 10:23). Earlier, `SP/reconcile.go.orig` (09:58) and `reconcile.go.orig2` (10:02), both sha256 `4a1a07a0…` (the unmutated file), fit the bdb reviewer's two reconcile.go runs. In the same window the egates run behind `SP/egates_mut2_log.jsonl` mutated reconcile.go five times (E9a-canEnd to E10-retire-when-unsupported, backups in `SP/egates_mut2_backup/`, 10:06–10:08), in the egates worktree. Which of these the orchestrator meant is not recorded | `SP/bdbfix3/run_all.sh` begins every loop with `mut.py --restore`, which restores any backup a crashed run left. Every bdbfix3 record for B11e and B11r shows reconcile.go restored to `4a1a07a0…`, and `SP/bdbfix3/backups/` no longer exists. `git log c445404..98d75d9 -- internal/igagraph/reconcile.go` is empty: no m1/bdb commit ever changed the file. On graph it is unchanged from `c445404` to `e63dfa7`. Three copies of the file at those commits, `SP/mutev_rc_c445404.go`, `_2b67d69.go` and `_bc921d2.go`, are byte-identical. They were written 2026-09-25 01:02, not for this report |
| m1/idetail, `internal/igaread/idetail_permissions.go` | a mutant from an in-place run stopped partway. This one is not in the orchestrator's list; the implementation report states it | `wave_reports.md` l.1130 and l.1215 | Restored from `SP/idetail_mutation_backup/` and checked against the recorded sha256. The final 42 checks ran as `-overlay` builds that never touch the worktree |

Leftover scans that found nothing:
- s3a (`wave_reports.md` l.10), trust (l.264, "0 suspicious"), s3b (l.400), lists (l.546) and class (l.678, l.858);
- the idetail fixer (l.1681) and the rdetail fixer (l.1694);
- the egates WIPs `96fca84` and `caf50e7`, and the load WIP `8fc488f` ("verified no mutation left applied"); the egates WIP `fe2e552` says every mutated file was verified restored.

A marker grep over graph HEAD's production packages finds no leftover mutant: `git grep -n -E 'MUTANT|pub != nil && false|&& false|\|\| true|OR true\)|OR TRUE' e63dfa7`, over internal/igagraph, internal/igaread, internal/awsdiscovery, services/iga_*, services/cloud_aws_*, cloud_observation_writer.go, repository, controllers/platform/iga_* and routes. It finds nothing, test files included (re-run for this check; the pathspecs match 143 files).

### 6.7 Checks that passed, or failed, for the wrong reason

**A compile error recorded as a catch.** A runner that treats a failed build as a failed test reports every non-compiling mutant as caught.
- Found and redone:
  - trust impl P13, G3, G15 and G23 (logged `caught: True`);
  - s2 fix M1a and M1c (logged CAUGHT on `[build failed]`);
  - s3b fix M1 (`build_broken: True, caught: True`);
  - contract impl edges-claim-limitations, node-evidence-limitations and envelope-passthrough (caught with empty evidence);
  - wdetail fix F5-no-trust-scope (the report's "one false catch").
- **Not redone:** rdetail impl M08 and M38. Both are listed caught in the report and are UNVERIFIED above.
- Recorded honestly as build failures and rewritten: s2 impl M14; lists impl M10, M21, M22 and M47; s3b impl M17 and M36; class #49; idetail fix M15; wdetail impl detail-decision; the first egates run's E11-closes-cycle.

**Masked by D-4.** The other workspace had nothing published, so the object route answered 404 before the lookup ran, and the scoping mutant looked caught or harmless:
- class #45 (fixed by publishing the other workspace);
- changes RV-7 (fixed: W1);
- contract review 1 M2. Not fixed in the contract test; the older TestP2ListsRoutesPermissionsAndCrossWorkspace and TestP2EgatesE14CrossWorkspaceAccess catch that filter.

**The fixture decided the outcome.** In each case the test's own setup made the assertion pass whatever the mutant did.
- s3a M20: the fake's error already contained the call name and code.
- egates RV-M5: the E9(b) fixture message contained "GetPolicyVersion".
- wdetail res-deny-count: one Allow and one Deny, so the counts matched.
- graph g6: no same-account edge in the fixture.
- lists M45: no two principals of one name in one account.
- idetail fix M16: no reconnected account.
- load C4: no test paged, at a small limit, through an event its branch reaches more than once (per the comment on TestP2LoadChangesPagesKeepEveryRepeatedEvent; the report says only that the earlier test did not catch it).
- load RV-M3: no holder had both an ended and a current grant on one reference.
- class #52: the retries ran serially.
- graph RV-2: an assertion that no budget could bind.

**Assertions pinned to a defect.**
- bfk: the `foreign_workspace_admitted` subtests (at `a986178`; `known_gap_foreign_workspace_admitted` on graph) passed while the §2.9 gap existed. `21436d4` turned them into SKIPs that name the key and its DDL.
- bdb: the deletion test passed only while iga_le_publication_fkey refused the delete. `1046c1a` asserts the correct behaviour and skips while the key is unfixed.

**Not the real code path.**
- egates E13 (RV-M1, RV-M2) went through a test copy of the fencer and a bare repository fence. The fix pass drives the real ProjectionService and AWSScanWorker.

**The failure came from the environment, not the mutant.**
- The rdetail review's RA and RB, and the bdb review's canEnd run, failed at setup on a dirty database. The contract review 2 run never executed.
- class #16a was caught by a deadlock and a 10-minute timeout, and the dirty database invalidated the following runs; they were re-run on a reset database.
- bdb fix W1's final re-run recorded "ERROR (build or setup problem)"; its catch at `1046c1a` stands.

**Flaky tests found alongside.**
- TestP2ClassConcurrentRetriesReplay gave up after 2 s of wall clock. The egates fix pass fixed it and re-checked C1–C4.
- E7 compared a microsecond timestamp with trailing zeros dropped; fixed in the egates implementation.
- TestP2ReadDoesNotStraddleAPublication failed once under machine load during the contract implementation and was left unchanged (B16, §5.1 above).
- The load harness measured an empty page for its "hub role" before `3a80c78`; MJ now guards that selection.

### 6.8 Not confirmed from a log

The following are counted above but rest on a report or commit message alone (Src R or R+b):
- **Whole stages:**
  - graph impl: 29 checks, specs only (`SP/mut/specs.json`);
  - wdetail impl: 34 checks, specs and backups only;
  - bdb impl: the 30 reported checks, specs only; 28 of them (and the unreported b11a) were re-run and logged at `1046c1a`, w1 and w2 never;
  - evidence fix: 15 checks, backups only;
  - the reviewers' mutants for trust, s3a, s3b, s2, lists, class, changes, graph, idetail, bfk and bdb (backups for each; the s3b, s2 and bdb backups are matched to their mutants by file and time only);
  - class fix M1/M4, s3a fix MUT-E/MUT-F, wdetail review E, and the three checks of D-57 (`3ea0244`).
- **First-run misses whose re-run is logged but whose miss is not:** idetail fix M16, and one of the load fix's MG, MH or MI. The logs show only the catch.
- **First-run misses with nothing logged, miss or catch:** graph g6 and wdetail res-deny-count (their stages have no outcome log). changes fix E5b may belong here too: the report says it would not have been caught without the second seeded row, and the log shows only the catch.

Discrepancies between a report and its log:
- rdetail M08 and M38 are reported caught; the log shows compile errors.
- wdetail fix F5-trust-kind-filter passed its first run; the report does not say so.
- The idetail aborted run: the report says 5 CAUGHT, the log has 4.
- The s3b fix report names M1–M21 plus three variants, 24 names; it says 23 mutants, and the log has 23 with no M12.
- The bfk impl summary says 15 mutations; its list and the logs have 16.
- The egates review's five mutants are logged in `SP/egmut/`; `SP/rv_egates_mut_log.jsonl` is an earlier review run with a partly different set and no report.
- load: the report's JSON lists 32 entries and its summary says 30 safeguards; the log has 33.

**Not found in any report:** the bdb reconcile.go loop incident. It is as the orchestrator described it. The logs and git show the bdb reviewer's two reconcile.go backups (09:58, 10:02), a stopped bdb fixer's unrun reconcile.go specs (10:19), an egates loop over reconcile.go in its own worktree (10:06–10:08), and a file that no m1/bdb commit changed.

## 7. Deviations from the spec, and why

Each is a provisional decision (§10 below) or, where it says "no D-n", a reading the build took without one. Who raised it, and the other way, are in the §9 entry named.

### 7.1 Where M1 does something other than the spec's text

| # | The spec | M1, and why where the record says | D-n | §9 |
|---|---|---|---|---|
| 1 | E9(b) (l.6458) denies `iam:GetPolicyVersion` on customer-managed `TicketRead`; M0's scenario 4 did the same | An attached AWS-managed policy is made unreadable; `TicketRead` is also denied and its grant stays current. After T3.1 a customer-managed document arrives in the `LocalManagedPolicy` listing (§1.4 l.212), so the denial never makes it unreadable | D-51 | 68 |
| 2 | A retired policy's, or an edited Sid-less statement's, grants end `statement_retired` / `policy_retired` (§2.7 l.605, cascade table l.5241, T5.2 gate l.6320) | They end `not_seen`: §4.10's `Reconcile` ends the grant partition before `retireUnsupported` runs (M0 §6.5). `TestP2BdbStatementIdentity` pins it | D-67 | 47 |
| 3 | A target's evidence is the policy version's observation, and T4.9 counts every projected edge (§4.8 l.4439, l.4446–4447) | A target's facts come from its statement's policy-version observation. `032`/`036` define no junction table for targets, so E4's "junction rows for every edge" does not hold for them | D-66 | 11 |
| 4 | §2.9 (l.660–661): no single-column foreign key to a workspace-scoped table | 19 such keys remain in `036` as shipped; B9 and B20 pass with them as named exemptions, each gap subtest skipping | D-95 | 5 |
| 5 | §5.1 l.5619: before the first publication, `200` with empty `data` and `graph_state: "not_published"` | `/graph`, `/graph/expand` and `/graph/path` answer `404 not_found`, inferred from D-4 (written for detail routes) and D-39 | no D-n | 25 |
| 6 | §5.4's `bound_by` values are `nodes`, `edges`, `assume_hops` and `time` (l.6130) | `/graph/path` also returns `paths` (beside `more_paths: true`) and `resolution_not_followed`. `/graph` sets `truncated` only when a budget binds, and reports an unfollowed resolution in `data.resolution_not_followed` | D-101, D-105 | 19, 26 |
| 7 | §2.14.14 l.1899: `meta.coverage` on every list and detail response | `/graph`, `/graph/expand`, `/graph/path` and `/evidence` state each gap as a `surface_*` limitation on the element it bears on; their meta carries no union | D-102(b) | 21 |
| 8 | §5.3's Identities-tab example shows `execution`, `other`, `groups` and `may_assume` as arrays (l.5834–5850) | Each is a paged section `{items, next_cursor, total_known, total}` | D-77 | 22 |
| 9 | §5.2 l.5729: "Errors, on every route" | The three new discovery routes' handler errors use the §5.2 envelope; the discovery group's shared 401 and its `discovery:*` 403 keep their existing bodies | D-103 | 24 |
| 10 | §2.14.9 l.1630: `effective_access` is `unknown` | `not_evaluated`, as in §5.3's example (l.5997) | D-20 | 70 |
| 11 | §3 rule 7 (l.3394, l.3433–3434): every grant query joins its statement on `effect = 'allow'` | Changes applies rule 7 to the statement revision that covers the grant's `valid_from`; `/evidence` keeps rule 7 on current content, so a grant ended by an Allow → Deny edit is `404` there | D-27g | 46 |
| 12 | §2.14.6 l.1433: every sort's tiebreaker is name, then account, then object id | Identities, resources and Used-by sort on `(lower(name), account, id)`; workloads keep §5.3's keyset `(lower(display_name), id)` | D-13 | 42 |
| 13 | §2.5 l.472–473: a key that disappears is `revoked`, under the four conditions | AWS `Inactive` becomes `revoked` on the key's existing row; absence revokes nothing, because there is no credential partition | D-64 | 14 |
| 14 | A workload's execution role is one of `029`'s four states, `none` rendering "No execution role configured" (§2.14.7 l.1520) | A workload with no earlier node whose first detail call fails is kept in `cloud_workload` under its constructed ARN and **not projected**: `029` has no "not read" state | D-53 | 8 |
| 15 | §1.4 l.209 collects "max session" for `iam_roles` | Existing rows keep a frozen value and new roles get none: RoleDetail returns neither `MaxSessionDuration` nor `Description` | D-48 | 58 |
| 16 | §2.2 l.370–373: a trust Deny is "shown as a restriction or limitation" | No edge; the role's `provider_attrs` carries `trust_has_deny`. The vocabulary has no code for it | D-44 | 56 |
| 17 | §2.6 l.560–562: a default-version change is a policy change event | No event type; revision and replacement events carry `policy_version_id` | D-69 | 50 |
| 18 | §1.4 l.200: of an `unsupported` surface, "nothing there is claimed" | `canEnd` requires every required surface `reached`, so an `unsupported` partition goes stale, and `/evidence` emits `surface_stale` for it | D-58, D-93 | 33 |
| 19 | §2.14.7 l.1537: measure the wait from enqueue to claim | `queued_at` = `requested_at`, documented as "last (re)queued at": `cloud_scan_run` has no enqueue column, and T1.3 moves `requested_at` on every refused claim | D-55 | 18 |

### 7.2 Additions the spec does not define

Each is additive to a frozen shape:
- `/pipeline`'s per-account `accounts[].state`, which E1 asserts on (no D-n; entry 37).
- `/graph/path`'s `data.direction`, and a reverse search when the forward one finds nothing (no D-n; entry 39).
- `include_ended=true` on `/graph`, `/graph/expand` and the detail tabs (D-12; entry 40).
- The workload's latest decision as `data.decision`, with `id` and `operation_id` added to §5.3's shape (no D-n; entry 44).
- D-79's summary sentence as `meta.summary.sentence` (no D-n; entry 45).
- A derived `unresolved_reason`, with a vocabulary the spec does not define (no D-n; entry 35).
- Two fields for a retired object's tabs, `meta.workload` and `data.identity`, with different nullability (no D-n; entry 23).
- `SurfaceCoverage`'s optional `error_code`, `api` and `items` (D-71; §9.2 a22).

### 7.3 How the proofs were run, against what §7 asks

- §7.3's proofs are "executed against real PostgreSQL through the implementation" (l.6509). B18's `scope()` half runs on gorm DryRun instead, and B16 is asserted at the `igaread.Reader` with no safeguard removal recorded (§5.3 above, items 1 and 4).
- §7.1's gates run on the *"real backend and the real console, against real AWS lab accounts, by Playwright (T8.2)"* (l.6431–6432). M1 has only the backend halves, on the P2-0 lab with AWS answered by fakes: E9's permission removal is a fake `AccessDenied`, E13's kills are in-process pauses and lease expiries, and E16 compares against a GitHub-only control workspace on the same binary, not `0e75ad7` (§5.2 above, and §5.3 item 8).
- The E2, E11 and E12 fixtures go beyond §7.1's lab table (§8.2 below).
- M0's mutations for B5, B14 and B15 were not re-run on M1's code, and those for B3 and B12 ran on the pre-M1 versions of their tests (§5.3 above, item 7).

### 7.4 M0 scenarios changed by M1

- Scenario 4, `TestP2UnreadableAndDetachedInOneRun` (B12), is re-expressed under D-51 (7.1 row 1; §4.2 above).
- Scenario 10, `TestP2TwoAccountsOneBucket` (B3): B's policy is removed, not merely detached, because a detached customer-managed policy is still listed (§4.2 above).
- Scenario 1, `TestP2UnchangedRescan`, now expects 2 relationships and 1 external principal, because the lab role's Lambda trust is projected (§4.1 above).
- `TestScanResumesPastIdentitiesAlreadyDone` became `TestLeftoverCheckpointSkipsNoIdentity`: authorization details leave no per-identity phase to resume (§4.2 above; entry 79).

### 7.5 Test seams added

`ProjectionService.WithBeforeGraphTx` (`services/iga_projection_service.go:84`; E13) and `ClassificationService.WithBeforeCommit` (`services/iga_classification_service.go:75`; B22). Neither exists at `7bdee07`, and no non-test file calls either at `9248549` (`git grep`).

## 8. Found wrong in the spec

Places where the spec contradicts itself, PostgreSQL or AWS, or cannot be met as written. The decision taken and the other way are in the §9 entry named. M0 §6 still stands: its 6.1 and 6.2 are in §10.3 below, and its 6.5 and 6.6 recur here as 8.3 item 4 and 8.1 item 5.

### 8.1 Schema (§3)

1. **`036`'s `iga_le_publication_fkey` is `ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED` (l.3354–3356).** PostgreSQL never defers `RESTRICT`, so every workspace that has published is undeletable. D-94; entry 1.
2. **§2.9's rule (l.660–661) does not hold for the schema §3 ships.** 19 single-column keys to workspace-scoped tables remain at `036`, six of them in B20's own *Catches* class, and three uuid columns have no key at all. D-95; entries 5 and 6.
3. **`029` has no execution-role state for "not read"** (`iga_workload_exec_role_state_chk`, l.2449–2452). D-53; entry 8.
4. **No evidence junction for targets**, although §4.8's table gives a target the policy version's observation (l.4439) and T4.9 counts every projected edge (l.4446–4447). D-66; entry 11.
5. **Credentials have no partition** in §4.10's `Partitions()`, so §2.5's revocation of a vanished key (l.472–473) cannot be implemented (M0 §6.6). D-64; entry 14.
6. **The §2.14.7 wait metric (l.1537) has no column.** D-55; entry 18.

### 8.2 Gates (§7.1) that cannot run as written

1. **E9(b) (l.6458)** cannot happen after T3.1: customer-managed `TicketRead` arrives in the `LocalManagedPolicy` listing (§1.4 l.212), so denying `GetPolicyVersion` never makes it unreadable. **E10 (l.6459, "Remove B's policy")** and scenario 4's retirement hold only when the policy is deleted or AWS-managed, because a detached customer-managed policy stays listed. D-51 (*Raise*); entry 68.
2. **E4's "evidence junction rows for every edge"** does not hold for target edges (8.1 item 4). D-66 (*Raise*).
3. **E1** (l.6450) expects `/pipeline` to move queued → collecting → projecting → published, but the frozen example (l.5766–5777) has no per-account state. No D-n; entry 37.
4. **E2, E11 and E12's fixtures.** E11's deep chain and 510-workload role, and E2's 120 fillers, are not in §7.1's lab table (l.6436–6442). E12's 210 fillers stand in for the "lab fixture generator" E12's setup names (l.6461), which T8.1 has to supply ("every §7.1 scenario's setup is reproducible", l.6361). T8.1's lab has nothing deeper than 2 assume hops, and no neighbourhood over 150 or 500 nodes (entry 69).

### 8.3 Passages that contradict each other

1. **A trust edge's source** when the principal is, or becomes, a connected identity: §4.7 l.4411, §2.12 l.841–842, and `034` l.3012–3016 with §2.3 l.397–399. D-41; entry 20.
2. **Resolutions in force.** §5.4 l.6111–6112 makes an external principal terminal; §2.12 l.859–860 implies an `active` resolution may be drawn through; §5.4's `bound_by` (l.6130) and outcome table (l.6141–6144) have no value for passing an unfollowed resolution. D-105, D-101; entry 19.
3. **§3 rule 7** (l.3394, l.3433–3434) assumes a statement's effect never changes in place, but a Sid-keyed statement edited from Allow to Deny keeps its id (§2.6). D-27g; entry 46.
4. **Cascade reasons.** §2.7 l.605, the cascade table (l.5241) and the T5.2 gate (l.6320) name reasons that §4.10's order makes unreachable (M0 §6.5). D-67; entry 47.
5. **`effective_access`**: `not_evaluated` in §5.3's example (l.5997), `unknown` in §2.14.9 (l.1630). D-20; entry 70.
6. **§5.3's evidence example (l.6010)** puts `resource_existence_not_verified` on a grant that names only a selector; the vocabulary gives that code to exact references (l.6030). D-21; entry 71.
7. **The Resources wireframe** (§2.14.6 l.1402–1404) labels a KMS key in a connected account "External reference", against §1.4 l.261 ("not a connected account"). D-16; entry 72.
8. **Sorts.** §2.14.6 l.1433 orders by name, then account, then id; §5.3 keysets workloads on `(lower(display_name), id)` over `idx_iga_workload_list` (l.5823–5825). D-13; entry 42.
9. **`include_ended`.** UI5 (l.6485) needs "1 current · 1 ended" on the canvas; §5.4 l.6103–6104 shows ended only when a Changes view asks, and the spec defines no parameter. D-12; entry 40.
10. **A default-version change** is a policy change event in §2.6 (l.560–562); §5.3's event table (l.6043–6051) has no such event. D-69; entry 50.
11. **A trust Deny** is "shown as a restriction or limitation" (§2.2 l.370–373); the vocabulary (l.6019–6036) has no code for it. D-44; entry 56.
12. **"10 000 objects per workspace"** (§5.6 l.6221) against "a generated 10 000-workload fixture" (l.6230). Entry 73.
13. **§1.4 l.209** lists "max session" for `iam_roles`, which `GetAccountAuthorizationDetails`' RoleDetail does not return. D-48; entry 58.

### 8.4 Out of date or mis-cited

1. **l.5792** cites "§5.4's limitations vocabulary"; it is in §5.3 (l.6019–6036). D-58; entry 33.
2. **§4.10 l.4943**: "`SurfaceCoverage` has exactly three fields". It now also has the optional `error_code`, `api` and `items`. D-71; §9.2 a22.
3. **§5.2's detail example (l.5703–5704)** lacks `graph_state`, which every detail meta carries. D-102(a); §9.2 a21.

## 9. Questions for review

This section lists every spec question the M1 build raised. Each one is deduplicated and triaged against `P2-DECISIONS.md` (D-1..D-106) at `graph` @ `9248549`. HEAD has since moved to `e63dfa7`, which changes neither the spec, the decisions file, nor any line cited below.

**218 raisings were read:**

| Source | Raisings |
|---|---:|
| `wave_reports.md`, `### spec_questions` of the twelve Wave A/B implement reports: s3a 5, s2 8, trust 7, s3b 8, lists 7, class 7, rdetail 12, changes 9, idetail 12, graph 12, wdetail 11, evidence 14 | 112 |
| `wave_reports.md`, the Wave A/B fix reports. Counted: the questions they label as such, the findings they rejected and raised, and fix:idetail's five "to record" decisions. By report: trust 2, s3a 2, s2 3, s3b 1, changes 4, idetail 5, rdetail 3, wdetail 3, evidence 5, graph 2 | 30 |
| `wave_c_reports.md`, `spec_questions` of the Wave C implement reports: bfk 7, bdb 6, contract 4, egates 5, load 5 | 27 |
| `wave_c_reports.md`, the half of a finding that fix:contract rejected and raised | 1 |
| `wave_c_reports.md`, finding 5 of review:contract `wf_4d2f68bd`, which no fix pass took up | 1 |
| `load_fix_report.md` | 2 |
| `egates_fix_report.md`. None new: its two raises are D-104 and D-105, counted below | 0 |
| `P2-DECISIONS.md` *Raise* notes, one per decision, on 39 decisions | 39 |
| `audit.md` raises not carried into `P2-DECISIONS.md` as a *Raise*: D-3(a) (applied as a fix instead, D-61), D-17, D-42 item 3, D-56, D-71 (l.4943), the `/lookup` reverse link | 6 |
| **Total** | **218** |

`gap.md` was read as context only. It digests nine pre-build reports whose `spec_issues` it cites but does not list; `gap.md` l.1514 says D-1..D-59 "already answers most of their spec_issues". They are not counted.

The 218 raisings reduce to **149 entries**:

| Triage | Entries |
|---|---:|
| **(b) open for Aditya** | **105**: schema/DDL 18, contract shape 27, semantics 14, indexes and §5.6 8, gate and spec wording 8, lower-consequence readings 30 |
| (a) answered by a decision | 22 |
| (c) withdrawn, or not a spec question | 22 |

**Rule.**
- An entry is **(b)** when a *Raise* marks it, or when no D-n covers it and the build took a provisional reading.
- An entry is **(a)** when a D-n answers it and has no *Raise* on that point. Like every D-n, it is still provisional.
- An entry is **(c)** in any of these cases: HEAD resolves it and nothing is left to decide; it states something without asking; the spec text already answers it; or it is outside Phase 2.

**Key.**
- `s3a.2` is the second bullet of `### spec_questions` under `## impl:s3a` (Waves A/B), or the second element of that report's `spec_questions` array (Wave C). In `changes`, bullet 1 is the index header and bullets 2–5 are its four DDL proposals.
- `fix:<key>(x)` is the question that fix report labels x.
- `review:<key>#n` is the n-th finding of that review. For contract, `contract-1` is `wf_4d2f68bd` and `contract-2` is `wf_2c6c2a42`. Reviews are cited where they bear on an entry but are not counted as raisings, except review:contract-1#5.
- `D-n R` is the *Raise* on D-n. `audit(D-n)` is a raise in the D-n entry of `audit.md`. `load-fix` is `load_fix_report.md`.
- The Wave C reports use their pre-merge decision numbers. This section uses HEAD's: contract's D-95..D-101 are D-97..D-103, egates' "D-egates" is D-105, and load's "D-load" is D-106.

**What was checked.**
- No commit in `7bdee07..9248549` touches `migrations/master`. Every DDL below is therefore a proposal, and none is applied.
- Every spec line, D-number, commit, test name and file:line below was checked at `9248549` with `git show` / `git grep`.
- Every other description of behaviour, and every measurement, is the raiser's report and was not re-verified. No test, build or database was run for this triage.
- Of the three M0 questions (M0 §9), Q1 and Q2 are not repeated here (Q1's two rollback defects are in §10.3 below); Q3 is entry 14. Entry 47 is M0 §6.5.

### 9.1 Open for Aditya, most consequential first

#### Schema and DDL

1. **`iga_le_publication_fkey` makes every workspace that has published undeletable.** §3 `036` l.3354-3356 declares the key `ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED`. PostgreSQL never defers `RESTRICT`. `DELETE FROM workspaces` therefore fails with 23503 as soon as the cascade reaches `iga_publication`, because `iga_lifecycle_event` rows still cite it.
   - *Now:* D-94; `036` is unchanged. The proposal is `ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED`, which keeps the l.6645 probe. `TestP2BdbWorkspaceDeletionAfterProjection` proves it in a rolled-back transaction. Its "under 036 as shipped" subtest **skips** and names D-94 (`tests/integration/p2_bdb_deletion_test.go:89`).
   - *Other way:* with `RESTRICT` kept, a workspace that has published can never be deleted, so a retention rule is needed instead. If entry 7 lets the cascade reach `cloud_scan_run`, the three `RESTRICT` run keys (`iga_publication_run_fkey`, `iga_sr_run_fkey`, `iga_le_run_fkey`) need the same change.
   - *Raised by:* bdb.1, review:bdb#2, D-94 R.

2. **Subject observations written before M1 can still collide when their subjects are deleted.** `uq_cloud_observation_dedupe_no_subject` (§3 `035` l.3143-3147) keys a subject-less row on `(workspace_id, source_api, content_hash)`, and deleting a subject nulls its key. Two deleted subjects with equal facts then collide. For example, one statement that names two resources gives two `cloud_permission` observations with identical facts. From then on the reconcile fails with a unique violation on every run, and the worker only logs it.
   - *Now:* no D-n. Since M1, `ObservationWriter.Record` stamps `observed_subject` into the facts before hashing (`services/cloud_observation_writer.go:267-272`; `TestP2S3aDeletedPolicyEvidenceNeverBlocksReconcile`), so new rows cannot collide. The rows production already holds are not stamped.
   - *Decide:* a data migration that stamps the existing subject observations, or a subject discriminator in the index.
   - *Other way (neither):* a production workspace wedges its Phase 1 reconcile the first time two such subjects are deleted.
   - *Raised by:* fix:s3a(2), review:s3a#1.

3. **External-principal keys omit the mechanism.** `ExternalPrincipalKey(issuer, subject)` (`internal/igagraph/sourcekey.go:200`) is unique per `(workspace_id, source_key)` (§3 `034` l.2968-2969). An IRSA `oidc` node and a pod-identity `k8s_service_account` node for the same issuer and service account would therefore be one node.
   - *Now:* D-42 prefixes the pod-identity subject with `pod:` (`sourcekey.go:277`).
   - *Other way:* the mechanism joins the key, and every external-principal key changes. Keys are frozen once published, so this must be settled before the first deployment (trust.2).
   - *Related, not carried into D-42:* §2.2 l.336 lists "a Kubernetes service account" as an external principal. Should an IRSA `oidc` node also be shown as one? That would be a display change only.
   - *Raised by:* trust.2, D-42 R, audit(D-42).

4. **The pod-identity partition is connector-wide, but collection is per selected region.** The partition requires `eks_pod_identity` + `iam_roles` once per connector (`internal/igagraph/snapshot.go:261-263`). §1.4 l.232 collects `eks_pod_identity` per selected region. `fix:s2` @ `230535ec` stopped a deselect from ending bindings: unread bindings are kept (`ReconcileGenerationKeeping`), and the surface reads `not_selected` (`TestP2S2DeselectedRegionKeepsPodIdentityBindings`).
   - *Residual, no D-n:* while any region holding bindings stays deselected, the partition can end **no** binding, including bindings removed from regions that are still selected. Those read stale rather than ended.
   - *Other way:* a per-region `eks_pod_identity:<region>`. That is a new required surface and a partition re-key, which D-60 allows only with a `partition_key` backfill.
   - *Raised by:* s2.1, review:s2#1, fix:s2(1).

5. **§2.9 fails for 19 single-column keys, so B9 and B20 pass only with named exemptions.** §2.9 l.660-661 says: "no single-column foreign key to a workspace-scoped table". B9 is l.6523. B20 is l.6533, whose Catches column is "single-column references to `cloud_identity`". At `036`, 19 such keys remain, pinned in `bfkLegacySingleColumn` (`tests/igagraph/p2_bfk_fk_test.go:142`):
   - 5 on Phase 2 `cloud_*` tables;
   - `iga_observations_delivery_fkey`;
   - 13 on Phase 1 `cloud_*` tables.

   All 19 are named in §10.3 below. Six of the 19 are B20's own class, the references to `cloud_identity`.
   - *Decide:* (i) whether §2.9 covers Phase 1's `cloud_*` tables; (ii) whether to accept D-95's composite DDL; (iii) a separate ruling for `iga_observations_delivery_fkey`. `iga_webhook_deliveries.workspace_id` is nullable, because a delivery is stored before it is bound.
   - *Now:* D-95. Each exempt key's `known_gap_foreign_workspace_admitted` subtest **skips**, and fails once the gap closes (`p2_bfk_fk_test.go:449`).
   - *Other way:* exempting Phase 1 writes 13 permanent exemptions into §2.9. The six Phase 2 keys still need DDL or a named exemption, and B20's Catches stays undemonstrated until then.
   - *Raised by:* bfk.1, bfk.4, review:bfk#2, D-95 R.

6. **Three uuid columns have no key, and D-95 does not list them.**
   - `iga_pipeline_lease.scan_run_id` (`027`) can name another workspace's run, or no run at all. The proposal is `(workspace_id, scan_run_id) → cloud_scan_run ON DELETE RESTRICT`. It cannot be `SET NULL`, because `iga_pipeline_lease_busy_chk` ties a null run to `idle`.
   - `iga_source_objects.integration_scope_id` and `iga_webhook_deliveries.integration_id` (`004`, GitHub path) have no key either.
   - *Now:* no D-n. All three are in `bfkNoForeignKey`, marked SPEC QUESTION (`p2_bfk_fk_test.go:196-200`).
   - *Other way:* §2.9 names them as exemptions.
   - *Raised by:* bfk.2, bfk.5.

7. **Nothing ties `cloud_connector` to its workspace.** `cloud_connector.workspace_id` (`001`/`010`) and `cloud_identity.workspace_id` (`011`) reference nothing. A workspace delete therefore leaves its connectors, runs, observations and collected `cloud_*` rows behind. This is Phase 1's schema, and it bears on E14 and T4.1.
   - *Now:* unchanged. D-94 records the orphans. D-95 proposes `cloud_connector.workspace_id REFERENCES workspaces (id)`, "if the connector rows of 001/010 permit it".
   - *If yes:* add `ON DELETE CASCADE` after a production-data check. Entry 1's `RESTRICT` run keys then enter the workspace cascade.
   - *Raised by:* bfk.3, bdb.2, D-94 R (its second half).

8. **`029` has no execution-role state for "not read".** `iga_workload_exec_role_state_chk` (§3 l.2449-2452) allows `resolved | not_in_scan | not_in_inventory | none`. `none` renders "No execution role configured (a real finding)" (§2.14.7 l.1520). A workload with no prior node whose first detail call fails therefore has no true state.
   - *Now:* D-53. Such a workload is kept in `cloud_workload` under its constructed ARN, with its surface `partial`, and is **not projected** (`internal/igagraph/project.go:532-541`). The template now grants `bedrock-agentcore:GetGateway` (`internal/awsdiscovery/authsec-aws-discovery-role.yaml:207`), so gateways are affected only on stacks not yet updated.
   - *Other way:* a fifth state in `029` (for example `unknown`), or a D-53 addendum that projects the node with a limitation. Either one puts such workloads in the graph (§1.3 l.146).
   - *Raised by:* s3b.1, review:s3b#9, fix:s3b(F9), D-53 R.

9. **The observation store keeps only a first and a last confirmation.** `cloud_observation` holds the first recorder (`scan_run_id`) and `last_confirmed_run_id`, and nothing about the runs in between. This has three consequences:
   - (i) `resource_policy` (§5.3 l.5944-5946). At one revision, a proven read becomes unprovable while a newer run is collecting: `read: true → false`, or `has_deny → null`, until that run publishes. §2.14.11 l.1766-1770 calls such a disagreement a bug.
   - (ii) A bucket policy deleted after it was read keeps `read: true`, so "read, none exists" and "not read" look the same.
   - (iii) Evidence content A → B → A cannot be told from A confirmed throughout, because the junction has no current-link marker.
   - *Now:* D-19 as changed by `fix:rdetail` @ `69cfb22c`: a read counts when its first **or** last recorder published at or below the current rev (`internal/igaread/resource_detail.go:415-420`). `TestP2RDetailResourcePolicyConfirmations` pins (i) as it stands: `read` goes true → false while a newer run is in flight, and `has_deny` true → null on the restored row (`tests/integration/p2_rdetail_detail_test.go:341-345`, `:366-367`). D-19's text still says "the latest such observation". Evidence facts use D-24 with `asOfRunSQL` (`internal/igaread/evidence_facts.go:180`; `TestP2EvidenceFactsIgnoreAnUnprojectedRun`).
   - *Proposed:* a `cloud_observation_confirmation (workspace_id, observation_id, scan_run_id, confirmed_at)` table with composite keys (full DDL in fix:rdetail(F1)), plus an explicit no-policy observation. The alternative is for the projector to stamp the resource-policy verdict on the reference at publication; D-85 excludes that today.
   - *Other way:* (i)–(iii) stay as documented behaviour.
   - *Raised by:* rdetail.1, review:rdetail#1, fix:rdetail(F1), evidence.7, fix:evidence(024), D-19 R, D-24 R.

10. **Targets have no history.** `iga_entitlement_target` (§3 l.3233-3249) is rewritten to the statement's current content (`ReplaceTargets`) and has no validity columns or timestamps. Four consequences:
    - A statement edited to stop naming a resource drops out of that resource's Changes, including its earlier events.
    - `include_ended` on Workload › Resources places an ended grant under today's targets.
    - A target's `first_seen_at` is borrowed from its statement.
    - A shared AWS-managed policy's targets hold whichever connector's read came last. So `/graph` and Resource › Access can draw an ended, stale or other-account grant to targets that its `/evidence` does not claim. `/evidence` reads the content as of the claim's run (`contentAsOf`, `internal/igaread/evidence_content.go:115`).
    - *Now:* D-27f uses current targets. Only `/evidence` is historical.
    - *Decide:* whether to add validity columns or a history table, and which content the graph and access routes treat as authoritative.
    - *Other way (keep as is):* the four consequences above become documented behaviour.
    - *Raised by:* changes.6, wdetail.7, evidence.10, fix:evidence(D-35), D-27f R.

11. **No evidence junction for targets.** §4.8's table gives a Target the policy version's observation (l.4439), and T4.9 counts every projected edge (l.4446-4447). `032`/`036` define three junction tables, none of them for targets.
    - *Now:* D-66: a target's facts come from its statement's policy-version observation.
    - *Other way:* a fourth junction table, and targets join T4.9's zero count.
    - *Raised by:* D-66 R.

12. **`statement_replaced` cannot carry an exact `policy_version_id` for Sid-less statements.** D-69 puts the version on both sides of the event. But a Sid-less statement has no revision row, and `iga_policy` keeps only its current `version_id`.
    - *Now:* D-27c reads both sides from the policy-version observations. A side with no proof is `null` (`TestP2ChangesReplacementVersionsAndIDs`).
    - *Proposed:* `iga_lifecycle_event ADD COLUMN policy_version_id text NOT NULL DEFAULT ''` and `iga_entitlements ADD COLUMN last_policy_version_id text NOT NULL DEFAULT ''`.
    - *Other way:* the nulls stay.
    - *Raised by:* review:changes#1, fix:changes(b), D-27c R.

13. **Nothing makes a publication's time unique.** D-26 recovers an event's rev and run by joining on `(workspace_id, published_at)`, but §3 declares no unique key on that pair.
    - *Proposed:* `CREATE UNIQUE INDEX uq_iga_publication_published_at ON public.iga_publication (workspace_id, published_at)`.
    - *Now:* D-27a renders `rev` and `run` as null when two publications share a time.
    - *Other way:* nulls remain possible, but an attribution is never wrong.
    - *Raised by:* changes.5, D-26 R.

14. **Credentials have no partition, so a deleted key is never revoked.** §2.5 l.472-473 revokes a vanished key "under the same four conditions" as a relationship end. §4.10's `Partitions()` has no credential partition, so a key deleted in AWS reads as active forever. This is M0 §6.6 and M0 §9 Q3.
    - *Now:* D-64: an AWS `Inactive` key becomes `revoked` on its existing row (`internal/igagraph/project.go:595-599`; `TestP2BdbInactiveKeyKeepsOneRow`). `last_seen_at` is the only signal of absence.
    - *D-64's Raise, the other half:* §2.5 reserves `revoked` for absence under those four conditions, and AWS `Inactive` is a status the provider reports, not an absence. Mapping it to `revoked` is the provisional reading.
    - *Other way:* a credential partition over `iam_access_keys`. That is a new partition kind, and entry 77 has to be settled first. Separately, `Inactive` could stay a `status` with `lifecycle` left `active`.
    - *Raised by:* idetail.2, D-64 R.

15. **Access Advisor usage has no per-run history.** `cloud_usage` is upserted in place. A pinned revision's activity is therefore either mixed with an unpublished run's rows or withheld while a scan runs. §2.14.8's "tracking since …" (l.1614-1616) has no start date to show, because none is collected.
    - *Now:* no D-n. Rows must carry exactly the revision run's generation; otherwise the answer is `not_collected` with reason `newer_scan_not_published` (`internal/igaread/idetail_permissions.go:698`; `TestP2IdetailActivityNewerScanNotMixed`). fix:idetail asked for that reason to be recorded in D-25. It was not.
    - *Decide:* whether to version `cloud_usage` per run, or accept the gap during scans.
    - *Raised by:* idetail.7, evidence.11, review:idetail#6, fix:idetail(D-25).

16. **`cloud_assume_edge`'s unique key omits the issuer.** The key is `uq_cloud_assume_edge_subject (identity_id, subject_kind, subject)` (`migrations/master/012_cloud_assume_edge.sql:93-94`). Two clusters presenting the same `ns/sa` to one role collapse into one row, yet produce two observations. This is a Phase 1 table, and there is no D-n.
    - *Other way:* the issuer joins the key.
    - The raising's other half, the pod evidence key, is resolved: `trustPodEvidenceWriterLanded = true` (`tests/integration/p2_trust_lab_test.go:218`).
    - *Raised by:* s3b.5.

17. **`negated_statement` on `can_assume` has no column.** D-88 marks a NotAction trust edge `negated_statement`, but `031`'s `iga_relationship` has nowhere to store the mark.
    - *Now:* no D-n. The target role's `provider_attrs.trust_negated_statements` lists the statement keys (`internal/igagraph/trust.go:60`). This is outside D-85's rendered allowlist.
    - *Other way:* a column on `iga_relationship`. `031` is still edited in place (§3 l.2141-2146).
    - *Raised by:* trust.1.

18. **The §2.14.7 wait metric has no column.** l.1537 asks for p50/p95 from enqueue to claim. `cloud_scan_run` has no `created_at`, and T1.3 moves `requested_at` on every refused claim.
    - *Now:* D-55: `queued_at` = `requested_at`, documented as "last (re)queued at".
    - *Other way:* a column for the original enqueue time.
    - *Raised by:* s2.6, D-55 R.

#### Contract shape

19. **Does the traversal follow a resolution that is in force?**
    - *Problem:* §5.4 l.6111-6112 makes an external principal a terminal node. §2.12 l.859-860 says only resolutions that are *not* in force are never drawn through, which implies an `active` one may be. §5.4's `bound_by` values (l.6130) and outcome table (l.6141-6144) have no value for "passed an unfollowed resolution".
    - *Consequence, with D-41 (entry 20):* results depend on onboarding order. A trust naming B's role that was projected **before** B connected keeps an external-principal source. Projected **after**, it is identity-sourced. So `/graph/path` data-reader → reader-access is found in one order and not in the other.
    - *Now:* D-105. `/graph` sets `truncated` only when a budget binds, and adds `data.resolution_not_followed` as true/false/null (`internal/igaread/traverse.go:327`). `/graph/path` answers `not_found_within_budget` with `bound_by: "resolution_not_followed"` (D-101; `traverse.go:102`), and never `none_exists`.
    - *Other way:* in-force resolutions become a traversal step. Both additions go away, and the path is found in either onboarding order.
    - *Raised by:* graph.2, review:graph#6, review:egates#5, D-105 R, D-101 R (its resolution half).

20. **Which object is a trust edge's source when the principal is, or later becomes, a connected identity?** Three passages disagree:
    - §4.7 l.4411: an exact role or user ARN in any connected account is "that identity; `basis = declared`".
    - §2.12 l.841-842: a resolution "upgrades the existing node and the edge keeps its identity".
    - `034` l.3012-3016 and §2.3 l.397-399: an exact match to an identity in another connected account is a `derived` resolution.
    - *Now:* D-41. A live external principal stays the source and gains a `derived` resolution. Otherwise, a live identity's exact ARN is the `declared` source. No edge is re-pointed. This is the projector half of entry 19.
    - *Other way:* either (a) always source the edge from the identity once the principal resolves, so its edges end and restart as new rows when the account connects; or (b) always source it from the principal, which changes §4.7 l.4411.
    - *Raised by:* D-41 R.

21. **`meta.coverage` on the graph routes and `/evidence`.** §2.14.14 requires it on "every list and detail response" (l.1899), "computed by the server, never inferred client-side" (l.1907).
    - *Now:* D-102(b). `/graph`, `/graph/expand`, `/graph/path` and `/evidence` state each gap as a `surface_*` limitation on the element it bears on, and their meta carries no union. `contractGraphMeta` pins the field as absent (`tests/integration/p2_contract_schemas_test.go:953-964`).
    - *Other way:* the server adds the deduplicated union for the canvas banner: one field, on four metas.
    - *Raised by:* contract.1, review:contract-1#2, D-102 R.

22. **The frozen Identities-tab example shows arrays, but the build pages every section.** §5.3 `GET /workloads/:id/identities` (l.5834-5850) shows `execution`, `other`, `groups` and `may_assume` as plain arrays.
    - *Now:* D-77. Each section is `{items, next_cursor, total_known, total}` and pages with `?section=<name>&cursor=` (all four are `PagedSection` objects, `internal/igaread/workload_identities.go:128-133`).
    - *Other way:* §5.3 says which sections are paged, and the rest stay arrays. A console typed from the example does not match HEAD.
    - *Raised by:* wdetail.2.

23. **No field says a tab's object has retired, and the build has two different ones.** §2.14.5 l.1237 says "Other tabs say they have no current data rather than rendering empty", but defines no field.
    - *Now:* no D-n. The two shapes are:
      - Workload tabs carry `meta.workload {ref, lifecycle, retired_reason}`, with `retired_reason` null while active (`internal/igaread/workload_identities.go:139-143`, `:149`; `workload_resources.go:109`).
      - Identity tabs carry `data.identity {ref, name, kind, lifecycle, retired_reason, state}`, with `retired_reason` omitted while empty (`idetail_helpers.go:118-125`; `idetail_permissions.go:47`).

      That is two placements and two nullability rules for one concept, against D-98.
    - *Decide:* one field in one place, for every object type's tabs.
    - *Raised by:* idetail.9, wdetail.5.

24. **Do §5.2's errors cover the discovery routes' middleware denials?** §5.2 l.5729 says "Errors, on every route". §5.3 keeps connectors and scans on `/authsec/discovery/aws/*` under `discovery:*` (l.5750-5760), while §5.2's 403 row (l.5735) names only `iga:*`.
    - *Now:* D-103. The three new discovery routes' handler errors use the §5.2 envelope. The discovery group's shared 401 and its `discovery:*` 403 keep `{"error": "<text>"}` and `{"error": "insufficient_scope", …}`, so the console has to branch on body shape per route.
    - *Other way:* the discovery group is wrapped in `GraphEnvelope`, as the graph catalogue is, and Phase 1's discovery bodies change with it.
    - *Raised by:* s2.8, review:contract-2#3, fix:contract(discovery), D-103 R.

25. **Rooted graph routes before the first publication.** §5.1 l.5619 says that with no publication the answer is `200`, with empty `data` and `graph_state: "not_published"`.
    - *Now:* `/graph`, `/graph/expand` and `/graph/path` answer `404 not_found` (`TestP2ContractNotPublished` asserts all three; `TestP2GraphWorkspaceAndGates` asserts `/graph` and `/graph/path`). This is inferred from D-4, which is written for detail routes, and D-39. D-4 does not name the graph routes.
    - *Other way:* `200` with empty data, which needs a `/graph` shape that has no root node.
    - *Raised by:* graph.1, review:graph#10, fix:graph(D-4).

26. **`bound_by: "paths"` is not in §5.4's vocabulary.** l.6130 lists `nodes | edges | assume_hops | time`. The `found` row says only "`more_paths: true` if the path budget bound" (l.6142).
    - *Now:* D-101. `/graph/path` returns `bound_by: "paths"` beside `more_paths: true` (`traverse.go:94`). The contract test allows exactly two additions to `/graph/path`'s `bound_by`: this one and `resolution_not_followed` (`p2_contract_schemas_test.go:1001`).
    - *Other way:* `bound_by: null` when only the path budget binds. Or §5.4 lists the value and says how the console renders an unknown `bound_by`.
    - *Raised by:* contract.3, review:contract-1#7, D-101 R.

27. **"Connected" follows three rules at one revision.**
    - Resource: the projected `provider_attrs.account_connected` (D-3, D-16; `internal/igaread/nodes.go:394`).
    - Workload and identity rows: the connector's current status, read in the request snapshot (`Accounts.Of`, `common.go:66`; used at `nodes.go:207`, `:320`).
    - External principal: a non-revoked connector with an `iga_projection_state` row (`RevisionConnectors`, `idetail_external.go:110`). fix:idetail asked for this rule to be recorded beside D-3; it was not written.

    So after a revocation and before reprojection, one account reads `connected: false` on identity rows and `true` on resource rows at the same rev. §2.14.11 l.1766-1770 calls that a bug. `/evidence` combines projected and live values for a resource (reported by evidence.14).
    - *Now:* D-3, D-61 and D-89, plus the unwritten external-principal rule.
    - *Decide:* one rule. Pinning to the revision everywhere shows a revocation only after the next publication. Reading live everywhere lets a resource's `kind` change within a revision, which D-16 forbids. Also confirm that `account_connected` is `null`, not `false`, when a principal states no account.
    - *Raised by:* lists.4, idetail.4, evidence.14, review:idetail#2, fix:idetail(D-3).

28. **A resource's `account_connected` is rewritten only when a projection pass names it.** After a new account publishes, references to it made only by other connectors' policies stay `false`, and so `kind: external`, until those connectors are projected again.
    - *Now:* D-3.
    - *Other way:* a publication recomputes the flag across the whole workspace.
    - *Raised by:* D-3 R.

29. **The Resources list's coverage leaves out surfaces the resource partition requires.** D-73 gives `/resources` the surfaces `iam_policies`, `policy_documents` and `permission_scan`. The resource partition also requires `iam_roles`, `iam_users` and `iam_groups`, because inline policies arrive with them. With `iam_users` denied, rows go stale with `stale_reason` `iam_users`, but the list shows no banner.
    - *Now:* the list follows D-73 (`listsAffects`, `internal/igaread/lists.go:944-985`). Resource detail and Access add every account's `iam_*` gaps (`ResourceDetailCoverage` / `ResourceAccessCoverage`, `resource_detail.go:239-250`; `TestP2RDetailCoverageEveryGapThatBears`). So the list and the detail disagree.
    - *Other way:* the three surfaces join D-73's resources row.
    - *Raised by:* lists.1, fix:rdetail(F2).

30. **Regions never selected become stale notes and partitions.** The workload scanner writes `compute:<region> = not_selected` for every one of the 17 built-in compute regions that is not selected. It does the same for every region ever selected or holding rows (`services/cloud_aws_workload_scan.go:219-229`, `:378-399`). D-58 and D-73 turn each one into a stale note: 16 on a single-region account's `/workloads` banner. Each region also gets partitions (M0 §6.7). §2.14.13 l.1856-1859 ("Earlier results from it are kept and marked stale") describes a region that had results.
    - *Now:* D-58, D-73.
    - *Other way:* stand-ins only for regions in `regions_ever_selected` (`models/cloud_discovery.go:706`, added by fix:s2) and for regions holding rows.
    - *Raised by:* lists.2.

31. **What "the far account's coverage" on a crossing edge includes.** §5.4 l.6113-6115 puts the far account's coverage on the edge, but does not say which gaps count.
    - *Now:* D-98(a): every surface that is not reached in the endpoint account that is not the claim connector's account. On a trust edge, that includes the far account's `compute:<region>` `not_selected` entries as `surface_stale` (16 in the contract fixture, as contract.2 reports). `TestP2ContractGraphLimitationsAreEvidences` pins them: the crossing edge must carry every surface of the far account whose `/coverage` `prevents` is `surface_*` (`tests/integration/p2_contract_routes_test.go:1238-1247`, `:1294-1300`). The vocabulary (l.6035) reserves `surface_*` for "a required surface for this claim".
    - *Other way:* only the surfaces the claim depends on in that account (IAM for `can_assume`).
    - *Raised by:* graph.6, contract.2, review:contract-1#4.

32. **Which claims carry `deny_statements_present` and `permissions_boundary_present`, and through which memberships?** The vocabulary says "the holder (or its groups)" and "the holder" (l.6026-6027). Three points are open:
    - (i) Should assignment claims carry them too, or grants only?
    - (ii) Do a member's own Deny statements bear on a group-held grant?
    - (iii) Member boundaries count only `current` memberships (`internal/igaread/limitations.go:585-591`). A holder's groups count non-ended memberships for Deny (`limitations.go:548-554`). D-18's Access rows include stale memberships.
    - *Now:* D-22, grants only. The graph now reads the same function (`traverse_limits.go:86`, D-98(a)), so fix:graph's non-ended reading for member boundaries no longer applies.
    - *Other way:* each point changes the codes E4 expects.
    - *Raised by:* evidence.4, evidence.5, D-22 R.

33. **Do `unsupported` and `not_configured` count as reached?** §1.4 l.200 says of `unsupported`: "nothing there is claimed". But:
    - `canEnd` requires every required surface to be `reached` (`internal/igagraph/reconcile.go:91`), so an `unsupported` partition goes stale.
    - `/evidence` emits `surface_stale` for such a surface (`internal/igaread/limitations.go:731-733`), while D-58 gives both states `prevents: null` on `/coverage`.
    - No mapping from state to code is specified, and l.5792 cites "§5.4's limitations vocabulary", which is in §5.3 (l.6019-6036).
    - *Now:* D-58, D-93.
    - *Other way:* counting them as reached lets those partitions end rows, and drops the limitation.
    - *Raised by:* s3b.6, evidence.6, D-58 R.

34. **One external principal gets two labels.** D-87 says the oidc/saml label is "issuer + subject". `/external-principals/:id` renders `issuer · subject` (`internal/igaread/idetail_external.go:44-45`). Graph nodes, `/evidence` and Changes render `issuer subject` (`traverse_nodes.go:233`, `evidence.go:1660`, `changes.go:2245`), except that Changes drops the subject when it is `*` or empty (`changes.go:2242-2244`), so a SAML principal with no `SAML:sub` reads `issuer` there and `issuer *` on the graph. Four functions build the label.
    - *Decide:* the format. The build then needs one function for it (D-98).
    - *Raised by:* idetail.6, graph.10, evidence.13.

35. **`unresolved_reason` is derived, not stored, and has no defined vocabulary.** §2.14.5 l.1214 says the page explains "why it is unresolved", but §5.3 l.5927-5929 defines no field, and `034` stores none.
    - *Now:* no D-n. `UnresolvedReasonOf` (`idetail_external.go:350-366`) gives no reason when a resolution is in force. Otherwise it checks, in order: `wildcard`, `service_principal`, `account_not_connected`, and `account_principal` (an `aws_account` principal in a connected account, added by fix:idetail). The fallback is `not_in_inventory`, which also covers suspended and pending resolutions.
    - A retired principal's `retired_reason` is `no_longer_referenced` (`idetail_external.go:103`). fix:idetail asked for both `account_principal` (as vocabulary) and `no_longer_referenced` (in D-47) to be recorded. Neither was.
    - *Decide:* the vocabulary, whether suspended assertions get their own reason, and whether `034` stores the reason.
    - *Raised by:* idetail.5, review:idetail#5, fix:idetail(vocab), fix:idetail(D-47).

36. **D-85 has no way to say that one field was not collected.** §2.14.7 l.1521 asks for per-field "not collected". At HEAD:
    - `env_var_names` is left out when Lambda returned the environment as an error, and `gateway_targets` when `ListGatewayTargets` failed (`internal/igagraph/project.go:466-486`). Both render as `null`.
    - An identity whose detail read failed (`DetailIncomplete`) is not marked at all (`identityProviderAttrs`, `project.go:440-456`). A missing boundary or missing tags therefore read as "none".
    - *Decide:* either "absent, and so null, means not collected" becomes the rule and is applied to identities too, or completeness fields (for example `gateway_targets_complete`) join the allowlist.
    - *Raised by:* idetail.12, wdetail.6, fix:wdetail(a), review:wdetail#2, review:wdetail#3.

37. **The frozen `/pipeline` example has no per-account state.** E1 (l.6450) expects `/pipeline` to move queued → collecting → projecting → published. The §5.3 example (l.5766-5777) has only `barrier.state`, `latest_run.status` and `projection`.
    - *Now:* no D-n. An additive `accounts[].state` takes the values `never_scanned | queued | collecting | projecting | published | failed | first_publication_pending | revoked` (`internal/igaread/pipeline.go:33-40`, `:76`). E1 asserts on it (egates.3).
    - *Other way:* §5.3 adds the field and its mapping from the frozen fields; or E1 asserts on the frozen fields only and the field goes.
    - *Raised by:* egates.3.

38. **A connector's own publication on `/pipeline`.** The §5.3 example shows `last_published_rev: 41` on both accounts, beside `current_rev: 41` (l.5772, l.5776-5777).
    - *Now:* D-56: `last_published_rev` is the current rev for every connector with a published run. The rev that published a connector's own run is on the run (`projection.rev`, l.5759-5760).
    - *Other way:* a per-connector "last own publication" field on `/pipeline`.
    - *Raised by:* audit(D-56).

39. **`/graph/path` orientation and parameters.** §5.4 l.6137 searches "from both ends", but edges have a direction and the route has no direction parameter. A pair given in reverse (resource → workload) found nothing and read `none_exists`.
    - *Now:* no D-n. fix:graph @ `a4c22054` searches `to → from` when `from → to` finds nothing. It adds `data.direction` (`forward | reverse | null`, `internal/igaread/graph_path.go:93`) to D-35's shape, and answers `none_exists` only when both orientations are exhausted (`TestP2GraphPathEitherOrientation`). Also, per graph.7: `from == to` is 400; `include_ended` and `assume_hops` are 400 on this route; and the hop limit applies to the paths enumerated.
    - *Other way:* a `direction` parameter.
    - *Raised by:* graph.7, review:graph#1.

40. **`include_ended` on the graph and the tabs.** §5.4 l.6103-6104 says the default is `current` and `stale`, with "ended only when a Changes view asks". UI5 (l.6485) needs "1 current · 1 ended" on the canvas. The spec defines no parameter.
    - *Now:* D-12: `include_ended=true` on `/graph`, `/graph/expand` and the detail tabs.
    - *Other way:* UI5 changes, or §5.3 defines the parameter.
    - *Raised by:* D-12 R.

41. **One claim's ended and stale fields differ between views.** D-98 requires one shape per concept, and D-74 says "A stale row, node or edge carries `stale_reason`". But:
    - Resource › Access's grant is `{claim, state, valid_from}`, with no `valid_to` or `ended_reason` (`internal/igaread/resource_access.go:93-97`), and its row has no `stale_reason` (`:66-73`).
    - Graph edges carry `stale_reason` but no `valid_to` or `ended_reason` (`traverse.go:264-279`).
    - Workload › Resources and Permissions show both fields for the same ended grant.
    - *Now:* no D-n. `contractAccessClaim` pins the three fields (`p2_contract_schemas_test.go:798-804`).
    - *Other way:* add `valid_to` and `ended_reason` (when ended) and `stale_reason` (when stale) to the Access grant, the membership and the row. Also decide whether graph edges state `valid_to` and `ended_reason`.
    - *Raised by:* review:contract-1#5. fix:contract did not take this finding up; it fixed `wf_2c6c2a42`'s findings.

42. **Should the name sort include the account?** §2.14.6 l.1433 orders by "name, then account, then object id". §5.3 keysets workloads on `(lower(display_name), id)` over `idx_iga_workload_list` (l.5823-5825).
    - *Now:* D-13. Identities, resources and Used-by sort on `(lower(name), account, id)`. Workloads keep §5.3's keyset.
    - *Other way:* the account joins the workload keyset and index, as a denormalised column.
    - *Raised by:* D-13 R.

43. **`/coverage`'s `api` when several calls failed.** §5.3 l.5790-5792 defines `api` as "the call that failed".
    - *Now:* D-104. `policy_documents` names the first refused call and its AWS code; `TestP2EgatesE9bUnreadableDocumentAndDetachInOneRun` asserts `iam:GetPolicyVersion` / `AccessDenied`. Items stay D-71's `{policy, version, error}`.
    - *Other way:* name every distinct failed call, or give `api` and `error_code` per item.
    - *Raised by:* s2.2, review:egates#4, D-104 R.

44. **The workload's latest decision has no field name.** §5.3 l.5831-5832 gives the decision's shape but not its key.
    - *Now:* no D-n. The key is `data.decision` (`internal/igaread/workload_detail.go:90`), the same key the POST 200 uses. It adds `id` and `operation_id` to the §5.3 shape (`classification.go:215-223`).
    - *Other way:* a different name, and the two additions dropped if the §5.3 shape is meant to be exact.
    - *Raised by:* wdetail.1.

45. **D-79's summary sentence has no field.** The frozen `/evidence` example (l.5992-6013) has nowhere to put a sentence that spans several claims.
    - *Now:* no D-n. It is `meta.summary.sentence` (`EvidenceMeta`, `internal/igaread/evidence.go:175-186`).
    - *Other way:* another placement, for example in `data`, or no summary.
    - *Raised by:* evidence.1.

#### Semantics: collection, lifecycle and Changes

46. **§3 rule 7 assumes a statement's effect never changes in place.** Rule 7 (l.3394, l.3433-3434) says every grant query joins on `effect = 'allow'`. A Sid-keyed statement edited from Allow to Deny keeps its id (§2.6). A join on the current effect therefore erases the old grant's start and end from Changes, with no `grant_ended` and no `remaining`.
    - *Now:* D-27g. History applies rule 7 to the statement revision that covers the grant's `valid_from` (`TestP2ChangesAllowEditedToDeny`). `/evidence` keeps rule 7 on current content, so such an ended grant is `404` there; fix:evidence chose this as the conservative reading.
    - *Other way:* one rule for both routes.
    - *Raised by:* review:changes#2, fix:changes(a), fix:evidence(Deny), D-27g R.

47. **Grants of a retired policy, or of an edited Sid-less statement, end `not_seen`.** §2.7 l.605 and the cascade table (l.5241) say `statement_retired`, and the T5.2 gate (l.6320) says `policy_retired`. But §4.10's `Reconcile` ends the grant partition before `retireUnsupported` runs. This is M0 §6.5.
    - *Now:* D-67. `TestP2BdbStatementIdentity` pins `not_seen` (`tests/integration/p2_bdb_statements_test.go:254-255`), and Changes never classifies an event by `ended_reason`.
    - *Other way:* run the cascade first, or reword §2.7, the cascade table and the T5.2 gate.
    - *Raised by:* changes.8, review:bdb#3, D-67 R.

48. **The Changes scope of each object type.** §5.3 l.6040-6055 names the events, but not which objects' events each view shows.
    - *Now:* D-68, one hop:
      - A workload sees its execution identities' events while its `executes_as` edge to them was valid, tagged `via`.
      - A resource sees the events of statements that name it positively.
      - Changes never walks through `can_assume` or `member_of`.
    - *Other way:* a wider scope changes the rows E6 and E7 expect.
    - *Raised by:* D-68 R.

49. **Should an identity see revisions of its own Deny statements?**
    - *Now:* D-27d: no. A Deny statement holds no grant, so its revisions appear only on the resources it names.
    - *Other way:* identity Changes include them.
    - *Raised by:* changes.7, D-27d R.

50. **A default-version change that alters no statement.** §2.6 l.560-562 calls such a change a policy change event. §5.3's event table (l.6043-6051) has no such event, and `iga_policy` keeps only the current version.
    - *Now:* D-69. There is no event type; revision and replacement events carry `policy_version_id`.
    - *Other way:* a `policy_version_changed` event plus storage for version history. Or the §2.6 sentence is dropped.
    - *Raised by:* D-69 R.

51. **What revoking a connector does to the graph.** Should revocation stale the connector's support rows? Separately, a `derived` resolution to an identity whose connector is later revoked is kept, because the trust pass only re-derives. §2.12 l.854 keeps resolutions while collection is incomplete.
    - *Now:* D-89. The connector's objects and edges keep their stored state, `account.connected` is `false`, and its claims carry `account_not_connected`.
    - *Other way:* revocation stales the support rows (a projector action), and clears or suspends derived resolutions into that account.
    - *Raised by:* D-89 R, trust.5.

52. **Nothing reads `Projector.EvidenceMissing`.** §4.8 l.4446-4452 says T4.9 and the P2-0 gate assert that the count of edges without evidence is zero. The counter is declared at `internal/igagraph/project.go:125-128` and incremented at `internal/igagraph/evidence.go:43`, but nothing outside `internal/igagraph` refers to it. It also counts `task_execution_role` edges under `executes_as`.
    - *Now:* no D-n. The gate is the per-edge database audit (`TestP2UnchangedRescan`, `TestP2BdbEveryEdgeHasEvidence`).
    - *Decide:* should `ProjectionService` log a non-zero count, or fail the pass?
    - *Raised by:* bdb.5.

53. **B21 inline: which reason the old inline policy's rows end with.** §2.7 l.612 and E8(a) (l.6457) do not say which reason the old inline policy's assignment and grants end with when their role is recreated.
    - *Now:* no D-n. They end `subject_recreated`, because the holder's recreation runs first. The policy cascade then retires the policy `recreated`, and finds no live assignment left (`TestP2BdbRecreatedRoleInlinePolicyIsANewIncarnation`).
    - *Other way:* `policy_recreated`, which needs the policy cascade to run first.
    - *Raised by:* bdb.4.

54. **A `"Principal": "*"` statement that allows only web identity or SAML.** D-43 takes the mechanism from the action, while D-88 says `*` → `sts_assume_role`.
    - *Now:* no D-n. `anyoneMechanism` (`internal/awsdiscovery/trust_policy.go:505`) gives `sts_assume_role` when `sts:AssumeRole` is allowed. Otherwise it gives the federation the statement allows, OIDC before SAML (`TestTrustAnyoneByWebIdentityIsAnEdge`). `{"AWS": "*"}` keeps the stricter AWS rule, although D-42 makes it the same node as `"*"`.
    - *Open fact, not verified:* whether IAM lets an AWS-typed wildcard match web-identity or SAML callers.
    - *Other way:* D-88's literal rule. A `*` that allows only federation then gets no edge, so the widest trust there is reads as nobody.
    - *Raised by:* fix:trust(a), fix:trust(b), review:trust#5.

55. **An EKS cluster with no OIDC issuer hides its pod-identity bindings while `eks_pod_identity` reads `reached`.** The scanner stores such a binding with a null issuer and calls that "legitimate for a Pod Identity-only cluster" (`services/cloud_aws_permission_scan.go:616-620`). A `DescribeCluster` that succeeds with no `identity.oidc` yields an empty issuer and records no failure (`internal/awsdiscovery/eks.go:137-152`), so the surface stays `reached`. The projector then writes no node and no edge for the association, and only keeps the role's existing pod-identity edges stale, never ended (`internal/igagraph/trust.go:327-337`).
    - *Now:* D-42 ("a cluster with no issuer leaves the association unresolved", no cluster-ARN fallback). The failed-describe half of trust.3 is fixed: that cluster is left out and the surface reads partial (`internal/awsdiscovery/eks.go:88-100`, `:122-125`).
    - *Decide:* a key for an issuer-less association that does not change between scans, or `eks_pod_identity` `partial` whenever an association is left unattributed, so coverage does not read complete while a binding is absent from the graph.
    - *Open fact, not verified:* how often a real `DescribeCluster` returns no OIDC issuer.
    - *Raised by:* trust.3. The succeeding-describe path was read in code at `9248549`, not run.

56. **A trust Deny has no limitation code.** §2.2 l.370-373 says a trust Deny is "shown as a restriction or limitation", but the vocabulary (l.6019-6036) has no code for it.
    - *Now:* D-44. The role's `provider_attrs` carries `trust_has_deny`, and no edge is written.
    - *Other way:* a new code on paths into the role.
    - *Raised by:* D-44 R.

57. **A reconcile failure after the snapshot has no coverage key.** §4.10 l.4628-4636 fixes the surface vocabulary, and `permission_scan` is written only when a scanner dies before its snapshot. Reusing `permission_scan` would veto every permission partition.
    - *Now:* no D-n. The failure is only logged. Its known cause is fixed (entry 2).
    - *Decide:* whether it gets a coverage entry, and under which name.
    - *Raised by:* fix:s3a(1).

58. **Role details omit `MaxSessionDuration` and `Description`.** §1.4 l.209 lists "max session" for `iam_roles`, but `GetAccountAuthorizationDetails`' RoleDetail returns neither field.
    - *Now:* D-48. Existing rows keep a frozen value, new roles get none, and a recreated role inherits nothing (`TestP2S3aRescanReplacesListedAttrsKeepsUnlisted`).
    - *Other way:* one paginated `ListRoles` per scan, or drop both fields from §1.4.
    - *Raised by:* s3a.5, D-48 R.

59. **The projector rewrites credential `lifecycle` on every pass.** §2.5 l.475 says only a human assertion writes `rotated`. No assertion path exists yet, and once one does, the next pass would overwrite it.
    - *Now:* no D-n. Each pass recomputes the lifecycle (`internal/igagraph/project.go:594-605`), and `UpsertCredential` writes it (`repository/iga_graph_repository.go:463-465`).
    - *Decide:* whether the projector leaves a `rotated` row alone.
    - *Raised by:* bdb.6.

#### Indexes and §5.6

Every §5.6 target was met on the T6.10 fixture without these indexes (`tests/load/RESULTS.md`, `m1/load` @ `3a80c78`, before the merge). The re-run on the merged code is in §3 above. None of these indexes is applied.

60. **Indexes for a resource's Changes.** §5.6 l.6228 gives Changes the index "lifecycle and validity columns". `036` has no index by entitlement that Changes can use, so every page and every total scans all three tables:
    - `idx_iga_access_edges_entitlement` is partial on `state <> 'ended'` (l.3317-3318);
    - `iga_statement_revision` has only `uq_iga_statement_revision_live` (l.3230-3231);
    - `iga_lifecycle_event` has no entitlement index (l.3376-3379).
    - *Proposed (D-106):* `idx_iga_access_edges_entitlement_all`, `idx_iga_le_entitlement` and `idx_iga_statement_revision_entitlement`. Measured: a typical resource's page and total go from 49.0/48.2 ms to 0.9/0.8 ms; hub references are unchanged. `/evidence`'s `contentAsOf` and `revision_count` read the same revision table.
    - *Other way:* no index, and the headroom shrinks as the estate grows.
    - *Raised by:* changes.1-4, idetail.11 (its first proposal), fix:changes(c), fix:evidence(DDL), load.1, review:load#7, load-fix(D-106), D-106 R.

61. **`cloud_observation.subject_native_id` has no index.** `resource_policy`, `resource_policy_not_projected` and `/evidence` presence facts filter on it.
    - *Proposed:* three shapes were raised:
      - `(workspace_id, subject_native_id, ingested_at DESC) WHERE source_api IN ('s3:GetBucketPolicy','kms:GetKeyPolicy')` (rdetail.3, fix:rdetail(F3));
      - `(workspace_id, subject_native_id, surface)` (evidence.8);
      - `(workspace_id, subject_native_id, source_api)` (load.5).
    - *Measured (fix:rdetail):* 33.8 ms at 80 003 observations in the workspace, and a median of 58 ms for the whole `GET /resources/:id` on `*`. The cost grows with the observation history.
    - *Raised by:* rdetail.3, evidence.8, fix:rdetail(F3), review:rdetail#3, load.5.

62. **No index leads with `iga_policy_assignment.policy_id`.** Restriction holders are found through that column. The proposal is `idx_iga_pa_policy (workspace_id, policy_id, state)`. Not measured. *Raised by:* rdetail.4.

63. **Grants by assignment, ended ones included.** `idx_iga_access_edges_entitlement` is partial. The proposal is `idx_iga_access_edges_assignment (workspace_id, assignment_id, entitlement_id)`. Not measured. *Raised by:* idetail.11 (its second proposal).

64. **`iga_external_principal` by resolved id.** D-105's check looks principals up by `resolved_identity_account_id` / `resolved_workload_id`, using only a prefix of `uq_iga_external_principal_key`. Two partial indexes are proposed. Not measured. *Raised by:* fix:graph(index).

65. **Plan settings per transaction or per server.** The read snapshot sets `plan_cache_mode = force_custom_plan` and `jit = off` per transaction (`internal/igaread/snapshot.go:52`). As reported: generic plans gave `504` on hub objects (mutation LM1), and a JIT-compiled count ran 875 ms against 106 ms without JIT (RESULTS.md).
    - *Decide:* keep these settings in the read path, or require them of production's configuration.
    - *Raised by:* load.2.

66. **The environment §5.6 is judged on.** Every number so far comes from PostgreSQL defaults on a shared laptop. Run 1 (`555a821`) missed four targets under outside load; run 2 (`3a80c78`) met all 77 (RESULTS.md).
    - *Decide:* the reference environment for "a target missed is a defect" (l.6230-6231).
    - *Raised by:* load.3.

67. **A path to a hub reference cannot complete.** `/graph/path` from a workload to `*` through the most-granted role answers `not_found_within_budget` with `bound_by: nodes` (RESULTS.md). The answer is honest, and it is not a §5.6 miss.
    - *Decide:* whether this is the intended answer, or whether hub references need a different search.
    - *Raised by:* load-fix(hub path).

#### Gate and spec wording

68. **E9(b) and E10 cannot run as written after T3.1.** E9(b) (l.6458) denies `iam:GetPolicyVersion` on customer-managed `TicketRead`. That document now arrives in the `LocalManagedPolicy` listing (§1.4 l.212), so the denial never makes it unreadable. E10 (l.6459, "Remove B's policy") and scenario 4's retirement hold only when the policy is deleted or AWS-managed, because a detached customer-managed policy stays listed.
    - *Now:* D-51. Scenario 4 and E9(b) use an attached AWS-managed policy. E9(b) also denies `GetPolicyVersion` on `TicketRead` and asserts that its grant stays current (`TestP2EgatesE9bUnreadableDocumentAndDetachInOneRun`, `tests/integration/p2_egates_failure_test.go:489-490`, `:547`).
    - *Decide:* the §7.1 wording, and whether E10 means delete or detach.
    - *Raised by:* s3a.2, egates.2, D-51 R.

69. **E11's "expand past the display default" has no fixture.** T8.1's lab (§7.1 l.6460) has nothing deeper than 2 assume hops, and no neighbourhood over 150 or 500 nodes.
    - *Now:* the egates fix added a 6-role chain. Through the route, chain-1 → chain-6 is `not_found_within_budget` with `bound_by: assume_hops` (`TestP2EgatesE11ExternalAccountsCyclesAndLimits`, `tests/integration/p2_egates_traversal_test.go:275-295`).
    - *Decide:* which default E11 means (assume hops or drawn nodes), and add the missing depth and breadth to T8.1.
    - *Raised by:* egates.4.

70. **`effective_access` is `not_evaluated` in §5.3's example (l.5997) but `unknown` in §2.14.9 (l.1630).**
    - *Now:* D-20 follows §5.3.
    - *Other way:* `unknown` on the wire.
    - *Raised by:* D-20 R.

71. **The §5.3 evidence example puts `resource_existence_not_verified` on a grant that names only a selector (l.6010).** The vocabulary gives that code to exact references (l.6030).
    - *Now:* D-21 follows the table.
    - *Other way:* the example is right, and the table changes.
    - *Raised by:* D-21 R.

72. **The Resources wireframe labels a KMS key in a connected account "External reference" (§2.14.6 l.1402-1404).** This contradicts §1.4 l.261 ("not a connected account").
    - *Now:* D-16 follows l.261.
    - *Other way:* `external` also covers a connected account whose surface was not read.
    - *Raised by:* D-16 R.

73. **"10 000 objects per workspace" (§5.6 l.6221) vs "a generated 10 000-workload fixture" (l.6230).** The fixture has 10 000 workloads, 10 000 resource references, 3 550 identities and 2 000 policies (RESULTS.md).
    - *Decide:* which the target means.
    - *Raised by:* load.4.

74. **One exhausted frontier already proves that no path exists.** §5.4 l.6143 requires both frontiers to be exhausted.
    - *Now:* D-38 follows the text, which is conservative.
    - *Other way:* "either frontier".
    - *Raised by:* D-38 R (marked optional).

75. **Node `state` has no column.** §5.3's list examples render `state`, but node tables carry only `lifecycle`.
    - *Now:* D-1 derives it from the support rows; for external principals, from their `can_assume` edges.
    - *Other way:* §5.3 defines the derivation, or the schema adds a column.
    - *Raised by:* D-1 R.

#### Lower-consequence readings

Where no code or test is cited, the "Now" is the raiser's report.

76. **`IGA_CURSOR_SECRET` unset.** The spec names the key (l.5634), but not what happens when it is absent.
    - *Now:* D-8: a random per-process key and a startup warning. Cursors then fail with `400 cursor_invalid` across restarts and replicas.
    - *Other way:* refuse to start.
    - *Raised by:* D-8 R.

77. **`iam_access_keys` reads `reached` when the user listing failed part-way.**
    - *Now:* unchanged Phase 1 semantics. No partition requires the surface.
    - *Other way:* `partial` whenever `iam_users` is not reached. This is needed once entry 14 adds a partition.
    - *Raised by:* s3a.3.

78. **Trust documents are named in `policy_documents`.** §4.10 l.4634 writes that surface "only when something failed to parse", and §1.4 frames it as covering policies only.
    - *Now:* an unreadable or absent trust document is an item there (`TestP2S3aTrustDocumentStoredAndJudged`).
    - *Other way:* trust documents get a surface of their own. That is a new name, which §4.10 forbids inventing.
    - *Raised by:* s3a.4.

79. **Scan resume.** The spec is silent on it, and `ScanPhaseIdentityPolicies` (`models/cloud_discovery.go:1618`) now skips nothing.
    - *Decide:* retire the checkpoint and the phase, or re-define resume over the listing markers.
    - *Raised by:* s3a.1.

80. **The template version is stamped only at onboarding.** D-72's `template.outdated` therefore never clears after the customer updates the stack.
    - *Decide:* how to detect an updated stack, for example a role tag read through `GetRole`, or the stack output.
    - *Raised by:* s2.3.

81. **"No integration" (§2.14.7 l.1499) is derived by the client** from D-92's connector list.
    - *Other way:* the server states it.
    - *Raised by:* s2.5.

82. **Activity when outcomes mix in one run.** §1.4 l.223 is silent on this.
    - *Now:* any throttle → `throttled`; every attempted identity failed → `denied`; otherwise `partial`.
    - *Other way:* another precedence.
    - *Raised by:* s3b.2.

83. **Which identities the 500-identity cap samples (§1.4 l.223).** D-86 fixes the order, by ARN.
    - *Now:* rows of any generation count, so stale rows take slots.
    - *Other way:* rows of the current generation only.
    - *Raised by:* s3b.3.

84. **`organizations: unsupported` has no reason field.** Its `Error` carries AuthSec's own sentence (§1.4 l.225).
    - *Other way:* a reason code.
    - *Raised by:* s3b.8.

85. **Unknown classification body keys (§5.5).**
    - *Now:* `400 invalid_parameter` naming the key. This follows D-75 by analogy; an ignored key would also sit outside the request hash.
    - *Other way:* unknown keys are ignored.
    - *Raised by:* class.1.

86. **Undo linkage.** §2.14.3 l.1110 defines undo as `unclassified` with `undoes_decision_id`.
    - *Now:* a plain `unclassified` without `undoes_decision_id`, and a `classified_agent` that names one, are both `422 invalid_decision`.
    - *Other way:* accept a plain `unclassified`.
    - *Raised by:* class.2.

87. **`409 classification_conflict` when no decision row exists.** §5.5 l.6177 shows only the populated case.
    - *Now:* `current` carries the workload's classification and version, with the decider fields `null`.
    - *Other way:* `current: null`.
    - *Raised by:* class.3.

88. **Decision ids are bare UUIDs.** §5.2's typed-reference tables (l.5661-5680) have no type for a decision.
    - *Other way:* a typed reference.
    - *Raised by:* class.6.

89. **Soft-deleted users are shown like any other user.** D-32 is silent on `deleted_at`.
    - *Other way:* mark or hide them.
    - *Raised by:* class.7.

90. **A resource policy that failed to parse gives `read: true, has_deny: null`.** The stored `has_deny: false` means only that nothing was parsed (§5.3 l.5944-5946).
    - *Other way:* `read: false`.
    - *Raised by:* rdetail.2.

91. **Whom a resource's restrictions name (§5.3 Resources).**
    - *Now:* holders of every assignment kind, boundary included. Groups are not expanded to their members. The statements listed are the active ones, whatever `include_ended` says.
    - *Other way:* expand groups, or exclude boundaries.
    - *Raised by:* rdetail.8.

92. **Member rows under `include_ended`** appear only where the membership and grant periods overlap.
    - *Other way:* show every ended membership.
    - *Raised by:* rdetail.10.

93. **`revision_count` is 0 for a Sid-less statement.** §5.3's example (l.5914) shows 1 for a Sid-keyed statement's first revision.
    - *Decide:* 0 or 1.
    - *Raised by:* idetail.3.

94. **The trust `statement.key` (D-98(c)) is the stored key verbatim,** including the role's endpoint key and the `\x1f` separators.
    - *Other way:* expose only the key's tail (`sid:X` or `h:hash#n`).
    - *Raised by:* idetail.8.

95. **Two live boundary assignments.** They can coexist when a replaced boundary's partition could not end. §5.3 defines a single `boundary.policy` (l.5915).
    - *Now:* current is chosen before stale, then the newest `valid_from`. The rest go in `boundary.others`.
    - *Other way:* a list.
    - *Raised by:* idetail.10.

96. **A target's state is its statement's D-1 state.** §5.3's Graph example shows no state on targets (l.5977-5978).
    - *Other way:* targets carry no state.
    - *Raised by:* graph.11.

97. **Workload › Resources holders include their groups.** §5.3 l.5858 says "(and their groups)", while D-78 names only the `executes_as` identities.
    - *Now:* groups are included. This makes no difference for AWS roles.
    - *Decide:* align D-78 or §5.3.
    - *Raised by:* wdetail.4.

98. **A Lambda environment returned as an error leaves `lambda:<region>` `reached`** (see entry 36).
    - *Other way:* `partial`.
    - *Raised by:* fix:wdetail(b).

99. **An account awaiting its first publication has no trust watermark,** so `may_assume` coverage does not name it (fix:wdetail(c)'s report; `TestP2WdetailMayAssumeCoverageNamesTrustingAccounts` covers published accounts only, not this case).
    - *Decide:* whether such an account bears on `may_assume`.
    - *Raised by:* fix:wdetail(c).

100. **`status.basis` for a coverage claim is `null`.** None of §2.14.9's basis values (l.1627) fits a run's own read record.
     - *Other way:* a basis value for it.
     - *Raised by:* evidence.2.

101. **What evidences a resource reference's existence.**
     - *Now:* the policy versions of up to 50 active statements that name or exclude it.
     - *Other way:* references have no presence facts.
     - *Raised by:* evidence.9.

102. **Coverage limitations on an ended claim use the current watermark.** A surface denied now therefore shows on a claim that ended earlier under complete coverage.
     - *Other way:* suppress them, or use the watermark as of the claim's end.
     - *Raised by:* evidence.12.

103. **An untagged EC2 instance has an empty display name.** §1.4 l.244 gives no fallback.
     - *Proposed:* the instance id. Not changed.
     - *Raised by:* egates.1.

104. **No reverse link from a graph object to its inventory row.** §2.14.5 l.1312-1317 promises "Raw inventory" on graph objects, "never a match by name". But `/lookup` (l.6063-6067, D-81) maps only inventory → graph.
     - *Now:* no reverse route. The audit planned a Cloud Inventory link filtered by the object's account.
     - *Other way:* a reverse route.
     - *Raised by:* audit(/lookup).

105. **Allow statements of a policy used only as a boundary count toward `named_by_count`.** D-17 is silent on this.
     - *Now:* the count is every active Allow statement with a positive target on the reference, whatever the policy's assignment kind (`ResourceTargetCounts`, `internal/igaread/nodes.go:527-549`).
     - *Other way:* exclude statements reached only through boundary assignments.
     - *Raised by:* audit(D-17).

### 9.2 Answered by a decision

| # | Question | Raised by | D-n | How |
|---|---|---|---|---|
| a1 | The account line when a newer run is queued while the previous one is still projecting | s2.4 | D-92 | `latest_run` is the newest non-terminal run. The projecting run shows as `barrier.scan_run` and as every queued run's `waiting_on` |
| a2 | What makes an external principal "live" for D-41 rule 1 | trust.4 | D-1, D-47 | Its lifecycle is derived from its `can_assume` edges: active while any of them is current or stale |
| a3 | One unknown Principal key freezes a role's trust edges | trust.7 | D-45 | Any skipped statement sets `trust_parse_error`, so the edges go stale and never end. This is intended |
| a4 | `resource_policies` has no throttled state | s3b.4 | D-93 | A throttled read is a failed read (partial or denied), and `Error`/`error_code` still name the throttle. Whether real accounts read as permanently partial is for S8 |
| a5 | Which runs `meta.coverage` reads when watermarks lag | lists.3 | D-25, D-57 | The runs the current revision was built from |
| a6 | `meta.coverage` is not narrowed by `integration` | lists.5 | D-73 | It is narrowed by the account and region filters only |
| a7 | `can_classify` when the permission lookup errors | class.5 | D-83 | `false` unless every condition is established, and never absent |
| a8 | The `via_group` shape | rdetail.6 | D-18 | The group plus the membership's state, beside the grant's. The row is stale if either one is |
| a9 | The shape of `excluded_by` and `deny_statements_naming` | rdetail.7 | D-99 | Capped lists with `_more` flags, never paged |
| a10 | Resource › Access's paging unit (vs §2.14.6's "20 of 63 statements") | rdetail.9 | D-99 | `limit`, `next_cursor` and `total` count holders |
| a11 | The `sources` shape | rdetail.11 | D-98(b) | One entry per support row, with the same fields on every detail |
| a12 | Coverage of an ended support after its last run | changes.9 | D-27e | An ended support speaks only up to the run that last confirmed it |
| a13 | Frontier entries run only in the request's direction, and "which workloads share this identity" | graph.4 | D-35, D-17 | `direction` is required. Sharing is answered by `used_by_count`, expandable in reverse |
| a14 | The `/graph/expand` shape, and a page that times out | graph.9 | D-35, D-40 | D-35's shape. The reserve check now runs before the page (`TestP2GraphExpandTimeReserve`) |
| a15 | Is `restrictions.deny_statements` holder-level? | wdetail.3 | D-78 | Yes, over the row's execution identities; matching is not evaluated |
| a16 | Stale boundary assignments counted as restrictions | wdetail.8 | D-12 | The default is current and stale (§5.4 l.6103-6104); a stale row is still believed |
| a17 | `used_by_count` counts the workload itself (vs l.1362 "shared with 1 other workload") | wdetail.9 | D-17 | One count definition everywhere; the console subtracts one |
| a18 | The `affects` text on detail responses | wdetail.10 | D-73 | A fixed string per surface, from the same table |
| a19 | Which keys B9's "one test per FK" covers | bfk.6 | D-95 | Every key on or into an `iga_*`/`cloud_*` table, read from the catalogue. bfk's implement report counted 116 under the narrower scope the review then widened; not re-counted at HEAD |
| a20 | A connector hard delete after a projection is refused | bdb.3 | D-94 | No DDL, because the product only revokes (D-89). The test asserts only that no edge survives without its evidence |
| a21 | `graph_state` on the detail envelope | contract.4 | D-102(a) | On every detail meta. Only the §5.2 detail example (l.5703-5704) lacks it |
| a22 | §4.10 l.4943 says `SurfaceCoverage` has exactly `State`, `Count` and `Error` | audit(D-71) | D-71 | It gains optional additive `error_code`, `api` and `items`. The l.4943 sentence is out of date |

### 9.3 Withdrawn, or not a spec question

| # | Question | Raised by | Why |
|---|---|---|---|
| c1 | Sorted regions move the STS signing region | s2.7, review:s2#8 | Fixed: `SigningRegion` (`internal/awsdiscovery/regions.go:152`; `TestP2S2SigningRegionIsNeverAnOptInSortedFirst`) |
| c2 | `034`'s comment on the mechanism values | trust.6 | §3 l.2911 lists the right values. The stale comment is in `migrations/master/034_iga_external_principal.sql:28`, and there is no CHECK on the column |
| c3 | The credential-report observation is keyed by the user ARN | s3b.7 | An implementation note for the IAM scanner (`services/cloud_aws_iam_scan.go:806-812`). D-24 keeps only the source APIs that bear on a claim |
| c4 | `lifecycle=active` and an absent `lifecycle` hash differently | lists.6 | It never serves a wrong page |
| c5 | `/capabilities` feature flags | lists.7 | Done: all eight follow the switch (`controllers/platform/iga_graph_read_controller.go:98-110`) |
| c6 | A cursor with no classification clock: 400 or 409? | class.4 | Resolved at integration: lists answer `409 listing_changed` (`internal/igaread/lists.go:245-246`), and `CheckClassificationSeq` (`classification.go:417`) has only a test caller |
| c7 | Resource › Access for `*` reads every grant before cutting holders | rdetail.5 | Now an identity-first page for dense references. p95 219.8 of 300 ms in run 2; run 1, under load, read 560.2 ms (RESULTS.md) |
| c8 | Resource detail omits `resource_policies` gaps | rdetail.12 | Fixed: `ResourceDetailCoverage` adds them for buckets and keys (`resource_detail.go:239-242`). The list side is entry 29 |
| c9 | The credential projector duplicates keys, and `issued_at` is never set | idetail.1 | Duplicates are fixed by D-64 in m1/bdb (`TestP2BdbInactiveKeyKeepsOneRow`). `issued_at` still has no writer (`internal/igagraph/project.go:600-605`). That is an implementation gap against §1.4 l.221's "created", not a spec question |
| c10 | `/graph` has no per-node neighbour cap | graph.3 | The spec text says so: "Neighbours per expansion" (§5.4 l.6126) |
| c11 | Target edges are read only through Allow statements | graph.5 | The spec text says so: `grant` is Allow only (l.6080), and Deny statements "are not edges" (l.6098-6099) |
| c12 | `account` never narrows a traversal | graph.8 | The spec text says so: §5.4 l.6115-6116 |
| c13 | "No DDL change is needed" | graph.12, wdetail.11 | A statement, not a question |
| c14 | `organizations_not_collected` on every claim | evidence.3 | The spec text says so: l.6028, "Always, for AWS" |
| c15 | Phase 1 deletes a deselected region's workload rows | fix:s2(2) | Resolved by fix:s3b. Reconcile is per reached surface, and a region that is no longer selected is kept (`repository/cloud_workload_repository.go:409-414`) |
| c16 | D-57's `Key()` must keep building from Partition fields | fix:s2(3) | A merge instruction, met at `3ea0244` (`TestP2S2CoverageMergesTheRunsTheRevisionStandsOn`) |
| c17 | An unreachable `document_error` guard | fix:changes(d) | A defence-in-depth note |
| c18 | D-24's "sentences from claim rows" vs the policy-version label | fix:evidence(D-24) | D-24's own text needs the exception; the spec is not involved |
| c19 | `cloud_gm_key` and `cloud_pa_key` omit the workspace | bfk.7 | Harmless, because the ids are global uuids. No change proposed |
| c20 | A GitHub rescan re-confirms the agent as a new `iga_agents` row | egates.5 | Phase 1 behaviour, outside Phase 2; E16 holds |
| c21 | D-86's "one entry per key" amendment | fix:idetail(D-86) | Moot after D-64: there is one row per key, and the read's dedupe only guards rows written before the fix (`internal/igaread/idetail_identity.go:241-249`, `DISTINCT ON` at `:260`) |
| c22 | `ConnectedAccounts` counts revoked connectors | audit(D-3a) | Fixed at the source: `internal/igagraph/load.go:118-123` excludes them (D-61) |

## 10. Decisions index and known schema defects

`P2-DECISIONS.md` has 113 entries: D-1–D-106, plus D-27a–g. **39 carry *Raise*** and are listed first. Every entry is provisional.

### 10.1 Raise (39)

| D | Short title | Raise |
|---|---|---|
| D-1 | Node `state` and `last_confirmed_at` derived from support rows; the §5.3 examples use a field no table defines | yes |
| D-3 | Account and `connected` fixed per revision; a resource's `account_connected` lags until its connectors re-project | yes |
| D-8 | `IGA_CURSOR_SECRET` unset: a random per-process key; the spec names no default | yes |
| D-12 | `include_ended` on tabs and the graph (UI5 vs §5.4) | yes |
| D-13 | Sorts: name then account (§2.14.6) vs §5.3's workload index | yes |
| D-16 | Resource API `kind` (the §2.14.6 wireframe vs §1.4 l.261) | yes |
| D-19 | `resource_policy` scoped to the revision; "read, none exists" and "not read" are indistinguishable | yes |
| D-20 | `effective_access: "not_evaluated"` (§2.14.9 says `unknown`) | yes |
| D-21 | Limitation conditions exact; the §5.3 example's code at l.6010 is wrong | yes |
| D-22 | A member's boundary on a group-held grant; the vocabulary says "the holder" | yes |
| D-24 | Evidence facts; the junction has no current-link marker | yes |
| D-26 | One timestamp per pass; propose `uq_iga_publication_published_at` | yes |
| D-27c | `statement_replaced`; D-69 cannot be met exactly for Sid-less statements; DDL proposed | yes |
| D-27d | Changes scope limits; should an identity see its own Deny revisions | yes |
| D-27f | A resource's Changes use current targets; targets have no validity period | yes |
| D-27g | Grant history judged by the revision at `valid_from`; §3 rule 7 assumes a statement's effect never changes | yes |
| D-38 | `none_exists` only when both frontiers are exhausted | yes (optional) |
| D-41 | Trust edge keys and source choice; no edge re-pointed (§4.7 l.4411 vs 034) | yes |
| D-42 | External principal identity; the `pod:` prefix until `ExternalPrincipalKey` carries the mechanism | yes |
| D-44 | Trust Deny and NotPrincipal: no edges, only flags; §5.3 has no code for a trust Deny | yes |
| D-48 | Authorization details; RoleDetail lacks MaxSessionDuration and Description | yes |
| D-51 | Scenario 4 / E9(b) fixture after T3.1 (E9(b) names customer-managed TicketRead) | yes |
| D-53 | Detail-call failures; 029 has no `unknown` execution-role state | yes |
| D-55 | `queued_at` = `requested_at`; no column for the enqueue-to-claim wait metric | yes |
| D-58 | The `prevents` mapping; none is specified, and l.5792 cites the wrong section | yes |
| D-64 | An Inactive key is updated in place; `revoked` (§2.5) vs AWS's `Inactive` | yes |
| D-66 | Target evidence from the policy-version observation; no target junction exists | yes |
| D-67 | A retired policy's assignments and a replaced statement's grants end `not_seen`, not with the cascade reason | yes |
| D-68 | Changes scope per object type | yes |
| D-69 | A default-version change raises no event; version ids appear on revised and replaced events | yes |
| D-89 | Revoked connectors stay visible; should revocation mark their support stale | yes |
| D-94 | A workspace cannot be deleted after a projection (RESTRICT is never deferred); schema defect, §10.3 below | yes |
| D-95 | B9/B20 pass only with 19 named §2.9 exemptions; schema defect, §10.3 below | yes |
| D-101 | `bound_by` values beyond §5.4: `paths`, and `/graph/path`'s `resolution_not_followed`. Its `/graph` half is **superseded by D-105** | yes |
| D-102 | Four shapes §5 leaves open (`graph_state`, `meta.coverage` on graph and evidence, frontier `expand`/`more`, identity `provider_attrs`) | yes |
| D-103 | The discovery routes' 401/403 keep the shared bodies | yes |
| D-104 | `policy_documents` names its first failing call | yes |
| D-105 | An unfollowed resolution is not a budget: `data.resolution_not_followed` on `/graph` | yes |
| D-106 | Proposed indexes for a resource's Changes (not applied) | yes |

### 10.2 No Raise (74)

| D | Short title | Raise |
|---|---|---|
| D-2 | ARN from the native segment of `source_key` | no |
| D-4 | Detail routes `404` before the first publication | no |
| D-5 | Route ids: a bare UUID or the route's own typed ref | no |
| D-6 | Readable rows: `provider = 'aws'` with a support row (spec-settled) | no |
| D-7 | The requested `rev` and the cursor's `rev` both checked (spec-settled) | no |
| D-9 | 401/403 in the §5.2 envelope on graph routes | no |
| D-10 | Order of checks: 403, 503, 401, 400, snapshot | no |
| D-11 | A `/capabilities` feature is `true` only when its routes exist and the switch is on | no |
| D-14 | Facets (spec-settled) | no |
| D-15 | Totals above 10 000 (spec-settled) | no |
| D-17 | Resource counts; `named_by_count` counts Allow statements only | no |
| D-18 | Resource › Access expands group-held grants to members | no |
| D-23 | `stale_since` from runs and revisions | no |
| D-25 | `cloud_*` reads keyed to the revision's runs (spec-settled) | no |
| D-27 | Changes event shape and paging | no |
| D-27a | Attribution on read; `rev` and `run` null when no single publication matches | no |
| D-27b | `statement_revised` only when the content changed | no |
| D-27e | `coverage_changed` lanes | no |
| D-28 | Remaining grants and per-target paths | no |
| D-29 | Classification request hash | no |
| D-30 | Classification validation and order | no |
| D-31 | Lock wait 3 s; a timeout is `504` | no |
| D-32 | Display names | no |
| D-33 | Classification history | no |
| D-34 | `/graph` depth; `assume_hops` limits only `can_assume` | no |
| D-35 | Traversal response shapes and limitations | no |
| D-36 | `crosses_account` | no |
| D-37 | `group_key` | no |
| D-39 | Traversal roots (spec-settled) | no |
| D-40 | Time reserve per level | no |
| D-43 | Trust mechanism on the edge | no |
| D-45 | Unreadable trust: the role's edges go stale | no |
| D-46 | Trust content hash | no |
| D-47 | External principals have no support rows | no |
| D-49 | A skipped statement makes its document unreadable | no |
| D-50 | AWS-managed boundary policies are fetched | no |
| D-52 | Instance profiles in `attrs`, not projected | no |
| D-54 | Regions list and PATCH validation | no |
| D-56 | `last_published_rev` = the current revision | no |
| D-57 | The manifest is cumulative; the partition key carries scope and connector (code fix `3ea0244`) | no |
| D-59 | A job failed below its attempt ceiling is `projecting`, `retrying` | no |
| D-60 | Partition keys frozen once deployed | no |
| D-61 | One definition of "connected" | no |
| D-62 | Cursor routes carry the object | no |
| D-63 | Regions on rows | no |
| D-65 | Presence refs on `/evidence` | no |
| D-70 | `coverage_changed` sequence | no |
| D-71 | Coverage detail fields stamped at collection | no |
| D-72 | `/coverage` fields | no |
| D-73 | The `meta.coverage` table | no |
| D-74 | `stale_reason` | no |
| D-75 | List filters | no |
| D-76 | `q` search | no |
| D-77 | Tab envelopes | no |
| D-78 | Workload › Resources holders | no |
| D-79 | Grouped-edge evidence | no |
| D-80 | Evidence details | no |
| D-81 | `/lookup` | no |
| D-82 | Revision-bound vs live routes | no |
| D-83 | `can_classify` | no |
| D-84 | Statement index is 1-based | no |
| D-85 | The `provider_attrs` allowlist | no |
| D-86 | Credentials and activity | no |
| D-87 | External principal rendering | no |
| D-88 | Trust actions and NotAction | no |
| D-90 | Regions failure modes | no |
| D-91 | Scan-run history | no |
| D-92 | `/pipeline` details | no |
| D-93 | `unsupported` and resource policies | no |
| D-96 | One rendering of `published_at` | no |
| D-97 | `meta.capabilities` on every detail envelope | no |
| D-98 | One shape per concept | no |
| D-99 | Resource › Access pages by holder | no |
| D-100 | D-9 wired in production (`SetupIGARoutes`) | no |

### 10.3 Known schema defects

None of these is fixed; every migration is still as it was at M0.

1. **D-94: a workspace cannot be deleted after a projection.** `036`'s `iga_le_publication_fkey` is `ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED` (§3 l.3354–3356; `036_iga_permission_model.sql:200–202`), and PostgreSQL never defers RESTRICT. The proof, the proposed `NO ACTION` key and the other way are §9 entry 1 above. `cloud_*` rows are left behind in both phases (Phase 1: `cloud_connector` has no FK to `workspaces`; entry 7).
2. **D-95: §2.9 does not hold for 19 single-column keys**, so B9 and B20 pass only for the keys outside this list. The 19 are pinned in `bfkLegacySingleColumn` (`tests/igagraph/p2_bfk_fk_test.go:142`):
   - `iga_observations_delivery_fkey`;
   - `cloud_identity_connector_id_fkey`;
   - `cloud_observation_{identity,permission,resource,workload}_id_fkey`;
   - `cloud_{secret,assume_edge,permission,resource,workload,usage,scan_checkpoint}_connector_id_fkey`;
   - `cloud_{secret,assume_edge,permission,workload,usage}_identity_id_fkey`;
   - `cloud_permission_resource_id_fkey`.

   Six of them are B20's "Catches" class: `cloud_observation_identity_id_fkey` and the five Phase 1 `*_identity_id_fkey`. D-95 gives the DDL for each. `iga_observations_delivery_fkey` needs a ruling first (§9 entry 5 above).
3. **Two rollback defects raised at M0 (M0 §6.1, §6.2) and not fixed.**
   - **`035`** replaces `uq_cloud_observation_dedupe` with a five-column `COALESCE(…, policy_id)` and widens the `_no_subject` predicate (`035_aws_collection_model.sql:118–126`). The `0e75ad7` writer's `ON CONFLICT` then matches no index, so a rolled-back deployment records no evidence, silently.
   - **`028`** adds `provider … DEFAULT ''` (`028_iga_recognition_keys.sql:21`, `:43`, `:65`, `:84`). GitHub rows written during a rollback are then invisible to readers filtering `provider = 'github'`.
   - The M0 proposals stand: keep the old indexes until `037`, and `DEFAULT 'github'`.

**Other proposed DDL.** These are additions, not defects in the schema as it exists: D-26 (`uq_iga_publication_published_at`), D-27c (`policy_version_id` columns) and D-106 (three indexes). **D-105 supersedes D-101's `/graph` half**; D-101's `/graph/path` `bound_by` value stands.

## 11. Not done

| Item | Why |
|---|---|
| **S7 console** (T7.1–T7.13, l.6339–6355) | `Authsec-ui`, owned by Aditya's team; outside M1. The backend contract it builds on is pinned by §4.16 above. E15 (keyboard, narrow screens) is console-only |
| **S8 lab** (T8.1, l.6361) | Terraform in AuthSec-owned AWS accounts, which this work has no access to. M1's tests answer AWS through fakes (and, for T2.1, a local STS/EC2 server) |
| **Playwright** (T8.2, l.6362) | E1–E16 through the real console against the lab; needs S7 and S8. §4.17 above covers only the backend halves |
| **§9 production-schema rehearsal** (T8.3, l.6363; §9 l.6598) | Needs a production schema dump, and there is no production access. `027`–`036` are proven only on fresh databases |
| **Deploys** | None. `graph` is not merged into `authsec-staging` before M3: pushing staging deploys production (§6.1 l.6258–6262). Only `origin/graph` up to `3ea0244` exists remotely |

**Open inside M1's scope.** These are from the item reports and were not re-verified:
- **Gateways on an old template.** A workload with no earlier node whose first detail call fails is collected but not projected (fix:s3b, rejected finding 9; D-53). An AgentCore gateway on a stack still at the pre-`2026-09-23` template, which lacks `GetGateway`, therefore never reaches the graph. §9 entry 8 above.
- **Template version.** `attrs.template_version` is stamped only at onboarding, so `template.outdated` cannot clear after a stack update (impl:s2, not_done). Entry 80.
- **Resume checkpoint.** The `ScanPhaseIdentityPolicies` checkpoint is inert after T3.1: a leftover checkpoint skips nothing and is cleared on completion. Whether to retire the phase or redefine resume (for example over listing markers) is open (impl:s3a, spec question). Entry 79.
- **`ReconcilePolicies` failures.** They are logged, not reported in coverage (fix:s3a, rejected). Entry 57.
- **Hub paths.** `/graph/path` from a workload to the most-granted reference (`*`) always answers `not_found_within_budget` with `bound_by: nodes` under the hard budgets (`load_fix_report.md`, spec question). Entry 67.
- **Timing flake.** `TestP2ReadDoesNotStraddleAPublication` failed once in each of two loaded full runs and passed alone and on rerun; it was not reproduced (the B16 row, §5.1 above).

**Whole-repository comparison against pre-Phase-2 `0e75ad7`.**

Run at `e63dfa7` against `0e75ad7` (a detached worktree), with the same environment on both sides (no IGA DSN set) and `go test -count=1 -p 2 -timeout 30m -json ./...`:

| | Tests | Failed | Packages failing |
|---|---:|---:|---:|
| `0e75ad7` (base) | 1015 | 21 | 6 |
| `e63dfa7` (head) | 1572 | 21 | 6 |

**No new failure, and none fixed**: the same 21 test results fail on both sides, in the same six packages (`controllers/admin`, `controllers/enduser`, `controllers/shared`, `internal/migration`, `internal/tokens`, `services`). Four packages are new at head. The causes, read from the output: sqlite tests on a `CGO_ENABLED=0` build (`controllers/enduser` 5, `internal/tokens` 2, `services` 7 resource-server tests), and tests that need PostgreSQL at `localhost:5432` (`controllers/shared` 2 AD-sync tests; `controllers/admin`, whose `TestGroupController_AddUserDefinedGroups` fails to connect; `internal/migration`'s `TestMasterMigrations_Flow`, "failed to ping postgres"). The same comparison at `9248549` found exactly one new failure, `TestP2BdbIAMDeniedEndsNothing`: without a DSN its first half skipped and its second half then failed. `e63dfa7` makes it skip as a whole, and the comparison above is the re-run.

**Known pre-existing failures, not from this branch** (confirmed by the comparison above):
- **sqlite/cgo.** Tests that open a sqlite database and fail without cgo:
  - `internal/tokens` (`cloud_onboarding_token_test.go`);
  - `services` (`resource_server_onboarding_service_test.go`, `resource_server_service_test.go`);
  - `controllers/enduser` (`enduser_controller_activation_test.go`).
- **GCP tests in `services`.** The guard refuses a `TEST_DATABASE_URL` whose database name lacks `"test"` (`services/cloud_gcp_test_db_guard_test.go:41`); the per-agent `igt_w_<key>` databases lack it. The `iga_test` of §1 above does not, so this cause applies to the agents' runs, not to §1's.
- **`controllers/shared`.** Needs PostgreSQL at `DB_HOST` localhost, `DB_PORT` 5432 (`ad_controller_test.go:71–75`).
- **Also failing at base in M0** (M0 §2, with an identical failing set at `0e75ad7`):
  - `internal/migration` (`TestMasterMigrations_Flow`; `runner_test.go` uses DB user `kloudone`);
  - `controllers/admin`.
- **`e63dfa7`.** The comparison above found `TestP2BdbIAMDeniedEndsNothing` failing without a DSN at `9248549`; `e63dfa7` fixed it, and the comparison at `e63dfa7` is clean.

## Appendix A. Load tables at `9248549`

As `TestP2LoadTargets` wrote them (`IGA_LOAD_REPORT`), unedited apart from heading levels.

Fixture: 492743 rows (main workspace 9823 active workloads), 50 measured iterations per read, sequential, warm, interleaved round-robin.


### Lists (p95 target 400ms)

| Read | p50 ms | p95 ms | max ms | Statements | COUNT ms (traced) | Slowest statement ms (traced) | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| GET /workloads first page | 35.6 | 49.3 | 54.6 | 18 | 20.2 | 20.2 | met |
| GET /workloads deep page (page 50, cursor) | 35.3 | 50.3 | 51.8 | 18 | 21.3 | 21.3 | met |
| GET /workloads q=<team> search | 51.5 | 72.1 | 106.4 | 18 | 16.7 | 18.6 | met |
| GET /workloads account=<account> | 33.1 | 46.8 | 63.3 | 11 | 14.0 | 14.0 | met |
| GET /workloads facets=account,runtime_kind,classification,region | 106.5 | 142.2 | 167.4 | 38 | 108.8 | 31.1 | met |
| GET /workloads q + account + facets | 125.6 | 163.4 | 196.0 | 31 | 86.0 | 24.3 | met |
| GET /identities first page | 48.9 | 66.5 | 83.3 | 16 | 12.1 | 35.1 | met |
| GET /identities deep page (page 30, cursor) | 29.9 | 39.8 | 44.7 | 16 | 10.8 | 13.7 | met |
| GET /identities q=<team> search | 27.2 | 42.4 | 57.0 | 16 | 11.7 | 10.7 | met |
| GET /identities account=<account> | 33.7 | 46.0 | 47.0 | 16 | 10.8 | 22.3 | met |
| GET /identities facets=account,kind | 66.6 | 90.7 | 101.0 | 26 | 36.9 | 68.3 | met |
| GET /identities q + account + facets | 39.7 | 52.5 | 59.9 | 26 | 25.8 | 9.9 | met |
| GET /resources first page | 127.6 | 163.7 | 207.8 | 16 | 25.6 | 123.2 | met |
| GET /resources deep page (page 50, cursor) | 93.0 | 124.8 | 164.8 | 16 | 24.1 | 90.8 | met |
| GET /resources q=<team> search | 54.8 | 71.5 | 101.2 | 16 | 23.8 | 27.6 | met |
| GET /resources account=<account> | 71.4 | 99.6 | 140.6 | 16 | 19.2 | 49.3 | met |
| GET /resources facets=kind,service,account | 188.8 | 249.6 | 279.1 | 31 | 88.5 | 118.3 | met |
| GET /resources q + account + facets | 83.4 | 111.0 | 152.8 | 31 | 70.9 | 23.6 | met |
| GET /workloads classification=agent sort=classification | 34.5 | 69.6 | 82.1 | 12 | 9.7 | 43.9 | met |
| GET /identities used_by=workloads | 66.7 | 99.1 | 132.5 | 16 | 27.7 | 36.9 | met |

### Totals and facets (p95 target 3s)

| Read | p50 ms | p95 ms | max ms | Statements | COUNT ms (traced) | Slowest statement ms (traced) | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| GET /workloads facets=account,runtime_kind,classification,region | 106.5 | 142.2 | 167.4 | 38 | 108.8 | 31.1 | met |
| GET /workloads q + account + facets | 125.6 | 163.4 | 196.0 | 31 | 86.0 | 24.3 | met |
| GET /identities facets=account,kind | 66.6 | 90.7 | 101.0 | 26 | 36.9 | 68.3 | met |
| GET /identities q + account + facets | 39.7 | 52.5 | 59.9 | 26 | 25.8 | 9.9 | met |
| GET /resources facets=kind,service,account | 188.8 | 249.6 | 279.1 | 31 | 88.5 | 118.3 | met |
| GET /resources q + account + facets | 83.4 | 111.0 | 152.8 | 31 | 70.9 | 23.6 | met |

### Detail tabs (p95 target 300ms)

| Read | p50 ms | p95 ms | max ms | Statements | COUNT ms (traced) | Slowest statement ms (traced) | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| GET /workloads/:id | 11.2 | 18.0 | 31.9 | 10 | 0.0 | 2.4 | met |
| GET /workloads/:id/identities | 34.8 | 57.8 | 77.1 | 40 | 8.5 | 3.2 | met |
| GET /workloads/:id/resources | 30.8 | 49.5 | 54.6 | 20 | 5.2 | 6.0 | met |
| GET /workloads/:id/classification | 8.2 | 13.0 | 18.6 | 10 | 8.9 | 10.1 | met |
| GET /workloads/:id/resources (most-granted role) | 30.7 | 44.7 | 64.7 | 20 | 4.7 | 5.4 | met |
| GET /workloads/:id (most-granted role) | 10.8 | 14.9 | 28.1 | 10 | 0.0 | 1.8 | met |
| GET /identities/:id (roles) | 11.2 | 16.5 | 17.2 | 12 | 2.8 | 2.8 | met |
| GET /identities/:id/used-by (roles) | 19.7 | 26.6 | 52.2 | 19 | 12.4 | 16.0 | met |
| GET /identities/:id/permissions (roles) | 30.0 | 39.8 | 50.5 | 19 | 4.2 | 6.7 | met |
| GET /identities/:id (users) | 12.6 | 18.5 | 19.8 | 13 | 1.7 | 1.7 | met |
| GET /identities/:id/permissions (users) | 36.8 | 50.9 | 62.7 | 20 | 5.2 | 9.2 | met |
| GET /identities/:id (hub role, 403 workloads) | 12.1 | 18.8 | 21.7 | 12 | 3.1 | 3.1 | met |
| GET /identities/:id/used-by (hub role, 403 workloads) | 36.1 | 57.0 | 65.0 | 19 | 9.3 | 9.2 | met |
| GET /identities/:id/used-by (ecsTaskExecutionRole, 1016) | 49.2 | 70.0 | 83.3 | 19 | 13.4 | 16.4 | met |
| GET /identities/:id/used-by (largest group) | 14.3 | 20.5 | 26.7 | 12 | 2.1 | 3.1 | met |
| GET /identities/:id/permissions (most grants) | 30.7 | 54.2 | 70.4 | 19 | 4.8 | 6.4 | met |
| GET /external-principals/:id | 8.9 | 14.3 | 20.6 | 7 | 0.0 | 2.9 | met |
| GET /external-principals/:id/referenced-by | 12.4 | 21.2 | 25.0 | 12 | 1.8 | 3.1 | met |
| GET /external-principals/:id (lambda.amazonaws.com) | 11.9 | 18.3 | 24.1 | 7 | 0.0 | 4.0 | met |
| GET /external-principals/:id/referenced-by (lambda.amazonaws.com) | 28.4 | 38.3 | 44.3 | 12 | 4.3 | 11.4 | met |
| GET /resources/:id | 33.2 | 47.7 | 82.5 | 14 | 2.2 | 17.7 | met |
| GET /resources/:id/access | 22.6 | 33.9 | 43.0 | 16 | 4.6 | 7.1 | met |
| GET /resources/:id ("*") | 42.4 | 57.3 | 63.0 | 14 | 11.5 | 18.3 | met |
| GET /resources/:id/access ("*") | 198.0 | 268.5 | 342.1 | 18 | 71.4 | 71.6 | met |
| GET /resources/:id (most-named bucket) | 35.8 | 48.6 | 52.8 | 14 | 4.3 | 19.9 | met |
| GET /resources/:id/access (most-named bucket) | 117.5 | 162.2 | 422.1 | 18 | 31.1 | 39.8 | met |
| GET /identities/:id/used-by section=workloads page 2 (ecsTaskExecutionRole, 1016) | 38.9 | 60.6 | 63.9 | 12 | 10.4 | 17.0 | met |
| GET /resources/:id/access page 2 ("*") | 199.3 | 251.8 | 383.4 | 18 | 58.1 | 76.0 | met |

### Graph (p95 target 1.5s)

| Read | p50 ms | p95 ms | max ms | Statements | COUNT ms (traced) | Slowest statement ms (traced) | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| GET /graph workload forward | 133.8 | 238.2 | 254.2 | 68 | 2.7 | 7.6 | met |
| GET /graph workload forward (most-granted role) | 166.6 | 261.4 | 275.4 | 68 | 3.5 | 8.2 | met |
| GET /graph identity forward (roles) | 119.0 | 360.8 | 467.0 | 56 | 9.6 | 9.0 | met |
| GET /graph identity reverse (hub role) | 307.5 | 549.3 | 617.6 | 34 | 11.0 | 319.0 | met |
| GET /graph resource reverse | 309.6 | 547.3 | 905.5 | 66 | 12.6 | 315.4 | met |
| GET /graph resource reverse (most-named bucket) | 436.9 | 760.8 | 837.3 | 55 | 42.2 | 333.3 | met |
| GET /graph external principal forward (lambda.amazonaws.com) | 443.9 | 706.6 | 775.7 | 37 | 94.8 | 57.2 | met |
| GET /graph/expand executes_as reverse (hub role, 403 workloads) | 72.3 | 106.7 | 132.3 | 24 | 1.8 | 25.9 | met |
| GET /graph/expand target reverse ("*") | 112.8 | 157.8 | 167.4 | 30 | 6.3 | 23.9 | met |
| GET /graph/path workload -> a resource its role reaches | 417.6 | 893.3 | 906.5 | 128 | 31.8 | 34.0 | met |
| GET /graph/path workload -> "*" (most-granted role) | 361.4 | 541.6 | 710.4 | 54 | 3.1 | 49.8 | met |

Response sizes (every measured, warm and traced response; display maxima 150 nodes, 300 edges):

| Read | Server budgets (meta.budgets) | Largest response: nodes | edges | Within the display maxima | Truncated (bound_by: responses) |
|---|---|---:|---:|---|---|
| GET /graph workload forward | 500 nodes, 2000 edges | 99 | 115 | yes | none |
| GET /graph workload forward (most-granted role) | 500 nodes, 2000 edges | 105 | 146 | yes | none |
| GET /graph identity forward (roles) | 500 nodes, 2000 edges | 189 | 237 | no | assume_hops: 12 |
| GET /graph identity reverse (hub role) | 500 nodes, 2000 edges | 405 | 404 | no | none |
| GET /graph resource reverse | 500 nodes, 2000 edges | 500 | 499 | no | assume_hops: 38, nodes: 2 |
| GET /graph resource reverse (most-named bucket) | 500 nodes, 2000 edges | 500 | 499 | no | nodes: 53 |
| GET /graph external principal forward (lambda.amazonaws.com) | 500 nodes, 2000 edges | 500 | 499 | no | nodes: 53 |
| GET /graph/expand executes_as reverse (hub role, 403 workloads) | 500 nodes, 2000 edges | 100 | 100 | yes | none |
| GET /graph/expand target reverse ("*") | 500 nodes, 2000 edges | 100 | 100 | yes | none |
| GET /graph/path workload -> a resource its role reaches | 500 nodes, 2000 edges | 4 | 3 | yes | nodes: 2 |
| GET /graph/path workload -> "*" (most-granted role) | 500 nodes, 2000 edges | 0 | 0 | yes | nodes: 53 |

### Evidence (p95 target 300ms)

| Read | p50 ms | p95 ms | max ms | Statements | COUNT ms (traced) | Slowest statement ms (traced) | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| GET /evidence grant | 41.9 | 55.7 | 66.8 | 14 | 0.0 | 20.0 | met |
| GET /evidence assignment | 11.3 | 15.3 | 16.8 | 8 | 0.0 | 3.8 | met |
| GET /evidence relationship (executes_as) | 11.0 | 16.4 | 20.0 | 8 | 0.0 | 3.2 | met |
| GET /evidence relationship (cross-account can_assume) | 10.5 | 16.7 | 76.4 | 8 | 0.0 | 2.9 | met |
| GET /evidence workload presence | 19.7 | 28.0 | 73.4 | 9 | 0.0 | 13.4 | met |
| GET /evidence coverage | 9.1 | 12.4 | 15.4 | 5 | 0.0 | 2.2 | met |
| GET /evidence grouped edge (39 grants) | 53.2 | 73.6 | 87.7 | 15 | 0.0 | 21.7 | met |
| GET /evidence 50 claims (the D-79 maximum, many holders) | 67.7 | 86.0 | 88.5 | 14 | 0.0 | 22.5 | met |

### Changes (p95 target 500ms)

| Read | p50 ms | p95 ms | max ms | Statements | COUNT ms (traced) | Slowest statement ms (traced) | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| GET /workloads/:id/changes | 82.4 | 157.8 | 182.4 | 24 | 29.2 | 27.5 | met |
| GET /workloads/:id/changes (role switched) | 87.8 | 153.0 | 179.4 | 29 | 36.1 | 33.6 | met |
| GET /workloads/:id/changes (most-granted role) | 72.2 | 95.1 | 107.4 | 24 | 25.9 | 24.2 | met |
| GET /workloads/:id/changes kind=coverage | 14.5 | 19.9 | 30.1 | 14 | 2.3 | 3.0 | met |
| GET /identities/:id/changes (roles) | 72.7 | 109.0 | 143.8 | 22 | 24.3 | 35.5 | met |
| GET /identities/:id/changes (most grants) | 56.4 | 81.1 | 86.6 | 17 | 21.4 | 20.1 | met |
| GET /identities/:id/changes page 2 (most grants) | 67.7 | 94.9 | 138.3 | 23 | 20.4 | 19.0 | met |
| GET /resources/:id/changes | 118.5 | 168.1 | 210.5 | 21 | 46.3 | 50.3 | met |
| GET /resources/:id/changes ("*") | 297.9 | 381.8 | 439.1 | 28 | 91.1 | 149.5 | met |
| GET /resources/:id/changes (most-named bucket) | 228.4 | 278.6 | 325.6 | 28 | 106.5 | 118.2 | met |

