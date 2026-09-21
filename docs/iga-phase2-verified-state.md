# Agentic IGA — verified state

**Verified 2026-09-18 against the tree at `aab66b2`.** Every claim below was
checked against a file, a migration or a command, not against another document.
File and line references are the evidence; follow them rather than trusting this
page's present tense.

This document exists because the onboarding brief and
`SPEC-iga-phase2-graph.md` are both stale in ways that change what someone
picks up next.

---

## 1. Corrections to the onboarding brief

| The brief says | Verified |
| --- | --- |
| backend `254cb4d` | **`aab66b2`.** `254cb4d` is three commits back |
| migrations `001`–`023` applied | **`024` exists and is merged** — PR #56, `b47adeb` |
| Phase 2 "planned in detail, not started" | **P2-2 has partially landed** |
| "Head is 023; Phase 2 starts at 024" | `024` is taken. Phase 2 continues at **`025`** |

Everything else in the brief held up: the invariants, the trap list (with one
correction in §4), and the phase model.

## 2. What migration `024` actually did

It is `024_scan_evidence_durability.sql`, and it does **not** match the `024`
drafted in `SPEC-iga-phase2-graph.md` §3. Two of the four defects are closed,
by a different mechanism than the spec proposed.

| Defect | Spec's plan | What shipped |
| --- | --- | --- |
| **D1** coverage not per-run | new `cloud_scan_coverage` table | **Closed differently** — `cloud_scan_run.coverage jsonb`, stamped once at publish. Same intent, one column instead of a table |
| **D2** `Complete()` ignores parse failures | persist `parse_failures` / `statements_skipped` per surface | **OPEN** |
| **D3** observations die with inventory | subject FKs → `SET NULL` | **Closed**, and improved: also adds `subject_native_id` so a nulled row still says what it was evidence for |
| **D4** dedupe erases run confirmation | new `cloud_observation_run` table | **OPEN** |
| **§2.9** workspace-qualified provenance FKs | `UNIQUE (workspace_id, id)` on `cloud_scan_run`, `cloud_observation` | **OPEN** — zero occurrences in `024` |

Verified: neither `cloud_scan_coverage` nor `cloud_observation_run` is created
by any migration.

### The consequence nobody has written down yet

**`024`'s chosen mechanism cannot close D2 as it stands.** The per-run report is
a serialised `ScanCoverage`, and `ScanCoverage` does not carry the counters:

- `ParseFailures` / `StatementsSkipped` are declared in
  `services/cloud_aws_permission_scan.go:94,97` — the scanner's own result type,
  not the coverage model.
- `ScanCoverage.Complete()` (`models/cloud_discovery.go:296`) iterates surface
  states only. Read the body: `NotSelected`/`Unsupported` continue, `Reached`
  increments, anything else returns false. **No counter is consulted.**

So closing D2 means either moving those counters into `ScanCoverage` before it
is serialised into `cloud_scan_run.coverage`, or adding the per-surface table
after all. That is a real design decision and it is currently unmade.

### Tests that exist

`tests/integration/cloud_scan_evidence_durability_test.go`:

- `TestPerRunCoverageSurvivesALaterRun` — D1
- `TestSetCoverageRefusedOnAnUnpublishedRun` — publish guard
- `TestObservationSurvivesItsSubjectBeingReconciledAway` — D3

D2 and D4 have no tests, which is consistent: they are not implemented.

## 3. Phase 2 task board, verified

| Task | Spec status | Verified status |
| --- | --- | --- |
| P2-1 CI boundary check | to do | `scripts/ci-iga-isolation-check.sh` exists (Phase 1); the `internal/igagraph` clause is not addable yet — no such package |
| **P2-2** evidence/coverage fixes | "first, blocking" | **Half done.** D1, D3 closed. D2, D4, §2.9 open |
| P2-3 `sourcekey.go` | to do | **Not started** — `internal/igagraph/` does not exist |
| **P2-4** make the upserts upsert | "testable immediately" | **Not started.** All five at `repository/iga_repository.go:616-629` are still bare `db.Create` — `UpsertIdentityAccount`, `UpsertCredential`, `UpsertResource`, `UpsertEntitlement`, `UpsertAccessEdge`. Verified by reading the bodies |
| P2-5 models + migrations `025`–`029` | to do | Not started |
| P2-6 projector | to do | Not started — no `iga_projection_service.go`, no `iga_graph_repository.go`, no `iga_projection_job_repository.go` |
| P2-7 reconciliation | to do | Not started |
| P2-8…P2-11 | to do | Not started |

`go build ./...` is clean at `aab66b2`.

## 4. Traps — re-verified

Still true, and each re-checked rather than copied forward:

- **Canonical tables have no recognition key.** Unchanged. `025` still owes it.
- **All five `Upsert*` are bare `Create`.** Confirmed at
  `repository/iga_repository.go:616-629`.
- **`ScanCoverage.Complete()` does not check parse failures.** Confirmed by
  reading the body at `models/cloud_discovery.go:296`.
- **Scan run status is `published`, not `complete`.** Unchanged.
- **One `cloud_permission` row is (identity, statement, resource).** Unchanged.

One trap in the brief now needs qualifying:

- **"Coverage is not per-run"** — *was* true; `024` fixed it. Coverage is now
  per-run on `cloud_scan_run.coverage`. `cloud_connector.coverage` is still
  overwritten by every scan and must still never be an input to a decision about
  absence, but the per-run report now exists to read instead.
- **"Observations are deleted by inventory churn"** — *was* true; `024` fixed
  it. The subject FKs are `SET NULL`, and `subject_native_id` keeps the row
  legible.

## 5. What to pick up next

Two candidates, and they are independent.

**Finish P2-2.** D2, D4 and §2.9 are open, and the spec's §2.7 `canEnd()` — the
single most important function in the phase — depends on all three:

- condition 2 needs D2 (per-surface counters that are actually persisted);
- condition 3 needs D4 (`cloud_observation_run`, because dedupe means the
  absence of a fresh observation proves nothing);
- §2.9 is the composite-FK target every later provenance reference needs.

Building the projector against a half-finished `024` means `canEnd()` cannot be
written correctly, and it is the function whose failure mode is "a credentials
outage renders as a successful access cleanup".

**Or do P2-4 first.** It is genuinely independent of AWS, testable today against
real Postgres, and it is the exit gate's first clause. It also touches the seven
known-failing `TestIGA*` tests — record their count before starting so a
regression is distinguishable from the inherited failure.

## 6. Before writing the next spec claim

The two habits from the brief, restated because this document exists as a result
of the first one being skipped:

**Verify before asserting.** The spec's §3 describes a `024` that was never
written. A table headed "Decision" reads as a description of a real system.

**Check every test for vacuity.** Remove the fix, confirm the test fails. The
Phase 1 deletion test passed with its fix removed because EKS was denied and the
coverage check was already false for an unrelated reason.
