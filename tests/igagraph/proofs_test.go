package igagraph_test

// P2-0 proofs 2, 3 and 4 (§6.1). Each one exists because the failure it
// guards against is invisible: the graph still reads plausibly afterwards.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

/* ===================== PROOF 2: execution role not in scan ================ */

// A workload whose configured role is missing from the current scan shows
// not_in_scan WITH THE ROLE'S ARN, writes no newly-confirmed executes_as, and
// PRESERVES the edge an earlier run discovered.
//
// The fixture seeds the prior edge deliberately: starting empty cannot tell
// preservation from deletion, because both look like "no edge".
func TestProof2NotInScanPreservesPriorEdge(t *testing.T) {
	f := newFixture(t)
	gx := func(q string, a ...any) {
		if err := f.gorm.Exec(q, a...).Error; err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	const (
		roleARN   = "arn:aws:iam::1234:role/refund-lambda-role"
		lambdaARN = "arn:aws:lambda:eu-central-1:1234:function:refund-processor"
	)
	roleID, lambdaID := uuid.New(), uuid.New()

	// Real cloud_* inventory, so this runs through the REAL igagraph.Load --
	// which is what resolves the ARN of an identity a workload references but
	// this run did not read. A hand-built snapshot skips that and cannot
	// exercise not_in_scan at all.
	gx(`INSERT INTO cloud_identity
	      (id, workspace_id, connector_id, kind, native_id, name, attrs, last_seen_generation)
	    VALUES (?, ?, ?, 'iam_role', ?, 'refund-lambda-role', ?, 1)`,
		roleID, f.workspace, f.connector, roleARN, `{"unique_id":"AROA5XK7QEXAMPLE"}`)
	gx(`INSERT INTO cloud_workload
	      (id, workspace_id, connector_id, identity_id, runtime_kind, native_id, name, region, last_seen_generation)
	    VALUES (?, ?, ?, ?, 'lambda_function', ?, 'refund-processor', ?, 1)`,
		lambdaID, f.workspace, f.connector, roleID, lambdaARN, region)

	// Run 1: everything read. The executes_as edge is created and current.
	run1 := f.publishedRun(f.connector, 1, cleanCoverage(region))
	snap1, err := igagraph.Load(t.Context(), f.gorm, run1.ID)
	if err != nil {
		t.Fatalf("load run 1: %v", err)
	}
	f.mustProject(snap1)

	var edgeID uuid.UUID
	var edgeState string
	if err := f.gorm.Raw(`SELECT id, state FROM iga_relationship
	                       WHERE relationship_type='executes_as'`).
		Row().Scan(&edgeID, &edgeState); err != nil {
		t.Fatalf("the prior edge must exist for this proof to mean anything: %v", err)
	}
	if edgeState != models.RelCurrent {
		t.Fatalf("prior edge state = %q, want current", edgeState)
	}
	var confirmedBefore time.Time
	f.gorm.Raw(`SELECT last_confirmed_at FROM iga_relationship WHERE id = ?`, edgeID).
		Scan(&confirmedBefore)
	var workloadState string
	f.gorm.Raw(`SELECT execution_role_state FROM iga_workload`).Scan(&workloadState)
	if workloadState != models.ExecRoleResolved {
		t.Fatalf("run 1 execution_role_state = %q, want resolved", workloadState)
	}

	// Run 2: the workload moves to generation 2; its ROLE does not, so the
	// role is absent from this run's snapshot while still referenced. IAM is
	// denied, which is what makes this "we could not look" rather than "gone".
	partial := cleanCoverage(region)
	partial[models.SurfaceIAMRoles] = denied()
	partial[models.SurfaceIAMUsers] = denied()

	gx(`UPDATE cloud_workload SET last_seen_generation = 2 WHERE id = ?`, lambdaID)
	f.clock = f.clock.Add(time.Hour)
	run2 := f.publishedRun(f.connector, 2, partial)
	snap2, err := igagraph.Load(t.Context(), f.gorm, run2.ID)
	if err != nil {
		t.Fatalf("load run 2: %v", err)
	}
	if len(snap2.Identities) != 0 {
		t.Fatalf("run 2 should not have read the role, got %d identities", len(snap2.Identities))
	}
	f.mustProject(snap2)

	// The workload says exactly which role it runs as, and why there is no
	// edge -- not silence, which would read as "no role configured".
	var state, arn string
	if err := f.gorm.Raw(`SELECT execution_role_state, execution_role_arn FROM iga_workload`).
		Row().Scan(&state, &arn); err != nil {
		t.Fatalf("read workload: %v", err)
	}
	if state != models.ExecRoleNotInScan {
		t.Errorf("execution_role_state = %q, want not_in_scan", state)
	}
	if arn != roleARN {
		t.Errorf("execution_role_arn = %q, want the role it runs as (%s)", arn, roleARN)
	}

	// THE PRIOR EDGE SURVIVES. Not deleted, and not silently re-confirmed.
	var nowState string
	var confirmedAfter time.Time
	var validTo *time.Time
	if err := f.gorm.Raw(`SELECT state, last_confirmed_at, valid_to FROM iga_relationship WHERE id = ?`,
		edgeID).Row().Scan(&nowState, &confirmedAfter, &validTo); err != nil {
		t.Fatalf("the prior edge was DELETED; it must be preserved: %v", err)
	}
	if nowState != models.RelStale {
		t.Errorf("edge state = %q, want stale while coverage is incomplete", nowState)
	}
	if validTo != nil {
		t.Error("a stale edge must not carry valid_to; it has not ended")
	}
	if !confirmedAfter.Equal(confirmedBefore) {
		t.Errorf("last_confirmed_at moved (%s -> %s); a scan that could not look must not re-confirm",
			confirmedBefore, confirmedAfter)
	}
}

// The converse: with NO role configured at all, the state is `none` and no ARN
// is claimed. This is what stops not_in_scan being confused with "none".
func TestProof2NoRoleConfiguredIsNone(t *testing.T) {
	f := newFixture(t)
	est := newEstate("arn:aws:iam::1234:role/unused", "AROAUNUSEDUNUSEDUNUS")
	est.workload.IdentityID = nil // no execution role

	run := f.publishedRun(f.connector, 1, cleanCoverage(region))
	snap := est.snapshot(f, run, cleanCoverage(region))
	f.mustProject(snap)

	var state, arn string
	f.gorm.Raw(`SELECT execution_role_state, execution_role_arn FROM iga_workload
	             WHERE source_key = ?`, igagraph.WorkloadKey(est.workload)).Row().Scan(&state, &arn)
	if state != models.ExecRoleNone {
		t.Errorf("execution_role_state = %q, want none", state)
	}
	if arn != "" {
		t.Errorf("execution_role_arn = %q, want empty: no role is configured", arn)
	}
}

/* ============ PROOF 3: retire -> suspend -> restore -> reconfirm ========== */

// A role confirmed absent retires; a person's asserted association with it is
// PRESERVED but suspended. The same UniqueID returning restores the SAME row
// -- id and first_seen_at intact -- and the association comes back
// pending_reconfirmation, never straight to active.
func TestProof3RetirementSuspensionRestoration(t *testing.T) {
	f := newFixture(t)
	const roleARN = "arn:aws:iam::1234:role/analyst"
	const uniqueID = "AROAANALYSTANALYST01"
	est := newEstate(roleARN, uniqueID)

	run1 := f.publishedRun(f.connector, 1, cleanCoverage(region))
	f.mustProject(est.snapshot(f, run1, cleanCoverage(region)))

	var identityID uuid.UUID
	var firstSeen time.Time
	f.gorm.Raw(`SELECT id, first_seen_at FROM iga_identity_accounts WHERE account_kind='iam_role'`).
		Row().Scan(&identityID, &firstSeen)

	// A human's decision: this external principal IS that role.
	f.exec(`INSERT INTO iga_external_principal
	          (workspace_id, issuer, subject_claim, mechanism, source_key,
	           resolved_identity_account_id, resolution_basis, resolved_by, resolution_state)
	        VALUES ($1, 'token.actions.githubusercontent.com', 'repo:acme/deploy:ref:refs/heads/main',
	                'oidc', $2, $3, 'asserted', 'user-42', 'active')`,
		f.workspace, "github\x1frepo:acme/deploy", identityID)

	// Run 2: complete coverage, the role is genuinely gone.
	f.clock = f.clock.Add(24 * time.Hour)
	run2 := f.publishedRun(f.connector, 2, cleanCoverage(region))
	var conn models.CloudConnector
	f.gorm.First(&conn, "id = ?", f.connector)
	f.mustProject(&igagraph.Snapshot{
		Run: run2, Connector: conn, Generation: 2,
		Coverage: cleanCoverage(region), ConfirmedBy: map[igagraph.SubjectRef][]uuid.UUID{},
	})

	var lifecycle, retiredReason string
	f.gorm.Raw(`SELECT lifecycle, retired_reason FROM iga_identity_accounts WHERE id = ?`,
		identityID).Row().Scan(&lifecycle, &retiredReason)
	if lifecycle != models.IGALifecycleRetired || retiredReason != models.RetiredUnsupported {
		t.Fatalf("role = %s/%s, want retired/unsupported", lifecycle, retiredReason)
	}

	// The decision is PRESERVED and suspended -- still pointing at the retired
	// row, so it stays explicable -- not deleted and not still in force.
	var resState string
	var resTarget *uuid.UUID
	f.gorm.Raw(`SELECT resolution_state, resolved_identity_account_id
	             FROM iga_external_principal`).Row().Scan(&resState, &resTarget)
	if resState != models.ResolutionSuspended {
		t.Errorf("resolution_state = %q, want suspended", resState)
	}
	if resTarget == nil || *resTarget != identityID {
		t.Error("a suspended assertion must keep pointing at the retired row")
	}

	// Run 3: the SAME role comes back -- same ARN, same UniqueID.
	f.clock = f.clock.Add(24 * time.Hour)
	run3 := f.publishedRun(f.connector, 3, cleanCoverage(region))
	est3 := newEstate(roleARN, uniqueID)
	f.mustProject(est3.snapshot(f, run3, cleanCoverage(region)))

	// RESTORED: the same row, not a new object.
	var count int
	f.gorm.Raw(`SELECT count(*) FROM iga_identity_accounts WHERE account_kind='iam_role'`).Scan(&count)
	if count != 1 {
		t.Fatalf("%d identity rows; a returning object must be restored, not duplicated", count)
	}
	var backLifecycle string
	var backFirstSeen time.Time
	f.gorm.Raw(`SELECT lifecycle, first_seen_at FROM iga_identity_accounts WHERE id = ?`,
		identityID).Row().Scan(&backLifecycle, &backFirstSeen)
	if backLifecycle != models.IGALifecycleActive {
		t.Errorf("restored role lifecycle = %q, want active", backLifecycle)
	}
	if !backFirstSeen.Equal(firstSeen) {
		t.Errorf("first_seen_at moved (%s -> %s); a restoration keeps the object's age",
			firstSeen, backFirstSeen)
	}

	// The human's decision does NOT come back automatically.
	f.gorm.Raw(`SELECT resolution_state FROM iga_external_principal`).Scan(&resState)
	if resState != models.ResolutionPendingReconfirmation {
		t.Errorf("resolution_state = %q, want pending_reconfirmation: the same UniqueID "+
			"returning is a reason to ask, not to assume", resState)
	}
}

/* ============== PROOF 4: kill after commit -> AlreadyPublished ============ */

// The worker commits the graph and dies before completing the job. Recovery
// reclaims `projecting`, the replay finds its own publication, WRITES NOTHING,
// and the job ends complete with the barrier idle.
//
// This is the case a `<=` generation guard got wrong: after a committed pass
// the watermark EQUALS this generation, so it reported a successful replay as
// obsolete and failed the job on every retry, forever.
func TestProof4KillAfterCommitReplaysAsAlreadyPublished(t *testing.T) {
	f := newFixture(t)
	est := newEstate("arn:aws:iam::1234:role/refund-lambda-role", "AROA5XK7QEXAMPLE")
	run := f.publishedRun(f.connector, 1, cleanCoverage(region))

	// The graph transaction commits.
	f.mustProject(est.snapshot(f, run, cleanCoverage(region)))

	var rev int64
	var pubCount int
	f.gorm.Raw(`SELECT count(*), coalesce(max(rev),0) FROM iga_publication WHERE scan_run_id = ?`,
		run.ID).Row().Scan(&pubCount, &rev)
	if pubCount != 1 {
		t.Fatalf("want exactly one publication for the run, got %d", pubCount)
	}
	shapeBefore := f.scalar(`SELECT count(*) FROM iga_access_edges`) +
		f.scalar(`SELECT count(*) FROM iga_relationship`)

	// ...and the worker dies here, before completeAndRelease.

	// The replay: same run, same generation.
	err := f.project(est.snapshot(f, run, cleanCoverage(region)))
	var replay *igagraph.AlreadyPublished
	if !errors.As(err, &replay) {
		t.Fatalf("replay must report AlreadyPublished, got %v", err)
	}
	if replay.Rev != rev {
		t.Errorf("replay names rev %d, want %d", replay.Rev, rev)
	}

	// IT WROTE NOTHING.
	f.gorm.Raw(`SELECT count(*) FROM iga_publication WHERE scan_run_id = ?`, run.ID).Scan(&pubCount)
	if pubCount != 1 {
		t.Errorf("replay published again (%d rows); UNIQUE(workspace,scan_run) exists for this", pubCount)
	}
	shapeAfter := f.scalar(`SELECT count(*) FROM iga_access_edges`) +
		f.scalar(`SELECT count(*) FROM iga_relationship`)
	if shapeAfter != shapeBefore {
		t.Errorf("replay changed the graph: %d -> %d edges", shapeBefore, shapeAfter)
	}

	// And the service settles it as SUCCESS: job complete, barrier idle.
	f.exec(`INSERT INTO iga_projection_job (workspace_id, scan_run_id, connector_id, generation)
	        VALUES ($1, $2, $3, 1)`, f.workspace, run.ID, f.connector)
	f.exec(`INSERT INTO iga_pipeline_lease (workspace_id, state, holder, scan_run_id, expires_at, version)
	        VALUES ($1, 'projecting', 'w1', $2, now() + interval '15 minutes', 7)`, f.workspace, run.ID)
	jobs := repositories.NewIGAProjectionJobRepository(f.gorm)
	job, jerr := jobs.Claim("w1", time.Minute, time.Now())
	if jerr != nil || job == nil {
		t.Fatalf("claim: %v %v", job, jerr)
	}
	if err := projectionServiceAs(f, "w1").
		CompleteAndReleaseForTest(context.Background(), job, 7); err != nil {
		t.Fatalf("completeAndRelease after replay: %v", err)
	}
	if got := jobStatus(t, f, job.ID); got != models.ProjectionComplete {
		t.Errorf("job = %q, want complete: a replay of a committed pass is SUCCESS", got)
	}
	if got := barrierState(t, f); got != models.PipelineIdle {
		t.Errorf("barrier = %q, want idle", got)
	}
}

// Keep the imports honest for fixtures that need them.
var _ = json.Marshal
var _ = pq.StringArray{}
