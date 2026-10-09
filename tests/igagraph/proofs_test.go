package igagraph_test

// Proofs of the mechanisms the spec KEEPS from the graph branch (§6.1):
// execution-role state, retire -> suspend -> restore -> reconfirm, and the
// AlreadyPublished replay. Each exists because the failure it guards against
// is invisible: the graph still reads plausibly afterwards. Every fixture is
// real cloud_* rows through the real igagraph.Load.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

/* ===================== execution role not in scan ======================== */

// A workload whose configured role is missing from the current scan shows
// not_in_scan WITH THE ROLE'S ARN, and PRESERVES the edge an earlier run
// discovered -- stale, never deleted, last_confirmed_at unmoved.
func TestProof2NotInScanPreservesPriorEdge(t *testing.T) {
	f := newFixture(t)
	est := newEstate(f, "arn:aws:iam::1234:role/refund-lambda-role", "AROA5XK7QEXAMPLE")
	est.seed(1)
	run1 := f.publishedRun(f.connector, 1, cleanCoverage(region))
	f.mustProject(est.load(run1))

	var edgeID uuid.UUID
	var edgeState string
	if err := f.gorm.Raw(`SELECT id, state FROM iga_relationship WHERE relationship_type='executes_as'`).
		Row().Scan(&edgeID, &edgeState); err != nil {
		t.Fatalf("the prior edge must exist for this proof to mean anything: %v", err)
	}
	var confirmedBefore time.Time
	f.gorm.Raw(`SELECT last_confirmed_at FROM iga_relationship WHERE id = ?`, edgeID).Scan(&confirmedBefore)

	// Run 2: the workload moves to generation 2; its ROLE does not. IAM is
	// denied, which is what makes this "we could not look" rather than "gone".
	partial := cleanCoverage(region)
	partial[models.SurfaceIAMRoles] = denied()
	partial[models.SurfaceIAMUsers] = denied()
	if err := f.gorm.Exec(`UPDATE cloud_workload SET last_seen_generation = 2 WHERE id = ?`, est.lambdaID).Error; err != nil {
		t.Fatal(err)
	}
	f.clock = f.clock.Add(time.Hour)
	run2 := f.publishedRun(f.connector, 2, partial)
	snap2 := est.load(run2)
	if len(snap2.Identities) != 0 {
		t.Fatalf("run 2 should not have read the role, got %d identities", len(snap2.Identities))
	}
	f.mustProject(snap2)

	var state, arn string
	f.gorm.Raw(`SELECT execution_role_state, execution_role_arn FROM iga_workload`).Row().Scan(&state, &arn)
	if state != models.ExecRoleNotInScan || arn != est.roleARN {
		t.Errorf("execution role = (%q, %q), want (not_in_scan, %s)", state, arn, est.roleARN)
	}
	var nowState string
	var confirmedAfter time.Time
	var validTo *time.Time
	if err := f.gorm.Raw(`SELECT state, last_confirmed_at, valid_to FROM iga_relationship WHERE id = ?`,
		edgeID).Row().Scan(&nowState, &confirmedAfter, &validTo); err != nil {
		t.Fatalf("the prior edge was DELETED; it must be preserved: %v", err)
	}
	if nowState != models.RelStale || validTo != nil {
		t.Errorf("edge = %s (valid_to %v), want stale with no valid_to", nowState, validTo)
	}
	if !confirmedAfter.Equal(confirmedBefore) {
		t.Errorf("last_confirmed_at moved (%s -> %s); a scan that could not look must not re-confirm",
			confirmedBefore, confirmedAfter)
	}
}

// With NO role configured the state is `none` and no ARN is claimed -- never
// confused with not_in_scan.
func TestProof2NoRoleConfiguredIsNone(t *testing.T) {
	f := newFixture(t)
	est := newEstate(f, "arn:aws:iam::1234:role/unused", "AROAUNUSEDUNUSEDUNUS")
	est.noRole = true
	est.seed(1)
	run := f.publishedRun(f.connector, 1, cleanCoverage(region))
	f.mustProject(est.load(run))

	var state, arn string
	f.gorm.Raw(`SELECT execution_role_state, execution_role_arn FROM iga_workload`).Row().Scan(&state, &arn)
	if state != models.ExecRoleNone || arn != "" {
		t.Errorf("execution role = (%q, %q), want (none, '')", state, arn)
	}
}

/* ============ retire -> suspend -> restore -> reconfirm ================== */

// A role confirmed absent retires; a person's asserted association with it is
// PRESERVED but suspended. The same UniqueID returning restores the SAME row
// -- id and first_seen_at intact -- and the association comes back
// pending_reconfirmation, never straight to active. Lifecycle events record
// both transitions (B24).
func TestProof3RetirementSuspensionRestoration(t *testing.T) {
	f := newFixture(t)
	est := newEstate(f, "arn:aws:iam::1234:role/analyst", "AROAANALYSTANALYST01")
	est.seed(1)
	run1 := f.publishedRun(f.connector, 1, cleanCoverage(region))
	f.mustProject(est.load(run1))

	var identityID uuid.UUID
	var firstSeen time.Time
	f.gorm.Raw(`SELECT id, first_seen_at FROM iga_identity_accounts WHERE account_kind='iam_role'`).
		Row().Scan(&identityID, &firstSeen)

	f.exec(`INSERT INTO iga_external_principal
	          (workspace_id, issuer, subject_claim, mechanism, source_key,
	           resolved_identity_account_id, resolution_basis, resolved_by, resolution_state)
	        VALUES ($1, 'token.actions.githubusercontent.com', 'repo:acme/deploy:ref:refs/heads/main',
	                'oidc', $2, $3, 'asserted', 'user-42', 'active')`,
		f.workspace, "github\x1frepo:acme/deploy", identityID)

	// Run 2: complete coverage, nothing seen -- the role is genuinely gone.
	f.clock = f.clock.Add(24 * time.Hour)
	run2 := f.publishedRun(f.connector, 2, cleanCoverage(region))
	f.mustProject(est.load(run2))

	var lifecycle, retiredReason string
	f.gorm.Raw(`SELECT lifecycle, retired_reason FROM iga_identity_accounts WHERE id = ?`,
		identityID).Row().Scan(&lifecycle, &retiredReason)
	if lifecycle != models.IGALifecycleRetired || retiredReason != models.RetiredUnsupported {
		t.Fatalf("role = %s/%s, want retired/unsupported", lifecycle, retiredReason)
	}
	var resState string
	var resTarget *uuid.UUID
	f.gorm.Raw(`SELECT resolution_state, resolved_identity_account_id FROM iga_external_principal`).
		Row().Scan(&resState, &resTarget)
	if resState != models.ResolutionSuspended || resTarget == nil || *resTarget != identityID {
		t.Errorf("assertion = %s -> %v, want suspended, still pointing at the retired row", resState, resTarget)
	}

	// Run 3: the SAME role returns -- same ARN, same UniqueID.
	f.clock = f.clock.Add(24 * time.Hour)
	est.seed(3)
	run3 := f.publishedRun(f.connector, 3, cleanCoverage(region))
	f.mustProject(est.load(run3))

	if n := f.scalar(`SELECT count(*) FROM iga_identity_accounts WHERE account_kind='iam_role'`); n != 1 {
		t.Fatalf("%d identity rows; a returning object must be restored, not duplicated", n)
	}
	var backLifecycle string
	var backFirstSeen time.Time
	f.gorm.Raw(`SELECT lifecycle, first_seen_at FROM iga_identity_accounts WHERE id = ?`,
		identityID).Row().Scan(&backLifecycle, &backFirstSeen)
	if backLifecycle != models.IGALifecycleActive || !backFirstSeen.Equal(firstSeen) {
		t.Errorf("restored = %s first_seen %s, want active and unchanged %s", backLifecycle, backFirstSeen, firstSeen)
	}
	f.gorm.Raw(`SELECT resolution_state FROM iga_external_principal`).Scan(&resState)
	if resState != models.ResolutionPendingReconfirmation {
		t.Errorf("resolution_state = %q, want pending_reconfirmation", resState)
	}

	// B24: the history survives the node row being overwritten -- retired
	// and restored, each with its rev and run.
	var events []models.IGALifecycleEvent
	f.gorm.Where("identity_account_id = ?", identityID).Order("rev").Find(&events)
	var kinds []string
	for _, e := range events {
		kinds = append(kinds, e.Event+":"+e.Reason)
	}
	want := []string{"first_seen:", "retired:unsupported", "restored:"}
	if len(kinds) != len(want) {
		t.Fatalf("lifecycle events = %v, want %v", kinds, want)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Fatalf("lifecycle events = %v, want %v", kinds, want)
		}
	}
	if events[1].ScanRunID != run2.ID || events[2].ScanRunID != run3.ID {
		t.Error("lifecycle events are not stamped with the run that made each transition")
	}
}

/* ============== kill after commit -> AlreadyPublished ==================== */

// The worker commits the graph and dies before completing the job. The replay
// finds its own publication, WRITES NOTHING, and the job ends complete with
// the barrier idle. A `<=` generation guard got this wrong: after a committed
// pass the watermark EQUALS this generation, so the replay failed forever.
func TestProof4KillAfterCommitReplaysAsAlreadyPublished(t *testing.T) {
	f := newFixture(t)
	est := newEstate(f, "arn:aws:iam::1234:role/refund-lambda-role", "AROA5XK7QEXAMPLE")
	est.seed(1)
	run := f.publishedRun(f.connector, 1, cleanCoverage(region))
	f.mustProject(est.load(run))

	var rev int64
	var pubCount int
	f.gorm.Raw(`SELECT count(*), coalesce(max(rev),0) FROM iga_publication WHERE scan_run_id = ?`,
		run.ID).Row().Scan(&pubCount, &rev)
	if pubCount != 1 {
		t.Fatalf("want exactly one publication for the run, got %d", pubCount)
	}
	shape := func() int {
		return f.scalar(`SELECT count(*) FROM iga_access_edges`) +
			f.scalar(`SELECT count(*) FROM iga_relationship`) +
			f.scalar(`SELECT count(*) FROM iga_policy_assignment`) +
			f.scalar(`SELECT count(*) FROM iga_lifecycle_event`)
	}
	before := shape()

	err := f.project(est.load(run))
	var replay *igagraph.AlreadyPublished
	if !errors.As(err, &replay) {
		t.Fatalf("replay must report AlreadyPublished, got %v", err)
	}
	if replay.Rev != rev {
		t.Errorf("replay names rev %d, want %d", replay.Rev, rev)
	}
	if n := f.scalar(`SELECT count(*) FROM iga_publication WHERE scan_run_id = $1`, run.ID); n != 1 {
		t.Errorf("replay published again (%d rows)", n)
	}
	if after := shape(); after != before {
		t.Errorf("replay changed the graph: %d -> %d rows", before, after)
	}

	// The service settles it as SUCCESS: job complete, barrier idle.
	jobID := uuid.New()
	f.exec(`INSERT INTO iga_projection_job (id, workspace_id, scan_run_id, connector_id, generation)
	        VALUES ($1, $2, $3, $4, 1)`, jobID, f.workspace, run.ID, f.connector)
	f.exec(`INSERT INTO iga_pipeline_lease (workspace_id, state, holder, scan_run_id, expires_at, version)
	        VALUES ($1, 'projecting', $2, $3, now() + interval '15 minutes', 7)`,
		f.workspace, models.PipelineJobHolder(jobID), run.ID)
	jobs := repositories.NewIGAProjectionJobRepository(f.gorm)
	job, jerr := jobs.Claim("w1", time.Minute, time.Now())
	if jerr != nil || job == nil {
		t.Fatalf("claim: %v %v", job, jerr)
	}
	if err := projectionServiceAs(f, "w1").CompleteAndReleaseForTest(context.Background(), job, 7); err != nil {
		t.Fatalf("completeAndRelease after replay: %v", err)
	}
	if got := jobStatus(t, f, job.ID); got != models.ProjectionComplete {
		t.Errorf("job = %q, want complete", got)
	}
	if got := barrierState(t, f); got != models.PipelineIdle {
		t.Errorf("barrier = %q, want idle", got)
	}
}
