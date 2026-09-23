package integration

// T2.3 /coverage (SPEC-iga-phase2-graph.md §5.3 l.5763, §2.14.13; D-57, D-71,
// D-72), the parts a single-run revision cannot exercise: a revision that
// stands on TWO runs of one account, the bound on the since walk, and the
// failed call named on every denied surface -- including the ones no
// scanner's surfaceResult builds.

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/smithy-go"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// A revision built from two runs of one account: each surface comes from the
// NEWEST run that speaks for it, and an older run speaks only for the
// partitions still standing on it.
//
// ap-south-2 (outside the built-in 17, holding no compute) leaves the
// selection WITHOUT passing through PATCH -- so no selection history records
// it -- and the next scan does not attempt it at all: its partitions keep the
// first run as their watermark, and the revision stands on both runs.
func TestP2S2CoverageMergesTheRunsTheRevisionStandsOn(t *testing.T) {
	l := newP2Lab(t, "p2-s2-coverage-merge", true)
	a := l.account(accountA, "us-east-1", "ap-south-2")
	role := a.role("fn-role", "AROAS2MERGEXXXXXXXXX")
	a.lambda("us-east-1", "east-fn", role)
	read := l.api()

	// Run 1: roles read only in part (GetRole refused), and the permission
	// scanner dies before producing anything (it cannot build an IAM client:
	// this verifier makes no session) -- a connector-wide permission_scan
	// stand-in.
	a.iam.fail["GetRole"] = denied("iam:GetRole")
	run1 := s2ScanWith(l, a, "s2-merge-1", func(_ *services.AWSIAMScanner, p *services.AWSPermissionScanner, _ *services.AWSWorkloadScanner) {
		p.WithIAMAPI(nil)
	})
	if run1.Status != models.CloudScanRunPublished {
		t.Fatalf("run 1 = %s (%s)", run1.Status, run1.LastError)
	}
	l.project("s2-merge-projector-1")
	cov1 := s2Coverage(run1).Surfaces
	if cov1[models.SurfaceIAMRoles].State != models.CloudCoveragePartial ||
		cov1[models.SurfacePermissionScan].State != models.CloudCoverageDenied ||
		cov1["lambda:ap-south-2"].State != models.CloudCoverageReached {
		t.Fatalf("setup: run 1 roles %+v, permission_scan %+v, lambda:ap-south-2 %+v",
			cov1[models.SurfaceIAMRoles], cov1[models.SurfacePermissionScan], cov1["lambda:ap-south-2"])
	}

	l.db.Exec(`UPDATE cloud_connector SET attrs = jsonb_set(attrs, '{regions}', '["us-east-1"]') WHERE id = ?`, a.conn)
	delete(a.iam.fail, "GetRole")
	time.Sleep(5 * time.Millisecond)
	run2 := l.scanAndProject(a)
	cov2 := s2Coverage(run2).Surfaces
	if _, ok := cov2["lambda:ap-south-2"]; ok {
		t.Fatalf("setup: run 2 attempted ap-south-2: %v", cov2["lambda:ap-south-2"])
	}
	if _, ok := cov2["compute:ap-south-2"]; ok {
		t.Fatalf("setup: run 2 wrote a stand-in for ap-south-2: %v", cov2["compute:ap-south-2"])
	}
	if cov2[models.SurfaceIAMRoles].State != models.CloudCoverageReached {
		t.Fatalf("setup: run 2 roles = %+v", cov2[models.SurfaceIAMRoles])
	}

	acc := s2CoverageAccount(t, read, "", a)
	runs := digl(acc, "runs")
	if len(runs) != 2 || digs(runs[0]) != refOf("cloud_scan_run", run2.ID) || digs(runs[1]) != refOf("cloud_scan_run", run1.ID) {
		t.Fatalf("/coverage runs = %v, want [run 2, run 1] (newest first)", runs)
	}
	// A surface both runs carry comes from the NEWEST: roles are reached now,
	// though the older run -- still the watermark of ap-south-2's executes_as
	// partitions, which require iam_roles -- read them in part.
	roles := s2Surface(t, acc, models.SurfaceIAMRoles)
	if digs(roles, "state") != models.CloudCoverageReached || digs(roles, "run") != refOf("cloud_scan_run", run2.ID) {
		t.Fatalf("iam_roles = %v, want reached, from run 2", roles)
	}
	// What only the older run read, and a partition still stands on, is
	// shown from it.
	old := s2Surface(t, acc, "lambda:ap-south-2")
	if digs(old, "state") != models.CloudCoverageReached || digs(old, "run") != refOf("cloud_scan_run", run1.ID) {
		t.Fatalf("lambda:ap-south-2 = %v, want reached, from run 1", old)
	}
	// The older run's connector-wide failure is NOT: permission_scan vetoed
	// partitions run 2 has since re-read, and ap-south-2's partitions -- all
	// that stand on run 1 -- never depended on it.
	for _, s := range digl(acc, "surfaces") {
		if digs(s, "surface") == models.SurfacePermissionScan {
			t.Fatalf("/coverage shows run 1's permission_scan %v, a gap the revision no longer has", s)
		}
	}
	if lam := s2Surface(t, acc, "lambda:us-east-1"); digs(lam, "run") != refOf("cloud_scan_run", run2.ID) {
		t.Fatalf("lambda:us-east-1 = %v, want from run 2", lam)
	}
	// A surface no partition names at all is the newest run's word, shown
	// from it whatever the partitions say.
	for _, name := range []string{models.SurfaceOIDCProviders, "activity"} {
		if s := s2Surface(t, acc, name); digs(s, "run") != refOf("cloud_scan_run", run2.ID) {
			t.Fatalf("%s = %v, want from run 2", name, s)
		}
	}

	// A watermark whose partition this build does not produce (a kind renamed
	// since, D-60) cannot be scoped: the older run it names is shown whole --
	// an old gap shown claims less; a hidden one would claim more.
	l.db.Exec(`UPDATE iga_projection_state SET partition_key = 'renamed|' || partition_key
	            WHERE workspace_id = ? AND last_run_id = ? AND partition_key LIKE '%ap-south-2%'
	              AND id = (SELECT id FROM iga_projection_state
	                         WHERE workspace_id = ? AND last_run_id = ? AND partition_key LIKE '%ap-south-2%'
	                         ORDER BY id LIMIT 1)`, l.ws, run1.ID, l.ws, run1.ID)
	perm := s2Surface(t, s2CoverageAccount(t, read, "", a), models.SurfacePermissionScan)
	if digs(perm, "state") != models.CloudCoverageDenied || digs(perm, "run") != refOf("cloud_scan_run", run1.ID) {
		t.Fatalf("an unscopable older run's permission_scan = %v, want shown (denied, run 1)", perm)
	}
}

// since (D-72) walks back at most 50 published runs: a streak that fits in
// the walk reports its first run; one longer than the walk is null -- not
// known -- never the 50th run's time.
func TestP2S2CoverageSinceIsNullPastTheWalk(t *testing.T) {
	l := newP2Lab(t, "p2-s2-coverage-since-walk", true)
	a := oneLambda(l)
	read := l.api()
	current := l.scanAndProject(a)
	if st := s2Coverage(current).Surfaces[models.SurfaceIAMRoles].State; st != models.CloudCoverageReached {
		t.Fatalf("setup: iam_roles = %q", st)
	}

	// 49 earlier published runs in the same state: a streak of exactly 50.
	older := s2InsertPublishedRuns(t, l, current, 1, 49, "")
	roles := s2Surface(t, s2CoverageAccount(t, read, "", a), models.SurfaceIAMRoles)
	oldest := older[len(older)-1]
	if digs(roles, "since_run") != refOf("cloud_scan_run", oldest.ID) || digs(roles, "since") != s2TS(&oldest.PublishedAt) {
		t.Fatalf("a 50-run streak: since %v / since_run %v, want the 50th run %s at %s",
			dig(roles, "since"), dig(roles, "since_run"), oldest.ID, s2TS(&oldest.PublishedAt))
	}

	// A 51st run that DIFFERS ends the streak exactly at the walk's edge: it
	// is still known, and still the 50th.
	breaker := s2InsertPublishedRuns(t, l, current, 50, 50, models.CloudCoverageDenied)
	roles = s2Surface(t, s2CoverageAccount(t, read, "", a), models.SurfaceIAMRoles)
	if digs(roles, "since_run") != refOf("cloud_scan_run", oldest.ID) {
		t.Fatalf("a 50-run streak ended by a different 51st: since_run %v, want %s", dig(roles, "since_run"), oldest.ID)
	}

	// The same 51st run in the SAME state: the streak runs past the walk, so
	// where it began is not known.
	l.db.Exec(`UPDATE cloud_scan_run SET coverage = jsonb_set(coverage, '{surfaces,iam_roles,state}', '"reached"') WHERE id = ?`, breaker[0].ID)
	roles = s2Surface(t, s2CoverageAccount(t, read, "", a), models.SurfaceIAMRoles)
	if dig(roles, "since") != nil || dig(roles, "since_run") != nil {
		t.Fatalf("a streak longer than the walk: since %v / since_run %v, want both null", dig(roles, "since"), dig(roles, "since_run"))
	}
	if digs(roles, "state") != models.CloudCoverageReached || digs(roles, "run") != refOf("cloud_scan_run", current.ID) {
		t.Fatalf("the surface itself = %v, want reached from the current run", roles)
	}
}

// Every denied surface names the call AWS refused and AWS's code (§5.3
// error_code, api; D-71) -- including activity, whose failures are gathered
// per identity, and the permission_scan / workload_scan stand-ins, which none
// of the scanners' surfaceResult builds.
func TestP2S2FailedCallsNamedOnEveryDeniedSurface(t *testing.T) {
	l := newP2Lab(t, "p2-s2-failed-calls", true)
	a := oneLambda(l)
	read := l.api()
	stsRefused := &smithy.OperationError{ServiceID: "STS", OperationName: "AssumeRole",
		Err: &smithy.GenericAPIError{Code: "AccessDenied", Message: "not authorized to perform sts:AssumeRole"}}
	// The permission scanner assumes the role for its IAM client, and STS
	// refuses; the activity report is refused by IAM itself.
	a.svc.WithVerifier(&s2RefusingVerifier{err: stsRefused})
	run := s2ScanWith(l, a, "s2-failed-calls", func(_ *services.AWSIAMScanner, p *services.AWSPermissionScanner, w *services.AWSWorkloadScanner) {
		p.WithIAMAPI(nil)
		w.WithActivityAPI(&s2RefusedActivity{}, func(context.Context, time.Duration) error { return nil })
	})
	if run.Status != models.CloudScanRunPublished {
		t.Fatalf("run = %s (%s)", run.Status, run.LastError)
	}
	l.project("s2-failed-calls-projector")
	cov := s2Coverage(run).Surfaces

	for surface, want := range map[string][2]string{
		"activity":                   {"iam:GenerateServiceLastAccessedDetails", "AccessDenied"},
		models.SurfacePermissionScan: {"sts:AssumeRole", "AccessDenied"},
	} {
		s := cov[surface]
		if s.State != models.CloudCoverageDenied || s.API != want[0] || s.ErrorCode != want[1] {
			t.Fatalf("%s = %+v, want denied naming %s / %s", surface, s, want[0], want[1])
		}
		got := s2Surface(t, s2CoverageAccount(t, read, "", a), surface)
		if digs(got, "api") != want[0] || digs(got, "error_code") != want[1] || digs(got, "prevents") != "surface_denied" {
			t.Fatalf("/coverage %s = %v, want api %s, error_code %s", surface, got, want[0], want[1])
		}
	}

	// The workload scanner dying before it read anything (it has no AWS
	// failure path of its own to trigger here) is folded in by the same
	// FinalizeCoverage: its stand-in names the call too -- and an error that
	// named none records none, never a guess.
	iamS := services.NewAWSIAMScanner(l.db, a.svc)
	merged := iamS.FinalizeCoverage(l.ws, a.conn, s2Coverage(run), models.SurfaceCoverage{},
		nil, map[string]models.SurfaceCoverage{}, stsRefused, nil)
	if s := merged.Surfaces[models.SurfaceWorkloadScan]; s.API != "sts:AssumeRole" || s.ErrorCode != "AccessDenied" {
		t.Fatalf("workload_scan stand-in = %+v, want sts:AssumeRole / AccessDenied", s)
	}
	merged = iamS.FinalizeCoverage(l.ws, a.conn, s2Coverage(run), models.SurfaceCoverage{},
		nil, map[string]models.SurfaceCoverage{}, context.DeadlineExceeded, nil)
	if s := merged.Surfaces[models.SurfaceWorkloadScan]; s.State != models.CloudCoverageDenied || s.API != "" || s.ErrorCode != "" {
		t.Fatalf("workload_scan stand-in from an error naming no call = %+v, want no api, no code", s)
	}
}

/* --------------------------------- helpers -------------------------------- */

// s2PublishedRun is one directly inserted published run.
type s2PublishedRun struct {
	ID          uuid.UUID
	PublishedAt time.Time
}

// s2InsertPublishedRuns inserts published runs of the same connector, copies
// of from's coverage, published `from - k minutes` for k in [first, last] --
// history the since walk reads. state, when set, overrides iam_roles' state.
// Returned in k order (newest first).
func s2InsertPublishedRuns(t *testing.T, l *p2Lab, from models.CloudScanRun, first, last int, state string) []s2PublishedRun {
	t.Helper()
	var rows []s2PublishedRun
	if err := l.db.Raw(`
		INSERT INTO cloud_scan_run (workspace_id, connector_id, generation, status, trigger,
		                            requested_at, started_at, published_at, updated_at, coverage)
		SELECT r.workspace_id, r.connector_id, 1, 'published', 'manual',
		       r.published_at - make_interval(mins => g), r.published_at - make_interval(mins => g),
		       r.published_at - make_interval(mins => g), r.published_at - make_interval(mins => g),
		       CASE WHEN ? = '' THEN r.coverage
		            ELSE jsonb_set(r.coverage, '{surfaces,iam_roles,state}', to_jsonb(?::text)) END
		  FROM cloud_scan_run r, generate_series(?::int, ?::int) g
		 WHERE r.id = ?
		RETURNING id, published_at`, state, state, first, last, from.ID).Scan(&rows).Error; err != nil {
		t.Fatalf("insert published runs: %v", err)
	}
	if len(rows) != last-first+1 {
		t.Fatalf("inserted %d runs, want %d", len(rows), last-first+1)
	}
	// RETURNING order follows the series; sort by published_at DESC anyway.
	for i := 0; i < len(rows); i++ {
		for j := i + 1; j < len(rows); j++ {
			if rows[j].PublishedAt.After(rows[i].PublishedAt) {
				rows[i], rows[j] = rows[j], rows[i]
			}
		}
	}
	return rows
}

// s2RefusingVerifier refuses every assume, for Verify and for a session
// config alike, with the error given.
type s2RefusingVerifier struct{ err error }

func (v *s2RefusingVerifier) Verify(context.Context, awsdiscovery.AssumeRequest) (*awsdiscovery.Identity, error) {
	return nil, v.err
}

func (v *s2RefusingVerifier) Config(context.Context, awsdiscovery.AssumeRequest) (aws.Config, error) {
	return aws.Config{}, v.err
}

// s2RefusedActivity refuses the service-last-accessed report, as IAM does to
// a role without iam:GenerateServiceLastAccessedDetails.
type s2RefusedActivity struct{}

func (s2RefusedActivity) GenerateServiceLastAccessedDetails(context.Context, *iam.GenerateServiceLastAccessedDetailsInput, ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error) {
	return nil, &smithy.OperationError{ServiceID: "IAM", OperationName: "GenerateServiceLastAccessedDetails",
		Err: &smithy.GenericAPIError{Code: "AccessDenied", Message: "not authorized to perform iam:GenerateServiceLastAccessedDetails"}}
}

func (s2RefusedActivity) GetServiceLastAccessedDetails(context.Context, *iam.GetServiceLastAccessedDetailsInput, ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error) {
	return nil, &smithy.OperationError{ServiceID: "IAM", OperationName: "GetServiceLastAccessedDetails",
		Err: &smithy.GenericAPIError{Code: "AccessDenied", Message: "not authorized"}}
}
