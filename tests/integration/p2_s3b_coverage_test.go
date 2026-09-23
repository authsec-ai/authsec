package integration

// T3.7 and T3.8 (SPEC-iga-phase2-graph.md §1.3, §1.4, §2.14.13): coverage that
// matches reality. Access Advisor is partial above its identity cap and
// throttled on a throttle; resource-policy failures are counted; AWS
// Organizations is reported unsupported; a service not offered in a region is
// unsupported and blocks nothing -- and each state gates exactly the
// reconciliation it should.

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

/* ---------------------------------- fakes ---------------------------------- */

// s3bActivity is an Access Advisor fake whose report can be made to fail per
// principal: a submit error for the ARNs in fail, or for every ARN (failAll).
// A report that is submitted completes on its first poll with one service.
type s3bActivity struct {
	mu      sync.Mutex
	fail    map[string]error
	failAll error
	jobs    int
	// submitted is every principal a report was requested for, in order.
	submitted []string
}

func (f *s3bActivity) GenerateServiceLastAccessedDetails(_ context.Context, in *iam.GenerateServiceLastAccessedDetailsInput, _ ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.submitted = append(f.submitted, aws.ToString(in.Arn))
	if f.failAll != nil {
		return nil, f.failAll
	}
	if err := f.fail[aws.ToString(in.Arn)]; err != nil {
		return nil, err
	}
	f.jobs++
	return &iam.GenerateServiceLastAccessedDetailsOutput{JobId: aws.String(fmt.Sprintf("job-%d", f.jobs))}, nil
}

func (f *s3bActivity) GetServiceLastAccessedDetails(context.Context, *iam.GetServiceLastAccessedDetailsInput, ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error) {
	done := time.Now().Add(-time.Hour)
	used := time.Now().Add(-48 * time.Hour)
	return &iam.GetServiceLastAccessedDetailsOutput{
		JobStatus: iamtypes.JobStatusTypeCompleted, JobCompletionDate: &done,
		ServicesLastAccessed: []iamtypes.ServiceLastAccessed{{
			ServiceNamespace: aws.String("s3"), ServiceName: aws.String("Amazon S3"), LastAuthenticated: &used,
		}},
	}, nil
}

// s3bThrottle is IAM's own throttle code, which classify maps to ErrThrottled.
func s3bThrottle(op string) error {
	return &smithy.GenericAPIError{Code: "ThrottlingException", Message: "Rate exceeded on " + op}
}

// s3bS3Policy answers GetBucketPolicy per bucket: a document, or an error.
type s3bS3Policy struct {
	docs map[string]string
	errs map[string]error
}

func (f *s3bS3Policy) GetBucketPolicy(_ context.Context, in *s3.GetBucketPolicyInput, _ ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	b := aws.ToString(in.Bucket)
	if err := f.errs[b]; err != nil {
		return nil, err
	}
	return &s3.GetBucketPolicyOutput{Policy: aws.String(f.docs[b])}, nil
}

// s3bDNSLambda fails ListFunctions the way the SDK does when a regional
// endpoint does not exist: a *net.DNSError (IsNotFound) inside the HTTP
// client's *url.Error.
type s3bDNSLambda struct{ host string }

func (f *s3bDNSLambda) ListFunctions(context.Context, *lambda.ListFunctionsInput, ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	return nil, &smithy.OperationError{ServiceID: "Lambda", OperationName: "ListFunctions",
		Err: &url.Error{Op: "Post", URL: "https://" + f.host + "/", Err: &net.OpError{Op: "dial", Net: "tcp",
			Err: &net.DNSError{Err: "no such host", Name: f.host, IsNotFound: true}}}}
}

var (
	_ awsdiscovery.ServiceLastAccessedAPI = (*s3bActivity)(nil)
	_ awsdiscovery.S3PolicyAPI            = (*s3bS3Policy)(nil)
	_ awsdiscovery.LambdaAPI              = (*s3bDNSLambda)(nil)
)

/* -------------------------------- fixtures -------------------------------- */

// s3bActivityFixture onboards a connector, runs the real IAM scan over
// populatedIAM (three identities) and, when extra > 0, adds that many more
// roles at the run's generation -- enough to cross the Access Advisor cap
// without a 500-role IAM fixture.
func s3bActivityFixture(t *testing.T, db *gorm.DB, ws uuid.UUID, extra int) (*services.AWSOnboardingService, *services.IAMSnapshot) {
	t.Helper()
	svc, _ := newOnboarding(db, okVerifier())
	conn, _, err := svc.Onboard(context.Background(), ws, singleRegionInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	snap, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(populatedIAM()).
		Scan(context.Background(), ws, conn.ID)
	if err != nil {
		t.Fatalf("identity scan: %v", err)
	}
	if extra > 0 {
		if err := db.Exec(`INSERT INTO cloud_identity (workspace_id, connector_id, kind, native_id, name, last_seen_generation)
		                   SELECT ?, ?, 'iam_role', 'arn:aws:iam::429418377036:role/s3b-bulk-' || g, 's3b-bulk-' || g, ?
		                     FROM generate_series(1, ?) g`, ws, conn.ID, snap.Generation, extra).Error; err != nil {
			t.Fatalf("add bulk identities: %v", err)
		}
	}
	return svc, snap
}

// s3bWorkloadScan runs the workload scanner with empty compute fakes (so no
// region falls back to a real client) and the given activity fake.
func s3bWorkloadScan(t *testing.T, db *gorm.DB, ws uuid.UUID, svc *services.AWSOnboardingService,
	snap *services.IAMSnapshot, activity awsdiscovery.ServiceLastAccessedAPI, lam awsdiscovery.LambdaAPI,
) *services.WorkloadSnapshot {
	t.Helper()
	if lam == nil {
		lam = &fakeLambda{}
	}
	noSleep := func(context.Context, time.Duration) error { return nil }
	out, err := services.NewAWSWorkloadScanner(db, svc).WithWorkloadAPIs(lam, nil, nil, nil).
		WithActivityAPI(activity, noSleep).ScanFromSnapshot(context.Background(), ws, snap)
	if err != nil {
		t.Fatalf("workload scan: %v", err)
	}
	return out
}

// s3bStaleRows plants one workload and one usage row from an EARLIER
// generation, so a test can see which reconciliation ran: a row that survives
// was protected; a row that is gone was reconciled away.
func s3bStaleRows(t *testing.T, db *gorm.DB, ws uuid.UUID, snap *services.IAMSnapshot) {
	t.Helper()
	var identityID uuid.UUID
	if err := db.Raw(`SELECT id FROM cloud_identity WHERE workspace_id = ? AND native_id = ?`, ws, plainRoleARN).
		Row().Scan(&identityID); err != nil {
		t.Fatalf("read role: %v", err)
	}
	old := snap.Generation - 1
	if old < 0 {
		old = 0
	}
	if err := db.Exec(`INSERT INTO cloud_workload (workspace_id, connector_id, runtime_kind, native_id, name, region, last_seen_generation)
	                   VALUES (?, ?, 'lambda_function', 'arn:aws:lambda:us-east-1:429418377036:function:s3b-gone', 's3b-gone', 'us-east-1', ?)`,
		ws, snap.ConnectorID, old).Error; err != nil {
		t.Fatalf("plant workload: %v", err)
	}
	if err := db.Exec(`INSERT INTO cloud_usage (workspace_id, connector_id, identity_id, service, source, last_seen_generation)
	                   VALUES (?, ?, ?, 's3b-gone-service', 'service_last_accessed', ?)`,
		ws, snap.ConnectorID, identityID, old).Error; err != nil {
		t.Fatalf("plant usage: %v", err)
	}
}

func s3bSurvived(t *testing.T, db *gorm.DB, ws uuid.UUID) (workload, usage bool) {
	t.Helper()
	var w, u int64
	db.Raw(`SELECT count(*) FROM cloud_workload WHERE workspace_id = ? AND name = 's3b-gone'`, ws).Scan(&w)
	db.Raw(`SELECT count(*) FROM cloud_usage WHERE workspace_id = ? AND service = 's3b-gone-service'`, ws).Scan(&u)
	return w > 0, u > 0
}

/* ------------------------------ Access Advisor ----------------------------- */

// T3.7 / E4: above the 500-identity cap, activity is PARTIAL and names both
// counts -- it used to stop silently at 500. Partial keeps usage (no
// ReconcileUsage) but, split from it, no longer vetoes workload
// reconciliation (ReconcileWorkloads still runs).
//
// Safeguards (mutation-checked): the cap check in scanActivity; the split
// gates in ScanFromSnapshot.
func TestP2S3bActivityIsPartialAboveTheCap(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "p2-s3b-activity-cap")
	defer cleanWorkloadTables(t, db, ws)

	svc, snap := s3bActivityFixture(t, db, ws, 498) // 3 + 498 = 501 identities
	s3bStaleRows(t, db, ws, snap)
	out := s3bWorkloadScan(t, db, ws, svc, snap, &s3bActivity{}, nil)

	cov := out.Surfaces[models.SurfaceActivity]
	if cov.State != models.CloudCoveragePartial {
		t.Fatalf("activity above the cap = %+v, want partial", cov)
	}
	if !strings.Contains(cov.Error, "500 of 501 identities") || !strings.Contains(cov.Error, "capped at 500") {
		t.Errorf("partial must name both counts and the cap, got %q", cov.Error)
	}
	if cov.Count != 500 || out.UsageWritten != 500 {
		t.Errorf("count = %d, usage written = %d, want 500 (one service for each identity read)", cov.Count, out.UsageWritten)
	}
	if out.UsageComplete || out.Complete || !out.WorkloadsComplete {
		t.Fatalf("gates: usage=%v workloads=%v complete=%v; want usage blocked, workloads free",
			out.UsageComplete, out.WorkloadsComplete, out.Complete)
	}
	workload, usage := s3bSurvived(t, db, ws)
	if !usage {
		t.Error("a stale usage row was deleted while activity was partial")
	}
	if workload {
		t.Error("a stale workload survived: a partial activity read must not veto workload reconciliation")
	}
}

// D-86: the capped sample is the first activityIdentityCap identities in BYTE
// order of their ARN -- deterministic, and named on the coverage
// (capped_after) so a reader can tell "not collected" from "no attempt
// reported" for any identity without re-deriving the sample.
//
// The fixture makes every plausible wrong order pick a different sample: the
// 498 extra users have ARNs user/Z-bulk-NNN (uppercase, so byte order puts
// them BEFORE user/ci-deployer while a locale collation puts them after) and
// names d-bulk-NNN (so ordering by name puts ci-deployer first). Byte order
// leaves out ci-deployer alone; name order or the database's default
// collation would leave out user/Z-bulk-498 instead.
//
// Safeguard (mutation-checked): the ORDER BY native_id COLLATE "C" in
// ActivitySample, and the CappedAfter stamp in scanActivity.
func TestP2S3bActivitySampleIsTheFirstByARN(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "p2-s3b-activity-sample")
	defer cleanWorkloadTables(t, db, ws)

	svc, snap := s3bActivityFixture(t, db, ws, 0) // 3 identities
	if err := db.Exec(`INSERT INTO cloud_identity (workspace_id, connector_id, kind, native_id, name, last_seen_generation)
	                   SELECT ?, ?, 'iam_user', 'arn:aws:iam::429418377036:user/Z-bulk-' || lpad(g::text, 3, '0'),
	                          'd-bulk-' || lpad(g::text, 3, '0'), ?
	                     FROM generate_series(1, 498) g`, ws, snap.ConnectorID, snap.Generation).Error; err != nil {
		t.Fatalf("add bulk identities: %v", err)
	}
	var all []string
	if err := db.Raw(`SELECT native_id FROM cloud_identity WHERE workspace_id = ? AND connector_id = ?`,
		ws, snap.ConnectorID).Scan(&all).Error; err != nil || len(all) != 501 {
		t.Fatalf("identities = %d (%v), want 501", len(all), err)
	}
	sort.Strings(all) // Go's string order is byte order
	want := all[:500]
	if all[500] != ciUserARN {
		t.Fatalf("fixture: byte order must leave out %s, leaves out %s", ciUserARN, all[500])
	}

	fake := &s3bActivity{}
	out := s3bWorkloadScan(t, db, ws, svc, snap, fake, nil)
	got := append([]string(nil), fake.submitted...)
	sort.Strings(got)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		missing := map[string]bool{}
		for _, a := range want {
			missing[a] = true
		}
		for _, a := range got {
			delete(missing, a)
		}
		t.Fatalf("sampled %d identities; not the first 500 by ARN (byte order) -- %d of those were skipped, e.g. %v",
			len(got), len(missing), s3bFirstKeys(missing, 3))
	}
	cov := out.Surfaces[models.SurfaceActivity]
	if cov.State != models.CloudCoveragePartial || cov.CappedAfter != want[499] {
		t.Fatalf("activity = %+v, want partial with capped_after %q (the last ARN sampled)", cov, want[499])
	}
	// Run it again: the same 500, in the same order.
	again := &s3bActivity{}
	s3bWorkloadScan(t, db, ws, svc, snap, again, nil)
	if strings.Join(again.submitted, "|") != strings.Join(fake.submitted, "|") {
		t.Fatal("the capped sample is not deterministic between scans of an unchanged inventory")
	}
}

// s3bFirstKeys lists up to n keys of a set, sorted, for a failure message.
func s3bFirstKeys(m map[string]bool, n int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// T3.7 / E4 (the throttling fixture): a throttle is reported THROTTLED, not
// denied, naming the call and the AWS code; one identity denied among many
// read is partial; every identity denied is denied. None reconciles usage.
//
// Safeguard (mutation-checked): the throttled branch of itemFailureCoverage.
func TestP2S3bActivityThrottledOnThrottle(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "p2-s3b-activity-throttle")
	defer cleanWorkloadTables(t, db, ws)
	svc, snap := s3bActivityFixture(t, db, ws, 0)

	// Throttled: one identity's submit is throttled past the retry budget.
	out := s3bWorkloadScan(t, db, ws, svc, snap, &s3bActivity{fail: map[string]error{
		agentRoleARN: s3bThrottle("iam:GenerateServiceLastAccessedDetails"),
	}}, nil)
	cov := out.Surfaces[models.SurfaceActivity]
	if cov.State != models.CloudCoverageThrottled {
		t.Fatalf("activity with a throttled report = %+v, want throttled (it used to read denied)", cov)
	}
	if !strings.Contains(cov.Error, "1 of 3") ||
		!strings.Contains(cov.Error, "iam:GenerateServiceLastAccessedDetails ThrottlingException") {
		t.Errorf("throttled must name the count, the call and the code, got %q", cov.Error)
	}
	if cov.API != "iam:GenerateServiceLastAccessedDetails" || cov.ErrorCode != "ThrottlingException" {
		t.Errorf("throttled api/error_code = %q/%q (D-71)", cov.API, cov.ErrorCode)
	}
	if out.UsageComplete {
		t.Error("a throttled activity read must not license deleting usage")
	}

	// Partial: one identity denied, the others read.
	out = s3bWorkloadScan(t, db, ws, svc, snap, &s3bActivity{fail: map[string]error{
		agentRoleARN: denied("iam:GenerateServiceLastAccessedDetails"),
	}}, nil)
	if cov := out.Surfaces[models.SurfaceActivity]; cov.State != models.CloudCoveragePartial ||
		!strings.Contains(cov.Error, "iam:GenerateServiceLastAccessedDetails AccessDenied") || cov.Count != 2 {
		t.Fatalf("activity with one denied report = %+v, want partial, count 2", cov)
	}

	// Denied: nothing could be read.
	out = s3bWorkloadScan(t, db, ws, svc, snap, &s3bActivity{failAll: denied("iam:GenerateServiceLastAccessedDetails")}, nil)
	if cov := out.Surfaces[models.SurfaceActivity]; cov.State != models.CloudCoverageDenied || cov.Count != 0 {
		t.Fatalf("activity with every report denied = %+v, want denied", cov)
	}

	// And the clean case still reads reached.
	out = s3bWorkloadScan(t, db, ws, svc, snap, &s3bActivity{}, nil)
	if cov := out.Surfaces[models.SurfaceActivity]; cov.State != models.CloudCoverageReached || !out.Complete {
		t.Fatalf("clean activity = %+v (complete=%v), want reached", cov, out.Complete)
	}
}

/* ----------------------------- resource policies ---------------------------- */

// T3.7 / E4, as D-93 records it: per-resource GetBucketPolicy failures are
// COUNTED -- the surface used to read reached even when every read was denied.
// All reads succeed -> reached (count = reads); some fail -> partial (count =
// the failures); all fail -> denied. "No policy" (NoSuchBucketPolicy) is a
// successful read, and a throttled read is a failed one (D-93 gives this
// surface no throttled state) whose error still names ThrottlingException. The
// surface stays out of the permission scan's own reconciliation gate: it is
// bonus evidence.
//
// Safeguards (mutation-checked): the failure count in scanResourcePolicies;
// the partial / denied split and the failure count in resourcePolicyCoverage.
func TestP2S3bResourcePolicyFailuresAreCounted(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "p2-s3b-resource-policies")
	defer cleanPermissionTables(t, db, ws)

	svc, _ := newOnboarding(db, okVerifier())
	conn, _, err := svc.Onboard(context.Background(), ws, singleRegionInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	iamFake := populatedIAM()
	iamFake.inlineRolePolicies["summarizer-agent"] = map[string]string{
		"read-buckets": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject",
			"Resource":["arn:aws:s3:::s3b-readable","arn:aws:s3:::s3b-locked","arn:aws:s3:::s3b-nopolicy"]}]}`,
	}
	snap, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(iamFake).Scan(context.Background(), ws, conn.ID)
	if err != nil {
		t.Fatalf("identity scan: %v", err)
	}
	noPolicy := &smithy.GenericAPIError{Code: "NoSuchBucketPolicy", Message: "The bucket policy does not exist"}
	scan := func(errs map[string]error) *services.PermissionSnapshot {
		t.Helper()
		out, err := services.NewAWSPermissionScanner(db, svc).WithIAMAPI(iamFake).WithEKSAPI(newFakeEKS()).
			WithResourcePolicyAPIs(&s3bS3Policy{
				docs: map[string]string{"s3b-readable": `{"Version":"2012-10-17","Statement":[{"Effect":"Deny",` +
					`"Principal":"*","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::s3b-readable/*"}]}`},
				errs: errs,
			}, &fakeKMSPolicy{}).
			ScanFromSnapshot(context.Background(), ws, snap)
		if err != nil {
			t.Fatalf("permission scan: %v", err)
		}
		return out
	}

	// One denied, one read, one with no policy at all: partial, 1 of 3.
	out := scan(map[string]error{"s3b-locked": denied("s3:GetBucketPolicy"), "s3b-nopolicy": noPolicy})
	cov := out.Surfaces[models.SurfaceResourcePolicies]
	if cov.State != models.CloudCoveragePartial || cov.Count != 1 ||
		!strings.Contains(cov.Error, "1 of 3 resource policies could not be read: s3:GetBucketPolicy AccessDenied") {
		t.Fatalf("resource_policies with one denied read = %+v, want partial, count 1 (the failures, D-93; "+
			"no-policy is a clean read), naming the call", cov)
	}
	// D-71: the call and AWS's own code, as stored fields -- never parsed back out of Error.
	if cov.API != "s3:GetBucketPolicy" || cov.ErrorCode != "AccessDenied" {
		t.Errorf("resource_policies api/error_code = %q/%q, want s3:GetBucketPolicy/AccessDenied", cov.API, cov.ErrorCode)
	}
	if !out.Complete {
		t.Error("resource-policy coverage must stay out of the permission scan's reconciliation gate")
	}

	// Every read denied: denied, never reached; count = the 3 failures.
	out = scan(map[string]error{"s3b-readable": denied("s3:GetBucketPolicy"),
		"s3b-locked": denied("s3:GetBucketPolicy"), "s3b-nopolicy": denied("s3:GetBucketPolicy")})
	if cov := out.Surfaces[models.SurfaceResourcePolicies]; cov.State != models.CloudCoverageDenied || cov.Count != 3 ||
		!strings.Contains(cov.Error, "3 of 3") {
		t.Fatalf("resource_policies with every read denied = %+v, want denied, count 3", cov)
	}

	// A throttled read is a failed read: partial, naming the throttle.
	out = scan(map[string]error{"s3b-locked": throttled("s3:GetBucketPolicy"), "s3b-nopolicy": noPolicy})
	if cov := out.Surfaces[models.SurfaceResourcePolicies]; cov.State != models.CloudCoveragePartial || cov.Count != 1 ||
		!strings.Contains(cov.Error, "s3:GetBucketPolicy Throttling") || cov.ErrorCode != "Throttling" {
		t.Fatalf("resource_policies with a throttled read = %+v, want partial (D-93) naming the throttle", cov)
	}

	// Clean: reached, every resource counted.
	out = scan(map[string]error{"s3b-nopolicy": noPolicy})
	if cov := out.Surfaces[models.SurfaceResourcePolicies]; cov.State != models.CloudCoverageReached || cov.Count != 3 ||
		cov.API != "" || cov.ErrorCode != "" {
		t.Fatalf("resource_policies with every read clean = %+v, want reached, count 3, no failed call", cov)
	}
}

/* ------------------------------- organizations ------------------------------ */

// T3.8 / E4: "Coverage shows organizations: unsupported" -- on the run (what
// the projector and /coverage read) and on the connector -- and it gates
// nothing: the same scan still reads complete.
//
// Safeguard (mutation-checked): the FinalizeCoverage entry.
func TestP2S3bOrganizationsIsReportedUnsupported(t *testing.T) {
	l := newP2Lab(t, "p2-s3b-organizations", true)
	a := oneLambda(l)
	run := l.scanAndProject(a)

	runCov := s3bRunCoverage(t, l, run.ID)
	org := s3bSurface(t, runCov, models.SurfaceOrganizations)
	if org.State != models.CloudCoverageUnsupported || !strings.Contains(org.Error, "not collected") {
		t.Fatalf("organizations on the run = %+v, want unsupported, saying SCPs are not collected", org)
	}
	if runCov.Status != models.ScanStatusComplete {
		t.Fatalf("run coverage status = %q with organizations unsupported, want complete (unsupported gates nothing): %+v",
			runCov.Status, runCov.IntendedIncomplete())
	}
	var raw []byte
	if err := l.db.Raw(`SELECT coverage FROM cloud_connector WHERE id = ?`, a.conn).Row().Scan(&raw); err != nil {
		t.Fatalf("read connector coverage: %v", err)
	}
	if got := models.DecodeScanCoverage(raw).Surfaces[models.SurfaceOrganizations]; got.State != models.CloudCoverageUnsupported {
		t.Fatalf("organizations on the connector = %+v, want unsupported", got)
	}
}

/* --------------------------- not offered in region -------------------------- */

// T3.6 / T3.8 / E9: a service whose regional endpoint does not resolve is not
// offered there -- unsupported, which blocks nothing (§1.4): the table still
// reads as authoritative (WorkloadsComplete) and the region's other surfaces
// still reconcile. It used to be denied, which vetoed workload reconciliation
// for the whole connector on every run.
//
// But once an earlier scan COLLECTED that service in that region, a
// non-resolving endpoint is not proof it is not offered: it is reported denied,
// and nothing there is deleted.
//
// Safeguards (mutation-checked): the DNS mapping in listErr; the prior-rows
// guard in regionalCoverage.
func TestP2S3bServiceNotOfferedInRegionIsUnsupported(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "p2-s3b-not-offered")
	defer cleanWorkloadTables(t, db, ws)

	svc, snap := s3bActivityFixture(t, db, ws, 0)
	s3bStaleRows(t, db, ws, snap)
	// The planted stale row becomes an ECS task definition, so us-east-1 has
	// never had a Lambda -- the genuinely-not-offered case -- and the stale
	// row belongs to a surface (ecs:us-east-1) that IS reached.
	db.Exec(`UPDATE cloud_workload SET runtime_kind = 'ecs_task_definition',
	                native_id = 'arn:aws:ecs:us-east-1:429418377036:task-definition/s3b-gone:1'
	          WHERE workspace_id = ? AND name = 's3b-gone'`, ws)

	out := s3bWorkloadScan(t, db, ws, svc, snap, &s3bActivity{}, &s3bDNSLambda{host: "lambda.us-east-1.amazonaws.com"})
	cov := out.Surfaces["lambda:us-east-1"]
	if cov.State != models.CloudCoverageUnsupported || !strings.Contains(cov.Error, "not offered in us-east-1") {
		t.Fatalf("lambda with a non-resolving endpoint = %+v, want unsupported", cov)
	}
	if cov.API != "lambda:ListFunctions" || cov.ErrorCode != "" {
		t.Errorf("unsupported api/error_code = %q/%q, want lambda:ListFunctions and no code (AWS returned none)",
			cov.API, cov.ErrorCode)
	}
	if _, listed := out.Errors["lambda:us-east-1"]; listed {
		t.Error("an unsupported surface is not an error")
	}
	if !out.WorkloadsComplete {
		t.Fatalf("unsupported must not make the workload table unauthoritative: %+v", out.Errors)
	}
	if workload, _ := s3bSurvived(t, db, ws); workload {
		t.Error("the stale ECS row survived: its surface was reached beside an unsupported one")
	}

	// ---- an earlier scan found a Lambda here ---------------------------------
	found := &fakeLambda{functions: []lambdatypes.FunctionConfiguration{{
		FunctionArn:  aws.String("arn:aws:lambda:us-east-1:429418377036:function:s3b-here"),
		FunctionName: aws.String("s3b-here"), Role: aws.String(plainRoleARN),
	}}}
	s3bWorkloadScan(t, db, ws, svc, snap, &s3bActivity{}, found)
	snap.Generation++
	out = s3bWorkloadScan(t, db, ws, svc, snap, &s3bActivity{}, &s3bDNSLambda{host: "lambda.us-east-1.amazonaws.com"})
	cov = out.Surfaces["lambda:us-east-1"]
	if cov.State != models.CloudCoverageDenied || !strings.Contains(cov.Error, "earlier scan collected") {
		t.Fatalf("lambda not resolving where a Lambda was collected before = %+v, want denied, saying why", cov)
	}
	if out.WorkloadsComplete {
		t.Fatal("a denied surface must block workload reconciliation")
	}
	var kept int64
	db.Raw(`SELECT count(*) FROM cloud_workload WHERE workspace_id = ? AND name = 's3b-here'`, ws).Scan(&kept)
	if kept != 1 {
		t.Fatalf("the earlier Lambda was deleted on an unresolvable endpoint (%d rows)", kept)
	}
}

/* --------------------------- EKS detail failures ---------------------------- */

// eks_pod_identity: a failed DescribePodIdentityAssociation (or
// DescribeCluster) used to skip the association SILENTLY while the surface
// read reached -- and the permission scan's reconcile then deleted the edge it
// had simply failed to read. Now the surface is partial, names the call, and
// nothing is deleted.
//
// Safeguard (mutation-checked): the association tally in eks.go.
func TestP2S3bPodIdentityDescribeFailureIsPartialAndKeepsTheEdge(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "p2-s3b-eks-detail")
	defer cleanPermissionTables(t, db, ws)

	iamFake := populatedIAM()
	eksFake := podIdentityEKS(plainRoleARN)
	scanner, snap := eksFixture(t, db, ws, iamFake, eksFake)
	if out, err := scanner.ScanFromSnapshot(context.Background(), ws, snap); err != nil || out.PodIdentityEdges != 1 {
		t.Fatalf("setup: %v, %+v", err, out)
	}

	eksFake.fail["DescribePodIdentityAssociation"] = denied("eks:DescribePodIdentityAssociation")
	snap.Generation++
	out, err := scanner.ScanFromSnapshot(context.Background(), ws, snap)
	if err != nil {
		t.Fatalf("permission scan: %v", err)
	}
	cov := out.Surfaces[models.SurfaceEKSPodIdentity]
	if cov.State != models.CloudCoveragePartial ||
		!strings.Contains(cov.Error, "eks:DescribePodIdentityAssociation AccessDenied") {
		t.Fatalf("eks_pod_identity after a denied describe = %+v, want partial naming the call", cov)
	}
	if out.Complete {
		t.Fatal("a partial eks_pod_identity must block the permission scan's reconciliation")
	}
	var edges int64
	db.Raw(`SELECT count(*) FROM cloud_assume_edge WHERE workspace_id = ? AND mechanism = ?`,
		ws, models.AssumeMechanismEKSPodIdentity).Scan(&edges)
	if edges != 1 {
		t.Fatalf("pod identity edges after a denied describe = %d, want the edge kept", edges)
	}

	// A cluster whose DescribeCluster fails is not rewritten with an empty
	// issuer (which would re-key its edges): left out, and counted.
	delete(eksFake.fail, "DescribePodIdentityAssociation")
	eksFake.fail["DescribeCluster"] = denied("eks:DescribeCluster")
	snap.Generation++
	out, err = scanner.ScanFromSnapshot(context.Background(), ws, snap)
	if err != nil {
		t.Fatalf("permission scan: %v", err)
	}
	if cov := out.Surfaces[models.SurfaceEKSPodIdentity]; cov.State != models.CloudCoveragePartial ||
		!strings.Contains(cov.Error, "eks:DescribeCluster AccessDenied") {
		t.Fatalf("eks_pod_identity after a denied DescribeCluster = %+v, want partial", cov)
	}
	var issuer *string
	db.Raw(`SELECT issuer FROM cloud_assume_edge WHERE workspace_id = ? AND mechanism = ?`,
		ws, models.AssumeMechanismEKSPodIdentity).Row().Scan(&issuer)
	if issuer == nil || *issuer != eksIssuerNoSch {
		t.Fatalf("the edge's issuer = %v after a failed DescribeCluster, want %s kept", issuer, eksIssuerNoSch)
	}
}

// s3bOneDescribeFails is an EKS API whose DescribePodIdentityAssociation fails
// for ONE association while every other call answers as the fake does.
type s3bOneDescribeFails struct {
	*fakeEKS
	failID string
}

func (f *s3bOneDescribeFails) DescribePodIdentityAssociation(ctx context.Context, in *eks.DescribePodIdentityAssociationInput, opts ...func(*eks.Options)) (*eks.DescribePodIdentityAssociationOutput, error) {
	if aws.ToString(in.AssociationId) == f.failID {
		return nil, denied("eks:DescribePodIdentityAssociation")
	}
	return f.fakeEKS.DescribePodIdentityAssociation(ctx, in, opts...)
}

// A cluster with two associations, one of whose describes fails: the surface
// is partial and the failed binding's edge is kept, as above -- AND the one
// that WAS read is written this run. The partial tally is returned beside the
// associations it read, and the permission scan must still write those; it
// used to skip the whole cluster on any error, so one unreadable association
// left every other binding in the cluster unconfirmed.
//
// Safeguard (mutation-checked): writePodIdentityEdges writes what was read
// before giving up on a cluster.
func TestP2S3bPodIdentityPartialStillWritesWhatWasRead(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "p2-s3b-eks-partial")
	defer cleanPermissionTables(t, db, ws)

	eksFake := podIdentityEKS(plainRoleARN)
	eksFake.associations["prod-cluster"] = append(eksFake.associations["prod-cluster"], ekstypes.PodIdentityAssociation{
		AssociationId:  aws.String("a-2222222222"),
		AssociationArn: aws.String("arn:aws:eks:us-east-1:429418377036:podidentityassociation/prod-cluster/a-2222222222"),
		ClusterName:    aws.String("prod-cluster"), Namespace: aws.String("payments"),
		ServiceAccount: aws.String("audit-agent"), RoleArn: aws.String(plainRoleARN),
	})
	scanner, snap := eksFixture(t, db, ws, populatedIAM(), eksFake)
	if out, err := scanner.ScanFromSnapshot(context.Background(), ws, snap); err != nil || out.PodIdentityEdges != 2 {
		t.Fatalf("setup: %v, %+v (want both associations written)", err, out)
	}
	first := snap.Generation

	scanner.WithEKSAPI(&s3bOneDescribeFails{fakeEKS: eksFake, failID: "a-2222222222"})
	snap.Generation++
	out, err := scanner.ScanFromSnapshot(context.Background(), ws, snap)
	if err != nil {
		t.Fatalf("permission scan: %v", err)
	}
	if cov := out.Surfaces[models.SurfaceEKSPodIdentity]; cov.State != models.CloudCoveragePartial ||
		!strings.Contains(cov.Error, "1 of 2 pod identity associations") || cov.API != "eks:DescribePodIdentityAssociation" {
		t.Fatalf("eks_pod_identity with one describe denied = %+v, want partial, 1 of 2, naming the call", cov)
	}
	if out.Complete || out.PodIdentityEdges != 1 {
		t.Fatalf("complete=%v edges=%d, want reconciliation blocked and the one readable binding written",
			out.Complete, out.PodIdentityEdges)
	}
	generations := map[string]int{}
	var rows []struct {
		Subject            string
		LastSeenGeneration int
	}
	db.Raw(`SELECT subject, last_seen_generation FROM cloud_assume_edge WHERE workspace_id = ? AND mechanism = ?`,
		ws, models.AssumeMechanismEKSPodIdentity).Scan(&rows)
	for _, r := range rows {
		generations[r.Subject] = r.LastSeenGeneration
	}
	read, failed := awsdiscovery.K8sSubject("payments", "ledger-agent"), awsdiscovery.K8sSubject("payments", "audit-agent")
	if len(generations) != 2 || generations[read] != snap.Generation || generations[failed] != first {
		t.Fatalf("edge generations = %v, want %s confirmed by this run (%d) and %s kept from the last (%d)",
			generations, read, snap.Generation, failed, first)
	}
}

/* ------------------------- listing failures, named -------------------------- */

// D-71: a listing that fails is reported with the call and AWS's own error
// code as FIELDS (api, error_code), stamped at collection -- the state is the
// one it always had (denied; throttled on a throttle), and a reader never has
// to parse the Error prose for either.
//
// Safeguard (mutation-checked): listErr naming the call.
func TestP2S3bListingFailureNamesTheCall(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "p2-s3b-listing-named")
	defer cleanWorkloadTables(t, db, ws)
	svc, snap := s3bActivityFixture(t, db, ws, 0)

	out := s3bWorkloadScan(t, db, ws, svc, snap, &s3bActivity{}, &fakeLambda{fail: denied("lambda:ListFunctions")})
	cov := out.Surfaces["lambda:us-east-1"]
	if cov.State != models.CloudCoverageDenied || cov.API != "lambda:ListFunctions" || cov.ErrorCode != "AccessDenied" ||
		!strings.Contains(cov.Error, "lambda:ListFunctions") {
		t.Fatalf("lambda with ListFunctions denied = %+v, want denied, api lambda:ListFunctions, error_code AccessDenied", cov)
	}
	if out.WorkloadsComplete {
		t.Fatal("a denied compute surface must block workload reconciliation")
	}

	out = s3bWorkloadScan(t, db, ws, svc, snap, &s3bActivity{}, &fakeLambda{fail: throttled("lambda:ListFunctions")})
	if cov := out.Surfaces["lambda:us-east-1"]; cov.State != models.CloudCoverageThrottled ||
		cov.API != "lambda:ListFunctions" || cov.ErrorCode != "Throttling" {
		t.Fatalf("lambda with ListFunctions throttled = %+v, want throttled, naming the call and code", cov)
	}
}
