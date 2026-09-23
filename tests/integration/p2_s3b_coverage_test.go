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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/aws/aws-sdk-go-v2/aws"
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
}

func (f *s3bActivity) GenerateServiceLastAccessedDetails(_ context.Context, in *iam.GenerateServiceLastAccessedDetailsInput, _ ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
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

// T3.7 / E4: per-resource GetBucketPolicy failures are COUNTED -- the surface
// used to read reached even when every read was denied. "No policy"
// (NoSuchBucketPolicy) is a clean answer, not a failure. The surface stays out
// of the permission scan's own reconciliation gate: it is bonus evidence.
//
// Safeguard (mutation-checked): the failure count in scanResourcePolicies.
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
	if cov.State != models.CloudCoveragePartial || cov.Count != 2 ||
		!strings.Contains(cov.Error, "1 of 3 resource policies could not be read: s3:GetBucketPolicy AccessDenied") {
		t.Fatalf("resource_policies with one denied read = %+v, want partial, count 2 (no-policy is a clean read), naming the call", cov)
	}
	if !out.Complete {
		t.Error("resource-policy coverage must stay out of the permission scan's reconciliation gate")
	}

	// Every read denied: denied, never reached.
	out = scan(map[string]error{"s3b-readable": denied("s3:GetBucketPolicy"),
		"s3b-locked": denied("s3:GetBucketPolicy"), "s3b-nopolicy": denied("s3:GetBucketPolicy")})
	if cov := out.Surfaces[models.SurfaceResourcePolicies]; cov.State != models.CloudCoverageDenied || cov.Count != 0 {
		t.Fatalf("resource_policies with every read denied = %+v, want denied", cov)
	}

	// Throttled.
	out = scan(map[string]error{"s3b-locked": throttled("s3:GetBucketPolicy"), "s3b-nopolicy": noPolicy})
	if cov := out.Surfaces[models.SurfaceResourcePolicies]; cov.State != models.CloudCoverageThrottled {
		t.Fatalf("resource_policies with a throttled read = %+v, want throttled", cov)
	}

	// Clean: reached, every resource counted.
	out = scan(map[string]error{"s3b-nopolicy": noPolicy})
	if cov := out.Surfaces[models.SurfaceResourcePolicies]; cov.State != models.CloudCoverageReached || cov.Count != 3 {
		t.Fatalf("resource_policies with every read clean = %+v, want reached, count 3", cov)
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
// offered there -- unsupported, which blocks nothing (§1.4), so workload
// reconciliation runs. It used to be denied, which vetoed workload
// reconciliation for the whole connector on every run.
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
	// The planted stale Lambda is in us-east-1 too; drop it, so this region
	// has never had a Lambda -- the genuinely-not-offered case.
	db.Exec(`UPDATE cloud_workload SET region = 'eu-west-1' WHERE workspace_id = ? AND name = 's3b-gone'`, ws)

	out := s3bWorkloadScan(t, db, ws, svc, snap, &s3bActivity{}, &s3bDNSLambda{host: "lambda.us-east-1.amazonaws.com"})
	cov := out.Surfaces["lambda:us-east-1"]
	if cov.State != models.CloudCoverageUnsupported || !strings.Contains(cov.Error, "not offered in us-east-1") {
		t.Fatalf("lambda with a non-resolving endpoint = %+v, want unsupported", cov)
	}
	if _, listed := out.Errors["lambda:us-east-1"]; listed {
		t.Error("an unsupported surface is not an error")
	}
	if !out.WorkloadsComplete {
		t.Fatalf("unsupported must not block workload reconciliation: %+v", out.Errors)
	}
	if workload, _ := s3bSurvived(t, db, ws); workload {
		t.Error("the stale workload survived: an unsupported region vetoed reconciliation")
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
