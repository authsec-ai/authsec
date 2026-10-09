package integration

// §7.1 E13's "kill the scan worker mid-collection ... no rows written by a
// superseded worker", staged on the REAL AWSScanWorker: a worker is paused
// inside an AWS call of one of its three scanners, its run is reclaimed by a
// second real worker that collects and publishes it, and the first then wakes
// and carries on with the lease it claimed. Every write it attempts from then
// on must be refused by the fence each scanner was built with (§2.10A part 3)
// -- nothing it does after waking may change a row.
//
// The pause is the only thing staged: the call it sits in answers from the
// account's fakes like any other, and the two workers are the production
// worker under two owner names.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// Where a worker is superseded: inside the FIRST call of one scanner, before
// that scanner has written anything.
const (
	// egatesPauseIAM: the IAM scanner's first authorization-details listing.
	egatesPauseIAM = "iam"
	// egatesPauseReport: the IAM scanner's credential-report read -- after
	// every IAM inventory write and reconcile, before the scanner files its
	// coverage and generation on the connector (commitScan). Not a first
	// call: the one point where only the connector row is left to write.
	egatesPauseReport = "credential_report"
	// egatesPausePermission: the permission scanner's OIDC-provider listing,
	// its first call -- the IAM scan's writes are behind it.
	egatesPausePermission = "permission"
	// egatesPauseWorkload: the workload scanner's first Lambda listing (A's
	// first region) -- the IAM and permission scans are behind it.
	egatesPauseWorkload = "workload"
)

// egatesPausedIAM is the account's IAM fake with a pause before the first
// call of one operation; the call is then served by the fake as it stands.
type egatesPausedIAM struct {
	*fakeIAM
	op    string
	once  sync.Once
	pause func()
}

func (f *egatesPausedIAM) GetAccountAuthorizationDetails(ctx context.Context, in *iam.GetAccountAuthorizationDetailsInput,
	opts ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error) {
	if f.op == "GetAccountAuthorizationDetails" {
		f.once.Do(f.pause)
	}
	return f.fakeIAM.GetAccountAuthorizationDetails(ctx, in, opts...)
}

func (f *egatesPausedIAM) ListOpenIDConnectProviders(ctx context.Context, in *iam.ListOpenIDConnectProvidersInput,
	opts ...func(*iam.Options)) (*iam.ListOpenIDConnectProvidersOutput, error) {
	if f.op == "ListOpenIDConnectProviders" {
		f.once.Do(f.pause)
	}
	return f.fakeIAM.ListOpenIDConnectProviders(ctx, in, opts...)
}

// egatesPausedReport is the credential-report fake with a pause before the
// report is requested.
type egatesPausedReport struct {
	*fakeCredentialReport
	once  sync.Once
	pause func()
}

func (f *egatesPausedReport) GenerateCredentialReport(ctx context.Context, in *iam.GenerateCredentialReportInput,
	opts ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error) {
	f.once.Do(f.pause)
	return f.fakeCredentialReport.GenerateCredentialReport(ctx, in, opts...)
}

// egatesPausedLambda is one region's Lambda fake with a pause before its
// first listing.
type egatesPausedLambda struct {
	*fakeLambda
	once  sync.Once
	pause func()
}

func (f *egatesPausedLambda) ListFunctions(ctx context.Context, in *lambda.ListFunctionsInput,
	opts ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	f.once.Do(f.pause)
	return f.fakeLambda.ListFunctions(ctx, in, opts...)
}

// egatesPauseHook wires pause into ONE worker's scanners at point, over the
// account's own fakes.
func egatesPauseHook(a *egatesAcct, point string, pause func()) services.ScannerHook {
	return func(iamS *services.AWSIAMScanner, perm *services.AWSPermissionScanner, wl *services.AWSWorkloadScanner) {
		switch point {
		case egatesPauseIAM:
			iamS.WithIAMAPI(&egatesPausedIAM{fakeIAM: a.iam, op: "GetAccountAuthorizationDetails", pause: pause})
		case egatesPauseReport:
			iamS.WithCredentialReportAPI(&egatesPausedReport{fakeCredentialReport: &fakeCredentialReport{}, pause: pause},
				func(context.Context, time.Duration) error { return nil })
		case egatesPausePermission:
			perm.WithIAMAPI(&egatesPausedIAM{fakeIAM: a.iam, op: "ListOpenIDConnectProviders", pause: pause})
		case egatesPauseWorkload:
			fns := a.lambdas[egatesPrimary]
			wl.WithRegionalAPIs(func(region string) (awsdiscovery.LambdaAPI, awsdiscovery.ECSAPI,
				awsdiscovery.EC2API, awsdiscovery.InstanceProfileAPI, awsdiscovery.BedrockAgentAPI,
				awsdiscovery.AgentCoreAPI, awsdiscovery.CloudTrailAPI) {
				lam, ecsAPI, ec2API, prof, bed, core, trail := a.regional(region)
				if region == egatesPrimary {
					lam = &egatesPausedLambda{fakeLambda: fns, pause: pause}
				}
				return lam, ecsAPI, ec2API, prof, bed, core, trail
			})
		}
	}
}

// egatesWorkerRows is every row a scan worker writes, rendered whole
// (updated_at included), sorted: every cloud_* table with a workspace_id --
// read from the catalogue, so a table added later is covered -- plus the
// barrier and the projection jobs a worker hands its run to.
func egatesWorkerRows(t *testing.T, l *p2Lab) []string {
	t.Helper()
	var tables []string
	if err := l.db.Raw(`SELECT DISTINCT c.table_name FROM information_schema.columns c
	                     JOIN information_schema.tables tb ON tb.table_schema = c.table_schema AND tb.table_name = c.table_name
	                    WHERE c.table_schema = 'public' AND c.column_name = 'workspace_id' AND tb.table_type = 'BASE TABLE'
	                      AND (c.table_name LIKE 'cloud\_%' OR c.table_name IN ('iga_pipeline_lease', 'iga_projection_job'))
	                    ORDER BY 1`).Scan(&tables).Error; err != nil || len(tables) < 5 {
		t.Fatalf("list the scan worker's tables: %v (%v)", tables, err)
	}
	var rows []string
	for _, table := range tables {
		var got []string
		if err := l.db.Raw(`SELECT '`+table+` ' || to_jsonb(x)::text FROM `+table+` x WHERE workspace_id = ?`, l.ws).
			Scan(&got).Error; err != nil {
			t.Fatalf("read %s: %v", table, err)
		}
		rows = append(rows, got...)
	}
	sort.Strings(rows)
	return rows
}

// egatesRowsChanged lists what differs between two egatesWorkerRows, a few
// lines each way, for a failure message.
func egatesRowsChanged(before, after []string) string {
	in := func(rows []string) map[string]bool {
		m := map[string]bool{}
		for _, r := range rows {
			m[r] = true
		}
		return m
	}
	b, a := in(before), in(after)
	var out []string
	for _, r := range before {
		if !a[r] && len(out) < 6 {
			out = append(out, "- "+r)
		}
	}
	for _, r := range after {
		if !b[r] && len(out) < 12 {
			out = append(out, "+ "+r)
		}
	}
	return strings.Join(out, "\n")
}

// egatesSupersedeMidScan runs one scan of a in which the worker that claimed
// it is superseded at point, and returns the run as the reclaiming worker
// published it, and the fence the superseded worker held.
//
// Worker A claims the run and the barrier and scans until the pause. While
// it is paused (its leases live), whilePaused runs. Then its leases run out
// (it renews neither) and worker B -- the real worker under another owner --
// reclaims the run, collects it whole and publishes it. The account then
// DIVERGES from what B read, so A would write something B did not: the
// permission point removes a policy before B reads (A's IAM snapshot still
// holds it), the IAM and workload points add a role and a function after
// (A's listing, served after the pause, holds them). A wakes and carries on.
//
// Asserted: A's RunOnce fails -- inside the IAM scan with the scan fence lost
// (its next write is refused), later with the lease lost (its publication is
// refused after every scanner write was); every row a worker writes, the
// connector's report included, is exactly as B left it; the diverging row is
// nowhere; B's run is published, on the second attempt.
func egatesSupersedeMidScan(t *testing.T, l *p2Lab, a *egatesAcct, point string,
	whilePaused func(owner string)) (models.CloudScanRun, repositories.ScanFence) {
	t.Helper()
	queued, err := l.runs.Enqueue(l.ws, a.conn, "manual")
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	owner, reclaimer := "egates-superseded-"+point, "egates-reclaiming-"+point
	guard := a.policyARN("GuardRails")
	ghostRole, ghostFn := "egates-ghost-role-"+point, "egates-ghost-fn-"+point
	var atWake []string
	var fence repositories.ScanFence
	fired := false
	pause := func() {
		fired = true
		a.extra = nil // B scans with the account's own fakes, unpaused
		// The fence A's execute built: its run, owner and claimed lease.
		fence = repositories.ScanFence{RunID: queued.ID, Owner: owner}
		if err := l.db.Raw(`SELECT lease_version FROM cloud_scan_run WHERE id = ? AND lease_owner = ? AND status = 'running'`,
			queued.ID, owner).Row().Scan(&fence.LeaseVersion); err != nil {
			t.Fatalf("setup: at the %s pause, run %s is not held by %s: %v", point, queued.ID, owner, err)
		}
		if whilePaused != nil {
			whilePaused(owner)
		}
		if point == egatesPausePermission {
			a.detach("guarded-role", guard)
			delete(a.iam.managedPolicies, guard)
		}
		egatesExec(t, l, `UPDATE cloud_scan_run SET lease_expires_at = now() - interval '1 minute' WHERE id = ?`, queued.ID)
		egatesExec(t, l, `UPDATE iga_pipeline_lease SET expires_at = now() - interval '1 minute' WHERE workspace_id = ?`, l.ws)
		if !egatesWork(l, a, reclaimer) {
			t.Fatalf("the %s-paused run was not reclaimed once its lease ran out", point)
		}
		atWake = egatesWorkerRows(t, l)
		switch point {
		case egatesPauseIAM:
			a.role(ghostRole, "AROAEGATESGHOST"+strings.ToUpper(point)[:1]+"0000")
		case egatesPauseWorkload:
			fns := a.lambdas[egatesPrimary]
			fns.functions = append(fns.functions, lambdatypes.FunctionConfiguration{
				FunctionArn:  aws.String("arn:aws:lambda:" + egatesPrimary + ":" + a.id + ":function:" + ghostFn),
				FunctionName: aws.String(ghostFn), Role: aws.String(a.roleARN(egatesSharedRole)), State: lambdatypes.StateActive,
			})
		}
	}
	a.extra = egatesPauseHook(a, point, pause)
	w := services.NewAWSScanWorker(l.db, a.svc).WithOwner(owner).WithGraphProjection(l.gate).WithScannerHook(a.hook())
	worked, err := w.RunOnce(context.Background())
	a.extra = nil
	if !fired {
		t.Fatalf("the worker never reached the %s pause: worked=%v err=%v", point, worked, err)
	}

	want := repositories.ErrLeaseLost
	if point == egatesPauseIAM || point == egatesPauseReport {
		want = repositories.ErrScanFenceLost
	}
	if !worked || !errors.Is(err, want) {
		t.Errorf("the worker superseded at the %s pause: worked=%v err=%v, want %v", point, worked, err, want)
	}
	if now := egatesWorkerRows(t, l); strings.Join(now, "\n") != strings.Join(atWake, "\n") {
		t.Errorf("the worker superseded at the %s pause wrote after waking (rows %d -> %d):\n%s",
			point, len(atWake), len(now), egatesRowsChanged(atWake, now))
	}
	var run models.CloudScanRun
	if err := l.db.First(&run, "id = ?", queued.ID).Error; err != nil || run.Status != models.CloudScanRunPublished ||
		run.Attempts != 2 {
		t.Fatalf("the %s-paused run = %s after %d attempts (%v), want published by the reclaiming worker",
			point, run.Status, run.Attempts, err)
	}
	var diverged int64
	switch point {
	case egatesPauseIAM:
		diverged = l.count(`SELECT count(*) FROM cloud_identity WHERE workspace_id = ? AND native_id = ?`, l.ws, a.roleARN(ghostRole))
	case egatesPausePermission:
		diverged = l.count(`SELECT count(*) FROM cloud_policy WHERE workspace_id = ? AND connector_id = ? AND native_id = ?
		                      AND last_seen_generation = ?`, l.ws, a.conn, guard, run.Generation)
	case egatesPauseWorkload:
		diverged = l.count(`SELECT count(*) FROM cloud_workload WHERE workspace_id = ? AND name = ?`, l.ws, ghostFn)
	}
	if diverged != 0 {
		t.Errorf("the worker superseded at the %s pause landed %d row(s) only it read", point, diverged)
	}
	// Only the superseded worker ever read the role or function added after
	// B's scan: take it back out, so the account is what B published.
	switch point {
	case egatesPauseIAM:
		kept := a.iam.roles[:0]
		for _, r := range a.iam.roles {
			if aws.ToString(r.RoleName) != ghostRole {
				kept = append(kept, r)
			}
		}
		a.iam.roles = kept
	case egatesPauseWorkload:
		fns := a.lambdas[egatesPrimary]
		kept := fns.functions[:0]
		for _, f := range fns.functions {
			if aws.ToString(f.FunctionName) != ghostFn {
				kept = append(kept, f)
			}
		}
		fns.functions = kept
	}
	return run, fence
}

// E13, every scanner: a worker superseded inside the permission scan, inside
// the workload scan, or at the end of the IAM scan (only the connector row
// left to write) writes nothing after waking -- each scanner writes through
// its own fence, and nothing after the scanners (the connector's coverage
// report and generation, the publication, the job, the barrier) lands
// either. The IAM scanner's first write is TestP2EgatesE13InterruptionLeaseLossReplay's
// first step. Each reclaimed run is then projected like any other: one
// publication per run, the graph as the reclaiming worker collected it.
//
// Safeguards (mutation-checked): the permission and workload scanners are
// built with the run's fence; the IAM scanner files its coverage and
// generation on the connector under it (commitScan, persistCoverage).
func TestP2EgatesE13SupersededScannersWriteNothing(t *testing.T) {
	l := newP2Lab(t, "p2-egates-e13-scanners", true)
	a := egatesProduction(t, l)
	egatesCycle(l, a)
	api := l.api()
	for i, point := range []string{egatesPausePermission, egatesPauseWorkload, egatesPauseReport} {
		run, _ := egatesSupersedeMidScan(t, l, a, point, nil)
		l.project(fmt.Sprintf("egates-projector-%s", point))
		pub := egatesPublicationOf(t, l, run.ID)
		if pub.Rev != int64(i+2) {
			t.Errorf("the %s-superseded run published rev %d, want %d", point, pub.Rev, i+2)
		}
		if acc := s2PipelineAccount(t, s2Pipeline(t, api), a.p2Account); digs(acc, "state") != "published" ||
			num(acc, "projection", "rev") != int64(i+2) || digs(acc, "latest_run", "ref") != refOf("cloud_scan_run", run.ID) {
			t.Errorf("pipeline after the %s-superseded run = %s", point, egatesJSON(acc))
		}
	}
	// The graph is what the reclaiming workers read: GuardRails (removed
	// before the permission scan's reclaimer read) is detached, and the
	// function only the superseded workload scanner read was never listed.
	if asg := l.assignments("GuardRails"); len(asg) != 1 || asg[0].State != models.RelEnded {
		t.Errorf("GuardRails assignment = %+v, want ended: the run was published by the worker that did not read it", asg)
	}
	if rows := digl(egatesGet(t, api, "/workloads"+qs("q", "egates-ghost")), "data"); len(rows) != 0 {
		t.Errorf("/workloads lists %s, which only the superseded worker read", egatesJSON(rows))
	}
	var perRun []int64
	l.db.Raw(`SELECT count(*) FROM iga_publication WHERE workspace_id = ? GROUP BY scan_run_id`, l.ws).Scan(&perRun)
	for _, n := range perRun {
		if n != 1 {
			t.Errorf("a run has %d publications, want exactly 1: %v", n, perRun)
		}
	}
	if st := l.barrier(); st != models.PipelineIdle {
		t.Errorf("barrier = %s, want idle", st)
	}
}
