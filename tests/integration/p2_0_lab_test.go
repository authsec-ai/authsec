package integration

// The P2-0 lab (SPEC-iga-phase2-graph.md §6.3): one workspace, one or more
// connected AWS accounts, scanned by the REAL AWSScanWorker and projected by
// the REAL ProjectionService -- under DIFFERENT owner names, with
// IGA_GRAPH_PROJECTION on and verified. Every AWS call is answered by a fake;
// nothing reaches AWS.
//
// This is deliberately the whole pipeline, not the projector alone: the graph
// branch's suites never ran two consecutive scans through the worker, and
// every defect §1.3 lists against it -- no projector started, the barrier left
// in the scan worker's name, the requeue hot loop -- lived exactly there.

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/aws/aws-sdk-go-v2/aws"
	bedrockagenttypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	accountA = testAccount // 429418377036, the default verifier's account
	accountB = "905418271234"

	lambdaTrust = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
)

type p2Lab struct {
	t    *testing.T
	db   *gorm.DB
	ws   uuid.UUID
	gate *services.GraphProjectionGate
	runs repositories.CloudScanRunRepository
}

type p2Account struct {
	lab     *p2Lab
	id      string
	conn    uuid.UUID
	svc     *services.AWSOnboardingService
	iam     *fakeIAM
	lambdas map[string]*fakeLambda // by region
}

// newP2Lab builds a workspace. projection=true verifies the switch against the
// integration database (at 036); false is Phase 1.
func newP2Lab(t *testing.T, name string, projection bool) *p2Lab {
	t.Helper()
	db := igaDB(t)
	runs := scanRuns(t, db) // clears cloud_scan_run at start and at end
	ws := newWorkspace(t, db, name)
	gate := services.NewGraphProjectionGate(projection, "")
	if projection {
		if err := gate.Verify(db); err != nil {
			t.Fatalf("the integration database must be at 036 for the P2-0 lab: %v", err)
		}
	}
	l := &p2Lab{t: t, db: db, ws: ws, gate: gate, runs: runs}
	t.Cleanup(l.cleanup)
	return l
}

// account onboards one AWS account into the lab's workspace.
func (l *p2Lab) account(id string, regions ...string) *p2Account {
	l.t.Helper()
	if len(regions) == 0 {
		regions = []string{"us-east-1"}
	}
	v := &stubVerifier{identity: &awsdiscovery.Identity{
		AccountID: id,
		ARN:       "arn:aws:sts::" + id + ":assumed-role/AuthSecCloudDiscovery/authsec-onboarding-p20",
		UserID:    "AROAP20:authsec-onboarding-p20",
	}}
	svc, _ := newOnboarding(l.db, v)
	c, _, err := svc.Onboard(context.Background(), l.ws, services.AWSOnboardInput{
		RoleARN:     "arn:aws:iam::" + id + ":role/AuthSecCloudDiscovery",
		ExternalID:  mustMint(l.t, l.ws),
		Regions:     regions,
		DisplayName: "acct-" + id,
	}, "admin")
	if err != nil {
		l.t.Fatalf("onboard %s: %v", id, err)
	}
	return &p2Account{lab: l, id: id, conn: c.ID, svc: svc, iam: newFakeIAM(), lambdas: map[string]*fakeLambda{}}
}

func (a *p2Account) roleARN(name string) string { return "arn:aws:iam::" + a.id + ":role/" + name }
func (a *p2Account) policyARN(name string) string {
	return "arn:aws:iam::" + a.id + ":policy/" + name
}

// role adds an IAM role with a Lambda trust policy.
func (a *p2Account) role(name, roleID string) string {
	arn := a.roleARN(name)
	for i := range a.iam.roles {
		if aws.ToString(a.iam.roles[i].RoleName) == name {
			a.iam.roles[i].RoleId = aws.String(roleID) // a recreation under the same name
			return arn
		}
	}
	a.iam.roles = append(a.iam.roles, iamtypes.Role{
		Arn: aws.String(arn), RoleName: aws.String(name), RoleId: aws.String(roleID),
		Path: aws.String("/"), CreateDate: ago(30 * 24 * time.Hour),
		AssumeRolePolicyDocument: aws.String(url.QueryEscape(lambdaTrust)),
	})
	return arn
}

// managed defines a customer-managed policy document.
func (a *p2Account) managed(name, doc string) string {
	arn := a.policyARN(name)
	a.iam.managedPolicies[arn] = doc
	return arn
}

func (a *p2Account) attach(roleName, policyARN string) {
	for _, p := range a.iam.attachedRolePolicies[roleName] {
		if aws.ToString(p.PolicyArn) == policyARN {
			return
		}
	}
	name := policyARN[len(policyARN)-len(lastSegment(policyARN)):]
	a.iam.attachedRolePolicies[roleName] = append(a.iam.attachedRolePolicies[roleName],
		iamtypes.AttachedPolicy{PolicyArn: aws.String(policyARN), PolicyName: aws.String(name)})
}

func (a *p2Account) detach(roleName, policyARN string) {
	var keep []iamtypes.AttachedPolicy
	for _, p := range a.iam.attachedRolePolicies[roleName] {
		if aws.ToString(p.PolicyArn) != policyARN {
			keep = append(keep, p)
		}
	}
	a.iam.attachedRolePolicies[roleName] = keep
}

func lastSegment(arn string) string {
	for i := len(arn) - 1; i >= 0; i-- {
		if arn[i] == '/' {
			return arn[i+1:]
		}
	}
	return arn
}

// lambda sets the region's one Lambda function to run as roleARN ("" removes it).
func (a *p2Account) lambda(region, name, roleARN string) {
	f := a.lambdas[region]
	if f == nil {
		f = &fakeLambda{}
		a.lambdas[region] = f
	}
	f.functions = nil
	if roleARN != "" {
		f.functions = []lambdatypes.FunctionConfiguration{{
			FunctionArn:  aws.String("arn:aws:lambda:" + region + ":" + a.id + ":function:" + name),
			FunctionName: aws.String(name), Role: aws.String(roleARN), State: lambdatypes.StateActive,
		}}
	}
}

// hook gives the real worker's scanners this account's fakes -- every one, so
// no scanner falls back to assuming a real role.
func (a *p2Account) hook() services.ScannerHook {
	return func(iamS *services.AWSIAMScanner, perm *services.AWSPermissionScanner, wl *services.AWSWorkloadScanner) {
		noSleep := func(context.Context, time.Duration) error { return nil }
		iamS.WithIAMAPI(a.iam).WithCredentialReportAPI(&fakeCredentialReport{}, noSleep)
		perm.WithIAMAPI(a.iam).WithEKSAPI(newFakeEKS()).
			WithResourcePolicyAPIs(&fakeS3Policy{policyByBucket: map[string]string{}}, &fakeKMSPolicy{})
		wl.WithRegionalAPIs(func(region string) (awsdiscovery.LambdaAPI, awsdiscovery.ECSAPI,
			awsdiscovery.EC2API, awsdiscovery.InstanceProfileAPI, awsdiscovery.BedrockAgentAPI,
			awsdiscovery.AgentCoreAPI, awsdiscovery.CloudTrailAPI) {
			lam := a.lambdas[region]
			if lam == nil {
				lam = &fakeLambda{}
			}
			return lam, &fakeECS{defs: map[string]ecstypes.TaskDefinition{}}, &fakeEC2{},
				&fakeInstanceProfile{roleByProfileName: map[string]string{}},
				&fakeBedrock{agents: map[string]bedrockagenttypes.Agent{}}, &fakeAgentCore{}, &fakeCloudTrail{}
		}).WithActivityAPI(&fakeActivity{}, noSleep)
	}
}

// scan runs ONE scan of the account through the REAL worker and returns the
// published run.
func (l *p2Lab) scan(a *p2Account, owner string) models.CloudScanRun {
	l.t.Helper()
	queued, err := l.runs.Enqueue(l.ws, a.conn, "manual")
	if err != nil {
		l.t.Fatalf("enqueue: %v", err)
	}
	w := services.NewAWSScanWorker(l.db, a.svc).WithOwner(owner).
		WithGraphProjection(l.gate).WithScannerHook(a.hook())
	worked, err := w.RunOnce(context.Background())
	if err != nil || !worked {
		l.t.Fatalf("scan worker %s: worked=%v err=%v", owner, worked, err)
	}
	var run models.CloudScanRun
	if err := l.db.First(&run, "id = ?", queued.ID).Error; err != nil {
		l.t.Fatalf("read run: %v", err)
	}
	if run.Status != models.CloudScanRunPublished {
		l.t.Fatalf("run %s is %s (%s), want published", run.ID, run.Status, run.LastError)
	}
	return run
}

// project runs ONE pass of the REAL projection service under `owner`, and
// requires it to COMPLETE on this first pass.
func (l *p2Lab) project(owner string) {
	l.t.Helper()
	svc := services.NewProjectionService(l.db,
		repositories.NewIGAProjectionJobRepository(l.db),
		repositories.NewIGAPipelineLeaseRepository(l.db),
		repositories.NewIGAGraphRepository(), owner, time.Minute)
	worked, err := svc.RunOnce(context.Background())
	if err != nil || !worked {
		l.t.Fatalf("projector %s: worked=%v err=%v", owner, worked, err)
	}
	var pending int64
	l.db.Raw(`SELECT count(*) FROM iga_projection_job WHERE workspace_id = ? AND status <> 'complete'`,
		l.ws).Scan(&pending)
	if pending != 0 {
		var last string
		l.db.Raw(`SELECT last_error FROM iga_projection_job WHERE workspace_id = ? AND status <> 'complete'
		          ORDER BY requested_at DESC LIMIT 1`, l.ws).Scan(&last)
		l.t.Fatalf("projection did not complete on its first pass: %s", last)
	}
	if state := l.barrier(); state != models.PipelineIdle {
		l.t.Fatalf("barrier is %s after a completed projection, want idle", state)
	}
}

var scanSeq int

// scanAndProject is one full cycle, with fresh owner names on both sides.
func (l *p2Lab) scanAndProject(a *p2Account) models.CloudScanRun {
	l.t.Helper()
	scanSeq++
	run := l.scan(a, fmt.Sprintf("scan-worker-%d", scanSeq))
	l.project(fmt.Sprintf("projector-%d", scanSeq))
	return run
}

func (l *p2Lab) barrier() string {
	var s string
	l.db.Raw(`SELECT state FROM iga_pipeline_lease WHERE workspace_id = ?`, l.ws).Scan(&s)
	return s
}

func (l *p2Lab) count(q string, args ...any) int64 {
	l.t.Helper()
	var n int64
	if err := l.db.Raw(q, args...).Scan(&n).Error; err != nil {
		l.t.Fatalf("count %q: %v", q, err)
	}
	return n
}

/* ---------------------------- graph read helpers -------------------------- */

type grantRow struct {
	ID          uuid.UUID
	Policy      string
	StatementID uuid.UUID
	Sid         string
	State       string
	ValidTo     *time.Time
	EndedReason string
	Assignment  uuid.UUID
}

// grants lists the workspace's AWS grants with the policy they come from.
func (l *p2Lab) grants() []grantRow {
	var out []grantRow
	l.db.Raw(`SELECT g.id, p.display_name AS policy, e.id AS statement_id, e.sid, g.state, g.valid_to,
	                 g.ended_reason, g.assignment_id AS assignment
	            FROM iga_access_edges g
	            JOIN iga_entitlements e ON e.workspace_id = g.workspace_id AND e.id = g.entitlement_id
	            JOIN iga_policy p ON p.workspace_id = e.workspace_id AND p.id = e.policy_id
	           WHERE g.workspace_id = ? AND g.provider = 'aws'
	           ORDER BY p.display_name, g.created_at`, l.ws).Scan(&out)
	return out
}

func grantsOf(rows []grantRow, policy string) []grantRow {
	var out []grantRow
	for _, r := range rows {
		if r.Policy == policy {
			out = append(out, r)
		}
	}
	return out
}

type assignmentRow struct {
	ID          uuid.UUID
	Policy      string
	State       string
	ValidTo     *time.Time
	EndedReason string
}

func (l *p2Lab) assignments(policy string) []assignmentRow {
	var out []assignmentRow
	l.db.Raw(`SELECT a.id, p.display_name AS policy, a.state, a.valid_to, a.ended_reason
	            FROM iga_policy_assignment a
	            JOIN iga_policy p ON p.workspace_id = a.workspace_id AND p.id = a.policy_id
	           WHERE a.workspace_id = ? AND p.display_name = ?
	           ORDER BY a.valid_from, a.id`, l.ws, policy).Scan(&out)
	return out
}

// supportOf returns a node's support states, by connector.
func (l *p2Lab) supportOf(column string, id uuid.UUID) map[uuid.UUID]string {
	var rows []struct {
		ConnectorID uuid.UUID
		State       string
	}
	l.db.Raw(`SELECT connector_id, state FROM iga_object_support WHERE workspace_id = ? AND `+column+` = ?`,
		l.ws, id).Scan(&rows)
	out := map[uuid.UUID]string{}
	for _, r := range rows {
		out[r.ConnectorID] = r.State
	}
	return out
}

func (l *p2Lab) resourceID(text string) (uuid.UUID, string) {
	var row struct {
		ID        uuid.UUID
		Lifecycle string
	}
	l.db.Raw(`SELECT id, lifecycle FROM iga_resources WHERE workspace_id = ? AND provider = 'aws'
	          AND display_name = ? AND lifecycle = 'active'`, l.ws, text).Scan(&row)
	if row.ID == uuid.Nil {
		l.db.Raw(`SELECT id, lifecycle FROM iga_resources WHERE workspace_id = ? AND provider = 'aws'
		          AND display_name = ? ORDER BY created_at DESC LIMIT 1`, l.ws, text).Scan(&row)
	}
	return row.ID, row.Lifecycle
}

// cleanup removes every row the lab wrote, children first. The integration
// database is shared, and cloud_scan_run is referenced RESTRICT by
// publications, lifecycle events, revisions and observations.
func (l *p2Lab) cleanup() {
	for _, table := range []string{
		"iga_lifecycle_event", "iga_access_edge_evidence", "iga_relationship_evidence",
		"iga_assignment_evidence", "iga_access_edges", "iga_policy_assignment",
		"iga_entitlement_target", "iga_statement_revision", "iga_object_support",
		"iga_relationship", "iga_entitlements", "iga_policy", "iga_resources", "iga_credentials",
		"iga_external_principal", "iga_workload", "iga_identity_accounts",
		"iga_projection_state", "iga_publication", "iga_projection_job", "iga_pipeline_lease",
		"iga_estate_scopes", "cloud_observation", "cloud_policy_attachment",
		"cloud_group_membership", "cloud_policy", "cloud_usage", "cloud_workload",
		"cloud_permission", "cloud_assume_edge", "cloud_resource", "cloud_secret",
		"cloud_identity", "cloud_scan_checkpoint", "cloud_scan_run", "cloud_connector",
	} {
		if err := l.db.Exec(`DELETE FROM `+table+` WHERE workspace_id = ?`, l.ws).Error; err != nil {
			l.t.Logf("cleanup %s: %v", table, err)
		}
	}
}
