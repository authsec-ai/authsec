package integration

// Shared plumbing for the §7.3 backend scenarios of the bdb stream
// (SPEC-iga-phase2-graph.md §7.3: B1, B4, B8, B10, B11, B13, B18, B21, B24;
// §7.1 E1; and the D-61/D-64/T4.4/T4.9 fixes). Every scenario runs through the
// P2-0 lab: the REAL scan worker and the REAL projection service, with AWS
// answered by fakes. Everything here is prefixed bdb so it cannot collide with
// another stream's helpers in this package.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	bedrockagenttypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// bdbFakes is what a scenario adds to the lab's own hook, which always hands
// the workload scanner EMPTY ECS and Bedrock fakes (p2Account.hook). Both are
// served in every region the account selected. ecsFail denies the ECS listing
// in every region (the surface is then not reached).
type bdbFakes struct {
	ecs     []ecstypes.TaskDefinition
	agents  []bedrockagenttypes.Agent
	ecsFail error
}

// bdbHook is the lab's hook with the ECS and Bedrock fakes replaced: the same
// IAM, permission and Lambda fakes, so a scenario differs from the lab only
// where it says so.
func bdbHook(a *p2Account, f bdbFakes) services.ScannerHook {
	return func(iamS *services.AWSIAMScanner, perm *services.AWSPermissionScanner, wl *services.AWSWorkloadScanner) {
		a.hook()(iamS, perm, wl)
		wl.WithRegionalAPIs(func(region string) (awsdiscovery.LambdaAPI, awsdiscovery.ECSAPI,
			awsdiscovery.EC2API, awsdiscovery.InstanceProfileAPI, awsdiscovery.BedrockAgentAPI,
			awsdiscovery.AgentCoreAPI, awsdiscovery.CloudTrailAPI) {
			lam := a.lambdas[region]
			if lam == nil {
				lam = &fakeLambda{}
			}
			ecs := &fakeECS{defs: map[string]ecstypes.TaskDefinition{}, fail: f.ecsFail}
			for _, d := range f.ecs {
				if arn := aws.ToString(d.TaskDefinitionArn); bdbRegionOf(arn) == region {
					ecs.defs[arn] = d
				}
			}
			bedrock := &fakeBedrock{agents: map[string]bedrockagenttypes.Agent{}}
			for _, ag := range f.agents {
				if bdbRegionOf(aws.ToString(ag.AgentArn)) == region {
					bedrock.agents[aws.ToString(ag.AgentId)] = ag
				}
			}
			return lam, ecs, &fakeEC2{}, &fakeInstanceProfile{roleByProfileName: map[string]string{}},
				bedrock, &fakeAgentCore{}, &fakeCloudTrail{}
		})
	}
}

// bdbRegionOf is an ARN's region field ("" when it has none).
func bdbRegionOf(arn string) string {
	if parts := strings.SplitN(arn, ":", 6); len(parts) == 6 {
		return parts[3]
	}
	return ""
}

// bdbScan is l.scan with bdbHook: ONE scan through the REAL worker under a
// fresh owner name, required to publish.
func bdbScan(l *p2Lab, a *p2Account, f bdbFakes) models.CloudScanRun {
	l.t.Helper()
	scanSeq++
	queued, err := l.runs.Enqueue(l.ws, a.conn, "manual")
	if err != nil {
		l.t.Fatalf("enqueue: %v", err)
	}
	w := services.NewAWSScanWorker(l.db, a.svc).WithOwner(fmt.Sprintf("bdb-scan-%d", scanSeq)).
		WithGraphProjection(l.gate).WithScannerHook(bdbHook(a, f))
	if worked, err := w.RunOnce(context.Background()); err != nil || !worked {
		l.t.Fatalf("scan worker: worked=%v err=%v", worked, err)
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

// bdbCycle is one full cycle with bdbHook: a scan, then a projection that must
// complete on its first pass with the barrier idle (p2Lab.project), under a
// different owner name on each side.
func bdbCycle(l *p2Lab, a *p2Account, f bdbFakes) models.CloudScanRun {
	l.t.Helper()
	run := bdbScan(l, a, f)
	l.project(fmt.Sprintf("bdb-projector-%d", scanSeq))
	return run
}

// bdbTaskDef is one ACTIVE ECS task definition revision in the account.
func bdbTaskDef(a *p2Account, region, family string, revision int, taskRole, execRole string) ecstypes.TaskDefinition {
	arn := fmt.Sprintf("arn:aws:ecs:%s:%s:task-definition/%s:%d", region, a.id, family, revision)
	return ecstypes.TaskDefinition{
		TaskDefinitionArn: aws.String(arn), Family: aws.String(family), Revision: int32(revision),
		TaskRoleArn: aws.String(taskRole), ExecutionRoleArn: aws.String(execRole),
		Status: ecstypes.TaskDefinitionStatusActive,
	}
}

// bdbAgent is one prepared Bedrock agent running as roleARN.
func bdbAgent(a *p2Account, region, id, name, roleARN string) bedrockagenttypes.Agent {
	return bedrockagenttypes.Agent{
		AgentId:              aws.String(id),
		AgentArn:             aws.String("arn:aws:bedrock:" + region + ":" + a.id + ":agent/" + id),
		AgentName:            aws.String(name),
		AgentResourceRoleArn: aws.String(roleARN),
		FoundationModel:      aws.String("amazon.titan-text-express-v1"),
		AgentStatus:          bedrockagenttypes.AgentStatusPrepared,
	}
}

// bdbID is the one id a query returns; zero or several rows fail the test.
func bdbID(t *testing.T, l *p2Lab, q string, args ...any) uuid.UUID {
	t.Helper()
	var ids []uuid.UUID
	if err := l.db.Raw(q, args...).Scan(&ids).Error; err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	if len(ids) != 1 {
		t.Fatalf("%s: %d rows, want exactly 1", q, len(ids))
	}
	return ids[0]
}

// bdbIdentity is the ACTIVE AWS identity with this display name.
func bdbIdentity(t *testing.T, l *p2Lab, name string) uuid.UUID {
	t.Helper()
	return bdbID(t, l, `SELECT id FROM iga_identity_accounts WHERE workspace_id = ? AND provider = 'aws'
	                    AND display_name = ? AND lifecycle = 'active'`, l.ws, name)
}

// bdbEdge is one edge row of any of the three edge tables, as reconciliation
// and the Changes view read it.
type bdbEdge struct {
	ID              uuid.UUID
	Kind            string // relationship type, "assignment" or "grant"
	State           string
	ValidFrom       time.Time
	ValidTo         *time.Time
	EndedReason     string
	LastConfirmedAt time.Time
	LastConfirmedBy *uuid.UUID
	ConnectorID     *uuid.UUID
}

// bdbEdges is every edge of the workspace (AWS grants only), keyed by id.
func bdbEdges(t *testing.T, l *p2Lab) map[uuid.UUID]bdbEdge {
	t.Helper()
	var rows []bdbEdge
	if err := l.db.Raw(`
		SELECT id, relationship_type AS kind, state, valid_from, valid_to, ended_reason,
		       last_confirmed_at, last_confirmed_by, connector_id
		  FROM iga_relationship WHERE workspace_id = ?
		UNION ALL
		SELECT id, 'assignment', state, valid_from, valid_to, ended_reason,
		       last_confirmed_at, last_confirmed_by, connector_id
		  FROM iga_policy_assignment WHERE workspace_id = ?
		UNION ALL
		SELECT id, 'grant', state, valid_from, valid_to, ended_reason,
		       last_confirmed_at, last_confirmed_by, connector_id
		  FROM iga_access_edges WHERE workspace_id = ? AND provider = 'aws'`,
		l.ws, l.ws, l.ws).Scan(&rows).Error; err != nil {
		t.Fatalf("read edges: %v", err)
	}
	out := make(map[uuid.UUID]bdbEdge, len(rows))
	for _, r := range rows {
		out[r.ID] = r
	}
	return out
}

// bdbSupport is one iga_object_support row, with the class it vouches for.
type bdbSupport struct {
	ID              uuid.UUID
	Class           string
	Object          uuid.UUID
	State           string
	EndedReason     string
	LastConfirmedAt *time.Time
	FirstSeenAt     time.Time
	PartitionKey    string
	ConnectorID     uuid.UUID
}

// bdbSupports is every support row of the workspace, keyed by id.
func bdbSupports(t *testing.T, l *p2Lab) map[uuid.UUID]bdbSupport {
	t.Helper()
	var rows []bdbSupport
	if err := l.db.Raw(`
		SELECT id,
		       CASE WHEN identity_account_id IS NOT NULL THEN 'identity'
		            WHEN workload_id IS NOT NULL THEN 'workload'
		            WHEN resource_id IS NOT NULL THEN 'resource'
		            WHEN entitlement_id IS NOT NULL THEN 'entitlement'
		            ELSE 'policy' END AS class,
		       COALESCE(identity_account_id, workload_id, resource_id, entitlement_id, policy_id) AS object,
		       state, ended_reason, last_confirmed_at, first_seen_at, partition_key, connector_id
		  FROM iga_object_support WHERE workspace_id = ?`, l.ws).Scan(&rows).Error; err != nil {
		t.Fatalf("read support: %v", err)
	}
	out := make(map[uuid.UUID]bdbSupport, len(rows))
	for _, r := range rows {
		out[r.ID] = r
	}
	return out
}

// bdbLifecycles is every AWS node's lifecycle and retired_reason, by id.
func bdbLifecycles(t *testing.T, l *p2Lab) map[uuid.UUID][2]string {
	t.Helper()
	var rows []struct {
		ID            uuid.UUID
		Lifecycle     string
		RetiredReason string
	}
	if err := l.db.Raw(`
		SELECT id, lifecycle, retired_reason FROM iga_identity_accounts WHERE workspace_id = ? AND provider = 'aws'
		UNION ALL SELECT id, lifecycle, retired_reason FROM iga_workload WHERE workspace_id = ?
		UNION ALL SELECT id, lifecycle, retired_reason FROM iga_policy WHERE workspace_id = ?
		UNION ALL SELECT id, lifecycle, retired_reason FROM iga_entitlements WHERE workspace_id = ? AND provider = 'aws'
		UNION ALL SELECT id, lifecycle, retired_reason FROM iga_resources WHERE workspace_id = ? AND provider = 'aws'`,
		l.ws, l.ws, l.ws, l.ws, l.ws).Scan(&rows).Error; err != nil {
		t.Fatalf("read lifecycles: %v", err)
	}
	out := make(map[uuid.UUID][2]string, len(rows))
	for _, r := range rows {
		out[r.ID] = [2]string{r.Lifecycle, r.RetiredReason}
	}
	return out
}

// bdbEvent is one iga_lifecycle_event row joined to the publication of its
// run, so a test can check the event's rev against the revision that run
// actually published (iga_le_publication_fkey proves only that the rev exists).
type bdbEvent struct {
	Event      string
	Reason     string
	Rev        int64
	ScanRunID  uuid.UUID
	PubRev     *int64
	OccurredAt time.Time
	PubAt      *time.Time
}

// bdbEventsOf is the lifecycle history of one object, oldest first. column is
// the event's typed subject column (identity_account_id, workload_id, ...).
func bdbEventsOf(t *testing.T, l *p2Lab, column string, id uuid.UUID) []bdbEvent {
	t.Helper()
	var out []bdbEvent
	if err := l.db.Raw(`SELECT e.event, e.reason, e.rev, e.scan_run_id, p.rev AS pub_rev,
	                           e.occurred_at, p.published_at AS pub_at
	                      FROM iga_lifecycle_event e
	                      LEFT JOIN iga_publication p ON p.workspace_id = e.workspace_id AND p.scan_run_id = e.scan_run_id
	                     WHERE e.workspace_id = ? AND e.`+column+` = ?
	                     ORDER BY e.rev, e.event`, l.ws, id).Scan(&out).Error; err != nil {
		t.Fatalf("read events: %v", err)
	}
	return out
}

// bdbRevOf is the revision a run published.
func bdbRevOf(t *testing.T, l *p2Lab, run uuid.UUID) int64 {
	t.Helper()
	var rev int64
	if err := l.db.Raw(`SELECT rev FROM iga_publication WHERE workspace_id = ? AND scan_run_id = ?`,
		l.ws, run).Row().Scan(&rev); err != nil {
		t.Fatalf("publication of run %s: %v", run, err)
	}
	return rev
}
