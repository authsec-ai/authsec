package integration

// used_by_count on /identities counts DISTINCT workloads (D-17): an ECS task
// definition whose task role is also its execution role reaches that role
// through two relationships, executes_as and task_execution_role, and is still
// ONE workload using it -- a count of relationships would read 2 with exact:
// true, a number that looks exact and is wrong.

import (
	"context"
	"fmt"
	"testing"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/aws/aws-sdk-go-v2/aws"
	bedrockagenttypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

// listsScanAndProjectECS is the lab's scanAndProject with these ECS task
// definitions in every selected region: the lab's own hook always hands the
// scanner an empty ECS fake, so this runs the same REAL worker and projector
// with a hook that differs only there.
func listsScanAndProjectECS(t *testing.T, l *p2Lab, a *p2Account, defs ...ecstypes.TaskDefinition) models.CloudScanRun {
	t.Helper()
	ecs := &fakeECS{defs: map[string]ecstypes.TaskDefinition{}}
	for _, d := range defs {
		ecs.defs[aws.ToString(d.TaskDefinitionArn)] = d
	}
	hook := func(iamS *services.AWSIAMScanner, perm *services.AWSPermissionScanner, wl *services.AWSWorkloadScanner) {
		a.hook()(iamS, perm, wl)
		wl.WithRegionalAPIs(func(region string) (awsdiscovery.LambdaAPI, awsdiscovery.ECSAPI,
			awsdiscovery.EC2API, awsdiscovery.InstanceProfileAPI, awsdiscovery.BedrockAgentAPI,
			awsdiscovery.AgentCoreAPI, awsdiscovery.CloudTrailAPI) {
			lam := a.lambdas[region]
			if lam == nil {
				lam = &fakeLambda{}
			}
			return lam, ecs, &fakeEC2{}, &fakeInstanceProfile{roleByProfileName: map[string]string{}},
				&fakeBedrock{agents: map[string]bedrockagenttypes.Agent{}}, &fakeAgentCore{}, &fakeCloudTrail{}
		})
	}

	scanSeq++
	queued, err := l.runs.Enqueue(l.ws, a.conn, "manual")
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	w := services.NewAWSScanWorker(l.db, a.svc).WithOwner(fmt.Sprintf("lists-ecs-scan-%d", scanSeq)).
		WithGraphProjection(l.gate).WithScannerHook(hook)
	if worked, err := w.RunOnce(context.Background()); err != nil || !worked {
		t.Fatalf("scan worker: worked=%v err=%v", worked, err)
	}
	var run models.CloudScanRun
	if err := l.db.First(&run, "id = ?", queued.ID).Error; err != nil {
		t.Fatalf("read run: %v", err)
	}
	if run.Status != models.CloudScanRunPublished {
		t.Fatalf("run %s is %s (%s), want published", run.ID, run.Status, run.LastError)
	}
	l.project(fmt.Sprintf("lists-ecs-projector-%d", scanSeq))
	return run
}

func TestP2ListsUsedByCountsDistinctWorkloads(t *testing.T) {
	l := newP2Lab(t, "p2-lists-used-by", true)
	a := l.account(accountA)
	ledgerRole := a.role("LedgerRole", "AROALEDGERROLELEDGE1")
	pullRole := a.role("ImagePullRole", "AROAIMAGEPULLROLEIMG")
	appRole := a.role("BillingAppRole", "AROABILLINGAPPROLEBI")
	// ledger-fn runs as LedgerRole too, so the right answer (2) is neither the
	// relationship count (3) nor "any use" (1).
	listsFunctions(a, "us-east-1", "ledger-fn", ledgerRole)
	taskDef := func(family, taskRole, execRole string) ecstypes.TaskDefinition {
		arn := "arn:aws:ecs:us-east-1:" + accountA + ":task-definition/" + family + ":1"
		return ecstypes.TaskDefinition{TaskDefinitionArn: aws.String(arn), Family: aws.String(family),
			TaskRoleArn: aws.String(taskRole), ExecutionRoleArn: aws.String(execRole),
			Status: ecstypes.TaskDefinitionStatusActive}
	}
	listsScanAndProjectECS(t, l, a,
		// The task role IS the execution role: two relationships, one workload.
		taskDef("ledger", ledgerRole, ledgerRole),
		// An execution role alone is a use too (task_execution_role, D-17).
		taskDef("billing", appRole, pullRole))

	// The fixture must really reach LedgerRole twice from one workload, or
	// this test proves nothing about DISTINCT.
	var edges []struct {
		RelationshipType string
		Workload         string
	}
	if err := l.db.Raw(`SELECT r.relationship_type, r.source_workload_id::text AS workload
	                      FROM iga_relationship r
	                      JOIN iga_identity_accounts ia ON ia.workspace_id = r.workspace_id AND ia.id = r.target_identity_account_id
	                     WHERE r.workspace_id = ? AND ia.display_name = 'LedgerRole' AND r.state = 'current'
	                       AND r.relationship_type IN ('executes_as', 'task_execution_role')
	                     ORDER BY 2, 1`, l.ws).Scan(&edges).Error; err != nil {
		t.Fatalf("read LedgerRole's uses: %v", err)
	}
	perWorkload := map[string]int{}
	for _, e := range edges {
		perWorkload[e.Workload]++
	}
	if len(edges) != 3 || len(perWorkload) != 2 {
		t.Fatalf("setup: LedgerRole's current uses = %+v, want 3 relationships from 2 workloads "+
			"(the ledger task definition through both executes_as and task_execution_role)", edges)
	}

	body := listsGet(t, l.api(), "/identities")
	for name, want := range map[string]int64{"LedgerRole": 2, "ImagePullRole": 1, "BillingAppRole": 1} {
		r := listsRowBy(t, digl(body, "data"), "name", name)
		if num(r, "used_by_count", "value") != want || dig(r, "used_by_count", "exact") != true {
			t.Errorf("%s used_by_count = %v, want {%d, exact: true}: distinct workloads, not relationships",
				name, r["used_by_count"], want)
		}
	}
	// The filter over the same relationships agrees (D-17).
	got := listsField(listsWalk(t, l.api(), "/identities", 100, "used_by", "workloads"), "name")
	if !listsSameSet(got, []string{"LedgerRole", "ImagePullRole", "BillingAppRole"}) {
		t.Errorf("used_by=workloads = %v, want every role some workload uses", got)
	}
}
