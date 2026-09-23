package integration

// T6.4: task_execution_role (§5.4, workload -> identity like executes_as),
// over ECS task definitions the REAL scan worker and projector read
// (listsScanAndProjectECS runs the lab's pipeline with an ECS fake).
//
// A task definition whose task role IS its execution role reaches that role
// through two edges: the node is returned ONCE and the two edges say how --
// neither closes a cycle (the role is not on the path that reached the
// workload).

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

func TestP2GraphTaskExecutionRole(t *testing.T) {
	l := newP2Lab(t, "p2-graph-ecs", true)
	a := l.account(accountA)
	ledgerRole := a.role("LedgerRole", "AROALEDGERROLELEDGE1")
	pullRole := a.role("ImagePullRole", "AROAIMAGEPULLROLEIMG")
	appRole := a.role("BillingAppRole", "AROABILLINGAPPROLEBI")
	taskDef := func(family, taskRole, execRole string) ecstypes.TaskDefinition {
		arn := "arn:aws:ecs:us-east-1:" + accountA + ":task-definition/" + family + ":1"
		return ecstypes.TaskDefinition{TaskDefinitionArn: aws.String(arn), Family: aws.String(family),
			TaskRoleArn: aws.String(taskRole), ExecutionRoleArn: aws.String(execRole),
			Status: ecstypes.TaskDefinitionStatusActive}
	}
	listsScanAndProjectECS(t, l, a, taskDef("ledger", ledgerRole, ledgerRole), taskDef("billing", appRole, pullRole))
	api := l.api()
	var billing, ledger string
	for _, w := range digl(listsGet(t, api, "/workloads"), "data") {
		switch {
		case digs(w, "arn") == "arn:aws:ecs:us-east-1:"+accountA+":task-definition/billing:1":
			billing = digs(w, "ref")
		case digs(w, "arn") == "arn:aws:ecs:us-east-1:"+accountA+":task-definition/ledger:1":
			ledger = digs(w, "ref")
		}
	}
	if billing == "" || ledger == "" {
		t.Fatal("setup: the task definitions were not projected as workloads")
	}
	app, pull, led := graphIdentity(t, l, "BillingAppRole"), graphIdentity(t, l, "ImagePullRole"), graphIdentity(t, l, "LedgerRole")

	// billing: runs as BillingAppRole, ECS pulls with ImagePullRole. Kind
	// order (§5.4): executes_as before task_execution_role.
	body := graphGet(t, api, "/graph"+qs("root", billing, "direction", "forward"))
	es := graphEdges(t, digl(body, "data", "edges"))
	if len(es) != 2 || es[0].Kind != "executes_as" || es[0].To != app ||
		es[1].Kind != "task_execution_role" || es[1].To != pull {
		t.Errorf("billing forward = %+v, want executes_as -> BillingAppRole then task_execution_role -> ImagePullRole", es)
	}
	// Reverse from the execution role: the workload, through that edge.
	rev := graphGet(t, api, "/graph"+qs("root", pull, "direction", "reverse"))
	if x := graphEdgesOfKind(graphEdges(t, digl(rev, "data", "edges")), "task_execution_role"); len(x) != 1 || x[0].From != billing {
		t.Errorf("reverse from ImagePullRole = %v, want billing's task_execution_role", rev["data"])
	}
	exp := graphGet(t, api, "/graph/expand"+qs("node", pull, "edge", "task_execution_role", "direction", "reverse"))
	if x := graphEdges(t, digl(exp, "data", "edges")); len(x) != 1 || x[0].From != billing {
		t.Errorf("expand ImagePullRole task_execution_role reverse = %v, want billing", exp["data"])
	}

	// ledger: one role, two edges, one node.
	body = graphGet(t, api, "/graph"+qs("root", ledger, "direction", "forward"))
	nodes := graphNodes(t, digl(body, "data", "nodes")) // fails on a node returned twice
	es = graphEdges(t, digl(body, "data", "edges"))
	if len(nodes) != 2 || nodes[led] == nil || len(es) != 2 || es[0].To != led || es[1].To != led ||
		es[0].Kind == es[1].Kind || es[0].ClosesCycle || es[1].ClosesCycle {
		t.Errorf("ledger forward = nodes %v edges %+v, want LedgerRole once, reached by executes_as AND task_execution_role, no cycle", nodes, es)
	}
	// Both are uses: the list's used_by_count on the node counts ONE workload.
	if c := nodes[led]["used_by_count"]; num(c, "value") != 1 || dig(c, "exact") != true {
		t.Errorf("LedgerRole used_by_count = %v, want 1 distinct workload (D-17)", c)
	}
}
