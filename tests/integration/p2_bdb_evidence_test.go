package integration

// T4.9 (SPEC-iga-phase2-graph.md §4.8, §7.1 E4): ZERO projected edges without
// evidence -- counted per edge, never per class -- over every edge kind the
// projector writes, in TWO connected accounts, after first scans AND after
// unchanged rescans (where content dedupe writes no new observation and the
// evidence must follow the re-confirmed one). TestP2UnchangedRescan covers only
// the one-Lambda slice: executes_as, one assignment, one grant.

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// bdbEvidenceCount is one (edge kind, connector) cell of the evidence audit.
type bdbEvidenceCount struct {
	Kind        string
	ConnectorID uuid.UUID
	Total       int
	// Bare: edges with no 'supports' link at all.
	Bare int
	// Unconfirmed: edges none of whose observations was confirmed by the run
	// that last confirmed the edge -- evidence of an older reading only (D-24).
	Unconfirmed int
	// Foreign: edges linked to an observation another connector collected.
	Foreign int
}

// bdbEvidenceAudit counts every non-ended edge of the workspace, per kind and
// connector: relationships by type, assignments, and AWS grants.
func bdbEvidenceAudit(t *testing.T, l *p2Lab) map[string]map[uuid.UUID]bdbEvidenceCount {
	t.Helper()
	audit := func(edges, kind, junction, column, extra string) string {
		ev := `FROM ` + junction + ` e JOIN cloud_observation o ON o.workspace_id = e.workspace_id AND o.id = e.observation_id
		       WHERE e.workspace_id = x.workspace_id AND e.` + column + ` = x.id AND e.relation = 'supports'`
		return `SELECT ` + kind + ` AS kind, x.connector_id, count(*) AS total,
		               count(*) FILTER (WHERE NOT EXISTS (SELECT 1 ` + ev + `)) AS bare,
		               count(*) FILTER (WHERE NOT EXISTS (SELECT 1 ` + ev + ` AND o.last_confirmed_run_id = x.last_confirmed_by)) AS unconfirmed,
		               count(*) FILTER (WHERE EXISTS (SELECT 1 ` + ev + ` AND o.connector_id IS DISTINCT FROM x.connector_id)) AS foreign
		          FROM ` + edges + ` x
		         WHERE x.workspace_id = @ws AND x.state <> 'ended'` + extra + `
		         GROUP BY 1, 2`
	}
	q := audit("iga_relationship", "x.relationship_type", "iga_relationship_evidence", "relationship_id", "") +
		` UNION ALL ` + audit("iga_policy_assignment", "'assignment'", "iga_assignment_evidence", "assignment_id", "") +
		` UNION ALL ` + audit("iga_access_edges", "'grant'", "iga_access_edge_evidence", "access_edge_id", ` AND x.provider = 'aws'`)
	var rows []bdbEvidenceCount
	if err := l.db.Raw(q, map[string]any{"ws": l.ws}).Scan(&rows).Error; err != nil {
		t.Fatalf("evidence audit: %v", err)
	}
	out := map[string]map[uuid.UUID]bdbEvidenceCount{}
	for _, r := range rows {
		if out[r.Kind] == nil {
			out[r.Kind] = map[uuid.UUID]bdbEvidenceCount{}
		}
		out[r.Kind][r.ConnectorID] = r
	}
	return out
}

// bdbEvidenceLab is two connected accounts carrying every edge kind:
//
//	A  ticket-tools (Lambda) and billing:1 (ECS)  -> executes_as, task_execution_role
//	   SharedToolRole: TicketRead (managed) + ToolsInline (inline)
//	   BillingTaskRole: DevBoundary as its permissions boundary
//	   priya in ops; OpsRead on ops, UserRead on priya  -> member_of, group and user assignments
//	B  report-tools (Lambda) -> ReportRole; sam in analysts, AnalystsRead on analysts
//	   CrossReader trusts A's SharedToolRole (an IDENTITY in a connected account)
//	   and account C's root (an external principal)  -> cross-account can_assume
//
// and every role trusts the Lambda service (can_assume from an external
// principal). A is projected first, so B's trust document finds A's role live.
func bdbEvidenceLab(t *testing.T) (*p2Lab, *p2Account, *p2Account, bdbFakes) {
	t.Helper()
	l := newP2Lab(t, "p2-bdb-t49", true)
	a := l.account(accountA)
	shared := a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	a.attach("SharedToolRole", a.managed("TicketRead", docTicketRead))
	a.iam.inlineRolePolicies["SharedToolRole"] = map[string]string{"ToolsInline": docToolboxRead}
	listsFunctions(a, "us-east-1", "ticket-tools", shared)
	taskRole := a.role("BillingTaskRole", "AROABILLINGTASKROLE1")
	pull := a.role("ImagePullRole", "AROAIMAGEPULLROLE001")
	boundary := a.managed("DevBoundary", s3aDoc("All", "s3:*", "*"))
	s3aEditRole(t, a, "BillingTaskRole", func(r *iamtypes.Role) { r.PermissionsBoundary = s3aBoundary(boundary) })
	s3aGroup(a, "ops", "AGPAOPSOPSOPSOPSOPS1")
	s3aUser(a, "priya", "AIDAPRIYAPRIYAPRIYA1")
	s3aJoin(a, "priya", "ops")
	s3aGroupAttach(t, a, "ops", a.managed("OpsRead", s3aDoc("OpsRead", "s3:GetObject", "arn:aws:s3:::ops-runbooks/*")))
	userRead := a.managed("UserRead", s3aDoc("UserRead", "s3:GetObject", "arn:aws:s3:::priya-home/*"))
	a.iam.attachedUserPolicies["priya"] = []iamtypes.AttachedPolicy{
		{PolicyArn: aws.String(userRead), PolicyName: aws.String("UserRead")}}
	fakesA := bdbFakes{ecs: []ecstypes.TaskDefinition{bdbTaskDef(a, "us-east-1", "billing", 1, taskRole, pull)}}

	b := l.account(accountB)
	report := b.role("ReportRole", "AROAREPORTROLEREPOR1")
	reportRead := b.managed("ReportRead", s3aDoc("ReportRead", "s3:GetObject", "arn:aws:s3:::reports/*"))
	b.attach("ReportRole", reportRead)
	listsFunctions(b, "us-east-1", "report-tools", report)
	trustRole(b, "CrossReader", "AROACROSSREADERCROS1", trustDoc(
		trustAllow(`{"AWS":"`+shared+`"}`, "sts:AssumeRole"),
		trustAllow(`{"AWS":"arn:aws:iam::`+trustAccountC+`:root"}`, "sts:AssumeRole")))
	b.attach("CrossReader", reportRead)
	s3aGroup(b, "analysts", "AGPAANALYSTSANALYST1")
	s3aUser(b, "sam", "AIDASAMSAMSAMSAMSAM1")
	s3aJoin(b, "sam", "analysts")
	s3aGroupAttach(t, b, "analysts", b.managed("AnalystsRead", s3aDoc("", "s3:ListBucket", "arn:aws:s3:::reports")))
	return l, a, b, fakesA
}

// T4.9, extended: after each cycle -- A, then B, then both again unchanged --
// every current or stale edge of every kind, in either account, has evidence;
// evidence the run that last confirmed it confirmed too (the fact the edge
// stands on now, D-24); and evidence its own account collected. Non-vacuity:
// every kind is present, in both accounts where the fixture puts it there,
// and the cross-account can_assume (B's CrossReader trusting A's identity)
// exists.
//
// Safeguards (mutation-checked): attachEvidence links member_of and can_assume
// edges (each dropped in turn).
func TestP2BdbEveryEdgeHasEvidence(t *testing.T) {
	l, a, b, fakesA := bdbEvidenceLab(t)
	check := func(stage string, wantB bool) {
		t.Helper()
		got := bdbEvidenceAudit(t, l)
		for kind, byConn := range got {
			for conn, c := range byConn {
				if c.Bare != 0 || c.Unconfirmed != 0 || c.Foreign != 0 {
					t.Errorf("%s: %s edges of connector %s: %d total, %d without evidence, %d without evidence from their confirming run, %d with another connector's (T4.9 requires zero)",
						stage, kind, conn, c.Total, c.Bare, c.Unconfirmed, c.Foreign)
				}
			}
		}
		// Non-vacuity: what the fixture must have produced by now.
		want := map[string][]uuid.UUID{
			models.RelTypeExecutesAs:        {a.conn},
			models.RelTypeTaskExecutionRole: {a.conn},
			models.RelTypeMemberOf:          {a.conn},
			models.RelTypeCanAssume:         {a.conn},
			"assignment":                    {a.conn},
			"grant":                         {a.conn},
		}
		if wantB {
			for _, k := range []string{models.RelTypeExecutesAs, models.RelTypeMemberOf, models.RelTypeCanAssume, "assignment", "grant"} {
				want[k] = append(want[k], b.conn)
			}
		}
		for kind, conns := range want {
			for _, conn := range conns {
				if got[kind][conn].Total == 0 {
					t.Errorf("%s: no live %s edge of connector %s -- the fixture must carry one (audit %+v)", stage, kind, conn, got[kind])
				}
			}
		}
	}

	bdbCycle(l, a, fakesA)
	check("after A", false)
	l.scanAndProject(b)
	check("after B", true)
	// The cross-account trust: sourced from A's IDENTITY, in B's partition.
	if n := l.count(`SELECT count(*) FROM iga_relationship r
	                   JOIN iga_identity_accounts s ON s.workspace_id = r.workspace_id AND s.id = r.source_identity_account_id
	                   JOIN iga_identity_accounts d ON d.workspace_id = r.workspace_id AND d.id = r.target_identity_account_id
	                  WHERE r.workspace_id = ? AND r.relationship_type = 'can_assume' AND r.state = 'current'
	                    AND s.display_name = 'SharedToolRole' AND d.display_name = 'CrossReader' AND r.connector_id = ?`,
		l.ws, b.conn); n != 1 {
		t.Errorf("can_assume SharedToolRole (A) -> CrossReader (B) = %d current rows, want 1", n)
	}

	// Unchanged rescans: no new observation is written (content dedupe), the
	// existing ones are re-confirmed, and every edge must follow them.
	time.Sleep(10 * time.Millisecond)
	bdbCycle(l, a, fakesA)
	check("after A again", true)
	time.Sleep(10 * time.Millisecond)
	l.scanAndProject(b)
	check("after B again", true)
}
