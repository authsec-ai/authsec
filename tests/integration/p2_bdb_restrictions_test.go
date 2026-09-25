package integration

// B10 (SPEC-iga-phase2-graph.md §7.3; §2.6 "a boundary limits, a Deny
// restricts, neither grants"), the database half: a permissions boundary and a
// Deny statement are STORED, as restrictions, and give ZERO grants. The API
// half (restrictions {deny_statements, permissions_boundary} and the limitation
// codes) is asserted by the T6.3/T6.5 route tests. Through the REAL scan worker
// and projector.

import (
	"testing"

	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// B10: BoundedRole carries the customer-managed DevBoundary as its
// permissions boundary -- a document of broad ALLOW statements -- and holds
// ReadButNotDelete, one Allow and one Deny. The boundary is a policy with its
// statements, attached to the role as an assignment of kind 'boundary', current;
// NOTHING is granted through it. The Deny statement is stored with its effect
// and has no grant. The role's only grant is the one Allow statement of the
// attached policy.
//
// Safeguards (mutation-checked): projectGrants skips boundary attachments (§2.6
// l.549: a boundary is a ceiling, never access); and the Deny rule -- the
// projector's effect check and the write-time refusal in UpsertGrant together
// (M8b's pair; either alone leaves the other).
func TestP2BdbBoundaryAndDenyGrantNothing(t *testing.T) {
	l := newP2Lab(t, "p2-bdb-b10", true)
	a := l.account(accountA)
	a.role("BoundedRole", "AROABOUNDEDROLEBOUND")
	boundary := a.managed("DevBoundary", `{"Version":"2012-10-17","Statement":[`+
		`{"Sid":"AllS3","Effect":"Allow","Action":"s3:*","Resource":"*"},`+
		`{"Effect":"Allow","Action":["dynamodb:GetItem","dynamodb:Query"],"Resource":"arn:aws:dynamodb:us-east-1:`+accountA+`:table/*"}]}`)
	s3aEditRole(t, a, "BoundedRole", func(r *iamtypes.Role) { r.PermissionsBoundary = s3aBoundary(boundary) })
	a.attach("BoundedRole", a.managed("ReadButNotDelete", `{"Version":"2012-10-17","Statement":[`+
		`{"Sid":"Read","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"},`+
		`{"Sid":"NoDelete","Effect":"Deny","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::b/*"}]}`))
	l.scanAndProject(a)
	role := bdbIdentity(t, l, "BoundedRole")

	// The boundary is a policy, with its statements, and a current assignment
	// of kind boundary on the role.
	var asg []struct {
		ID     uuid.UUID
		Policy string
		Kind   string
		State  string
	}
	l.db.Raw(`SELECT a.id, p.display_name AS policy, a.assignment_kind AS kind, a.state
	            FROM iga_policy_assignment a JOIN iga_policy p ON p.workspace_id = a.workspace_id AND p.id = a.policy_id
	           WHERE a.workspace_id = ? AND a.holder_identity_account_id = ? ORDER BY p.display_name`, l.ws, role).Scan(&asg)
	if len(asg) != 2 || asg[0].Policy != "DevBoundary" || asg[0].Kind != models.AssignmentBoundary ||
		asg[0].State != models.RelCurrent || asg[1].Policy != "ReadButNotDelete" || asg[1].Kind != models.CloudAttachmentAttached {
		t.Fatalf("assignments = %+v, want DevBoundary as a current 'boundary' assignment beside ReadButNotDelete 'attached'", asg)
	}
	boundaryAsg := asg[0].ID
	if n := l.count(`SELECT count(*) FROM iga_entitlements e JOIN iga_policy p ON p.workspace_id = e.workspace_id AND p.id = e.policy_id
	                  WHERE e.workspace_id = ? AND e.provider = 'aws' AND p.display_name = 'DevBoundary'
	                    AND e.effect = 'allow' AND e.lifecycle = 'active'`, l.ws); n != 2 {
		t.Fatalf("DevBoundary statements = %d, want its 2 Allow statements stored (a restriction is recorded, not dropped)", n)
	}

	// ZERO grants through the boundary, whatever its statements allow.
	if n := l.count(`SELECT count(*) FROM iga_access_edges WHERE workspace_id = ? AND provider = 'aws' AND assignment_id = ?`,
		l.ws, boundaryAsg); n != 0 {
		t.Errorf("%d grants through the permissions boundary: a boundary limits, it never grants", n)
	}
	if n := l.count(`SELECT count(*) FROM iga_access_edges g
	                   JOIN iga_entitlements e ON e.workspace_id = g.workspace_id AND e.id = g.entitlement_id
	                   JOIN iga_policy p ON p.workspace_id = e.workspace_id AND p.id = e.policy_id
	                  WHERE g.workspace_id = ? AND p.display_name = 'DevBoundary'`, l.ws); n != 0 {
		t.Errorf("%d grants on DevBoundary's statements", n)
	}

	// The Deny statement: stored with its effect, and no grant.
	var deny struct {
		ID     uuid.UUID
		Effect string
	}
	l.db.Raw(`SELECT id, effect FROM iga_entitlements WHERE workspace_id = ? AND provider = 'aws' AND sid = 'NoDelete'`,
		l.ws).Scan(&deny)
	if deny.ID == uuid.Nil || deny.Effect != models.EffectDeny {
		t.Fatalf("NoDelete = %+v, want stored with effect deny", deny)
	}
	if n := l.count(`SELECT count(*) FROM iga_access_edges WHERE workspace_id = ? AND entitlement_id = ?`, l.ws, deny.ID); n != 0 {
		t.Errorf("%d grants on the Deny statement: a Deny is a restriction, never access", n)
	}

	// The role's grants: exactly the attached policy's one Allow statement.
	g := l.grants()
	if len(g) != 1 || g[0].Policy != "ReadButNotDelete" || g[0].Sid != "Read" || g[0].State != models.RelCurrent ||
		g[0].Assignment != asg[1].ID {
		t.Errorf("grants = %+v, want exactly ReadButNotDelete/Read, current, through the attached assignment", g)
	}
}
