package integration

// AS-108 (Phase 3 R2 and R3 under row-level security): temporary grants,
// session revocations and the R3 runtime controls run every statement in a
// transaction under RLS for one workspace. These tests show that workspace
// A -- through the services, the jobs and an agent authenticated for A --
// can neither read nor change workspace B's rows: every foreign id is 404
// and B's rows are left exactly as they were, while B itself still reads
// and changes its own rows through the same services.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// p3R23Gates turns IGA_POLICY, IGA_POLICY_R2 and IGA_POLICY_R3 on, each
// verified against the integration database, and restores the process-wide
// gates afterwards.
func p3R23Gates(t *testing.T, db *gorm.DB) {
	t.Helper()
	graph := services.NewGraphProjectionGate(true)
	if err := graph.Verify(db); err != nil {
		t.Fatalf("graph projection gate: %v", err)
	}
	pol := services.NewPolicyGate(true, func() *services.GraphProjectionGate { return graph })
	if err := pol.Verify(db); err != nil {
		t.Fatalf("policy gate: %v", err)
	}
	prevP, prev2, prev3 := services.PolicyGateState(), services.PolicyR2GateState(), services.PolicyR3GateState()
	services.SetPolicyGate(pol)
	t.Cleanup(func() {
		services.SetPolicyGate(prevP)
		services.SetPolicyR2Gate(prev2)
		services.SetPolicyR3Gate(prev3)
	})
	r2 := services.NewPolicyR2Gate(true)
	if err := r2.Verify(db); err != nil {
		t.Fatalf("R2 gate (061, 134): %v", err)
	}
	services.SetPolicyR2Gate(r2)
	r3 := services.NewPolicyR3Gate(true)
	if err := r3.Verify(db); err != nil {
		t.Fatalf("R3 gate (062): %v", err)
	}
	services.SetPolicyR3Gate(r3)
	if !services.PolicyR2On() || !services.PolicyR3On() {
		t.Fatal("R2 and R3 must be on")
	}
}

// p3R23Member adds an active member of g's workspace whose role holds perms.
func p3R23Member(t *testing.T, g *p3Gov, perms ...string) uuid.UUID {
	t.Helper()
	user, role, mem := uuid.New(), uuid.New(), uuid.New()
	p3exec(t, g.db, `INSERT INTO users (id, email, name, workspace_id) VALUES (?, ?, 'Rhea Approver', ?)`, user, user.String()+"@p3r23.test", g.ws)
	p3exec(t, g.db, `INSERT INTO roles (id, name, workspace_id) VALUES (?, ?, ?)`, role, "p3r23-"+role.String()[:8], g.ws)
	p3exec(t, g.db, `INSERT INTO workspace_memberships (id, workspace_id, user_id, role_id, status) VALUES (?, ?, ?, ?, 'active')`,
		mem, g.ws, user, role)
	for _, p := range perms {
		p3exec(t, g.db, `INSERT INTO role_permissions (role_id, permission_id)
			SELECT ?, id FROM permissions WHERE full_permission_string = ? AND workspace_id IS NULL`, role, p)
	}
	g.users, g.roles = append(g.users, user), append(g.roles, role)
	t.Cleanup(func() { g.db.Exec(`DELETE FROM role_permissions WHERE role_id = ?`, role) })
	return user
}

// p3R2Grant inserts a temporary grant of g's workspace in the given state
// (requested, or approved with an expiry already past).
func p3R2Grant(t *testing.T, g *p3Gov, state string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	created, expires := time.Now().Add(-2*time.Hour), time.Now().Add(time.Hour)
	var decidedBy, approvedHash any
	if state == models.R2StateApproved {
		expires, decidedBy, approvedHash = time.Now().Add(-time.Hour), g.approver, "sha256:req-"+id.String()
	}
	p3exec(t, g.db, `INSERT INTO iga_gov_temp_grant (id, workspace_id, connector_id, identity_account_id, account_id, role_id, role_arn,
		actions, resources, reason, expires_at, policy_name, policy_arn, document_hash, request_hash, request_key, state,
		requested_by, decided_by, decided_at, approved_request_hash, created_at, updated_at)
		VALUES (?, ?, ?, ?, '111111111111', ?, ?, '["s3:GetObject"]', '["*"]', 'p3r23', ?, ?, ?, ?, ?, ?, ?, ?, ?,
		        CASE WHEN ?::uuid IS NULL THEN NULL ELSE now() END, ?, ?, ?)`,
		id, g.ws, g.conn, uuid.New(), "AROAP3R23"+id.String()[:8], "arn:aws:iam::111111111111:role/p3r23-"+id.String()[:8],
		expires, "authsec-grant-"+id.String()[:8], "arn:aws:iam::111111111111:policy/authsec/authsec-grant-"+id.String()[:8],
		g.docHash, "sha256:req-"+id.String(), "key-"+id.String(), state, g.author, decidedBy, decidedBy, approvedHash, created, created)
	return id
}

func p3R2Revocation(t *testing.T, g *p3Gov) uuid.UUID {
	t.Helper()
	id := uuid.New()
	p3exec(t, g.db, `INSERT INTO iga_gov_session_revocation (id, workspace_id, connector_id, identity_account_id, account_id, role_id,
		role_arn, reason, keep_hours, policy_name, policy_arn, request_hash, state, requested_by)
		VALUES (?, ?, ?, ?, '111111111111', ?, ?, 'p3r23', 13, ?, ?, ?, 'requested', ?)`,
		id, g.ws, g.conn, uuid.New(), "AROAP3R23R"+id.String()[:8], "arn:aws:iam::111111111111:role/p3r23r-"+id.String()[:8],
		"authsec-revoke-"+id.String()[:8], "arn:aws:iam::111111111111:policy/authsec/authsec-revoke-"+id.String()[:8],
		"sha256:rev-"+id.String(), g.author)
	return id
}

// p3R23NotFound fails unless err is the 404 not_found GovError.
func p3R23NotFound(t *testing.T, what string, err error) {
	t.Helper()
	var ge *services.GovError
	if !errors.As(err, &ge) || ge.Code != "not_found" {
		t.Fatalf("%s: %v, want 404 not_found", what, err)
	}
}

// rowState is the row's state and updated_at, to prove it unchanged.
func p3R23State(t *testing.T, db *gorm.DB, table string, id uuid.UUID) string {
	t.Helper()
	var s string
	if err := db.Raw(`SELECT state || '|' || updated_at::text || '|' || COALESCE(decided_by::text, '') FROM `+table+` WHERE id = ?`, id).
		Row().Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// p3R23RLS checks that the database itself hides B's rows of each table
// from A's transaction, though the statement names B's workspace, and shows
// them to B's own.
func p3R23RLS(t *testing.T, db *gorm.DB, a, b uuid.UUID, tables ...string) {
	t.Helper()
	count := func(ws uuid.UUID, table string) int64 {
		var n int64
		if err := tenancy.InWorkspaceRead(context.Background(), db, ws, func(tx *gorm.DB) error {
			return tx.Raw(`SELECT count(*) FROM `+table+` WHERE workspace_id = ?`, b).Scan(&n).Error
		}); err != nil {
			t.Fatalf("%s in workspace %s: %v", table, ws, err)
		}
		return n
	}
	for _, table := range tables {
		if n := count(a, table); n != 0 {
			t.Fatalf("A's transaction sees %d of B's %s rows", n, table)
		}
		if n := count(b, table); n == 0 {
			t.Fatalf("B's transaction sees none of its own %s rows", table)
		}
	}
}

// R2: workspace A cannot read, list, approve, reject, revoke, decide or lift
// B's temporary grants and session revocations (404, rows unchanged); B
// reads its own.
func TestP3R2GrantsAndRevocationsWorkspaceIsolation(t *testing.T) {
	db := igaDB(t)
	p3R23Gates(t, db)
	a := p3NewGov(t, db, "p3-r2-iso-a")
	b := p3NewGov(t, db, "p3-r2-iso-b")
	ctx := context.Background()
	svc := services.NewGovR2(db)

	grant := p3R2Grant(t, b, models.R2StateRequested)
	rev := p3R2Revocation(t, b)
	grantBefore := p3R23State(t, db, "iga_gov_temp_grant", grant)
	revBefore := p3R23State(t, db, "iga_gov_session_revocation", rev)

	// B reads its own rows through the same service.
	if g, err := svc.GetGrant(ctx, b.ws, grant); err != nil || g.ID != grant {
		t.Fatalf("B's own grant: %v %v", g, err)
	}
	if r, err := svc.GetRevocation(ctx, b.ws, rev); err != nil || r.ID != rev {
		t.Fatalf("B's own revocation: %v %v", r, err)
	}
	if gs, err := svc.ListGrants(ctx, b.ws, "", "", 0); err != nil || len(gs) != 1 {
		t.Fatalf("B's own grants: %d %v", len(gs), err)
	}

	// A: every foreign id is 404, lists are empty.
	_, err := svc.GetGrant(ctx, a.ws, grant)
	p3R23NotFound(t, "A reads B's grant", err)
	_, err = svc.ApproveGrant(ctx, a.ws, a.approver, grant, services.GovDecisionRequest{Reason: "x"})
	p3R23NotFound(t, "A approves B's grant", err)
	_, err = svc.RejectGrant(ctx, a.ws, a.approver, grant, services.GovDecisionRequest{Reason: "x"})
	p3R23NotFound(t, "A rejects B's grant", err)
	_, err = svc.RevokeGrant(ctx, a.ws, a.approver, grant, services.GovDecisionRequest{Reason: "x"})
	p3R23NotFound(t, "A revokes B's grant", err)
	_, err = svc.GetRevocation(ctx, a.ws, rev)
	p3R23NotFound(t, "A reads B's revocation", err)
	_, err = svc.DecideRevocation(ctx, a.ws, a.approver, rev, true, services.GovDecisionRequest{})
	p3R23NotFound(t, "A approves B's revocation", err)
	_, err = svc.DecideRevocation(ctx, a.ws, a.approver, rev, false, services.GovDecisionRequest{Reason: "x"})
	p3R23NotFound(t, "A rejects B's revocation", err)
	_, err = svc.LiftRevocation(ctx, a.ws, a.approver, rev, services.GovDecisionRequest{Reason: "x"})
	p3R23NotFound(t, "A lifts B's revocation", err)
	if gs, err := svc.ListGrants(ctx, a.ws, "", "", 0); err != nil || len(gs) != 0 {
		t.Fatalf("A lists B's grants: %d %v", len(gs), err)
	}
	if rs, err := svc.ListRevocations(ctx, a.ws, "", "", 0); err != nil || len(rs) != 0 {
		t.Fatalf("A lists B's revocations: %d %v", len(rs), err)
	}
	// A member of B holding nothing in A is not granted governance:emergency in A.
	if ok, err := svc.HoldsPermission(ctx, a.ws, b.author, "governance", "emergency"); err != nil || ok {
		t.Fatalf("B's member holds a permission in A: %v %v", ok, err)
	}

	if s := p3R23State(t, db, "iga_gov_temp_grant", grant); s != grantBefore {
		t.Fatalf("B's grant changed: %s -> %s", grantBefore, s)
	}
	if s := p3R23State(t, db, "iga_gov_session_revocation", rev); s != revBefore {
		t.Fatalf("B's revocation changed: %s -> %s", revBefore, s)
	}
	if n := p3sCount(t, db, `SELECT count(*) FROM iga_gov_event WHERE workspace_id IN (?, ?)`, a.ws, b.ws); n != 0 {
		t.Fatalf("%d events written by refused calls", n)
	}
	p3R23RLS(t, db, a.ws, b.ws, "iga_gov_temp_grant", "iga_gov_session_revocation")
}

// R2 expiry: a temp_grant job of workspace A naming B's expired grant finds
// nothing (abandoned) and leaves it untouched; B's own job expires it.
func TestP3R2GrantExpiryJobIsWorkspaceBound(t *testing.T) {
	db := igaDB(t)
	p3R23Gates(t, db)
	a := p3NewGov(t, db, "p3-r2-exp-a")
	b := p3NewGov(t, db, "p3-r2-exp-b")
	ctx := context.Background()
	svc := services.NewGovR2(db)
	grant := p3R2Grant(t, b, models.R2StateApproved)
	before := p3R23State(t, db, "iga_gov_temp_grant", grant)

	run := func(ws uuid.UUID, owner string) error {
		t.Helper()
		subject := grant
		j := &models.IGAGovJob{WorkspaceID: ws, Kind: repositories.GovJobTempGrant, SubjectID: &subject,
			DedupeKey: "temporary_grant:" + grant.String(), RunAfter: time.Now().Add(-time.Minute)}
		if _, err := repositories.NewIGAGovJobRepository(db).EnqueueTx(db, j); err != nil {
			t.Fatal(err)
		}
		c := p3ClaimOwn(t, db, ws, owner, 2*time.Minute, time.Now(), repositories.GovJobTempGrant)
		if c == nil || c.ID != j.ID {
			t.Fatalf("claim: %+v", c)
		}
		return svc.TempGrantHandler(ctx, services.NewPolicyJobRun(db, *c, owner))
	}

	err := run(a.ws, "p3r23-a")
	if err == nil || err.Error() == "" {
		t.Fatalf("A's job on B's grant: %v, want abandoned (grant not found)", err)
	}
	if s := p3R23State(t, db, "iga_gov_temp_grant", grant); s != before {
		t.Fatalf("A's job changed B's grant: %s -> %s", before, s)
	}
	if n := p3sCount(t, db, `SELECT count(*) FROM iga_gov_event WHERE workspace_id = ?`, b.ws); n != 0 {
		t.Fatalf("A's job wrote %d events in B", n)
	}

	if err := run(b.ws, "p3r23-b"); err != nil {
		t.Fatalf("B's own expiry job: %v", err)
	}
	if n := p3sCount(t, db, `SELECT count(*) FROM iga_gov_temp_grant WHERE id = ? AND state = 'expired' AND end_reason = 'expired_before_deploy'`, grant); n != 1 {
		t.Fatalf("B's job did not expire B's grant: %s", p3R23State(t, db, "iga_gov_temp_grant", grant))
	}
	if n := p3sCount(t, db, `SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = 'temporary_grant.ended'`, b.ws); n != 1 {
		t.Fatalf("B's job wrote %d ended events in B", n)
	}
}

// R3: A cannot read or change B's runtime policies, versions, holds and
// decisions; an agent authenticated for A -- even under the same SPIFFE ID
// and idempotency key, holding B's decision token -- cannot replay, redeem,
// report on or read B's decisions and holds.
func TestP3R3RuntimeControlsWorkspaceIsolation(t *testing.T) {
	db := igaDB(t)
	p3R23Gates(t, db)
	a := p3NewGov(t, db, "p3-r3-iso-a")
	b := p3NewGov(t, db, "p3-r3-iso-b")
	ctx := context.Background()
	svc := services.NewGovR3(db)
	approverB := p3R23Member(t, b, "governance:approve")
	approverA := p3R23Member(t, a, "governance:approve")

	const spiffe = "spiffe://p3r23.test/agent"
	intent := json.RawMessage(`{"kind":"runtime_controls","subjects":[{"spiffe_id":"` + spiffe + `"}],
		"tools":[{"tool":"lookup"},{"tool":"search","require_approval":true,"approval_reason":"needs a human"}]}`)
	pv, err := svc.CreateRuntimePolicy(ctx, b.ws, b.author, services.RuntimePolicyRequest{Name: "p3r23-runtime", Intent: intent})
	if err != nil {
		t.Fatalf("B creates its runtime policy: %v", err)
	}
	pol := pv.ID
	if pv.InReview == nil {
		t.Fatal("no version in review")
	}
	if _, err := svc.DecideRuntimeVersion(ctx, b.ws, approverB, pol, 1, true,
		services.RuntimeDecisionRequest{IntentHash: pv.InReview.IntentHash}); err != nil {
		t.Fatalf("B approves its version: %v", err)
	}
	agB := services.RuntimeAgent{SpiffeID: spiffe, HumanUserID: b.author}
	allow, err := svc.Decide(ctx, b.ws, agB, services.RuntimeDecideRequest{Tool: "lookup", IdempotencyKey: "k-allow",
		Arguments: json.RawMessage(`{"q":1}`)})
	if err != nil || allow.Decision != igagov.RuntimeAllow || allow.DecisionToken == "" {
		t.Fatalf("B's allow: %+v %v", allow, err)
	}
	held, err := svc.Decide(ctx, b.ws, agB, services.RuntimeDecideRequest{Tool: "search", IdempotencyKey: "k-hold",
		Arguments: json.RawMessage(`{"q":2}`)})
	if err != nil || held.Decision != igagov.RuntimeHold || held.Hold == nil {
		t.Fatalf("B's hold: %+v %v", held, err)
	}
	hold := held.Hold.ID
	stateOf := func() string {
		var s string
		if err := db.Raw(`SELECT (SELECT status FROM iga_gov_runtime_version WHERE policy_id = ? AND version_no = 1) || '|' ||
		                         (SELECT state || COALESCE(decided_by::text, '') FROM iga_gov_runtime_hold WHERE id = ?) || '|' ||
		                         (SELECT COALESCE(consumed_at::text, 'unconsumed') || COALESCE(tool_outcome, '') FROM iga_gov_runtime_decision WHERE id = ?) || '|' ||
		                         (SELECT count(*)::text FROM iga_gov_runtime_version WHERE policy_id = ?) || '|' ||
		                         (SELECT count(*)::text FROM iga_gov_event WHERE workspace_id = ?)`,
			pol, hold, allow.DecisionID, pol, b.ws).Row().Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	before := stateOf()

	// Management routes of A: 404 on every foreign id, empty lists.
	_, err = svc.GetRuntimePolicy(ctx, a.ws, pol)
	p3R23NotFound(t, "A reads B's runtime policy", err)
	if ps, err := svc.ListRuntimePolicies(ctx, a.ws); err != nil || len(ps) != 0 {
		t.Fatalf("A lists B's runtime policies: %d %v", len(ps), err)
	}
	_, err = svc.CreateRuntimeVersion(ctx, a.ws, a.author, pol, services.RuntimeVersionRequest{BaseVersionNo: 1, Intent: intent})
	p3R23NotFound(t, "A versions B's runtime policy", err)
	_, err = svc.WithdrawRuntimeVersion(ctx, a.ws, a.author, pol, 1, "x")
	p3R23NotFound(t, "A withdraws B's version", err)
	_, err = svc.DecideRuntimeVersion(ctx, a.ws, approverA, pol, 1, false, services.RuntimeDecisionRequest{Reason: "x"})
	p3R23NotFound(t, "A decides B's version", err)
	_, err = svc.CompileRuntimeCedar(ctx, a.ws, pol, 1, "arn:aws:bedrock-agentcore:us-east-1:111111111111:gateway/gw-1")
	p3R23NotFound(t, "A compiles B's version", err)
	_, err = svc.GetHold(ctx, a.ws, hold)
	p3R23NotFound(t, "A reads B's hold", err)
	_, err = svc.DecideHold(ctx, a.ws, approverA, hold, true, "")
	p3R23NotFound(t, "A approves B's hold", err)
	_, err = svc.GetDecision(ctx, a.ws, allow.DecisionID)
	p3R23NotFound(t, "A reads B's decision", err)
	if hs, err := svc.ListHolds(ctx, a.ws, "", 0); err != nil || len(hs) != 0 {
		t.Fatalf("A lists B's holds: %d %v", len(hs), err)
	}
	if ds, err := svc.ListDecisions(ctx, a.ws, services.RuntimeDecisionFilter{}); err != nil || len(ds) != 0 {
		t.Fatalf("A lists B's decisions: %d %v", len(ds), err)
	}
	if cov, err := svc.RuntimeCoverage(ctx, a.ws); err != nil || len(cov) != 0 {
		t.Fatalf("A's coverage shows B's policies: %d %v", len(cov), err)
	}

	// The runtime routes for an agent authenticated for A, same SPIFFE ID.
	agA := services.RuntimeAgent{SpiffeID: spiffe, HumanUserID: a.author}
	d, err := svc.Decide(ctx, a.ws, agA, services.RuntimeDecideRequest{Tool: "lookup", IdempotencyKey: "k-allow",
		Arguments: json.RawMessage(`{"q":1}`)})
	if err != nil || d.Replayed || d.DecisionID == allow.DecisionID || d.Decision != igagov.RuntimeDeny || d.Reason != igagov.RuntimeReasonNoPolicy {
		t.Fatalf("A's decide with B's key: %+v %v, want a fresh no_policy deny", d, err)
	}
	_, err = svc.Redeem(ctx, a.ws, agA, allow.DecisionID, services.RuntimeRedeemRequest{DecisionToken: allow.DecisionToken,
		ArgumentsDigest: allow.ArgsDigest, Tool: "lookup"})
	p3R23NotFound(t, "A redeems B's allow with B's token", err)
	_, err = svc.ReportOutcome(ctx, a.ws, agA, allow.DecisionID, services.RuntimeOutcomeRequest{DecisionToken: allow.DecisionToken,
		ToolOutcome: "not_executed"})
	p3R23NotFound(t, "A reports an outcome on B's allow", err)
	_, err = svc.AgentHold(ctx, a.ws, agA, hold)
	p3R23NotFound(t, "A's agent reads B's hold", err)

	if after := stateOf(); after != before {
		t.Fatalf("B's runtime rows changed: %s -> %s", before, after)
	}
	// B still reaches its own rows through the same service.
	if h, err := svc.AgentHold(ctx, b.ws, agB, hold); err != nil || h.ID != hold {
		t.Fatalf("B's agent reads its hold: %v %v", h, err)
	}
	if r, err := svc.Redeem(ctx, b.ws, agB, allow.DecisionID, services.RuntimeRedeemRequest{DecisionToken: allow.DecisionToken,
		ArgumentsDigest: allow.ArgsDigest, Tool: "lookup"}); err != nil || r.ConsumedAt == nil {
		t.Fatalf("B redeems its allow: %v %v", r, err)
	}
	p3R23RLS(t, db, a.ws, b.ws, "iga_gov_runtime_version", "iga_gov_runtime_decision", "iga_gov_runtime_hold", "iga_gov_event")
}
