package integration

// Review P0-1: deleting a workspace once it has Phase 3 data. The production
// purge (DELETE /authsec/uflow/admin/tenants/:workspace_id ->
// AdminUserController.DeleteTenant -> WorkspaceRepository.DeleteTenant) runs
// over workspaces whose Phase 3 rows were written by the real services:
//
//   - A: the T3.11/T3.15/T3.17 lab -- real scan, projection and evaluation
//     (lifecycle events), proposal + compile through /api/iga/v1/policy,
//     owner review opened and excepted, approval with acceptances, an
//     observed rollout up to its queued canary deployment, an IaC source
//     mapped through the route, Slack installed through the OAuth flow and a
//     user link, a manual owner. Its APPROVER is homed in workspace D (a
//     member of A by membership only).
//   - B: the T3.16 lab -- a binding verified through the real binding service,
//     a stored approved plan deployed and verified by the real deploy and
//     verify jobs (attempts, artifacts, verifications, posture, events).
//   - C: a bystander with fixture rows that is never purged.
//
// It proves: D cannot be purged while A's records name its user (409
// user_has_audit_history, nothing deleted); A purges completely, leaving B,
// C and D untouched; then D purges; a single user named by B's approvals is
// refused with 409 user_has_audit_history while a user with no history is
// deleted; B purges completely; C is untouched throughout.
//
// Mutation-checked (see the report): the SET LOCAL authsec.workspace_purge;
// users after workspaces; memberships before roles; iga_lifecycle_event
// before workspaces.

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/controllers/admin"
	"github.com/authsec-ai/authsec/controllers/enduser"
	"github.com/authsec-ai/authsec/database"
	"github.com/authsec-ai/authsec/internal/iacpr"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

/* -------------------------------- plumbing -------------------------------- */

// p3pAPI mounts the production tenant- and user-delete handlers over the
// integration database (config.Database is the lib/pq connection the admin
// repositories use, config.DB the GORM one the end-user handler uses), with
// the caller's identity set the way AuthMiddleware sets it.
type p3pAPI struct {
	t   *testing.T
	eng *gin.Engine
}

func newP3pAPI(t *testing.T, db *gorm.DB) *p3pAPI {
	t.Helper()
	raw, err := sql.Open("postgres", os.Getenv("IGA_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	raw.SetMaxOpenConns(2)
	t.Cleanup(func() { raw.Close() })
	prevDatabase, prevDB := config.Database, config.DB
	config.Database, config.DB = &database.DBConnection{DB: raw}, db
	t.Cleanup(func() { config.Database, config.DB = prevDatabase, prevDB })
	ctl, err := admin.NewAdminUserController()
	if err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	eng := gin.New()
	as := func(c *gin.Context) {
		c.Set("user_info", &middlewares.UserInfo{WorkspaceID: c.GetHeader("X-P3p-Workspace"), UserID: uuid.NewString(), Email: "op@p3purge.test"})
		c.Next()
	}
	eng.DELETE("/authsec/uflow/admin/tenants/:workspace_id", as, ctl.DeleteTenant)
	eng.POST("/authsec/uflow/user/enduser/delete_all", as, (&enduser.EndUserController{}).DeleteUserAll)
	return &p3pAPI{t: t, eng: eng}
}

func (a *p3pAPI) do(method, path, callerWS string, body any) (int, map[string]any) {
	a.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-P3p-Workspace", callerWS)
	w := httptest.NewRecorder()
	a.eng.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// purge deletes a workspace as a super admin through the production route.
func (a *p3pAPI) purge(ws uuid.UUID) (int, map[string]any) {
	return a.do(http.MethodDelete, "/authsec/uflow/admin/tenants/"+ws.String(), "admin", nil)
}

// deleteUser hard-deletes an end user as an admin of ws.
func (a *p3pAPI) deleteUser(ws, user uuid.UUID) (int, map[string]any) {
	return a.do(http.MethodPost, "/authsec/uflow/user/enduser/delete_all", ws.String(),
		map[string]any{"workspace_id": ws.String(), "user_id": user.String()})
}

// p3pTables lists every public base table with a workspace_id column.
func p3pTables(t *testing.T, db *gorm.DB) []string {
	t.Helper()
	var out []string
	if err := db.Raw(`SELECT c.table_name FROM information_schema.columns c
		JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name
		WHERE c.table_schema = 'public' AND c.column_name = 'workspace_id' AND t.table_type = 'BASE TABLE'
		ORDER BY 1`).Scan(&out).Error; err != nil {
		t.Fatal(err)
	}
	return out
}

// p3pMustGo is the set of tables a workspace purge must empty for the
// workspace: every table with a key to workspaces (the cascade), every
// Phase 3 table, and the rows DeleteTenant deletes explicitly.
func p3pMustGo(t *testing.T, db *gorm.DB) map[string]bool {
	t.Helper()
	var keyed []string
	if err := db.Raw(`SELECT DISTINCT c.relname FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid
		WHERE k.contype = 'f' AND k.confrelid = 'public.workspaces'::regclass`).Scan(&keyed).Error; err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, x := range keyed {
		out[x] = true
	}
	for _, x := range []string{"users", "roles", "permissions", "role_bindings", "oauth_scopes", "totp_secrets",
		"workspace_memberships", "user_groups", "iga_lifecycle_event"} {
		out[x] = true
	}
	for _, x := range p3pTables(t, db) {
		if strings.HasPrefix(x, "iga_gov_") || strings.HasPrefix(x, "slack_") || x == "workspace_slack_integration" ||
			x == "cloud_enforcement_binding" || strings.HasPrefix(x, "cloud_resource_policy_") || x == "cloud_policy_document" {
			out[x] = true
		}
	}
	return out
}

// p3pCounts is the workspace's row count in every table with a workspace_id
// column, plus its workspaces row.
func p3pCounts(t *testing.T, db *gorm.DB, tables []string, ws uuid.UUID) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	for _, tb := range tables {
		var n int64
		if err := db.Raw(`SELECT count(*) FROM "`+tb+`" WHERE workspace_id::text = ?`, ws.String()).Scan(&n).Error; err != nil {
			t.Fatalf("count %s: %v", tb, err)
		}
		out[tb] = n
	}
	var n int64
	db.Raw(`SELECT count(*) FROM workspaces WHERE id = ?`, ws).Scan(&n)
	out["(workspaces row)"] = n
	return out
}

// p3pAssertGone fails for any must-go table that still holds a row of ws
// and logs what is left in the others (tables with no key to workspaces,
// e.g. the cloud_* collection and audit_events: not Phase 3, not P0-1).
func p3pAssertGone(t *testing.T, db *gorm.DB, tables []string, mustGo map[string]bool, ws uuid.UUID, name string) {
	t.Helper()
	var left []string
	for tb, n := range p3pCounts(t, db, tables, ws) {
		switch {
		case n == 0:
		case mustGo[tb] || tb == "(workspaces row)":
			t.Errorf("%s: %d row(s) of the purged workspace remain in %s", name, n, tb)
		default:
			left = append(left, tb)
		}
	}
	sort.Strings(left)
	t.Logf("%s purged; rows left only in tables with no key to workspaces (pre-existing, not P0-1): %v", name, left)
}

// p3pAssertSame fails if any of ws's counts changed.
func p3pAssertSame(t *testing.T, before, after map[string]int64, name string) {
	t.Helper()
	for tb, n := range before {
		if after[tb] != n {
			t.Errorf("bystander %s: %s had %d rows, now %d", name, tb, n, after[tb])
		}
	}
}

func p3pRequire(t *testing.T, db *gorm.DB, ws uuid.UUID, name string, tables ...string) {
	t.Helper()
	for _, tb := range tables {
		var n int64
		db.Raw(`SELECT count(*) FROM "`+tb+`" WHERE workspace_id = ?`, ws).Scan(&n)
		if n == 0 {
			t.Fatalf("setup: workspace %s has no %s row -- the purge would prove nothing about it", name, tb)
		}
	}
}

func p3pExists(db *gorm.DB, q string, args ...any) bool {
	var n int64
	db.Raw(q, args...).Scan(&n)
	return n > 0
}

/* ---------------------------------- test ---------------------------------- */

func TestP3WorkspacePurgeWithPhase3Data(t *testing.T) {
	// D: the approver's home workspace (created first: its user must outlive
	// A's cleanup if the test stops early).
	db := igaDB(t)
	wsD := newWorkspace(t, db, "p3-purge-d")
	approver := p3aMember{user: uuid.New(), membership: uuid.New(), role: uuid.New()}
	p3exec(t, db, `INSERT INTO users (id, email, name, workspace_id) VALUES (?, ?, 'Dana Approver', ?)`,
		approver.user, "dana-"+approver.user.String()[:8]+"@p3purge.test", wsD)
	t.Cleanup(func() { db.Exec(`DELETE FROM users WHERE id = ?`, approver.user) })

	// A: real scan / projection / evaluation, proposal, owner review,
	// approval with acceptances, rollout to the canary, IaC source, Slack.
	i := newP3iLab(t, "p3-purge-a")
	a := p3rOn(t, i.p3aLab, "p3-purge-a", true)
	wsA := a.ws
	p3exec(t, db, `INSERT INTO roles (id, name, workspace_id) VALUES (?, ?, ?)`, approver.role, "p3purge-approve-"+approver.role.String()[:8], wsA)
	p3exec(t, db, `INSERT INTO workspace_memberships (id, workspace_id, user_id, role_id, status) VALUES (?, ?, ?, ?, 'active')`,
		approver.membership, wsA, approver.user, approver.role)
	p3exec(t, db, `INSERT INTO role_permissions (role_id, permission_id)
		SELECT ?, id FROM permissions WHERE workspace_id IS NULL AND resource = 'governance' AND action = 'approve'`, approver.role)
	a.roles = append(a.roles, approver.role)
	a.approver = approver // homed in D, a member of A

	a.role("PurgeRole", "AROAPURGEROLE001", map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil, "ecr": p3eTime(2 * time.Hour)})
	a.publish()
	i.mapSource(iacpr.FormatTerraform, "iam", map[string]string{"iam/main.tf": "# empty\n"})
	policy := a.prepare("AROAPURGEROLE001") // proposal, compile, owner review excepted by the approver
	a.observed(policy)
	canary := a.toCanary(policy, 1) // approved (with acceptances), canary queued
	if a.deploymentState(canary) == "" {
		t.Fatal("setup: no canary deployment")
	}
	roleIdentity := bdbID(t, a.p2Lab, `SELECT id FROM iga_identity_accounts WHERE workspace_id = ? AND immutable_key = 'AROAPURGEROLE001'`, wsA)
	if err := repositories.NewIGAGovOwnershipRepository(db).AddOwner(&models.IGAGovOwner{WorkspaceID: wsA, ObjectKind: models.GovObjectIdentityAccount,
		IdentityAccountID: &roleIdentity, UserID: a.author.user, Role: models.GovOwnerAccountable, Source: models.GovOwnerSourceManual, CreatedBy: &a.author.user}); err != nil {
		t.Fatalf("setup: owner: %v", err)
	}
	s := newP3sApp(t, db, a.policy)
	slackAdmin := a.member("slackadmin", "enforce")
	s.install(a.token(wsA, slackAdmin, "governance:enforce"), "TP3PURGE", "p3 purge")
	s.link(wsA, "UP3PURGE", approver.user)
	p3pRequire(t, db, wsA, "A", "iga_gov_event", "iga_gov_policy", "iga_gov_policy_version", "iga_gov_plan", "iga_gov_approval",
		"iga_gov_acceptance", "iga_gov_owner_review", "iga_gov_rollout", "iga_gov_deployment", "iga_gov_job", "iga_gov_iac_source",
		"iga_gov_owner", "iga_gov_settings", "cloud_enforcement_binding", "workspace_slack_integration", "slack_user_link",
		"iga_publication", "workspace_memberships", "users")
	var lifecycle int64
	db.Raw(`SELECT count(*) FROM iga_lifecycle_event WHERE workspace_id = ?`, wsA).Scan(&lifecycle)
	t.Logf("workspace A: %d lifecycle events (D-94 ordering exercised when > 0)", lifecycle)

	// A's binding (consented by A's author) is revoked now that the canary
	// is queued: B binds the same fake account, and only one workspace may
	// hold a live enforcement binding per account (T3.09, A17).
	a.bind("revoked")

	// B: a real binding, deployment and verification with attempts.
	d := newDLab(t)
	wsB := d.ws
	x := d.role("PurgeDeployRole", "/", nil)
	tp := d.compile(d.fake.Discovery(), x, "sqs")
	stored := d.storeApproved(x, tp.Apply, *tp.Undo)
	d.finding(x, "sqs")
	d.applyAndVerify(x, stored)
	p3pRequire(t, db, wsB, "B", "iga_gov_event", "iga_gov_attempt", "iga_gov_artifact", "iga_gov_verification", "iga_gov_deployment",
		"iga_gov_approval", "iga_gov_service_posture", "cloud_enforcement_binding")

	// C: a bystander that is never purged.
	g := p3NewGov(t, db, "p3-purge-c")
	lane := g.lane()
	g.deployment(lane, "verified")
	p3exec(t, db, `INSERT INTO iga_gov_event (workspace_id, event, actor_kind, actor_id) VALUES (?, 'p3purge_bystander', 'system', '')`, g.ws)

	api := newP3pAPI(t, db)

	// A single user (outside a purge): one with no history is deleted; B's
	// approver, named by B's approvals, is refused 409 and nothing changes.
	fresh := uuid.New()
	p3exec(t, db, `INSERT INTO users (id, email, workspace_id) VALUES (?, ?, ?)`, fresh, fresh.String()+"@p3purge.test", wsB)
	if code, body := api.deleteUser(wsB, fresh); code != http.StatusOK || p3pExists(db, `SELECT count(*) FROM users WHERE id = ?`, fresh) {
		t.Fatalf("delete a user with no history: %d %v", code, body)
	}

	tables := p3pTables(t, db)
	mustGo := p3pMustGo(t, db)
	beforeB, beforeC := p3pCounts(t, db, tables, wsB), p3pCounts(t, db, tables, g.ws)
	beforeD := p3pCounts(t, db, tables, wsD)

	code, body := api.deleteUser(wsB, d.approver)
	if code != http.StatusConflict || body["code"] != database.UserHasAuditHistoryCode {
		t.Errorf("delete B's approver: %d %v, want 409 %s", code, body, database.UserHasAuditHistoryCode)
	}
	if !p3pExists(db, `SELECT count(*) FROM users WHERE id = ?`, d.approver) {
		t.Fatal("the refused user was deleted")
	}
	p3pAssertSame(t, beforeB, p3pCounts(t, db, tables, wsB), "B after a refused user delete")

	// D cannot be purged while A's records name its user: refused, nothing
	// deleted, A untouched.
	beforeA := p3pCounts(t, db, tables, wsA)
	code, body = api.purge(wsD)
	if code != http.StatusConflict || body["code"] != database.UserHasAuditHistoryCode {
		t.Errorf("purge D while A names its user: %d %v, want 409 %s", code, body, database.UserHasAuditHistoryCode)
	}
	p3pAssertSame(t, beforeD, p3pCounts(t, db, tables, wsD), "D after its refused purge")
	p3pAssertSame(t, beforeA, p3pCounts(t, db, tables, wsA), "A after D's refused purge")

	// A purges completely through the production route.
	code, body = api.purge(wsA)
	if code != http.StatusOK {
		t.Fatalf("purge A: %d %v", code, body)
	}
	p3pAssertGone(t, db, tables, mustGo, wsA, "A")
	p3pAssertSame(t, beforeB, p3pCounts(t, db, tables, wsB), "B after A's purge")
	p3pAssertSame(t, beforeC, p3pCounts(t, db, tables, g.ws), "C after A's purge")
	p3pAssertSame(t, beforeD, p3pCounts(t, db, tables, wsD), "D after A's purge")
	if !p3pExists(db, `SELECT count(*) FROM users WHERE id = ?`, approver.user) {
		t.Fatal("A's purge deleted a user homed in D")
	}

	// Now nothing names D's user: D purges.
	if code, body = api.purge(wsD); code != http.StatusOK || p3pExists(db, `SELECT count(*) FROM users WHERE id = ?`, approver.user) {
		t.Fatalf("purge D after A: %d %v", code, body)
	}
	p3pAssertGone(t, db, tables, mustGo, wsD, "D")

	// B purges completely; C untouched.
	if code, body = api.purge(wsB); code != http.StatusOK {
		t.Fatalf("purge B: %d %v", code, body)
	}
	p3pAssertGone(t, db, tables, mustGo, wsB, "B")
	p3pAssertSame(t, beforeC, p3pCounts(t, db, tables, g.ws), "C after B's purge")
	var cEvents int64
	db.Raw(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ?`, g.ws).Scan(&cEvents)
	if cEvents != 1 {
		t.Fatalf("bystander C events: %d", cEvents)
	}

	// The purge mode is transaction-local: outside a purge an event is still
	// append-only.
	if err := db.Exec(`DELETE FROM iga_gov_event WHERE workspace_id = ?`, g.ws).Error; err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("event delete outside a purge: %v, want append-only", err)
	}
}

// deploymentState is the state of a deployment of the lab's workspace.
func (l *p3rLab) deploymentState(id uuid.UUID) string {
	var s string
	l.db.Raw(`SELECT state FROM iga_gov_deployment WHERE workspace_id = ? AND id = ?`, l.ws, id).Scan(&s)
	return s
}
