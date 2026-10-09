package integration

// Shared plumbing for the T3.11 / T3.13 scenarios (SPEC-iga-phase3-policy.md
// §2.7, §2.8, §2.10, §7.3, §7.5): the P3 evaluation lab (REAL scan worker,
// REAL projection with evaluation, AWS answered by fakes), plus verified
// workspace members (author, approvers), the production /api/iga/v1 surface
// with a FAKE discovery-role live reader (the LiveReader T3.10 implements),
// and helpers to propose, compile and approve. Prefixed p3a.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/config"
	platform "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/monitoring"
	"github.com/authsec-ai/authsec/routes"
	"github.com/authsec-ai/authsec/services"
)

/* ------------------------------ live reader ------------------------------- */

// p3aLive is the fake discovery-role live reader: roles by ARN, policies by
// ARN; a requested policy that is not registered reads as NoSuchEntity.
type p3aLive struct {
	mu       sync.Mutex
	roles    map[string]*igagov.LiveRole
	policies map[string]*igagov.LivePolicy
	fail     error
	reads    int
	// delegate, when set, answers every read (fix/p3-appr: the production
	// GovAWSLiveReader over a fake AWS account the deploy job writes to).
	delegate services.LiveReader
}

func newP3aLive() *p3aLive {
	return &p3aLive{roles: map[string]*igagov.LiveRole{}, policies: map[string]*igagov.LivePolicy{}}
}

func (f *p3aLive) ReadRole(ctx context.Context, req services.LiveReadRequest) (igagov.LiveRead, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.fail != nil {
		return igagov.LiveRead{}, f.fail
	}
	if f.delegate != nil {
		return f.delegate.ReadRole(ctx, req)
	}
	out := igagov.LiveRead{ReadAt: time.Now().UTC(), Policies: map[string]*igagov.LivePolicy{}}
	if r, ok := f.roles[req.RoleARN]; ok {
		cp := *r
		out.Role = &cp
		if cp.BoundaryARN != "" {
			out.Policies[cp.BoundaryARN] = f.policies[cp.BoundaryARN]
		}
	}
	for _, arn := range req.PolicyARNs {
		out.Policies[arn] = f.policies[arn]
	}
	return out, nil
}

func (f *p3aLive) setRole(r igagov.LiveRole) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.roles[r.ARN] = &r
}

/* --------------------------------- members -------------------------------- */

type p3aMember struct {
	user, membership, role uuid.UUID
}

/* ----------------------------------- lab ---------------------------------- */

type p3aLab struct {
	*p3eLab
	a        *p2Account
	live     *p3aLive
	eng      *gin.Engine
	author   p3aMember
	approver p3aMember
	second   p3aMember // a second approver
	users    []uuid.UUID
	roles    []uuid.UUID
}

const p3aSecret = "p3-t311-jwt-secret"

var p3aAuditOnce sync.Once

func newP3aLab(t *testing.T, name string) *p3aLab {
	t.Helper()
	l := &p3aLab{p3eLab: newP3eLab(t, name), live: newP3aLive()}
	l.a = l.account(accountA)
	// Runs first (LIFO): the Phase 3 rows reference the members.
	t.Cleanup(func() {
		p3ePurge(t, l.db, l.ws)
		l.db.Exec(`DELETE FROM audit_events WHERE workspace_id = ?`, l.ws.String())
		for _, u := range l.users {
			l.db.Exec(`DELETE FROM workspace_memberships WHERE user_id = ?`, u)
			l.db.Exec(`DELETE FROM users WHERE id = ?`, u)
		}
		for _, r := range l.roles {
			l.db.Exec(`DELETE FROM role_permissions WHERE role_id = ?`, r)
			l.db.Exec(`DELETE FROM roles WHERE id = ?`, r)
		}
	})
	l.author = l.member("author", "author")
	l.approver = l.member("approver", "approve")
	l.second = l.member("second", "approve")
	// fix/p3-appr (P1-4): Approve refuses (503 owner_gate_unavailable)
	// without an owner gate hook. The owner gate is not what these
	// scenarios test (the review and wiring tests install the real T3.12
	// wiring over this): an explicit pass-through gate, restored after.
	prevHooks := services.SetGovAuthoringHooks(services.GovAuthoringHooks{
		OwnerGate: func(*gorm.DB, services.GovApprovalCheck) error { return nil }})
	t.Cleanup(func() { services.SetGovAuthoringHooks(prevHooks) })

	p3aAuditOnce.Do(func() {
		if monitoring.GetLogger() == nil {
			monitoring.InitMetrics()
		}
	})
	prev := config.AuditLogger
	config.AuditLogger = monitoring.NewAuditLogger(l.db)
	t.Cleanup(func() { config.AuditLogger = prev })

	gin.SetMode(gin.TestMode)
	t.Setenv("JWT_SDK_SECRET", p3aSecret)
	t.Setenv("JWT_DEF_SECRET", p3aSecret+"-default")
	t.Setenv("AUTH_EXPECT_ISS", "authsec-ai/auth-manager")
	t.Setenv("REQUIRE_SERVER_AUTH", "true")
	l.eng = gin.New()
	ctl := platform.NewIGAGraphReadControllerWith(l.db, l.gate, readTestCursorKey).WithPolicyGate(l.policy).WithGovLiveReader(l.live)
	routes.SetupIGARoutes(l.eng, platform.NewIGAController(l.db), ctl)
	return l
}

// member is an active member whose membership role holds governance:<perm>
// (so the database re-check of §2.8 sees it).
func (l *p3aLab) member(name, perm string) p3aMember {
	l.t.Helper()
	m := p3aMember{user: uuid.New(), membership: uuid.New(), role: uuid.New()}
	p3exec(l.t, l.db, `INSERT INTO users (id, email, name, workspace_id) VALUES (?, ?, ?, ?)`,
		m.user, name+"-"+m.user.String()[:8]+"@p3a.test", name, l.ws)
	p3exec(l.t, l.db, `INSERT INTO roles (id, name, workspace_id) VALUES (?, ?, ?)`, m.role, "p3a-"+name+"-"+m.role.String()[:8], l.ws)
	p3exec(l.t, l.db, `INSERT INTO workspace_memberships (id, workspace_id, user_id, role_id, status) VALUES (?, ?, ?, ?, 'active')`,
		m.membership, l.ws, m.user, m.role)
	p3exec(l.t, l.db, `INSERT INTO role_permissions (role_id, permission_id)
	                   SELECT ?, id FROM permissions WHERE workspace_id IS NULL AND resource = 'governance' AND action = ?`, m.role, perm)
	l.users = append(l.users, m.user)
	l.roles = append(l.roles, m.role)
	return m
}

func (l *p3aLab) token(ws uuid.UUID, m p3aMember, scope string) string {
	l.t.Helper()
	claims := jwt.MapClaims{"iss": "authsec-ai/auth-manager", "exp": time.Now().Add(time.Hour).Unix(),
		"workspace_id": ws.String(), "user_id": m.user.String(), "scope": scope}
	if m.membership != uuid.Nil {
		claims["workspace_membership_id"] = m.membership.String()
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(p3aSecret))
	if err != nil {
		l.t.Fatal(err)
	}
	return s
}

const p3aAllScopes = "governance:read governance:author governance:approve governance:enforce"

// call invokes /api/iga/v1/policy<path> as m in the lab's workspace with
// every governance scope (the database decides the rest).
func (l *p3aLab) call(m p3aMember, method, path string, body any) (int, map[string]any) {
	return l.callAs(l.token(l.ws, m, p3aAllScopes), method, path, body)
}

func (l *p3aLab) callAs(bearer, method, path string, body any) (int, map[string]any) {
	l.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			l.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "/api/iga/v1/policy"+path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	l.eng.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (l *p3aLab) must(code int, body map[string]any, want int, what string) map[string]any {
	l.t.Helper()
	if code != want {
		l.t.Fatalf("%s: %d %v, want %d", what, code, body, want)
	}
	d, _ := body["data"].(map[string]any)
	return d
}

/* --------------------------------- roles ---------------------------------- */

// p3aDoc is an identity policy granting one action of each service. Not
// <svc>:* on "*": that would add a broad_grant finding to every scenario
// (it evaluates since p3-wire; TestP3WireBroadGrantEvaluates).
func p3aDoc(services ...string) string {
	var acts []string
	for _, s := range services {
		acts = append(acts, fmt.Sprintf("%q", s+":DescribeP3a"))
	}
	return `{"Version":"2012-10-17","Statement":[{"Sid":"Work","Effect":"Allow","Action":[` + strings.Join(acts, ",") + `],"Resource":"*"}]}`
}

// role adds an old role (200 days) with one managed policy granting every
// service of report, a Lambda running as it, its Access Advisor report
// (service -> last attempt, nil: none), and its live read (no boundary).
func (l *p3aLab) role(name, roleID string, report map[string]*time.Time) string {
	l.t.Helper()
	var svcs []string
	for s := range report {
		svcs = append(svcs, s)
	}
	sort.Strings(svcs)
	arn := p3eOldRole(l.a, name, roleID, 200*24*time.Hour, name+"Work", p3aDoc(svcs...))
	p3eAddLambda(l.a, "us-east-1", strings.ToLower(name)+"-fn", arn)
	l.activity(l.a).set(arn, report)
	l.live.setRole(igagov.LiveRole{RoleID: roleID, ARN: arn, Name: name, Path: "/", AccountID: accountA, Partition: "aws",
		Tags: map[string]string{}, ManagedPolicies: []igagov.PolicyRef{{Ref: l.a.policyARN(name + "Work"), DocumentHash: "sha256:" + strings.Repeat("a", 64)}}})
	return arn
}

// publish runs one scan, gives it complete resource-policy coverage of
// every collected form (what T3.03b's collector writes), and projects it
// with the evaluation step. It returns the run.
func (l *p3aLab) publish() uuid.UUID {
	l.t.Helper()
	run := l.scanOnly(l.a)
	p3eCompleteCoverage(l.t, l.p3eLab, l.a, run.ID)
	l.projectOnly()
	return run.ID
}

// proposeTemplate opens a proposal for the roles (template + keys) as the
// author and returns (policy id, data).
func (l *p3aLab) proposeTemplate(roleIDs ...string) (string, map[string]any) {
	l.t.Helper()
	var keys []map[string]any
	for _, r := range roleIDs {
		keys = append(keys, map[string]any{"provider": "aws", "role_id": r})
	}
	code, body := l.call(l.author, http.MethodPost, "/proposals", map[string]any{"template": "right_size_services", "keys": keys})
	d := l.must(code, body, http.StatusCreated, "POST /proposals")
	return d["policy"].(map[string]any)["id"].(string), d
}

// compile proposes version no and returns the plans view.
func (l *p3aLab) compile(policy string, no int) map[string]any {
	l.t.Helper()
	code, body := l.call(l.author, http.MethodPost, fmt.Sprintf("/policies/%s/versions/%d/propose", policy, no), nil)
	d := l.must(code, body, http.StatusOK, "propose")
	return d["plans"].(map[string]any)
}

func (l *p3aLab) plans(policy string, no int) map[string]any {
	l.t.Helper()
	code, body := l.call(l.author, http.MethodGet, fmt.Sprintf("/policies/%s/versions/%d/plans", policy, no), nil)
	return l.must(code, body, http.StatusOK, "plans")
}

// approveBody echoes a plans view's hashes and accepts the given items
// (nil: every item) with a reason.
func p3aApproveBody(plans map[string]any, accept func(item map[string]any) bool) map[string]any {
	h := plans["hashes"].(map[string]any)
	acc := []map[string]any{}
	for _, x := range plans["acceptance_items"].([]any) {
		it := x.(map[string]any)
		if accept != nil && !accept(it) {
			continue
		}
		acc = append(acc, map[string]any{"kind": it["kind"], "plan_id": it["plan_id"], "item_key": it["item_key"],
			"item_hash": it["item_hash"], "reason": "accepted for " + it["item_key"].(string)})
	}
	return map[string]any{"intent_hash": h["intent_hash"], "impact_hashes": h["impact_hashes"], "plan_hashes": h["plan_hashes"],
		"material_hashes": h["material_hashes"], "acceptances": acc}
}

func (l *p3aLab) approve(m p3aMember, policy string, no int, body map[string]any) (int, map[string]any) {
	return l.call(m, http.MethodPost, fmt.Sprintf("/policies/%s/versions/%d/approve", policy, no), body)
}

// approveAll approves version no as the approver, accepting every item.
func (l *p3aLab) approveAll(policy string, no int) map[string]any {
	l.t.Helper()
	code, body := l.approve(l.approver, policy, no, p3aApproveBody(l.plans(policy, no), nil))
	return l.must(code, body, http.StatusOK, "approve")
}

// applyPlan is the current apply plan of version no of a policy.
func (l *p3aLab) applyPlan(policy string, no int) map[string]any {
	l.t.Helper()
	for _, x := range l.plans(policy, no)["plans"].([]any) {
		p := x.(map[string]any)
		if p["kind"] == "apply" {
			return p
		}
	}
	l.t.Fatalf("no apply plan for %s v%d", policy, no)
	return nil
}

func (l *p3aLab) versionID(policy string, no int) uuid.UUID {
	l.t.Helper()
	return bdbID(l.t, l.p2Lab, `SELECT id FROM iga_gov_policy_version WHERE workspace_id = ? AND policy_id = ? AND version_no = ?`, l.ws, policy, no)
}

func (l *p3aLab) authoring() *services.GovAuthoring { return services.NewGovAuthoring(l.db, l.live) }

func (l *p3aLab) status(policy string, no int) string {
	l.t.Helper()
	var s string
	if err := l.db.Raw(`SELECT status FROM iga_gov_policy_version WHERE workspace_id = ? AND policy_id = ? AND version_no = ?`,
		l.ws, policy, no).Row().Scan(&s); err != nil {
		l.t.Fatal(err)
	}
	return s
}

func (l *p3aLab) events(name string) int64 {
	return l.count(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = ?`, l.ws, name)
}

func (l *p3aLab) audits(action string) int64 {
	return l.count(`SELECT count(*) FROM audit_events WHERE workspace_id = ? AND action = ?`, l.ws.String(), action)
}

func p3aStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, fmt.Sprint(x))
	}
	return out
}

func p3aItemKeys(plans map[string]any, kind string) []string {
	var out []string
	for _, x := range plans["acceptance_items"].([]any) {
		it := x.(map[string]any)
		if it["kind"] == kind {
			out = append(out, it["item_key"].(string))
		}
	}
	sort.Strings(out)
	return out
}
