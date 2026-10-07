package integration

import (
	"bytes"
	"context"
	"encoding/json"
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
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/monitoring"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/routes"
	"github.com/authsec-ai/authsec/services"
)

// T3.07 (SPEC-iga-phase3-policy.md §2.9, §7.1; scenarios A5 owner part, A10):
// ownership -- role-owner resolution (own owners plus the accountable owners
// of every live consuming workload), tag rules, the evaluator's inputs, and
// the §7.1 owners routes through the production chain.

func p3Manual(t *testing.T, db *gorm.DB, g *p3Gov, kind string, obj, user uuid.UUID, role string) uuid.UUID {
	t.Helper()
	o := &models.IGAGovOwner{WorkspaceID: g.ws, ObjectKind: kind, UserID: user, Role: role, Source: models.GovOwnerSourceManual, CreatedBy: &g.author}
	if kind == models.GovObjectWorkload {
		o.WorkloadID = &obj
	} else {
		o.IdentityAccountID = &obj
	}
	if err := repositories.NewIGAGovOwnershipRepository(db).AddOwner(o); err != nil {
		t.Fatal(err)
	}
	return o.ID
}

// A10: a role shared by two workloads -- both workloads' accountable owners
// are the role's owners, each named with the workload it owns; the role's own
// owners (accountable or technical) are included; a workload's TECHNICAL
// owner is not derived; an ended relationship is not a consumer; a stale one
// still is; task_execution_role counts.
//
// Safeguards (mutation-checked): the accountable-only filter on derived
// owners; the live-state filter on consumers.
func TestP3T307RoleOwnerResolution(t *testing.T) {
	db := igaDB(t)
	g := p3NewGov(t, db, "p3own-owners-resolve")
	svc := services.NewIGAGovOwnershipService(db)
	role, _ := g.identity("RefundTaskRole", nil)
	agent := g.workload("refund-agent", &role, models.RelTypeExecutesAs)
	recon := g.workload("refund-reconciler", &role, models.RelTypeExecutesAs)
	exec := g.workload("refund-pull", &role, models.RelTypeTaskExecutionRole)
	gone := g.workload("refund-old", nil, "")
	g.relate(gone, role, models.RelTypeExecutesAs, "ended")
	staleWL := g.workload("refund-stale", nil, "")
	g.relate(staleWL, role, models.RelTypeExecutesAs, "stale")

	akash, _ := g.member("akash@p3own.test", "Akash M.", "active")
	priya, _ := g.member("priya@p3own.test", "Priya K.", "active")
	tech, _ := g.member("tech@p3own.test", "Tess Tech", "active")
	old, _ := g.member("old@p3own.test", "Olly Old", "active")
	pull, _ := g.member("pull@p3own.test", "Pat Pull", "active")
	roleTech, _ := g.member("roletech@p3own.test", "Rory Role", "active")

	p3Manual(t, db, g, models.GovObjectWorkload, agent, akash, models.GovOwnerAccountable)
	p3Manual(t, db, g, models.GovObjectWorkload, recon, priya, models.GovOwnerAccountable)
	p3Manual(t, db, g, models.GovObjectWorkload, recon, tech, models.GovOwnerTechnical) // not derived
	p3Manual(t, db, g, models.GovObjectWorkload, gone, old, models.GovOwnerAccountable) // ended: not a consumer
	p3Manual(t, db, g, models.GovObjectWorkload, exec, pull, models.GovOwnerAccountable)
	p3Manual(t, db, g, models.GovObjectIdentityAccount, role, roleTech, models.GovOwnerTechnical)

	ro, err := svc.ResolveRoleOwners(db, g.ws, role)
	if err != nil {
		t.Fatal(err)
	}
	got := map[uuid.UUID][]string{}
	for _, r := range ro.Resolved {
		for _, of := range r.OwnerOf {
			got[r.UserID] = append(got[r.UserID], of.ObjectKind+":"+of.Name+":"+of.Role)
		}
	}
	want := map[uuid.UUID][]string{
		akash:    {"workload:refund-agent:accountable"},
		priya:    {"workload:refund-reconciler:accountable"},
		pull:     {"workload:refund-pull:accountable"},
		roleTech: {"identity_account::technical"},
	}
	if len(got) != len(want) {
		t.Fatalf("resolved owners %v, want %v", got, want)
	}
	for u, w := range want {
		if strings.Join(got[u], ",") != strings.Join(w, ",") {
			t.Errorf("owner %s: %v, want %v", u, got[u], w)
		}
	}
	if _, ok := got[tech]; ok {
		t.Error("a workload's technical owner was derived onto the role")
	}
	if _, ok := got[old]; ok {
		t.Error("the owner of an ended consumer was derived onto the role")
	}
	// Consumers: four live (agent, reconciler, pull, stale), each listed; the
	// stale one has no owner.
	names := []string{}
	for _, c := range ro.Consumers {
		names = append(names, c.Name+"/"+c.Relationship)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "refund-agent/executes_as,refund-pull/task_execution_role,refund-reconciler/executes_as,refund-stale/executes_as" {
		t.Fatalf("consumers %v", names)
	}
	if un := ro.UnownedConsumers(); len(un) != 1 || un[0].Name != "refund-stale" {
		t.Fatalf("unowned consumers %+v", un)
	}
	ids := ro.UserIDs()
	if len(ids) != 4 || !sort.SliceIsSorted(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() }) {
		t.Fatalf("user ids %v", ids)
	}
	// Another workspace's role is not found.
	other := p3NewGov(t, db, "p3own-owners-resolve-other")
	if _, err := svc.ResolveRoleOwners(db, other.ws, role); err != services.ErrOwnerObjectNotFound {
		t.Fatalf("cross-workspace resolution: %v", err)
	}
	// A suspended member stays listed, flagged not a member.
	p3exec(t, db, `UPDATE workspace_memberships SET status = 'suspended' WHERE user_id = ?`, priya)
	ro, _ = svc.ResolveRoleOwners(db, g.ws, role)
	for _, r := range ro.Resolved {
		if r.UserID == priya && r.Member {
			t.Error("a suspended owner reads as a member")
		}
	}
}

// Tag rules (§2.9): a rule maps a tag key to a member by email (case and
// spaces ignored); the job applies it in a fenced transaction; a value that
// names no active member is reported "key=value" for missing_owner; a manual
// owner with the same (user, role) is never duplicated; a tag change, a
// member leaving and the rule's deletion each remove the rule's owner; the
// evaluator's inputs carry owner records and unmatched tags.
//
// Safeguards (mutation-checked): SyncRuleOwners' delete of no-longer-desired
// rows; MembersByEmail's active filter.
func TestP3T307OwnerRules(t *testing.T) {
	db := igaDB(t)
	g := p3NewGov(t, db, "p3own-owner-rules")
	svc := services.NewIGAGovOwnershipService(db)
	maria, _ := g.member("maria@p3own.test", "Maria", "active")
	roleA, _ := g.identity("TaggedRoleA", map[string]string{"owner": "  MARIA@p3own.test ", "team": "refunds"})
	roleB, _ := g.identity("TaggedRoleB", map[string]string{"owner": "nobody@p3own.test"})
	roleC, _ := g.identity("UntaggedRole", nil)
	manualID := p3Manual(t, db, g, models.GovObjectIdentityAccount, roleB, maria, models.GovOwnerTechnical)

	rule, err := svc.CreateRule(context.Background(), g.ws, g.author, "owner", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if rule.AppliesTo != "both" || rule.Role != models.GovOwnerAccountable {
		t.Fatalf("rule defaults: %+v", rule)
	}
	if _, err := svc.CreateRule(context.Background(), g.ws, g.author, "owner", "both", "accountable"); err != services.ErrOwnerRuleExists {
		t.Fatalf("duplicate rule: %v", err)
	}
	// Creating the rule enqueued its evaluation; the production worker runs it.
	var queued int64
	db.Raw(`SELECT count(*) FROM iga_gov_job WHERE workspace_id = ? AND kind = 'evaluate_owner_rules' AND status = 'queued'`, g.ws).Scan(&queued)
	if queued != 1 {
		t.Fatalf("evaluate_owner_rules queued: %d", queued)
	}
	w := services.NewDefaultPolicyJobWorker(db).WithGate(func() bool { return true })
	runOwnJob := func() {
		t.Helper()
		for i := 0; i < 5; i++ {
			ran, err := w.RunOnce(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !ran {
				return
			}
		}
	}
	runOwnJob()
	if st := ""; db.Raw(`SELECT status FROM iga_gov_job WHERE workspace_id = ? AND kind = 'evaluate_owner_rules'`, g.ws).Scan(&st).Error != nil || st != "complete" {
		t.Fatalf("evaluate_owner_rules job: %q", st)
	}
	owners := func(id uuid.UUID) []models.IGAGovOwner {
		os, err := repositories.NewIGAGovOwnershipRepository(db).ListOwners(g.ws, models.GovObjectIdentityAccount, id)
		if err != nil {
			t.Fatal(err)
		}
		return os
	}
	if os := owners(roleA); len(os) != 1 || os[0].UserID != maria || os[0].Source != models.GovOwnerSourceTagRule ||
		os[0].RuleID == nil || *os[0].RuleID != rule.ID || os[0].Role != models.GovOwnerAccountable {
		t.Fatalf("role A owners: %+v", os)
	}
	if os := owners(roleB); len(os) != 1 || os[0].ID != manualID {
		t.Fatalf("role B owners: %+v (the unmatched tag assigned someone, or the manual owner changed)", os)
	}
	if len(owners(roleC)) != 0 {
		t.Fatal("an untagged role got an owner")
	}
	evs := g.events()
	if evs[len(evs)-1] != "owner_rule.evaluated" {
		t.Fatalf("events %v", evs)
	}

	// The evaluator's inputs (T3.06 calls this on its transaction).
	in, err := svc.EvaluatorOwnershipInputs(db, g.ws, []uuid.UUID{roleA, roleB, roleC}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Owners) != 2 {
		t.Fatalf("owner records %+v", in.Owners)
	}
	for _, o := range in.Owners {
		if o.ObjectKind != models.GovObjectIdentityAccount || o.UserID != maria.String() || o.ID == "" || o.WorkloadID != "" {
			t.Errorf("owner record %+v", o)
		}
	}
	if u := in.UnmatchedIdentityTags[roleB.String()]; len(u) != 1 || u[0] != "owner=nobody@p3own.test" {
		t.Fatalf("unmatched tags of role B: %v", in.UnmatchedIdentityTags)
	}
	if _, ok := in.UnmatchedIdentityTags[roleA.String()]; ok {
		t.Fatal("a matched tag was reported unmatched")
	}
	// Ids not asked for are not returned.
	if in, _ := svc.EvaluatorOwnershipInputs(db, g.ws, []uuid.UUID{roleC}, nil); len(in.Owners) != 0 || len(in.UnmatchedIdentityTags) != 0 {
		t.Fatalf("inputs for role C only: %+v", in)
	}

	// A manual owner with the same (user, role) as the rule's: no duplicate.
	p3exec(t, db, `UPDATE iga_identity_accounts SET provider_attrs = jsonb_set(provider_attrs, '{tags,owner}', '"maria@p3own.test"') WHERE id = ?`, roleB)
	p3exec(t, db, `UPDATE iga_gov_owner SET role = 'accountable' WHERE id = ?`, manualID)
	apply := func() *services.RuleEvaluation {
		t.Helper()
		var ev *services.RuleEvaluation
		if err := db.Transaction(func(tx *gorm.DB) error {
			var err error
			ev, err = svc.ApplyOwnerRulesTx(tx, g.ws, nil)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return ev
	}
	if ev := apply(); ev.Added != 0 || ev.Removed != 0 {
		t.Fatalf("re-apply with a manual owner in place: %+v", ev)
	}
	if os := owners(roleB); len(os) != 1 || os[0].Source != models.GovOwnerSourceManual {
		t.Fatalf("role B after: %+v", os)
	}
	// The tag changes to an unknown address: the rule's owner of role A goes.
	p3exec(t, db, `UPDATE iga_identity_accounts SET provider_attrs = jsonb_set(provider_attrs, '{tags,owner}', '"someone-else@p3own.test"') WHERE id = ?`, roleA)
	if ev := apply(); ev.Removed != 1 || ev.UnmatchedIdentityTags[roleA.String()][0] != "owner=someone-else@p3own.test" {
		t.Fatalf("after the tag change: %+v", ev)
	}
	// Back to Maria, then Maria leaves the workspace: removed again.
	p3exec(t, db, `UPDATE iga_identity_accounts SET provider_attrs = jsonb_set(provider_attrs, '{tags,owner}', '"maria@p3own.test"') WHERE id = ?`, roleA)
	if ev := apply(); ev.Added != 1 {
		t.Fatalf("re-added: %+v", ev)
	}
	p3exec(t, db, `UPDATE workspace_memberships SET status = 'left' WHERE user_id = ?`, maria)
	if ev := apply(); ev.Removed != 1 {
		t.Fatalf("after the member left: %+v", ev)
	}
	p3exec(t, db, `UPDATE workspace_memberships SET status = 'active' WHERE user_id = ?`, maria)
	apply()
	// Deleting the rule removes its owners (cascade), and says how many.
	_, removed, err := svc.DeleteRule(context.Background(), g.ws, g.author, rule.ID)
	if err != nil || removed != 1 || len(owners(roleA)) != 0 {
		t.Fatalf("delete rule: removed %d err %v, owners left %d", removed, err, len(owners(roleA)))
	}
	// A rule that applies only to workloads ignores roles.
	if _, err := svc.CreateRule(context.Background(), g.ws, g.author, "owner", "workload", "accountable"); err != nil {
		t.Fatal(err)
	}
	if ev := apply(); ev.Added != 0 || len(ev.UnmatchedIdentityTags) != 0 {
		t.Fatalf("workload-only rule touched roles: %+v", ev)
	}
}

/* --------------------------------- routes --------------------------------- */

var p3MetricsOnce sync.Once

type p3OwnersAPI struct {
	t   *testing.T
	eng *gin.Engine
}

const p3OwnersSecret = "p3own-owners-jwt-secret"

func p3NewOwnersAPI(t *testing.T, db *gorm.DB) *p3OwnersAPI {
	t.Helper()
	gin.SetMode(gin.TestMode)
	t.Setenv("JWT_SDK_SECRET", p3OwnersSecret)
	t.Setenv("JWT_DEF_SECRET", p3OwnersSecret+"-default")
	t.Setenv("AUTH_EXPECT_ISS", "authsec-ai/auth-manager")
	t.Setenv("REQUIRE_SERVER_AUTH", "true")
	graphOn := p3GraphOn(t, db)
	gate := services.NewPolicyGate(true, "", graphOn)
	if err := gate.Verify(db); err != nil {
		t.Fatal(err)
	}
	eng := gin.New()
	ctl := platform.NewIGAGraphReadControllerWith(db, services.NewGraphProjectionGate(false, ""), readTestCursorKey).WithPolicyGate(gate)
	routes.SetupIGARoutes(eng, platform.NewIGAController(db), ctl)
	return &p3OwnersAPI{t: t, eng: eng}
}

// token is a console session of user in g's workspace (membership set: a
// verified human) with the given scope.
func (a *p3OwnersAPI) token(ws, user, membership uuid.UUID, scope string) string {
	a.t.Helper()
	claims := jwt.MapClaims{"iss": "authsec-ai/auth-manager", "exp": time.Now().Add(time.Hour).Unix(),
		"workspace_id": ws.String(), "user_id": user.String(), "scope": scope}
	if membership != uuid.Nil {
		claims["workspace_membership_id"] = membership.String()
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(p3OwnersSecret))
	if err != nil {
		a.t.Fatal(err)
	}
	return s
}

func (a *p3OwnersAPI) call(method, path, bearer string, body any) (int, map[string]any) {
	a.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "/api/iga/v1/policy"+path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	a.eng.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func p3ErrCode(body map[string]any) string {
	e, _ := body["error"].(map[string]any)
	s, _ := e["code"].(string)
	return s
}

// The §7.1 owners routes through the production chain: GET with derived
// consumer owners; PUT sets and clears manual owners (an iga_gov_event in
// the transaction and an audit_events row); PATCH sets a review date;
// owner rules list/create/delete; another workspace's ids are 404 on every
// route; permissions and the verified-human rule are enforced.
//
// Safeguards (mutation-checked): the workspace scoping of objectName; the
// event in SetManualOwners' transaction.
func TestP3T307OwnerRoutes(t *testing.T) {
	db := igaDB(t)
	p3MetricsOnce.Do(monitoring.InitMetrics) // the audit logger's logrus logger; once per process
	prev := config.AuditLogger
	config.AuditLogger = monitoring.NewAuditLogger(db)
	t.Cleanup(func() { config.AuditLogger = prev })
	api := p3NewOwnersAPI(t, db)
	g := p3NewGov(t, db, "p3own-owner-routes")
	other := p3NewGov(t, db, "p3own-owner-routes-other")
	t.Cleanup(func() {
		db.Exec(`DELETE FROM audit_events WHERE workspace_id IN (?, ?)`, g.ws.String(), other.ws.String())
	})

	role, _ := g.identity("SharedRole", nil)
	w1 := g.workload("refund-agent", &role, models.RelTypeExecutesAs)
	w2 := g.workload("refund-reconciler", &role, models.RelTypeExecutesAs)
	u1, _ := g.member("u1@p3own.test", "Una One", "active")
	u2, _ := g.member("u2@p3own.test", "Uli Two", "active")
	otherRole, _ := other.identity("OtherRole", nil)

	admin := api.token(g.ws, g.author, g.authorMember, "governance:read iga:admin")
	reader := api.token(g.ws, g.author, g.authorMember, "governance:read")
	service := api.token(g.ws, uuid.New(), uuid.Nil, "governance:read iga:admin")
	otherAdmin := api.token(other.ws, other.author, other.authorMember, "governance:read iga:admin")

	// PUT owners on both workloads (A10's setup through the API).
	for _, x := range []struct{ wl, u uuid.UUID }{{w1, u1}, {w2, u2}} {
		code, body := api.call(http.MethodPut, "/owners", admin, map[string]any{
			"object_kind": "workload", "object_id": x.wl.String(),
			"owners": []map[string]any{{"user_id": x.u.String(), "role": "accountable"}},
		})
		if code != http.StatusOK {
			t.Fatalf("PUT owners: %d %v", code, body)
		}
	}
	code, body := api.call(http.MethodGet, "/owners?object_kind=identity_account&object_id="+role.String(), reader, nil)
	if code != http.StatusOK {
		t.Fatalf("GET owners: %d %v", code, body)
	}
	data := body["data"].(map[string]any)
	resolved := data["resolved"].([]any)
	consumers := data["consumers"].([]any)
	if len(resolved) != 2 || len(consumers) != 2 || data["has_accountable"] != true {
		t.Fatalf("shared role owners: %v", data)
	}
	seen := map[string]string{}
	for _, r := range resolved {
		m := r.(map[string]any)
		of := m["owner_of"].([]any)[0].(map[string]any)
		seen[m["user_id"].(string)] = of["name"].(string)
	}
	if seen[u1.String()] != "refund-agent" || seen[u2.String()] != "refund-reconciler" {
		t.Fatalf("A10: both owners named with their workload: %v", seen)
	}
	if _, ok := body["meta"]; !ok {
		t.Fatal("no meta in the envelope")
	}

	// PUT with a review date, then clear with [].
	due := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)
	code, body = api.call(http.MethodPut, "/owners", admin, map[string]any{
		"object_kind": "identity_account", "object_id": role.String(),
		"owners": []map[string]any{{"user_id": u1.String(), "role": "accountable", "review_due_at": due}},
	})
	if code != http.StatusOK {
		t.Fatalf("PUT role owners: %d %v", code, body)
	}
	own := body["data"].(map[string]any)["owners"].([]any)
	if len(own) != 1 || own[0].(map[string]any)["review_due_at"] == nil {
		t.Fatalf("role owners after PUT: %v", own)
	}
	ownerID := own[0].(map[string]any)["id"].(string)
	// PATCH the review date to null, then back.
	code, body = api.call(http.MethodPatch, "/owners/"+ownerID, admin, map[string]any{"review_due_at": nil})
	if code != http.StatusOK || body["data"].(map[string]any)["review_due_at"] != nil {
		t.Fatalf("PATCH clear: %d %v", code, body)
	}
	if code, body = api.call(http.MethodPatch, "/owners/"+ownerID, admin, map[string]any{"review_due_at": due}); code != http.StatusOK {
		t.Fatalf("PATCH set: %d %v", code, body)
	}
	if code, _ = api.call(http.MethodPatch, "/owners/"+ownerID, admin, map[string]any{"review_due_at": "tomorrow"}); code != http.StatusBadRequest {
		t.Fatalf("PATCH bad date: %d", code)
	}
	code, body = api.call(http.MethodPut, "/owners", admin, map[string]any{
		"object_kind": "identity_account", "object_id": role.String(), "owners": []any{},
	})
	if code != http.StatusOK || len(body["data"].(map[string]any)["owners"].([]any)) != 0 {
		t.Fatalf("PUT [] (clear): %d %v", code, body)
	}

	// Validation: a non-member, a duplicate, a bad role, owners missing.
	nonMember := uuid.New()
	for name, b := range map[string]map[string]any{
		"non-member": {"object_kind": "workload", "object_id": w1.String(), "owners": []map[string]any{{"user_id": nonMember.String()}}},
		"duplicate": {"object_kind": "workload", "object_id": w1.String(), "owners": []map[string]any{
			{"user_id": u1.String(), "role": "accountable"}, {"user_id": u1.String(), "role": "accountable"}}},
		"bad role":       {"object_kind": "workload", "object_id": w1.String(), "owners": []map[string]any{{"user_id": u1.String(), "role": "boss"}}},
		"owners missing": {"object_kind": "workload", "object_id": w1.String()},
		"bad kind":       {"object_kind": "role", "object_id": w1.String(), "owners": []any{}},
	} {
		if code, body := api.call(http.MethodPut, "/owners", admin, b); code != http.StatusBadRequest || p3ErrCode(body) != "invalid_parameter" {
			t.Errorf("%s: %d %v", name, code, body)
		}
	}

	// Cross-workspace: every route answers 404 for another workspace's ids.
	if code, body := api.call(http.MethodGet, "/owners?object_kind=identity_account&object_id="+otherRole.String(), admin, nil); code != http.StatusNotFound || p3ErrCode(body) != "not_found" {
		t.Errorf("GET other workspace's role: %d %v", code, body)
	}
	if code, _ := api.call(http.MethodGet, "/owners?object_kind=identity_account&object_id="+role.String(), otherAdmin, nil); code != http.StatusNotFound {
		t.Errorf("GET from the other workspace: %d", code)
	}
	if code, _ := api.call(http.MethodPut, "/owners", otherAdmin, map[string]any{"object_kind": "workload", "object_id": w1.String(), "owners": []any{}}); code != http.StatusNotFound {
		t.Errorf("PUT from the other workspace: %d", code)
	}
	if code, _ := api.call(http.MethodPatch, "/owners/"+ownerID, otherAdmin, map[string]any{"review_due_at": nil}); code != http.StatusNotFound {
		t.Errorf("PATCH from the other workspace: %d", code)
	}

	// Permissions: governance:read cannot write; a service token (no member
	// session) cannot write; no token is 401.
	if code, body := api.call(http.MethodPut, "/owners", reader, map[string]any{"object_kind": "workload", "object_id": w1.String(), "owners": []any{}}); code != http.StatusForbidden || p3ErrCode(body) != "forbidden" {
		t.Errorf("PUT with governance:read: %d %v", code, body)
	}
	if code, body := api.call(http.MethodPut, "/owners", service, map[string]any{"object_kind": "workload", "object_id": w1.String(), "owners": []any{}}); code != http.StatusForbidden || p3ErrCode(body) != "forbidden" {
		t.Errorf("PUT with a service token: %d %v", code, body)
	}
	if code, _ := api.call(http.MethodGet, "/owners?object_kind=workload&object_id="+w1.String(), "", nil); code != http.StatusUnauthorized {
		t.Errorf("no token: %d", code)
	}
	if code, _ := api.call(http.MethodGet, "/owner-rules", reader, nil); code != http.StatusForbidden {
		t.Errorf("owner rules with governance:read: %d", code)
	}

	// Owner rules: create (201, job enqueued), duplicate 409, list with
	// paging, delete; another workspace's rule id is 404.
	ruleIDs := []string{}
	for _, k := range []string{"owner", "team-owner", "cost-owner"} {
		code, body := api.call(http.MethodPost, "/owner-rules", admin, map[string]any{"tag_key": k})
		if code != http.StatusCreated {
			t.Fatalf("create rule %s: %d %v", k, code, body)
		}
		ruleIDs = append(ruleIDs, body["data"].(map[string]any)["id"].(string))
	}
	if code, body := api.call(http.MethodPost, "/owner-rules", admin, map[string]any{"tag_key": "owner"}); code != http.StatusConflict || p3ErrCode(body) != "owner_rule_exists" {
		t.Errorf("duplicate rule: %d %v", code, body)
	}
	if code, body := api.call(http.MethodPost, "/owner-rules", admin, map[string]any{"tag_key": " "}); code != http.StatusBadRequest {
		t.Errorf("empty tag key: %d %v", code, body)
	}
	code, body = api.call(http.MethodGet, "/owner-rules?limit=2", admin, nil)
	if code != http.StatusOK || len(body["data"].([]any)) != 2 || body["meta"].(map[string]any)["next_cursor"] == nil {
		t.Fatalf("rules page 1: %d %v", code, body)
	}
	cursor := body["meta"].(map[string]any)["next_cursor"].(string)
	code, body = api.call(http.MethodGet, "/owner-rules?limit=2&cursor="+cursor, admin, nil)
	if code != http.StatusOK || len(body["data"].([]any)) != 1 || body["meta"].(map[string]any)["next_cursor"] != nil {
		t.Fatalf("rules page 2: %d %v", code, body)
	}
	if code, _ := api.call(http.MethodGet, "/owner-rules?limit=500", admin, nil); code != http.StatusBadRequest {
		t.Errorf("limit 500: %d", code)
	}
	if code, _ := api.call(http.MethodDelete, "/owner-rules/"+ruleIDs[0], otherAdmin, nil); code != http.StatusNotFound {
		t.Errorf("delete another workspace's rule: %d", code)
	}
	if code, body := api.call(http.MethodDelete, "/owner-rules/"+ruleIDs[0], admin, nil); code != http.StatusOK {
		t.Errorf("delete rule: %d %v", code, body)
	}
	if code, _ := api.call(http.MethodDelete, "/owner-rules/"+ruleIDs[0], admin, nil); code != http.StatusNotFound {
		t.Errorf("delete twice: %d", code)
	}

	// Audit: one iga_gov_event per mutation, in order, by the actor; and the
	// platform audit trail (written asynchronously).
	type ev struct{ Event, ActorKind, ActorID string }
	var evs []ev
	db.Raw(`SELECT event, actor_kind, actor_id FROM iga_gov_event WHERE workspace_id = ? ORDER BY id`, g.ws).Scan(&evs)
	names := []string{}
	for _, e := range evs {
		names = append(names, e.Event)
		if e.ActorKind != models.GovActorUser || e.ActorID != g.author.String() {
			t.Errorf("event %+v: want the user actor %s", e, g.author)
		}
	}
	wantEvents := "owners.set,owners.set,owners.set,owner.review_date_set,owner.review_date_set,owners.set," +
		"owner_rule.created,owner_rule.created,owner_rule.created,owner_rule.deleted"
	if strings.Join(names, ",") != wantEvents {
		t.Fatalf("events %v\nwant   %s", names, wantEvents)
	}
	var otherEvents int64
	db.Raw(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ?`, other.ws).Scan(&otherEvents)
	if otherEvents != 0 {
		t.Fatalf("refused cross-workspace calls wrote %d events", otherEvents)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var audits []string
		db.Raw(`SELECT action || ':' || resource FROM audit_events WHERE workspace_id = ? ORDER BY id`, g.ws.String()).Scan(&audits)
		if len(audits) == 10 {
			sort.Strings(audits)
			want := []string{"create:iga_gov_owner_rule", "create:iga_gov_owner_rule", "create:iga_gov_owner_rule",
				"delete:iga_gov_owner_rule", "set_owners:iga_gov_owner", "set_owners:iga_gov_owner", "set_owners:iga_gov_owner",
				"set_owners:iga_gov_owner", "set_review_date:iga_gov_owner", "set_review_date:iga_gov_owner"}
			if strings.Join(audits, ",") != strings.Join(want, ",") {
				t.Fatalf("audit_events %v", audits)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("audit_events %v, want 10 rows", audits)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A tag-rule owner taken over by PUT becomes manual (no duplicate row), and
// survives the rule's deletion.
func TestP3T307ManualTakesOverRuleOwner(t *testing.T) {
	db := igaDB(t)
	g := p3NewGov(t, db, "p3own-owner-takeover")
	svc := services.NewIGAGovOwnershipService(db)
	maria, _ := g.member("maria-t@p3own.test", "Maria", "active")
	role, _ := g.identity("TakeoverRole", map[string]string{"owner": "maria-t@p3own.test"})
	rule, err := svc.CreateRule(context.Background(), g.ws, g.author, "owner", "identity_account", "accountable")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Transaction(func(tx *gorm.DB) error { _, err := svc.ApplyOwnerRulesTx(tx, g.ws, nil); return err }); err != nil {
		t.Fatal(err)
	}
	ch, err := svc.SetManualOwners(context.Background(), g.ws, g.author, models.GovObjectIdentityAccount, role,
		[]services.OwnerAssignment{{UserID: maria, Role: models.GovOwnerAccountable}})
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Before.Owners) != 1 || ch.Before.Owners[0].Source != models.GovOwnerSourceTagRule ||
		len(ch.After.Owners) != 1 || ch.After.Owners[0].Source != models.GovOwnerSourceManual || ch.After.Owners[0].ID != ch.Before.Owners[0].ID {
		t.Fatalf("takeover: before %+v after %+v", ch.Before.Owners, ch.After.Owners)
	}
	if _, removed, err := svc.DeleteRule(context.Background(), g.ws, g.author, rule.ID); err != nil || removed != 0 {
		t.Fatalf("delete rule: %d %v", removed, err)
	}
	if o, _ := svc.Owners(context.Background(), g.ws, models.GovObjectIdentityAccount, role); len(o.Owners) != 1 {
		t.Fatalf("the manual owner went with the rule: %+v", o.Owners)
	}
}
