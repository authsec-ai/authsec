package integration

// The flat Kubernetes access route against the graph walk (D-112):
// GET /authsec/discovery/k8s/identities/:id/access and the identities,
// workloads and clusters lists, through the REAL K8sGraphController, over a
// cluster written through the REAL projection (the k8s graph fixture's world,
// p2_k8s_graph_fixture_test.go, plus two group bindings):
//
//	ClusterRole pod-viewer   list pods
//	ClusterRoleBinding all-sas-view-pods        -> pod-viewer,    Group system:serviceaccounts:iga-demo
//	RoleBinding iga-demo/authenticated-secrets  -> secret-reader, Group system:authenticated
//
// so every ServiceAccount of iga-demo holds two grants through implicit group
// membership -- one cluster-wide, one a ClusterRole's rule confined to iga-demo
// by its RoleBinding -- and research holds its five direct rows besides
// (research-reads-secrets, research-secrets-ns, research-pods x2, dangling).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	platform "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

const (
	k8sAccessAllSAs = "system:serviceaccounts:" + k8sGraphNS
	k8sAccessAuthn  = "system:authenticated"
)

// k8sAccessGroups adds the group bindings (and pod-viewer) to a sweep,
// leaving out the bindings drop names.
func k8sAccessGroups(s *models.K8sRBACSnapshot, drop map[string]bool) {
	s.Roles = append(s.Roles, models.K8sRole{Kind: models.K8sKindClusterRole, Name: "pod-viewer",
		Rules: []models.K8sPolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list"}}}})
	for _, b := range []models.K8sBinding{
		{Kind: models.K8sKindClusterRoleBinding, Name: "all-sas-view-pods",
			RoleRef:  models.K8sRoleRef{Kind: models.K8sKindClusterRole, Name: "pod-viewer"},
			Subjects: []models.K8sSubject{{Kind: models.K8sSubjectGroup, Name: k8sAccessAllSAs}}},
		{Kind: models.K8sKindRoleBinding, Name: "authenticated-secrets", Namespace: k8sGraphNS,
			RoleRef:  models.K8sRoleRef{Kind: models.K8sKindClusterRole, Name: "secret-reader"},
			Subjects: []models.K8sSubject{{Kind: models.K8sSubjectGroup, Name: k8sAccessAuthn}}},
	} {
		if !drop[b.Name] {
			s.Bindings = append(s.Bindings, b)
		}
	}
}

// accessSweep ingests one sweep of the world (with the group bindings when
// groups is set) through the real projection; clusterOnly objects are left out
// when the world cannot read cluster-scoped objects, as the agent would.
func (k *k8sGraphLab) accessSweep(w k8sWorld, groups bool) {
	k.t.Helper()
	k.at = k.at.Add(time.Minute)
	s := w.snapshot(k, k.at)
	if groups {
		k8sAccessGroups(&s, w.drop)
	}
	if !w.clusterScoped {
		var roles []models.K8sRole
		for _, r := range s.Roles {
			if r.Kind != models.K8sKindClusterRole {
				roles = append(roles, r)
			}
		}
		var bs []models.K8sBinding
		for _, b := range s.Bindings {
			if b.Kind != models.K8sKindClusterRoleBinding {
				bs = append(bs, b)
			}
		}
		s.Roles, s.Bindings = roles, bs
	}
	res, err := k.mgr.Ingest(k.ws, s)
	if err != nil || !res.Accepted {
		k.t.Fatalf("ingest: %+v %v", res, err)
	}
}

// newK8sAccessLab is a lab with research-agent and one complete, cluster-wide
// sweep of the world with its group bindings.
func newK8sAccessLab(t *testing.T, name string) *k8sGraphLab {
	t.Helper()
	k := newK8sGraphLab(t, name)
	k.agent("research-agent", k8sGraphNS, "system:serviceaccount:"+k8sGraphNS+":research", "Deployment")
	k.accessSweep(k8sFullWorld(), true)
	return k
}

/* ------------------------------ the route harness ---------------------------- */

// k8sAccessAPI is the Kubernetes graph routes, as routes.go registers them,
// over the lab's database, with the token's workspace set as AuthMiddleware
// sets it.
type k8sAccessAPI struct {
	t   *testing.T
	eng *gin.Engine
	ws  uuid.UUID
}

func newK8sAccessAPI(t *testing.T, db *gorm.DB, ws uuid.UUID) *k8sAccessAPI {
	gin.SetMode(gin.TestMode)
	a := &k8sAccessAPI{t: t, ws: ws}
	ctl := platform.NewK8sGraphController(db)
	eng := gin.New()
	// Stands in for AuthMiddleware: the workspace is the token's, carried as
	// the tenancy context the k8s reads run under (RLS).
	g := eng.Group("/authsec/discovery", func(c *gin.Context) {
		c.Set("workspace_id", a.ws.String())
		tenancy.Set(c, tenancy.Context{WorkspaceID: a.ws, PrincipalKind: "user"})
	})
	g.GET("/k8s/clusters", ctl.ListClusters)
	g.GET("/k8s/identities", ctl.ListIdentities)
	g.GET("/k8s/workloads", ctl.ListWorkloads)
	g.GET("/k8s/identities/:id", ctl.GetIdentity)
	g.GET("/k8s/identities/:id/access", ctl.GetAccess)
	a.eng = eng
	return a
}

// get calls a route and returns the decoded body and the raw bytes.
func (a *k8sAccessAPI) get(path string) (map[string]any, []byte) {
	a.t.Helper()
	w := httptest.NewRecorder()
	a.eng.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/authsec/discovery"+path, nil))
	if w.Code != http.StatusOK {
		a.t.Fatalf("GET %s: %d %s", path, w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		a.t.Fatalf("GET %s: not JSON: %v", path, err)
	}
	return out, w.Body.Bytes()
}

func (a *k8sAccessAPI) access(id uuid.UUID) (map[string]any, []byte) {
	a.t.Helper()
	return a.get("/k8s/identities/" + id.String() + "/access")
}

// k8sAccessRow is one grant row, keyed for comparison.
type k8sAccessRow struct {
	binding, role, scopeKind, scopeNS, via, state string
	resolved                                      bool
	raw                                           map[string]any
}

func (r k8sAccessRow) key() string {
	return strings.Join([]string{r.binding, r.role, r.scopeKind, r.scopeNS, r.via, r.state}, "|")
}

func k8sAccessRows(t *testing.T, body map[string]any) []k8sAccessRow {
	t.Helper()
	var out []k8sAccessRow
	for _, g := range digl(body, "grants") {
		m := g.(map[string]any)
		r := k8sAccessRow{binding: digs(m, "binding_name"), role: digs(m, "role_name"),
			scopeKind: digs(m, "effective_scope", "kind"), scopeNS: digs(m, "effective_scope", "namespace"),
			via: digs(m, "via", "group"), state: digs(m, "state"), resolved: dig(m, "resolved") == true, raw: m}
		if _, ok := m["via"]; !ok {
			t.Errorf("grant %v has no via key; it must be null for a direct grant", m)
		}
		if _, ok := m["effective_scope"]; !ok {
			t.Errorf("grant %v has no effective_scope", m)
		}
		out = append(out, r)
	}
	return out
}

func k8sAccessKeys(rows []k8sAccessRow) []string {
	var out []string
	for _, r := range rows {
		out = append(out, r.key())
	}
	sort.Strings(out)
	return out
}

// k8sNoEffective fails when a response claims access is effective: no
// effective_conclusion, no key with "effective" in it but effective_scope
// (D-109's name for where a rule applies), and no value saying "effective".
func k8sNoEffective(t *testing.T, what string, v any) {
	t.Helper()
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if strings.Contains(strings.ToLower(k), "effective") && k != "effective_scope" {
				t.Errorf("%s: key %q claims access is effective", what, k)
			}
			k8sNoEffective(t, what+"."+k, val)
		}
	case []any:
		for _, val := range x {
			k8sNoEffective(t, what, val)
		}
	case string:
		if strings.Contains(strings.ToLower(x), "effective") {
			t.Errorf("%s: value %q says effective", what, x)
		}
	}
}

func k8sSummary(body map[string]any) map[string]int64 {
	out := map[string]int64{}
	for _, k := range []string{"total", "partial", "stale", "resolved", "unresolved", "direct", "via_group", "complete"} {
		out[k] = num(body, "summary", k)
	}
	return out
}

func k8sWant(t *testing.T, what string, got map[string]int64, want map[string]int64) {
	t.Helper()
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s summary.%s = %d, want %d (summary %v)", what, k, got[k], v, got)
		}
	}
	if got["complete"] != -1 {
		t.Errorf("%s summary still carries complete = %d", what, got["complete"])
	}
}

// k8sListCounts reads one identity's grants/stale from the identities list.
func k8sListCounts(t *testing.T, a *k8sAccessAPI, id uuid.UUID) (int64, int64, bool) {
	t.Helper()
	body, _ := a.get("/k8s/identities")
	for _, i := range digl(body, "identities") {
		if digs(i, "id") == id.String() {
			return num(i, "grants"), num(i, "stale"), dig(i, "wildcard") == true
		}
	}
	t.Fatalf("identity %s not in the list: %v", id, body)
	return 0, 0, false
}

func k8sWorkloadGrants(t *testing.T, a *k8sAccessAPI, name string) int64 {
	t.Helper()
	body, _ := a.get("/k8s/workloads")
	for _, w := range digl(body, "workloads") {
		if digs(w, "display_name") == name {
			return num(w, "grants")
		}
	}
	t.Fatalf("workload %s not in the list: %v", name, body)
	return 0
}

/* ----------------------------------- tests ---------------------------------- */

// Group grants are on the identity's access, named and marked as implicit,
// exactly the grants the graph walk reaches through member_of; every count
// that reports the identity's access includes them.
func TestP2K8sAccessRouteGroupGrants(t *testing.T) {
	k := newK8sAccessLab(t, "p2-k8s-access-groups")
	a := newK8sAccessAPI(t, k.db, k.ws)
	research := k.k8sID("iga_identity_accounts", "display_name = ?", "system:serviceaccount:iga-demo:research")
	idle := k.k8sID("iga_identity_accounts", "display_name = ?", "system:serviceaccount:iga-demo:idle")
	allSAs := k.k8sID("iga_identity_accounts", "display_name = ?", k8sAccessAllSAs)
	authn := k.k8sID("iga_identity_accounts", "display_name = ?", k8sAccessAuthn)

	body, raw := a.access(research)
	t.Logf("GET access (research): %s", raw)
	rows := k8sAccessRows(t, body)
	want := []string{
		"all-sas-view-pods|pod-viewer|cluster||" + k8sAccessAllSAs + "|current",
		"authenticated-secrets|secret-reader|namespace|iga-demo|" + k8sAccessAuthn + "|current",
		"dangling||namespace|iga-demo||current",
		"research-pods|iga-demo/pod-reader|namespace|iga-demo||current",
		"research-pods|iga-demo/pod-reader|namespace|iga-demo||current",
		"research-reads-secrets|secret-reader|cluster|||current",
		"research-secrets-ns|secret-reader|namespace|iga-demo||current",
	}
	if got := k8sAccessKeys(rows); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("research access =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, r := range rows {
		if r.via == "" {
			if r.raw["via"] != nil {
				t.Errorf("direct grant %s via = %v, want null", r.binding, r.raw["via"])
			}
			continue
		}
		wantGroup := map[string]uuid.UUID{k8sAccessAllSAs: allSAs, k8sAccessAuthn: authn}[r.via]
		if digs(r.raw, "via", "relationship") != "member_of" || dig(r.raw, "via", "implicit_membership") != true ||
			digs(r.raw, "via", "group_id") != wantGroup.String() || digs(r.raw, "via", "state") != "current" ||
			digs(r.raw, "via", "basis") != "declared" {
			t.Errorf("via of %s = %v, want member_of %s (%s), implicit, current, declared", r.binding, r.raw["via"], r.via, wantGroup)
		}
	}
	for _, r := range rows {
		if digs(r.raw, "basis") != "declared" || digs(r.raw, "calculation_state") != "partial" {
			t.Errorf("grant %s basis/calculation = %s/%s, want declared/partial", r.binding,
				digs(r.raw, "basis"), digs(r.raw, "calculation_state"))
		}
		if r.resolved != (r.binding != "dangling") {
			t.Errorf("grant %s resolved = %v", r.binding, r.resolved)
		}
	}
	k8sWant(t, "research", k8sSummary(body), map[string]int64{"total": 7, "partial": 7, "stale": 0,
		"resolved": 6, "unresolved": 1, "direct": 5, "via_group": 2})
	k8sNoEffective(t, "access", body)

	// idle holds no binding of its own: its access is the two groups'.
	ib, _ := a.access(idle)
	if got := k8sAccessKeys(k8sAccessRows(t, ib)); strings.Join(got, ",") != strings.Join(want[:2], ",") {
		t.Errorf("idle access = %v, want the two group grants", got)
	}
	k8sWant(t, "idle", k8sSummary(ib), map[string]int64{"total": 2, "partial": 2, "direct": 0, "via_group": 2})

	// The lists count the same rows.
	if g, s, _ := k8sListCounts(t, a, research); g != 7 || s != 0 {
		t.Errorf("identities list research grants/stale = %d/%d, want 7/0", g, s)
	}
	if g, s, _ := k8sListCounts(t, a, idle); g != 2 || s != 0 {
		t.Errorf("identities list idle grants/stale = %d/%d, want 2/0", g, s)
	}
	if g := k8sWorkloadGrants(t, a, "research-agent"); g != 7 {
		t.Errorf("workload research-agent grants = %d, want 7 (its identity's access, group grants included)", g)
	}
	for _, p := range []string{"/k8s/identities", "/k8s/workloads", "/k8s/clusters"} {
		lb, _ := a.get(p)
		k8sNoEffective(t, p, lb)
	}

	// Exactly what the graph walk shows: every resolved row is a grant edge
	// of the walk from research -- from research itself, or from a group
	// research is member_of -- with the same binding and effective_scope.
	gb := graphGet(t, k.api(), "/graph"+k8sQS("root", refOf("identity", research), "direction", "forward"))
	nodes := graphNodes(t, digl(gb, "data", "nodes"))
	es := graphEdges(t, digl(gb, "data", "edges"))
	groups := map[string]string{}
	for _, m := range graphEdgesOfKind(es, "member_of") {
		if m.From == refOf("identity", research) && dig(m.Raw, "implicit_membership") == true {
			groups[m.To] = digs(nodes[m.To], "label")
		}
	}
	var graph []string
	for _, e := range graphEdgesOfKind(es, "grant") {
		via := ""
		if e.From != refOf("identity", research) {
			var ok bool
			if via, ok = groups[e.From]; !ok {
				continue
			}
		}
		graph = append(graph, strings.Join([]string{digs(e.Raw, "assignment", "name"), digs(e.Raw, "effective_scope", "kind"),
			digs(e.Raw, "effective_scope", "namespace"), via, e.State}, "|"))
	}
	var flat []string
	for _, r := range rows {
		if r.resolved {
			flat = append(flat, strings.Join([]string{r.binding, r.scopeKind, r.scopeNS, r.via, r.state}, "|"))
		}
	}
	sort.Strings(graph)
	sort.Strings(flat)
	if strings.Join(graph, "\n") != strings.Join(flat, "\n") {
		t.Errorf("flat route and graph walk disagree:\nflat\n%s\ngraph\n%s", strings.Join(flat, "\n"), strings.Join(graph, "\n"))
	}
}

// D-109 on the flat route: a ClusterRole's rule reached through a RoleBinding
// applies in the binding's namespace; through a ClusterRoleBinding, the
// cluster. The row's namespace stays the ROLE's.
func TestP2K8sAccessRouteBindingScope(t *testing.T) {
	k := newK8sAccessLab(t, "p2-k8s-access-scope")
	a := newK8sAccessAPI(t, k.db, k.ws)
	research := k.k8sID("iga_identity_accounts", "display_name = ?", "system:serviceaccount:iga-demo:research")
	body, _ := a.access(research)
	seen := 0
	for _, r := range k8sAccessRows(t, body) {
		if r.role != "secret-reader" {
			continue
		}
		seen++
		wantKind, wantNS := "namespace", any(k8sGraphNS)
		if r.binding == "research-reads-secrets" {
			wantKind, wantNS = "cluster", nil
		}
		if s, _ := r.raw["effective_scope"].(map[string]any); s == nil || s["kind"] != wantKind || s["namespace"] != wantNS {
			t.Errorf("%s -> secret-reader effective_scope = %v, want %s %v", r.binding, r.raw["effective_scope"], wantKind, wantNS)
		}
		if digs(r.raw, "namespace") != "" || digs(r.raw, "role_kind") != "k8s_cluster_role" {
			t.Errorf("%s: namespace/role_kind = %q/%q, want the ClusterRole's (\"\", k8s_cluster_role)", r.binding,
				digs(r.raw, "namespace"), digs(r.raw, "role_kind"))
		}
		if digs(r.raw, "binding_kind") == "k8s_role_binding" && wantKind != "namespace" {
			t.Errorf("%s: a RoleBinding reported cluster-wide", r.binding)
		}
	}
	if seen != 3 {
		t.Errorf("%d secret-reader rows, want 3 (ClusterRoleBinding, RoleBinding, group RoleBinding)", seen)
	}
}

// Stale and ended through the real reconciler. A namespaced sweep cannot see
// cluster-scoped objects: the ClusterRoleBinding grants and the membership of
// the group only a ClusterRoleBinding names go stale, never ended. A complete
// cluster-wide sweep that drops the group bindings ends them, and the rows
// leave the route. A membership ended while the group's grant lives hides the
// grant; a stale membership makes a current grant's row stale.
func TestP2K8sAccessRouteStaleAndEnded(t *testing.T) {
	k := newK8sAccessLab(t, "p2-k8s-access-stale")
	a := newK8sAccessAPI(t, k.db, k.ws)
	research := k.k8sID("iga_identity_accounts", "display_name = ?", "system:serviceaccount:iga-demo:research")

	// 1. Namespaced sweep: ClusterRoles and ClusterRoleBindings unread.
	k.accessSweep(k8sWorld{complete: true, clusterScoped: false, namespaces: []string{k8sGraphNS}}, true)
	body, raw := a.access(research)
	t.Logf("after a namespaced sweep: %s", raw)
	rows := k8sAccessRows(t, body)
	byKey := map[string]k8sAccessRow{}
	for _, r := range rows {
		byKey[r.binding+"|"+r.via] = r
	}
	// The membership of a group only a ClusterRoleBinding names cannot be
	// reconfirmed or ended by a namespaced sweep (k8sgraph.Scope.CanEnd): it
	// goes stale, and the group's grant -- itself still current -- is listed
	// stale through it.
	if r, ok := byKey["all-sas-view-pods|"+k8sAccessAllSAs]; !ok || r.state != "stale" || digs(r.raw, "via", "state") != "stale" {
		t.Errorf("group grant through a membership the namespaced sweep could not reconfirm = %+v, want stale row, stale membership", r.raw)
	}
	var groupGrant string
	if err := k.db.Raw(`SELECT e.state FROM iga_access_edges e JOIN iga_identity_accounts g ON g.id = e.subject_identity_account_id
	                     WHERE e.workspace_id = ? AND g.display_name = ? AND e.state <> 'ended'`, k.ws, k8sAccessAllSAs).Row().Scan(&groupGrant); err != nil || groupGrant != "current" {
		t.Errorf("the group's own grant = %q (%v), want current: the row's stale must come from the membership", groupGrant, err)
	}
	// A namespaced sweep does not reconcile the cluster-scoped partition at
	// all (k8sgraph.Partitions): the ClusterRoleBinding's own grant is left as
	// it was -- listed, never ended.
	if r, ok := byKey["research-reads-secrets|"]; !ok || r.state != "current" {
		t.Errorf("ClusterRoleBinding grant after a namespaced sweep = %+v, want still listed, current", r.raw)
	}
	if r, ok := byKey["authenticated-secrets|"+k8sAccessAuthn]; !ok || r.state != "current" || digs(r.raw, "via", "state") != "current" {
		t.Errorf("group RoleBinding grant (namespace swept, group still named) = %+v, want current", r.raw)
	}
	sum := k8sSummary(body)
	var stale int64
	for _, r := range rows {
		if r.state == "stale" {
			stale++
		}
	}
	if stale == 0 || sum["stale"] != stale || sum["partial"]+sum["stale"] != sum["total"] || sum["total"] != int64(len(rows)) ||
		sum["resolved"]+sum["unresolved"] != sum["total"] || sum["direct"]+sum["via_group"] != sum["total"] {
		t.Errorf("summary %v does not add up over %d rows (%d stale)", sum, len(rows), stale)
	}
	if g, s, _ := k8sListCounts(t, a, research); g != sum["partial"] || s != sum["stale"] {
		t.Errorf("identities list grants/stale = %d/%d, want the summary's %d/%d", g, s, sum["partial"], sum["stale"])
	}
	if g := k8sWorkloadGrants(t, a, "research-agent"); g != sum["partial"] {
		t.Errorf("workload grants = %d, want the summary's partial %d", g, sum["partial"])
	}

	// 2. A membership ended while the group's grant lives: the grant is not
	// research's any more. A stale membership of a current grant: stale row.
	var authnMember uuid.UUID
	if err := k.db.Raw(`SELECT r.id FROM iga_relationship r JOIN iga_identity_accounts g ON g.id = r.target_identity_account_id
	                     WHERE r.workspace_id = ? AND r.relationship_type = 'member_of' AND r.source_identity_account_id = ?
	                       AND g.display_name = ? AND r.state = 'current'`, k.ws, research, k8sAccessAuthn).Row().Scan(&authnMember); err != nil {
		t.Fatalf("authenticated membership: %v", err)
	}
	setState := func(state string) {
		t.Helper()
		ended := state == "ended"
		if err := k.db.Exec(`UPDATE iga_relationship SET state = ?, valid_to = CASE WHEN ? THEN now() END,
		                            ended_reason = CASE WHEN ? THEN 'test' ELSE '' END
		                      WHERE id = ?`, state, ended, ended, authnMember).Error; err != nil {
			t.Fatalf("membership -> %s: %v", state, err)
		}
	}
	setState("stale")
	body, _ = a.access(research)
	for _, r := range k8sAccessRows(t, body) {
		if r.via == k8sAccessAuthn && (r.state != "stale" || digs(r.raw, "via", "state") != "stale") {
			t.Errorf("grant through a stale membership = %v, want stale (the weaker link)", r.raw)
		}
	}
	setState("ended")
	body, _ = a.access(research)
	for _, r := range k8sAccessRows(t, body) {
		if r.via == k8sAccessAuthn {
			t.Errorf("grant through an ended membership still listed: %v", r.raw)
		}
	}
	if g, _, _ := k8sListCounts(t, a, research); g != num(body, "summary", "partial") {
		t.Errorf("identities list grants = %d after the membership ended, want %d", g, num(body, "summary", "partial"))
	}
	setState("current")

	// 3. A complete cluster-wide sweep without the group bindings ends the
	// memberships and the groups' grants: research is back to its own five.
	w := k8sFullWorld()
	w.drop = map[string]bool{"all-sas-view-pods": true, "authenticated-secrets": true}
	k.accessSweep(w, true)
	body, _ = a.access(research)
	for _, r := range k8sAccessRows(t, body) {
		if r.via != "" {
			t.Errorf("group grant listed after the group bindings ended: %v", r.raw)
		}
	}
	k8sWant(t, "after the groups ended", k8sSummary(body), map[string]int64{"total": 5, "stale": 0, "via_group": 0, "direct": 5})
	var live int
	if err := k.db.Raw(`SELECT count(*) FROM iga_relationship WHERE workspace_id = ? AND relationship_type = 'member_of'
	                     AND state <> 'ended'`, k.ws).Row().Scan(&live); err != nil {
		t.Fatalf("memberships: %v", err)
	}
	if n := live; n != 0 {
		t.Errorf("%d memberships not ended after the groups stopped being named", n)
	}
	if g, s, _ := k8sListCounts(t, a, research); g != 5 || s != 0 {
		t.Errorf("identities list research = %d/%d after the groups ended, want 5/0", g, s)
	}
	if g := k8sWorkloadGrants(t, a, "research-agent"); g != 5 {
		t.Errorf("workload grants = %d after the groups ended, want 5", g)
	}
}

// Another workspace never sees this one's access: not by id, not in its lists,
// and its own group grants are its own groups'.
func TestP2K8sAccessRouteWorkspaceIsolation(t *testing.T) {
	ka := newK8sAccessLab(t, "p2-k8s-access-iso-a")
	kb := newK8sAccessLab(t, "p2-k8s-access-iso-b")
	researchA := ka.k8sID("iga_identity_accounts", "display_name = ?", "system:serviceaccount:iga-demo:research")
	researchB := kb.k8sID("iga_identity_accounts", "display_name = ?", "system:serviceaccount:iga-demo:research")
	groupsB := map[string]bool{
		kb.k8sID("iga_identity_accounts", "display_name = ?", k8sAccessAllSAs).String(): true,
		kb.k8sID("iga_identity_accounts", "display_name = ?", k8sAccessAuthn).String():  true,
	}

	asB := newK8sAccessAPI(t, kb.db, kb.ws)
	// Another workspace's identity is not found (404), exactly like an unknown
	// one -- never an empty list, which would read as "no access".
	if code, body := asB.status("/k8s/identities/" + researchA.String() + "/access"); code != http.StatusNotFound {
		t.Errorf("workspace B reads workspace A's identity: %d %v, want 404", code, body)
	}
	body, _ := asB.access(researchB)
	if num(body, "summary", "total") != 7 || num(body, "summary", "via_group") != 2 {
		t.Errorf("workspace B's own access = %v", body["summary"])
	}
	for _, r := range k8sAccessRows(t, body) {
		if r.via != "" && !groupsB[digs(r.raw, "via", "group_id")] {
			t.Errorf("workspace B's grant came through another workspace's group: %v", r.raw)
		}
	}
	for _, p := range []string{"/k8s/identities", "/k8s/workloads"} {
		lb, _ := asB.get(p)
		for _, key := range []string{"identities", "workloads"} {
			for _, i := range digl(lb, key) {
				if digs(i, "id") == researchA.String() {
					t.Errorf("%s in workspace B lists workspace A's %s", p, researchA)
				}
				if num(i, "grants") > 7 {
					t.Errorf("%s in workspace B counts %d grants for %s: another workspace's rows", p, num(i, "grants"), digs(i, "id"))
				}
			}
		}
	}
}
