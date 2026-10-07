package integration

// Kubernetes identities of every kind on the flat routes (D-113):
// GET /authsec/discovery/k8s/identities/:id (new), the kind / cluster /
// namespace filters and cursor paging of GET /authsec/discovery/k8s/identities,
// and /identities/:id/access for Users and Groups -- through the REAL
// K8sGraphController over clusters written through the REAL projection.
//
// The world is the access lab's (p2_k8s_access_route_test.go: research, idle
// and the two implicit-group bindings) plus, in kg-cluster:
//
//	ClusterRole controller  * * *  (wildcard)
//	ClusterRoleBinding kcm         -> controller, User system:kube-controller-manager
//	ClusterRoleBinding ops-admin   -> controller, Group ops
//	RoleBinding iga-demo/alice-pods -> Role iga-demo/pod-reader (2 rules), User alice
//	SAs other/builder, other/deployer (members of system:authenticated only)
//
// and a second cluster, kg-other, from its own source:
//
//	SA iga-demo/far <- ClusterRoleBinding far-view   -> ClusterRole viewer (1 rule)
//	User system:kube-controller-manager <- ClusterRoleBinding kcm-other -> viewer
//
// so the workspace holds 5 ServiceAccounts, 3 Users and 3 Groups.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/authsec-ai/authsec/models"
)

const (
	k8sKindsOtherCluster = "kg-other"
	k8sKindsKCM          = "system:kube-controller-manager"
	k8sKindsAllKinds     = "kind=service_account,user,group"
)

// newK8sKindsLab is the access lab with the world above.
func newK8sKindsLab(t *testing.T, name string) *k8sGraphLab {
	t.Helper()
	return newK8sKindsLabN(t, name, 0)
}

// newK8sKindsLabN is newK8sKindsLab with bulk more ServiceAccounts in
// iga-demo, each bound to pod-reader (two direct rows) by one RoleBinding
// and a member of both implicit groups (two group rows).
func newK8sKindsLabN(t *testing.T, name string, bulk int) *k8sGraphLab {
	t.Helper()
	k := newK8sGraphLab(t, name)
	k.agent("research-agent", k8sGraphNS, "system:serviceaccount:"+k8sGraphNS+":research", "Deployment")

	// kg-cluster: the access world plus Users, a Group and two more SAs.
	k.at = k.at.Add(time.Minute)
	s := k8sFullWorld().snapshot(k, k.at)
	k8sAccessGroups(&s, nil)
	s.Namespaces = []string{k8sGraphNS, "other"}
	for _, n := range []string{"builder", "deployer"} {
		s.ServiceAccounts = append(s.ServiceAccounts, models.K8sServiceAccount{
			Name: n, Namespace: "other", Anchor: "system:serviceaccount:other:" + n})
	}
	s.Roles = append(s.Roles, models.K8sRole{Kind: models.K8sKindClusterRole, Name: "controller",
		Rules: []models.K8sPolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}})
	s.Bindings = append(s.Bindings,
		models.K8sBinding{Kind: models.K8sKindClusterRoleBinding, Name: "kcm",
			RoleRef:  models.K8sRoleRef{Kind: models.K8sKindClusterRole, Name: "controller"},
			Subjects: []models.K8sSubject{{Kind: models.K8sSubjectUser, Name: k8sKindsKCM}}},
		models.K8sBinding{Kind: models.K8sKindClusterRoleBinding, Name: "ops-admin",
			RoleRef:  models.K8sRoleRef{Kind: models.K8sKindClusterRole, Name: "controller"},
			Subjects: []models.K8sSubject{{Kind: models.K8sSubjectGroup, Name: "ops"}}},
		models.K8sBinding{Kind: models.K8sKindRoleBinding, Name: "alice-pods", Namespace: k8sGraphNS,
			RoleRef:  models.K8sRoleRef{Kind: models.K8sKindRole, Name: "pod-reader"},
			Subjects: []models.K8sSubject{{Kind: models.K8sSubjectUser, Name: "alice"}}},
	)
	if bulk > 0 {
		rb := models.K8sBinding{Kind: models.K8sKindRoleBinding, Name: "bulk-pods", Namespace: k8sGraphNS,
			RoleRef: models.K8sRoleRef{Kind: models.K8sKindRole, Name: "pod-reader"}}
		for i := 0; i < bulk; i++ {
			n := fmt.Sprintf("bulk-%04d", i)
			s.ServiceAccounts = append(s.ServiceAccounts, models.K8sServiceAccount{
				Name: n, Namespace: k8sGraphNS, Anchor: "system:serviceaccount:" + k8sGraphNS + ":" + n})
			rb.Subjects = append(rb.Subjects, models.K8sSubject{Kind: models.K8sSubjectServiceAccount, Name: n, Namespace: k8sGraphNS})
		}
		s.Bindings = append(s.Bindings, rb)
	}
	if res, err := k.mgr.Ingest(k.ws, s); err != nil || !res.Accepted || !res.Reconciled {
		t.Fatalf("ingest kg-cluster: %+v %v", res, err)
	}

	// kg-other, from its own source.
	src := uuid.New()
	if err := k.db.Exec(`INSERT INTO discovery_sources (id, workspace_id, kind, display_name, cluster_name)
	                     VALUES (?, ?, ?, ?, ?)`, src, k.ws, models.DiscoverySourceK8sWebhook,
		"agent-"+src.String()[:8], k8sKindsOtherCluster).Error; err != nil {
		t.Fatalf("second source: %v", err)
	}
	k.at = k.at.Add(time.Minute)
	o := s
	o.DiscoverySourceID, o.Cluster, o.Namespaces = src.String(), k8sKindsOtherCluster, []string{k8sGraphNS}
	o.SweepStartedAt, o.ObservedAt = k.at.Add(-30*time.Second).Format(time.RFC3339), k.at.Format(time.RFC3339)
	o.ServiceAccounts = []models.K8sServiceAccount{{Name: "far", Namespace: k8sGraphNS,
		Anchor: "system:serviceaccount:" + k8sGraphNS + ":far"}}
	o.Roles = []models.K8sRole{{Kind: models.K8sKindClusterRole, Name: "viewer",
		Rules: []models.K8sPolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}}}}
	o.Bindings = []models.K8sBinding{
		{Kind: models.K8sKindClusterRoleBinding, Name: "far-view",
			RoleRef:  models.K8sRoleRef{Kind: models.K8sKindClusterRole, Name: "viewer"},
			Subjects: []models.K8sSubject{{Kind: models.K8sSubjectServiceAccount, Name: "far", Namespace: k8sGraphNS}}},
		{Kind: models.K8sKindClusterRoleBinding, Name: "kcm-other",
			RoleRef:  models.K8sRoleRef{Kind: models.K8sKindClusterRole, Name: "viewer"},
			Subjects: []models.K8sSubject{{Kind: models.K8sSubjectUser, Name: k8sKindsKCM}}},
	}
	if res, err := k.mgr.Ingest(k.ws, o); err != nil || !res.Accepted || !res.Reconciled {
		t.Fatalf("ingest kg-other: %+v %v", res, err)
	}
	return k
}

// kindsID is the id of a live Kubernetes identity by kind, name and cluster.
func (k *k8sGraphLab) kindsID(kind, anchor, cluster string) uuid.UUID {
	k.t.Helper()
	return k.k8sID("iga_identity_accounts", "account_kind = ? AND display_name = ? AND provider_attrs->>'cluster' = ?",
		kind, anchor, cluster)
}

// status calls a route and returns its status and decoded body.
func (a *k8sAccessAPI) status(path string) (int, map[string]any) {
	a.t.Helper()
	w := httptest.NewRecorder()
	a.eng.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/authsec/discovery"+path, nil))
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// kindsRows is a list response's identities, by id.
func kindsRows(body map[string]any) (ids []string, byID map[string]map[string]any) {
	byID = map[string]map[string]any{}
	for _, r := range digl(body, "identities") {
		m := r.(map[string]any)
		ids = append(ids, digs(m, "id"))
		byID[digs(m, "id")] = m
	}
	return ids, byID
}

func kindsSet(ids []string) string {
	s := append([]string(nil), ids...)
	sort.Strings(s)
	return strings.Join(s, ",")
}

// kindsAll walks every page of a list query at a page size, failing on a
// repeat, and returns the ids in order and each page's total.
func kindsAll(t *testing.T, a *k8sAccessAPI, query string, limit int) ([]string, []int64) {
	t.Helper()
	var ids []string
	var totals []int64
	seen := map[string]bool{}
	cursor := ""
	for page := 0; ; page++ {
		if page > 100 {
			t.Fatalf("%s: paging does not end", query)
		}
		q := query + "&limit=" + strconv.Itoa(limit)
		if cursor != "" {
			q += "&cursor=" + url.QueryEscape(cursor)
		}
		body, _ := a.get("/k8s/identities?" + q)
		totals = append(totals, num(body, "meta", "total"))
		pageIDs, _ := kindsRows(body)
		if len(pageIDs) > limit {
			t.Fatalf("%s: page of %d at limit %d", q, len(pageIDs), limit)
		}
		for _, id := range pageIDs {
			if seen[id] {
				t.Fatalf("%s: %s repeated across pages", q, id)
			}
			seen[id] = true
		}
		ids = append(ids, pageIDs...)
		next, _ := dig(body, "meta", "next_cursor").(string)
		if next == "" {
			if dig(body, "meta", "next_cursor") != nil {
				t.Errorf("%s: last page next_cursor = %v, want null", q, dig(body, "meta", "next_cursor"))
			}
			return ids, totals
		}
		if len(pageIDs) != limit {
			t.Errorf("%s: a short page (%d of %d) carries a next_cursor", q, len(pageIDs), limit)
		}
		cursor = next
	}
}

/* ----------------------------------- tests ---------------------------------- */

// The detail route reads one identity of each kind, with its list row's
// fields and counts; another workspace's id, an unknown id and a malformed
// one are 404, 404 and 400.
func TestP2K8sIdentityKindsDetail(t *testing.T) {
	k := newK8sKindsLab(t, "p2-k8s-kinds-detail")
	a := newK8sAccessAPI(t, k.db, k.ws)
	research := k.kindsID(models.K8sAccountKindServiceAccount, "system:serviceaccount:iga-demo:research", k8sGraphCluster)
	kcm := k.kindsID("k8s_user", k8sKindsKCM, k8sGraphCluster)
	kcmOther := k.kindsID("k8s_user", k8sKindsKCM, k8sKindsOtherCluster)
	allSAs := k.kindsID("k8s_group", k8sAccessAllSAs, k8sGraphCluster)
	authn := k.kindsID("k8s_group", k8sAccessAuthn, k8sGraphCluster)
	ops := k.kindsID("k8s_group", "ops", k8sGraphCluster)

	type want struct {
		id                         uuid.UUID
		kind, name, anchor, ns, cl string
		grants, stale, members     int64 // members -1: absent
		wildcard                   bool
	}
	_, list := kindsRows(func() map[string]any { b, _ := a.get("/k8s/identities?" + k8sKindsAllKinds); return b }())
	for _, w := range []want{
		{research, "k8s_service_account", "research", "system:serviceaccount:iga-demo:research", k8sGraphNS, k8sGraphCluster, 7, 0, -1, false},
		{kcm, "k8s_user", k8sKindsKCM, k8sKindsKCM, "", k8sGraphCluster, 1, 0, -1, true},
		{kcmOther, "k8s_user", k8sKindsKCM, k8sKindsKCM, "", k8sKindsOtherCluster, 1, 0, -1, false},
		{allSAs, "k8s_group", k8sAccessAllSAs, k8sAccessAllSAs, "", k8sGraphCluster, 1, 0, 2, false},
		{authn, "k8s_group", k8sAccessAuthn, k8sAccessAuthn, "", k8sGraphCluster, 1, 0, 4, false},
		{ops, "k8s_group", "ops", "ops", "", k8sGraphCluster, 1, 0, 0, true},
	} {
		body, raw := a.get("/k8s/identities/" + w.id.String())
		t.Logf("GET /k8s/identities/%s: %s", w.id, raw)
		got, _ := body["identity"].(map[string]any)
		if got == nil {
			t.Fatalf("%s: no identity in %s", w.anchor, raw)
		}
		if digs(got, "id") != w.id.String() || digs(got, "kind") != w.kind || digs(got, "name") != w.name ||
			digs(got, "anchor") != w.anchor || digs(got, "namespace") != w.ns || digs(got, "cluster") != w.cl ||
			digs(got, "lifecycle") != "active" || digs(got, "last_seen_at") == "" {
			t.Errorf("%s/%s detail = %v, want kind %s name %s namespace %q cluster %s, active", w.kind, w.anchor, got, w.kind, w.name, w.ns, w.cl)
		}
		if num(got, "grants") != w.grants || num(got, "stale") != w.stale || (dig(got, "wildcard") == true) != w.wildcard {
			t.Errorf("%s/%s counts = %d/%d/%v, want %d/%d/%v", w.kind, w.anchor,
				num(got, "grants"), num(got, "stale"), dig(got, "wildcard"), w.grants, w.stale, w.wildcard)
		}
		if m := num(got, "members"); m != w.members {
			t.Errorf("%s/%s members = %d, want %d (-1 = absent)", w.kind, w.anchor, m, w.members)
		}
		// The detail is the list row.
		lb, _ := json.Marshal(list[w.id.String()])
		db, _ := json.Marshal(got)
		if string(lb) != string(db) {
			t.Errorf("%s detail and list row differ:\n%s\n%s", w.anchor, db, lb)
		}
		// Its counts are its access route's summary.
		acc, _ := a.access(w.id)
		if num(acc, "summary", "partial") != w.grants || num(acc, "summary", "stale") != w.stale {
			t.Errorf("%s access summary %v, want partial %d stale %d", w.anchor, acc["summary"], w.grants, w.stale)
		}
	}

	// Another workspace: 404, as an unknown id; a malformed id is 400.
	kb := newK8sKindsLab(t, "p2-k8s-kinds-detail-b")
	asB := newK8sAccessAPI(t, kb.db, kb.ws)
	for _, id := range []uuid.UUID{research, kcm, ops, uuid.New()} {
		if code, body := asB.status("/k8s/identities/" + id.String()); code != http.StatusNotFound || digs(body, "code") != "not_found" {
			t.Errorf("workspace B GET identity %s = %d %v, want 404 not_found", id, code, body)
		}
	}
	if code, _ := a.status("/k8s/identities/not-a-uuid"); code != http.StatusBadRequest {
		t.Errorf("malformed id = %d, want 400", code)
	}
	// Nor does B's list carry A's identities, of any kind.
	bb, _ := asB.get("/k8s/identities?" + k8sKindsAllKinds)
	_, bList := kindsRows(bb)
	for _, id := range []uuid.UUID{research, kcm, kcmOther, allSAs, authn, ops} {
		if bList[id.String()] != nil {
			t.Errorf("workspace B lists workspace A's %s", id)
		}
	}
	if len(bList) != 11 || num(bb, "meta", "total") != 11 {
		t.Errorf("workspace B lists %d (total %d), want its own 11", len(bList), num(bb, "meta", "total"))
	}
}

// The list's kind, cluster and namespace filters; the default is unchanged
// (ServiceAccounts only), every identity carries its counts, and total is
// the filter's whole count.
func TestP2K8sIdentityKindsListFilters(t *testing.T) {
	k := newK8sKindsLab(t, "p2-k8s-kinds-list")
	a := newK8sAccessAPI(t, k.db, k.ws)
	sa := func(ns, n, cl string) string {
		return k.kindsID(models.K8sAccountKindServiceAccount, "system:serviceaccount:"+ns+":"+n, cl).String()
	}
	user := func(n, cl string) string { return k.kindsID("k8s_user", n, cl).String() }
	group := func(n string) string { return k.kindsID("k8s_group", n, k8sGraphCluster).String() }
	sas := []string{sa(k8sGraphNS, "research", k8sGraphCluster), sa(k8sGraphNS, "idle", k8sGraphCluster),
		sa("other", "builder", k8sGraphCluster), sa("other", "deployer", k8sGraphCluster), sa(k8sGraphNS, "far", k8sKindsOtherCluster)}
	users := []string{user(k8sKindsKCM, k8sGraphCluster), user("alice", k8sGraphCluster), user(k8sKindsKCM, k8sKindsOtherCluster)}
	groups := []string{group(k8sAccessAllSAs), group(k8sAccessAuthn), group("ops")}
	all := append(append(append([]string(nil), sas...), users...), groups...)

	// The default: ServiceAccounts only, every pre-D-113 field, total, no cursor.
	body, raw := a.get("/k8s/identities")
	t.Logf("GET /k8s/identities: %s", raw)
	ids, rows := kindsRows(body)
	if kindsSet(ids) != kindsSet(sas) {
		t.Errorf("default list = %v, want the 5 ServiceAccounts %v", ids, sas)
	}
	for _, r := range rows {
		for _, key := range []string{"id", "anchor", "namespace", "lifecycle", "grants", "wildcard", "stale"} {
			if _, ok := r[key]; !ok {
				t.Errorf("default list row lost %q: %v", key, r)
			}
		}
		if digs(r, "kind") != models.K8sAccountKindServiceAccount {
			t.Errorf("default list row kind = %q", digs(r, "kind"))
		}
	}
	if num(body, "meta", "total") != 5 || num(body, "meta", "limit") != 500 || dig(body, "meta", "next_cursor") != nil ||
		digs(body, "meta", "kinds", 0) != models.K8sAccountKindServiceAccount || len(digl(body, "meta", "kinds")) != 1 ||
		!strings.HasPrefix(digs(body, "meta", "note"), "a ServiceAccount is an identity") {
		t.Errorf("default meta = %v", body["meta"])
	}
	// An explicit service_account is the default.
	eb, _ := a.get("/k8s/identities?kind=service_account")
	if e, _ := kindsRows(eb); strings.Join(e, ",") != strings.Join(ids, ",") {
		t.Errorf("kind=service_account = %v, want the default's %v", e, ids)
	}

	for _, c := range []struct {
		query string
		want  []string
	}{
		{"kind=user", users},
		{"kind=group", groups},
		{"kind=user&kind=group", append(append([]string(nil), users...), groups...)},
		{k8sKindsAllKinds, all},
		{"kind=k8s_user,k8s_group,k8s_service_account", all},
		{"cluster=" + k8sKindsOtherCluster, sas[4:]},
		{"cluster=" + k8sKindsOtherCluster + "&" + k8sKindsAllKinds, []string{sas[4], users[2]}},
		{"cluster=" + k8sGraphCluster + "&kind=user", users[:2]},
		{"cluster=kg", nil}, // a prefix of a cluster's name is not that cluster
		{"namespace=other", sas[2:4]},
		{"namespace=" + k8sGraphNS + "&" + k8sKindsAllKinds, []string{sas[0], sas[1], sas[4]}},
		{"namespace=" + k8sGraphNS + "&cluster=" + k8sGraphCluster, sas[:2]},
		{"namespace=other&kind=user,group", nil}, // a User or Group has no namespace
	} {
		body, _ := a.get("/k8s/identities?" + c.query)
		got, rows := kindsRows(body)
		if kindsSet(got) != kindsSet(c.want) {
			t.Errorf("%s = %v, want %v", c.query, got, c.want)
		}
		if num(body, "meta", "total") != int64(len(c.want)) {
			t.Errorf("%s total = %d, want %d", c.query, num(body, "meta", "total"), len(c.want))
		}
		// Every row's counts are its access route's.
		for id, r := range rows {
			acc, _ := a.access(uuid.MustParse(id))
			if num(r, "grants") != num(acc, "summary", "partial") || num(r, "stale") != num(acc, "summary", "stale") {
				t.Errorf("%s: %s %s counts %d/%d, access summary %v", c.query, digs(r, "kind"), digs(r, "anchor"),
					num(r, "grants"), num(r, "stale"), acc["summary"])
			}
		}
	}

	// Users' and Groups' counts are set, not missing.
	ub, _ := a.get("/k8s/identities?kind=user,group")
	_, ur := kindsRows(ub)
	wantGrants := map[string]int64{users[0]: 1, users[1]: 2, users[2]: 1, groups[0]: 1, groups[1]: 1, groups[2]: 1}
	for id, n := range wantGrants {
		if num(ur[id], "grants") != n || num(ur[id], "stale") != 0 {
			t.Errorf("%s grants/stale = %d/%d, want %d/0", digs(ur[id], "anchor"), num(ur[id], "grants"), num(ur[id], "stale"), n)
		}
	}
	if dig(ur[users[0]], "wildcard") != true || dig(ur[groups[2]], "wildcard") != true || dig(ur[users[1]], "wildcard") != false {
		t.Errorf("wildcard: kcm %v ops %v alice %v, want true true false",
			dig(ur[users[0]], "wildcard"), dig(ur[groups[2]], "wildcard"), dig(ur[users[1]], "wildcard"))
	}
	if num(ur[groups[0]], "members") != 2 || num(ur[groups[1]], "members") != 4 || num(ur[groups[2]], "members") != 0 {
		t.Errorf("group members = %d/%d/%d, want 2/4/0", num(ur[groups[0]], "members"), num(ur[groups[1]], "members"), num(ur[groups[2]], "members"))
	}
	if _, ok := ur[users[0]]["members"]; ok {
		t.Errorf("a User carries members: %v", ur[users[0]])
	}

	// Bad parameters are 400, never ignored.
	for _, q := range []string{"kind=robot", "kind=user,robot", "cluster=a&cluster=b", "namespace=a&namespace=b"} {
		if code, b := a.status("/k8s/identities?" + q); code != http.StatusBadRequest || digs(b, "code") != "invalid_parameter" {
			t.Errorf("%s = %d %v, want 400 invalid_parameter", q, code, b)
		}
	}
	// limit: 1-1000, 500 when absent or unreadable.
	for q, want := range map[string]int64{"limit=3": 3, "limit=5000": 1000, "limit=abc": 500, "limit=0": 500, "limit=-2": 500} {
		b, _ := a.get("/k8s/identities?" + q)
		if num(b, "meta", "limit") != want {
			t.Errorf("%s: meta.limit = %d, want %d", q, num(b, "meta", "limit"), want)
		}
	}
}

// Cursor paging: every page size walks the same rows, in the unpaged order,
// with no repeat and a constant total; a cursor is bound to its workspace and
// filter set.
func TestP2K8sIdentityKindsPaging(t *testing.T) {
	k := newK8sKindsLab(t, "p2-k8s-kinds-paging")
	a := newK8sAccessAPI(t, k.db, k.ws)

	for _, query := range []string{k8sKindsAllKinds, "kind=service_account", "kind=user,group&cluster=" + k8sGraphCluster} {
		whole, _ := a.get("/k8s/identities?" + query + "&limit=1000")
		want, _ := kindsRows(whole)
		total := num(whole, "meta", "total")
		if total != int64(len(want)) || dig(whole, "meta", "next_cursor") != nil {
			t.Fatalf("%s unpaged: %d rows, total %d, next %v", query, len(want), total, dig(whole, "meta", "next_cursor"))
		}
		for _, limit := range []int{1, 2, 4} {
			got, totals := kindsAll(t, a, query, limit)
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("%s limit %d paged =\n%v\nwant\n%v", query, limit, got, want)
			}
			if wantPages := (len(want) + limit - 1) / limit; len(totals) != wantPages {
				t.Errorf("%s limit %d: %d pages for %d rows", query, limit, len(totals), len(want))
			}
			for _, tot := range totals {
				if tot != total {
					t.Errorf("%s limit %d: a page's total = %d, want %d", query, limit, tot, total)
				}
			}
		}
	}
	all, _ := a.get("/k8s/identities?" + k8sKindsAllKinds + "&limit=1000")
	if n := len(digl(all, "identities")); n != 11 {
		t.Fatalf("all kinds = %d, want 11", n)
	}

	// The cursor is bound to the filter set -- normalised, so the same kinds
	// in another spelling are the same filter -- and to the workspace.
	first, firstRaw := a.get("/k8s/identities?kind=user,group&limit=1")
	t.Logf("GET /k8s/identities?kind=user,group&limit=1: %s", firstRaw)
	cur, _ := dig(first, "meta", "next_cursor").(string)
	if cur == "" {
		t.Fatalf("no next_cursor on a first page of 1: %v", first["meta"])
	}
	c := url.QueryEscape(cur)
	if code, b := a.status("/k8s/identities?kind=group&kind=user&limit=3&cursor=" + c); code != http.StatusOK || len(digl(b, "identities")) != 3 {
		t.Errorf("the same kinds respelled, another limit = %d %v, want 200 and a page of 3", code, b)
	}
	for _, q := range []string{
		"kind=user&cursor=" + c,
		"kind=user,group,service_account&cursor=" + c,
		"cursor=" + c,
		"kind=user,group&cluster=" + k8sGraphCluster + "&cursor=" + c,
		"kind=user,group&namespace=x&cursor=" + c,
		"kind=user,group&cursor=" + c + "x",
		"kind=user,group&cursor=garbage",
	} {
		if code, b := a.status("/k8s/identities?" + q); code != http.StatusBadRequest || digs(b, "code") != "cursor_invalid" {
			t.Errorf("%s = %d %v, want 400 cursor_invalid", q, code, b)
		}
	}
	// Same signer, another workspace's token.
	kb := newK8sGraphLab(t, "p2-k8s-kinds-paging-b")
	a.ws = kb.ws
	if code, b := a.status("/k8s/identities?kind=user,group&cursor=" + c); code != http.StatusBadRequest ||
		digs(b, "code") != "cursor_invalid" || !strings.Contains(digs(b, "error"), "workspace") {
		t.Errorf("workspace A's cursor in workspace B = %d %v, want 400 cursor_invalid (another workspace)", code, b)
	}
}

// /identities/:id/access for Users and Groups: a Group's rows are its own
// grants, a User's likewise -- no via, every row direct.
func TestP2K8sIdentityKindsAccess(t *testing.T) {
	k := newK8sKindsLab(t, "p2-k8s-kinds-access")
	a := newK8sAccessAPI(t, k.db, k.ws)
	for _, c := range []struct {
		kind, anchor string
		want         []string
	}{
		{"k8s_group", "ops", []string{"ops-admin|controller|cluster|||current"}},
		{"k8s_group", k8sAccessAllSAs, []string{"all-sas-view-pods|pod-viewer|cluster|||current"}},
		{"k8s_group", k8sAccessAuthn, []string{"authenticated-secrets|secret-reader|namespace|iga-demo||current"}},
		{"k8s_user", k8sKindsKCM, []string{"kcm|controller|cluster|||current"}},
		{"k8s_user", "alice", []string{"alice-pods|iga-demo/pod-reader|namespace|iga-demo||current",
			"alice-pods|iga-demo/pod-reader|namespace|iga-demo||current"}},
	} {
		id := k.kindsID(c.kind, c.anchor, k8sGraphCluster)
		body, raw := a.access(id)
		t.Logf("GET access (%s %s): %s", c.kind, c.anchor, raw)
		rows := k8sAccessRows(t, body)
		if got := k8sAccessKeys(rows); strings.Join(got, "\n") != strings.Join(c.want, "\n") {
			t.Errorf("%s %s access =\n%s\nwant\n%s", c.kind, c.anchor, strings.Join(got, "\n"), strings.Join(c.want, "\n"))
		}
		for _, r := range rows {
			if r.raw["via"] != nil || !r.resolved || digs(r.raw, "basis") != "declared" {
				t.Errorf("%s %s grant %v: want direct, resolved, declared", c.kind, c.anchor, r.raw)
			}
		}
		n := int64(len(c.want))
		k8sWant(t, c.anchor, k8sSummary(body), map[string]int64{"total": n, "partial": n, "stale": 0,
			"resolved": n, "unresolved": 0, "direct": n, "via_group": 0})
		k8sNoEffective(t, "access", body)
	}
}

/* ------------------------- counts are the page's only ------------------------ */

// k8sCaptured is one statement a route ran, as the driver received it.
type k8sCaptured struct {
	sql  string
	vars []any
}

// k8sCapturingDB is a second connection to the test database that records
// every statement read through it.
func k8sCapturingDB(t *testing.T) (*gorm.DB, func() []k8sCaptured) {
	t.Helper()
	db, err := gorm.Open(postgres.Open(os.Getenv("IGA_TEST_DSN")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("capturing db: %v", err)
	}
	t.Cleanup(func() {
		if s, err := db.DB(); err == nil {
			_ = s.Close()
		}
	})
	var mu sync.Mutex
	var got []k8sCaptured
	if err := db.Callback().Row().After("gorm:row").Register("k8s_kinds_capture", func(d *gorm.DB) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, k8sCaptured{sql: d.Statement.SQL.String(), vars: append([]any(nil), d.Statement.Vars...)})
	}); err != nil {
		t.Fatalf("capture callback: %v", err)
	}
	return db, func() []k8sCaptured {
		mu.Lock()
		defer mu.Unlock()
		out := got
		got = nil
		return out
	}
}

// k8sCountStatement is the one captured statement that reads access rows.
func k8sCountStatement(t *testing.T, what string, stmts []k8sCaptured) k8sCaptured {
	t.Helper()
	var hits []k8sCaptured
	for _, s := range stmts {
		if strings.Contains(s.sql, "iga_access_edges") {
			hits = append(hits, s)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("%s: %d statements read access rows, want exactly one (the page's counts)", what, len(hits))
	}
	return hits[0]
}

// k8sBoundIDs is every uuid a statement binds but the workspace's.
func k8sBoundIDs(s k8sCaptured, ws uuid.UUID) map[string]bool {
	out := map[string]bool{}
	for _, v := range s.vars {
		var id string
		switch x := v.(type) {
		case uuid.UUID:
			id = x.String()
		case string:
			if u, err := uuid.Parse(x); err == nil {
				id = u.String()
			}
		}
		if id != "" && id != ws.String() {
			out[id] = true
		}
	}
	return out
}

// k8sPlanScan is one scan node of an EXPLAIN ANALYZE: its relation, the rows
// it produced (actual rows x loops) and its conditions.
type k8sPlanScan struct {
	rel   string
	rows  float64
	conds string
}

func k8sPlanRows(t *testing.T, db *gorm.DB, s k8sCaptured) []k8sPlanScan {
	t.Helper()
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := sqlDB.QueryRow("EXPLAIN (ANALYZE, FORMAT JSON) "+s.sql, s.vars...).Scan(&raw); err != nil {
		t.Fatalf("explain: %v\n%s", err, s.sql)
	}
	var plan []map[string]any
	if err := json.Unmarshal([]byte(raw), &plan); err != nil || len(plan) == 0 {
		t.Fatalf("explain output: %v %s", err, raw)
	}
	var out []k8sPlanScan
	var walk func(n map[string]any)
	walk = func(n map[string]any) {
		if rel, _ := n["Relation Name"].(string); rel != "" {
			rows, _ := n["Actual Rows"].(float64)
			loops, _ := n["Actual Loops"].(float64)
			var conds []string
			for _, k := range []string{"Index Cond", "Filter", "Recheck Cond"} {
				if c, _ := n[k].(string); c != "" {
					conds = append(conds, c)
				}
			}
			out = append(out, k8sPlanScan{rel: rel, rows: rows * loops, conds: strings.Join(conds, " AND ")})
		}
		for _, c := range digl(n, "Plans") {
			if m, ok := c.(map[string]any); ok {
				walk(m)
			}
		}
	}
	walk(plan[0]["Plan"].(map[string]any))
	return out
}

// The list routes choose their page first and count access rows for that
// page's identities only (D-113): the one statement that reads access rows
// binds exactly the page's ids, and its plan reads memberships and direct
// grants of those holders only -- a handful for a page of 5 in a workspace of
// 200+ identities, against hundreds for the whole list. The counts are still
// the access route's.
func TestP2K8sIdentityKindsCountsArePageScoped(t *testing.T) {
	const bulk = 200
	k := newK8sKindsLabN(t, "p2-k8s-kinds-pagescope", bulk)
	capDB, captured := k8sCapturingDB(t)
	a := newK8sAccessAPI(t, capDB, k.ws)
	// Statistics, as autovacuum keeps them on a live database: without them
	// the planner takes every table for a few rows and loops seq scans.
	if err := k.db.Exec(`ANALYZE iga_access_edges, iga_relationship, iga_identity_accounts, iga_object_support, iga_entitlements`).Error; err != nil {
		t.Fatalf("analyze: %v", err)
	}

	// A page of 5 of 205 ServiceAccounts (the bulk ones sort first: each
	// holds 2 direct and 2 group rows).
	captured()
	body, _ := a.get("/k8s/identities?kind=service_account&limit=5")
	stmts := captured()
	pageIDs, rows := kindsRows(body)
	if len(pageIDs) != 5 || num(body, "meta", "total") != 5+bulk {
		t.Fatalf("page of %d, total %d; want 5 of %d", len(pageIDs), num(body, "meta", "total"), 5+bulk)
	}
	count := k8sCountStatement(t, "identities page", stmts)
	if got := k8sBoundIDs(count, k.ws); kindsSet(keys(got)) != kindsSet(pageIDs) {
		t.Errorf("the counting statement binds %v, want exactly the page's ids %v", keys(got), pageIDs)
	}
	scans := k8sPlanRows(t, capDB, count)
	t.Logf("page of 5, plan scans: %+v", scans)
	// 5 holders, each with 2 direct rows and 2 memberships (one grant per
	// group): every scan of a per-identity table produces a handful of rows.
	// iga_entitlements is the rules -- bounded by the roles, not the
	// identities -- and is not checked.
	const pageBound = 40
	sawDirect, sawMember := false, false
	for _, sc := range scans {
		switch sc.rel {
		case "iga_access_edges", "iga_relationship", "iga_identity_accounts", "iga_object_support":
			if sc.rows > pageBound {
				t.Errorf("%s scan produced %v rows for a page of 5 (%s): not restricted to the page", sc.rel, sc.rows, sc.conds)
			}
		}
		if sc.rel == "iga_relationship" && strings.Contains(sc.conds, "source_identity_account_id = ANY") {
			sawMember = true
		}
		if sc.rel == "iga_access_edges" && strings.Contains(sc.conds, "subject_identity_account_id = ANY") {
			sawDirect = true
		}
	}
	if !sawDirect || !sawMember {
		t.Errorf("direct-grant scan restricted to the page's holders: %v; membership scan restricted to them: %v; plan %+v", sawDirect, sawMember, scans)
	}

	// The same statement for the whole list reads hundreds: the bound above
	// is not vacuous.
	captured()
	a.get("/k8s/identities?" + k8sKindsAllKinds + "&limit=1000")
	whole := k8sCountStatement(t, "whole list", captured())
	var wholeRel float64
	for _, sc := range k8sPlanRows(t, capDB, whole) {
		if sc.rel == "iga_relationship" {
			wholeRel += sc.rows
		}
	}
	if wholeRel < 2*bulk {
		t.Errorf("whole list's membership scan read %v rows, want >= %d", wholeRel, 2*bulk)
	}

	// The page's counts are its rows' access summaries.
	for id, r := range rows {
		acc, _ := a.access(uuid.MustParse(id))
		if num(r, "grants") != num(acc, "summary", "partial") || num(r, "stale") != num(acc, "summary", "stale") {
			t.Errorf("%s counts %d/%d, access summary %v", digs(r, "anchor"), num(r, "grants"), num(r, "stale"), acc["summary"])
		}
	}
	// And so are a bulk ServiceAccount's (2 direct + 2 group rows), and the
	// groups' members count every bulk ServiceAccount.
	nb, _ := a.get("/k8s/identities?" + k8sKindsAllKinds + "&limit=1000")
	_, all := kindsRows(nb)
	bulk0 := k.kindsID(models.K8sAccountKindServiceAccount, "system:serviceaccount:iga-demo:bulk-0000", k8sGraphCluster)
	acc0, _ := a.access(bulk0)
	if num(all[bulk0.String()], "grants") != 4 || num(acc0, "summary", "partial") != 4 {
		t.Errorf("bulk-0000 grants = %d (access partial %d), want 4 (2 direct, 2 through groups)",
			num(all[bulk0.String()], "grants"), num(acc0, "summary", "partial"))
	}
	if g := k.kindsID("k8s_group", k8sAccessAllSAs, k8sGraphCluster).String(); num(all[g], "members") != 2+bulk {
		t.Errorf("%s members = %d, want %d", k8sAccessAllSAs, num(all[g], "members"), 2+bulk)
	}

	// The workloads list counts its page's execution identities only.
	captured()
	wb, _ := a.get("/k8s/workloads?limit=1")
	wcount := k8sCountStatement(t, "workloads page", captured())
	research := k.kindsID(models.K8sAccountKindServiceAccount, "system:serviceaccount:iga-demo:research", k8sGraphCluster)
	if got := k8sBoundIDs(wcount, k.ws); kindsSet(keys(got)) != research.String() {
		t.Errorf("the workloads counting statement binds %v, want only %s (the page's runs_as)", keys(got), research)
	}
	if n := num(wb, "workloads", 0, "grants"); n != 7 {
		t.Errorf("research-agent grants = %d, want 7", n)
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
