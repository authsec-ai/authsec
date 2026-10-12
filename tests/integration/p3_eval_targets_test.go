package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// T3.06b (SPEC-iga-phase3-policy.md §2.11, §2.12, §7.1, §7.2): the target
// resolver, the evidence bundle builder and readiness, outside the barrier,
// over evaluations the REAL projection job produced.

// projectOnly runs one projection pass (with evaluation) of a scanned run.
func (l *p3eLab) projectOnly() int64 {
	l.t.Helper()
	scanSeq++
	worked, err := l.projector(fmt.Sprintf("p3e-projector-%d", scanSeq), nil).RunOnce(context.Background())
	if err != nil || !worked {
		l.t.Fatalf("projector: worked=%v err=%v", worked, err)
	}
	return l.latestRev()
}

// p3eUser inserts a workspace member.
func (l *p3eLab) user() uuid.UUID {
	l.t.Helper()
	id := uuid.New()
	if err := l.db.Exec(`INSERT INTO users (id, email, workspace_id) VALUES (?, ?, ?)`, id, id.String()+"@p3e.test", l.ws).Error; err != nil {
		l.t.Fatal(err)
	}
	l.t.Cleanup(func() { l.db.Exec(`DELETE FROM users WHERE id = ?`, id) })
	return id
}

// owner records an accountable owner on an identity or workload.
func (l *p3eLab) owner(kind string, object, user uuid.UUID) {
	l.t.Helper()
	col := "identity_account_id"
	if kind == models.GovObjectWorkload {
		col = "workload_id"
	}
	if err := l.db.Exec(`INSERT INTO iga_gov_owner (workspace_id, object_kind, `+col+`, user_id, role, source)
	                     VALUES (?, ?, ?, ?, 'accountable', 'manual')`, l.ws, kind, object, user).Error; err != nil {
		l.t.Fatalf("owner: %v", err)
	}
}

func (l *p3eLab) workloadID(name string) uuid.UUID {
	l.t.Helper()
	return bdbID(l.t, l.p2Lab, `SELECT id FROM iga_workload WHERE workspace_id = ? AND display_name = ? AND lifecycle = 'active'`, l.ws, name)
}

func p3eTag(a *p2Account, role string, tags map[string]string, boundary string) {
	for i := range a.iam.roles {
		if aws.ToString(a.iam.roles[i].RoleName) != role {
			continue
		}
		for k, v := range tags {
			a.iam.roles[i].Tags = append(a.iam.roles[i].Tags, iamtypes.Tag{Key: aws.String(k), Value: aws.String(v)})
		}
		if boundary != "" {
			a.iam.roles[i].PermissionsBoundary = &iamtypes.AttachedPermissionsBoundary{PermissionsBoundaryArn: aws.String(boundary),
				PermissionsBoundaryType: iamtypes.PermissionsBoundaryAttachmentTypePolicy}
		}
	}
}

// A63. Roles in every category, some in several: counts sum to the roles
// reviewed, each role once by precedence, every reason listed; paging
// returns each role exactly once; links name the connection coverage and
// the findings.
//
// Safeguards (mutation-checked): the precedence order; counts over every
// role reviewed rather than the page.
func TestP3T306bA63Readiness(t *testing.T) {
	l := newP3eLab(t, "p3-t306b-a63")
	a := l.account(accountA)
	act := l.activity(a)
	unused := map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil}
	roles := map[string]string{}
	for i, name := range []string{"CollectRole", "ProtectedRole", "OwnerlessRole", "CustomerBoundaryRole", "DirectRole", "QuietRole"} {
		arn := p3eOldRole(a, name, fmt.Sprintf("AROAREADY%05d", i), 200*24*time.Hour, name+"Work", p3eSQSS3)
		roles[name] = arn
		if name != "QuietRole" {
			p3eAddLambda(a, "us-east-1", strings.ToLower(name)+"-fn", arn)
		}
		act.set(arn, unused)
	}
	act.fail[roles["CollectRole"]] = true
	act.set(roles["QuietRole"], map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": p3eTime(time.Hour)})
	p3eTag(a, "ProtectedRole", map[string]string{"authsec:protected": "true"}, "")
	boundary := a.managed("CustomerBoundary", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
	p3eTag(a, "CustomerBoundaryRole", nil, boundary)

	run := l.scanOnly(a)
	l.projectOnly()
	u := l.user()
	for _, name := range []string{"ProtectedRole", "CustomerBoundaryRole", "DirectRole", "QuietRole"} {
		l.owner(models.GovObjectIdentityAccount, bdbIdentity(t, l.p2Lab, name), u)
	}
	// Enforce mode, and a verified enforcement binding for the connector.
	if err := l.db.Exec(`INSERT INTO iga_gov_settings (workspace_id, enforcement_mode) VALUES (?, 'enforce')`, l.ws).Error; err != nil {
		t.Fatal(err)
	}
	if err := l.db.Exec(`INSERT INTO cloud_enforcement_binding (workspace_id, connector_id, account_id, state, consented_by, verified_at)
	                     VALUES (?, ?, ?, 'verified', ?, now())`, l.ws, a.conn, accountA, u).Error; err != nil {
		t.Fatal(err)
	}
	// Resource-policy coverage complete is not collected by this branch; an
	// unused_service role is then blocked by collection unless the run has
	// complete coverage. Give the run complete coverage of every collected
	// form so the other categories are reachable.
	p3eCompleteCoverage(t, l, a, run.ID)

	api := l.api()
	code, body := api.get(l.ws, "/readiness")
	if code != http.StatusOK {
		t.Fatalf("/readiness: %d %v", code, body)
	}
	d, _ := body["data"].(map[string]any)
	counts, _ := d["counts"].(map[string]any)
	sum := 0.0
	for _, c := range services.ReadinessOrder {
		sum += counts[c].(float64)
	}
	if d["roles_reviewed"] != float64(6) || sum != 6 {
		t.Fatalf("roles reviewed %v, counts %v (sum %v), want 6 summing to 6", d["roles_reviewed"], counts, sum)
	}
	want := map[string]string{
		"CollectRole": services.ReadinessBlockedByCollection, "ProtectedRole": services.ReadinessIneligible,
		"OwnerlessRole": services.ReadinessNeedsOwner, "CustomerBoundaryRole": services.ReadinessIaCOnly,
		"DirectRole": services.ReadinessDirectEligible, "QuietRole": services.ReadinessNoChangeNeeded,
	}
	got := map[string]map[string]any{}
	for _, r := range d["roles"].([]any) {
		m := r.(map[string]any)
		got[m["role_name"].(string)] = m
	}
	for name, cat := range want {
		r := got[name]
		if r == nil || r["category"] != cat {
			t.Fatalf("%s: %v, want category %s", name, r, cat)
		}
		if counts[cat] != float64(1) {
			t.Fatalf("count[%s] = %v, want 1", cat, counts[cat])
		}
	}
	// "Some in several": every reason is listed, not only the deciding one.
	reasonCats := func(name string) map[string]bool {
		out := map[string]bool{}
		for _, x := range got[name]["reasons"].([]any) {
			out[x.(map[string]any)["category"].(string)] = true
		}
		return out
	}
	if rc := reasonCats("CollectRole"); !rc[services.ReadinessBlockedByCollection] || !rc[services.ReadinessNeedsOwner] {
		t.Fatalf("CollectRole reasons %v, want blocked_by_collection AND needs_owner", got["CollectRole"]["reasons"])
	}
	if rc := reasonCats("ProtectedRole"); !rc[services.ReadinessIneligible] || rc[services.ReadinessNeedsOwner] {
		t.Fatalf("ProtectedRole reasons %v", got["ProtectedRole"]["reasons"])
	}
	if got["CollectRole"]["remedy"] != "/iga/connections/"+a.conn.String()+"/coverage" {
		t.Fatalf("collection remedy %v", got["CollectRole"]["remedy"])
	}
	if !strings.HasPrefix(fmt.Sprint(got["OwnerlessRole"]["remedy"]), "/iga/policy/findings?kind=missing_owner") {
		t.Fatalf("owner remedy %v", got["OwnerlessRole"]["remedy"])
	}
	// Paging: limit 4 then the cursor; every role once; counts unchanged.
	seen := map[string]int{}
	cursor := ""
	for page := 0; page < 5; page++ {
		path := "/readiness?limit=4"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		code, body = api.get(l.ws, path)
		if code != http.StatusOK {
			t.Fatalf("%s: %d %v", path, code, body)
		}
		pd := body["data"].(map[string]any)
		if pd["roles_reviewed"] != float64(6) {
			t.Fatalf("page %d: roles_reviewed %v, want 6 on every page", page, pd["roles_reviewed"])
		}
		for _, r := range pd["roles"].([]any) {
			seen[r.(map[string]any)["role_name"].(string)]++
		}
		next, _ := p3eMeta(body, "next_cursor").(string)
		if next == "" {
			break
		}
		cursor = next
	}
	if len(seen) != 6 {
		t.Fatalf("paged roles %v, want all 6 once", seen)
	}
	for n, c := range seen {
		if c != 1 {
			t.Fatalf("%s paged %d times", n, c)
		}
	}
	// Account filter.
	if code, body = api.get(l.ws, "/readiness?account="+accountB); code != http.StatusOK || body["data"].(map[string]any)["roles_reviewed"] != float64(0) {
		t.Fatalf("other account: %d %v", code, body)
	}
}

// p3eCompleteCoverage writes complete resource-policy coverage for every
// collected form in the account's regions for a run (what T3.03b's
// collector will write; not collected by this branch), and freezes the
// run's region scope as the collector does (us-east-1 selected and the only
// enabled region; review P1-6). TestP3CovUnselectedRegions* drive the real
// collector instead.
func p3eCompleteCoverage(t *testing.T, l *p3eLab, a *p2Account, run uuid.UUID) {
	t.Helper()
	if err := l.db.Exec(`UPDATE cloud_scan_run SET coverage = jsonb_set(coverage, '{regions}',
	                       '{"selected":["us-east-1"],"enabled":["us-east-1"],"enabled_known":true}'::jsonb, true)
	                     WHERE workspace_id = ? AND id = ?`, l.ws, run).Error; err != nil {
		t.Fatalf("region scope: %v", err)
	}
	for _, f := range igagov.AllForms() {
		if f.State != igagov.FormCollected {
			continue
		}
		if err := l.db.Exec(`INSERT INTO cloud_resource_policy_coverage (workspace_id, connector_id, scan_run_id, resource_form, region, state)
		                     VALUES (?, ?, ?, ?, 'us-east-1', 'complete')`, l.ws, a.conn, run, f.Name).Error; err != nil {
			t.Fatalf("coverage %s: %v", f.Name, err)
		}
	}
}

// A53. (a) An activity report older than the freshness rule: the bundle is
// untrusted naming the source (stale), and evidence_untrusted (422) names
// it with the Connections remedy; the resolver reports the same trust.
// (b) Resource-policy coverage partial: the bundle is partial with the gap
// listed (its acceptance is T3.13's). (c) A Kubernetes key: not_supported
// with K-1, and no finding for it. The bundle is insert-once, re-verified
// by the 050 trigger, and served back verified.
func TestP3T306bA53EvidenceTrust(t *testing.T) {
	l := newP3eLab(t, "p3-t306b-a53")
	a := l.account(accountA)
	arn := p3eOldRole(a, "StaleRole", "AROASTALE00001", 200*24*time.Hour, "StaleWork", p3eSQSS3)
	a.lambda("us-east-1", "stale", arn)
	act := l.activity(a)
	act.set(arn, map[string]*time.Time{"s3": p3eTime(40 * time.Hour), "sqs": nil})
	act.completed = time.Now().Add(-30 * time.Hour) // older than the 24 h rule
	l.cycle(a, nil)
	ident := bdbIdentity(t, l.p2Lab, "StaleRole")
	tg := services.NewGovTargets(l.db)

	// (a)
	b, err := tg.BuildEvidenceBundle(context.Background(), l.ws, ident, []string{"sqs"}, models.GovActorSystem, "test")
	if err != nil {
		t.Fatal(err)
	}
	if b.Trust != igagov.TrustUntrusted || !p3eHas(b.TrustReasons, "stale") {
		t.Fatalf("stale report: trust %s %v, want untrusted naming stale", b.Trust, b.TrustReasons)
	}
	ue := b.UntrustedError()
	if ue == nil || ue.Status != http.StatusUnprocessableEntity || ue.Code != "evidence_untrusted" {
		t.Fatalf("untrusted error %+v", ue)
	}
	srcs, _ := ue.Detail["sources"].([]map[string]any)
	if len(srcs) != 1 || srcs[0]["remedy"] != "/iga/connections/"+a.conn.String()+"/coverage" || !p3eHas(srcs[0]["reasons"].([]string), "stale") {
		t.Fatalf("evidence_untrusted detail %v, want the source with its reason and the Connections remedy", ue.Detail)
	}
	api := l.api()
	code, body := api.do(l.ws, http.MethodPost, "/targets/resolve", map[string]any{"keys": []map[string]any{
		{"provider": "aws", "account_id": accountA, "role_arn": arn}}})
	res := p3eList(body)
	if code != http.StatusOK || len(res) != 1 || res[0]["status"] != services.TargetResolved {
		t.Fatalf("resolve: %d %v", code, body)
	}
	if ev, _ := res[0]["evidence"].(map[string]any); ev["trust"] != igagov.TrustUntrusted || ev["freshness_hours"].(float64) < 24 {
		t.Fatalf("resolver evidence %v, want untrusted and > 24 h old", ev)
	}
	// Insert-once: the same facts reuse the row; the 050 trigger refuses a
	// tampered row and any update; GET re-verifies.
	again, err := tg.WithClock(func() time.Time { return time.Now() }).BuildEvidenceBundle(context.Background(), l.ws, ident, []string{"sqs"}, models.GovActorSystem, "test")
	if err != nil {
		t.Fatal(err)
	}
	if again.Hash == b.Hash && (again.ID != b.ID || again.Created) {
		t.Fatalf("identical bundle inserted twice: %v / %v", b.ID, again.ID)
	}
	if err := l.db.Exec(`UPDATE iga_gov_evidence_bundle SET trust = 'trusted' WHERE id = ?`, b.ID).Error; err == nil {
		t.Fatal("a bundle was updated")
	}
	if err := l.db.Exec(`INSERT INTO iga_gov_evidence_bundle (workspace_id, provider, trust, bundle_hash, canonical, facts)
	                     SELECT workspace_id, provider, trust, 'sha256:00', canonical, facts FROM iga_gov_evidence_bundle WHERE id = ?`, b.ID).Error; err == nil ||
		!strings.Contains(err.Error(), "hash does not match") {
		t.Fatalf("a bundle with a wrong hash: %v, want the 050 trigger's refusal", err)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = 'evidence_bundle_created'`, l.ws); n < 1 {
		t.Fatal("no evidence_bundle_created event")
	}
	code, body = api.get(l.ws, "/evidence-bundles/"+b.ID.String())
	bd, _ := body["data"].(map[string]any)
	if code != http.StatusOK || bd["bundle_hash"] != b.Hash || bd["trust"] != igagov.TrustUntrusted {
		t.Fatalf("GET bundle: %d %v", code, body)
	}

	// (b) A fresh scan whose resource-policy coverage of sqs queues is partial.
	act.completed = time.Now().Add(-2 * time.Hour)
	run := l.scanOnly(a)
	p3eCompleteCoverage(t, l, a, run.ID)
	if err := l.db.Exec(`DELETE FROM cloud_resource_policy_coverage WHERE scan_run_id = ? AND resource_form = 'sqs_queue'`, run.ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := l.db.Exec(`INSERT INTO cloud_resource_policy_coverage (workspace_id, connector_id, scan_run_id, resource_form, region, state,
	                            enumerated, read_ok, read_failed, reason)
	                     VALUES (?, ?, ?, 'sqs_queue', 'us-east-1', 'partial', 2, 1, 1, 'GetQueueAttributes AccessDenied')`,
		l.ws, a.conn, run.ID).Error; err != nil {
		t.Fatal(err)
	}
	l.projectOnly()
	pb, err := tg.BuildEvidenceBundle(context.Background(), l.ws, ident, []string{"sqs"}, models.GovActorSystem, "test")
	if err != nil {
		t.Fatal(err)
	}
	var gapKeys []string
	for _, g := range pb.Facts.Gaps {
		gapKeys = append(gapKeys, g.Key)
	}
	if pb.Trust != igagov.TrustPartial || !p3eHas(gapKeys, "sqs_queue") || pb.Facts.Sources[0].ResourcePolicyCoverage != igagov.CoveragePartial {
		t.Fatalf("partial coverage: trust %s %v gaps %v source %+v, want partial with the sqs_queue gap", pb.Trust, pb.TrustReasons, gapKeys, pb.Facts.Sources[0])
	}
	if len(pb.GapRefs) != len(pb.Facts.Gaps) {
		t.Fatalf("gap refs %d for %d gaps", len(pb.GapRefs), len(pb.Facts.Gaps))
	}

	// (c) A Kubernetes ServiceAccount: by key and by graph object id.
	k8sID := uuid.New()
	if err := l.db.Exec(`INSERT INTO iga_identity_accounts (id, workspace_id, display_name, account_kind, provider, source_key)
	                     VALUES (?, ?, 'payments-sa', 'service_account', 'k8s', ?)`, k8sID, l.ws, "k8s\x1fsa\x1f"+k8sID.String()).Error; err != nil {
		t.Fatal(err)
	}
	code, body = api.do(l.ws, http.MethodPost, "/targets/resolve", map[string]any{"keys": []map[string]any{
		{"provider": "k8s", "cluster_uid": "c-1", "namespace": "payments", "service_account": "payments-sa"},
		{"object_id": k8sID.String()}}})
	for _, r := range p3eList(body) {
		if r["status"] != services.TargetNotSupported || r["prerequisite"] != "K-1" {
			t.Fatalf("Kubernetes key: %d %v, want not_supported with K-1", code, r)
		}
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_finding WHERE workspace_id = ? AND identity_account_id = ?`, l.ws, k8sID); n != 0 {
		t.Fatalf("%d findings for a Kubernetes identity", n)
	}
	if _, err := tg.BuildEvidenceBundle(context.Background(), l.ws, k8sID, []string{"sqs"}, models.GovActorSystem, "test"); err == nil {
		t.Fatal("a bundle was built for a Kubernetes identity")
	}
}

func p3eHas(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// A54. A workspace with more than 10,000 inventory rows: a role absent from
// the first inventory page resolves by ARN, by RoleId and by Discovery
// object id with every consumer and owner (consumers_unresolved = 0), and
// its evidence bundle matches the one built for an identical role on the
// first page.
//
// Safeguard (mutation-checked): resolution by key, never from a capped list.
func TestP3T306bA54TargetBeyondListCaps(t *testing.T) {
	l := newP3eLab(t, "p3-t306b-a54")
	a := l.account(accountA)
	act := l.activity(a)
	report := map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil}
	twin := p3eOldRole(a, "AAA-twin", "AROATWIN000001", 200*24*time.Hour, "TwinWork", p3eSQSS3)
	target := p3eOldRole(a, "zz-target", "AROATARGET0001", 200*24*time.Hour, "TargetWork", p3eSQSS3)
	for _, r := range []struct{ arn, prefix string }{{twin, "twin"}, {target, "target"}} {
		p3eAddLambda(a, "us-east-1", r.prefix+"-api", r.arn)
		p3eAddLambda(a, "us-east-1", r.prefix+"-worker", r.arn)
		act.set(r.arn, report)
	}
	l.cycle(a, nil)
	u := l.user()
	for _, p := range []string{"twin", "target"} {
		name := map[string]string{"twin": "AAA-twin", "target": "zz-target"}[p]
		l.owner(models.GovObjectIdentityAccount, bdbIdentity(t, l.p2Lab, name), u)
		l.owner(models.GovObjectWorkload, l.workloadID(p+"-api"), l.user())
	}
	targetID := bdbIdentity(t, l.p2Lab, "zz-target")

	// 10,050 more inventory rows, all sorting before the target.
	// Each with a live support row, as the inventory lists only supported rows.
	if err := l.db.Exec(`WITH pad AS (
	                       INSERT INTO iga_identity_accounts (workspace_id, display_name, account_kind, provider, source_key, last_seen_at)
	                       SELECT ?, 'A-pad-' || lpad(g::text, 5, '0'), 'iam_role', 'aws',
	                              'aws' || chr(31) || 'arn:aws:iam::429418377036:role/A-pad-' || lpad(g::text, 5, '0'), now() + interval '1 hour'
	                         FROM generate_series(1, 10050) g
	                       RETURNING id)
	                     INSERT INTO iga_object_support (workspace_id, identity_account_id, connector_id, partition_key, state)
	                     SELECT ?, id, ?, 'p3e-pad', 'current' FROM pad`, l.ws, l.ws, a.conn).Error; err != nil {
		t.Fatalf("pad inventory: %v", err)
	}
	// Planner statistics for the freshly loaded rows (autovacuum would do it).
	if err := l.db.Exec(`ANALYZE iga_identity_accounts; ANALYZE iga_object_support`).Error; err != nil {
		t.Fatal(err)
	}
	if n := l.count(`SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = ?`, l.ws); n <= 10000 {
		t.Fatalf("inventory rows %d, want more than 10,000", n)
	}
	api := l.api()
	// The inventory's first page does not contain the target.
	req := httptest.NewRequest(http.MethodGet, "/api/iga/v1/inventory/identities?limit=200", nil)
	req.Header.Set("Authorization", "Bearer "+api.token(l.ws, "iga:read"))
	w := httptest.NewRecorder()
	api.eng.ServeHTTP(w, req)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), targetID.String()) {
		t.Fatalf("inventory page 1: %d (contains target: %v)", w.Code, strings.Contains(w.Body.String(), targetID.String()))
	}
	var inv map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &inv)
	if items, _ := inv["data"].([]any); len(items) != 200 {
		t.Fatalf("inventory page 1 has %d rows, want a full page of 200: %.300s", len(items), w.Body.String())
	}

	code, body := api.do(l.ws, http.MethodPost, "/targets/resolve", map[string]any{"keys": []map[string]any{
		{"provider": "aws", "account_id": accountA, "role_arn": target},
		{"provider": "aws", "role_id": "AROATARGET0001"},
		{"object_id": targetID.String()},
		{"object_id": l.workloadID("target-worker").String()},
	}})
	res := p3eList(body)
	if code != http.StatusOK || len(res) != 4 {
		t.Fatalf("resolve: %d %v", code, body)
	}
	for i, r := range res {
		id, _ := r["identity"].(map[string]any)
		if r["status"] != services.TargetResolved || id["role_id"] != "AROATARGET0001" || id["id"] != targetID.String() {
			t.Fatalf("key %d: %v, want resolved to the target incarnation", i, r)
		}
		if n := len(r["consumers"].([]any)); n != 2 || r["consumers_unresolved"] != float64(0) {
			t.Fatalf("key %d consumers %v (unresolved %v), want both, none unresolved", i, r["consumers"], r["consumers_unresolved"])
		}
		if n := len(r["owners"].([]any)); n != 2 {
			t.Fatalf("key %d owners %v, want the role's and the workload's", i, r["owners"])
		}
		if r["eligible"] != true {
			t.Fatalf("key %d not eligible: %v", i, r["ineligible_reasons"])
		}
	}
	if ctx, _ := res[3]["context"].(map[string]any); ctx["object_kind"] != "workload" {
		t.Fatalf("a workload id is context: %v", res[3]["context"])
	}

	// The bundle for the target matches the twin's, role identity aside.
	tg := services.NewGovTargets(l.db)
	bt, err := tg.BuildEvidenceBundle(context.Background(), l.ws, targetID, []string{"sqs"}, models.GovActorSystem, "test")
	if err != nil {
		t.Fatal(err)
	}
	bw, err := tg.BuildEvidenceBundle(context.Background(), l.ws, bdbIdentity(t, l.p2Lab, "AAA-twin"), []string{"sqs"}, models.GovActorSystem, "test")
	if err != nil {
		t.Fatal(err)
	}
	shape := func(f igagov.BundleFacts) string {
		var acts, grants []string
		for _, x := range f.Activity {
			acts = append(acts, x.Service+":"+x.State+":"+x.Outcome+":"+x.GrantAgeBasis)
		}
		for _, g := range f.Grants {
			grants = append(grants, strings.Join(g.Services, ","))
		}
		sort.Strings(grants)
		return fmt.Sprintf("trust=%s removed=%v consumers=%d unresolved=%d owners=%d activity=%v grants=%v gaps=%d",
			f.Sources[0].Trust, f.RemovedServices, len(f.Consumers), f.ConsumersUnresolved, len(f.Owners), acts, grants, len(f.Gaps))
	}
	if shape(bt.Facts) != shape(bw.Facts) {
		t.Fatalf("target bundle differs from the first-page twin's:\n%s\n%s", shape(bt.Facts), shape(bw.Facts))
	}
	if len(bt.Facts.Consumers) != 2 || bt.Facts.ConsumersUnresolved != 0 {
		t.Fatalf("bundle consumers %v unresolved %d", bt.Facts.Consumers, bt.Facts.ConsumersUnresolved)
	}
}

// Another workspace's ids are 404 on every read, never 403, and its lists
// are empty; resolving another workspace's role is not_found.
func TestP3T306bCrossWorkspaceIs404(t *testing.T) {
	l := newP3eLab(t, "p3-t306b-xws")
	a := l.account(accountA)
	arn := p3eOldRole(a, "SecretRole", "AROASECRET0001", 200*24*time.Hour, "SecretWork", p3eSQSS3)
	a.lambda("us-east-1", "secret", arn)
	l.activity(a).set(arn, map[string]*time.Time{"sqs": nil})
	l.cycle(a, nil)
	ident := bdbIdentity(t, l.p2Lab, "SecretRole")
	b, err := services.NewGovTargets(l.db).BuildEvidenceBundle(context.Background(), l.ws, ident, []string{"sqs"}, models.GovActorSystem, "test")
	if err != nil {
		t.Fatal(err)
	}
	var finding uuid.UUID
	if err := l.db.Raw(`SELECT id FROM iga_gov_finding WHERE workspace_id = ? LIMIT 1`, l.ws).Row().Scan(&finding); err != nil {
		t.Fatal(err)
	}
	other := newWorkspace(t, l.db, "p3-t306b-xws-other")
	api := l.api()
	for _, path := range []string{"/findings/" + finding.String(), "/identities/" + ident.String() + "/activity-evidence",
		"/evidence-bundles/" + b.ID.String()} {
		if code, body := api.get(other, path); code != http.StatusNotFound || p3eErr(body) != "not_found" {
			t.Fatalf("other workspace %s: %d %v, want 404 not_found", path, code, body)
		}
		if code, _ := api.get(l.ws, path); code != http.StatusOK {
			t.Fatalf("own workspace %s: %d", path, code)
		}
	}
	if code, body := api.get(other, "/findings"); code != http.StatusOK || len(p3eList(body)) != 0 {
		t.Fatalf("other workspace list: %d %v", code, body)
	}
	code, body := api.do(other, http.MethodPost, "/targets/resolve", map[string]any{"keys": []map[string]any{
		{"object_id": ident.String()}, {"provider": "aws", "role_id": "AROASECRET0001"},
		{"provider": "aws", "account_id": accountA, "role_arn": arn}}})
	for _, r := range p3eList(body) {
		if r["status"] != services.TargetNotFound || r["identity"] != nil {
			t.Fatalf("other workspace resolve: %d %v, want not_found", code, r)
		}
	}
	// Bad shapes are 400, before any lookup.
	if code, body = api.do(l.ws, http.MethodPost, "/targets/resolve", map[string]any{"keys": []map[string]any{{}}}); code != http.StatusBadRequest {
		t.Fatalf("empty key: %d %v", code, body)
	}
	many := make([]map[string]any, services.MaxTargetKeys+1)
	for i := range many {
		many[i] = map[string]any{"provider": "aws", "role_id": "x"}
	}
	if code, _ = api.do(l.ws, http.MethodPost, "/targets/resolve", map[string]any{"keys": many}); code != http.StatusBadRequest {
		t.Fatalf("51 keys: %d, want 400", code)
	}
}
