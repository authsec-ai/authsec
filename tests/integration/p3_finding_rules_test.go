package integration

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// Review fix R1a P2 "missing §7.1 routes": the /finding-rules CRUD and
// POST/DELETE /findings/:id/exception, through the PRODUCTION routes over the
// P3 lab (REAL scan worker, REAL projection with the evaluation step).

// missing_review_date fires end to end: a role consumed by a Lambda whose
// accountable owner has no review date raises nothing until a
// require_review_date rule is created THROUGH THE ROUTE; the next publication
// then produces the finding (with a result at that revision citing the rule);
// disabling the rule through PATCH clears it at the next publication; DELETE
// removes the rule. Validation, cursor paging, permissions, cross-workspace
// 404, iga_gov_event and audit_events on every mutation.
func TestP3FindingRuleMissingReviewDateEndToEnd(t *testing.T) {
	l := newP3aLab(t, "p3misc-finding-rules")
	roleID := "AROAMISCREVIEWDATE01"
	l.role("ReviewDateRole", roleID, map[string]*time.Time{"s3": p3eTime(time.Hour)})
	l.publish()
	identity := bdbID(t, l.p2Lab, `SELECT id FROM iga_identity_accounts WHERE workspace_id = ? AND immutable_key = ?`, l.ws, roleID)
	var wl []struct {
		ID          uuid.UUID
		RuntimeKind string
	}
	l.db.Raw(`SELECT DISTINCT w.id, w.runtime_kind FROM iga_relationship r
		JOIN iga_workload w ON w.workspace_id = r.workspace_id AND w.id = r.source_workload_id
		WHERE r.workspace_id = ? AND r.target_identity_account_id = ?`, l.ws, identity).Scan(&wl)
	if len(wl) != 1 {
		t.Fatalf("consumers %+v, want the Lambda", wl)
	}
	owner := l.member("rd-owner", "read")
	admin := l.token(l.ws, l.author, p3aAllScopes+" iga:admin")
	code, body := l.callAs(admin, http.MethodPut, "/owners", map[string]any{"object_kind": "workload", "object_id": wl[0].ID.String(),
		"owners": []map[string]any{{"user_id": owner.user.String(), "role": "accountable"}}})
	l.must(code, body, http.StatusOK, "PUT owners")

	key := "missing_review_date/" + roleID + "/"
	l.publish()
	if f, ok := l.findingsAt(l.latestRev())[key]; ok && f.ResultRev != nil {
		t.Fatalf("missing_review_date without a rule: %+v", f)
	}

	// Validation (each 400 invalid_parameter, nothing stored).
	for name, b := range map[string]map[string]any{
		"kind":          {"kind": "require_everything"},
		"stage":         {"kind": "require_review_date", "scope": map[string]any{"stages": []string{"prod"}}},
		"scope field":   {"kind": "require_review_date", "scope": map[string]any{"teams": []string{"x"}}},
		"params":        {"kind": "require_review_date", "params": map[string]any{"days": 90}},
		"window low":    {"kind": "unused_window", "params": map[string]any{"window_days": 5}},
		"window absent": {"kind": "unused_window"},
	} {
		code, body := l.call(l.author, http.MethodPost, "/finding-rules", b)
		if code != http.StatusBadRequest || p3eErr(body) != "invalid_parameter" {
			t.Fatalf("%s: %d %v, want 400 invalid_parameter", name, code, body)
		}
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_finding_rule WHERE workspace_id = ?`, l.ws); n != 0 {
		t.Fatalf("%d rules stored by refused requests", n)
	}
	// governance:read alone may not manage rules.
	if code, _ := l.callAs(l.token(l.ws, l.author, "governance:read"), http.MethodGet, "/finding-rules", nil); code != http.StatusForbidden {
		t.Fatalf("GET /finding-rules with governance:read: %d, want 403", code)
	}

	// The rule, through the route.
	code, body = l.call(l.author, http.MethodPost, "/finding-rules", map[string]any{"kind": "require_review_date",
		"scope": map[string]any{"runtime_kinds": []string{wl[0].RuntimeKind}, "stages": []string{"production", "unknown", "non_production"}}})
	rule := l.must(code, body, http.StatusCreated, "POST /finding-rules")
	ruleID := fmt.Sprint(rule["id"])
	if rule["enabled"] != true || fmt.Sprint(dig(rule, "scope", "stages")) != "[non_production production unknown]" {
		t.Fatalf("created rule %v", rule)
	}
	code, body = l.call(l.author, http.MethodPost, "/finding-rules", map[string]any{"kind": "unused_window",
		"params": map[string]any{"window_days": 120}, "scope": map[string]any{"stages": []string{"production"}}})
	window := l.must(code, body, http.StatusCreated, "POST unused_window")

	// Cursor paging: one per page, both rules, then no cursor.
	seen := map[string]bool{}
	cursor := ""
	for i := 0; i < 3; i++ {
		q := "/finding-rules?limit=1"
		if cursor != "" {
			q += "&cursor=" + cursor
		}
		code, body := l.call(l.author, http.MethodGet, q, nil)
		if code != http.StatusOK {
			t.Fatalf("GET %s: %d %v", q, code, body)
		}
		for _, r := range p3eList(body) {
			seen[fmt.Sprint(r["id"])] = true
		}
		next, _ := p3eMeta(body, "next_cursor").(string)
		if next == "" {
			break
		}
		cursor = next
	}
	if len(seen) != 2 || !seen[ruleID] || !seen[fmt.Sprint(window["id"])] {
		t.Fatalf("paged rules %v", seen)
	}

	// Another workspace: lists nothing of ours, and our ids are 404.
	other := p3NewGov(t, l.db, "p3misc-finding-rules-other")
	otherTok := l.token(other.ws, p3aMember{user: other.author, membership: other.authorMember}, p3aAllScopes)
	if code, body := l.callAs(otherTok, http.MethodGet, "/finding-rules", nil); code != http.StatusOK || len(p3eList(body)) != 0 {
		t.Fatalf("other workspace list: %d %v", code, body)
	}
	for _, m := range []string{http.MethodPatch, http.MethodDelete} {
		if code, body := l.callAs(otherTok, m, "/finding-rules/"+ruleID, map[string]any{"enabled": false}); code != http.StatusNotFound {
			t.Fatalf("%s another workspace's rule: %d %v, want 404", m, code, body)
		}
	}

	// The next publication produces the finding.
	l.publish()
	rev := l.latestRev()
	f, ok := l.findingsAt(rev)[key]
	if !ok || f.ResultRev == nil || *f.ResultRev != rev || f.Status != igagov.StatusOpen {
		t.Fatalf("missing_review_date at rev %d = %+v (ok %v), want open with a result", rev, f, ok)
	}
	var detail string
	l.db.Raw(`SELECT detail::text FROM iga_gov_finding_result WHERE workspace_id = ? AND rev = ? AND finding_id = ?`, l.ws, rev, f.ID).Scan(&detail)
	if !strings.Contains(detail, ruleID) {
		t.Fatalf("result detail %s does not cite rule %s", detail, ruleID)
	}

	// PATCH: kind immutable; disable clears it at the next publication.
	if code, body := l.call(l.author, http.MethodPatch, "/finding-rules/"+ruleID, map[string]any{"kind": "unused_window"}); code != http.StatusBadRequest {
		t.Fatalf("PATCH kind: %d %v", code, body)
	}
	code, body = l.call(l.author, http.MethodPatch, "/finding-rules/"+ruleID, map[string]any{"enabled": false})
	if d := l.must(code, body, http.StatusOK, "PATCH enabled"); d["enabled"] != false {
		t.Fatalf("PATCH answer %v", d)
	}
	l.publish()
	if f := l.findingsAt(l.latestRev())[key]; f.ResultRev != nil || f.Status != igagov.StatusCleared {
		t.Fatalf("after disabling the rule: %+v, want cleared", f)
	}
	code, body = l.call(l.author, http.MethodDelete, "/finding-rules/"+ruleID, nil)
	l.must(code, body, http.StatusOK, "DELETE rule")
	if n := l.count(`SELECT count(*) FROM iga_gov_finding_rule WHERE workspace_id = ? AND id = ?`, l.ws, ruleID); n != 0 {
		t.Fatal("the rule survived DELETE")
	}
	for name, want := range map[string]int64{services.GovEventFindingRuleCreated: 2, services.GovEventFindingRuleUpdated: 1, services.GovEventFindingRuleDeleted: 1} {
		if n := l.events(name); n != want {
			t.Errorf("%s events: %d, want %d", name, n, want)
		}
	}
	p3WaitAudit(t, l.db, l.ws, http.MethodDelete, "/api/iga/v1/policy/finding-rules/"+ruleID)
	if n := l.count(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = ? AND payload->>'finding_rule_id' = ?`,
		l.ws, services.GovEventFindingRuleDeleted, ruleID); n != 1 {
		t.Fatalf("finding_rule.deleted event naming the rule: %d", n)
	}
}

// Finding exceptions end to end: recorded through the route on an open
// unused_service finding (validation, cross-workspace 404, event naming the
// finding, audit row); the evaluator's lifecycle keeps it excepted while the
// condition holds and the exception has not passed; the owner gate refuses a
// version that removes the excepted service (409 review_incomplete,
// finding_excepted) until DELETE clears it, after which the same version is
// approved; a lapsed exception returns to open at the next publication.
func TestP3FindingExceptionEndToEnd(t *testing.T) {
	l := newP3aLab(t, "p3misc-finding-exception")
	t.Cleanup(services.InstallGovOwnerReviewWiring(l.db))
	roleID := "AROAMISCEXCEPTION001"
	l.role("ExceptionRole", roleID, map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	l.publish()
	key := "unused_service/" + roleID + "/sqs"
	f, ok := l.findingsAt(l.latestRev())[key]
	if !ok || f.Status != igagov.StatusOpen {
		t.Fatalf("unused_service(sqs) = %+v (ok %v)", f, ok)
	}
	path := "/findings/" + f.ID.String() + "/exception"
	until := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)

	for name, b := range map[string]map[string]any{
		"no reason":  {"until": until.Format(time.RFC3339)},
		"past":       {"until": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), "reason": "x"},
		"too far":    {"until": time.Now().Add(400 * 24 * time.Hour).UTC().Format(time.RFC3339), "reason": "x"},
		"not a time": {"until": "next tuesday", "reason": "x"},
	} {
		if code, body := l.call(l.author, http.MethodPost, path, b); code != http.StatusBadRequest {
			t.Fatalf("%s: %d %v, want 400", name, code, body)
		}
	}
	other := p3NewGov(t, l.db, "p3misc-finding-exception-other")
	otherTok := l.token(other.ws, p3aMember{user: other.author, membership: other.authorMember}, p3aAllScopes)
	if code, _ := l.callAs(otherTok, http.MethodPost, path, map[string]any{"until": until.Format(time.RFC3339), "reason": "x"}); code != http.StatusNotFound {
		t.Fatalf("another workspace's finding: %d, want 404", code)
	}
	if code, _ := l.callAs(l.token(l.ws, l.author, "governance:read"), http.MethodPost, path,
		map[string]any{"until": until.Format(time.RFC3339), "reason": "x"}); code != http.StatusForbidden {
		t.Fatalf("governance:read: %d, want 403", code)
	}
	if code, body := l.call(l.author, http.MethodDelete, path, nil); code != http.StatusConflict || p3eErr(body) != services.GovCodeFindingNotExcepted {
		t.Fatalf("DELETE with no exception: %d %v", code, body)
	}

	code, body := l.call(l.author, http.MethodPost, path, map[string]any{"until": until.Format(time.RFC3339),
		"reason": "the nightly DLQ drain uses sqs; reviewed with the app team"})
	d := l.must(code, body, http.StatusOK, "POST exception")
	if d["status"] != igagov.StatusExcepted || fmt.Sprint(d["excepted_until"]) != until.Format(time.RFC3339) {
		t.Fatalf("exception answer %v", d)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = ? AND finding_id = ?`,
		l.ws, services.GovEventFindingExcepted, f.ID); n != 1 {
		t.Fatalf("finding.excepted events naming the finding: %d", n)
	}
	p3WaitAudit(t, l.db, l.ws, http.MethodPost, "/api/iga/v1/policy"+path)

	// The evaluator keeps it excepted while the condition holds.
	l.publish()
	rev := l.latestRev()
	if f2 := l.findingsAt(rev)[key]; f2.Status != igagov.StatusExcepted || f2.ResultRev == nil || *f2.ResultRev != rev {
		t.Fatalf("after a publication: %+v, want excepted with a result at rev %d", f2, rev)
	}

	// The owner gate honours it.
	identity := bdbID(t, l.p2Lab, `SELECT id FROM iga_identity_accounts WHERE workspace_id = ? AND immutable_key = ?`, l.ws, roleID)
	roleOwner := l.member("exc-owner", "read")
	wireOwner(t, l, models.GovObjectIdentityAccount, identity, roleOwner.user)
	var workloads []uuid.UUID
	l.db.Raw(`SELECT DISTINCT w.id FROM iga_relationship r
		JOIN iga_workload w ON w.workspace_id = r.workspace_id AND w.id = r.source_workload_id
		WHERE r.workspace_id = ? AND r.target_identity_account_id = ?`, l.ws, identity).Scan(&workloads)
	for _, w := range workloads {
		wireOwner(t, l, models.GovObjectWorkload, w, roleOwner.user)
	}
	policy, _ := l.proposeTemplate(roleID)
	plans := l.compile(policy, 1)
	review, _ := l.reviewOfVersion(policy, 1)
	l.ack(roleOwner, review)
	code, body = l.approve(l.approver, policy, 1, p3aApproveBody(plans, nil))
	if code != http.StatusConflict || p3eErr(body) != "review_incomplete" || digs(body, "error", "detail", "reason") != services.GovBlockFindingExcepted ||
		!strings.Contains(fmt.Sprint(body), f.ID.String()) {
		t.Fatalf("approve over an excepted removal: %d %v, want 409 review_incomplete finding_excepted naming the finding", code, body)
	}
	code, body = l.call(l.author, http.MethodDelete, path, map[string]any{"reason": "the DLQ drain moved to its own role"})
	if d := l.must(code, body, http.StatusOK, "DELETE exception"); d["status"] != igagov.StatusOpen || d["excepted_until"] != nil {
		t.Fatalf("DELETE answer %v", d)
	}
	if n := l.events(services.GovEventFindingExceptionCleared); n != 1 {
		t.Fatalf("finding.exception_cleared events: %d", n)
	}
	code, body = l.approve(l.approver, policy, 1, p3aApproveBody(l.plans(policy, 1), nil))
	l.must(code, body, http.StatusOK, "approve after the exception is cleared")

	// A lapsed exception returns to open at the next evaluation (until is
	// moved into the past: time passing, not a lifecycle write).
	f3 := l.findingsAt(l.latestRev())[key]
	if f3.Status == igagov.StatusOpen || f3.Status == igagov.StatusReopened {
		code, body = l.call(l.author, http.MethodPost, path, map[string]any{"until": until.Format(time.RFC3339), "reason": "again"})
		l.must(code, body, http.StatusOK, "POST exception again")
		p3exec(t, l.db, `UPDATE iga_gov_finding SET excepted_until = now() - interval '1 minute' WHERE id = ?`, f.ID)
		l.publish()
		if f4 := l.findingsAt(l.latestRev())[key]; f4.Status != igagov.StatusOpen {
			t.Fatalf("a lapsed exception: %+v, want open", f4)
		}
	}
}
