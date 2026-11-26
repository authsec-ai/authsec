package integration

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/services"
)

// W5 (SPEC-secops-backend-upgrade.md P3): the approvals inbox over the
// seven second-person mechanisms, break-glass reviews and the overdue
// worker, automation identities, case subjects, the remediate right and
// W7's break-glass. Needs IGA_TEST_DSN (skipped otherwise).

const w5Base = "/api/iga/v1"

// w5Seeds inserts one row of every second-person kind into g's workspace,
// requested by requester: pending (open) or break-glass applied with a review
// due at due. It returns kind -> id.
func w5Seed(t *testing.T, db *gorm.DB, ws, requester uuid.UUID, breakGlass bool, due time.Time) map[string]uuid.UUID {
	t.Helper()
	ids := map[string]uuid.UUID{}
	for _, k := range services.ApprovalKinds() {
		ids[k] = uuid.New()
	}
	state := uuid.New()
	p3exec(t, db, `INSERT INTO agent_capability_state (id, workspace_id, estate_scope, scope_kind, capability, state, gap_kind)
		VALUES (?, ?, ?, 'account', 'C3', 'off', 'broken')`, state, ws, "aws:"+state.String()[:12])
	hash := strings.Repeat("a", 64)
	if !breakGlass {
		p3exec(t, db, `INSERT INTO pending_change (id, workspace_id, kind, target_ref, reason, requested_by, expires_at)
			VALUES (?, ?, 'agent_gateway.runtime', 'agent_gateway:x', 'loosen', ?, now() + interval '7 days')`, ids[services.ApprovalKindPendingChange], ws, requester)
		p3exec(t, db, `INSERT INTO agent_detection_rule_version (id, workspace_id, version_no, state, proposed_by, proposed_at, reason)
			VALUES (?, ?, 1, 'proposed', ?, now(), 'turn D5 off')`, ids[services.ApprovalKindRuleVersion], ws, requester)
		p3exec(t, db, `INSERT INTO agent_alert_suppression (id, workspace_id, identity_id, detection, reason, duration_days, state, requested_by)
			VALUES (?, ?, gen_random_uuid(), 'D5', 'noisy', 30, 'proposed', ?)`, ids[services.ApprovalKindSuppression], ws, requester)
		p3exec(t, db, `INSERT INTO agent_capability_declaration (id, workspace_id, capability_state_id, reason, requested_by)
			VALUES (?, ?, ?, 'no resolver logs', ?)`, ids[services.ApprovalKindCoverageDeclare], ws, state, requester)
		p3exec(t, db, `INSERT INTO audit_governance_change (id, workspace_id, kind, target, reason, requested_by, expires_at)
			VALUES (?, ?, 'retention_shorten', 'standard', 'cost', ?, now() + interval '7 days')`, ids[services.ApprovalKindAuditChange], ws, requester)
		p3exec(t, db, `INSERT INTO agent_pending_change (id, workspace_id, kind, subject_id, reason, requested_by)
			VALUES (?, ?, 'agent_risk_class_lower', gen_random_uuid(), 'narrowed', ?)`, ids[services.ApprovalKindAgentChange], ws, requester)
		p3exec(t, db, `INSERT INTO iga_history_approval (id, workspace_id, action, params_hash, reason, requested_by, expires_at)
			VALUES (?, ?, 'bulk_export', ?, 'audit request', ?, now() + interval '7 days')`, ids[services.ApprovalKindHistoryChange], ws, hash, requester)
		return ids
	}
	p3exec(t, db, `INSERT INTO pending_change (id, workspace_id, kind, target_ref, reason, state, requested_by, expires_at, applied_at, break_glass, review_due_at)
		VALUES (?, ?, 'agent_gateway.runtime', 'agent_gateway:x', 'loosen', 'applied', ?, now(), now(), true, ?)`, ids[services.ApprovalKindPendingChange], ws, requester, due)
	p3exec(t, db, `INSERT INTO agent_detection_rule_version (id, workspace_id, version_no, state, proposed_by, proposed_at, activated_at, reason, break_glass, review_due_at)
		VALUES (?, ?, 7, 'superseded', ?, now(), now(), 'turn D5 off', true, ?)`, ids[services.ApprovalKindRuleVersion], ws, requester, due)
	p3exec(t, db, `INSERT INTO agent_alert_suppression (id, workspace_id, identity_id, detection, reason, duration_days, state, requested_by, starts_at, ends_at, break_glass, review_due_at)
		VALUES (?, ?, gen_random_uuid(), 'D5', 'noisy', 30, 'active', ?, now(), now() + interval '30 days', true, ?)`, ids[services.ApprovalKindSuppression], ws, requester, due)
	p3exec(t, db, `INSERT INTO agent_capability_declaration (id, workspace_id, capability_state_id, reason, requested_by, state, decided_by, decided_at, break_glass, review_due_at)
		VALUES (?, ?, ?, 'no resolver logs', ?, 'applied', ?, now(), true, ?)`, ids[services.ApprovalKindCoverageDeclare], ws, state, requester, requester, due)
	p3exec(t, db, `INSERT INTO audit_governance_change (id, workspace_id, kind, target, reason, status, requested_by, expires_at, decided_by, decided_at, break_glass, review_due_at)
		VALUES (?, ?, 'retention_shorten', 'standard', 'cost', 'applied', ?, now(), ?, now(), true, ?)`, ids[services.ApprovalKindAuditChange], ws, requester, requester, due)
	p3exec(t, db, `INSERT INTO agent_pending_change (id, workspace_id, kind, subject_id, reason, requested_by, state, decided_by, decided_at, break_glass, review_due_at)
		VALUES (?, ?, 'agent_risk_class_lower', gen_random_uuid(), 'narrowed', ?, 'applied', ?, now(), true, ?)`, ids[services.ApprovalKindAgentChange], ws, requester, requester, due)
	p3exec(t, db, `INSERT INTO iga_history_approval (id, workspace_id, action, params_hash, reason, requested_by, expires_at, state, decided_by, decided_at, break_glass, review_due_at)
		VALUES (?, ?, 'bulk_export', ?, 'audit request', ?, now(), 'applied', ?, now(), true, ?)`, ids[services.ApprovalKindHistoryChange], ws, hash, requester, requester, due)
	return ids
}

func w5Items(t *testing.T, code int, out map[string]any) []map[string]any {
	t.Helper()
	if code != http.StatusOK {
		t.Fatalf("list: %d %v", code, out)
	}
	raw, _ := out["data"].([]any)
	items := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		items = append(items, r.(map[string]any))
	}
	return items
}

func w5List(t *testing.T, e *agEnv, path, tok string) []map[string]any {
	t.Helper()
	code, out := e.call("GET", path, tok, nil)
	return w5Items(t, code, out)
}

func w5Code(out map[string]any) string {
	if e, ok := out["error"].(map[string]any); ok {
		c, _ := e["code"].(string)
		return c
	}
	return ""
}

func w5Membership(t *testing.T, db *gorm.DB, ws, user uuid.UUID) uuid.UUID {
	t.Helper()
	var m struct{ ID uuid.UUID }
	if err := db.Raw(`SELECT id FROM workspace_memberships WHERE workspace_id = ? AND user_id = ?`, ws, user).Scan(&m).Error; err != nil || m.ID == uuid.Nil {
		t.Fatalf("membership: %v", err)
	}
	return m.ID
}

// w5AutomationToken is a session of user that names a machine principal
// (a SOAR playbook acting through a service user).
func w5AutomationToken(t *testing.T, ws, user, membership uuid.UUID, scope string) string {
	t.Helper()
	claims := jwt.MapClaims{"iss": "authsec-ai/auth-manager", "exp": time.Now().Add(time.Hour).Unix(),
		"workspace_id": ws.String(), "user_id": user.String(), "workspace_membership_id": membership.String(),
		"scope": scope, "actor_kind": "automation"}
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(p3OwnersSecret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

const w5Scopes = "governance:read governance:author governance:approve governance:enforce governance:emergency discovery:read"

// The inbox lists every kind's open requests, with the kind's own approve and
// reject routes; expired requests are left out; another workspace sees none of
// them, and acting on them from there is 404.
func TestApprovalsInboxListsEveryKindAndIsolates(t *testing.T) {
	e := agSetup(t)
	a, b := e.gov("w5-inbox-a"), e.gov("w5-inbox-b")
	e.grant(a, a.approver, "governance:approve")
	idsA := w5Seed(t, e.db, a.ws, a.author, false, time.Time{})
	expired := uuid.New()
	p3exec(t, e.db, `INSERT INTO pending_change (id, workspace_id, kind, target_ref, reason, requested_by, requested_at, expires_at)
		VALUES (?, ?, 'agent_gateway.runtime', 'agent_gateway:old', 'old', ?, now() - interval '8 days', now() - interval '1 day')`, expired, a.ws, a.author)
	idsB := w5Seed(t, e.db, b.ws, b.author, false, time.Time{})

	tokA := e.api.token(a.ws, a.approver, w5Membership(t, e.db, a.ws, a.approver), w5Scopes)
	tokB := e.api.token(b.ws, b.author, b.authorMember, w5Scopes)

	items := w5List(t, e, w5Base+"/approvals", tokA)
	seen := map[string]bool{}
	for _, it := range items {
		id, _ := uuid.Parse(it["id"].(string))
		if id == expired {
			t.Errorf("expired request listed: %v", it)
		}
		for _, bid := range idsB {
			if id == bid {
				t.Fatalf("A's inbox lists B's request %v", it)
			}
		}
		kind := it["kind"].(string)
		if idsA[kind] != id {
			t.Errorf("unexpected item %v", it)
			continue
		}
		seen[kind] = true
		links := it["links"].(map[string]any)
		if !strings.HasSuffix(links["approve"].(string), id.String()+"/approve") || !strings.HasSuffix(links["reject"].(string), id.String()+"/reject") {
			t.Errorf("%s links: %v", kind, links)
		}
		if it["requested_by"] != a.author.String() || it["requested_at"] == nil {
			t.Errorf("%s requester: %v", kind, it)
		}
		if (kind == services.ApprovalKindPendingChange || kind == services.ApprovalKindAuditChange || kind == services.ApprovalKindHistoryChange) && it["expires_at"] == nil {
			t.Errorf("%s has no expiry: %v", kind, it)
		}
	}
	for _, k := range services.ApprovalKinds() {
		if !seen[k] {
			t.Errorf("kind %s missing from the inbox", k)
		}
	}
	// B sees its own seven, none of A's.
	if got := w5List(t, e, w5Base+"/approvals", tokB); len(got) != len(idsB) {
		t.Errorf("B's inbox has %d items, want %d", len(got), len(idsB))
	}
	if got := w5List(t, e, w5Base+"/approvals?kind=audit_change", tokA); len(got) != 1 {
		t.Errorf("kind filter: %d items", len(got))
	}
	if code, out := e.call("GET", w5Base+"/approvals?kind=bogus", tokA, nil); code != http.StatusBadRequest {
		t.Errorf("bad kind: %d %v", code, out)
	}
	// B acting on A's requests: 404 on every kind's own route.
	for _, it := range items {
		links := it["links"].(map[string]any)
		if code, out := e.call("POST", links["approve"].(string), tokB, map[string]any{"reason": "x"}); code != http.StatusNotFound {
			t.Errorf("B approving A's %s: %d %v", it["kind"], code, out)
		}
	}
	// A reader without governance:read cannot list.
	if code, _ := e.call("GET", w5Base+"/approvals", e.api.token(a.ws, a.author, a.authorMember, "discovery:read"), nil); code != http.StatusForbidden {
		t.Errorf("inbox without governance:read: %d", code)
	}
}

// Break-glass changes of every kind are listed for review; the worker raises
// one governance.review_overdue event and one operator alert per overdue
// item, once; a second person reviews each kind through the shared route;
// the requester and another workspace cannot.
func TestBreakGlassReviewsOverdueWorkerAndSharedReview(t *testing.T) {
	e := agSetup(t)
	a, b := e.gov("w5-review-a"), e.gov("w5-review-b")
	e.grant(a, a.approver, "governance:approve")
	now := time.Now().UTC()
	overdue := w5Seed(t, e.db, a.ws, a.author, true, now.Add(-2*time.Hour))
	notDue := uuid.New()
	p3exec(t, e.db, `INSERT INTO pending_change (id, workspace_id, kind, target_ref, reason, state, requested_by, expires_at, applied_at, break_glass, review_due_at)
		VALUES (?, ?, 'agent_gateway.runtime', 'agent_gateway:y', 'loosen', 'applied', ?, now(), now(), true, now() + interval '20 hours')`, notDue, a.ws, a.author)

	approverTok := e.api.token(a.ws, a.approver, w5Membership(t, e.db, a.ws, a.approver), w5Scopes)
	authorTok := e.api.token(a.ws, a.author, a.authorMember, w5Scopes)
	tokB := e.api.token(b.ws, b.author, b.authorMember, w5Scopes)

	all := w5List(t, e, w5Base+"/approvals/reviews", approverTok)
	if len(all) != len(overdue)+1 {
		t.Fatalf("reviews: %d items, want %d: %v", len(all), len(overdue)+1, all)
	}
	late := w5List(t, e, w5Base+"/approvals/reviews?overdue=true", approverTok)
	if len(late) != len(overdue) {
		t.Fatalf("overdue: %d items, want %d", len(late), len(overdue))
	}
	for _, it := range late {
		if it["overdue"] != true || !strings.Contains(it["links"].(map[string]any)["review"].(string), "/approvals/reviews/") {
			t.Errorf("overdue item: %v", it)
		}
	}
	if got := w5List(t, e, w5Base+"/approvals/reviews", tokB); len(got) != 0 {
		t.Fatalf("B sees A's reviews: %v", got)
	}

	// The worker: one event and one operator alert per overdue item, once.
	ctx := context.Background()
	raised, err := services.RaiseOverdueReviews(ctx, e.db, a.ws, now)
	if err != nil || len(raised) != len(overdue) {
		t.Fatalf("raise: %d %v", len(raised), err)
	}
	if again, err := services.RaiseOverdueReviews(ctx, e.db, a.ws, now.Add(time.Hour)); err != nil || len(again) != 0 {
		t.Fatalf("raised twice: %d %v", len(again), err)
	}
	if rb, err := services.RaiseOverdueReviews(ctx, e.db, b.ws, now); err != nil || len(rb) != 0 {
		t.Fatalf("B raised A's items: %d %v", len(rb), err)
	}
	var events int64
	e.db.Raw(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = ?`, a.ws, services.GovEventReviewOverdue).Scan(&events)
	kinds := map[string]bool{}
	var payloadKinds []string
	e.db.Raw(`SELECT payload->>'kind' FROM iga_gov_event WHERE workspace_id = ? AND event = ?`, a.ws, services.GovEventReviewOverdue).Scan(&payloadKinds)
	for _, k := range payloadKinds {
		kinds[k] = true
	}
	if events != int64(len(overdue)) || len(kinds) != len(services.ApprovalKinds()) {
		t.Fatalf("overdue events: %d over kinds %v", events, kinds)
	}
	var alerts int64
	e.db.Raw(`SELECT count(*) FROM operator_alert WHERE workspace_id = ? AND user_id = ? AND metric = 'review_overdue'`, a.ws, a.author.String()).Scan(&alerts)
	if alerts != 1 {
		t.Fatalf("operator alerts: %d", alerts)
	}

	// The shared review route: requester refused, B 404, second person once.
	for _, kind := range services.ApprovalKinds() {
		path := w5Base + "/approvals/reviews/" + kind + "/" + overdue[kind].String()
		if code, out := e.call("POST", path, authorTok, map[string]any{"note": "mine"}); code != http.StatusForbidden || w5Code(out) != services.GovCodeSelfApproval {
			t.Errorf("%s: requester reviewing: %d %v", kind, code, out)
		}
		if code, out := e.call("POST", path, tokB, map[string]any{"note": "x"}); code != http.StatusNotFound {
			t.Errorf("%s: B reviewing A's: %d %v", kind, code, out)
		}
		if code, out := e.call("POST", path, approverTok, map[string]any{"note": "checked"}); code != http.StatusOK {
			t.Errorf("%s: second person reviewing: %d %v", kind, code, out)
		}
		if code, _ := e.call("POST", path, approverTok, map[string]any{"note": "again"}); code != http.StatusConflict {
			t.Errorf("%s: reviewed twice: %d", kind, code)
		}
	}
	if code, _ := e.call("POST", w5Base+"/approvals/reviews/bogus/"+notDue.String(), approverTok, nil); code != http.StatusNotFound {
		t.Errorf("unknown kind: %d", code)
	}
	left := w5List(t, e, w5Base+"/approvals/reviews", approverTok)
	if len(left) != 1 || left[0]["id"] != notDue.String() {
		t.Fatalf("after reviews: %v", left)
	}
}

// An automation identity performs tier-0/1 actions only: every tier-2/3
// route refuses it (approving, reviewing, requesting a loosening, suspending
// an operator), and the second-person rule refuses it even where it
// reaches a service another way; a person with the same rights is admitted.
func TestAutomationIdentityLimitedToTierOne(t *testing.T) {
	e := agSetup(t)
	a := e.gov("w5-auto-a")
	e.grant(a, a.approver, "governance:approve")
	ids := w5Seed(t, e.db, a.ws, a.author, false, time.Time{})
	m := w5Membership(t, e.db, a.ws, a.approver)
	bot := w5AutomationToken(t, a.ws, a.approver, m, w5Scopes)
	person := e.api.token(a.ws, a.approver, m, w5Scopes)

	refused := []struct{ method, path string }{
		{"POST", w5Base + "/pending-changes/" + ids[services.ApprovalKindPendingChange].String() + "/approve"},
		{"POST", w5Base + "/agent-changes/" + ids[services.ApprovalKindAgentChange].String() + "/approve"},
		{"POST", w5Base + "/audit/changes/" + ids[services.ApprovalKindAuditChange].String() + "/approve"},
		{"POST", w5Base + "/history-approvals/" + ids[services.ApprovalKindHistoryChange].String() + "/approve"},
		{"POST", w5Base + "/coverage/declarations/" + ids[services.ApprovalKindCoverageDeclare].String() + "/approve"},
		{"POST", w5Base + "/agent-runtime/suppressions/" + ids[services.ApprovalKindSuppression].String() + "/approve"},
		{"POST", w5Base + "/agent-runtime/alert-settings/versions/" + ids[services.ApprovalKindRuleVersion].String() + "/approve"},
		{"POST", w5Base + "/approvals/reviews/pending_change/" + ids[services.ApprovalKindPendingChange].String()},
		{"POST", w5Base + "/agent-runtime/suppressions"},
		{"POST", w5Base + "/exports"},
		{"POST", "/authsec/admin/operators/" + a.author.String() + "/suspend"},
	}
	for _, r := range refused {
		if code, out := e.call(r.method, r.path, bot, map[string]any{"reason": "playbook"}); code != http.StatusForbidden || w5Code(out) != services.GovCodeAutomationTier {
			t.Errorf("automation %s %s: %d %v", r.method, r.path, code, out)
		}
	}
	// Tier 0/1 stays open to it: opening a case, listing the inbox.
	if code, out := e.call("POST", w5Base+"/agent-runtime/cases", bot, map[string]any{"title": "triage", "severity": "low"}); code == http.StatusForbidden {
		t.Errorf("automation opening a case: %d %v", code, out)
	}
	if code, out := e.call("GET", w5Base+"/approvals", bot, nil); code != http.StatusOK {
		t.Errorf("automation reading the inbox: %d %v", code, out)
	}
	// The same user as a person approves.
	if code, out := e.call("POST", w5Base+"/agent-changes/"+ids[services.ApprovalKindAgentChange].String()+"/reject", person, map[string]any{"reason": "no"}); code != http.StatusOK {
		t.Errorf("person deciding: %d %v", code, out)
	}
	// Defence in depth: the service refuses an automation context directly.
	ctx := services.WithGovActorAutomation(context.Background(), true)
	if _, _, err := services.NewPendingChangeService(e.db).Approve(ctx, a.ws, ids[services.ApprovalKindPendingChange], a.approver); err == nil ||
		!strings.Contains(err.Error(), "automation") {
		t.Errorf("service approve by automation: %v", err)
	}
	// A stop by automation names an open case of the workspace.
	if err := services.CheckStopCase(ctx, e.db, a.ws, nil); err == nil {
		t.Error("automation stop without a case accepted")
	}
	other := uuid.New()
	if err := services.CheckStopCase(ctx, e.db, a.ws, &other); err == nil || !strings.Contains(strings.ToLower(err.Error()), "not found") {
		t.Errorf("unknown case: %v", err)
	}
	open, closed := uuid.New(), uuid.New()
	p3exec(t, e.db, `INSERT INTO agent_case (id, workspace_id, number, title, severity, opened_by) VALUES (?, ?, 9001, 'c', 'low', 'system')`, open, a.ws)
	p3exec(t, e.db, `INSERT INTO agent_case (id, workspace_id, number, title, severity, opened_by, state, outcome, closed_at, closed_by)
		VALUES (?, ?, 9002, 'c', 'low', 'system', 'closed', 'benign', now(), ?)`, closed, a.ws, a.author)
	if err := services.CheckStopCase(ctx, e.db, a.ws, &open); err != nil {
		t.Errorf("open case: %v", err)
	}
	if err := services.CheckStopCase(ctx, e.db, a.ws, &closed); err == nil {
		t.Error("closed case accepted")
	}
	b := e.gov("w5-auto-b")
	if err := services.CheckStopCase(ctx, e.db, b.ws, &open); err == nil {
		t.Error("B named A's case")
	}
}

// The subject of an open case never approves a request about it: a
// suppression of the alert identity of a case whose IAM user is the
// approver is refused until the case is closed.
func TestCaseSubjectCannotApprove(t *testing.T) {
	e := agSetup(t)
	a := e.gov("w5-subject-a")
	e.grant(a, a.approver, "governance:approve")
	var email string
	e.db.Raw(`SELECT email FROM users WHERE id = ?`, a.approver).Scan(&email)
	identity, alert, kase := uuid.New(), uuid.New(), uuid.New()
	p3exec(t, e.db, `INSERT INTO cloud_identity (id, workspace_id, connector_id, kind, native_id, name) VALUES (?, ?, ?, 'iam_user', ?, ?)`,
		identity, a.ws, a.conn, "arn:aws:iam::111111111111:user/"+identity.String(), strings.Split(email, "@")[0])
	p3exec(t, e.db, `INSERT INTO agent_alert (id, workspace_id, connector_id, identity_id, subject_label, detection, severity, title, dedupe_key, first_seen, last_seen)
		VALUES (?, ?, ?, ?, 'agent', 'D5', 'medium', 'refused calls', ?, now(), now())`, alert, a.ws, a.conn, identity, "w5:"+alert.String())
	p3exec(t, e.db, `INSERT INTO agent_case (id, workspace_id, number, title, severity, opened_by) VALUES (?, ?, 9101, 'iam user', 'medium', 'system')`, kase, a.ws)
	p3exec(t, e.db, `INSERT INTO agent_case_alert (workspace_id, case_id, alert_id, added_by) VALUES (?, ?, ?, 'system')`, a.ws, kase, alert)
	sup := uuid.New()
	p3exec(t, e.db, `INSERT INTO agent_alert_suppression (id, workspace_id, identity_id, detection, reason, duration_days, state, requested_by)
		VALUES (?, ?, ?, 'D5', 'noisy', 30, 'proposed', ?)`, sup, a.ws, identity, a.author)

	tok := e.api.token(a.ws, a.approver, w5Membership(t, e.db, a.ws, a.approver), w5Scopes)
	path := w5Base + "/agent-runtime/suppressions/" + sup.String() + "/approve"
	if code, out := e.call("POST", path, tok, map[string]any{"reason": "fine"}); code != http.StatusForbidden || w5Code(out) != services.GovCodeCaseSubject {
		t.Fatalf("case subject approving: %d %v", code, out)
	}
	// A directory record linked to the user also makes them the subject.
	var subject bool
	err := e.db.Transaction(func(tx *gorm.DB) error {
		var err error
		subject, err = services.IsCaseSubject(tx, a.ws, a.approver, []uuid.UUID{kase}, nil)
		return err
	})
	if err != nil || !subject {
		t.Fatalf("subject by e-mail local part: %v %v", subject, err)
	}
	p3exec(t, e.db, `UPDATE agent_case SET state = 'closed', outcome = 'benign', closed_at = now(), closed_by = ? WHERE id = ?`, a.author, kase)
	if code, out := e.call("POST", path, tok, map[string]any{"reason": "fine"}); code != http.StatusOK {
		t.Fatalf("approving once the case is closed: %d %v", code, out)
	}
}

// governance:remediate is in the catalog and migration 210 binds it to every
// workspace admin role; a tier-4 action needs it.
func TestRemediateRightForAdmins(t *testing.T) {
	e := agSetup(t)
	a := e.gov("w5-remediate-a")
	var n int64
	e.db.Raw(`SELECT count(*) FROM permissions WHERE workspace_id IS NULL AND resource = 'governance' AND action = 'remediate'`).Scan(&n)
	if n != 1 {
		t.Fatalf("catalog has %d governance:remediate rows", n)
	}
	admin := uuid.New()
	p3exec(t, e.db, `INSERT INTO roles (id, name, workspace_id) VALUES (?, 'admin', ?)`, admin, a.ws)
	t.Cleanup(func() {
		e.db.Exec(`DELETE FROM role_permissions WHERE role_id = ?`, admin)
		e.db.Exec(`DELETE FROM roles WHERE id = ?`, admin)
	})
	p3exec(t, e.db, `UPDATE workspace_memberships SET role_id = ? WHERE workspace_id = ? AND user_id = ?`, admin, a.ws, a.approver)
	raw, err := os.ReadFile("../../migrations/master/210_governance_remediate_right.sql")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.db.Exec(string(raw)).Error; err != nil {
		t.Fatalf("apply 210: %v", err)
	}
	if err := e.db.Exec(string(raw)).Error; err != nil {
		t.Fatalf("210 again (idempotent): %v", err)
	}
	var holds bool
	if err := e.db.Transaction(func(tx *gorm.DB) error {
		var err error
		holds, err = services.WorkspaceUserHoldsPermission(tx, a.ws, a.approver, "governance", "remediate")
		return err
	}); err != nil || !holds {
		t.Fatalf("admin holds governance:remediate: %v %v", holds, err)
	}
	if a, ok := services.GovActionFor(services.GovActionRemediationApply); !ok || a.Tier != services.GovTier4 {
		t.Fatalf("remediation tier: %+v", a)
	}
}

// W7's lowering now has break-glass: the workspace's only approver lowers a
// classification alone, it is applied, marked and due a review; with a
// second approver it waits.
func TestAgentChangeBreakGlass(t *testing.T) {
	e := agSetup(t)
	a := e.gov("w5-w7bg-a")
	e.grant(a, a.author, "governance:approve")
	res := uuid.New()
	p3exec(t, e.db, `INSERT INTO cloud_resource (id, workspace_id, connector_id, kind, native_id, name) VALUES (?, ?, ?, 's3_bucket', ?, 'pii')`,
		res, a.ws, a.conn, "arn:aws:s3:::w5-"+res.String())
	svc := services.NewResourceClassificationService(e.db)
	ctx := context.Background()
	yes, no := true, false
	if _, err := svc.Set(ctx, a.ws, res, a.author, services.ResourceClassificationRequest{CrownJewel: &yes, Reason: "records"}); err != nil {
		t.Fatal(err)
	}
	out, err := svc.Set(ctx, a.ws, res, a.author, services.ResourceClassificationRequest{CrownJewel: &no, Reason: "archived"})
	if err != nil || out.PendingChange == nil || !out.PendingChange.BreakGlass || out.PendingChange.State != "applied" ||
		out.PendingChange.ReviewDueAt == nil || out.Applied == nil || out.Applied.CrownJewel {
		t.Fatalf("break-glass lowering: %+v %v", out, err)
	}
	reviews, err := services.NewApprovalsService(e.db).Reviews(ctx, a.ws, services.ApprovalKindAgentChange, false)
	if err != nil || len(reviews) != 1 || reviews[0].ID != out.PendingChange.ID {
		t.Fatalf("break-glass lowering not due a review: %v %v", reviews, err)
	}
	// A second approver: the next lowering waits.
	e.grant(a, a.approver, "governance:approve")
	if _, err := svc.Set(ctx, a.ws, res, a.author, services.ResourceClassificationRequest{CrownJewel: &yes, Reason: "records"}); err != nil {
		t.Fatal(err)
	}
	out, err = svc.Set(ctx, a.ws, res, a.author, services.ResourceClassificationRequest{CrownJewel: &no, Reason: "archived"})
	if err != nil || out.PendingChange == nil || out.PendingChange.BreakGlass || out.PendingChange.State != "pending" {
		t.Fatalf("lowering with a second approver: %+v %v", out, err)
	}
}
