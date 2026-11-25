package integration

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentruntime"
)

// SecOps F6 (versioned detection rules, tier 3), F8 (alert lifecycle) and
// P6 (alert suppressions), over HTTP through the production route table:
// loosening needs a second person holding governance:approve (never the
// requester), the workspace's only approver applies alone as break-glass
// with a review due, a suppression never silences a succeeded harmful
// outcome and keeps alerts out of SIEM/Slack, and workspace B gets 404 for
// every one of workspace A's rows.

// arGrantApprove gives user's membership role governance:approve.
func arGrantApprove(t *testing.T, db *gorm.DB, ws, user uuid.UUID) {
	t.Helper()
	p3exec(t, db, `INSERT INTO role_permissions (role_id, permission_id)
		SELECT m.role_id, p.id FROM workspace_memberships m, permissions p
		 WHERE m.workspace_id = ? AND m.user_id = ? AND p.workspace_id IS NULL AND p.resource = 'governance' AND p.action = 'approve'
		ON CONFLICT DO NOTHING`, ws, user)
}

func arCount(t *testing.T, db *gorm.DB, q string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := db.Raw(q, args...).Scan(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

// arDenials is n refused calls by role starting at from, one per 10 s.
func arDenials(prefix, role string, from time.Time, n int) []agentruntime.Event {
	var out []agentruntime.Event
	for i := 0; i < n; i++ {
		e := arEvent(fmt.Sprintf("%s-%d", prefix, i), role, "s3.amazonaws.com", "GetObject", from.Add(time.Duration(i)*10*time.Second))
		e.ErrorCode, e.AuthorizationDenied = "AccessDenied", true
		out = append(out, e)
	}
	return out
}

const arAll = "governance:read governance:enforce governance:approve"

func TestAgentAlertRuleVersionsTier3(t *testing.T) {
	db := igaDB(t)
	a := p3NewGov(t, db, "ar-rules-a")
	b := p3NewGov(t, db, "ar-rules-b")
	p3Audit(t, db, a.ws, b.ws)
	api := p3NewOwnersAPI(t, db)
	arGrantApprove(t, db, a.ws, a.author)
	arGrantApprove(t, db, a.ws, a.approver)
	other, otherMember := a.member("other-"+a.ws.String()[:8]+"@p3own.test", "Oz Other", "active")
	tokAuthor := api.token(a.ws, a.author, a.authorMember, arAll)
	tokApprover := api.token(a.ws, a.approver, a.membershipOf(a.approver), arAll)
	// The token claims governance:approve; the database does not grant it.
	tokOther := api.token(a.ws, other, otherMember, arAll)
	tokB := api.token(b.ws, b.author, b.authorMember, arAll)

	// Tightening applies at once: version 1, with before and after logged.
	code, body := arCall(t, api, http.MethodPut, "/alert-settings", tokAuthor, map[string]any{
		"detections": map[string]any{"D5": map[string]any{"n": 5}}, "reason": "catch smaller bursts"})
	if code != http.StatusOK || dig(body, "change", "applied") != true || dig(body, "data", "version") != float64(1) ||
		dig(body, "data", "detections", "D5", "n") != float64(5) {
		t.Fatalf("tighten: %d %v", code, body)
	}
	v1 := digs(body, "change", "version", "id")
	if n := arCount(t, db, `SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = 'agent_alert.rules_applied'
	                         AND payload->'before'->'detections'->'D5'->>'n' = '10' AND payload->'after'->'detections'->'D5'->>'n' = '5'`, a.ws); n != 1 {
		t.Errorf("rules_applied with before/after: %d", n)
	}

	// Loosening is proposed; the active rules do not change.
	code, body = arCall(t, api, http.MethodPut, "/alert-settings", tokAuthor, map[string]any{
		"detections": map[string]any{"D1": map[string]any{"enabled": false}}, "reason": "noisy in staging"})
	if code != http.StatusAccepted || dig(body, "change", "pending") != true || dig(body, "data", "detections", "D1", "enabled") != true {
		t.Fatalf("loosen: %d %v", code, body)
	}
	v2 := digs(body, "change", "version", "id")
	if l := digl(body, "change", "loosening"); len(l) != 1 || l[0] != "D1: disabled" {
		t.Errorf("loosening %v", l)
	}
	if code, body := arCall(t, api, http.MethodGet, "/alert-settings", tokAuthor, nil); code != http.StatusOK ||
		digs(body, "data", "pending_version_id") != v2 || dig(body, "data", "detections", "D1", "enabled") != true {
		t.Fatalf("settings while pending: %d %v", code, body)
	}
	// One proposal at a time.
	if code, body := arCall(t, api, http.MethodPut, "/alert-settings", tokApprover, map[string]any{"slack_enabled": false}); code != http.StatusConflict ||
		digs(body, "error", "code") != "rule_change_pending" {
		t.Fatalf("second proposal: %d %v", code, body)
	}

	// Nobody approves their own; a member without governance:approve in the
	// database cannot; workspace B gets 404.
	if code, body := arCall(t, api, http.MethodPost, "/alert-settings/versions/"+v2+"/approve", tokAuthor, nil); code != http.StatusForbidden ||
		digs(body, "error", "code") != "self_approval" {
		t.Fatalf("self-approval: %d %v", code, body)
	}
	if code, body := arCall(t, api, http.MethodPost, "/alert-settings/versions/"+v2+"/approve", tokOther, nil); code != http.StatusForbidden ||
		digs(body, "error", "code") != "approver_not_authorized" {
		t.Fatalf("approval without governance:approve: %d %v", code, body)
	}
	for _, p := range []string{"/approve", "/reject"} {
		if code, body := arCall(t, api, http.MethodPost, "/alert-settings/versions/"+v2+p, tokB, map[string]any{"reason": "x"}); code != http.StatusNotFound {
			t.Errorf("B %s: %d %v", p, code, body)
		}
	}
	if code, body := arCall(t, api, http.MethodGet, "/alert-settings/versions", tokB, nil); code != http.StatusOK || len(digl(body, "data")) != 0 {
		t.Fatalf("B lists A's versions: %d %v", code, body)
	}

	// The second person approves: D1 is off, version 2 active, v1 superseded.
	if code, body := arCall(t, api, http.MethodPost, "/alert-settings/versions/"+v2+"/approve", tokApprover, map[string]any{"reason": "ok"}); code != http.StatusOK ||
		dig(body, "data", "detections", "D1", "enabled") != false || dig(body, "data", "version") != float64(2) {
		t.Fatalf("approve: %d %v", code, body)
	}
	code, body = arCall(t, api, http.MethodGet, "/alert-settings/versions", tokAuthor, nil)
	if code != http.StatusOK || len(digl(body, "data")) != 2 || digs(body, "data", 0, "state") != "active" || digs(body, "data", 1, "state") != "superseded" ||
		digs(body, "data", 1, "id") != v1 || digs(body, "data", 0, "approved_by") != a.approver.String() {
		t.Fatalf("versions: %d %v", code, body)
	}
	if n := arCount(t, db, `SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = 'agent_alert.rules_approved'
	                         AND payload->>'rule_version_id' = ? AND payload->'before'->'detections'->'D1'->>'enabled' = 'true'
	                         AND payload->'after'->'detections'->'D1'->>'enabled' = 'false'`, a.ws, v2); n != 1 {
		t.Errorf("rules_approved event: %d", n)
	}
	// B's rules are untouched.
	if code, body := arCall(t, api, http.MethodGet, "/alert-settings", tokB, nil); code != http.StatusOK ||
		dig(body, "data", "version") != float64(0) || dig(body, "data", "detections", "D1", "enabled") != true {
		t.Fatalf("B's settings: %d %v", code, body)
	}

	// Rejection needs a reason; the proposer may withdraw.
	code, body = arCall(t, api, http.MethodPut, "/alert-settings", tokAuthor, map[string]any{"retention_days": 30})
	if code != http.StatusAccepted {
		t.Fatalf("propose retention: %d %v", code, body)
	}
	v3 := digs(body, "change", "version", "id")
	if code, _ := arCall(t, api, http.MethodPost, "/alert-settings/versions/"+v3+"/reject", tokApprover, nil); code != http.StatusBadRequest {
		t.Errorf("reject without reason: %d", code)
	}
	if code, body := arCall(t, api, http.MethodPost, "/alert-settings/versions/"+v3+"/reject", tokAuthor, map[string]any{"reason": "withdrawn"}); code != http.StatusOK ||
		digs(body, "data", "state") != "rejected" {
		t.Fatalf("withdraw: %d %v", code, body)
	}
	if code, _ := arCall(t, api, http.MethodPost, "/alert-settings/versions/"+v3+"/approve", tokApprover, nil); code != http.StatusConflict {
		t.Errorf("approve a rejected version: %d", code)
	}

	// A tightening applied while a proposal waits supersedes the proposal.
	code, body = arCall(t, api, http.MethodPut, "/alert-settings", tokAuthor, map[string]any{"slack_enabled": false})
	if code != http.StatusAccepted {
		t.Fatalf("propose slack off: %d %v", code, body)
	}
	v4 := digs(body, "change", "version", "id")
	if code, body := arCall(t, api, http.MethodPut, "/alert-settings", tokApprover, map[string]any{
		"detections": map[string]any{"D1": map[string]any{"enabled": true}}}); code != http.StatusOK || dig(body, "change", "applied") != true {
		t.Fatalf("re-enable D1: %d %v", code, body)
	}
	if code, body := arCall(t, api, http.MethodPost, "/alert-settings/versions/"+v4+"/approve", tokApprover, nil); code != http.StatusConflict {
		t.Fatalf("approve a superseded proposal: %d %v", code, body)
	}
	if n := arCount(t, db, `SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = 'agent_alert.rules_superseded' AND payload->>'rule_version_id' = ?`, a.ws, v4); n != 1 {
		t.Errorf("rules_superseded events: %d", n)
	}
	// The database refuses self-approval too.
	if err := db.Exec(`UPDATE agent_detection_rule_version SET approved_by = proposed_by, approved_at = now() WHERE workspace_id = ? AND id = ?`, a.ws, v4).Error; err == nil {
		t.Error("the table accepted approved_by = proposed_by")
	}
	p3WaitAudit(t, db, a.ws, http.MethodPost, "/api/iga/v1/agent-runtime/alert-settings/versions/"+v2+"/approve")
}

func TestAgentAlertBreakGlassSoleApprover(t *testing.T) {
	db := igaDB(t)
	c := p3NewGov(t, db, "ar-breakglass")
	p3Audit(t, db, c.ws)
	api := p3NewOwnersAPI(t, db)
	r := arSetup(t, db)
	arGrantApprove(t, db, c.ws, c.author) // the only holder
	tok := api.token(c.ws, c.author, c.authorMember, arAll)
	start := time.Now()

	code, body := arCall(t, api, http.MethodPut, "/alert-settings", tok, map[string]any{
		"detections": map[string]any{"D6": map[string]any{"enabled": false}}})
	if code != http.StatusOK || dig(body, "change", "break_glass") != true || dig(body, "data", "detections", "D6", "enabled") != false {
		t.Fatalf("break-glass rule change: %d %v", code, body)
	}
	due, err := time.Parse(time.RFC3339Nano, digs(body, "change", "version", "review_due_at"))
	if err != nil || due.Sub(start) < 23*time.Hour || due.Sub(start) > 25*time.Hour {
		t.Fatalf("review_due_at %v %v", due, err)
	}
	if n := arCount(t, db, `SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = 'agent_alert.rules_break_glass'`, c.ws); n != 1 {
		t.Errorf("rules_break_glass events: %d", n)
	}

	// A suppression by the sole approver is in force at once, flagged.
	const role = "arn:aws:iam::111111111111:role/bg-agent"
	id := uuid.New()
	r.set(c.ws, role, agentruntime.Subject{IdentityID: id, ConnectorID: c.conn, Label: agentruntime.LabelAgent, Name: "bg-agent"})
	if err := agentruntime.Dispatch(context.Background(), c.ws, c.conn, arDenials("bg", role, time.Now().UTC().Add(-30*time.Minute), 10)); err != nil {
		t.Fatal(err)
	}
	code, body = arCall(t, api, http.MethodPost, "/suppressions", tok, map[string]any{"identity_id": id, "detection": "D5", "reason": "load test", "days": 7})
	if code != http.StatusCreated || dig(body, "data", "break_glass") != true || digs(body, "data", "suppression", "state") != "active" ||
		digs(body, "data", "suppression", "review_due_at") == "" {
		t.Fatalf("break-glass suppression: %d %v", code, body)
	}
	if n := arCount(t, db, `SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = 'agent_alert.suppression_break_glass'`, c.ws); n != 1 {
		t.Errorf("suppression_break_glass events: %d", n)
	}
}

func TestAgentAlertLifecycleReopenOutcomes(t *testing.T) {
	db := igaDB(t)
	a := p3NewGov(t, db, "ar-life-a")
	b := p3NewGov(t, db, "ar-life-b")
	p3Audit(t, db, a.ws, b.ws)
	api := p3NewOwnersAPI(t, db)
	r := arSetup(t, db)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	const role = "arn:aws:iam::111111111111:role/life-agent"
	id := uuid.New()
	r.set(a.ws, role, agentruntime.Subject{IdentityID: id, ConnectorID: a.conn, Label: agentruntime.LabelAgent, Name: "life-agent"})
	if err := agentruntime.Dispatch(ctx, a.ws, a.conn, []agentruntime.Event{
		arEvent("life-1", role, "iam.amazonaws.com", "CreateAccessKey", now.Add(-50*time.Minute))}); err != nil {
		t.Fatal(err)
	}
	as := arAlerts(t, db, a.ws)
	if len(as) != 1 {
		t.Fatalf("alerts %+v", as)
	}
	aID := as[0].ID.String()
	tokAuthor := api.token(a.ws, a.author, a.authorMember, arAll)
	tokApprover := api.token(a.ws, a.approver, a.membershipOf(a.approver), arAll)
	tokB := api.token(b.ws, b.author, b.authorMember, arAll)

	if code, body := arCall(t, api, http.MethodPost, "/alerts/"+aID+"/acknowledge", tokAuthor, map[string]any{"reason": "looking"}); code != http.StatusOK ||
		digs(body, "data", "acknowledged_by") != a.author.String() {
		t.Fatalf("acknowledge: %d %v", code, body)
	}
	// The outcome is required and must be a code.
	for _, b := range []map[string]any{{"reason": "done"}, {"outcome": "fixed"}} {
		if code, body := arCall(t, api, http.MethodPost, "/alerts/"+aID+"/resolve", tokApprover, b); code != http.StatusBadRequest {
			t.Errorf("resolve %v: %d %v", b, code, body)
		}
	}
	code, body := arCall(t, api, http.MethodPost, "/alerts/"+aID+"/resolve", tokApprover, map[string]any{"outcome": "false_positive"})
	if code != http.StatusOK || digs(body, "data", "state") != "resolved" || digs(body, "data", "outcome") != "false_positive" ||
		digs(body, "data", "resolved_by") != a.approver.String() || digs(body, "data", "acknowledged_by") != a.author.String() {
		t.Fatalf("resolve: %d %v", code, body)
	}
	// Reopen: only from resolved, with a reason; workspace B gets 404.
	if code, _ := arCall(t, api, http.MethodPost, "/alerts/"+aID+"/reopen", tokAuthor, nil); code != http.StatusBadRequest {
		t.Errorf("reopen without reason: %d", code)
	}
	if code, _ := arCall(t, api, http.MethodPost, "/alerts/"+aID+"/reopen", tokB, map[string]any{"reason": "mine?"}); code != http.StatusNotFound {
		t.Errorf("B reopens: %d", code)
	}
	code, body = arCall(t, api, http.MethodPost, "/alerts/"+aID+"/reopen", tokAuthor, map[string]any{"reason": "key used again"})
	if code != http.StatusOK || digs(body, "data", "state") != "reopened" || digs(body, "data", "reopened_by") != a.author.String() ||
		dig(body, "data", "reopen_count") != float64(1) || dig(body, "data", "outcome") != nil {
		t.Fatalf("reopen: %d %v", code, body)
	}
	if code, _ := arCall(t, api, http.MethodPost, "/alerts/"+aID+"/reopen", tokAuthor, map[string]any{"reason": "again"}); code != http.StatusConflict {
		t.Errorf("reopen a reopened alert: %d", code)
	}
	// A reopened alert is extended like an open one.
	if err := agentruntime.Dispatch(ctx, a.ws, a.conn, []agentruntime.Event{
		arEvent("life-2", role, "iam.amazonaws.com", "CreateAccessKey", now.Add(-40*time.Minute))}); err != nil {
		t.Fatal(err)
	}
	if got := arAlerts(t, db, a.ws); len(got) != 1 || got[0].EventCount != 2 || got[0].State != "reopened" {
		t.Fatalf("after reopen: %+v", got)
	}
	if code, body := arCall(t, api, http.MethodGet, "/alerts?state=reopened", tokAuthor, nil); code != http.StatusOK || len(digl(body, "data")) != 1 {
		t.Fatalf("list reopened: %d %v", code, body)
	}
	if code, _ := arCall(t, api, http.MethodPost, "/alerts/"+aID+"/resolve", tokAuthor, map[string]any{"outcome": "duplicate"}); code != http.StatusOK {
		t.Fatalf("resolve again: %d", code)
	}
	code, body = arCall(t, api, http.MethodGet, "/alerts/"+aID, tokAuthor, nil)
	tr := digl(body, "data", "transitions")
	if code != http.StatusOK || len(tr) != 4 || digs(tr[0], "to_state") != "acknowledged" || digs(tr[1], "outcome") != "false_positive" ||
		digs(tr[1], "actor_id") != a.approver.String() || digs(tr[2], "to_state") != "reopened" || digs(tr[3], "outcome") != "duplicate" {
		t.Fatalf("transitions: %d %v", code, tr)
	}
	for ev, want := range map[string]int64{"agent_alert.acknowledged": 1, "agent_alert.resolved": 2, "agent_alert.reopened": 1} {
		if n := arCount(t, db, `SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = ? AND payload->>'alert_id' = ?`, a.ws, ev, aID); n != want {
			t.Errorf("%s events: %d, want %d", ev, n, want)
		}
	}

	// Low severity: a workspace sets D2's severity to low (loosening:
	// approved by the second person); the next alert is stored low.
	arGrantApprove(t, db, a.ws, a.approver)
	code, body = arCall(t, api, http.MethodPut, "/alert-settings", tokAuthor, map[string]any{
		"detections": map[string]any{"D2": map[string]any{"severity": "low"}}})
	if code != http.StatusAccepted {
		t.Fatalf("propose low: %d %v", code, body)
	}
	if code, body := arCall(t, api, http.MethodPost, "/alert-settings/versions/"+digs(body, "change", "version", "id")+"/approve", tokApprover, nil); code != http.StatusOK {
		t.Fatalf("approve low: %d %v", code, body)
	}
	if err := agentruntime.Dispatch(ctx, a.ws, a.conn, []agentruntime.Event{
		arEvent("life-3", role, "iam.amazonaws.com", "CreateAccessKey", now.Add(-time.Minute))}); err != nil {
		t.Fatal(err)
	}
	if code, body := arCall(t, api, http.MethodGet, "/alerts?severity=low", tokAuthor, nil); code != http.StatusOK || len(digl(body, "data")) != 1 ||
		digs(body, "data", 0, "severity") != "low" {
		t.Fatalf("low alert: %d %v", code, body)
	}
}

func TestAgentAlertSuppressions(t *testing.T) {
	db := igaDB(t)
	a := p3NewGov(t, db, "ar-sup-a")
	b := p3NewGov(t, db, "ar-sup-b")
	p3Audit(t, db, a.ws, b.ws)
	api := p3NewOwnersAPI(t, db)
	r := arSetup(t, db)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	arGrantApprove(t, db, a.ws, a.author)
	arGrantApprove(t, db, a.ws, a.approver)
	// A SIEM endpoint, so a delivered alert queues a delivery row.
	p3exec(t, db, `INSERT INTO agent_alert_siem_endpoint (workspace_id, url, created_by) VALUES (?, 'https://siem.example/hook', ?)`, a.ws, a.author)
	const role = "arn:aws:iam::111111111111:role/sup-agent"
	id := uuid.New()
	r.set(a.ws, role, agentruntime.Subject{IdentityID: id, ConnectorID: a.conn, Label: agentruntime.LabelAgent, Name: "sup-agent"})
	if err := agentruntime.Dispatch(ctx, a.ws, a.conn, arDenials("sup1", role, now.Add(-3*time.Hour), 10)); err != nil {
		t.Fatal(err)
	}
	first := arAlerts(t, db, a.ws)
	if len(first) != 1 || first[0].Detection != "D5" {
		t.Fatalf("first D5 alert: %+v", first)
	}
	if n := arCount(t, db, `SELECT count(*) FROM agent_alert_delivery WHERE workspace_id = ? AND alert_id = ?`, a.ws, first[0].ID); n != 1 {
		t.Fatalf("deliveries of an unsuppressed alert: %d", n)
	}
	tokAuthor := api.token(a.ws, a.author, a.authorMember, arAll)
	tokApprover := api.token(a.ws, a.approver, a.membershipOf(a.approver), arAll)
	tokB := api.token(b.ws, b.author, b.authorMember, arAll)

	// Refused: a detection that records a succeeded harmful outcome, more
	// than 90 days, no reason; B cannot name A's identity.
	for _, c := range []struct {
		body map[string]any
		tok  string
		want int
		code string
	}{
		{map[string]any{"identity_id": id, "detection": "D1", "reason": "x"}, tokAuthor, http.StatusBadRequest, "suppression_not_allowed"},
		{map[string]any{"identity_id": id, "detection": "D7", "reason": "x"}, tokAuthor, http.StatusBadRequest, "suppression_not_allowed"},
		{map[string]any{"identity_id": id, "detection": "D5", "reason": "x", "days": 91}, tokAuthor, http.StatusBadRequest, "invalid_parameter"},
		{map[string]any{"identity_id": id, "detection": "D5"}, tokAuthor, http.StatusBadRequest, "invalid_parameter"},
		{map[string]any{"identity_id": id, "detection": "D5", "reason": "x"}, tokB, http.StatusNotFound, "not_found"},
	} {
		if code, body := arCall(t, api, http.MethodPost, "/suppressions", c.tok, c.body); code != c.want || digs(body, "error", "code") != c.code {
			t.Errorf("POST %v: %d %v, want %d %s", c.body, code, body, c.want, c.code)
		}
	}

	// Requested (tier 3), never approved by the requester, 404 for B.
	code, body := arCall(t, api, http.MethodPost, "/suppressions", tokAuthor, map[string]any{
		"identity_id": id, "detection": "D5", "reason": "scanner probes S3", "days": 30})
	if code != http.StatusAccepted || digs(body, "data", "suppression", "state") != "proposed" || dig(body, "data", "suppression", "renewals") != float64(0) {
		t.Fatalf("request: %d %v", code, body)
	}
	sID := digs(body, "data", "suppression", "id")
	if code, body := arCall(t, api, http.MethodPost, "/suppressions/"+sID+"/approve", tokAuthor, nil); code != http.StatusForbidden ||
		digs(body, "error", "code") != "self_approval" {
		t.Fatalf("self-approval: %d %v", code, body)
	}
	for _, p := range []string{"/approve", "/reject", "/renew", "/end", ""} {
		method := http.MethodPost
		if p == "" {
			method = http.MethodGet
		}
		if code, body := arCall(t, api, method, "/suppressions/"+sID+p, tokB, map[string]any{"reason": "x"}); code != http.StatusNotFound {
			t.Errorf("B %s %s: %d %v", method, p, code, body)
		}
	}
	if code, body := arCall(t, api, http.MethodGet, "/suppressions", tokB, nil); code != http.StatusOK || len(digl(body, "data")) != 0 {
		t.Fatalf("B lists A's suppressions: %d %v", code, body)
	}
	code, body = arCall(t, api, http.MethodPost, "/suppressions/"+sID+"/approve", tokApprover, nil)
	if code != http.StatusOK || digs(body, "data", "suppression", "state") != "active" {
		t.Fatalf("approve: %d %v", code, body)
	}
	starts, _ := time.Parse(time.RFC3339Nano, digs(body, "data", "suppression", "starts_at"))
	ends, _ := time.Parse(time.RFC3339Nano, digs(body, "data", "suppression", "ends_at"))
	if ends.Sub(starts) != 30*24*time.Hour {
		t.Fatalf("window %s .. %s", starts, ends)
	}

	// The next D5 burst is stored, suppressed, and never queued for delivery.
	if code, _ := arCall(t, api, http.MethodPost, "/alerts/"+first[0].ID.String()+"/resolve", tokAuthor, map[string]any{"outcome": "benign"}); code != http.StatusOK {
		t.Fatalf("resolve first: %d", code)
	}
	if err := agentruntime.Dispatch(ctx, a.ws, a.conn, arDenials("sup2", role, now.Add(-30*time.Minute), 10)); err != nil {
		t.Fatal(err)
	}
	all := arAlerts(t, db, a.ws)
	if len(all) != 2 {
		t.Fatalf("after the second burst: %+v", all)
	}
	second := all[1].ID
	if n := arCount(t, db, `SELECT count(*) FROM agent_alert WHERE workspace_id = ? AND id = ? AND suppressed_by = ?`, a.ws, second, sID); n != 1 {
		t.Fatal("the second alert is not marked suppressed_by the suppression")
	}
	if n := arCount(t, db, `SELECT count(*) FROM agent_alert_delivery WHERE workspace_id = ? AND alert_id = ?`, a.ws, second); n != 0 {
		t.Fatalf("a suppressed alert queued %d deliveries", n)
	}
	if code, body := arCall(t, api, http.MethodGet, "/alerts?suppressed=true", tokAuthor, nil); code != http.StatusOK || len(digl(body, "data")) != 1 ||
		digs(body, "data", 0, "id") != second.String() {
		t.Fatalf("list suppressed: %d %v", code, body)
	}

	// Never a succeeded harmful outcome: even a D1 suppression written past
	// the API does not silence a secret read that succeeded.
	p3exec(t, db, `INSERT INTO agent_alert_suppression (workspace_id, identity_id, detection, reason, duration_days, state, requested_by,
	                   approved_by, approved_at, starts_at, ends_at)
	               VALUES (?, ?, 'D1', 'forced', 30, 'active', ?, ?, now(), now() - interval '1 minute', now() + interval '1 day')`,
		a.ws, id, a.author, a.approver)
	if err := agentruntime.Dispatch(ctx, a.ws, a.conn, []agentruntime.Event{
		arEvent("sup-secret", role, "secretsmanager.amazonaws.com", "GetSecretValue", now.Add(-time.Minute))}); err != nil {
		t.Fatal(err)
	}
	if n := arCount(t, db, `SELECT count(*) FROM agent_alert WHERE workspace_id = ? AND detection = 'D1' AND suppressed_by IS NULL`, a.ws); n != 1 {
		t.Fatal("a succeeded secret read was suppressed")
	}
	if n := arCount(t, db, `SELECT count(*) FROM agent_alert_delivery d JOIN agent_alert x ON x.workspace_id = d.workspace_id AND x.id = d.alert_id
	                         WHERE d.workspace_id = ? AND x.detection = 'D1'`, a.ws); n != 1 {
		t.Fatalf("the secret read's deliveries: %d", n)
	}

	// A second request for an active scope is refused (renew instead).
	if code, body := arCall(t, api, http.MethodPost, "/suppressions", tokAuthor, map[string]any{"identity_id": id, "detection": "D5", "reason": "again"}); code != http.StatusConflict ||
		digs(body, "error", "code") != "suppression_exists" {
		t.Fatalf("duplicate: %d %v", code, body)
	}
	// Renewal: tier 3 again, counted per agent x rule, replaces the old one.
	code, body = arCall(t, api, http.MethodPost, "/suppressions/"+sID+"/renew", tokAuthor, map[string]any{"reason": "still probing", "days": 90})
	if code != http.StatusAccepted || dig(body, "data", "suppression", "renewals") != float64(1) || digs(body, "data", "suppression", "renewal_of") != sID {
		t.Fatalf("renew: %d %v", code, body)
	}
	rID := digs(body, "data", "suppression", "id")
	if code, body := arCall(t, api, http.MethodPost, "/suppressions/"+rID+"/approve", tokApprover, nil); code != http.StatusOK {
		t.Fatalf("approve renewal: %d %v", code, body)
	}
	if code, body := arCall(t, api, http.MethodGet, "/suppressions/"+sID, tokAuthor, nil); code != http.StatusOK || digs(body, "data", "state") != "ended" {
		t.Fatalf("renewed suppression: %d %v", code, body)
	}
	// End early (applies at once): later bursts are delivered again.
	if code, _ := arCall(t, api, http.MethodPost, "/suppressions/"+rID+"/end", tokAuthor, nil); code != http.StatusBadRequest {
		t.Errorf("end without reason: %d", code)
	}
	if code, body := arCall(t, api, http.MethodPost, "/suppressions/"+rID+"/end", tokAuthor, map[string]any{"reason": "fixed the scanner"}); code != http.StatusOK ||
		digs(body, "data", "state") != "ended" {
		t.Fatalf("end: %d %v", code, body)
	}
	if code, body := arCall(t, api, http.MethodPost, "/suppressions/"+rID+"/end", tokAuthor, map[string]any{"reason": "again"}); code != http.StatusConflict {
		t.Fatalf("end twice: %d %v", code, body)
	}
	// Rejection: the approver turns down a new request.
	code, body = arCall(t, api, http.MethodPost, "/suppressions", tokAuthor, map[string]any{"identity_id": id, "detection": "D8", "reason": "vpn"})
	if code != http.StatusAccepted || dig(body, "data", "suppression", "renewals") != float64(0) {
		t.Fatalf("request D8: %d %v", code, body)
	}
	if code, body := arCall(t, api, http.MethodPost, "/suppressions/"+digs(body, "data", "suppression", "id")+"/reject", tokApprover,
		map[string]any{"reason": "too broad"}); code != http.StatusOK || digs(body, "data", "state") != "rejected" {
		t.Fatalf("reject: %d %v", code, body)
	}
	for ev, want := range map[string]int64{"agent_alert.suppression_requested": 3, "agent_alert.suppression_approved": 2,
		"agent_alert.suppression_ended": 2, "agent_alert.suppression_rejected": 1} {
		if n := arCount(t, db, `SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = ?`, a.ws, ev); n != want {
			t.Errorf("%s: %d, want %d", ev, n, want)
		}
	}
	// The database caps a window at 90 days.
	if err := db.Exec(`UPDATE agent_alert_suppression SET ends_at = starts_at + interval '91 days' WHERE workspace_id = ? AND id = ?`, a.ws, rID).Error; err == nil ||
		!strings.Contains(err.Error(), "window") {
		t.Errorf("a 91-day window was stored: %v", err)
	}
	p3WaitAudit(t, db, a.ws, http.MethodPost, "/api/iga/v1/agent-runtime/suppressions/"+sID+"/approve")
}
