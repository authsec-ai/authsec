package integration

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/slackapp"
	"github.com/authsec-ai/authsec/services"
)

func p3sGrant(t *testing.T, db *gorm.DB, role uuid.UUID, action string) {
	t.Helper()
	p3exec(t, db, `INSERT INTO role_permissions (role_id, permission_id)
	               SELECT ?, id FROM permissions WHERE workspace_id IS NULL AND resource = 'governance' AND action = ?
	               ON CONFLICT DO NOTHING`, role, action)
}

// T3.14 install, settings and disconnect (§7.11, §10): the OAuth state is
// bound to the workspace, the member and the browser session that started
// the install (signed state + HttpOnly cookie); every refusal happens before
// the code is exchanged; the bot token goes to Vault and the team to
// workspace_slack_integration; one Slack team is bound to one workspace;
// settings and disconnect need governance:enforce; disconnect revokes the
// token, deletes it and the member links, and Slack stops reaching anyone.
//
// Safeguard (mutation-checked): the state binding (cookie nonce vs state).
func TestP3T314SlackInstallStateBinding(t *testing.T) {
	db := igaDB(t)
	gA := p3NewGov(t, db, "p3-t314-install-a")
	gB := p3NewGov(t, db, "p3-t314-install-b")
	gate := p3sGate(t, db)
	app := newP3sApp(t, db, gate)
	roleA, roleB := gA.roles[0], gB.roles[0] // the authors' roles
	p3sGrant(t, db, roleA, "enforce")
	p3sGrant(t, db, roleB, "enforce")
	tokA := p3sToken(t, gA.ws, gA.author, gA.authorMember, "governance:enforce governance:read")
	tokB := p3sToken(t, gB.ws, gB.author, gB.authorMember, "governance:enforce governance:read")
	app.fake.AddUser(slackapp.User{ID: "UAUTHA", TeamID: "TALPHA", Email: p3sEmail(t, db, gA.author), IsEmailConfirmed: true})
	app.fake.AddUser(slackapp.User{ID: "UAPPRA", TeamID: "TALPHA", Email: p3sEmail(t, db, gA.approver), IsEmailConfirmed: false})

	stateA, cookieA := app.startInstall(tokA)
	stateB, cookieB := app.startInstall(tokB)
	app.fake.AddInstall("code-a", p3sClientID, slackapp.OAuthResult{AccessToken: "xoxb-alpha", TeamID: "TALPHA", TeamName: "Alpha", Scope: slackapp.Scopes})
	refused := func(name, state string, cookie *http.Cookie, reason string) {
		t.Helper()
		code, body := app.callback(state, "code-a", cookie)
		if code != http.StatusForbidden || p3eErr(body) != services.SlackCodeStateInvalid || p3sDetail(body, "reason") != reason {
			t.Fatalf("%s: %d %v, want 403 slack_state_invalid %s", name, code, body, reason)
		}
	}
	refused("no session cookie", stateA, nil, "session_mismatch")
	refused("another browser session (workspace B install)", stateA, cookieB, "session_mismatch")
	refused("workspace B state with the A session", stateB, cookieA, "session_mismatch")
	i := strings.IndexByte(stateA, '.')
	refused("tampered state", stateA[:i-2]+"AA"+stateA[i:], cookieA, "state_signature")
	refused("no state", "", cookieA, "state_signature")
	// A well-formed state re-pointed at workspace B (its member), keeping A's
	// signature and A's session: only the signature stands in the way.
	{
		raw, err := base64.RawURLEncoding.DecodeString(stateA[:i])
		if err != nil {
			t.Fatal(err)
		}
		var st map[string]any
		if err := json.Unmarshal(raw, &st); err != nil {
			t.Fatal(err)
		}
		st["w"], st["u"], st["m"] = gB.ws.String(), gB.author.String(), gB.authorMember.String()
		forged, _ := json.Marshal(st)
		refused("state re-pointed at another workspace", base64.RawURLEncoding.EncodeToString(forged)+stateA[i:], cookieA, "state_signature")
	}
	app.svc.WithClock(func() time.Time { return time.Now().Add(11 * time.Minute) })
	refused("expired state", stateA, cookieA, "state_expired")
	app.svc.WithClock(time.Now)
	p3exec(t, db, `DELETE FROM role_permissions WHERE role_id = ?`, roleA)
	refused("member lost governance:enforce", stateA, cookieA, "permission_revoked")
	p3sGrant(t, db, roleA, "enforce")
	p3exec(t, db, `UPDATE workspace_memberships SET status = 'suspended' WHERE id = ?`, gA.authorMember)
	refused("member suspended", stateA, cookieA, "membership_not_active")
	p3exec(t, db, `UPDATE workspace_memberships SET status = 'active' WHERE id = ?`, gA.authorMember)
	if len(app.fake.Exchanges) != 0 {
		t.Fatalf("a refused callback exchanged the code: %v", app.fake.Exchanges)
	}

	code, body := app.callback(stateA, "code-a", cookieA)
	if code != http.StatusOK || digs(body, "data", "integration", "slack_team_id") != "TALPHA" {
		t.Fatalf("callback: %d %v", code, body)
	}
	if digs(body, "data", "integration", "bot_token_ref") != services.SlackBotTokenPath(gA.ws) || strings.Contains(string(p3rMustJSON(body)), "xoxb-") {
		t.Fatalf("install answer leaks or misplaces the token: %v", body)
	}
	if sec, err := app.vault.ReadSecret(services.SlackBotTokenPath(gA.ws)); err != nil || sec["token"] != "xoxb-alpha" {
		t.Fatalf("vault token %v %v", sec, err)
	}
	// Linked by verified email only: the approver's Slack email is unconfirmed.
	if n := p3sCount(t, db, `SELECT count(*) FROM slack_user_link WHERE workspace_id = ?`, gA.ws); n != 1 {
		t.Fatalf("%d links, want 1 (the unconfirmed email is not linked)", n)
	}
	if n := p3sCount(t, db, `SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = 'slack.installed' AND actor_id = ?`, gA.ws, gA.author.String()); n != 1 {
		t.Fatalf("%d install events", n)
	}
	if n := p3sCountEventually(t, db, 1, `SELECT count(*) FROM audit_events WHERE workspace_id = ? AND action = 'install' AND user_id = ?`, gA.ws.String(), gA.author.String()); n != 1 {
		t.Fatalf("%d install audit rows", n)
	}

	// The code is single use, and a team is bound to one workspace.
	if code, body = app.callback(stateA, "code-a", cookieA); code != http.StatusBadGateway {
		t.Fatalf("code reused: %d %v", code, body)
	}
	app.fake.AddInstall("code-b", p3sClientID, slackapp.OAuthResult{AccessToken: "xoxb-alpha-2", TeamID: "TALPHA", TeamName: "Alpha"})
	if code, body = app.callback(stateB, "code-b", cookieB); code != http.StatusConflict || p3eErr(body) != services.SlackCodeTeamBound {
		t.Fatalf("second workspace installs the same team: %d %v", code, body)
	}
	if _, err := app.vault.ReadSecret(services.SlackBotTokenPath(gB.ws)); err == nil {
		t.Fatal("a refused install stored a token")
	}

	// Settings.
	reader := p3sToken(t, gA.ws, gA.author, gA.authorMember, "governance:read")
	if w, body := app.do(http.MethodPut, "/settings", reader, map[string]any{"approvals_channel_id": "C123"}); w.Code != http.StatusForbidden {
		t.Fatalf("settings without governance:enforce: %d %v", w.Code, body)
	}
	if w, body := app.do(http.MethodPut, "/settings", tokA, map[string]any{"approvals_channel_id": "#general"}); w.Code != http.StatusBadRequest {
		t.Fatalf("bad channel id: %d %v", w.Code, body)
	}
	if w, body := app.do(http.MethodPut, "/settings", tokB, map[string]any{"approvals_channel_id": "C123ABC"}); w.Code != http.StatusConflict ||
		p3eErr(body) != services.SlackCodeNotConnected {
		t.Fatalf("settings of an unconnected workspace: %d %v", w.Code, body)
	}
	if w, body := app.do(http.MethodPut, "/settings", tokA, map[string]any{"approvals_channel_id": "C123ABC"}); w.Code != http.StatusOK ||
		digs(body, "data", "approvals_channel_id") != "C123ABC" {
		t.Fatalf("settings: %d %v", w.Code, body)
	}
	if st := services.SlackStatusForSettings(db, gA.ws); !st.Connected || st.ApprovalsChannelID != "C123ABC" || st.TeamName != "Alpha" || st.LinkedUsers != 1 {
		t.Fatalf("status %+v", st)
	}
	ch := services.NewSlackNotificationChannel(app.svc)
	if ok, err := ch.Reaches(db, gA.ws, gA.author); err != nil || !ok {
		t.Fatalf("Reaches before disconnect: %v %v", ok, err)
	}

	// The gate: off, every Slack route is 503 policy_unavailable.
	off := newP3sApp(t, db, services.NewPolicyGate(false, "", p3GraphOn(t, db)))
	if w, body := off.do(http.MethodGet, "/install", tokA, nil); w.Code != http.StatusServiceUnavailable || p3eErr(body) != "policy_unavailable" {
		t.Fatalf("gate off /install: %d %v", w.Code, body)
	}
	if code, body := off.post([]byte("payload={}"), "1", "v0=x"); code != http.StatusServiceUnavailable {
		t.Fatalf("gate off /interactions: %d %v", code, body)
	}

	// Disconnect.
	if w, body := app.do(http.MethodDelete, "", reader, nil); w.Code != http.StatusForbidden {
		t.Fatalf("disconnect without governance:enforce: %d %v", w.Code, body)
	}
	if w, body := app.do(http.MethodDelete, "", tokA, nil); w.Code != http.StatusOK {
		t.Fatalf("disconnect: %d %v", w.Code, body)
	}
	if n := p3sCount(t, db, `SELECT count(*) FROM workspace_slack_integration WHERE workspace_id = ? AND revoked_at IS NOT NULL`, gA.ws); n != 1 {
		t.Fatal("installation not revoked")
	}
	if n := p3sCount(t, db, `SELECT count(*) FROM slack_user_link WHERE workspace_id = ?`, gA.ws); n != 0 {
		t.Fatalf("%d links left after disconnect", n)
	}
	if _, err := app.vault.ReadSecret(services.SlackBotTokenPath(gA.ws)); err == nil {
		t.Fatal("bot token left in Vault")
	}
	if len(app.fake.Revoked) != 1 || app.fake.Revoked[0] != "xoxb-alpha" {
		t.Fatalf("auth.revoke calls %v", app.fake.Revoked)
	}
	if ok, _ := ch.Reaches(db, gA.ws, gA.author); ok {
		t.Fatal("Slack still reaches a member after disconnect")
	}
	for _, ev := range []string{"slack.settings_updated", "slack.disconnected"} {
		if n := p3sCount(t, db, `SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = ?`, gA.ws, ev); n != 1 {
			t.Fatalf("%d %s events", n, ev)
		}
	}
	if n := p3sCountEventually(t, db, 2, `SELECT count(*) FROM audit_events WHERE workspace_id = ? AND action IN ('update_settings','disconnect')`, gA.ws.String()); n != 2 {
		t.Fatalf("%d settings/disconnect audit rows", n)
	}
	if w, _ := app.do(http.MethodDelete, "", tokA, nil); w.Code != http.StatusNotFound {
		t.Fatalf("second disconnect: %d", w.Code)
	}
	// The team is free again: workspace B installs it.
	stateB2, cookieB2 := app.startInstall(tokB)
	app.fake.AddInstall("code-b2", p3sClientID, slackapp.OAuthResult{AccessToken: "xoxb-alpha-3", TeamID: "TALPHA", TeamName: "Alpha"})
	if code, body := app.callback(stateB2, "code-b2", cookieB2); code != http.StatusOK {
		t.Fatalf("install after disconnect elsewhere: %d %v", code, body)
	}
}
