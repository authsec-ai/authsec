package integration

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/slackapp"
	"github.com/authsec-ai/authsec/internal/slackapp/slacktest"
	"github.com/authsec-ai/authsec/services"
)

// T3.14 approval through Slack (SPEC-iga-phase3-policy.md §7.11, §7.12,
// §2.10, §9.3 S6, §10; L-11; A14; §14.1 step 5), end to end on the P3 lab:
// a real proposal compiled into a first-attachment plan (which carries
// unanalysed residuals), the Slack app installed through OAuth with members
// linked by verified email, the approval request delivered by the notify
// job to the (fake) approvals channel, and button clicks posted to
// /interactions.
//
// A14: forged signature, stale timestamp, replay, unlinked user and the
// author approving are each refused with the documented error, and none of
// them writes a decision. §14.1 step 5: with residuals Slack offers no
// Approve button and says why; the author's own attempt is refused.
//
// Safeguards (mutation-checked): signature verification; the timestamp
// window; the action_ts replay check; the SoD path (Approve's author
// check, reached from Slack).
func TestP3T314SlackApprovalA14(t *testing.T) {
	l := newP3aLab(t, "p3-t314-approve")
	app := newP3sApp(t, l.db, l.policy)
	admin := l.member("slackadmin", "enforce")
	stranger := l.member("stranger", "approve")
	// The author also holds governance:approve (an admin author): §2.10
	// refuses self-approval in code for every role.
	p3exec(t, l.db, `INSERT INTO role_permissions (role_id, permission_id)
	                 SELECT ?, id FROM permissions WHERE workspace_id IS NULL AND resource = 'governance' AND action = 'approve'`, l.author.role)
	const team, channel = "T314APPR", "C314APPROVALS"
	for id, m := range map[string]p3aMember{"UAPPROVER": l.approver, "UAUTHOR": l.author, "USECOND": l.second, "UADMIN": admin} {
		app.fake.AddUser(slackapp.User{ID: id, TeamID: team, Email: p3sEmail(t, l.db, m.user), IsEmailConfirmed: true})
	}
	// The stranger's Slack email is not their AuthSec email: no automatic link.
	app.fake.AddUser(slackapp.User{ID: "USTRANGER", TeamID: team, Email: "someone-else@elsewhere.test", IsEmailConfirmed: true})

	app.install(l.token(l.ws, admin, "governance:enforce"), team, "Acme")
	if w, body := app.do(http.MethodPut, "/settings", l.token(l.ws, admin, "governance:enforce"), map[string]any{"approvals_channel_id": channel}); w.Code != http.StatusOK {
		t.Fatalf("PUT /settings: %d %v", w.Code, body)
	}
	if n := l.count(`SELECT count(*) FROM slack_user_link WHERE workspace_id = ? AND linked_via = 'verified_email'`, l.ws); n != 4 {
		t.Fatalf("%d members linked by verified email, want 4", n)
	}

	// Two policies: A is approved through Slack, B rejected.
	l.role("SlackApprRole", "AROASLACKAPPR001", map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	l.role("SlackRejRole", "AROASLACKREJ0001", map[string]*time.Time{"s3": p3eTime(time.Hour), "sns": nil})
	l.publish()
	polA, _ := l.proposeTemplate("AROASLACKAPPR001")
	l.compile(polA, 1)
	polB, _ := l.proposeTemplate("AROASLACKREJ0001")
	l.compile(polB, 1)
	verA, verB := l.versionID(polA, 1), l.versionID(polB, 1)

	worker := p3NotifyWorker(l.db, &p3Outbox{}, &p3Outbox{})
	p3Drain(t, worker)
	posts := app.fake.PostsTo(channel)
	if len(posts) != 2 {
		t.Fatalf("%d approval requests posted to the approvals channel, want 2", len(posts))
	}
	notice := func(v uuid.UUID) (uuid.UUID, string) {
		var row struct {
			ID      uuid.UUID
			SlackTS string
		}
		if err := l.db.Raw(`SELECT id, slack_ts FROM iga_gov_notification WHERE workspace_id = ? AND subject_kind = 'approval_request'
			AND subject_id = ? AND channel = 'slack' AND recipient = 'approvals_channel' AND state = 'sent'`, l.ws, v).Scan(&row).Error; err != nil || row.ID == uuid.Nil {
			t.Fatalf("approval notice of %s: %+v %v", v, row, err)
		}
		return row.ID, row.SlackTS
	}
	nA, tsA := notice(verA)
	nB, tsB := notice(verB)
	var postA, postB slacktest.Post
	for _, p := range posts {
		switch p.TS {
		case tsA:
			postA = p
		case tsB:
			postB = p
		}
	}
	if postA.TS == "" || postB.TS == "" || postA.Token != "xoxb-"+team {
		t.Fatalf("posts %+v (ts %s %s)", posts, tsA, tsB)
	}

	// §14.1 step 5: a first attachment has residuals -> no Approve button;
	// the message says acceptance is in AuthSec.
	btnA := p3sButtons(postA)
	if _, has := btnA[slackapp.ActionApprove]; has {
		t.Fatalf("residual plan offers Approve in Slack: %v", btnA)
	}
	if btnA[slackapp.ActionReject] == "" || !strings.Contains(p3sText(postA.Message), "cannot be approved from Slack") ||
		!strings.Contains(p3sText(postA.Message), "1 residual to accept") {
		t.Fatalf("residual message: %v\n%s", btnA, p3sText(postA.Message))
	}
	val := btnA[slackapp.ActionReject]
	click := func(user, action, value, msgTS string, state map[string]any) (int, map[string]any) {
		return app.click(p3sClick{team: team, user: user, messageTS: msgTS, action: action, value: value, state: state})
	}
	decisions := func() int64 {
		return l.count(`SELECT count(*) FROM iga_gov_approval WHERE workspace_id = ?`, l.ws)
	}
	lastTS := func(n uuid.UUID) string {
		var s string
		l.db.Raw(`SELECT last_action_ts FROM iga_gov_notification WHERE id = ?`, n).Row().Scan(&s)
		return s
	}

	t.Run("A14 forged signature", func(t *testing.T) {
		body := p3sClick{team: team, user: "UAPPROVER", messageTS: tsA, action: slackapp.ActionApprove, value: val, actionTS: app.nextActionTS()}.body()
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		for name, sig := range map[string]string{"wrong secret": slackapp.Sign("not-the-secret", ts, body), "none": "",
			"tampered": slackapp.Sign(p3sSigning, ts, append([]byte("x"), body...))} {
			code, out := app.post(body, ts, sig)
			if code != http.StatusUnauthorized || p3eErr(out) != services.SlackCodeSignatureInvalid {
				t.Fatalf("%s: %d %v, want 401 slack_signature_invalid", name, code, out)
			}
		}
		if lastTS(nA) != "" || decisions() != 0 {
			t.Fatal("a forged request reached the notification or a decision")
		}
	})

	t.Run("A14 stale timestamp", func(t *testing.T) {
		body := p3sClick{team: team, user: "UAPPROVER", messageTS: tsA, action: slackapp.ActionApprove, value: val, actionTS: app.nextActionTS()}.body()
		for _, age := range []time.Duration{6 * time.Minute, -6 * time.Minute} {
			ts := strconv.FormatInt(time.Now().Add(-age).Unix(), 10)
			code, out := app.post(body, ts, slackapp.Sign(p3sSigning, ts, body))
			if code != http.StatusUnauthorized || p3eErr(out) != services.SlackCodeSignatureInvalid || p3sDetail(out, "reason") != slackapp.ReasonStale {
				t.Fatalf("age %s: %d %v, want 401 stale_timestamp", age, code, out)
			}
		}
		if lastTS(nA) != "" {
			t.Fatal("a stale request was recorded")
		}
	})

	t.Run("A14 author approves (SoD)", func(t *testing.T) {
		before := app.fake.ResponseCount()
		code, out := click("UAUTHOR", slackapp.ActionApprove, val, tsA, nil)
		if code != http.StatusForbidden || p3eErr(out) != services.GovCodeSelfApproval {
			t.Fatalf("author approves via Slack: %d %v, want 403 self_approval", code, out)
		}
		if app.fake.ResponseCount() != before+1 || !strings.Contains(p3sText(app.fake.LastResponse().Message), slackapp.CopyAuthored) ||
			app.fake.LastResponse().Message.ResponseType != "ephemeral" {
			t.Fatalf("refusal answer %+v", app.fake.LastResponse())
		}
		// The author cannot reject either.
		if code, out = click("UAUTHOR", slackapp.ActionReject, val, tsA, p3sNote("mine")); code != http.StatusForbidden || p3eErr(out) != services.GovCodeSelfApproval {
			t.Fatalf("author rejects via Slack: %d %v", code, out)
		}
		if decisions() != 0 || l.status(polA, 1) != "in_review" {
			t.Fatal("a refused self-approval wrote a decision")
		}
	})

	t.Run("residuals cannot be approved from Slack", func(t *testing.T) {
		code, out := click("UAPPROVER", slackapp.ActionApprove, val, tsA, nil)
		if code != http.StatusConflict || p3eErr(out) != services.GovCodeResidualsNotAccept {
			t.Fatalf("approve with residuals: %d %v, want 409 residuals_not_accepted", code, out)
		}
		if !strings.Contains(p3sText(app.fake.LastResponse().Message), slackapp.CopyAcceptInAuthSec) || decisions() != 0 {
			t.Fatalf("answer %+v", app.fake.LastResponse())
		}
	})

	t.Run("A14 unlinked user; its link token proves nothing", func(t *testing.T) {
		code, out := click("USTRANGER", slackapp.ActionApprove, val, tsA, nil)
		if code != http.StatusForbidden || p3eErr(out) != services.SlackCodeUserNotLinked {
			t.Fatalf("unlinked user: %d %v, want 403 slack_user_not_linked", code, out)
		}
		if !strings.Contains(p3sText(app.fake.LastResponse().Message), slackapp.CopyLinkAccount) {
			t.Fatalf("answer %+v", app.fake.LastResponse())
		}
		// A user of another Slack team is not this workspace's.
		if code, out = app.click(p3sClick{team: "TOTHER", user: "UAPPROVER", messageTS: tsA, action: slackapp.ActionApprove, value: val}); code != http.StatusForbidden ||
			p3eErr(out) != services.SlackCodeUserNotLinked {
			t.Fatalf("other team: %d %v", code, out)
		}
		_, tok := app.svc.LinkURL(l.ws, team, "USTRANGER")
		bad := tok[:len(tok)-2] + "xx"
		if w, body := app.do(http.MethodPost, "/link/confirm", l.token(l.ws, stranger, "governance:read"), map[string]any{"token": bad}); w.Code != http.StatusBadRequest ||
			p3eErr(body) != services.SlackCodeLinkInvalid {
			t.Fatalf("tampered link token: %d %v", w.Code, body)
		}
		_, otherWS := app.svc.LinkURL(uuid.New(), team, "USTRANGER")
		if w, body := app.do(http.MethodPost, "/link/confirm", l.token(l.ws, stranger, "governance:read"), map[string]any{"token": otherWS}); w.Code != http.StatusNotFound {
			t.Fatalf("another workspace's link token: %d %v", w.Code, body)
		}
		// P0-3: the token only names the Slack user. Slack reports that
		// account's confirmed email as someone-else@..., which is no
		// member's: neither the stranger nor anyone the token is forwarded
		// to can claim it.
		for name, m := range map[string]p3aMember{"stranger": stranger, "second": l.second} {
			w, body := app.do(http.MethodPost, "/link/confirm", l.token(l.ws, m, "governance:read"), map[string]any{"token": tok})
			if w.Code != http.StatusForbidden || p3eErr(body) != "slack_link_email_mismatch" || p3sDetail(body, "reason") != "email_mismatch" {
				t.Fatalf("%s confirms the stranger's Slack account: %d %v", name, w.Code, body)
			}
		}
		if l.events(services.GovEventSlackUserLinked) != 4 || l.count(`SELECT count(*) FROM slack_user_link WHERE workspace_id = ? AND slack_user_id = 'USTRANGER'`, l.ws) != 0 {
			t.Fatalf("link events %d", l.events(services.GovEventSlackUserLinked))
		}
	})

	t.Run("A14 replay", func(t *testing.T) {
		body := p3sClick{team: team, user: "UAPPROVER", messageTS: tsA, action: slackapp.ActionApprove, value: val, actionTS: app.nextActionTS()}.body()
		code, out, ts, sig := app.signed(body)
		if code != http.StatusConflict || p3eErr(out) != services.GovCodeResidualsNotAccept {
			t.Fatalf("first: %d %v", code, out)
		}
		received := func() int64 {
			return l.count(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = ?`, l.ws, services.GovEventSlackActionReceived)
		}
		n0 := received()
		code, out = app.post(body, ts, sig)
		if code != http.StatusUnauthorized || p3eErr(out) != services.SlackCodeSignatureInvalid || p3sDetail(out, "reason") != "replayed" {
			t.Fatalf("replay: %d %v, want 401 replayed", code, out)
		}
		if received() != n0 {
			t.Fatal("a replay was recorded as a received action")
		}
		// An older action_ts, freshly signed, is a replay too.
		old := p3sClick{team: team, user: "UAPPROVER", messageTS: tsA, action: slackapp.ActionApprove, value: val,
			actionTS: strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10) + ".000001"}
		if code, out = app.click(old); code != http.StatusUnauthorized || p3sDetail(out, "reason") != "replayed" {
			t.Fatalf("older action_ts: %d %v", code, out)
		}
	})

	t.Run("not an approver, departed member", func(t *testing.T) {
		code, out := click("UADMIN", slackapp.ActionApprove, val, tsA, nil)
		if code != http.StatusForbidden || p3eErr(out) != "forbidden" {
			t.Fatalf("member without governance:approve: %d %v", code, out)
		}
		p3exec(t, l.db, `UPDATE workspace_memberships SET status = 'suspended' WHERE id = ?`, l.second.membership)
		code, out = click("USECOND", slackapp.ActionReject, btnBReject(t, postB), tsB, p3sNote("no"))
		p3exec(t, l.db, `UPDATE workspace_memberships SET status = 'active' WHERE id = ?`, l.second.membership)
		if code != http.StatusForbidden || p3sDetail(out, "reason") != "not_active_member" {
			t.Fatalf("departed member: %d %v", code, out)
		}
		if decisions() != 0 {
			t.Fatal("a refused click wrote a decision")
		}
	})

	t.Run("reject through Slack", func(t *testing.T) {
		v := btnBReject(t, postB)
		if code, out := click("UAPPROVER", slackapp.ActionReject, v, tsB, nil); code != http.StatusBadRequest {
			t.Fatalf("reject without a reason: %d %v", code, out)
		}
		code, out := click("UAPPROVER", slackapp.ActionReject, v, tsB, p3sNote("sns is the nightly alert path"))
		if code != http.StatusOK {
			t.Fatalf("reject: %d %v", code, out)
		}
		var ch, reason string
		l.db.Raw(`SELECT channel, reason FROM iga_gov_approval WHERE workspace_id = ? AND version_id = ? AND decision = 'reject'`, l.ws, verB).Row().Scan(&ch, &reason)
		if ch != "slack" || reason != "sns is the nightly alert path" || l.status(polB, 1) != "rejected" ||
			p3sCountEventually(t, l.db, 1, `SELECT count(*) FROM audit_events WHERE workspace_id = ? AND action = 'reject'`, l.ws.String()) != 1 {
			t.Fatalf("rejection channel %q reason %q status %s audits %d", ch, reason, l.status(polB, 1), l.audits("reject"))
		}
		if r := app.fake.LastResponse().Message; !r.ReplaceOriginal || !strings.Contains(r.Text, "Rejected by approver") {
			t.Fatalf("outcome %+v", r)
		}
		_ = nB
	})

	// Without residuals (a plan that is not a first attachment carries none;
	// the stored items are cleared to stand in for one), the re-sent
	// request offers Approve.
	p3exec(t, l.db, `UPDATE iga_gov_plan SET unanalysed = '[]' WHERE workspace_id = ? AND version_id = ?`, l.ws, verA)
	if err := l.db.Transaction(func(tx *gorm.DB) error { return services.EnqueueSlackApprovalRequestTx(tx, l.ws, verA, true) }); err != nil {
		t.Fatal(err)
	}
	p3Drain(t, worker)
	_, tsA2 := notice(verA)
	var postA2 slacktest.Post
	for _, p := range app.fake.PostsTo(channel) {
		if p.TS == tsA2 {
			postA2 = p
		}
	}
	btnA2 := p3sButtons(postA2)
	if tsA2 == tsA || btnA2[slackapp.ActionApprove] == "" || btnA2[slackapp.ActionReject] == "" {
		t.Fatalf("re-sent request: ts %s (was %s) buttons %v", tsA2, tsA, btnA2)
	}
	valA2 := btnA2[slackapp.ActionApprove]

	t.Run("stale message and changed plan", func(t *testing.T) {
		if code, out := click("UAPPROVER", slackapp.ActionApprove, val, tsA, nil); code != http.StatusConflict || p3eErr(out) != services.GovCodePlanChanged {
			t.Fatalf("superseded message: %d %v", code, out)
		}
		bv, _ := slackapp.DecodeButtonValue(valA2)
		bv.Digest = strings.Repeat("0", 32)
		if code, out := click("UAPPROVER", slackapp.ActionApprove, bv.Encode(), tsA2, nil); code != http.StatusConflict || p3eErr(out) != services.GovCodePlanChanged {
			t.Fatalf("changed digest: %d %v", code, out)
		}
		if !strings.Contains(p3sText(app.fake.LastResponse().Message), slackapp.CopyPlanChanged) {
			t.Fatalf("answer %+v", app.fake.LastResponse())
		}
	})

	t.Run("A14 author approves the approvable request", func(t *testing.T) {
		if code, out := click("UAUTHOR", slackapp.ActionApprove, valA2, tsA2, nil); code != http.StatusForbidden || p3eErr(out) != services.GovCodeSelfApproval {
			t.Fatalf("author: %d %v, want 403 self_approval", code, out)
		}
		if decisions() != 1 { // B's rejection only
			t.Fatalf("%d decisions", decisions())
		}
	})

	t.Run("approve through Slack", func(t *testing.T) {
		body := p3sClick{team: team, user: "UAPPROVER", messageTS: tsA2, action: slackapp.ActionApprove, value: valA2, actionTS: app.nextActionTS(),
			state: p3sNote("looks right")}.body()
		code, out, ts, sig := app.signed(body)
		if code != http.StatusOK {
			t.Fatalf("approve: %d %v", code, out)
		}
		var ch, by string
		l.db.Raw(`SELECT channel, decided_by FROM iga_gov_approval WHERE workspace_id = ? AND version_id = ? AND decision = 'approve'`, l.ws, verA).Row().Scan(&ch, &by)
		if ch != "slack" || by != l.approver.user.String() || l.status(polA, 1) != "approved" {
			t.Fatalf("approval channel %q by %s status %s", ch, by, l.status(polA, 1))
		}
		if l.count(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = 'version_approved' AND payload->>'channel' = 'slack'`, l.ws) != 1 ||
			p3sCountEventually(t, l.db, 1, `SELECT count(*) FROM audit_events WHERE workspace_id = ? AND action = 'approve' AND user_id = ?`, l.ws.String(), l.approver.user.String()) != 1 {
			t.Fatal("approval event or audit row missing")
		}
		if r := app.fake.LastResponse().Message; !r.ReplaceOriginal || !strings.HasPrefix(r.Text, "Approved by approver at ") {
			t.Fatalf("outcome %+v", r)
		}
		// Replaying the approving request is refused before anything runs.
		if code, out = app.post(body, ts, sig); code != http.StatusUnauthorized || p3sDetail(out, "reason") != "replayed" {
			t.Fatalf("replayed approval: %d %v", code, out)
		}
	})

	// Every Slack mutation and every interaction was recorded.
	for _, ev := range []string{services.GovEventSlackInstalled, services.GovEventSlackSettings} {
		if l.events(ev) != 1 {
			t.Errorf("%s events: %d", ev, l.events(ev))
		}
	}
	if p3sCountEventually(t, l.db, 2, `SELECT count(*) FROM audit_events WHERE workspace_id = ? AND action IN ('install','update_settings')`, l.ws.String()) != 2 {
		t.Errorf("install/settings audits %d %d", l.audits("install"), l.audits("update_settings"))
	}
}

func btnBReject(t *testing.T, p slacktest.Post) string {
	t.Helper()
	v := p3sButtons(p)[slackapp.ActionReject]
	if v == "" {
		t.Fatalf("no reject button: %v", p3sButtons(p))
	}
	return v
}
