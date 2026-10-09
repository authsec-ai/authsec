package integration

// Phase 3 R1a review fixes, Slack (REVIEW-FIXLIST.md P0-3 and the P2 Slack
// items), on the real Slack routes with the Slack Web API answered by
// slacktest.Fake and Vault by an in-memory KV v2 mount (p3sKV). Error codes
// introduced by the fixes are spelled as literals so these tests also build
// against the pre-fix service (to show they fail there).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/slackapp"
	"github.com/authsec-ai/authsec/internal/slackapp/slacktest"
	"github.com/authsec-ai/authsec/services"
)

// p3sxApproval is a lab with the Slack app installed through OAuth, an
// approvals channel and one version of a policy in review whose approval
// request was delivered (by the notify job) to the channel.
type p3sxApproval struct {
	l       *p3aLab
	app     *p3sApp
	team    string
	pol     string
	ver     uuid.UUID
	notice  uuid.UUID
	post    slacktest.Post
	buttons map[string]string
}

// newP3sxApproval builds it; slackUsers are added to the fake before the
// install (so the install links whoever it can by confirmed email).
// approvable clears the plan's unanalysed items so Slack offers Approve.
func newP3sxApproval(t *testing.T, name, team string, approvable bool, setup func(l *p3aLab, app *p3sApp)) *p3sxApproval {
	t.Helper()
	l := newP3aLab(t, name)
	app := newP3sApp(t, l.db, l.policy)
	x := &p3sxApproval{l: l, app: app, team: team}
	admin := l.member("slackadmin", "enforce")
	if setup != nil {
		setup(l, app)
	}
	app.install(l.token(l.ws, admin, "governance:enforce"), team, "Fix")
	channel := "C" + team
	if w, body := app.do(http.MethodPut, "/settings", l.token(l.ws, admin, "governance:enforce"), map[string]any{"approvals_channel_id": channel}); w.Code != http.StatusOK {
		t.Fatalf("PUT /settings: %d %v", w.Code, body)
	}
	roleID := "AROAFIX" + strings.ToUpper(strings.ReplaceAll(uuid.NewString(), "-", ""))[:10]
	l.role("FixRole"+roleID[7:12], roleID, map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	l.publish()
	x.pol, _ = l.proposeTemplate(roleID)
	l.compile(x.pol, 1)
	x.ver = l.versionID(x.pol, 1)
	if approvable {
		p3exec(t, l.db, `UPDATE iga_gov_plan SET unanalysed = '[]' WHERE workspace_id = ? AND version_id = ?`, l.ws, x.ver)
	}
	p3Drain(t, p3NotifyWorker(l.db, &p3Outbox{}, &p3Outbox{}))
	var row struct {
		ID      uuid.UUID
		SlackTS string
	}
	if err := l.db.Raw(`SELECT id, slack_ts FROM iga_gov_notification WHERE workspace_id = ? AND subject_kind = 'approval_request'
		AND subject_id = ? AND channel = 'slack' AND state = 'sent'`, l.ws, x.ver).Scan(&row).Error; err != nil || row.ID == uuid.Nil {
		t.Fatalf("approval notice: %+v %v", row, err)
	}
	x.notice = row.ID
	for _, p := range app.fake.PostsTo(channel) {
		if p.TS == row.SlackTS {
			x.post = p
		}
	}
	x.buttons = p3sButtons(x.post)
	if approvable && x.buttons[slackapp.ActionApprove] == "" {
		t.Fatalf("no Approve button: %v", x.buttons)
	}
	return x
}

func (x *p3sxApproval) click(user, action string, state map[string]any) (int, map[string]any) {
	return x.app.click(p3sClick{team: x.team, user: user, messageTS: x.post.TS, action: action, value: x.buttons[action], state: state})
}

func (x *p3sxApproval) decisions() int64 {
	return x.l.count(`SELECT count(*) FROM iga_gov_approval WHERE workspace_id = ?`, x.l.ws)
}

func (x *p3sxApproval) confirm(m p3aMember, token string) (int, map[string]any) {
	w, body := x.app.do(http.MethodPost, "/link/confirm", x.l.token(x.l.ws, m, "governance:read"), map[string]any{"token": token})
	return w.Code, body
}

// p3sxSameEmailMember adds an active member whose account email is email
// (another users row: users are unique per home workspace and email, and
// this one has no home workspace), holding governance:<perm>.
func p3sxSameEmailMember(t *testing.T, l *p3aLab, email, perm string) p3aMember {
	t.Helper()
	m := p3aMember{user: uuid.New(), membership: uuid.New(), role: uuid.New()}
	p3exec(t, l.db, `INSERT INTO users (id, email, name, workspace_id) VALUES (?, ?, 'same-mailbox', NULL)`, m.user, email)
	p3exec(t, l.db, `INSERT INTO roles (id, name, workspace_id) VALUES (?, ?, ?)`, m.role, "p3sx-"+m.role.String()[:8], l.ws)
	p3exec(t, l.db, `INSERT INTO workspace_memberships (id, workspace_id, user_id, role_id, status) VALUES (?, ?, ?, ?, 'active')`,
		m.membership, l.ws, m.user, m.role)
	p3exec(t, l.db, `INSERT INTO role_permissions (role_id, permission_id)
	                 SELECT ?, id FROM permissions WHERE workspace_id IS NULL AND resource = 'governance' AND action = ?`, m.role, perm)
	l.users = append(l.users, m.user)
	l.roles = append(l.roles, m.role)
	return m
}

// P0-3: Slack linking must not bypass separation of duties.
//
// Prove: a forwarded link token used by another member is refused; the
// author cannot make their Slack clicks act as an approver; a member cannot
// hold two links in one team. Also: the ambiguous-email case /link/confirm
// exists for still works, and a link it makes acts for its member.
//
// Safeguards (mutation-checked): ConfirmLink's confirmed-email match; the
// one-link-per-member check (code and 057's index).
func TestP3FixSlackLinkSeparationOfDuties(t *testing.T) {
	const team = "TFIXLINK"
	var dupA, dupB p3aMember
	dupEmail := "shared-" + uuid.NewString()[:8] + "@p3sx.test"
	x := newP3sxApproval(t, "p3-fix-slack-link", team, true, func(l *p3aLab, app *p3sApp) {
		// The approver's Slack account: confirmed AuthSec email (linked at install).
		app.fake.AddUser(slackapp.User{ID: "UAPPROVER", TeamID: team, Email: p3sEmail(t, l.db, l.approver.user), IsEmailConfirmed: true})
		// The author's Slack account carries a personal email: not linked.
		app.fake.AddUser(slackapp.User{ID: "UAUTHOR", TeamID: team, Email: "asha.personal@elsewhere.test", IsEmailConfirmed: true})
		// Two members share one mailbox (ambiguous: never linked automatically).
		dupA = l.member("dupa", "approve")
		p3exec(t, l.db, `UPDATE users SET email = ? WHERE id = ?`, dupEmail, dupA.user)
		dupB = p3sxSameEmailMember(t, l, dupEmail, "approve")
		app.fake.AddUser(slackapp.User{ID: "UDUP1", TeamID: team, Email: dupEmail, IsEmailConfirmed: true})
		app.fake.AddUser(slackapp.User{ID: "UDUP2", TeamID: team, Email: strings.ToUpper(dupEmail), IsEmailConfirmed: true})
	})
	l, app := x.l, x.app
	links := func(q string, args ...any) int64 {
		return l.count(`SELECT count(*) FROM slack_user_link WHERE workspace_id = ? `+q, append([]any{l.ws}, args...)...)
	}
	if links(`AND slack_user_id = 'UAPPROVER' AND user_id = ?`, l.approver.user) != 1 || links(``) != 1 {
		t.Fatalf("after install: %d links, want only UAPPROVER -> approver", links(``))
	}

	t.Run("the author cannot make their Slack clicks act as an approver", func(t *testing.T) {
		code, out := x.click("UAUTHOR", slackapp.ActionApprove, nil)
		if code != http.StatusForbidden || p3eErr(out) != services.SlackCodeUserNotLinked {
			t.Fatalf("author's unlinked Slack account: %d %v", code, out)
		}
		// The author forwards the link they were sent to the approver, who
		// confirms it (or the author confirms it themself): refused.
		_, tok := app.svc.LinkURL(l.ws, team, "UAUTHOR")
		for name, m := range map[string]p3aMember{"approver (forwarded)": l.approver, "second approver (forwarded)": l.second, "author": l.author} {
			code, body := x.confirm(m, tok)
			if code != http.StatusForbidden || p3eErr(body) != "slack_link_email_mismatch" || p3sDetail(body, "reason") != "email_mismatch" {
				t.Fatalf("%s confirms UAUTHOR: %d %v, want 403 slack_link_email_mismatch", name, code, body)
			}
		}
		if links(`AND slack_user_id = 'UAUTHOR'`) != 0 {
			t.Fatal("UAUTHOR was linked")
		}
		code, out = x.click("UAUTHOR", slackapp.ActionApprove, nil)
		if code != http.StatusForbidden || p3eErr(out) != services.SlackCodeUserNotLinked {
			t.Fatalf("author's Slack click after the forwarded confirmation: %d %v", code, out)
		}
		if x.decisions() != 0 || l.status(x.pol, 1) != "in_review" {
			t.Fatal("the author's Slack click decided the version")
		}
	})

	t.Run("a forwarded link token used by another member is refused", func(t *testing.T) {
		// UDUP1's confirmed email is the shared mailbox's: ambiguous, so
		// it is answered with a link; forwarded to the approver: refused.
		code, out := x.click("UDUP1", slackapp.ActionApprove, nil)
		if code != http.StatusForbidden || p3eErr(out) != services.SlackCodeUserNotLinked {
			t.Fatalf("ambiguous Slack user: %d %v", code, out)
		}
		_, tok := app.svc.LinkURL(l.ws, team, "UDUP1")
		if code, body := x.confirm(l.approver, tok); code != http.StatusForbidden || p3eErr(body) != "slack_link_email_mismatch" {
			t.Fatalf("approver confirms UDUP1 (forwarded): %d %v", code, body)
		}
		// A member of the shared mailbox confirms: linked.
		code, body := x.confirm(dupA, tok)
		if code != http.StatusOK || digs(body, "data", "link", "user_id") != dupA.user.String() ||
			digs(body, "data", "link", "linked_via") != "console_confirmation" {
			t.Fatalf("dupA confirms UDUP1: %d %v", code, body)
		}
		// The other member of the mailbox can no longer take it.
		if code, body := x.confirm(dupB, tok); code != http.StatusConflict || p3eErr(body) != services.SlackCodeAlreadyLinked {
			t.Fatalf("dupB confirms UDUP1: %d %v", code, body)
		}
	})

	t.Run("a member cannot hold two links in one team", func(t *testing.T) {
		_, tok2 := app.svc.LinkURL(l.ws, team, "UDUP2")
		if code, body := x.confirm(dupA, tok2); code != http.StatusConflict || p3eErr(body) != "slack_member_already_linked" {
			t.Fatalf("dupA confirms a second Slack account: %d %v", code, body)
		}
		// Automatic linking makes no second link either: UAPPROVER2, a
		// second Slack account with the approver's confirmed email, acts;
		// the approver already holds UAPPROVER.
		app.fake.AddUser(slackapp.User{ID: "UAPPROVER2", TeamID: team, Email: p3sEmail(t, l.db, l.approver.user), IsEmailConfirmed: true})
		code, out := x.click("UAPPROVER2", slackapp.ActionApprove, nil)
		if code != http.StatusForbidden || p3eErr(out) != services.SlackCodeUserNotLinked {
			t.Fatalf("second Slack account of the approver: %d %v", code, out)
		}
		if links(`AND user_id = ?`, l.approver.user) != 1 || links(`AND user_id = ?`, dupA.user) != 1 {
			t.Fatalf("approver %d links, dupA %d links", links(`AND user_id = ?`, l.approver.user), links(`AND user_id = ?`, dupA.user))
		}
		// The database refuses it too (057).
		err := l.db.Exec(`INSERT INTO slack_user_link (workspace_id, slack_user_id, user_id, linked_via) VALUES (?, 'UDUP2', ?, 'verified_email')`,
			l.ws, dupA.user).Error
		if err == nil || !strings.Contains(err.Error(), "uq_slack_user_link_member") {
			t.Fatalf("second link for a member inserted directly: %v", err)
		}
		// dupB, whose email is UDUP2's, links it.
		if code, body := x.confirm(dupB, tok2); code != http.StatusOK || digs(body, "data", "link", "user_id") != dupB.user.String() {
			t.Fatalf("dupB confirms UDUP2: %d %v", code, body)
		}
	})

	t.Run("a confirmed link acts for its own member", func(t *testing.T) {
		code, out := x.click("UDUP1", slackapp.ActionApprove, nil)
		if code != http.StatusOK {
			t.Fatalf("UDUP1 approves: %d %v", code, out)
		}
		var by string
		l.db.Raw(`SELECT decided_by FROM iga_gov_approval WHERE workspace_id = ? AND version_id = ? AND decision = 'approve'`, l.ws, x.ver).Row().Scan(&by)
		if by != dupA.user.String() || l.status(x.pol, 1) != "approved" {
			t.Fatalf("approval by %s, status %s", by, l.status(x.pol, 1))
		}
	})
}

// p3sxBlockingHealth is a health reporter that blocks until released.
type p3sxBlockingHealth struct {
	entered chan struct{}
	release chan struct{}
	mu      sync.Mutex
	got     []services.GovHealthReport
}

func (h *p3sxBlockingHealth) ReportHealth(_ context.Context, r services.GovHealthReport) (any, error) {
	close(h.entered)
	<-h.release
	h.mu.Lock()
	h.got = append(h.got, r)
	h.mu.Unlock()
	return map[string]any{"kind": r.Kind}, nil
}

func (h *p3sxBlockingHealth) reports() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.got)
}

// P2 Slack (a): Slack must get its HTTP 200 within 3 seconds. The action is
// done after the answer, with its own context, and its outcome is posted
// to the response_url; the audit row is written when it completes.
func TestP3FixSlackInteractionAckedBeforeTheWork(t *testing.T) {
	db := igaDB(t)
	g := p3NewGov(t, db, "p3-fix-slack-ack")
	app := newP3sApp(t, db, p3sGate(t, db))
	const team = "TFIXACK"
	app.connectDirect(g.ws, team, "CFIXACK", g.author)
	u1, _ := g.member("ack-owner-"+g.ws.String()[:8]+"@p3sx.test", "Ada Owner", "active")
	app.link(g.ws, "UOWNERACK", u1)
	dep, n := uuid.New(), uuid.New()
	p3exec(t, db, `INSERT INTO iga_gov_notification (id, workspace_id, subject_kind, subject_id, channel, recipient, state, sent_at, slack_ts)
		VALUES (?, ?, 'deployment', ?, 'slack', ?, 'sent', now(), '1700000000.777777')`, n, g.ws, dep, "user:"+u1.String())
	h := &p3sxBlockingHealth{entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(services.SetGovHealthReporter(h))
	released := false
	release := func() {
		if !released {
			released = true
			close(h.release)
		}
	}
	defer release()

	body := p3sClick{team: team, user: "UOWNERACK", messageTS: "1700000000.777777", action: slackapp.ActionReportProblem,
		value: slackapp.ButtonValue{Notification: n.String()}.Encode(), actionTS: app.nextActionTS(), state: p3sNote("refunds time out")}.body()
	type ack struct {
		code int
		out  map[string]any
	}
	acked := make(chan ack, 1)
	before := app.fake.ResponseCount()
	go func() {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		code, out := app.postAck(body, ts, slackapp.Sign(p3sSigning, ts, body))
		acked <- ack{code, out}
	}()
	var a ack
	select {
	case a = <-acked:
	case <-time.After(3 * time.Second):
		release()
		<-acked
		t.Fatal("Slack was not answered within 3 s: the request waited for the action")
	}
	if a.code != http.StatusOK || dig(a.out, "data", "accepted") != true {
		t.Fatalf("ack: %d %v, want 200 {accepted: true}", a.code, a.out)
	}
	// The action runs after the answer: the reporter is (or will be) busy,
	// nothing is reported or answered yet.
	select {
	case <-h.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the accepted action never ran")
	}
	if h.reports() != 0 || app.fake.ResponseCount() != before {
		t.Fatal("the outcome was produced before the action finished")
	}
	release()
	code, out := app.next()
	if code != http.StatusOK || digs(out, "data", "action") != "health_report" {
		t.Fatalf("outcome: %d %v", code, out)
	}
	if h.reports() != 1 || app.fake.ResponseCount() != before+1 || !strings.HasPrefix(app.fake.LastResponse().Message.Text, "Problem reported by Ada Owner") {
		t.Fatalf("reports %d, response %+v", h.reports(), app.fake.LastResponse())
	}
	if n := p3sCountEventually(t, db, 1, `SELECT count(*) FROM audit_events WHERE workspace_id = ? AND action = 'health_report' AND user_id = ?`,
		g.ws.String(), u1.String()); n != 1 {
		t.Fatalf("%d health_report audit rows", n)
	}
}

// P2 Slack (d): the action_ts is claimed only after the signature AND the
// authorization checks pass, and still atomically.
func TestP3FixSlackActionTSClaimedAfterAuthorization(t *testing.T) {
	const team = "TFIXCLAIM"
	x := newP3sxApproval(t, "p3-fix-slack-claim", team, false, func(l *p3aLab, app *p3sApp) {
		admin := l.member("noapprove", "read")
		for id, m := range map[string]p3aMember{"UAPPROVER": l.approver, "UAUTHOR": l.author, "UNOAPPROVE": admin} {
			app.fake.AddUser(slackapp.User{ID: id, TeamID: team, Email: p3sEmail(t, l.db, m.user), IsEmailConfirmed: true})
		}
		app.fake.AddUser(slackapp.User{ID: "USTRANGER", TeamID: team, Email: "stranger@elsewhere.test", IsEmailConfirmed: true})
	})
	l, app := x.l, x.app
	// The author also holds governance:approve: only separation of duties
	// stands in the way.
	p3exec(t, l.db, `INSERT INTO role_permissions (role_id, permission_id)
	                 SELECT ?, id FROM permissions WHERE workspace_id IS NULL AND resource = 'governance' AND action = 'approve'`, l.author.role)
	lastTS := func() string {
		var s string
		l.db.Raw(`SELECT last_action_ts FROM iga_gov_notification WHERE id = ?`, x.notice).Row().Scan(&s)
		return s
	}
	received := func() int64 { return l.events(services.GovEventSlackActionReceived) }
	reject := x.buttons[slackapp.ActionReject]
	at := func(sec int64, seq int) string { return fmt.Sprintf("%d.%06d", sec, seq) }
	now := time.Now().Unix()

	// Unauthorized clicks carrying the NEWEST action_ts: none is recorded.
	for i, c := range []struct {
		user, code string
	}{{"USTRANGER", services.SlackCodeUserNotLinked}, {"UNOAPPROVE", "forbidden"}, {"UAUTHOR", services.GovCodeSelfApproval}} {
		code, out := app.click(p3sClick{team: team, user: c.user, messageTS: x.post.TS, action: slackapp.ActionReject, value: reject,
			actionTS: at(now+60, 100+i), state: p3sNote("no")})
		if code != http.StatusForbidden || p3eErr(out) != c.code {
			t.Fatalf("%s: %d %v, want 403 %s", c.user, code, out, c.code)
		}
		if lastTS() != "" || received() != 0 {
			t.Fatalf("%s's refused click was claimed: last_action_ts %q, %d received events", c.user, lastTS(), received())
		}
	}

	// The approver's click, older than those refused ones, is not a replay.
	body := p3sClick{team: team, user: "UAPPROVER", messageTS: x.post.TS, action: slackapp.ActionReject, value: reject,
		actionTS: at(now, 1), state: p3sNote("sqs is still used by the nightly job")}.body()
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := slackapp.Sign(p3sSigning, ts, body)
	// Two deliveries of the same click at once: exactly one acts.
	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, _ := app.postAck(body, ts, sig)
			codes[i] = c
		}(i)
	}
	wg.Wait()
	accepted := 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			accepted++
		case http.StatusUnauthorized:
		default:
			t.Fatalf("delivery answered %d", c)
		}
	}
	var outs []int
	acted := 0
	for i := 0; i < accepted; i++ {
		c, out := app.next()
		outs = append(outs, c)
		switch {
		case c == http.StatusOK:
			acted++
		case c == http.StatusUnauthorized && p3sDetail(out, "reason") == "replayed":
		default:
			t.Fatalf("outcome %d %v", c, out)
		}
	}
	if acted != 1 || x.decisions() != 1 || l.status(x.pol, 1) != "rejected" || received() != 1 || lastTS() != at(now, 1) {
		t.Fatalf("deliveries %v outcomes %v: %d acted, %d decisions, status %s, %d received, last %q", codes, outs, acted, x.decisions(),
			l.status(x.pol, 1), received(), lastTS())
	}
	// Replayed later: refused before anything runs.
	if code, out := app.postAck(body, ts, sig); code != http.StatusUnauthorized || p3sDetail(out, "reason") != "replayed" {
		t.Fatalf("replay: %d %v", code, out)
	}
}

// P2 Slack (b): the OAuth nonce cookie must reach the callback. The
// console calls the API at api.authsec.test; the console itself is
// console.authsec.test (config BaseURL). A browser cookie jar stands in for
// the browser.
func TestP3FixSlackInstallCookieReachesCallback(t *testing.T) {
	db := igaDB(t)
	gate := p3sGate(t, db)
	prevCfg := config.AppConfig
	config.AppConfig = &config.Config{BaseURL: "https://console.authsec.test"}
	t.Cleanup(func() { config.AppConfig = prevCfg })
	const apiHost, consoleHost = "api.authsec.test", "console.authsec.test"

	type flow struct {
		app   *p3sApp
		g     *p3Gov
		token string
	}
	newFlow := func(name, redirectEnv, cookieDomainEnv string) flow {
		t.Setenv(services.SlackRedirectURLEnv, redirectEnv)
		t.Setenv("AUTHSEC_SLACK_COOKIE_DOMAIN", cookieDomainEnv)
		cfg := services.SlackConfigFromEnv()
		cfg.SigningSecret = p3sSigning
		g := p3NewGov(t, db, name)
		p3sGrant(t, db, g.roles[0], "enforce")
		return flow{app: newP3sAppWith(t, db, gate, cfg), g: g,
			token: p3sToken(t, g.ws, g.author, g.authorMember, "governance:enforce governance:read")}
	}
	// install runs GET /install on the API host through jar, then follows
	// the redirect URI with whatever cookies the jar sends there.
	install := func(f flow, code string) (installCode int, installBody map[string]any, cbCode int, cbBody map[string]any, redirect *url.URL) {
		t.Helper()
		jar, _ := cookiejar.New(nil)
		installURL, _ := url.Parse("https://" + apiHost + "/authsec/integrations/slack/install")
		req := httptest.NewRequest(http.MethodGet, installURL.Path, nil)
		req.Host = apiHost
		req.Header.Set("Authorization", "Bearer "+f.token)
		w := httptest.NewRecorder()
		f.app.eng.ServeHTTP(w, req)
		_ = json.Unmarshal(w.Body.Bytes(), &installBody)
		if w.Code != http.StatusOK {
			return w.Code, installBody, 0, nil, nil
		}
		jar.SetCookies(installURL, w.Result().Cookies())
		authz, err := url.Parse(digs(installBody, "data", "authorize_url"))
		if err != nil {
			t.Fatal(err)
		}
		redirect, err = url.Parse(authz.Query().Get("redirect_uri"))
		if err != nil || redirect.Host == "" {
			t.Fatalf("redirect_uri %q", authz.Query().Get("redirect_uri"))
		}
		f.app.fake.AddInstall(code, p3sClientID, slackapp.OAuthResult{AccessToken: "xoxb-" + code, TeamID: "T" + strings.ToUpper(code), TeamName: code})
		cb := *redirect
		cb.RawQuery = url.Values{"state": {authz.Query().Get("state")}, "code": {code}}.Encode()
		req = httptest.NewRequest(http.MethodGet, cb.RequestURI(), nil)
		req.Host = redirect.Host
		for _, c := range jar.Cookies(redirect) {
			req.AddCookie(c)
		}
		w = httptest.NewRecorder()
		f.app.eng.ServeHTTP(w, req)
		_ = json.Unmarshal(w.Body.Bytes(), &cbBody)
		if w.Code == http.StatusFound {
			loc, _ := url.Parse(w.Header().Get("Location"))
			cbBody = map[string]any{"slack": loc.Query().Get("slack"), "slack_error": loc.Query().Get("slack_error")}
		}
		return http.StatusOK, installBody, w.Code, cbBody, redirect
	}

	t.Run("default: the callback is on the host that set the cookie", func(t *testing.T) {
		f := newFlow("p3-fix-slack-cookie-a", "", "")
		ic, ib, cc, cb, redirect := install(f, "cookiea")
		if ic != http.StatusOK {
			t.Fatalf("GET /install: %d %v", ic, ib)
		}
		if redirect.Host != apiHost || redirect.Path != services.SlackCallbackPath {
			t.Errorf("redirect_uri %s: not the API host's callback", redirect)
		}
		if cc != http.StatusFound || cb["slack"] != "connected" {
			t.Fatalf("callback at %s: %d %v (the install cookie did not reach it)", redirect, cc, cb)
		}
	})

	t.Run("a redirect host that cannot receive the cookie is refused at install", func(t *testing.T) {
		f := newFlow("p3-fix-slack-cookie-b", "https://"+consoleHost+services.SlackCallbackPath, "")
		ic, ib, _, _, _ := install(f, "cookieb")
		if ic != http.StatusServiceUnavailable || p3eErr(ib) != services.SlackCodeNotConfigured || p3sDetail(ib, "reason") != "redirect_cookie_mismatch" {
			t.Fatalf("GET /install with a console redirect and a host-only cookie: %d %v", ic, ib)
		}
	})

	t.Run("a shared cookie domain reaches a redirect on another host", func(t *testing.T) {
		f := newFlow("p3-fix-slack-cookie-c", "https://"+consoleHost+services.SlackCallbackPath, "authsec.test")
		ic, ib, cc, cb, redirect := install(f, "cookiec")
		if ic != http.StatusOK || redirect.Host != consoleHost {
			t.Fatalf("GET /install: %d %v (redirect %v)", ic, ib, redirect)
		}
		if cc != http.StatusFound || cb["slack"] != "connected" {
			t.Fatalf("callback at %s: %d %v", redirect, cc, cb)
		}
	})
}

// P2 Slack (c): disconnect destroys every version of the bot token in
// Vault (not a soft delete), and reinstalling the workspace into another
// Slack team revokes the old team's token.
func TestP3FixSlackDisconnectDestroysTokenAndReinstallRevokes(t *testing.T) {
	db := igaDB(t)
	g := p3NewGov(t, db, "p3-fix-slack-vault")
	app := newP3sApp(t, db, p3sGate(t, db))
	p3sGrant(t, db, g.roles[0], "enforce")
	tok := p3sToken(t, g.ws, g.author, g.authorMember, "governance:enforce governance:read")
	path := services.SlackBotTokenPath(g.ws)

	app.install(tok, "TFIXONE", "One")
	app.install(tok, "TFIXTWO", "Two")
	if sec, err := app.vault.ReadSecret(path); err != nil || sec["token"] != "xoxb-TFIXTWO" {
		t.Fatalf("current token %v %v", sec, err)
	}
	if strings.Join(app.fake.Revoked, ",") != "xoxb-TFIXONE" {
		t.Fatalf("auth.revoke calls after reinstalling into another team: %v, want the old team's token", app.fake.Revoked)
	}
	var replaced string
	db.Raw(`SELECT payload->>'replaced_slack_team_id' FROM iga_gov_event WHERE workspace_id = ? AND event = 'slack.installed' ORDER BY id DESC LIMIT 1`, g.ws).Row().Scan(&replaced)
	if replaced != "TFIXONE" {
		t.Errorf("slack.installed replaced_slack_team_id %q", replaced)
	}
	// Reinstalling the same team with the same token revokes nothing.
	app.fake.AddInstall("code-same", p3sClientID, slackapp.OAuthResult{AccessToken: "xoxb-TFIXTWO", TeamID: "TFIXTWO", TeamName: "Two"})
	state, cookie := app.startInstall(tok)
	if c, body := app.callback(state, "code-same", cookie); c != http.StatusOK {
		t.Fatalf("same-team reinstall: %d %v", c, body)
	}
	if len(app.fake.Revoked) != 1 {
		t.Fatalf("a reinstall keeping the token revoked it: %v", app.fake.Revoked)
	}

	if w, body := app.do(http.MethodDelete, "", tok, nil); w.Code != http.StatusOK {
		t.Fatalf("disconnect: %d %v", w.Code, body)
	}
	if v := app.vault.recoverable(path); len(v) != 0 {
		t.Fatalf("token versions still recoverable from Vault after disconnect: %v", v)
	}
	if strings.Join(app.fake.Revoked, ",") != "xoxb-TFIXONE,xoxb-TFIXTWO" {
		t.Fatalf("auth.revoke calls %v", app.fake.Revoked)
	}
}

// 057: links the old /link/confirm made, and every link of a member who
// holds several, are revoked before the one-link-per-member index is
// created; a re-run changes nothing. Run inside a transaction that is
// rolled back (the index is dropped in it to stand at 056).
func TestP3FixSlack057RevokesUnprovenLinks(t *testing.T) {
	db := igaDB(t)
	raw, err := os.ReadFile("../../migrations/master/057_slack_link_one_per_member.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx := db.Begin()
	defer tx.Rollback()
	must := func(q string, args ...any) {
		t.Helper()
		if err := tx.Exec(q, args...).Error; err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	must(`DROP INDEX IF EXISTS uq_slack_user_link_member`)
	ws := uuid.New()
	must(`INSERT INTO workspaces (id,name,slug,owner_user_id,workspace_type,workspace_domain,email,status,created_at,updated_at)
		VALUES (?,'p3-fix-057',NULL,?,'team',?,?,'active',NOW(),NOW())`, ws, ws, ws.String()+".test", ws.String()+"@test.local")
	users := make([]uuid.UUID, 4)
	for i := range users {
		users[i] = uuid.New()
		must(`INSERT INTO users (id, email, name, workspace_id) VALUES (?, ?, 'u', ?)`, users[i], fmt.Sprintf("u%d-%s@p3sx.test", i, ws.String()[:8]), ws)
	}
	link := func(slack string, u uuid.UUID, via string) {
		must(`INSERT INTO slack_user_link (workspace_id, slack_user_id, user_id, linked_via) VALUES (?, ?, ?, ?)`, ws, slack, u, via)
	}
	link("UV1", users[0], "verified_email")       // kept
	link("UC2", users[1], "console_confirmation") // revoked: unproven
	link("UV3A", users[2], "verified_email")      // revoked: two links
	link("UV3B", users[2], "verified_email")      // revoked: two links
	link("UV4", users[3], "verified_email")       // kept
	link("UC4", users[3], "console_confirmation") // revoked: unproven
	left := func() string {
		var ids []string
		if err := tx.Raw(`SELECT slack_user_id FROM slack_user_link WHERE workspace_id = ? ORDER BY slack_user_id`, ws).Scan(&ids).Error; err != nil {
			t.Fatal(err)
		}
		return strings.Join(ids, ",")
	}
	must(string(raw))
	if got := left(); got != "UV1,UV4" {
		t.Fatalf("links after 057: %s, want UV1,UV4", got)
	}
	// Re-run: idempotent, and links made under the new rule are kept.
	link("UC5", users[1], "console_confirmation")
	must(string(raw))
	if got := left(); got != "UC5,UV1,UV4" {
		t.Fatalf("links after re-running 057: %s", got)
	}
	if err := tx.Exec(`INSERT INTO slack_user_link (workspace_id, slack_user_id, user_id, linked_via) VALUES (?, 'UV1B', ?, 'verified_email')`, ws, users[0]).Error; err == nil ||
		!strings.Contains(err.Error(), "uq_slack_user_link_member") {
		t.Fatalf("second link of a member after 057: %v", err)
	}
}
