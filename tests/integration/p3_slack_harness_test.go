package integration

// Shared plumbing for the T3.14 Slack scenarios (SPEC-iga-phase3-policy.md
// §7.11, §7.12, §2.10, §10; A14): the production Slack routes on a gin
// engine, the Slack Web API answered by slacktest.Fake (no network), Vault
// in memory, the Slack app installed process-wide (notification channel +
// approval-request hooks) for the test's duration. Prefixed p3s.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/config"
	platform "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/internal/slackapp"
	"github.com/authsec-ai/authsec/internal/slackapp/slacktest"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/monitoring"
	"github.com/authsec-ai/authsec/services"
)

const (
	p3sSigning  = "p3-t314-slack-signing-secret"
	p3sClientID = "p3-t314-client-id"
	p3sRedirect = "https://authsec.test/authsec/integrations/slack/oauth/callback"
)

type p3sApp struct {
	t     *testing.T
	db    *gorm.DB
	svc   *services.SlackIntegrationService
	fake  *slacktest.Fake
	vault *memVault
	eng   *gin.Engine
	seq   atomic.Int64
}

// newP3sApp installs the Slack app over db for this test and mounts its
// routes on a fresh engine behind gate. Tokens are signed with p3aSecret.
func newP3sApp(t *testing.T, db *gorm.DB, gate *services.PolicyGate) *p3sApp {
	t.Helper()
	a := &p3sApp{t: t, db: db, fake: slacktest.New(), vault: newMemVault()}
	if err := a.vault.WriteSecret(services.DefaultSlackAppPath, map[string]interface{}{"client_id": p3sClientID, "client_secret": "p3-t314-client-secret"}); err != nil {
		t.Fatal(err)
	}
	a.svc = services.NewSlackIntegrationService(db, a.vault, a.fake, services.SlackConfig{SigningSecret: p3sSigning, RedirectURL: p3sRedirect})
	restore := services.InstallSlackApp(a.svc)
	t.Cleanup(restore)
	p3aAuditOnce.Do(func() {
		if monitoring.GetLogger() == nil {
			monitoring.InitMetrics()
		}
	})
	prevAudit := config.AuditLogger
	config.AuditLogger = monitoring.NewAuditLogger(db)
	t.Cleanup(func() { config.AuditLogger = prevAudit })
	gin.SetMode(gin.TestMode)
	t.Setenv("JWT_SDK_SECRET", p3aSecret)
	t.Setenv("JWT_DEF_SECRET", p3aSecret+"-default")
	t.Setenv("AUTH_EXPECT_ISS", "authsec-ai/auth-manager")
	t.Setenv("REQUIRE_SERVER_AUTH", "true")
	a.eng = gin.New()
	platform.MountSlackIntegrationRoutes(a.eng.Group("/authsec"),
		platform.NewSlackIntegrationController(db, a.svc).WithPolicyGate(gate), middlewares.AuthMiddleware(), middlewares.Require)
	return a
}

// p3sToken is a member's workspace token.
func p3sToken(t *testing.T, ws, user, membership uuid.UUID, scope string) string {
	t.Helper()
	claims := jwt.MapClaims{"iss": "authsec-ai/auth-manager", "exp": time.Now().Add(time.Hour).Unix(),
		"workspace_id": ws.String(), "user_id": user.String(), "scope": scope}
	if membership != uuid.Nil {
		claims["workspace_membership_id"] = membership.String()
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(p3aSecret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// do performs a request on the Slack routes.
func (a *p3sApp) do(method, path, bearer string, body any, cookies ...*http.Cookie) (*httptest.ResponseRecorder, map[string]any) {
	a.t.Helper()
	var rd *strings.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = strings.NewReader(string(raw))
	} else {
		rd = strings.NewReader("")
	}
	req := httptest.NewRequest(method, "/authsec/integrations/slack"+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	a.eng.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

// startInstall is GET /install: the authorize URL's state and the cookie.
func (a *p3sApp) startInstall(bearer string) (state string, cookie *http.Cookie) {
	a.t.Helper()
	w, body := a.do(http.MethodGet, "/install", bearer, nil)
	if w.Code != http.StatusOK {
		a.t.Fatalf("GET /install: %d %v", w.Code, body)
	}
	u, err := url.Parse(digs(body, "data", "authorize_url"))
	if err != nil || u.Host != "slack.com" || u.Query().Get("client_id") != p3sClientID || u.Query().Get("redirect_uri") != p3sRedirect ||
		u.Query().Get("scope") != "chat:write,users:read,users:read.email" || u.Query().Get("state") == "" {
		a.t.Fatalf("authorize_url %v", digs(body, "data", "authorize_url"))
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == services.SlackInstallCookie {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Value == "" {
		a.t.Fatalf("install cookie %+v", cookie)
	}
	return u.Query().Get("state"), &http.Cookie{Name: cookie.Name, Value: cookie.Value}
}

func (a *p3sApp) callback(state, code string, cookie *http.Cookie) (int, map[string]any) {
	a.t.Helper()
	q := url.Values{"state": {state}, "code": {code}}
	var cs []*http.Cookie
	if cookie != nil {
		cs = append(cs, cookie)
	}
	w, body := a.do(http.MethodGet, "/oauth/callback?"+q.Encode(), "", nil, cs...)
	return w.Code, body
}

// install runs the whole OAuth flow for a member and returns the team.
func (a *p3sApp) install(bearer, team, teamName string) {
	a.t.Helper()
	state, cookie := a.startInstall(bearer)
	code := "code-" + uuid.NewString()[:8]
	a.fake.AddInstall(code, p3sClientID, slackapp.OAuthResult{AccessToken: "xoxb-" + team, TeamID: team, TeamName: teamName,
		BotUserID: "B" + team, Scope: slackapp.Scopes})
	if c, body := a.callback(state, code, cookie); c != http.StatusOK {
		a.t.Fatalf("callback: %d %v", c, body)
	}
}

// connectDirect stores an installation without the OAuth flow.
func (a *p3sApp) connectDirect(ws uuid.UUID, team, channel string, by uuid.UUID) {
	a.t.Helper()
	if err := a.vault.WriteSecret(services.SlackBotTokenPath(ws), map[string]interface{}{"token": "xoxb-" + team}); err != nil {
		a.t.Fatal(err)
	}
	p3exec(a.t, a.db, `INSERT INTO workspace_slack_integration (workspace_id, slack_team_id, slack_team_name, bot_token_ref, approvals_channel_id, installed_by)
		VALUES (?, ?, 'p3s', ?, ?, ?)`, ws, team, services.SlackBotTokenPath(ws), channel, by)
}

func (a *p3sApp) link(ws uuid.UUID, slackUser string, user uuid.UUID) {
	a.t.Helper()
	p3exec(a.t, a.db, `INSERT INTO slack_user_link (workspace_id, slack_user_id, user_id, linked_via) VALUES (?, ?, ?, 'verified_email')`, ws, slackUser, user)
}

/* ------------------------------ interactions ------------------------------- */

// p3sClick describes one button click.
type p3sClick struct {
	team, user, messageTS, action, value, actionTS string
	state                                          map[string]any
}

func (a *p3sApp) nextActionTS() string {
	n := a.seq.Add(1)
	return fmt.Sprintf("%d.%06d", time.Now().Unix(), n)
}

func p3sNote(text string) map[string]any {
	return map[string]any{slackapp.BlockNote: map[string]any{"value": map[string]any{"type": "plain_text_input", "value": text}}}
}

// body renders the form body Slack posts.
func (c p3sClick) body() []byte {
	payload := map[string]any{"type": "block_actions", "team": map[string]any{"id": c.team},
		"user":         map[string]any{"id": c.user, "team_id": c.team},
		"container":    map[string]any{"type": "message", "message_ts": c.messageTS, "channel_id": "C0"},
		"response_url": "https://hooks.slack.com/actions/" + c.team + "/1/p3s",
		"actions":      []any{map[string]any{"action_id": c.action, "value": c.value, "action_ts": c.actionTS, "type": "button"}},
		"state":        map[string]any{"values": c.state}}
	raw, _ := json.Marshal(payload)
	return []byte(url.Values{"payload": {string(raw)}}.Encode())
}

// post sends a raw interaction with explicit headers.
func (a *p3sApp) post(body []byte, ts, sig string) (int, map[string]any) {
	a.t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/authsec/integrations/slack/interactions", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if ts != "" {
		req.Header.Set(slackapp.HeaderTimestamp, ts)
	}
	if sig != "" {
		req.Header.Set(slackapp.HeaderSignature, sig)
	}
	w := httptest.NewRecorder()
	a.eng.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// signed sends body signed now with the app's secret; it returns the
// headers used so a replay can resend them.
func (a *p3sApp) signed(body []byte) (int, map[string]any, string, string) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := slackapp.Sign(p3sSigning, ts, body)
	code, out := a.post(body, ts, sig)
	return code, out, ts, sig
}

// click sends c (a fresh action_ts when empty), correctly signed.
func (a *p3sApp) click(c p3sClick) (int, map[string]any) {
	a.t.Helper()
	if c.actionTS == "" {
		c.actionTS = a.nextActionTS()
	}
	code, out, _, _ := a.signed(c.body())
	return code, out
}

// buttons maps a post's action ids to their values.
func p3sButtons(p slacktest.Post) map[string]string {
	out := map[string]string{}
	for _, b := range p.Message.Blocks {
		if b["type"] != "actions" {
			continue
		}
		for _, e := range b["elements"].([]any) {
			m := e.(map[string]any)
			v, _ := m["value"].(string)
			out[m["action_id"].(string)] = v
		}
	}
	return out
}

// p3sText is every text string of a message, joined.
func p3sText(m slackapp.Message) string {
	var out []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, y := range x {
				if s, ok := y.(string); ok && k == "text" {
					out = append(out, s)
				} else {
					walk(y)
				}
			}
		case []any:
			for _, y := range x {
				walk(y)
			}
		}
	}
	raw, _ := json.Marshal(m.Blocks)
	var blocks any
	_ = json.Unmarshal(raw, &blocks)
	walk(blocks)
	return m.Text + " | " + strings.Join(out, " | ")
}

// p3sEmail is a user's email.
func p3sEmail(t *testing.T, db *gorm.DB, user uuid.UUID) string {
	t.Helper()
	var e string
	if err := db.Raw(`SELECT email FROM users WHERE id = ?`, user).Row().Scan(&e); err != nil {
		t.Fatal(err)
	}
	return e
}

func p3sCount(t *testing.T, db *gorm.DB, q string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := db.Raw(q, args...).Scan(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

func p3sDetail(body map[string]any, key string) string {
	return digs(body, "error", "detail", key)
}

// p3sHealth is a fake T3.15 health reporter.
type p3sHealth struct{ got []services.GovHealthReport }

func (h *p3sHealth) ReportHealth(_ context.Context, r services.GovHealthReport) (any, error) {
	h.got = append(h.got, r)
	return map[string]any{"kind": r.Kind, "detail": r.Detail}, nil
}

// p3sCountEventually polls a count until it equals want (audit rows are
// written asynchronously by the audit logger) and returns the last value.
func p3sCountEventually(t *testing.T, db *gorm.DB, want int64, q string, args ...any) int64 {
	t.Helper()
	var n int64
	for i := 0; i < 100; i++ {
		n = p3sCount(t, db, q, args...)
		if n == want {
			return n
		}
		time.Sleep(20 * time.Millisecond)
	}
	return n
}
