package services

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/slackapp"
	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/models"
)

// The AuthSec Slack app (SPEC-iga-phase3-policy.md §7.11, §7.12, §2.10, §10;
// requirement L-11; scenario A14; T3.14).
//
// One AuthSec Slack app serves every workspace (open item "Slack app
// distribution"): its signing secret is the env AUTHSEC_SLACK_SIGNING_SECRET,
// its OAuth client id and secret live in Vault (AUTHSEC_SLACK_APP_VAULT_PATH,
// keys client_id / client_secret). A workspace installs it once (OAuth v2);
// the bot token goes to Vault, the team to workspace_slack_integration (one
// live installation per Slack team: a team is bound to one workspace).
//
// This file: install (OAuth state bound to workspace + member + browser
// session), settings, disconnect, Slack user <-> member links. The
// interaction route is slack_integration_interactions.go; the notification
// channel slack_integration_channel.go.
//
// DECISIONS (T3.14):
//   - OAuth state binding. GET /install (an XHR from the console with the
//     member's bearer token) returns the Slack authorize URL and sets an
//     HttpOnly, SameSite=Lax cookie holding a random nonce; the state is
//     {workspace, user, membership, sha256(nonce), redirect URI, expiry}
//     HMAC-signed with a key derived from the signing secret. GET
//     /oauth/callback is Slack's browser redirect (no bearer token), so
//     "bound to workspace + session" is checked as: the state's signature
//     and 10-minute expiry; the cookie's nonce matches the state (the
//     browser that started the install); the membership named in the state
//     is still this user's, active, in this workspace, and the user still
//     holds governance:enforce. The state is not stored, so single use rests
//     on Slack's single-use code and the cookie being cleared by the
//     callback.
//   - Where the cookie goes (review fix, P2 Slack: "the OAuth nonce cookie
//     is host-only on the API host while the redirect defaults to the
//     console host"). The cookie is set by the answer to GET /install, i.e.
//     on the API host the console calls (VITE_API_URL), and a browser sends
//     it back only to a host the cookie domain-matches. So the redirect URI
//     is:
//       * AUTHSEC_SLACK_REDIRECT_URL when set (an operator's choice; it must
//         be registered in the Slack app); else
//       * https://<the host that served GET /install><SlackCallbackPath>:
//         the callback lands on the very host that set the cookie. It no
//         longer defaults to the console base URL, whose host does not
//         receive a cookie set by the API host.
//     The cookie is host-only unless AUTHSEC_SLACK_COOKIE_DOMAIN is set
//     (e.g. "authsec.ai": then every host under it receives it), and its
//     Path is the redirect URI's path. GET /install REFUSES (503
//     slack_not_configured, detail.reason redirect_cookie_mismatch) when the
//     redirect URI's host could not receive the cookie, so a mis-deployment
//     shows at the start of an install instead of as session_mismatch after
//     the user consented in Slack. DEPLOYMENT ASSUMPTION: the redirect URI
//     (by default https://<api host>/authsec/integrations/slack/oauth/callback)
//     is registered among the Slack app's Redirect URLs; that host routes
//     the path to this service with the browser's Host header preserved;
//     TLS is terminated in front of it (the cookie is Secure).
//   - Vault paths: the app at kv/data/secret/authsec/slack/app (override
//     AUTHSEC_SLACK_APP_VAULT_PATH); a workspace's bot token at
//     kv/data/secret/workspaces/<ws>/slack/bot (key "token"), which is the
//     row's bot_token_ref.
//   - Linking (review fix P0-3: "Slack linking bypasses separation of
//     duties"). A Slack user acts in AuthSec as the member it is linked to,
//     so a link must prove that the member owns the Slack account. The one
//     proof used is Slack's own: users.info, read with the bot token when
//     the link is made, reports the Slack account's email as confirmed
//     (is_email_confirmed) and that email equals the member's AuthSec
//     account email (users.email, the sign-in identity; AuthSec keeps no
//     separate email-verified flag). Nothing a person can forward or retype
//     proves ownership -- a console link and a one-time code DM'd by the bot
//     can both be handed to someone else -- so neither is accepted on its
//     own; that is why this design was chosen over a Slack round trip.
//       * Automatic: after install (every active member looked up by
//         email, capped) and when an unlinked Slack user acts, when the
//         confirmed email names exactly one active member.
//       * POST /link/confirm (§7.11: "confirm an ambiguous Slack <-> member
//         link"): when the confirmed email names several active members
//         (MembersByEmail never guesses), the unlinked Slack user is
//         answered, ephemerally, with a console link carrying a signed
//         24-hour token {workspace, team, slack user}. The signed-in member
//         who confirms it is linked ONLY if Slack, asked at that moment,
//         reports that Slack user's confirmed email as the member's own
//         email (else 403 slack_link_email_mismatch). A forwarded token is
//         useless to anyone else, and an author cannot bind their Slack
//         account to an approver.
//     A member holds at most one link per workspace (= per Slack team: a
//     workspace has one team, and its links are deleted when the team is
//     disconnected or replaced) and a Slack user maps to at most one member:
//     057's uq_slack_user_link_member and 054's primary key. /link/confirm
//     answers 409 slack_member_already_linked / slack_user_already_linked;
//     the automatic paths make no second link. 057 revoked every link the
//     old /link/confirm had made.
//   - Disconnect revokes the token (auth.revoke, best effort), DESTROYS it
//     in Vault (KV v2 metadata delete: every version, not the soft delete of
//     the latest one), sets revoked_at and deletes the workspace's user
//     links (they are ids of the old team). Reinstalling a workspace into
//     ANOTHER Slack team revokes the old team's token once the new
//     installation is committed; a reinstall that fails puts the previous
//     token back (and revokes the new token unless it is the same team's).
//   - Every mutation writes an iga_gov_event (slack.*) in its transaction;
//     the controller writes the audit_events row.

// Env and defaults.
const (
	SlackSigningSecretEnv = "AUTHSEC_SLACK_SIGNING_SECRET"
	SlackAppVaultPathEnv  = "AUTHSEC_SLACK_APP_VAULT_PATH"
	SlackRedirectURLEnv   = "AUTHSEC_SLACK_REDIRECT_URL"
	SlackCookieDomainEnv  = "AUTHSEC_SLACK_COOKIE_DOMAIN"
	DefaultSlackAppPath   = "kv/data/secret/authsec/slack/app"
	// SlackInstallCookie carries the install nonce (session binding).
	SlackInstallCookie = "authsec_slack_install"
	// SlackCallbackPath is the OAuth redirect path.
	SlackCallbackPath = "/authsec/integrations/slack/oauth/callback"
	// SlackRecipientApprovals is the recipient of a notice posted to the
	// workspace's approvals channel.
	SlackRecipientApprovals = "approvals_channel"

	slackStateTTL     = 10 * time.Minute
	slackLinkTokenTTL = 24 * time.Hour
	slackLinkSyncCap  = 1000
)

// Slack error codes (§7.12 plus the install/link codes this task needs).
const (
	SlackCodeSignatureInvalid = "slack_signature_invalid"
	SlackCodeUserNotLinked    = "slack_user_not_linked"
	SlackCodeNotConfigured    = "slack_not_configured"
	SlackCodeNotConnected     = "slack_not_connected"
	SlackCodeStateInvalid     = "slack_state_invalid"
	SlackCodeTeamBound        = "slack_team_bound_elsewhere"
	SlackCodeInstallFailed    = "slack_install_failed"
	SlackCodeLinkInvalid      = "slack_link_invalid"
	SlackCodeAlreadyLinked    = "slack_user_already_linked"
	// SlackCodeMemberLinked: the member already holds a Slack link in this
	// workspace (one link per member per Slack team).
	SlackCodeMemberLinked = "slack_member_already_linked"
	// SlackCodeLinkEmailMismatch: Slack does not report the Slack user's
	// confirmed email as the confirming member's email.
	SlackCodeLinkEmailMismatch = "slack_link_email_mismatch"
	// SlackCodeUnavailable: Slack could not be asked (users.info failed).
	SlackCodeUnavailable = "slack_unavailable"
)

// Event names (vocabulary: iga_gov_event_vocabulary.go).
const (
	GovEventSlackInstalled      = "slack.installed"
	GovEventSlackSettings       = "slack.settings_updated"
	GovEventSlackDisconnected   = "slack.disconnected"
	GovEventSlackUserLinked     = "slack.user_linked"
	GovEventSlackActionReceived = "slack.action_received"
)

// SlackConfig is the app's server configuration.
type SlackConfig struct {
	SigningSecret string
	AppVaultPath  string
	// RedirectURL is the OAuth redirect URI; "" derives it per install from
	// the host that served GET /install (DECISIONS above).
	RedirectURL string
	// CookieDomain is the install cookie's Domain attribute; "" makes it
	// host-only on the host that served GET /install.
	CookieDomain string
}

// SlackConfigFromEnv reads the configuration. An unset redirect URL is
// derived per install from the API host that served GET /install -- never
// the console base URL (DECISIONS above).
func SlackConfigFromEnv() SlackConfig {
	return SlackConfig{SigningSecret: strings.TrimSpace(os.Getenv(SlackSigningSecretEnv)),
		AppVaultPath: strings.TrimSpace(os.Getenv(SlackAppVaultPathEnv)), RedirectURL: strings.TrimSpace(os.Getenv(SlackRedirectURLEnv)),
		CookieDomain: os.Getenv(SlackCookieDomainEnv)}
}

// SlackIntegrationService is the Slack app's server side.
type SlackIntegrationService struct {
	db      *gorm.DB
	vault   vault.VaultClient
	api     slackapp.API
	cfg     SlackConfig
	live    LiveReader
	members WorkspaceMemberDirectory
	now     func() time.Time
	// Interactions run after Slack has been answered
	// (slack_integration_interactions.go): in flight, bounded, observed.
	inflight sync.WaitGroup
	slots    chan struct{}
	observer func(*SlackInteractionResult, error)
}

// NewSlackIntegrationService builds the service. vc and api must be
// non-nil and cfg.SigningSecret set for anything to work (Configured).
func NewSlackIntegrationService(db *gorm.DB, vc vault.VaultClient, api slackapp.API, cfg SlackConfig) *SlackIntegrationService {
	if cfg.AppVaultPath == "" {
		cfg.AppVaultPath = DefaultSlackAppPath
	}
	cfg.CookieDomain = strings.ToLower(strings.Trim(strings.TrimSpace(cfg.CookieDomain), "."))
	return &SlackIntegrationService{db: db, vault: vc, api: api, cfg: cfg, now: time.Now,
		slots: make(chan struct{}, slackInteractionWorkers)}
}

// WithClock sets the clock (tests: signature windows, token expiry).
func (s *SlackIntegrationService) WithClock(now func() time.Time) *SlackIntegrationService {
	s.now = now
	return s
}

// WithLiveReader gives the authoring service the interaction path builds a
// live reader (approval does not read AWS; set for completeness).
func (s *SlackIntegrationService) WithLiveReader(r LiveReader) *SlackIntegrationService {
	s.live = r
	return s
}

// Configured reports whether the app can run, and why not.
func (s *SlackIntegrationService) Configured() (bool, string) {
	switch {
	case s == nil:
		return false, "The Slack app is not configured on this server."
	case s.cfg.SigningSecret == "":
		return false, "The Slack app is not configured on this server: " + SlackSigningSecretEnv + " is not set."
	case s.vault == nil:
		return false, "The Slack app is not configured on this server: the secrets store (Vault) is not configured."
	case s.api == nil:
		return false, "The Slack app is not configured on this server: no Slack API client."
	}
	return true, ""
}

func (s *SlackIntegrationService) mustConfigured() error {
	if ok, reason := s.Configured(); !ok {
		return govErr(http.StatusServiceUnavailable, SlackCodeNotConfigured, reason, nil)
	}
	return nil
}

func slackErr(status int, code, msg string, detail map[string]any) *GovError {
	return govErr(status, code, msg, detail)
}

// derivedKey is HMAC(signing secret, purpose): one secret, separate keys
// for the OAuth state and link tokens.
func (s *SlackIntegrationService) derivedKey(purpose string) []byte {
	m := hmac.New(sha256.New, []byte(s.cfg.SigningSecret))
	m.Write([]byte("authsec.slack." + purpose + ".v1"))
	return m.Sum(nil)
}

func (s *SlackIntegrationService) signToken(purpose string, payload any) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(raw)
	m := hmac.New(sha256.New, s.derivedKey(purpose))
	m.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil)), nil
}

// openToken verifies a token from signToken (constant-time) and decodes it.
func (s *SlackIntegrationService) openToken(purpose, tok string, out any) bool {
	i := strings.IndexByte(tok, '.')
	if i <= 0 || i == len(tok)-1 {
		return false
	}
	body, sig := tok[:i], tok[i+1:]
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	m := hmac.New(sha256.New, s.derivedKey(purpose))
	m.Write([]byte(body))
	if !hmac.Equal(got, m.Sum(nil)) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return false
	}
	return json.Unmarshal(raw, out) == nil
}

func slackRandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func nonceDigest(nonce string) string {
	sum := sha256.Sum256([]byte("authsec.slack.install_nonce\x1f" + nonce))
	return hex.EncodeToString(sum[:])
}

// SlackBotTokenPath is a workspace's bot token path in Vault.
func SlackBotTokenPath(ws uuid.UUID) string {
	return fmt.Sprintf("kv/data/secret/workspaces/%s/slack/bot", ws)
}

func (s *SlackIntegrationService) appCredentials() (clientID, clientSecret string, err error) {
	sec, err := s.vault.ReadSecret(s.cfg.AppVaultPath)
	if err != nil {
		return "", "", slackErr(http.StatusServiceUnavailable, SlackCodeNotConfigured,
			"The Slack app's credentials are not in the secrets store.", nil)
	}
	clientID, _ = sec["client_id"].(string)
	clientSecret, _ = sec["client_secret"].(string)
	if clientID == "" || clientSecret == "" {
		return "", "", slackErr(http.StatusServiceUnavailable, SlackCodeNotConfigured,
			"The Slack app's client_id / client_secret are not in the secrets store.", nil)
	}
	return clientID, clientSecret, nil
}

// botToken reads an integration's bot token.
func (s *SlackIntegrationService) botToken(in *models.WorkspaceSlackIntegration) (string, error) {
	sec, err := s.vault.ReadSecret(in.BotTokenRef)
	if err != nil {
		return "", fmt.Errorf("slack bot token unreadable: %w", err)
	}
	t, _ := sec["token"].(string)
	if t == "" {
		return "", errors.New("slack bot token missing in the secrets store")
	}
	return t, nil
}

// activeSlackIntegration is the workspace's live installation, or nil.
func activeSlackIntegration(db *gorm.DB, ws uuid.UUID) (*models.WorkspaceSlackIntegration, error) {
	var rows []models.WorkspaceSlackIntegration
	if err := db.Where("workspace_id = ? AND revoked_at IS NULL", ws).Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

/* --------------------------------- install --------------------------------- */

type slackState struct {
	W string `json:"w"`
	U string `json:"u"`
	M string `json:"m"`
	N string `json:"n"`
	// R is the redirect URI the authorize request named (the code exchange
	// must repeat it); "" in states minted before it was recorded.
	R string `json:"r,omitempty"`
	E int64  `json:"e"`
}

// SlackInstallStart is GET /install's answer.
type SlackInstallStart struct {
	AuthorizeURL string    `json:"authorize_url"`
	RedirectURI  string    `json:"redirect_uri"`
	ExpiresAt    time.Time `json:"expires_at"`
	// Nonce is set as the SlackInstallCookie by the controller, with
	// CookieDomain ("" host-only) and CookiePath; never in the JSON.
	Nonce        string `json:"-"`
	CookieDomain string `json:"-"`
	CookiePath   string `json:"-"`
}

var slackHostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$`)

// slackCookieReaches reports whether a cookie set by a response from
// setter, with Domain domain ("" = host-only), is sent by a browser to
// target (hostnames, no port: cookies ignore ports).
func slackCookieReaches(setter, target, domain string) bool {
	setter, target, domain = strings.ToLower(setter), strings.ToLower(target), strings.ToLower(domain)
	if domain == "" {
		return setter != "" && setter == target
	}
	under := func(h string) bool { return h == domain || strings.HasSuffix(h, "."+domain) }
	return under(setter) && under(target)
}

// installRedirect is the redirect URI of an install started on installHost
// (the Host the browser sent GET /install to, where the cookie is set), and
// the cookie path; it refuses a redirect whose host would not receive the
// cookie (DECISIONS above).
func (s *SlackIntegrationService) installRedirect(installHost string) (redirect, cookiePath string, err error) {
	host := strings.ToLower(strings.TrimSpace(installHost))
	if !slackHostRe.MatchString(host) {
		return "", "", slackErr(http.StatusBadRequest, "invalid_parameter", "The request has no usable Host.", map[string]any{"parameter": "Host"})
	}
	raw := s.cfg.RedirectURL
	if raw == "" {
		raw = (&url.URL{Scheme: "https", Host: host, Path: SlackCallbackPath}).String()
	}
	u, perr := url.Parse(raw)
	if perr != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.RawQuery != "" || u.Fragment != "" {
		return "", "", slackErr(http.StatusServiceUnavailable, SlackCodeNotConfigured,
			"The Slack app's redirect URL ("+SlackRedirectURLEnv+") is not an absolute http(s) URL without query.", map[string]any{"reason": "redirect_invalid"})
	}
	setter := (&url.URL{Host: host}).Hostname()
	if !slackCookieReaches(setter, u.Hostname(), s.cfg.CookieDomain) {
		return "", "", slackErr(http.StatusServiceUnavailable, SlackCodeNotConfigured,
			"The Slack install cannot complete here: the browser would not send this host's install cookie to the redirect URL's host. Set "+
				SlackRedirectURLEnv+" to this API host's callback, or "+SlackCookieDomainEnv+" to a domain both hosts share.",
			map[string]any{"reason": "redirect_cookie_mismatch", "install_host": setter, "redirect_host": u.Hostname(), "cookie_domain": s.cfg.CookieDomain})
	}
	cookiePath = u.EscapedPath()
	if cookiePath == "" {
		cookiePath = "/"
	}
	return u.String(), cookiePath, nil
}

// StartInstall begins an install for the member (actor, membership) of ws;
// installHost is the Host the browser sent GET /install to.
func (s *SlackIntegrationService) StartInstall(ctx context.Context, ws, actor, membership uuid.UUID, installHost string) (*SlackInstallStart, error) {
	if err := s.mustConfigured(); err != nil {
		return nil, err
	}
	redirect, cookiePath, err := s.installRedirect(installHost)
	if err != nil {
		return nil, err
	}
	clientID, _, err := s.appCredentials()
	if err != nil {
		return nil, err
	}
	nonce, err := slackRandomToken(32)
	if err != nil {
		return nil, err
	}
	exp := s.now().Add(slackStateTTL)
	state, err := s.signToken("oauth_state", slackState{W: ws.String(), U: actor.String(), M: membership.String(),
		N: nonceDigest(nonce), R: redirect, E: exp.Unix()})
	if err != nil {
		return nil, err
	}
	q := url.Values{"client_id": {clientID}, "scope": {slackapp.Scopes}, "state": {state}, "redirect_uri": {redirect}}
	return &SlackInstallStart{AuthorizeURL: slackapp.AuthorizeURL + "?" + q.Encode(), RedirectURI: redirect, ExpiresAt: exp,
		Nonce: nonce, CookieDomain: s.cfg.CookieDomain, CookiePath: cookiePath}, nil
}

// CallbackCookieScope is the Domain and Path of the install cookie a
// callback carrying state must clear: from the state's (signed) redirect
// URI, else the defaults.
func (s *SlackIntegrationService) CallbackCookieScope(state string) (domain, path string) {
	path = SlackCallbackPath
	var st slackState
	if s != nil && state != "" && s.openToken("oauth_state", state, &st) && st.R != "" {
		if u, err := url.Parse(st.R); err == nil && u.EscapedPath() != "" {
			path = u.EscapedPath()
		}
	}
	if s != nil {
		domain = s.cfg.CookieDomain
	}
	return domain, path
}

// SlackInstallResult is a completed install.
type SlackInstallResult struct {
	WorkspaceID uuid.UUID                         `json:"workspace_id"`
	ActorID     uuid.UUID                         `json:"-"`
	Before      *models.WorkspaceSlackIntegration `json:"-"`
	Integration models.WorkspaceSlackIntegration  `json:"integration"`
	Linked      int                               `json:"linked_users"`
}

func stateRefused(reason string) *GovError {
	return slackErr(http.StatusForbidden, SlackCodeStateInvalid,
		"This Slack install link is not valid for this browser session; start the install again from AuthSec.",
		map[string]any{"reason": reason})
}

// CompleteInstall is GET /oauth/callback: verify the state against the
// cookie nonce and the member, exchange the code, store the token in Vault
// and the team on the workspace.
func (s *SlackIntegrationService) CompleteInstall(ctx context.Context, state, cookieNonce, code string) (*SlackInstallResult, error) {
	if err := s.mustConfigured(); err != nil {
		return nil, err
	}
	var st slackState
	if state == "" || !s.openToken("oauth_state", state, &st) {
		return nil, stateRefused("state_signature")
	}
	if s.now().Unix() > st.E {
		return nil, stateRefused("state_expired")
	}
	if cookieNonce == "" || !hmac.Equal([]byte(nonceDigest(cookieNonce)), []byte(st.N)) {
		return nil, stateRefused("session_mismatch")
	}
	ws, err1 := uuid.Parse(st.W)
	actor, err2 := uuid.Parse(st.U)
	membership, err3 := uuid.Parse(st.M)
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, stateRefused("state_payload")
	}
	db := s.db.WithContext(ctx)
	var live int64
	if err := db.Raw(`SELECT count(*) FROM workspace_memberships WHERE id = ? AND workspace_id = ? AND user_id = ? AND status = 'active'`,
		membership, ws, actor).Scan(&live).Error; err != nil {
		return nil, err
	}
	if live == 0 {
		return nil, stateRefused("membership_not_active")
	}
	if ok, err := WorkspaceUserHoldsPermission(db, ws, actor, "governance", "enforce"); err != nil {
		return nil, err
	} else if !ok {
		return nil, stateRefused("permission_revoked")
	}
	if strings.TrimSpace(code) == "" {
		return nil, GovBadParam("code", "Slack returned no authorization code.")
	}
	clientID, clientSecret, err := s.appCredentials()
	if err != nil {
		return nil, err
	}
	redirect := st.R
	if redirect == "" {
		redirect = s.cfg.RedirectURL
	}
	res, err := s.api.OAuthV2Access(ctx, clientID, clientSecret, code, redirect)
	if err != nil {
		log.Printf("[slack] workspace %s: oauth.v2.access failed: %v", ws, err)
		return nil, slackErr(http.StatusBadGateway, SlackCodeInstallFailed, "Slack did not complete the install; try again.", nil)
	}
	if res.AccessToken == "" || res.TeamID == "" {
		return nil, slackErr(http.StatusBadGateway, SlackCodeInstallFailed, "Slack returned no bot token.", nil)
	}
	// A Slack team is bound to one workspace (§10).
	var other []models.WorkspaceSlackIntegration
	if err := db.Where("slack_team_id = ? AND revoked_at IS NULL AND workspace_id <> ?", res.TeamID, ws).Limit(1).Find(&other).Error; err != nil {
		return nil, err
	}
	if len(other) > 0 {
		return nil, slackErr(http.StatusConflict, SlackCodeTeamBound,
			"This Slack workspace is already connected to another AuthSec workspace; disconnect it there first.", nil)
	}
	path := SlackBotTokenPath(ws)
	// The token of the installation being replaced: put back if this
	// install fails; revoked once the new one is committed when it was
	// another team's.
	var prevSecret map[string]interface{}
	prevToken, prevTeam := "", ""
	if cur, err := activeSlackIntegration(db, ws); err != nil {
		return nil, err
	} else if cur != nil && cur.BotTokenRef != "" {
		prevTeam = cur.SlackTeamID
		if sec, rerr := s.vault.ReadSecret(cur.BotTokenRef); rerr == nil {
			prevSecret = sec
			prevToken, _ = sec["token"].(string)
		}
	}
	// DECISION: only a team change revokes. For the same team Slack keeps
	// one bot installation (a reinstall normally returns the same token);
	// auth.revoke of a token of a live installation could uninstall the app
	// the new token belongs to.
	teamChanged := prevTeam != "" && prevTeam != res.TeamID
	if err := s.vault.WriteSecret(path, map[string]interface{}{"token": res.AccessToken, "team_id": res.TeamID,
		"bot_user_id": res.BotUserID, "scope": res.Scope}); err != nil {
		log.Printf("[slack] workspace %s: storing the bot token failed: %v", ws, err)
		return nil, slackErr(http.StatusServiceUnavailable, SlackCodeNotConfigured, "AuthSec could not store the Slack token; try again shortly.", nil)
	}
	out := &SlackInstallResult{WorkspaceID: ws, ActorID: actor}
	err = db.Transaction(func(tx *gorm.DB) error {
		var prev []models.WorkspaceSlackIntegration
		if err := tx.Raw(`SELECT * FROM workspace_slack_integration WHERE workspace_id = ? FOR UPDATE`, ws).Scan(&prev).Error; err != nil {
			return err
		}
		if len(prev) == 1 {
			p := prev[0]
			out.Before = &p
			if p.RevokedAt == nil && p.SlackTeamID != res.TeamID {
				// Another team replaces this one: the old team's links go.
				if err := tx.Exec(`DELETE FROM slack_user_link WHERE workspace_id = ?`, ws).Error; err != nil {
					return err
				}
			}
		}
		channel := ""
		if len(prev) == 1 && prev[0].SlackTeamID == res.TeamID {
			channel = prev[0].ApprovalsChannelID
		}
		var rows []models.WorkspaceSlackIntegration
		if err := tx.Raw(`INSERT INTO workspace_slack_integration (workspace_id, slack_team_id, slack_team_name, bot_token_ref, approvals_channel_id, installed_by, installed_at, revoked_at)
			VALUES (?, ?, ?, ?, ?, ?, now(), NULL)
			ON CONFLICT (workspace_id) DO UPDATE SET slack_team_id = EXCLUDED.slack_team_id, slack_team_name = EXCLUDED.slack_team_name,
			  bot_token_ref = EXCLUDED.bot_token_ref, approvals_channel_id = EXCLUDED.approvals_channel_id,
			  installed_by = EXCLUDED.installed_by, installed_at = now(), revoked_at = NULL
			RETURNING *`, ws, res.TeamID, res.TeamName, path, channel, actor).Scan(&rows).Error; err != nil {
			if isUniqueViolation(err, "uq_workspace_slack_team") {
				return slackErr(http.StatusConflict, SlackCodeTeamBound,
					"This Slack workspace is already connected to another AuthSec workspace; disconnect it there first.", nil)
			}
			return err
		}
		out.Integration = rows[0]
		payload := map[string]any{"slack_team_id": res.TeamID, "slack_team_name": res.TeamName, "scopes": res.Scope, "reinstall": len(prev) == 1,
			"previous_token_revoked": teamChanged && prevToken != "" && prevToken != res.AccessToken}
		if len(prev) == 1 && prev[0].RevokedAt == nil && prev[0].SlackTeamID != res.TeamID {
			payload["replaced_slack_team_id"] = prev[0].SlackTeamID
		}
		return appendGovEvent(tx, ws, GovEventSlackInstalled, models.GovActorUser, actor.String(), govEventRefs{}, payload)
	})
	if err != nil {
		// The new token is stored nowhere now: revoke it, unless it may be
		// the still-active installation's own (same team).
		s.undoTokenWrite(ctx, ws, path, prevSecret, res.AccessToken, prevTeam == "" || teamChanged)
		return nil, err
	}
	// The replaced team's token is dead from now on: revoke it at Slack.
	if teamChanged && prevToken != "" && prevToken != res.AccessToken {
		if rerr := s.api.AuthRevoke(ctx, prevToken); rerr != nil {
			log.Printf("[slack] workspace %s: auth.revoke of the replaced token: %v", ws, rerr)
		}
	}
	n, err := s.SyncLinks(ctx, ws)
	if err != nil {
		log.Printf("[slack] workspace %s: linking members by email after install: %v", ws, err)
	}
	out.Linked = n
	return out, nil
}

// undoTokenWrite undoes the Vault write of an install whose transaction
// failed: the previous installation's secret is written back (it is again
// the current version), or, with none, the path is destroyed; the new token
// is revoked when revokeNew.
func (s *SlackIntegrationService) undoTokenWrite(ctx context.Context, ws uuid.UUID, path string, prevSecret map[string]interface{}, newToken string, revokeNew bool) {
	if prevSecret != nil {
		if err := s.vault.WriteSecret(path, prevSecret); err != nil {
			log.Printf("[slack] workspace %s: restoring the previous bot token after a failed install: %v", ws, err)
		}
	} else if _, err := vault.Destroy(s.vault, path); err != nil {
		log.Printf("[slack] workspace %s: removing the bot token of a failed install: %v", ws, err)
	}
	if revokeNew && newToken != "" {
		if err := s.api.AuthRevoke(ctx, newToken); err != nil {
			log.Printf("[slack] workspace %s: auth.revoke of a failed install's token: %v", ws, err)
		}
	}
}

/* ------------------------------ settings, disconnect ----------------------- */

var slackChannelRe = regexp.MustCompile(`^[CG][A-Z0-9]{2,30}$`)

// SlackSettingsInput is PUT /settings.
type SlackSettingsInput struct {
	ApprovalsChannelID string `json:"approvals_channel_id"`
}

// UpdateSettings sets the approvals channel (a Slack channel id; "" clears it).
func (s *SlackIntegrationService) UpdateSettings(ctx context.Context, ws, actor uuid.UUID, in SlackSettingsInput) (before, after *models.WorkspaceSlackIntegration, err error) {
	ch := strings.TrimSpace(in.ApprovalsChannelID)
	if ch != "" && !slackChannelRe.MatchString(ch) {
		return nil, nil, GovBadParam("approvals_channel_id", "approvals_channel_id must be a Slack channel id (C… or G…).")
	}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var rows []models.WorkspaceSlackIntegration
		if err := tx.Raw(`SELECT * FROM workspace_slack_integration WHERE workspace_id = ? AND revoked_at IS NULL FOR UPDATE`, ws).Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return slackErr(http.StatusConflict, SlackCodeNotConnected, "Slack is not connected to this workspace.", nil)
		}
		b := rows[0]
		before = &b
		if err := tx.Exec(`UPDATE workspace_slack_integration SET approvals_channel_id = ? WHERE workspace_id = ?`, ch, ws).Error; err != nil {
			return err
		}
		a := b
		a.ApprovalsChannelID = ch
		after = &a
		return appendGovEvent(tx, ws, GovEventSlackSettings, models.GovActorUser, actor.String(), govEventRefs{}, map[string]any{
			"approvals_channel_id": ch, "previous_approvals_channel_id": b.ApprovalsChannelID})
	})
	return before, after, err
}

// Disconnect removes the installation (DELETE /).
func (s *SlackIntegrationService) Disconnect(ctx context.Context, ws, actor uuid.UUID) (before *models.WorkspaceSlackIntegration, err error) {
	var token string
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var rows []models.WorkspaceSlackIntegration
		if err := tx.Raw(`SELECT * FROM workspace_slack_integration WHERE workspace_id = ? AND revoked_at IS NULL FOR UPDATE`, ws).Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return GovNotFound()
		}
		b := rows[0]
		before = &b
		if s.vault != nil {
			token, _ = s.botToken(&b)
		}
		var links int64
		if err := tx.Raw(`SELECT count(*) FROM slack_user_link WHERE workspace_id = ?`, ws).Scan(&links).Error; err != nil {
			return err
		}
		if err := tx.Exec(`UPDATE workspace_slack_integration SET revoked_at = now() WHERE workspace_id = ?`, ws).Error; err != nil {
			return err
		}
		if err := tx.Exec(`DELETE FROM slack_user_link WHERE workspace_id = ?`, ws).Error; err != nil {
			return err
		}
		return appendGovEvent(tx, ws, GovEventSlackDisconnected, models.GovActorUser, actor.String(), govEventRefs{}, map[string]any{
			"slack_team_id": b.SlackTeamID, "links_removed": links})
	})
	if err != nil {
		return nil, err
	}
	if token != "" && s.api != nil {
		if rerr := s.api.AuthRevoke(ctx, token); rerr != nil {
			log.Printf("[slack] workspace %s: auth.revoke on disconnect: %v", ws, rerr)
		}
	}
	if s.vault != nil && before.BotTokenRef != "" {
		// Destroy, not a soft delete: no version of the token may stay
		// recoverable from Vault after a disconnect.
		destroyed, derr := vault.Destroy(s.vault, before.BotTokenRef)
		switch {
		case derr != nil:
			log.Printf("[slack] workspace %s: destroying the bot token: %v", ws, derr)
		case !destroyed:
			log.Printf("[slack] workspace %s: the secrets store can only soft-delete the bot token at %s", ws, before.BotTokenRef)
		}
	}
	return before, nil
}

// SlackStatusView is the Slack part of GET /policy/settings notifications.
type SlackStatusView struct {
	Connected          bool       `json:"connected"`
	TeamName           string     `json:"team_name,omitempty"`
	ApprovalsChannelID string     `json:"approvals_channel_id,omitempty"`
	InstalledAt        *time.Time `json:"installed_at,omitempty"`
	LinkedUsers        int64      `json:"linked_users"`
}

// slackStatusFor reads a workspace's Slack status for the settings view.
func slackStatusFor(db *gorm.DB, ws uuid.UUID) *SlackStatusView {
	in, err := activeSlackIntegration(db, ws)
	if err != nil || in == nil {
		return &SlackStatusView{}
	}
	v := &SlackStatusView{Connected: true, TeamName: in.SlackTeamName, ApprovalsChannelID: in.ApprovalsChannelID}
	t := in.InstalledAt
	v.InstalledAt = &t
	db.Raw(`SELECT count(*) FROM slack_user_link WHERE workspace_id = ?`, ws).Scan(&v.LinkedUsers)
	return v
}

/* ---------------------------------- links ---------------------------------- */

// insertLinkTx links slackUser to user unless the Slack user is linked
// already, or the member already holds a link (one per member: 057); it
// reports whether it made the link.
func (s *SlackIntegrationService) insertLinkTx(tx *gorm.DB, ws uuid.UUID, slackUser string, user uuid.UUID, via string, actorKind, actorID string) (bool, error) {
	var held int64
	if err := tx.Raw(`SELECT count(*) FROM slack_user_link WHERE workspace_id = ? AND user_id = ? AND slack_user_id <> ?`, ws, user, slackUser).
		Scan(&held).Error; err != nil {
		return false, err
	}
	if held > 0 {
		return false, nil
	}
	// No conflict target: either unique key (the Slack user's, 054; the
	// member's, 057) makes a concurrent second link a no-op.
	res := tx.Exec(`INSERT INTO slack_user_link (workspace_id, slack_user_id, user_id, linked_via) VALUES (?, ?, ?, ?)
		ON CONFLICT DO NOTHING`, ws, slackUser, user, via)
	if res.Error != nil {
		return false, res.Error
	}
	if res.RowsAffected == 0 {
		return false, nil
	}
	return true, appendGovEvent(tx, ws, GovEventSlackUserLinked, actorKind, actorID, govEventRefs{}, map[string]any{
		"slack_user_id": slackUser, "user_id": user, "linked_via": via})
}

// SyncLinks links every active member Slack finds by a confirmed account
// email (capped at slackLinkSyncCap members). It returns how many links it
// made.
func (s *SlackIntegrationService) SyncLinks(ctx context.Context, ws uuid.UUID) (int, error) {
	db := s.db.WithContext(ctx)
	in, err := activeSlackIntegration(db, ws)
	if err != nil || in == nil {
		return 0, err
	}
	token, err := s.botToken(in)
	if err != nil {
		return 0, err
	}
	var members []WorkspaceMember
	if err := db.Raw(activeMemberSQL+` ORDER BY u.id LIMIT ?`, ws, slackLinkSyncCap).Scan(&members).Error; err != nil {
		return 0, err
	}
	byEmail := map[string]int{}
	for _, m := range members {
		byEmail[NormalizeMemberEmail(m.Email)]++
	}
	made := 0
	for _, m := range members {
		e := NormalizeMemberEmail(m.Email)
		if e == "" || byEmail[e] != 1 {
			continue // ambiguous: never a guess
		}
		u, err := s.api.LookupByEmail(ctx, token, m.Email)
		if err != nil {
			if !slackapp.IsAPIError(err, "users_not_found") {
				log.Printf("[slack] workspace %s: users.lookupByEmail: %v", ws, err)
			}
			continue
		}
		if !slackUserLinkable(u, in.SlackTeamID, e) {
			continue
		}
		var ok bool
		err = db.Transaction(func(tx *gorm.DB) error {
			var e2 error
			ok, e2 = s.insertLinkTx(tx, ws, u.ID, m.UserID, "verified_email", models.GovActorSystem, "slack-link-sync")
			return e2
		})
		if err != nil {
			return made, err
		}
		if ok {
			made++
		}
	}
	return made, nil
}

// slackUserLinkable: a real, current user of the team whose Slack account
// email is confirmed and equals email.
func slackUserLinkable(u *slackapp.User, team, email string) bool {
	return slackLinkRefusal(u, team, email) == ""
}

// slackLinkRefusal is why u cannot be linked to the member whose email is
// email ("" when it can): the only proof of ownership is Slack's confirmed
// account email being the member's.
func slackLinkRefusal(u *slackapp.User, team, email string) string {
	switch {
	case u == nil || u.ID == "" || u.Deleted || u.IsBot:
		return "slack_user_unusable"
	case u.TeamID != "" && u.TeamID != team:
		return "other_team"
	case !u.IsEmailConfirmed:
		return "email_unconfirmed"
	case email == "" || NormalizeMemberEmail(u.Email) != email:
		return "email_mismatch"
	}
	return ""
}

type slackLinkToken struct {
	W string `json:"w"`
	T string `json:"t"`
	S string `json:"s"`
	E int64  `json:"e"`
}

// LinkURL is the console link an unlinked Slack user is sent to.
func (s *SlackIntegrationService) LinkURL(ws uuid.UUID, team, slackUser string) (string, string) {
	tok, err := s.signToken("link", slackLinkToken{W: ws.String(), T: team, S: slackUser, E: s.now().Add(slackLinkTokenTTL).Unix()})
	if err != nil {
		return "", ""
	}
	return govConsoleLink("/iga/policy/setup/notifications?slack_link=" + url.QueryEscape(tok)), tok
}

// SlackLinkResult is POST /link/confirm's answer.
type SlackLinkResult struct {
	Link models.SlackUserLink `json:"link"`
}

// ConfirmLink is POST /link/confirm {token}: the signed-in member confirms
// that the Slack user the token names is them. The token only says which
// Slack user to look at -- it proves nothing, since it can be forwarded:
// the link is made only when Slack, asked now, reports that Slack user's
// confirmed account email as the member's own (DECISIONS above, P0-3).
func (s *SlackIntegrationService) ConfirmLink(ctx context.Context, ws, actor uuid.UUID, token string) (*SlackLinkResult, error) {
	if err := s.mustConfigured(); err != nil {
		return nil, err
	}
	var lt slackLinkToken
	if token == "" || !s.openToken("link", token, &lt) || s.now().Unix() > lt.E {
		return nil, slackErr(http.StatusBadRequest, SlackCodeLinkInvalid, "This Slack link is not valid or has expired; use Link in Slack again.", nil)
	}
	if lt.W != ws.String() {
		// Another workspace's token: the same answer as an absent object.
		return nil, GovNotFound()
	}
	db := s.db.WithContext(ctx)
	in, err := activeSlackIntegration(db, ws)
	if err != nil {
		return nil, err
	}
	if in == nil || in.SlackTeamID != lt.T {
		return nil, slackErr(http.StatusConflict, SlackCodeNotConnected, "That Slack workspace is no longer connected to this workspace.", nil)
	}
	m, err := s.members.ActiveMembers(db, ws, []uuid.UUID{actor})
	if err != nil {
		return nil, err
	}
	member, ok := m[actor]
	if !ok {
		return nil, govErr(http.StatusForbidden, "forbidden", "Only an active member of this workspace can link a Slack account.", nil)
	}
	bot, err := s.botToken(in)
	if err != nil {
		log.Printf("[slack] workspace %s: link confirmation: %v", ws, err)
		return nil, slackErr(http.StatusBadGateway, SlackCodeUnavailable, "AuthSec could not ask Slack about this account; try again shortly.", nil)
	}
	u, err := s.api.UsersInfo(ctx, bot, lt.S)
	if err != nil {
		log.Printf("[slack] workspace %s: users.info %s for a link confirmation: %v", ws, lt.S, err)
		return nil, slackErr(http.StatusBadGateway, SlackCodeUnavailable, "AuthSec could not ask Slack about this account; try again shortly.", nil)
	}
	if reason := slackLinkRefusal(u, in.SlackTeamID, NormalizeMemberEmail(member.Email)); reason != "" {
		return nil, slackErr(http.StatusForbidden, SlackCodeLinkEmailMismatch,
			"This Slack account can be linked only by the member whose AuthSec email is the Slack account's confirmed email.",
			map[string]any{"reason": reason})
	}
	var out SlackLinkResult
	err = db.Transaction(func(tx *gorm.DB) error {
		var existing []models.SlackUserLink
		if err := tx.Raw(`SELECT * FROM slack_user_link WHERE workspace_id = ? AND (slack_user_id = ? OR user_id = ?) FOR UPDATE`,
			ws, lt.S, actor).Scan(&existing).Error; err != nil {
			return err
		}
		for _, l := range existing {
			if l.SlackUserID == lt.S {
				if l.UserID != actor {
					return slackErr(http.StatusConflict, SlackCodeAlreadyLinked, "This Slack account is linked to another member.", nil)
				}
				out.Link = l
				return nil
			}
		}
		if len(existing) > 0 {
			return slackErr(http.StatusConflict, SlackCodeMemberLinked,
				"You already have a Slack account linked in this workspace; one Slack account per member.", nil)
		}
		made, err := s.insertLinkTx(tx, ws, lt.S, actor, "console_confirmation", models.GovActorUser, actor.String())
		if err != nil {
			return err
		}
		if !made { // a concurrent link took the Slack user or the member
			return slackErr(http.StatusConflict, SlackCodeAlreadyLinked, "This Slack account or member was linked meanwhile; reload.", nil)
		}
		return tx.Where("workspace_id = ? AND slack_user_id = ?", ws, lt.S).Take(&out.Link).Error
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// linkedUser maps a Slack user to a member: the link, else a link made now
// from a confirmed email naming exactly one active member who holds no
// other link.
func (s *SlackIntegrationService) linkedUser(ctx context.Context, in *models.WorkspaceSlackIntegration, slackUser string) (uuid.UUID, error) {
	db := s.db.WithContext(ctx)
	var links []models.SlackUserLink
	if err := db.Where("workspace_id = ? AND slack_user_id = ?", in.WorkspaceID, slackUser).Limit(1).Find(&links).Error; err != nil {
		return uuid.Nil, err
	}
	if len(links) == 1 {
		return links[0].UserID, nil
	}
	token, err := s.botToken(in)
	if err != nil {
		return uuid.Nil, nil
	}
	u, err := s.api.UsersInfo(ctx, token, slackUser)
	if err != nil {
		log.Printf("[slack] workspace %s: users.info %s: %v", in.WorkspaceID, slackUser, err)
		return uuid.Nil, nil
	}
	e := NormalizeMemberEmail(u.Email)
	if e == "" || !slackUserLinkable(u, in.SlackTeamID, e) {
		return uuid.Nil, nil
	}
	m, err := s.members.MembersByEmail(db, in.WorkspaceID, []string{e})
	if err != nil {
		return uuid.Nil, err
	}
	member, ok := m[e]
	if !ok {
		return uuid.Nil, nil // none, or ambiguous: console confirmation
	}
	made := false
	err = db.Transaction(func(tx *gorm.DB) error {
		var e2 error
		made, e2 = s.insertLinkTx(tx, in.WorkspaceID, slackUser, member.UserID, "verified_email", models.GovActorSlackUser, slackUser)
		return e2
	})
	if err != nil {
		return uuid.Nil, err
	}
	if !made {
		// Linked meanwhile (read it back), or the member holds another
		// Slack link (one per member): this Slack user stays unlinked.
		links = nil
		if err := db.Where("workspace_id = ? AND slack_user_id = ?", in.WorkspaceID, slackUser).Limit(1).Find(&links).Error; err != nil {
			return uuid.Nil, err
		}
		if len(links) == 1 {
			return links[0].UserID, nil
		}
		return uuid.Nil, nil
	}
	return member.UserID, nil
}
