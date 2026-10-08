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
//     {workspace, user, membership, sha256(nonce), expiry} HMAC-signed with
//     a key derived from the signing secret. GET /oauth/callback is Slack's
//     browser redirect (no bearer token), so "bound to workspace + session"
//     is checked as: the state's signature and 10-minute expiry; the
//     cookie's nonce matches the state (the browser that started the
//     install); the membership named in the state is still this user's,
//     active, in this workspace, and the user still holds
//     governance:enforce. The state is not stored, so single use rests on
//     Slack's single-use code and the cookie being cleared by the callback.
//   - Vault paths: the app at kv/data/secret/authsec/slack/app (override
//     AUTHSEC_SLACK_APP_VAULT_PATH); a workspace's bot token at
//     kv/data/secret/workspaces/<ws>/slack/bot (key "token"), which is the
//     row's bot_token_ref.
//   - Linking. A Slack user is linked to a member when Slack reports the
//     user's account email as confirmed (is_email_confirmed) and that email
//     names exactly one active member (MembersByEmail: ambiguous is
//     unmatched). Links are made after install (every active member looked
//     up by email, capped) and on demand when an unlinked Slack user acts.
//     Otherwise the Slack user is answered, ephemerally, with a link to the
//     console carrying a signed 24-hour token {workspace, team, slack
//     user}; POST /link/confirm by the signed-in member records a
//     console_confirmation link. The token reaches only that Slack user
//     (ephemeral response), so confirming it proves control of both
//     accounts.
//   - Disconnect revokes the token (auth.revoke, best effort), deletes it
//     from Vault, sets revoked_at and deletes the workspace's user links
//     (they are ids of the old team).
//   - Every mutation writes an iga_gov_event (slack.*) in its transaction;
//     the controller writes the audit_events row.

// Env and defaults.
const (
	SlackSigningSecretEnv = "AUTHSEC_SLACK_SIGNING_SECRET"
	SlackAppVaultPathEnv  = "AUTHSEC_SLACK_APP_VAULT_PATH"
	SlackRedirectURLEnv   = "AUTHSEC_SLACK_REDIRECT_URL"
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
	RedirectURL   string
}

// SlackConfigFromEnv reads the configuration; the redirect URL defaults to
// the console base URL + SlackCallbackPath.
func SlackConfigFromEnv() SlackConfig {
	c := SlackConfig{SigningSecret: strings.TrimSpace(os.Getenv(SlackSigningSecretEnv)),
		AppVaultPath: strings.TrimSpace(os.Getenv(SlackAppVaultPathEnv)), RedirectURL: strings.TrimSpace(os.Getenv(SlackRedirectURLEnv))}
	if c.RedirectURL == "" {
		c.RedirectURL = govConsoleLink(SlackCallbackPath)
	}
	return c
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
}

// NewSlackIntegrationService builds the service. vc and api must be
// non-nil and cfg.SigningSecret set for anything to work (Configured).
func NewSlackIntegrationService(db *gorm.DB, vc vault.VaultClient, api slackapp.API, cfg SlackConfig) *SlackIntegrationService {
	if cfg.AppVaultPath == "" {
		cfg.AppVaultPath = DefaultSlackAppPath
	}
	return &SlackIntegrationService{db: db, vault: vc, api: api, cfg: cfg, now: time.Now}
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
	E int64  `json:"e"`
}

// SlackInstallStart is GET /install's answer.
type SlackInstallStart struct {
	AuthorizeURL string    `json:"authorize_url"`
	ExpiresAt    time.Time `json:"expires_at"`
	// Nonce is set as the SlackInstallCookie by the controller; never in
	// the JSON.
	Nonce string `json:"-"`
}

// StartInstall begins an install for the member (actor, membership) of ws.
func (s *SlackIntegrationService) StartInstall(ctx context.Context, ws, actor, membership uuid.UUID) (*SlackInstallStart, error) {
	if err := s.mustConfigured(); err != nil {
		return nil, err
	}
	if s.cfg.RedirectURL == "" {
		return nil, slackErr(http.StatusServiceUnavailable, SlackCodeNotConfigured,
			"The Slack app has no redirect URL: set "+SlackRedirectURLEnv+" or the console base URL.", nil)
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
		N: nonceDigest(nonce), E: exp.Unix()})
	if err != nil {
		return nil, err
	}
	q := url.Values{"client_id": {clientID}, "scope": {slackapp.Scopes}, "state": {state}, "redirect_uri": {s.cfg.RedirectURL}}
	return &SlackInstallStart{AuthorizeURL: slackapp.AuthorizeURL + "?" + q.Encode(), ExpiresAt: exp, Nonce: nonce}, nil
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
	res, err := s.api.OAuthV2Access(ctx, clientID, clientSecret, code, s.cfg.RedirectURL)
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
		return appendGovEvent(tx, ws, GovEventSlackInstalled, models.GovActorUser, actor.String(), govEventRefs{}, map[string]any{
			"slack_team_id": res.TeamID, "slack_team_name": res.TeamName, "scopes": res.Scope, "reinstall": len(prev) == 1})
	})
	if err != nil {
		var ge *GovError
		if errors.As(err, &ge) && ge.Code == SlackCodeTeamBound && (out.Before == nil || out.Before.SlackTeamID != res.TeamID) {
			_ = s.vault.DeleteSecret(path)
		}
		return nil, err
	}
	n, err := s.SyncLinks(ctx, ws)
	if err != nil {
		log.Printf("[slack] workspace %s: linking members by email after install: %v", ws, err)
	}
	out.Linked = n
	return out, nil
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
		if derr := s.vault.DeleteSecret(before.BotTokenRef); derr != nil {
			log.Printf("[slack] workspace %s: deleting the bot token: %v", ws, derr)
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

func (s *SlackIntegrationService) insertLinkTx(tx *gorm.DB, ws uuid.UUID, slackUser string, user uuid.UUID, via string, actorKind, actorID string) (bool, error) {
	res := tx.Exec(`INSERT INTO slack_user_link (workspace_id, slack_user_id, user_id, linked_via) VALUES (?, ?, ?, ?)
		ON CONFLICT (workspace_id, slack_user_id) DO NOTHING`, ws, slackUser, user, via)
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
	return u != nil && u.ID != "" && !u.Deleted && !u.IsBot && u.IsEmailConfirmed &&
		(u.TeamID == "" || u.TeamID == team) && NormalizeMemberEmail(u.Email) == email
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
// the Slack user the token names is them.
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
	var out SlackLinkResult
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		in, err := activeSlackIntegration(tx, ws)
		if err != nil {
			return err
		}
		if in == nil || in.SlackTeamID != lt.T {
			return slackErr(http.StatusConflict, SlackCodeNotConnected, "That Slack workspace is no longer connected to this workspace.", nil)
		}
		var existing []models.SlackUserLink
		if err := tx.Where("workspace_id = ? AND slack_user_id = ?", ws, lt.S).Find(&existing).Error; err != nil {
			return err
		}
		if len(existing) == 1 {
			if existing[0].UserID != actor {
				return slackErr(http.StatusConflict, SlackCodeAlreadyLinked, "This Slack account is linked to another member.", nil)
			}
			out.Link = existing[0]
			return nil
		}
		if _, err := s.insertLinkTx(tx, ws, lt.S, actor, "console_confirmation", models.GovActorUser, actor.String()); err != nil {
			return err
		}
		return tx.Where("workspace_id = ? AND slack_user_id = ?", ws, lt.S).Take(&out.Link).Error
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// linkedUser maps a Slack user to a member: the link, else a link made now
// from a confirmed email naming exactly one active member.
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
	err = db.Transaction(func(tx *gorm.DB) error {
		_, e2 := s.insertLinkTx(tx, in.WorkspaceID, slackUser, member.UserID, "verified_email", models.GovActorSlackUser, slackUser)
		return e2
	})
	if err != nil {
		return uuid.Nil, err
	}
	return member.UserID, nil
}
