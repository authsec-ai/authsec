package slackapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Scopes are the bot scopes AuthSec asks for (§10 "Slack token leak":
// chat:write, users:read, users:read.email; nothing else).
const Scopes = "chat:write,users:read,users:read.email"

// AuthorizeURL is Slack's OAuth v2 authorize endpoint.
const AuthorizeURL = "https://slack.com/oauth/v2/authorize"

// OAuthResult is what oauth.v2.access returns for a bot install.
type OAuthResult struct {
	AccessToken string
	TokenType   string
	Scope       string
	BotUserID   string
	AppID       string
	TeamID      string
	TeamName    string
}

// User is a Slack user (users.info / users.lookupByEmail).
type User struct {
	ID               string
	TeamID           string
	Name             string
	RealName         string
	Email            string
	IsEmailConfirmed bool
	Deleted          bool
	IsBot            bool
}

// APIError is a Slack Web API error ("ok": false), e.g. not_in_channel,
// users_not_found, invalid_auth.
type APIError struct {
	Method string
	Code   string
}

func (e *APIError) Error() string { return "slack " + e.Method + ": " + e.Code }

// IsAPIError reports whether err is a Slack error with one of codes.
func IsAPIError(err error, codes ...string) bool {
	var ae *APIError
	if !errors.As(err, &ae) {
		return false
	}
	for _, c := range codes {
		if ae.Code == c {
			return true
		}
	}
	return false
}

// API is the Slack Web API AuthSec uses. HTTPAPI is the production
// implementation; slacktest.Fake the tests'. No other code calls Slack.
type API interface {
	// OAuthV2Access exchanges an install code for the bot token.
	OAuthV2Access(ctx context.Context, clientID, clientSecret, code, redirectURI string) (*OAuthResult, error)
	// PostMessage posts msg to channel (a channel id, or a user id for the
	// app's DM) and returns the message ts and the channel it landed in.
	PostMessage(ctx context.Context, token, channel string, msg Message) (ts, ch string, err error)
	// UsersInfo reads one user.
	UsersInfo(ctx context.Context, token, userID string) (*User, error)
	// LookupByEmail finds the user with this account email (users_not_found
	// when none).
	LookupByEmail(ctx context.Context, token, email string) (*User, error)
	// Respond posts msg to an interaction's response_url.
	Respond(ctx context.Context, responseURL string, msg Message) error
	// AuthRevoke revokes a token (disconnect).
	AuthRevoke(ctx context.Context, token string) error
}

// HTTPAPI calls https://slack.com/api.
type HTTPAPI struct {
	Client  *http.Client
	BaseURL string // default https://slack.com/api
	// ResponseHosts are the hosts a response_url may name (default
	// hooks.slack.com): a response_url comes from a signed payload, but it is
	// still a URL AuthSec posts to, so it is pinned.
	ResponseHosts []string
}

// NewHTTPAPI is the production client (10 s timeout).
func NewHTTPAPI() *HTTPAPI {
	return &HTTPAPI{Client: &http.Client{Timeout: 10 * time.Second}}
}

func (h *HTTPAPI) base() string {
	if h.BaseURL != "" {
		return strings.TrimRight(h.BaseURL, "/")
	}
	return "https://slack.com/api"
}

func (h *HTTPAPI) client() *http.Client {
	if h.Client != nil {
		return h.Client
	}
	return http.DefaultClient
}

// call performs one Web API method and decodes the JSON answer into out
// after checking "ok".
func (h *HTTPAPI) call(ctx context.Context, method, token string, form url.Values, jsonBody any, out any) error {
	var req *http.Request
	var err error
	u := h.base() + "/" + method
	if jsonBody != nil {
		raw, merr := json.Marshal(jsonBody)
		if merr != nil {
			return merr
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(raw))
		if err == nil {
			req.Header.Set("Content-Type", "application/json; charset=utf-8")
		}
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := h.client().Do(req)
	if err != nil {
		return fmt.Errorf("slack %s: %w", method, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("slack %s: %w", method, err)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return &APIError{Method: method, Code: "ratelimited"}
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("slack %s: HTTP %d", method, resp.StatusCode)
	}
	var head struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return fmt.Errorf("slack %s: %w", method, err)
	}
	if !head.OK {
		code := head.Error
		if code == "" {
			code = "unknown_error"
		}
		return &APIError{Method: method, Code: code}
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// OAuthV2Access implements API.
func (h *HTTPAPI) OAuthV2Access(ctx context.Context, clientID, clientSecret, code, redirectURI string) (*OAuthResult, error) {
	form := url.Values{"client_id": {clientID}, "client_secret": {clientSecret}, "code": {code}}
	if redirectURI != "" {
		form.Set("redirect_uri", redirectURI)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
		BotUserID   string `json:"bot_user_id"`
		AppID       string `json:"app_id"`
		Team        struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"team"`
	}
	if err := h.call(ctx, "oauth.v2.access", "", form, nil, &out); err != nil {
		return nil, err
	}
	return &OAuthResult{AccessToken: out.AccessToken, TokenType: out.TokenType, Scope: out.Scope, BotUserID: out.BotUserID,
		AppID: out.AppID, TeamID: out.Team.ID, TeamName: out.Team.Name}, nil
}

// PostMessage implements API.
func (h *HTTPAPI) PostMessage(ctx context.Context, token, channel string, msg Message) (string, string, error) {
	body := map[string]any{"channel": channel, "text": msg.Text, "blocks": msg.Blocks, "unfurl_links": false}
	var out struct {
		TS      string `json:"ts"`
		Channel string `json:"channel"`
	}
	if err := h.call(ctx, "chat.postMessage", token, nil, body, &out); err != nil {
		return "", "", err
	}
	return out.TS, out.Channel, nil
}

type wireUser struct {
	ID               string `json:"id"`
	TeamID           string `json:"team_id"`
	Name             string `json:"name"`
	RealName         string `json:"real_name"`
	Deleted          bool   `json:"deleted"`
	IsBot            bool   `json:"is_bot"`
	IsEmailConfirmed bool   `json:"is_email_confirmed"`
	Profile          struct {
		Email    string `json:"email"`
		RealName string `json:"real_name"`
	} `json:"profile"`
}

func (w wireUser) user() *User {
	rn := w.RealName
	if rn == "" {
		rn = w.Profile.RealName
	}
	return &User{ID: w.ID, TeamID: w.TeamID, Name: w.Name, RealName: rn, Email: w.Profile.Email,
		IsEmailConfirmed: w.IsEmailConfirmed, Deleted: w.Deleted, IsBot: w.IsBot}
}

// UsersInfo implements API.
func (h *HTTPAPI) UsersInfo(ctx context.Context, token, userID string) (*User, error) {
	var out struct {
		User wireUser `json:"user"`
	}
	if err := h.call(ctx, "users.info", token, url.Values{"user": {userID}}, nil, &out); err != nil {
		return nil, err
	}
	return out.User.user(), nil
}

// LookupByEmail implements API.
func (h *HTTPAPI) LookupByEmail(ctx context.Context, token, email string) (*User, error) {
	var out struct {
		User wireUser `json:"user"`
	}
	if err := h.call(ctx, "users.lookupByEmail", token, url.Values{"email": {email}}, nil, &out); err != nil {
		return nil, err
	}
	return out.User.user(), nil
}

// AuthRevoke implements API.
func (h *HTTPAPI) AuthRevoke(ctx context.Context, token string) error {
	return h.call(ctx, "auth.revoke", token, url.Values{}, nil, nil)
}

// ValidResponseURL reports whether u is an https URL on one of hosts
// (default hooks.slack.com).
func ValidResponseURL(u string, hosts []string) bool {
	p, err := url.Parse(u)
	if err != nil || p.Scheme != "https" || p.User != nil {
		return false
	}
	if len(hosts) == 0 {
		hosts = []string{"hooks.slack.com"}
	}
	for _, h := range hosts {
		if strings.EqualFold(p.Hostname(), h) && (p.Port() == "" || p.Port() == "443") {
			return true
		}
	}
	return false
}

// Respond implements API.
func (h *HTTPAPI) Respond(ctx context.Context, responseURL string, msg Message) error {
	if !ValidResponseURL(responseURL, h.ResponseHosts) {
		return fmt.Errorf("slack response_url refused: not an https URL on a Slack hooks host")
	}
	raw, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, responseURL, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client().Do(req)
	if err != nil {
		return fmt.Errorf("slack response_url: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("slack response_url: HTTP %d", resp.StatusCode)
	}
	return nil
}
