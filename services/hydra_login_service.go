package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// HydraLoginService wraps the Hydra admin OAuth login + consent challenge
// endpoints. These are what Hydra calls "user login flow" — they're how the
// backend tells Hydra "yes, accept the login challenge for subject X with
// these claims" or "yes, accept the consent challenge with these granted
// scopes."
//
// All calls hit the v2 Hydra admin URL (HYDRA_V2_ADMIN_URL, falling back to
// HYDRA_ADMIN_URL when unset). The v2 flow runs on its own Hydra instance
// so legacy hmgr login flows aren't disturbed by URLS_LOGIN config drift —
// see hydraV2AdminURL() for resolution. The public Hydra endpoint is what
// browser-facing user agents talk to; this service is for backend-to-Hydra
// calls that happen between login and token exchange.
//
// Backport-lean equivalent of the dev branch's services/hydra_login.go.
// Same shape, same fail modes, no surprises.
type HydraLoginService struct{}

func NewHydraLoginService() *HydraLoginService { return &HydraLoginService{} }

// ─────────────────────────────────────────────────────────────────────────
// Login challenge
// ─────────────────────────────────────────────────────────────────────────

// HydraLoginRequest is the subset of fields the dev branch reads from
// Hydra's GET /admin/oauth2/auth/requests/login response.
type HydraLoginRequest struct {
	Challenge      string   `json:"challenge"`
	Skip           bool     `json:"skip"` // true when Hydra has an existing session and wants us to skip auth
	Subject        string   `json:"subject"`
	Client         struct { // partial — just enough to identify which client + audience
		ClientID string   `json:"client_id"`
		Audience []string `json:"audience"`
	} `json:"client"`
	RequestURL     string   `json:"request_url"`        // original /oauth2/auth URL — we parse out authsec_ctx from here
	RequestedScope []string `json:"requested_scope"`
	OIDCContext    struct {
		Prompt   []string `json:"prompt,omitempty"`
		MaxAge   *int     `json:"max_age,omitempty"`
		AuthTime *int64   `json:"auth_time,omitempty"`
	} `json:"oidc_context"`
}

// GetLoginRequest fetches Hydra's login challenge metadata. Called by
// /authsec/oauth/v2/login/page-data.
func (s *HydraLoginService) GetLoginRequest(challenge string) (*HydraLoginRequest, error) {
	if challenge == "" {
		return nil, fmt.Errorf("login_challenge required")
	}
	u := fmt.Sprintf("%s/admin/oauth2/auth/requests/login?challenge=%s",
		hydraV2AdminURL(), challenge)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := CircuitDoHydra(req)
	if err != nil {
		return nil, fmt.Errorf("hydra get login: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("hydra get login status %d: %s", resp.StatusCode, body)
	}
	var out HydraLoginRequest
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("hydra get login decode: %w", err)
	}
	return &out, nil
}

// HydraAcceptLoginRequest is the body we POST to accept-login. Subject is
// the AuthSec users.id (UUID string). Context is opaque metadata stored
// in Hydra's session and surfaced back in introspection's `ext` claim.
type HydraAcceptLoginRequest struct {
	Subject     string                 `json:"subject"`
	Remember    bool                   `json:"remember"`
	RememberFor int                    `json:"remember_for"` // seconds; 0 = no remember
	ACR         string                 `json:"acr,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
}

// HydraAcceptResponse is the response shape from Hydra's accept endpoints.
type HydraAcceptResponse struct {
	RedirectTo string `json:"redirect_to"`
}

// AcceptLoginRequest tells Hydra "user is authenticated, here's their
// subject + claims." Hydra returns a redirect_to URL that the browser
// must follow to continue the dance (usually to the consent endpoint).
//
// `subject` MUST be the AuthSec users.id. The introspect-time RBAC filter
// (commit 2d9f8ae) resolves sub → users.id by direct UUID parse, so this
// is the load-bearing identifier for all downstream enforcement.
func (s *HydraLoginService) AcceptLoginRequest(challenge string, req HydraAcceptLoginRequest) (*HydraAcceptResponse, error) {
	if challenge == "" {
		return nil, fmt.Errorf("login_challenge required")
	}
	if req.Subject == "" {
		return nil, fmt.Errorf("subject required")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	u := fmt.Sprintf("%s/admin/oauth2/auth/requests/login/accept?challenge=%s",
		hydraV2AdminURL(), challenge)
	httpReq, err := http.NewRequest("PUT", u, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := CircuitDoHydra(httpReq)
	if err != nil {
		return nil, fmt.Errorf("hydra accept login: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("hydra accept login status %d: %s", resp.StatusCode, body)
	}
	var out HydraAcceptResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("hydra accept login decode: %w", err)
	}
	return &out, nil
}

// HydraRejectLoginRequest is the body for reject-login. Used when the
// user cancels at the login page.
type HydraRejectLoginRequest struct {
	Error            string `json:"error"`             // e.g. "access_denied"
	ErrorDescription string `json:"error_description"`
}

// RejectLoginRequest tells Hydra "user refused to authenticate." Hydra
// returns a redirect_to that ends the dance back at the client's
// redirect_uri with an error param.
func (s *HydraLoginService) RejectLoginRequest(challenge string, req HydraRejectLoginRequest) (*HydraAcceptResponse, error) {
	if challenge == "" {
		return nil, fmt.Errorf("login_challenge required")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	u := fmt.Sprintf("%s/admin/oauth2/auth/requests/login/reject?challenge=%s",
		hydraV2AdminURL(), challenge)
	httpReq, err := http.NewRequest("PUT", u, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := CircuitDoHydra(httpReq)
	if err != nil {
		return nil, fmt.Errorf("hydra reject login: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("hydra reject login status %d: %s", resp.StatusCode, body)
	}
	var out HydraAcceptResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("hydra reject login decode: %w", err)
	}
	return &out, nil
}

// ─────────────────────────────────────────────────────────────────────────
// Consent challenge
// ─────────────────────────────────────────────────────────────────────────

// HydraConsentRequest is the subset of fields we read from Hydra's
// GET /admin/oauth2/auth/requests/consent.
type HydraConsentRequest struct {
	Challenge      string   `json:"challenge"`
	Skip           bool     `json:"skip"` // true when Hydra already has a remembered consent
	Subject        string   `json:"subject"`
	Client         struct {
		ClientID string   `json:"client_id"`
		Audience []string `json:"audience"`
	} `json:"client"`
	RequestURL     string   `json:"request_url"`
	RequestedScope []string `json:"requested_scope"`
	RequestedAccessTokenAudience []string `json:"requested_access_token_audience"`
	Context        map[string]interface{} `json:"context"`
}

// GetConsentRequest fetches Hydra's consent challenge metadata. Called by
// the consent handler (Session 3 of the port).
func (s *HydraLoginService) GetConsentRequest(challenge string) (*HydraConsentRequest, error) {
	if challenge == "" {
		return nil, fmt.Errorf("consent_challenge required")
	}
	u := fmt.Sprintf("%s/admin/oauth2/auth/requests/consent?challenge=%s",
		hydraV2AdminURL(), challenge)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := CircuitDoHydra(req)
	if err != nil {
		return nil, fmt.Errorf("hydra get consent: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("hydra get consent status %d: %s", resp.StatusCode, body)
	}
	var out HydraConsentRequest
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("hydra get consent decode: %w", err)
	}
	return &out, nil
}

// HydraAcceptConsentRequest tells Hydra the user granted these scopes.
// GrantScope is the narrowed scope set (after RBAC + scope-supported
// intersection — Session 3 wires this). Audience is the resource_uri.
type HydraAcceptConsentRequest struct {
	GrantScope               []string               `json:"grant_scope"`
	GrantAccessTokenAudience []string               `json:"grant_access_token_audience"`
	Remember                 bool                   `json:"remember"`
	RememberFor              int                    `json:"remember_for"`
	Session                  HydraConsentSession    `json:"session,omitempty"`
}

// HydraConsentSession carries claims that Hydra will embed into the
// access/id tokens. We use `access_token.ext` to stash our context_id so
// /oauth/v2/token can find the auth_request_context row by introspecting
// the freshly-minted token.
type HydraConsentSession struct {
	AccessToken map[string]interface{} `json:"access_token,omitempty"`
	IDToken     map[string]interface{} `json:"id_token,omitempty"`
}

// AcceptConsentRequest tells Hydra to mint the code + tokens for this
// consent challenge. Returns redirect_to (back to client's redirect_uri).
func (s *HydraLoginService) AcceptConsentRequest(challenge string, req HydraAcceptConsentRequest) (*HydraAcceptResponse, error) {
	if challenge == "" {
		return nil, fmt.Errorf("consent_challenge required")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	u := fmt.Sprintf("%s/admin/oauth2/auth/requests/consent/accept?challenge=%s",
		hydraV2AdminURL(), challenge)
	httpReq, err := http.NewRequest("PUT", u, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := CircuitDoHydra(httpReq)
	if err != nil {
		return nil, fmt.Errorf("hydra accept consent: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("hydra accept consent status %d: %s", resp.StatusCode, body)
	}
	var out HydraAcceptResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("hydra accept consent decode: %w", err)
	}
	return &out, nil
}

// HydraRejectConsentRequest tells Hydra the user declined consent.
type HydraRejectConsentRequest struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// RejectConsentRequest is the user-clicked-Deny case. Returns the same
// redirect_to shape ending at client's redirect_uri with error.
func (s *HydraLoginService) RejectConsentRequest(challenge string, req HydraRejectConsentRequest) (*HydraAcceptResponse, error) {
	if challenge == "" {
		return nil, fmt.Errorf("consent_challenge required")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	u := fmt.Sprintf("%s/admin/oauth2/auth/requests/consent/reject?challenge=%s",
		hydraV2AdminURL(), challenge)
	httpReq, err := http.NewRequest("PUT", u, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := CircuitDoHydra(httpReq)
	if err != nil {
		return nil, fmt.Errorf("hydra reject consent: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("hydra reject consent status %d: %s", resp.StatusCode, body)
	}
	var out HydraAcceptResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("hydra reject consent decode: %w", err)
	}
	return &out, nil
}
