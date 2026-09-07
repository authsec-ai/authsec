package azureonboard

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// requestTimeout bounds one call to Microsoft. Generous enough for a token
// endpoint under load, short enough that a wedged request does not hold an HTTP
// handler open until a proxy kills it.
const requestTimeout = 30 * time.Second

// maxErrorBody caps how much of a failed response is retained. Microsoft's
// AADSTS descriptions are useful and safe to surface; an unbounded body is not.
const maxErrorBody = 2048

// TokenSet is a token and what is needed to know when it dies.
//
// It has no String or MarshalJSON on purpose: the zero-effort path for a caller
// must not be one that prints a bearer token. See Redacted.
type TokenSet struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time

	// PrincipalObjectID is the oid claim: for an app-only token it is the object
	// id of THIS application's service principal in the tenant that issued it.
	//
	// That id is what an Azure RBAC role assignment has to name, and getting it
	// this way costs nothing -- no Graph call, no directory permission. Reading
	// it from /servicePrincipals would need Application.Read.All and would
	// break the promise that this package never touches those endpoints.
	PrincipalObjectID string
}

// Expired reports whether the access token is past use. The minute of slack
// stops a token expiring mid-flight on a call that was valid when it started.
func (t TokenSet) Expired() bool {
	return t.AccessToken == "" || time.Now().After(t.ExpiresAt.Add(-time.Minute))
}

// Redacted is what a log line or an API response is allowed to see.
func (t TokenSet) Redacted() map[string]any {
	return map[string]any{
		"has_access_token":  t.AccessToken != "",
		"has_refresh_token": t.RefreshToken != "",
		"expires_at":        t.ExpiresAt.UTC(),
	}
}

// Tenant is one entry from ARM's tenant list -- the same list the Azure portal
// shows under "Manage tenants" for the signed-in account.
type Tenant struct {
	TenantID      string   `json:"tenantId"`
	DisplayName   string   `json:"displayName"`
	Domains       []string `json:"domains"`
	DefaultDomain string   `json:"defaultDomain"`
	Category      string   `json:"tenantCategory"`
}

// PrimaryDomain is the one domain worth storing on the connector row.
func (t Tenant) PrimaryDomain() string {
	if t.DefaultDomain != "" {
		return t.DefaultDomain
	}
	if len(t.Domains) > 0 {
		return t.Domains[0]
	}
	return ""
}

// Subscription is one entry from ARM's subscription list.
type Subscription struct {
	SubscriptionID string `json:"subscriptionId"`
	DisplayName    string `json:"displayName"`
	State          string `json:"state"`
}

// APIError is a refusal from Microsoft, reduced to what is safe to show.
type APIError struct {
	Status      int
	Code        string
	Description string
}

func (e *APIError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("azure returned %d (%s): %s", e.Status, e.Code, e.Description)
	}
	return fmt.Sprintf("azure returned %d (%s)", e.Status, e.Code)
}

// Client is everything this package needs from Microsoft. An interface so the
// service layer can be driven by a fake, the same way awsdiscovery.IAMAPI works.
type Client interface {
	// ExchangeCode turns an authorization code into a delegated ARM token.
	ExchangeCode(ctx context.Context, code, redirectURI string) (*TokenSet, error)

	// Refresh renews a delegated token without a browser round trip.
	Refresh(ctx context.Context, refreshToken string) (*TokenSet, error)

	// ClientCredentials gets an app-only ARM token in one tenant. Fails when the
	// application has never been consented there.
	ClientCredentials(ctx context.Context, tenantID string) (*TokenSet, error)

	// ListTenants is the delegated call behind the tenant picker.
	ListTenants(ctx context.Context, accessToken string) ([]Tenant, error)

	// ListSubscriptions is the ARM Reader probe.
	ListSubscriptions(ctx context.Context, accessToken string) ([]Subscription, error)

	// RefreshForTenant gets a delegated ARM token valid in one specific tenant.
	RefreshForTenant(ctx context.Context, refreshToken, tenantID string) (*TokenSet, error)

	// AssignRole creates a role assignment as the signed-in operator.
	AssignRole(ctx context.Context, userAccessToken, scope, principalObjectID, roleDefinitionID string) AssignmentResult

	// GraphToken acquires an app-only Microsoft Graph token for one tenant.
	GraphToken(ctx context.Context, tenantID string) (*TokenSet, error)

	// ProbeGraphCapabilities checks what a granted permission can actually reach.
	ProbeGraphCapabilities(ctx context.Context, accessToken string) []GraphCapability
}

// HTTPClient is the live Client.
type HTTPClient struct {
	clientID     string
	clientSecret string
	http         *http.Client
}

// NewHTTPClient builds the live client. The secret never leaves this struct.
func NewHTTPClient(clientID, clientSecret string) *HTTPClient {
	return &HTTPClient{
		clientID:     clientID,
		clientSecret: clientSecret,
		http:         &http.Client{Timeout: requestTimeout},
	}
}

var _ Client = (*HTTPClient)(nil)

func (c *HTTPClient) ExchangeCode(ctx context.Context, code, redirectURI string) (*TokenSet, error) {
	form := url.Values{}
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("scope", ScopeARMDelegated)
	return c.token(ctx, TokenURL(), form)
}

func (c *HTTPClient) Refresh(ctx context.Context, refreshToken string) (*TokenSet, error) {
	form := url.Values{}
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("scope", ScopeARMDelegated)
	return c.token(ctx, TokenURL(), form)
}

func (c *HTTPClient) ClientCredentials(ctx context.Context, tenantID string) (*TokenSet, error) {
	if err := ValidateTenantID(tenantID); err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("grant_type", "client_credentials")
	form.Set("scope", ScopeARMDefault)

	tok, err := c.token(ctx, TenantTokenURL(tenantID), form)
	if err != nil {
		// AADSTS700016 / AADSTS7000229: the app has no service principal in this
		// directory. That is "consent was never completed", which is a different
		// operator action from "Reader is missing", so it gets its own error.
		var apiErr *APIError
		if errors.As(err, &apiErr) &&
			(strings.Contains(apiErr.Description, "AADSTS700016") ||
				strings.Contains(apiErr.Description, "AADSTS7000229") ||
				apiErr.Code == "unauthorized_client") {
			return nil, fmt.Errorf("%w: %s", ErrAppNotInTenant, apiErr.Description)
		}
		return nil, err
	}
	return tok, nil
}

// token posts a form to a Microsoft token endpoint.
//
// The form is never logged and never returned: it carries the client secret on
// every call and an authorization code on one of them.
func (c *HTTPClient) token(ctx context.Context, endpoint string, form url.Values) (*TokenSet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		// Deliberately not %w on the transport error: net/url errors embed the
		// request URL, and for a token POST that is fine, but keeping the shape
		// uniform avoids a future endpoint leaking a query string.
		return nil, fmt.Errorf("reach microsoft identity platform: %v", redactURLError(err))
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var oauthErr struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &oauthErr)
		code := oauthErr.Error
		if code == "" {
			code = "unknown_error"
		}
		return nil, &APIError{
			Status:      resp.StatusCode,
			Code:        code,
			Description: truncate(firstLine(oauthErr.Description), maxErrorBody),
		}
	}

	var payload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if payload.AccessToken == "" {
		return nil, errors.New("microsoft returned no access token")
	}

	lifetime := time.Duration(payload.ExpiresIn) * time.Second
	if lifetime <= 0 {
		lifetime = time.Hour
	}
	return &TokenSet{
		AccessToken:       payload.AccessToken,
		RefreshToken:      payload.RefreshToken,
		ExpiresAt:         time.Now().Add(lifetime),
		PrincipalObjectID: objectIDFromToken(payload.AccessToken),
	}, nil
}

// objectIDFromToken reads the oid claim out of an access token.
//
// The signature is deliberately NOT verified, and that is safe here: this token
// was just issued to us by Microsoft over TLS in response to our own request,
// and the value is used only to fill in a role-assignment command for a human
// to run. It is never an authorisation decision. Returns "" on anything
// unexpected rather than failing the token exchange over a cosmetic field.
func objectIDFromToken(raw string) string {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return ""
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		OID string `json:"oid"`
	}
	if err := json.Unmarshal(body, &claims); err != nil {
		return ""
	}
	return claims.OID
}

func (c *HTTPClient) ListTenants(ctx context.Context, accessToken string) ([]Tenant, error) {
	var out []Tenant
	err := c.armGet(ctx, accessToken, ARMBase+"/tenants?api-version="+APIVersionTenants, &out)
	return out, err
}

func (c *HTTPClient) ListSubscriptions(ctx context.Context, accessToken string) ([]Subscription, error) {
	var out []Subscription
	err := c.armGet(ctx, accessToken, ARMBase+"/subscriptions?api-version="+APIVersionSubscriptions, &out)
	return out, err
}

// armGet reads one paginated ARM collection into dest.
//
// ARM pages with nextLink and both of these lists can exceed one page on a large
// account. Following it is not optional: a truncated tenant list silently hides
// tenants from the operator, and a truncated subscription list can turn a
// working Reader assignment into a false negative.
func (c *HTTPClient) armGet(ctx context.Context, accessToken, next string, dest any) error {
	const maxPages = 100

	var collected []json.RawMessage
	for page := 0; next != "" && page < maxPages; page++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return fmt.Errorf("build arm request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Accept", "application/json")

		resp, err := c.http.Do(req)
		if err != nil {
			return fmt.Errorf("reach azure resource manager: %v", redactURLError(err))
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			var armErr struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			_ = json.Unmarshal(body, &armErr)
			apiErr := &APIError{
				Status:      resp.StatusCode,
				Code:        orDefault(armErr.Error.Code, "unknown_error"),
				Description: truncate(firstLine(armErr.Error.Message), maxErrorBody),
			}
			if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
				return fmt.Errorf("%w: %s", ErrARMForbidden, apiErr.Error())
			}
			return apiErr
		}

		var page struct {
			Value    []json.RawMessage `json:"value"`
			NextLink string            `json:"nextLink"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("decode arm response: %w", err)
		}
		collected = append(collected, page.Value...)

		// A nextLink echoing the URL just fetched would loop forever.
		if page.NextLink == next {
			break
		}
		next = page.NextLink
	}

	merged, err := json.Marshal(collected)
	if err != nil {
		return fmt.Errorf("merge arm pages: %w", err)
	}
	return json.Unmarshal(merged, dest)
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// redactURLError strips the URL from a *url.Error. A token endpoint URL is not
// sensitive, but the same helper covers ARM's nextLink, which carries an opaque
// continuation token.
func redactURLError(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return fmt.Errorf("%s: %v", uerr.Op, uerr.Err)
	}
	return err
}

/* ------------------------- assigning the role for them ------------------------ */

// RefreshForTenant exchanges a refresh token for an ARM access token in ONE
// specific tenant.
//
// Needed because ARM access tokens are per-tenant. The token from sign-in is
// issued by whichever authority the operator signed in through, and it will be
// refused by ARM when writing to a subscription that lives in a different
// directory -- even though the same person administers both. A refresh token
// redeemed at the target tenant's authority produces a token that tenant
// accepts. This is the same silent-acquisition MSAL performs when an app
// switches directories.
func (c *HTTPClient) RefreshForTenant(ctx context.Context, refreshToken, tenantID string) (*TokenSet, error) {
	if err := ValidateTenantID(tenantID); err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("scope", ScopeARMDelegated)
	return c.token(ctx, TenantTokenURL(tenantID), form)
}

// AssignmentResult is the outcome of one role assignment attempt.
type AssignmentResult struct {
	Scope string `json:"scope"`
	OK    bool   `json:"ok"`

	// AlreadyExisted is success too: the grant is present either way, and a
	// retry must not look like a failure.
	AlreadyExisted bool   `json:"already_existed,omitempty"`
	Error          string `json:"error,omitempty"`
}

// AssignRole creates a role assignment at scope, AS THE SIGNED-IN OPERATOR.
//
// This is the only write this package performs, and it is deliberately made
// with the operator's own delegated token rather than the application's. The
// application cannot grant itself a role -- Azure has no such mechanism, by
// design. What it can do is ask ARM on behalf of a human who already holds
// Owner or User Access Administrator, which is exactly what a person clicking
// through the portal would be doing, minus the clicking.
//
// A caller without that privilege gets a clean 403 back, not a partial state.
func (c *HTTPClient) AssignRole(
	ctx context.Context, userAccessToken, scope, principalObjectID, roleDefinitionID string,
) AssignmentResult {
	out := AssignmentResult{Scope: scope}

	// The assignment name must be a GUID, and deriving it from the grant itself
	// makes the call idempotent: a retry addresses the same object instead of
	// creating a second identical assignment.
	name := uuid.NewSHA1(uuid.NameSpaceURL,
		[]byte(scope+"|"+principalObjectID+"|"+roleDefinitionID)).String()

	body := map[string]any{
		"properties": map[string]any{
			"roleDefinitionId": scope + "/providers/Microsoft.Authorization/roleDefinitions/" + roleDefinitionID,
			"principalId":      principalObjectID,
			// Without this ARM refuses to wait for directory replication and a
			// freshly consented principal intermittently 400s as "not found".
			"principalType": "ServicePrincipal",
		},
	}
	payload, err := json.Marshal(body)
	if err != nil {
		out.Error = err.Error()
		return out
	}

	endpoint := ARMBase + scope + "/providers/Microsoft.Authorization/roleAssignments/" +
		name + "?api-version=2022-04-01"

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, strings.NewReader(string(payload)))
	if err != nil {
		out.Error = err.Error()
		return out
	}
	req.Header.Set("Authorization", "Bearer "+userAccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		out.Error = fmt.Sprintf("reach azure resource manager: %v", redactURLError(err))
		return out
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		out.OK = true
		return out
	}

	var armErr struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &armErr)

	// 409 RoleAssignmentExists means someone already granted it. That is the
	// desired end state, so it is success -- reporting it as a failure would
	// send an operator to fix something that is already correct.
	if resp.StatusCode == http.StatusConflict ||
		strings.EqualFold(armErr.Error.Code, "RoleAssignmentExists") {
		out.OK = true
		out.AlreadyExisted = true
		return out
	}

	out.Error = fmt.Sprintf("%s: %s",
		orDefault(armErr.Error.Code, fmt.Sprintf("http %d", resp.StatusCode)),
		truncate(firstLine(armErr.Error.Message), 300))
	return out
}

/* --------------------------- plane 1: graph authorisation --------------------------- */

// RequiredGraphRoles is what Azure discovery needs from Microsoft Graph, as
// Application permissions. Delegated grants of the same names never appear in
// an app-only token's roles claim, and mistaking one for the other is the most
// common way a consent appears to succeed while granting nothing.
//
// Deliberately not requested and not listed: anything that reads a secret
// VALUE. Recording that a credential exists, its age and its last use is the
// product's claim; reading it is not.
func RequiredGraphRoles() []string {
	return []string{
		// App registrations, service principals, their credentials and app role
		// assignments -- the non-human identities themselves.
		"Application.Read.All",
		// Users, groups, and the OAuth2 permission grants that say which
		// delegated consents exist.
		"Directory.Read.All",
		// Entra directory role assignments: who holds Global Administrator and
		// the rest. Not covered by Directory.Read.All for the unified role API.
		"RoleManagement.Read.Directory",
		// Sign-in activity, which is how an identity's liveness is established
		// without paying for a log pipeline.
		"AuditLog.Read.All",
	}
}

// GraphAuthorization is what an app-only Graph token reveals about consent.
type GraphAuthorization struct {
	// Granted is the token's roles claim, verbatim.
	Granted []string `json:"granted"`
	// Missing is RequiredGraphRoles minus Granted.
	Missing []string `json:"missing"`
	// OK is true when nothing required is missing.
	OK bool `json:"ok"`
}

// GraphToken acquires an app-only Microsoft Graph token for one tenant.
func (c *HTTPClient) GraphToken(ctx context.Context, tenantID string) (*TokenSet, error) {
	if err := ValidateTenantID(tenantID); err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("grant_type", "client_credentials")
	form.Set("scope", ScopeGraphDefault)

	tok, err := c.token(ctx, TenantTokenURL(tenantID), form)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) &&
			(strings.Contains(apiErr.Description, "AADSTS700016") ||
				strings.Contains(apiErr.Description, "AADSTS7000229") ||
				apiErr.Code == "unauthorized_client") {
			return nil, fmt.Errorf("%w: %s", ErrAppNotInTenant, apiErr.Description)
		}
		return nil, err
	}
	return tok, nil
}

// AuthorizationFromToken reports which required permissions a Graph token
// actually carries.
//
// The verdict comes from the token's own roles claim rather than from probing a
// Graph endpoint. That costs no extra call, needs no permission of its own to
// work even when nothing was granted, and enumerates exactly WHICH permissions
// landed -- where a probe only proves that one endpoint happened to answer, and
// tells an operator nothing about the one they are missing.
func AuthorizationFromToken(accessToken string) GraphAuthorization {
	granted := rolesFromToken(accessToken)
	have := make(map[string]bool, len(granted))
	for _, r := range granted {
		have[r] = true
	}

	auth := GraphAuthorization{Granted: granted, Missing: []string{}}
	for _, want := range RequiredGraphRoles() {
		if !have[want] {
			auth.Missing = append(auth.Missing, want)
		}
	}
	auth.OK = len(auth.Missing) == 0
	return auth
}

// rolesFromToken reads the roles claim. Same unverified decode as
// objectIDFromToken, and safe for the same reason: Microsoft issued this token
// to us over TLS moments ago in answer to our own request, and the value drives
// a report, never an authorisation decision.
func rolesFromToken(raw string) []string {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return []string{}
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return []string{}
	}
	var claims struct {
		Roles []string `json:"roles"`
	}
	if err := json.Unmarshal(body, &claims); err != nil || claims.Roles == nil {
		return []string{}
	}
	return claims.Roles
}

/* ------------------------- granted is not always usable ------------------------- */

// GraphCapability is a permission that is granted and may still not work.
//
// A granted permission and an available capability are different facts, and
// Microsoft gates some data on the tenant's LICENCE rather than on consent.
// /auditLogs/signIns is the one that matters here: AuditLog.Read.All grants it,
// and a tenant without Entra ID P1 or P2 still gets 403
// Authentication_RequestFromNonPremiumTenantOrB2CTenant. Observed against a
// real free-tier tenant holding the permission.
//
// Discovery has to know this up front. Without it, the sign-in-activity reader
// fails on free-tier tenants in a way that reads as a code bug and is not, and
// "last used" quietly becomes unknown with nothing saying why.
type GraphCapability struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`

	// LicenseGated is true when the permission is held but the tenant's licence
	// withholds the data -- a customer action (buy P1), not an AuthSec bug and
	// not a missing consent.
	LicenseGated bool `json:"license_gated,omitempty"`
}

// ProbeGraphCapabilities checks the capabilities that consent alone does not
// settle. Cheap: one page-of-one request each.
func (c *HTTPClient) ProbeGraphCapabilities(ctx context.Context, accessToken string) []GraphCapability {
	type probe struct{ name, url string }
	probes := []probe{
		// The licence-gated one. Everything else discovery needs was verified
		// against a real tenant to work on the free tier.
		{"signin_activity", ARMGraphSignInsURL()},
	}

	out := make([]GraphCapability, 0, len(probes))
	for _, pr := range probes {
		cap := GraphCapability{Name: pr.name, Available: true}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pr.url, nil)
		if err != nil {
			cap.Available, cap.Reason = false, err.Error()
			out = append(out, cap)
			continue
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)

		resp, err := c.http.Do(req)
		if err != nil {
			cap.Available = false
			cap.Reason = fmt.Sprintf("reach microsoft graph: %v", redactURLError(err))
			out = append(out, cap)
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			out = append(out, cap)
			continue
		}

		var gErr struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(body, &gErr)
		cap.Available = false
		cap.Reason = fmt.Sprintf("%s: %s",
			orDefault(gErr.Error.Code, fmt.Sprintf("http %d", resp.StatusCode)),
			truncate(firstLine(gErr.Error.Message), 200))

		// Microsoft's own marker for the licence gate.
		if strings.Contains(gErr.Error.Code, "NonPremiumTenant") ||
			strings.Contains(gErr.Error.Message, "premium license") {
			cap.LicenseGated = true
			cap.Reason = "the tenant has no Entra ID P1/P2 licence, so sign-in logs are " +
				"withheld even though AuditLog.Read.All is granted"
		}
		out = append(out, cap)
	}
	return out
}

// ARMGraphSignInsURL is the sign-in activity endpoint, as one page of one.
func ARMGraphSignInsURL() string {
	return "https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=1"
}
