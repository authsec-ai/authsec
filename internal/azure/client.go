package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/microsoftgraph/msgraph-sdk-go/serviceprincipals"
	"github.com/microsoftgraph/msgraph-sdk-go/users"
)

// Microsoft public-cloud endpoints. Sovereign clouds (Azure Government, 21Vianet)
// use different hosts and are not supported by this onboarding path yet.
const (
	AuthorityHost = "https://login.microsoftonline.com"
	ARMEndpoint   = "https://management.azure.com"
	GraphEndpoint = "https://graph.microsoft.com"

	// GraphAppID is Microsoft Graph's own application id, identical in every
	// tenant. Its service principal carries the app roles AuthSec requests.
	GraphAppID = "00000003-0000-0000-c000-000000000000"

	// ARMResourceAppID is Azure Service Management's application id. Its
	// delegated user_impersonation scope is what lets a signed-in customer
	// administrator create the Reader assignments.
	ARMResourceAppID = "797f4846-ba00-4fd7-ba43-dac1f8f63013"

	apiVersionAuthorization   = "2022-04-01"
	maxPages                  = 100
	graphPageSize             = 999
	maxAttempts               = 4
	maxRetryAfter             = 10 * time.Second
	defaultRequestTimeout     = 30 * time.Second
	maxErrorBodyBytes         = 64 << 10
	maxSuccessBodyBytes       = 32 << 20
	errorMessageTruncateBytes = 300
)

// Client calls login.microsoftonline.com, Microsoft Graph and Azure Resource
// Manager. Resource Manager and AuthSec's app-only tokens go through the Azure
// SDK (arm.go, sdk.go), Graph through the Microsoft Graph SDK (graphsdk.go);
// only the authorization-code redemption stays plain REST. It holds no
// credential: every call takes the bearer token it should use, so one Client
// serves AuthSec's app-only tokens and a customer's one-shot delegated token
// alike.
type Client struct {
	http *http.Client
	// sleep is a seam so a test can run the retry ladder without waiting.
	sleep func(context.Context, time.Duration) error
	// graphSDK is the Microsoft Graph SDK client, built on first use.
	graphSDK graphSDK
}

// NewClient builds a Client. httpClient may be nil.
func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultRequestTimeout}
	}
	return &Client{http: httpClient, sleep: sleepCtx}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// do sends one request, retrying 429/502/503/504 with Retry-After honoured and
// capped. 500 and every other 4xx are returned at once: a 409 or a 403 does
// not change by asking again. out may be nil.
func (c *Client) do(ctx context.Context, service, method, rawURL, token string, form url.Values, body interface{}, out interface{}) (int, error) {
	var payload []byte
	contentType := ""
	switch {
	case form != nil:
		payload = []byte(form.Encode())
		contentType = "application/x-www-form-urlencoded"
	case body != nil:
		b, err := json.Marshal(body)
		if err != nil {
			return 0, fmt.Errorf("azure %s: encode request: %w", service, err)
		}
		payload = b
		contentType = "application/json"
	}

	base, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return 0, fmt.Errorf("azure %s: build request: %w", service, err)
	}
	if contentType != "" {
		base.Header.Set("Content-Type", contentType)
	}
	base.Header.Set("Accept", "application/json")
	if token != "" {
		base.Header.Set("Authorization", "Bearer "+token)
	}
	// The token endpoint is never retried on status: a login answer does not
	// change by asking again.
	resp, err := c.retrying(ctx, idempotentRequest(method, rawURL), service != "login", func() (*http.Response, error) {
		req := base.Clone(ctx)
		if payload != nil {
			req.Body = io.NopCloser(bytes.NewReader(payload))
			req.ContentLength = int64(len(payload))
		}
		return c.http.Do(req)
	})
	if err != nil {
		return 0, fmt.Errorf("azure %s: request failed: %w", service, err)
	}
	status, derr := decodeResponse(service, resp, out)
	resp.Body.Close()
	return status, derr
}

// retrying is this package's one retry ladder, used by Client.do and by the
// Azure SDK pipelines alike: when retryStatus, 429, 502, 503 and 504 are
// retried with Retry-After honoured and capped; 500 and every other 4xx come
// back at once, since a 409 or a 403 does not change by asking again. A
// transport error (connection reset, TLS handshake or header timeout) is
// retried only for an idempotent request: a POST to the token endpoint that
// reached Microsoft and lost its answer would redeem the same authorization
// code twice. On the last attempt, or when the wait would pass the deadline,
// the retryable answer itself is returned for the caller to decode.
func (c *Client) retrying(ctx context.Context, idempotent, retryStatus bool, send func() (*http.Response, error)) (*http.Response, error) {
	backoff := 500 * time.Millisecond
	for attempt := 1; ; attempt++ {
		resp, err := send()
		if err != nil {
			if idempotent && attempt < maxAttempts && ctx.Err() == nil {
				if serr := c.sleep(ctx, backoff); serr != nil {
					return nil, serr
				}
				backoff *= 2
				continue
			}
			return nil, err
		}
		if !retryStatus || !retryableStatus(resp.StatusCode) || attempt >= maxAttempts {
			return resp, nil
		}
		wait := retryAfter(resp.Header.Get("Retry-After"), backoff)
		if dl, ok := ctx.Deadline(); ok && time.Until(dl) < wait {
			return resp, nil
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBodyBytes))
		resp.Body.Close()
		if err := c.sleep(ctx, wait); err != nil {
			return nil, err
		}
		backoff *= 2
	}
}

func retryableStatus(status int) bool {
	return status == http.StatusTooManyRequests ||
		status == http.StatusBadGateway ||
		status == http.StatusServiceUnavailable ||
		status == http.StatusGatewayTimeout
}

// idempotentRequest reports whether repeating a request can change nothing: a
// GET, or a Resource Graph query (a read sent as POST).
func idempotentRequest(method, rawURL string) bool {
	return method == http.MethodGet ||
		(method == http.MethodPost && strings.Contains(rawURL, "/providers/Microsoft.ResourceGraph/resources"))
}

func retryAfter(h string, fallback time.Duration) time.Duration {
	h = strings.TrimSpace(h)
	if h == "" {
		return fallback
	}
	d := fallback
	if secs, err := strconv.Atoi(h); err == nil {
		d = time.Duration(secs) * time.Second
	} else if t, err := http.ParseTime(h); err == nil {
		d = time.Until(t)
	}
	if d < 0 {
		d = 0
	}
	if d > maxRetryAfter {
		d = maxRetryAfter
	}
	return d
}

// microsoftError covers the three error shapes this package reads:
// ARM/Graph ({"error":{"code","message"}}) and the token endpoint
// ({"error","error_description","error_codes"}).
type microsoftError struct {
	Error            json.RawMessage `json:"error"`
	ErrorDescription string          `json:"error_description"`
	ErrorCodes       []int           `json:"error_codes"`
}

func decodeResponse(service string, resp *http.Response, out interface{}) (int, error) {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out == nil || resp.StatusCode == http.StatusNoContent {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBodyBytes))
			return resp.StatusCode, nil
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxSuccessBodyBytes)).Decode(out); err != nil && !errors.Is(err, io.EOF) {
			return resp.StatusCode, fmt.Errorf("azure %s: unreadable response: %w", service, err)
		}
		return resp.StatusCode, nil
	}

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
	return resp.StatusCode, apiErrorFrom(service, resp.StatusCode, raw)
}

// apiErrorFrom builds the *APIError for a non-success answer from its body,
// whichever path (Client.do or the SDK) received it.
func apiErrorFrom(service string, status int, raw []byte) *APIError {
	if len(raw) > maxErrorBodyBytes {
		raw = raw[:maxErrorBodyBytes]
	}
	apiErr := &APIError{Service: service, Status: status}
	var me microsoftError
	if json.Unmarshal(raw, &me) == nil && len(me.Error) > 0 {
		var nested struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		var flat string
		switch {
		case json.Unmarshal(me.Error, &nested) == nil && nested.Code != "":
			apiErr.Code = nested.Code
			apiErr.Message = nested.Message
		case json.Unmarshal(me.Error, &flat) == nil:
			apiErr.Code = flat
			apiErr.Message = me.ErrorDescription
		}
	}
	if apiErr.Message == "" {
		apiErr.Message = http.StatusText(status)
	}
	// The token endpoint's description is multi-line and ends in trace and
	// correlation ids. The first line carries the AADSTS code and the reason.
	if i := strings.IndexAny(apiErr.Message, "\r\n"); i > 0 {
		apiErr.Message = apiErr.Message[:i]
	}
	apiErr.Message = truncate(apiErr.Message, errorMessageTruncateBytes)
	return apiErr
}

// ErrPageLimit means a listing had more pages than this package follows. The
// rows read so far are returned alongside it, so a caller can record a partial
// read instead of mistaking a capped list for a complete one.
var ErrPageLimit = errors.New("azure: listing stopped at the page limit")

/* ------------------------------- Microsoft Graph ------------------------------ */

// ServicePrincipal is the subset of a Graph servicePrincipal AuthSec reads.
type ServicePrincipal struct {
	ID                     string    `json:"id"`
	AppID                  string    `json:"appId"`
	DisplayName            string    `json:"displayName"`
	AppOwnerOrganizationID string    `json:"appOwnerOrganizationId"`
	AccountEnabled         *bool     `json:"accountEnabled"`
	AppRoles               []AppRole `json:"appRoles,omitempty"`
}

// AppRole is one application permission a resource exposes. Value is what a
// token carries ("Mail.Read"); a role meant only for users may have none, and
// is then known by its DisplayName.
type AppRole struct {
	ID          string `json:"id"`
	Value       string `json:"value"`
	DisplayName string `json:"displayName,omitempty"`
}

// AppRoleAssignment is one application permission granted to a principal.
type AppRoleAssignment struct {
	AppRoleID  string `json:"appRoleId"`
	ResourceID string `json:"resourceId"`
}

// FindServicePrincipal returns the service principal of appID in the tenant the
// token belongs to, or ErrAppNotInTenant when there is none.
func (c *Client) FindServicePrincipal(ctx context.Context, graphToken, appID string, withRoles bool) (*ServicePrincipal, error) {
	sel := []string{"id", "appId", "displayName", "appOwnerOrganizationId", "accountEnabled"}
	if withRoles {
		sel = append(sel, "appRoles")
	}
	g, err := c.graph()
	if err != nil {
		return nil, err
	}
	ri, err := g.ServicePrincipals().ToGetRequestInformation(ctx, &serviceprincipals.ServicePrincipalsRequestBuilderGetRequestConfiguration{
		QueryParameters: &serviceprincipals.ServicePrincipalsRequestBuilderGetQueryParameters{
			Filter: to.Ptr(fmt.Sprintf("appId eq '%s'", appID)),
			Select: sel,
		}})
	sps, err := graphPaged[ServicePrincipal](ctx, c, graphToken, ri, err, maxPages)
	if err != nil {
		return nil, err
	}
	if len(sps) == 0 {
		return nil, ErrAppNotInTenant
	}
	return &sps[0], nil
}

// ListAppRoleAssignments returns the application permissions granted to the
// service principal spID.
func (c *Client) ListAppRoleAssignments(ctx context.Context, graphToken, spID string) ([]AppRoleAssignment, error) {
	g, err := c.graph()
	if err != nil {
		return nil, err
	}
	ri, err := g.ServicePrincipals().ByServicePrincipalId(spID).AppRoleAssignments().ToGetRequestInformation(ctx,
		&serviceprincipals.ItemAppRoleAssignmentsRequestBuilderGetRequestConfiguration{
			QueryParameters: &serviceprincipals.ItemAppRoleAssignmentsRequestBuilderGetQueryParameters{Select: []string{"appRoleId", "resourceId"}}})
	return graphPaged[AppRoleAssignment](ctx, c, graphToken, ri, err, maxPages)
}

// ProbeGraph issues one minimal read (path must start with "/v1.0/") and
// reports whether the token may make it. Callers pass $top=1&$select=id so a
// probe reads an identifier at most.
func (c *Client) ProbeGraph(ctx context.Context, graphToken, path string) error {
	ri, err := graphURL(GraphEndpoint + path)
	if err != nil {
		return fmt.Errorf("azure graph: build request: %w", err)
	}
	return c.graphSend(ctx, graphToken, ri, nil)
}

// DirectoryUser is the subset of a Graph user AuthSec reads to decide whether
// the person who signed in may attach their tenant to a workspace.
type DirectoryUser struct {
	ID                string `json:"id"`
	UserType          string `json:"userType"`
	UserPrincipalName string `json:"userPrincipalName"`
	AccountEnabled    *bool  `json:"accountEnabled"`
}

// GetUser reads one user by object id.
func (c *Client) GetUser(ctx context.Context, graphToken, objectID string) (*DirectoryUser, error) {
	g, err := c.graph()
	if err != nil {
		return nil, err
	}
	ri, err := g.Users().ByUserId(objectID).ToGetRequestInformation(ctx, &users.UserItemRequestBuilderGetRequestConfiguration{
		QueryParameters: &users.UserItemRequestBuilderGetQueryParameters{
			Select: []string{"id", "userType", "userPrincipalName", "accountEnabled"},
		}})
	return graphGet[DirectoryUser](ctx, c, graphToken, ri, err)
}

// UserDirectoryRoleTemplateIDs returns the role template ids of every
// directory role the user holds, directly or through a role-assignable group.
// Only active roles are returned: an eligible-but-not-activated PIM role is not
// a membership.
func (c *Client) UserDirectoryRoleTemplateIDs(ctx context.Context, graphToken, objectID string) ([]string, error) {
	type member struct {
		ODataType      string `json:"@odata.type"`
		RoleTemplateID string `json:"roleTemplateId"`
	}
	g, err := c.graph()
	if err != nil {
		return nil, err
	}
	ri, err := g.Users().ByUserId(objectID).TransitiveMemberOf().ToGetRequestInformation(ctx, &users.ItemTransitiveMemberOfRequestBuilderGetRequestConfiguration{
		QueryParameters: &users.ItemTransitiveMemberOfRequestBuilderGetQueryParameters{Top: to.Ptr(int32(graphPageSize))}})
	rows, err := graphPaged[member](ctx, c, graphToken, ri, err, maxPages)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range rows {
		if strings.EqualFold(m.ODataType, "#microsoft.graph.directoryRole") && m.RoleTemplateID != "" {
			out = append(out, strings.ToLower(m.RoleTemplateID))
		}
	}
	return out, nil
}
