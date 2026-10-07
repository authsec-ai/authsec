package azure

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// staticToken hands the SDK a bearer token the caller already holds, so the
// Client keeps taking its token per call: the administrator's delegated token
// during Connect, AuthSec's app-only token when it proves its own access.
type staticToken string

func (t staticToken) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: string(t), ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// armOptions configures every Resource Manager SDK client. The SDK's own
// retry is off in favour of retryPolicy, which keeps this package's rules, and
// resource-provider auto-registration is off: it would attempt a write in a
// customer subscription whenever a provider is not registered there.
func (c *Client) armOptions() *arm.ClientOptions {
	return &arm.ClientOptions{
		ClientOptions: policy.ClientOptions{
			Transport:       c.http,
			Retry:           policy.RetryOptions{MaxRetries: -1},
			PerCallPolicies: []policy.Policy{retryPolicy{c}},
		},
		DisableRPRegistration: true,
	}
}

// armHost is the only host a Resource Manager request, nextLinks included, may
// go to: the bearer token rides along on each one.
var armHost = strings.TrimPrefix(ARMEndpoint, "https://")

// retryPolicy runs each Resource Manager request through Client.retrying,
// after refusing any host but Resource Manager's.
type retryPolicy struct{ c *Client }

func (p retryPolicy) Do(req *policy.Request) (*http.Response, error) {
	raw := req.Raw()
	if raw.URL.Scheme != "https" || !strings.EqualFold(raw.URL.Host, armHost) || raw.URL.User != nil {
		return nil, fmt.Errorf("azure arm: refusing a request to %s", raw.URL.Host)
	}
	ctx := raw.Context()
	return p.c.retrying(ctx, idempotentRequest(raw.Method, raw.URL.String()), true, func() (*http.Response, error) {
		if err := req.RewindBody(); err != nil {
			return nil, err
		}
		return req.Clone(ctx).Next()
	})
}

// armError turns an SDK failure into this package's *APIError, so callers'
// errors.Is / IsAPICode / APIStatus checks see what they always saw.
func armError(err error) error {
	var re *azcore.ResponseError
	if errors.As(err, &re) && re.RawResponse != nil {
		body, _ := runtime.Payload(re.RawResponse)
		return apiErrorFrom("arm", re.StatusCode, body)
	}
	return fmt.Errorf("azure arm: request failed: %w", err)
}

// collect reads a pager to its end, stopping after limit pages with
// ErrPageLimit and the rows read.
func collect[P, T any](ctx context.Context, pager *runtime.Pager[P], limit int, rows func(P) []T) ([]T, error) {
	if limit <= 0 || limit > maxPages {
		limit = maxPages
	}
	var out []T
	for page := 0; pager.More(); page++ {
		if page >= limit {
			return out, ErrPageLimit
		}
		p, err := pager.NextPage(ctx)
		if err != nil {
			return nil, armError(err)
		}
		out = append(out, rows(p)...)
	}
	return out, nil
}

// appToken is AuthSec's client-credentials token through azidentity. A new
// credential per call, so no token is cached: a permission an administrator
// has just granted must show on the very next Verify, not an hour later.
func (c *Client) appToken(ctx context.Context, cfg AppConfig, tenantID, scope string) (string, error) {
	cred, err := azidentity.NewClientSecretCredential(tenantID, cfg.ClientID, cfg.ClientSecret, &azidentity.ClientSecretCredentialOptions{
		ClientOptions: policy.ClientOptions{
			Transport: c.http,
			// The token endpoint is never retried, as in Client.do.
			Retry: policy.RetryOptions{MaxRetries: -1},
		},
		DisableInstanceDiscovery: true,
	})
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}})
	if err != nil {
		var af *azidentity.AuthenticationFailedError
		if errors.As(err, &af) && af.RawResponse != nil {
			body, _ := runtime.Payload(af.RawResponse)
			return "", apiErrorFrom("login", af.RawResponse.StatusCode, body)
		}
		return "", fmt.Errorf("azure login: request failed: %w", err)
	}
	if tok.Token == "" {
		return "", errors.New("azure login: the token response carried no access token")
	}
	return tok.Token, nil
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
