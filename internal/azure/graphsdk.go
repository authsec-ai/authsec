package azure

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	abs "github.com/microsoft/kiota-abstractions-go"
	kiotahttp "github.com/microsoft/kiota-http-go"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
)

// Microsoft Graph through the Graph SDK. The SDK builds every request (its
// request builders for v1.0; the same adapter with an explicit URL for beta
// and for Agent ID, which no builder covers) and sends it. The answer is
// decoded by decodeResponse into this package's own types, exactly as before:
// the selected fields, @odata.type, and the secret-bearing fields left
// undeclared so they are dropped.

var graphHost = strings.TrimPrefix(GraphEndpoint, "https://")

type graphTokenKey struct{}

// graphAuth puts the caller's token on each request. The token travels in the
// context, so one SDK client serves every tenant and every token.
type graphAuth struct{}

func (graphAuth) AuthenticateRequest(ctx context.Context, req *abs.RequestInformation, _ map[string]interface{}) error {
	tok, _ := ctx.Value(graphTokenKey{}).(string)
	if tok == "" {
		return fmt.Errorf("azure graph: no token for the request")
	}
	req.Headers.Add("Authorization", "Bearer "+tok)
	return nil
}

// graphTransport refuses any host but Graph's (a nextLink is followed with the
// same token) and sends each attempt through Client.retrying and the Client's
// own http.Client, so the per-attempt timeout is unchanged.
type graphTransport struct{ c *Client }

func (t graphTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || !strings.EqualFold(r.URL.Host, graphHost) || r.URL.User != nil {
		return nil, fmt.Errorf("azure graph: refusing a request to %s", r.URL.Host)
	}
	ctx := r.Context()
	return t.c.retrying(ctx, r.Method == http.MethodGet, true, func() (*http.Response, error) {
		return t.c.http.Do(r.Clone(ctx))
	})
}

type graphSDK struct {
	once    sync.Once
	adapter *kiotahttp.NetHttpRequestAdapter
	client  *msgraphsdk.GraphServiceClient
	err     error
}

// graph is the Client's Graph SDK client, built on first use.
func (c *Client) graph() (*msgraphsdk.GraphServiceClient, error) {
	c.graphSDK.once.Do(func() {
		hc := &http.Client{Transport: graphTransport{c}}
		c.graphSDK.adapter, c.graphSDK.err = kiotahttp.NewNetHttpRequestAdapterWithParseNodeFactoryAndSerializationWriterFactoryAndHttpClient(graphAuth{}, nil, nil, hc)
		if c.graphSDK.err == nil {
			c.graphSDK.client = msgraphsdk.NewGraphServiceClient(c.graphSDK.adapter)
		}
	})
	return c.graphSDK.client, c.graphSDK.err
}

// graphSend sends one request and decodes its answer into out (nil to discard
// it); a failure is the same *APIError Client.do returns.
func (c *Client) graphSend(ctx context.Context, token string, ri *abs.RequestInformation, out interface{}) error {
	if _, err := c.graph(); err != nil {
		return err
	}
	var derr error
	handler := abs.NewRequestHandlerOption()
	handler.SetResponseHandler(func(resp interface{}, _ abs.ErrorMappings) (interface{}, error) {
		r := resp.(*http.Response)
		defer r.Body.Close()
		_, derr = decodeResponse("graph", r, out)
		return nil, nil
	})
	ctx = context.WithValue(ctx, graphTokenKey{}, token)
	ctx = context.WithValue(ctx, abs.ResponseHandlerOptionKey, handler)
	ri.Headers.TryAdd("Accept", "application/json")
	if err := c.graphSDK.adapter.SendNoContent(ctx, ri, nil); err != nil {
		return fmt.Errorf("azure graph: request failed: %w", err)
	}
	return derr
}

// graphPaged follows @odata.nextLink from the first request and appends every
// page's value array, stopping after limit pages with ErrPageLimit and the rows
// read.
func graphPaged[T any](ctx context.Context, c *Client, token string, first *abs.RequestInformation, firstErr error, limit int) ([]T, error) {
	if firstErr != nil {
		return nil, fmt.Errorf("azure graph: build request: %w", firstErr)
	}
	if limit <= 0 || limit > maxPages {
		limit = maxPages
	}
	var out []T
	ri := first
	for page := 0; ri != nil; page++ {
		if page >= limit {
			return out, ErrPageLimit
		}
		var body struct {
			Value    []T    `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if err := c.graphSend(ctx, token, ri, &body); err != nil {
			return nil, err
		}
		out = append(out, body.Value...)
		ri = nil
		if body.NextLink != "" {
			if ri, _ = graphURL(body.NextLink); ri == nil {
				return nil, fmt.Errorf("azure graph: unreadable next page link")
			}
		}
	}
	return out, nil
}

// graphURL is a GET of an explicit Graph URL: a nextLink, a beta or Agent ID
// listing, or a permission probe. The SDK adapter still sends it.
func graphURL(raw string) (*abs.RequestInformation, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	ri := abs.NewRequestInformation()
	ri.Method = abs.GET
	ri.SetUri(*u)
	return ri, nil
}

// graphList builds a GET of path (from "/v1.0/" or "/beta/") with $select and
// $top, for the listings no SDK builder covers.
func graphList(path, sel, top string) (*abs.RequestInformation, error) {
	q := url.Values{}
	q.Set("$select", sel)
	q.Set("$top", top)
	return graphURL(GraphEndpoint + path + "?" + q.Encode())
}

func graphGet[T any](ctx context.Context, c *Client, token string, ri *abs.RequestInformation, buildErr error) (*T, error) {
	if buildErr != nil {
		return nil, fmt.Errorf("azure graph: build request: %w", buildErr)
	}
	var v T
	if err := c.graphSend(ctx, token, ri, &v); err != nil {
		return nil, err
	}
	return &v, nil
}
