package modelprovider

import (
	"context"
	"net/url"
	"strconv"
	"time"
)

/* OpenAI Admin API (https://api.openai.com/v1, Authorization: Bearer):

   GET /organization/projects                         list projects
   GET /organization/projects/{project_id}/api_keys   list project API keys
   GET /organization/usage/completions                text usage (incl. Responses API)
   GET /organization/usage/embeddings                 embeddings usage
   GET /organization/audit_logs                       api_key.created / api_key.deleted

 https://developers.openai.com/api/reference/resources/admin */

type openAIClient struct{ h *httpGetter }

func (c *openAIClient) Provider() string { return OpenAI }

type openAIList[T any] struct {
	Data    []T     `json:"data"`
	HasMore bool    `json:"has_more"`
	LastID  *string `json:"last_id"`
}

type openAIProject struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type openAIKey struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	RedactedValue string `json:"redacted_value"`
	CreatedAt     *int64 `json:"created_at"`
	LastUsedAt    *int64 `json:"last_used_at"`
	ExpiresAt     *int64 `json:"expires_at"`
	Owner         struct {
		Type string `json:"type"`
		User *struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"user"`
		ServiceAccount *struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"service_account"`
	} `json:"owner"`
}

// Validate lists one project; the organisation is the openai-organization
// response header (OpenAI has no "current organisation" admin endpoint).
func (c *openAIClient) Validate(ctx context.Context) (Org, error) {
	var page openAIList[openAIProject]
	hdr, err := c.h.get(ctx, "/organization/projects", url.Values{"limit": {"1"}}, &page)
	if err != nil {
		return Org{}, err
	}
	return Org{ID: hdr.Get("openai-organization")}, nil
}

func (c *openAIClient) projects(ctx context.Context) ([]openAIProject, error) {
	var out []openAIProject
	after := ""
	for i := 0; i < maxPages; i++ {
		q := url.Values{"limit": {"100"}}
		if after != "" {
			q.Set("after", after)
		}
		var page openAIList[openAIProject]
		if _, err := c.h.get(ctx, "/organization/projects", q, &page); err != nil {
			return nil, err
		}
		out = append(out, page.Data...)
		next := str(page.LastID)
		if !page.HasMore || next == "" || next == after {
			break
		}
		after = next
	}
	return out, nil
}

// ListKeys lists every active project's API keys.
func (c *openAIClient) ListKeys(ctx context.Context, max int) ([]Key, bool, error) {
	projects, err := c.projects(ctx)
	if err != nil {
		return nil, false, err
	}
	now := time.Now()
	var out []Key
	for _, p := range projects {
		after := ""
		for i := 0; i < maxPages; i++ {
			q := url.Values{"limit": {"100"}}
			if after != "" {
				q.Set("after", after)
			}
			var page openAIList[openAIKey]
			if _, err := c.h.get(ctx, "/organization/projects/"+url.PathEscape(p.ID)+"/api_keys", q, &page); err != nil {
				return nil, false, err
			}
			for _, k := range page.Data {
				if k.ID == "" {
					continue
				}
				if len(out) >= max {
					return out, true, nil
				}
				key := Key{ID: k.ID, Name: k.Name, Hint: k.RedactedValue, ProjectID: p.ID, ProjectName: p.Name,
					CreatedAt: unixPtr(k.CreatedAt), LastUsedAt: unixPtr(k.LastUsedAt), Status: "active"}
				switch {
				case k.Owner.Type == "service_account" && k.Owner.ServiceAccount != nil:
					key.OwnerType, key.OwnerID, key.OwnerName = "service_account", k.Owner.ServiceAccount.ID, k.Owner.ServiceAccount.Name
				case k.Owner.Type == "user" && k.Owner.User != nil:
					key.OwnerType, key.OwnerID, key.OwnerName = "user", k.Owner.User.ID, k.Owner.User.Name
				}
				if exp := unixPtr(k.ExpiresAt); exp != nil && exp.Before(now) {
					key.Status = "expired"
				}
				out = append(out, key)
			}
			next := str(page.LastID)
			if !page.HasMore || next == "" || next == after {
				break
			}
			after = next
		}
	}
	return out, false, nil
}

type openAIUsagePage struct {
	Data []struct {
		StartTime int64 `json:"start_time"`
		Results   []struct {
			InputTokens       int64   `json:"input_tokens"`
			OutputTokens      int64   `json:"output_tokens"`
			InputCachedTokens int64   `json:"input_cached_tokens"`
			NumModelRequests  int64   `json:"num_model_requests"`
			ProjectID         *string `json:"project_id"`
			APIKeyID          *string `json:"api_key_id"`
			Model             *string `json:"model"`
		} `json:"results"`
	} `json:"data"`
	HasMore  bool    `json:"has_more"`
	NextPage *string `json:"next_page"`
}

// openAIUsageEndpoints are the usage endpoints read: text generation
// (completions, which reports the Responses API too) and embeddings.
var openAIUsageEndpoints = []string{"/organization/usage/completions", "/organization/usage/embeddings"}

// Usage reads both endpoints in 1 h buckets grouped by key, project, model.
func (c *openAIClient) Usage(ctx context.Context, from, to time.Time) ([]UsageRow, error) {
	agg := newUsageAgg()
	for _, ep := range openAIUsageEndpoints {
		page := ""
		for i := 0; i < maxPages; i++ {
			q := url.Values{
				"start_time":   {strconv.FormatInt(from.Unix(), 10)},
				"end_time":     {strconv.FormatInt(to.Unix(), 10)},
				"bucket_width": {"1h"},
				"group_by":     {"api_key_id", "project_id", "model"},
				"limit":        {"168"},
			}
			if page != "" {
				q.Set("page", page)
			}
			var p openAIUsagePage
			if _, err := c.h.get(ctx, ep, q, &p); err != nil {
				return nil, err
			}
			for _, b := range p.Data {
				for _, r := range b.Results {
					n := r.NumModelRequests
					agg.add(UsageRow{KeyID: str(r.APIKeyID), ProjectID: str(r.ProjectID), Model: str(r.Model),
						BucketStart: time.Unix(b.StartTime, 0), Requests: &n,
						InputTokens: r.InputTokens, CachedInputTokens: r.InputCachedTokens, OutputTokens: r.OutputTokens})
				}
			}
			next := str(p.NextPage)
			if !p.HasMore || next == "" || next == page {
				break
			}
			page = next
		}
	}
	return agg.rows(), nil
}

type openAIAuditLog struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	EffectiveAt int64  `json:"effective_at"`
	Project     *struct {
		ID string `json:"id"`
	} `json:"project"`
	Created *struct {
		ID string `json:"id"`
	} `json:"api_key.created"`
	Deleted *struct {
		ID string `json:"id"`
	} `json:"api_key.deleted"`
}

// KeyEvents reads api_key.created / api_key.deleted. An organisation that has
// not enabled audit logging answers with an error: that is "no events", not
// a failed sync (the caller decides; this returns the error).
func (c *openAIClient) KeyEvents(ctx context.Context, since time.Time) ([]KeyEvent, error) {
	var out []KeyEvent
	after := ""
	for i := 0; i < maxPages; i++ {
		q := url.Values{
			"event_types[]":     {"api_key.created", "api_key.deleted"},
			"effective_at[gte]": {strconv.FormatInt(since.Unix(), 10)},
			"limit":             {"100"},
		}
		if after != "" {
			q.Set("after", after)
		}
		var page openAIList[openAIAuditLog]
		if _, err := c.h.get(ctx, "/organization/audit_logs", q, &page); err != nil {
			return nil, err
		}
		for _, e := range page.Data {
			ev := KeyEvent{ID: e.ID, Type: e.Type, At: time.Unix(e.EffectiveAt, 0).UTC()}
			if e.Project != nil {
				ev.ProjectID = e.Project.ID
			}
			switch {
			case e.Type == "api_key.created" && e.Created != nil:
				ev.KeyID = e.Created.ID
			case e.Type == "api_key.deleted" && e.Deleted != nil:
				ev.KeyID = e.Deleted.ID
			default:
				continue
			}
			if ev.KeyID != "" {
				out = append(out, ev)
			}
		}
		next := str(page.LastID)
		if !page.HasMore || next == "" || next == after {
			break
		}
		after = next
	}
	return out, nil
}
