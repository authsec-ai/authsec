package modelprovider

import (
	"context"
	"net/url"
	"time"
)

/* Anthropic Admin API (https://api.anthropic.com/v1, x-api-key,
   anthropic-version 2026-10-21):

     GET /organizations/me                       the organisation
     GET /organizations/workspaces               workspace names
     GET /organizations/api_keys                 API keys
     GET /organizations/usage_report/messages    messages usage (legacy, supported)

   https://platform.claude.com/docs/en/api/admin */

type anthropicClient struct{ h *httpGetter }

func (c *anthropicClient) Provider() string { return Anthropic }

type anthropicList[T any] struct {
	Data    []T     `json:"data"`
	HasMore bool    `json:"has_more"`
	LastID  *string `json:"last_id"`
}

func (c *anthropicClient) Validate(ctx context.Context) (Org, error) {
	var org struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if _, err := c.h.get(ctx, "/organizations/me", nil, &org); err != nil {
		return Org{}, err
	}
	return Org{ID: org.ID, Name: org.Name}, nil
}

type anthropicWorkspace struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type anthropicKey struct {
	ID              string  `json:"id"`
	Name            string  `json:"name"`
	PartialKeyHint  *string `json:"partial_key_hint"`
	Status          string  `json:"status"`
	CreatedAt       *string `json:"created_at"`
	LegacyWorkspace *string `json:"workspace_id"`
	CreatedBy       *struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"created_by"`
	Principal *struct {
		Type             string `json:"type"`
		UserID           string `json:"user_id"`
		ServiceAccountID string `json:"service_account_id"`
	} `json:"principal"`
	Scope *struct {
		Type        string `json:"type"`
		WorkspaceID string `json:"workspace_id"`
	} `json:"scope"`
}

func (c *anthropicClient) workspaces(ctx context.Context) (map[string]string, error) {
	out := map[string]string{}
	after := ""
	for i := 0; i < maxPages; i++ {
		q := url.Values{"limit": {"1000"}, "include_default": {"true"}}
		if after != "" {
			q.Set("after_id", after)
		}
		var page anthropicList[anthropicWorkspace]
		if _, err := c.h.get(ctx, "/organizations/workspaces", q, &page); err != nil {
			return nil, err
		}
		for _, w := range page.Data {
			out[w.ID] = w.Name
		}
		next := str(page.LastID)
		if !page.HasMore || next == "" || next == after {
			break
		}
		after = next
	}
	return out, nil
}

func parseRFC3339(p *string) *time.Time {
	if p == nil || *p == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, *p)
	if err != nil {
		return nil
	}
	t = t.UTC()
	return &t
}

// ListKeys lists the organisation's API keys (every status). Anthropic
// reports no last-used time; the caller takes it from usage.
func (c *anthropicClient) ListKeys(ctx context.Context, max int) ([]Key, bool, error) {
	names, err := c.workspaces(ctx)
	if err != nil {
		return nil, false, err
	}
	var out []Key
	after := ""
	for i := 0; i < maxPages; i++ {
		q := url.Values{"limit": {"1000"}}
		if after != "" {
			q.Set("after_id", after)
		}
		var page anthropicList[anthropicKey]
		if _, err := c.h.get(ctx, "/organizations/api_keys", q, &page); err != nil {
			return nil, false, err
		}
		for _, k := range page.Data {
			if k.ID == "" {
				continue
			}
			if len(out) >= max {
				return out, true, nil
			}
			key := Key{ID: k.ID, Name: k.Name, Hint: str(k.PartialKeyHint), Status: k.Status, CreatedAt: parseRFC3339(k.CreatedAt)}
			switch {
			case k.Scope != nil && k.Scope.WorkspaceID != "":
				key.ProjectID = k.Scope.WorkspaceID
			case k.LegacyWorkspace != nil:
				key.ProjectID = *k.LegacyWorkspace
			}
			key.ProjectName = names[key.ProjectID]
			switch {
			case k.Principal != nil && k.Principal.Type == "service_account_actor":
				key.OwnerType, key.OwnerID = "service_account", k.Principal.ServiceAccountID
			case k.Principal != nil && k.Principal.Type == "user_actor":
				key.OwnerType, key.OwnerID = "user", k.Principal.UserID
			case k.CreatedBy != nil && (k.CreatedBy.Type == "user" || k.CreatedBy.Type == "service_account"):
				key.OwnerType, key.OwnerID = k.CreatedBy.Type, k.CreatedBy.ID
			}
			switch key.Status {
			case "active", "inactive", "archived", "expired":
			default:
				key.Status = "active"
			}
			out = append(out, key)
		}
		next := str(page.LastID)
		if !page.HasMore || next == "" || next == after {
			break
		}
		after = next
	}
	return out, false, nil
}

type anthropicUsagePage struct {
	Data []struct {
		StartingAt string `json:"starting_at"`
		Results    []struct {
			APIKeyID            *string `json:"api_key_id"`
			WorkspaceID         *string `json:"workspace_id"`
			Model               *string `json:"model"`
			UncachedInputTokens int64   `json:"uncached_input_tokens"`
			CacheReadInput      int64   `json:"cache_read_input_tokens"`
			OutputTokens        int64   `json:"output_tokens"`
			CacheCreation       struct {
				OneHour  int64 `json:"ephemeral_1h_input_tokens"`
				FiveMins int64 `json:"ephemeral_5m_input_tokens"`
			} `json:"cache_creation"`
		} `json:"results"`
	} `json:"data"`
	HasMore  bool    `json:"has_more"`
	NextPage *string `json:"next_page"`
}

// Usage reads the messages usage report in 1 h buckets grouped by key,
// workspace and model. Input tokens are uncached + cache read + cache
// creation; requests are not reported (nil).
func (c *anthropicClient) Usage(ctx context.Context, from, to time.Time) ([]UsageRow, error) {
	agg := newUsageAgg()
	page := ""
	for i := 0; i < maxPages; i++ {
		q := url.Values{
			"starting_at":  {from.UTC().Format(time.RFC3339)},
			"ending_at":    {to.UTC().Format(time.RFC3339)},
			"bucket_width": {"1h"},
			"group_by[]":   {"api_key_id", "workspace_id", "model"},
			"limit":        {"168"},
		}
		if page != "" {
			q.Set("page", page)
		}
		var p anthropicUsagePage
		if _, err := c.h.get(ctx, "/organizations/usage_report/messages", q, &p); err != nil {
			return nil, err
		}
		for _, b := range p.Data {
			start, err := time.Parse(time.RFC3339Nano, b.StartingAt)
			if err != nil {
				continue
			}
			for _, r := range b.Results {
				in := r.UncachedInputTokens + r.CacheReadInput + r.CacheCreation.OneHour + r.CacheCreation.FiveMins
				agg.add(UsageRow{KeyID: str(r.APIKeyID), ProjectID: str(r.WorkspaceID), Model: str(r.Model),
					BucketStart: start, InputTokens: in, CachedInputTokens: r.CacheReadInput, OutputTokens: r.OutputTokens})
			}
		}
		next := str(p.NextPage)
		if !p.HasMore || next == "" || next == page {
			break
		}
		page = next
	}
	return agg.rows(), nil
}

// KeyEvents: the Anthropic Admin API has no audit log of key events.
func (c *anthropicClient) KeyEvents(context.Context, time.Time) ([]KeyEvent, error) { return nil, nil }
