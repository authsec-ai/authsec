package askconnect

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

/* ---------------------------------- Jira ---------------------------------- */

// JiraClient opens issues in one Jira Cloud project (REST API v3, basic auth
// with an account email and an API token).
type JiraClient struct {
	Site       string // https://<site>.atlassian.net, from SiteURL
	Email      string
	Token      string
	ProjectKey string
	IssueType  string // default "Task"
	HTTP       *http.Client
}

// JiraProjectKey is a Jira project key's form.
var JiraProjectKey = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,19}$`)

func basic(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func adf(text string) map[string]any {
	var paras []any
	for _, p := range strings.Split(text, "\n") {
		if strings.TrimSpace(p) == "" {
			continue
		}
		paras = append(paras, map[string]any{"type": "paragraph",
			"content": []any{map[string]any{"type": "text", "text": clip(p, 4000)}}})
	}
	if len(paras) == 0 {
		paras = []any{map[string]any{"type": "paragraph", "content": []any{}}}
	}
	return map[string]any{"type": "doc", "version": 1, "content": paras}
}

// Create opens an issue.
func (j JiraClient) Create(ctx context.Context, in Input) (Item, error) {
	it := j.IssueType
	if it == "" {
		it = "Task"
	}
	desc := in.Description
	if in.Link != "" {
		desc += "\n\nOpen in AuthSec: " + in.Link
	}
	body := map[string]any{"fields": map[string]any{
		"project":     map[string]any{"key": j.ProjectKey},
		"summary":     clip(strings.ReplaceAll(in.Summary, "\n", " "), 250),
		"issuetype":   map[string]any{"name": it},
		"description": adf(desc),
		"labels":      []string{"authsec"},
	}}
	var out struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}
	if err := do(ctx, j.HTTP, Jira, "create issue", http.MethodPost, j.Site+"/rest/api/3/issue", body,
		map[string]string{"Authorization": basic(j.Email, j.Token)}, &out); err != nil {
		return Item{}, err
	}
	if out.Key == "" {
		return Item{}, &Error{Provider: Jira, Op: "create issue", msg: "no issue key in the answer"}
	}
	return Item{Key: out.Key, Number: out.Key, URL: j.Site + "/browse/" + url.PathEscape(out.Key), Status: "created"}, nil
}

// Get reads an issue's status. Resolved only in the "done" category.
func (j JiraClient) Get(ctx context.Context, key string) (Item, error) {
	var out struct {
		Key    string `json:"key"`
		Fields struct {
			Status struct {
				Name           string `json:"name"`
				StatusCategory struct {
					Key string `json:"key"`
				} `json:"statusCategory"`
			} `json:"status"`
		} `json:"fields"`
	}
	if err := do(ctx, j.HTTP, Jira, "read issue", http.MethodGet, j.Site+"/rest/api/3/issue/"+url.PathEscape(key)+"?fields=status", nil,
		map[string]string{"Authorization": basic(j.Email, j.Token)}, &out); err != nil {
		return Item{}, err
	}
	st := out.Fields.Status
	return Item{Key: key, Number: key, URL: j.Site + "/browse/" + url.PathEscape(key), Status: st.Name,
		Resolved: JiraResolved(st.StatusCategory.Key)}, nil
}

// JiraResolved maps a status category key: only "done" is resolved.
func JiraResolved(categoryKey string) bool { return categoryKey == "done" }

/* -------------------------------- ServiceNow ------------------------------- */

// ServiceNowClient opens incidents on one instance (Table API, basic auth).
type ServiceNowClient struct {
	Instance string // https://<instance>.service-now.com, from SiteURL
	Username string
	Password string
	HTTP     *http.Client
}

// ServiceNowResolved maps an incident state: 6 Resolved, 7 Closed and
// 8 Canceled are terminal; anything else (including an unknown value) is open.
func ServiceNowResolved(state string) bool {
	switch strings.TrimSpace(state) {
	case "6", "7", "8":
		return true
	}
	return false
}

func snUrgency(sev string) string {
	switch sev {
	case "high":
		return "1"
	case "medium":
		return "2"
	}
	return "3"
}

type snResult struct {
	Result struct {
		SysID  string `json:"sys_id"`
		Number string `json:"number"`
		State  string `json:"state"`
	} `json:"result"`
}

func (s ServiceNowClient) link(sysID string) string {
	return s.Instance + "/nav_to.do?uri=" + url.QueryEscape("incident.do?sys_id="+sysID)
}

// Create opens an incident.
func (s ServiceNowClient) Create(ctx context.Context, in Input) (Item, error) {
	desc := in.Description
	if in.Link != "" {
		desc += "\n\nOpen in AuthSec: " + in.Link
	}
	body := map[string]any{"short_description": clip(strings.ReplaceAll(in.Summary, "\n", " "), 160),
		"description": clip(desc, 30000), "urgency": snUrgency(in.Severity), "impact": snUrgency(in.Severity),
		"correlation_id": clip(in.DedupeKey, 100), "correlation_display": "AuthSec"}
	var out snResult
	if err := do(ctx, s.HTTP, ServiceNow, "create incident", http.MethodPost, s.Instance+"/api/now/table/incident", body,
		map[string]string{"Authorization": basic(s.Username, s.Password)}, &out); err != nil {
		return Item{}, err
	}
	if out.Result.SysID == "" {
		return Item{}, &Error{Provider: ServiceNow, Op: "create incident", msg: "no sys_id in the answer"}
	}
	return Item{Key: out.Result.SysID, Number: out.Result.Number, URL: s.link(out.Result.SysID), Status: out.Result.State,
		Resolved: ServiceNowResolved(out.Result.State)}, nil
}

// Get reads an incident's state.
func (s ServiceNowClient) Get(ctx context.Context, sysID string) (Item, error) {
	var out snResult
	if err := do(ctx, s.HTTP, ServiceNow, "read incident", http.MethodGet,
		s.Instance+"/api/now/table/incident/"+url.PathEscape(sysID)+"?sysparm_fields=sys_id,number,state", nil,
		map[string]string{"Authorization": basic(s.Username, s.Password)}, &out); err != nil {
		return Item{}, err
	}
	return Item{Key: sysID, Number: out.Result.Number, URL: s.link(sysID), Status: out.Result.State,
		Resolved: ServiceNowResolved(out.Result.State)}, nil
}

/* -------------------------------- PagerDuty -------------------------------- */

// PagerDuty Events API v2 hosts.
const (
	PagerDutyEventsUS = "https://events.pagerduty.com"
	PagerDutyEventsEU = "https://events.eu.pagerduty.com"
)

// PagerDutyClient sends Events v2 to one integration (its routing key).
type PagerDutyClient struct {
	Base       string // PagerDutyEventsUS / EU
	RoutingKey string
	HTTP       *http.Client
}

func pdSeverity(sev string) string {
	switch sev {
	case "high":
		return "critical"
	case "medium":
		return "error"
	}
	return "warning"
}

// Trigger opens (or re-triggers, idempotently by dedup key) an incident.
func (p PagerDutyClient) Trigger(ctx context.Context, in Input) (Item, error) {
	body := map[string]any{"routing_key": p.RoutingKey, "event_action": "trigger", "dedup_key": clip(in.DedupeKey, 255),
		"payload": map[string]any{"summary": clip(strings.ReplaceAll(in.Summary, "\n", " "), 1024), "source": "authsec",
			"severity": pdSeverity(in.Severity), "custom_details": map[string]any{"description": clip(in.Description, 4000)}}}
	if in.Link != "" {
		body["links"] = []any{map[string]any{"href": in.Link, "text": "Open in AuthSec"}}
	}
	var out struct {
		Status   string `json:"status"`
		DedupKey string `json:"dedup_key"`
	}
	if err := do(ctx, p.HTTP, PagerDuty, "trigger", http.MethodPost, p.Base+"/v2/enqueue", body, nil, &out); err != nil {
		return Item{}, err
	}
	key := out.DedupKey
	if key == "" {
		key = in.DedupeKey
	}
	return Item{Key: key, Number: key, Status: "triggered"}, nil
}

// Resolve resolves the incident of a dedup key.
func (p PagerDutyClient) Resolve(ctx context.Context, dedupKey string) error {
	body := map[string]any{"routing_key": p.RoutingKey, "event_action": "resolve", "dedup_key": dedupKey}
	return do(ctx, p.HTTP, PagerDuty, "resolve", http.MethodPost, p.Base+"/v2/enqueue", body, nil, nil)
}

/* --------------------------------- Opsgenie -------------------------------- */

// Opsgenie API hosts.
const (
	OpsgenieUS = "https://api.opsgenie.com"
	OpsgenieEU = "https://api.eu.opsgenie.com"
)

// OpsgenieClient creates and closes alerts with an API integration key.
type OpsgenieClient struct {
	Base   string // OpsgenieUS / EU
	APIKey string
	HTTP   *http.Client
}

func ogPriority(sev string) string {
	switch sev {
	case "high":
		return "P1"
	case "medium":
		return "P3"
	}
	return "P4"
}

func (o OpsgenieClient) auth() map[string]string {
	return map[string]string{"Authorization": "GenieKey " + o.APIKey}
}

// Trigger creates an alert whose alias is the dedupe key (Opsgenie
// de-duplicates open alerts by alias).
func (o OpsgenieClient) Trigger(ctx context.Context, in Input) (Item, error) {
	alias := clip(in.DedupeKey, 512)
	body := map[string]any{"message": clip(strings.ReplaceAll(in.Summary, "\n", " "), 130), "alias": alias,
		"description": clip(in.Description, 15000), "priority": ogPriority(in.Severity), "source": "AuthSec",
		"tags": []string{"authsec"}}
	if in.Link != "" {
		body["details"] = map[string]string{"link": in.Link}
	}
	if err := do(ctx, o.HTTP, Opsgenie, "create alert", http.MethodPost, o.Base+"/v2/alerts", body, o.auth(), nil); err != nil {
		return Item{}, err
	}
	return Item{Key: alias, Number: alias, Status: "created"}, nil
}

// Resolve closes the alert of an alias.
func (o OpsgenieClient) Resolve(ctx context.Context, alias string) error {
	return do(ctx, o.HTTP, Opsgenie, "close alert", http.MethodPost,
		o.Base+"/v2/alerts/"+url.PathEscape(alias)+"/close?identifierType=alias",
		map[string]any{"source": "AuthSec", "note": "Answered in AuthSec."}, o.auth(), nil)
}
