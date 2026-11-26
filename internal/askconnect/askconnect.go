// Package askconnect is the outbound side of the ticketing and paging
// connectors of asks (SPEC-secops-backend-upgrade.md W4, C13): Jira Cloud and
// ServiceNow (an issue / incident per ask or case, and its state read back)
// and PagerDuty Events v2 and Opsgenie (an incident triggered for a
// high-severity ask and resolved when the ask is answered).
//
// It is transport only: what to open, when, and what an outcome means belong
// to the caller (services/agent_ask_connectors.go). Every request goes
// through the *http.Client the caller passes -- in production an SSRF-safe
// client from internal/safehttp, since a Jira site or a ServiceNow instance
// is the workspace's choice (CLAUDE.md 2026-10-07). A redirect is never
// followed: an answer that moves the request elsewhere is an error.
//
// Status mapping is conservative: an external item counts as resolved only
// in the provider's terminal "done" states (Jira: status category "done";
// ServiceNow incident: 6 Resolved, 7 Closed, 8 Canceled). Anything else,
// including an unknown value, is open.
package askconnect

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
)

// Providers.
const (
	Jira       = "jira"
	ServiceNow = "servicenow"
	PagerDuty  = "pagerduty"
	Opsgenie   = "opsgenie"
)

// maxBody bounds what is read of an answer.
const maxBody = 256 << 10

// Error is a provider failure. Permanent is true when retrying cannot help
// (a 4xx other than 408 / 429: bad credentials, a missing project, a
// malformed request).
type Error struct {
	Provider  string
	Op        string
	Status    int
	Permanent bool
	msg       string
	err       error
}

// Unwrap is the transport error, when there was one (errors.Is against
// safehttp.ErrBlockedAddress tells a refused destination).
func (e *Error) Unwrap() error { return e.err }

func (e *Error) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("%s %s: HTTP %d%s", e.Provider, e.Op, e.Status, e.msg)
	}
	return fmt.Sprintf("%s %s: %s", e.Provider, e.Op, e.msg)
}

// IsPermanent reports whether err is a permanent provider error.
func IsPermanent(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Permanent
}

// Item is a ticket or a page as the provider knows it.
type Item struct {
	// Key is the provider's id (Jira issue key, ServiceNow sys_id, the
	// PagerDuty dedup key, the Opsgenie alias).
	Key string
	// Number is what people call it (Jira key, ServiceNow INC number).
	Number string
	// URL opens it in the provider's UI ("" when unknown).
	URL string
	// Status is the provider's own state, verbatim.
	Status string
	// Resolved is true in a terminal done state only.
	Resolved bool
}

// Input is what is opened.
type Input struct {
	// Summary is one line; Description the body (plain text).
	Summary     string
	Description string
	// Severity is high, medium or low.
	Severity string
	// DedupeKey identifies the subject across retries (pages use it as their
	// dedup key / alias so a retried trigger never opens a second incident).
	DedupeKey string
	// Link is the console URL of the subject ("" without a base URL).
	Link string
}

// noRedirect refuses every redirect: the request must be answered where it
// was sent.
func noRedirect(c *http.Client) *http.Client {
	cp := *c
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cp
}

func do(ctx context.Context, c *http.Client, provider, op, method, u string, body any, hdr map[string]string, out any) error {
	if c == nil {
		return &Error{Provider: provider, Op: op, Permanent: true, msg: "no HTTP client"}
	}
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return &Error{Provider: provider, Op: op, Permanent: true, msg: "encode: " + err.Error()}
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return &Error{Provider: provider, Op: op, Permanent: true, msg: "build request"}
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "authsec-asks")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := noRedirect(c).Do(req)
	if err != nil {
		// The URL may carry nothing secret, but the error text of a dial can
		// be long; keep it, it is the operator's diagnosis.
		return &Error{Provider: provider, Op: op, msg: sanitize(err), err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		perm := resp.StatusCode >= 300 && resp.StatusCode < 500 && resp.StatusCode != http.StatusRequestTimeout &&
			resp.StatusCode != http.StatusTooManyRequests
		return &Error{Provider: provider, Op: op, Status: resp.StatusCode, Permanent: perm}
	}
	if out != nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return &Error{Provider: provider, Op: op, msg: "unreadable answer"}
		}
	}
	return nil
}

// sanitize keeps an error's text without any URL credentials or query.
func sanitize(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Op + " " + redactURL(ue.URL) + ": " + ue.Err.Error()
	}
	return err.Error()
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(url)"
	}
	u.User, u.RawQuery = nil, ""
	return u.String()
}

// SiteURL checks a tenant-chosen base URL (a Jira site, a ServiceNow
// instance): https, a host, no credentials, query or fragment. It returns
// the URL without a trailing slash.
func SiteURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.Opaque != "" {
		return "", errors.New("the URL must be an https:// address with a host and nothing else")
	}
	if p := strings.TrimRight(u.Path, "/"); p != "" {
		return "", errors.New("the URL must be the site's root, without a path")
	}
	return "https://" + u.Host, nil
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut]
}
