package igaread

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

// Account is how every response names an account (§2.14.6 "What every IGA
// response must carry"): {id, label, connected}, or null for Unknown account.
type Account struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Connected bool   `json:"connected"`
}

// ConnectorInfo is one AWS connector of the workspace, as the read side needs
// it: which account it reads, its operator label, and whether it is live.
type ConnectorInfo struct {
	ID        uuid.UUID
	AccountID string
	Label     string
	Status    string
	Regions   []string
}

// Accounts is the per-request directory of the workspace's AWS accounts,
// loaded once per request from its connectors, in the snapshot.
type Accounts struct {
	byAccount   map[string]*ConnectorInfo
	byConnector map[uuid.UUID]*ConnectorInfo
}

// LoadAccounts reads the workspace's AWS connectors. An account is CONNECTED
// when a connector for it exists and is not revoked; its label is the
// operator's display name, falling back to the account id.
func (q *Query) LoadAccounts() (*Accounts, error) {
	var rows []models.CloudConnector
	if err := q.tx.Where("workspace_id = ? AND provider = ?", q.WS, "aws").
		Order("created_at, id").Find(&rows).Error; err != nil {
		return nil, err
	}
	a := &Accounts{byAccount: map[string]*ConnectorInfo{}, byConnector: map[uuid.UUID]*ConnectorInfo{}}
	for i := range rows {
		c := &rows[i]
		attrs := c.AWSAttrs()
		info := &ConnectorInfo{ID: c.ID, AccountID: c.ScopeID, Label: attrs.DisplayName, Status: c.Status, Regions: attrs.Regions}
		if info.Label == "" {
			info.Label = c.ScopeID
		}
		a.byConnector[c.ID] = info
		// Prefer a live connector when an account was connected more than once.
		if prev, ok := a.byAccount[c.ScopeID]; !ok || (prev.Status == models.CloudConnectorRevoked && c.Status != models.CloudConnectorRevoked) {
			a.byAccount[c.ScopeID] = info
		}
	}
	return a, nil
}

// Of returns the account object for an account id, or nil (Unknown account)
// for "". An account no connector reads is named, with connected=false.
func (a *Accounts) Of(accountID string) *Account {
	if accountID == "" {
		return nil
	}
	if info, ok := a.byAccount[accountID]; ok {
		return &Account{ID: accountID, Label: info.Label, Connected: info.Status != models.CloudConnectorRevoked}
	}
	return &Account{ID: accountID, Label: accountID, Connected: false}
}

// Connected reports whether an account id is read by a live connector.
func (a *Accounts) Connected(accountID string) bool {
	info, ok := a.byAccount[accountID]
	return ok && info.Status != models.CloudConnectorRevoked
}

// Connector returns a connector by id, or nil.
func (a *Accounts) Connector(id uuid.UUID) *ConnectorInfo { return a.byConnector[id] }

// ConnectorForAccount returns the connector reading an account, or nil.
func (a *Accounts) ConnectorForAccount(accountID string) *ConnectorInfo {
	return a.byAccount[accountID]
}

// All returns every connector, in no particular order; callers sort when order
// matters.
func (a *Accounts) All() []*ConnectorInfo {
	out := make([]*ConnectorInfo, 0, len(a.byConnector))
	for _, c := range a.byConnector {
		out = append(out, c)
	}
	return out
}

// NativeOfKey returns the native segment of an AWS source key built by
// igagraph.Key("aws", <native>): the ARN of an identity or workload. Keys with
// more segments (ref, uid, policy ...) return the last segment; a non-AWS or
// empty key returns "".
func NativeOfKey(sourceKey string) string {
	parts := strings.Split(sourceKey, igagraph.Sep)
	if len(parts) < 2 || parts[0] != "aws" {
		return ""
	}
	return parts[len(parts)-1]
}

// ARNAccount returns the account field of an ARN when it states one
// (arn:partition:service:region:account:resource), else "". Every S3 ARN and
// every wildcard account returns "" -- never the scanning account (§2.14.10).
func ARNAccount(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" {
		return ""
	}
	acct := parts[4]
	if acct == "" || strings.ContainsAny(acct, "*?") {
		return ""
	}
	return acct
}

// ARNRegion returns the region field of an ARN when it states one, else "".
func ARNRegion(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" {
		return ""
	}
	r := parts[3]
	if r == "" || strings.ContainsAny(r, "*?") {
		return ""
	}
	return r
}

// ARNService returns the service field of an ARN, else "".
func ARNService(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" {
		return ""
	}
	return parts[2]
}

// TS renders a time as RFC 3339 UTC; nil or zero is JSON null.
func TS(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

// T renders a non-pointer time as RFC 3339 UTC; zero is JSON null.
func T(t time.Time) any { return TS(&t) }

// Exact is a count that says whether it is exact ({value, exact}, §5.3).
type Exact struct {
	Value *int64 `json:"value"`
	Exact bool   `json:"exact"`
}

// ExactOf is a known count.
func ExactOf(n int64) Exact { return Exact{Value: &n, Exact: true} }

// Unknown is a count that could not be established (an optional query that
// timed out): {value: null, exact: false}.
func Unknown() Exact { return Exact{Value: nil, Exact: false} }
