package agentruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// authorizationErrorCodes mirrors awsdiscovery.AuthorizationErrorCodes.
var authorizationErrorCodes = map[string]bool{
	"AccessDenied":                 true,
	"AccessDeniedException":        true,
	"UnauthorizedOperation":        true,
	"Client.UnauthorizedOperation": true,
}

type rawIdentity struct {
	Type           string `json:"type"`
	ARN            string `json:"arn"`
	PrincipalID    string `json:"principalId"`
	UserName       string `json:"userName"`
	InvokedBy      string `json:"invokedBy"`
	SessionContext *struct {
		SessionIssuer *struct {
			Type        string `json:"type"`
			ARN         string `json:"arn"`
			PrincipalID string `json:"principalId"`
		} `json:"sessionIssuer"`
	} `json:"sessionContext"`
}

type rawRecord struct {
	EventID            string                     `json:"eventID"`
	EventTime          string                     `json:"eventTime"`
	EventSource        string                     `json:"eventSource"`
	EventName          string                     `json:"eventName"`
	EventType          string                     `json:"eventType"`
	EventCategory      string                     `json:"eventCategory"`
	ReadOnly           *bool                      `json:"readOnly"`
	RecipientAccountID string                     `json:"recipientAccountId"`
	AWSRegion          string                     `json:"awsRegion"`
	SourceIPAddress    string                     `json:"sourceIPAddress"`
	UserAgent          string                     `json:"userAgent"`
	UserIdentity       *rawIdentity               `json:"userIdentity"`
	ErrorCode          string                     `json:"errorCode"`
	ErrorMessage       string                     `json:"errorMessage"`
	RequestParameters  map[string]json.RawMessage `json:"requestParameters"`
	Resources          []struct {
		ARN string `json:"ARN"`
	} `json:"resources"`
}

// requestFactKeys maps a requestParameters key to the RequestFacts key it
// fills. Only scalar strings (or string arrays, comma-joined) and booleans
// ("true" / "false") are kept.
var requestFactKeys = map[string]string{
	"modelId":      FactModelID,
	"model":        FactModelID,
	"secretId":     FactSecretID,
	"name":         FactParameter, // ssm GetParameter; cloudtrail trail name is "name" too, see below
	"names":        FactParameter,
	"roleArn":      FactRoleARN,
	"roleName":     FactRoleName,
	"userName":     FactUserName,
	"policyArn":    FactPolicyARN,
	"trailName":    FactTrailName,
	"keyId":        FactKeyID,
	"functionName": FactFunction,
	"bucketName":   FactBucket,
	// ssm GetParameter*: a bool, kept as "true" / "false" (detect D1).
	"withDecryption": FactWithDecryption,
}

// ParseCloudTrailRecord normalises one CloudTrail record (the JSON of
// LookupEvents' CloudTrailEvent, or EventBridge's detail).
func ParseCloudTrailRecord(raw []byte) (Event, error) {
	var r rawRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return Event{}, fmt.Errorf("cloudtrail record: %w", err)
	}
	if r.EventID == "" || r.EventName == "" {
		return Event{}, fmt.Errorf("cloudtrail record: missing eventID or eventName")
	}
	e := Event{
		EventID: r.EventID, EventSource: r.EventSource, EventName: r.EventName,
		EventType: r.EventType, EventCategory: r.EventCategory, ReadOnly: r.ReadOnly,
		AccountID: r.RecipientAccountID, Region: r.AWSRegion, SourceIP: r.SourceIPAddress,
		UserAgent: r.UserAgent, ErrorCode: r.ErrorCode, ErrorMessage: r.ErrorMessage,
		AuthorizationDenied: authorizationErrorCodes[r.ErrorCode],
	}
	if t, err := time.Parse(time.RFC3339, r.EventTime); err == nil {
		e.EventTime = t.UTC()
	}
	if id := r.UserIdentity; id != nil {
		e.PrincipalType, e.PrincipalARN, e.PrincipalID = id.Type, id.ARN, id.PrincipalID
		e.UserName, e.InvokedBy = id.UserName, id.InvokedBy
		if id.SessionContext != nil && id.SessionContext.SessionIssuer != nil {
			si := id.SessionContext.SessionIssuer
			e.SessionIssuerType, e.SessionIssuerARN, e.SessionIssuerPrincipalID = si.Type, si.ARN, si.PrincipalID
		}
		if id.Type == "AssumedRole" {
			if i := strings.LastIndex(id.ARN, "/"); i >= 0 {
				e.SessionName = id.ARN[i+1:]
			}
		}
	}
	for k, v := range r.RequestParameters {
		fk, ok := requestFactKeys[k]
		if !ok {
			continue
		}
		if k == "name" && e.EventSource == "cloudtrail.amazonaws.com" {
			fk = FactTrailName
		}
		if s := scalarString(v); s != "" {
			if e.RequestFacts == nil {
				e.RequestFacts = map[string]string{}
			}
			e.RequestFacts[fk] = s
		}
	}
	for _, res := range r.Resources {
		if res.ARN != "" {
			e.Resources = append(e.Resources, res.ARN)
		}
	}
	return e, nil
}

func scalarString(v json.RawMessage) string {
	var s string
	if json.Unmarshal(v, &s) == nil {
		return truncate(s, 512)
	}
	var arr []string
	if json.Unmarshal(v, &arr) == nil && len(arr) > 0 {
		if len(arr) > 20 {
			arr = arr[:20]
		}
		return truncate(strings.Join(arr, ","), 512)
	}
	var b bool
	if json.Unmarshal(v, &b) == nil {
		if b {
			return "true"
		}
		return "false"
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// EventBridgeEnvelope is the part of an EventBridge event the ingest reads.
type EventBridgeEnvelope struct {
	ID         string          `json:"id"`
	DetailType string          `json:"detail-type"`
	Source     string          `json:"source"`
	Account    string          `json:"account"`
	Region     string          `json:"region"`
	Detail     json.RawMessage `json:"detail"`
}

// CloudTrail detail types EventBridge delivers.
const (
	DetailTypeAPICall     = "AWS API Call via CloudTrail"
	DetailTypeServiceEvt  = "AWS Service Event via CloudTrail"
	DetailTypeConsoleSign = "AWS Console Sign In via CloudTrail"
)

// ParseEventBridge normalises one EventBridge event carrying a CloudTrail
// record. The account in the envelope must match the record's recipient
// account; the caller checks it against the connector's account.
func ParseEventBridge(raw []byte) (Event, error) {
	var env EventBridgeEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return Event{}, fmt.Errorf("eventbridge event: %w", err)
	}
	switch env.DetailType {
	case DetailTypeAPICall, DetailTypeServiceEvt, DetailTypeConsoleSign:
	default:
		return Event{}, fmt.Errorf("eventbridge event: unsupported detail-type %q", env.DetailType)
	}
	e, err := ParseCloudTrailRecord(env.Detail)
	if err != nil {
		return Event{}, err
	}
	if e.AccountID == "" {
		e.AccountID = env.Account
	}
	if e.Region == "" {
		e.Region = env.Region
	}
	return e, nil
}

/* ---------------------------------------------------------------------------- */
/*                                   Registry                                   */
/* ---------------------------------------------------------------------------- */

var registry struct {
	sync.RWMutex
	sinks    []EventSink
	resolver SubjectResolver
}

// RegisterSink adds a sink (cmd/main.go; tests). Order is registration order.
func RegisterSink(s EventSink) {
	registry.Lock()
	defer registry.Unlock()
	for _, x := range registry.sinks {
		if x.Name() == s.Name() {
			return
		}
	}
	registry.sinks = append(registry.sinks, s)
}

// Sinks returns the registered sinks.
func Sinks() []EventSink {
	registry.RLock()
	defer registry.RUnlock()
	return append([]EventSink(nil), registry.sinks...)
}

// ResetSinks clears the registry (tests).
func ResetSinks() {
	registry.Lock()
	registry.sinks = nil
	registry.resolver = nil
	registry.Unlock()
}

// SetResolver installs the subject resolver (inference installs it).
func SetResolver(r SubjectResolver) {
	registry.Lock()
	registry.resolver = r
	registry.Unlock()
}

// Resolver returns the installed resolver, or nil.
func Resolver() SubjectResolver {
	registry.RLock()
	defer registry.RUnlock()
	return registry.resolver
}

// Dispatch hands events of one connector to every sink. A sink's error does
// not stop the others; the first error is returned.
func Dispatch(ctx context.Context, workspaceID, connectorID uuid.UUID, events []Event) error {
	if len(events) == 0 {
		return nil
	}
	var first error
	for _, s := range Sinks() {
		if err := s.Process(ctx, workspaceID, connectorID, events); err != nil && first == nil {
			first = fmt.Errorf("sink %s: %w", s.Name(), err)
		}
	}
	return first
}
