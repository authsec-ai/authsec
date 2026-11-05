// Package agentactivity normalises what an AI workload or agent did into
// activity rows (SPEC-agent-runtime-activity.md): CloudTrail events, AgentCore
// observability spans read from CloudWatch Logs, and OpenTelemetry spans
// posted to the OTLP receiver.
//
// It holds no database code and never decides a workspace: callers resolve
// attribution hints within the workspace their credential names.
//
// What it never keeps (spec §6): prompt, completion and message content, tool
// call argument values (a sha256 digest only), span events, status messages,
// and anything not on the allowlist in span.go.
package agentactivity

import (
	"strings"
	"time"
	"unicode/utf8"
)

// Sources (agent_activity_event.source).
const (
	SourceCloudTrail      = "cloudtrail"
	SourceCloudTrailData  = "cloudtrail_data"
	SourceAgentCoreSpan   = "agentcore_span"
	SourceOTLP            = "otlp"
	SourceAuthSecDecision = "authsec_decision"
)

// Kinds (agent_activity_event.kind).
const (
	KindModelCall   = "model_call"
	KindToolCall    = "tool_call"
	KindAgentStep   = "agent_step"
	KindCloudAction = "cloud_action"
	KindDataAccess  = "data_access"
	KindSignIn      = "sign_in"
	KindDecision    = "decision"
)

// Outcomes (agent_activity_event.outcome).
const (
	OutcomeSuccess = "success"
	OutcomeDenied  = "denied"
	OutcomeError   = "error"
)

// Column limits (migration 155's CHECKs and spec §8).
const (
	MaxAction          = 200
	MaxResourceRef     = 512
	MaxOnBehalfOf      = 256
	MaxProviderEventID = 300
	MaxIDLen           = 64
	MaxAttrString      = 256
	MaxAttrKeys        = 64
	MaxArrayItems      = 10
)

// ValidSource, ValidKind and ValidOutcome check API filter values.
func ValidSource(s string) bool {
	switch s {
	case SourceCloudTrail, SourceCloudTrailData, SourceAgentCoreSpan, SourceOTLP, SourceAuthSecDecision:
		return true
	}
	return false
}

func ValidKind(s string) bool {
	switch s {
	case KindModelCall, KindToolCall, KindAgentStep, KindCloudAction, KindDataAccess, KindSignIn, KindDecision:
		return true
	}
	return false
}

func ValidOutcome(s string) bool {
	switch s {
	case OutcomeSuccess, OutcomeDenied, OutcomeError:
		return true
	}
	return false
}

// Activity is one row before attribution: everything agent_activity_event
// stores except the workspace and the connector / identity / workload ids,
// which the caller resolves from Hints within its workspace.
type Activity struct {
	Source          string
	Kind            string
	OccurredAt      time.Time
	Action          string
	ResourceRef     string
	Outcome         string
	OnBehalfOf      string // "" when the source states no human
	TraceID         string
	SpanID          string
	ParentSpanID    string
	ProviderEventID string
	// Attrs is sanitised: allowlisted keys, bounded strings, no content.
	Attrs map[string]any
	// Hints say what the activity claims to belong to. Never trusted for the
	// workspace; resolved against the caller's workspace inventory only.
	Hints Hints
}

// Hints are attribution claims from span resource attributes (OTLP: asserted
// by the sender) or from the AgentCore span record.
type Hints struct {
	WorkloadID  string // authsec.workload_id
	IdentityARN string // authsec.identity_arn
	AccountID   string // cloud.account.id
	Region      string // cloud.region
	ResourceARN string // cloud.resource_id / faas.id / aws.lambda.invoked_arn
	FaaSName    string // faas.name
	ECSFamily   string // aws.ecs.task.family
	ECSRevision string // aws.ecs.task.revision
	RuntimeARN  string // the AgentCore runtime ARN prefix, when ResourceARN is one
	AgentID     string // gen_ai.agent.id (AgentCore runtime id fallback)
}

// Empty reports hints that name nothing.
func (h Hints) Empty() bool { return h == Hints{} }

// Key identifies equal hints (a resolution cache key).
func (h Hints) Key() string {
	return strings.Join([]string{h.WorkloadID, h.IdentityARN, h.AccountID, h.Region, h.ResourceARN,
		h.FaaSName, h.ECSFamily, h.ECSRevision, h.RuntimeARN, h.AgentID}, "\x1f")
}

// Truncate cuts s to at most n bytes on a rune boundary.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// NormaliseID lower-cases a trace or span id and strips an X-Ray trace id's
// "1-" prefix and dashes ("1-5759e988-bd862e3fe1be46a994272793" ->
// "5759e988bd862e3fe1be46a994272793"). "" when it is not hex or too long, or
// all zeros (OTLP's "no parent").
func NormaliseID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if strings.HasPrefix(s, "1-") && strings.Count(s, "-") == 2 {
		s = strings.ReplaceAll(s[2:], "-", "")
	}
	if s == "" || len(s) > MaxIDLen {
		return ""
	}
	zero := true
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			if r != '0' {
				zero = false
			}
		default:
			return ""
		}
	}
	if zero {
		return ""
	}
	return s
}
