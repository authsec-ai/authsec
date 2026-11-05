// Package agentruntime holds the contracts shared by agent runtime visibility
// on AWS (SPEC-agent-runtime-visibility.md, revision 2): the normalised
// CloudTrail event every reader produces, the labels the console shows, the
// model-call evidence stored in cloud_usage, and the interfaces that let the
// poller, the event-stream ingest, inference, detections and containment be
// built separately.
//
// It imports nothing from the rest of the tree, so any package may import it.
package agentruntime

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Labels (spec §1). The console uses exactly these words.
const (
	// LabelAIWorkload: seen calling a model. Evidence only, never an agent.
	LabelAIWorkload = "ai_workload"
	// LabelSuggestedAgent: an AI workload that, in the same window, also acted
	// on other resources under its own identity. A suggestion; never sets the
	// graph's classification.
	LabelSuggestedAgent = "suggested_agent"
	// LabelAgent: provider-native (projector) or classified by a person.
	LabelAgent = "agent"
)

// Event is one CloudTrail record, normalised. Produced by the LookupEvents
// poller (from CloudTrailEvent JSON) and by the EventBridge ingest (from the
// event's detail), both through ParseCloudTrailRecord.
//
// It never carries request or response bodies beyond the sanitised
// RequestFacts below: no prompts, no secret values, no policy documents.
type Event struct {
	EventID     string    // CloudTrail eventID; the idempotency key
	EventTime   time.Time // eventTime
	EventSource string    // e.g. "bedrock.amazonaws.com"
	EventName   string    // e.g. "Converse"
	// EventType is "AwsApiCall" for a real API call. A streaming call's
	// completion record is "AwsServiceEvent" with the same EventName and must
	// not be counted as a call (spec §5.1).
	EventType string
	// EventCategory is "Management" or "Data" (CloudTrail's eventCategory).
	EventCategory string
	ReadOnly      *bool  // readOnly when the record states it
	AccountID     string // recipientAccountId
	Region        string // awsRegion
	SourceIP      string // sourceIPAddress
	UserAgent     string

	// The caller (userIdentity), as awsdiscovery.TrailEvent reads it.
	PrincipalType            string // userIdentity.type
	PrincipalARN             string
	PrincipalID              string
	SessionIssuerType        string
	SessionIssuerARN         string
	SessionIssuerPrincipalID string
	SessionName              string // RoleSessionName of an assumed role
	UserName                 string // userIdentity.userName (IAM user)
	// InvokedBy is userIdentity.invokedBy, set when an AWS service made the
	// call on the principal's behalf.
	InvokedBy string

	ErrorCode    string
	ErrorMessage string
	// AuthorizationDenied: ErrorCode is one of the authorization denials
	// (AccessDenied, AccessDeniedException, UnauthorizedOperation, ...).
	AuthorizationDenied bool

	// RequestFacts are the few request parameters detections and evidence
	// need, by fixed key (FactModelID, FactSecretID, ...). Never a body.
	RequestFacts map[string]string
	// Resources are the ARNs the record lists in resources[].
	Resources []string
}

// Request fact keys (Event.RequestFacts).
const (
	FactModelID   = "model_id"   // bedrock modelId / mantle model
	FactSecretID  = "secret_id"  // secretsmanager secretId
	FactParameter = "parameter"  // ssm parameter name(s), comma-joined
	FactRoleARN   = "role_arn"   // sts AssumeRole roleArn; iam roleName as ARN when known
	FactRoleName  = "role_name"  // iam role name in IAM write calls
	FactUserName  = "user_name"  // iam userName in CreateAccessKey etc.
	FactPolicyARN = "policy_arn" // iam Attach*Policy policyArn
	FactTrailName = "trail_name" // cloudtrail name
	FactKeyID     = "key_id"     // kms keyId
	FactFunction  = "function"   // lambda functionName
	FactBucket    = "bucket"     // s3 bucketName
	// FactWithDecryption is ssm's requestParameters.withDecryption, stored
	// as "true" or "false"; absent when the record does not state it.
	FactWithDecryption = "with_decryption"
)

// Attribution is how an event is tied to an identity, mirroring
// awsdiscovery.TrailEvent.Attribution: by the session issuer (role ARN +
// RoleId) for any session, by the user ARN + AIDA id for an IAM user, and to
// nothing otherwise. Never by a name.
type Attribution struct {
	How      string // AttributionSessionIssuer | AttributionPrincipalARN | ""
	ARN      string
	UniqueID string
}

// Attribution kinds.
const (
	AttributionSessionIssuer = "session_issuer"
	AttributionPrincipalARN  = "principal_arn"
)

// Attribution returns the key the caller resolves against its inventory.
func (e Event) Attribution() Attribution {
	switch {
	case e.SessionIssuerARN != "":
		return Attribution{How: AttributionSessionIssuer, ARN: e.SessionIssuerARN, UniqueID: e.SessionIssuerPrincipalID}
	case e.PrincipalType == "IAMUser" && e.PrincipalARN != "":
		return Attribution{How: AttributionPrincipalARN, ARN: e.PrincipalARN, UniqueID: e.PrincipalID}
	}
	return Attribution{}
}

// IsAPICall reports whether the record is a real API call (not a streaming
// completion record or an AWS service event).
func (e Event) IsAPICall() bool { return e.EventType == "" || e.EventType == "AwsApiCall" }

// Model-call event sources and names (spec §5.1).
const (
	SourceBedrock = "bedrock.amazonaws.com"
	// SourceBedrockMantle is the OpenAI/Anthropic-compatible endpoint's event
	// source. UNVERIFIED: confirm against a lab call before relying on it
	// (spec §5.1); ModelCallSources matches it by prefix as well.
	SourceBedrockMantle = "bedrock-mantle.amazonaws.com"
	SourceAgentCore     = "bedrock-agentcore.amazonaws.com"
)

// modelCallNames are the Bedrock Runtime operations that run inference.
var modelCallNames = map[string]bool{
	"InvokeModel": true, "InvokeModelWithResponseStream": true,
	"Converse": true, "ConverseStream": true,
	"InvokeAgent": true, "InvokeInlineAgent": true,
	"RetrieveAndGenerate": true, "RetrieveAndGenerateStream": true, "InvokeFlow": true,
}

// IsModelCall reports whether the event is an inference call by its caller:
// a real API call to a Bedrock inference operation, or any API call to the
// mantle endpoint whose name is an inference operation there.
func (e Event) IsModelCall() bool {
	if !e.IsAPICall() {
		return false
	}
	switch {
	case e.EventSource == SourceBedrock:
		return modelCallNames[e.EventName]
	case isMantleSource(e.EventSource):
		return true
	}
	return false
}

func isMantleSource(src string) bool {
	return src == SourceBedrockMantle || (len(src) > len("bedrock-mantle") && src[:len("bedrock-mantle")] == "bedrock-mantle")
}

// ModelCallUsage is the attrs document of a cloud_usage row with
// source='cloudtrail', service='bedrock' (spec §5.1): one row per identity,
// cumulative over the windows read, with the coverage of what was read.
type ModelCallUsage struct {
	Calls  int `json:"calls"`  // successful AwsApiCall model calls
	Errors int `json:"errors"` // non-authorization errors
	// Denied counts authorization refusals: with the tag-gated template in
	// deny mode these are the untagged AI workloads (spec §5.4).
	Denied       int            `json:"denied"`
	Models       map[string]int `json:"models"`        // model id -> calls
	Endpoints    map[string]int `json:"endpoints"`     // event source -> calls
	SessionNames []string       `json:"session_names"` // capped; weak evidence only (§5.2)
	FirstCallAt  *time.Time     `json:"first_call_at,omitempty"`
	LastCallAt   *time.Time     `json:"last_call_at,omitempty"`
	// Tokens is the sum of token counts from stream-completion records and
	// responses that state them; 0 when none did.
	Tokens int64 `json:"tokens"`
	// CoveredFrom / CoveredTo bound what was read; Partial says a cap was hit
	// inside it, so "no calls" is not claimed for the gap (§5.1).
	CoveredFrom *time.Time `json:"covered_from,omitempty"`
	CoveredTo   *time.Time `json:"covered_to,omitempty"`
	Partial     bool       `json:"partial"`
	// OtherServices are the other AWS services the identity called in the
	// same windows (event source -> successful calls): the "acted on other
	// resources" evidence of a suggested agent (§5.3).
	OtherServices map[string]int `json:"other_services"`

	// Live evidence (the "agent_runtime_live" sink): model calls seen on the
	// event stream (or a poll's dispatch) AFTER the scan's exact coverage of
	// their region, so a new AI workload shows before the next scan. Never
	// added to the exact counts above, which only the scan writes. An event
	// inside the scan's coverage of its region is not counted live (the scan
	// counts it). LiveCalls, LiveDenied, LiveModels and LiveRegions are
	// cleared once the scan's coverage of every region in LiveRegions reaches
	// that region's latest live call (the scan now counts those calls
	// exactly); LiveLastCallAt is kept, so "seen live" stays answerable.
	LiveCalls      int            `json:"live_calls"`
	LiveDenied     int            `json:"live_denied"`
	LiveLastCallAt *time.Time     `json:"live_last_call_at,omitempty"`
	LiveModels     map[string]int `json:"live_models,omitempty"`
	// LiveRegions is each region's latest live call: the counters are
	// cleared only once the scan covers every one of them.
	LiveRegions map[string]time.Time `json:"live_regions,omitempty"`
}

// Usage keys in cloud_usage.
const (
	UsageSource  = "cloudtrail"
	UsageService = "bedrock"
)

// Subject is what an event's identity is, resolved within one workspace.
type Subject struct {
	IdentityID  uuid.UUID   // cloud_identity id; uuid.Nil when unresolved
	ConnectorID uuid.UUID   // the account's connector
	WorkloadIDs []uuid.UUID // cloud_workload rows that run as the identity
	// Label is the strongest of LabelAgent, LabelSuggestedAgent,
	// LabelAIWorkload, or "" when the identity is none of them.
	Label string
	// SharedRole: more than one workload runs as the identity.
	SharedRole bool
	Name       string // display name for alerts
}

// SubjectResolver resolves an event's attribution to a Subject. Implemented
// by inference (it knows the labels); used by detections and containment.
type SubjectResolver interface {
	Resolve(ctx context.Context, workspaceID, connectorID uuid.UUID, a Attribution) (Subject, error)
}

// EventSink receives normalised events of one connector, from the scan
// poller and from the stream ingest. Sinks must be idempotent by EventID: the
// same event can arrive from both paths.
type EventSink interface {
	Name() string
	Process(ctx context.Context, workspaceID, connectorID uuid.UUID, events []Event) error
}
