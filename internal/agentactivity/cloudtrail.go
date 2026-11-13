package agentactivity

import (
	"strings"

	"github.com/authsec-ai/authsec/internal/agentruntime"
)

// FromCloudTrail maps one normalised CloudTrail event to an activity row
// (spec §4.1). ok is false for records that are not activity: an
// AwsServiceEvent (a streaming call's completion record, counted once by the
// model-call evidence) or an event without an id.
func FromCloudTrail(e agentruntime.Event) (Activity, bool) {
	if e.EventID == "" || e.EventType == "AwsServiceEvent" {
		return Activity{}, false
	}
	source, kind := SourceCloudTrail, KindCloudAction
	data := strings.EqualFold(e.EventCategory, "Data")
	if data {
		source = SourceCloudTrailData
	}
	switch {
	case e.IsModelCall():
		kind = KindModelCall
	case data:
		kind = KindDataAccess
	case e.EventName == "ConsoleLogin":
		kind = KindSignIn
	}
	outcome := OutcomeSuccess
	switch {
	case e.AuthorizationDenied:
		outcome = OutcomeDenied
	case e.ErrorCode != "":
		outcome = OutcomeError
	}
	attrs := map[string]any{
		"event_source": e.EventSource,
		"event_name":   e.EventName,
	}
	put := func(k, v string) {
		if v != "" {
			attrs[k] = Truncate(v, MaxAttrString)
		}
	}
	put("event_type", e.EventType)
	put("event_category", e.EventCategory)
	put("account_id", e.AccountID)
	put("region", e.Region)
	put("source_ip", e.SourceIP)
	put("user_agent", e.UserAgent)
	put("error_code", e.ErrorCode)
	put("principal_type", e.PrincipalType)
	put("principal_arn", e.PrincipalARN)
	put("invoked_by", e.InvokedBy)
	// Weak, unverified evidence only (parent spec §10, §5.2 change).
	put("session_name", e.SessionName)
	if e.ReadOnly != nil {
		attrs["read_only"] = *e.ReadOnly
	}
	if len(e.RequestFacts) > 0 {
		facts := map[string]any{}
		for k, v := range e.RequestFacts {
			facts[k] = Truncate(v, MaxAttrString)
		}
		attrs["request_facts"] = facts
	}
	if len(e.Resources) > 0 {
		res := []any{}
		for _, r := range e.Resources {
			if len(res) == MaxArrayItems {
				break
			}
			res = append(res, Truncate(r, MaxAttrString))
		}
		attrs["resources"] = res
	}
	return Activity{
		Source: source, Kind: kind, OccurredAt: e.EventTime.UTC(),
		Action:          Truncate(serviceOf(e.EventSource)+":"+e.EventName, MaxAction),
		ResourceRef:     Truncate(cloudTrailResource(e), MaxResourceRef),
		Outcome:         outcome,
		ProviderEventID: Truncate(e.EventID, MaxProviderEventID),
		Attrs:           attrs,
	}, true
}

// serviceOf is "s3" for "s3.amazonaws.com".
func serviceOf(src string) string {
	return strings.TrimSuffix(src, ".amazonaws.com")
}

// cloudTrailResource is what the call acted on: the model, else the first
// resource ARN, else a request fact.
func cloudTrailResource(e agentruntime.Event) string {
	if m := e.RequestFacts[agentruntime.FactModelID]; m != "" {
		return m
	}
	if len(e.Resources) > 0 {
		return e.Resources[0]
	}
	for _, k := range []string{agentruntime.FactSecretID, agentruntime.FactParameter, agentruntime.FactBucket,
		agentruntime.FactFunction, agentruntime.FactRoleARN, agentruntime.FactRoleName, agentruntime.FactPolicyARN,
		agentruntime.FactUserName, agentruntime.FactTrailName, agentruntime.FactKeyID} {
		if v := e.RequestFacts[k]; v != "" {
			return v
		}
	}
	return ""
}
