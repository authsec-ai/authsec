package awsenforce

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/authsec-ai/authsec/internal/igagov"
)

// CloudTrail evidence of one enforcement session (SPEC-iga-phase3-policy.md
// §8.1 step 2, review P1-7): resolve_unknown "looks up the enforcement
// session's CloudTrail events for the op". The lookup is made through the
// DISCOVERY role (cloudtrail:LookupEvents is a read the discovery role holds,
// §3.5), filtered server-side by the op's event name and the time window, and
// client-side by the session name (the RoleSessionName of the assumed-role
// userIdentity, authsec-enforce-<deployment 16hex>) and the op's target
// (policy ARN / name, role name, boundary ARN, version id).
//
// A lookup that cannot be completed (an API error, more pages than the bound)
// is an ERROR, never "no events": an unreadable trail is no evidence that a
// request was not applied.

// TrailAPI is the slice of CloudTrail the session lookup uses
// (*cloudtrail.Client satisfies it; enforcetest.FakeAWS fakes it).
type TrailAPI interface {
	LookupEvents(ctx context.Context, in *cloudtrail.LookupEventsInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

// NewLiveTrail builds the CloudTrail client of a discovery-role config. IAM
// is a global service whose events CloudTrail records in the partition's
// home region (TrailRegion); the caller builds cfg for that region.
func NewLiveTrail(cfg aws.Config) TrailAPI { return cloudtrail.NewFromConfig(cfg) }

// TrailRegion is the region CloudTrail records IAM (global service) events
// in for a partition.
func TrailRegion(partition string) string {
	switch partition {
	case "aws-us-gov":
		return "us-gov-west-1"
	case "aws-cn":
		return "cn-north-1"
	}
	return "us-east-1"
}

// TrailQuery selects one session's events of one IAM operation.
type TrailQuery struct {
	SessionName string
	EventName   string
	From, To    time.Time
}

// TrailEvent is one CloudTrail record of an IAM write, reduced to what
// matching an attempt needs.
type TrailEvent struct {
	EventID     string    `json:"event_id"`
	EventName   string    `json:"event_name"`
	EventTime   time.Time `json:"event_time"`
	SessionName string    `json:"session_name"`
	// ErrorCode is set when AWS refused the request (it was not applied).
	ErrorCode string `json:"error_code,omitempty"`
	// The request's target, from requestParameters (and, for CreatePolicy,
	// responseElements.policy.arn).
	PolicyARN   string `json:"policy_arn,omitempty"`
	PolicyName  string `json:"policy_name,omitempty"`
	Path        string `json:"path,omitempty"`
	RoleName    string `json:"role_name,omitempty"`
	BoundaryARN string `json:"boundary_arn,omitempty"`
	VersionID   string `json:"version_id,omitempty"`
	// DocumentHash is the canonical hash of requestParameters.policyDocument
	// when it is present and parses ("" otherwise).
	DocumentHash string `json:"document_hash,omitempty"`
}

// Applied reports whether the event records a request AWS applied.
func (e TrailEvent) Applied() bool { return e.ErrorCode == "" }

// ErrTrailIncomplete: the lookup hit its page bound; more events exist.
var ErrTrailIncomplete = errors.New("awsenforce: the CloudTrail lookup did not complete")

// maxSessionTrailPages bounds one session lookup (50 events per page). The
// server-side filter is the event name over a window of minutes to a day, so
// the bound is generous; reaching it is an error, not an empty answer.
const maxSessionTrailPages = 40

// LookupSessionEvents returns the events of q.EventName in [q.From, q.To]
// made by the assumed-role session q.SessionName.
func LookupSessionEvents(ctx context.Context, api TrailAPI, q TrailQuery) ([]TrailEvent, error) {
	if api == nil {
		return nil, errors.New("awsenforce: no CloudTrail access")
	}
	if q.SessionName == "" || q.EventName == "" {
		return nil, errors.New("awsenforce: a session lookup needs a session name and an event name")
	}
	in := &cloudtrail.LookupEventsInput{
		StartTime: aws.Time(q.From.UTC()), EndTime: aws.Time(q.To.UTC()),
		LookupAttributes: []cttypes.LookupAttribute{{AttributeKey: cttypes.LookupAttributeKeyEventName, AttributeValue: aws.String(q.EventName)}},
	}
	var out []TrailEvent
	for page := 0; ; page++ {
		if page >= maxSessionTrailPages {
			return out, fmt.Errorf("%w: %d pages of %s events", ErrTrailIncomplete, maxSessionTrailPages, q.EventName)
		}
		resp, err := api.LookupEvents(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("cloudtrail:LookupEvents %s: %w", q.EventName, err)
		}
		for _, e := range resp.Events {
			ev, ok := sessionEventFrom(e)
			if !ok || ev.SessionName != q.SessionName || ev.EventName != q.EventName {
				continue
			}
			out = append(out, ev)
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			return out, nil
		}
		in.NextToken = resp.NextToken
	}
}

// sessionRecord is the slice of a CloudTrail record a session lookup reads.
type sessionRecord struct {
	EventID      string `json:"eventID"`
	EventName    string `json:"eventName"`
	EventTime    string `json:"eventTime"`
	ErrorCode    string `json:"errorCode"`
	UserIdentity *struct {
		Type string `json:"type"`
		ARN  string `json:"arn"`
	} `json:"userIdentity"`
	RequestParameters map[string]any `json:"requestParameters"`
	ResponseElements  map[string]any `json:"responseElements"`
}

func sessionEventFrom(e cttypes.Event) (TrailEvent, bool) {
	raw := aws.ToString(e.CloudTrailEvent)
	var rec sessionRecord
	if raw == "" || json.Unmarshal([]byte(raw), &rec) != nil || rec.UserIdentity == nil || rec.UserIdentity.Type != "AssumedRole" {
		return TrailEvent{}, false
	}
	out := TrailEvent{EventID: aws.ToString(e.EventId), EventName: aws.ToString(e.EventName), ErrorCode: rec.ErrorCode}
	if out.EventName == "" {
		out.EventName = rec.EventName
	}
	if e.EventTime != nil {
		out.EventTime = e.EventTime.UTC()
	} else if t, err := time.Parse(time.RFC3339, rec.EventTime); err == nil {
		out.EventTime = t.UTC()
	}
	if _, res, ok := strings.Cut(rec.UserIdentity.ARN, ":assumed-role/"); ok {
		if parts := strings.Split(res, "/"); len(parts) >= 2 {
			out.SessionName = parts[len(parts)-1]
		}
	}
	str := func(m map[string]any, k string) string {
		if m == nil {
			return ""
		}
		s, _ := m[k].(string)
		return s
	}
	rp := rec.RequestParameters
	out.PolicyARN, out.PolicyName, out.Path = str(rp, "policyArn"), str(rp, "policyName"), str(rp, "path")
	out.RoleName, out.BoundaryARN, out.VersionID = str(rp, "roleName"), str(rp, "permissionsBoundary"), str(rp, "versionId")
	if out.PolicyARN == "" && rec.ResponseElements != nil {
		if p, ok := rec.ResponseElements["policy"].(map[string]any); ok {
			out.PolicyARN = str(p, "arn")
		}
	}
	if doc := str(rp, "policyDocument"); doc != "" {
		if dec, err := url.QueryUnescape(doc); err == nil && strings.HasPrefix(strings.TrimSpace(dec), "{") {
			doc = dec
		}
		if _, h, err := igagov.CanonicalDocument(doc); err == nil {
			out.DocumentHash = h
		}
	}
	return out, true
}

// MatchesTrail reports whether ev records THIS request: the same operation
// on the same target (and, when both carry one, the same document).
func (r Request) MatchesTrail(ev TrailEvent) bool {
	if ev.EventName != r.Op {
		return false
	}
	if r.DocumentHash != "" && ev.DocumentHash != "" && needsDocument(r.Op) && ev.DocumentHash != r.DocumentHash {
		return false
	}
	switch r.Op {
	case igagov.OpCreatePolicy:
		if ev.PolicyName != r.PolicyName {
			return false
		}
		return ev.Path == "" || r.Path == "" || ev.Path == r.Path
	case igagov.OpCreatePolicyVersion, igagov.OpTagPolicy, igagov.OpDeletePolicy:
		return ev.PolicyARN == r.PolicyARN
	case igagov.OpDeletePolicyVersion:
		return ev.PolicyARN == r.PolicyARN && ev.VersionID == r.VersionID
	case igagov.OpPutRolePermissionsBoundary:
		return ev.RoleName == r.RoleName && ev.BoundaryARN == r.PolicyARN
	case igagov.OpDeleteRolePermissionsBoundary:
		return ev.RoleName == r.RoleName
	}
	return false
}
