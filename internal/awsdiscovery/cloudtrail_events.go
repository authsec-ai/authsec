package awsdiscovery

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// CloudTrail management events: WHO actually called WHAT, including calls
// AWS denied. iam:GenerateServiceLastAccessedDetails (activity.go) answers
// "has this identity touched this SERVICE, ever" from a rolling window AWS
// maintains for you; it cannot show a single call, cannot show a denied
// attempt, and cannot show WHICH other identity was assuming a shared role
// when it happened. CloudTrail is the source that can, at the cost this file
// is built around: LookupEvents is account-wide, not identity-scoped, and
// there is no server-side filter for "calls made while assuming role R".
//
// ATTRIBUTION (SPEC-iga-phase3-policy.md §8.6, T3.04). An event is tied to an
// identity by the record's own userIdentity, never by a name:
//
//   - an assumed-role session (and a federated-user session) by
//     userIdentity.sessionContext.sessionIssuer: its arn is the role's ARN and
//     its principalId the role's RoleId, the incarnation. Username is the
//     SESSION's display form ("session-name", or "AssumedRole/R/session-name",
//     inconsistently across event sources), so matching it against role names
//     attributed a session named like some other role to that role, and never
//     attributed the role's own sessions. It is not used for a session.
//   - an IAM user's own call by userIdentity.arn and principalId (AIDA...).
//   - a record that carries no userIdentity at all -- not one CloudTrail
//     writes, but the shape of a LookupEvents result whose CloudTrailEvent
//     could not be read -- falls back to the legacy hint, Username against an
//     IAM USER's name only, and says so (AttributionUsername).
//
// Any other principal (root, an AWS service, another account, an Identity
// Center user, a session whose issuer the record omits) is attributed to
// nothing. The caller decides whether an attribution key names one of its
// identities and checks the incarnation (TrailEvent.Attribution).
//
// The record's errorCode and errorMessage are read too: an authorization
// error code marks the event AuthorizationDenied, and the message's documented
// phrase names which policy type denied it (ClassifyDenial). The message text
// itself is never kept.
//
// WHY BOUNDED. LookupEvents has no documented hard rate limit as generous as
// most list calls, and an account's default trail can hold ninety days of
// management events -- reading all of it every scan does not scale with
// account age. lookupWindow and maxPages bound one call to a recent slice,
// the same trade activity.go's own header makes explicit for the wider
// CloudTrail upgrade this is a first, narrower step toward.

// CloudTrailAPI is the slice of CloudTrail this package uses.
type CloudTrailAPI interface {
	LookupEvents(ctx context.Context, in *cloudtrail.LookupEventsInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)

	// DescribeTrails/GetTrailStatus answer a different question than
	// LookupEvents: not "what happened", but "is anything capturing what
	// happens at all". RecentEvents returning nothing is ambiguous between a
	// quiet account and a blind one -- these two calls are what tells the two
	// apart. Granted in the role template from the start; this file is the
	// first caller.
	DescribeTrails(ctx context.Context, in *cloudtrail.DescribeTrailsInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error)
	GetTrailStatus(ctx context.Context, in *cloudtrail.GetTrailStatusInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error)
}

// NewCloudTrailClient builds a real CloudTrail client.
func NewCloudTrailClient(cfg aws.Config) CloudTrailAPI { return cloudtrail.NewFromConfig(cfg) }

// lookupWindow bounds LookupEvents to a recent slice rather than however much
// history the account's trail retains.
const lookupWindow = 48 * time.Hour

// maxTrailPages bounds one RecentEvents read: at LookupEvents' 50 events per
// page, 200 pages is the first 10,000 events of the window. Its own constant,
// not IAM's maxPages: that one is sized for 1,000-item pages and a runaway
// marker, while this one is a deliberate cost bound that a busy account
// reaches in normal operation. Reaching it is reported as a partial read.
const (
	maxTrailPages       = 200
	lookupEventsPerPage = 50
)

// TrailEvent is one CloudTrail management event, reduced to what a reader
// needs to decide whether it is evidence of one of THIS scan's identities
// acting -- including a call AWS denied, which
// GenerateServiceLastAccessedDetails cannot show at all.
type TrailEvent struct {
	EventID     string
	EventName   string
	EventSource string
	EventTime   time.Time
	// Username is CloudTrail's own field, kept verbatim -- see the file header
	// on why it is a hint for the caller to match, not a resolved identity.
	Username string
	// ErrorCode is set when AWS denied or otherwise rejected the call. Absent
	// entirely for a normal successful event, not merely empty, so a caller
	// can tell "no error recorded" from "recorded and empty".
	ErrorCode string
	// Denied is the legacy flag: true for ANY error code (a throttle or a
	// NoSuchBucket included). AuthorizationDenied is the narrow one.
	Denied bool

	// The record's userIdentity (T3.04). PrincipalType is userIdentity.type
	// ("AssumedRole", "IAMUser", "FederatedUser", "Root", "AWSService", ...);
	// "" when the record carried no userIdentity.
	PrincipalType string
	// PrincipalARN and PrincipalID are userIdentity.arn and principalId: for
	// an assumed role "arn:aws:sts::<acct>:assumed-role/<role>/<session>" and
	// "AROA...:<session>"; for an IAM user its ARN and AIDA... id.
	PrincipalARN string
	PrincipalID  string
	// SessionIssuer* are userIdentity.sessionContext.sessionIssuer: for an
	// assumed role, the ROLE -- its ARN (with its path) and its RoleId. Empty
	// for a call that was not made from a session.
	SessionIssuerType        string
	SessionIssuerARN         string
	SessionIssuerPrincipalID string
	// SessionName is the RoleSessionName: the last segment of an assumed-role
	// userIdentity.arn. Empty for anything but an assumed-role session.
	SessionName string

	// AuthorizationDenied is true only for the authorization error codes
	// (AuthorizationErrorCodes): AWS refused the call on a policy decision.
	AuthorizationDenied bool
	// DenialPolicyType is set exactly when AuthorizationDenied: the policy type
	// errorMessage names (ClassifyDenial), DenialUnknown when it names none.
	DenialPolicyType string
}

// AuthorizationErrorCodes are the error codes that mean AWS denied a call on
// an authorization decision (SPEC-iga-phase3-policy.md §8.6). Any other
// error code -- a throttle, a missing resource, a validation error -- is not
// a denial and must never be read as one.
var AuthorizationErrorCodes = map[string]bool{
	"AccessDenied":                 true,
	"AccessDeniedException":        true,
	"UnauthorizedOperation":        true,
	"Client.UnauthorizedOperation": true,
}

// Denial policy types (sanitized_facts.denial_policy_type, §8.6): which policy
// type AWS's access-denied message names as the reason.
const (
	DenialPermissionsBoundary = "permissions_boundary"
	DenialIdentityPolicy      = "identity_policy"
	DenialSCP                 = "scp"
	DenialRCP                 = "rcp"
	DenialResourcePolicy      = "resource_policy"
	DenialSessionPolicy       = "session_policy"
	DenialUnknown             = "unknown"
)

// denialReason matches the reason clause of AWS's access-denied messages
// ("Access denied error messages", IAM User Guide): an implicit deny reads
// "... because no <policy type> allows the <action> action", an explicit one
// "... with an explicit deny in a(n) <policy type>". Anchored on those two
// clauses so a policy-type phrase anywhere else in the message (a resource
// name, a session name) is not taken for the reason.
var denialReason = regexp.MustCompile(`(?i)(?:because no|with an explicit deny in an?)\s+` +
	`(permissions boundary|identity-based policy|service control policy|resource control policy|` +
	`resource-based policy|session policy|vpc endpoint policy)`)

// ClassifyDenial names the policy type an access-denied message attributes the
// denial to, from AWS's documented phrases. A message with no recognised
// reason clause -- an older or service-specific format, an encoded EC2
// authorization message, a VPC endpoint policy (not a type this enum names) --
// is DenialUnknown: never guessed.
func ClassifyDenial(message string) string {
	m := denialReason.FindStringSubmatch(message)
	if m == nil {
		return DenialUnknown
	}
	switch strings.ToLower(m[1]) {
	case "permissions boundary":
		return DenialPermissionsBoundary
	case "identity-based policy":
		return DenialIdentityPolicy
	case "service control policy":
		return DenialSCP
	case "resource control policy":
		return DenialRCP
	case "resource-based policy":
		return DenialResourcePolicy
	case "session policy":
		return DenialSessionPolicy
	}
	return DenialUnknown
}

// How an event was tied to an identity (sanitized_facts.attribution).
const (
	// AttributionSessionIssuer: a session, by sessionContext.sessionIssuer's
	// ARN and principalId (the role's RoleId).
	AttributionSessionIssuer = "session_issuer"
	// AttributionPrincipalARN: an IAM user's own call, by userIdentity.arn and
	// principalId.
	AttributionPrincipalARN = "principal_arn"
	// AttributionUsername: a record with no userIdentity; Username matched
	// against an IAM user's name. A hint, and only ever an IAM user.
	AttributionUsername = "username"
)

// Attribution is what the caller looks an event's identity up by.
type Attribution struct {
	// How is one of the Attribution* constants; "" means the event names no
	// identity this reader can attribute, and it must not be matched at all.
	How string
	// ARN is the identity's ARN (the session issuer's, or the user's); empty
	// for AttributionUsername.
	ARN string
	// UniqueID is the identity's immutable id as the record states it (RoleId
	// or AIDA...). When both it and the identity's recorded unique id are
	// known they must be equal: a role recreated under the same ARN is a
	// different principal, and its predecessor's events are not its own.
	UniqueID string
	// UserName is the IAM user name for AttributionUsername.
	UserName string
}

// Attribution says how this event may be tied to an identity (see the file
// header). Pure: the caller resolves the key against its own inventory.
func (e TrailEvent) Attribution() Attribution {
	switch {
	case e.PrincipalType == "" && e.PrincipalARN == "" && e.SessionIssuerARN == "":
		// No userIdentity in the record at all: the legacy hint, users only.
		if e.Username == "" {
			return Attribution{}
		}
		return Attribution{How: AttributionUsername, UserName: e.Username}
	case e.SessionIssuerARN != "":
		// Any session -- an assumed role, a federated user -- belongs to its
		// issuer, whatever its own display name is.
		return Attribution{How: AttributionSessionIssuer, ARN: e.SessionIssuerARN, UniqueID: e.SessionIssuerPrincipalID}
	case e.PrincipalType == "IAMUser" && e.PrincipalARN != "":
		return Attribution{How: AttributionPrincipalARN, ARN: e.PrincipalARN, UniqueID: e.PrincipalID}
	}
	// An assumed role whose record omits its issuer, root, an AWS service,
	// another account, an Identity Center user: nothing to attribute to.
	return Attribution{}
}

// CloudTrailReader reads recent management events for one region.
type CloudTrailReader struct {
	api CloudTrailAPI
}

// NewCloudTrailReader constructs a reader over the given API.
func NewCloudTrailReader(api CloudTrailAPI) *CloudTrailReader {
	return &CloudTrailReader{api: api}
}

// RecentEvents lists management events from the last lookupWindow, across at
// most maxPages of up to 50 events each.
//
// No LookupAttributes filter is applied: CloudTrail permits only one, and
// filtering by Username would mean one call per identity for an account that
// may have hundreds, where this unfiltered call costs the same regardless of
// how many identities it ends up matching.
func (r *CloudTrailReader) RecentEvents(ctx context.Context) ([]TrailEvent, error) {
	if r.api == nil {
		return nil, nil
	}
	now := time.Now()
	start := now.Add(-lookupWindow)

	var out []TrailEvent
	var next *string
	for page := 0; ; page++ {
		if page >= maxTrailPages {
			return out, fmt.Errorf("%w: read the first %d CloudTrail events of the last %s; more exist",
				ErrTooManyPages, maxTrailPages*lookupEventsPerPage, lookupWindow)
		}
		resp, err := r.api.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
			StartTime: aws.Time(start), EndTime: aws.Time(now), NextToken: next,
		})
		if err != nil {
			return out, classify(err)
		}
		for _, e := range resp.Events {
			out = append(out, trailEventFrom(e))
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			return out, nil
		}
		next = resp.NextToken
	}
}

// trailEventFrom normalises one SDK event. The error code, the error message
// and the principal are read out of the embedded CloudTrailEvent JSON:
// LookupEvents' own typed fields surface none of them, only the raw event
// record does.
func trailEventFrom(e cttypes.Event) TrailEvent {
	out := TrailEvent{
		EventID:     aws.ToString(e.EventId),
		EventName:   aws.ToString(e.EventName),
		EventSource: aws.ToString(e.EventSource),
		Username:    aws.ToString(e.Username),
	}
	if e.EventTime != nil {
		out.EventTime = *e.EventTime
	}
	raw := aws.ToString(e.CloudTrailEvent)
	var rec trailRecord
	message := ""
	if raw != "" && json.Unmarshal([]byte(raw), &rec) == nil {
		out.ErrorCode, message = rec.ErrorCode, rec.ErrorMessage
		if u := rec.UserIdentity; u != nil {
			out.PrincipalType, out.PrincipalARN, out.PrincipalID = u.Type, u.ARN, u.PrincipalID
			if u.SessionContext != nil && u.SessionContext.SessionIssuer != nil {
				si := u.SessionContext.SessionIssuer
				out.SessionIssuerType, out.SessionIssuerARN, out.SessionIssuerPrincipalID = si.Type, si.ARN, si.PrincipalID
			}
			out.SessionName = assumedRoleSessionName(u.Type, u.ARN)
		}
	} else {
		// Not a record this reader can decode: the error code is still worth
		// keeping, from the one narrow scan the reader always made.
		out.ErrorCode = errorCodeFromRawEvent(raw)
	}
	if out.ErrorCode != "" {
		out.Denied = true
		if AuthorizationErrorCodes[out.ErrorCode] {
			out.AuthorizationDenied = true
			out.DenialPolicyType = ClassifyDenial(message)
		}
	}
	return out
}

// trailRecord is the slice of a CloudTrail record this reader reads. Fields it
// does not name are ignored, so the record schema can grow without breaking it.
type trailRecord struct {
	ErrorCode    string `json:"errorCode"`
	ErrorMessage string `json:"errorMessage"`
	UserIdentity *struct {
		Type           string `json:"type"`
		ARN            string `json:"arn"`
		PrincipalID    string `json:"principalId"`
		SessionContext *struct {
			SessionIssuer *struct {
				Type        string `json:"type"`
				ARN         string `json:"arn"`
				PrincipalID string `json:"principalId"`
			} `json:"sessionIssuer"`
		} `json:"sessionContext"`
	} `json:"userIdentity"`
}

// assumedRoleSessionName is the RoleSessionName of an assumed-role session:
// the last segment of "arn:<partition>:sts::<acct>:assumed-role/<role>/<session>".
// Empty for any other principal -- a federated user's name is not a role
// session name.
func assumedRoleSessionName(principalType, arn string) string {
	if principalType != "AssumedRole" {
		return ""
	}
	_, resource, ok := strings.Cut(arn, ":assumed-role/")
	if !ok {
		return ""
	}
	parts := strings.Split(resource, "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-1]
}

// errorCodeFromRawEvent extracts errorCode from a raw event that did not
// decode as JSON: a cheap, deliberately narrow scan for one field.
func errorCodeFromRawEvent(raw string) string {
	const key = `"errorCode":"`
	i := strings.Index(raw, key)
	if i < 0 {
		return ""
	}
	rest := raw[i+len(key):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// TrailStatus is one trail's configuration plus whether it is actually
// logging right now. IsLogging is nil when GetTrailStatus itself failed for
// a trail DescribeTrails could see -- a trail we cannot get the status of is
// still worth recording as evidence, and nil keeps that failure from being
// misread as a confirmed "not logging".
type TrailStatus struct {
	NativeID                   string // trail ARN
	Name                       string
	HomeRegion                 string
	IsMultiRegionTrail         bool
	IsOrganizationTrail        bool
	IncludeGlobalServiceEvents bool
	LogFileValidationEnabled   bool
	IsLogging                  *bool
}

// Trails describes every trail visible in this region and whether each is
// actually logging.
//
// IncludeShadowTrails is set false: a shadow trail is the same trail's
// config replicated into every other Region, and this reader already runs
// once per Region as part of the wider scan -- including shadow trails would
// report the same organization trail's logging state once per Region on top
// of the one Region call that already reports it for real.
func (r *CloudTrailReader) Trails(ctx context.Context) ([]TrailStatus, error) {
	if r.api == nil {
		return nil, nil
	}
	resp, err := r.api.DescribeTrails(ctx,
		&cloudtrail.DescribeTrailsInput{IncludeShadowTrails: aws.Bool(false)})
	if err != nil {
		return nil, classify(err)
	}
	out := make([]TrailStatus, 0, len(resp.TrailList))
	for _, t := range resp.TrailList {
		ts := TrailStatus{
			NativeID:                   aws.ToString(t.TrailARN),
			Name:                       aws.ToString(t.Name),
			HomeRegion:                 aws.ToString(t.HomeRegion),
			IsMultiRegionTrail:         aws.ToBool(t.IsMultiRegionTrail),
			IsOrganizationTrail:        aws.ToBool(t.IsOrganizationTrail),
			IncludeGlobalServiceEvents: aws.ToBool(t.IncludeGlobalServiceEvents),
			LogFileValidationEnabled:   aws.ToBool(t.LogFileValidationEnabled),
		}
		// GetTrailStatus takes a name OR an arn; the ARN always resolves, a
		// bare name does not for an organization trail replicated from
		// another account, so the ARN is preferred whenever DescribeTrails
		// returned one.
		id := ts.Name
		if ts.NativeID != "" {
			id = ts.NativeID
		}
		if statusResp, serr := r.api.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: aws.String(id)}); serr == nil {
			logging := aws.ToBool(statusResp.IsLogging)
			ts.IsLogging = &logging
		}
		out = append(out, ts)
	}
	return out, nil
}
