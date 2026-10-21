package igagov

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// This file is R1b -- action-level right-sizing (SPEC-iga-phase3-policy.md
// §12.1; requirements P-15, Appendix C "S3 / DynamoDB actions: R1b, with data
// events"). There is no R1b implementation spec; every assumption is a
// DECISION R1b-n comment, collected in the R1b report for review.
//
// R1a removes whole SERVICES from a role, on Access Advisor evidence. R1b
// removes individual ACTIONS of a service R1a keeps, on CloudTrail evidence:
// the management events R1a's scanner already stores (cloud_observation,
// source_api cloudtrail:LookupEvents), attributed to the role by
// userIdentity.sessionContext.sessionIssuer.principalId = RoleId (T3.04), so
// a recreated role never inherits its predecessor's history.
//
// Everything here is pure: the trail reads, the aggregated events, the grant
// history and every time are inputs. Everything is behind R1b:
// with it off Snapshot.ActionLevel is false and nothing in this file runs.

// ActionCatalogVersion versions the event→action map and the data-event
// catalog below (§12.1 "a versioned event→action map with unknown kept as
// unknown"). Any change to either is a catalog change: bump it.
const ActionCatalogVersion = 1

// ActionCatalogLabel is the catalog reference stored on action evidence,
// findings and bundles.
func ActionCatalogLabel() string { return "actions@" + strconv.Itoa(ActionCatalogVersion) }

// TrailDeliveryLag is subtracted from a CloudTrail read's end before it is
// claimed as coverage. DECISION R1b-3: AWS delivers management events to
// LookupEvents "typically within 15 minutes"; one hour is the conservative
// figure, as R1a's 4-hour reporting lag is for Access Advisor.
const TrailDeliveryLag = time.Hour

// Action evidence outcomes (iga_gov_action_evidence.outcome, 060).
const (
	// ActionObserved: an attributed event for the action (allowed OR denied
	// -- an attempt, as Access Advisor counts attempts) inside the window.
	ActionObserved = "observed"
	// ActionNoEvent: no event in a qualified window of >= MinQualifiedDays;
	// the unused_action condition.
	ActionNoEvent = "no_event"
	// ActionNotEnoughHistory: no event, but the window is shorter than
	// MinQualifiedDays ("Not enough history (N days)").
	ActionNotEnoughHistory = "not_enough_history"
	// ActionNotObservable: the action is recorded only as a CloudTrail DATA
	// event, which the management-event reader never sees; its absence says
	// nothing (DECISION R1b-5). Never an unused_action finding.
	ActionNotObservable = "not_observable"
	// ActionUnreviewed: the grant cannot be reconstructed, the namespace is a
	// dependency of the workload context, or the service has events AuthSec
	// cannot explain from the role's grants. Kept, never removed.
	ActionUnreviewed = "unreviewed"
	// ActionNotCollected: no CloudTrail coverage for the role's connector.
	ActionNotCollected = "not_collected"
)

// Remove-action bases (RightSizeIntent.RemoveActions[].basis).
const (
	// RemoveActionNoEvent: a qualified no_event basis (management event).
	RemoveActionNoEvent = "no_event"
	// RemoveActionDataEventAcknowledged: a data-event action AuthSec cannot
	// observe, removed only with an explicit, recorded acknowledgement
	// (DECISION R1b-5).
	RemoveActionDataEventAcknowledged = "data_event_acknowledged"
)

// KindUnusedAction is R1b's finding kind (060 widens 048's kind CHECK).
const KindUnusedAction = "unused_action"

/* --------------------------- event → action map --------------------------- */

// reEventVersionSuffix strips the API-version suffix some services put on
// their CloudTrail eventName (Lambda "ListFunctions20150331",
// "UpdateFunctionCode20150331v2"; CloudFront "GetDistribution2020_05_31").
var reEventVersionSuffix = regexp.MustCompile(`^([A-Za-z]+?)(\d{8}(v\d+)?|\d{4}_\d{2}_\d{2})$`)

var versionSuffixedNamespaces = map[string]bool{"lambda": true, "cloudfront": true}

// actionEventAlias maps management events whose API name is not the IAM
// action that authorises them (lower-cased "<ns>:<eventName>" → action).
// Beyond R1a's s3:ListBuckets alias (ActionForEvent), these are the ones a
// role's own sessions commonly produce. DECISION R1b-4: an event outside the
// map is "<ns>:<eventName>"; a SUCCESSFUL event whose action no live grant
// of the role explains is treated as "unknown" and makes the whole namespace
// unreviewed for that role (EvaluateActions), so a mis-mapped event can
// never make a used action look unused.
var actionEventAlias = map[string]string{
	"s3:listbuckets":   "s3:ListAllMyBuckets",
	"s3:headbucket":    "s3:ListBucket",
	"s3:listobjects":   "s3:ListBucket",
	"s3:listobjectsv2": "s3:ListBucket",
	"s3:headobject":    "s3:GetObject",
	"lambda:invoke":    "lambda:InvokeFunction",
}

// ActionForEventR1B maps a CloudTrail event to the IAM action it exercises,
// for R1b. It is R1a's ActionForEvent (left exactly as it is, so the R1a
// canary is unchanged) plus the version-suffix normalisation and the alias
// map above. ok=false when the source is not an AWS service endpoint
// ("unknown": counted, never guessed).
func ActionForEventR1B(eventSource, eventName string) (string, bool) {
	a, ok := ActionForEvent(eventSource, eventName)
	if !ok {
		return "", false
	}
	ns, act, ok := SplitAction(a)
	if !ok {
		return "", false
	}
	if versionSuffixedNamespaces[ns] {
		if m := reEventVersionSuffix.FindStringSubmatch(act); m != nil {
			act = m[1]
		}
	}
	key := strings.ToLower(ns + ":" + act)
	if alias, ok := actionEventAlias[key]; ok {
		return alias, true
	}
	return ns + ":" + act, true
}

/* --------------------------- data-event catalog --------------------------- */

// dataEventActions are IAM actions whose calls CloudTrail records only as
// DATA events (lower-cased). LookupEvents returns management events only, so
// for these AuthSec has no evidence either way (DECISION R1b-5; §8.6 already
// says "a service whose calls are data events only (for example S3 object
// reads) needs a validation or owner confirmation"). The list is the
// documented data-event APIs of the services a workload role most often
// holds; an action outside it is treated as a management event -- the
// known risk of this catalog version, recorded in the R1b report.
var dataEventActions = map[string]bool{}

func init() {
	for _, a := range []string{
		// S3 object-level and bucket-listing operations.
		"s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectAcl", "s3:GetObjectVersionAcl", "s3:GetObjectTagging",
		"s3:GetObjectVersionTagging", "s3:GetObjectAttributes", "s3:GetObjectVersionAttributes", "s3:GetObjectRetention",
		"s3:GetObjectLegalHold", "s3:GetObjectTorrent", "s3:GetObjectVersionTorrent", "s3:PutObject", "s3:PutObjectAcl",
		"s3:PutObjectVersionAcl", "s3:PutObjectTagging", "s3:PutObjectVersionTagging", "s3:PutObjectRetention",
		"s3:PutObjectLegalHold", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:DeleteObjectTagging",
		"s3:DeleteObjectVersionTagging", "s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads",
		"s3:ListMultipartUploadParts", "s3:AbortMultipartUpload", "s3:RestoreObject", "s3:ReplicateObject",
		"s3:ReplicateDelete", "s3:ReplicateTags", "s3:BypassGovernanceRetention", "s3:ObjectOwnerOverrideToBucketOwner",
		// DynamoDB item and stream operations.
		"dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query",
		"dynamodb:Scan", "dynamodb:BatchGetItem", "dynamodb:BatchWriteItem", "dynamodb:ConditionCheckItem",
		"dynamodb:PartiQLSelect", "dynamodb:PartiQLInsert", "dynamodb:PartiQLUpdate", "dynamodb:PartiQLDelete",
		"dynamodb:GetRecords", "dynamodb:GetShardIterator",
		// Lambda invocation.
		"lambda:InvokeFunction", "lambda:InvokeFunctionUrl", "lambda:InvokeAsync",
		// SQS and SNS message operations (data events since 2023).
		"sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility",
		"sns:Publish",
		// Kinesis Data Streams record operations.
		"kinesis:PutRecord", "kinesis:PutRecords", "kinesis:GetRecords", "kinesis:GetShardIterator",
		"kinesis:SubscribeToShard",
		// Bedrock agent runtime operations.
		"bedrock:InvokeAgent", "bedrock:InvokeInlineAgent", "bedrock:Retrieve", "bedrock:RetrieveAndGenerate",
		"bedrock:InvokeFlow",
	} {
		dataEventActions[strings.ToLower(a)] = true
	}
}

// dataEventNamespaces are namespaces whose every action is a data event.
var dataEventNamespaces = map[string]bool{"s3-object-lambda": true, "ebs": true}

// IsDataEventAction reports whether CloudTrail records the action only as a
// data event (catalog actions@1).
func IsDataEventAction(action string) bool {
	ns, _, ok := SplitAction(action)
	if !ok {
		return false
	}
	return dataEventNamespaces[strings.ToLower(ns)] || dataEventActions[strings.ToLower(action)]
}

/* ------------------------------ action names ------------------------------ */

// reAction is one literal IAM action: a namespace and an action name with no
// wildcard (R1b removes named actions only, never patterns).
var reAction = regexp.MustCompile(`^([a-z0-9-]+):([A-Za-z0-9]+)$`)

// ActionKey is the case-insensitive identity of an action (IAM action names
// are case-insensitive): its lower-cased text. It is the unused_action
// finding's detail_key and iga_gov_action_evidence.action_key.
func ActionKey(action string) string { return strings.ToLower(action) }

// CanonicalAction returns the action with a lower-cased namespace and the
// name as written; ok=false when it is not one literal action.
func CanonicalAction(action string) (string, bool) {
	ns, name, ok := SplitAction(strings.TrimSpace(action))
	if !ok {
		return "", false
	}
	a := strings.ToLower(ns) + ":" + name
	if !reAction.MatchString(a) {
		return "", false
	}
	return a, true
}

// GrantsAction reports whether an Allow statement grants the literal action:
// an Action pattern matching it, or a NotAction list that does not match it.
// Deny statements grant nothing. Conditions and resources are ignored (a
// conditional grant counts as a grant: never over-claims a removal).
func (st Statement) GrantsAction(action string) bool {
	if st.Effect != EffectAllow {
		return false
	}
	if st.IsNotAction {
		for _, p := range st.NotAction {
			if globMatch(p, action) {
				return false
			}
		}
		return true
	}
	for _, p := range st.Action {
		if globMatch(p, action) {
			return true
		}
	}
	return false
}

// ExplicitActions returns the literal actions of namespace ns an Allow
// statement names in its Action list (canonical, sorted). Patterns with a
// wildcard in the action part ("s3:Get*", "s3:*") name no literal action:
// DECISION R1b-2, R1b recommends removing only actions a grant names, because
// AuthSec has no catalog of every action a pattern expands to.
func (st Statement) ExplicitActions(ns string) []string {
	if st.Effect != EffectAllow || st.IsNotAction {
		return nil
	}
	var out []string
	for _, p := range st.Action {
		a, ok := CanonicalAction(p)
		if !ok {
			continue
		}
		if pns, _, _ := SplitAction(a); pns == strings.ToLower(ns) {
			out = append(out, a)
		}
	}
	return sortedUnique(out)
}

// BoundaryExcludesAction reports whether a boundary document excludes the
// action: no Allow statement grants it (the per-action analogue of
// BoundaryExcludes).
func BoundaryExcludesAction(doc PolicyDocument, action string) bool {
	for _, st := range doc.Statements {
		if st.GrantsAction(action) {
			return false
		}
	}
	return true
}

// GrantPathsForAction is §2.6's grant paths (GrantPathsFor) at action level:
// per non-boundary policy assignment and statement key, the assignment's
// intervals and the merged intervals of the statement's revisions that grant
// the action.
func GrantPathsForAction(r RoleSnapshot, action string, observationStart time.Time) []GrantPath {
	open := func(from time.Time) bool { return !from.After(observationStart) }
	byPolicy := map[string]map[string][]StatementRevision{}
	for _, sr := range r.Statements {
		if byPolicy[sr.PolicyKey] == nil {
			byPolicy[sr.PolicyKey] = map[string][]StatementRevision{}
		}
		byPolicy[sr.PolicyKey][sr.StatementKey] = append(byPolicy[sr.PolicyKey][sr.StatementKey], sr)
	}
	assigns := append([]PolicyAssignment{}, r.Assignments...)
	sort.Slice(assigns, func(i, j int) bool { return assigns[i].PolicyKey < assigns[j].PolicyKey })
	var paths []GrantPath
	for _, a := range assigns {
		if a.Kind == AssignBoundary {
			continue
		}
		var aIv []Interval
		for _, tr := range a.Intervals {
			aIv = append(aIv, Interval{From: tr.From, To: tr.To, OpenStart: open(tr.From)})
		}
		stmts := byPolicy[a.PolicyKey]
		for _, key := range sortedKeys(stmts) {
			var sIv []Interval
			for _, rev := range stmts[key] {
				if rev.Statement.GrantsAction(action) {
					sIv = append(sIv, Interval{From: rev.From, To: rev.To, OpenStart: open(rev.From)})
				}
			}
			if len(sIv) == 0 || len(aIv) == 0 {
				continue
			}
			paths = append(paths, GrantPath{Key: a.PolicyKey + "#" + key, Components: [][]Interval{aIv, sIv}})
		}
	}
	return paths
}

/* ------------------------------ trail coverage ----------------------------- */

// ActionTrailRead is one published scan's CloudTrail read of the account:
// [From, To] with whether it is COMPLETE for action evidence. DECISION R1b-6:
// a read is complete only when every Region of the scan's set has a
// cloudtrail-events surface that was reached, did not stop at the 10,000
// event cap and was not partial; anything else is a hole (Reason says why),
// because an event missed in one Region would make a used action look
// unused. R1a's canary keeps its own, looser TrailRead.
type ActionTrailRead struct {
	From     time.Time
	To       time.Time
	Complete bool
	Reason   string
}

// TrailEventAgg is a role's CloudTrail events of one (source, name),
// aggregated: the latest event time, the count, and whether any was allowed
// (no error code).
type TrailEventAgg struct {
	EventSource string
	EventName   string
	Last        time.Time
	Count       int
	Succeeded   bool
}

// ActionTrail is one connector's CloudTrail history as R1b reads it: its
// reads, and per RoleId (the session issuer's principalId) the aggregated
// events.
type ActionTrail struct {
	Reads  []ActionTrailRead
	Events map[string][]TrailEventAgg
}

// TrailCoverage is the contiguous span of COMPLETE reads that ends at the
// newest complete read whose end is at or before `at`: [from, to]. Touching
// or overlapping reads merge; an incomplete read contributes nothing, so a
// span not covered by any complete read is a gap. partial lists the reasons
// of incomplete reads that ended inside the requested lookback (newest
// first), for the "partial coverage" explanation. ok=false: no complete read.
func TrailCoverage(reads []ActionTrailRead, at time.Time) (from, to time.Time, partial []string, ok bool) {
	var complete []ActionTrailRead
	for _, r := range reads {
		if !r.To.After(r.From) || r.To.After(at) {
			continue
		}
		if r.Complete {
			complete = append(complete, r)
		}
	}
	if len(complete) == 0 {
		for _, r := range reads {
			if !r.Complete && !r.To.After(at) && r.Reason != "" {
				partial = append(partial, r.Reason)
			}
		}
		return time.Time{}, time.Time{}, sortedUnique(partial), false
	}
	sort.Slice(complete, func(i, j int) bool { return complete[i].From.Before(complete[j].From) })
	type seg struct{ from, to time.Time }
	var segs []seg
	for _, r := range complete {
		if n := len(segs); n > 0 && !r.From.After(segs[n-1].to) {
			if r.To.After(segs[n-1].to) {
				segs[n-1].to = r.To
			}
			continue
		}
		segs = append(segs, seg{r.From, r.To})
	}
	last := segs[len(segs)-1]
	for _, r := range reads {
		if !r.Complete && r.Reason != "" && !r.To.After(at) && r.To.After(last.from.Add(-time.Duration(MaxWindowDays)*24*time.Hour)) {
			partial = append(partial, r.Reason)
		}
	}
	return last.from, last.to, sortedUnique(partial), true
}

/* ----------------------------- qualification ------------------------------ */

// ActionQualifyInput is everything one role × action's qualification needs.
type ActionQualifyInput struct {
	Action              string
	RoleCreatedAt       time.Time
	RequestedWindowDays int
	Paths               []GrantPath
	At                  time.Time
	// CoverageFrom / CoverageTo are TrailCoverage's span (required).
	CoverageFrom time.Time
	CoverageTo   time.Time
	// LastEventAt is the newest attributed event for the action (allowed or
	// denied); nil when none was recorded.
	LastEventAt *time.Time
	EventCount  int
	// Unexplained: the namespace has allowed events no live grant explains
	// (DECISION R1b-4).
	Unexplained bool
	// Dependency: the namespace is a dependency of the workload context
	// (DECISION R1b-7).
	Dependency bool
}

// ActionQualification is §2.6 at action level: the CloudTrail coverage, the
// grant continuity of the action, the window and the outcome.
type ActionQualification struct {
	Action              string     `json:"action"`
	Service             string     `json:"service"`
	Outcome             string     `json:"outcome"`
	Reason              string     `json:"reason,omitempty"`
	LastEventAt         *time.Time `json:"last_event_at"`
	EventCount          int        `json:"event_count"`
	CoveredUntil        time.Time  `json:"covered_until"`
	CoverageStart       time.Time  `json:"coverage_start"`
	RoleFrom            time.Time  `json:"role_from"`
	RequestedWindowDays int        `json:"requested_window_days"`
	VerifiedGrantFrom   *time.Time `json:"verified_grant_from"`
	GrantAgeBasis       string     `json:"grant_age_basis"`
	WindowStart         time.Time  `json:"window_start"`
	QualifiedDays       int        `json:"qualified_days"`
	Confidence          string     `json:"confidence"`
	DataEvent           bool       `json:"data_event"`
}

// QualifyAction is §2.6 for one role × action, on CloudTrail coverage:
//
//	covered_until  = coverage_to − TrailDeliveryLag
//	coverage_start = max(covered_until − window, role_from, coverage_from)
//	window_start   = verified_grant_from ? max(coverage_start, it) : coverage_start
//	qualified_days = covered_until − window_start
//
// Outcome, in order: unreviewed (no grant path holds now; a dependency
// namespace; unexplained events), observed (an event inside the window),
// not_observable (a data-event action, DECISION R1b-5), not_enough_history
// (< 30 qualified days), else no_event. Confidence as R1a: qualified for an
// observed grant start, age_unverified when the grant predates observation.
func QualifyAction(in ActionQualifyInput) ActionQualification {
	ns, _, _ := SplitAction(in.Action)
	q := ActionQualification{
		Action: in.Action, Service: strings.ToLower(ns), LastEventAt: in.LastEventAt, EventCount: in.EventCount,
		RoleFrom: in.RoleCreatedAt, RequestedWindowDays: ClampWindowDays(in.RequestedWindowDays),
		Confidence: ConfidenceNotApplicable, DataEvent: IsDataEventAction(in.Action),
	}
	q.CoveredUntil = in.CoverageTo.Add(-TrailDeliveryLag)
	floor := q.CoveredUntil.Add(-time.Duration(q.RequestedWindowDays) * 24 * time.Hour)
	q.CoverageStart = maxTime(floor, in.RoleCreatedAt, in.CoverageFrom)
	from, basis, ok := VerifiedGrantFrom(in.Paths, in.At)
	q.GrantAgeBasis, q.VerifiedGrantFrom = basis, from
	q.WindowStart = q.CoverageStart
	if from != nil && from.After(q.WindowStart) {
		q.WindowStart = *from
	}
	q.QualifiedDays = wholeDays(q.CoveredUntil.Sub(q.WindowStart))
	switch {
	case !ok:
		q.Outcome, q.Reason = ActionUnreviewed, "grant_path_not_reconstructable"
		return q
	case in.Dependency:
		q.Outcome, q.Reason = ActionUnreviewed, "dependency_namespace"
		return q
	}
	if in.LastEventAt != nil && !in.LastEventAt.Before(q.WindowStart) {
		q.Outcome = ActionObserved
		return q
	}
	switch {
	case q.DataEvent:
		q.Outcome, q.Reason = ActionNotObservable, "data_event"
		return q
	case in.Unexplained:
		q.Outcome, q.Reason = ActionUnreviewed, "unexplained_events"
		return q
	case q.QualifiedDays < MinQualifiedDays:
		q.Outcome = ActionNotEnoughHistory
		return q
	}
	q.Outcome = ActionNoEvent
	if basis == GrantAgeObservedSinceChange {
		q.Confidence = ConfidenceQualified
	} else {
		q.Confidence = ConfidenceAgeUnverified
	}
	return q
}

// ActionEscalation reports the escalation-catalog pattern (§3.7) a literal
// action matches, "" when none.
func ActionEscalation(action string) string {
	for _, e := range escalationCatalog {
		if globMatch(e.Pattern, action) {
			return e.Pattern
		}
	}
	return ""
}
