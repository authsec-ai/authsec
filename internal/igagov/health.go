package igagov

import (
	"sort"
	"strings"
	"time"
)

// This file is §8.6's observation and canary gates and §8.7's
// application_health and restriction dimensions, from evidence: CloudTrail
// management events from the role's sessions (T3.04 attribution), declared
// validations and owner health reports. Pure: "now" is an input.

// Gate names (§8.6) and outcomes (051 iga_gov_verification.outcome
// vocabulary; iga_gov_rollout.gate_results values).
const (
	GateArtifactVerified     = "artifact_verified"
	GateNoUnexpectedFailures = "no_unexpected_failures"
	GateRequiredOperations   = "required_operations"
	GateNoProblemReports     = "no_problem_reports"
	GateWindowElapsed        = "window_elapsed"

	OutcomePassed           = "passed"
	OutcomeFailed           = "failed"
	OutcomeAwaitingEvidence = "awaiting_evidence"
	OutcomeNotAvailable     = "not_available"
	OutcomeNotApplicable    = "not_applicable"

	AttributionNotApplicable = "not_applicable"
	AttributionBoundary      = "boundary_attributed"
	AttributionCauseUnknown  = "cause_unknown"
	AttributionValidation    = "validation_request"

	ExpectDenied  = "denied"
	ExpectAllowed = "allowed"

	DenialPermissionsBoundary = "permissions_boundary"

	ReportProblem = "problem"
	ReportWorking = "working"

	// MaxTrailScanGap: "a scan at least every 48 h" (§8.6); the reader looks
	// back 48 h per scan, so reads further apart leave a hole.
	MaxTrailScanGap = 48 * time.Hour
)

// authorizationErrorCodes are §8.6's authorization error codes.
var authorizationErrorCodes = map[string]bool{
	"AccessDenied": true, "AccessDeniedException": true,
	"UnauthorizedOperation": true, "Client.UnauthorizedOperation": true,
}

// IsAuthorizationDenial reports whether an error code is an authorization
// denial (§8.6; T3.04 sets authorization_denied only for these).
func IsAuthorizationDenial(code string) bool { return authorizationErrorCodes[code] }

// eventSourceNamespace maps CloudTrail event sources whose host differs from
// the IAM namespace (DECISION D39: the catalog's event→action map is
// "<namespace of eventSource>:<eventName>", with these exceptions; an event
// source outside it maps to its host's first label).
var eventSourceNamespace = map[string]string{
	"monitoring": "cloudwatch",
	"email":      "ses",
	"tagging":    "tag",
}

// ActionForEvent maps a management event to its IAM action
// ("sqs.amazonaws.com", "ListQueues" → "sqs:ListQueues"). ok=false when the
// source is not an AWS service endpoint.
func ActionForEvent(eventSource, eventName string) (string, bool) {
	host := strings.ToLower(eventSource)
	if !strings.HasSuffix(host, ".amazonaws.com") || eventName == "" {
		return "", false
	}
	label := strings.SplitN(strings.TrimSuffix(host, ".amazonaws.com"), ".", 2)[0]
	if ns, ok := eventSourceNamespace[label]; ok {
		label = ns
	}
	if !reService.MatchString(label) {
		return "", false
	}
	return label + ":" + eventName, true
}

// TrailEvent is one CloudTrail management event attributed to a role
// session (T3.04 sanitized facts).
type TrailEvent struct {
	EventTime time.Time
	// PrincipalID is userIdentity.sessionContext.sessionIssuer.principalId:
	// the role's RoleId, so a recreated role's events never match.
	PrincipalID string
	SessionName string
	EventSource string
	EventName   string
	ErrorCode   string
	// DenialPolicyType is T3.04's classification of the denial message:
	// permissions_boundary, identity_policy, scp, rcp, resource_policy,
	// session_policy or unknown.
	DenialPolicyType string
}

func (e TrailEvent) action() string {
	a, _ := ActionForEvent(e.EventSource, e.EventName)
	return a
}

func (e TrailEvent) service() string {
	ns, _, _ := SplitAction(e.action())
	return ns
}

func (e TrailEvent) denied() bool { return IsAuthorizationDenial(e.ErrorCode) }

// ValidationItem is one declared action with its expected outcome.
type ValidationItem struct {
	Action   string
	Expected string
}

// Validation is one declared validation request (§8.7).
type Validation struct {
	ID          string
	RoleID      string
	SessionName string
	WindowStart time.Time
	WindowEnd   time.Time
	Items       []ValidationItem
}

// HealthReport is an owner's report (051 iga_gov_health_report).
type HealthReport struct {
	Kind      string
	Service   string
	CreatedAt time.Time
}

// TrailRead is one CloudTrail read of the role's account that covered
// [From, To]; CapHit when it stopped at the 10,000-event cap.
type TrailRead struct {
	From   time.Time
	To     time.Time
	CapHit bool
}

// RetainedService is a retained service and what §8.6's
// required_operations needs to know about it.
type RetainedService struct {
	Service string
	// ActiveInQualifiedInterval: an attempt was reported in the qualified
	// interval (only these need success evidence).
	ActiveInQualifiedInterval bool
	// DataEventsOnly: its calls are data events (S3 object reads), which
	// management-event reads do not see; it needs a validation or an owner
	// confirmation in R1a.
	DataEventsOnly bool
}

// CanaryInput is the evidence for one deployment's canary (or verification)
// window.
type CanaryInput struct {
	RoleID      string
	AppliedAt   time.Time
	Now         time.Time
	CanaryHours int
	// RemovesServices: a present plan that removes services (restriction
	// applies only then; absent, split and split_revert are not_applicable).
	RemovesServices bool
	Removed         []string
	Retained        []RetainedService
	Events          []TrailEvent
	Validations     []Validation
	Reports         []HealthReport
	Trail           []TrailRead
	// PublishedAfterApply: a publication after applied_at exists.
	PublishedAfterApply bool
	// ArtifactOutcome is the artifact dimension's outcome.
	ArtifactOutcome string
}

// GateResult is one gate's outcome.
type GateResult struct {
	Gate     string   `json:"gate"`
	Outcome  string   `json:"outcome"`
	Reason   string   `json:"reason,omitempty"`
	Evidence []string `json:"evidence,omitempty"`
}

// DimensionResult is an §8.7 dimension's outcome and attribution.
type DimensionResult struct {
	Outcome     string `json:"outcome"`
	Attribution string `json:"attribution"`
	Reason      string `json:"reason,omitempty"`
}

// ItemResult is one validation item's correlation (051 CHECK
// iga_gov_vi_result_chk: contradicted ⇒ opposite > 0; matched ⇒ matched > 0
// and opposite = 0; not_seen ⇒ both 0).
type ItemResult struct {
	Action           string `json:"action"`
	Expected         string `json:"expected"`
	Result           string `json:"result"`
	MatchedEvents    int    `json:"matched_events"`
	OppositeEvents   int    `json:"opposite_events"`
	BoundaryAttested bool   `json:"boundary_attributed"`
}

// ValidationResult is one request's correlation.
type ValidationResult struct {
	ID     string       `json:"id"`
	Result string       `json:"result"`
	Items  []ItemResult `json:"items"`
}

// Event classifications for denials.
const (
	DeniedRetainedService = "denied_retained_service"
	DeniedRemovedService  = "denied_removed_service"
	DeniedOtherService    = "denied_other_service"
)

// UnexpectedFailure is a denial no declared expected=denied item explains.
type UnexpectedFailure struct {
	EventTime        time.Time `json:"event_time"`
	Action           string    `json:"action"`
	SessionName      string    `json:"session_name"`
	ErrorCode        string    `json:"error_code"`
	Class            string    `json:"class"`
	DenialPolicyType string    `json:"denial_policy_type"`
}

// CanaryResult is §8.6's gates plus §8.7's health-related dimensions.
type CanaryResult struct {
	Gates []GateResult `json:"gates"`
	// Pass: every gate passed (accepted not_available gates are the
	// approver's decision, outside this function). Pause: any gate failed.
	Pass               bool                `json:"pass"`
	Pause              bool                `json:"pause"`
	NotAvailable       []string            `json:"not_available"`
	ApplicationHealth  DimensionResult     `json:"application_health"`
	Restriction        DimensionResult     `json:"restriction"`
	ServiceRestriction map[string]string   `json:"service_restriction"`
	Validations        []ValidationResult  `json:"validations"`
	UnexpectedFailures []UnexpectedFailure `json:"unexpected_failures"`
}

// windowEnd is the canary window's end as of now.
func (in CanaryInput) windowEnd() time.Time {
	end := in.AppliedAt.Add(time.Duration(in.CanaryHours) * time.Hour)
	if in.Now.Before(end) {
		return in.Now
	}
	return end
}

// trailCovers reports whether the reads cover [from, to] without a hole and
// without hitting the event cap there; the reason names the failure.
func trailCovers(reads []TrailRead, from, to time.Time) (bool, string) {
	if !to.After(from) {
		return true, ""
	}
	rs := append([]TrailRead{}, reads...)
	sort.Slice(rs, func(i, j int) bool { return rs[i].From.Before(rs[j].From) })
	cur := from
	for _, r := range rs {
		if !r.To.After(from) || r.From.After(to) {
			continue
		}
		if r.CapHit {
			return false, "cloudtrail_event_cap_hit"
		}
		if r.From.After(cur) {
			return false, "cloudtrail_coverage_gap"
		}
		if r.To.After(cur) {
			cur = r.To
		}
	}
	if cur.Before(to) {
		if len(rs) == 0 {
			return false, "no_cloudtrail_coverage"
		}
		return false, "cloudtrail_coverage_gap"
	}
	return true, ""
}

// belongs is §8.7: an event belongs to a validation item when the issuer's
// RoleId, the session name, the action and the window all match.
func belongs(e TrailEvent, v Validation, it ValidationItem) bool {
	return e.PrincipalID == v.RoleID && e.SessionName == v.SessionName &&
		strings.EqualFold(e.action(), it.Action) &&
		!e.EventTime.Before(v.WindowStart) && !e.EventTime.After(v.WindowEnd)
}

// CorrelateValidations is §8.7's item and request results. DECISION D40: an
// event "allowed" is any event without an authorization error code (a
// NoSuchEntity answer was authorized).
func CorrelateValidations(vs []Validation, events []TrailEvent) []ValidationResult {
	out := []ValidationResult{}
	for _, v := range vs {
		vr := ValidationResult{ID: v.ID, Items: []ItemResult{}}
		matched, contradicted, notSeen := 0, 0, 0
		for _, it := range v.Items {
			ir := ItemResult{Action: it.Action, Expected: it.Expected}
			for _, e := range events {
				if !belongs(e, v, it) {
					continue
				}
				denied := e.denied()
				if (it.Expected == ExpectDenied) == denied {
					ir.MatchedEvents++
					if denied && e.DenialPolicyType == DenialPermissionsBoundary {
						ir.BoundaryAttested = true
					}
				} else {
					ir.OppositeEvents++
				}
			}
			switch {
			case ir.OppositeEvents > 0:
				ir.Result = "contradicted"
				contradicted++
			case ir.MatchedEvents > 0:
				ir.Result = "matched"
				matched++
			default:
				ir.Result = "not_seen"
				notSeen++
			}
			vr.Items = append(vr.Items, ir)
		}
		switch {
		case contradicted > 0:
			vr.Result = "contradicted"
		case matched > 0 && notSeen == 0:
			vr.Result = "matched"
		case matched > 0:
			vr.Result = "partial"
		default:
			vr.Result = "not_seen"
		}
		out = append(out, vr)
	}
	return out
}

// EvaluateCanary is §8.6's gates (canary → expand) and §8.7's
// application_health and restriction dimensions.
//
//   - no_unexpected_failures fails on ANY authorization denial from the role
//     in the window — a retained service, a removed service the workload was
//     not expected to use (A24), any other service — unless the event
//     belongs to a declared expected=denied item on role incarnation,
//     session, action, window and outcome (A28). A denial seen fails the gate
//     even when the trail coverage is incomplete; no denial with incomplete
//     coverage is not_available.
//   - required_operations needs, per retained service active in the
//     qualified interval, success evidence after applied_at: a management
//     event without an error code, a matched expected=allowed item, or an
//     owner "working" report naming it (data-event-only services: the last
//     two). It fails only on a contradicted expected=allowed item. Missing
//     evidence is awaiting_evidence while the window is open, not_available
//     once it has elapsed (DECISION D41, A18).
//   - no_problem_reports fails on any problem report after applied_at.
//   - window_elapsed passes when canary_hours elapsed, the trail covers the
//     whole window, and a publication followed applied_at.
func EvaluateCanary(in CanaryInput) CanaryResult {
	res := CanaryResult{NotAvailable: []string{}, ServiceRestriction: map[string]string{}, UnexpectedFailures: []UnexpectedFailure{}}
	end := in.windowEnd()
	fullEnd := in.AppliedAt.Add(time.Duration(in.CanaryHours) * time.Hour)
	elapsed := !in.Now.Before(fullEnd)
	covered, covReason := trailCovers(in.Trail, in.AppliedAt, end)

	removed := map[string]bool{}
	for _, s := range in.Removed {
		removed[s] = true
	}
	retained := map[string]bool{}
	for _, r := range in.Retained {
		retained[r.Service] = true
	}
	inWindow := func(e TrailEvent) bool {
		return e.PrincipalID == in.RoleID && !e.EventTime.Before(in.AppliedAt) && !e.EventTime.After(end)
	}
	res.Validations = CorrelateValidations(in.Validations, in.Events)

	// artifact_verified
	art := GateResult{Gate: GateArtifactVerified, Outcome: OutcomeAwaitingEvidence}
	switch in.ArtifactOutcome {
	case OutcomePassed:
		art.Outcome = OutcomePassed
	case OutcomeFailed:
		art.Outcome = OutcomeFailed
	}

	// no_unexpected_failures
	nuf := GateResult{Gate: GateNoUnexpectedFailures}
	for _, e := range in.Events {
		if !inWindow(e) || !e.denied() {
			continue
		}
		exempt := false
		for _, v := range in.Validations {
			for _, it := range v.Items {
				if it.Expected == ExpectDenied && belongs(e, v, it) {
					exempt = true
				}
			}
		}
		if exempt {
			continue
		}
		svc := e.service()
		class := DeniedOtherService
		switch {
		case removed[svc]:
			class = DeniedRemovedService
		case retained[svc]:
			class = DeniedRetainedService
		}
		res.UnexpectedFailures = append(res.UnexpectedFailures, UnexpectedFailure{EventTime: e.EventTime.UTC(), Action: e.action(),
			SessionName: e.SessionName, ErrorCode: e.ErrorCode, Class: class, DenialPolicyType: e.DenialPolicyType})
	}
	sort.SliceStable(res.UnexpectedFailures, func(i, j int) bool {
		return res.UnexpectedFailures[i].EventTime.Before(res.UnexpectedFailures[j].EventTime)
	})
	switch {
	case len(res.UnexpectedFailures) > 0:
		nuf.Outcome = OutcomeFailed
		nuf.Reason = res.UnexpectedFailures[0].Class
		for _, f := range res.UnexpectedFailures {
			nuf.Evidence = append(nuf.Evidence, f.Class+" "+f.Action+" by "+f.SessionName)
		}
	case !covered:
		nuf.Outcome, nuf.Reason = OutcomeNotAvailable, covReason
	default:
		nuf.Outcome = OutcomePassed
	}

	// required_operations
	rop := GateResult{Gate: GateRequiredOperations}
	contradictedAllowed := []string{}
	allowedMatched := map[string]bool{}
	for vi, vr := range res.Validations {
		for ii, ir := range vr.Items {
			ns, _, _ := SplitAction(in.Validations[vi].Items[ii].Action)
			if ir.Expected != ExpectAllowed {
				continue
			}
			switch ir.Result {
			case "contradicted":
				contradictedAllowed = append(contradictedAllowed, ir.Action)
			case "matched":
				allowedMatched[strings.ToLower(ns)] = true
			}
		}
	}
	working := map[string]bool{}
	for _, r := range in.Reports {
		if r.Kind == ReportWorking && !r.CreatedAt.Before(in.AppliedAt) {
			working[r.Service] = true
		}
	}
	succeeded := map[string]bool{}
	for _, e := range in.Events {
		if inWindow(e) && e.ErrorCode == "" {
			succeeded[e.service()] = true
		}
	}
	var missing []string
	for _, r := range in.Retained {
		if !r.ActiveInQualifiedInterval {
			continue
		}
		ok := allowedMatched[r.Service] || working[r.Service] || (!r.DataEventsOnly && succeeded[r.Service])
		if !ok {
			missing = append(missing, r.Service)
		}
	}
	sort.Strings(missing)
	switch {
	case len(contradictedAllowed) > 0:
		rop.Outcome, rop.Reason, rop.Evidence = OutcomeFailed, "allowed_validation_denied", contradictedAllowed
	case len(missing) == 0:
		rop.Outcome = OutcomePassed
	case elapsed:
		rop.Outcome, rop.Reason, rop.Evidence = OutcomeNotAvailable, "no_success_evidence_in_window", missing
	default:
		rop.Outcome, rop.Reason, rop.Evidence = OutcomeAwaitingEvidence, "awaiting_success_evidence", missing
	}

	// no_problem_reports
	npr := GateResult{Gate: GateNoProblemReports, Outcome: OutcomePassed}
	for _, r := range in.Reports {
		if r.Kind == ReportProblem && !r.CreatedAt.Before(in.AppliedAt) {
			npr.Outcome = OutcomeFailed
			npr.Evidence = append(npr.Evidence, r.Service)
		}
	}
	if npr.Outcome == OutcomeFailed {
		npr.Reason = "problem_reported"
	}

	// window_elapsed
	we := GateResult{Gate: GateWindowElapsed}
	switch {
	case !elapsed:
		we.Outcome, we.Reason = OutcomeAwaitingEvidence, "canary_hours_not_elapsed"
	case !covered:
		we.Outcome, we.Reason = OutcomeNotAvailable, covReason
	case !in.PublishedAfterApply:
		we.Outcome, we.Reason = OutcomeAwaitingEvidence, "no_publication_after_apply"
	default:
		we.Outcome = OutcomePassed
	}

	res.Gates = []GateResult{art, nuf, rop, npr, we}
	res.Pass = true
	for _, g := range res.Gates {
		if g.Outcome != OutcomePassed {
			res.Pass = false
		}
		if g.Outcome == OutcomeFailed {
			res.Pause = true
		}
		if g.Outcome == OutcomeNotAvailable {
			res.NotAvailable = append(res.NotAvailable, g.Gate)
		}
	}

	// application_health (§8.7): the three health gates over the window.
	ah := DimensionResult{Outcome: OutcomeAwaitingEvidence, Attribution: AttributionNotApplicable}
	hg := []GateResult{nuf, rop, npr}
	anyFailed, anyNA, allPassed := false, false, true
	for _, g := range hg {
		anyFailed = anyFailed || g.Outcome == OutcomeFailed
		anyNA = anyNA || g.Outcome == OutcomeNotAvailable
		allPassed = allPassed && g.Outcome == OutcomePassed
	}
	switch {
	case anyFailed:
		ah.Outcome = OutcomeFailed
	case allPassed:
		ah.Outcome = OutcomePassed
	case anyNA:
		ah.Outcome = OutcomeNotAvailable
	}
	res.ApplicationHealth = ah
	res.Restriction = restriction(in, res.Validations)
	for _, s := range sortedUnique(in.Removed) {
		res.ServiceRestriction[s] = serviceRestriction(in, res.Validations, s)
	}
	return res
}

// restriction is §8.7's restriction dimension. DECISION D42: a boundary-
// attributed denial on a removed service passes restriction (the boundary
// demonstrably acts) even when it also fails no_unexpected_failures because
// nobody expected the call (A24): the two are reported side by side, never
// folded, and the gate failure pauses the rollout.
func restriction(in CanaryInput, vrs []ValidationResult) DimensionResult {
	if !in.RemovesServices {
		return DimensionResult{Outcome: OutcomeNotApplicable, Attribution: AttributionNotApplicable}
	}
	removed := map[string]bool{}
	for _, s := range in.Removed {
		removed[s] = true
	}
	viaValidation, contradicted := false, false
	for vi, vr := range vrs {
		for ii, ir := range vr.Items {
			ns, _, _ := SplitAction(in.Validations[vi].Items[ii].Action)
			if ir.Expected != ExpectDenied || !removed[strings.ToLower(ns)] {
				continue
			}
			if ir.Result == "contradicted" {
				contradicted = true
			}
			if ir.Result == "matched" && ir.BoundaryAttested {
				viaValidation = true
			}
		}
	}
	if contradicted {
		return DimensionResult{Outcome: OutcomeFailed, Attribution: AttributionValidation, Reason: "expected_denial_was_allowed"}
	}
	if viaValidation {
		return DimensionResult{Outcome: OutcomePassed, Attribution: AttributionValidation}
	}
	unknownCause := false
	for _, e := range in.Events {
		if e.PrincipalID != in.RoleID || e.EventTime.Before(in.AppliedAt) || !e.denied() || !removed[e.service()] {
			continue
		}
		if e.DenialPolicyType == DenialPermissionsBoundary {
			return DimensionResult{Outcome: OutcomePassed, Attribution: AttributionBoundary}
		}
		unknownCause = true
	}
	if unknownCause {
		return DimensionResult{Outcome: OutcomeAwaitingEvidence, Attribution: AttributionCauseUnknown, Reason: "denied_cause_not_attributed"}
	}
	return DimensionResult{Outcome: OutcomeAwaitingEvidence, Attribution: AttributionNotApplicable, Reason: "not_observed"}
}

// Posture restriction values (051 iga_gov_service_posture.restriction).
const (
	RestrictionNotObserved  = "not_observed"
	RestrictionObserved     = "observed"
	RestrictionContradicted = "contradicted"
)

// serviceRestriction is one removed service's posture restriction fact.
func serviceRestriction(in CanaryInput, vrs []ValidationResult, svc string) string {
	observed := false
	for vi, vr := range vrs {
		for ii, ir := range vr.Items {
			ns, _, _ := SplitAction(in.Validations[vi].Items[ii].Action)
			if ir.Expected != ExpectDenied || strings.ToLower(ns) != svc {
				continue
			}
			if ir.Result == "contradicted" {
				return RestrictionContradicted
			}
			if ir.Result == "matched" && ir.BoundaryAttested {
				observed = true
			}
		}
	}
	for _, e := range in.Events {
		if e.PrincipalID == in.RoleID && !e.EventTime.Before(in.AppliedAt) && e.denied() &&
			e.service() == svc && e.DenialPolicyType == DenialPermissionsBoundary {
			observed = true
		}
	}
	if observed {
		return RestrictionObserved
	}
	return RestrictionNotObserved
}

/* ------------------------------------------------------------------------- */
/*                    Observation: the fresh-report rule (§8.6)               */
/* ------------------------------------------------------------------------- */

// ObserveEvidenceRequiredAfter is §2.6 / §8.6:
// observe_evidence_required_after = observe_until + reporting_lag.
func ObserveEvidenceRequiredAfter(observeUntil time.Time) time.Time {
	return observeUntil.Add(ReportingLag)
}

// ObservationTarget is one target's latest activity evidence during
// observation.
type ObservationTarget struct {
	RoleID string
	// EvidenceReportAt is the report time of the version's evidence
	// revision for this role (what the removal was proposed from).
	EvidenceReportAt time.Time
	// ReportGeneratedAt is the newest collected report's generation time
	// (nil when none was collected since).
	ReportGeneratedAt *time.Time
	// LastAttempts holds, per removed service, last_authenticated_at in that
	// newest report (nil = no attempt reported).
	LastAttempts map[string]*time.Time
}

// AttemptDuringObservation sends a version back to draft.
type AttemptDuringObservation struct {
	RoleID  string    `json:"role_id"`
	Service string    `json:"service"`
	At      time.Time `json:"at"`
}

// ObservationResult is one observe_tick's conclusion.
type ObservationResult struct {
	RequiredAfter time.Time                  `json:"required_after"`
	Complete      bool                       `json:"complete"`
	BackToDraft   []AttemptDuringObservation `json:"back_to_draft"`
	// AwaitingReport lists targets without a report generated at or after
	// RequiredAfter; NeedsRefresh asks for a refresh_activity scan.
	AwaitingReport []string `json:"awaiting_report"`
	NeedsRefresh   bool     `json:"needs_refresh"`
}

// EvaluateObservation is §8.6's observe step: a removed service attempted
// after the evidence report sends the version back to draft; observation
// ends only when observe_until has passed AND every target has a report
// generated at or after observe_until + 4 h. Elapsed time alone never ends
// it (§2.6 "Observation needs a fresh report").
func EvaluateObservation(observeUntil, now time.Time, targets []ObservationTarget) ObservationResult {
	r := ObservationResult{RequiredAfter: ObserveEvidenceRequiredAfter(observeUntil),
		BackToDraft: []AttemptDuringObservation{}, AwaitingReport: []string{}}
	for _, t := range targets {
		for _, svc := range sortedKeys(t.LastAttempts) {
			if at := t.LastAttempts[svc]; at != nil && at.After(t.EvidenceReportAt) {
				r.BackToDraft = append(r.BackToDraft, AttemptDuringObservation{RoleID: t.RoleID, Service: svc, At: at.UTC()})
			}
		}
		if t.ReportGeneratedAt == nil || t.ReportGeneratedAt.Before(r.RequiredAfter) {
			r.AwaitingReport = append(r.AwaitingReport, t.RoleID)
		}
	}
	sort.Strings(r.AwaitingReport)
	r.Complete = !now.Before(observeUntil) && len(r.AwaitingReport) == 0 && len(r.BackToDraft) == 0
	r.NeedsRefresh = !now.Before(observeUntil) && len(r.AwaitingReport) > 0
	return r
}
