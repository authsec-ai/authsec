package igagov

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

/* ------------------------------- vocabulary ------------------------------- */

// Finding kinds (048 iga_gov_finding.kind; §2.5).
const (
	KindUnusedService     = "unused_service"
	KindBroadGrant        = "broad_grant"
	KindSharedRole        = "shared_role"
	KindMissingOwner      = "missing_owner"
	KindMissingReviewDate = "missing_review_date"
	KindActivityNotRead   = "activity_not_read"
)

// Finding families (048 CHECK family IN ('governance','cloud_access')).
const (
	FamilyGovernance  = "governance"
	FamilyCloudAccess = "cloud_access"
)

// Severities (048 CHECK).
const (
	SeverityHigh   = "high"
	SeverityMedium = "medium"
	SeverityLow    = "low"
	SeverityInfo   = "info"
)

// Confidence (048 CHECK) and grant-age basis (iga_gov_activity_evidence).
const (
	ConfidenceQualified     = "qualified"
	ConfidenceAgeUnverified = "age_unverified"
	ConfidenceNotApplicable = "not_applicable"

	GrantAgeObservedSinceChange = "observed_since_change"
	GrantAgePredatesObservation = "predates_observation"
	GrantAgeUnknown             = "unknown"
)

// Finding statuses (048 CHECK; §2.5 lifecycle). There is no hide or dismiss.
const (
	StatusOpen        = "open"
	StatusUnderReview = "under_review"
	StatusExcepted    = "excepted"
	StatusMitigated   = "mitigated"
	StatusResolved    = "resolved"
	StatusCleared     = "cleared"
	StatusSuperseded  = "superseded"
	StatusReopened    = "reopened"
)

// Activity evidence states (048 iga_gov_activity_evidence.state).
const (
	EvidenceCollected    = "collected"
	EvidenceNotCollected = "not_collected"
)

// Relationship types the evaluator reads (iga_relationship.relationship_type).
const (
	RelExecutesAs        = "executes_as"
	RelTaskExecutionRole = "task_execution_role"
)

// Assignment kinds (iga_policy_assignment.assignment_kind).
const (
	AssignAttached = "attached"
	AssignInline   = "inline"
	AssignBoundary = "boundary"
)

// Rule kinds (048 iga_gov_finding_rule.kind).
const (
	RuleRequireReviewDate = "require_review_date"
	RuleUnusedWindow      = "unused_window"
)

// Owner roles (047).
const (
	OwnerAccountable = "accountable"
	OwnerTechnical   = "technical"

	OwnerObjectWorkload = "workload"
	OwnerObjectIdentity = "identity_account"
)

// FindingFamily returns the family a kind is stored with (DECISION D10:
// ownership and review dates are governance; everything that speaks about
// access, including the evidence gap that blocks right-sizing, is
// cloud_access).
func FindingFamily(kind string) string {
	switch kind {
	case KindMissingOwner, KindMissingReviewDate:
		return FamilyGovernance
	}
	return FamilyCloudAccess
}

/* ------------------------------- the snapshot ----------------------------- */

// Snapshot is what §8.2's evaluation reads for revision N, under the
// pipeline barrier, gathered by services/iga_gov_evaluator.go: the
// manifest, each manifest run's evidence, every AWS role with its grant
// history, activity report and consumers, workloads, owners and rules.
type Snapshot struct {
	Rev int64
	// EvaluatedAt is the evaluation time: the revision's published_at. It
	// picks "current" grants (§2.6) and lapsed exceptions.
	EvaluatedAt time.Time
	// Manifest is rev N's iga_publication.manifest: partition_key → run id.
	Manifest map[string]string
	// Runs holds the evidence of every run the manifest names, by run id.
	Runs      map[string]RunEvidence
	Roles     []RoleSnapshot
	Workloads []WorkloadSnapshot
	Owners    []OwnerRecord
	Rules     []FindingRule
	// DefaultWindowDays is iga_gov_settings.default_window_days (0 = 90).
	DefaultWindowDays int
}

// RunEvidence is one connector run named in the manifest (§2.5 step 2).
type RunEvidence struct {
	RunID       string
	ConnectorID string
	AccountID   string
	// ConnectorFirstPublishedAt is the connector's first published scan: a
	// grant component whose interval starts at or before it is open-start
	// (§2.6). Required.
	ConnectorFirstPublishedAt time.Time
	// EnabledRegions are the Regions enabled in the account (tracking
	// catalog region set, §3.9 coverage completeness).
	EnabledRegions []string
	// ResourcePolicy is the run's immutable resource-policy evidence; nil
	// when the run collected none.
	ResourcePolicy *ResourcePolicyEvidence
}

// TimeRange is one validity interval of a graph row (valid_from, valid_to).
type TimeRange struct {
	From time.Time
	To   *time.Time
}

// PolicyAssignment is a policy's assignment history to the role
// (iga_policy_assignment rows for one policy, inline policies included).
type PolicyAssignment struct {
	PolicyKey string
	PolicyARN string
	Kind      string
	Intervals []TimeRange
}

// StatementRevision is one iga_statement_revision of a statement in a
// policy, decoded.
type StatementRevision struct {
	PolicyKey    string
	StatementKey string
	Hash         string
	Statement    Statement
	From         time.Time
	To           *time.Time
}

// ServiceActivity is one service line of an Access Advisor report.
type ServiceActivity struct {
	Service             string
	LastAuthenticatedAt *time.Time
}

// ActivityReport is the role's cloud_usage report as read under the
// barrier, with the run it was generated by.
type ActivityReport struct {
	ScanRunID   string
	State       string // collected | not_collected
	Reason      string
	GeneratedAt time.Time
	Services    []ServiceActivity
}

// Consumer is a live relationship from a workload to the role.
type Consumer struct {
	WorkloadID   string
	Relationship string
}

// RoleSnapshot is one AWS role at rev N.
type RoleSnapshot struct {
	IdentityAccountID string
	RoleID            string
	ARN               string
	Name              string
	Path              string
	AccountID         string
	ConnectorID       string
	PartitionKey      string
	Partition         string
	CreatedAt         time.Time
	Tags              map[string]string
	Assignments       []PolicyAssignment
	Statements        []StatementRevision
	// Activity is nil when the role has no report (outside the sample).
	Activity  *ActivityReport
	Consumers []Consumer
	// UnmatchedOwnerTags are owner-rule tag values on the role that match no
	// active member (§2.9), shown on missing_owner.
	UnmatchedOwnerTags []string
}

// WorkloadSnapshot is one workload consuming some role.
type WorkloadSnapshot struct {
	ID                 string
	Name               string
	RuntimeKind        string
	Stage              string
	Classification     string
	UnmatchedOwnerTags []string
}

// OwnerRecord is one iga_gov_owner row.
type OwnerRecord struct {
	ID                string
	ObjectKind        string
	WorkloadID        string
	IdentityAccountID string
	UserID            string
	Role              string
	ReviewDueAt       *time.Time
}

// RuleScope selects workloads by class (DECISION D11: the 048 scope jsonb is
// {"runtime_kinds": [...], "stages": [...], "classifications": [...]}; an
// empty list matches anything).
type RuleScope struct {
	RuntimeKinds    []string `json:"runtime_kinds,omitempty"`
	Stages          []string `json:"stages,omitempty"`
	Classifications []string `json:"classifications,omitempty"`
}

// FindingRule is one enabled iga_gov_finding_rule.
type FindingRule struct {
	ID      string
	Kind    string
	Enabled bool
	Scope   RuleScope
	// WindowDays is params.window_days of an unused_window rule.
	WindowDays int
}

// ParseFindingRule decodes an iga_gov_finding_rule row's jsonb columns.
func ParseFindingRule(id, kind string, enabled bool, scope, params []byte) (FindingRule, error) {
	r := FindingRule{ID: id, Kind: kind, Enabled: enabled}
	if kind != RuleRequireReviewDate && kind != RuleUnusedWindow {
		return r, fmt.Errorf("igagov: unknown finding rule kind %q", kind)
	}
	if len(scope) > 0 {
		if err := json.Unmarshal(scope, &r.Scope); err != nil {
			return r, fmt.Errorf("igagov: finding rule %s scope: %w", id, err)
		}
	}
	if kind == RuleUnusedWindow {
		var p struct {
			WindowDays int `json:"window_days"`
		}
		if len(params) > 0 {
			if err := json.Unmarshal(params, &p); err != nil {
				return r, fmt.Errorf("igagov: finding rule %s params: %w", id, err)
			}
		}
		if p.WindowDays < MinWindowDays || p.WindowDays > MaxWindowDays {
			return r, fmt.Errorf("igagov: finding rule %s window_days must be %d..%d", id, MinWindowDays, MaxWindowDays)
		}
		r.WindowDays = p.WindowDays
	}
	return r, nil
}

func (s RuleScope) matches(w WorkloadSnapshot) bool {
	in := func(list []string, v string) bool {
		if len(list) == 0 {
			return true
		}
		for _, x := range list {
			if x == v {
				return true
			}
		}
		return false
	}
	return in(s.RuntimeKinds, w.RuntimeKind) && in(s.Stages, w.Stage) && in(s.Classifications, w.Classification)
}

/* -------------------------------- the output ------------------------------ */

// ActivityEvidence is one iga_gov_activity_evidence row (048), field for
// field; empty strings and nil pointers are NULL.
type ActivityEvidence struct {
	IdentityAccountID   string
	RoleID              string
	Service             string
	State               string
	Reason              string
	LastAuthenticatedAt *time.Time
	ReportGeneratedAt   *time.Time
	GrantObservedSince  *time.Time
	GrantAgeBasis       string
	TrackingFrom        *time.Time
	ScanRunID           string
	RouteUsage          string
}

// Finding is a finding whose condition holds at rev N: the identity columns
// of iga_gov_finding plus the iga_gov_finding_result columns (severity,
// confidence, detail, evidence_scan_run_id). Detail is RFC 8785 text.
type Finding struct {
	Fingerprint       string
	Kind              string
	Family            string
	Severity          string
	Confidence        string
	IdentityAccountID string
	WorkloadID        string
	RoleID            string
	ConnectorID       string
	DetailKey         string
	Detail            json.RawMessage
	EvidenceScanRunID string
}

// ConditionScope names conditions that could not be evaluated at rev N for
// a role (DetailKey "" = every finding of that kind for the role). Their
// findings are left exactly as they are: no result row, no status change,
// no last_evaluated_rev bump.
type ConditionScope struct {
	RoleID    string
	Kind      string
	DetailKey string
	Reason    string
}

// RouteFacts is one role × service's route facts at rev N, for the route
// columns of iga_gov_service_posture (§8.2 step 2; §8.7). Routes are the
// remaining routes (empty exactly when RouteState is none_observed).
type RouteFacts struct {
	AccountID  string
	RoleID     string
	Service    string
	RouteUsage string
	RouteState string
	Routes     []Route
	ScanRunID  string
}

// RoleAssessment is one role × service's §2.6 qualification, for "Not enough
// history (N days)" and readiness.
type RoleAssessment struct {
	RoleID        string
	Qualification Qualification
}

// SkippedRole is a role the evaluator does not produce findings for.
type SkippedRole struct {
	RoleID string
	Reason string
}

// Evaluation is igagov.Evaluate's output for one revision (§8.2): every
// slice is in a deterministic order.
type Evaluation struct {
	Rev         int64
	EvaluatedAt time.Time
	Evidence    []ActivityEvidence
	Findings    []Finding
	Unknown     []ConditionScope
	Routes      []RouteFacts
	Assessments []RoleAssessment
	// PresentRoles are the RoleIds present at rev N (evaluated or skipped);
	// a stored finding whose RoleId is absent is superseded (§2.2).
	PresentRoles []string
	Skipped      []SkippedRole
}

/* ------------------------------- evaluation ------------------------------- */

type evalIndex struct {
	s         Snapshot
	workloads map[string]WorkloadSnapshot
	owners    []OwnerRecord
}

// skipReason returns why a role is outside findings (DECISION D9): AWS
// manages service-linked and reserved roles, and ManagedBy=AuthSec roles are
// AuthSec's own (§3.1).
func skipReason(r RoleSnapshot) string {
	switch {
	case strings.HasPrefix(r.Path, "/aws-service-role/"):
		return "service_linked_role"
	case strings.HasPrefix(r.Path, "/aws-reserved/"):
		return "aws_reserved_role"
	case r.Tags["ManagedBy"] == "AuthSec":
		return "authsec_managed_role"
	}
	return ""
}

func validateSnapshot(s Snapshot) error {
	if s.Rev <= 0 {
		return errors.New("igagov: snapshot revision must be positive")
	}
	if s.EvaluatedAt.IsZero() {
		return errors.New("igagov: snapshot needs the evaluation time")
	}
	seen := map[string]bool{}
	for _, r := range s.Roles {
		if r.RoleID == "" || r.IdentityAccountID == "" {
			return fmt.Errorf("igagov: role %q lacks its RoleId or identity id", r.ARN)
		}
		if seen[r.RoleID] {
			return fmt.Errorf("igagov: role %s appears twice", r.RoleID)
		}
		seen[r.RoleID] = true
	}
	for id, run := range s.Runs {
		if run.RunID != id {
			return fmt.Errorf("igagov: run %s is keyed as %s", run.RunID, id)
		}
		if run.ConnectorFirstPublishedAt.IsZero() {
			return fmt.Errorf("igagov: run %s lacks its connector's first publication time", id)
		}
	}
	return nil
}

// Evaluate is igagov.Evaluate (§2.5, §8.2): from one revision's snapshot it
// computes, in memory and deterministically, the activity evidence, the
// findings whose condition holds at rev N (with their per-revision result
// fields), the conditions that could not be evaluated, and the route facts.
// Every role is judged on the evidence of ITS OWN connector's run named in
// rev N's manifest (A47); a role whose partition is absent, whose run is
// missing or whose report does not belong to that run is not_collected and
// gets no absence conclusion.
func Evaluate(s Snapshot) (Evaluation, error) {
	if err := validateSnapshot(s); err != nil {
		return Evaluation{}, err
	}
	ix := &evalIndex{s: s, workloads: map[string]WorkloadSnapshot{}, owners: s.Owners}
	for _, w := range s.Workloads {
		ix.workloads[w.ID] = w
	}
	out := Evaluation{Rev: s.Rev, EvaluatedAt: s.EvaluatedAt}
	roles := append([]RoleSnapshot{}, s.Roles...)
	sort.Slice(roles, func(i, j int) bool { return roles[i].RoleID < roles[j].RoleID })
	for _, r := range roles {
		out.PresentRoles = append(out.PresentRoles, r.RoleID)
		if why := skipReason(r); why != "" {
			out.Skipped = append(out.Skipped, SkippedRole{RoleID: r.RoleID, Reason: why})
			continue
		}
		if err := ix.evaluateRole(r, &out); err != nil {
			return Evaluation{}, err
		}
	}
	sort.Slice(out.Evidence, func(i, j int) bool {
		a, b := out.Evidence[i], out.Evidence[j]
		if a.IdentityAccountID != b.IdentityAccountID {
			return a.IdentityAccountID < b.IdentityAccountID
		}
		return a.Service < b.Service
	})
	sort.Slice(out.Findings, func(i, j int) bool { return out.Findings[i].Fingerprint < out.Findings[j].Fingerprint })
	sort.Slice(out.Unknown, func(i, j int) bool {
		a, b := out.Unknown[i], out.Unknown[j]
		if a.RoleID != b.RoleID {
			return a.RoleID < b.RoleID
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.DetailKey < b.DetailKey
	})
	sort.Slice(out.Routes, func(i, j int) bool {
		a, b := out.Routes[i], out.Routes[j]
		if a.RoleID != b.RoleID {
			return a.RoleID < b.RoleID
		}
		return a.Service < b.Service
	})
	sort.Slice(out.Assessments, func(i, j int) bool {
		a, b := out.Assessments[i], out.Assessments[j]
		if a.RoleID != b.RoleID {
			return a.RoleID < b.RoleID
		}
		return a.Qualification.Service < b.Qualification.Service
	})
	return out, nil
}

func ts(t *time.Time) *string {
	if t == nil || t.IsZero() {
		return nil
	}
	s := t.UTC().Format(time.RFC3339Nano)
	return &s
}

func tsv(t time.Time) *string { return ts(&t) }

func ptrTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// liveRelationship reports whether a relationship makes a role
// workload-bound and counts toward shared_role (§2.5).
func liveRelationship(rel string) bool {
	return rel == RelExecutesAs || rel == RelTaskExecutionRole
}

func (ix *evalIndex) activityState(r RoleSnapshot) (state, reason, runID string, run *RunEvidence) {
	runID, inManifest := ix.s.Manifest[r.PartitionKey]
	if !inManifest || r.PartitionKey == "" {
		return EvidenceNotCollected, "partition_not_in_manifest", "", nil
	}
	rv, ok := ix.s.Runs[runID]
	if !ok {
		return EvidenceNotCollected, "run_evidence_missing", runID, nil
	}
	run = &rv
	switch {
	case r.Activity == nil:
		return EvidenceNotCollected, "not_in_activity_sample", runID, run
	case r.Activity.State != EvidenceCollected:
		reason = r.Activity.Reason
		if reason == "" {
			reason = "report_not_collected"
		}
		return EvidenceNotCollected, reason, runID, run
	case r.Activity.ScanRunID != runID:
		return EvidenceNotCollected, "report_run_mismatch", runID, run
	case r.Activity.GeneratedAt.IsZero():
		return EvidenceNotCollected, "report_time_missing", runID, run
	}
	return EvidenceCollected, "", runID, run
}

func (ix *evalIndex) windowFor(consumers []WorkloadSnapshot) int {
	w := ClampWindowDays(ix.s.DefaultWindowDays)
	best := 0
	for _, rule := range ix.s.Rules {
		if !rule.Enabled || rule.Kind != RuleUnusedWindow {
			continue
		}
		for _, wl := range consumers {
			if rule.Scope.matches(wl) && rule.WindowDays > best {
				best = rule.WindowDays
			}
		}
	}
	// DECISION D11: several matching unused_window rules → the longest
	// window, which asks for more evidence before an absence claim.
	if best > 0 {
		return ClampWindowDays(best)
	}
	return w
}

// GrantPathsFor builds §2.6's grant paths of service ns for a role from its
// graph history: per non-boundary policy assignment and per statement key
// in that policy, the assignment's intervals and the merged intervals of the
// statement's revisions that grant ns. A component starting at or before
// observationStart is open-start.
func GrantPathsFor(r RoleSnapshot, ns string, observationStart time.Time) []GrantPath {
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
				if rev.Statement.GrantsNamespace(ns) {
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

type liveStatement struct {
	assign PolicyAssignment
	rev    StatementRevision
}

func holdsAt(tr TimeRange, at time.Time) bool {
	return !at.Before(tr.From) && (tr.To == nil || at.Before(*tr.To))
}

// liveStatements are the current revisions of statements in policies
// currently assigned (not as a boundary) to the role.
func liveStatements(r RoleSnapshot, at time.Time) []liveStatement {
	live := map[string]PolicyAssignment{}
	for _, a := range r.Assignments {
		if a.Kind == AssignBoundary {
			continue
		}
		for _, tr := range a.Intervals {
			if holdsAt(tr, at) {
				live[a.PolicyKey] = a
			}
		}
	}
	var out []liveStatement
	for _, sr := range r.Statements {
		a, ok := live[sr.PolicyKey]
		if !ok || !holdsAt(TimeRange{From: sr.From, To: sr.To}, at) {
			continue
		}
		out = append(out, liveStatement{assign: a, rev: sr})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].rev.PolicyKey != out[j].rev.PolicyKey {
			return out[i].rev.PolicyKey < out[j].rev.PolicyKey
		}
		return out[i].rev.StatementKey < out[j].rev.StatementKey
	})
	return out
}

type grantRef struct {
	PolicyKey     string `json:"policy_key"`
	PolicyARN     string `json:"policy_arn"`
	StatementKey  string `json:"statement_key"`
	StatementHash string `json:"statement_hash"`
}

// BroadGrantDetailKey is a broad_grant finding's detail_key: the graph
// statement key, escaped so it can never contain U+001F (the fingerprint's
// field separator, which Fingerprint refuses). DECISION (p3-wire, item 5):
// the AWS graph's statement keys join their parts with U+001F, so the raw
// key made Fingerprint fail and with it the WHOLE evaluation of a workspace
// holding any broad grant. The escape is percent-style -- "%" -> "%25" first,
// then U+001F -> "%1F" -- which is injective (two keys never share a
// detail_key), deterministic (the same statement keeps the same fingerprint
// across revisions) and leaves every key without either character
// unchanged. The raw key stays in the finding's detail (statement_key).
func BroadGrantDetailKey(statementKey string) string {
	if !strings.ContainsAny(statementKey, "%"+unitSep) {
		return statementKey
	}
	return strings.ReplaceAll(strings.ReplaceAll(statementKey, "%", "%25"), unitSep, "%1F")
}

func (ix *evalIndex) newFinding(kind, severity, confidence string, r RoleSnapshot, detailKey, runID string, detail any) (Finding, error) {
	fp, err := Fingerprint(kind, r.RoleID, detailKey)
	if err != nil {
		return Finding{}, err
	}
	d, err := CanonicalizeValue(detail)
	if err != nil {
		return Finding{}, err
	}
	if err := checkStorable(d); err != nil {
		return Finding{}, err
	}
	f := Finding{Fingerprint: fp, Kind: kind, Family: FindingFamily(kind), Severity: severity, Confidence: confidence,
		IdentityAccountID: r.IdentityAccountID, RoleID: r.RoleID, ConnectorID: r.ConnectorID, DetailKey: detailKey,
		Detail: json.RawMessage(d)}
	if f.Family == FamilyCloudAccess {
		f.EvidenceScanRunID = runID
	}
	return f, nil
}

func (ix *evalIndex) evaluateRole(r RoleSnapshot, out *Evaluation) error {
	at := ix.s.EvaluatedAt
	state, reason, runID, run := ix.activityState(r)

	// Consumers: distinct workloads with a live executes_as /
	// task_execution_role relationship (DECISION D13).
	consumerSet := map[string]bool{}
	var consumers []Consumer
	for _, c := range r.Consumers {
		if !liveRelationship(c.Relationship) {
			continue
		}
		k := c.WorkloadID + "\x1f" + c.Relationship
		if consumerSet[k] {
			continue
		}
		consumerSet[k] = true
		consumers = append(consumers, c)
	}
	sort.Slice(consumers, func(i, j int) bool {
		if consumers[i].WorkloadID != consumers[j].WorkloadID {
			return consumers[i].WorkloadID < consumers[j].WorkloadID
		}
		return consumers[i].Relationship < consumers[j].Relationship
	})
	var workloadIDs []string
	for _, c := range consumers {
		workloadIDs = append(workloadIDs, c.WorkloadID)
	}
	workloadIDs = sortedUnique(workloadIDs)
	var workloads []WorkloadSnapshot
	for _, id := range workloadIDs {
		if w, ok := ix.workloads[id]; ok {
			workloads = append(workloads, w)
		} else {
			workloads = append(workloads, WorkloadSnapshot{ID: id})
		}
	}
	bound := len(workloadIDs) > 0
	consumerDetail := make([]ImpactConsumer, 0, len(consumers))
	for _, c := range consumers {
		consumerDetail = append(consumerDetail, ImpactConsumer{WorkloadID: c.WorkloadID, Relationship: c.Relationship})
	}

	live := liveStatements(r, at)
	ref := RoleRef{RoleID: r.RoleID, ARN: r.ARN, Name: r.Name, AccountID: r.AccountID, Partition: r.Partition}

	/* ---- activity evidence and unused_service ---- */
	if state == EvidenceCollected {
		window := ix.windowFor(workloads)
		report := append([]ServiceActivity{}, r.Activity.Services...)
		sort.Slice(report, func(i, j int) bool { return report[i].Service < report[j].Service })
		seen := map[string]bool{}
		for _, sa := range report {
			if seen[sa.Service] {
				return fmt.Errorf("igagov: role %s report lists %s twice", r.RoleID, sa.Service)
			}
			seen[sa.Service] = true
			trackFrom, tracked, treason := TrackingStart(sa.Service, run.EnabledRegions)
			qi := QualifyInput{
				Service: sa.Service, ReportGeneratedAt: r.Activity.GeneratedAt, LastAuthenticatedAt: sa.LastAuthenticatedAt,
				RoleCreatedAt: r.CreatedAt, RequestedWindowDays: window,
				Paths: GrantPathsFor(r, sa.Service, run.ConnectorFirstPublishedAt), At: at,
			}
			if tracked {
				qi.TrackingFrom = &trackFrom
			} else {
				qi.TrackingReason = treason
			}
			q := Qualify(qi)
			ra := AnalyzeRoutes(sa.Service, ref, run.ResourcePolicy, run.EnabledRegions)
			gen := r.Activity.GeneratedAt
			out.Evidence = append(out.Evidence, ActivityEvidence{
				IdentityAccountID: r.IdentityAccountID, RoleID: r.RoleID, Service: sa.Service,
				State: EvidenceCollected, Reason: q.Reason, LastAuthenticatedAt: sa.LastAuthenticatedAt,
				ReportGeneratedAt: &gen, GrantObservedSince: q.VerifiedGrantFrom, GrantAgeBasis: q.GrantAgeBasis,
				TrackingFrom: q.TrackingFrom, ScanRunID: runID, RouteUsage: ra.Usage,
			})
			out.Assessments = append(out.Assessments, RoleAssessment{RoleID: r.RoleID, Qualification: q})
			out.Routes = append(out.Routes, RouteFacts{AccountID: r.AccountID, RoleID: r.RoleID, Service: sa.Service,
				RouteUsage: ra.Usage, RouteState: ra.State, Routes: ra.RemainingRoutes(), ScanRunID: runID})

			switch q.Outcome {
			case QualUnreviewed:
				out.Unknown = append(out.Unknown, ConditionScope{RoleID: r.RoleID, Kind: KindUnusedService, DetailKey: sa.Service, Reason: q.Reason})
			case QualNoAttempt:
				var grants []grantRef
				for _, ls := range live {
					if ls.rev.Statement.GrantsNamespace(sa.Service) {
						grants = append(grants, grantRef{PolicyKey: ls.rev.PolicyKey, PolicyARN: ls.assign.PolicyARN,
							StatementKey: ls.rev.StatementKey, StatementHash: ls.rev.Hash})
					}
				}
				detail := map[string]any{
					"service":               sa.Service,
					"scope":                 "identity_policies",
					"qualified_days":        q.QualifiedDays,
					"requested_window_days": q.RequestedWindowDays,
					"window_start":          tsv(q.WindowStart),
					"coverage_start":        tsv(q.CoverageStart),
					"covered_until":         tsv(q.CoveredUntil),
					"report_generated_at":   tsv(q.ReportGeneratedAt),
					"last_authenticated_at": ts(q.LastAuthenticatedAt),
					"role_created_at":       tsv(q.RoleFrom),
					"tracking_from":         ts(q.TrackingFrom),
					"grant_age_basis":       q.GrantAgeBasis,
					"verified_grant_from":   ts(q.VerifiedGrantFrom),
					"route_usage":           ra.Usage,
					"route_state":           ra.State,
					"routes":                ra.Routes,
					"grants":                grants,
				}
				f, err := ix.newFinding(KindUnusedService, SeverityMedium, q.Confidence, r, sa.Service, runID, detail)
				if err != nil {
					return err
				}
				out.Findings = append(out.Findings, f)
			}
		}
	} else {
		// No activity facts: one not_collected row per service the live
		// statements name (DECISION D14), and no absence conclusion.
		var granted []string
		for _, ls := range live {
			granted = append(granted, ls.rev.Statement.ExplicitNamespaces()...)
		}
		for _, svc := range sortedUnique(granted) {
			out.Evidence = append(out.Evidence, ActivityEvidence{
				IdentityAccountID: r.IdentityAccountID, RoleID: r.RoleID, Service: svc,
				State: EvidenceNotCollected, Reason: reason, GrantAgeBasis: GrantAgeUnknown,
				ScanRunID: runID, RouteUsage: RouteUsageConfirmRequired,
			})
		}
		out.Unknown = append(out.Unknown, ConditionScope{RoleID: r.RoleID, Kind: KindUnusedService, Reason: reason})
		if bound {
			detail := map[string]any{"reason": reason, "scan_run_id": nilIfEmpty(runID),
				"connector_id": nilIfEmpty(r.ConnectorID), "consumers": consumerDetail}
			f, err := ix.newFinding(KindActivityNotRead, SeverityInfo, ConfidenceNotApplicable, r, "", runID, detail)
			if err != nil {
				return err
			}
			out.Findings = append(out.Findings, f)
		}
	}

	/* ---- broad_grant ---- */
	seenKeys := map[string]bool{}
	for _, ls := range live {
		st := ls.rev.Statement
		if st.Effect != EffectAllow {
			continue
		}
		var reasons []string
		var svcWild []string
		wild := st.ResourceIsWildcard()
		if wild {
			if st.IsNotAction {
				reasons = append(reasons, "not_action_on_all_resources")
			}
			for _, p := range st.Action {
				if allStars(p) {
					reasons = append(reasons, "full_wildcard")
				} else if ns, act, ok := SplitAction(p); ok && allStars(act) {
					svcWild = append(svcWild, strings.ToLower(ns))
				}
			}
		}
		esc := EscalationsGranted(st)
		if len(svcWild) > 0 {
			reasons = append(reasons, "service_wildcard")
		}
		if len(esc) > 0 {
			reasons = append(reasons, "escalation")
		}
		if len(reasons) == 0 {
			continue
		}
		key := ls.rev.StatementKey
		if seenKeys[key] {
			return fmt.Errorf("igagov: role %s has two live statements keyed %q", r.RoleID, key)
		}
		seenKeys[key] = true
		// DECISION D17/D26: severity is not specified; escalation, "*" and
		// NotAction-on-"*" are high, a service wildcard on "*" medium.
		// NotResource counts as all resources.
		severity := SeverityMedium
		for _, why := range reasons {
			if why == "full_wildcard" || why == "not_action_on_all_resources" || why == "escalation" {
				severity = SeverityHigh
			}
		}
		detail := map[string]any{
			"policy_key": ls.rev.PolicyKey, "policy_arn": ls.assign.PolicyARN, "assignment_kind": ls.assign.Kind,
			"statement_key": key, "statement_hash": ls.rev.Hash, "sid": st.Sid,
			"reasons": sortedUnique(reasons), "service_wildcards": sortedUnique(svcWild), "escalations": esc,
			"has_condition": len(st.Conditions) > 0,
		}
		f, err := ix.newFinding(KindBroadGrant, severity, ConfidenceNotApplicable, r, BroadGrantDetailKey(key), runID, detail)
		if err != nil {
			return err
		}
		out.Findings = append(out.Findings, f)
	}

	/* ---- shared_role ---- */
	if len(workloadIDs) >= 2 {
		detail := map[string]any{"workload_count": len(workloadIDs), "consumers": consumerDetail}
		f, err := ix.newFinding(KindSharedRole, SeverityMedium, ConfidenceNotApplicable, r, "", runID, detail)
		if err != nil {
			return err
		}
		out.Findings = append(out.Findings, f)
	}

	/* ---- ownership ---- */
	if bound {
		inWorkloads := map[string]bool{}
		for _, id := range workloadIDs {
			inWorkloads[id] = true
		}
		var accountable []OwnerRecord
		for _, o := range ix.owners {
			if o.Role != OwnerAccountable {
				continue
			}
			if (o.ObjectKind == OwnerObjectIdentity && o.IdentityAccountID == r.IdentityAccountID) ||
				(o.ObjectKind == OwnerObjectWorkload && inWorkloads[o.WorkloadID]) {
				accountable = append(accountable, o)
			}
		}
		if len(accountable) == 0 {
			var tags []string
			tags = append(tags, r.UnmatchedOwnerTags...)
			for _, w := range workloads {
				tags = append(tags, w.UnmatchedOwnerTags...)
			}
			detail := map[string]any{"consumers": consumerDetail, "unmatched_owner_tags": sortedUnique(tags)}
			f, err := ix.newFinding(KindMissingOwner, SeverityMedium, ConfidenceNotApplicable, r, "", "", detail)
			if err != nil {
				return err
			}
			out.Findings = append(out.Findings, f)
		} else if err := ix.reviewDate(r, workloads, accountable, out); err != nil {
			return err
		}
	}
	return nil
}

// reviewDate raises missing_review_date (§2.5) when an enabled
// require_review_date rule's scope matches a consuming workload and an
// accountable owner record of the role, or of a matching workload, has no
// review_due_at (DECISION D11).
func (ix *evalIndex) reviewDate(r RoleSnapshot, workloads []WorkloadSnapshot, accountable []OwnerRecord, out *Evaluation) error {
	var ruleIDs []string
	matched := map[string]bool{}
	for _, rule := range ix.s.Rules {
		if !rule.Enabled || rule.Kind != RuleRequireReviewDate {
			continue
		}
		hit := false
		for _, w := range workloads {
			if rule.Scope.matches(w) {
				matched[w.ID] = true
				hit = true
			}
		}
		if hit {
			ruleIDs = append(ruleIDs, rule.ID)
		}
	}
	if len(ruleIDs) == 0 {
		return nil
	}
	var missing []string
	for _, o := range accountable {
		relevant := o.ObjectKind == OwnerObjectIdentity || matched[o.WorkloadID]
		if relevant && o.ReviewDueAt == nil {
			missing = append(missing, o.ID)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	detail := map[string]any{"rule_ids": sortedUnique(ruleIDs), "owner_ids_without_review_date": sortedUnique(missing)}
	f, err := ix.newFinding(KindMissingReviewDate, SeverityLow, ConfidenceNotApplicable, r, "", "", detail)
	if err != nil {
		return err
	}
	out.Findings = append(out.Findings, f)
	return nil
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

/* ------------------------- finding upserts (§2.5) ------------------------- */

// StoredFinding is the part of an iga_gov_finding row the lifecycle needs.
type StoredFinding struct {
	Fingerprint      string
	Kind             string
	RoleID           string
	DetailKey        string
	Status           string
	LastEvaluatedRev int64
	ExceptedUntil    *time.Time
}

// FindingUpdate is one planned write to iga_gov_finding for rev N. Insert
// rows carry the Finding; updates set Status (ClearException when leaving
// excepted, 048 iga_gov_finding_exception_chk) and LastEvaluatedRev = N.
// HasResult says a finding_result row for rev N is written (its condition
// holds).
type FindingUpdate struct {
	Fingerprint      string
	Insert           bool
	Finding          *Finding
	Status           string
	StatusChanged    bool
	ClearException   bool
	FirstSeenRev     int64
	LastEvaluatedRev int64
	HasResult        bool
}

// PostureKey identifies one role × service posture row.
type PostureKey struct {
	RoleID  string
	Service string
}

// Posture outcomes (051 iga_gov_service_posture.outcome).
const (
	OutcomePending               = "pending"
	OutcomeNotRemoved            = "not_removed"
	OutcomeRemoved               = "removed"
	OutcomeExcludedRoutesRemain  = "excluded_routes_remain"
	OutcomeExcludedRoutesUnknown = "excluded_routes_unknown"
)

func (e Evaluation) unknown(f StoredFinding) bool {
	for _, u := range e.Unknown {
		if u.RoleID == f.RoleID && u.Kind == f.Kind && (u.DetailKey == "" || u.DetailKey == f.DetailKey) {
			return true
		}
	}
	return false
}

// postureStatus maps a service posture outcome to the finding status it
// implies for unused_service findings that AuthSec acted on (§2.5: resolved
// and mitigated follow the current posture; not_removed reopens them).
func postureStatus(current, outcome string) (string, bool) {
	switch outcome {
	case OutcomeRemoved:
		return StatusResolved, true
	case OutcomeExcludedRoutesRemain, OutcomeExcludedRoutesUnknown:
		return StatusMitigated, true
	case OutcomeNotRemoved:
		if current == StatusResolved || current == StatusMitigated {
			return StatusReopened, true
		}
	}
	return current, false
}

// PlanFindingUpdates (DECISION D19) is the pure part of §8.2 step 3's finding upserts: it
// decides, for rev N, which iga_gov_finding rows to insert or update and
// with which status, from the evaluation, the stored findings and the
// current service posture. It never touches a finding whose stored
// last_evaluated_rev is >= N (an older revision never overwrites a newer
// one; the 048 trigger enforces the same in storage, A21), and never touches
// a finding whose condition could not be evaluated at N. The result is
// ordered by fingerprint (the lock order of §8.2).
func PlanFindingUpdates(ev Evaluation, stored []StoredFinding, posture map[PostureKey]string) []FindingUpdate {
	at := ev.EvaluatedAt
	holds := map[string]Finding{}
	for _, f := range ev.Findings {
		holds[f.Fingerprint] = f
	}
	present := map[string]bool{}
	for _, r := range ev.PresentRoles {
		present[r] = true
	}
	byFP := map[string]StoredFinding{}
	for _, s := range stored {
		byFP[s.Fingerprint] = s
	}
	var out []FindingUpdate
	for fp, f := range holds {
		if _, ok := byFP[fp]; ok {
			continue
		}
		fc := f
		status := StatusOpen
		if f.Kind == KindUnusedService {
			if o, ok := posture[PostureKey{RoleID: f.RoleID, Service: f.DetailKey}]; ok {
				status, _ = postureStatus(status, o)
			}
		}
		out = append(out, FindingUpdate{Fingerprint: fp, Insert: true, Finding: &fc, Status: status,
			FirstSeenRev: ev.Rev, LastEvaluatedRev: ev.Rev, HasResult: true})
	}
	for _, s := range stored {
		if s.LastEvaluatedRev >= ev.Rev {
			continue // A21: never overwrite a newer (or the same) revision
		}
		f, isHeld := holds[s.Fingerprint]
		if !isHeld && present[s.RoleID] && ev.unknown(s) {
			continue // indeterminate at N: leave the finding exactly as it is
		}
		next := s.Status
		switch {
		case !present[s.RoleID]:
			next = StatusSuperseded
		case isHeld:
			switch s.Status {
			case StatusCleared, StatusSuperseded:
				next = StatusReopened
			case StatusExcepted:
				if s.ExceptedUntil == nil || !at.Before(*s.ExceptedUntil) {
					next = StatusOpen
				}
			}
		default: // condition false at N
			switch s.Status {
			case StatusOpen, StatusReopened:
				next = StatusCleared
			case StatusExcepted:
				next = StatusCleared
			}
		}
		if s.Kind == KindUnusedService && next != StatusSuperseded && next != StatusExcepted {
			if o, ok := posture[PostureKey{RoleID: s.RoleID, Service: s.DetailKey}]; ok {
				if ps, changed := postureStatus(next, o); changed {
					next = ps
				}
			}
		}
		u := FindingUpdate{Fingerprint: s.Fingerprint, Status: next, StatusChanged: next != s.Status,
			ClearException:   s.Status == StatusExcepted && next != StatusExcepted,
			LastEvaluatedRev: ev.Rev, HasResult: isHeld}
		if isHeld {
			fc := f
			u.Finding = &fc
		}
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fingerprint < out[j].Fingerprint })
	return out
}
