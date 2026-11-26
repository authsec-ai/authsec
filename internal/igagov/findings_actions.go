package igagov

import (
	"sort"
	"time"
)

// R1b's part of the §8.2 evaluation step: action-level activity evidence
// and unused_action findings, computed in the same in-memory pass as R1a's
// findings and written in the same fenced transaction. It runs only when
// Snapshot.ActionLevel is set (R1b on and the 060 schema
// verified); otherwise Evaluate's output is exactly R1a's.

// ActionEvidence is one iga_gov_action_evidence row (060), field for field;
// empty strings and nil pointers are NULL.
type ActionEvidence struct {
	IdentityAccountID  string
	RoleID             string
	Service            string
	Action             string
	ActionKey          string
	State              string
	Outcome            string
	Reason             string
	LastEventAt        *time.Time
	EventCount         int
	CoverageStart      *time.Time
	CoveredUntil       *time.Time
	WindowStart        *time.Time
	QualifiedDays      int
	GrantObservedSince *time.Time
	GrantAgeBasis      string
	DataEvent          bool
	ScanRunID          string
	Catalog            string
}

// boundaryInForce is the role's boundary document at `at` as the graph shows
// it: the statements, live at `at`, of the policy assigned as the role's
// boundary at `at`. nil when the role has no boundary.
func boundaryInForce(r RoleSnapshot, at time.Time) *PolicyDocument {
	key := ""
	for _, a := range r.Assignments {
		if a.Kind != AssignBoundary {
			continue
		}
		for _, tr := range a.Intervals {
			if holdsAt(tr, at) {
				key = a.PolicyKey
			}
		}
	}
	if key == "" {
		return nil
	}
	doc := &PolicyDocument{}
	for _, sr := range r.Statements {
		if sr.PolicyKey == key && holdsAt(TimeRange{From: sr.From, To: sr.To}, at) {
			doc.Statements = append(doc.Statements, sr.Statement)
		}
	}
	return doc
}

// actionOutcome is the posture outcome of one action for an unused_action
// finding (DECISION R1b-8): R1a keeps a service posture table written by
// enforcement observers; R1b derives an action's posture at each evaluation
// from the boundary in force in the published graph -- removed when the
// boundary excludes the action and the service has no remaining
// resource-policy route, excluded_routes_* when it has one, not_removed
// otherwise -- and the finding follows it exactly as an unused_service
// finding follows its posture (postureStatus).
func actionOutcome(boundary *PolicyDocument, action, routeState string) string {
	if boundary == nil || !BoundaryExcludesAction(*boundary, action) {
		return OutcomeNotRemoved
	}
	switch routeState {
	case RouteStateNoneObserved:
		return OutcomeRemoved
	case RouteStateBypassKnown:
		return OutcomeExcludedRoutesRemain
	}
	return OutcomeExcludedRoutesUnknown
}

type actionUse struct {
	last  time.Time
	count int
}

// evaluateActions is R1b for one role whose activity report was collected:
// for every service R1a keeps because it was used (outcome observed), the
// literal actions its live Allow statements name are qualified on the
// connector's CloudTrail coverage; no_event raises unused_action.
func (ix *evalIndex) evaluateActions(r RoleSnapshot, run *RunEvidence, runID string, quals map[string]Qualification,
	routeStates map[string]string, live []liveStatement, workloads []WorkloadSnapshot, window int, out *Evaluation) error {
	at := ix.s.EvaluatedAt
	if out.ActionOutcomes == nil {
		out.ActionOutcomes = map[PostureKey]string{}
	}
	var svcs []string
	for svc, q := range quals {
		if q.Outcome == QualObserved {
			svcs = append(svcs, svc)
		}
	}
	sort.Strings(svcs)
	cands := map[string][]string{}
	for _, svc := range svcs {
		byKey := map[string]string{}
		for _, ls := range live {
			for _, a := range ls.rev.Statement.ExplicitActions(svc) {
				k := ActionKey(a)
				if cur, ok := byKey[k]; !ok || a < cur {
					byKey[k] = a
				}
			}
		}
		for _, k := range sortedKeys(byKey) {
			cands[svc] = append(cands[svc], byKey[k])
		}
	}

	trail, hasTrail := ix.s.ActionTrails[r.ConnectorID]
	var covFrom, covTo time.Time
	var partial []string
	covered := false
	if hasTrail {
		covFrom, covTo, partial, covered = TrailCoverage(trail.Reads, at)
	}
	if !covered {
		// "Not read": no complete CloudTrail read covers this connector. No
		// absence conclusion; existing unused_action findings of the role are
		// left exactly as they are.
		reason := "no_cloudtrail_coverage"
		if len(partial) > 0 {
			reason = "cloudtrail_coverage_incomplete:" + partial[0]
		}
		for _, svc := range svcs {
			for _, a := range cands[svc] {
				out.ActionEvidence = append(out.ActionEvidence, ActionEvidence{IdentityAccountID: r.IdentityAccountID,
					RoleID: r.RoleID, Service: svc, Action: a, ActionKey: ActionKey(a), State: EvidenceNotCollected,
					Outcome: ActionNotCollected, Reason: reason, GrantAgeBasis: GrantAgeUnknown, DataEvent: IsDataEventAction(a),
					ScanRunID: runID, Catalog: ActionCatalogLabel()})
			}
		}
		out.Unknown = append(out.Unknown, ConditionScope{RoleID: r.RoleID, Kind: KindUnusedAction, Reason: reason})
		return nil
	}

	// The role's events, by action. An allowed event no live grant explains
	// makes its namespace unreviewed (DECISION R1b-4).
	uses := map[string]*actionUse{}
	unexplained := map[string]bool{}
	for _, e := range trail.Events[r.RoleID] {
		a, ok := ActionForEventR1B(e.EventSource, e.EventName)
		if !ok {
			continue // unknown source: counted by nobody, never guessed
		}
		k := ActionKey(a)
		u := uses[k]
		if u == nil {
			u = &actionUse{}
			uses[k] = u
		}
		if e.Last.After(u.last) {
			u.last = e.Last
		}
		u.count += e.Count
		if e.Succeeded {
			granted := false
			for _, ls := range live {
				if ls.rev.Statement.GrantsAction(a) {
					granted = true
					break
				}
			}
			if !granted {
				ns, _, _ := SplitAction(k)
				unexplained[ns] = true
			}
		}
	}

	// DECISION R1b-7: a namespace the dependency catalog retains for the
	// role's workload context is never right-sized at action level either.
	var ctxs []DependencyContext
	seenCtx := map[string]bool{}
	wl := map[string]WorkloadSnapshot{}
	for _, w := range workloads {
		wl[w.ID] = w
	}
	for _, c := range r.Consumers {
		if !liveRelationship(c.Relationship) {
			continue
		}
		if ctx, ok := DependencyContextFor(wl[c.WorkloadID].RuntimeKind, c.Relationship); ok && !seenCtx[ctx] {
			seenCtx[ctx] = true
			ctxs = append(ctxs, DependencyContext{Context: ctx})
		}
	}
	boundary := boundaryInForce(r, at)
	tsOK := func(t time.Time) *time.Time { return ptrTime(t) }

	for _, svc := range svcs {
		_, dep := IsDependency(svc, ctxs)
		for _, a := range cands[svc] {
			k := ActionKey(a)
			qi := ActionQualifyInput{Action: a, RoleCreatedAt: r.CreatedAt, RequestedWindowDays: window,
				Paths: GrantPathsForAction(r, a, run.ConnectorFirstPublishedAt), At: at,
				CoverageFrom: covFrom, CoverageTo: covTo, Unexplained: unexplained[svc], Dependency: dep}
			if u := uses[k]; u != nil {
				t := u.last
				qi.LastEventAt, qi.EventCount = &t, u.count
			}
			q := QualifyAction(qi)
			out.ActionEvidence = append(out.ActionEvidence, ActionEvidence{IdentityAccountID: r.IdentityAccountID,
				RoleID: r.RoleID, Service: svc, Action: a, ActionKey: k, State: EvidenceCollected, Outcome: q.Outcome,
				Reason: q.Reason, LastEventAt: q.LastEventAt, EventCount: q.EventCount, CoverageStart: tsOK(q.CoverageStart),
				CoveredUntil: tsOK(q.CoveredUntil), WindowStart: tsOK(q.WindowStart), QualifiedDays: q.QualifiedDays,
				GrantObservedSince: q.VerifiedGrantFrom, GrantAgeBasis: q.GrantAgeBasis, DataEvent: q.DataEvent,
				ScanRunID: runID, Catalog: ActionCatalogLabel()})
			out.ActionOutcomes[PostureKey{RoleID: r.RoleID, Service: k}] = actionOutcome(boundary, a, routeStates[svc])
			if q.Outcome == ActionUnreviewed && q.Reason == "grant_path_not_reconstructable" {
				out.Unknown = append(out.Unknown, ConditionScope{RoleID: r.RoleID, Kind: KindUnusedAction, DetailKey: k, Reason: q.Reason})
			}
			if q.Outcome != ActionNoEvent {
				continue
			}
			var grants []grantRef
			for _, ls := range live {
				if ls.rev.Statement.GrantsAction(a) {
					grants = append(grants, grantRef{PolicyKey: ls.rev.PolicyKey, PolicyARN: ls.assign.PolicyARN,
						StatementKey: ls.rev.StatementKey, StatementHash: ls.rev.Hash})
				}
			}
			severity := SeverityLow
			var esc any
			if e := ActionEscalation(a); e != "" {
				severity, esc = SeverityMedium, e
			}
			detail := map[string]any{
				"service":               svc,
				"action":                a,
				"scope":                 "cloudtrail_management_events",
				"catalog":               ActionCatalogLabel(),
				"qualified_days":        q.QualifiedDays,
				"requested_window_days": q.RequestedWindowDays,
				"window_start":          tsv(q.WindowStart),
				"coverage_start":        tsv(q.CoverageStart),
				"covered_until":         tsv(q.CoveredUntil),
				"last_event_at":         ts(q.LastEventAt),
				"role_created_at":       tsv(q.RoleFrom),
				"grant_age_basis":       q.GrantAgeBasis,
				"verified_grant_from":   ts(q.VerifiedGrantFrom),
				"route_state":           routeStates[svc],
				"partial_coverage":      sortedUnique(partial),
				"escalation":            esc,
				"grants":                grants,
			}
			f, err := ix.newFinding(KindUnusedAction, severity, q.Confidence, r, k, runID, detail)
			if err != nil {
				return err
			}
			out.Findings = append(out.Findings, f)
		}
	}
	return nil
}

func sortActionEvidence(ev []ActionEvidence) {
	sort.Slice(ev, func(i, j int) bool {
		a, b := ev[i], ev[j]
		if a.IdentityAccountID != b.IdentityAccountID {
			return a.IdentityAccountID < b.IdentityAccountID
		}
		return a.ActionKey < b.ActionKey
	})
}
