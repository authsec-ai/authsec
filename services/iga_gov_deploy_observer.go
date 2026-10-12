package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
)

// The enforcement observer (SPEC-iga-phase3-policy.md §8.7 "Who writes
// posture, and in what order"; T3.16). Every writer of posture ENFORCEMENT
// facts -- the verify job at verification, undo and supersession, the
// drift check at each readback, and restriction updates -- goes through
// observeTx, one transaction in the shared lock order:
//
//  1. iga_gov_control: the compare-and-swap UPDATE enforcement_seq = seen+1
//     WHERE enforcement_seq = seen AND state <> 'removed' (a retirement sets
//     state = 'removed' in the same statement, the old epoch's final
//     observation). 0 rows: someone observed later, or the control is
//     retired -> errGovCASLost; the caller discards what it read and reads
//     AWS again (A50 b, A51).
//  2. iga_gov_deployment, then iga_gov_artifact (the caller's step2, by id).
//  3. iga_gov_service_posture of the role, ORDER BY service FOR UPDATE:
//     every row re-pointed to this control (the handoff from a retired
//     control, 051 trigger) and its exclusion recomputed from the boundary
//     in force; first rows inserted for services a deployment excludes for
//     the first time. The outcome is GENERATED and only read back.
//  4. iga_gov_finding of the role's unused_service findings, ORDER BY
//     fingerprint FOR UPDATE, statuses from the derived outcomes
//     (igagov.PostureFindingStatus, the evaluation's own rule).
//
// 40P01 / 40001 are retried at most 3 times with 50-500 ms jittered backoff,
// then the job fails; a lost swap re-reads AWS (bounded rounds, then the
// job is handed back).

var errGovCASLost = errors.New("enforcement observer lost the control's compare-and-swap")

// govBoundaryInForce is the role's boundary as the observer read it.
type govBoundaryInForce struct {
	ARN     string
	DocHash string
	DocText string
}

// govPostureSeed is a posture row to insert when absent, with the route
// facts of the deployment's named scan.
type govPostureSeed struct {
	Service     string
	RouteState  string
	Routes      []igagov.Route
	EvidenceRev int64
	ScanRunID   *uuid.UUID
}

// govObservation is one enforcement observation.
type govObservation struct {
	Dep       models.IGAGovDeployment // the deployment the events name
	ControlID uuid.UUID
	Seen      int64
	// InForce is the role's boundary now; nil = the role has no boundary.
	InForce *govBoundaryInForce
	// CurrentDeployment is the deployment whose boundary is in force (nil
	// keeps each row's).
	CurrentDeployment *uuid.UUID
	Retire            bool
	Seeds             []govPostureSeed
	// Restriction overrides the restriction fact per service.
	Restriction map[string]string
	ResolvedBy  *uuid.UUID
	Writer      string
	// Step2 writes the deployment and ledger rows (lock order 2).
	Step2 func(tx *gorm.DB, newSeq int64) error
}

// govPostureChange is one posture row whose outcome changed.
type govPostureChange struct {
	Service string `json:"service"`
	From    string `json:"from"`
	To      string `json:"to"`
}

// controlSeen reads the control's sequence BEFORE an observer reads AWS.
func controlSeen(db *gorm.DB, ws, control uuid.UUID) (int64, string, error) {
	var row struct {
		EnforcementSeq int64
		State          string
	}
	err := db.Raw(`SELECT enforcement_seq, state FROM iga_gov_control WHERE workspace_id = ? AND id = ?`, ws, control).Scan(&row).Error
	return row.EnforcementSeq, row.State, err
}

func (s *GovDeployments) hook(stage string, control uuid.UUID, tx *gorm.DB) error {
	if s.ObserverHook != nil {
		return s.ObserverHook(stage, control, tx)
	}
	return nil
}

// observe runs build (which reads the control's sequence, then AWS) and
// observeTx with the shared retries. build returning nil means nothing to
// write.
func (s *GovDeployments) observe(ctx context.Context, run *PolicyJobRun, build func(ctx context.Context) (*govObservation, error)) ([]govPostureChange, error) {
	casLost, failures := 0, 0
	for {
		o, err := build(ctx)
		if err != nil || o == nil {
			return nil, err
		}
		var changes []govPostureChange
		err = run.InTx(ctx, func(tx *gorm.DB) error {
			var e error
			changes, e = s.observeTx(tx, o)
			return e
		})
		if err == nil {
			return changes, nil
		}
		if errors.Is(err, errGovCASLost) {
			casLost++
			if casLost >= govDeployObserverMaxCASRounds {
				return nil, PolicyJobRetryLater(30*time.Second, "the control's compare-and-swap was lost repeatedly")
			}
			continue // a fresh readback, never the stale one
		}
		if st := sqlState(err); st == "40P01" || st == "40001" {
			_ = s.hook("retry:"+st, uuid.Nil, nil) // test seam: count retries
			failures++
			if failures >= govDeployObserverMaxAttempts {
				return nil, fmt.Errorf("enforcement observer: after %d attempts: %w", failures, err)
			}
			backoff := 50*time.Millisecond + time.Duration(rand.Int63n(int64(450*time.Millisecond)))
			if serr := s.sleep(ctx, backoff); serr != nil {
				return nil, serr
			}
			continue
		}
		return nil, err
	}
}

func excludes(doc *igagov.PolicyDocument, svc string) bool {
	return doc != nil && igagov.BoundaryExcludes(*doc, svc)
}

// observeTx is one observation in the shared lock order (see the file
// comment).
func (s *GovDeployments) observeTx(tx *gorm.DB, o *govObservation) ([]govPostureChange, error) {
	ws := o.Dep.WorkspaceID
	// 1. control: compare-and-swap.
	res := tx.Exec(`UPDATE iga_gov_control
		SET enforcement_seq = enforcement_seq + 1,
		    state = CASE WHEN ? THEN 'removed' ELSE state END, updated_at = now()
		WHERE workspace_id = ? AND id = ? AND enforcement_seq = ? AND state <> 'removed'`, o.Retire, ws, o.ControlID, o.Seen)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected != 1 {
		return nil, errGovCASLost
	}
	newSeq := o.Seen + 1
	if err := s.hook("after_cas", o.ControlID, tx); err != nil {
		return nil, err
	}
	var c models.IGAGovControl
	if err := tx.Where("workspace_id = ? AND id = ?", ws, o.ControlID).Take(&c).Error; err != nil {
		return nil, err
	}
	// 2. deployment, then ledger.
	if o.Step2 != nil {
		if err := o.Step2(tx, newSeq); err != nil {
			return nil, err
		}
	}
	// 3. posture.
	var doc *igagov.PolicyDocument
	var inForceHash *string
	if o.InForce != nil {
		canon, h, err := igagov.CanonicalDocument(o.InForce.DocText)
		if err != nil {
			return nil, fmt.Errorf("boundary in force: %w", err)
		}
		if err := archiveDocumentTx(tx, ws, string(canon), h); err != nil {
			return nil, err
		}
		d, err := igagov.DecodePolicyDocument(o.InForce.DocText)
		if err != nil {
			return nil, err
		}
		doc, inForceHash = &d, &h
	}
	var rows []models.IGAGovServicePosture
	if err := tx.Raw(`SELECT * FROM iga_gov_service_posture WHERE workspace_id = ? AND account_id = ? AND role_id = ?
		ORDER BY service FOR UPDATE`, ws, c.AccountID, c.RoleID).Scan(&rows).Error; err != nil {
		return nil, err
	}
	have := map[string]bool{}
	outcomes := map[string]string{}
	var changes []govPostureChange
	for _, r := range rows {
		have[r.Service] = true
		excl := models.GovExclusionNotApplied
		if excludes(doc, r.Service) {
			excl = models.GovExclusionApplied
		}
		cur := r.CurrentDeploymentID
		if o.CurrentDeployment != nil {
			cur = o.CurrentDeployment
		}
		if excl == models.GovExclusionApplied && cur == nil {
			excl = models.GovExclusionNotApplied // 051 iga_gov_sp_in_force_chk: applied names its deployment
		}
		restr := r.Restriction
		if (r.BoundaryDocumentHash == nil) != (inForceHash == nil) ||
			(r.BoundaryDocumentHash != nil && inForceHash != nil && *r.BoundaryDocumentHash != *inForceHash) {
			restr = igagov.RestrictionNotObserved // "since the boundary in force was applied"
		}
		if v, ok := o.Restriction[r.Service]; ok {
			restr = v
		}
		var out string
		if err := tx.Raw(`UPDATE iga_gov_service_posture
			SET control_id = ?, current_deployment_id = ?, boundary_document_hash = ?, exclusion = ?, restriction = ?,
			    enforcement_seq = ?, enforcement_observed_at = now(), assessed_at = now()
			WHERE workspace_id = ? AND account_id = ? AND role_id = ? AND service = ? RETURNING outcome`,
			c.ID, cur, inForceHash, excl, restr, newSeq, ws, r.AccountID, r.RoleID, r.Service).Scan(&out).Error; err != nil {
			return nil, fmt.Errorf("posture %s/%s: %w", r.RoleID, r.Service, err)
		}
		outcomes[r.Service] = out
		if out != r.Outcome {
			changes = append(changes, govPostureChange{Service: r.Service, From: r.Outcome, To: out})
		}
	}
	sort.Slice(o.Seeds, func(i, j int) bool { return o.Seeds[i].Service < o.Seeds[j].Service })
	for _, sd := range o.Seeds {
		if have[sd.Service] {
			continue
		}
		have[sd.Service] = true
		excl := models.GovExclusionNotApplied
		if excludes(doc, sd.Service) && o.CurrentDeployment != nil {
			excl = models.GovExclusionApplied
		}
		restr := igagov.RestrictionNotObserved
		if v, ok := o.Restriction[sd.Service]; ok {
			restr = v
		}
		routes := sd.Routes
		if routes == nil {
			routes = []igagov.Route{}
		}
		raw, _ := json.Marshal(routes)
		var out string
		if err := tx.Raw(`INSERT INTO iga_gov_service_posture (workspace_id, account_id, role_id, service, control_id,
			current_deployment_id, boundary_document_hash, exclusion, restriction, enforcement_seq, enforcement_observed_at,
			route_state, routes, evidence_rev, evidence_scan_run_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, now(), ?, ?::jsonb, ?, ?) RETURNING outcome`,
			ws, c.AccountID, c.RoleID, sd.Service, c.ID, o.CurrentDeployment, inForceHash, excl, restr, newSeq,
			sd.RouteState, string(raw), sd.EvidenceRev, sd.ScanRunID).Scan(&out).Error; err != nil {
			return nil, fmt.Errorf("posture %s/%s insert: %w", c.RoleID, sd.Service, err)
		}
		outcomes[sd.Service] = out
		changes = append(changes, govPostureChange{Service: sd.Service, From: "", To: out})
	}
	for _, ch := range changes {
		if err := s.event(tx, o.Dep, GovEventPostureChanged, map[string]any{"control_id": c.ID, "role_id": c.RoleID,
			"service": ch.Service, "from": ch.From, "to": ch.To, "enforcement_seq": newSeq, "writer": o.Writer}); err != nil {
			return nil, err
		}
	}
	// 4. findings.
	if len(outcomes) > 0 {
		svcs := make([]string, 0, len(outcomes))
		for k := range outcomes {
			svcs = append(svcs, k)
		}
		var fs []struct {
			ID          uuid.UUID
			Fingerprint string
			DetailKey   string
			Status      string
		}
		if err := tx.Raw(`SELECT id, fingerprint, detail_key, status FROM iga_gov_finding
			WHERE workspace_id = ? AND kind = 'unused_service' AND role_id = ? AND detail_key IN ?
			ORDER BY fingerprint FOR UPDATE`, ws, c.RoleID, svcs).Scan(&fs).Error; err != nil {
			return nil, err
		}
		for _, f := range fs {
			next, changed := igagov.PostureFindingStatus(f.Status, outcomes[f.DetailKey])
			if !changed {
				continue
			}
			q := `UPDATE iga_gov_finding SET status = ?, status_changed_at = now()`
			args := []any{next}
			if next == igagov.StatusResolved && o.ResolvedBy != nil {
				q += `, resolved_by_deployment_id = ?`
				args = append(args, *o.ResolvedBy)
			}
			args = append(args, f.ID)
			if err := tx.Exec(q+` WHERE id = ?`, args...).Error; err != nil {
				return nil, err
			}
			fid := f.ID
			pol, _, err := s.policyOfVersion(tx, ws, o.Dep.VersionID)
			if err != nil {
				return nil, err
			}
			refs := depRefs(o.Dep, pol)
			refs.FindingID = &fid
			if err := appendGovEvent(tx, ws, GovEventFindingPostureStatus, models.GovActorSystem, "policy-worker", refs,
				map[string]any{"from": f.Status, "to": next, "service": f.DetailKey, "outcome": outcomes[f.DetailKey],
					"writer": o.Writer}); err != nil {
				return nil, err
			}
		}
	}
	return changes, nil
}

/* ---------------------------- route facts helpers -------------------------- */

// routeFacts is a service's route state and remaining routes from a plan's
// impact (the named scan's routes, §8.7 history "route_state: the plan's
// named scan"). Role-ARN routes (limited) do not count. A service with no
// named scan is not_analysed with one explanatory route (051
// iga_gov_sp_routes_chk: only none_observed has no routes).
func routeFacts(p igagov.Plan, svc string) (string, []igagov.Route) {
	var rem []igagov.Route
	state := igagov.RouteStateNoneObserved
	rank := map[string]int{igagov.RouteStateNoneObserved: 0, igagov.RouteStateNotAnalysed: 1,
		igagov.RouteStateEffectUnknown: 2, igagov.RouteStateBypassKnown: 3}
	for _, r := range p.Impact.Routes {
		if r.Service != svc || r.Effect == igagov.RouteEffectLimited {
			continue
		}
		rem = append(rem, r)
		if rank[r.Effect] > rank[state] {
			state = r.Effect
		}
	}
	if p.ResourcePolicyScanRunID == nil && state == igagov.RouteStateNoneObserved {
		return igagov.RouteStateNotAnalysed, []igagov.Route{{Service: svc, Effect: igagov.RouteStateNotAnalysed,
			Reason: "no resource-policy scan named by the plan"}}
	}
	if rem == nil {
		rem = []igagov.Route{}
	}
	igagov.SortRoutes(rem)
	return state, rem
}

func scanOf(p igagov.Plan) *uuid.UUID {
	if p.ResourcePolicyScanRunID == nil {
		return nil
	}
	id, err := uuid.Parse(*p.ResourcePolicyScanRunID)
	if err != nil {
		return nil
	}
	return &id
}

// seedsFor are the posture rows a deployment inserts for the services its
// boundary excludes for the first time (§8.7 table).
func seedsFor(p igagov.Plan) []govPostureSeed {
	var out []govPostureSeed
	set := map[string]bool{}
	for _, svc := range append(append([]string{}, p.Diff.NewlyExcluded...), p.Diff.AlreadyExcluded...) {
		set[strings.ToLower(svc)] = true
	}
	for _, r := range p.Impact.Removed {
		set[r.Service] = true
	}
	for svc := range set {
		st, rs := routeFacts(p, svc)
		out = append(out, govPostureSeed{Service: svc, RouteState: st, Routes: rs, EvidenceRev: p.EvidenceRev, ScanRunID: scanOf(p)})
	}
	return out
}

// historyTx writes the deployment's iga_gov_service_outcome rows at its
// verification (§8.7 history: written once, never rewritten). An undo or a
// control removal records only actual differences (§8.9).
func historyTx(tx *gorm.DB, d models.IGAGovDeployment, p igagov.Plan, restriction map[string]string) error {
	type item struct{ svc, change, excl string }
	var items []item
	for _, s := range p.Diff.NewlyExcluded {
		items = append(items, item{s, "newly_excluded", "applied"})
	}
	if d.Kind == igagov.PlanApply {
		for _, s := range p.Diff.AlreadyExcluded {
			items = append(items, item{s, "already_excluded", "applied"})
		}
	}
	for _, s := range p.Diff.NewlyUnexcluded {
		items = append(items, item{s, "newly_unexcluded", "reverted"})
	}
	for _, it := range items {
		st, routes := routeFacts(p, it.svc)
		restr := igagov.RestrictionNotObserved
		if v, ok := restriction[it.svc]; ok {
			restr = v
		}
		outcome := models.GovOutcomeNotRemoved
		if it.excl == "applied" && restr != igagov.RestrictionContradicted {
			switch st {
			case igagov.RouteStateNoneObserved:
				outcome = models.GovOutcomeRemoved
			case igagov.RouteStateBypassKnown:
				outcome = models.GovOutcomeExcludedRoutesRemain
			default:
				outcome = models.GovOutcomeExcludedRoutesUnknown
			}
		}
		raw, _ := json.Marshal(routes)
		if err := tx.Exec(`INSERT INTO iga_gov_service_outcome (workspace_id, deployment_id, service, change, exclusion, route_state,
			routes, restriction, outcome) VALUES (?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?)
			ON CONFLICT (workspace_id, deployment_id, service) DO NOTHING`,
			d.WorkspaceID, d.ID, it.svc, it.change, it.excl, st, string(raw), restr, outcome).Error; err != nil {
			return fmt.Errorf("history %s: %w", it.svc, err)
		}
	}
	return nil
}
