package services

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
)

// R1b's reads and writes (SPEC-iga-phase3-policy.md §12.1): the CloudTrail
// history the evaluation qualifies actions on, the frozen action evidence it
// writes (060 iga_gov_action_evidence), and the reads the bundle, the
// recommendation, observation and the finding detail make of it. Everything
// here runs only while PolicyActionsOn() (IGA_POLICY_R1B).

// govActionEvidence is one iga_gov_action_evidence row.
type govActionEvidence struct {
	WorkspaceID        uuid.UUID  `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	Rev                int64      `json:"rev" gorm:"primaryKey"`
	IdentityAccountID  uuid.UUID  `json:"identity_account_id" gorm:"type:uuid;primaryKey"`
	RoleID             string     `json:"role_id"`
	Service            string     `json:"service"`
	Action             string     `json:"action"`
	ActionKey          string     `json:"action_key" gorm:"primaryKey"`
	State              string     `json:"state"`
	Outcome            string     `json:"outcome"`
	Reason             string     `json:"reason"`
	LastEventAt        *time.Time `json:"last_event_at"`
	EventCount         int        `json:"event_count"`
	CoverageStart      *time.Time `json:"coverage_start"`
	CoveredUntil       *time.Time `json:"covered_until"`
	WindowStart        *time.Time `json:"window_start"`
	QualifiedDays      int        `json:"qualified_days"`
	GrantObservedSince *time.Time `json:"grant_observed_since"`
	GrantAgeBasis      string     `json:"grant_age_basis"`
	DataEvent          bool       `json:"data_event"`
	ScanRunID          *uuid.UUID `json:"scan_run_id" gorm:"type:uuid"`
	Catalog            string     `json:"catalog"`
}

func (govActionEvidence) TableName() string { return "iga_gov_action_evidence" }

// GovActionEvidence is the API view of one action evidence row.
type GovActionEvidence = govActionEvidence

// actionTrailLookback bounds the CloudTrail history read: the longest window
// (MaxWindowDays) plus one scan's look-back.
const actionTrailLookback = time.Duration(igagov.MaxWindowDays)*24*time.Hour + igagov.MaxTrailScanGap

// actionTrailRead turns one published scan's coverage into an R1b trail read
// (DECISION R1b-6): [scan start − 48 h, scan start], complete only when
// every Region of the scan's frozen scope -- selected and, when known,
// enabled -- has a cloudtrail-events surface that was reached below the
// 10,000-event cap. Without a frozen scope, every cloudtrail-events surface
// present must be reached, and there must be at least one.
func actionTrailRead(startedAt *time.Time, requestedAt time.Time, raw []byte) (igagov.ActionTrailRead, bool) {
	cov := models.DecodeScanCoverage(raw)
	at := requestedAt
	if startedAt != nil {
		at = *startedAt
	}
	read := igagov.ActionTrailRead{From: at.Add(-igagov.MaxTrailScanGap).UTC(), To: at.UTC(), Complete: true}
	prefix := models.SurfaceCloudTrailEventsPrefix + ":"
	surfaces := map[string]models.SurfaceCoverage{}
	for k, sc := range cov.Surfaces {
		if strings.HasPrefix(k, prefix) {
			surfaces[strings.TrimPrefix(k, prefix)] = sc
		}
	}
	if len(surfaces) == 0 {
		return read, false // this scan read no CloudTrail at all
	}
	var want []string
	if cov.Regions != nil {
		want = append(want, cov.Regions.Selected...)
		if cov.Regions.EnabledKnown {
			want = append(want, cov.Regions.Enabled...)
		}
	}
	if len(want) == 0 {
		// No frozen scope: every surface the scan meant to read.
		for r, sc := range surfaces {
			if sc.State != models.CloudCoverageNotSelected {
				want = append(want, r)
			}
		}
		if len(want) == 0 {
			return read, false
		}
	}
	sort.Strings(want)
	for _, r := range want {
		sc, ok := surfaces[r]
		switch {
		case !ok || sc.State == models.CloudCoverageNotSelected:
			read.Complete, read.Reason = false, "cloudtrail_region_not_read:"+r
		case sc.State == "partial" || sc.Count >= 10000:
			read.Complete, read.Reason = false, "cloudtrail_event_cap_hit:"+r
		case sc.State != models.CloudCoverageReached:
			read.Complete, read.Reason = false, "cloudtrail_"+sc.State+":"+r
		}
		if !read.Complete {
			break
		}
	}
	return read, true
}

// loadActionTrails reads, on db (the evaluation's transaction under row-level
// security for ws), for every connector of the workspace, its CloudTrail
// reads up to `at` and its roles' attributed events aggregated per (source,
// name): the evaluation's R1b input. Events are cloud_observation rows of
// cloudtrail:LookupEvents attributed by session issuer (T3.04); the role is
// the issuer's principalId (its RoleId), so a recreated role's predecessor's
// events never count.
func loadActionTrails(ctx context.Context, db *gorm.DB, ws uuid.UUID, at time.Time) (map[string]igagov.ActionTrail, error) {
	db = db.WithContext(ctx)
	since := at.Add(-actionTrailLookback)
	out := map[string]igagov.ActionTrail{}
	var runs []struct {
		ConnectorID uuid.UUID
		StartedAt   *time.Time
		RequestedAt time.Time
		Coverage    []byte
	}
	// Bound to workspace_id = ? as well as RLS (the evaluation's workspace).
	if err := db.Raw(`SELECT connector_id, started_at, requested_at, coverage FROM cloud_scan_run
	                   WHERE workspace_id = ? AND status = 'published'
	                     AND COALESCE(started_at, requested_at) >= ? AND COALESCE(started_at, requested_at) <= ?
	                   ORDER BY connector_id, COALESCE(started_at, requested_at), id`, ws, since, at).Scan(&runs).Error; err != nil {
		return nil, fmt.Errorf("cloudtrail reads: %w", err)
	}
	for _, r := range runs {
		read, ok := actionTrailRead(r.StartedAt, r.RequestedAt, r.Coverage)
		if !ok {
			continue
		}
		t := out[r.ConnectorID.String()]
		t.Reads = append(t.Reads, read)
		out[r.ConnectorID.String()] = t
	}
	var evs []struct {
		ConnectorID uuid.UUID
		RoleID      string
		EventSource string
		EventName   string
		Last        time.Time
		N           int
		Succeeded   bool
	}
	if err := db.Raw(`SELECT o.connector_id,
	                         o.sanitized_facts->>'session_issuer_principal_id' AS role_id,
	                         COALESCE(o.sanitized_facts->>'event_source', '') AS event_source,
	                         COALESCE(o.sanitized_facts->>'event_name', '') AS event_name,
	                         max(o.observed_at) AS last, count(*) AS n,
	                         bool_or(COALESCE(o.sanitized_facts->>'error_code', '') = '') AS succeeded
	                    FROM cloud_observation o
	                   WHERE o.workspace_id = ? AND o.source_api = 'cloudtrail:LookupEvents'
	                     AND o.sanitized_facts->>'attribution' = 'session_issuer'
	                     AND COALESCE(o.sanitized_facts->>'session_issuer_principal_id', '') <> ''
	                     AND o.observed_at >= ? AND o.observed_at <= ?
	                   GROUP BY 1, 2, 3, 4
	                   ORDER BY 1, 2, 3, 4`, ws, since, at).Scan(&evs).Error; err != nil {
		return nil, fmt.Errorf("cloudtrail events: %w", err)
	}
	for _, e := range evs {
		t := out[e.ConnectorID.String()]
		if t.Events == nil {
			t.Events = map[string][]igagov.TrailEventAgg{}
		}
		t.Events[e.RoleID] = append(t.Events[e.RoleID], igagov.TrailEventAgg{EventSource: e.EventSource, EventName: e.EventName,
			Last: e.Last.UTC(), Count: e.N, Succeeded: e.Succeeded})
		out[e.ConnectorID.String()] = t
	}
	return out, nil
}

// insertActionEvidenceTx writes the evaluation's action evidence (the
// evaluation is running: the 060 freeze trigger refuses it otherwise).
func insertActionEvidenceTx(tx *gorm.DB, ws uuid.UUID, rev int64, ev []igagov.ActionEvidence) error {
	if len(ev) == 0 {
		return nil
	}
	rows := make([]govActionEvidence, 0, len(ev))
	for _, a := range ev {
		iid, err := uuid.Parse(a.IdentityAccountID)
		if err != nil {
			return fmt.Errorf("action evidence identity %q: %w", a.IdentityAccountID, err)
		}
		rows = append(rows, govActionEvidence{WorkspaceID: ws, Rev: rev, IdentityAccountID: iid, RoleID: a.RoleID,
			Service: a.Service, Action: a.Action, ActionKey: a.ActionKey, State: a.State, Outcome: a.Outcome, Reason: a.Reason,
			LastEventAt: a.LastEventAt, EventCount: a.EventCount, CoverageStart: a.CoverageStart, CoveredUntil: a.CoveredUntil,
			WindowStart: a.WindowStart, QualifiedDays: a.QualifiedDays, GrantObservedSince: a.GrantObservedSince,
			GrantAgeBasis: a.GrantAgeBasis, DataEvent: a.DataEvent, ScanRunID: uuidPtr(a.ScanRunID), Catalog: a.Catalog})
	}
	return tx.CreateInBatches(rows, 500).Error
}

// pruneActionEvidenceTx deletes the action evidence of every revision the
// R1a prune recorded as pruned (iga_gov_evaluation_pruned, 059): R1b's
// evidence follows the same retention as the activity evidence (§2.5).
func pruneActionEvidenceTx(tx *gorm.DB, ws uuid.UUID) (int64, error) {
	// tx is the prune's transaction under RLS for ws; both statements are
	// bound to workspace_id = ? as well.
	res := tx.Exec(`DELETE FROM iga_gov_action_evidence
	                 WHERE workspace_id = ? AND rev IN (SELECT rev FROM iga_gov_evaluation_pruned WHERE workspace_id = ?)`, ws, ws)
	return res.RowsAffected, res.Error
}

// actionEvidenceAt reads a role's frozen action evidence at rev.
func actionEvidenceAt(db *gorm.DB, ws uuid.UUID, rev int64, identity uuid.UUID) ([]govActionEvidence, error) {
	out := []govActionEvidence{}
	err := db.Where("workspace_id = ? AND rev = ? AND identity_account_id = ?", ws, rev, identity).
		Order("action_key").Find(&out).Error
	return out, err
}

// bundleActionActivity renders frozen action evidence as bundle facts.
func bundleActionActivity(rows []govActionEvidence) []igagov.BundleActionActivity {
	ts := func(t *time.Time) *string {
		if t == nil {
			return nil
		}
		s := t.UTC().Format(time.RFC3339Nano)
		return &s
	}
	out := make([]igagov.BundleActionActivity, 0, len(rows))
	for _, r := range rows {
		out = append(out, igagov.BundleActionActivity{Action: r.Action, Service: r.Service, State: r.State, Outcome: r.Outcome,
			Reason: r.Reason, LastEventAt: ts(r.LastEventAt), GrantAgeBasis: r.GrantAgeBasis,
			VerifiedGrantFrom: ts(r.GrantObservedSince), QualifiedDays: r.QualifiedDays, DataEvent: r.DataEvent})
	}
	return out
}

// removableActions are the actions a removal can be justified for at action
// level (justifyActionRemovals' rules), from a role's frozen evidence:
// collected, no_event for >= MinQualifiedDays, a known grant age, not a
// dependency namespace and not a removed service. DECISION R1b-5: data-event
// actions (not_observable) are never recommended; an author adds them with
// an explicit acknowledgement.
func removableActions(rows []govActionEvidence, ctxs []igagov.DependencyContext, removedSvc map[string]bool) []govActionEvidence {
	var out []govActionEvidence
	for _, r := range rows {
		if r.State != igagov.EvidenceCollected || r.Outcome != igagov.ActionNoEvent || r.QualifiedDays < igagov.MinQualifiedDays {
			continue
		}
		if r.GrantAgeBasis != igagov.GrantAgeObservedSinceChange && r.GrantAgeBasis != igagov.GrantAgePredatesObservation {
			continue
		}
		if _, dep := igagov.IsDependency(r.Service, ctxs); dep || removedSvc[r.Service] {
			continue
		}
		out = append(out, r)
	}
	return out
}

// actionObservation adds, for the removed actions of one observation target,
// the newest attributed event recorded in the action evidence at rev as
// LastAttempts[action] (igagov.EvaluateObservation sends the version back to
// draft for an event after the evidence report).
func actionObservation(db *gorm.DB, ws uuid.UUID, rev int64, identity uuid.UUID, acts []string, ot *igagov.ObservationTarget) error {
	rows, err := actionEvidenceAt(db, ws, rev, identity)
	if err != nil {
		return err
	}
	want := map[string]string{}
	for _, a := range acts {
		want[igagov.ActionKey(a)] = a
	}
	for _, r := range rows {
		if a, ok := want[r.ActionKey]; ok && r.LastEventAt != nil {
			t := r.LastEventAt.UTC()
			ot.LastAttempts[a] = &t
		}
	}
	return nil
}
