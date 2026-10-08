package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// Metrics (SPEC-iga-phase3-policy.md §8.12, §7.8; requirement P-14; T3.18).
//
// metrics_rollup upserts one iga_gov_metrics_hourly row per workspace and
// hour, in ONE statement (one snapshot, so the numbers of a row never mix
// two moments). Two kinds of number are kept apart:
//
//   - posture_* -- current posture, from iga_gov_service_posture: one count
//     per (account, role incarnation, service) by its GENERATED outcome.
//     Rows of a retired control (iga_gov_control.state = 'removed') are not
//     counted. "Removed" is only the `removed` outcome: an exclusion with a
//     known remaining route (excluded_routes_remain, A43) or an unknown one
//     is its own column and never part of it. One row per key, so
//     successive deployments, supersession and partial rollouts cannot
//     double-count (A48: v1 sqs + v2 sqs,sns = 2, not 3).
//   - changes_* -- from iga_gov_service_outcome (history) of the
//     deployments VERIFIED during the hour: each newly_excluded and
//     newly_unexcluded row counted once; already_excluded never (DB94). An
//     undo records only newly_unexcluded (or newly_excluded) services, so a
//     verified undo subtracts exactly what it returned (A19, A48). A
//     deployment that never verified has no history and contributes nothing
//     (A49).
//
// DECISIONS (T3.18):
//
//	M1  Posture "at the end of the hour" is the posture when the job runs:
//	    iga_gov_service_posture holds only the current state, so the past
//	    cannot be re-read. The job for hour H is enqueued at H+1h and the row
//	    carries computed_at, which the API reports as posture_as_of; a late
//	    run says how late it is instead of pretending. A rerun of the same
//	    hour (retry) re-reads posture and rewrites the row (upsert).
//	M2  A change belongs to the hour its deployment's verified_at falls in
//	    (the history rows are written in the same transaction that sets it).
//	M3  Only the immediately preceding hour is enqueued (dedupe hour:<RFC
//	    3339 UTC>, once per workspace-hour). Hours missed while no worker ran
//	    are NOT backfilled, because their posture can no longer be read; the
//	    API reports them as missing hours, never as zeros.
//	M4  roles_right_sized = distinct roles with at least one `removed`
//	    posture row on a live control. roles_eligible = distinct roles with
//	    a posture row on a live control UNION roles with an unused_service
//	    finding still open / reopened / under_review: a candidate not yet
//	    acted on is in the denominator, so the ratio is not inflated by
//	    counting only roles AuthSec already changed (P-14 "coverage
//	    denominators"). Roles are keyed by RoleId (the incarnation).
//	M5  approval_p50/p95_seconds: approvals (approve or reject) DECIDED in
//	    the hour, measured from the latest version_proposed event of the
//	    version at or before the decision; approvals_pending = versions in
//	    in_review when the job runs.
//	M6  apply_to_verified_p95_seconds: deployments verified in the hour,
//	    verified_at - applied_at. E-11 asks to separate AuthSec processing
//	    from provider latency; 052 has one column, so the split needs DDL
//	    (reported, not invented here).
//	M7  unexpected_failures: distinct unexpected authorization failures
//	    (§8.6 no_unexpected_failures: denials no declared expected=denied
//	    validation explains) whose event_time falls in the hour, from the
//	    application_health verification evidence, deduplicated per
//	    (role, event time, action, session, error code) across overlapping
//	    deployments of the same role.
//	M8  undos: undo deployments verified in the hour.
//	M9  Hours are UTC-aligned; the rollup sets TimeZone UTC for its
//	    transaction so 052's CHECK (date_trunc('hour', hour) = hour) holds
//	    whatever the session zone (a +05:30 session would otherwise refuse
//	    a UTC hour).
//	M10 A workspace is rolled up once it has a Phase 3 policy
//	    (iga_gov_policy); a workspace without one has nothing to count.

// GovMetricsEvery is metrics_rollup's interval (§8.1: hourly).
const GovMetricsEvery = time.Hour

// GovMetrics computes and reads iga_gov_metrics_hourly.
type GovMetrics struct {
	db  *gorm.DB
	key []byte
	now func() time.Time
}

// NewGovMetrics builds the metrics service; cursorKey signs list cursors.
func NewGovMetrics(db *gorm.DB, cursorKey []byte) *GovMetrics {
	return &GovMetrics{db: db, key: cursorKey, now: time.Now}
}

// WithClock replaces the clock (tests).
func (m *GovMetrics) WithClock(now func() time.Time) *GovMetrics {
	m.now = now
	return m
}

// GovMetricsDedupeKey is the job's dedupe key for an hour: hour:<RFC 3339 UTC>.
func GovMetricsDedupeKey(hour time.Time) string {
	return "hour:" + hour.UTC().Format(time.RFC3339)
}

// ParseGovMetricsHour reads an hour from a dedupe key; the hour must be
// aligned.
func ParseGovMetricsHour(key string) (time.Time, error) {
	raw, ok := strings.CutPrefix(key, "hour:")
	if !ok {
		return time.Time{}, fmt.Errorf("metrics_rollup dedupe key %q is not hour:<ts>", key)
	}
	h, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("metrics_rollup dedupe key %q: %w", key, err)
	}
	h = h.UTC()
	if !h.Equal(h.Truncate(time.Hour)) {
		return time.Time{}, fmt.Errorf("metrics_rollup hour %s is not aligned to the hour", h.Format(time.RFC3339))
	}
	return h, nil
}

// govMetricsRollupSQL computes one workspace-hour and upserts it, in one
// statement. Parameters: @ws, @from (the hour), @to (the hour + 1h). The
// CTE names carry the iga_ prefix so scripts/ci-iga-isolation-check.sh,
// which reads every FROM/JOIN target as a table, accepts them.
const govMetricsRollupSQL = `
WITH
iga_m_posture AS (
  SELECT sp.account_id, sp.role_id, sp.outcome
    FROM iga_gov_service_posture sp
    JOIN iga_gov_control c ON c.workspace_id = sp.workspace_id AND c.id = sp.control_id
   WHERE sp.workspace_id = @ws AND c.state <> 'removed'
),
iga_m_verified AS (
  SELECT d.id, d.kind, d.applied_at, d.verified_at
    FROM iga_gov_deployment d
   WHERE d.workspace_id = @ws AND d.verified_at IS NOT NULL AND d.verified_at >= @from AND d.verified_at < @to
),
iga_m_changes AS (
  SELECT o.change
    FROM iga_gov_service_outcome o
    JOIN iga_m_verified vd ON vd.id = o.deployment_id
   WHERE o.workspace_id = @ws
),
iga_m_eligible AS (
  SELECT role_id FROM iga_m_posture
  UNION
  SELECT f.role_id FROM iga_gov_finding f
   WHERE f.workspace_id = @ws AND f.kind = 'unused_service' AND f.role_id IS NOT NULL
     AND f.status IN ('open','reopened','under_review')
),
iga_m_approvals AS (
  SELECT EXTRACT(EPOCH FROM (a.decided_at - s.submitted_at)) AS secs
    FROM iga_gov_approval a
    CROSS JOIN LATERAL (
      SELECT max(e.occurred_at) AS submitted_at FROM iga_gov_event e
       WHERE e.workspace_id = a.workspace_id AND e.version_id = a.version_id
         AND e.event = 'version_proposed' AND e.occurred_at <= a.decided_at) s
   WHERE a.workspace_id = @ws AND a.decided_at >= @from AND a.decided_at < @to AND s.submitted_at IS NOT NULL
),
iga_m_failures AS (
  SELECT DISTINCT c.role_id, x->>'event_time' AS at, x->>'action' AS action, x->>'session_name' AS session, x->>'error_code' AS code
    FROM iga_gov_verification v
    JOIN iga_gov_deployment d ON d.workspace_id = v.workspace_id AND d.id = v.deployment_id
    JOIN iga_gov_control c ON c.workspace_id = d.workspace_id AND c.id = d.control_id
    CROSS JOIN LATERAL jsonb_path_query(v.evidence, '$.canary.unexpected_failures[*]') x
   WHERE v.workspace_id = @ws AND v.dimension = 'application_health' AND jsonb_typeof(x) = 'object'
     AND (x->>'event_time')::timestamptz >= @from AND (x->>'event_time')::timestamptz < @to
)
INSERT INTO iga_gov_metrics_hourly (workspace_id, hour,
  posture_removed, posture_excluded_routes_remain, posture_excluded_routes_unknown, posture_pending,
  changes_newly_excluded, changes_newly_unexcluded, roles_right_sized, roles_eligible,
  approval_p50_seconds, approval_p95_seconds, approvals_pending, apply_to_verified_p95_seconds,
  unexpected_failures, undos, computed_at)
SELECT CAST(@ws AS uuid), CAST(@from AS timestamptz),
  (SELECT count(*) FROM iga_m_posture WHERE outcome = 'removed'),
  (SELECT count(*) FROM iga_m_posture WHERE outcome = 'excluded_routes_remain'),
  (SELECT count(*) FROM iga_m_posture WHERE outcome = 'excluded_routes_unknown'),
  (SELECT count(*) FROM iga_m_posture WHERE outcome = 'pending'),
  (SELECT count(*) FROM iga_m_changes WHERE change = 'newly_excluded'),
  (SELECT count(*) FROM iga_m_changes WHERE change = 'newly_unexcluded'),
  (SELECT count(DISTINCT role_id) FROM iga_m_posture WHERE outcome = 'removed'),
  (SELECT count(*) FROM iga_m_eligible),
  (SELECT round(percentile_cont(0.5) WITHIN GROUP (ORDER BY secs))::int FROM iga_m_approvals),
  (SELECT round(percentile_cont(0.95) WITHIN GROUP (ORDER BY secs))::int FROM iga_m_approvals),
  (SELECT count(*) FROM iga_gov_policy_version pv WHERE pv.workspace_id = @ws AND pv.status = 'in_review'),
  (SELECT round(percentile_cont(0.95) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (verified_at - applied_at))))::int
     FROM iga_m_verified WHERE applied_at IS NOT NULL),
  (SELECT count(*) FROM iga_m_failures),
  (SELECT count(*) FROM iga_m_verified WHERE kind = 'undo'),
  CAST(@computed AS timestamptz)
ON CONFLICT (workspace_id, hour) DO UPDATE SET
  posture_removed = EXCLUDED.posture_removed,
  posture_excluded_routes_remain = EXCLUDED.posture_excluded_routes_remain,
  posture_excluded_routes_unknown = EXCLUDED.posture_excluded_routes_unknown,
  posture_pending = EXCLUDED.posture_pending,
  changes_newly_excluded = EXCLUDED.changes_newly_excluded,
  changes_newly_unexcluded = EXCLUDED.changes_newly_unexcluded,
  roles_right_sized = EXCLUDED.roles_right_sized,
  roles_eligible = EXCLUDED.roles_eligible,
  approval_p50_seconds = EXCLUDED.approval_p50_seconds,
  approval_p95_seconds = EXCLUDED.approval_p95_seconds,
  approvals_pending = EXCLUDED.approvals_pending,
  apply_to_verified_p95_seconds = EXCLUDED.apply_to_verified_p95_seconds,
  unexpected_failures = EXCLUDED.unexpected_failures,
  undos = EXCLUDED.undos,
  computed_at = EXCLUDED.computed_at
RETURNING *`

// RollupTx computes and upserts the row of (ws, hour) in tx. hour must be
// aligned to the hour (UTC).
func (m *GovMetrics) RollupTx(tx *gorm.DB, ws uuid.UUID, hour time.Time) (*models.IGAGovMetricsHourly, error) {
	hour = hour.UTC()
	if !hour.Equal(hour.Truncate(time.Hour)) {
		return nil, fmt.Errorf("metrics hour %s is not aligned to the hour", hour.Format(time.RFC3339Nano))
	}
	// M9: the CHECK compares date_trunc in the session zone.
	if err := tx.Exec(`SET LOCAL TIME ZONE 'UTC'`).Error; err != nil {
		return nil, err
	}
	var row models.IGAGovMetricsHourly
	if err := tx.Raw(govMetricsRollupSQL, map[string]any{"ws": ws, "from": hour, "to": hour.Add(time.Hour),
		"computed": m.now().UTC()}).Scan(&row).Error; err != nil {
		return nil, fmt.Errorf("metrics rollup %s %s: %w", ws, hour.Format(time.RFC3339), err)
	}
	return &row, nil
}

// Rollup runs RollupTx in its own transaction.
func (m *GovMetrics) Rollup(ctx context.Context, ws uuid.UUID, hour time.Time) (*models.IGAGovMetricsHourly, error) {
	var out *models.IGAGovMetricsHourly
	err := m.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		out, err = m.RollupTx(tx, ws, hour)
		return err
	})
	return out, err
}

// RollupHandler is the metrics_rollup job: the hour comes from its dedupe
// key. An hour that has not ended yet is handed back until it has (its
// changes are not complete); a malformed key is abandoned.
func (m *GovMetrics) RollupHandler(ctx context.Context, run *PolicyJobRun) error {
	hour, err := ParseGovMetricsHour(run.Job.DedupeKey)
	if err != nil {
		return PolicyJobAbandon(err.Error())
	}
	if end := hour.Add(time.Hour); m.now().Before(end) {
		return PolicyJobRetryLater(end.Sub(m.now())+time.Second, "the hour has not ended")
	}
	return run.InTx(ctx, func(tx *gorm.DB) error {
		_, err := m.RollupTx(tx, run.Job.WorkspaceID, hour)
		return err
	})
}

// dueMetricsRollups lists, for the hour that just ended, every workspace
// with a Phase 3 policy and no metrics_rollup job for that hour yet (M3,
// M10).
func dueMetricsRollups(ctx context.Context, db *gorm.DB, now time.Time) ([]ScheduledPolicyJob, error) {
	hour := now.UTC().Truncate(time.Hour).Add(-time.Hour)
	key := GovMetricsDedupeKey(hour)
	var wss []uuid.UUID
	if err := db.Raw(`SELECT DISTINCT p.workspace_id FROM iga_gov_policy p
		WHERE NOT EXISTS (SELECT 1 FROM iga_gov_job j WHERE j.workspace_id = p.workspace_id AND j.kind = ? AND j.dedupe_key = ?)`,
		repositories.GovJobMetricsRollup, key).Scan(&wss).Error; err != nil {
		return nil, err
	}
	out := make([]ScheduledPolicyJob, 0, len(wss))
	for _, ws := range wss {
		out = append(out, ScheduledPolicyJob{WorkspaceID: ws, DedupeKey: key, Once: true})
	}
	return out, nil
}

// GovMetricsSchedule is metrics_rollup's schedule: the hour that just
// ended, once per workspace.
func GovMetricsSchedule() PolicyJobSchedule {
	return PolicyJobSchedule{Kind: repositories.GovJobMetricsRollup, Every: GovMetricsEvery, Due: dueMetricsRollups}
}

// RegisterMetricsJobs installs metrics_rollup and its hourly schedule on w.
func RegisterMetricsJobs(w *PolicyJobWorker, m *GovMetrics) {
	w.Register(PolicyJobKind{Kind: repositories.GovJobMetricsRollup, Handler: m.RollupHandler,
		Backoff: func(n int) time.Duration { return time.Duration(n) * time.Minute }})
	w.Scheduler().Add(GovMetricsSchedule())
}

/* --------------------------------- reads ---------------------------------- */

// GovMetricsRow is one hourly row as the API returns it.
type GovMetricsRow struct {
	Hour                         time.Time `json:"hour"`
	PostureAsOf                  time.Time `json:"posture_as_of"`
	PostureRemoved               int       `json:"posture_removed"`
	PostureExcludedRoutesRemain  int       `json:"posture_excluded_routes_remain"`
	PostureExcludedRoutesUnknown int       `json:"posture_excluded_routes_unknown"`
	PosturePending               int       `json:"posture_pending"`
	ChangesNewlyExcluded         int       `json:"changes_newly_excluded"`
	ChangesNewlyUnexcluded       int       `json:"changes_newly_unexcluded"`
	RolesRightSized              int       `json:"roles_right_sized"`
	RolesEligible                int       `json:"roles_eligible"`
	ApprovalP50Seconds           *int      `json:"approval_p50_seconds"`
	ApprovalP95Seconds           *int      `json:"approval_p95_seconds"`
	ApprovalsPending             int       `json:"approvals_pending"`
	ApplyToVerifiedP95Seconds    *int      `json:"apply_to_verified_p95_seconds"`
	UnexpectedFailures           int       `json:"unexpected_failures"`
	Undos                        int       `json:"undos"`
}

func govMetricsRow(r models.IGAGovMetricsHourly) GovMetricsRow {
	return GovMetricsRow{Hour: r.Hour.UTC(), PostureAsOf: r.ComputedAt.UTC(),
		PostureRemoved: r.PostureRemoved, PostureExcludedRoutesRemain: r.PostureExcludedRoutesRemain,
		PostureExcludedRoutesUnknown: r.PostureExcludedRoutesUnknown, PosturePending: r.PosturePending,
		ChangesNewlyExcluded: r.ChangesNewlyExcluded, ChangesNewlyUnexcluded: r.ChangesNewlyUnexcluded,
		RolesRightSized: r.RolesRightSized, RolesEligible: r.RolesEligible,
		ApprovalP50Seconds: r.ApprovalP50Seconds, ApprovalP95Seconds: r.ApprovalP95Seconds, ApprovalsPending: r.ApprovalsPending,
		ApplyToVerifiedP95Seconds: r.ApplyToVerifiedP95Seconds, UnexpectedFailures: r.UnexpectedFailures, Undos: r.Undos}
}

// GovMetricsRoute is one known remaining route of a service that is
// excluded but still reachable (named in the headline, A43).
type GovMetricsRoute struct {
	AccountID string         `json:"account_id"`
	RoleID    string         `json:"role_id"`
	RoleName  string         `json:"role_name"`
	Service   string         `json:"service"`
	Routes    []igagov.Route `json:"routes"`
	Text      string         `json:"text"`
}

// GovMetricsSummary is the range's headline (meta.summary). Posture and
// role counts are the LATEST row's (as of its posture_as_of); changes are
// summed over every row in the range. Percentiles are per hour and are not
// aggregated across hours (the rows carry them).
type GovMetricsSummary struct {
	From         time.Time  `json:"from"`
	To           time.Time  `json:"to"`
	HoursInRange int        `json:"hours_in_range"`
	HoursWithRow int        `json:"hours_with_row"`
	HoursMissing int        `json:"hours_missing"`
	LatestHour   *time.Time `json:"latest_hour"`
	PostureAsOf  *time.Time `json:"posture_as_of"`

	Removed               int `json:"removed"`
	ExcludedRoutesRemain  int `json:"excluded_routes_remain"`
	ExcludedRoutesUnknown int `json:"excluded_routes_unknown"`
	Pending               int `json:"pending"`
	RolesRightSized       int `json:"roles_right_sized"`
	RolesEligible         int `json:"roles_eligible"`
	ApprovalsPending      int `json:"approvals_pending"`

	NewlyExcluded      int `json:"newly_excluded"`
	NewlyUnexcluded    int `json:"newly_unexcluded"`
	NetExcluded        int `json:"net_excluded"`
	Undos              int `json:"undos"`
	UnexpectedFailures int `json:"unexpected_failures"`

	// CurrentRoutesRemaining names the routes of every service that is
	// excluded with a known remaining route NOW (read from the current
	// posture at request time; at most 50, with the total).
	CurrentRoutesRemaining      []GovMetricsRoute `json:"current_routes_remaining"`
	CurrentRoutesRemainingTotal int               `json:"current_routes_remaining_total"`
	CurrentAsOf                 time.Time         `json:"current_as_of"`

	Headline []string `json:"headline"`
}

// GovMetricsPage is GET /metrics' answer.
type GovMetricsPage struct {
	Rows       []GovMetricsRow
	NextCursor *string
	Summary    GovMetricsSummary
}

// GovMetricsDefaultRange is the range GET /metrics reads without from/to.
const GovMetricsDefaultRange = 24 * time.Hour

// ParseGovMetricsRange reads ?from&to (RFC 3339); defaults: to = now, from
// = to - 24h. from must be before to.
func ParseGovMetricsRange(from, to string, now time.Time) (time.Time, time.Time, error) {
	t := now.UTC()
	if to != "" {
		x, err := time.Parse(time.RFC3339Nano, to)
		if err != nil {
			return time.Time{}, time.Time{}, GovBadParam("to", "to must be an RFC 3339 time.")
		}
		t = x.UTC()
	}
	f := t.Add(-GovMetricsDefaultRange)
	if from != "" {
		x, err := time.Parse(time.RFC3339Nano, from)
		if err != nil {
			return time.Time{}, time.Time{}, GovBadParam("from", "from must be an RFC 3339 time.")
		}
		f = x.UTC()
	}
	if !f.Before(t) {
		return time.Time{}, time.Time{}, GovBadParam("from", "from must be before to.")
	}
	return f, t, nil
}

const govMetricsRoutesMax = 50

// List is GET /metrics: the workspace's hourly rows whose hour starts in
// [from, to), oldest first, cursor-paged (limit <= 200), with the range's
// summary in every page.
func (m *GovMetrics) List(ctx context.Context, ws uuid.UUID, from, to time.Time, cursor string, limit int) (*GovMetricsPage, error) {
	if limit <= 0 || limit > MaxGovPage {
		limit = MaxGovPage
	}
	from, to = from.UTC(), to.UTC()
	db := m.db.WithContext(ctx)
	rd := NewGovReader(m.db, m.key)
	want := govCursor{Route: "metrics", WS: ws.String(), Q: from.Format(time.RFC3339Nano) + "|" + to.Format(time.RFC3339Nano)}
	q := db.Where("workspace_id = ? AND hour >= ? AND hour < ?", ws, from, to)
	if cursor != "" {
		after, err := rd.open(cursor, want)
		if err != nil {
			return nil, err
		}
		at, err := time.Parse(time.RFC3339, after)
		if err != nil {
			return nil, govErr(http.StatusBadRequest, "cursor_invalid", "The cursor is not valid for this list; restart it.", nil)
		}
		q = q.Where("hour > ?", at)
	}
	var rows []models.IGAGovMetricsHourly
	if err := q.Order("hour").Limit(limit + 1).Find(&rows).Error; err != nil {
		return nil, err
	}
	page := &GovMetricsPage{Rows: make([]GovMetricsRow, 0, len(rows))}
	if len(rows) > limit {
		rows = rows[:limit]
		c := rd.sign(govCursor{Route: want.Route, WS: want.WS, Q: want.Q, After: rows[len(rows)-1].Hour.UTC().Format(time.RFC3339)})
		page.NextCursor = &c
	}
	for _, r := range rows {
		page.Rows = append(page.Rows, govMetricsRow(r))
	}
	s, err := m.summary(db, ws, from, to)
	if err != nil {
		return nil, err
	}
	page.Summary = *s
	return page, nil
}

// hoursIn counts the aligned hours that start in [from, to).
func hoursIn(from, to time.Time) int {
	first := from.Truncate(time.Hour)
	if first.Before(from) {
		first = first.Add(time.Hour)
	}
	if !first.Before(to) {
		return 0
	}
	return int((to.Sub(first)-1)/time.Hour) + 1
}

func (m *GovMetrics) summary(db *gorm.DB, ws uuid.UUID, from, to time.Time) (*GovMetricsSummary, error) {
	s := &GovMetricsSummary{From: from, To: to, HoursInRange: hoursIn(from, to),
		CurrentRoutesRemaining: []GovMetricsRoute{}, Headline: []string{}}
	var agg struct {
		N                  int
		NewlyExcluded      int
		NewlyUnexcluded    int
		Undos              int
		UnexpectedFailures int
	}
	if err := db.Raw(`SELECT count(*) AS n, COALESCE(sum(changes_newly_excluded),0) AS newly_excluded,
		COALESCE(sum(changes_newly_unexcluded),0) AS newly_unexcluded, COALESCE(sum(undos),0) AS undos,
		COALESCE(sum(unexpected_failures),0) AS unexpected_failures
		FROM iga_gov_metrics_hourly WHERE workspace_id = ? AND hour >= ? AND hour < ?`, ws, from, to).Scan(&agg).Error; err != nil {
		return nil, err
	}
	s.HoursWithRow, s.HoursMissing = agg.N, s.HoursInRange-agg.N
	if s.HoursMissing < 0 {
		s.HoursMissing = 0
	}
	s.NewlyExcluded, s.NewlyUnexcluded, s.Undos, s.UnexpectedFailures = agg.NewlyExcluded, agg.NewlyUnexcluded, agg.Undos, agg.UnexpectedFailures
	s.NetExcluded = s.NewlyExcluded - s.NewlyUnexcluded
	var latest []models.IGAGovMetricsHourly
	if err := db.Where("workspace_id = ? AND hour >= ? AND hour < ?", ws, from, to).Order("hour DESC").Limit(1).Find(&latest).Error; err != nil {
		return nil, err
	}
	if len(latest) == 1 {
		l := latest[0]
		h, a := l.Hour.UTC(), l.ComputedAt.UTC()
		s.LatestHour, s.PostureAsOf = &h, &a
		s.Removed, s.ExcludedRoutesRemain, s.ExcludedRoutesUnknown, s.Pending = l.PostureRemoved, l.PostureExcludedRoutesRemain,
			l.PostureExcludedRoutesUnknown, l.PosturePending
		s.RolesRightSized, s.RolesEligible, s.ApprovalsPending = l.RolesRightSized, l.RolesEligible, l.ApprovalsPending
	}
	// The routes named now (current posture, live controls).
	var rr []struct {
		AccountID string
		RoleID    string
		RoleArn   string
		Service   string
		Routes    json.RawMessage
	}
	if err := db.Raw(`SELECT sp.account_id, sp.role_id, c.role_arn, sp.service, sp.routes
		FROM iga_gov_service_posture sp
		JOIN iga_gov_control c ON c.workspace_id = sp.workspace_id AND c.id = sp.control_id
		WHERE sp.workspace_id = ? AND c.state <> 'removed' AND sp.outcome = 'excluded_routes_remain'
		ORDER BY sp.account_id, sp.role_id, sp.service`, ws).Scan(&rr).Error; err != nil {
		return nil, err
	}
	s.CurrentAsOf = m.now().UTC()
	s.CurrentRoutesRemainingTotal = len(rr)
	for i, r := range rr {
		if i >= govMetricsRoutesMax {
			break
		}
		var routes []igagov.Route
		_ = json.Unmarshal(r.Routes, &routes)
		known := make([]igagov.Route, 0, len(routes))
		for _, x := range routes {
			if x.Effect == igagov.RouteEffectBypassKnown {
				known = append(known, x)
			}
		}
		name := roleNameOf(r.RoleArn)
		s.CurrentRoutesRemaining = append(s.CurrentRoutesRemaining, GovMetricsRoute{AccountID: r.AccountID, RoleID: r.RoleID,
			RoleName: name, Service: r.Service, Routes: known, Text: routeRemainText(r.Service, name, known)})
	}
	s.Headline = metricsHeadline(s)
	return s, nil
}

func roleNameOf(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 {
		return arn[i+1:]
	}
	return arn
}

// govFormNoun names a resource-policy form in prose ("the queue policy of
// refunds").
var govFormNoun = map[string]string{
	"sqs_queue": "queue", "sns_topic": "topic", "s3_bucket": "bucket", "kms_key": "key", "lambda_function": "function",
	"ecr_repository": "repository", "secretsmanager_secret": "secret",
}

func resourceNameOf(arn string) string {
	if i := strings.LastIndexAny(arn, ":/"); i >= 0 && i < len(arn)-1 {
		return arn[i+1:]
	}
	return arn
}

// routeRemainText is §8.7's wording for excluded_routes_remain: excluded
// from the role's IAM permissions, still reachable through the named
// resource policies. Never "removed".
func routeRemainText(service, role string, routes []igagov.Route) string {
	var via []string
	seen := map[string]bool{}
	for _, r := range routes {
		noun := govFormNoun[r.Form]
		if noun == "" {
			noun = strings.ReplaceAll(r.Form, "_", " ")
		}
		v := "the " + noun + " policy of " + resourceNameOf(r.Resource)
		if !seen[v] {
			seen[v] = true
			via = append(via, v)
		}
	}
	who := "the role's"
	if role != "" {
		who = role + "'s"
	}
	if len(via) == 0 {
		return fmt.Sprintf("%s excluded from %s IAM permissions; still reachable through a resource policy", service, who)
	}
	return fmt.Sprintf("%s excluded from %s IAM permissions; still reachable through %s", service, who, strings.Join(via, " and "))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// metricsHeadline is the honest wording (§8.7, §8.12): "removed" counts only
// established removals; an exclusion with a remaining or unknown route is
// said as such, never as removed; reversed exclusions are subtracted and
// never called "access restored".
func metricsHeadline(s *GovMetricsSummary) []string {
	var out []string
	if s.LatestHour == nil {
		out = append(out, "No metrics recorded in this range.")
	} else {
		out = append(out, plural(s.Removed, "service removed", "services removed")+
			" (no known route remains)")
		if s.ExcludedRoutesRemain > 0 {
			out = append(out, plural(s.ExcludedRoutesRemain, "service", "services")+
				" excluded from IAM permissions but still reachable through a resource policy; not counted as removed")
		}
		if s.ExcludedRoutesUnknown > 0 {
			out = append(out, plural(s.ExcludedRoutesUnknown, "service", "services")+
				" excluded from IAM permissions; access through resource policies not analysed; not counted as removed")
		}
		if s.Pending > 0 {
			out = append(out, plural(s.Pending, "service", "services")+" still applying")
		}
		out = append(out, fmt.Sprintf("%d of %d eligible roles right-sized", s.RolesRightSized, s.RolesEligible))
	}
	if s.NewlyExcluded > 0 || s.NewlyUnexcluded > 0 {
		line := fmt.Sprintf("In this range: %s, %s (net %+d)", plural(s.NewlyExcluded, "exclusion verified", "exclusions verified"),
			plural(s.NewlyUnexcluded, "exclusion reversed", "exclusions reversed"), s.NetExcluded)
		if s.Undos > 0 {
			line += "; " + plural(s.Undos, "undo", "undos") + ": AuthSec's change was undone; other controls may still restrict these roles"
		}
		out = append(out, line)
	}
	if s.HoursMissing > 0 {
		out = append(out, plural(s.HoursMissing, "hour has", "hours have")+" no metrics row (not counted as zero)")
	}
	for _, r := range s.CurrentRoutesRemaining {
		out = append(out, r.Text)
	}
	return out
}
