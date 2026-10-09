package services

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// PolicyJobScheduler enqueues §8.1's periodic jobs.
//
// There is no leader: every worker replica runs it on its loop tick, and the
// database decides. A periodic subject is enqueued with EnqueuePeriodicTx
// (nothing open for its dedupe key, nothing completed within the interval), a
// one-shot subject with EnqueueOnceTx (no job with its key ever), so N
// replicas ticking together still produce one job per subject per interval.
//
// Each schedule names a kind, an interval and a Due query listing the
// subjects. The built-in schedules (DefaultPolicyJobSchedules) are the ones
// §8.1 drives from state this schema already has; a later task adds its own
// with Add (prune_evidence is added by RegisterPruneEvidenceJob; verify_binding belongs to T3.09, whose
// binding table an IGA file may not name; metrics_rollup is added by
// RegisterMetricsJobs, T3.18).
type PolicyJobScheduler struct {
	db   *gorm.DB
	jobs repositories.IGAGovJobRepository

	mu        sync.Mutex
	schedules []PolicyJobSchedule
	lastRun   map[string]time.Time
	// Every is how often the Due queries run at most; default 1 minute.
	Every time.Duration
}

// PolicyJobSchedule is one periodic source.
type PolicyJobSchedule struct {
	// Name identifies the schedule (defaults to Kind).
	Name string
	Kind string
	// Every is the default interval between runs for one subject.
	Every time.Duration
	// Due lists the subjects to run now.
	Due func(ctx context.Context, db *gorm.DB, now time.Time) ([]ScheduledPolicyJob, error)
}

// ScheduledPolicyJob is one subject a schedule wants run.
type ScheduledPolicyJob struct {
	WorkspaceID uuid.UUID
	SubjectID   *uuid.UUID
	Rev         *int64
	DedupeKey   string
	// RunAfter delays the job (zero: now).
	RunAfter time.Time
	// Every overrides the schedule's interval for this subject (drift_check
	// runs every 5 minutes for 24 h after an unknown attempt, §8.1).
	Every time.Duration
	// Once enqueues the key at most once ever (refresh_activity's
	// connector:<id>:after:<ts>), not periodically.
	Once bool
}

// NewPolicyJobScheduler builds a scheduler with DefaultPolicyJobSchedules.
func NewPolicyJobScheduler(db *gorm.DB) *PolicyJobScheduler {
	s := &PolicyJobScheduler{db: db, jobs: repositories.NewIGAGovJobRepository(db), lastRun: map[string]time.Time{}}
	for _, sc := range DefaultPolicyJobSchedules() {
		s.Add(sc)
	}
	return s
}

// Add registers a schedule; a schedule with the same name replaces it.
func (s *PolicyJobScheduler) Add(sc PolicyJobSchedule) {
	if sc.Name == "" {
		sc.Name = sc.Kind
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.schedules {
		if s.schedules[i].Name == sc.Name {
			s.schedules[i] = sc
			return
		}
	}
	s.schedules = append(s.schedules, sc)
}

// ScheduleNames lists the registered schedules' names.
func (s *PolicyJobScheduler) ScheduleNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.schedules))
	for _, sc := range s.schedules {
		out = append(out, sc.Name)
	}
	return out
}

// Tick runs every schedule whose Due query is due, and enqueues its subjects.
// One schedule's failure does not stop the others; the first error is
// returned after all ran.
func (s *PolicyJobScheduler) Tick(ctx context.Context, now time.Time) error {
	every := s.Every
	if every <= 0 {
		every = time.Minute
	}
	s.mu.Lock()
	var due []PolicyJobSchedule
	for _, sc := range s.schedules {
		if last, ok := s.lastRun[sc.Name]; ok && now.Sub(last) < every {
			continue
		}
		s.lastRun[sc.Name] = now
		due = append(due, sc)
	}
	s.mu.Unlock()

	var first error
	for _, sc := range due {
		n, err := s.runSchedule(ctx, sc, now)
		if err != nil {
			log.Printf("[policy-scheduler] %s: %v", sc.Name, err)
			if first == nil {
				first = fmt.Errorf("%s: %w", sc.Name, err)
			}
			continue
		}
		if n > 0 {
			log.Printf("[policy-scheduler] %s: %d job(s) enqueued", sc.Name, n)
		}
	}
	return first
}

// RunSchedulesNow runs every schedule regardless of the Due throttle and
// reports how many jobs were enqueued (tests).
func (s *PolicyJobScheduler) RunSchedulesNow(ctx context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	all := append([]PolicyJobSchedule(nil), s.schedules...)
	s.mu.Unlock()
	total := 0
	for _, sc := range all {
		n, err := s.runSchedule(ctx, sc, now)
		if err != nil {
			return total, fmt.Errorf("%s: %w", sc.Name, err)
		}
		total += n
	}
	return total, nil
}

func (s *PolicyJobScheduler) runSchedule(ctx context.Context, sc PolicyJobSchedule, now time.Time) (int, error) {
	items, err := sc.Due(ctx, s.db.WithContext(ctx), now)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, it := range items {
		job := &models.IGAGovJob{WorkspaceID: it.WorkspaceID, Kind: sc.Kind, SubjectID: it.SubjectID, Rev: it.Rev,
			DedupeKey: it.DedupeKey, RunAfter: it.RunAfter}
		var created bool
		switch {
		case it.Once:
			created, err = s.jobs.EnqueueOnceTx(s.db.WithContext(ctx), job)
		default:
			ev := it.Every
			if ev <= 0 {
				ev = sc.Every
			}
			created, err = s.jobs.EnqueuePeriodicTx(s.db.WithContext(ctx), job, ev)
		}
		if err != nil {
			return n, err
		}
		if created {
			n++
		}
	}
	return n, nil
}

// §8.1 intervals.
const (
	DriftCheckEvery          = 10 * time.Minute
	DriftCheckEveryAfterLate = 5 * time.Minute
	LateMutationWatch        = 24 * time.Hour
	IaCSyncEvery             = 10 * time.Minute
)

// DefaultPolicyJobSchedules are the periodic jobs §8.1 drives from state
// 049-053 already hold:
//
//   - drift_check: every 10 min per deployment in `verified`; every 5 min for
//     24 h after an `unknown` attempt on the deployment's control (§8.1
//     step 5). Dedupe deployment:<id>.
//   - iac_sync: every 10 min per open IaC change (state opening, open,
//     changed_after_review or merged -- DECISION: `merged` is still synced,
//     because the apply after merge is followed through it, §8.11). Dedupe
//     iac:<id>.
//   - refresh_activity: once per (connector, observe_evidence_required_after)
//     of every rollout in `observe`, run at that time (§2.6: the fresh report
//     must be generated at or after it). DECISION: the scheduler does not
//     decide whether a scan is already scheduled to produce the report; the
//     handler (T3.15) does, and completes without queueing one when it is.
//     Dedupe connector:<id>:after:<RFC 3339 UTC>.
func DefaultPolicyJobSchedules() []PolicyJobSchedule {
	return []PolicyJobSchedule{
		{Kind: repositories.GovJobDriftCheck, Every: DriftCheckEvery, Due: dueDriftChecks},
		{Kind: repositories.GovJobIaCSync, Every: IaCSyncEvery, Due: dueIaCSyncs},
		{Kind: repositories.GovJobRefreshActivity, Every: time.Hour, Due: dueActivityRefreshes},
	}
}

func dueDriftChecks(ctx context.Context, db *gorm.DB, now time.Time) ([]ScheduledPolicyJob, error) {
	var rows []struct {
		WorkspaceID uuid.UUID
		ID          uuid.UUID
		LateWatch   bool
	}
	err := db.Raw(`
		SELECT d.workspace_id, d.id,
		       EXISTS (SELECT 1 FROM iga_gov_attempt a
		                 JOIN iga_gov_deployment ad ON ad.workspace_id = a.workspace_id AND ad.id = a.deployment_id
		                WHERE ad.workspace_id = d.workspace_id AND ad.control_id = d.control_id
		                  AND a.status = 'unknown' AND a.dispatched_at > ?) AS late_watch
		  FROM iga_gov_deployment d
		 WHERE d.state = 'verified'`, now.Add(-LateMutationWatch)).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]ScheduledPolicyJob, 0, len(rows))
	for _, r := range rows {
		id := r.ID
		it := ScheduledPolicyJob{WorkspaceID: r.WorkspaceID, SubjectID: &id, DedupeKey: "deployment:" + id.String()}
		if r.LateWatch {
			it.Every = DriftCheckEveryAfterLate
		}
		out = append(out, it)
	}
	return out, nil
}

func dueIaCSyncs(ctx context.Context, db *gorm.DB, now time.Time) ([]ScheduledPolicyJob, error) {
	var rows []struct {
		WorkspaceID uuid.UUID
		ID          uuid.UUID
	}
	// T3.17: plus every awaiting_apply deployment without an open change
	// (J1 export, or a J2 change already in the source), subject = the
	// deployment (DECISION in iga_gov_iac_delivery.go).
	err := db.Raw(`SELECT workspace_id, id FROM iga_gov_iac_change
		WHERE state IN ('opening','open','changed_after_review','merged')
		UNION ALL
		SELECT d.workspace_id, d.id FROM iga_gov_deployment d
		 WHERE d.state = 'awaiting_apply'
		   AND NOT EXISTS (SELECT 1 FROM iga_gov_iac_change c WHERE c.workspace_id = d.workspace_id AND c.deployment_id = d.id
		                     AND c.state IN ('opening','open','changed_after_review','merged'))`).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]ScheduledPolicyJob, 0, len(rows))
	for _, r := range rows {
		id := r.ID
		out = append(out, ScheduledPolicyJob{WorkspaceID: r.WorkspaceID, SubjectID: &id, DedupeKey: "iac:" + id.String()})
	}
	return out, nil
}

func dueActivityRefreshes(ctx context.Context, db *gorm.DB, now time.Time) ([]ScheduledPolicyJob, error) {
	var rows []struct {
		WorkspaceID uuid.UUID
		ConnectorID uuid.UUID
		After       time.Time
	}
	err := db.Raw(`
		SELECT DISTINCT r.workspace_id, c.connector_id, r.observe_evidence_required_after AS after
		  FROM iga_gov_rollout r
		  JOIN iga_gov_target t ON t.workspace_id = r.workspace_id AND t.version_id = r.version_id
		  JOIN iga_gov_control c ON c.workspace_id = t.workspace_id AND c.id = t.control_id
		 WHERE r.stage = 'observe' AND r.observe_evidence_required_after IS NOT NULL`).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]ScheduledPolicyJob, 0, len(rows))
	for _, r := range rows {
		cid := r.ConnectorID
		out = append(out, ScheduledPolicyJob{
			WorkspaceID: r.WorkspaceID, SubjectID: &cid, Once: true, RunAfter: r.After,
			DedupeKey: "connector:" + cid.String() + ":after:" + r.After.UTC().Format(time.RFC3339),
		})
	}
	return out, nil
}
