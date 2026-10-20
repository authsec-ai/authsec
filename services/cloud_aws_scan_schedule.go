package services

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"os"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/scanslot"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Automatic AWS rescans.
//
// A connector with an enabled schedule is rescanned on its own: the scheduler
// queues the same scan "Scan now" queues (a cloud_scan_run with trigger
// "scheduled") and the existing scan worker runs it. Nothing here touches AWS,
// reads a secret, or changes what a scan reads: it decides WHEN, not WHAT.
//
// See .claude/specs/SPEC-aws-scheduled-scans.md.

// ScheduledScansEnv switches the scheduler on. Default off, so the feature
// ships dark.
const ScheduledScansEnv = "AUTHSEC_AWS_SCHEDULED_SCANS"

// ScheduledScansEnabled reports whether the scheduler is switched on.
func ScheduledScansEnabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(ScheduledScansEnv)), "true")
}

const (
	schedTick = time.Minute
	// schedBatch bounds how many due schedules one tick takes. After an outage
	// every overdue schedule is due at once; this spreads them over ticks.
	schedBatch = 20
	// schedClaimLease is how long a claimed schedule stays out of reach of
	// other instances while this one enqueues. A crash costs this, not an interval.
	schedClaimLease = 5 * time.Minute
	// schedPauseAfter is how many scheduled runs in a row must have failed
	// before the schedule pauses itself.
	schedPauseAfter = 3
	schedMaxJitter  = 30 * time.Minute
	// schedLiveRetry is how soon a slot is tried again when a scan (a manual
	// one, say) was already running at its due time. Without it the slot would
	// be lost and the next scan a whole interval away: a week on weekly.
	schedLiveRetry = time.Hour
	schedActor      = "system:scheduler"
)

// ErrScheduleInterval is an interval outside the allowed range.
var ErrScheduleInterval = fmt.Errorf("interval_minutes must be %d (daily) or %d (weekly)",
	models.ScanScheduleDailyMinutes, models.ScanScheduleWeeklyMinutes)

/* ------------------------------- pure helpers ------------------------------ */

// scheduleJitter is a stable per-connector offset in [0, min(interval/10, 30m)),
// so connectors spread out and each keeps its slot.
func scheduleJitter(connectorID uuid.UUID, interval time.Duration) time.Duration {
	window := interval / 10
	if window > schedMaxJitter {
		window = schedMaxJitter
	}
	secs := uint64(window / time.Second)
	if secs == 0 {
		return 0
	}
	h := fnv.New64a()
	_, _ = h.Write(connectorID[:])
	return time.Duration(h.Sum64()%secs) * time.Second
}

// nextDueAfter is the slot after one that was due at prevDue and is being
// served at now. A slot served on time anchors on prevDue, so the schedule does
// not drift later by the scan duration. A slot served a whole interval late
// (after an outage) starts over from now, so a backlog is not replayed.
func nextDueAfter(prevDue, now time.Time, interval, jitter time.Duration) time.Time {
	if !prevDue.IsZero() && !prevDue.After(now) && now.Sub(prevDue) < interval {
		return prevDue.Add(interval)
	}
	return now.Add(interval + jitter)
}

// shouldPause reports whether the newest scheduled runs (newest first) all
// failed: schedPauseAfter of them, every one failed or abandoned. A run that is
// published, queued or running means the schedule is working.
func shouldPause(runs []models.CloudScanRun) bool {
	if len(runs) < schedPauseAfter {
		return false
	}
	for _, r := range runs[:schedPauseAfter] {
		if r.Status != models.CloudScanRunFailed && r.Status != models.CloudScanRunAbandoned {
			return false
		}
	}
	return true
}

func pauseReason(newest models.CloudScanRun) string {
	msg := strings.TrimSpace(newest.LastError)
	if len(msg) > 200 {
		msg = msg[:200]
	}
	if msg == "" {
		return "repeated_failures"
	}
	return "repeated_failures: " + msg
}

func auditSchedule(workspaceID, connectorID uuid.UUID, action string, after map[string]any) {
	if config.AuditLogger == nil {
		return
	}
	config.AuditLogger.LogAdminAction(
		uuid.NewString(), workspaceID.String(), schedActor, action,
		"cloud_connector", connectorID.String(),
		"SCHEDULER", "aws-scan-scheduler", "", "authsec-scheduler",
		200, 0, nil, after, "",
	)
}

// specOf turns a schedule's chosen time into a scanslot.Spec. ok is false when
// no time was chosen, or the stored zone cannot be loaded; either way the
// caller falls back to "one interval later", so a bad row never stops scans.
func specOf(intervalMinutes int, tod *int, tz string, dow *int) (scanslot.Spec, bool) {
	if tod == nil {
		return scanslot.Spec{}, false
	}
	loc, err := scanslot.LoadLocation(tz)
	if err != nil {
		log.Printf("[aws-sched] stage=timing outcome=bad_timezone tz=%q err=%v", tz, err)
		return scanslot.Spec{}, false
	}
	spec := scanslot.Spec{
		Interval:  time.Duration(intervalMinutes) * time.Minute,
		TimeOfDay: *tod,
		Location:  loc,
	}
	if dow != nil {
		spec.Weekday = time.Weekday(*dow)
	}
	return spec, true
}

func intPtrEq(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

/* -------------------------------- scheduler -------------------------------- */

// AWSScanScheduler queues scheduled scans. Safe to run on every backend
// replica: ClaimDue hands each due schedule to exactly one of them.
type AWSScanScheduler struct {
	db    *gorm.DB
	sched repositories.CloudScanScheduleRepository
	runs  repositories.CloudScanRunRepository
	now   func() time.Time
	tick  time.Duration
}

func NewAWSScanScheduler(db *gorm.DB) *AWSScanScheduler {
	return &AWSScanScheduler{
		db:    db,
		sched: repositories.NewCloudScanScheduleRepository(db),
		runs:  repositories.NewCloudScanRunRepository(db),
		now:   time.Now,
		tick:  schedTick,
	}
}

// WithClock replaces time.Now, so a test can move through slots.
func (s *AWSScanScheduler) WithClock(f func() time.Time) *AWSScanScheduler { s.now = f; return s }

// Run ticks until ctx ends.
func (s *AWSScanScheduler) Run(ctx context.Context) {
	log.Printf("[aws-sched] scheduler started")
	t := time.NewTicker(s.tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("[aws-sched] scheduler stopping")
			return
		case <-t.C:
			if _, err := s.RunOnce(ctx); err != nil {
				log.Printf("[aws-sched] tick failed: %v", err)
			}
		}
	}
}

// RunOnce serves every schedule that is due now (up to schedBatch). Separate
// from Run so a test drives exactly one pass.
func (s *AWSScanScheduler) RunOnce(ctx context.Context) (int, error) {
	now := s.now()
	due, err := s.sched.ClaimDue(now, schedBatch, schedClaimLease)
	if err != nil {
		return 0, fmt.Errorf("claim due schedules: %w", err)
	}
	for _, d := range due {
		s.serve(ctx, d, now)
	}
	return len(due), nil
}

// serve handles one claimed schedule. It never returns an error: a failure is
// logged and the claim lease brings the schedule back in a few minutes.
func (s *AWSScanScheduler) serve(ctx context.Context, d repositories.DueSchedule, now time.Time) {
	lg := fmt.Sprintf("connector=%s workspace=%s", d.ConnectorID, d.WorkspaceID)
	interval := time.Duration(d.IntervalMinutes) * time.Minute

	// 1. Has this schedule been failing? Judged from the runs themselves.
	var recent []models.CloudScanRun
	err := tenancy.InWorkspaceRead(ctx, s.db, d.WorkspaceID, func(tx *gorm.DB) error {
		cur, gerr := s.sched.Get(tx, d.WorkspaceID, d.ConnectorID)
		if gerr != nil {
			return gerr
		}
		recent, gerr = s.sched.RecentScheduledRuns(tx, d.WorkspaceID, d.ConnectorID, cur.StreakSince, schedPauseAfter)
		return gerr
	})
	if err != nil {
		log.Printf("[aws-sched] stage=read outcome=error %s err=%v", lg, err)
		return
	}
	if shouldPause(recent) {
		reason := pauseReason(recent[0])
		if err := tenancy.InWorkspace(ctx, s.db, d.WorkspaceID, func(tx *gorm.DB) error {
			return s.sched.Pause(tx, d.WorkspaceID, d.ConnectorID, reason, now)
		}); err != nil {
			log.Printf("[aws-sched] stage=pause outcome=error %s err=%v", lg, err)
			return
		}
		log.Printf("[aws-sched] ALERT paused %s reason=%q", lg, reason)
		auditSchedule(d.WorkspaceID, d.ConnectorID, "pause_scan_schedule", map[string]any{"paused_reason": reason})
		return
	}

	// 2. Move to the next slot BEFORE queueing, so a slow or repeated tick can
	//    never queue two scans for one slot.
	jit := scheduleJitter(d.ConnectorID, interval)
	next := nextDueAfter(d.PrevDueAt, now, interval, jit)
	if spec, ok := specOf(d.IntervalMinutes, d.TimeOfDayMinutes, d.Timezone, d.DayOfWeek); ok {
		// The administrator chose a time: the next slot is the next occurrence
		// of it, not one interval from now.
		next = scanslot.NextDue(spec, now, jit)
	}
	if err := tenancy.InWorkspace(ctx, s.db, d.WorkspaceID, func(tx *gorm.DB) error {
		return s.sched.Advance(tx, d.WorkspaceID, d.ConnectorID, now, next)
	}); err != nil {
		log.Printf("[aws-sched] stage=advance outcome=error %s err=%v", lg, err)
		return
	}

	// 3. Queue the scan, exactly as Scan now does.
	_, err = s.runs.Enqueue(d.WorkspaceID, d.ConnectorID, models.CloudScanTriggerScheduled)
	switch {
	case err == nil:
		log.Printf("[aws-sched] stage=enqueue outcome=queued %s next=%s", lg, next.UTC().Format(time.RFC3339))
		if merr := tenancy.InWorkspace(ctx, s.db, d.WorkspaceID, func(tx *gorm.DB) error {
			return s.sched.MarkEnqueued(tx, d.WorkspaceID, d.ConnectorID, now)
		}); merr != nil {
			log.Printf("[aws-sched] stage=mark outcome=error %s err=%v", lg, merr)
		}
		auditSchedule(d.WorkspaceID, d.ConnectorID, "scheduled_scan", map[string]any{
			"trigger": models.CloudScanTriggerScheduled, "next_due_at": next.UTC(),
		})
	case errors.Is(err, repositories.ErrScanAlreadyLive):
		// A scan is already running, so this slot has nothing to add; try again
		// soon rather than waiting out the whole interval.
		log.Printf("[aws-sched] stage=enqueue outcome=skipped_live %s retry_in=%s", lg, schedLiveRetry)
		if rerr := tenancy.InWorkspace(ctx, s.db, d.WorkspaceID, func(tx *gorm.DB) error {
			return s.sched.RetrySoon(tx, d.WorkspaceID, d.ConnectorID, now.Add(schedLiveRetry))
		}); rerr != nil {
			log.Printf("[aws-sched] stage=retry outcome=error %s err=%v", lg, rerr)
		}
	default:
		log.Printf("[aws-sched] stage=enqueue outcome=error %s err=%v", lg, err)
		retryAt := now.Add(schedClaimLease)
		if rerr := tenancy.InWorkspace(ctx, s.db, d.WorkspaceID, func(tx *gorm.DB) error {
			return s.sched.RetrySoon(tx, d.WorkspaceID, d.ConnectorID, retryAt)
		}); rerr != nil {
			log.Printf("[aws-sched] stage=retry outcome=error %s err=%v", lg, rerr)
		}
	}
}

/* ------------------------------ schedule service --------------------------- */

// ScanScheduleView is a connector's schedule as the API returns it.
type ScanScheduleView struct {
	Enabled         bool       `json:"enabled"`
	IntervalMinutes int        `json:"interval_minutes"`
	NextDueAt       *time.Time `json:"next_due_at"`
	LastEnqueuedAt  *time.Time `json:"last_enqueued_at"`
	PausedReason    string     `json:"paused_reason"`
	// TimeOfDay is the chosen time as "HH:MM" in Timezone, or null when none was
	// chosen (the schedule then runs one interval after it was turned on).
	// DayOfWeek is 0 (Sunday) to 6, set for weekly schedules with a chosen time.
	TimeOfDay *string `json:"time_of_day"`
	Timezone  string  `json:"timezone"`
	DayOfWeek *int    `json:"day_of_week"`
	// SchedulerActive is false when this deployment has the scheduler switched
	// off: the settings are kept but nothing runs on them.
	SchedulerActive bool `json:"scheduler_active"`
}

func scheduleViewOf(s *models.CloudScanSchedule) *ScanScheduleView {
	v := &ScanScheduleView{
		IntervalMinutes: models.ScanScheduleDefaultIntervalMinutes,
		Timezone:        "UTC",
		SchedulerActive: ScheduledScansEnabled(),
	}
	if s == nil {
		return v
	}
	if s.Timezone != "" {
		v.Timezone = s.Timezone
	}
	if s.TimeOfDayMinutes != nil {
		t := scanslot.FormatTimeOfDay(*s.TimeOfDayMinutes)
		v.TimeOfDay = &t
	}
	v.DayOfWeek = s.DayOfWeek
	v.Enabled = s.Enabled
	v.IntervalMinutes = s.IntervalMinutes
	v.NextDueAt = s.NextDueAt
	v.LastEnqueuedAt = s.LastEnqueuedAt
	v.PausedReason = s.PausedReason
	return v
}

// AWSScanScheduleService reads and changes a connector's schedule.
type AWSScanScheduleService struct {
	db         *gorm.DB
	onboarding *AWSOnboardingService
	sched      repositories.CloudScanScheduleRepository
	now        func() time.Time
}

func NewAWSScanScheduleService(db *gorm.DB, onboarding *AWSOnboardingService) *AWSScanScheduleService {
	return &AWSScanScheduleService{
		db: db, onboarding: onboarding,
		sched: repositories.NewCloudScanScheduleRepository(db),
		now:   time.Now,
	}
}

func (s *AWSScanScheduleService) load(ctx context.Context, ws, id uuid.UUID) (*models.CloudScanSchedule, error) {
	var cur *models.CloudScanSchedule
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		got, gerr := s.sched.Get(tx, ws, id)
		if errors.Is(gerr, repositories.ErrCloudScanScheduleNotFound) {
			return nil
		}
		cur = got
		return gerr
	})
	return cur, err
}

// Get returns the connector's schedule; a connector never scheduled reads as
// off with the default interval. A connector that is not this workspace's AWS
// connector is repositories.ErrCloudConnectorNotFound.
func (s *AWSScanScheduleService) Get(ctx context.Context, ws, id uuid.UUID) (*ScanScheduleView, error) {
	if _, err := s.onboarding.awsConnector(ws, id); err != nil {
		return nil, err
	}
	cur, err := s.load(ctx, ws, id)
	if err != nil {
		return nil, err
	}
	return scheduleViewOf(cur), nil
}

// ScheduleTiming is an optional chosen time for a schedule. A nil field keeps
// the schedule's current value.
type ScheduleTiming struct {
	TimeOfDay *string // "HH:MM" on a quarter hour
	Timezone  *string // IANA zone name, e.g. "Asia/Kolkata"
	DayOfWeek *int    // 0 = Sunday .. 6 = Saturday; weekly schedules
}

// ScheduleParamError is a rejected schedule parameter and which one it was.
type ScheduleParamError struct{ Param, Msg string }

func (e *ScheduleParamError) Error() string { return e.Msg }

// Put turns the schedule on or off and sets its interval (nil keeps the
// current one, or the default), leaving any chosen time as it is. See
// PutWithTiming.
func (s *AWSScanScheduleService) Put(
	ctx context.Context, ws, id uuid.UUID, enabled bool, intervalMinutes *int, actor string,
) (after, before *ScanScheduleView, err error) {
	return s.PutWithTiming(ctx, ws, id, enabled, intervalMinutes, nil, actor)
}

// PutWithTiming turns the schedule on or off, sets its interval (nil keeps the
// current one, or the default) and, when timing is given, its time of day,
// timezone and weekday (nil fields keep their current value). It returns the
// schedule after the change and as it was before.
//
// Turning a schedule on, resuming a paused one, or changing its interval moves
// the next scan: to the next occurrence of the chosen time when there is one,
// otherwise to one interval (plus the connector's jitter) from now. Changing
// only the chosen time of a running schedule moves the next scan the same way
// and leaves its failure history alone. It never scans immediately (Scan now
// does that).
func (s *AWSScanScheduleService) PutWithTiming(
	ctx context.Context, ws, id uuid.UUID, enabled bool, intervalMinutes *int,
	timing *ScheduleTiming, actor string,
) (after, before *ScanScheduleView, err error) {
	c, err := s.onboarding.awsConnector(ws, id)
	if err != nil {
		return nil, nil, err
	}
	if c.Status == models.CloudConnectorRevoked {
		return nil, nil, ErrAWSConnectorRevoked
	}
	if intervalMinutes != nil && !models.ScheduleIntervalAllowed(*intervalMinutes) {
		return nil, nil, ErrScheduleInterval
	}

	// Validate the chosen time before touching the database.
	var reqTod, reqDow *int
	reqTz, tzSet := "", false
	if timing != nil {
		if timing.TimeOfDay != nil {
			m, perr := scanslot.ParseTimeOfDay(*timing.TimeOfDay)
			if perr != nil {
				return nil, nil, &ScheduleParamError{Param: "time_of_day", Msg: perr.Error()}
			}
			reqTod = &m
		}
		if timing.Timezone != nil {
			if _, lerr := scanslot.LoadLocation(*timing.Timezone); lerr != nil {
				return nil, nil, &ScheduleParamError{Param: "timezone", Msg: lerr.Error()}
			}
			reqTz, tzSet = strings.TrimSpace(*timing.Timezone), true
			if reqTz == "" {
				reqTz = "UTC"
			}
		}
		if timing.DayOfWeek != nil {
			if *timing.DayOfWeek < 0 || *timing.DayOfWeek > 6 {
				return nil, nil, &ScheduleParamError{
					Param: "day_of_week", Msg: "day_of_week must be 0 (Sunday) to 6 (Saturday)"}
			}
			reqDow = timing.DayOfWeek
		}
	}

	// Read and write in one transaction with the row locked: the scheduler may
	// claim this very schedule while it is being changed, and a write built from
	// an earlier read would put the old next_due_at back over its claim.
	var paramErr error
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		cur, gerr := s.sched.GetForUpdate(tx, ws, id)
		if errors.Is(gerr, repositories.ErrCloudScanScheduleNotFound) {
			cur, gerr = nil, nil
		}
		if gerr != nil {
			return gerr
		}
		before = scheduleViewOf(cur)

		interval := models.ScanScheduleDefaultIntervalMinutes
		if cur != nil && models.ScheduleIntervalAllowed(cur.IntervalMinutes) {
			interval = cur.IntervalMinutes
		}
		if intervalMinutes != nil {
			interval = *intervalMinutes
		}

		// The chosen time: what is stored, with what was asked for on top.
		var curTod, curDow *int
		curTz := "UTC"
		if cur != nil {
			curTod, curDow = cur.TimeOfDayMinutes, cur.DayOfWeek
			if cur.Timezone != "" {
				curTz = cur.Timezone
			}
		}
		newTod, newDow, newTz := curTod, curDow, curTz
		if reqTod != nil {
			newTod = reqTod
		}
		if reqDow != nil {
			newDow = reqDow
		}
		if tzSet {
			newTz = reqTz
		}
		weekly := interval >= models.ScanScheduleWeeklyMinutes
		if !weekly {
			newDow = nil
		}
		if weekly && newTod != nil && newDow == nil {
			paramErr = &ScheduleParamError{
				Param: "day_of_week", Msg: "day_of_week is required for a weekly schedule with a chosen time"}
			return nil
		}
		timingChanged := !intPtrEq(curTod, newTod) || !intPtrEq(curDow, newDow) || curTz != newTz

		now := s.now()
		next := &models.CloudScanSchedule{
			ConnectorID: id, WorkspaceID: ws, Enabled: enabled,
			IntervalMinutes: interval, UpdatedBy: actor,
			TimeOfDayMinutes: newTod, Timezone: newTz, DayOfWeek: newDow,
		}
		if cur != nil {
			next.NextDueAt, next.LastEnqueuedAt = cur.NextDueAt, cur.LastEnqueuedAt
			next.StreakSince, next.PausedReason = cur.StreakSince, cur.PausedReason
		}
		dur := time.Duration(interval) * time.Minute
		jit := scheduleJitter(id, dur)
		firstDue := func() time.Time {
			if spec, ok := specOf(interval, newTod, newTz, newDow); ok {
				return scanslot.NextDue(spec, now, jit)
			}
			return now.Add(dur + jit)
		}
		switch {
		case !enabled:
			next.NextDueAt, next.PausedReason = nil, ""
		case cur == nil || !cur.Enabled || cur.PausedReason != "" || cur.IntervalMinutes != interval:
			due := firstDue()
			since := now
			next.NextDueAt, next.StreakSince, next.PausedReason = &due, &since, ""
		case timingChanged:
			due := firstDue()
			next.NextDueAt = &due
		}
		if uerr := s.sched.Upsert(tx, next); uerr != nil {
			return uerr
		}
		after = scheduleViewOf(next)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if paramErr != nil {
		return nil, nil, paramErr
	}
	return after, before, nil
}

// DisableForConnector turns a connector's schedule off. Called when the
// connector is revoked: re-onboarding the same account reactivates the same
// connector row, and an old schedule must not silently resume with it.
func (s *AWSScanScheduleService) DisableForConnector(ctx context.Context, ws, id uuid.UUID) error {
	return tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		return s.sched.Disable(tx, ws, id, s.now())
	})
}
