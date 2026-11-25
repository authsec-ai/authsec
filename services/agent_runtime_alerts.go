package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/agentruntime/detect"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// Agent runtime alerts (SPEC-agent-runtime-visibility.md §5.7, with review
// 2's decisions in §10: Q3 tables plus log entries, D1 without kms:Decrypt
// made by Secrets Manager or SSM, Q7 thresholds).
//
// The "agent_alerts" EventSink receives every normalised CloudTrail event of
// a connector (the scan poller and the event-stream ingest both dispatch to
// it). Per event:
//
//   - the identity is resolved through agentruntime.Resolver() (installed by
//     inference); no resolver, an unresolved identity, or one that is not an
//     AI workload, suggested agent or agent is skipped;
//   - an event already processed (by EventID, from either path) is skipped
//     (agent_alert_event_seen), so the sink is idempotent;
//   - the detections run over the identity's baseline (detect.Evaluate) in
//     event-time order, and the baseline is saved;
//   - a finding opens an alert, or extends the alert of the same (workspace,
//     identity, detection) that is not resolved and whose activity is within
//     the dedupe window (default 1 h) of the event: last_seen, event_count
//     and capped evidence references are updated instead of a new row.
//
// A new alert writes "agent_alert.opened" into iga_gov_event (Logs) and queues
// its deliveries: Slack through the governance notification outbox
// (iga_gov_notify.go, GovChannelSlack, the workspace's approvals channel)
// and every enabled SIEM endpoint (agent_runtime_alert_delivery.go). A new
// alert matched by an active suppression (agent_runtime_alert_suppression.go)
// is stored with suppressed_by set and queues no delivery; a suppression
// never matches a harmful outcome that succeeded (detect.SucceededHarm).
//
// Lifecycle (SecOps F8, migration 165): open -> acknowledged -> resolved,
// resolved -> reopened -> acknowledged | resolved. Each transition records
// its actor on the alert (acknowledged_by, resolved_by, reopened_by) and a
// row of agent_alert_transition, and writes "agent_alert.acknowledged",
// "agent_alert.resolved" or "agent_alert.reopened". A resolution carries an
// outcome code (true_positive | benign | false_positive | duplicate); a
// reopen carries a reason.
//
// The detections read the workspace's ACTIVE detection rule version
// (agent_runtime_alert_rules.go, migration 164).
//
// Everything a workspace's alerts touch runs in one transaction under
// row-level security for that workspace (tenancy.InWorkspace).
//
// DECISIONS (P2b):
//   - Events older than agentAlertMaxEventAge (7 days) teach the baseline but
//     raise no alert: a first scan reading 90 days of history must not open
//     an alert for every secret read of the last quarter. 7 days keeps a
//     weekly connector's window alertable.
//   - Backfill (lab 2026-11-05): a finding on an event older than
//     agentAlertBackfillAge (24 h) is history arriving in one batch (a scan's
//     window, a replay), not a live incident. All such findings of one batch
//     for the same (identity, detection) go into ONE alert: the first is
//     deduplicated as usual (it extends an alert within the window or opens
//     one), every later one extends that same alert whatever the gap. Recent
//     events keep the per-window dedupe.
//   - One finding per detection per event: when D6 matches twice on one
//     event (a new model during a spike) the details are joined.
//   - An acknowledged alert is still extended (the same incident); a
//     resolved one never is: the next finding opens a new alert.
//   - Severity of an extended alert rises to the highest finding seen.

// Sink and alert states.
const (
	AgentAlertSinkName = "agent_alerts"

	AgentAlertOpen         = "open"
	AgentAlertAcknowledged = "acknowledged"
	AgentAlertResolved     = "resolved"
	AgentAlertReopened     = "reopened"
)

// AgentAlertActiveStates are the states of an alert that needs attention
// (not acknowledged, not resolved).
var AgentAlertActiveStates = []string{AgentAlertOpen, AgentAlertReopened}

// Resolution outcome codes (agent_alert.outcome, required on resolve).
const (
	AgentAlertOutcomeTruePositive  = "true_positive"
	AgentAlertOutcomeBenign        = "benign"
	AgentAlertOutcomeFalsePositive = "false_positive"
	AgentAlertOutcomeDuplicate     = "duplicate"
)

// AgentAlertOutcomes lists the outcome codes.
var AgentAlertOutcomes = []string{AgentAlertOutcomeTruePositive, AgentAlertOutcomeBenign, AgentAlertOutcomeFalsePositive,
	AgentAlertOutcomeDuplicate}

// ValidAgentAlertOutcome reports whether o is an outcome code.
func ValidAgentAlertOutcome(o string) bool {
	for _, x := range AgentAlertOutcomes {
		if x == o {
			return true
		}
	}
	return false
}

// iga_gov_event names (iga_gov_event_vocabulary.go) and the notice subject.
const (
	GovEventAgentAlertOpened       = "agent_alert.opened"
	GovEventAgentAlertAcknowledged = "agent_alert.acknowledged"
	GovEventAgentAlertResolved     = "agent_alert.resolved"
	GovEventAgentAlertReopened     = "agent_alert.reopened"
	// SIEM delivery outcomes that end a delivery (not each retry).
	GovEventAgentAlertSIEMDelivered = "agent_alert.siem_delivered"
	GovEventAgentAlertSIEMFailed    = "agent_alert.siem_failed"

	GovNoticeAgentAlert = "agent_alert"
)

// Defaults and limits.
const (
	DefaultAgentAlertDedupeMinutes = 60
	DefaultAgentAlertRetentionDays = 90

	agentAlertMaxEventAge = 7 * 24 * time.Hour
	// agentAlertBackfillAge: older findings are grouped per batch (DECISIONS).
	agentAlertBackfillAge = 24 * time.Hour
	// Evidence keeps the first agentAlertEvidenceHead references and the
	// latest agentAlertEvidenceTail.
	agentAlertEvidenceHead = 5
	agentAlertEvidenceTail = 20
)

// AgentAlertLabels are the labels detections run for: AI workloads and
// agents (§5.7). A possible AI workload rests on configuration hints or on
// network traffic attributed only at scan time, which is not evidence of
// model use, so it raises no alerts.
var AgentAlertLabels = map[string]bool{
	agentruntime.LabelAIWorkload: true, agentruntime.LabelSuggestedAgent: true, agentruntime.LabelAgent: true,
}

/* ------------------------------------------------------------------------- */
/*                                   Rows                                     */
/* ------------------------------------------------------------------------- */

// AgentAlert is one agent_alert row.
type AgentAlert struct {
	ID             uuid.UUID       `json:"id" gorm:"column:id"`
	WorkspaceID    uuid.UUID       `json:"workspace_id" gorm:"column:workspace_id"`
	ConnectorID    uuid.UUID       `json:"connector_id" gorm:"column:connector_id"`
	IdentityID     uuid.UUID       `json:"identity_id" gorm:"column:identity_id"`
	WorkloadIDs    json.RawMessage `json:"workload_ids" gorm:"column:workload_ids"`
	SubjectLabel   string          `json:"subject_label" gorm:"column:subject_label"`
	SubjectName    string          `json:"subject_name" gorm:"column:subject_name"`
	Detection      string          `json:"detection" gorm:"column:detection"`
	Severity       string          `json:"severity" gorm:"column:severity"`
	Title          string          `json:"title" gorm:"column:title"`
	DedupeKey      string          `json:"dedupe_key" gorm:"column:dedupe_key"`
	FirstSeen      time.Time       `json:"first_seen" gorm:"column:first_seen"`
	LastSeen       time.Time       `json:"last_seen" gorm:"column:last_seen"`
	EventCount     int             `json:"event_count" gorm:"column:event_count"`
	Evidence       json.RawMessage `json:"evidence" gorm:"column:evidence"`
	State          string          `json:"state" gorm:"column:state"`
	StateChangedBy *uuid.UUID      `json:"state_changed_by" gorm:"column:state_changed_by"`
	StateChangedAt *time.Time      `json:"state_changed_at" gorm:"column:state_changed_at"`
	Reason         string          `json:"reason" gorm:"column:reason"`
	CreatedAt      time.Time       `json:"created_at" gorm:"column:created_at"`
	// Per-transition actors (migration 165): the latest of each.
	AcknowledgedBy *uuid.UUID `json:"acknowledged_by" gorm:"column:acknowledged_by"`
	AcknowledgedAt *time.Time `json:"acknowledged_at" gorm:"column:acknowledged_at"`
	ResolvedBy     *uuid.UUID `json:"resolved_by" gorm:"column:resolved_by"`
	ResolvedAt     *time.Time `json:"resolved_at" gorm:"column:resolved_at"`
	Outcome        *string    `json:"outcome" gorm:"column:outcome"`
	ReopenedBy     *uuid.UUID `json:"reopened_by" gorm:"column:reopened_by"`
	ReopenedAt     *time.Time `json:"reopened_at" gorm:"column:reopened_at"`
	ReopenCount    int        `json:"reopen_count" gorm:"column:reopen_count"`
	// SuppressedBy is the suppression that kept the alert from Slack and
	// SIEM (migration 166).
	SuppressedBy *uuid.UUID `json:"suppressed_by" gorm:"column:suppressed_by"`
}

// AgentAlertTransition is one agent_alert_transition row.
type AgentAlertTransition struct {
	ID        uuid.UUID `json:"id" gorm:"column:id"`
	FromState string    `json:"from_state" gorm:"column:from_state"`
	ToState   string    `json:"to_state" gorm:"column:to_state"`
	ActorID   uuid.UUID `json:"actor_id" gorm:"column:actor_id"`
	Outcome   *string   `json:"outcome" gorm:"column:outcome"`
	Reason    string    `json:"reason" gorm:"column:reason"`
	At        time.Time `json:"at" gorm:"column:at"`
}

// AgentAlertEventRef is one sanitised event reference in an alert's
// evidence: never a request or response body, never a secret value or name.
type AgentAlertEventRef struct {
	EventID string    `json:"event_id"`
	Time    time.Time `json:"time"`
	Source  string    `json:"source"`
	Name    string    `json:"name"`
	IP      string    `json:"ip,omitempty"`
	Region  string    `json:"region,omitempty"`
	Error   string    `json:"error,omitempty"`
	// Detail is the detection's finding detail (detect.Finding.Detail).
	Detail string `json:"detail,omitempty"`
}

// AgentAlertDelivery is one agent_alert_delivery row.
type AgentAlertDelivery struct {
	ID            uuid.UUID  `json:"id" gorm:"column:id"`
	AlertID       uuid.UUID  `json:"alert_id" gorm:"column:alert_id"`
	Channel       string     `json:"channel" gorm:"column:channel"`
	EndpointID    *uuid.UUID `json:"endpoint_id" gorm:"column:endpoint_id"`
	Attempt       int        `json:"attempt" gorm:"column:attempt"`
	Status        string     `json:"status" gorm:"column:status"`
	NextAttemptAt time.Time  `json:"next_attempt_at" gorm:"column:next_attempt_at"`
	LastError     string     `json:"last_error" gorm:"column:last_error"`
	SentAt        *time.Time `json:"sent_at" gorm:"column:sent_at"`
	CreatedAt     time.Time  `json:"created_at" gorm:"column:created_at"`
}

// AgentAlertView is GET /alerts/:id: the alert and its deliveries.
type AgentAlertView struct {
	AgentAlert
	DetectionName string                 `json:"detection_name"`
	Deliveries    []AgentAlertDelivery   `json:"deliveries,omitempty"`
	Transitions   []AgentAlertTransition `json:"transitions"`
}

/* ------------------------------------------------------------------------- */
/*                                 Settings                                   */
/* ------------------------------------------------------------------------- */

// AgentAlertDetectionSetting is one detection's switch and thresholds (N and
// Minutes for D5, K for D6), and its severity when the workspace sets one
// ("" = the severity the detection raises).
type AgentAlertDetectionSetting struct {
	Enabled  bool    `json:"enabled"`
	N        int     `json:"n,omitempty"`
	Minutes  int     `json:"minutes,omitempty"`
	K        float64 `json:"k,omitempty"`
	Severity string  `json:"severity,omitempty"`
}

// effectiveSeverity is the highest severity the detection raises under d.
func (d AgentAlertDetectionSetting) effectiveSeverity(id detect.ID) string {
	if d.Severity != "" {
		return d.Severity
	}
	return detect.DefaultSeverity(id)
}

// AgentAlertSettings is a workspace's alert configuration (absent row = the
// defaults).
type AgentAlertSettings struct {
	Detections          map[string]AgentAlertDetectionSetting `json:"detections"`
	SlackEnabled        bool                                  `json:"slack_enabled"`
	DedupeWindowMinutes int                                   `json:"dedupe_window_minutes"`
	RetentionDays       int                                   `json:"retention_days"`
	Saved               bool                                  `json:"saved"`
	UpdatedAt           *time.Time                            `json:"updated_at,omitempty"`
	// Version is the active detection rule version (0: none saved, the
	// defaults); PendingVersionID is the proposal waiting for approval.
	Version          int        `json:"version"`
	VersionID        *uuid.UUID `json:"version_id,omitempty"`
	PendingVersionID *uuid.UUID `json:"pending_version_id,omitempty"`
}

// applySeverity sets each finding's severity to the workspace's severity for
// its detection, when one is set.
func (s AgentAlertSettings) applySeverity(fs []detect.Finding) []detect.Finding {
	for i := range fs {
		if d, ok := s.Detections[string(fs[i].Detection)]; ok && d.Severity != "" {
			fs[i].Severity = d.Severity
		}
	}
	return fs
}

// DefaultAgentAlertSettings is every detection on with spec §10's
// thresholds, Slack on, a 1 h dedupe window and 90-day retention.
func DefaultAgentAlertSettings() AgentAlertSettings {
	s := AgentAlertSettings{Detections: map[string]AgentAlertDetectionSetting{}, SlackEnabled: true,
		DedupeWindowMinutes: DefaultAgentAlertDedupeMinutes, RetentionDays: DefaultAgentAlertRetentionDays}
	for _, id := range detect.All {
		d := AgentAlertDetectionSetting{Enabled: true}
		switch id {
		case detect.D5:
			d.N, d.Minutes = detect.DefaultDenialBurst, int(detect.DefaultDenialWindow/time.Minute)
		case detect.D6:
			d.K = detect.DefaultSpikeFactor
		}
		s.Detections[string(id)] = d
	}
	return s
}

// DetectConfig is the settings as detect.Config.
func (s AgentAlertSettings) DetectConfig() detect.Config {
	cfg := detect.DefaultConfig()
	for _, id := range detect.All {
		d, ok := s.Detections[string(id)]
		if !ok {
			continue
		}
		if !d.Enabled {
			cfg.Disabled[id] = true
		}
		switch id {
		case detect.D5:
			if d.N > 0 {
				cfg.DenialBurst = d.N
			}
			if d.Minutes > 0 {
				cfg.DenialWindow = time.Duration(d.Minutes) * time.Minute
			}
		case detect.D6:
			if d.K > 0 {
				cfg.SpikeFactor = d.K
			}
		}
	}
	return cfg
}

// AgentAlertDetectionUpdate changes one detection (nil = unchanged;
// Severity "" = the detection's own severity).
type AgentAlertDetectionUpdate struct {
	Enabled  *bool    `json:"enabled"`
	N        *int     `json:"n"`
	Minutes  *int     `json:"minutes"`
	K        *float64 `json:"k"`
	Severity *string  `json:"severity"`
}

// AgentAlertSettingsUpdate is PUT /alert-settings: omitted fields keep
// their value.
type AgentAlertSettingsUpdate struct {
	Detections          map[string]*AgentAlertDetectionUpdate `json:"detections"`
	SlackEnabled        *bool                                 `json:"slack_enabled"`
	DedupeWindowMinutes *int                                  `json:"dedupe_window_minutes"`
	RetentionDays       *int                                  `json:"retention_days"`
	// Reason is recorded on the rule version (optional, at most 1000
	// characters).
	Reason string `json:"reason"`
}

// settingsFromStored is the defaults overlaid with a stored version's values.
func settingsFromStored(ws uuid.UUID, detections json.RawMessage, slack bool, dedupe, retention int) AgentAlertSettings {
	out := DefaultAgentAlertSettings()
	stored := map[string]AgentAlertDetectionSetting{}
	if len(detections) > 0 {
		if err := json.Unmarshal(detections, &stored); err != nil {
			log.Printf("[agent-alerts] workspace %s: unreadable detection settings, using defaults: %v", ws, err)
		}
	}
	for k, v := range stored {
		if detect.Valid(detect.ID(k)) {
			def := out.Detections[k]
			if v.N == 0 {
				v.N = def.N
			}
			if v.Minutes == 0 {
				v.Minutes = def.Minutes
			}
			if v.K == 0 {
				v.K = def.K
			}
			if v.Severity != "" && !detect.ValidSeverity(v.Severity) {
				v.Severity = ""
			}
			out.Detections[k] = v
		}
	}
	out.SlackEnabled = slack
	if dedupe > 0 {
		out.DedupeWindowMinutes = dedupe
	}
	if retention > 0 {
		out.RetentionDays = retention
	}
	return out
}

// readAgentAlertSettings reads ws's ACTIVE detection rule version on tx
// (under RLS for ws); without one, the defaults.
func readAgentAlertSettings(tx *gorm.DB, ws uuid.UUID) (AgentAlertSettings, error) {
	v, err := activeAgentRuleVersion(tx, ws, false)
	if err != nil || v == nil {
		return DefaultAgentAlertSettings(), err
	}
	return v.settings(ws), nil
}

// apply merges u onto s, validating every value; s itself is not changed.
func (u AgentAlertSettingsUpdate) apply(s AgentAlertSettings) (AgentAlertSettings, error) {
	det := make(map[string]AgentAlertDetectionSetting, len(s.Detections))
	for k, v := range s.Detections {
		det[k] = v
	}
	s.Detections = det
	if len(u.Reason) > 1000 {
		return s, GovBadParam("reason", "reason must be at most 1000 characters.")
	}
	for k, d := range u.Detections {
		if !detect.Valid(detect.ID(k)) {
			return s, GovBadParam("detections", fmt.Sprintf("Unknown detection %q (D1..D8).", k))
		}
		if d == nil {
			continue
		}
		cur := s.Detections[k]
		if d.Enabled != nil {
			cur.Enabled = *d.Enabled
		}
		if (d.N != nil || d.Minutes != nil) && k != string(detect.D5) {
			return s, GovBadParam("detections."+k, "Only D5 takes n and minutes.")
		}
		if d.K != nil && k != string(detect.D6) {
			return s, GovBadParam("detections."+k, "Only D6 takes k.")
		}
		if d.N != nil {
			if *d.N < 1 || *d.N > 1000 {
				return s, GovBadParam("detections.D5.n", "n must be between 1 and 1000.")
			}
			cur.N = *d.N
		}
		if d.Minutes != nil {
			if *d.Minutes < 1 || *d.Minutes > 1440 {
				return s, GovBadParam("detections.D5.minutes", "minutes must be between 1 and 1440.")
			}
			cur.Minutes = *d.Minutes
		}
		if d.K != nil {
			if *d.K < 1 || *d.K > 100 {
				return s, GovBadParam("detections.D6.k", "k must be between 1 and 100.")
			}
			cur.K = *d.K
		}
		if d.Severity != nil {
			if *d.Severity != "" && !detect.ValidSeverity(*d.Severity) {
				return s, GovBadParam("detections."+k+".severity", `severity must be high, medium, low or "" (the detection's own).`)
			}
			cur.Severity = *d.Severity
		}
		s.Detections[k] = cur
	}
	if u.SlackEnabled != nil {
		s.SlackEnabled = *u.SlackEnabled
	}
	if u.DedupeWindowMinutes != nil {
		if *u.DedupeWindowMinutes < 5 || *u.DedupeWindowMinutes > 1440 {
			return s, GovBadParam("dedupe_window_minutes", "dedupe_window_minutes must be between 5 and 1440.")
		}
		s.DedupeWindowMinutes = *u.DedupeWindowMinutes
	}
	if u.RetentionDays != nil {
		if *u.RetentionDays < 7 || *u.RetentionDays > 3650 {
			return s, GovBadParam("retention_days", "retention_days must be between 7 and 3650.")
		}
		s.RetentionDays = *u.RetentionDays
	}
	return s, nil
}

/* ------------------------------------------------------------------------- */
/*                                  The sink                                  */
/* ------------------------------------------------------------------------- */

// AgentAlertSink is the "agent_alerts" agentruntime.EventSink.
type AgentAlertSink struct {
	db  *gorm.DB
	now func() time.Time
}

// NewAgentAlertSink builds the sink over db.
func NewAgentAlertSink(db *gorm.DB) *AgentAlertSink { return &AgentAlertSink{db: db, now: time.Now} }

// WithClock replaces the wall clock (tests).
func (s *AgentAlertSink) WithClock(now func() time.Time) *AgentAlertSink {
	s.now = now
	return s
}

// Name implements agentruntime.EventSink.
func (s *AgentAlertSink) Name() string { return AgentAlertSinkName }

// Process implements agentruntime.EventSink.
func (s *AgentAlertSink) Process(ctx context.Context, workspaceID, connectorID uuid.UUID, events []agentruntime.Event) error {
	r := agentruntime.Resolver()
	if r == nil || workspaceID == uuid.Nil || len(events) == 0 {
		return nil
	}
	// Without migration 150 the sink is absent, not failing: events are not
	// alerted on, and the ingest must not treat that as a dispatch failure.
	// TENANT-EXEMPT: the 150 schema check below reads the Postgres catalog only.
	if s.db == nil {
		// no database to gate (tests); nothing below reads one before resolving
	} else if ok, reason := AgentAlertsStatus(s.db); !ok { // TENANT-EXEMPT: catalog-only schema check
		agentAlertsGate.logWait("alert sink", reason)
		return nil
	}
	groups := map[agentruntime.Attribution][]agentruntime.Event{}
	var keys []agentruntime.Attribution
	for _, e := range events {
		a := e.Attribution()
		if a.How == "" || e.EventID == "" {
			continue
		}
		if _, ok := groups[a]; !ok {
			keys = append(keys, a)
		}
		groups[a] = append(groups[a], e)
	}
	if len(keys) == 0 {
		return nil
	}
	// Resolve first: most events are not by an AI workload or agent, and
	// then nothing is read or written.
	type target struct {
		subj   agentruntime.Subject
		events []agentruntime.Event
	}
	var targets []target
	byIdentity := map[uuid.UUID]int{} // index in targets
	var first error
	for _, a := range keys {
		subj, err := r.Resolve(ctx, workspaceID, connectorID, a)
		if err != nil {
			if first == nil {
				first = fmt.Errorf("agent alerts: resolve %s: %w", a.ARN, err)
			}
			continue
		}
		if subj.IdentityID == uuid.Nil || !AgentAlertLabels[subj.Label] {
			continue
		}
		if subj.ConnectorID == uuid.Nil {
			subj.ConnectorID = connectorID
		}
		// Attributions that resolve to one identity (the same role named with
		// and without its RoleId) are one identity's batch.
		if i, ok := byIdentity[subj.IdentityID]; ok {
			targets[i].events = append(targets[i].events, groups[a]...)
			continue
		}
		byIdentity[subj.IdentityID] = len(targets)
		targets = append(targets, target{subj: subj, events: groups[a]})
	}
	if len(targets) == 0 {
		return first
	}
	var settings AgentAlertSettings
	if err := tenancy.InWorkspaceRead(ctx, s.db, workspaceID, func(tx *gorm.DB) error {
		var err error
		settings, err = readAgentAlertSettings(tx, workspaceID)
		return err
	}); err != nil {
		return fmt.Errorf("agent alerts: settings: %w", err)
	}
	for _, t := range targets {
		if err := s.processIdentity(ctx, workspaceID, t.subj, settings, t.events); err != nil && first == nil {
			first = fmt.Errorf("agent alerts: identity %s: %w", t.subj.IdentityID, err)
		}
	}
	return first
}

// agentAlertHit is one finding of one event.
type agentAlertHit struct {
	f detect.Finding
	e agentruntime.Event
}

func (s *AgentAlertSink) processIdentity(ctx context.Context, ws uuid.UUID, subj agentruntime.Subject, st AgentAlertSettings, events []agentruntime.Event) error {
	sort.SliceStable(events, func(i, j int) bool { return events[i].EventTime.Before(events[j].EventTime) })
	now := s.now().UTC()
	window := time.Duration(st.DedupeWindowMinutes) * time.Minute
	cfg := st.DetectConfig()
	return tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		// One writer per identity at a time: the stream and the poller can
		// deliver its events concurrently, and both the baseline and the
		// dedupe decision read before they write.
		if err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtext(?))`, "agent_alert:"+ws.String()+":"+subj.IdentityID.String()).Error; err != nil {
			return err
		}
		fresh, err := agentAlertFreshEvents(tx, ws, subj.IdentityID, events, now)
		if err != nil || len(fresh) == 0 {
			return err
		}
		b, err := loadAgentAlertBaseline(tx, ws, subj.IdentityID, fresh[0].EventTime, now)
		if err != nil {
			return err
		}
		var hits []agentAlertHit
		for _, e := range fresh {
			fs := st.applySeverity(mergeAgentAlertFindings(detect.Evaluate(cfg, b, e, now)))
			if len(fs) == 0 || now.Sub(e.EventTime) > agentAlertMaxEventAge {
				continue
			}
			for _, f := range fs {
				hits = append(hits, agentAlertHit{f: f, e: e})
			}
		}
		if err := saveAgentAlertBaseline(tx, ws, subj.IdentityID, b, now); err != nil {
			return err
		}
		// Backfill: one alert per detection for this batch's old findings.
		backfill := map[detect.ID]uuid.UUID{}
		for _, h := range hits {
			old := now.Sub(h.e.EventTime) > agentAlertBackfillAge
			var into *uuid.UUID
			if id, ok := backfill[h.f.Detection]; old && ok {
				into = &id
			}
			id, err := upsertAgentAlert(tx, ws, subj, st, h, window, now, into)
			if err != nil {
				return err
			}
			if old {
				backfill[h.f.Detection] = id
			}
		}
		return nil
	})
}

// agentAlertFreshEvents records each event as seen and returns those not
// seen before (by EventID, per workspace).
func agentAlertFreshEvents(tx *gorm.DB, ws, identity uuid.UUID, events []agentruntime.Event, now time.Time) ([]agentruntime.Event, error) {
	var out []agentruntime.Event
	seen := map[string]bool{}
	for _, e := range events {
		if seen[e.EventID] {
			continue
		}
		seen[e.EventID] = true
		res := tx.Exec(`INSERT INTO agent_alert_event_seen (workspace_id, event_id, identity_id, event_time, seen_at)
		                VALUES (?, ?, ?, ?, ?) ON CONFLICT (workspace_id, event_id) DO NOTHING`,
			ws, truncate(e.EventID, 128), identity, e.EventTime.UTC(), now)
		if res.Error != nil {
			return nil, res.Error
		}
		if res.RowsAffected == 1 {
			out = append(out, e)
		}
	}
	return out, nil
}

type agentAlertBaselineRow struct {
	Kind      string
	Key       string
	FirstSeen time.Time
	Count     int
}

// loadAgentAlertBaseline reads the identity's baseline: every seen key, the
// hourly buckets D6 needs before the earliest event, the minute buckets D5
// needs, and when the identity was first observed.
func loadAgentAlertBaseline(tx *gorm.DB, ws, identity uuid.UUID, earliest, now time.Time) (*detect.Baseline, error) {
	var rows []agentAlertBaselineRow
	hourlySince := earliest.Add(-time.Duration(detect.BaselineHours+1) * time.Hour)
	deniedSince := earliest.Add(-25 * time.Hour)
	if err := tx.Raw(`SELECT kind, key, first_seen, count FROM agent_alert_baseline
	                   WHERE workspace_id = ? AND identity_id = ?
	                     AND (kind IN ('model', 'role', 'ip', 'region', 'observed')
	                          OR (kind = 'hourly' AND last_seen >= ?)
	                          OR (kind = 'denied' AND last_seen >= ?))`,
		ws, identity, hourlySince, deniedSince).Scan(&rows).Error; err != nil {
		return nil, err
	}
	observed := now
	for _, r := range rows {
		if r.Kind == detect.KindObserved {
			observed = r.FirstSeen
		}
	}
	b := detect.NewBaseline(observed)
	for _, r := range rows {
		switch r.Kind {
		case detect.KindHourly, detect.KindDenied:
			b.LoadBucket(r.Kind, r.Key, r.Count)
		case detect.KindObserved:
		default:
			b.Know(r.Kind, r.Key)
		}
	}
	return b, nil
}

// saveAgentAlertBaseline upserts the baseline's changes and the identity's
// observed row (kept at its first value).
func saveAgentAlertBaseline(tx *gorm.DB, ws, identity uuid.UUID, b *detect.Baseline, now time.Time) error {
	changes := append(b.Changes(), detect.Change{Kind: detect.KindObserved, Key: "", First: b.ObservedSince, Last: now, Delta: 0})
	for _, c := range changes {
		if err := tx.Exec(`INSERT INTO agent_alert_baseline (workspace_id, identity_id, kind, key, first_seen, last_seen, count)
		                   VALUES (?, ?, ?, ?, ?, ?, ?)
		                   ON CONFLICT (workspace_id, identity_id, kind, key) DO UPDATE SET
		                     first_seen = LEAST(agent_alert_baseline.first_seen, EXCLUDED.first_seen),
		                     last_seen  = GREATEST(agent_alert_baseline.last_seen, EXCLUDED.last_seen),
		                     count      = agent_alert_baseline.count + EXCLUDED.count`,
			ws, identity, c.Kind, truncate(c.Key, 512), c.First.UTC(), c.Last.UTC(), c.Delta).Error; err != nil {
			return err
		}
	}
	return nil
}

// mergeAgentAlertFindings keeps one finding per detection: the highest
// severity, details joined.
func mergeAgentAlertFindings(fs []detect.Finding) []detect.Finding {
	if len(fs) < 2 {
		return fs
	}
	idx := map[detect.ID]int{}
	var out []detect.Finding
	for _, f := range fs {
		i, ok := idx[f.Detection]
		if !ok {
			idx[f.Detection] = len(out)
			out = append(out, f)
			continue
		}
		if detect.SeverityRank(f.Severity) > detect.SeverityRank(out[i].Severity) {
			out[i].Severity = f.Severity
		}
		if f.Detail != "" {
			out[i].Detail = strings.TrimPrefix(out[i].Detail+"; "+f.Detail, "; ")
		}
	}
	return out
}

// AgentAlertDedupeKey is an alert's dedupe key: identity and detection
// (the workspace is the row's).
func AgentAlertDedupeKey(identity uuid.UUID, d detect.ID) string {
	return identity.String() + "/" + string(d)
}

func agentAlertRef(h agentAlertHit) AgentAlertEventRef {
	e := h.e
	return AgentAlertEventRef{EventID: e.EventID, Time: e.EventTime.UTC(), Source: e.EventSource, Name: e.EventName,
		IP: e.SourceIP, Region: e.Region, Error: e.ErrorCode, Detail: truncate(h.f.Detail, 300)}
}

// appendAgentAlertEvidence appends ref to raw, keeping the first
// agentAlertEvidenceHead and the latest agentAlertEvidenceTail references.
func appendAgentAlertEvidence(raw json.RawMessage, ref AgentAlertEventRef) (json.RawMessage, error) {
	var refs []AgentAlertEventRef
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &refs); err != nil {
			refs = nil // unreadable evidence is replaced, never fatal
		}
	}
	refs = append(refs, ref)
	if max := agentAlertEvidenceHead + agentAlertEvidenceTail; len(refs) > max {
		refs = append(refs[:agentAlertEvidenceHead:agentAlertEvidenceHead], refs[len(refs)-agentAlertEvidenceTail:]...)
	}
	return json.Marshal(refs)
}

func agentAlertTitle(subj agentruntime.Subject, d detect.ID) string {
	name := strings.TrimSpace(subj.Name)
	if name == "" {
		name = "identity " + subj.IdentityID.String()
	}
	label := map[string]string{agentruntime.LabelAIWorkload: "AI workload", agentruntime.LabelSuggestedAgent: "suggested agent",
		agentruntime.LabelAgent: "agent", agentruntime.LabelPossibleAIWorkload: "possible AI workload"}[subj.Label]
	return truncate(fmt.Sprintf("%s: %s (%s)", detect.Name(d), name, label), 300)
}

type agentAlertOpenRow struct {
	ID           uuid.UUID
	Severity     string
	Evidence     json.RawMessage
	SuppressedBy *uuid.UUID
}

// upsertAgentAlert extends the open alert of (identity, detection) whose
// activity is within window of the event, or opens one, and returns the
// alert's id. into, when set, is the alert this batch's backfill already
// wrote for the detection: it is extended whatever the gap (unless it was
// resolved meanwhile, when the usual rule applies).
func upsertAgentAlert(tx *gorm.DB, ws uuid.UUID, subj agentruntime.Subject, st AgentAlertSettings, h agentAlertHit, window time.Duration, now time.Time, into *uuid.UUID) (uuid.UUID, error) {
	key := AgentAlertDedupeKey(subj.IdentityID, h.f.Detection)
	at := h.e.EventTime.UTC()
	workloads := subj.WorkloadIDs
	if workloads == nil {
		workloads = []uuid.UUID{}
	}
	wl, err := json.Marshal(workloads)
	if err != nil {
		return uuid.Nil, err
	}
	var open []agentAlertOpenRow
	if into != nil {
		if err := tx.Raw(`SELECT id, severity, evidence, suppressed_by FROM agent_alert
		                   WHERE workspace_id = ? AND id = ? AND dedupe_key = ? AND state <> 'resolved'
		                   FOR UPDATE`, ws, *into, key).Scan(&open).Error; err != nil {
			return uuid.Nil, err
		}
	}
	if len(open) == 0 {
		if err := tx.Raw(`SELECT id, severity, evidence, suppressed_by FROM agent_alert
		                   WHERE workspace_id = ? AND dedupe_key = ? AND state <> 'resolved'
		                     AND last_seen >= ? AND first_seen <= ?
		                   ORDER BY last_seen DESC LIMIT 1 FOR UPDATE`,
			ws, key, at.Add(-window), at.Add(window)).Scan(&open).Error; err != nil {
			return uuid.Nil, err
		}
	}
	harm := detect.SucceededHarm(h.f, h.e)
	if len(open) == 1 {
		cur := open[0]
		ev, err := appendAgentAlertEvidence(cur.Evidence, agentAlertRef(h))
		if err != nil {
			return uuid.Nil, err
		}
		sev := cur.Severity
		if detect.SeverityRank(h.f.Severity) > detect.SeverityRank(sev) {
			sev = h.f.Severity
		}
		if err := tx.Exec(`UPDATE agent_alert SET last_seen = GREATEST(last_seen, ?), first_seen = LEAST(first_seen, ?),
		                       event_count = event_count + 1, severity = ?, evidence = ?::jsonb, workload_ids = ?::jsonb,
		                       subject_label = ?, subject_name = ?
		                 WHERE workspace_id = ? AND id = ?`,
			at, at, sev, string(ev), string(wl), subj.Label, truncate(subj.Name, 300), ws, cur.ID).Error; err != nil {
			return uuid.Nil, err
		}
		// A suppressed alert that now records a harmful outcome that
		// succeeded is no longer suppressed: it is delivered.
		if cur.SuppressedBy != nil && harm {
			if err := tx.Exec(`UPDATE agent_alert SET suppressed_by = NULL WHERE workspace_id = ? AND id = ?`, ws, cur.ID).Error; err != nil {
				return uuid.Nil, err
			}
			if err := appendGovEvent(tx, ws, GovEventAgentAlertUnsuppressed, models.GovActorSystem, AgentAlertSinkName, govEventRefs{},
				map[string]any{"alert_id": cur.ID, "suppression_id": *cur.SuppressedBy, "detection": string(h.f.Detection),
					"event_id": h.e.EventID, "reason": "succeeded_harmful_outcome"}); err != nil {
				return uuid.Nil, err
			}
			return cur.ID, enqueueAgentAlertDeliveries(tx, ws, cur.ID, st)
		}
		return cur.ID, nil
	}
	ev, err := appendAgentAlertEvidence(nil, agentAlertRef(h))
	if err != nil {
		return uuid.Nil, err
	}
	var suppressedBy *uuid.UUID
	if !harm {
		if suppressedBy, err = matchAgentAlertSuppression(tx, ws, subj.IdentityID, h.f.Detection, "", now); err != nil {
			return uuid.Nil, err
		}
	}
	var ids []uuid.UUID
	if err := tx.Raw(`INSERT INTO agent_alert (workspace_id, connector_id, identity_id, workload_ids, subject_label, subject_name,
	                         detection, severity, title, dedupe_key, first_seen, last_seen, event_count, evidence, state, created_at,
	                         suppressed_by)
	                  VALUES (?, ?, ?, ?::jsonb, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?::jsonb, 'open', ?, ?)
	                  RETURNING id`,
		ws, subj.ConnectorID, subj.IdentityID, string(wl), subj.Label, truncate(subj.Name, 300),
		string(h.f.Detection), h.f.Severity, agentAlertTitle(subj, h.f.Detection), key, at, at, string(ev), now,
		suppressedBy).Scan(&ids).Error; err != nil {
		return uuid.Nil, err
	}
	if len(ids) != 1 {
		return uuid.Nil, errors.New("agent alert insert returned no id")
	}
	id := ids[0]
	payload := map[string]any{"alert_id": id, "detection": string(h.f.Detection), "severity": h.f.Severity,
		"identity_id": subj.IdentityID, "connector_id": subj.ConnectorID, "subject_label": subj.Label,
		"first_event_id": h.e.EventID}
	if suppressedBy != nil {
		payload["suppressed_by"] = *suppressedBy
	}
	if err := appendGovEvent(tx, ws, GovEventAgentAlertOpened, models.GovActorSystem, AgentAlertSinkName, govEventRefs{}, payload); err != nil {
		return uuid.Nil, err
	}
	if suppressedBy != nil {
		// Stored, never delivered to Slack or SIEM.
		return id, nil
	}
	return id, enqueueAgentAlertDeliveries(tx, ws, id, st)
}

/* ------------------------------------------------------------------------- */
/*                               Reads and writes                             */
/* ------------------------------------------------------------------------- */

// AgentAlertService serves the alert, settings and SIEM endpoint APIs.
type AgentAlertService struct {
	db  *gorm.DB
	now func() time.Time
}

// NewAgentAlertService builds the service over db.
func NewAgentAlertService(db *gorm.DB) *AgentAlertService {
	return &AgentAlertService{db: db, now: time.Now}
}

// WithClock replaces the wall clock (tests).
func (s *AgentAlertService) WithClock(now func() time.Time) *AgentAlertService {
	s.now = now
	return s
}

// AgentAlertFilter filters GET /alerts. Suppressed: nil = every alert, true =
// only alerts a suppression kept from delivery, false = only the others.
type AgentAlertFilter struct {
	State, Severity, Detection string
	IdentityID                 *uuid.UUID
	Suppressed                 *bool
}

func errAgentAlertNotFound() error {
	return govErr(http.StatusNotFound, "not_found", "Not found.", nil)
}

// Validate checks the filter's values.
func (f AgentAlertFilter) Validate() error {
	switch f.State {
	case "", AgentAlertOpen, AgentAlertAcknowledged, AgentAlertResolved, AgentAlertReopened:
	default:
		return GovBadParam("state", "state must be open, acknowledged, resolved or reopened.")
	}
	if f.Severity != "" && !detect.ValidSeverity(f.Severity) {
		return GovBadParam("severity", "severity must be high, medium or low.")
	}
	if f.Detection != "" && !detect.Valid(detect.ID(f.Detection)) {
		return GovBadParam("detection", "detection must be one of D1..D8.")
	}
	return nil
}

func encodeAgentAlertCursor(t time.Time, id uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(t.UTC().Format(time.RFC3339Nano) + "|" + id.String()))
}

func decodeAgentAlertCursor(c string) (time.Time, uuid.UUID, error) {
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return time.Time{}, uuid.Nil, err
	}
	ts, idStr, ok := strings.Cut(string(raw), "|")
	if !ok {
		return time.Time{}, uuid.Nil, errors.New("malformed cursor")
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return time.Time{}, uuid.Nil, err
	}
	id, err := uuid.Parse(idStr)
	return t, id, err
}

const agentAlertColumns = `id, workspace_id, connector_id, identity_id, workload_ids, subject_label, subject_name, detection,
	severity, title, dedupe_key, first_seen, last_seen, event_count, evidence, state, state_changed_by, state_changed_at,
	reason, created_at, acknowledged_by, acknowledged_at, resolved_by, resolved_at, outcome, reopened_by, reopened_at,
	reopen_count, suppressed_by`

// List is GET /alerts: newest first (created_at, id), limit 1..200.
func (s *AgentAlertService) List(ctx context.Context, ws uuid.UUID, f AgentAlertFilter, cursor string, limit int) ([]AgentAlert, string, error) {
	if err := f.Validate(); err != nil {
		return nil, "", err
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	q := `SELECT ` + agentAlertColumns + ` FROM agent_alert WHERE workspace_id = ?`
	args := []any{ws}
	if f.State != "" {
		q += ` AND state = ?`
		args = append(args, f.State)
	}
	if f.Severity != "" {
		q += ` AND severity = ?`
		args = append(args, f.Severity)
	}
	if f.Detection != "" {
		q += ` AND detection = ?`
		args = append(args, f.Detection)
	}
	if f.IdentityID != nil {
		q += ` AND identity_id = ?`
		args = append(args, *f.IdentityID)
	}
	if f.Suppressed != nil {
		if *f.Suppressed {
			q += ` AND suppressed_by IS NOT NULL`
		} else {
			q += ` AND suppressed_by IS NULL`
		}
	}
	if cursor != "" {
		t, id, err := decodeAgentAlertCursor(cursor)
		if err != nil {
			return nil, "", GovBadParam("cursor", "The cursor is not valid.")
		}
		q += ` AND (created_at, id) < (?, ?)`
		args = append(args, t, id)
	}
	q += ` ORDER BY created_at DESC, id DESC LIMIT ?`
	args = append(args, limit+1)
	var rows []AgentAlert
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(q, args...).Scan(&rows).Error
	}); err != nil {
		return nil, "", err
	}
	next := ""
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		next = encodeAgentAlertCursor(last.CreatedAt, last.ID)
	}
	if rows == nil {
		rows = []AgentAlert{}
	}
	return rows, next, nil
}

// Get is GET /alerts/:id with its deliveries and transitions. Another
// workspace's alert is not found.
func (s *AgentAlertService) Get(ctx context.Context, ws, id uuid.UUID) (*AgentAlertView, error) {
	var out *AgentAlertView
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var rows []AgentAlert
		if err := tx.Raw(`SELECT `+agentAlertColumns+` FROM agent_alert WHERE workspace_id = ? AND id = ?`, ws, id).Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return errAgentAlertNotFound()
		}
		v := &AgentAlertView{AgentAlert: rows[0], DetectionName: detect.Name(detect.ID(rows[0].Detection))}
		if err := tx.Raw(`SELECT id, alert_id, channel, endpoint_id, attempt, status, next_attempt_at, last_error, sent_at, created_at
		                    FROM agent_alert_delivery WHERE workspace_id = ? AND alert_id = ? ORDER BY created_at, id`, ws, id).
			Scan(&v.Deliveries).Error; err != nil {
			return err
		}
		if err := tx.Raw(`SELECT id, from_state, to_state, actor_id, outcome, reason, at
		                    FROM agent_alert_transition WHERE workspace_id = ? AND alert_id = ? ORDER BY at, id`, ws, id).
			Scan(&v.Transitions).Error; err != nil {
			return err
		}
		if v.Transitions == nil {
			v.Transitions = []AgentAlertTransition{}
		}
		out = v
		return nil
	})
	return out, err
}

// Acknowledge is POST /alerts/:id/acknowledge: open or reopened ->
// acknowledged (acknowledging an acknowledged alert changes nothing), with
// an "agent_alert.acknowledged" log entry.
func (s *AgentAlertService) Acknowledge(ctx context.Context, ws, id, actor uuid.UUID, reason string) (*AgentAlert, error) {
	return s.transition(ctx, ws, id, actor, AgentAlertAcknowledged, "", reason)
}

// Resolve is POST /alerts/:id/resolve: open, acknowledged or reopened ->
// resolved with an outcome code (required) and an optional reason, with an
// "agent_alert.resolved" log entry. Who acknowledged stays recorded.
func (s *AgentAlertService) Resolve(ctx context.Context, ws, id, actor uuid.UUID, outcome, reason string) (*AgentAlert, error) {
	outcome = strings.TrimSpace(outcome)
	if outcome == "" {
		return nil, GovBadParam("outcome", "outcome is required: true_positive, benign, false_positive or duplicate.")
	}
	if !ValidAgentAlertOutcome(outcome) {
		return nil, GovBadParam("outcome", "outcome must be true_positive, benign, false_positive or duplicate.")
	}
	return s.transition(ctx, ws, id, actor, AgentAlertResolved, outcome, reason)
}

// Reopen is POST /alerts/:id/reopen: resolved -> reopened, with a reason
// (required) and an "agent_alert.reopened" log entry. A reopened alert is
// extended by new findings like an open one.
func (s *AgentAlertService) Reopen(ctx context.Context, ws, id, actor uuid.UUID, reason string) (*AgentAlert, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, GovBadParam("reason", "reason is required to reopen an alert.")
	}
	return s.transition(ctx, ws, id, actor, AgentAlertReopened, "", reason)
}

// agentAlertTransitionAllowed reports whether from -> to is a transition
// (same == true: to equals from and nothing changes).
func agentAlertTransitionAllowed(from, to string) (ok, same bool) {
	switch to {
	case AgentAlertAcknowledged:
		if from == AgentAlertAcknowledged {
			return true, true
		}
		return from == AgentAlertOpen || from == AgentAlertReopened, false
	case AgentAlertResolved:
		return from == AgentAlertOpen || from == AgentAlertAcknowledged || from == AgentAlertReopened, false
	case AgentAlertReopened:
		return from == AgentAlertResolved, false
	}
	return false, false
}

func (s *AgentAlertService) transition(ctx context.Context, ws, id, actor uuid.UUID, to, outcome, reason string) (*AgentAlert, error) {
	reason = strings.TrimSpace(reason)
	if len(reason) > 1000 {
		return nil, GovBadParam("reason", "reason must be at most 1000 characters.")
	}
	var out *AgentAlert
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var rows []AgentAlert
		if err := tx.Raw(`SELECT `+agentAlertColumns+` FROM agent_alert WHERE workspace_id = ? AND id = ? FOR UPDATE`, ws, id).Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return errAgentAlertNotFound()
		}
		a := rows[0]
		ok, same := agentAlertTransitionAllowed(a.State, to)
		if same {
			out = &a
			return nil
		}
		if !ok {
			msg := fmt.Sprintf("An alert in state %s cannot be %s.", a.State, to)
			if a.State == AgentAlertResolved {
				msg = "The alert is already resolved."
			}
			return govErr(http.StatusConflict, "invalid_state", msg, map[string]any{"state": a.State})
		}
		now := s.now().UTC()
		var (
			set   string
			event string
			oc    *string
		)
		args := []any{to, actor, now, reason, actor, now}
		switch to {
		case AgentAlertAcknowledged:
			set, event = `acknowledged_by = ?, acknowledged_at = ?`, GovEventAgentAlertAcknowledged
			a.AcknowledgedBy, a.AcknowledgedAt = &actor, &now
		case AgentAlertResolved:
			oc = &outcome
			set, event = `resolved_by = ?, resolved_at = ?, outcome = ?`, GovEventAgentAlertResolved
			args = append(args, outcome)
			a.ResolvedBy, a.ResolvedAt, a.Outcome = &actor, &now, oc
		case AgentAlertReopened:
			// The previous resolution stays in agent_alert_transition.
			set, event = `reopened_by = ?, reopened_at = ?, reopen_count = reopen_count + 1,
			              resolved_by = NULL, resolved_at = NULL, outcome = NULL`, GovEventAgentAlertReopened
			a.ReopenedBy, a.ReopenedAt, a.ReopenCount = &actor, &now, a.ReopenCount+1
			a.ResolvedBy, a.ResolvedAt, a.Outcome = nil, nil, nil
		}
		args = append(args, ws, id)
		if err := tx.Exec(`UPDATE agent_alert SET state = ?, state_changed_by = ?, state_changed_at = ?, reason = ?, `+set+`
		                    WHERE workspace_id = ? AND id = ?`, args...).Error; err != nil {
			return err
		}
		if err := tx.Exec(`INSERT INTO agent_alert_transition (workspace_id, alert_id, from_state, to_state, actor_id, outcome, reason, at)
		                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, ws, id, a.State, to, actor, oc, reason, now).Error; err != nil {
			return err
		}
		payload := map[string]any{"alert_id": id, "detection": a.Detection, "identity_id": a.IdentityID, "from": a.State,
			"reason": reason, "event_count": a.EventCount}
		if oc != nil {
			payload["outcome"] = *oc
		}
		if err := appendGovEvent(tx, ws, event, models.GovActorUser, actor.String(), govEventRefs{}, payload); err != nil {
			return err
		}
		a.State, a.StateChangedBy, a.StateChangedAt, a.Reason = to, &actor, &now, reason
		out = &a
		return nil
	})
	return out, err
}

// Settings is GET /alert-settings: the active detection rule version (or
// the defaults) and the pending proposal's id.
func (s *AgentAlertService) Settings(ctx context.Context, ws uuid.UUID) (AgentAlertSettings, error) {
	var out AgentAlertSettings
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		out, err = readAgentAlertSettingsWithPending(tx, ws)
		return err
	})
	return out, err
}
