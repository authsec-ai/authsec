package services

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentruntime/detect"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// Agent runtime cases (SPEC-secops-backend-upgrade.md W3 / P2; migration
// 186). A case groups the alerts of one incident: an operator works it,
// assigns it, writes notes, splits or merges it, closes it with an outcome
// and exports it.
//
// Clustering. When the alert sink opens a NEW alert (upsertAgentAlert), the
// alert joins the open case that shares an indicator with it within
// AgentCaseClusterWindow; if none, a case is opened by "system". An extended
// alert is already in its case. Indicators are what an alert carries today:
// the identity it was raised on ("identity:<cloud_identity id>": one IAM role
// or user, i.e. one ARN) and every workload that runs as it
// ("workload:<id>": the agent). Alerts carry no access key id and no provider
// key yet; those sources add "access_key:" / "provider_key:" indicators to
// agent_case_alert.indicators when they raise alerts.
//
// The window: a case is a candidate while its alerts' activity
// [min(first_seen), max(last_seen)] is within 24 h of the new alert's
// [first_seen, last_seen] (event time, so a backfilled batch clusters the way
// it happened). Of several candidates the most recently active wins.
//
// "A success breaks the group". What the detections record
// (internal/agentruntime/detect): D1-D4 fire only on a call that SUCCEEDED
// and did harm (read a secret, created credentials, changed IAM, weakened
// logging): a succeeded harmful outcome. D5 fires only on authorization
// denials: an attempt that was refused. D6-D8 are anomalies on successful
// calls that are not by themselves a harmful outcome (new model, spike, new
// role, new place): signals. A success-class alert does NOT join a candidate
// case that holds at least one attempt and no success: the refusals were one
// incident ("tried and was stopped"), the success is a new one ("got
// through"). A new case is opened and linked "related" to the attempt case.
// An unknown detection id (a later rule) is a signal.
//
// DECISIONS (W3):
//   - The case log is iga_gov_event (payload case_id; index
//     idx_iga_gov_event_case), not a table of its own: it is already
//     append-only (trigger), redacted before insert, shown in Logs and checked
//     by the event vocabulary test. A move writes an event on BOTH cases.
//   - All case writes of a workspace take one advisory lock
//     ("agent_case:<ws>"): case numbers are max+1 under it, and clustering
//     never races a move. The alert sink only TRIES the lock (it holds alert
//     row locks the API's foreign-key checks would wait on); when busy, or
//     when clustering fails, the alert is left out of every case under a
//     savepoint -- the alert itself is never lost -- and the cluster worker
//     (RunAgentCaseClusterWorker, every minute; also the backfill of alerts
//     raised before 186) places it.
//   - A case's severity is the highest of its alerts' and only rises by
//     itself; a person may raise it (tier 0). Lowering is tier 3 (a second
//     person, W5) and is refused here.
//   - Alerts in a closed case are frozen: they are not moved in or out until
//     the case is reopened. Notes may be added to a closed case.
//   - Closing pins the case's current alert evidence; so does an export.
//     outcome=duplicate needs duplicate_of (another case), recorded as a link.
//   - Tiers (P3) are recorded per action in AgentCaseActionTier for W5; until
//     then every write needs the alert routes' governance:enforce and a
//     verified member session.

// States, outcomes, relations.
const (
	AgentCaseOpen   = "open"
	AgentCaseClosed = "closed"

	AgentCaseOutcomeTruePositive  = "true_positive"
	AgentCaseOutcomeBenign        = "benign"
	AgentCaseOutcomeFalsePositive = "false_positive"
	AgentCaseOutcomeDuplicate     = "duplicate"

	AgentCaseLinkDuplicateOf = "duplicate_of"
	AgentCaseLinkRelated     = "related"
	AgentCaseLinkSplitFrom   = "split_from"

	// AgentCaseEvidenceSourceCloudTrail is the evidence source of an alert's
	// event references (CloudTrail events, from the poller or the stream).
	AgentCaseEvidenceSourceCloudTrail = "cloudtrail"

	// AgentCaseClusterWindow: see the package comment.
	AgentCaseClusterWindow = 24 * time.Hour

	agentCaseSystem        = "system"
	agentCaseSystemActorID = "agent_case_cluster"
	agentCaseMaxAlerts     = 100
	agentCaseMaxNote       = 10000
	agentCaseMaxTitle      = 300
	agentCaseMaxReason     = 1000
	agentCaseStopsLimit    = 100
	agentCaseClusterBatch  = 500
	// AgentCaseExportFormat names the export bundle's shape.
	AgentCaseExportFormat = "authsec.agent_case.v1"
)

// iga_gov_event names (iga_gov_event_vocabulary.go).
const (
	GovEventAgentCaseOpened         = "case.opened"
	GovEventAgentCaseAlertAdded     = "case.alert_added"
	GovEventAgentCaseAlertRemoved   = "case.alert_removed"
	GovEventAgentCaseLinked         = "case.linked"
	GovEventAgentCaseAssigned       = "case.assigned"
	GovEventAgentCaseNoteAdded      = "case.note_added"
	GovEventAgentCaseSplit          = "case.split"
	GovEventAgentCaseSeverityRaised = "case.severity_raised"
	GovEventAgentCaseClosed         = "case.closed"
	GovEventAgentCaseReopened       = "case.reopened"
	GovEventAgentCaseExported       = "case.exported"
)

// AgentCaseActionTier is each case action's tier (SPEC P3), for W5's static
// action -> tier map.
var AgentCaseActionTier = map[string]int{
	"read": 0, "close": 0, "export": 0, "raise_severity": 0,
	"open": 1, "assign": 1, "note": 1, "split": 1, "move_alerts": 1, "reopen": 1,
	"lower_severity": 3,
}

// Alert outcome classes (see the package comment).
const (
	AgentAlertClassSuccess = "success"
	AgentAlertClassAttempt = "attempt"
	AgentAlertClassSignal  = "signal"
)

var (
	agentCaseSuccessDetections = []string{string(detect.D1), string(detect.D2), string(detect.D3), string(detect.D4)}
	agentCaseAttemptDetections = []string{string(detect.D5)}
)

// AgentAlertOutcomeClass is the class of an alert's detection.
func AgentAlertOutcomeClass(detection string) string {
	for _, d := range agentCaseSuccessDetections {
		if d == detection {
			return AgentAlertClassSuccess
		}
	}
	for _, d := range agentCaseAttemptDetections {
		if d == detection {
			return AgentAlertClassAttempt
		}
	}
	return AgentAlertClassSignal
}

// agentCaseSeverityRank orders case severities ('low' ahead of the alerts).
func agentCaseSeverityRank(s string) int {
	switch s {
	case detect.SeverityHigh:
		return 3
	case detect.SeverityMedium:
		return 2
	case "low":
		return 1
	}
	return 0
}

// AgentCaseIndicators are an alert's clustering indicators, sorted.
func AgentCaseIndicators(identity uuid.UUID, workloads []uuid.UUID) []string {
	set := map[string]bool{}
	if identity != uuid.Nil {
		set["identity:"+identity.String()] = true
	}
	for _, w := range workloads {
		if w != uuid.Nil {
			set["workload:"+w.String()] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

/* ------------------------------------------------------------------------- */
/*                                Evidence pins                               */
/* ------------------------------------------------------------------------- */

// AgentCaseEvidenceRef names one pinned event.
type AgentCaseEvidenceRef struct {
	Source  string
	EventID string
}

// EvidencePinner is told about every pin a case takes or drops, so the
// evidence store (W1's agent_evidence_event) can keep pinned events past
// retention (pin_count). The default does nothing.
type EvidencePinner interface {
	Pin(tx *gorm.DB, ws, caseID uuid.UUID, refs []AgentCaseEvidenceRef) error
	Unpin(tx *gorm.DB, ws, caseID uuid.UUID, refs []AgentCaseEvidenceRef) error
}

type noopEvidencePinner struct{}

func (noopEvidencePinner) Pin(*gorm.DB, uuid.UUID, uuid.UUID, []AgentCaseEvidenceRef) error {
	return nil
}
func (noopEvidencePinner) Unpin(*gorm.DB, uuid.UUID, uuid.UUID, []AgentCaseEvidenceRef) error {
	return nil
}

var agentCaseEvidencePinner EvidencePinner = noopEvidencePinner{}

// SetAgentCaseEvidencePinner installs the evidence store's pinner (nil
// restores the no-op).
func SetAgentCaseEvidencePinner(p EvidencePinner) {
	if p == nil {
		p = noopEvidencePinner{}
	}
	agentCaseEvidencePinner = p
}

/* ------------------------------------------------------------------------- */
/*                                    Rows                                    */
/* ------------------------------------------------------------------------- */

// AgentCase is one agent_case row with its alert count and activity.
type AgentCase struct {
	ID             uuid.UUID  `json:"id" gorm:"column:id"`
	WorkspaceID    uuid.UUID  `json:"workspace_id" gorm:"column:workspace_id"`
	Number         int        `json:"number" gorm:"column:number"`
	Title          string     `json:"title" gorm:"column:title"`
	Severity       string     `json:"severity" gorm:"column:severity"`
	State          string     `json:"state" gorm:"column:state"`
	Outcome        *string    `json:"outcome" gorm:"column:outcome"`
	AssigneeUserID *uuid.UUID `json:"assignee_user_id" gorm:"column:assignee_user_id"`
	ClassifiedAt   *time.Time `json:"classified_at" gorm:"column:classified_at"`
	ClassifiedBy   *uuid.UUID `json:"classified_by" gorm:"column:classified_by"`
	ExerciseID     *uuid.UUID `json:"exercise_id" gorm:"column:exercise_id"`
	OpenedBy       string     `json:"opened_by" gorm:"column:opened_by"`
	OpenedAt       time.Time  `json:"opened_at" gorm:"column:opened_at"`
	ClosedBy       *uuid.UUID `json:"closed_by" gorm:"column:closed_by"`
	ClosedAt       *time.Time `json:"closed_at" gorm:"column:closed_at"`
	CloseReason    string     `json:"close_reason" gorm:"column:close_reason"`
	ReopenedCount  int        `json:"reopened_count" gorm:"column:reopened_count"`
	UpdatedAt      time.Time  `json:"updated_at" gorm:"column:updated_at"`
	AlertCount     int        `json:"alert_count" gorm:"column:alert_count"`
	LastActivityAt *time.Time `json:"last_activity_at" gorm:"column:last_activity_at"`
}

// AgentCaseAlert is an alert of a case with its membership.
type AgentCaseAlert struct {
	AgentAlert
	OutcomeClass string    `json:"outcome_class"`
	Indicators   []string  `json:"indicators"`
	AddedBy      string    `json:"added_by"`
	AddedAt      time.Time `json:"added_at"`
}

// AgentCaseEvidence is one agent_case_evidence row.
type AgentCaseEvidence struct {
	ID            uuid.UUID       `json:"id" gorm:"column:id"`
	Source        string          `json:"source" gorm:"column:source"`
	EventID       string          `json:"event_id" gorm:"column:event_id"`
	AlertID       *uuid.UUID      `json:"alert_id" gorm:"column:alert_id"`
	AlertEventRef json.RawMessage `json:"alert_event_ref" gorm:"column:alert_event_ref"`
	PinnedBy      string          `json:"pinned_by" gorm:"column:pinned_by"`
	PinnedAt      time.Time       `json:"pinned_at" gorm:"column:pinned_at"`
}

// AgentCaseNote is one agent_case_note row.
type AgentCaseNote struct {
	ID           uuid.UUID `json:"id" gorm:"column:id"`
	CaseID       uuid.UUID `json:"case_id" gorm:"column:case_id"`
	AuthorUserID uuid.UUID `json:"author_user_id" gorm:"column:author_user_id"`
	Body         string    `json:"body" gorm:"column:body"`
	CreatedAt    time.Time `json:"created_at" gorm:"column:created_at"`
}

// AgentCaseLink is one agent_case_link row (either end may be the case).
type AgentCaseLink struct {
	ID              uuid.UUID `json:"id" gorm:"column:id"`
	CaseID          uuid.UUID `json:"case_id" gorm:"column:case_id"`
	OtherCaseID     uuid.UUID `json:"other_case_id" gorm:"column:other_case_id"`
	OtherCaseNumber int       `json:"other_case_number" gorm:"column:other_case_number"`
	Relation        string    `json:"relation" gorm:"column:relation"`
	CreatedBy       string    `json:"created_by" gorm:"column:created_by"`
	CreatedAt       time.Time `json:"created_at" gorm:"column:created_at"`
}

// AgentCaseStop is a containment related to the case: held by it (W2's
// agent_containment_hold) or on one of its alerts' identities or workloads.
type AgentCaseStop struct {
	ID          uuid.UUID  `json:"id" gorm:"column:id"`
	IdentityID  uuid.UUID  `json:"identity_id" gorm:"column:identity_id"`
	IdentityARN string     `json:"identity_arn" gorm:"column:identity_arn"`
	Level       string     `json:"level" gorm:"column:level"`
	State       string     `json:"state" gorm:"column:state"`
	Effective   *bool      `json:"effective" gorm:"column:effective"`
	CreatedAt   time.Time  `json:"created_at" gorm:"column:created_at"`
	ContainedAt *time.Time `json:"contained_at" gorm:"column:contained_at"`
	ReleasedAt  *time.Time `json:"released_at" gorm:"column:released_at"`
	// LinkedBy is "hold" (the case holds the stop) or "identity" (the stop
	// is on an identity or workload of the case's alerts).
	LinkedBy string `json:"linked_by" gorm:"-"`
}

// AgentCaseView is GET /cases/:id.
type AgentCaseView struct {
	AgentCase
	Alerts   []AgentCaseAlert    `json:"alerts"`
	Evidence []AgentCaseEvidence `json:"evidence"`
	// Asks are the case's asks (W4: agent_ask.case_id).
	Asks  []AgentAskSummary   `json:"asks"`
	Stops []AgentCaseStop     `json:"stops"`
	Notes []AgentCaseNote     `json:"notes"`
	Links []AgentCaseLink     `json:"links"`
	Log   []AgentCaseLogEntry `json:"log"`
}

// agentCaseActor is who makes a change: the clustering ("system") or a user.
type agentCaseActor struct {
	kind string // models.GovActorSystem / GovActorUser
	id   string // event actor id
	by   string // the *_by column: "system" or the user id
	user *uuid.UUID
}

func agentCaseSystemActor() agentCaseActor {
	return agentCaseActor{kind: models.GovActorSystem, id: agentCaseSystemActorID, by: agentCaseSystem}
}

func agentCaseUserActor(u uuid.UUID) agentCaseActor {
	return agentCaseActor{kind: models.GovActorUser, id: u.String(), by: u.String(), user: &u}
}

/* ------------------------------------------------------------------------- */
/*                                 Low level                                  */
/* ------------------------------------------------------------------------- */

func errAgentCaseClosed(state string) error {
	return govErr(http.StatusConflict, "case_closed", "The case is closed; reopen it first.", map[string]any{"state": state})
}

// lockAgentCases takes the workspace's case lock for the transaction.
func lockAgentCases(tx *gorm.DB, ws uuid.UUID) error {
	return tx.Exec(`SELECT pg_advisory_xact_lock(hashtext(?))`, "agent_case:"+ws.String()).Error
}

// tryLockAgentCases takes it only if free.
func tryLockAgentCases(tx *gorm.DB, ws uuid.UUID) (bool, error) {
	var ok bool
	err := tx.Raw(`SELECT pg_try_advisory_xact_lock(hashtext(?))`, "agent_case:"+ws.String()).Scan(&ok).Error
	return ok, err
}

const agentCaseSelect = `SELECT c.id, c.workspace_id, c.number, c.title, c.severity, c.state, c.outcome, c.assignee_user_id,
	c.classified_at, c.classified_by, c.exercise_id, c.opened_by, c.opened_at, c.closed_by, c.closed_at, c.close_reason,
	c.reopened_count, c.updated_at,
	(SELECT count(*) FROM agent_case_alert ca WHERE ca.workspace_id = c.workspace_id AND ca.case_id = c.id) AS alert_count,
	(SELECT max(a.last_seen) FROM agent_case_alert ca JOIN agent_alert a ON a.workspace_id = ca.workspace_id AND a.id = ca.alert_id
	  WHERE ca.workspace_id = c.workspace_id AND ca.case_id = c.id) AS last_activity_at
	FROM agent_case c`

// getAgentCase reads one case of ws (404 when absent or another workspace's).
func getAgentCase(tx *gorm.DB, ws, id uuid.UUID) (*AgentCase, error) {
	var rows []AgentCase
	if err := tx.Raw(agentCaseSelect+` WHERE c.workspace_id = ? AND c.id = ?`, ws, id).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, GovNotFound()
	}
	return &rows[0], nil
}

// agentCaseAlertRow is an alert as clustering and moves read it, with its
// current case.
type agentCaseAlertRow struct {
	ID          uuid.UUID
	IdentityID  uuid.UUID
	WorkloadIDs json.RawMessage
	Detection   string
	Severity    string
	Title       string
	FirstSeen   time.Time
	LastSeen    time.Time
	Evidence    json.RawMessage
	CaseID      *uuid.UUID
	CaseState   *string
}

func (r agentCaseAlertRow) indicators() []string {
	var ids []uuid.UUID
	if len(r.WorkloadIDs) > 0 {
		_ = json.Unmarshal(r.WorkloadIDs, &ids) // unreadable: the identity alone
	}
	return AgentCaseIndicators(r.IdentityID, ids)
}

// loadAgentCaseAlerts reads alerts of ws by id; an id of another workspace
// or none is absent from the map.
func loadAgentCaseAlerts(tx *gorm.DB, ws uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]agentCaseAlertRow, error) {
	out := map[uuid.UUID]agentCaseAlertRow{}
	if len(ids) == 0 {
		return out, nil
	}
	var rows []agentCaseAlertRow
	if err := tx.Raw(`SELECT a.id, a.identity_id, a.workload_ids, a.detection, a.severity, a.title, a.first_seen, a.last_seen,
	                         a.evidence, ca.case_id, c.state AS case_state
	                    FROM agent_alert a
	                    LEFT JOIN agent_case_alert ca ON ca.workspace_id = a.workspace_id AND ca.alert_id = a.id
	                    LEFT JOIN agent_case c ON c.workspace_id = ca.workspace_id AND c.id = ca.case_id
	                   WHERE a.workspace_id = ? AND a.id IN ?`, ws, ids).Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.ID] = r
	}
	return out, nil
}

// openAgentCase opens a case (number max+1 under the workspace's case lock).
func openAgentCase(tx *gorm.DB, ws uuid.UUID, title, severity string, exercise *uuid.UUID, act agentCaseActor, now time.Time, extra map[string]any) (uuid.UUID, int, error) {
	var number int
	if err := tx.Raw(`SELECT COALESCE(max(number), 0) + 1 FROM agent_case WHERE workspace_id = ?`, ws).Scan(&number).Error; err != nil {
		return uuid.Nil, 0, err
	}
	title = strings.TrimSpace(title)
	if title == "" {
		title = fmt.Sprintf("Case %d", number)
	}
	title = truncateRunes(title, agentCaseMaxTitle)
	if agentCaseSeverityRank(severity) == 0 {
		severity = detect.SeverityMedium
	}
	var ids []uuid.UUID
	if err := tx.Raw(`INSERT INTO agent_case (workspace_id, number, title, severity, state, exercise_id, opened_by, opened_at, updated_at)
	                  VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?) RETURNING id`,
		ws, number, title, severity, exercise, act.by, now, now).Scan(&ids).Error; err != nil {
		return uuid.Nil, 0, err
	}
	if len(ids) != 1 {
		return uuid.Nil, 0, errors.New("agent case insert returned no id")
	}
	payload := map[string]any{"case_id": ids[0], "number": number, "severity": severity, "opened_by": act.by}
	if exercise != nil {
		payload["exercise_id"] = *exercise
	}
	for k, v := range extra {
		payload[k] = v
	}
	if err := appendGovEvent(tx, ws, GovEventAgentCaseOpened, act.kind, act.id, govEventRefs{}, payload); err != nil {
		return uuid.Nil, 0, err
	}
	return ids[0], number, nil
}

// addAlertToAgentCase puts a (case-less) alert in caseID: membership, the
// case's severity raised to the alert's, its evidence pinned, logged.
func addAlertToAgentCase(tx *gorm.DB, ws, caseID uuid.UUID, a agentCaseAlertRow, from *uuid.UUID, act agentCaseActor, now time.Time) error {
	if err := tx.Exec(`INSERT INTO agent_case_alert (workspace_id, case_id, alert_id, indicators, added_by, added_at)
	                   VALUES (?, ?, ?, ?::text[], ?, ?)`,
		ws, caseID, a.ID, pq.StringArray(a.indicators()), act.by, now).Error; err != nil {
		return err
	}
	if err := raiseAgentCaseSeverity(tx, ws, caseID, a.Severity, now); err != nil {
		return err
	}
	if from != nil {
		if err := moveAgentCaseAlertEvidence(tx, ws, *from, caseID, a.ID); err != nil {
			return err
		}
	}
	if _, err := pinAgentCaseAlertEvidence(tx, ws, caseID, a.ID, a.Evidence, act.by, now); err != nil {
		return err
	}
	payload := map[string]any{"case_id": caseID, "alert_id": a.ID, "detection": a.Detection, "severity": a.Severity,
		"outcome_class": AgentAlertOutcomeClass(a.Detection)}
	if from != nil {
		payload["from_case_id"] = *from
	}
	if err := appendGovEvent(tx, ws, GovEventAgentCaseAlertAdded, act.kind, act.id, govEventRefs{}, payload); err != nil {
		return err
	}
	return touchAgentCase(tx, ws, caseID, now)
}

// removeAlertFromAgentCase takes an alert out of its case (to another),
// logged on the case it leaves.
func removeAlertFromAgentCase(tx *gorm.DB, ws, caseID, alertID, to uuid.UUID, act agentCaseActor, now time.Time) error {
	if err := tx.Exec(`DELETE FROM agent_case_alert WHERE workspace_id = ? AND case_id = ? AND alert_id = ?`, ws, caseID, alertID).Error; err != nil {
		return err
	}
	if err := appendGovEvent(tx, ws, GovEventAgentCaseAlertRemoved, act.kind, act.id, govEventRefs{},
		map[string]any{"case_id": caseID, "alert_id": alertID, "to_case_id": to}); err != nil {
		return err
	}
	return touchAgentCase(tx, ws, caseID, now)
}

// moveAlertToAgentCase moves an alert (in an open case or none) into caseID,
// logging both cases.
func moveAlertToAgentCase(tx *gorm.DB, ws, caseID uuid.UUID, a agentCaseAlertRow, act agentCaseActor, now time.Time) error {
	if a.CaseID != nil && *a.CaseID == caseID {
		return nil
	}
	if a.CaseID != nil {
		if err := removeAlertFromAgentCase(tx, ws, *a.CaseID, a.ID, caseID, act, now); err != nil {
			return err
		}
	}
	return addAlertToAgentCase(tx, ws, caseID, a, a.CaseID, act, now)
}

func touchAgentCase(tx *gorm.DB, ws, caseID uuid.UUID, now time.Time) error {
	return tx.Exec(`UPDATE agent_case SET updated_at = GREATEST(updated_at, ?) WHERE workspace_id = ? AND id = ?`, now, ws, caseID).Error
}

// raiseAgentCaseSeverity raises the case's severity to sev when higher.
func raiseAgentCaseSeverity(tx *gorm.DB, ws, caseID uuid.UUID, sev string, now time.Time) error {
	var cur string
	if err := tx.Raw(`SELECT severity FROM agent_case WHERE workspace_id = ? AND id = ?`, ws, caseID).Scan(&cur).Error; err != nil {
		return err
	}
	if agentCaseSeverityRank(sev) <= agentCaseSeverityRank(cur) {
		return nil
	}
	return tx.Exec(`UPDATE agent_case SET severity = ?, updated_at = ? WHERE workspace_id = ? AND id = ?`, sev, now, ws, caseID).Error
}

// linkAgentCases records caseID -relation-> other, logged on both cases.
func linkAgentCases(tx *gorm.DB, ws, caseID, other uuid.UUID, relation string, act agentCaseActor, now time.Time) error {
	res := tx.Exec(`INSERT INTO agent_case_link (workspace_id, case_id, other_case_id, relation, created_by, created_at)
	                VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (workspace_id, case_id, other_case_id, relation) DO NOTHING`,
		ws, caseID, other, relation, act.by, now)
	if res.Error != nil || res.RowsAffected == 0 {
		return res.Error
	}
	if err := appendGovEvent(tx, ws, GovEventAgentCaseLinked, act.kind, act.id, govEventRefs{},
		map[string]any{"case_id": caseID, "other_case_id": other, "relation": relation, "direction": "outgoing"}); err != nil {
		return err
	}
	return appendGovEvent(tx, ws, GovEventAgentCaseLinked, act.kind, act.id, govEventRefs{},
		map[string]any{"case_id": other, "other_case_id": caseID, "relation": relation, "direction": "incoming"})
}

// pinAgentCaseAlertEvidence pins an alert's evidence references to caseID
// and returns how many were new.
func pinAgentCaseAlertEvidence(tx *gorm.DB, ws, caseID, alertID uuid.UUID, evidence json.RawMessage, by string, now time.Time) (int, error) {
	var refs []AgentAlertEventRef
	if len(evidence) > 0 {
		if err := json.Unmarshal(evidence, &refs); err != nil {
			return 0, nil // unreadable evidence pins nothing, never fatal
		}
	}
	var pinned []AgentCaseEvidenceRef
	for _, r := range refs {
		id := truncate(strings.TrimSpace(r.EventID), 256)
		if id == "" {
			continue
		}
		raw, err := json.Marshal(r)
		if err != nil {
			return 0, err
		}
		res := tx.Exec(`INSERT INTO agent_case_evidence (workspace_id, case_id, source, event_id, alert_id, alert_event_ref, pinned_by, pinned_at)
		                VALUES (?, ?, ?, ?, ?, ?::jsonb, ?, ?) ON CONFLICT DO NOTHING`,
			ws, caseID, AgentCaseEvidenceSourceCloudTrail, id, alertID, string(raw), by, now)
		if res.Error != nil {
			return 0, res.Error
		}
		if res.RowsAffected == 1 {
			pinned = append(pinned, AgentCaseEvidenceRef{Source: AgentCaseEvidenceSourceCloudTrail, EventID: id})
		}
	}
	if len(pinned) == 0 {
		return 0, nil
	}
	return len(pinned), agentCaseEvidencePinner.Pin(tx, ws, caseID, pinned)
}

// moveAgentCaseAlertEvidence moves the pins an alert brought from one case
// to another.
func moveAgentCaseAlertEvidence(tx *gorm.DB, ws, from, to, alertID uuid.UUID) error {
	var rows []struct {
		Source  string
		EventID string
	}
	if err := tx.Raw(`UPDATE agent_case_evidence SET case_id = ? WHERE workspace_id = ? AND case_id = ? AND alert_id = ?
	                  RETURNING source, event_id`, to, ws, from, alertID).Scan(&rows).Error; err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	refs := make([]AgentCaseEvidenceRef, 0, len(rows))
	for _, r := range rows {
		refs = append(refs, AgentCaseEvidenceRef{Source: r.Source, EventID: r.EventID})
	}
	if err := agentCaseEvidencePinner.Unpin(tx, ws, from, refs); err != nil {
		return err
	}
	return agentCaseEvidencePinner.Pin(tx, ws, to, refs)
}

// pinAgentCaseEvidenceNow pins the current evidence of every alert in caseID.
func pinAgentCaseEvidenceNow(tx *gorm.DB, ws, caseID uuid.UUID, by string, now time.Time) error {
	var rows []struct {
		ID       uuid.UUID
		Evidence json.RawMessage
	}
	if err := tx.Raw(`SELECT a.id, a.evidence FROM agent_case_alert ca
	                    JOIN agent_alert a ON a.workspace_id = ca.workspace_id AND a.id = ca.alert_id
	                   WHERE ca.workspace_id = ? AND ca.case_id = ? ORDER BY a.id`, ws, caseID).Scan(&rows).Error; err != nil {
		return err
	}
	for _, r := range rows {
		if _, err := pinAgentCaseAlertEvidence(tx, ws, caseID, r.ID, r.Evidence, by, now); err != nil {
			return err
		}
	}
	return nil
}

/* ------------------------------------------------------------------------- */
/*                                 Clustering                                 */
/* ------------------------------------------------------------------------- */

type agentCaseCandidate struct {
	ID           uuid.UUID
	LastActivity time.Time
	HasSuccess   bool
	HasAttempt   bool
}

// clusterAgentAlert places a case-less alert of ws (the case lock held):
// it joins the most recently active open case sharing an indicator within
// the window, unless a success would join an attempts-only case; else a case
// is opened. It returns the case.
func clusterAgentAlert(tx *gorm.DB, ws, alertID uuid.UUID, now time.Time) (uuid.UUID, error) {
	rows, err := loadAgentCaseAlerts(tx, ws, []uuid.UUID{alertID})
	if err != nil {
		return uuid.Nil, err
	}
	a, ok := rows[alertID]
	if !ok {
		return uuid.Nil, GovNotFound()
	}
	if a.CaseID != nil {
		return *a.CaseID, nil
	}
	act := agentCaseSystemActor()
	ind := a.indicators()
	var cands []agentCaseCandidate
	if len(ind) > 0 {
		if err := tx.Raw(`SELECT c.id, max(a.last_seen) AS last_activity,
		                         bool_or(a.detection IN ?) AS has_success, bool_or(a.detection IN ?) AS has_attempt
		                    FROM agent_case c
		                    JOIN agent_case_alert ca ON ca.workspace_id = c.workspace_id AND ca.case_id = c.id
		                    JOIN agent_alert a ON a.workspace_id = ca.workspace_id AND a.id = ca.alert_id
		                   WHERE c.workspace_id = ? AND c.state = 'open'
		                     AND c.id IN (SELECT m.case_id FROM agent_case_alert m WHERE m.workspace_id = ? AND m.indicators && ?::text[])
		                   GROUP BY c.id
		                  HAVING max(a.last_seen) >= ? AND min(a.first_seen) <= ?
		                   ORDER BY max(a.last_seen) DESC, c.id`,
			agentCaseSuccessDetections, agentCaseAttemptDetections, ws, ws, pq.StringArray(ind),
			a.FirstSeen.Add(-AgentCaseClusterWindow), a.LastSeen.Add(AgentCaseClusterWindow)).Scan(&cands).Error; err != nil {
			return uuid.Nil, err
		}
	}
	var related *uuid.UUID
	if len(cands) > 0 {
		c := cands[0]
		if !(AgentAlertOutcomeClass(a.Detection) == AgentAlertClassSuccess && c.HasAttempt && !c.HasSuccess) {
			return c.ID, addAlertToAgentCase(tx, ws, c.ID, a, nil, act, now)
		}
		related = &c.ID // a success breaks the group
	}
	extra := map[string]any{"alert_id": a.ID}
	if related != nil {
		extra["related_to"] = *related
		extra["reason"] = "success_after_attempts"
	}
	caseID, _, err := openAgentCase(tx, ws, a.Title, a.Severity, nil, act, now, extra)
	if err != nil {
		return uuid.Nil, err
	}
	if err := addAlertToAgentCase(tx, ws, caseID, a, nil, act, now); err != nil {
		return uuid.Nil, err
	}
	if related != nil {
		if err := linkAgentCases(tx, ws, caseID, *related, AgentCaseLinkRelated, act, now); err != nil {
			return uuid.Nil, err
		}
	}
	return caseID, nil
}

// clusterNewAgentAlert is the alert sink's hook (upsertAgentAlert, a new
// alert): it places the alert in a case under a savepoint, so a failure, a
// busy case lock or a missing 186 never loses the alert; the cluster worker
// places what is left.
func clusterNewAgentAlert(tx *gorm.DB, ws, alertID uuid.UUID, now time.Time) {
	if err := tx.Exec(`SAVEPOINT agent_case_cluster`).Error; err != nil {
		log.Printf("[agent-cases] workspace %s alert %s: savepoint: %v", ws, alertID, err)
		return
	}
	err := func() error {
		if ok, _ := agentCasesGate.status(tx); !ok {
			return nil
		}
		locked, err := tryLockAgentCases(tx, ws)
		if err != nil || !locked {
			return err // busy: the worker places it
		}
		_, err = clusterAgentAlert(tx, ws, alertID, now)
		return err
	}()
	if err != nil {
		log.Printf("[agent-cases] workspace %s alert %s: left for the cluster worker: %v", ws, alertID, err)
		if rerr := tx.Exec(`ROLLBACK TO SAVEPOINT agent_case_cluster`).Error; rerr != nil {
			log.Printf("[agent-cases] workspace %s: rollback to savepoint: %v", ws, rerr)
		}
		return
	}
	_ = tx.Exec(`RELEASE SAVEPOINT agent_case_cluster`).Error
}

/* ------------------------------------------------------------------------- */
/*                                  Service                                   */
/* ------------------------------------------------------------------------- */

// AgentCaseService serves the case API and the cluster worker.
type AgentCaseService struct {
	db  *gorm.DB
	now func() time.Time
}

// NewAgentCaseService builds the service over db.
func NewAgentCaseService(db *gorm.DB) *AgentCaseService {
	return &AgentCaseService{db: db, now: time.Now}
}

// WithClock replaces the wall clock (tests).
func (s *AgentCaseService) WithClock(now func() time.Time) *AgentCaseService {
	s.now = now
	return s
}

// write runs fn in ws's transaction holding the case lock.
func (s *AgentCaseService) write(ctx context.Context, ws uuid.UUID, fn func(tx *gorm.DB, now time.Time) error) error {
	now := s.now().UTC()
	return tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		if err := lockAgentCases(tx, ws); err != nil {
			return err
		}
		return fn(tx, now)
	})
}

// AgentCaseExistsTx reports whether case id is ws's, on a transaction under
// RLS for ws (W2's holds check their case with it).
func AgentCaseExistsTx(tx *gorm.DB, ws, id uuid.UUID) (bool, error) {
	var n int64
	err := tx.Raw(`SELECT count(*) FROM agent_case WHERE workspace_id = ? AND id = ?`, ws, id).Scan(&n).Error
	return n > 0, err
}

// CaseExists reports whether case id is ws's (another workspace's: false).
func (s *AgentCaseService) CaseExists(ctx context.Context, ws, id uuid.UUID) (bool, error) {
	var ok bool
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		ok, err = AgentCaseExistsTx(tx, ws, id)
		return err
	})
	return ok, err
}

// AgentCaseFilter filters GET /cases.
type AgentCaseFilter struct {
	State, Severity string
	// Assignee: a user, or Unassigned for cases with none.
	Assignee   *uuid.UUID
	Unassigned bool
	// Agent: an identity or workload of one of the case's alerts.
	Agent *uuid.UUID
}

// Validate checks the filter's values.
func (f AgentCaseFilter) Validate() error {
	switch f.State {
	case "", AgentCaseOpen, AgentCaseClosed:
	default:
		return GovBadParam("state", "state must be open or closed.")
	}
	if f.Severity != "" && agentCaseSeverityRank(f.Severity) == 0 {
		return GovBadParam("severity", "severity must be high, medium or low.")
	}
	return nil
}

// List is GET /cases: newest first (opened_at, id), limit 1..200.
func (s *AgentCaseService) List(ctx context.Context, ws uuid.UUID, f AgentCaseFilter, cursor string, limit int) ([]AgentCase, string, error) {
	if err := f.Validate(); err != nil {
		return nil, "", err
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > MaxGovPage {
		limit = MaxGovPage
	}
	q := agentCaseSelect + ` WHERE c.workspace_id = ?`
	args := []any{ws}
	if f.State != "" {
		q += ` AND c.state = ?`
		args = append(args, f.State)
	}
	if f.Severity != "" {
		q += ` AND c.severity = ?`
		args = append(args, f.Severity)
	}
	if f.Unassigned {
		q += ` AND c.assignee_user_id IS NULL`
	} else if f.Assignee != nil {
		q += ` AND c.assignee_user_id = ?`
		args = append(args, *f.Assignee)
	}
	if f.Agent != nil {
		q += ` AND EXISTS (SELECT 1 FROM agent_case_alert m WHERE m.workspace_id = c.workspace_id AND m.case_id = c.id
		                     AND m.indicators && ?::text[])`
		args = append(args, pq.StringArray{"identity:" + f.Agent.String(), "workload:" + f.Agent.String()})
	}
	if cursor != "" {
		t, id, err := decodeAgentAlertCursor(cursor)
		if err != nil {
			return nil, "", GovBadParam("cursor", "The cursor is not valid.")
		}
		q += ` AND (c.opened_at, c.id) < (?, ?)`
		args = append(args, t, id)
	}
	q += ` ORDER BY c.opened_at DESC, c.id DESC LIMIT ?`
	args = append(args, limit+1)
	var rows []AgentCase
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(q, args...).Scan(&rows).Error
	}); err != nil {
		return nil, "", err
	}
	next := ""
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		next = encodeAgentAlertCursor(last.OpenedAt, last.ID)
	}
	if rows == nil {
		rows = []AgentCase{}
	}
	return rows, next, nil
}

// Get is GET /cases/:id.
func (s *AgentCaseService) Get(ctx context.Context, ws, id uuid.UUID) (*AgentCaseView, error) {
	var out *AgentCaseView
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		v, err := readAgentCaseView(tx, ws, id, false)
		out = v
		return err
	})
	return out, err
}

type agentCaseMemberRow struct {
	AlertID    uuid.UUID
	Indicators pq.StringArray
	AddedBy    string
	AddedAt    time.Time
}

// readAgentCaseView reads a case with everything attached; forExport leaves
// case.exported events out of the log (they describe exports, not the case,
// and would change every later export's hash).
func readAgentCaseView(tx *gorm.DB, ws, id uuid.UUID, forExport bool) (*AgentCaseView, error) {
	c, err := getAgentCase(tx, ws, id)
	if err != nil {
		return nil, err
	}
	v := &AgentCaseView{AgentCase: *c, Alerts: []AgentCaseAlert{}, Evidence: []AgentCaseEvidence{}, Asks: []AgentAskSummary{},
		Stops: []AgentCaseStop{}, Notes: []AgentCaseNote{}, Links: []AgentCaseLink{}, Log: []AgentCaseLogEntry{}}
	var members []agentCaseMemberRow
	if err := tx.Raw(`SELECT alert_id, indicators, added_by, added_at FROM agent_case_alert
	                   WHERE workspace_id = ? AND case_id = ?`, ws, id).Scan(&members).Error; err != nil {
		return nil, err
	}
	if len(members) > 0 {
		ids := make([]uuid.UUID, 0, len(members))
		byID := map[uuid.UUID]agentCaseMemberRow{}
		for _, m := range members {
			ids = append(ids, m.AlertID)
			byID[m.AlertID] = m
		}
		var alerts []AgentAlert
		if err := tx.Raw(`SELECT `+agentAlertColumns+` FROM agent_alert WHERE workspace_id = ? AND id IN ?
		                   ORDER BY created_at, id`, ws, ids).Scan(&alerts).Error; err != nil {
			return nil, err
		}
		for _, a := range alerts {
			m := byID[a.ID]
			ind := []string(m.Indicators)
			if ind == nil {
				ind = []string{}
			}
			v.Alerts = append(v.Alerts, AgentCaseAlert{AgentAlert: a, OutcomeClass: AgentAlertOutcomeClass(a.Detection),
				Indicators: ind, AddedBy: m.AddedBy, AddedAt: m.AddedAt})
		}
	}
	if err := tx.Raw(`SELECT id, source, event_id, alert_id, alert_event_ref, pinned_by, pinned_at FROM agent_case_evidence
	                   WHERE workspace_id = ? AND case_id = ? ORDER BY pinned_at, source, event_id, id`, ws, id).Scan(&v.Evidence).Error; err != nil {
		return nil, err
	}
	if err := tx.Raw(`SELECT id, case_id, author_user_id, body, created_at FROM agent_case_note
	                   WHERE workspace_id = ? AND case_id = ? ORDER BY created_at, id`, ws, id).Scan(&v.Notes).Error; err != nil {
		return nil, err
	}
	if err := tx.Raw(`SELECT l.id, l.case_id, l.other_case_id, o.number AS other_case_number, l.relation, l.created_by, l.created_at
	                    FROM agent_case_link l
	                    JOIN agent_case o ON o.workspace_id = l.workspace_id
	                     AND o.id = CASE WHEN l.case_id = ? THEN l.other_case_id ELSE l.case_id END
	                   WHERE l.workspace_id = ? AND (l.case_id = ? OR l.other_case_id = ?)
	                   ORDER BY l.created_at, l.id`, id, ws, id, id).Scan(&v.Links).Error; err != nil {
		return nil, err
	}
	asks, err := readCaseAsks(tx, ws, id)
	if err != nil {
		return nil, err
	}
	v.Asks = asks
	stops, err := readAgentCaseStops(tx, ws, id, v.Alerts)
	if err != nil {
		return nil, err
	}
	v.Stops = stops
	entries, err := readAgentCaseLog(tx, ws, id, forExport)
	if err != nil {
		return nil, err
	}
	v.Log = entries
	if v.Evidence == nil {
		v.Evidence = []AgentCaseEvidence{}
	}
	if v.Notes == nil {
		v.Notes = []AgentCaseNote{}
	}
	if v.Links == nil {
		v.Links = []AgentCaseLink{}
	}
	return v, nil
}

// readAgentCaseStops lists containments the case holds (W2's
// agent_containment_hold, when present) and those on its alerts' identities
// or workloads (agent_containment, migration 151, when present).
func readAgentCaseStops(tx *gorm.DB, ws, caseID uuid.UUID, alerts []AgentCaseAlert) ([]AgentCaseStop, error) {
	out := []AgentCaseStop{}
	var present bool
	if err := tx.Raw(`SELECT to_regclass('public.agent_containment') IS NOT NULL`).Scan(&present).Error; err != nil || !present {
		return out, err
	}
	const cols = `SELECT id, identity_id, identity_arn, level, state, effective, created_at, contained_at, released_at FROM agent_containment`
	seen := map[uuid.UUID]bool{}
	var holdCols int64
	// TENANT-EXEMPT: Postgres catalog (information_schema), whether W2's hold table is there.
	if err := tx.Raw(`SELECT count(*) FROM information_schema.columns
	                   WHERE table_schema = 'public' AND table_name = 'agent_containment_hold'
	                     AND column_name IN ('workspace_id', 'containment_id', 'case_id')`).Scan(&holdCols).Error; err != nil {
		return nil, err
	}
	if holdCols == 3 {
		var held []AgentCaseStop
		if err := tx.Raw(cols+` WHERE workspace_id = ? AND id IN
		                    (SELECT h.containment_id FROM agent_containment_hold h WHERE h.workspace_id = ? AND h.case_id = ?)
		                   ORDER BY created_at DESC, id`, ws, ws, caseID).Scan(&held).Error; err != nil {
			return nil, err
		}
		for _, h := range held {
			h.LinkedBy = "hold"
			seen[h.ID] = true
			out = append(out, h)
		}
	}
	var identities, workloads []string
	idSeen := map[string]bool{}
	for _, a := range alerts {
		if a.IdentityID != uuid.Nil && !idSeen[a.IdentityID.String()] {
			idSeen[a.IdentityID.String()] = true
			identities = append(identities, a.IdentityID.String())
		}
		for _, ind := range a.Indicators {
			if w, ok := strings.CutPrefix(ind, "workload:"); ok && !idSeen[w] {
				idSeen[w] = true
				workloads = append(workloads, w)
			}
		}
	}
	if len(identities)+len(workloads) == 0 {
		return out, nil
	}
	var rel []AgentCaseStop
	if err := tx.Raw(cols+` WHERE workspace_id = ? AND (identity_id = ANY(?::uuid[]) OR workload_ids && ?::uuid[])
	                   ORDER BY created_at DESC, id LIMIT ?`,
		ws, pq.StringArray(identities), pq.StringArray(workloads), agentCaseStopsLimit).Scan(&rel).Error; err != nil {
		return nil, err
	}
	for _, r := range rel {
		if seen[r.ID] {
			continue
		}
		r.LinkedBy = "identity"
		out = append(out, r)
	}
	return out, nil
}

// AgentCaseCreate is POST /cases.
type AgentCaseCreate struct {
	AlertIDs   []uuid.UUID `json:"alert_ids"`
	Title      string      `json:"title"`
	ExerciseID *uuid.UUID  `json:"exercise_id"`
}

// validateAgentCaseAlertIDs dedupes ids and bounds their number.
func validateAgentCaseAlertIDs(ids []uuid.UUID) ([]uuid.UUID, error) {
	seen := map[uuid.UUID]bool{}
	var out []uuid.UUID
	for _, id := range ids {
		if id == uuid.Nil || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	if len(out) == 0 {
		return nil, GovBadParam("alert_ids", "alert_ids must name at least one alert.")
	}
	if len(out) > agentCaseMaxAlerts {
		return nil, GovBadParam("alert_ids", fmt.Sprintf("alert_ids may name at most %d alerts.", agentCaseMaxAlerts))
	}
	return out, nil
}

// movableAgentCaseAlerts reads ids for a move: every one must be ws's (else
// 404) and not in a closed case (409).
func movableAgentCaseAlerts(tx *gorm.DB, ws uuid.UUID, ids []uuid.UUID) ([]agentCaseAlertRow, error) {
	rows, err := loadAgentCaseAlerts(tx, ws, ids)
	if err != nil {
		return nil, err
	}
	out := make([]agentCaseAlertRow, 0, len(ids))
	for _, id := range ids {
		r, ok := rows[id]
		if !ok {
			return nil, govErr(http.StatusNotFound, "not_found", "Not found.", map[string]any{"alert_id": id})
		}
		if r.CaseState != nil && *r.CaseState == AgentCaseClosed {
			return nil, govErr(http.StatusConflict, "alert_case_closed", "The alert is in a closed case; reopen that case first.",
				map[string]any{"alert_id": id, "case_id": r.CaseID})
		}
		out = append(out, r)
	}
	return out, nil
}

func maxAgentCaseSeverity(rows []agentCaseAlertRow) string {
	sev := ""
	for _, r := range rows {
		if agentCaseSeverityRank(r.Severity) > agentCaseSeverityRank(sev) {
			sev = r.Severity
		}
	}
	return sev
}

// Create is POST /cases: a case of the given alerts (moved out of their
// current, open, cases).
func (s *AgentCaseService) Create(ctx context.Context, ws, actor uuid.UUID, in AgentCaseCreate) (*AgentCase, error) {
	ids, err := validateAgentCaseAlertIDs(in.AlertIDs)
	if err != nil {
		return nil, err
	}
	if utf8.RuneCountInString(strings.TrimSpace(in.Title)) > agentCaseMaxTitle {
		return nil, GovBadParam("title", "title must be at most 300 characters.")
	}
	act := agentCaseUserActor(actor)
	var out *AgentCase
	err = s.write(ctx, ws, func(tx *gorm.DB, now time.Time) error {
		rows, err := movableAgentCaseAlerts(tx, ws, ids)
		if err != nil {
			return err
		}
		title := in.Title
		if strings.TrimSpace(title) == "" {
			title = rows[0].Title
		}
		caseID, _, err := openAgentCase(tx, ws, title, maxAgentCaseSeverity(rows), in.ExerciseID, act, now, nil)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if err := moveAlertToAgentCase(tx, ws, caseID, r, act, now); err != nil {
				return err
			}
		}
		out, err = getAgentCase(tx, ws, caseID)
		return err
	})
	return out, err
}

// openAgentCaseForWrite reads a case that must be open.
func openAgentCaseForWrite(tx *gorm.DB, ws, id uuid.UUID) (*AgentCase, error) {
	c, err := getAgentCase(tx, ws, id)
	if err != nil {
		return nil, err
	}
	if c.State != AgentCaseOpen {
		return nil, errAgentCaseClosed(c.State)
	}
	return c, nil
}

// Assign is POST /cases/:id/assign: assignee must be an active member of
// ws; nil unassigns.
func (s *AgentCaseService) Assign(ctx context.Context, ws, id, actor uuid.UUID, assignee *uuid.UUID) (*AgentCase, error) {
	act := agentCaseUserActor(actor)
	var out *AgentCase
	err := s.write(ctx, ws, func(tx *gorm.DB, now time.Time) error {
		c, err := openAgentCaseForWrite(tx, ws, id)
		if err != nil {
			return err
		}
		if assignee != nil {
			var n int64
			if err := tx.Raw(`SELECT count(*) FROM workspace_memberships WHERE workspace_id = ? AND user_id = ? AND status = 'active'`,
				ws, *assignee).Scan(&n).Error; err != nil {
				return err
			}
			if n == 0 {
				return govErr(http.StatusBadRequest, "assignee_not_member", "The assignee must be an active member of this workspace.",
					map[string]any{"parameter": "assignee_user_id"})
			}
		}
		same := (c.AssigneeUserID == nil && assignee == nil) || (c.AssigneeUserID != nil && assignee != nil && *c.AssigneeUserID == *assignee)
		if same {
			out = c
			return nil
		}
		if err := tx.Exec(`UPDATE agent_case SET assignee_user_id = ?, updated_at = ? WHERE workspace_id = ? AND id = ?`,
			assignee, now, ws, id).Error; err != nil {
			return err
		}
		if err := appendGovEvent(tx, ws, GovEventAgentCaseAssigned, act.kind, act.id, govEventRefs{},
			map[string]any{"case_id": id, "from_user_id": c.AssigneeUserID, "to_user_id": assignee}); err != nil {
			return err
		}
		out, err = getAgentCase(tx, ws, id)
		return err
	})
	return out, err
}

// AddNote is POST /cases/:id/notes (append-only; a closed case takes notes).
func (s *AgentCaseService) AddNote(ctx context.Context, ws, id, actor uuid.UUID, body string) (*AgentCaseNote, error) {
	body = strings.TrimSpace(body)
	if body == "" {
		return nil, GovBadParam("body", "body must not be empty.")
	}
	if utf8.RuneCountInString(body) > agentCaseMaxNote {
		return nil, GovBadParam("body", "body must be at most 10000 characters.")
	}
	act := agentCaseUserActor(actor)
	var out *AgentCaseNote
	err := s.write(ctx, ws, func(tx *gorm.DB, now time.Time) error {
		if _, err := getAgentCase(tx, ws, id); err != nil {
			return err
		}
		var notes []AgentCaseNote
		if err := tx.Raw(`INSERT INTO agent_case_note (workspace_id, case_id, author_user_id, body, created_at)
		                  VALUES (?, ?, ?, ?, ?) RETURNING id, case_id, author_user_id, body, created_at`,
			ws, id, actor, body, now).Scan(&notes).Error; err != nil {
			return err
		}
		if len(notes) != 1 {
			return errors.New("agent case note insert returned no row")
		}
		if err := appendGovEvent(tx, ws, GovEventAgentCaseNoteAdded, act.kind, act.id, govEventRefs{},
			map[string]any{"case_id": id, "note_id": notes[0].ID, "length": utf8.RuneCountInString(body)}); err != nil {
			return err
		}
		out = &notes[0]
		return touchAgentCase(tx, ws, id, now)
	})
	return out, err
}

// caseAlertsIn reads ids that must all be alerts of case id (404 for an
// alert ws does not have, 409 for one in another case).
func caseAlertsIn(tx *gorm.DB, ws, id uuid.UUID, ids []uuid.UUID) ([]agentCaseAlertRow, error) {
	rows, err := loadAgentCaseAlerts(tx, ws, ids)
	if err != nil {
		return nil, err
	}
	out := make([]agentCaseAlertRow, 0, len(ids))
	for _, aid := range ids {
		r, ok := rows[aid]
		if !ok {
			return nil, govErr(http.StatusNotFound, "not_found", "Not found.", map[string]any{"alert_id": aid})
		}
		if r.CaseID == nil || *r.CaseID != id {
			return nil, govErr(http.StatusConflict, "alert_not_in_case", "The alert is not in this case.", map[string]any{"alert_id": aid})
		}
		out = append(out, r)
	}
	return out, nil
}

// Split is POST /cases/:id/split: the listed alerts move to a new case
// linked split_from the source, which keeps at least one alert.
func (s *AgentCaseService) Split(ctx context.Context, ws, id, actor uuid.UUID, alertIDs []uuid.UUID, title string) (*AgentCase, error) {
	ids, err := validateAgentCaseAlertIDs(alertIDs)
	if err != nil {
		return nil, err
	}
	if utf8.RuneCountInString(strings.TrimSpace(title)) > agentCaseMaxTitle {
		return nil, GovBadParam("title", "title must be at most 300 characters.")
	}
	act := agentCaseUserActor(actor)
	var out *AgentCase
	err = s.write(ctx, ws, func(tx *gorm.DB, now time.Time) error {
		src, err := openAgentCaseForWrite(tx, ws, id)
		if err != nil {
			return err
		}
		rows, err := caseAlertsIn(tx, ws, id, ids)
		if err != nil {
			return err
		}
		if len(rows) >= src.AlertCount {
			return GovBadParam("alert_ids", "A split must leave at least one alert in the case.")
		}
		if strings.TrimSpace(title) == "" {
			title = rows[0].Title
		}
		newID, _, err := openAgentCase(tx, ws, title, maxAgentCaseSeverity(rows), src.ExerciseID, act, now,
			map[string]any{"split_from": id})
		if err != nil {
			return err
		}
		for _, r := range rows {
			if err := moveAlertToAgentCase(tx, ws, newID, r, act, now); err != nil {
				return err
			}
		}
		if err := linkAgentCases(tx, ws, newID, id, AgentCaseLinkSplitFrom, act, now); err != nil {
			return err
		}
		if err := appendGovEvent(tx, ws, GovEventAgentCaseSplit, act.kind, act.id, govEventRefs{},
			map[string]any{"case_id": id, "new_case_id": newID, "alert_ids": ids}); err != nil {
			return err
		}
		out, err = getAgentCase(tx, ws, newID)
		return err
	})
	return out, err
}

// MoveAlerts is POST /cases/:id/alerts: the listed alerts move into the
// (open) case from wherever they are (an open case or none).
func (s *AgentCaseService) MoveAlerts(ctx context.Context, ws, id, actor uuid.UUID, alertIDs []uuid.UUID) (*AgentCase, error) {
	ids, err := validateAgentCaseAlertIDs(alertIDs)
	if err != nil {
		return nil, err
	}
	act := agentCaseUserActor(actor)
	var out *AgentCase
	err = s.write(ctx, ws, func(tx *gorm.DB, now time.Time) error {
		if _, err := openAgentCaseForWrite(tx, ws, id); err != nil {
			return err
		}
		rows, err := movableAgentCaseAlerts(tx, ws, ids)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if err := moveAlertToAgentCase(tx, ws, id, r, act, now); err != nil {
				return err
			}
		}
		out, err = getAgentCase(tx, ws, id)
		return err
	})
	return out, err
}

// AgentCaseClose is POST /cases/:id/close.
type AgentCaseClose struct {
	Outcome     string     `json:"outcome"`
	Reason      string     `json:"reason"`
	DuplicateOf *uuid.UUID `json:"duplicate_of"`
}

// ValidAgentCaseOutcome reports whether o is an outcome code.
func ValidAgentCaseOutcome(o string) bool {
	switch o {
	case AgentCaseOutcomeTruePositive, AgentCaseOutcomeBenign, AgentCaseOutcomeFalsePositive, AgentCaseOutcomeDuplicate:
		return true
	}
	return false
}

// Close is POST /cases/:id/close: an outcome is required; the case's
// current evidence is pinned.
func (s *AgentCaseService) Close(ctx context.Context, ws, id, actor uuid.UUID, in AgentCaseClose) (*AgentCase, error) {
	in.Outcome = strings.TrimSpace(in.Outcome)
	in.Reason = strings.TrimSpace(in.Reason)
	if in.Outcome == "" {
		return nil, GovBadParam("outcome", "Closing a case needs an outcome: true_positive, benign, false_positive or duplicate.")
	}
	if !ValidAgentCaseOutcome(in.Outcome) {
		return nil, GovBadParam("outcome", "outcome must be true_positive, benign, false_positive or duplicate.")
	}
	if utf8.RuneCountInString(in.Reason) > agentCaseMaxReason {
		return nil, GovBadParam("reason", "reason must be at most 1000 characters.")
	}
	if in.Outcome == AgentCaseOutcomeDuplicate && in.DuplicateOf == nil {
		return nil, GovBadParam("duplicate_of", "outcome duplicate needs duplicate_of: the case this one duplicates.")
	}
	if in.Outcome != AgentCaseOutcomeDuplicate && in.DuplicateOf != nil {
		return nil, GovBadParam("duplicate_of", "duplicate_of goes with outcome duplicate only.")
	}
	if in.DuplicateOf != nil && *in.DuplicateOf == id {
		return nil, GovBadParam("duplicate_of", "A case cannot duplicate itself.")
	}
	act := agentCaseUserActor(actor)
	var out *AgentCase
	err := s.write(ctx, ws, func(tx *gorm.DB, now time.Time) error {
		c, err := openAgentCaseForWrite(tx, ws, id)
		if err != nil {
			return err
		}
		if in.DuplicateOf != nil {
			ok, err := AgentCaseExistsTx(tx, ws, *in.DuplicateOf)
			if err != nil {
				return err
			}
			if !ok {
				return govErr(http.StatusNotFound, "not_found", "Not found.", map[string]any{"duplicate_of": *in.DuplicateOf})
			}
		}
		if err := pinAgentCaseEvidenceNow(tx, ws, id, act.by, now); err != nil {
			return err
		}
		if err := tx.Exec(`UPDATE agent_case SET state = 'closed', outcome = ?, closed_by = ?, closed_at = ?, close_reason = ?,
		                          classified_at = COALESCE(classified_at, ?), classified_by = COALESCE(classified_by, ?), updated_at = ?
		                    WHERE workspace_id = ? AND id = ?`,
			in.Outcome, actor, now, in.Reason, now, actor, now, ws, id).Error; err != nil {
			return err
		}
		if in.DuplicateOf != nil {
			if err := linkAgentCases(tx, ws, id, *in.DuplicateOf, AgentCaseLinkDuplicateOf, act, now); err != nil {
				return err
			}
		}
		payload := map[string]any{"case_id": id, "outcome": in.Outcome, "reason": in.Reason, "alert_count": c.AlertCount,
			"severity": c.Severity}
		if in.DuplicateOf != nil {
			payload["duplicate_of"] = *in.DuplicateOf
		}
		if err := appendGovEvent(tx, ws, GovEventAgentCaseClosed, act.kind, act.id, govEventRefs{}, payload); err != nil {
			return err
		}
		out, err = getAgentCase(tx, ws, id)
		return err
	})
	return out, err
}

// Reopen is POST /cases/:id/reopen: closed -> open; the outcome is cleared
// (the log keeps it) and the reopen counted.
func (s *AgentCaseService) Reopen(ctx context.Context, ws, id, actor uuid.UUID, reason string) (*AgentCase, error) {
	reason = strings.TrimSpace(reason)
	if utf8.RuneCountInString(reason) > agentCaseMaxReason {
		return nil, GovBadParam("reason", "reason must be at most 1000 characters.")
	}
	act := agentCaseUserActor(actor)
	var out *AgentCase
	err := s.write(ctx, ws, func(tx *gorm.DB, now time.Time) error {
		c, err := getAgentCase(tx, ws, id)
		if err != nil {
			return err
		}
		if c.State != AgentCaseClosed {
			return govErr(http.StatusConflict, "case_open", "The case is already open.", map[string]any{"state": c.State})
		}
		if err := tx.Exec(`UPDATE agent_case SET state = 'open', outcome = NULL, closed_by = NULL, closed_at = NULL, close_reason = '',
		                          reopened_count = reopened_count + 1, updated_at = ?
		                    WHERE workspace_id = ? AND id = ?`, now, ws, id).Error; err != nil {
			return err
		}
		if err := appendGovEvent(tx, ws, GovEventAgentCaseReopened, act.kind, act.id, govEventRefs{},
			map[string]any{"case_id": id, "previous_outcome": c.Outcome, "reason": reason, "reopened_count": c.ReopenedCount + 1}); err != nil {
			return err
		}
		out, err = getAgentCase(tx, ws, id)
		return err
	})
	return out, err
}

// RaiseSeverity is POST /cases/:id/severity: a person raises the severity
// (tier 0). Lowering is tier 3 (a second person, W5) and refused here.
func (s *AgentCaseService) RaiseSeverity(ctx context.Context, ws, id, actor uuid.UUID, severity string) (*AgentCase, error) {
	severity = strings.TrimSpace(severity)
	if agentCaseSeverityRank(severity) == 0 {
		return nil, GovBadParam("severity", "severity must be high, medium or low.")
	}
	act := agentCaseUserActor(actor)
	var out *AgentCase
	err := s.write(ctx, ws, func(tx *gorm.DB, now time.Time) error {
		c, err := openAgentCaseForWrite(tx, ws, id)
		if err != nil {
			return err
		}
		switch r, cur := agentCaseSeverityRank(severity), agentCaseSeverityRank(c.Severity); {
		case r < cur:
			return govErr(http.StatusConflict, "lowering_needs_second_person",
				"Lowering a case's severity is a tier 3 change that needs a second person; it is not available yet.",
				map[string]any{"severity": c.Severity})
		case r == cur && c.ClassifiedAt != nil:
			out = c
			return nil
		}
		if err := tx.Exec(`UPDATE agent_case SET severity = ?, classified_at = COALESCE(classified_at, ?),
		                          classified_by = COALESCE(classified_by, ?), updated_at = ?
		                    WHERE workspace_id = ? AND id = ?`, severity, now, actor, now, ws, id).Error; err != nil {
			return err
		}
		if err := appendGovEvent(tx, ws, GovEventAgentCaseSeverityRaised, act.kind, act.id, govEventRefs{},
			map[string]any{"case_id": id, "from": c.Severity, "to": severity}); err != nil {
			return err
		}
		out, err = getAgentCase(tx, ws, id)
		return err
	})
	return out, err
}

// AgentCaseBundle is the export: the case and everything attached to it.
type AgentCaseBundle struct {
	Format   string              `json:"format"`
	Case     AgentCase           `json:"case"`
	Alerts   []AgentCaseAlert    `json:"alerts"`
	Evidence []AgentCaseEvidence `json:"evidence"`
	Asks     []AgentAskSummary   `json:"asks"`
	Stops    []AgentCaseStop     `json:"stops"`
	Notes    []AgentCaseNote     `json:"notes"`
	Links    []AgentCaseLink     `json:"links"`
	Log      []AgentCaseLogEntry `json:"log"`
}

// AgentCaseExport is POST /cases/:id/export. SHA256 (hex) is over the
// bundle's canonical JSON (AgentCaseCanonicalJSON: object keys sorted,
// compact, no HTML escaping), so a receiver re-encodes the bundle it got
// that way and compares.
type AgentCaseExport struct {
	Bundle     json.RawMessage `json:"bundle"`
	SHA256     string          `json:"sha256"`
	ExportedAt time.Time       `json:"exported_at"`
	ExportedBy uuid.UUID       `json:"exported_by"`
}

// AgentCaseBundleHash is the hex sha256 of a bundle's canonical JSON.
func AgentCaseBundleHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// AgentCaseCanonicalJSON re-encodes JSON canonically: object keys sorted,
// numbers as written, compact, without HTML escaping.
func AgentCaseCanonicalJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}

// Export is POST /cases/:id/export (tier 0, one case): the case's evidence
// is pinned, the bundle built and hashed, and "case.exported" logged. The
// bundle leaves case.exported events out, so exporting an unchanged case
// again gives the same hash.
func (s *AgentCaseService) Export(ctx context.Context, ws, id, actor uuid.UUID) (*AgentCaseExport, error) {
	act := agentCaseUserActor(actor)
	var out *AgentCaseExport
	err := s.write(ctx, ws, func(tx *gorm.DB, now time.Time) error {
		if _, err := getAgentCase(tx, ws, id); err != nil {
			return err
		}
		if err := pinAgentCaseEvidenceNow(tx, ws, id, act.by, now); err != nil {
			return err
		}
		v, err := readAgentCaseView(tx, ws, id, true)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(AgentCaseBundle{Format: AgentCaseExportFormat, Case: v.AgentCase, Alerts: v.Alerts,
			Evidence: v.Evidence, Asks: v.Asks, Stops: v.Stops, Notes: v.Notes, Links: v.Links, Log: v.Log})
		if err != nil {
			return err
		}
		if raw, err = AgentCaseCanonicalJSON(raw); err != nil {
			return err
		}
		sum := AgentCaseBundleHash(raw)
		if err := appendGovEvent(tx, ws, GovEventAgentCaseExported, act.kind, act.id, govEventRefs{},
			map[string]any{"case_id": id, "sha256": sum, "alerts": len(v.Alerts), "notes": len(v.Notes),
				"evidence": len(v.Evidence), "bytes": len(raw)}); err != nil {
			return err
		}
		out = &AgentCaseExport{Bundle: raw, SHA256: sum, ExportedAt: now, ExportedBy: actor}
		return nil
	})
	return out, err
}

/* ------------------------------------------------------------------------- */
/*                         Cluster worker (and backfill)                      */
/* ------------------------------------------------------------------------- */

// ClusterPending places ws's alerts that are not resolved and in no case
// (alerts raised before 186, or left by the sink), oldest first. It returns
// how many were placed.
func (s *AgentCaseService) ClusterPending(ctx context.Context, ws uuid.UUID) (int, error) {
	n := 0
	err := s.write(ctx, ws, func(tx *gorm.DB, now time.Time) error {
		var ids []uuid.UUID
		if err := tx.Raw(`SELECT a.id FROM agent_alert a
		                   WHERE a.workspace_id = ? AND a.state <> 'resolved'
		                     AND NOT EXISTS (SELECT 1 FROM agent_case_alert m WHERE m.workspace_id = a.workspace_id AND m.alert_id = a.id)
		                   ORDER BY a.first_seen, a.created_at, a.id LIMIT ?`, ws, agentCaseClusterBatch).Scan(&ids).Error; err != nil {
			return err
		}
		for _, id := range ids {
			if _, err := clusterAgentAlert(tx, ws, id, now); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// RunAgentCaseClusterWorker places case-less open alerts every minute,
// starting with the backfill of every workspace. AUTHSEC_DISABLE_AGENT_CASE_CLUSTER=true
// turns it off.
func RunAgentCaseClusterWorker(ctx context.Context, db *gorm.DB) {
	if os.Getenv("AUTHSEC_DISABLE_AGENT_CASE_CLUSTER") == "true" {
		log.Printf("[agent-cases] cluster worker not started: AUTHSEC_DISABLE_AGENT_CASE_CLUSTER=true")
		return
	}
	svc := NewAgentCaseService(db)
	for {
		if ok, reason := AgentCasesStatus(db); !ok {
			agentCasesGate.logWait("case cluster worker", reason)
		} else if err := svc.clusterAll(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[agent-cases] cluster: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
	}
}

func (s *AgentCaseService) clusterAll(ctx context.Context) error {
	var wss []uuid.UUID
	// TENANT-EXEMPT: the cluster worker runs across workspaces (no request tenant) and lists workspace ids only; each workspace's alerts are placed in its own workspace_id-bound transaction under RLS.
	if err := s.db.WithContext(ctx).Raw(`SELECT DISTINCT a.workspace_id FROM agent_alert a
	                                     WHERE a.state <> 'resolved'
	                                       AND NOT EXISTS (SELECT 1 FROM agent_case_alert m WHERE m.workspace_id = a.workspace_id AND m.alert_id = a.id)
	                                     LIMIT 200`).Scan(&wss).Error; err != nil {
		return err
	}
	var first error
	for _, ws := range wss {
		if n, err := s.ClusterPending(ctx, ws); err != nil {
			if first == nil {
				first = fmt.Errorf("workspace %s: %w", ws, err)
			}
		} else if n > 0 {
			log.Printf("[agent-cases] workspace %s: placed %d alerts in cases", ws, n)
		}
	}
	return first
}

// truncateRunes cuts s to at most n characters.
func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}
