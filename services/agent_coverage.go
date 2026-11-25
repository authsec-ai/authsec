package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
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

// Coverage (SPEC-secops-backend-upgrade W1, P8): source heartbeats and
// their silence (coverage alert COV-01), capability states C1..C13 per estate
// scope, and declared gaps (tier 3: a second person decides).
//
// Silence reuses the event stream's rule (streamSilence,
// agent_runtime_ingest.go): a source is silent once nothing arrived for its
// silent_after, counted from its last receipt or, if it never delivered,
// from when it was set up. The AWS stream's heartbeat is synced from
// agent_event_stream itself (its threshold, receipts and revocation), so the
// stream view and the heartbeat never disagree.
//
// HONESTY: a capability AuthSec does not implement is reported "off" with
// detail "not implemented" -- never "on" for something nothing reads.

// Capabilities (spec §3).
var CoverageCapabilities = []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11", "C12", "C13"}

// CoverageCapabilityNames are the capabilities' short names.
var CoverageCapabilityNames = map[string]string{
	"C1": "Streams", "C2": "Data events", "C3": "DNS lookups", "C4": "Flow logs", "C5": "Provider usage",
	"C6": "Gateway", "C7": "Who is behind a call", "C8": "Session revocation", "C9": "Platform stops",
	"C10": "Directory", "C11": "Remediation writers", "C12": "Classification", "C13": "Delivery",
}

// Capability states and gap kinds.
const (
	CapabilityOn      = "on"
	CapabilityPartial = "partial"
	CapabilityOff     = "off"

	GapNone     = "none"
	GapDeclared = "declared"
	GapBroken   = "broken"

	capNotImplemented = "not implemented"
)

// Coverage alert detection and subject label (agent_alert, migration 170).
const (
	CoverageDetectionSilent = string(detect.COV01)
	coverageSubjectLabel    = "source"
)

// Gov event names (Logs): the declare flow.
const (
	GovCatCoverage                    = "coverage"
	GovObjCapabilityState             = "capability_state"
	GovEventCoverageDeclareRequested  = "coverage.gap_declaration_requested"
	GovEventCoverageGapDeclared       = "coverage.gap_declared"
	GovEventCoverageDeclareRejected   = "coverage.gap_declaration_rejected"
	GovEventCoverageBreakGlassApplied = "coverage.gap_declared_break_glass"
	GovEventCoverageBreakGlassReview  = "coverage.break_glass_reviewed"
	coverageBreakGlassReviewWithin    = SecondPersonReviewWindow
	coverageMaxGapBackfill            = 7 * 24 * time.Hour
	coverageDataEventLookback         = 7 * 24 * time.Hour
)

func init() {
	// Additive: the coverage events join the Logs vocabulary from here, so
	// the shared table is not edited.
	GovEventVocabulary = append(GovEventVocabulary,
		GovEventKind{GovEventCoverageDeclareRequested, GovCatCoverage, GovObjCapabilityState, "A member asked to declare a coverage gap (tier 3: a second person decides)."},
		GovEventKind{GovEventCoverageGapDeclared, GovCatCoverage, GovObjCapabilityState, "A second person approved a coverage gap declaration."},
		GovEventKind{GovEventCoverageDeclareRejected, GovCatCoverage, GovObjCapabilityState, "A coverage gap declaration was rejected."},
		GovEventKind{GovEventCoverageBreakGlassApplied, GovCatCoverage, GovObjCapabilityState, "The workspace's only approver declared a coverage gap alone (break-glass); a review is due within 24 hours."},
		GovEventKind{GovEventCoverageBreakGlassReview, GovCatCoverage, GovObjCapabilityState, "A second person reviewed a break-glass coverage gap declaration."},
	)
	govEventObjectFilters[GovObjCapabilityState] = struct{ column, payloadKey string }{payloadKey: "capability_state_id"}
}

/* ------------------------------------------------------------------------- */
/*                                 Heartbeats                                 */
/* ------------------------------------------------------------------------- */

// SourceHeartbeat is one source_heartbeat row.
type SourceHeartbeat struct {
	ID                   uuid.UUID  `json:"id" gorm:"column:id"`
	SourceKind           string     `json:"source_kind" gorm:"column:source_kind"`
	SourceRef            string     `json:"source_ref" gorm:"column:source_ref"`
	ConnectorID          *uuid.UUID `json:"connector_id" gorm:"column:connector_id"`
	LastEventAt          *time.Time `json:"last_event_at" gorm:"column:last_event_at"`
	LastReceivedAt       *time.Time `json:"last_received_at" gorm:"column:last_received_at"`
	ExpectedFloorSeconds *int64     `json:"expected_floor_seconds" gorm:"column:expected_floor_seconds"`
	SilentAfterSeconds   *int64     `json:"silent_after_seconds" gorm:"column:silent_after_seconds"`
	State                string     `json:"state" gorm:"column:state"`
	SilentSince          *time.Time `json:"silent_since" gorm:"column:silent_since"`
	CreatedAt            time.Time  `json:"created_at" gorm:"column:created_at"`
	UpdatedAt            time.Time  `json:"updated_at" gorm:"column:updated_at"`
}

const sourceHeartbeatColumns = `id, source_kind, source_ref, connector_id, last_event_at, last_received_at,
	expected_floor_seconds, silent_after_seconds, state, silent_since, created_at, updated_at`

func readHeartbeats(tx *gorm.DB, ws uuid.UUID) ([]SourceHeartbeat, error) {
	var rows []SourceHeartbeat
	err := tx.Raw(`SELECT `+sourceHeartbeatColumns+` FROM source_heartbeat WHERE workspace_id = ?
	               ORDER BY source_kind, source_ref`, ws).Scan(&rows).Error
	if rows == nil {
		rows = []SourceHeartbeat{}
	}
	return rows, err
}

// heartbeatSilence is the silence rule for a heartbeat: the stream's rule,
// with the heartbeat's creation as "set up". A heartbeat without a threshold
// is never silent.
func heartbeatSilence(h SourceHeartbeat, now time.Time) (bool, *time.Time) {
	if h.SilentAfterSeconds == nil || *h.SilentAfterSeconds <= 0 {
		return false, nil
	}
	return streamSilence(AgentEventStreamActive, h.CreatedAt, nil, h.LastReceivedAt,
		time.Duration(*h.SilentAfterSeconds)*time.Second, now)
}

type coverageStreamRow struct {
	ConnectorID        uuid.UUID
	CreatedAt          time.Time
	RotatedAt          *time.Time
	RevokedAt          *time.Time
	LastReceivedAt     *time.Time
	LastEventTime      *time.Time
	SilentAfterSeconds int64
}

// syncStreamHeartbeats mirrors every event stream of ws into its aws_stream
// heartbeat: receipts, threshold, and silence by the stream's own rule.
// A revoked stream is not silent (streamSilence), and its heartbeat goes.
func syncStreamHeartbeats(tx *gorm.DB, ws uuid.UUID, now time.Time) error {
	var streams []coverageStreamRow
	if err := tx.Raw(`SELECT connector_id, created_at, rotated_at, revoked_at, last_received_at, last_event_time,
	                         EXTRACT(EPOCH FROM silent_after)::bigint AS silent_after_seconds
	                    FROM agent_event_stream WHERE workspace_id = ?`, ws).Scan(&streams).Error; err != nil {
		return err
	}
	for _, st := range streams {
		ref := HeartbeatRef(st.ConnectorID)
		if st.RevokedAt != nil {
			if err := tx.Exec(`DELETE FROM source_heartbeat WHERE workspace_id = ? AND source_kind = ? AND source_ref = ?`,
				ws, agentruntime.DeliveryAWSStream, ref).Error; err != nil {
				return err
			}
			continue
		}
		after := time.Duration(st.SilentAfterSeconds) * time.Second
		if after <= 0 {
			after = AgentEventDefaultSilentAfter
		}
		created := st.CreatedAt
		if st.RotatedAt != nil {
			created = *st.RotatedAt
		}
		// Only the facts: evaluateHeartbeats judges the silence with the same
		// rule (streamSilence, counted from the rotation when there was one)
		// and raises or resolves the alert on the transition.
		if err := tx.Exec(`INSERT INTO source_heartbeat (workspace_id, source_kind, source_ref, connector_id, last_event_at,
		                       last_received_at, silent_after_seconds, created_at, updated_at)
		                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		                   ON CONFLICT (workspace_id, source_kind, source_ref) DO UPDATE SET
		                     last_event_at        = GREATEST(source_heartbeat.last_event_at, EXCLUDED.last_event_at),
		                     last_received_at     = GREATEST(source_heartbeat.last_received_at, EXCLUDED.last_received_at),
		                     silent_after_seconds = EXCLUDED.silent_after_seconds,
		                     created_at           = EXCLUDED.created_at,
		                     connector_id         = EXCLUDED.connector_id,
		                     updated_at           = EXCLUDED.updated_at`,
			ws, agentruntime.DeliveryAWSStream, ref, st.ConnectorID, st.LastEventTime, st.LastReceivedAt,
			int64(after/time.Second), created, now).Error; err != nil {
			return err
		}
	}
	return nil
}

// heartbeatTransition is one change of state evaluateHeartbeats made.
type heartbeatTransition struct {
	Heartbeat SourceHeartbeat
	ToSilent  bool
	// RecoveredFrom is when the silence began, for a source that recovered.
	RecoveredFrom *time.Time
}

// evaluateHeartbeats judges every heartbeat of ws, writes the state, opens a
// COV-01 alert for a source that fell silent (and keeps it fresh while it
// stays silent), resolves it when the source recovers, and queues a
// trail-bucket backfill for the window an AWS stream missed.
func evaluateHeartbeats(tx *gorm.DB, ws uuid.UUID, now time.Time, alerts bool) ([]heartbeatTransition, error) {
	hbs, err := readHeartbeats(tx, ws)
	if err != nil {
		return nil, err
	}
	var settings *AgentAlertSettings
	var out []heartbeatTransition
	for _, h := range hbs {
		silent, since := heartbeatSilence(h, now)
		wasSilent := h.State == "silent"
		switch {
		case silent && !wasSilent:
			if err := tx.Exec(`UPDATE source_heartbeat SET state = 'silent', silent_since = ?, updated_at = ?
			                    WHERE workspace_id = ? AND id = ?`, since, now, ws, h.ID).Error; err != nil {
				return nil, err
			}
			h.State, h.SilentSince = "silent", since
			out = append(out, heartbeatTransition{Heartbeat: h, ToSilent: true})
		case !silent && wasSilent:
			from := h.SilentSince
			if err := tx.Exec(`UPDATE source_heartbeat SET state = 'ok', silent_since = NULL, updated_at = ?
			                    WHERE workspace_id = ? AND id = ?`, now, ws, h.ID).Error; err != nil {
				return nil, err
			}
			h.State, h.SilentSince = "ok", nil
			out = append(out, heartbeatTransition{Heartbeat: h, RecoveredFrom: from})
		}
		if !alerts {
			continue
		}
		switch {
		case silent:
			if settings == nil {
				st, err := readAgentAlertSettings(tx, ws)
				if err != nil {
					return nil, err
				}
				settings = &st
			}
			if err := upsertCoverageAlert(tx, ws, h, *settings, now); err != nil {
				return nil, err
			}
		case wasSilent:
			if err := resolveCoverageAlert(tx, ws, h, now); err != nil {
				return nil, err
			}
		}
	}
	for _, t := range out {
		if t.RecoveredFrom == nil || t.Heartbeat.SourceKind != agentruntime.DeliveryAWSStream || t.Heartbeat.ConnectorID == nil {
			continue
		}
		if err := queueGapBackfill(tx, ws, t.Heartbeat, *t.RecoveredFrom, now); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func coverageDedupeKey(h SourceHeartbeat) string {
	return CoverageDetectionSilent + "/" + h.ID.String()
}

func coverageSubjectName(h SourceHeartbeat) string {
	return truncate(h.SourceKind+" "+h.SourceRef, 300)
}

// upsertCoverageAlert opens the source's COV-01 alert, or keeps the open one
// fresh (last_seen). One alert per silent source: a partial unique index
// (uq_agent_alert_coverage_open) holds it.
func upsertCoverageAlert(tx *gorm.DB, ws uuid.UUID, h SourceHeartbeat, st AgentAlertSettings, now time.Time) error {
	key := coverageDedupeKey(h)
	res := tx.Exec(`UPDATE agent_alert SET last_seen = GREATEST(last_seen, ?)
	                 WHERE workspace_id = ? AND dedupe_key = ? AND detection = ? AND state <> 'resolved'`,
		now, ws, key, CoverageDetectionSilent)
	if res.Error != nil || res.RowsAffected > 0 {
		return res.Error
	}
	since := now
	if h.SilentSince != nil {
		since = h.SilentSince.UTC()
	}
	if since.After(now) {
		since = now
	}
	conn := h.ID
	if h.ConnectorID != nil {
		conn = *h.ConnectorID
	}
	severity := detect.SeverityMedium
	if h.SourceKind == agentruntime.DeliveryAWSStream {
		severity = detect.SeverityHigh
	}
	detail := "nothing received since " + since.Format(time.RFC3339)
	if h.LastReceivedAt == nil {
		detail = "nothing received since the source was set up at " + since.Format(time.RFC3339)
	}
	ev, err := json.Marshal([]AgentAlertEventRef{{Time: since, Source: h.SourceKind, Name: "source_silent", Detail: truncate(detail, 300)}})
	if err != nil {
		return err
	}
	var ids []uuid.UUID
	if err := tx.Raw(`INSERT INTO agent_alert (workspace_id, connector_id, identity_id, workload_ids, subject_label, subject_name,
	                         detection, severity, title, dedupe_key, first_seen, last_seen, event_count, evidence, state, created_at)
	                  VALUES (?, ?, ?, '[]'::jsonb, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?::jsonb, 'open', ?)
	                  ON CONFLICT (workspace_id, dedupe_key) WHERE detection = 'COV-01' AND state <> 'resolved' DO NOTHING
	                  RETURNING id`,
		ws, conn, h.ID, coverageSubjectLabel, coverageSubjectName(h), CoverageDetectionSilent, severity,
		truncate("Source silent: "+coverageSubjectName(h), 300), key, since, now, string(ev), now).Scan(&ids).Error; err != nil {
		return err
	}
	if len(ids) != 1 {
		return nil // a concurrent run opened it
	}
	if err := appendGovEvent(tx, ws, GovEventAgentAlertOpened, models.GovActorSystem, "coverage", govEventRefs{},
		map[string]any{"alert_id": ids[0], "detection": CoverageDetectionSilent, "severity": severity,
			"heartbeat_id": h.ID, "source_kind": h.SourceKind, "source_ref": h.SourceRef, "silent_since": since}); err != nil {
		return err
	}
	return enqueueAgentAlertDeliveries(tx, ws, ids[0], st)
}

// resolveCoverageAlert resolves the source's open COV-01 alert (the source
// recovered), as the system.
func resolveCoverageAlert(tx *gorm.DB, ws uuid.UUID, h SourceHeartbeat, now time.Time) error {
	var ids []uuid.UUID
	if err := tx.Raw(`UPDATE agent_alert SET state = 'resolved', state_changed_at = ?, reason = 'source recovered'
	                   WHERE workspace_id = ? AND dedupe_key = ? AND detection = ? AND state <> 'resolved'
	                   RETURNING id`, now, ws, coverageDedupeKey(h), CoverageDetectionSilent).Scan(&ids).Error; err != nil {
		return err
	}
	for _, id := range ids {
		if err := appendGovEvent(tx, ws, GovEventAgentAlertResolved, models.GovActorSystem, "coverage", govEventRefs{},
			map[string]any{"alert_id": id, "detection": CoverageDetectionSilent, "heartbeat_id": h.ID,
				"reason": "source recovered"}); err != nil {
			return err
		}
	}
	return nil
}

// queueGapBackfill queues a trail-bucket backfill of the window an AWS
// stream was silent (at most coverageMaxGapBackfill, ending now), once per
// silence.
func queueGapBackfill(tx *gorm.DB, ws uuid.UUID, h SourceHeartbeat, from, now time.Time) error {
	if now.Sub(from) > coverageMaxGapBackfill {
		from = now.Add(-coverageMaxGapBackfill)
	}
	if !now.After(from) {
		return nil
	}
	return tx.Exec(`INSERT INTO agent_trail_backfill (workspace_id, connector_id, window_from, window_to, cause, heartbeat_id)
	                VALUES (?, ?, ?, ?, 'gap', ?)
	                ON CONFLICT (workspace_id, heartbeat_id, window_from) WHERE cause = 'gap' DO NOTHING`,
		ws, *h.ConnectorID, from.UTC(), now.UTC(), h.ID).Error
}

/* ------------------------------------------------------------------------- */
/*                                Capabilities                                */
/* ------------------------------------------------------------------------- */

// coverageScope is one estate scope and the facts its capabilities read.
type coverageScope struct {
	Scope       string
	Kind        string // account | tenant | cluster | workspace
	Provider    string // aws | azure | k8s | ""
	ConnectorID *uuid.UUID

	// AWS
	StreamActive, StreamSilent bool
	StreamSilentSince          *time.Time
	PolledTrail                bool
	DataEventsSeen             int64
	DNSRead, DNSError          bool
	BrokerRoles                int64
	EnforcementState           string
	// Azure
	DiagSecretActive, DiagSilent bool
	// Kubernetes
	AuditSeen, AuditSilent bool
}

// coverageWorkspace is what every scope of a workspace shares.
type coverageWorkspace struct {
	ProviderConnections int64
	Gateways            int64
	SCIM                int64
	Slack               bool
	SIEMEndpoints       int64
}

// CapabilityResult is one computed capability of a scope.
type CapabilityResult struct {
	Capability string
	State      string
	Detail     string
	Fallback   string
}

func capOff(c, detail, fallback string) CapabilityResult {
	return CapabilityResult{Capability: c, State: CapabilityOff, Detail: detail, Fallback: fallback}
}

// computeScopeCapabilities decides C1..C13 for one scope from its facts.
// Pure: the unit tests drive it directly.
func computeScopeCapabilities(s coverageScope, w coverageWorkspace) []CapabilityResult {
	out := make([]CapabilityResult, 0, len(CoverageCapabilities))
	add := func(r CapabilityResult) { out = append(out, r) }
	pollFallback := "CloudTrail read by LookupEvents during scans (up to 90 days back); a trail-bucket backfill fills the stream's gaps."

	// C1 Streams.
	switch s.Provider {
	case models.CloudProviderAWS:
		switch {
		case s.StreamActive && !s.StreamSilent:
			add(CapabilityResult{"C1", CapabilityOn, "Event stream delivering (all management events of the account).", pollFallback})
		case s.StreamActive && s.StreamSilent:
			since := ""
			if s.StreamSilentSince != nil {
				since = " since " + s.StreamSilentSince.UTC().Format(time.RFC3339)
			}
			add(CapabilityResult{"C1", CapabilityPartial, "Event stream silent" + since + ".", pollFallback})
		case s.PolledTrail:
			add(CapabilityResult{"C1", CapabilityPartial, "No event stream: events arrive only when a scan polls CloudTrail.", pollFallback})
		default:
			add(capOff("C1", "No event stream and no CloudTrail read yet.", "Run a scan, or turn the event stream on."))
		}
	case models.CloudProviderAzure:
		switch {
		case s.DiagSecretActive && !s.DiagSilent:
			add(CapabilityResult{"C1", CapabilityOn, "Diagnostic-settings export delivering.", "Azure discovery's 12-hour aggregates."})
		case s.DiagSecretActive:
			add(CapabilityResult{"C1", CapabilityPartial, "Diagnostic-settings export silent.", "Azure discovery's 12-hour aggregates."})
		default:
			add(CapabilityResult{"C1", CapabilityPartial, "No diagnostic-settings export connected: Azure activity is polled as 12-hour aggregates.",
				"Azure discovery's 12-hour aggregates."})
		}
	case models.ProviderK8s:
		switch {
		case s.AuditSeen && !s.AuditSilent:
			add(CapabilityResult{"C1", CapabilityOn, "Kubernetes audit events delivered by the iga-agent.", "RBAC snapshots and admission sightings."})
		case s.AuditSeen:
			add(CapabilityResult{"C1", CapabilityPartial, "Kubernetes audit feed silent.", "RBAC snapshots and admission sightings."})
		default:
			add(capOff("C1", "Kubernetes audit not forwarded: the iga-agent does not forward audit events yet.", "RBAC snapshots and admission sightings."))
		}
	default:
		add(capOff("C1", "No connected account, subscription or cluster.", "None."))
	}

	// C2 Data events: AuthSec cannot read a trail's selectors, only what arrives.
	if s.Provider == models.CloudProviderAWS {
		if s.DataEventsSeen > 0 {
			add(CapabilityResult{"C2", CapabilityPartial,
				fmt.Sprintf("%d data events received in the last 7 days; the trail's selectors are not readable by AuthSec, so which kinds are logged is not known.", s.DataEventsSeen),
				"Management events only for data kinds not logged."})
		} else {
			add(capOff("C2", "No data events received in the last 7 days (the trail's selectors are not readable by AuthSec).",
				"Management events only; add the DataEvents* selectors from the AuthSec stack template."))
		}
	} else {
		add(capOff("C2", capNotImplemented, "Management events only."))
	}

	// C3 DNS lookups.
	switch {
	case s.Provider == models.CloudProviderAWS && s.DNSRead && !s.DNSError:
		add(CapabilityResult{"C3", CapabilityPartial, "Route 53 Resolver query logs read through Logs Insights during scans; lookups are joined, not stored.", "Gateway and provider usage."})
	case s.Provider == models.CloudProviderAWS && s.DNSRead:
		add(CapabilityResult{"C3", CapabilityPartial, "Route 53 Resolver query log reads are failing.", "Gateway and provider usage."})
	case s.Provider == models.CloudProviderAWS:
		add(capOff("C3", "No Route 53 Resolver query logging read for this account.", "Gateway and provider usage."))
	default:
		add(capOff("C3", capNotImplemented, "Gateway and provider usage."))
	}

	// C4 Flow logs.
	add(capOff("C4", capNotImplemented, "DNS lookups and provider usage."))

	// C5 Provider usage (workspace-wide).
	if w.ProviderConnections > 0 {
		add(CapabilityResult{"C5", CapabilityPartial,
			fmt.Sprintf("%d model provider organisation(s) connected: hourly usage per key; per-minute buckets and cost not implemented.", w.ProviderConnections),
			"Hourly aggregates."})
	} else {
		add(capOff("C5", "No model provider organisation connected.", "Model calls seen in CloudTrail (Bedrock) only."))
	}

	// C6 Gateway (workspace-wide).
	if w.Gateways > 0 {
		add(CapabilityResult{"C6", CapabilityOn, fmt.Sprintf("%d agent gateway(s) registered with the PDP.", w.Gateways), "Provider usage and CloudTrail."})
	} else {
		add(capOff("C6", "No agent gateway registered.", "Provider usage and CloudTrail."))
	}

	// C7 Who is behind a call.
	if s.Provider == models.CloudProviderAWS && s.BrokerRoles > 0 {
		add(CapabilityResult{"C7", CapabilityPartial,
			fmt.Sprintf("The broker sets SourceIdentity on brokered sessions of %d role(s); sessions the broker did not open are not attributed to a person.", s.BrokerRoles),
			"The role or user that made the call."})
	} else if s.Provider == models.CloudProviderAWS {
		add(capOff("C7", "No role opted in to brokered sessions.", "The role or user that made the call."))
	} else {
		add(capOff("C7", capNotImplemented, "The identity that made the call."))
	}

	// C8 Session revocation.
	switch {
	case s.Provider == models.CloudProviderAWS && (s.EnforcementState == "verified" || s.EnforcementState == "partial"):
		add(CapabilityResult{"C8", CapabilityPartial, "Role sessions can be revoked (TokenIssueTime deny, 13 h); IAM users, Entra and Kubernetes are not supported.",
			"Stop the identity (containment)."})
	case s.Provider == models.CloudProviderAWS:
		add(capOff("C8", "No verified enforcement binding for this account.", "None until the enforcement stack is deployed."))
	default:
		add(capOff("C8", capNotImplemented, "None."))
	}

	// C9 Platform stops.
	if s.Provider == models.CloudProviderAzure {
		add(capOff("C9", capNotImplemented+": Entra accountEnabled is read only.", "Role assignment holds through Azure access policies."))
	} else {
		add(capOff("C9", capNotImplemented, "None."))
	}

	// C10 Directory (workspace-wide).
	if w.SCIM > 0 {
		add(CapabilityResult{"C10", CapabilityPartial, "SCIM provisioning active: active and department only; manager, contractor and leave not implemented.", "Workspace members."})
	} else {
		add(capOff("C10", "No SCIM connection.", "Workspace members."))
	}

	// C11 Remediation writers.
	add(capOff("C11", capNotImplemented+": no remediation role; a remediation is a prepared change, never a write.", "Prepared change or IaC pull request."))

	// C12 Classification.
	if s.Provider == models.CloudProviderAWS {
		add(CapabilityResult{"C12", CapabilityPartial, "Heuristic resource sensitivity only; customer classification not implemented.", "Heuristic sensitivity."})
	} else {
		add(capOff("C12", capNotImplemented, "None."))
	}

	// C13 Delivery (workspace-wide).
	var ch []string
	if w.Slack {
		ch = append(ch, "Slack (non-interactive)")
	}
	if w.SIEMEndpoints > 0 {
		ch = append(ch, fmt.Sprintf("%d signed SIEM webhook(s)", w.SIEMEndpoints))
	}
	if len(ch) > 0 {
		add(CapabilityResult{"C13", CapabilityPartial, strings.Join(ch, " and ") + "; interactive asks, e-mail, ticketing and paging not implemented.", "The console."})
	} else {
		add(capOff("C13", "Neither Slack nor a SIEM endpoint configured.", "The console."))
	}
	return out
}

func relExists(tx *gorm.DB, rel string) (bool, error) {
	var ok bool
	err := tx.Raw(`SELECT to_regclass(?) IS NOT NULL`, "public."+rel).Scan(&ok).Error
	return ok, err
}

// countIf runs a count when rel exists, else 0.
func countIf(tx *gorm.DB, rel, q string, args ...any) (int64, error) {
	ok, err := relExists(tx, rel)
	if err != nil || !ok {
		return 0, err
	}
	var n int64
	err = tx.Raw(q, args...).Scan(&n).Error
	return n, err
}

// gatherCoverage reads ws's scopes and facts.
func gatherCoverage(tx *gorm.DB, ws uuid.UUID, hbs []SourceHeartbeat, now time.Time) ([]coverageScope, coverageWorkspace, error) {
	var w coverageWorkspace
	var err error
	if w.ProviderConnections, err = countIf(tx, "model_provider_connection",
		`SELECT count(*) FROM model_provider_connection WHERE workspace_id = ? AND status = 'active'`, ws); err != nil {
		return nil, w, err
	}
	if w.Gateways, err = countIf(tx, "agent_gateway",
		`SELECT count(*) FROM agent_gateway WHERE workspace_id = ? AND revoked_at IS NULL`, ws); err != nil {
		return nil, w, err
	}
	if w.SCIM, err = countIf(tx, "scim_connections",
		`SELECT count(*) FROM scim_connections WHERE workspace_id = ? AND status = 'active'`, ws); err != nil {
		return nil, w, err
	}
	slack, err := countIf(tx, "workspace_slack_integration",
		`SELECT count(*) FROM workspace_slack_integration WHERE workspace_id = ? AND revoked_at IS NULL`, ws)
	if err != nil {
		return nil, w, err
	}
	w.Slack = slack > 0
	if w.SIEMEndpoints, err = countIf(tx, "agent_alert_siem_endpoint",
		`SELECT count(*) FROM agent_alert_siem_endpoint WHERE workspace_id = ? AND enabled AND deleted_at IS NULL`, ws); err != nil {
		return nil, w, err
	}

	hb := map[string]SourceHeartbeat{}
	for _, h := range hbs {
		hb[h.SourceKind+"|"+h.SourceRef] = h
	}

	var conns []struct {
		ID       uuid.UUID
		Provider string
		ScopeID  string
	}
	if err := tx.Raw(`SELECT id, provider, scope_id FROM cloud_connector
	                   WHERE workspace_id = ? AND provider IN ('aws', 'azure') AND status <> 'revoked'
	                   ORDER BY provider, scope_id`, ws).Scan(&conns).Error; err != nil {
		return nil, w, err
	}
	var scopes []coverageScope
	for _, c := range conns {
		id := c.ID
		s := coverageScope{Scope: c.ScopeID, Provider: c.Provider, ConnectorID: &id}
		switch c.Provider {
		case models.CloudProviderAWS:
			s.Kind = "account"
			var streams int64
			if streams, err = countIf(tx, "agent_event_stream",
				`SELECT count(*) FROM agent_event_stream WHERE workspace_id = ? AND connector_id = ? AND revoked_at IS NULL`, ws, id); err != nil {
				return nil, w, err
			}
			s.StreamActive = streams > 0
			if h, ok := hb[agentruntime.DeliveryAWSStream+"|"+HeartbeatRef(id)]; ok && h.State == "silent" {
				s.StreamSilent, s.StreamSilentSince = true, h.SilentSince
			}
			var polled int64
			if polled, err = countIf(tx, "cloud_trail_cursor",
				`SELECT count(*) FROM cloud_trail_cursor WHERE workspace_id = ? AND connector_id = ?`, ws, id); err != nil {
				return nil, w, err
			}
			s.PolledTrail = polled > 0
			if s.DataEventsSeen, err = countIf(tx, "agent_evidence_event",
				`SELECT count(*) FROM (SELECT 1 FROM agent_evidence_event WHERE workspace_id = ? AND connector_id = ?
				   AND event_time >= ? AND body->>'event_category' = 'Data' LIMIT 10000) d`, ws, id, now.Add(-coverageDataEventLookback)); err != nil {
				return nil, w, err
			}
			var dns, dnsErr int64
			if dns, err = countIf(tx, "cloud_dns_cursor",
				`SELECT count(*) FROM cloud_dns_cursor WHERE workspace_id = ? AND connector_id = ?`, ws, id); err != nil {
				return nil, w, err
			}
			if dns > 0 {
				if dnsErr, err = countIf(tx, "cloud_dns_cursor",
					`SELECT count(*) FROM cloud_dns_cursor WHERE workspace_id = ? AND connector_id = ? AND last_error <> ''`, ws, id); err != nil {
					return nil, w, err
				}
			}
			s.DNSRead, s.DNSError = dns > 0, dnsErr > 0
			if s.BrokerRoles, err = countIf(tx, "iga_gov_runtime_broker_role",
				`SELECT count(*) FROM iga_gov_runtime_broker_role WHERE workspace_id = ? AND connector_id = ? AND state = 'active'`, ws, id); err != nil {
				return nil, w, err
			}
			if ok, err := relExists(tx, "cloud_enforcement_binding"); err != nil {
				return nil, w, err
			} else if ok {
				var states []string
				if err := tx.Raw(`SELECT state FROM cloud_enforcement_binding WHERE workspace_id = ? AND connector_id = ?
				                   ORDER BY updated_at DESC LIMIT 1`, ws, id).Scan(&states).Error; err != nil {
					return nil, w, err
				}
				if len(states) == 1 {
					s.EnforcementState = states[0]
				}
			}
		case models.CloudProviderAzure:
			s.Kind = "tenant"
			var secrets int64
			if secrets, err = countIf(tx, "agent_ingest_secret",
				`SELECT count(*) FROM agent_ingest_secret WHERE workspace_id = ? AND connector_id = ? AND kind = 'azure_diag' AND revoked_at IS NULL`,
				ws, id); err != nil {
				return nil, w, err
			}
			s.DiagSecretActive = secrets > 0
			if h, ok := hb[agentruntime.DeliveryAzureDiag+"|"+HeartbeatRef(id)]; ok && h.State == "silent" {
				s.DiagSilent = true
			}
		}
		scopes = append(scopes, s)
	}

	if ok, err := relExists(tx, "discovery_sources"); err != nil {
		return nil, w, err
	} else if ok {
		var clusters []struct {
			ID          uuid.UUID
			ClusterName string
		}
		if err := tx.Raw(`SELECT id, cluster_name FROM discovery_sources WHERE workspace_id = ? AND kind = ? ORDER BY id`,
			ws, models.DiscoverySourceK8sWebhook).Scan(&clusters).Error; err != nil {
			return nil, w, err
		}
		for _, c := range clusters {
			id := c.ID
			s := coverageScope{Scope: "cluster/" + c.ID.String(), Kind: "cluster", Provider: models.ProviderK8s, ConnectorID: &id}
			if h, ok := hb[agentruntime.DeliveryK8sAudit+"|"+HeartbeatRef(id)]; ok {
				s.AuditSeen, s.AuditSilent = true, h.State == "silent"
			}
			scopes = append(scopes, s)
		}
	}
	if len(scopes) == 0 {
		scopes = append(scopes, coverageScope{Scope: "workspace", Kind: "workspace"})
	}
	return scopes, w, nil
}

// computeCapabilities writes ws's capability states: one row per scope and
// capability; since moves only when the state changes; a declaration lapses
// once the capability is on; scopes no longer connected are removed.
func computeCapabilities(tx *gorm.DB, ws uuid.UUID, now time.Time) error {
	hbs, err := readHeartbeats(tx, ws)
	if err != nil {
		return err
	}
	scopes, w, err := gatherCoverage(tx, ws, hbs, now)
	if err != nil {
		return err
	}
	var keep []string
	for _, s := range scopes {
		keep = append(keep, s.Scope)
		for _, r := range computeScopeCapabilities(s, w) {
			gap := GapBroken
			if r.State == CapabilityOn {
				gap = GapNone
			}
			if err := tx.Exec(`INSERT INTO agent_capability_state (workspace_id, estate_scope, scope_kind, connector_id, capability,
			                       state, gap_kind, since, detail, fallback, computed_at)
			                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			                   ON CONFLICT (workspace_id, estate_scope, capability) DO UPDATE SET
			                     scope_kind      = EXCLUDED.scope_kind,
			                     connector_id    = EXCLUDED.connector_id,
			                     since           = CASE WHEN agent_capability_state.state <> EXCLUDED.state THEN EXCLUDED.since
			                                            ELSE agent_capability_state.since END,
			                     gap_kind        = CASE WHEN EXCLUDED.state = 'on' THEN 'none'
			                                            WHEN agent_capability_state.declared_at IS NOT NULL THEN 'declared'
			                                            ELSE 'broken' END,
			                     declared_by     = CASE WHEN EXCLUDED.state = 'on' THEN NULL ELSE agent_capability_state.declared_by END,
			                     declared_at     = CASE WHEN EXCLUDED.state = 'on' THEN NULL ELSE agent_capability_state.declared_at END,
			                     declared_reason = CASE WHEN EXCLUDED.state = 'on' THEN '' ELSE agent_capability_state.declared_reason END,
			                     state           = EXCLUDED.state,
			                     detail          = EXCLUDED.detail,
			                     fallback        = EXCLUDED.fallback,
			                     computed_at     = EXCLUDED.computed_at`,
				ws, truncate(s.Scope, 256), s.Kind, s.ConnectorID, r.Capability, r.State, gap, now,
				truncate(r.Detail, 2000), truncate(r.Fallback, 2000), now).Error; err != nil {
				return err
			}
		}
	}
	return tx.Exec(`DELETE FROM agent_capability_state WHERE workspace_id = ? AND NOT (estate_scope = ANY(?::text[]))`,
		ws, "{"+strings.Join(quoteArray(keep), ",")+"}").Error
}

// quoteArray quotes values for a Postgres text[] literal.
func quoteArray(xs []string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(x) + `"`
	}
	return out
}

/* ------------------------------------------------------------------------- */
/*                                 The service                                */
/* ------------------------------------------------------------------------- */

// AgentCoverageService serves the coverage APIs and runs the coverage passes.
type AgentCoverageService struct {
	db  *gorm.DB
	now func() time.Time
}

// NewAgentCoverageService builds the service over db.
func NewAgentCoverageService(db *gorm.DB) *AgentCoverageService {
	return &AgentCoverageService{db: db, now: time.Now}
}

// WithClock replaces the wall clock (tests).
func (s *AgentCoverageService) WithClock(now func() time.Time) *AgentCoverageService {
	s.now = now
	return s
}

// EvaluateSources syncs the stream heartbeats and judges every heartbeat of
// ws (COV-01 open / resolve, gap backfills). Alerts are raised only once the
// alert schema (150) verified.
func (s *AgentCoverageService) EvaluateSources(ctx context.Context, ws uuid.UUID) ([]heartbeatTransition, error) {
	now := s.now().UTC()
	// TENANT-EXEMPT: the 150 schema check reads the Postgres catalog only.
	alerts, _ := AgentAlertsStatus(s.db)
	var out []heartbeatTransition
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		if ok, err := relExists(tx, "agent_event_stream"); err != nil {
			return err
		} else if ok {
			if err := syncStreamHeartbeats(tx, ws, now); err != nil {
				return err
			}
		}
		var err error
		out, err = evaluateHeartbeats(tx, ws, now, alerts)
		return err
	})
	return out, err
}

// ComputeCapabilities recomputes ws's capability states.
func (s *AgentCoverageService) ComputeCapabilities(ctx context.Context, ws uuid.UUID) error {
	now := s.now().UTC()
	return tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		return computeCapabilities(tx, ws, now)
	})
}

// Sources is the workspace's heartbeats, each with its silence judged now.
func (s *AgentCoverageService) Sources(ctx context.Context, ws uuid.UUID) ([]SourceHeartbeat, error) {
	var out []SourceHeartbeat
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		out, err = readHeartbeats(tx, ws)
		return err
	})
	return out, err
}

// AgentCapabilityState is one agent_capability_state row as the API shows it.
type AgentCapabilityState struct {
	ID             uuid.UUID  `json:"id" gorm:"column:id"`
	EstateScope    string     `json:"estate_scope" gorm:"column:estate_scope"`
	ScopeKind      string     `json:"scope_kind" gorm:"column:scope_kind"`
	ConnectorID    *uuid.UUID `json:"connector_id" gorm:"column:connector_id"`
	Capability     string     `json:"capability" gorm:"column:capability"`
	Name           string     `json:"name" gorm:"-"`
	State          string     `json:"state" gorm:"column:state"`
	GapKind        string     `json:"gap_kind" gorm:"column:gap_kind"`
	Since          time.Time  `json:"since" gorm:"column:since"`
	Detail         string     `json:"detail" gorm:"column:detail"`
	Fallback       string     `json:"fallback" gorm:"column:fallback"`
	DeclaredBy     *uuid.UUID `json:"declared_by" gorm:"column:declared_by"`
	DeclaredAt     *time.Time `json:"declared_at" gorm:"column:declared_at"`
	DeclaredReason string     `json:"declared_reason" gorm:"column:declared_reason"`
	ComputedAt     time.Time  `json:"computed_at" gorm:"column:computed_at"`
	// PendingDeclaration is the open declare request, if any.
	PendingDeclaration *AgentCapabilityDeclaration `json:"pending_declaration,omitempty" gorm:"-"`
}

const agentCapabilityStateColumns = `id, estate_scope, scope_kind, connector_id, capability, state, gap_kind, since, detail,
	fallback, declared_by, declared_at, declared_reason, computed_at`

// AgentCapabilityDeclaration is one agent_capability_declaration row.
type AgentCapabilityDeclaration struct {
	ID                uuid.UUID  `json:"id" gorm:"column:id"`
	CapabilityStateID uuid.UUID  `json:"capability_state_id" gorm:"column:capability_state_id"`
	Reason            string     `json:"reason" gorm:"column:reason"`
	RequestedBy       uuid.UUID  `json:"requested_by" gorm:"column:requested_by"`
	RequestedAt       time.Time  `json:"requested_at" gorm:"column:requested_at"`
	State             string     `json:"state" gorm:"column:state"`
	DecidedBy         *uuid.UUID `json:"decided_by" gorm:"column:decided_by"`
	DecidedAt         *time.Time `json:"decided_at" gorm:"column:decided_at"`
	DecisionReason    string     `json:"decision_reason" gorm:"column:decision_reason"`
	BreakGlass        bool       `json:"break_glass" gorm:"column:break_glass"`
	ReviewDueAt       *time.Time `json:"review_due_at" gorm:"column:review_due_at"`
	ReviewedBy        *uuid.UUID `json:"reviewed_by" gorm:"column:reviewed_by"`
	ReviewedAt        *time.Time `json:"reviewed_at" gorm:"column:reviewed_at"`
}

const agentCapabilityDeclarationColumns = `id, capability_state_id, reason, requested_by, requested_at, state, decided_by,
	decided_at, decision_reason, break_glass, review_due_at, reviewed_by, reviewed_at`

// CoverageCapabilitiesFilter filters GET /coverage/capabilities.
type CoverageCapabilitiesFilter struct {
	Scope, Capability, State string
}

// Capabilities is GET /coverage/capabilities: every scope's states (scope,
// then C1..C13), each with its open declare request.
func (s *AgentCoverageService) Capabilities(ctx context.Context, ws uuid.UUID, f CoverageCapabilitiesFilter) ([]AgentCapabilityState, error) {
	if f.Capability != "" && CoverageCapabilityNames[f.Capability] == "" {
		return nil, GovBadParam("capability", "capability must be one of C1..C13.")
	}
	switch f.State {
	case "", CapabilityOn, CapabilityPartial, CapabilityOff:
	default:
		return nil, GovBadParam("state", "state must be on, partial or off.")
	}
	q := `SELECT ` + agentCapabilityStateColumns + ` FROM agent_capability_state WHERE workspace_id = ?`
	args := []any{ws}
	if f.Scope != "" {
		q += ` AND estate_scope = ?`
		args = append(args, f.Scope)
	}
	if f.Capability != "" {
		q += ` AND capability = ?`
		args = append(args, f.Capability)
	}
	if f.State != "" {
		q += ` AND state = ?`
		args = append(args, f.State)
	}
	var rows []AgentCapabilityState
	var pending []AgentCapabilityDeclaration
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		if err := tx.Raw(q, args...).Scan(&rows).Error; err != nil {
			return err
		}
		return tx.Raw(`SELECT `+agentCapabilityDeclarationColumns+` FROM agent_capability_declaration
		               WHERE workspace_id = ? AND state = 'pending'`, ws).Scan(&pending).Error
	})
	if err != nil {
		return nil, err
	}
	byState := map[uuid.UUID]*AgentCapabilityDeclaration{}
	for i := range pending {
		byState[pending[i].CapabilityStateID] = &pending[i]
	}
	order := map[string]int{}
	for i, c := range CoverageCapabilities {
		order[c] = i
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].EstateScope != rows[j].EstateScope {
			return rows[i].EstateScope < rows[j].EstateScope
		}
		return order[rows[i].Capability] < order[rows[j].Capability]
	})
	for i := range rows {
		rows[i].Name = CoverageCapabilityNames[rows[i].Capability]
		rows[i].PendingDeclaration = byState[rows[i].ID]
	}
	if rows == nil {
		rows = []AgentCapabilityState{}
	}
	return rows, nil
}

/* ------------------------------------------------------------------------- */
/*                         Declaring a gap (tier 3)                           */
/* ------------------------------------------------------------------------- */

// Declare errors.
const (
	GovCodeCoverageNothingToDeclare = "nothing_to_declare"
	GovCodeCoverageAlreadyDeclared  = "already_declared"
	GovCodeCoverageDeclarePending   = "declaration_pending"
	GovCodeCoverageNoApprover       = "no_approver"
	GovCodeCoverageNotPending       = "declaration_not_pending"
	GovCodeCoverageNotBreakGlass    = "not_break_glass"
)

func errCoverageNotFound() error { return govErr(http.StatusNotFound, "not_found", "Not found.", nil) }

func loadCapabilityState(tx *gorm.DB, ws, id uuid.UUID, lock bool) (*AgentCapabilityState, error) {
	q := `SELECT ` + agentCapabilityStateColumns + ` FROM agent_capability_state WHERE workspace_id = ? AND id = ?`
	if lock {
		q += ` FOR UPDATE`
	}
	var rows []AgentCapabilityState
	if err := tx.Raw(q, ws, id).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errCoverageNotFound()
	}
	rows[0].Name = CoverageCapabilityNames[rows[0].Capability]
	return &rows[0], nil
}

func loadDeclaration(tx *gorm.DB, ws, id uuid.UUID) (*AgentCapabilityDeclaration, error) {
	var rows []AgentCapabilityDeclaration
	if err := tx.Raw(`SELECT `+agentCapabilityDeclarationColumns+` FROM agent_capability_declaration
	                   WHERE workspace_id = ? AND id = ? FOR UPDATE`, ws, id).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errCoverageNotFound()
	}
	return &rows[0], nil
}

// applyDeclaration marks the capability state declared.
func applyDeclaration(tx *gorm.DB, ws uuid.UUID, d *AgentCapabilityDeclaration, now time.Time) error {
	return tx.Exec(`UPDATE agent_capability_state SET gap_kind = 'declared', declared_by = ?, declared_at = ?, declared_reason = ?
	                 WHERE workspace_id = ? AND id = ? AND state <> 'on'`,
		d.RequestedBy, now, d.Reason, ws, d.CapabilityStateID).Error
}

// DeclareResult is what a declare request did.
type DeclareResult struct {
	Declaration AgentCapabilityDeclaration `json:"declaration"`
	State       AgentCapabilityState       `json:"capability_state"`
}

// Declare is PUT /coverage/capabilities/:id/declare (tier 3). It records the
// request; a second member holding governance:approve applies it (Approve).
// When the requester is the workspace's only holder of governance:approve
// (decision 4) the declaration is applied at once as break-glass, logged, and
// a review by a second person is due within 24 hours. A requester with no
// other approver who is not an approver either is refused (no_approver).
func (s *AgentCoverageService) Declare(ctx context.Context, ws, stateID, actor uuid.UUID, reason string) (*DeclareResult, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 2000 {
		return nil, GovBadParam("reason", "A declaration needs a reason (at most 2000 characters).")
	}
	now := s.now().UTC()
	var out *DeclareResult
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		st, err := loadCapabilityState(tx, ws, stateID, true)
		if err != nil {
			return err
		}
		if st.State == CapabilityOn {
			return govConflict(GovCodeCoverageNothingToDeclare, "The capability is on: there is no gap to declare.", nil)
		}
		if st.GapKind == GapDeclared {
			return govConflict(GovCodeCoverageAlreadyDeclared, "The gap is already declared.", nil)
		}
		var open int64
		if err := tx.Raw(`SELECT count(*) FROM agent_capability_declaration WHERE workspace_id = ? AND capability_state_id = ? AND state = 'pending'`,
			ws, stateID).Scan(&open).Error; err != nil {
			return err
		}
		if open > 0 {
			return govConflict(GovCodeCoverageDeclarePending, "A declaration of this gap is already waiting for a second person.", nil)
		}
		if err := CheckTier3Requester(ctx); err != nil {
			return err
		}
		breakGlass, err := BreakGlassAllowed(ctx, tx, ws, actor)
		if err != nil {
			return err
		}
		if !breakGlass {
			// W1's own refusal, kept: a request nobody could ever decide.
			holders, err := WorkspaceUsersHoldingPermission(tx, ws, "governance", "approve")
			if err != nil {
				return err
			}
			if len(holders) == 0 {
				return govConflict(GovCodeCoverageNoApprover, "Nobody in the workspace holds governance:approve, so the declaration could not be decided.", nil)
			}
		}
		var d AgentCapabilityDeclaration
		if breakGlass {
			due := ReviewDue(now)
			if err := tx.Raw(`INSERT INTO agent_capability_declaration (workspace_id, capability_state_id, reason, requested_by, requested_at,
			                         state, decided_by, decided_at, decision_reason, break_glass, review_due_at)
			                  VALUES (?, ?, ?, ?, ?, 'applied', ?, ?, 'break-glass: the workspace has one approver', true, ?)
			                  RETURNING `+agentCapabilityDeclarationColumns, ws, stateID, reason, actor, now, actor, now, due).Scan(&d).Error; err != nil {
				return err
			}
			if err := applyDeclaration(tx, ws, &d, now); err != nil {
				return err
			}
			if err := appendGovEvent(tx, ws, GovEventCoverageBreakGlassApplied, models.GovActorUser, actor.String(), govEventRefs{},
				map[string]any{"capability_state_id": stateID, "declaration_id": d.ID, "capability": st.Capability,
					"estate_scope": st.EstateScope, "reason": reason, "review_due_at": due}); err != nil {
				return err
			}
		} else {
			if err := tx.Raw(`INSERT INTO agent_capability_declaration (workspace_id, capability_state_id, reason, requested_by, requested_at)
			                  VALUES (?, ?, ?, ?, ?) RETURNING `+agentCapabilityDeclarationColumns, ws, stateID, reason, actor, now).Scan(&d).Error; err != nil {
				return err
			}
			if err := appendGovEvent(tx, ws, GovEventCoverageDeclareRequested, models.GovActorUser, actor.String(), govEventRefs{},
				map[string]any{"capability_state_id": stateID, "declaration_id": d.ID, "capability": st.Capability,
					"estate_scope": st.EstateScope, "reason": reason}); err != nil {
				return err
			}
		}
		st, err = loadCapabilityState(tx, ws, stateID, false)
		if err != nil {
			return err
		}
		out = &DeclareResult{Declaration: d, State: *st}
		return nil
	})
	return out, err
}

// Decide is POST /coverage/declarations/:id/approve or /reject: a second
// member holding governance:approve (now, in the database) decides a
// pending declaration; the requester never decides their own.
func (s *AgentCoverageService) Decide(ctx context.Context, ws, declID, approver uuid.UUID, approve bool, reason string) (*DeclareResult, error) {
	reason = strings.TrimSpace(reason)
	if len(reason) > 2000 {
		return nil, GovBadParam("reason", "reason must be at most 2000 characters.")
	}
	if !approve && reason == "" {
		return nil, GovBadParam("reason", "A rejection needs a reason.")
	}
	now := s.now().UTC()
	var out *DeclareResult
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		d, err := loadDeclaration(tx, ws, declID)
		if err != nil {
			return err
		}
		if err := CheckApprover(ctx, tx, ws, d.RequestedBy, approver); err != nil {
			return err
		}
		if d.State != "pending" {
			return govConflict(GovCodeCoverageNotPending, "Only a pending declaration can be decided.", map[string]any{"state": d.State})
		}
		st, err := loadCapabilityState(tx, ws, d.CapabilityStateID, true)
		if err != nil {
			return err
		}
		to, event := "rejected", GovEventCoverageDeclareRejected
		if approve {
			to, event = "applied", GovEventCoverageGapDeclared
		}
		if err := tx.Exec(`UPDATE agent_capability_declaration SET state = ?, decided_by = ?, decided_at = ?, decision_reason = ?
		                    WHERE workspace_id = ? AND id = ?`, to, approver, now, reason, ws, declID).Error; err != nil {
			return err
		}
		d.State, d.DecidedBy, d.DecidedAt, d.DecisionReason = to, &approver, &now, reason
		if approve {
			if err := applyDeclaration(tx, ws, d, now); err != nil {
				return err
			}
		}
		if err := appendGovEvent(tx, ws, event, models.GovActorUser, approver.String(), govEventRefs{},
			map[string]any{"capability_state_id": d.CapabilityStateID, "declaration_id": d.ID, "capability": st.Capability,
				"estate_scope": st.EstateScope, "requested_by": d.RequestedBy, "reason": reason}); err != nil {
			return err
		}
		if st, err = loadCapabilityState(tx, ws, d.CapabilityStateID, false); err != nil {
			return err
		}
		out = &DeclareResult{Declaration: *d, State: *st}
		return nil
	})
	return out, err
}

// Review is POST /coverage/declarations/:id/review: a second member holding
// governance:approve reviews a break-glass declaration.
func (s *AgentCoverageService) Review(ctx context.Context, ws, declID, reviewer uuid.UUID) (*AgentCapabilityDeclaration, error) {
	now := s.now().UTC()
	var out *AgentCapabilityDeclaration
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		d, err := loadDeclaration(tx, ws, declID)
		if err != nil {
			return err
		}
		if !d.BreakGlass {
			return govConflict(GovCodeCoverageNotBreakGlass, "Only a break-glass declaration is reviewed.", nil)
		}
		if err := CheckApprover(ctx, tx, ws, d.RequestedBy, reviewer); err != nil {
			return err
		}
		if d.ReviewedAt != nil {
			out = d
			return nil
		}
		if err := tx.Exec(`UPDATE agent_capability_declaration SET reviewed_by = ?, reviewed_at = ? WHERE workspace_id = ? AND id = ?`,
			reviewer, now, ws, declID).Error; err != nil {
			return err
		}
		d.ReviewedBy, d.ReviewedAt = &reviewer, &now
		if err := appendGovEvent(tx, ws, GovEventCoverageBreakGlassReview, models.GovActorUser, reviewer.String(), govEventRefs{},
			map[string]any{"capability_state_id": d.CapabilityStateID, "declaration_id": d.ID, "requested_by": d.RequestedBy}); err != nil {
			return err
		}
		out = d
		return nil
	})
	return out, err
}

/* ------------------------------------------------------------------------- */
/*                                  /capabilities                             */
/* ------------------------------------------------------------------------- */

// CoverageCapabilitiesBlock is /api/iga/v1/capabilities' additive "sources"
// and "capabilities" blocks for ws: the heartbeats, and per scope its
// capability states. Empty (never an error) until migration 170 verified.
func CoverageCapabilitiesBlock(ctx context.Context, db *gorm.DB, ws uuid.UUID) (sources []SourceHeartbeat, scopes []map[string]any) {
	sources, scopes = []SourceHeartbeat{}, []map[string]any{}
	if db == nil || ws == uuid.Nil {
		return
	}
	// TENANT-EXEMPT: the 170 schema check reads the Postgres catalog only.
	if ok, _ := AgentEvidenceStatus(db); !ok {
		return
	}
	svc := NewAgentCoverageService(db)
	if hb, err := svc.Sources(ctx, ws); err == nil {
		sources = hb
	} else {
		log.Printf("[coverage] capabilities: sources for %s: %v", ws, err)
	}
	states, err := svc.Capabilities(ctx, ws, CoverageCapabilitiesFilter{})
	if err != nil {
		log.Printf("[coverage] capabilities: states for %s: %v", ws, err)
		return
	}
	idx := map[string]int{}
	for _, st := range states {
		i, ok := idx[st.EstateScope]
		if !ok {
			i = len(scopes)
			idx[st.EstateScope] = i
			scopes = append(scopes, map[string]any{"estate_scope": st.EstateScope, "scope_kind": st.ScopeKind,
				"connector_id": st.ConnectorID, "capabilities": []map[string]any{}})
		}
		caps := scopes[i]["capabilities"].([]map[string]any)
		scopes[i]["capabilities"] = append(caps, map[string]any{"id": st.ID, "capability": st.Capability, "name": st.Name,
			"state": st.State, "gap_kind": st.GapKind, "since": st.Since, "detail": st.Detail, "fallback": st.Fallback})
	}
	return
}

/* ------------------------------------------------------------------------- */
/*                                   Worker                                   */
/* ------------------------------------------------------------------------- */

// Worker cadence.
const (
	coverageSourcesEvery      = time.Minute
	coverageCapabilitiesEvery = 15 * time.Minute
	evidencePurgeEvery        = time.Hour
)

// coverageWorkspaces lists the workspaces the coverage worker visits.
func coverageWorkspaces(ctx context.Context, db *gorm.DB) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	// TENANT-EXEMPT: the coverage worker runs across workspaces (no request tenant) and lists workspace ids from the tenant registry only; every statement after runs in that workspace's RLS transaction.
	err := db.WithContext(ctx).Raw(`SELECT id FROM workspaces ORDER BY id`).Scan(&ids).Error
	return ids, err
}

// RunAgentCoverageWorker runs the evidence and coverage passes: every minute
// the sources (heartbeats, COV-01), every 15 minutes the capability states,
// every hour the evidence retention purge. AUTHSEC_DISABLE_AGENT_COVERAGE_WORKER=true
// turns it off.
func RunAgentCoverageWorker(ctx context.Context, db *gorm.DB) {
	if os.Getenv("AUTHSEC_DISABLE_AGENT_COVERAGE_WORKER") == "true" {
		log.Printf("[coverage] worker not started: AUTHSEC_DISABLE_AGENT_COVERAGE_WORKER=true")
		return
	}
	cov := NewAgentCoverageService(db)
	ev := NewAgentEvidenceService(db)
	var lastCaps, lastPurge time.Time
	for {
		// TENANT-EXEMPT: the 170 schema check reads the Postgres catalog only.
		if ok, reason := AgentEvidenceStatus(db); !ok {
			agentEvidenceGate.logWait("coverage worker", reason)
		} else if err := runCoveragePass(ctx, db, cov, ev, &lastCaps, &lastPurge); err != nil && ctx.Err() == nil {
			log.Printf("[coverage] pass: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(coverageSourcesEvery):
		}
	}
}

func runCoveragePass(ctx context.Context, db *gorm.DB, cov *AgentCoverageService, ev *AgentEvidenceService, lastCaps, lastPurge *time.Time) error {
	wss, err := coverageWorkspaces(ctx, db)
	if err != nil {
		return err
	}
	caps := time.Since(*lastCaps) >= coverageCapabilitiesEvery
	purge := time.Since(*lastPurge) >= evidencePurgeEvery
	var errs []error
	for _, ws := range wss {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, err := cov.EvaluateSources(ctx, ws); err != nil {
			errs = append(errs, fmt.Errorf("sources %s: %w", ws, err))
		}
		if caps {
			if err := cov.ComputeCapabilities(ctx, ws); err != nil {
				errs = append(errs, fmt.Errorf("capabilities %s: %w", ws, err))
			}
		}
		if purge {
			if _, err := ev.Purge(ctx, ws); err != nil {
				errs = append(errs, fmt.Errorf("retention %s: %w", ws, err))
			}
		}
	}
	if caps {
		*lastCaps = time.Now()
	}
	if purge {
		*lastPurge = time.Now()
	}
	return errors.Join(errs...)
}
