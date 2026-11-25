package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/tenancy"
)

// Agent runtime evidence store (SPEC-secops-backend-upgrade W1, P8, C1).
//
// The "agent_evidence" EventSink stores EVERY event dispatched for a
// connector -- from the event stream, the scan poller, a trail-bucket
// backfill, the Azure and Kubernetes collectors -- for every principal of
// the connected account, not only the labelled AI workloads and agents the
// other sinks look at. One row per (workspace, provider, event id), inserted
// ON CONFLICT DO NOTHING, so the same CloudTrail event from the stream and
// the poller is stored once (source = the path that delivered it first).
//
// What is stored: the redacted normalised event (agentruntime.Event):
// names, ARNs and ids, the request facts by fixed key, resources, result.
// Never a request or response body, an error message (it can echo input),
// a secret value or a prompt. raw_hash is sha256 of the record as received,
// so a copy of the raw record can be matched against it later.
//
// Each batch also refreshes the heartbeat of the source that delivered it
// (source_heartbeat), which the coverage worker turns into silence alerts
// (COV-01) and capability states (agent_coverage.go).
//
// Retention is by record class (agent_evidence_retention; default 90 d,
// elevated 1 y, regulated 7 y); rows pinned by a case (pin_count > 0) are
// never purged.
//
// Every statement runs in a transaction under row-level security for the
// batch's workspace (tenancy.InWorkspace).

// Sink name, schema head and 503 code.
const (
	AgentEvidenceSinkName              = "agent_evidence"
	AgentEvidenceSchemaHead            = "170"
	GovCodeAgentEvidenceUnavailable    = "agent_evidence_unavailable"
	agentEvidenceInsertChunk           = 400
	agentEvidenceBodyString            = 512
	agentEvidenceBodyItems             = 20
	agentEvidenceMaxIDLen              = 256
	agentEvidencePurgeBatch            = 5000
	agentEvidenceDefaultListLimit      = 100
	agentEvidenceMaxListLimit          = 500
	agentEvidenceDefaultStreamSilentHB = 6 * time.Hour
)

// Record classes (retention).
const (
	EvidenceClassDefault   = "default"
	EvidenceClassElevated  = "elevated"
	EvidenceClassRegulated = "regulated"
)

// DefaultEvidenceRetentionDays is decision 5: 90 days, 1 year, 7 years.
var DefaultEvidenceRetentionDays = map[string]int{
	EvidenceClassDefault: 90, EvidenceClassElevated: 365, EvidenceClassRegulated: 7 * 365,
}

var agentEvidenceGate = &agentSchemaGate{head: AgentEvidenceSchemaHead, relations: []string{
	"agent_evidence_event", "agent_evidence_retention", "source_heartbeat", "agent_capability_state",
	"agent_capability_declaration", "agent_ingest_secret", "agent_trail_backfill"}}

// AgentEvidenceStatus is whether the evidence store and coverage can run
// (migration 170).
func AgentEvidenceStatus(db *gorm.DB) (bool, string) { return agentEvidenceGate.status(db) }

// RequireAgentEvidence is nil while evidence and coverage can run, else the 503.
func RequireAgentEvidence(db *gorm.DB) error {
	if ok, reason := AgentEvidenceStatus(db); !ok {
		return govErr(http.StatusServiceUnavailable, GovCodeAgentEvidenceUnavailable,
			"Agent runtime evidence and coverage are not available on this server.", map[string]any{"reason": reason})
	}
	return nil
}

// AgentEvidenceCapabilities is /capabilities' agent_evidence block.
func AgentEvidenceCapabilities(db *gorm.DB) map[string]any {
	ok, reason := AgentEvidenceStatus(db)
	return map[string]any{"available": ok, "reason": nullable(reason)}
}

/* ------------------------------------------------------------------------- */
/*                                  The sink                                  */
/* ------------------------------------------------------------------------- */

// AgentEvidenceSink is the "agent_evidence" agentruntime.EventSink.
type AgentEvidenceSink struct {
	db  *gorm.DB
	now func() time.Time
}

// NewAgentEvidenceSink builds the sink over db.
func NewAgentEvidenceSink(db *gorm.DB) *AgentEvidenceSink {
	return &AgentEvidenceSink{db: db, now: time.Now}
}

// WithClock replaces the wall clock (tests).
func (s *AgentEvidenceSink) WithClock(now func() time.Time) *AgentEvidenceSink {
	s.now = now
	return s
}

// RegisterAgentEvidenceSink registers the sink (cmd/main.go). It comes first:
// every event is evidence, whatever the other sinks decide.
func RegisterAgentEvidenceSink(db *gorm.DB) {
	agentruntime.RegisterSink(NewAgentEvidenceSink(db))
}

// Name implements agentruntime.EventSink.
func (s *AgentEvidenceSink) Name() string { return AgentEvidenceSinkName }

// evidenceRow is one agent_evidence_event insert.
type evidenceRow struct {
	Provider, EventID                         string
	EventTime                                 time.Time
	SkewMS                                    int64
	Principal, PrincipalKind, PrincipalDetail string
	AccountID, Region, EventSource, EventName string
	Outcome, RawHash, Body, RecordClass       string
}

// Process implements agentruntime.EventSink: it stores the batch and
// refreshes the delivering source's heartbeat. Without migration 170 the sink
// is absent, not failing.
func (s *AgentEvidenceSink) Process(ctx context.Context, workspaceID, connectorID uuid.UUID, events []agentruntime.Event) error {
	if workspaceID == uuid.Nil || len(events) == 0 {
		return nil
	}
	// TENANT-EXEMPT: the 170 schema check reads the Postgres catalog only.
	if ok, reason := AgentEvidenceStatus(s.db); !ok {
		agentEvidenceGate.logWait("evidence sink", reason)
		return nil
	}
	d := agentruntime.DeliveryFrom(ctx)
	now := s.now().UTC()
	rows := make([]evidenceRow, 0, len(events))
	seen := map[string]bool{}
	var newest time.Time
	for _, e := range events {
		row, ok := evidenceRowOf(e, now)
		if !ok || seen[row.Provider+"|"+row.EventID] {
			continue
		}
		seen[row.Provider+"|"+row.EventID] = true
		rows = append(rows, row)
		if row.EventTime.After(newest) && !row.EventTime.After(now.Add(time.Hour)) {
			newest = row.EventTime
		}
	}
	if len(rows) == 0 {
		return nil
	}
	var conn *uuid.UUID
	if connectorID != uuid.Nil {
		conn = &connectorID
	}
	return tenancy.InWorkspace(ctx, s.db, workspaceID, func(tx *gorm.DB) error {
		if err := insertEvidenceRows(tx, workspaceID, d.Kind, conn, rows, now); err != nil {
			return fmt.Errorf("agent evidence: insert: %w", err)
		}
		var last *time.Time
		if !newest.IsZero() {
			last = &newest
		}
		if err := touchSourceHeartbeat(tx, workspaceID, d, conn, last, now); err != nil {
			return fmt.Errorf("agent evidence: heartbeat: %w", err)
		}
		return nil
	})
}

// evidenceRowOf builds the stored row of e; false for an event without id.
func evidenceRowOf(e agentruntime.Event, now time.Time) (evidenceRow, bool) {
	if e.EventID == "" || len(e.EventID) > agentEvidenceMaxIDLen {
		return evidenceRow{}, false
	}
	body := evidenceBody(e)
	raw, err := json.Marshal(body)
	if err != nil {
		return evidenceRow{}, false
	}
	hash := e.RawHash
	if len(hash) != 64 {
		hash = agentruntime.RawHash(raw)
	}
	at := e.EventTime.UTC()
	if at.IsZero() {
		at = now
	}
	r := evidenceRow{
		Provider: e.ProviderOf(), EventID: e.EventID, EventTime: at, SkewMS: now.Sub(at).Milliseconds(),
		PrincipalKind: truncate(e.PrincipalType, 64), AccountID: truncate(e.AccountID, 256),
		Region: truncate(e.Region, 64), EventSource: truncate(e.EventSource, 256), EventName: truncate(e.EventName, 256),
		Outcome: "success", RawHash: hash, Body: string(raw), RecordClass: evidenceRecordClass(e),
	}
	r.Principal, r.PrincipalDetail = evidencePrincipal(e)
	switch {
	case e.AuthorizationDenied:
		r.Outcome = "denied"
	case e.ErrorCode != "":
		r.Outcome = "error"
	}
	return r, true
}

// evidencePrincipal is the principal an evidence query names, and the caller
// as the record states it. AWS: an assumed role's role ARN (the session
// issuer), an IAM user's ARN, else the caller ARN. Azure: the Entra object
// id. Kubernetes: the user name.
func evidencePrincipal(e agentruntime.Event) (string, string) {
	detail := truncate(e.PrincipalARN, 2048)
	switch e.ProviderOf() {
	case agentruntime.ProviderAzure:
		if e.PrincipalID != "" {
			return truncate(e.PrincipalID, 2048), detail
		}
		return detail, detail
	case agentruntime.ProviderK8s:
		return detail, truncate(e.PrincipalID, 2048)
	}
	if a := e.Attribution(); a.ARN != "" {
		return truncate(a.ARN, 2048), detail
	}
	if detail == "" {
		detail = truncate(e.UserName, 2048)
	}
	return detail, detail
}

// sensitiveEvidenceSources are services whose calls keep evidence for the
// elevated period: identity, credentials, keys, secrets and logging.
var sensitiveEvidenceSources = map[string]bool{
	"iam.amazonaws.com": true, "sts.amazonaws.com": true, "secretsmanager.amazonaws.com": true,
	"kms.amazonaws.com": true, "cloudtrail.amazonaws.com": true, "organizations.amazonaws.com": true,
	"signin.amazonaws.com": true, "sso.amazonaws.com": true,
	"azure:microsoft.authorization": true, "azure:microsoft.keyvault": true, "azure:entra-audit": true,
	"azure:microsoft.managedidentity": true, "k8s:rbac.authorization.k8s.io": true,
}

// evidenceRecordClass is the retention class an event is stored with:
// elevated for authorization refusals, model calls and calls to identity,
// credential, key, secret and logging services (and Kubernetes secrets);
// default otherwise. Regulated is never inferred: it is set when a case or a
// classification asks for it.
func evidenceRecordClass(e agentruntime.Event) string {
	switch {
	case e.AuthorizationDenied, e.IsModelCall(), sensitiveEvidenceSources[strings.ToLower(e.EventSource)]:
		return EvidenceClassElevated
	case e.ProviderOf() == agentruntime.ProviderK8s && strings.Contains(e.EventName, " secrets"):
		return EvidenceClassElevated
	}
	return EvidenceClassDefault
}

// evidenceBody is the redacted normalised event (the same fields as the
// activity timeline keeps, agentactivity.FromCloudTrail): no request or
// response body, no error message.
func evidenceBody(e agentruntime.Event) map[string]any {
	b := map[string]any{"provider": e.ProviderOf(), "event_source": truncate(e.EventSource, agentEvidenceBodyString),
		"event_name": truncate(e.EventName, agentEvidenceBodyString)}
	put := func(k, v string) {
		if v != "" {
			b[k] = truncate(v, agentEvidenceBodyString)
		}
	}
	put("event_type", e.EventType)
	put("event_category", e.EventCategory)
	put("account_id", e.AccountID)
	put("region", e.Region)
	put("source_ip", e.SourceIP)
	put("user_agent", e.UserAgent)
	put("error_code", e.ErrorCode)
	put("principal_type", e.PrincipalType)
	put("principal_arn", e.PrincipalARN)
	put("principal_id", e.PrincipalID)
	put("session_issuer_type", e.SessionIssuerType)
	put("session_issuer_arn", e.SessionIssuerARN)
	put("user_name", e.UserName)
	put("invoked_by", e.InvokedBy)
	// Weak, unverified evidence only (as on the activity timeline).
	put("session_name", e.SessionName)
	if e.ReadOnly != nil {
		b["read_only"] = *e.ReadOnly
	}
	if e.AuthorizationDenied {
		b["authorization_denied"] = true
	}
	if len(e.RequestFacts) > 0 {
		facts := map[string]any{}
		for k, v := range e.RequestFacts {
			facts[k] = truncate(v, agentEvidenceBodyString)
		}
		b["request_facts"] = facts
	}
	if len(e.Resources) > 0 {
		var res []string
		for _, r := range e.Resources {
			if len(res) == agentEvidenceBodyItems {
				break
			}
			res = append(res, truncate(r, agentEvidenceBodyString))
		}
		b["resources"] = res
	}
	return b
}

// insertEvidenceRows inserts rows ON CONFLICT DO NOTHING, in chunks.
func insertEvidenceRows(tx *gorm.DB, ws uuid.UUID, source string, conn *uuid.UUID, rows []evidenceRow, now time.Time) error {
	if !validEvidenceSource(source) {
		source = agentruntime.DeliveryOther
	}
	for start := 0; start < len(rows); start += agentEvidenceInsertChunk {
		end := start + agentEvidenceInsertChunk
		if end > len(rows) {
			end = len(rows)
		}
		var sb strings.Builder
		sb.WriteString(`INSERT INTO agent_evidence_event (workspace_id, provider, source, event_id, connector_id, event_time,
			received_at, skew_ms, principal, principal_kind, principal_detail, account_id, region, event_source, event_name,
			outcome, raw_hash, body, record_class) VALUES `)
		args := make([]any, 0, (end-start)*19)
		for i, r := range rows[start:end] {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString("(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?::jsonb,?)")
			args = append(args, ws, r.Provider, source, r.EventID, conn, r.EventTime, now, r.SkewMS, r.Principal,
				r.PrincipalKind, r.PrincipalDetail, r.AccountID, r.Region, r.EventSource, r.EventName, r.Outcome,
				r.RawHash, r.Body, r.RecordClass)
		}
		sb.WriteString(` ON CONFLICT (workspace_id, provider, event_id) DO NOTHING`)
		if err := tx.Exec(sb.String(), args...).Error; err != nil {
			return err
		}
	}
	return nil
}

func validEvidenceSource(s string) bool {
	switch s {
	case agentruntime.DeliveryAWSStream, agentruntime.DeliveryCloudTrailPoll, agentruntime.DeliveryTrailBackfill,
		agentruntime.DeliveryAzureDiag, agentruntime.DeliveryK8sAudit, agentruntime.DeliveryGateway, agentruntime.DeliveryOther:
		return true
	}
	return false
}

// defaultHeartbeatSilentAfter is a new heartbeat's silence threshold by
// source kind: pushed sources are expected to keep delivering; the poller and
// the backfill run only when a scan or a person runs them (never silent).
// The stream's own threshold is the connector's (agent_event_stream), synced
// by the coverage worker.
func defaultHeartbeatSilentAfter(kind string) *int64 {
	var d time.Duration
	switch kind {
	case agentruntime.DeliveryAWSStream:
		d = agentEvidenceDefaultStreamSilentHB
	case agentruntime.DeliveryAzureDiag:
		d = 6 * time.Hour
	case agentruntime.DeliveryK8sAudit:
		d = time.Hour
	default:
		return nil
	}
	s := int64(d / time.Second)
	return &s
}

// HeartbeatRef is the default source reference of a connector.
func HeartbeatRef(connectorID uuid.UUID) string { return "connector/" + connectorID.String() }

// touchSourceHeartbeat records a delivery: last receipt now, last event the
// newest event time. A delivery to a silent source is not judged here; the
// coverage worker moves it back to ok and resolves its alert.
func touchSourceHeartbeat(tx *gorm.DB, ws uuid.UUID, d agentruntime.Delivery, conn *uuid.UUID, lastEvent *time.Time, now time.Time) error {
	kind := d.Kind
	if !validEvidenceSource(kind) {
		kind = agentruntime.DeliveryOther
	}
	ref := d.Ref
	if ref == "" {
		if conn != nil {
			ref = HeartbeatRef(*conn)
		} else {
			ref = "workspace"
		}
	}
	return tx.Exec(`INSERT INTO source_heartbeat (workspace_id, source_kind, source_ref, connector_id, last_event_at,
	                       last_received_at, silent_after_seconds, created_at, updated_at)
	                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	                ON CONFLICT (workspace_id, source_kind, source_ref) DO UPDATE SET
	                  last_event_at    = GREATEST(source_heartbeat.last_event_at, EXCLUDED.last_event_at),
	                  last_received_at = GREATEST(source_heartbeat.last_received_at, EXCLUDED.last_received_at),
	                  connector_id     = COALESCE(source_heartbeat.connector_id, EXCLUDED.connector_id),
	                  updated_at       = EXCLUDED.updated_at`,
		ws, kind, truncate(ref, 300), conn, lastEvent, now, defaultHeartbeatSilentAfter(kind), now, now).Error
}

/* ------------------------------------------------------------------------- */
/*                                   Reads                                    */
/* ------------------------------------------------------------------------- */

// AgentEvidenceEvent is one agent_evidence_event row as the API returns it.
type AgentEvidenceEvent struct {
	ID              uuid.UUID       `json:"id" gorm:"column:id"`
	Provider        string          `json:"provider" gorm:"column:provider"`
	Source          string          `json:"source" gorm:"column:source"`
	EventID         string          `json:"event_id" gorm:"column:event_id"`
	ConnectorID     *uuid.UUID      `json:"connector_id" gorm:"column:connector_id"`
	EventTime       time.Time       `json:"event_time" gorm:"column:event_time"`
	ReceivedAt      time.Time       `json:"received_at" gorm:"column:received_at"`
	SkewMS          int64           `json:"skew_ms" gorm:"column:skew_ms"`
	Principal       string          `json:"principal" gorm:"column:principal"`
	PrincipalKind   string          `json:"principal_kind" gorm:"column:principal_kind"`
	PrincipalDetail string          `json:"principal_detail" gorm:"column:principal_detail"`
	AccountID       string          `json:"account_id" gorm:"column:account_id"`
	Region          string          `json:"region" gorm:"column:region"`
	EventSource     string          `json:"event_source" gorm:"column:event_source"`
	EventName       string          `json:"event_name" gorm:"column:event_name"`
	Outcome         string          `json:"outcome" gorm:"column:outcome"`
	RawHash         string          `json:"raw_hash" gorm:"column:raw_hash"`
	Body            json.RawMessage `json:"body" gorm:"column:body"`
	RecordClass     string          `json:"record_class" gorm:"column:record_class"`
	PinCount        int             `json:"pin_count" gorm:"column:pin_count"`
}

const agentEvidenceColumns = `id, provider, source, event_id, connector_id, event_time, received_at, skew_ms, principal,
	principal_kind, principal_detail, account_id, region, event_source, event_name, outcome, raw_hash, body,
	record_class, pin_count`

// AgentEvidenceFilter filters GET /agent-runtime/evidence.
type AgentEvidenceFilter struct {
	Principal string
	Source    string
	From, To  *time.Time
}

// AgentEvidenceService serves the evidence and retention APIs and the purge.
type AgentEvidenceService struct {
	db  *gorm.DB
	now func() time.Time
}

// NewAgentEvidenceService builds the service over db.
func NewAgentEvidenceService(db *gorm.DB) *AgentEvidenceService {
	return &AgentEvidenceService{db: db, now: time.Now}
}

// WithClock replaces the wall clock (tests).
func (s *AgentEvidenceService) WithClock(now func() time.Time) *AgentEvidenceService {
	s.now = now
	return s
}

// List is GET /agent-runtime/evidence: newest event first (event_time, id),
// limit 1..500, keyset-paginated. principal matches the attributed
// principal or the caller as stated.
func (s *AgentEvidenceService) List(ctx context.Context, ws uuid.UUID, f AgentEvidenceFilter, cursor string, limit int) ([]AgentEvidenceEvent, string, error) {
	if f.Source != "" && !validEvidenceSource(f.Source) {
		return nil, "", GovBadParam("source", "source must be one of aws_stream, cloudtrail_poll, trail_backfill, azure_diag, k8s_audit, gateway, other.")
	}
	if len(f.Principal) > 2048 {
		return nil, "", GovBadParam("principal", "principal is too long.")
	}
	if f.From != nil && f.To != nil && f.To.Before(*f.From) {
		return nil, "", GovBadParam("to", "to must not be before from.")
	}
	if limit <= 0 {
		limit = agentEvidenceDefaultListLimit
	}
	if limit > agentEvidenceMaxListLimit {
		limit = agentEvidenceMaxListLimit
	}
	q := `SELECT ` + agentEvidenceColumns + ` FROM agent_evidence_event WHERE workspace_id = ?`
	args := []any{ws}
	if f.Principal != "" {
		q += ` AND (principal = ? OR principal_detail = ?)`
		args = append(args, f.Principal, f.Principal)
	}
	if f.Source != "" {
		q += ` AND source = ?`
		args = append(args, f.Source)
	}
	if f.From != nil {
		q += ` AND event_time >= ?`
		args = append(args, f.From.UTC())
	}
	if f.To != nil {
		q += ` AND event_time < ?`
		args = append(args, f.To.UTC())
	}
	if cursor != "" {
		t, id, err := decodeAgentAlertCursor(cursor)
		if err != nil {
			return nil, "", GovBadParam("cursor", "The cursor is not valid.")
		}
		q += ` AND (event_time, id) < (?, ?)`
		args = append(args, t, id)
	}
	q += ` ORDER BY event_time DESC, id DESC LIMIT ?`
	args = append(args, limit+1)
	var rows []AgentEvidenceEvent
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(q, args...).Scan(&rows).Error
	}); err != nil {
		return nil, "", err
	}
	next := ""
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		next = encodeAgentAlertCursor(last.EventTime, last.ID)
	}
	if rows == nil {
		rows = []AgentEvidenceEvent{}
	}
	return rows, next, nil
}

// PinAgentEvidence adds delta (+1 pin, -1 unpin) to the pin count of the
// workspace's evidence rows ids, inside tx (a case pinning its evidence, W3).
// The count never goes below zero. It returns how many rows it changed.
func PinAgentEvidence(tx *gorm.DB, ws uuid.UUID, ids []uuid.UUID, delta int) (int64, error) {
	if len(ids) == 0 || delta == 0 {
		return 0, nil
	}
	res := tx.Exec(`UPDATE agent_evidence_event SET pin_count = GREATEST(pin_count + ?, 0)
	                 WHERE workspace_id = ? AND id IN ?`, delta, ws, ids)
	return res.RowsAffected, res.Error
}

/* ------------------------------------------------------------------------- */
/*                                 Retention                                  */
/* ------------------------------------------------------------------------- */

// AgentEvidenceRetention is a workspace's retention per record class.
type AgentEvidenceRetention struct {
	Days      map[string]int `json:"retention_days"`
	Defaults  map[string]int `json:"defaults"`
	UpdatedAt *time.Time     `json:"updated_at,omitempty"`
}

func readEvidenceRetention(tx *gorm.DB, ws uuid.UUID) (AgentEvidenceRetention, error) {
	out := AgentEvidenceRetention{Days: map[string]int{}, Defaults: map[string]int{}}
	for k, v := range DefaultEvidenceRetentionDays {
		out.Days[k], out.Defaults[k] = v, v
	}
	var rows []struct {
		RecordClass   string
		RetentionDays int
		UpdatedAt     time.Time
	}
	if err := tx.Raw(`SELECT record_class, retention_days, updated_at FROM agent_evidence_retention WHERE workspace_id = ?`, ws).
		Scan(&rows).Error; err != nil {
		return out, err
	}
	for _, r := range rows {
		out.Days[r.RecordClass] = r.RetentionDays
		if t := r.UpdatedAt.UTC(); out.UpdatedAt == nil || t.After(*out.UpdatedAt) {
			out.UpdatedAt = &t
		}
	}
	return out, nil
}

// Retention is GET /agent-runtime/evidence/retention.
func (s *AgentEvidenceService) Retention(ctx context.Context, ws uuid.UUID) (AgentEvidenceRetention, error) {
	var out AgentEvidenceRetention
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		out, err = readEvidenceRetention(tx, ws)
		return err
	})
	return out, err
}

// SetRetention is PUT /agent-runtime/evidence/retention: days per class,
// 30..3650; a class left out keeps its value. Regulated may not be shorter
// than elevated, nor elevated than default.
func (s *AgentEvidenceService) SetRetention(ctx context.Context, ws, actor uuid.UUID, days map[string]int) (AgentEvidenceRetention, error) {
	for k, v := range days {
		if _, ok := DefaultEvidenceRetentionDays[k]; !ok {
			return AgentEvidenceRetention{}, GovBadParam("retention_days", fmt.Sprintf("Unknown record class %q (default, elevated, regulated).", k))
		}
		if v < 30 || v > 3650 {
			return AgentEvidenceRetention{}, GovBadParam("retention_days."+k, "retention must be between 30 and 3650 days.")
		}
	}
	var out AgentEvidenceRetention
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		cur, err := readEvidenceRetention(tx, ws)
		if err != nil {
			return err
		}
		next := map[string]int{}
		for k, v := range cur.Days {
			next[k] = v
		}
		for k, v := range days {
			next[k] = v
		}
		if next[EvidenceClassRegulated] < next[EvidenceClassElevated] || next[EvidenceClassElevated] < next[EvidenceClassDefault] {
			return GovBadParam("retention_days", "regulated must be kept at least as long as elevated, and elevated at least as long as default.")
		}
		for k, v := range days {
			if err := tx.Exec(`INSERT INTO agent_evidence_retention (workspace_id, record_class, retention_days, updated_by, updated_at)
			                   VALUES (?, ?, ?, ?, now())
			                   ON CONFLICT (workspace_id, record_class) DO UPDATE SET retention_days = EXCLUDED.retention_days,
			                     updated_by = EXCLUDED.updated_by, updated_at = now()`, ws, k, v, actor).Error; err != nil {
				return err
			}
		}
		out, err = readEvidenceRetention(tx, ws)
		return err
	})
	return out, err
}

// Purge deletes the workspace's unpinned evidence older than its class's
// retention (by receipt time), in batches, and returns how many rows went.
// A pinned row (pin_count > 0) is never deleted.
func (s *AgentEvidenceService) Purge(ctx context.Context, ws uuid.UUID) (int64, error) {
	now := s.now().UTC()
	var total int64
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		ret, err := readEvidenceRetention(tx, ws)
		if err != nil {
			return err
		}
		for _, class := range []string{EvidenceClassDefault, EvidenceClassElevated, EvidenceClassRegulated} {
			cutoff := now.Add(-time.Duration(ret.Days[class]) * 24 * time.Hour)
			for {
				res := tx.Exec(`DELETE FROM agent_evidence_event WHERE workspace_id = ? AND id IN (
				                   SELECT id FROM agent_evidence_event
				                    WHERE workspace_id = ? AND record_class = ? AND pin_count = 0 AND received_at < ?
				                    LIMIT ?)`, ws, ws, class, cutoff, agentEvidencePurgeBatch)
				if res.Error != nil {
					return res.Error
				}
				total += res.RowsAffected
				if res.RowsAffected < agentEvidencePurgeBatch {
					break
				}
			}
		}
		return nil
	})
	if err == nil && total > 0 {
		log.Printf("[agent-evidence] retention: workspace=%s deleted=%d", ws, total)
	}
	return total, err
}
