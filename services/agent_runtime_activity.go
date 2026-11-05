package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentactivity"
	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// Agent runtime activity timeline (SPEC-agent-runtime-activity.md).
//
// agent_activity_event (migration 155) is written by three sources:
//
//   - the "agent_activity" agentruntime.EventSink (this file): every
//     CloudTrail event, from the scan poller and the event-stream ingest, of
//     an identity the resolver labels an AI workload, suggested agent, agent
//     or possible AI workload;
//   - the AgentCore span reader (agent_runtime_activity_spans.go), during the
//     AWS scan;
//   - the OTLP/HTTP receiver (agent_runtime_activity_otlp.go).
//
// Every writer inserts ON CONFLICT (workspace_id, source, provider_event_id)
// DO NOTHING, so each source is idempotent. Rows are append-only (a trigger
// refuses UPDATE and any DELETE but retention's and a workspace purge's).
// Everything runs in a transaction under row-level security for one
// workspace (tenancy.InWorkspace / InWorkspaceRead); the only statement that
// is not is the retention job's listing of workspace ids.

// Sink name, defaults and limits.
const (
	AgentActivitySinkName = "agent_activity"

	DefaultAgentActivityRetentionDays = 90
	MinAgentActivityRetentionDays     = 1
	MaxAgentActivityRetentionDays     = 400

	agentActivityInsertChunk  = 200
	agentActivityPurgeBatch   = 5000
	agentActivityMaxAttrBytes = 15000
	agentActivityMaxFuture    = time.Hour
	agentActivityMaxTrace     = 2000
	// agentActivityRetentionPurge is the session flag the append-only trigger
	// lets DELETE through with (migration 155).
	agentActivityRetentionPurge = `SET LOCAL authsec.activity_retention = 'on'`
)

// AgentActivityLabels are the subject labels whose CloudTrail events become
// activity. Strings, not constants: "possible_ai_workload" may or may not
// exist as an agentruntime constant (spec §4.1).
var AgentActivityLabels = map[string]bool{
	agentruntime.LabelAIWorkload: true, agentruntime.LabelSuggestedAgent: true, agentruntime.LabelAgent: true,
	"possible_ai_workload": true,
}

/* ------------------------------------------------------------------------- */
/*                                 Writing                                    */
/* ------------------------------------------------------------------------- */

// activityInsert is one row to write: the normalised activity and what it was
// attributed to within the workspace.
type activityInsert struct {
	agentactivity.Activity
	ConnectorID *uuid.UUID
	IdentityID  *uuid.UUID
	WorkloadID  *uuid.UUID
	// AttributedHow records how (attrs.attribution.how); "" when unattributed.
	AttributedHow string
}

// readAgentActivityRetention is the workspace's retention in days.
func readAgentActivityRetention(tx *gorm.DB, ws uuid.UUID) (int, error) {
	var days []int
	if err := tx.Raw(`SELECT retention_days FROM agent_activity_setting WHERE workspace_id = ?`, ws).Scan(&days).Error; err != nil {
		return 0, err
	}
	if len(days) == 0 || days[0] < MinAgentActivityRetentionDays {
		return DefaultAgentActivityRetentionDays, nil
	}
	return days[0], nil
}

// activityAttrsJSON marshals attrs within the column's size bound: the
// largest values are dropped until it fits.
func activityAttrsJSON(attrs map[string]any) (string, error) {
	if attrs == nil {
		attrs = map[string]any{}
	}
	for {
		raw, err := json.Marshal(attrs)
		if err != nil {
			return "", err
		}
		if len(raw) <= agentActivityMaxAttrBytes || len(attrs) == 0 {
			return string(raw), nil
		}
		big, bigLen := "", -1
		for k, v := range attrs {
			b, _ := json.Marshal(v)
			if len(b) > bigLen || (len(b) == bigLen && k < big) {
				big, bigLen = k, len(b)
			}
		}
		delete(attrs, big)
	}
}

// insertActivities writes rows into the transaction's workspace, skipping
// rows older than the workspace's retention or too far in the future, and
// returns how many were new (the rest were already stored).
func insertActivities(tx *gorm.DB, ws uuid.UUID, rows []activityInsert, now time.Time) (inserted, dropped int, err error) {
	if len(rows) == 0 {
		return 0, 0, nil
	}
	days, err := readAgentActivityRetention(tx, ws)
	if err != nil {
		return 0, 0, err
	}
	cutoff := now.AddDate(0, 0, -days)
	var keep []activityInsert
	for _, r := range rows {
		if r.OccurredAt.IsZero() {
			r.OccurredAt = now
		}
		if r.OccurredAt.Before(cutoff) || r.OccurredAt.After(now.Add(agentActivityMaxFuture)) {
			dropped++
			continue
		}
		keep = append(keep, r)
	}
	for start := 0; start < len(keep); start += agentActivityInsertChunk {
		end := start + agentActivityInsertChunk
		if end > len(keep) {
			end = len(keep)
		}
		var sb strings.Builder
		sb.WriteString(`INSERT INTO agent_activity_event (workspace_id, connector_id, identity_id, workload_id, source, kind,
		    occurred_at, action, resource_ref, outcome, on_behalf_of, trace_id, span_id, parent_span_id,
		    provider_event_id, attrs) VALUES `)
		args := make([]any, 0, (end-start)*16)
		for i, r := range keep[start:end] {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString("(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?::jsonb)")
			attrs := map[string]any{}
			for k, v := range r.Attrs {
				attrs[k] = v
			}
			if r.AttributedHow != "" {
				attrs["attribution.how"] = r.AttributedHow
			}
			aj, err := activityAttrsJSON(attrs)
			if err != nil {
				return inserted, dropped, err
			}
			var obo *string
			if r.OnBehalfOf != "" {
				s := agentactivity.Truncate(r.OnBehalfOf, agentactivity.MaxOnBehalfOf)
				obo = &s
			}
			args = append(args, ws, r.ConnectorID, r.IdentityID, r.WorkloadID, r.Source, r.Kind,
				r.OccurredAt.UTC(), agentactivity.Truncate(r.Action, agentactivity.MaxAction),
				agentactivity.Truncate(r.ResourceRef, agentactivity.MaxResourceRef), r.Outcome, obo,
				r.TraceID, r.SpanID, r.ParentSpanID,
				agentactivity.Truncate(r.ProviderEventID, agentactivity.MaxProviderEventID), aj)
		}
		sb.WriteString(` ON CONFLICT (workspace_id, source, provider_event_id) DO NOTHING`)
		res := tx.Exec(sb.String(), args...)
		if res.Error != nil {
			return inserted, dropped, res.Error
		}
		inserted += int(res.RowsAffected)
	}
	return inserted, dropped, nil
}

/* ------------------------------------------------------------------------- */
/*                               Attribution                                  */
/* ------------------------------------------------------------------------- */

// activityTarget is what a row is attributed to.
type activityTarget struct {
	ConnectorID *uuid.UUID
	IdentityID  *uuid.UUID
	WorkloadID  *uuid.UUID
	How         string
}

type activityWorkloadRef struct {
	ID          uuid.UUID
	ConnectorID uuid.UUID
	IdentityID  *uuid.UUID
}

func (w activityWorkloadRef) target(how string) activityTarget {
	id, conn := w.ID, w.ConnectorID
	return activityTarget{ConnectorID: &conn, IdentityID: w.IdentityID, WorkloadID: &id, How: how}
}

// lambdaFunctionARN strips a version or alias qualifier from a Lambda ARN.
func lambdaFunctionARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) > 7 && parts[2] == "lambda" && parts[5] == "function" {
		return strings.Join(parts[:7], ":")
	}
	return arn
}

// resolveActivityHints attributes hints to a workload / identity of the
// transaction's workspace -- and, when restrict is set, of that connector
// only. Hints are claims (OTLP: the sender's); they can only ever select rows
// of ws, never name another workspace. A hint that matches nothing, or
// matches ambiguously, attributes nothing.
func resolveActivityHints(tx *gorm.DB, ws uuid.UUID, restrict *uuid.UUID, h agentactivity.Hints) (activityTarget, error) {
	none := activityTarget{ConnectorID: restrict}
	if h.Empty() {
		return none, nil
	}
	one := func(how, where string, args ...any) (*activityTarget, error) {
		q := `SELECT w.id, w.connector_id, w.identity_id FROM cloud_workload w WHERE w.workspace_id = ? AND ` + where
		all := append([]any{ws}, args...)
		if restrict != nil {
			q += ` AND w.connector_id = ?`
			all = append(all, *restrict)
		}
		q += ` LIMIT 2`
		var rows []activityWorkloadRef
		if err := tx.Raw(q, all...).Scan(&rows).Error; err != nil {
			return nil, err
		}
		if len(rows) != 1 {
			return nil, nil
		}
		t := rows[0].target(how)
		return &t, nil
	}
	if h.WorkloadID != "" {
		if id, err := uuid.Parse(h.WorkloadID); err == nil {
			if t, err := one("authsec.workload_id", `w.id = ?`, id); err != nil || t != nil {
				return deref(t, none), err
			}
		}
	}
	if h.IdentityARN != "" {
		q := `SELECT id, connector_id FROM cloud_identity WHERE workspace_id = ? AND native_id = ?`
		args := []any{ws, h.IdentityARN}
		if restrict != nil {
			q += ` AND connector_id = ?`
			args = append(args, *restrict)
		}
		var rows []struct {
			ID          uuid.UUID
			ConnectorID uuid.UUID
		}
		if err := tx.Raw(q+` LIMIT 1`, args...).Scan(&rows).Error; err != nil {
			return none, err
		}
		if len(rows) == 1 {
			id, conn := rows[0].ID, rows[0].ConnectorID
			return activityTarget{ConnectorID: &conn, IdentityID: &id, How: "authsec.identity_arn"}, nil
		}
	}
	if h.RuntimeARN != "" {
		if t, err := one("cloud.resource_id", `w.runtime_kind = ? AND w.native_id = ?`, models.WorkloadBedrockAgentCoreRT, h.RuntimeARN); err != nil || t != nil {
			return deref(t, none), err
		}
	} else if h.ResourceARN != "" {
		if t, err := one("cloud.resource_id", `w.native_id = ?`, lambdaFunctionARN(h.ResourceARN)); err != nil || t != nil {
			return deref(t, none), err
		}
	}
	if h.AccountID != "" && h.FaaSName != "" {
		where := `w.runtime_kind = ? AND w.name = ? AND EXISTS (SELECT 1 FROM cloud_connector c
		          WHERE c.workspace_id = w.workspace_id AND c.id = w.connector_id AND c.scope_id = ?)`
		args := []any{models.WorkloadLambdaFunction, h.FaaSName, h.AccountID}
		if h.Region != "" {
			where += ` AND w.region = ?`
			args = append(args, h.Region)
		}
		if t, err := one("faas.name", where, args...); err != nil || t != nil {
			return deref(t, none), err
		}
	}
	if h.AccountID != "" && h.ECSFamily != "" && h.ECSRevision != "" {
		suffix := ":task-definition/" + h.ECSFamily + ":" + h.ECSRevision
		if t, err := one("aws.ecs.task", `w.runtime_kind = ? AND right(w.native_id, ?) = ? AND EXISTS (SELECT 1 FROM cloud_connector c
		          WHERE c.workspace_id = w.workspace_id AND c.id = w.connector_id AND c.scope_id = ?)`,
			models.WorkloadECSTaskDefinition, len(suffix), suffix, h.AccountID); err != nil || t != nil {
			return deref(t, none), err
		}
	}
	if h.AgentID != "" && restrict != nil {
		// AgentCore: gen_ai.agent.id names the runtime id when the record
		// carries no ARN. Only within the scanned connector.
		suffix := ":runtime/" + h.AgentID
		if t, err := one("gen_ai.agent.id", `w.runtime_kind = ? AND right(w.native_id, ?) = ?`,
			models.WorkloadBedrockAgentCoreRT, len(suffix), suffix); err != nil || t != nil {
			return deref(t, none), err
		}
	}
	return none, nil
}

func deref(t *activityTarget, def activityTarget) activityTarget {
	if t == nil {
		return def
	}
	return *t
}

// attributeActivities resolves each distinct hint set once and returns the
// rows to insert.
func attributeActivities(tx *gorm.DB, ws uuid.UUID, restrict *uuid.UUID, acts []agentactivity.Activity) ([]activityInsert, error) {
	cache := map[string]activityTarget{}
	out := make([]activityInsert, 0, len(acts))
	for _, a := range acts {
		key := a.Hints.Key()
		t, ok := cache[key]
		if !ok {
			var err error
			if t, err = resolveActivityHints(tx, ws, restrict, a.Hints); err != nil {
				return nil, err
			}
			cache[key] = t
		}
		out = append(out, activityInsert{Activity: a, ConnectorID: t.ConnectorID, IdentityID: t.IdentityID,
			WorkloadID: t.WorkloadID, AttributedHow: t.How})
	}
	return out, nil
}

/* ------------------------------------------------------------------------- */
/*                          Source A: the CloudTrail sink                     */
/* ------------------------------------------------------------------------- */

// AgentActivitySink is the "agent_activity" agentruntime.EventSink.
type AgentActivitySink struct {
	db  *gorm.DB
	now func() time.Time
}

// NewAgentActivitySink builds the sink over db.
func NewAgentActivitySink(db *gorm.DB) *AgentActivitySink {
	return &AgentActivitySink{db: db, now: time.Now}
}

// WithClock replaces the wall clock (tests).
func (s *AgentActivitySink) WithClock(now func() time.Time) *AgentActivitySink {
	s.now = now
	return s
}

// Name implements agentruntime.EventSink.
func (s *AgentActivitySink) Name() string { return AgentActivitySinkName }

// Process implements agentruntime.EventSink: the events of labelled
// identities become rows, once (by eventID).
func (s *AgentActivitySink) Process(ctx context.Context, workspaceID, connectorID uuid.UUID, events []agentruntime.Event) error {
	r := agentruntime.Resolver()
	if r == nil || workspaceID == uuid.Nil || len(events) == 0 {
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
	var rows []activityInsert
	var first error
	for _, a := range keys {
		subj, err := r.Resolve(ctx, workspaceID, connectorID, a)
		if err != nil {
			if first == nil {
				first = fmt.Errorf("agent activity: resolve %s: %w", a.ARN, err)
			}
			continue
		}
		if subj.IdentityID == uuid.Nil || !AgentActivityLabels[subj.Label] {
			continue
		}
		conn := subj.ConnectorID
		if conn == uuid.Nil {
			conn = connectorID
		}
		identity := subj.IdentityID
		var workload *uuid.UUID
		if len(subj.WorkloadIDs) == 1 && !subj.SharedRole {
			w := subj.WorkloadIDs[0]
			workload = &w
		}
		for _, e := range groups[a] {
			act, ok := agentactivity.FromCloudTrail(e)
			if !ok {
				continue
			}
			act.Attrs["subject_label"] = subj.Label
			c, id := conn, identity
			rows = append(rows, activityInsert{Activity: act, ConnectorID: &c, IdentityID: &id, WorkloadID: workload,
				AttributedHow: a.How})
		}
	}
	if len(rows) == 0 {
		return first
	}
	now := s.now().UTC()
	if err := tenancy.InWorkspace(ctx, s.db, workspaceID, func(tx *gorm.DB) error {
		_, _, err := insertActivities(tx, workspaceID, rows, now)
		return err
	}); err != nil && first == nil {
		first = fmt.Errorf("agent activity: write: %w", err)
	}
	return first
}

/* ------------------------------------------------------------------------- */
/*                                  Reads                                     */
/* ------------------------------------------------------------------------- */

// AgentActivity is one agent_activity_event row as the API returns it.
type AgentActivity struct {
	ID              uuid.UUID       `json:"id" gorm:"column:id"`
	ConnectorID     *uuid.UUID      `json:"connector_id" gorm:"column:connector_id"`
	IdentityID      *uuid.UUID      `json:"identity_id" gorm:"column:identity_id"`
	WorkloadID      *uuid.UUID      `json:"workload_id" gorm:"column:workload_id"`
	Source          string          `json:"source" gorm:"column:source"`
	Kind            string          `json:"kind" gorm:"column:kind"`
	OccurredAt      time.Time       `json:"occurred_at" gorm:"column:occurred_at"`
	ReceivedAt      time.Time       `json:"received_at" gorm:"column:received_at"`
	Action          string          `json:"action" gorm:"column:action"`
	ResourceRef     string          `json:"resource_ref" gorm:"column:resource_ref"`
	Outcome         string          `json:"outcome" gorm:"column:outcome"`
	OnBehalfOf      *string         `json:"on_behalf_of" gorm:"column:on_behalf_of"`
	TraceID         string          `json:"trace_id" gorm:"column:trace_id"`
	SpanID          string          `json:"span_id" gorm:"column:span_id"`
	ParentSpanID    string          `json:"parent_span_id" gorm:"column:parent_span_id"`
	ProviderEventID string          `json:"provider_event_id" gorm:"column:provider_event_id"`
	Attrs           json.RawMessage `json:"attrs" gorm:"column:attrs"`
}

const agentActivityColumns = `id, connector_id, identity_id, workload_id, source, kind, occurred_at, received_at, action,
	resource_ref, outcome, on_behalf_of, trace_id, span_id, parent_span_id, provider_event_id, attrs`

// AgentActivityFilter filters GET /activity.
type AgentActivityFilter struct {
	IdentityID, WorkloadID *uuid.UUID
	Kind, Outcome, Source  string
	From, To               *time.Time
}

// Validate checks the filter's values.
func (f AgentActivityFilter) Validate() error {
	if f.Kind != "" && !agentactivity.ValidKind(f.Kind) {
		return GovBadParam("kind", "kind must be one of model_call, tool_call, agent_step, cloud_action, data_access, sign_in, decision.")
	}
	if f.Outcome != "" && !agentactivity.ValidOutcome(f.Outcome) {
		return GovBadParam("outcome", "outcome must be success, denied or error.")
	}
	if f.Source != "" && !agentactivity.ValidSource(f.Source) {
		return GovBadParam("source", "source must be one of cloudtrail, cloudtrail_data, agentcore_span, otlp, authsec_decision.")
	}
	if f.From != nil && f.To != nil && f.To.Before(*f.From) {
		return GovBadParam("to", "to must not be before from.")
	}
	return nil
}

// AgentActivityService reads the timeline and owns settings and retention.
type AgentActivityService struct {
	db  *gorm.DB
	now func() time.Time
}

// NewAgentActivityService builds the service over db.
func NewAgentActivityService(db *gorm.DB) *AgentActivityService {
	return &AgentActivityService{db: db, now: time.Now}
}

// WithClock replaces the wall clock (tests).
func (s *AgentActivityService) WithClock(now func() time.Time) *AgentActivityService {
	s.now = now
	return s
}

func encodeActivityCursor(t time.Time, id uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(t.UTC().Format(time.RFC3339Nano) + "|" + id.String()))
}

// List is GET /activity: newest first (occurred_at, id), limit 1..200.
// Another workspace's rows are never read (RLS and the workspace filter).
func (s *AgentActivityService) List(ctx context.Context, ws uuid.UUID, f AgentActivityFilter, cursor string, limit int) ([]AgentActivity, string, error) {
	if err := f.Validate(); err != nil {
		return nil, "", err
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > MaxGovPage {
		limit = MaxGovPage
	}
	q := `SELECT ` + agentActivityColumns + ` FROM agent_activity_event WHERE workspace_id = ?`
	args := []any{ws}
	if f.IdentityID != nil {
		q += ` AND identity_id = ?`
		args = append(args, *f.IdentityID)
	}
	if f.WorkloadID != nil {
		q += ` AND workload_id = ?`
		args = append(args, *f.WorkloadID)
	}
	for col, v := range map[string]string{"kind": f.Kind, "outcome": f.Outcome, "source": f.Source} {
		if v != "" {
			q += ` AND ` + col + ` = ?`
			args = append(args, v)
		}
	}
	if f.From != nil {
		q += ` AND occurred_at >= ?`
		args = append(args, f.From.UTC())
	}
	if f.To != nil {
		q += ` AND occurred_at < ?`
		args = append(args, f.To.UTC())
	}
	if cursor != "" {
		t, id, err := decodeAgentAlertCursor(cursor)
		if err != nil {
			return nil, "", GovBadParam("cursor", "The cursor is not valid.")
		}
		q += ` AND (occurred_at, id) < (?, ?)`
		args = append(args, t, id)
	}
	q += ` ORDER BY occurred_at DESC, id DESC LIMIT ?`
	args = append(args, limit+1)
	var rows []AgentActivity
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(q, args...).Scan(&rows).Error
	}); err != nil {
		return nil, "", err
	}
	next := ""
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		next = encodeActivityCursor(last.OccurredAt, last.ID)
	}
	if rows == nil {
		rows = []AgentActivity{}
	}
	return rows, next, nil
}

// AgentActivityNode is one span of a trace with its children.
type AgentActivityNode struct {
	AgentActivity
	Children []*AgentActivityNode `json:"children"`
}

// AgentActivityTrace is GET /activity/traces/:trace_id.
type AgentActivityTrace struct {
	TraceID   string               `json:"trace_id"`
	Count     int                  `json:"count"`
	Truncated bool                 `json:"truncated"`
	Spans     []*AgentActivityNode `json:"spans"`
}

// Trace returns every stored span of one trace in the workspace as a tree
// (roots: no parent, or a parent that was not stored). Not found when the
// workspace holds none of it.
func (s *AgentActivityService) Trace(ctx context.Context, ws uuid.UUID, traceID string) (*AgentActivityTrace, error) {
	id := agentactivity.NormaliseID(traceID)
	if id == "" {
		return nil, GovNotFound()
	}
	var rows []AgentActivity
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT `+agentActivityColumns+` FROM agent_activity_event
		               WHERE workspace_id = ? AND trace_id = ? ORDER BY occurred_at, id LIMIT ?`,
			ws, id, agentActivityMaxTrace+1).Scan(&rows).Error
	}); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, GovNotFound()
	}
	out := &AgentActivityTrace{TraceID: id}
	if len(rows) > agentActivityMaxTrace {
		rows, out.Truncated = rows[:agentActivityMaxTrace], true
	}
	out.Count = len(rows)
	out.Spans = activityTree(rows)
	return out, nil
}

// activityTree links rows by span id; rows without a span id (none in a
// trace today) and orphans are roots. Children keep time order.
func activityTree(rows []AgentActivity) []*AgentActivityNode {
	nodes := make([]*AgentActivityNode, len(rows))
	bySpan := map[string]*AgentActivityNode{}
	for i := range rows {
		nodes[i] = &AgentActivityNode{AgentActivity: rows[i], Children: []*AgentActivityNode{}}
		if rows[i].SpanID != "" {
			if _, dup := bySpan[rows[i].SpanID]; !dup {
				bySpan[rows[i].SpanID] = nodes[i]
			}
		}
	}
	roots := []*AgentActivityNode{}
	for _, n := range nodes {
		p, ok := bySpan[n.ParentSpanID]
		if n.ParentSpanID == "" || !ok || p == n {
			roots = append(roots, n)
			continue
		}
		p.Children = append(p.Children, n)
	}
	return roots
}

/* -------------------------------- coverage -------------------------------- */

// AgentActivityCursorView is one span reader cursor.
type AgentActivityCursorView struct {
	ConnectorID uuid.UUID  `json:"connector_id" gorm:"column:connector_id"`
	Region      string     `json:"region" gorm:"column:region"`
	Stream      string     `json:"stream" gorm:"column:stream"`
	CursorAt    *time.Time `json:"cursor_at" gorm:"column:cursor_at"`
	State       string     `json:"state" gorm:"column:state"`
	LastError   string     `json:"last_error" gorm:"column:last_error"`
	ErrorCode   string     `json:"error_code" gorm:"column:error_code"`
	LastScanAt  time.Time  `json:"last_scan_at" gorm:"column:last_scan_at"`
	RowsWritten int64      `json:"rows_written" gorm:"column:rows_written"`
}

// AgentActivityCoverage is GET /activity/coverage.
type AgentActivityCoverage struct {
	RetentionDays int                       `json:"retention_days"`
	Spans         []AgentActivityCursorView `json:"agentcore_spans"`
	OTLP          struct {
		LiveTokens int        `json:"live_tokens"`
		LastUsedAt *time.Time `json:"last_used_at"`
	} `json:"otlp"`
	SemanticConventions string `json:"semantic_conventions"`
}

// Coverage reports what each source covers in the workspace.
func (s *AgentActivityService) Coverage(ctx context.Context, ws uuid.UUID) (*AgentActivityCoverage, error) {
	out := &AgentActivityCoverage{Spans: []AgentActivityCursorView{}, SemanticConventions: agentactivity.SemconvPin}
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		if out.RetentionDays, err = readAgentActivityRetention(tx, ws); err != nil {
			return err
		}
		if err := tx.Raw(`SELECT connector_id, region, stream, cursor_at, state, last_error, error_code, last_scan_at, rows_written
		                  FROM agent_activity_cursor WHERE workspace_id = ? ORDER BY connector_id, region, stream`, ws).
			Scan(&out.Spans).Error; err != nil {
			return err
		}
		var tok struct {
			Live int
			Last *time.Time
		}
		if err := tx.Raw(`SELECT count(*) FILTER (WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())) AS live,
		                         max(last_used_at) AS last
		                    FROM agent_otlp_token WHERE workspace_id = ?`, ws).Scan(&tok).Error; err != nil {
			return err
		}
		out.OTLP.LiveTokens, out.OTLP.LastUsedAt = tok.Live, tok.Last
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

/* -------------------------------- settings -------------------------------- */

// AgentActivitySettings is GET/PUT /activity/settings.
type AgentActivitySettings struct {
	RetentionDays int        `json:"retention_days"`
	UpdatedAt     *time.Time `json:"updated_at,omitempty"`
}

// Settings returns the workspace's settings (defaults when none are stored).
func (s *AgentActivityService) Settings(ctx context.Context, ws uuid.UUID) (AgentActivitySettings, error) {
	out := AgentActivitySettings{RetentionDays: DefaultAgentActivityRetentionDays}
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var rows []struct {
			RetentionDays int
			UpdatedAt     time.Time
		}
		if err := tx.Raw(`SELECT retention_days, updated_at FROM agent_activity_setting WHERE workspace_id = ?`, ws).Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 1 {
			t := rows[0].UpdatedAt.UTC()
			out.RetentionDays, out.UpdatedAt = rows[0].RetentionDays, &t
		}
		return nil
	})
	return out, err
}

// UpdateSettings sets the retention (1..400 days).
func (s *AgentActivityService) UpdateSettings(ctx context.Context, ws, actor uuid.UUID, retentionDays int) (AgentActivitySettings, error) {
	if retentionDays < MinAgentActivityRetentionDays || retentionDays > MaxAgentActivityRetentionDays {
		return AgentActivitySettings{}, GovBadParam("retention_days",
			fmt.Sprintf("retention_days must be between %d and %d.", MinAgentActivityRetentionDays, MaxAgentActivityRetentionDays))
	}
	if err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Exec(`INSERT INTO agent_activity_setting (workspace_id, retention_days, updated_by, updated_at)
		                VALUES (?, ?, ?, now())
		                ON CONFLICT (workspace_id) DO UPDATE SET retention_days = EXCLUDED.retention_days,
		                    updated_by = EXCLUDED.updated_by, updated_at = now()`, ws, retentionDays, actor).Error
	}); err != nil {
		return AgentActivitySettings{}, err
	}
	return s.Settings(ctx, ws)
}

/* -------------------------------- retention ------------------------------- */

// PurgeWorkspace deletes the workspace's rows older than its retention, in
// batches, each its own transaction carrying the retention flag the
// append-only trigger admits. It returns how many rows it deleted.
func (s *AgentActivityService) PurgeWorkspace(ctx context.Context, ws uuid.UUID) (int64, error) {
	var total int64
	for {
		var n int64
		err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
			days, err := readAgentActivityRetention(tx, ws)
			if err != nil {
				return err
			}
			if err := tx.Exec(agentActivityRetentionPurge).Error; err != nil {
				return err
			}
			cutoff := s.now().UTC().AddDate(0, 0, -days)
			res := tx.Exec(`DELETE FROM agent_activity_event WHERE workspace_id = ? AND id IN (
			                  SELECT id FROM agent_activity_event WHERE workspace_id = ? AND occurred_at < ?
			                  ORDER BY occurred_at LIMIT ?)`, ws, ws, cutoff, agentActivityPurgeBatch)
			n = res.RowsAffected
			return res.Error
		})
		if err != nil {
			return total, err
		}
		total += n
		if n < agentActivityPurgeBatch || ctx.Err() != nil {
			return total, ctx.Err()
		}
	}
}

// Purge applies retention in every workspace holding activity.
func (s *AgentActivityService) Purge(ctx context.Context) error {
	var wss []uuid.UUID
	// TENANT-EXEMPT: retention runs across workspaces (no request tenant) and lists workspace ids only; each workspace is purged in its own workspace_id-bound transaction.
	if err := s.db.WithContext(ctx).Raw(`SELECT DISTINCT workspace_id FROM agent_activity_event`).Scan(&wss).Error; err != nil {
		return err
	}
	sort.Slice(wss, func(i, j int) bool { return wss[i].String() < wss[j].String() })
	var first error
	for _, ws := range wss {
		if _, err := s.PurgeWorkspace(ctx, ws); err != nil && first == nil {
			first = fmt.Errorf("workspace %s: %w", ws, err)
		}
	}
	return first
}

// RunAgentActivityRetention purges expired activity hourly until ctx ends.
// AUTHSEC_DISABLE_AGENT_ACTIVITY_RETENTION=true turns it off on a replica.
func RunAgentActivityRetention(ctx context.Context, db *gorm.DB) {
	if os.Getenv("AUTHSEC_DISABLE_AGENT_ACTIVITY_RETENTION") == "true" {
		log.Printf("[agent-activity] retention not started: AUTHSEC_DISABLE_AGENT_ACTIVITY_RETENTION=true")
		return
	}
	svc := NewAgentActivityService(db)
	for {
		if err := svc.Purge(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[agent-activity] retention: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour):
		}
	}
}

// InstallAgentRuntimeActivity registers the "agent_activity" sink and starts
// the retention job. cmd/main.go calls it once at startup.
func InstallAgentRuntimeActivity(db *gorm.DB) {
	agentruntime.RegisterSink(NewAgentActivitySink(db))
	go RunAgentActivityRetention(context.Background(), db)
}
