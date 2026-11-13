package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentgateway"
	"github.com/authsec-ai/authsec/internal/tenancy"
)

// The gateway decision log (SPEC-agent-runtime-gateway.md §7, §9):
// agent_gateway_decision, append-only, metadata only. The PDP's own
// decisions are written here through a buffered writer (off the request
// path; synchronous when the buffer is full, so nothing is dropped); a
// gateway uploads the decisions it made itself (cache, fail mode, pinning)
// and the outcomes of allowed calls (token usage) with
// POST /authsec/pdp/v1/decisions. Rows older than the workspace's retention
// are purged at most hourly per workspace per process.

// Record types and sources.
const (
	AgentGatewayRecordDecision = "decision"
	AgentGatewayRecordOutcome  = "outcome"

	AgentGatewaySourcePDP        = "pdp"
	AgentGatewaySourceCache      = "cache"
	AgentGatewaySourceGateway    = "gateway"
	AgentGatewaySourceFailOpen   = "fail_open"
	AgentGatewaySourceFailClosed = "fail_closed"

	// AgentGatewayMaxUploadRecords bounds one upload.
	AgentGatewayMaxUploadRecords = 1000
	// AgentGatewayMaxBodyBytes bounds every PDP request body.
	AgentGatewayMaxBodyBytes = 1 << 20

	agentGatewayWriterBuffer = 10000
	agentGatewayWriterBatch  = 200
	agentGatewayWriterEvery  = 250 * time.Millisecond
	agentGatewayPurgeEvery   = time.Hour
	agentGatewayUploadMaxAge = 7 * 24 * time.Hour
	agentGatewayUploadSkew   = 5 * time.Minute
)

var agentGatewayUploadSources = map[string]bool{
	AgentGatewaySourceCache: true, AgentGatewaySourceGateway: true,
	AgentGatewaySourceFailOpen: true, AgentGatewaySourceFailClosed: true,
}

var reAgentGatewayReason = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// AgentGatewayUsage is token usage reported for an allowed model call.
type AgentGatewayUsage struct {
	InputTokens  *int64 `json:"input_tokens,omitempty"`
	OutputTokens *int64 `json:"output_tokens,omitempty"`
	TotalTokens  *int64 `json:"total_tokens,omitempty"`
}

func (u *AgentGatewayUsage) valid() bool {
	for _, v := range []*int64{u.InputTokens, u.OutputTokens, u.TotalTokens} {
		if v != nil && (*v < 0 || *v > 1<<40) {
			return false
		}
	}
	return true
}

// agentGatewayDecisionRow is one row to insert.
type agentGatewayDecisionRow struct {
	ID             uuid.UUID
	WorkspaceID    uuid.UUID
	GatewayID      uuid.UUID
	RecordType     string
	Source         string
	DecidedAt      time.Time
	SubjectType    string
	SubjectID      string
	Subject        string
	Action         string
	Kind           string
	ResourceID     string
	Resource       string
	Decision       string
	Reason         string
	PolicyID       *uuid.UUID
	DecisionRef    *uuid.UUID
	LatencyMS      *float64
	ArgsDigest     *string
	Usage          *string
	UpstreamStatus *int
	RequestID      string
}

func agwJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func decisionWord(allowed bool) string {
	if allowed {
		return agentgateway.EffectAllow
	}
	return agentgateway.EffectDeny
}

func agwStrPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func pdpDecisionRow(p AgentGatewayPrincipal, id uuid.UUID, at time.Time, req agentgateway.Request, res agentgateway.Result, latencyMS float64) agentGatewayDecisionRow {
	action := agentgateway.ActionToolsCall
	if req.Kind == agentgateway.KindModel {
		action = agentgateway.ActionModelInvoke
	}
	return agentGatewayDecisionRow{ID: id, WorkspaceID: p.WorkspaceID, GatewayID: p.GatewayID,
		RecordType: AgentGatewayRecordDecision, Source: AgentGatewaySourcePDP, DecidedAt: at.UTC(),
		SubjectType: agentgateway.SubjectTypeAgent, SubjectID: req.SubjectID, Subject: agwJSON(req.SubjectProps()),
		Action: action, Kind: req.Kind, ResourceID: req.ResourceID(), Resource: agwJSON(req.ResourceProps()),
		Decision: decisionWord(res.Allowed), Reason: res.Reason, PolicyID: nullUUID(res.PolicyID),
		LatencyMS: &latencyMS, ArgsDigest: agwStrPtr(req.ArgsDigest), RequestID: req.RequestID}
}

const agentGatewayDecisionInsertCols = `id, workspace_id, gateway_id, record_type, source, decided_at, subject_type,
	subject_id, subject, action, kind, resource_id, resource, decision, reason, policy_id, decision_ref, latency_ms,
	args_digest, usage, upstream_status, request_id`

// insertDecisions writes rows of one workspace in one transaction and
// returns how many were new (a retried upload's rows are not).
func (s *AgentGatewayService) insertDecisions(ctx context.Context, ws uuid.UUID, rows []agentGatewayDecisionRow) (int64, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	var inserted int64
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		for start := 0; start < len(rows); start += agentGatewayWriterBatch {
			end := start + agentGatewayWriterBatch
			if end > len(rows) {
				end = len(rows)
			}
			var sb strings.Builder
			args := make([]any, 0, (end-start)*22)
			sb.WriteString(`INSERT INTO agent_gateway_decision (` + agentGatewayDecisionInsertCols + `) VALUES `)
			for i, r := range rows[start:end] {
				if i > 0 {
					sb.WriteString(", ")
				}
				sb.WriteString(`(?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?::jsonb, ?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?)`)
				args = append(args, r.ID, ws, r.GatewayID, r.RecordType, r.Source, r.DecidedAt, r.SubjectType,
					r.SubjectID, r.Subject, r.Action, r.Kind, r.ResourceID, r.Resource, r.Decision, r.Reason,
					r.PolicyID, r.DecisionRef, r.LatencyMS, r.ArgsDigest, r.Usage, r.UpstreamStatus, r.RequestID)
			}
			sb.WriteString(` ON CONFLICT (workspace_id, id) DO NOTHING`)
			res := tx.Exec(sb.String(), args...)
			if res.Error != nil {
				return res.Error
			}
			inserted += res.RowsAffected
		}
		return nil
	})
	if err == nil {
		s.maybePurgeDecisions(ws)
	}
	return inserted, err
}

/* --------------------------------- writer --------------------------------- */

// agentGatewayDecisionWriter writes PDP decisions off the request path.
type agentGatewayDecisionWriter struct {
	s     *AgentGatewayService
	ch    chan agentGatewayDecisionRow
	flush chan chan struct{}
	once  sync.Once
}

func newAgentGatewayDecisionWriter(s *AgentGatewayService) *agentGatewayDecisionWriter {
	return &agentGatewayDecisionWriter{s: s, ch: make(chan agentGatewayDecisionRow, agentGatewayWriterBuffer),
		flush: make(chan chan struct{})}
}

func (w *agentGatewayDecisionWriter) enqueue(r agentGatewayDecisionRow) {
	w.once.Do(func() { go w.loop() })
	select {
	case w.ch <- r:
	default:
		// Full: write it in the request rather than lose it.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := w.s.insertDecisions(ctx, r.WorkspaceID, []agentGatewayDecisionRow{r}); err != nil {
			log.Printf("[agent-gateway] stage=decision_log workspace=%s outcome=failed err=%v", r.WorkspaceID, err)
		}
	}
}

func (w *agentGatewayDecisionWriter) loop() {
	t := time.NewTicker(agentGatewayWriterEvery)
	defer t.Stop()
	var pending []agentGatewayDecisionRow
	write := func() {
		if len(pending) == 0 {
			return
		}
		byWS := map[uuid.UUID][]agentGatewayDecisionRow{}
		for _, r := range pending {
			byWS[r.WorkspaceID] = append(byWS[r.WorkspaceID], r)
		}
		pending = nil
		for ws, rows := range byWS {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if _, err := w.s.insertDecisions(ctx, ws, rows); err != nil {
				log.Printf("[agent-gateway] stage=decision_log workspace=%s rows=%d outcome=failed err=%v", ws, len(rows), err)
			}
			cancel()
		}
	}
	drain := func() {
		for {
			select {
			case r := <-w.ch:
				pending = append(pending, r)
			default:
				return
			}
		}
	}
	for {
		select {
		case r := <-w.ch:
			pending = append(pending, r)
			if len(pending) >= agentGatewayWriterBatch {
				write()
			}
		case <-t.C:
			write()
		case done := <-w.flush:
			drain()
			write()
			close(done)
		}
	}
}

// FlushDecisions writes every buffered PDP decision now (tests, shutdown).
func (s *AgentGatewayService) FlushDecisions() {
	w := s.writer
	w.once.Do(func() { go w.loop() })
	done := make(chan struct{})
	w.flush <- done
	<-done
}

/* ---------------------------------- purge --------------------------------- */

func (s *AgentGatewayService) maybePurgeDecisions(ws uuid.UUID) {
	now := s.now()
	s.purgeMu.Lock()
	if last, ok := s.lastPurge[ws]; ok && now.Sub(last) < agentGatewayPurgeEvery {
		s.purgeMu.Unlock()
		return
	}
	s.lastPurge[ws] = now
	s.purgeMu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if _, err := s.PurgeDecisions(ctx, ws); err != nil {
			log.Printf("[agent-gateway] stage=purge workspace=%s outcome=failed err=%v", ws, err)
		}
	}()
}

// PurgeDecisions deletes the workspace's decision rows older than its
// retention and returns how many it deleted.
func (s *AgentGatewayService) PurgeDecisions(ctx context.Context, ws uuid.UUID) (int64, error) {
	var n int64
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		st, err := readAgentGatewaySettings(tx, ws)
		if err != nil {
			return err
		}
		if err := tx.Exec(`SET LOCAL authsec.gateway_decision_purge = 'on'`).Error; err != nil {
			return err
		}
		res := tx.Exec(`DELETE FROM agent_gateway_decision
			WHERE workspace_id = ? AND decided_at < now() - make_interval(days => ?)`, ws, st.DecisionRetentionDays)
		n = res.RowsAffected
		return res.Error
	})
	return n, err
}

/* --------------------------------- upload --------------------------------- */

// AgentGatewayUploadRecord is one record a gateway uploads.
type AgentGatewayUploadRecord struct {
	ID             string               `json:"id"`
	RecordType     string               `json:"record_type"`
	Source         string               `json:"source"`
	DecidedAt      time.Time            `json:"decided_at"`
	Subject        *agentgateway.Entity `json:"subject"`
	Action         *agentgateway.Action `json:"action"`
	Resource       *agentgateway.Entity `json:"resource"`
	Decision       string               `json:"decision"`
	Reason         string               `json:"reason"`
	PolicyID       string               `json:"policy_id,omitempty"`
	DecisionRef    string               `json:"decision_ref,omitempty"`
	LatencyMS      *float64             `json:"latency_ms,omitempty"`
	ArgsDigest     string               `json:"args_digest,omitempty"`
	Usage          *AgentGatewayUsage   `json:"usage,omitempty"`
	UpstreamStatus *int                 `json:"upstream_status,omitempty"`
	RequestID      string               `json:"request_id,omitempty"`
}

// AgentGatewayUpload is the upload body.
type AgentGatewayUpload struct {
	Records []AgentGatewayUploadRecord `json:"records"`
}

// AgentGatewayUploadResult counts an upload.
type AgentGatewayUploadResult struct {
	Received   int `json:"received"`
	Accepted   int `json:"accepted"`
	Duplicates int `json:"duplicates"`
	Rejected   int `json:"rejected"`
	// Errors names the first refused records (index and why), at most 20.
	Errors []map[string]any `json:"errors,omitempty"`
}

// uploadRow validates one record and maps it to a row of the credential's
// workspace and gateway; "" reason means accepted.
func uploadRow(p AgentGatewayPrincipal, rec AgentGatewayUploadRecord, now time.Time) (agentGatewayDecisionRow, string) {
	id, err := uuid.Parse(rec.ID)
	if err != nil {
		return agentGatewayDecisionRow{}, "id must be a UUID"
	}
	switch rec.RecordType {
	case AgentGatewayRecordDecision:
		if !agentGatewayUploadSources[rec.Source] {
			return agentGatewayDecisionRow{}, "source must be cache, gateway, fail_open or fail_closed"
		}
	case AgentGatewayRecordOutcome:
		if rec.Source != AgentGatewaySourcePDP && !agentGatewayUploadSources[rec.Source] {
			return agentGatewayDecisionRow{}, "unknown source"
		}
		if rec.Decision != agentgateway.EffectAllow {
			return agentGatewayDecisionRow{}, "an outcome is of an allowed call"
		}
	default:
		return agentGatewayDecisionRow{}, "record_type must be decision or outcome"
	}
	if rec.Decision != agentgateway.EffectAllow && rec.Decision != agentgateway.EffectDeny {
		return agentGatewayDecisionRow{}, "decision must be allow or deny"
	}
	if !reAgentGatewayReason.MatchString(rec.Reason) {
		return agentGatewayDecisionRow{}, "reason must be a lower-case code"
	}
	if rec.DecidedAt.IsZero() || rec.DecidedAt.Before(now.Add(-agentGatewayUploadMaxAge)) || rec.DecidedAt.After(now.Add(agentGatewayUploadSkew)) {
		return agentGatewayDecisionRow{}, "decided_at must be within the last 7 days"
	}
	ctx := map[string]any{}
	if rec.ArgsDigest != "" {
		ctx["args_digest"] = rec.ArgsDigest
	}
	if rec.RequestID != "" {
		ctx["request_id"] = rec.RequestID
	}
	req, err := agentgateway.FromAuthZEN(agentgateway.EvaluationRequest{Subject: rec.Subject, Action: rec.Action,
		Resource: rec.Resource, Context: ctx})
	if err != nil {
		return agentGatewayDecisionRow{}, strings.TrimPrefix(err.Error(), agentgateway.ErrInvalid.Error()+": ")
	}
	row := agentGatewayDecisionRow{ID: id, WorkspaceID: p.WorkspaceID, GatewayID: p.GatewayID,
		RecordType: rec.RecordType, Source: rec.Source, DecidedAt: rec.DecidedAt.UTC(),
		SubjectType: agentgateway.SubjectTypeAgent, SubjectID: req.SubjectID, Subject: agwJSON(req.SubjectProps()),
		Action: rec.Action.Name, Kind: req.Kind, ResourceID: req.ResourceID(), Resource: agwJSON(req.ResourceProps()),
		Decision: rec.Decision, Reason: rec.Reason, PolicyID: nullUUID(rec.PolicyID), DecisionRef: nullUUID(rec.DecisionRef),
		ArgsDigest: agwStrPtr(req.ArgsDigest), RequestID: req.RequestID}
	if rec.PolicyID != "" && row.PolicyID == nil {
		return agentGatewayDecisionRow{}, "policy_id must be a UUID"
	}
	if rec.DecisionRef != "" && row.DecisionRef == nil {
		return agentGatewayDecisionRow{}, "decision_ref must be a UUID"
	}
	if rec.LatencyMS != nil {
		if *rec.LatencyMS < 0 || *rec.LatencyMS > 3600000 {
			return agentGatewayDecisionRow{}, "latency_ms out of range"
		}
		row.LatencyMS = rec.LatencyMS
	}
	if rec.UpstreamStatus != nil {
		if *rec.UpstreamStatus < 100 || *rec.UpstreamStatus > 599 {
			return agentGatewayDecisionRow{}, "upstream_status must be an HTTP status"
		}
		row.UpstreamStatus = rec.UpstreamStatus
	}
	if rec.Usage != nil {
		if !rec.Usage.valid() {
			return agentGatewayDecisionRow{}, "usage out of range"
		}
		u := agwJSON(rec.Usage)
		row.Usage = &u
	}
	return row, ""
}

// Upload stores a gateway's records under the credential's workspace and
// gateway. Invalid records are counted and refused one by one; the rest are
// stored, idempotent by id.
func (s *AgentGatewayService) Upload(ctx context.Context, p AgentGatewayPrincipal, up AgentGatewayUpload) (AgentGatewayUploadResult, error) {
	res := AgentGatewayUploadResult{Received: len(up.Records)}
	now := s.now()
	var rows []agentGatewayDecisionRow
	seen := map[uuid.UUID]bool{}
	for i, rec := range up.Records {
		row, why := uploadRow(p, rec, now)
		if why == "" && seen[row.ID] {
			res.Duplicates++
			continue
		}
		if why != "" {
			res.Rejected++
			if len(res.Errors) < 20 {
				res.Errors = append(res.Errors, map[string]any{"index": i, "error": why})
			}
			continue
		}
		seen[row.ID] = true
		rows = append(rows, row)
	}
	n, err := s.insertDecisions(ctx, p.WorkspaceID, rows)
	if err != nil {
		return res, err
	}
	res.Accepted = int(n)
	res.Duplicates += len(rows) - int(n)
	return res, nil
}

/* ---------------------------------- list ---------------------------------- */

// AgentGatewayDecisionView is a decision log row as the admin API shows it.
type AgentGatewayDecisionView struct {
	ID             uuid.UUID       `json:"id"`
	GatewayID      uuid.UUID       `json:"gateway_id"`
	RecordType     string          `json:"record_type"`
	Source         string          `json:"source"`
	DecidedAt      time.Time       `json:"decided_at"`
	ReceivedAt     time.Time       `json:"received_at"`
	SubjectType    string          `json:"subject_type"`
	SubjectID      string          `json:"subject_id"`
	Subject        json.RawMessage `json:"subject"`
	Action         string          `json:"action"`
	Kind           string          `json:"kind"`
	ResourceID     string          `json:"resource_id"`
	Resource       json.RawMessage `json:"resource"`
	Decision       string          `json:"decision"`
	Reason         string          `json:"reason"`
	PolicyID       *uuid.UUID      `json:"policy_id,omitempty"`
	DecisionRef    *uuid.UUID      `json:"decision_ref,omitempty"`
	LatencyMS      *float64        `json:"latency_ms,omitempty"`
	ArgsDigest     *string         `json:"args_digest,omitempty"`
	Usage          json.RawMessage `json:"usage,omitempty"`
	UpstreamStatus *int            `json:"upstream_status,omitempty"`
	RequestID      string          `json:"request_id,omitempty"`
}

// AgentGatewayDecisionFilter narrows a list.
type AgentGatewayDecisionFilter struct {
	GatewayID  *uuid.UUID
	Decision   string
	Kind       string
	SubjectID  string
	Source     string
	RecordType string
	Since      *time.Time
	Until      *time.Time
}

func encodeDecisionCursor(t time.Time, id uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(t.UnixNano(), 10) + "|" + id.String()))
}

func decodeDecisionCursor(c string) (time.Time, uuid.UUID, error) {
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return time.Time{}, uuid.Nil, err
	}
	ns, idS, ok := strings.Cut(string(raw), "|")
	if !ok {
		return time.Time{}, uuid.Nil, fmt.Errorf("bad cursor")
	}
	n, err := strconv.ParseInt(ns, 10, 64)
	if err != nil {
		return time.Time{}, uuid.Nil, err
	}
	id, err := uuid.Parse(idS)
	if err != nil {
		return time.Time{}, uuid.Nil, err
	}
	return time.Unix(0, n).UTC(), id, nil
}

// ListDecisions lists the workspace's decision log, newest first.
func (s *AgentGatewayService) ListDecisions(ctx context.Context, ws uuid.UUID, f AgentGatewayDecisionFilter, cursor string, limit int) ([]AgentGatewayDecisionView, *string, error) {
	if limit <= 0 || limit > MaxGovPage {
		limit = 50
	}
	var (
		where = []string{"workspace_id = ?"}
		args  = []any{ws}
	)
	if f.GatewayID != nil {
		where, args = append(where, "gateway_id = ?"), append(args, *f.GatewayID)
	}
	for col, v := range map[string]string{"decision": f.Decision, "kind": f.Kind, "subject_id": f.SubjectID,
		"source": f.Source, "record_type": f.RecordType} {
		if v != "" {
			where, args = append(where, col+" = ?"), append(args, v)
		}
	}
	if f.Since != nil {
		where, args = append(where, "decided_at >= ?"), append(args, *f.Since)
	}
	if f.Until != nil {
		where, args = append(where, "decided_at < ?"), append(args, *f.Until)
	}
	if cursor != "" {
		t, id, err := decodeDecisionCursor(cursor)
		if err != nil {
			return nil, nil, GovBadParam("cursor", "The cursor is not valid.")
		}
		where, args = append(where, "(decided_at, id) < (?, ?)"), append(args, t, id)
	}
	args = append(args, limit+1)
	var rows []struct {
		ID             uuid.UUID
		GatewayID      uuid.UUID
		RecordType     string
		Source         string
		DecidedAt      time.Time
		ReceivedAt     time.Time
		SubjectType    string
		SubjectID      string
		Subject        string
		Action         string
		Kind           string
		ResourceID     string
		Resource       string
		Decision       string
		Reason         string
		PolicyID       *uuid.UUID
		DecisionRef    *uuid.UUID
		LatencyMS      *float64 `gorm:"column:latency_ms"`
		ArgsDigest     *string
		Usage          *string
		UpstreamStatus *int
		RequestID      string
	}
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT id, gateway_id, record_type, source, decided_at, received_at, subject_type, subject_id,
			    subject::text AS subject, action, kind, resource_id, resource::text AS resource, decision, reason,
			    policy_id, decision_ref, latency_ms, args_digest, usage::text AS usage, upstream_status, request_id
			FROM agent_gateway_decision WHERE `+strings.Join(where, " AND ")+`
			ORDER BY decided_at DESC, id DESC LIMIT ?`, args...).Scan(&rows).Error
	})
	if err != nil {
		return nil, nil, err
	}
	var next *string
	if len(rows) > limit {
		rows = rows[:limit]
		c := encodeDecisionCursor(rows[limit-1].DecidedAt, rows[limit-1].ID)
		next = &c
	}
	out := make([]AgentGatewayDecisionView, 0, len(rows))
	for _, r := range rows {
		v := AgentGatewayDecisionView{ID: r.ID, GatewayID: r.GatewayID, RecordType: r.RecordType, Source: r.Source,
			DecidedAt: r.DecidedAt.UTC(), ReceivedAt: r.ReceivedAt.UTC(), SubjectType: r.SubjectType, SubjectID: r.SubjectID,
			Subject: json.RawMessage(r.Subject), Action: r.Action, Kind: r.Kind, ResourceID: r.ResourceID,
			Resource: json.RawMessage(r.Resource), Decision: r.Decision, Reason: r.Reason, PolicyID: r.PolicyID,
			DecisionRef: r.DecisionRef, LatencyMS: r.LatencyMS, ArgsDigest: r.ArgsDigest, UpstreamStatus: r.UpstreamStatus,
			RequestID: r.RequestID}
		if r.Usage != nil {
			v.Usage = json.RawMessage(*r.Usage)
		}
		out = append(out, v)
	}
	return out, next, nil
}
