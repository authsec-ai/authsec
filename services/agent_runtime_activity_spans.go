package services

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentactivity"
	"github.com/authsec-ai/authsec/internal/tenancy"
)

// AgentCore observability spans (SPEC-agent-runtime-activity.md §4.2).
//
// During the AWS scan, per connector and selected region, one Logs Insights
// query reads the GenAI / agent / MCP span records written to aws/spans since
// the region's cursor (agent_activity_cursor, stream aws_spans), at most
// DefaultSpanQueryLimit per scan. Spans become activity rows (source
// agentcore_span) attributed to the AgentCore runtime workload of this
// connector, and its role. A refused or unconfigured read is recorded on the
// cursor (permission_missing / not_configured) and as a scan warning; it
// never fails the scan and never changes the scan's own coverage.

// Span reader window.
const (
	// AgentSpanFirstWindow is how far back a region's first read goes.
	AgentSpanFirstWindow = 24 * time.Hour
	// AgentSpanIngestLag keeps the newest minutes for the next scan: spans
	// reach aws/spans with a delay, and a cursor past them would skip them.
	AgentSpanIngestLag = 5 * time.Minute
	// agentSpanStream is agent_activity_cursor.stream.
	agentSpanStream = "aws_spans"
)

// AgentSpanAPIFunc returns the Logs Insights client for one connector and
// region.
type AgentSpanAPIFunc func(ctx context.Context, ws, connectorID uuid.UUID, region string) (agentactivity.LogsInsightsAPI, error)

var agentSpanAPIOverride struct {
	sync.RWMutex
	f AgentSpanAPIFunc
}

// SetAgentSpanAPI installs a Logs Insights client factory for every scanner
// (tests); nil restores the default (assume the connector's role).
func SetAgentSpanAPI(f AgentSpanAPIFunc) {
	agentSpanAPIOverride.Lock()
	agentSpanAPIOverride.f = f
	agentSpanAPIOverride.Unlock()
}

func agentSpanAPIFor() AgentSpanAPIFunc {
	agentSpanAPIOverride.RLock()
	defer agentSpanAPIOverride.RUnlock()
	return agentSpanAPIOverride.f
}

// scanAgentActivitySpans is the scan's one call per region. Without a
// database it does nothing; a scanner built on injected test clients reads
// spans only when a test installed SetAgentSpanAPI, so a scan test never
// reaches AWS.
func (s *AWSWorkloadScanner) scanAgentActivitySpans(
	ctx context.Context, workspaceID uuid.UUID, snapshot *IAMSnapshot, region string, out *WorkloadSnapshot,
) {
	// TENANT-EXEMPT: not a statement: a nil check; every statement runs in the collector's workspace transactions.
	if s.db == nil || snapshot == nil {
		return
	}
	apiFor := agentSpanAPIFor()
	injected := s.regionalAPIs != nil || s.lambdaAPI != nil || s.ecsAPI != nil || s.ec2API != nil ||
		s.bedrockAPI != nil || s.agentCoreAPI != nil || s.cloudTrailAPI != nil
	if apiFor == nil {
		if injected || s.onboarding == nil {
			return
		}
		apiFor = func(ctx context.Context, ws, connectorID uuid.UUID, region string) (agentactivity.LogsInsightsAPI, error) {
			cfg, _, err := s.onboarding.ConfigForConnector(ctx, ws, connectorID, region)
			if err != nil {
				return nil, err
			}
			return agentactivity.NewLogsInsightsClient(cfg), nil
		}
	}
	// TENANT-EXEMPT: not a statement here: the collector runs every statement under tenancy.InWorkspace / InWorkspaceRead for workspaceID.
	res, err := NewAgentSpanCollector(s.db).Collect(ctx, workspaceID, snapshot.ConnectorID, region, apiFor)
	if err != nil {
		msg := fmt.Sprintf("agentcore spans %s: %v", region, err)
		log.Printf("aws workload scan: %s", msg)
		out.Warnings = append(out.Warnings, msg)
		return
	}
	switch res.State {
	case agentactivity.SpanStatePermissionMissing, agentactivity.SpanStateError:
		msg := fmt.Sprintf("agentcore spans %s: %s (%s)", region, res.State, res.Error)
		log.Printf("aws workload scan: %s", msg)
		out.Warnings = append(out.Warnings, msg)
	}
}

// AgentSpanCollectResult is what one region's read did.
type AgentSpanCollectResult struct {
	State    string
	Error    string
	Read     int
	Ignored  int
	Inserted int
	CursorAt time.Time
}

// AgentSpanCollector reads AgentCore spans for one (connector, region).
type AgentSpanCollector struct {
	db    *gorm.DB
	now   func() time.Time
	limit int
	sleep func(context.Context, time.Duration) error
}

// NewAgentSpanCollector builds the collector.
func NewAgentSpanCollector(db *gorm.DB) *AgentSpanCollector {
	return &AgentSpanCollector{db: db, now: time.Now, limit: agentactivity.DefaultSpanQueryLimit}
}

// WithClock, WithLimit and WithSleep are test seams.
func (c *AgentSpanCollector) WithClock(now func() time.Time) *AgentSpanCollector {
	c.now = now
	return c
}
func (c *AgentSpanCollector) WithLimit(n int) *AgentSpanCollector { c.limit = n; return c }
func (c *AgentSpanCollector) WithSleep(f func(context.Context, time.Duration) error) *AgentSpanCollector {
	c.sleep = f
	return c
}

// Collect reads the region's spans since its cursor, stores them and moves
// the cursor. A read failure is a state on the cursor (returned in the
// result), not an error; an error is AuthSec's own database failure.
func (c *AgentSpanCollector) Collect(ctx context.Context, ws, connectorID uuid.UUID, region string, apiFor AgentSpanAPIFunc) (AgentSpanCollectResult, error) {
	var res AgentSpanCollectResult
	now := c.now().UTC()
	var cursor *time.Time
	if err := tenancy.InWorkspaceRead(ctx, c.db, ws, func(tx *gorm.DB) error {
		var rows []struct{ CursorAt *time.Time }
		if err := tx.Raw(`SELECT cursor_at FROM agent_activity_cursor
		                  WHERE workspace_id = ? AND connector_id = ? AND region = ? AND stream = ?`,
			ws, connectorID, region, agentSpanStream).Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 1 {
			cursor = rows[0].CursorAt
		}
		return nil
	}); err != nil {
		return res, err
	}
	since := now.Add(-AgentSpanFirstWindow)
	if cursor != nil {
		since = cursor.UTC()
	}
	until := now.Add(-AgentSpanIngestLag)
	if !until.After(since) {
		res.State = agentactivity.SpanStateReached
		if cursor != nil {
			res.CursorAt = *cursor
		}
		return res, nil
	}

	api, err := apiFor(ctx, ws, connectorID, region)
	var read agentactivity.SpanRead
	if err == nil {
		read, err = agentactivity.ReadAWSSpans(ctx, api, agentactivity.SpanQuery{Since: since, Until: until, Limit: c.limit, Sleep: c.sleep})
	}
	if err != nil {
		state, code := agentactivity.SpanReadState(err)
		res.State, res.Error = state, agentactivity.Truncate(err.Error(), 1000)
		return res, c.saveCursor(ctx, ws, connectorID, region, cursor, state, res.Error, code, 0)
	}

	res.Read = len(read.Spans)
	var acts []agentactivity.Activity
	for _, sp := range read.Spans {
		a, ok := agentactivity.Normalise(sp, agentactivity.SourceAgentCoreSpan)
		if !ok {
			res.Ignored++
			continue
		}
		acts = append(acts, a)
	}
	next, state := until, agentactivity.SpanStateReached
	if read.CapHit {
		state = agentactivity.SpanStatePartial
		next = read.Last
		// No progress (every row at the cursor's second): step past it, so
		// the reader is never stuck; the gap is reported as partial.
		if !next.After(since) {
			next = since.Add(time.Second)
		}
	}
	err = tenancy.InWorkspace(ctx, c.db, ws, func(tx *gorm.DB) error {
		conn := connectorID
		rows, err := attributeActivities(tx, ws, &conn, acts)
		if err != nil {
			return err
		}
		if res.Inserted, _, err = insertActivities(tx, ws, rows, now); err != nil {
			return err
		}
		return upsertAgentSpanCursor(tx, ws, connectorID, region, &next, state, "", "", int64(res.Inserted))
	})
	if err != nil {
		return res, err
	}
	res.State, res.CursorAt = state, next
	return res, nil
}

// saveCursor records a failed read without moving the cursor.
func (c *AgentSpanCollector) saveCursor(ctx context.Context, ws, connectorID uuid.UUID, region string,
	cursor *time.Time, state, msg, code string, rows int64) error {
	return tenancy.InWorkspace(ctx, c.db, ws, func(tx *gorm.DB) error {
		return upsertAgentSpanCursor(tx, ws, connectorID, region, cursor, state, msg, code, rows)
	})
}

func upsertAgentSpanCursor(tx *gorm.DB, ws, connectorID uuid.UUID, region string, cursor *time.Time,
	state, msg, code string, rows int64) error {
	return tx.Exec(`INSERT INTO agent_activity_cursor
	                    (workspace_id, connector_id, region, stream, cursor_at, state, last_error, error_code, last_scan_at, rows_written)
	                VALUES (?, ?, ?, ?, ?, ?, ?, ?, now(), ?)
	                ON CONFLICT (workspace_id, connector_id, region, stream) DO UPDATE SET
	                    cursor_at    = COALESCE(EXCLUDED.cursor_at, agent_activity_cursor.cursor_at),
	                    state        = EXCLUDED.state,
	                    last_error   = EXCLUDED.last_error,
	                    error_code   = EXCLUDED.error_code,
	                    last_scan_at = now(),
	                    rows_written = agent_activity_cursor.rows_written + EXCLUDED.rows_written`,
		ws, connectorID, region, agentSpanStream, cursor, state, agentactivity.Truncate(msg, 1000),
		agentactivity.Truncate(code, 128), rows).Error
}
