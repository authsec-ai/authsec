package integration

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// Live discovery (lab 2026-11-05): a streamed model call by a role with no
// scan evidence makes it an AI workload at once -- listed with seen_live and
// its live counts, labelled by the resolver so the detections run on it in
// the same batch -- without a scan. The same event dispatched twice (the
// stream and the poller) counts once; workspace B sees nothing of A's, and an
// event dispatched under B's workspace cannot reach A's identity.

type liveWorld struct {
	g       *p3Gov
	role    uuid.UUID
	roleARN string
	roleID  string
}

func liveSeed(t *testing.T, db *gorm.DB, name string) *liveWorld {
	t.Helper()
	g := p3NewGov(t, db, name)
	w := &liveWorld{g: g, role: uuid.New(), roleARN: "arn:aws:iam::111111111111:role/live-agent",
		roleID: "AROALIVE" + strings.ToUpper(strings.ReplaceAll(uuid.NewString(), "-", ""))[:12]}
	attrs, _ := json.Marshal(map[string]string{"unique_id": w.roleID})
	arExec(t, db, `INSERT INTO cloud_identity (id, workspace_id, connector_id, kind, native_id, name, attrs)
		VALUES (?, ?, ?, ?, ?, 'live-agent', ?::jsonb)`, w.role, g.ws, g.conn, models.CloudIdentityIAMRole, w.roleARN, string(attrs))
	arExec(t, db, `INSERT INTO cloud_workload (workspace_id, connector_id, identity_id, runtime_kind, native_id, name, region, attrs)
		VALUES (?, ?, ?, ?, ?, 'live-fn', 'us-east-1', '{}'::jsonb)`, g.ws, g.conn, w.role, models.WorkloadLambdaFunction,
		"arn:aws:lambda:us-east-1:111111111111:function:live-fn-"+name)
	return w
}

func (w *liveWorld) event(id, source, name string, at time.Time) agentruntime.Event {
	e := agentruntime.Event{EventID: id, EventTime: at, EventSource: source, EventName: name, EventType: "AwsApiCall",
		AccountID: "111111111111", Region: "us-east-1", SourceIP: "203.0.113.30",
		PrincipalType: "AssumedRole", PrincipalARN: "arn:aws:sts::111111111111:assumed-role/live-agent/live-fn",
		SessionIssuerType: "Role", SessionIssuerARN: w.roleARN, SessionIssuerPrincipalID: w.roleID}
	if source == agentruntime.SourceBedrock {
		e.RequestFacts = map[string]string{agentruntime.FactModelID: "anthropic.claude-sonnet"}
	}
	return e
}

func TestAgentLiveDiscovery(t *testing.T) {
	db := igaDB(t)
	a := liveSeed(t, db, "ar-live-a")
	b := liveSeed(t, db, "ar-live-b")
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	type inferred struct {
		ws, conn uuid.UUID
		res      services.AgentInferenceResult
		err      error
	}
	ran := make(chan inferred, 8)
	live := services.NewAgentLiveSink(db).WithInference(func(ctx context.Context, ws, conn uuid.UUID) error {
		res, err := services.NewAgentRuntimeService(db).RunAgentInference(ctx, ws, conn)
		ran <- inferred{ws, conn, res, err}
		return err
	}, 50*time.Millisecond)
	agentruntime.ResetSinks()
	t.Cleanup(agentruntime.ResetSinks)
	agentruntime.SetResolver(services.NewAgentRuntimeResolver(db))
	agentruntime.RegisterSink(live)
	agentruntime.RegisterSink(services.NewAgentAlertSink(db))

	svc := services.NewAgentRuntimeService(db)
	list := func(ws uuid.UUID) []*services.AIWorkload {
		t.Helper()
		items, _, err := svc.ListAIWorkloads(ctx, ws, services.AIWorkloadFilter{})
		if err != nil {
			t.Fatal(err)
		}
		return items
	}
	label := func(w *liveWorld) string {
		t.Helper()
		s, err := services.NewAgentRuntimeResolver(db).Resolve(ctx, w.g.ws, w.g.conn,
			agentruntime.Attribution{How: agentruntime.AttributionSessionIssuer, ARN: w.roleARN, UniqueID: w.roleID})
		if err != nil {
			t.Fatal(err)
		}
		return s.Label
	}

	// No scan evidence: not an AI workload.
	if got := list(a.g.ws); len(got) != 0 || label(a) != "" {
		t.Fatalf("before: %d AI workloads, label %q", len(got), label(a))
	}

	// One streamed batch: a model call and a secret read by the same role.
	call := a.event("live-call-1", agentruntime.SourceBedrock, "Converse", now.Add(-5*time.Minute))
	read := a.event("live-read-1", "secretsmanager.amazonaws.com", "GetSecretValue", now.Add(-4*time.Minute))
	if err := agentruntime.Dispatch(ctx, a.g.ws, a.g.conn, []agentruntime.Event{call, read}); err != nil {
		t.Fatal(err)
	}
	items := list(a.g.ws)
	if len(items) != 1 {
		t.Fatalf("after the stream: %d AI workloads, want 1", len(items))
	}
	ai := items[0]
	if ai.Identity.ID != a.role || !ai.SeenLive || ai.Live.Calls != 1 || ai.Live.Denied != 0 ||
		ai.Live.Models["anthropic.claude-sonnet"] != 1 || ai.Live.LastCallAt == nil || ai.Calls != 0 ||
		ai.Label != agentruntime.LabelAIWorkload {
		t.Fatalf("live AI workload: %+v", ai)
	}
	raw, _ := json.Marshal(ai)
	if !strings.Contains(string(raw), `"seen_live":true`) || !strings.Contains(string(raw), `"live":{"calls":1,"denied":0,`) {
		t.Fatalf("list JSON lacks live / seen_live: %s", raw)
	}
	if l := label(a); l != agentruntime.LabelAIWorkload {
		t.Fatalf("resolver label %q, want ai_workload without a scan", l)
	}
	// D1 ran on the read in the same batch: the label was already there.
	if got := arAlerts(t, db, a.g.ws); len(got) != 1 || got[0].Detection != "D1" {
		t.Fatalf("alerts %+v, want one D1", got)
	}
	select {
	case r := <-ran:
		if r.ws != a.g.ws || r.conn != a.g.conn || r.err != nil || r.res.AIWorkloads != 1 {
			t.Fatalf("inference %+v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("inference was not triggered")
	}

	// The same event again (the poller after the stream), and a denial.
	denied := a.event("live-call-2", agentruntime.SourceBedrock, "InvokeModel", now.Add(-time.Minute))
	denied.ErrorCode, denied.AuthorizationDenied = "AccessDeniedException", true
	if err := agentruntime.Dispatch(ctx, a.g.ws, a.g.conn, []agentruntime.Event{call, denied}); err != nil {
		t.Fatal(err)
	}
	if n, err := live.Record(ctx, a.g.ws, a.g.conn, []agentruntime.Event{call, denied}); err != nil || n != 0 {
		t.Fatalf("a third delivery counted %d (%v)", n, err)
	}
	// The denial was new: inference runs again (debounced), and is awaited
	// so nothing writes while the workspaces are removed.
	select {
	case r := <-ran:
		if r.err != nil {
			t.Fatalf("second inference: %v", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("inference was not triggered for the denial")
	}
	ai = list(a.g.ws)[0]
	if ai.Live.Calls != 1 || ai.Live.Denied != 1 {
		t.Fatalf("after duplicates: live %+v, want 1 call and 1 denial", ai.Live)
	}
	var rows int64
	db.Raw(`SELECT count(*) FROM cloud_usage WHERE workspace_id = ? AND source = 'cloudtrail' AND service = 'bedrock'`, a.g.ws).Scan(&rows)
	if rows != 1 {
		t.Fatalf("%d model-call rows in A, want 1", rows)
	}

	// Workspace B sees nothing of A's: no AI workload, no label, no alert.
	if got := list(b.g.ws); len(got) != 0 {
		t.Fatalf("workspace B lists %d AI workloads", len(got))
	}
	if l := label(b); l != "" {
		t.Fatalf("workspace B's role is labelled %q", l)
	}
	if got := arAlerts(t, db, b.g.ws); len(got) != 0 {
		t.Fatalf("workspace B has alerts %+v", got)
	}
	// A's event dispatched under B's workspace with A's connector reaches
	// nothing: the attribution is read under B's row-level security.
	other := a.event("live-call-3", agentruntime.SourceBedrock, "Converse", now)
	if n, err := live.Record(ctx, b.g.ws, a.g.conn, []agentruntime.Event{other}); err != nil || n != 0 {
		t.Fatalf("B's workspace with A's connector counted %d (%v)", n, err)
	}
	db.Raw(`SELECT count(*) FROM cloud_usage WHERE workspace_id = ? AND source = 'cloudtrail'`, b.g.ws).Scan(&rows)
	if rows != 0 {
		t.Fatalf("%d model-call rows in B", rows)
	}
	db.Raw(`SELECT count(*) FROM agent_live_event_seen WHERE workspace_id = ?`, b.g.ws).Scan(&rows)
	if rows != 0 {
		t.Fatalf("%d seen rows in B", rows)
	}
	if ai = list(a.g.ws)[0]; ai.Live.Calls != 1 {
		t.Fatalf("A changed through B: %+v", ai.Live)
	}

	// The purge keeps the workspace's recent rows and removes old ones.
	db.Exec(`UPDATE agent_live_event_seen SET seen_at = now() - interval '9 days' WHERE workspace_id = ? AND event_id = ?`, a.g.ws, "live-call-1")
	if n, err := live.PurgeSeen(ctx, a.g.ws, time.Now().Add(-services.AgentLiveSeenRetention)); err != nil || n != 1 {
		t.Fatalf("purge removed %d (%v), want 1", n, err)
	}
}
