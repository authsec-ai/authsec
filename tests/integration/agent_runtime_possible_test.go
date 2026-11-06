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

// Possible AI workloads from configuration hints: an agent that calls a model
// provider directly (no Bedrock) leaves no model-call evidence, but its
// Lambda's environment variable NAMES do. Inference records an
// ai_config_hint finding per workload, the identity is labelled
// possible_ai_workload (listed, resolved, alerted on, never suggested); an
// open ai_network_traffic finding (another writer's) makes an identity an AI
// workload and is never resolved by inference; hints that are unknown keep
// the finding, hints that are gone resolve it. Workspace B sees none of A's.

type possibleWorld struct {
	g                         *p3Gov
	hint, net, plain          uuid.UUID
	hintARN, netARN, plainARN string
	hintFn                    string
}

func possibleSeed(t *testing.T, db *gorm.DB, name string) *possibleWorld {
	t.Helper()
	g := p3NewGov(t, db, name)
	w := &possibleWorld{g: g}
	role := func(rn string, env map[string]any) (uuid.UUID, string, string) {
		id := uuid.New()
		arn := "arn:aws:iam::111111111111:role/" + rn
		arExec(t, db, `INSERT INTO cloud_identity (id, workspace_id, connector_id, kind, native_id, name, attrs)
			VALUES (?, ?, ?, ?, ?, ?, ?::jsonb)`, id, g.ws, g.conn, models.CloudIdentityIAMRole, arn, rn,
			`{"unique_id":"AROA`+strings.ToUpper(rn)+`"}`)
		attrs, _ := json.Marshal(env)
		fn := "arn:aws:lambda:us-east-1:111111111111:function:" + rn + "-fn"
		arExec(t, db, `INSERT INTO cloud_workload (workspace_id, connector_id, identity_id, runtime_kind, native_id, name, region, attrs)
			VALUES (?, ?, ?, ?, ?, ?, 'us-east-1', ?::jsonb)`, g.ws, g.conn, id, models.WorkloadLambdaFunction, fn, rn+"-fn", string(attrs))
		return id, arn, fn
	}
	w.hint, w.hintARN, w.hintFn = role("direct-openai", map[string]any{"env_var_names": []string{"OPENAI_API_KEY", "PATH"}})
	w.net, w.netARN, _ = role("dns-seen", map[string]any{})
	w.plain, w.plainARN, _ = role("plain", map[string]any{"env_var_names": []string{"PATH"}})
	// The network evidence path's finding (migration 153 on its branch).
	arExec(t, db, `INSERT INTO agent_finding (workspace_id, connector_id, kind, subject_key, identity_id, subject, evidence)
		VALUES (?, ?, 'ai_network_traffic', ?, ?, '{}'::jsonb, '{"providers":["openai"],"attribution":{"how":"srcids_instance","confidence":"query_time"}}'::jsonb)`,
		g.ws, g.conn, "dns:"+w.netARN, w.net)
	return w
}

func setWorkloadAttrs(t *testing.T, db *gorm.DB, ws uuid.UUID, fn string, attrs map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(attrs)
	arExec(t, db, `UPDATE cloud_workload SET attrs = ?::jsonb WHERE workspace_id = ? AND native_id = ?`, string(raw), ws, fn)
}

func TestAgentRuntimePossibleAIWorkloadFromConfigHints(t *testing.T) {
	db := igaDB(t)
	a := possibleSeed(t, db, "ar-possible-a")
	b := possibleSeed(t, db, "ar-possible-b")
	ctx := context.Background()
	svc := services.NewAgentRuntimeService(db)

	infer := func(w *possibleWorld) services.AgentInferenceResult {
		t.Helper()
		res, err := svc.RunAgentInference(ctx, w.g.ws, w.g.conn)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	list := func(w *possibleWorld, label string) []*services.AIWorkload {
		t.Helper()
		items, _, err := svc.ListAIWorkloads(ctx, w.g.ws, services.AIWorkloadFilter{Label: label})
		if err != nil {
			t.Fatal(err)
		}
		return items
	}
	label := func(w *possibleWorld, arn string) string {
		t.Helper()
		s, err := services.NewAgentRuntimeResolver(db).Resolve(ctx, w.g.ws, w.g.conn,
			agentruntime.Attribution{How: agentruntime.AttributionSessionIssuer, ARN: arn})
		if err != nil {
			t.Fatal(err)
		}
		return s.Label
	}
	hintFindings := func(w *possibleWorld, state string) []services.AgentFinding {
		t.Helper()
		fs, _, err := svc.ListFindings(ctx, w.g.ws, services.FindingListFilter{Kind: services.FindingAIConfigHint, State: state})
		if err != nil {
			t.Fatal(err)
		}
		return fs
	}

	res := infer(a)
	if res.PossibleAIWorkloads != 1 || res.AIWorkloads != 1 || res.ConfigHintsOpen != 1 {
		t.Fatalf("inference %+v, want 1 possible (hints), 1 AI workload (network), 1 hint", res)
	}
	fs := hintFindings(a, services.FindingOpen)
	if len(fs) != 1 || fs[0].IdentityID == nil || *fs[0].IdentityID != a.hint || fs[0].SubjectKey != a.hintFn {
		t.Fatalf("hint findings %+v", fs)
	}
	if ev := string(fs[0].Evidence); !strings.Contains(ev, `"OPENAI_API_KEY"`) || strings.Contains(ev, "PATH") {
		t.Fatalf("hint evidence %s", ev)
	}

	possible := list(a, agentruntime.LabelPossibleAIWorkload)
	if len(possible) != 1 || possible[0].Identity.ID != a.hint || len(possible[0].ConfigHints) != 1 || possible[0].Suggestion != nil {
		t.Fatalf("possible AI workloads %+v", possible)
	}
	evidenced := list(a, agentruntime.LabelAIWorkload)
	if len(evidenced) != 1 || evidenced[0].Identity.ID != a.net || len(evidenced[0].NetworkTraffic) != 1 {
		t.Fatalf("AI workloads %+v", evidenced)
	}
	if all := list(a, ""); len(all) != 2 {
		t.Fatalf("the list holds %d, want 2", len(all))
	}
	if l := label(a, a.hintARN); l != agentruntime.LabelPossibleAIWorkload {
		t.Fatalf("hint role label %q", l)
	}
	if l := label(a, a.netARN); l != agentruntime.LabelAIWorkload {
		t.Fatalf("network role label %q", l)
	}
	if l := label(a, a.plainARN); l != "" {
		t.Fatalf("plain role label %q", l)
	}
	// Inference never resolves another writer's finding, and never suggests
	// from names.
	var n int64
	db.Raw(`SELECT count(*) FROM agent_finding WHERE workspace_id = ? AND kind = 'ai_network_traffic' AND state = 'open'`, a.g.ws).Scan(&n)
	if n != 1 {
		t.Fatalf("network findings open: %d, want 1", n)
	}
	db.Raw(`SELECT count(*) FROM agent_suggestion WHERE workspace_id = ?`, a.g.ws).Scan(&n)
	if n != 0 {
		t.Fatalf("%d suggestions from names", n)
	}

	// Detections do not apply to a possible AI workload (§5.7): names are not
	// evidence of model use.
	agentruntime.ResetSinks()
	t.Cleanup(agentruntime.ResetSinks)
	agentruntime.SetResolver(services.NewAgentRuntimeResolver(db))
	agentruntime.RegisterSink(services.NewAgentAlertSink(db))
	read := agentruntime.Event{EventID: "possible-read-1", EventTime: time.Now().UTC().Add(-time.Minute),
		EventSource: "secretsmanager.amazonaws.com", EventName: "GetSecretValue", EventType: "AwsApiCall",
		AccountID: "111111111111", Region: "us-east-1", SourceIP: "203.0.113.40", PrincipalType: "AssumedRole",
		SessionIssuerType: "Role", SessionIssuerARN: a.hintARN, SessionIssuerPrincipalID: "AROADIRECT-OPENAI"}
	if err := agentruntime.Dispatch(ctx, a.g.ws, a.g.conn, []agentruntime.Event{read}); err != nil {
		t.Fatal(err)
	}
	var titles []string
	db.Raw(`SELECT title FROM agent_alert WHERE workspace_id = ?`, a.g.ws).Scan(&titles)
	if len(titles) != 0 {
		t.Fatalf("a possible AI workload raised alerts: %v", titles)
	}

	// Workspace B: nothing of A's before its own inference, its own after.
	// Before its own inference B lists only its own network-proven role.
	if got := list(b, ""); len(got) != 1 || got[0].Identity.ID != b.net {
		t.Fatalf("workspace B before its inference: %+v", got)
	}
	_ = infer(b)
	if got := hintFindings(b, ""); len(got) != 1 || *got[0].IdentityID != b.hint {
		t.Fatalf("workspace B hint findings %+v", got)
	}
	if got := hintFindings(a, ""); len(got) != 1 || *got[0].IdentityID != a.hint {
		t.Fatalf("workspace A hint findings changed: %+v", got)
	}
	db.Raw(`SELECT count(*) FROM agent_alert WHERE workspace_id = ?`, b.g.ws).Scan(&n)
	if n != 0 {
		t.Fatalf("workspace B has %d alerts", n)
	}

	// An unreadable environment is unknown, not gone: the finding stays.
	setWorkloadAttrs(t, db, a.g.ws, a.hintFn, map[string]any{"env_vars_unread": true})
	if res := infer(a); res.ConfigHintsResolved != 0 {
		t.Fatalf("resolved on an unreadable environment: %+v", res)
	}
	if fs := hintFindings(a, services.FindingOpen); len(fs) != 1 {
		t.Fatalf("open hint findings %d, want 1", len(fs))
	}
	// The hint is gone: resolved, and the identity is nothing any more.
	setWorkloadAttrs(t, db, a.g.ws, a.hintFn, map[string]any{"env_var_names": []string{"PATH"}})
	if res := infer(a); res.ConfigHintsResolved != 1 || res.PossibleAIWorkloads != 0 {
		t.Fatalf("after the hint went: %+v", res)
	}
	if got := list(a, agentruntime.LabelPossibleAIWorkload); len(got) != 0 {
		t.Fatalf("still possible: %+v", got)
	}
	if l := label(a, a.hintARN); l != "" {
		t.Fatalf("label after the hint went: %q", l)
	}
}
