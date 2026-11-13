package services

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestActivityTree(t *testing.T) {
	at := time.Now()
	rows := []AgentActivity{
		{ID: uuid.New(), SpanID: "a", OccurredAt: at},
		{ID: uuid.New(), SpanID: "b", ParentSpanID: "a", OccurredAt: at.Add(time.Second)},
		{ID: uuid.New(), SpanID: "c", ParentSpanID: "b", OccurredAt: at.Add(2 * time.Second)},
		{ID: uuid.New(), SpanID: "d", ParentSpanID: "missing", OccurredAt: at.Add(3 * time.Second)},
		{ID: uuid.New(), SpanID: "e", ParentSpanID: "e", OccurredAt: at.Add(4 * time.Second)},
	}
	roots := activityTree(rows)
	if len(roots) != 3 || roots[0].SpanID != "a" || roots[1].SpanID != "d" || roots[2].SpanID != "e" {
		t.Fatalf("roots: %d", len(roots))
	}
	if len(roots[0].Children) != 1 || roots[0].Children[0].SpanID != "b" || roots[0].Children[0].Children[0].SpanID != "c" {
		t.Fatalf("children of a: %+v", roots[0].Children)
	}
}

func TestLambdaFunctionARN(t *testing.T) {
	for in, want := range map[string]string{
		"arn:aws:lambda:us-east-1:111111111111:function:fn":         "arn:aws:lambda:us-east-1:111111111111:function:fn",
		"arn:aws:lambda:us-east-1:111111111111:function:fn:$LATEST": "arn:aws:lambda:us-east-1:111111111111:function:fn",
		"arn:aws:lambda:us-east-1:111111111111:function:fn:prod":    "arn:aws:lambda:us-east-1:111111111111:function:fn",
		"arn:aws:ecs:us-east-1:111111111111:task-definition/f:3":    "arn:aws:ecs:us-east-1:111111111111:task-definition/f:3",
	} {
		if got := lambdaFunctionARN(in); got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
}

func TestActivityAttrsJSONBounded(t *testing.T) {
	attrs := map[string]any{"small": "x", "big": strings.Repeat("y", 20000)}
	raw, err := activityAttrsJSON(attrs)
	if err != nil || len(raw) > agentActivityMaxAttrBytes || !strings.Contains(raw, `"small"`) || strings.Contains(raw, `"big"`) {
		t.Fatalf("bounded attrs: %v %d", err, len(raw))
	}
}

func TestAgentOTLPTokenShape(t *testing.T) {
	tok, err := GenerateAgentOTLPToken()
	if err != nil || !wellFormedAgentOTLPToken(tok) || !strings.HasPrefix(tok, AgentOTLPTokenPrefix) {
		t.Fatalf("token %q: %v", tok, err)
	}
	for _, bad := range []string{"", "aot_short", "aev_" + tok[4:], tok + "x", "aot_" + strings.Repeat("!", 43)} {
		if wellFormedAgentOTLPToken(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	if len(HashAgentEventSecret(tok)) != 64 {
		t.Error("hash")
	}
}

func TestAgentActivityLabels(t *testing.T) {
	for _, l := range []string{"ai_workload", "suggested_agent", "agent", "possible_ai_workload"} {
		if !AgentActivityLabels[l] {
			t.Errorf("%s not labelled", l)
		}
	}
	if AgentActivityLabels[""] {
		t.Error("an unlabelled identity is recorded")
	}
}
