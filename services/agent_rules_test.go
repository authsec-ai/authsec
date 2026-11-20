package services

import (
	"testing"
	"time"
)

// The examples are the feature-rules document's ("6 Features for AI Agent
// Detection").

var ruleT0 = time.Date(2026, 3, 15, 14, 23, 40, 0, time.UTC)

// seq builds events one second apart inside one window, starting at offset
// seconds. "bedrock" names are AI calls; "lambda:Invoke" style names keep
// their event name.
func seq(offset int, calls ...string) []ruleEvent {
	var out []ruleEvent
	for i, c := range calls {
		svc, name := c, "Call"
		for j := 0; j < len(c); j++ {
			if c[j] == ':' {
				svc, name = c[:j], c[j+1:]
			}
		}
		e := ruleEvent{At: ruleT0.Add(time.Duration(offset+i) * time.Second), Service: svc, Name: name}
		if svc == "bedrock" {
			e.AI, e.Name = true, "InvokeModel"
			if name != "Call" {
				e.ModelID = name
			}
		}
		out = append(out, e)
	}
	return out
}

// windowsOf joins sequences one minute apart, so each is its own window.
func windowsOf(seqs ...[]string) []ruleEvent {
	var out []ruleEvent
	for i, s := range seqs {
		out = append(out, seq(i*60, s...)...)
	}
	return out
}

func TestBurstRatioDataEnricher(t *testing.T) {
	// 2+3+2+1+1+2 = 11 AI calls in 6 windows.
	counts := []int{2, 3, 2, 1, 1, 2}
	var seqs [][]string
	for _, n := range counts {
		var s []string
		for i := 0; i < n; i++ {
			s = append(s, "bedrock")
		}
		seqs = append(seqs, s)
	}
	f := computeAgentRuleFeatures(windowsOf(seqs...))
	if f.BurstRatio != 1.83 || f.AICalls != 11 || f.Windows != 6 {
		t.Fatalf("burst_ratio = %v (%d calls / %d windows), want 1.83 (11/6)", f.BurstRatio, f.AICalls, f.Windows)
	}
}

func TestFanOutCountsServicesAfterAICalls(t *testing.T) {
	f := computeAgentRuleFeatures(windowsOf(
		[]string{"bedrock", "dynamodb:GetItem", "s3:PutObject"},
		[]string{"bedrock", "dynamodb:PutItem", "sns:Publish"},
		[]string{"bedrock", "lambda:Invoke"},
	))
	if f.FanOut != 4 {
		t.Fatalf("fan_out = %d, want 4 (DynamoDB, S3, SNS, Lambda)", f.FanOut)
	}
	// A service called only BEFORE the AI call is not fan-out.
	if f := computeAgentRuleFeatures(windowsOf([]string{"dynamodb:GetItem", "bedrock"})); f.FanOut != 0 {
		t.Errorf("fan_out = %d, want 0 for a read before the model call", f.FanOut)
	}
}

func TestModelDiversity(t *testing.T) {
	one := computeAgentRuleFeatures(windowsOf([]string{"bedrock:claude-3-sonnet"}, []string{"bedrock:claude-3-sonnet"}))
	three := computeAgentRuleFeatures(windowsOf(
		[]string{"bedrock:claude-3-sonnet"}, []string{"bedrock:claude-3-haiku"}, []string{"bedrock:titan-embed-text"}))
	if one.ModelDiversity != 1 || three.ModelDiversity != 3 {
		t.Fatalf("model_diversity = %d and %d, want 1 and 3", one.ModelDiversity, three.ModelDiversity)
	}
}

func TestLoopsDetected(t *testing.T) {
	loop := computeAgentRuleFeatures(windowsOf(
		[]string{"dynamodb:GetItem", "bedrock", "dynamodb:GetItem", "bedrock", "s3:PutObject"}))
	if !loop.LoopsDetected || loop.LoopWindows != 1 {
		t.Fatalf("loops_detected = %v, want true for AI -> DynamoDB -> AI", loop.LoopsDetected)
	}
	once := computeAgentRuleFeatures(windowsOf([]string{"bedrock", "s3:PutObject"}))
	if once.LoopsDetected {
		t.Fatal("a single model call is not a loop")
	}
}

func TestSequenceOrdering(t *testing.T) {
	// 4 of 6 windows DB first: 67%, under 80% -> mixed.
	mixed := computeAgentRuleFeatures(windowsOf(
		[]string{"dynamodb:GetItem", "bedrock"}, []string{"dynamodb:GetItem", "bedrock"},
		[]string{"bedrock", "lambda:Invoke"}, []string{"dynamodb:GetItem", "bedrock"},
		[]string{"bedrock", "dynamodb:PutItem"}, []string{"dynamodb:GetItem", "bedrock"}))
	if mixed.SequenceOrdering != OrderingMixed {
		t.Errorf("ordering = %s, want mixed", mixed.SequenceOrdering)
	}
	rag := computeAgentRuleFeatures(windowsOf([]string{"dynamodb:GetItem", "bedrock"}, []string{"dynamodb:GetItem", "bedrock"}))
	if rag.SequenceOrdering != OrderingDBBeforeModel {
		t.Errorf("ordering = %s, want db_before_model", rag.SequenceOrdering)
	}
	agent := computeAgentRuleFeatures(windowsOf([]string{"bedrock", "dynamodb:GetItem"}, []string{"bedrock", "s3:PutObject"}))
	if agent.SequenceOrdering != OrderingModelBeforeDB {
		t.Errorf("ordering = %s, want model_before_db", agent.SequenceOrdering)
	}
}

func TestCrossWorkloadTriggers(t *testing.T) {
	yes := computeAgentRuleFeatures(windowsOf([]string{"bedrock", "lambda:Invoke", "bedrock"}))
	no := computeAgentRuleFeatures(windowsOf([]string{"lambda:Invoke", "bedrock", "s3:PutObject"}))
	if !yes.CrossWorkloadTriggers || no.CrossWorkloadTriggers {
		t.Fatalf("cross_workload_triggers = %v / %v, want true only for an Invoke AFTER the model call",
			yes.CrossWorkloadTriggers, no.CrossWorkloadTriggers)
	}
}

func TestWindowsSplitOnGapAndDropWindowsWithoutAI(t *testing.T) {
	events := append(seq(0, "bedrock", "s3:PutObject"), seq(3600, "s3:GetObject", "s3:GetObject")...)
	if w := ruleWindows(events); len(w) != 1 {
		t.Fatalf("got %d windows, want 1: an hour apart splits, and a window without AI is dropped", len(w))
	}
}

func TestRulesDocumentExamples(t *testing.T) {
	cases := []struct {
		name   string
		events []ruleEvent
		label  string
		reason string
	}{
		{"translate-text (Rule 1)", windowsOf([]string{"bedrock"}), AgentLabelNonAI, ""},
		{"summarizer saves to S3 (Rule 1)", windowsOf([]string{"bedrock", "s3:PutObject"}), AgentLabelNonAI, ""},
		{"customer-support-bot RAG (Rule 2)", windowsOf(
			[]string{"dynamodb:GetItem", "bedrock", "dynamodb:PutItem"},
			[]string{"dynamodb:GetItem", "bedrock", "s3:PutObject"}), AgentLabelSuspected, ""},
		{"data-enricher (Rule 3)", windowsOf([]string{"bedrock", "dynamodb:GetItem", "bedrock", "s3:PutObject",
			"bedrock", "sns:Publish", "dynamodb:PutItem"}), AgentLabelConfirmed, ""},
		{"task-orchestrator (Rule 4)", windowsOf([]string{"bedrock", "lambda:Invoke", "bedrock", "lambda:Invoke", "bedrock"}),
			AgentLabelConfirmed, ""},
		{"simple-looper: loop, one service", windowsOf([]string{"bedrock", "dynamodb:PutItem", "bedrock", "dynamodb:PutItem"}),
			"", AgentReviewReasonBorderline},
		{"complex-pipeline: fan_out 3, no loop", windowsOf([]string{"bedrock", "dynamodb:PutItem", "s3:PutObject", "sns:Publish"}),
			"", AgentReviewReasonBorderline},
		{"loop in 1 of 6 windows", windowsOf(
			[]string{"bedrock", "dynamodb:GetItem", "bedrock", "s3:PutObject", "sns:Publish"},
			[]string{"bedrock"}, []string{"bedrock"}, []string{"bedrock"}, []string{"bedrock"}, []string{"bedrock"}),
			"", AgentReviewReasonIntermittent},
	}
	for _, c := range cases {
		d := decideAgentRules(computeAgentRuleFeatures(c.events), false)
		if d.Label != c.label || d.Reason != c.reason {
			t.Errorf("%s: got label %q reason %q, want label %q reason %q", c.name, d.Label, d.Reason, c.label, c.reason)
		}
	}
}

func TestRulesContradictingEvidence(t *testing.T) {
	// DNS shows a model provider, CloudTrail no model call at all.
	if d := decideAgentRules(AgentRuleFeatures{}, true); d.Reason != AgentReviewReasonContradicting {
		t.Fatalf("got %+v, want contradicting_evidence", d)
	}
	// With model calls the network traffic agrees; the rules decide.
	f := computeAgentRuleFeatures(windowsOf([]string{"bedrock"}))
	if d := decideAgentRules(f, true); d.Label != AgentLabelNonAI {
		t.Fatalf("got %+v, want Rule 1", d)
	}
}
