package services

import (
	"math"
	"sort"
	"strings"
	"time"
)

/* agent_rules_features.go is the six features of the AI agent rules engine
   (agent_rules_engine.go): how a workload uses AI, computed from its own
   CloudTrail events in agent_activity_event, ordered by time.

   Events are cut into windows (a gap over ruleWindowGap or a span over
   ruleWindowMax closes one); only windows with an AI call count. Over them:

     burst_ratio             AI calls per window (11 calls in 6 windows: 1.83)
     fan_out                 distinct non-AI services called after an AI call
     model_diversity         distinct model ids
     loops_detected          AI -> non-AI -> AI, as consecutive events, in a window
     sequence_ordering       db_before_model / model_before_db when one comes
                             first in over 80% of windows, else mixed
     cross_workload_triggers Invoke, RunTask or StartExecution after an AI call

   The same formulas as the review service's analysis/features.py, so a
   workload reads the same in AuthSec and in an investigation. */

const (
	ruleWindowGap      = 5 * time.Second
	ruleWindowMax      = 30 * time.Second
	ruleOrderDominance = 0.8
)

// Sequence orderings.
const (
	OrderingDBBeforeModel = "db_before_model"
	OrderingModelBeforeDB = "model_before_db"
	OrderingMixed         = "mixed"
)

// ruleTriggerEvents start another workload (Lambda, ECS, Step Functions).
var ruleTriggerEvents = map[string]bool{"Invoke": true, "RunTask": true, "StartExecution": true}

// ruleEvent is one CloudTrail event of a workload, as the features read it.
type ruleEvent struct {
	At      time.Time
	Service string // "dynamodb", from the event source without .amazonaws.com
	Name    string // "GetItem"
	AI      bool   // a model invocation (Bedrock, SageMaker endpoint)
	ModelID string
}

// AgentRuleFeatures are the six features, plus the counts behind them.
type AgentRuleFeatures struct {
	BurstRatio            float64 `json:"burst_ratio"`
	FanOut                int     `json:"fan_out"`
	ModelDiversity        int     `json:"model_diversity"`
	LoopsDetected         bool    `json:"loops_detected"`
	SequenceOrdering      string  `json:"sequence_ordering"`
	CrossWorkloadTriggers bool    `json:"cross_workload_triggers"`
	AICalls               int     `json:"ai_calls"`
	Windows               int     `json:"windows"`
	LoopWindows           int     `json:"loop_windows"`
}

// ruleWindows splits time-ordered events into windows and keeps those with an
// AI call: a window without one says nothing about how the workload uses AI.
func ruleWindows(events []ruleEvent) [][]ruleEvent {
	sorted := append([]ruleEvent(nil), events...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].At.Before(sorted[j].At) })
	var all [][]ruleEvent
	var cur []ruleEvent
	for _, e := range sorted {
		if len(cur) > 0 && (e.At.Sub(cur[len(cur)-1].At) > ruleWindowGap || e.At.Sub(cur[0].At) > ruleWindowMax) {
			all = append(all, cur)
			cur = nil
		}
		cur = append(cur, e)
	}
	if len(cur) > 0 {
		all = append(all, cur)
	}
	var out [][]ruleEvent
	for _, w := range all {
		for _, e := range w {
			if e.AI {
				out = append(out, w)
				break
			}
		}
	}
	return out
}

func windowHasLoop(w []ruleEvent) bool {
	for i := 0; i+2 < len(w); i++ {
		if w[i].AI && !w[i+1].AI && w[i+2].AI {
			return true
		}
	}
	return false
}

// computeAgentRuleFeatures is the six features of a workload's events.
func computeAgentRuleFeatures(events []ruleEvent) AgentRuleFeatures {
	windows := ruleWindows(events)
	f := AgentRuleFeatures{Windows: len(windows), SequenceOrdering: OrderingMixed}
	if len(windows) == 0 {
		return f
	}
	services := map[string]bool{}
	models := map[string]bool{}
	modelFirst := 0
	for _, w := range windows {
		if w[0].AI {
			modelFirst++
		}
		if windowHasLoop(w) {
			f.LoopWindows++
		}
		seenAI := false
		for _, e := range w {
			if e.AI {
				seenAI = true
				f.AICalls++
				if e.ModelID != "" {
					models[e.ModelID] = true
				}
				continue
			}
			if seenAI {
				services[e.Service] = true
				if ruleTriggerEvents[e.Name] {
					f.CrossWorkloadTriggers = true
				}
			}
		}
	}
	n := float64(len(windows))
	f.BurstRatio = math.Round(float64(f.AICalls)/n*100) / 100
	f.FanOut = len(services)
	f.ModelDiversity = len(models)
	f.LoopsDetected = f.LoopWindows > 0
	switch {
	case float64(len(windows)-modelFirst)/n > ruleOrderDominance:
		f.SequenceOrdering = OrderingDBBeforeModel
	case float64(modelFirst)/n > ruleOrderDominance:
		f.SequenceOrdering = OrderingModelBeforeDB
	}
	return f
}

// ruleServiceOf is the service of an event source: "dynamodb.amazonaws.com"
// -> "dynamodb".
func ruleServiceOf(eventSource string) string {
	return strings.TrimSuffix(eventSource, ".amazonaws.com")
}

// sageMakerInvocations are the SageMaker endpoint calls that are model
// invocations (agentruntime's IsModelCall covers Bedrock only).
var sageMakerInvocations = map[string]bool{
	"InvokeEndpoint": true, "InvokeEndpointAsync": true, "InvokeEndpointWithResponseStream": true,
}

func isSageMakerInvocation(eventSource, name string) bool {
	return (eventSource == "sagemaker.amazonaws.com" || eventSource == "runtime.sagemaker.amazonaws.com") &&
		sageMakerInvocations[name]
}
