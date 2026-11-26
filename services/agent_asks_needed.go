package services

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// W7's agent.ask_needed events become real asks (W4). The event is still
// written (it is the governance record of why); the ask carries the
// question, its choices, the deciders and the due time. One open ask per
// (agent, reason[, subject]) through its dedupe key.

// askNeededSpec is the ask an agent.ask_needed reason raises.
func askNeededSpec(reason string, subject map[string]any) (question string, choices []AskChoice, severity, key string) {
	switch reason {
	case AskReasonDeletedAtSource:
		return "Every source of this agent reports it gone. Retire it, say where it went, or keep it if it will come back.",
			[]AskChoice{{ID: "retire", Label: "Retire it"}, {ID: "transferred", Label: "It moved elsewhere"},
				{ID: "keep", Label: "Keep it: it will come back"}}, "low", ""
	case AskReasonDeciderLeft:
		who := fmt.Sprint(subject["user_id"])
		return "The only person who decided for this agent left the organisation. Who decides for it now?",
			[]AskChoice{{ID: "assign_group", Label: "Assign another responder group"}, {ID: "retire", Label: "Retire the agent"}},
			"medium", ":" + who
	case AskReasonUnknownDeployer:
		dep := fmt.Sprint(subject["deployer"])
		sum := sha256.Sum256([]byte(dep))
		return fmt.Sprintf("A new instance of this agent was deployed by %q, who is not among its recorded deployers. Is this expected?", clipText(dep, 300)),
			[]AskChoice{{ID: "expected", Label: "Expected: record the deployer"}, {ID: "investigate", Label: "Not expected: investigate"}},
			"high", ":" + hex.EncodeToString(sum[:8])
	}
	return "A person must decide about this agent.", []AskChoice{{ID: "acknowledge", Label: "Acknowledge"}, {ID: "investigate", Label: "Investigate"}},
		"medium", ""
}

// raiseAgentAskNeeded raises the ask of an agent.ask_needed event in tx (a
// savepoint; a failure is logged and never fails the writer).
func raiseAgentAskNeeded(tx *gorm.DB, ws, agentID uuid.UUID, reason string, subject map[string]any, exclude ...uuid.UUID) {
	q, choices, sev, key := askNeededSpec(reason, subject)
	a := agentID
	ctx := map[string]any{"reason": reason, "event": GovEventAgentAskNeeded}
	if subject != nil {
		ctx["subject"] = subject
	}
	raiseSystemAskTx(tx, ws, AskInput{AboutKind: AskAboutAgent, AboutID: agentID.String(), AgentID: &a, Question: q,
		Choices: choices, Severity: sev, ExcludeUserIDs: exclude, Context: ctx,
		DedupeKey: "agent:" + agentID.String() + ":" + reason + key})
}
