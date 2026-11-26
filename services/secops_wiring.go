package services

// SecOps cross-workstream wiring: the hooks each workstream left with a
// no-op or event-only default are installed here once all of them are on
// one branch (secops/batch1).
//
//   - W8 remediation asks (provider key create/revoke, pull request review)
//     become real asks (W4).
//   - W6 gateway holds raise an ask to the hold's deciders (W4). The hold is
//     still decided on its own route (POST gateway-holds/:id/decide); the
//     ask is how the decider hears of it.
//   - W8's retire step removes the agent's gateway keys and rules (W6).
//   - W3 cases pin their evidence in W1's store (pin_count), so retention
//     keeps it.
//   - W2's platform stop raises an ask (see recordContainment).

import (
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// InstallSecOpsWiring installs the cross-workstream hooks on db.
func InstallSecOpsWiring(db *gorm.DB) {
	SetRemediationAskCreator(secopsRemediationAsks{})
	SetGatewayHoldAsker(secopsGatewayHoldAsks{})
	SetRemediationGatewayRules(secopsGatewayRules{svc: AgentGatewayServiceFor(db)})
	SetAgentCaseEvidencePinner(secopsCaseEvidencePins{})
}

// secopsAskChoices turns plain choice labels into ask choices with stable ids.
func secopsAskChoices(labels []string) []AskChoice {
	out := make([]AskChoice, 0, len(labels))
	for _, l := range labels {
		id := strings.Trim(strings.Map(func(r rune) rune {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
				return r
			case r >= 'A' && r <= 'Z':
				return r + ('a' - 'A')
			}
			return '_'
		}, l), "_")
		if id == "" {
			id = "choice"
		}
		out = append(out, AskChoice{ID: id, Label: l})
	}
	return out
}

type secopsRemediationAsks struct{}

func (secopsRemediationAsks) CreateAsk(tx *gorm.DB, ws uuid.UUID, a RemediationAsk) (string, error) {
	in := AskInput{AboutKind: AskAboutRemediation, AboutID: a.RemediationID.String(), CaseID: a.CaseID,
		Question: a.Question, Choices: secopsAskChoices(a.Choices), Role: a.Role,
		DedupeKey: "remediation:" + a.RemediationID.String() + ":" + a.Reason,
		Context:   map[string]any{"reason": a.Reason, "link": a.Link}}
	if a.RequestedBy != uuid.Nil {
		req := a.RequestedBy
		in.RequesterUserID = &req
	}
	row, _, err := createAskTx(tx, ws, in, time.Now().UTC())
	if err != nil {
		return "", err
	}
	return row.ID.String(), nil
}

type secopsGatewayHoldAsks struct{}

func (secopsGatewayHoldAsks) AskForHold(tx *gorm.DB, ws uuid.UUID, h GatewayHoldAsk) error {
	deciders := append([]uuid.UUID(nil), h.Deciders...)
	if h.ApproverUserID != nil {
		deciders = append([]uuid.UUID{*h.ApproverUserID}, deciders...)
	}
	exp := h.ExpiresAt
	in := AskInput{AboutKind: AskAboutGatewayCall, AboutID: h.HoldID.String(), AgentID: h.AgentID,
		Question: "An agent's tool call is held by a gateway policy (its arguments are outside the policy's bounds). Approve or deny it on the hold before it expires.",
		Choices:  []AskChoice{{ID: "approve", Label: "Approve the call"}, {ID: "deny", Label: "Deny the call"}},
		Deciders: deciders, ExternalDeadline: &exp, ExternalDeadlineSource: "gateway_hold_expiry",
		DedupeKey: "gateway_hold:" + h.HoldID.String(),
		Context:   map[string]any{"hold_id": h.HoldID, "gateway_id": h.GatewayID, "run_id": h.RunID, "subject_id": h.SubjectID}}
	_, _, err := createAskTx(tx, ws, in, time.Now().UTC())
	return err
}

type secopsGatewayRules struct{ svc *AgentGatewayService }

func (g secopsGatewayRules) RemoveAgentRules(tx *gorm.DB, ws, agentID uuid.UUID) (int, bool, error) {
	ctx := tx.Statement.Context
	out, err := g.svc.RemoveGatewayRulesForAgent(ctx, ws, agentID.String())
	if err != nil {
		return 0, true, err
	}
	return int(out.AgentKeysRevoked + out.PoliciesDisabled), true, nil
}

type secopsCaseEvidencePins struct{}

func (secopsCaseEvidencePins) Pin(tx *gorm.DB, ws, _ uuid.UUID, refs []AgentCaseEvidenceRef) error {
	return secopsPinCaseEvidence(tx, ws, refs, 1)
}

func (secopsCaseEvidencePins) Unpin(tx *gorm.DB, ws, _ uuid.UUID, refs []AgentCaseEvidenceRef) error {
	return secopsPinCaseEvidence(tx, ws, refs, -1)
}

// secopsPinCaseEvidence moves the pin count of the evidence rows a case names by
// their event ids (a case pins CloudTrail events, the store keys them by
// provider and event id), inside the case's workspace transaction.
func secopsPinCaseEvidence(tx *gorm.DB, ws uuid.UUID, refs []AgentCaseEvidenceRef, delta int) error {
	ids := make([]string, 0, len(refs))
	for _, r := range refs {
		if r.EventID != "" {
			ids = append(ids, r.EventID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	// The evidence store may not be migrated yet (170): pins are best effort.
	if ok, _ := AgentEvidenceStatus(tx); !ok {
		return nil
	}
	return tx.Exec(`UPDATE agent_evidence_event SET pin_count = GREATEST(pin_count + ?, 0)
	                 WHERE workspace_id = ? AND event_id IN ?`, delta, ws, ids).Error
}
