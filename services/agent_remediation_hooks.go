package services

import (
	"context"
	"sync"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
)

// Seams of remediation (W8) that other workstreams fill in:
//
//   - RemediationAskCreator (W4 asks): where a remediation needs a person
//     -- code owners reviewing a pull request, a provider console step
//     AuthSec cannot do, a pull request closed unmerged -- it raises an
//     ask. Until W4 plugs its creator in, the default records the
//     governance event remediation.ask_needed with the question, so the
//     need is visible and auditable.
//   - RemediationGatewayRules (W6 gateway): retiring an agent removes its
//     gateway rules. The default removes nothing and says so in the step.
//   - ProviderKeyRotator: rotating a provider admin key AuthSec holds,
//     centrally, where the provider's API can create keys. None is
//     registered: the model provider clients are GET-only by design
//     (CLAUDE.md 2026-11-05), so the create step is an ask.

// RemediationAsk is one ask a remediation raises.
type RemediationAsk struct {
	RemediationID uuid.UUID  `json:"remediation_id"`
	CaseID        *uuid.UUID `json:"case_id,omitempty"`
	// Role is who should answer: code_owners, provider_admin, remediator.
	Role     string   `json:"role"`
	Question string   `json:"question"`
	Choices  []string `json:"choices"`
	// Link is where the answer is given (a pull request, a console).
	Link string `json:"link,omitempty"`
	// Reason names why the ask was raised (pr_review, pr_closed,
	// provider_key_create, provider_key_revoke_old).
	Reason      string    `json:"reason"`
	RequestedBy uuid.UUID `json:"requested_by"`
}

// RemediationAskCreator raises an ask inside the remediation's transaction
// (tx is under row-level security for ws) and returns its reference.
type RemediationAskCreator interface {
	CreateAsk(tx *gorm.DB, ws uuid.UUID, ask RemediationAsk) (string, error)
}

// eventAskCreator is the default: the governance event remediation.ask_needed.
type eventAskCreator struct{}

func (eventAskCreator) CreateAsk(tx *gorm.DB, ws uuid.UUID, ask RemediationAsk) (string, error) {
	payload := map[string]any{"remediation_id": ask.RemediationID, "role": ask.Role, "question": ask.Question,
		"choices": ask.Choices, "reason": ask.Reason}
	if ask.CaseID != nil {
		payload["case_id"] = *ask.CaseID
	}
	if ask.Link != "" {
		payload["link"] = ask.Link
	}
	if err := appendGovEvent(tx, ws, GovEventRemediationAskNeeded, models.GovActorSystem, "remediation", govEventRefs{}, payload); err != nil {
		return "", err
	}
	return "event:" + GovEventRemediationAskNeeded, nil
}

// RemediationGatewayRules removes an agent's gateway rules (W6) inside the
// retirement's transaction and reports how many it removed.
type RemediationGatewayRules interface {
	RemoveAgentRules(tx *gorm.DB, ws, agentID uuid.UUID) (removed int, supported bool, err error)
}

type noGatewayRules struct{}

func (noGatewayRules) RemoveAgentRules(*gorm.DB, uuid.UUID, uuid.UUID) (int, bool, error) {
	return 0, false, nil
}

// ProviderKeyRotator rotates a provider admin key AuthSec holds, centrally:
// it creates the new key at the provider, stores it where the connection
// keeps its key, and returns the new key's fingerprint. Never the key.
type ProviderKeyRotator interface {
	RotateAdminKey(ctx context.Context, ws, connectionID uuid.UUID) (fingerprint string, err error)
}

var remediationHooks = struct {
	sync.RWMutex
	asks     RemediationAskCreator
	gateway  RemediationGatewayRules
	rotators map[string]ProviderKeyRotator
}{asks: eventAskCreator{}, gateway: noGatewayRules{}, rotators: map[string]ProviderKeyRotator{}}

// SetRemediationAskCreator installs the ask creator (W4); nil restores the
// default (the remediation.ask_needed event). It returns the undo.
func SetRemediationAskCreator(c RemediationAskCreator) (restore func()) {
	remediationHooks.Lock()
	prev := remediationHooks.asks
	if c == nil {
		c = eventAskCreator{}
	}
	remediationHooks.asks = c
	remediationHooks.Unlock()
	return func() { SetRemediationAskCreator(prev) }
}

// SetRemediationGatewayRules installs the gateway rule remover (W6); nil
// restores the default (removes nothing). It returns the undo.
func SetRemediationGatewayRules(g RemediationGatewayRules) (restore func()) {
	remediationHooks.Lock()
	prev := remediationHooks.gateway
	if g == nil {
		g = noGatewayRules{}
	}
	remediationHooks.gateway = g
	remediationHooks.Unlock()
	return func() { SetRemediationGatewayRules(prev) }
}

// SetProviderKeyRotator registers the central rotator of one provider
// (openai, anthropic); nil removes it. It returns the undo.
func SetProviderKeyRotator(provider string, r ProviderKeyRotator) (restore func()) {
	remediationHooks.Lock()
	prev := remediationHooks.rotators[provider]
	if r == nil {
		delete(remediationHooks.rotators, provider)
	} else {
		remediationHooks.rotators[provider] = r
	}
	remediationHooks.Unlock()
	return func() { SetProviderKeyRotator(provider, prev) }
}

func remediationAsks() RemediationAskCreator {
	remediationHooks.RLock()
	defer remediationHooks.RUnlock()
	return remediationHooks.asks
}

func remediationGateway() RemediationGatewayRules {
	remediationHooks.RLock()
	defer remediationHooks.RUnlock()
	return remediationHooks.gateway
}

func providerKeyRotator(provider string) ProviderKeyRotator {
	remediationHooks.RLock()
	defer remediationHooks.RUnlock()
	return remediationHooks.rotators[provider]
}
