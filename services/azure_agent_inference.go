package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

/* azure_agent_inference.go proposes AI agents among a tenant's workload
   identities (PRD A3, "Inferred").

   Azure has no list-agents API: an agent there is a service principal or a
   managed identity that exists AND gets used. Discovery already holds the
   per-identity evidence -- sign-ins aggregated per resource (cloud_usage),
   API permissions, federated credentials, the compute an identity runs on --
   so inference is a rule over those aggregates, never over raw events.

   An identity that meets the rule becomes a discovered_agents row with
   evidence_mode 'inferred' (the lowest trust) and status 'unregistered': a
   proposal for a human, who confirms (claims), ignores or quarantines it
   through the existing discovery endpoints. UpsertSighting never moves a
   human's decision, so a re-run refreshes the evidence and nothing else.

   The rule, each half explainable on its own:
     - it obtained tokens for an Azure AI service (Azure OpenAI, Cognitive
       Services) -- the PRD's strongest Azure agent signal; or
     - it signs in as itself (app-only) AND does something an agent does:
       holds application permissions to tenant data, is federated to a
       pipeline or a Kubernetes service account, or runs on compute.
   Microsoft's own first-party service principals are never proposed.

   Agents Microsoft Entra Agent ID declares are not inferred: they have their
   own kind (entra_agent_identity), outside the kinds read here, and are
   registered as declared by azure_agent_discovery.go. */

const (
	// azureAgentFingerprintPrefix namespaces Azure agents in discovered_agents
	// (unique on workspace, source, fingerprint).
	azureAgentFingerprintPrefix = "entra:"
	// azureAgentActiveWindow is how recent a sign-in must be to count as the
	// identity running now.
	azureAgentActiveWindow = 7 * 24 * time.Hour
)

// azureAgentEvidence is what one candidate identity was seen doing.
type azureAgentEvidence struct {
	identity        models.CloudIdentity
	aiServices      map[string]bool
	resources       map[string]bool
	appOnlySignIns  int
	delegatedSignIn bool
	lastSignIn      *time.Time
	appPermissions  []string
	delegatedGrants int
	federation      map[string]bool
	workloads       []string
	// cadence is the most machine-like sign-in pattern seen for the identity.
	cadence *azureCadence
}

// inferAgents evaluates every non-Microsoft service principal and managed
// identity of the tenant and proposes the ones the rule matches. Returns how
// many were proposed.
func (s *AzureOnboardingService) inferAgents(workspaceID, tenantConnectorID uuid.UUID, tenantID string) (int, error) {
	var identities []models.CloudIdentity
	if err := tenancy.InWorkspaceRead(context.Background(), s.db, workspaceID, func(tx *gorm.DB) error {
		return tx.Where("workspace_id = ? AND connector_id = ? AND kind IN ?",
			workspaceID, tenantConnectorID,
			[]string{models.CloudIdentityEntraServicePrincipal, models.CloudIdentityEntraManagedIdentity}).
			Find(&identities).Error
	}); err != nil {
		return 0, err
	}
	// The app this tenant is read with: AuthSec's own, or the customer's own
	// app when the tenant was connected with one (ConnectCustom).
	scanner := map[string]bool{}
	if s.cfg.ClientID != "" {
		scanner[strings.ToLower(s.cfg.ClientID)] = true
	}
	if tc, err := s.connectors.Get(workspaceID, tenantConnectorID); err == nil && tc != nil {
		if a := tc.AzureTenantAttrs(); a.AppID != "" {
			scanner[strings.ToLower(a.AppID)] = true
		}
	}
	declared := s.registryAppIDs(workspaceID, tenantConnectorID)
	botIdentities := map[uuid.UUID]bool{}
	// Identities an Azure Bot Service bot or a Logic Apps agent workflow runs
	// as: those agents are declared, by the resource that runs them.
	runners, err := s.tenantWorkloads(workspaceID, tenantID, []string{azureBotRuntimeKind, azureLogicRuntimeKind})
	if err != nil {
		return 0, err
	}
	var botNative []string
	for _, b := range runners {
		if b.IdentityNativeID == "" {
			continue
		}
		if b.RuntimeKind == azureLogicRuntimeKind && !strings.Contains(string(b.Attrs), `"agent_workflow"`) {
			continue
		}
		botNative = append(botNative, b.IdentityNativeID)
	}
	// The bots of Teams apps are declared by the Teams app catalog.
	for _, e := range s.tenantTeamsAgents(workspaceID, tenantConnectorID) {
		if id, _ := e["bot_app_id"].(string); id != "" {
			declared[strings.ToLower(id)] = true
		}
	}
	if len(botNative) > 0 {
		ids, err := s.inventory.IdentityIDs(workspaceID, botNative)
		if err != nil {
			return 0, err
		}
		for _, id := range ids {
			botIdentities[id] = true
		}
	}
	ev := map[uuid.UUID]*azureAgentEvidence{}
	for _, i := range identities {
		var attrs struct {
			AppID               string     `json:"app_id"`
			MicrosoftFirstParty bool       `json:"microsoft_first_party"`
			LastDelegated       *time.Time `json:"last_delegated_sign_in_at"`
			AgentType           string     `json:"agent_type"`
		}
		_ = json.Unmarshal(i.Attrs, &attrs)
		// A blueprint's service principal is part of declared agents, which
		// registerDeclaredAgents records; guessing at it adds nothing.
		if attrs.AgentType != "" {
			continue
		}
		// The scanner's service principal reads this tenant: automated, signing
		// in as itself, holding directory read -- it would match the rule on
		// every run, and it is not the customer's agent.
		if attrs.MicrosoftFirstParty || scanner[strings.ToLower(attrs.AppID)] {
			continue
		}
		// An agent the Microsoft 365 agent registry lists, or an identity an
		// Azure Bot Service bot runs as, is declared (registerDeclaredAgents).
		if declared[strings.ToLower(attrs.AppID)] || botIdentities[i.ID] {
			continue
		}
		ev[i.ID] = &azureAgentEvidence{
			identity: i, aiServices: map[string]bool{}, resources: map[string]bool{},
			federation: map[string]bool{}, lastSignIn: i.LastUsedAt, delegatedSignIn: attrs.LastDelegated != nil,
		}
	}
	if len(ev) == 0 {
		return 0, nil
	}
	ids := make([]uuid.UUID, 0, len(ev))
	for id := range ev {
		ids = append(ids, id)
	}

	// The evidence, then the proposals, in one transaction under row-level
	// security for the workspace: every proposal, or (on an error) none.
	proposed := 0
	err = tenancy.InWorkspace(context.Background(), s.db, workspaceID, func(tx *gorm.DB) error {
		proposed = 0
		// Sign-ins, per resource.
		var usage []models.CloudUsage
		if err := tx.Where("workspace_id = ? AND identity_id IN ? AND source = ?",
			workspaceID, ids, models.UsageSourceEntraSignIn).Find(&usage).Error; err != nil {
			return err
		}
		for _, u := range usage {
			e := ev[u.IdentityID]
			var a struct {
				SignIns   int           `json:"sign_ins"`
				AIService bool          `json:"ai_service"`
				Cadence   *azureCadence `json:"cadence"`
			}
			_ = json.Unmarshal(u.Attrs, &a)
			if a.SignIns == 0 {
				continue
			}
			e.appOnlySignIns += a.SignIns
			e.resources[u.Service] = true
			if a.AIService {
				e.aiServices[u.Service] = true
			}
			if a.Cadence != nil && a.Cadence.machineLike() &&
				(e.cadence == nil || a.Cadence.HoursActive > e.cadence.HoursActive) {
				c := *a.Cadence
				e.cadence = &c
			}
			if u.LastUsedAt != nil && (e.lastSignIn == nil || u.LastUsedAt.After(*e.lastSignIn)) {
				e.lastSignIn = u.LastUsedAt
			}
		}

		// API permissions: application permissions by name, delegated by count.
		var grants []struct {
			IdentityID uuid.UUID
			Kind       string
			Action     string
		}
		if err := tx.Table("cloud_permission p").
			Select("p.identity_id, r.kind, p.actions[1] AS action").
			Joins("JOIN cloud_resource r ON r.id = p.resource_id").
			Where("p.workspace_id = ? AND p.identity_id IN ? AND r.kind IN ?", workspaceID, ids,
				[]string{models.CloudResourceEntraAppRole, models.CloudResourceEntraDelegatedScope}).
			Scan(&grants).Error; err != nil {
			return err
		}
		for _, g := range grants {
			e := ev[g.IdentityID]
			if g.Kind == models.CloudResourceEntraDelegatedScope {
				e.delegatedGrants++
			} else if g.Action != "" && g.Action != "default_access" {
				e.appPermissions = append(e.appPermissions, g.Action)
			}
		}

		// Who may become it from outside, and what compute runs as it. Only a
		// federated credential is how a workload signs in as an identity; an
		// owner (who could add a credential) says nothing about how it is used.
		var edges []struct {
			IdentityID  uuid.UUID
			SubjectKind string
		}
		if err := tx.Table("cloud_assume_edge").Select("identity_id, subject_kind").
			Where("workspace_id = ? AND identity_id IN ? AND mechanism = ?", workspaceID, ids,
				models.AssumeMechanismOIDCFederation).Scan(&edges).Error; err != nil {
			return err
		}
		for _, e := range edges {
			ev[e.IdentityID].federation[e.SubjectKind] = true
		}
		var workloads []struct {
			IdentityID  uuid.UUID
			RuntimeKind string
		}
		if err := tx.Table("cloud_workload").Select("identity_id, runtime_kind").
			Where("workspace_id = ? AND identity_id IN ?", workspaceID, ids).Scan(&workloads).Error; err != nil {
			return err
		}
		for _, w := range workloads {
			ev[w.IdentityID].workloads = append(ev[w.IdentityID].workloads, w.RuntimeKind)
		}

		repo := repositories.NewDiscoveryRepository(tx)
		now := time.Now()
		for _, e := range ev {
			signals, confidence := azureAgentSignals(e, now)
			if confidence == "" {
				continue
			}
			agent := azureAgentSighting(workspaceID, tenantID, e, signals, confidence, now)
			if _, _, err := repo.UpsertSighting(agent); err != nil {
				return fmt.Errorf("propose %s: %w", e.identity.NativeID, err)
			}
			proposed++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return proposed, nil
}

// azureAgentSignals applies the rule. confidence is "" when the identity is
// not proposed, "high" for an AI-service caller that also acts on its own,
// "medium" otherwise.
func azureAgentSignals(e *azureAgentEvidence, now time.Time) ([]string, string) {
	var signals []string
	ai := len(e.aiServices) > 0
	if ai {
		signals = append(signals, "obtained tokens for an Azure AI service: "+strings.Join(sortedKeys(e.aiServices), ", "))
	}
	active := e.appOnlySignIns > 0 || (e.lastSignIn != nil && now.Sub(*e.lastSignIn) <= azureAgentActiveWindow)
	if e.appOnlySignIns > 0 {
		signals = append(signals, fmt.Sprintf("signed in as itself %d times in the last week (to %s)",
			e.appOnlySignIns, strings.Join(sortedKeys(e.resources), ", ")))
	}
	if active && !e.delegatedSignIn {
		signals = append(signals, "no sign-in on behalf of a user: machine-only")
	}
	actsLikeAgent := false
	if c := e.cadence; c != nil {
		// A schedule or round-the-clock activity is how a workload signs in,
		// not a person (PRD A3, "machine cadence").
		if c.Pattern == CadenceRegular {
			signals = append(signals, fmt.Sprintf("signs in on a schedule, about every %s", humanGap(c.MedianGapSeconds)))
		}
		if c.AroundTheClock {
			signals = append(signals, fmt.Sprintf("active around the clock (%d of 24 hours)", c.HoursActive))
		}
		actsLikeAgent = true
	}
	if len(e.appPermissions) > 0 {
		perms := append([]string(nil), e.appPermissions...)
		sort.Strings(perms)
		signals = append(signals, "holds application permissions: "+strings.Join(perms, ", "))
		actsLikeAgent = true
	}
	if len(e.federation) > 0 {
		var from []string
		for _, k := range sortedKeys(e.federation) {
			from = append(from, azureFederationSubjectWords(k))
		}
		signals = append(signals, "a federated credential lets "+strings.Join(from, ", ")+" sign in as it")
		actsLikeAgent = true
	}
	if len(e.workloads) > 0 {
		signals = append(signals, "runs on "+strings.Join(e.workloads, ", "))
		actsLikeAgent = true
	}
	switch {
	case ai && active:
		return signals, "high"
	case ai, active && actsLikeAgent:
		return signals, "medium"
	}
	return nil, ""
}

// azureFederationSubjectWords says who a federated credential lets sign in.
func azureFederationSubjectWords(kind string) string {
	switch kind {
	case models.AssumeSubjectK8sSA:
		return "a Kubernetes service account"
	case models.AssumeSubjectCIPipeline:
		return "a CI/CD pipeline"
	case models.AssumeSubjectIdentity:
		return "another Microsoft Entra identity"
	case models.AssumeSubjectExternal:
		return "an external identity provider"
	}
	return kind
}

// humanGap renders a gap between sign-ins: "45s", "12 min", "2 h".
func humanGap(seconds int) string {
	switch {
	case seconds < 120:
		return fmt.Sprintf("%ds", seconds)
	case seconds < 2*3600:
		return fmt.Sprintf("%d min", seconds/60)
	}
	return fmt.Sprintf("%d h", seconds/3600)
}

// azureAgentArchetype: autonomous when it acts as itself, user_delegated when
// it only ever acts for a signed-in user, hybrid when both.
func azureAgentArchetype(e *azureAgentEvidence) string {
	self := e.appOnlySignIns > 0 || len(e.appPermissions) > 0
	user := e.delegatedSignIn || e.delegatedGrants > 0
	switch {
	case self && user:
		return "hybrid"
	case user:
		return "user_delegated"
	case self:
		return "autonomous"
	}
	return ""
}

func azureAgentSighting(workspaceID uuid.UUID, tenantID string, e *azureAgentEvidence, signals []string, confidence string, now time.Time) *models.DiscoveredAgent {
	var attrs struct {
		AppID string `json:"app_id"`
	}
	_ = json.Unmarshal(e.identity.Attrs, &attrs)
	meta, _ := json.Marshal(map[string]interface{}{
		"provider":       "azure",
		"tenant_id":      strings.ToLower(tenantID),
		"object_id":      e.identity.NativeID,
		"app_id":         attrs.AppID,
		"identity_kind":  e.identity.Kind,
		"inference_rule": "azure_agent_v1",
		"confidence":     confidence,
		"signals":        signals,
		"last_sign_in":   e.lastSignIn,
	})
	runtime, reason := models.RuntimeStatusUnknown, ""
	var running *time.Time
	if e.lastSignIn != nil && now.Sub(*e.lastSignIn) <= azureAgentActiveWindow {
		// A sign-in is the identity obtaining a token: evidence it ran, and when.
		runtime, running = models.RuntimeStatusRunning, e.lastSignIn
		reason = "signed in to Entra at " + e.lastSignIn.UTC().Format(time.RFC3339)
	}
	return &models.DiscoveredAgent{
		ID: uuid.New(), WorkspaceID: workspaceID, Source: models.DiscoverySourceAzure,
		Fingerprint:      azureAgentFingerprintPrefix + strings.ToLower(tenantID) + ":" + e.identity.NativeID,
		DisplayName:      e.identity.Name,
		Metadata:         meta,
		DeploymentOrigin: models.DeploymentOriginUnknown,
		EvidenceMode:     models.EvidenceInferred,
		// No LastObservedRunningAt: an Azure agent is upgraded in place to
		// declared when Microsoft lists it, and a declared row may not carry
		// one (database constraint). The sign-in is its runtime status and
		// reason instead, as on a declared row.
		Archetype:         azureAgentArchetype(e),
		Status:            models.DiscoveredAgentUnregistered,
		RuntimeStatus:     runtime,
		RuntimeReason:     reason,
		RuntimeObservedAt: azureObservedAt(running, now),
		FirstSeenAt:       now,
		LastSeenAt:        now,
		SightingCount:     1,
		CreatedBy:         "azure-discovery",
	}
}

// logInferAgents runs inference after a tenant pass and logs the outcome.
// Inference reads only what discovery already stored, so a failure here
// changes nothing that was discovered.
func (s *AzureOnboardingService) logInferAgents(workspaceID, tenantConnectorID uuid.UUID, tenantID string) bool {
	n, err := s.inferAgents(workspaceID, tenantConnectorID, tenantID)
	if err != nil {
		log.Printf("[azure] agent inference for tenant %s failed: %v", tenantID, err)
		return false
	}
	log.Printf("[azure] agent inference for tenant %s: %d identities proposed as agents", tenantID, n)
	return true
}
