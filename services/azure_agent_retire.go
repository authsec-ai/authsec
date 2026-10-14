package services

import (
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
)

/* azure_agent_retire.go closes the Azure agents a tenant pass no longer saw.

   Registration and inference only ever add or refresh discovered agents, so an
   agent deleted in Microsoft Entra, or one the inference rule no longer
   matches, would otherwise stay listed as it was last seen. After the agent
   steps of a tenant pass, every Azure agent of that tenant they did not
   refresh is closed:

     declared by Microsoft Entra Agent ID   gone, when the agent identity
                                            listing was read completely
     declared by the agent registry         gone, when the registry was read
                                            completely
     inferred                               gone, when the service principal
                                            listing was read completely and
                                            the identity is no longer there;
                                            otherwise its runtime is unknown,
                                            since the rule no longer matches

   A listing that was not read completely proves nothing about what is missing
   from it, so its agents are left as they are (the reconciliation rule
   ScanCoverage.Complete states for the whole scan). Each change is a lifecycle
   event, so the agent's trail says when and why it was closed; a human's
   decision on the agent (status) is never changed. An agent seen again by a
   later pass is refreshed by its sighting as usual. */

// azureObservedAt is when a pass observed an agent's runtime: the pass itself.
// A sighting always carries it, so an agent closed by an earlier pass is
// refreshed when it is seen again (UpsertSighting applies only a runtime
// observation at least as recent as the stored one).
func azureObservedAt(_ *time.Time, now time.Time) *time.Time {
	t := now
	return &t
}

// azureAgentEvidenceSource values, as the sightings record them in metadata.
const (
	azureEvidenceAgentID  = "entra_agent_id"
	azureEvidenceRegistry = "agent_registry"
)

// retireAzureAgents closes the tenant's Azure agents not refreshed since
// cutoff (when the agent steps began). Returns how many were changed.
//
// declaredOK and inferredOK say whether this pass's registration and inference
// steps finished: a step that failed part way refreshed only some agents, so
// the rest prove nothing.
//
// subs is every subscription pass of the run: a bot or Foundry agent is closed
// only when every subscription's surface listing them was read completely.
func (s *AzureOnboardingService) retireAzureAgents(workspaceID, tenantConnectorID uuid.UUID, tenantID string, coverage models.ScanCoverage, subs azureSubscriptionsRead, cutoff time.Time, declaredOK, inferredOK bool) (int, error) {
	reached := func(surface string) bool {
		sc, ok := coverage.Surfaces[surface]
		return ok && sc.State == models.CloudCoverageReached
	}
	agentIDRead := declaredOK && reached(models.SurfaceEntraAgentIdentities)
	registryRead := declaredOK && reached(models.SurfaceEntraAgentRegistry)
	principalsRead := inferredOK && reached(models.SurfaceEntraServicePrincipals)
	botsRead := declaredOK && subs.all(models.SurfaceAzureWorkloads)
	foundryRead := declaredOK && subs.all(models.SurfaceAzureFoundry)
	foundryAgentsRead := declaredOK && subs.all(models.SurfaceAzureFoundry) && subs.all(models.SurfaceAzureFoundryAgents)
	teamsRead := declaredOK && reached(models.SurfaceEntraTeamsApps)
	if !agentIDRead && !registryRead && !principalsRead && !botsRead && !foundryRead && !foundryAgentsRead && !teamsRead {
		return 0, nil
	}

	var stale []models.DiscoveredAgent
	if err := s.db.Where("workspace_id = ? AND source = ? AND lower(metadata->>'tenant_id') = lower(?)",
		workspaceID, models.DiscoverySourceAzure, tenantID).
		Where("runtime_status <> ?", models.RuntimeStatusGone).
		Where("last_seen_at < ?", cutoff).
		Find(&stale).Error; err != nil {
		return 0, err
	}
	if len(stale) == 0 {
		return 0, nil
	}

	// The identities the tenant pass stored, by object id: an inferred agent
	// whose identity is here still exists.
	present := map[string]bool{}
	if principalsRead {
		var ids []string
		if err := s.db.Model(&models.CloudIdentity{}).
			Where("workspace_id = ? AND connector_id = ?", workspaceID, tenantConnectorID).
			Pluck("native_id", &ids).Error; err != nil {
			return 0, err
		}
		for _, id := range ids {
			present[id] = true
		}
	}

	repo := repositories.NewDiscoveryRepository(s.db)
	now := time.Now()
	n := 0
	for _, a := range stale {
		var meta struct {
			EvidenceSource string `json:"evidence_source"`
			PackageID      string `json:"package_id"`
			ObjectID       string `json:"object_id"`
			SubscriptionID string `json:"subscription_id"`
		}
		_ = json.Unmarshal(a.Metadata, &meta)

		status, reason := "", ""
		switch {
		case a.EvidenceMode == models.EvidenceDeclared && meta.EvidenceSource == azureEvidenceAgentID:
			if agentIDRead {
				status, reason = models.RuntimeStatusGone, "no longer listed by Microsoft Entra Agent ID"
			}
		case a.EvidenceMode == models.EvidenceDeclared && meta.EvidenceSource == azureEvidenceBotService:
			if botsRead && subs.covers(meta.SubscriptionID) {
				status, reason = models.RuntimeStatusGone, "the Azure Bot Service bot no longer exists"
			}
		case a.EvidenceMode == models.EvidenceDeclared && meta.EvidenceSource == azureEvidenceLogicApps:
			if botsRead && subs.covers(meta.SubscriptionID) {
				status, reason = models.RuntimeStatusGone, "the Logic Apps workflow no longer runs an agent loop, or no longer exists"
			}
		case a.EvidenceMode == models.EvidenceDeclared && meta.EvidenceSource == azureEvidenceFoundryAgent:
			if foundryAgentsRead && subs.covers(meta.SubscriptionID) {
				status, reason = models.RuntimeStatusGone, "no longer listed by its Microsoft Foundry project"
			}
		case a.EvidenceMode == models.EvidenceDeclared && meta.EvidenceSource == azureEvidenceTeamsApp:
			if teamsRead {
				status, reason = models.RuntimeStatusGone, "no longer in the organization's Teams app catalog"
			}
		case a.EvidenceMode == models.EvidenceDeclared && meta.EvidenceSource == azureEvidenceFoundryApp:
			if foundryRead && subs.covers(meta.SubscriptionID) {
				status, reason = models.RuntimeStatusGone, "no longer published as a Microsoft Foundry agent application"
			}
		case a.EvidenceMode == models.EvidenceDeclared && (meta.EvidenceSource == azureEvidenceRegistry || meta.PackageID != ""):
			if registryRead {
				status, reason = models.RuntimeStatusGone, "no longer listed in the Microsoft 365 agent registry"
			}
		case a.EvidenceMode == models.EvidenceInferred:
			if !principalsRead {
				break
			}
			if meta.ObjectID != "" && !present[meta.ObjectID] {
				status, reason = models.RuntimeStatusGone, "its identity is no longer in the Microsoft Entra ID tenant"
			} else if a.RuntimeStatus != models.RuntimeStatusUnknown {
				status, reason = models.RuntimeStatusUnknown, "no longer meets the agent inference rule"
			}
		}
		if status == "" {
			continue
		}
		event := models.AgentEventAbsent
		if _, err := repo.ApplyLifecycleEvent(&models.DiscoveredAgentEvent{
			WorkspaceID:   workspaceID,
			Source:        models.DiscoverySourceAzure,
			Fingerprint:   a.Fingerprint,
			Event:         event,
			RuntimeStatus: status,
			Reason:        reason,
			// No actor: a pass can show an agent is missing, never who removed it.
			Channel:    "azure_tenant_pass",
			ObservedAt: now,
		}); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// logRetireAzureAgents runs retirement after the agent steps and logs it.
func (s *AzureOnboardingService) logRetireAzureAgents(workspaceID, tenantConnectorID uuid.UUID, tenantID string, coverage models.ScanCoverage, subs azureSubscriptionsRead, cutoff time.Time, declaredOK, inferredOK bool) {
	n, err := s.retireAzureAgents(workspaceID, tenantConnectorID, tenantID, coverage, subs, cutoff, declaredOK, inferredOK)
	if err != nil {
		log.Printf("[azure] closing agents no longer seen in tenant %s failed: %v", tenantID, err)
		return
	}
	if n > 0 {
		log.Printf("[azure] tenant %s: %d agents no longer seen were closed", tenantID, n)
	}
}

// azureSubscriptionsRead is what a run's subscription passes read: wanted is
// how many subscriptions the run meant to read, passes the ones that ran.
type azureSubscriptionsRead struct {
	wanted int
	passes []*azurePassResult
	// ids are the subscription ids the run read, lowercased.
	ids map[string]bool
}

// covers reports whether the run read this subscription.
func (r azureSubscriptionsRead) covers(subscriptionID string) bool {
	return subscriptionID != "" && r.ids[strings.ToLower(subscriptionID)]
}

// all reports whether every wanted subscription ran and read surface
// completely. A run over no subscriptions has read nothing, so it is false.
func (r azureSubscriptionsRead) all(surface string) bool {
	if r.wanted == 0 || len(r.passes) < r.wanted {
		return false
	}
	for _, p := range r.passes {
		sc, ok := p.Coverage.Surfaces[surface]
		if !ok || sc.State != models.CloudCoverageReached {
			return false
		}
	}
	return true
}
