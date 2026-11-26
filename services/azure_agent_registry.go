package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

/* azure_agent_registry.go reads the Microsoft 365 agent registry -- the
   tenant's Copilot catalog: Copilot Studio agents, Microsoft 365 Copilot
   Agent Builder agents, declarative and custom engine agents from any
   publisher. Many of these have no Entra agent identity at all, so this is
   the only place AuthSec sees them.

   Each agent is recorded as Microsoft lists it: where it was built, who
   published it, whether an administrator blocked it, to whom it is
   available, Microsoft's own agent class, and its use over the last 30 days.
   An agent with a Microsoft Entra Agent ID identity carries these facts on
   that identity (attrs.registry); every agent is registered in the product's
   agent inventory as declared (registerDeclaredAgents).

   CopilotPackages.Read.All, and a Microsoft Agent 365 licence in the tenant
   for the API to answer at all. */

const (
	// azureRegistryPermission reads the catalog.
	azureRegistryPermission = "CopilotPackages.Read.All"
	// azureRegistryDetailLimit caps how many agents have their use read in
	// one pass; azureRegistryKeep how many are stored on the tenant.
	azureRegistryDetailLimit = 300
	azureRegistryKeep        = 1000
)

// readAgentRegistry reads the catalog's agents and each one's use. ok is false
// when the catalog could not be read, and what an earlier pass stored stays.
func (s *AzureOnboardingService) readAgentRegistry(ctx context.Context, graphToken string, surfaces map[string]models.SurfaceCoverage, counters map[string]int, ungranted map[string]bool) ([]map[string]interface{}, bool) {
	sc := models.SurfaceCoverage{State: models.CloudCoverageReached, API: "GET /v1.0/copilot/admin/catalog/packages (agents)"}
	if ungranted[azureRegistryPermission] {
		sc.State, sc.ErrorCode = models.CloudCoverageDenied, models.AzureGraphPermissionNotGranted
		sc.Error = azureRegistryPermission + " is not granted to AuthSec in this tenant: an administrator adds it to the AuthSec app and grants consent again"
		surfaces[models.SurfaceEntraAgentRegistry] = sc
		return nil, false
	}
	pkgs, err := s.api.ListCopilotAgents(ctx, graphToken)
	if err != nil && !errors.Is(err, azure.ErrPageLimit) {
		logAzureError("agent registry", err)
		sc = surfaceFailure(sc, err, 0)
		if st := azure.APIStatus(err); st == 401 || st == 403 {
			// The permission is granted (or this read would not have been
			// tried): the Package Management API answers only a tenant with a
			// Microsoft Agent 365 licence. Microsoft does not offer the data.
			sc.State, sc.ErrorCode = models.CloudCoverageUnsupported, "license_required"
			sc.Error = "the agent registry needs a Microsoft Agent 365 licence in this tenant: " + err.Error()
		}
		surfaces[models.SurfaceEntraAgentRegistry] = sc
		return nil, false
	}
	if errors.Is(err, azure.ErrPageLimit) {
		sc.State, sc.Error = models.CloudCoveragePartial, "stopped at the listing page limit"
	}

	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].ID < pkgs[j].ID })
	details := make([]*azure.CopilotPackageDetail, len(pkgs))
	n := len(pkgs)
	if n > azureRegistryDetailLimit {
		n = azureRegistryDetailLimit
	}
	var mu sync.Mutex
	failed := 0
	forEachLimited(n, azureAssignConcurrency, func(i int) {
		d, err := s.api.GetCopilotPackage(ctx, graphToken, pkgs[i].ID)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			failed++
			return
		}
		details[i] = d
	})
	out := make([]map[string]interface{}, 0, len(pkgs))
	for i, p := range pkgs {
		if i >= azureRegistryKeep {
			break
		}
		out = append(out, registryEntry(p, details[i]))
		counters["registry_agents"]++
		if p.AgentIdentityID != "" {
			counters["registry_agents_with_identity"]++
		}
		if p.IsBlocked {
			counters["registry_agents_blocked"]++
		}
	}
	sc.Count = len(pkgs)
	if failed > 0 && sc.State == models.CloudCoverageReached {
		sc.State, sc.Error = models.CloudCoveragePartial, fmt.Sprintf("the use of %d of %d agents could not be read", failed, n)
	}
	if len(pkgs) > azureRegistryDetailLimit && sc.State == models.CloudCoverageReached {
		sc.Error = fmt.Sprintf("use read for the first %d of %d agents", azureRegistryDetailLimit, len(pkgs))
	}
	surfaces[models.SurfaceEntraAgentRegistry] = sc
	return out, true
}

// registryEntry is one catalog agent as stored: Microsoft's facts about it.
func registryEntry(p azure.CopilotPackage, d *azure.CopilotPackageDetail) map[string]interface{} {
	m := map[string]interface{}{
		"package_id": p.ID, "name": p.DisplayName, "platform": p.Platform, "publisher": p.Publisher,
		"type": p.Type, "agent_class": p.AgentClass, "is_blocked": p.IsBlocked,
		"available_to": p.AvailableTo, "deployed_to": p.DeployedTo, "version": p.Version,
		"element_types": p.ElementTypes, "description": p.ShortDescription,
		"app_id": strings.ToLower(p.AppID), "agent_identity_id": strings.ToLower(p.AgentIdentityID),
	}
	if p.CreatedDateTime != nil {
		m["created_at"] = p.CreatedDateTime.UTC()
	}
	if p.LastModifiedDateTime != nil {
		m["modified_at"] = p.LastModifiedDateTime.UTC()
	}
	if d != nil {
		if d.ActiveUsers != nil {
			m["active_users_30d"] = *d.ActiveUsers
		}
		if d.TotalSessions != nil {
			m["sessions_30d"] = *d.TotalSessions
		}
		if d.TotalRunTimeInHours != nil {
			m["run_hours_30d"] = *d.TotalRunTimeInHours
		}
		if d.LastUsedDateTime != nil {
			m["last_used_at"] = d.LastUsedDateTime.UTC()
		}
		if d.Sensitivity != "" {
			m["sensitivity"] = d.Sensitivity
		}
		if len(d.Categories) > 0 {
			m["categories"] = d.Categories
		}
	}
	return m
}

// registryByIdentity indexes catalog agents by their Entra agent identity.
func registryByIdentity(entries []map[string]interface{}) map[string]map[string]interface{} {
	out := map[string]map[string]interface{}{}
	for _, e := range entries {
		if id, _ := e["agent_identity_id"].(string); id != "" {
			out[id] = e
		}
	}
	return out
}

/* ----------------------------- declared agents ----------------------------- */

// azureRegistryFingerprint is the inventory fingerprint of a catalog agent
// with no Entra agent identity (one with an identity uses the identity's).
func azureRegistryFingerprint(tenantID, packageID string) string {
	return azureAgentFingerprintPrefix + strings.ToLower(tenantID) + ":registry:" + packageID
}

// registryAgentSighting is a catalog agent with no Entra agent identity, as a
// declared agent: Microsoft's registry says it is an agent. spObjectID is the
// tenant's service principal of the agent's app registration (its appId), or
// "": with one, the agent is recorded under that service principal's
// fingerprint, the one inference uses, so the agent is listed once and an
// inferred finding for it is upgraded in place.
func registryAgentSighting(workspaceID uuid.UUID, tenantID string, e map[string]interface{}, spObjectID string, now time.Time) *models.DiscoveredAgent {
	str := func(k string) string { v, _ := e[k].(string); return v }
	signals := []string{"listed in the Microsoft 365 agent registry"}
	if p := str("platform"); p != "" {
		signals = append(signals, "targets "+p)
	}
	if p := str("publisher"); p != "" {
		signals = append(signals, "published by "+p)
	}
	if b, _ := e["is_blocked"].(bool); b {
		signals = append(signals, "blocked by an administrator")
	}
	if n, ok := e["active_users_30d"].(float64); ok {
		signals = append(signals, fmt.Sprintf("used by %d people in the last 30 days", int(n)))
	} else if n, ok := e["active_users_30d"].(int); ok {
		signals = append(signals, fmt.Sprintf("used by %d people in the last 30 days", n))
	}
	meta := map[string]interface{}{
		"provider": "azure", "tenant_id": strings.ToLower(tenantID), "evidence_source": "agent_registry",
		"signals": signals, "registry": e,
	}
	fingerprint := azureRegistryFingerprint(tenantID, str("package_id"))
	if spObjectID != "" {
		fingerprint = azureAgentFingerprintPrefix + strings.ToLower(tenantID) + ":" + spObjectID
		meta["object_id"] = spObjectID
	}
	raw, _ := json.Marshal(meta)
	runtime, reason := models.RuntimeStatusUnknown, ""
	var running *time.Time
	if s := str("last_used_at"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil && now.Sub(t) <= azureAgentActiveWindow {
			runtime, running, reason = models.RuntimeStatusRunning, &t, "used in Microsoft 365 at "+t.UTC().Format(time.RFC3339)
		}
	}
	return &models.DiscoveredAgent{
		ID: uuid.New(), WorkspaceID: workspaceID, Source: models.DiscoverySourceAzure,
		Fingerprint:      fingerprint,
		DisplayName:      firstNonEmpty(str("name"), str("package_id")),
		Metadata:         raw,
		DeploymentOrigin: models.DeploymentOriginUnknown,
		EvidenceMode:     models.EvidenceDeclared,
		// Declared rows never carry last_observed_running_at (database
		// constraint); recent use is the runtime status and reason.
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

// tenantRegistry is the catalog the last tenant pass stored.
func (s *AzureOnboardingService) tenantRegistry(workspaceID, tenantConnectorID uuid.UUID) []map[string]interface{} {
	var row struct{ Registry []byte }
	if err := tenancy.InWorkspaceRead(context.Background(), s.db, workspaceID, func(tx *gorm.DB) error {
		return tx.Model(&models.CloudConnector{}).Select("attrs->'agent_registry' AS registry").
			Where("workspace_id = ? AND id = ?", workspaceID, tenantConnectorID).Scan(&row).Error
	}); err != nil || len(row.Registry) == 0 {
		return nil
	}
	var out []map[string]interface{}
	_ = json.Unmarshal(row.Registry, &out)
	return out
}
