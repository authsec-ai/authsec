package services

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
)

/* azure_resource_agents.go registers the agents Azure Resource Manager lists
   as resources of their own, after the subscription passes recorded them:

     Microsoft Foundry agent application   a published Foundry agent
                                           (accounts/projects/applications)
     Microsoft Foundry project agent       an agent of a Foundry project, read
                                           from its data plane
     Azure Bot Service bot                 a Bot Framework or Teams bot, or the
                                           Azure channel of a Copilot Studio
                                           agent (botServices)
     Logic Apps agent workflow             a workflow running an agent loop
     Teams app with a bot                  a Copilot Studio agent or custom
                                           bot published to Teams

   Both are declared: Azure says they are agents. Each is recorded under the
   fingerprint of the identity it runs as when the tenant has it -- the one
   Agent ID, the agent registry and inference use -- so an agent is listed
   once whichever source names it, and one already declared by Microsoft
   Entra Agent ID or the agent registry in this pass is left to that source.
   Otherwise it has a fingerprint of its own, from its ARM id. */

const (
	azureEvidenceFoundryApp   = "foundry_agent_application"
	azureEvidenceFoundryAgent = "foundry_project_agent"
	azureEvidenceBotService   = "azure_bot_service"
	azureEvidenceLogicApps    = "logic_apps_agent"
	azureEvidenceTeamsApp     = "teams_app_catalog"
)

// azureTenantWorkload is a workload of one of the tenant's subscriptions, with
// the native id of the identity it runs as.
type azureTenantWorkload struct {
	NativeID         string
	Name             string
	RuntimeKind      string
	Region           string
	Attrs            json.RawMessage
	IdentityNativeID string
	SubscriptionID   string
}

// tenantWorkloads returns the workloads of the tenant's subscriptions whose
// runtime kind is one of kinds.
func (s *AzureOnboardingService) tenantWorkloads(workspaceID uuid.UUID, tenantID string, kinds []string) ([]azureTenantWorkload, error) {
	var rows []azureTenantWorkload
	err := s.db.Table("cloud_workload w").
		Select("w.native_id, w.name, w.runtime_kind, w.region, w.attrs, i.native_id AS identity_native_id, c.scope_id AS subscription_id").
		Joins("JOIN cloud_connector c ON c.id = w.connector_id").
		Joins("LEFT JOIN cloud_identity i ON i.id = w.identity_id").
		Where("w.workspace_id = ? AND c.workspace_id = ? AND c.provider = ? AND c.scope_kind = ? AND lower(c.parent_scope_id) = lower(?)",
			workspaceID, workspaceID, models.CloudProviderAzure, models.CloudScopeSubscription, tenantID).
		Where("w.runtime_kind IN ?", kinds).
		Order("w.native_id").
		Scan(&rows).Error
	return rows, err
}

// registerResourceAgents records the tenant's Foundry agent applications and
// Azure Bot Service bots as declared agents. declared holds the fingerprints
// Agent ID and the registry recorded in this pass. Returns how many it
// recorded.
func (s *AzureOnboardingService) registerResourceAgents(workspaceID, tenantConnectorID uuid.UUID, tenantID string, declared map[string]bool, now time.Time) (int, error) {
	repo := repositories.NewDiscoveryRepository(s.db)
	tenant := strings.ToLower(tenantID)
	n := 0
	record := func(a *models.DiscoveredAgent) error {
		if declared[a.Fingerprint] {
			return nil
		}
		if err := s.readyForDeclared(workspaceID, a.Fingerprint); err != nil {
			return err
		}
		if _, _, err := repo.UpsertSighting(a); err != nil {
			return fmt.Errorf("declare %s: %w", a.DisplayName, err)
		}
		declared[a.Fingerprint] = true
		n++
		return nil
	}

	projects, err := s.tenantWorkloads(workspaceID, tenantID, []string{"microsoft.cognitiveservices/accounts/projects"})
	if err != nil {
		return n, err
	}
	for _, p := range projects {
		var attrs struct {
			ResourceID string                   `json:"resource_id"`
			Apps       []map[string]interface{} `json:"agent_applications"`
			Agents     []map[string]interface{} `json:"project_agents"`
		}
		_ = json.Unmarshal(p.Attrs, &attrs)
		for _, app := range attrs.Apps {
			if err := record(foundryAppSighting(workspaceID, tenant, p, attrs.ResourceID, app, now)); err != nil {
				return n, err
			}
		}
		for _, a := range attrs.Agents {
			if err := record(foundryProjectAgentSighting(workspaceID, tenant, p, attrs.ResourceID, a, now)); err != nil {
				return n, err
			}
		}
	}

	logic, err := s.tenantWorkloads(workspaceID, tenantID, []string{azureLogicRuntimeKind})
	if err != nil {
		return n, err
	}
	// One agent per workflow, whichever identities it runs as.
	byWorkflow := map[string][]azureTenantWorkload{}
	var order []string
	for _, w := range logic {
		var attrs struct {
			ResourceID string                 `json:"resource_id"`
			Agent      map[string]interface{} `json:"agent_workflow"`
		}
		_ = json.Unmarshal(w.Attrs, &attrs)
		if attrs.Agent == nil {
			continue
		}
		id := strings.ToLower(attrs.ResourceID)
		if _, ok := byWorkflow[id]; !ok {
			order = append(order, id)
		}
		byWorkflow[id] = append(byWorkflow[id], w)
	}
	for _, id := range order {
		if err := record(logicAgentSighting(workspaceID, tenant, id, byWorkflow[id], now)); err != nil {
			return n, err
		}
	}

	bots, err := s.tenantWorkloads(workspaceID, tenantID, []string{azureBotRuntimeKind})
	if err != nil {
		return n, err
	}
	for _, b := range bots {
		if err := record(botSighting(workspaceID, tenant, b, now)); err != nil {
			return n, err
		}
	}

	teams := s.tenantTeamsAgents(workspaceID, tenantConnectorID)
	if len(teams) > 0 {
		spByApp, err := s.servicePrincipalsByAppID(workspaceID, tenantConnectorID)
		if err != nil {
			return n, err
		}
		for _, e := range teams {
			appID, _ := e["bot_app_id"].(string)
			if err := record(teamsAgentSighting(workspaceID, tenant, e, spByApp[strings.ToLower(appID)], now)); err != nil {
				return n, err
			}
		}
	}
	return n, nil
}

// foundryAppSighting is one published Foundry agent as a declared agent.
func foundryAppSighting(workspaceID uuid.UUID, tenant string, project azureTenantWorkload, projectID string, app map[string]interface{}, now time.Time) *models.DiscoveredAgent {
	str := func(k string) string { v, _ := app[k].(string); return v }
	name := firstNonEmpty(str("display_name"), str("name"))
	resourceID := strings.ToLower(str("resource_id"))
	agentID := strings.ToLower(str("agent_identity_principal_id"))

	signals := []string{"published as a Microsoft Foundry agent application in project " + project.Name}
	if agents, _ := app["agents"].([]interface{}); len(agents) > 0 {
		names := make([]string, 0, len(agents))
		for _, a := range agents {
			names = append(names, fmt.Sprint(a))
		}
		sort.Strings(names)
		signals = append(signals, "exposes agents: "+strings.Join(names, ", "))
	}
	if a := str("authorization"); a != "" {
		signals = append(signals, "callers are authorized by: "+a)
	}
	if e, ok := app["enabled"].(bool); ok && !e {
		signals = append(signals, "disabled")
	}

	fingerprint := azureAgentFingerprintPrefix + tenant + ":foundry:" + resourceID
	meta := map[string]interface{}{
		"provider": "azure", "tenant_id": tenant, "evidence_source": azureEvidenceFoundryApp,
		"signals": signals, "foundry_application": app,
		"foundry_project_id": projectID, "subscription_id": project.SubscriptionID,
	}
	if agentID != "" {
		// Its Microsoft Entra agent identity: the fingerprint Agent ID uses.
		fingerprint = azureAgentFingerprintPrefix + tenant + ":" + agentID
		meta["object_id"] = agentID
	}
	raw, _ := json.Marshal(meta)
	return &models.DiscoveredAgent{
		ID: uuid.New(), WorkspaceID: workspaceID, Source: models.DiscoverySourceAzure,
		Fingerprint:       fingerprint,
		DisplayName:       name,
		Metadata:          raw,
		DeploymentOrigin:  models.DeploymentOriginUnknown,
		EvidenceMode:      models.EvidenceDeclared,
		Status:            models.DiscoveredAgentUnregistered,
		RuntimeStatus:     models.RuntimeStatusUnknown,
		RuntimeObservedAt: azureObservedAt(nil, now),
		FirstSeenAt:       now,
		LastSeenAt:        now,
		SightingCount:     1,
		CreatedBy:         "azure-discovery",
	}
}

// botSighting is one Azure Bot Service bot as a declared agent.
func botSighting(workspaceID uuid.UUID, tenant string, b azureTenantWorkload, now time.Time) *models.DiscoveredAgent {
	var attrs map[string]interface{}
	_ = json.Unmarshal(b.Attrs, &attrs)
	str := func(k string) string { v, _ := attrs[k].(string); return v }

	signals := []string{"an Azure Bot Service bot"}
	switch str("bot_app_type") {
	case "UserAssignedMSI":
		signals = append(signals, "authenticates as a user-assigned managed identity")
	case "SingleTenant", "MultiTenant":
		signals = append(signals, "authenticates as a "+strings.ToLower(str("bot_app_type"))+" Microsoft Entra app")
	}
	if b.IdentityNativeID == "" && str("bot_app_id") != "" {
		signals = append(signals, "its app has no service principal in this tenant")
	}
	if e := str("endpoint"); e != "" {
		signals = append(signals, "messaging endpoint: "+safeTarget(e))
	}

	resourceID := strings.TrimSuffix(b.NativeID, "#bot")
	fingerprint := azureAgentFingerprintPrefix + tenant + ":bot:" + resourceID
	meta := map[string]interface{}{
		"provider": "azure", "tenant_id": tenant, "evidence_source": azureEvidenceBotService,
		"signals": signals, "bot": attrs, "resource_id": resourceID, "subscription_id": b.SubscriptionID,
	}
	if b.IdentityNativeID != "" {
		fingerprint = azureAgentFingerprintPrefix + tenant + ":" + b.IdentityNativeID
		meta["object_id"] = b.IdentityNativeID
	}
	raw, _ := json.Marshal(meta)
	return &models.DiscoveredAgent{
		ID: uuid.New(), WorkspaceID: workspaceID, Source: models.DiscoverySourceAzure,
		Fingerprint:       fingerprint,
		DisplayName:       firstNonEmpty(str("display_name"), b.Name),
		Metadata:          raw,
		DeploymentOrigin:  models.DeploymentOriginUnknown,
		EvidenceMode:      models.EvidenceDeclared,
		Status:            models.DiscoveredAgentUnregistered,
		RuntimeStatus:     models.RuntimeStatusUnknown,
		RuntimeObservedAt: azureObservedAt(nil, now),
		FirstSeenAt:       now,
		LastSeenAt:        now,
		SightingCount:     1,
		CreatedBy:         "azure-discovery",
	}
}

// declaredAzureAgent is the shape every resource agent shares.
func declaredAzureAgent(workspaceID uuid.UUID, fingerprint, name string, meta map[string]interface{}, now time.Time) *models.DiscoveredAgent {
	raw, _ := json.Marshal(meta)
	return &models.DiscoveredAgent{
		ID: uuid.New(), WorkspaceID: workspaceID, Source: models.DiscoverySourceAzure,
		Fingerprint:       fingerprint,
		DisplayName:       name,
		Metadata:          raw,
		DeploymentOrigin:  models.DeploymentOriginUnknown,
		EvidenceMode:      models.EvidenceDeclared,
		Status:            models.DiscoveredAgentUnregistered,
		RuntimeStatus:     models.RuntimeStatusUnknown,
		RuntimeObservedAt: azureObservedAt(nil, now),
		FirstSeenAt:       now,
		LastSeenAt:        now,
		SightingCount:     1,
		CreatedBy:         "azure-discovery",
	}
}

// joinAny renders a JSON list of names.
func joinAny(v interface{}) string {
	list, _ := v.([]interface{})
	names := make([]string, 0, len(list))
	for _, x := range list {
		names = append(names, fmt.Sprint(x))
	}
	return strings.Join(names, ", ")
}

// foundryProjectAgentSighting is one agent of a Foundry project, from its data
// plane, as a declared agent: under its agent identity's fingerprint when it
// has one, so Agent ID and Foundry list it once.
func foundryProjectAgentSighting(workspaceID uuid.UUID, tenant string, project azureTenantWorkload, projectID string, a map[string]interface{}, now time.Time) *models.DiscoveredAgent {
	get := func(k string) string { v, _ := a[k].(string); return v }
	signals := []string{"an agent of Microsoft Foundry project " + project.Name}
	if k := get("kind"); k != "" {
		signals = append(signals, "kind: "+k)
	}
	if m := get("model"); m != "" {
		signals = append(signals, "model: "+m)
	}
	if t := joinAny(a["tool_types"]); t != "" {
		signals = append(signals, "tools: "+t)
	}
	if get("state") == "disabled" {
		signals = append(signals, "disabled")
	}
	meta := map[string]interface{}{
		"provider": "azure", "tenant_id": tenant, "evidence_source": azureEvidenceFoundryAgent,
		"signals": signals, "foundry_agent": a, "foundry_project_id": projectID, "subscription_id": project.SubscriptionID,
	}
	fingerprint := azureAgentFingerprintPrefix + tenant + ":foundry-agent:" + strings.ToLower(projectID) + "/" + strings.ToLower(get("name"))
	if id, ok := a["instance_identity"].(map[string]interface{}); ok {
		oid, _ := id["principal_id"].(string)
		if oid == "" {
			oid, _ = id["object_id"].(string)
		}
		if oid != "" {
			fingerprint = azureAgentFingerprintPrefix + tenant + ":" + oid
			meta["object_id"] = oid
		}
	}
	return declaredAzureAgent(workspaceID, fingerprint, firstNonEmpty(get("name"), get("id")), meta, now)
}

// logicAgentSighting is one Logic Apps workflow running an agent loop. It is
// keyed by the workflow: a managed identity may serve several workflows.
func logicAgentSighting(workspaceID uuid.UUID, tenant, resourceID string, rows []azureTenantWorkload, now time.Time) *models.DiscoveredAgent {
	var attrs struct {
		Agent map[string]interface{} `json:"agent_workflow"`
	}
	_ = json.Unmarshal(rows[0].Attrs, &attrs)
	facts := attrs.Agent
	signals := []string{"a Logic Apps workflow that runs an agent loop"}
	agents, _ := facts["agents"].([]interface{})
	for _, x := range agents {
		am, _ := x.(map[string]interface{})
		line := "agent " + fmt.Sprint(am["name"])
		if d, ok := am["deploymentId"].(string); ok && d != "" {
			line += " on model deployment " + d
		}
		if t := joinAny(am["tools"]); t != "" {
			line += " with tools " + t
		}
		signals = append(signals, line)
	}
	if conns, ok := facts["connections"].([]interface{}); ok && len(conns) > 0 {
		names := make([]string, 0, len(conns))
		for _, y := range conns {
			cm, _ := y.(map[string]interface{})
			names = append(names, fmt.Sprint(cm["name"]))
		}
		signals = append(signals, "uses connections: "+strings.Join(names, ", "))
	}
	if st, _ := facts["state"].(string); st != "" && !strings.EqualFold(st, "Enabled") {
		signals = append(signals, "workflow state: "+st)
	}
	meta := map[string]interface{}{
		"provider": "azure", "tenant_id": tenant, "evidence_source": azureEvidenceLogicApps,
		"signals": signals, "logic_app": facts, "resource_id": resourceID, "subscription_id": rows[0].SubscriptionID,
	}
	var identities []string
	for _, r := range rows {
		if r.IdentityNativeID != "" {
			identities = append(identities, r.IdentityNativeID)
		}
	}
	if len(identities) > 0 {
		sort.Strings(identities)
		meta["object_id"] = identities[0]
		meta["runs_as"] = identities
	}
	name, _ := facts["workflow_name"].(string)
	return declaredAzureAgent(workspaceID, azureAgentFingerprintPrefix+tenant+":logicapp:"+resourceID,
		firstNonEmpty(name, rows[0].Name), meta, now)
}

// teamsAgentSighting is one Teams app with a bot, as a declared agent: under
// its bot's service principal when the tenant has it.
func teamsAgentSighting(workspaceID uuid.UUID, tenant string, e map[string]interface{}, spObjectID string, now time.Time) *models.DiscoveredAgent {
	get := func(k string) string { v, _ := e[k].(string); return v }
	signals := []string{"published to the organization's Teams app catalog with a bot"}
	if st := get("publishing_state"); st != "" && st != "published" {
		signals = append(signals, "publishing state: "+st)
	}
	if by := get("created_by"); by != "" {
		signals = append(signals, "created by "+by)
	}
	meta := map[string]interface{}{
		"provider": "azure", "tenant_id": tenant, "evidence_source": azureEvidenceTeamsApp,
		"signals": signals, "teams_app": e,
	}
	fingerprint := azureAgentFingerprintPrefix + tenant + ":teams:" + get("teams_app_id")
	if spObjectID != "" {
		fingerprint = azureAgentFingerprintPrefix + tenant + ":" + spObjectID
		meta["object_id"] = spObjectID
	}
	return declaredAzureAgent(workspaceID, fingerprint, firstNonEmpty(get("name"), get("teams_app_id")), meta, now)
}
