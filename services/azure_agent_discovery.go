package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

/* azure_agent_discovery.go reads Microsoft Entra Agent ID: the agents a
   tenant has DECLARED, as directory objects of their own.

   Agent ID adds four objects to the directory, each a subtype of one the
   tenant pass already reads:

     agent identity       a service principal  -> entra_agent_identity
     agent user           a user               -> entra_agent_user
     blueprint            an app registration  -> entra_application, agent_type
     blueprint principal  a service principal  -> entra_service_principal, agent_type

   So they are read with their own listings, merged into the base listings
   (an object both list is recorded once, as its subtype), and flow through
   the rest of the pass unchanged: a blueprint's secrets and federated
   credentials are read as any app registration's, an agent identity's API
   permissions and sign-ins as any service principal's.

   What Agent ID adds beyond the objects is who may act as whom:
     - a blueprint's credentials obtain its agent identities' tokens, so the
       blueprint's service principal (or the blueprint, with none here) can
       become each agent identity created from it;
     - an agent identity obtains its agent user's tokens.
   Both are recorded as cloud_assume_edge rows, and so as can_assume edges on
   the graph: whoever holds a blueprint's secret reaches every agent made
   from it.

   Every agent identity is then registered as a discovered agent with
   evidence_mode 'declared': the directory says it is an agent, which is
   stronger than anything inference concludes. */

// Agent ID @odata.type values, for objects the base listings return.
const (
	odataAgentIdentity           = "#microsoft.graph.agentIdentity"
	odataAgentBlueprint          = "#microsoft.graph.agentIdentityBlueprint"
	odataAgentBlueprintPrincipal = "#microsoft.graph.agentIdentityBlueprintPrincipal"
	odataAgentUser               = "#microsoft.graph.agentUser"
	// agentServicePrincipalType is servicePrincipalType of every agent identity.
	agentServicePrincipalType = "ServiceIdentity"
)

// azureAgentObjects is what the Agent ID listings returned, by lowercase
// object id.
type azureAgentObjects struct {
	identities map[string]azure.AgentIdentity
	blueprints map[string]azure.AgentBlueprint
	principals map[string]azure.AgentBlueprintPrincipal
	users      map[string]azure.AgentUser
	// blueprintByApp finds a blueprint by its appId, which is how an agent
	// identity names it.
	blueprintByApp map[string]azure.AgentBlueprint
}

// readAgentObjects reads the four Agent ID listings, each into its surface.
// ungranted are the permissions the tenant's last check found not granted:
// a listing behind one of them is not taken as complete however it answered.
func (s *AzureOnboardingService) readAgentObjects(ctx context.Context, graphToken string, surfaces map[string]models.SurfaceCoverage, ungranted map[string]bool) *azureAgentObjects {
	out := &azureAgentObjects{
		identities: map[string]azure.AgentIdentity{}, blueprints: map[string]azure.AgentBlueprint{},
		principals: map[string]azure.AgentBlueprintPrincipal{}, users: map[string]azure.AgentUser{},
		blueprintByApp: map[string]azure.AgentBlueprint{},
	}
	ids, err := s.api.ListAgentIdentities(ctx, graphToken)
	surfaces[models.SurfaceEntraAgentIdentities] = distrustUngranted(agentSurface(
		"GET /v1.0/servicePrincipals/microsoft.graph.agentIdentity", "AgentIdentity.Read.All", len(ids), err),
		"AgentIdentity.Read.All", ungranted)
	for _, a := range ids {
		out.identities[strings.ToLower(a.ID)] = a
	}
	bps, err := s.api.ListAgentBlueprints(ctx, graphToken)
	surfaces[models.SurfaceEntraAgentBlueprints] = distrustUngranted(agentSurface(
		"GET /v1.0/applications/microsoft.graph.agentIdentityBlueprint", "AgentIdentityBlueprint.Read.All", len(bps), err),
		"AgentIdentityBlueprint.Read.All", ungranted)
	for _, b := range bps {
		out.blueprints[strings.ToLower(b.ID)] = b
		out.blueprintByApp[strings.ToLower(b.AppID)] = b
	}
	ps, err := s.api.ListAgentBlueprintPrincipals(ctx, graphToken)
	surfaces[models.SurfaceEntraAgentBlueprintPrincipals] = distrustUngranted(agentSurface(
		"GET /v1.0/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal", "AgentIdentityBlueprintPrincipal.Read.All", len(ps), err),
		"AgentIdentityBlueprintPrincipal.Read.All", ungranted)
	for _, p := range ps {
		out.principals[strings.ToLower(p.ID)] = p
	}
	us, err := s.api.ListAgentUsers(ctx, graphToken)
	surfaces[models.SurfaceEntraAgentUsers] = agentSurface(
		"GET /beta/users/microsoft.graph.agentUser", "Directory.Read.All", len(us), err)
	for _, u := range us {
		out.users[strings.ToLower(u.ID)] = u
	}
	return out
}

// agentSurface is listSurface for an Agent ID listing, which fails in two
// ways the base listings do not:
//   - 401/403: the optional permission is not granted. Denied, and said so in
//     words an administrator can act on.
//   - 400/404: this tenant's Graph does not offer the type cast. Nothing there
//     to read, and nobody can fix it: unsupported.
func agentSurface(api, permission string, read int, err error) models.SurfaceCoverage {
	sc := listSurface(api, read, err)
	if err == nil {
		return sc
	}
	switch azure.APIStatus(err) {
	case 401, 403:
		sc.State = models.CloudCoverageDenied
		sc.Error = permission + " is not granted to AuthSec in this tenant: an administrator adds it to the AuthSec app and grants consent again"
	case 400, 404:
		sc.State = models.CloudCoverageUnsupported
		sc.Error = "this tenant's Microsoft Graph does not offer it: " + err.Error()
	}
	return sc
}

// distrustUngranted keeps a listing whose permission is not granted from
// counting as read in full. Seen live: without the AgentIdentity* permissions
// Graph answers the agent listings 200 with an empty list rather than 403, and
// an empty answer the caller had no right to see past proves nothing -- taken
// as complete, it would license deleting every agent recorded earlier. What
// such a listing did return is still real: partial, not denied, then.
func distrustUngranted(sc models.SurfaceCoverage, permission string, ungranted map[string]bool) models.SurfaceCoverage {
	if sc.State != models.CloudCoverageReached || !ungranted[permission] {
		return sc
	}
	sc.State, sc.ErrorCode = models.CloudCoverageDenied, models.AzureGraphPermissionNotGranted
	if sc.Count > 0 {
		sc.State = models.CloudCoveragePartial
	}
	sc.Error = permission + " is not granted to AuthSec in this tenant, so this listing cannot be complete: an administrator adds it to the AuthSec app and grants consent again"
	return sc
}

// ungrantedPermissions are the Graph permissions the tenant's last check
// (Connect or Verify, which every pass follows) found not granted or refused.
func (s *AzureOnboardingService) ungrantedPermissions(workspaceID, connectorID uuid.UUID) map[string]bool {
	out := map[string]bool{}
	var c models.CloudConnector
	if err := tenancy.InWorkspaceRead(context.Background(), s.db, workspaceID, func(tx *gorm.DB) error {
		return tx.Select("attrs").Where("workspace_id = ? AND id = ?", workspaceID, connectorID).First(&c).Error
	}); err != nil {
		return out
	}
	var attrs models.AzureTenantAttrs
	_ = json.Unmarshal(c.Attrs, &attrs)
	for _, p := range attrs.GraphPermissions {
		if p.State == models.AzureGraphPermissionNotGranted || p.State == models.AzureGraphPermissionDenied {
			out[p.Name] = true
		}
	}
	return out
}

// mergeInto adds the Agent ID objects the base listings did not return, so
// the rest of the pass sees one listing per base type.
func (a *azureAgentObjects) mergeInto(users []azure.GraphUser, apps []azure.GraphApplication, sps []azure.ServicePrincipal) ([]azure.GraphUser, []azure.GraphApplication, []azure.ServicePrincipal) {
	seen := map[string]bool{}
	for _, u := range users {
		seen[strings.ToLower(u.ID)] = true
	}
	for _, x := range apps {
		seen[strings.ToLower(x.ID)] = true
	}
	for _, sp := range sps {
		seen[strings.ToLower(sp.ID)] = true
	}
	for id, u := range a.users {
		if !seen[id] {
			users = append(users, azure.GraphUser{ID: u.ID, DisplayName: u.DisplayName, UserPrincipalName: u.UserPrincipalName,
				Mail: u.Mail, AccountEnabled: u.AccountEnabled, CreatedDateTime: u.CreatedDateTime, ODataType: odataAgentUser})
		}
	}
	for id, b := range a.blueprints {
		if !seen[id] {
			apps = append(apps, azure.GraphApplication{ID: b.ID, AppID: b.AppID, DisplayName: b.DisplayName,
				SignInAudience: b.SignInAudience, CreatedDateTime: b.CreatedDateTime,
				PasswordCredentials: b.PasswordCredentials, KeyCredentials: b.KeyCredentials, ODataType: odataAgentBlueprint})
		}
	}
	for id, p := range a.principals {
		if !seen[id] {
			sps = append(sps, azure.ServicePrincipal{ID: p.ID, AppID: p.AppID, DisplayName: p.DisplayName,
				AccountEnabled: p.AccountEnabled, AppOwnerOrganizationID: p.AppOwnerOrganizationID,
				ServicePrincipalType: p.ServicePrincipalType, ODataType: odataAgentBlueprintPrincipal})
		}
	}
	for id, x := range a.identities {
		if !seen[id] {
			sps = append(sps, azure.ServicePrincipal{ID: x.ID, DisplayName: x.DisplayName, AccountEnabled: x.AccountEnabled,
				ServicePrincipalType: firstNonEmpty(x.ServicePrincipalType, agentServicePrincipalType), ODataType: odataAgentIdentity})
		}
	}
	return users, apps, sps
}

// classifyUser makes an agent user of a user Agent ID lists or types as one.
func (a *azureAgentObjects) classifyUser(ident *models.CloudIdentity, u azure.GraphUser, counters map[string]int) {
	au, listed := a.users[ident.NativeID]
	if !listed && !strings.EqualFold(u.ODataType, odataAgentUser) {
		return
	}
	ident.Kind = models.CloudIdentityEntraAgentUser
	extra := map[string]interface{}{"agent_listed": listed}
	if parent := strings.ToLower(au.IdentityParentID); parent != "" {
		extra["agent_identity_id"] = parent
		if p, ok := a.identities[parent]; ok {
			extra["agent_identity_name"] = p.DisplayName
		}
	}
	mergeAttrs(ident, extra)
	counters["agent_users"]++
}

// classifyApplication marks a blueprint among the app registrations.
func (a *azureAgentObjects) classifyApplication(ident *models.CloudIdentity, app azure.GraphApplication, counters map[string]int) {
	b, listed := a.blueprints[ident.NativeID]
	if !listed && !strings.EqualFold(app.ODataType, odataAgentBlueprint) {
		return
	}
	extra := map[string]interface{}{"agent_type": models.AgentTypeBlueprint, "agent_listed": listed}
	if listed {
		extra["publisher_domain"] = b.PublisherDomain
		extra["created_by_app_id"] = strings.ToLower(b.CreatedByAppID)
		extra["tags"] = b.Tags
		extra["disabled_by_microsoft"] = disabledByMicrosoft(b.DisabledByMicrosoftStatus)
		agents := 0
		for _, x := range a.identities {
			if strings.EqualFold(x.AgentIdentityBlueprintID, b.AppID) {
				agents++
			}
		}
		extra["agent_count"] = agents
	}
	mergeAttrs(ident, extra)
	counters["agent_blueprints"]++
}

// classifyServicePrincipal makes an agent identity of a service principal
// Agent ID lists or types as one, and marks a blueprint principal.
func (a *azureAgentObjects) classifyServicePrincipal(ident *models.CloudIdentity, sp azure.ServicePrincipal, counters map[string]int) {
	if _, listed := a.principals[ident.NativeID]; listed || strings.EqualFold(sp.ODataType, odataAgentBlueprintPrincipal) {
		mergeAttrs(ident, map[string]interface{}{"agent_type": models.AgentTypeBlueprintPrincipal, "agent_listed": listed})
		counters["agent_blueprint_principals"]++
		return
	}
	x, listed := a.identities[ident.NativeID]
	if !listed && !strings.EqualFold(sp.ODataType, odataAgentIdentity) &&
		!strings.EqualFold(sp.ServicePrincipalType, agentServicePrincipalType) {
		return
	}
	ident.Kind = models.CloudIdentityEntraAgentIdentity
	extra := map[string]interface{}{"agent_listed": listed}
	if listed {
		bp := strings.ToLower(x.AgentIdentityBlueprintID)
		extra["agent_blueprint_app_id"] = bp
		if b, ok := a.blueprintByApp[bp]; ok {
			extra["agent_blueprint_id"] = strings.ToLower(b.ID)
			extra["agent_blueprint_name"] = b.DisplayName
		}
		extra["created_by_app_id"] = strings.ToLower(x.CreatedByAppID)
		extra["tags"] = x.Tags
		extra["disabled_by_microsoft"] = disabledByMicrosoft(x.DisabledByMicrosoftStatus)
		if x.CreatedDateTime != nil {
			ident.ProviderCreatedAt = x.CreatedDateTime
		}
	}
	for _, u := range a.users {
		if strings.EqualFold(u.IdentityParentID, ident.NativeID) {
			extra["agent_user_id"] = strings.ToLower(u.ID)
			extra["agent_user_principal_name"] = u.UserPrincipalName
			break
		}
	}
	mergeAttrs(ident, extra)
	counters["agent_identities"]++
}

func disabledByMicrosoft(status string) bool {
	return status != "" && !strings.EqualFold(status, "NotDisabled")
}

// agentAssumeEdges records who may obtain an agent's tokens: a blueprint's
// service principal (or the blueprint) for each agent identity made from it,
// and each agent identity for its agent user.
func (a *azureAgentObjects) agentAssumeEdges(spByApp map[string]string, idMap map[string]uuid.UUID, counters map[string]int) []models.CloudAssumeEdge {
	var out []models.CloudAssumeEdge
	for id, x := range a.identities {
		target, ok := idMap[id]
		bpApp := strings.ToLower(x.AgentIdentityBlueprintID)
		if !ok || bpApp == "" {
			continue
		}
		// The credentials live on the blueprint, but tokens are issued to its
		// service principal in this tenant; with none here, the blueprint.
		subject, owner := spByApp[bpApp], "blueprint_principal"
		if _, known := idMap[subject]; subject == "" || !known {
			b, found := a.blueprintByApp[bpApp]
			if !found {
				counters["agent_blueprints_unresolved"]++
				continue
			}
			subject, owner = strings.ToLower(b.ID), "blueprint"
		}
		out = append(out, models.CloudAssumeEdge{
			IdentityID: target, SubjectKind: models.AssumeSubjectIdentity, Subject: subject,
			Mechanism: models.AssumeMechanismAgentBlueprint,
			Attrs: attrsJSON(map[string]interface{}{
				"blueprint_app_id": bpApp, "edge_owner": owner,
				"why": "the blueprint's credentials obtain this agent identity's tokens",
			}),
		})
		counters["agent_blueprint_edges"]++
	}
	for id, u := range a.users {
		target, ok := idMap[id]
		parent := strings.ToLower(u.IdentityParentID)
		if _, known := idMap[parent]; !ok || parent == "" || !known {
			continue
		}
		out = append(out, models.CloudAssumeEdge{
			IdentityID: target, SubjectKind: models.AssumeSubjectIdentity, Subject: parent,
			Mechanism: models.AssumeMechanismAgentUser,
			Attrs: attrsJSON(map[string]interface{}{
				"edge_owner": "agent_identity",
				"why":        "the agent identity obtains this agent user's tokens",
			}),
		})
		counters["agent_user_edges"]++
	}
	return out
}

/* ------------------------------ declared agents ------------------------------ */

// registerDeclaredAgents records every agent identity of the tenant as a
// discovered agent with evidence_mode 'declared'. The fingerprint is the one
// inference uses, so an identity inferred before Agent ID was read is
// upgraded in place, and a human's decision on it is kept (UpsertSighting
// never moves status).
func (s *AzureOnboardingService) registerDeclaredAgents(workspaceID, tenantConnectorID uuid.UUID, tenantID string) (int, error) {
	declared := map[string]bool{}
	n, err := s.registerDirectoryAgents(workspaceID, tenantConnectorID, tenantID, declared)
	if err != nil {
		return n, err
	}
	// Then the agents Azure Resource Manager lists (Foundry agent
	// applications, Azure Bot Service bots), skipping any declared above.
	m, err := s.registerResourceAgents(workspaceID, tenantConnectorID, tenantID, declared, time.Now())
	return n + m, err
}

// registerDirectoryAgents records the agents the directory declares: Agent ID
// agent identities and Microsoft 365 agent registry agents. declared collects
// their fingerprints.
func (s *AzureOnboardingService) registerDirectoryAgents(workspaceID, tenantConnectorID uuid.UUID, tenantID string, declared map[string]bool) (int, error) {
	// What the passes stored, read first; each helper reads in a transaction
	// of its own under row-level security for the workspace.
	var agents []models.CloudIdentity
	signIns := map[uuid.UUID]int{}
	if err := tenancy.InWorkspaceRead(context.Background(), s.db, workspaceID, func(tx *gorm.DB) error {
		if err := tx.Where("workspace_id = ? AND connector_id = ? AND kind = ?",
			workspaceID, tenantConnectorID, models.CloudIdentityEntraAgentIdentity).Find(&agents).Error; err != nil {
			return err
		}
		if len(agents) == 0 {
			return nil
		}
		ids := make([]uuid.UUID, 0, len(agents))
		for _, a := range agents {
			ids = append(ids, a.ID)
		}
		var usage []struct {
			IdentityID uuid.UUID
			SignIns    int
		}
		if err := tx.Table("cloud_usage").
			Select("identity_id, COALESCE(SUM((attrs->>'sign_ins')::int), 0) AS sign_ins").
			Where("workspace_id = ? AND identity_id IN ? AND source = ?", workspaceID, ids, models.UsageSourceEntraSignIn).
			Group("identity_id").Scan(&usage).Error; err != nil {
			return err
		}
		for _, u := range usage {
			signIns[u.IdentityID] = u.SignIns
		}
		return nil
	}); err != nil {
		return 0, err
	}
	spByApp, err := s.servicePrincipalsByAppID(workspaceID, tenantConnectorID)
	if err != nil {
		return 0, err
	}
	registry := s.tenantRegistry(workspaceID, tenantConnectorID)

	now := time.Now()
	// Agents in the Microsoft 365 agent registry with no Entra agent identity
	// here: declared by the registry. One with an identity is declared below,
	// through that identity, which carries its registry facts.
	known := make(map[string]bool, len(agents))
	for _, a := range agents {
		known[a.NativeID] = true
	}
	// Every sighting is written in one transaction under row-level security
	// for the workspace: all of them, or (on an error) none.
	n := 0
	recorded := map[string]bool{}
	err = tenancy.InWorkspace(context.Background(), s.db, workspaceID, func(tx *gorm.DB) error {
		n = 0
		repo := repositories.NewDiscoveryRepository(tx)
		for _, e := range registry {
			if id, _ := e["agent_identity_id"].(string); id != "" && known[id] {
				continue
			}
			if pid, _ := e["package_id"].(string); pid == "" {
				continue
			}
			appID, _ := e["app_id"].(string)
			sighting := registryAgentSighting(workspaceID, tenantID, e, spByApp[strings.ToLower(appID)], now)
			if err := readyForDeclared(tx, workspaceID, sighting.Fingerprint); err != nil {
				return err
			}
			if _, _, err := repo.UpsertSighting(sighting); err != nil {
				return fmt.Errorf("declare registry agent: %w", err)
			}
			recorded[sighting.Fingerprint] = true
			n++
		}
		for _, a := range agents {
			sighting := declaredAgentSighting(workspaceID, tenantID, a, signIns[a.ID], now)
			if err := readyForDeclared(tx, workspaceID, sighting.Fingerprint); err != nil {
				return err
			}
			if _, _, err := repo.UpsertSighting(sighting); err != nil {
				return fmt.Errorf("declare %s: %w", a.NativeID, err)
			}
			recorded[sighting.Fingerprint] = true
			n++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	for f := range recorded {
		declared[f] = true
	}
	return n, nil
}

func declaredAgentSighting(workspaceID uuid.UUID, tenantID string, a models.CloudIdentity, signIns int, now time.Time) *models.DiscoveredAgent {
	var attrs struct {
		Blueprint     string     `json:"agent_blueprint_name"`
		BlueprintApp  string     `json:"agent_blueprint_app_id"`
		AgentUser     string     `json:"agent_user_principal_name"`
		CreatedBy     string     `json:"created_by_app_id"`
		Tags          []string   `json:"tags"`
		Disabled      bool       `json:"disabled_by_microsoft"`
		LastAppOnly   *time.Time `json:"last_app_only_sign_in_at"`
		LastDelegated *time.Time `json:"last_delegated_sign_in_at"`
		// Registry is the agent's entry in the Microsoft 365 agent registry.
		Registry map[string]interface{} `json:"registry"`
	}
	_ = json.Unmarshal(a.Attrs, &attrs)

	signals := []string{"listed by Microsoft Entra Agent ID as an agent identity"}
	if attrs.Blueprint != "" {
		signals = append(signals, "created from blueprint "+attrs.Blueprint)
	} else if attrs.BlueprintApp != "" {
		signals = append(signals, "created from blueprint "+attrs.BlueprintApp)
	}
	if attrs.AgentUser != "" {
		signals = append(signals, "acts as user "+attrs.AgentUser)
	}
	if signIns > 0 {
		signals = append(signals, fmt.Sprintf("signed in %d times in the last week", signIns))
	}
	if !a.Enabled {
		signals = append(signals, "disabled")
	}
	if attrs.Disabled {
		signals = append(signals, "disabled by Microsoft")
	}
	if attrs.Registry != nil {
		reg := "listed in the Microsoft 365 agent registry"
		if p, _ := attrs.Registry["platform"].(string); p != "" {
			reg += " (built with " + p + ")"
		}
		signals = append(signals, reg)
		if b, _ := attrs.Registry["is_blocked"].(bool); b {
			signals = append(signals, "blocked by an administrator in the agent registry")
		}
	}

	archetype := ""
	switch {
	case attrs.LastAppOnly != nil && attrs.LastDelegated != nil:
		archetype = "hybrid"
	case attrs.LastDelegated != nil:
		archetype = "user_delegated"
	case attrs.LastAppOnly != nil || attrs.AgentUser != "":
		archetype = "autonomous"
	}

	meta, _ := json.Marshal(map[string]interface{}{
		"provider":         "azure",
		"tenant_id":        strings.ToLower(tenantID),
		"object_id":        a.NativeID,
		"identity_kind":    a.Kind,
		"evidence_source":  "entra_agent_id",
		"blueprint_name":   attrs.Blueprint,
		"blueprint_app_id": attrs.BlueprintApp,
		"agent_user":       attrs.AgentUser,
		"created_by":       attrs.CreatedBy,
		"tags":             attrs.Tags,
		"signals":          signals,
		"last_sign_in":     a.LastUsedAt,
		"registry":         attrs.Registry,
	})
	runtime, reason := models.RuntimeStatusUnknown, ""
	var running *time.Time
	if a.LastUsedAt != nil && now.Sub(*a.LastUsedAt) <= azureAgentActiveWindow {
		runtime, running = models.RuntimeStatusRunning, a.LastUsedAt
		reason = "signed in to Entra at " + a.LastUsedAt.UTC().Format(time.RFC3339)
	}
	return &models.DiscoveredAgent{
		ID: uuid.New(), WorkspaceID: workspaceID, Source: models.DiscoverySourceAzure,
		Fingerprint:      azureAgentFingerprintPrefix + strings.ToLower(tenantID) + ":" + a.NativeID,
		DisplayName:      a.Name,
		Metadata:         meta,
		DeploymentOrigin: models.DeploymentOriginUnknown,
		EvidenceMode:     models.EvidenceDeclared,
		// A declared row never carries last_observed_running_at (the
		// discovered_agents_declared_never_running_check constraint): its recent
		// sign-in is the runtime status and reason instead.
		Archetype:         archetype,
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

// logRegisterDeclaredAgents runs registration after a tenant pass and logs
// the outcome; like inference, it reads only what discovery stored.
func (s *AzureOnboardingService) logRegisterDeclaredAgents(workspaceID, tenantConnectorID uuid.UUID, tenantID string) bool {
	n, err := s.registerDeclaredAgents(workspaceID, tenantConnectorID, tenantID)
	if err != nil {
		log.Printf("[azure] declared agents for tenant %s failed: %v", tenantID, err)
		return false
	}
	log.Printf("[azure] declared agents for tenant %s: %d registered (agent identities and registry agents)", tenantID, n)
	return true
}

// servicePrincipalsByAppID maps each appId to the tenant's service principal
// for it (object id), from what the tenant pass stored.
func (s *AzureOnboardingService) servicePrincipalsByAppID(workspaceID, tenantConnectorID uuid.UUID) (map[string]string, error) {
	var rows []struct {
		NativeID string
		AppID    string
	}
	if err := tenancy.InWorkspaceRead(context.Background(), s.db, workspaceID, func(tx *gorm.DB) error {
		return tx.Model(&models.CloudIdentity{}).
			Select("native_id, lower(attrs->>'app_id') AS app_id").
			Where("workspace_id = ? AND connector_id = ? AND kind = ? AND attrs->>'app_id' <> ''",
				workspaceID, tenantConnectorID, models.CloudIdentityEntraServicePrincipal).
			Scan(&rows).Error
	}); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r.AppID] = r.NativeID
	}
	return out, nil
}

// registryAppIDs is the appId of every agent in the tenant's Microsoft 365
// agent registry: those agents are declared by the registry, so inference
// leaves their service principals alone.
func (s *AzureOnboardingService) registryAppIDs(workspaceID, tenantConnectorID uuid.UUID) map[string]bool {
	out := map[string]bool{}
	for _, e := range s.tenantRegistry(workspaceID, tenantConnectorID) {
		if id, _ := e["app_id"].(string); id != "" {
			out[strings.ToLower(id)] = true
		}
	}
	return out
}

// readyForDeclared clears last_observed_running_at on an Azure agent about to
// be recorded as declared: an agent first inferred (which an older inference
// marked running) is upgraded in place, and a declared row may not carry it
// (discovered_agents_declared_never_running_check). Its running state stays
// in runtime_status and runtime_reason. tx is the caller's transaction under
// row-level security for workspaceID, in which the sighting is then recorded.
func readyForDeclared(tx *gorm.DB, workspaceID uuid.UUID, fingerprint string) error {
	return tx.Model(&models.DiscoveredAgent{}).
		Where("workspace_id = ? AND source = ? AND fingerprint = ? AND last_observed_running_at IS NOT NULL",
			workspaceID, models.DiscoverySourceAzure, fingerprint).
		Update("last_observed_running_at", nil).Error
}
