package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"

	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

/* azure_workload_discovery.go is the rest of a subscription pass, after the
   resource inventory and Azure RBAC (azure_discovery.go,
   azure_identity_discovery.go):

     Key Vault access policies  vaults still on the access-policy model grant
                                data access RBAC never shows
                                -> cloud_permission plane=cloud
     workloads                  every resource that runs as a managed identity
                                (VMs, Function and Web Apps, Container Apps, AKS
                                and its kubelet, ...), and each AKS cluster's
                                OIDC issuer -> cloud_workload
     managed identity federation federated credentials on user-assigned
                                identities, the AKS workload identity join key
                                -> cloud_assume_edge

   All read with AuthSec's own app-only ARM token under Reader. Identities are
   the tenant pass's rows: a workload naming an identity the tenant pass has
   not recorded is stored unattributed, never with an invented identity. */

// Cognitive Services accounts, Foundry projects and Machine Learning
// workspaces (hub-based Foundry) are left to the Foundry surface
// (models.AzureFoundryRuntimeKinds), which writes them with their models and
// connections.
const azureWorkloadQuery = `Resources
| where (isnotempty(identity) and tostring(identity.type) !~ 'None') or type =~ 'microsoft.containerservice/managedclusters'
| where type !in~ ('microsoft.cognitiveservices/accounts', 'microsoft.cognitiveservices/accounts/projects', 'microsoft.machinelearningservices/workspaces', 'microsoft.botservice/botservices')
| project id, name, type, kind, location, identity,
    oidcIssuer = tostring(properties.oidcIssuerProfile.issuerURL),
    workloadIdentity = tobool(properties.securityProfile.workloadIdentity.enabled),
    kubeletIdentity = properties.identityProfile.kubeletidentity
| order by id asc`

// azureBotQuery reads every Azure Bot Service bot: the Entra app (or the
// user-assigned managed identity) it authenticates as is in its properties,
// not in the resource's identity block.
const azureBotQuery = `Resources
| where type =~ 'microsoft.botservice/botservices'
| project id, name, kind, location, sku = tostring(sku.name),
    displayName = tostring(properties.displayName),
    msaAppId = tostring(properties.msaAppId),
    msaAppType = tostring(properties.msaAppType),
    msaAppTenantId = tostring(properties.msaAppTenantId),
    msaAppMSIResourceId = tostring(properties.msaAppMSIResourceId),
    endpoint = tostring(properties.endpoint),
    isStreamingSupported = tobool(properties.isStreamingSupported),
    disableLocalAuth = tobool(properties.disableLocalAuth),
    publicNetworkAccess = tostring(properties.publicNetworkAccess)
| order by id asc`

const azureKeyVaultQuery = `Resources
| where type =~ 'microsoft.keyvault/vaults'
| project id, name, rbac = tobool(properties.enableRbacAuthorization), accessPolicies = properties.accessPolicies
| order by id asc`

const azureUserAssignedIdentityQuery = `Resources
| where type =~ 'microsoft.managedidentity/userassignedidentities'
| project id, principalId = tostring(properties.principalId)
| order by id asc`

// azureQueryAll runs a Resource Graph query over one subscription to the end,
// up to the inventory's page cap.
func azureQueryAll[T any](ctx context.Context, s *AzureOnboardingService, armToken, subscriptionID, query string) ([]T, error) {
	var out []T
	skip := ""
	for page := 0; page < azureInventoryMaxPages; page++ {
		p, err := azure.QueryResourceGraph[T](ctx, s.api, armToken, []string{subscriptionID}, query, skip, azureInventoryPageSize)
		if err != nil {
			return out, err
		}
		out = append(out, p.Data...)
		if skip = p.SkipToken; skip == "" {
			return out, nil
		}
	}
	return out, azure.ErrPageLimit
}

/* ------------------------- Key Vault access policies ------------------------- */

type azureVaultRow struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	RBAC           *bool  `json:"rbac"`
	AccessPolicies []struct {
		ObjectID      string `json:"objectId"`
		ApplicationID string `json:"applicationId"`
		Permissions   struct {
			Keys         []string `json:"keys"`
			Secrets      []string `json:"secrets"`
			Certificates []string `json:"certificates"`
			Storage      []string `json:"storage"`
		} `json:"permissions"`
	} `json:"accessPolicies"`
}

// collectKeyVaultAccessPolicies records every access-policy entry of the vaults
// that still use them. A vault with enableRbacAuthorization ignores its access
// policies, so its entries grant nothing and are not recorded.
func (s *AzureOnboardingService) collectKeyVaultAccessPolicies(ctx context.Context, workspaceID, connectorID uuid.UUID, generation int, subscriptionID, armToken string, counters map[string]int) models.SurfaceCoverage {
	surface := models.SurfaceCoverage{State: models.CloudCoverageReached, API: "Microsoft.ResourceGraph/resources (Microsoft.KeyVault/vaults accessPolicies)"}
	vaults, err := azureQueryAll[azureVaultRow](ctx, s, armToken, subscriptionID, azureKeyVaultQuery)
	if err != nil && !errors.Is(err, azure.ErrPageLimit) {
		logAzureError("key vault access policies", err)
		return surfaceFailure(surface, err, 0)
	}
	capped := errors.Is(err, azure.ErrPageLimit)
	var principals, vaultIDs []string
	for _, v := range vaults {
		vaultIDs = append(vaultIDs, strings.ToLower(v.ID))
		for _, p := range v.AccessPolicies {
			principals = append(principals, strings.ToLower(p.ObjectID))
		}
	}
	idMap, err := s.inventory.IdentityIDs(workspaceID, principals)
	if err != nil {
		return surfaceFailure(surface, err, 0)
	}
	resMap, err := s.inventory.ResourceIDs(workspaceID, vaultIDs)
	if err != nil {
		return surfaceFailure(surface, err, 0)
	}

	var rows []models.CloudPermission
	for _, v := range vaults {
		if v.RBAC != nil && *v.RBAC {
			counters["key_vaults_rbac"]++
			continue
		}
		counters["key_vaults_access_policy"]++
		vaultID := strings.ToLower(v.ID)
		resID, ok := resMap[vaultID]
		if !ok {
			counters["key_vault_access_policies_unresolved"]++
			continue
		}
		for _, p := range v.AccessPolicies {
			identityID, ok := idMap[strings.ToLower(p.ObjectID)]
			if !ok {
				counters["key_vault_access_policies_unresolved"]++
				continue
			}
			var actions []string
			for _, set := range []struct {
				plane string
				ops   []string
			}{{"keys", p.Permissions.Keys}, {"secrets", p.Permissions.Secrets},
				{"certificates", p.Permissions.Certificates}, {"storage", p.Permissions.Storage}} {
				for _, op := range set.ops {
					actions = append(actions, set.plane+"/"+strings.ToLower(op))
				}
			}
			if len(actions) == 0 {
				continue
			}
			sort.Strings(actions)
			role := "Key Vault access policy"
			rid := resID
			g := models.CloudPermission{
				IdentityID:      identityID,
				ResourceID:      &rid,
				Plane:           models.PermissionPlaneCloud,
				Effect:          models.PermissionEffectAllow,
				RoleName:        &role,
				Actions:         pq.StringArray(actions),
				ConstraintState: models.ConstraintUnconstrained,
				ScopeKind:       models.PermissionScopeResource,
				Derivation:      models.PermissionDerivationGranted,
				Sensitivity:     keyVaultPolicySensitivity(actions),
				NativeID:        vaultID + "/accesspolicies/" + strings.ToLower(p.ObjectID),
			}
			if p.ApplicationID != "" {
				// A compound identity: the application, only while acting for
				// this principal.
				cond, _ := json.Marshal(map[string]string{"compound_application_id": strings.ToLower(p.ApplicationID)})
				c := string(cond)
				g.Condition, g.ConstraintState = &c, models.ConstraintConditional
				g.NativeID += "/" + strings.ToLower(p.ApplicationID)
			}
			rows = append(rows, g)
			counters["key_vault_access_policies"]++
		}
	}
	if _, err := s.inventory.UpsertPermissions(workspaceID, connectorID, generation, rows); err != nil {
		log.Printf("[azure] scan: could not record key vault access policies for connector %s: %v", connectorID, err)
		surface.State, surface.Error = models.CloudCoveragePartial, "AuthSec could not record the access policies it read"
		return surface
	}
	surface.Count = len(rows)
	if capped {
		surface.State, surface.Error = models.CloudCoveragePartial, "stopped at the per-pass cap"
	}
	return surface
}

// keyVaultPolicySensitivity: reading a secret, or using a key to decrypt or
// sign, is reaching what the vault protects; managing the vault's contents is
// as bad. Listing alone is medium.
func keyVaultPolicySensitivity(actions []string) string {
	for _, a := range actions {
		plane, op, _ := strings.Cut(a, "/")
		switch {
		case op == "all" || op == "purge" || op == "delete" || op == "set" || op == "import" || op == "restore":
			return models.SensitivityHigh
		case plane == "secrets" && op == "get":
			return models.SensitivityHigh
		case plane == "keys" && (op == "decrypt" || op == "unwrapkey" || op == "sign"):
			return models.SensitivityHigh
		}
	}
	return models.SensitivityMedium
}

/* ---------------------------------- workloads --------------------------------- */

type azureWorkloadRow struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Kind     string `json:"kind"`
	Location string `json:"location"`
	Identity *struct {
		Type                   string `json:"type"`
		PrincipalID            string `json:"principalId"`
		UserAssignedIdentities map[string]struct {
			PrincipalID string `json:"principalId"`
			ClientID    string `json:"clientId"`
		} `json:"userAssignedIdentities"`
	} `json:"identity"`
	OIDCIssuer       string `json:"oidcIssuer"`
	WorkloadIdentity *bool  `json:"workloadIdentity"`
	KubeletIdentity  *struct {
		ResourceID string `json:"resourceId"`
		ObjectID   string `json:"objectId"`
		ClientID   string `json:"clientId"`
	} `json:"kubeletIdentity"`
}

// azureRunsAs is one identity a resource runs as.
type azureRunsAs struct {
	assignment, principalID, identityResource, clientID string
}

// collectWorkloads records every resource that runs as a managed identity: one
// cloud_workload row per (resource, identity), since a resource can hold its
// system-assigned identity and several user-assigned ones at once. An AKS
// cluster's row also carries its OIDC issuer, the half of the workload
// identity join that lives in Azure.
func (s *AzureOnboardingService) collectWorkloads(ctx context.Context, workspaceID, connectorID uuid.UUID, generation int, subscriptionID, armToken string, counters map[string]int) models.SurfaceCoverage {
	surface := models.SurfaceCoverage{State: models.CloudCoverageReached, API: "Microsoft.ResourceGraph/resources (identity)"}
	resources, err := azureQueryAll[azureWorkloadRow](ctx, s, armToken, subscriptionID, azureWorkloadQuery)
	if err != nil && !errors.Is(err, azure.ErrPageLimit) {
		logAzureError("workloads", err)
		return surfaceFailure(surface, err, 0)
	}
	capped := errors.Is(err, azure.ErrPageLimit)

	runsAs := make([][]azureRunsAs, len(resources))
	var principals, identityResources []string
	for i, r := range resources {
		if r.Identity != nil {
			if r.Identity.PrincipalID != "" {
				runsAs[i] = append(runsAs[i], azureRunsAs{assignment: "system_assigned", principalID: strings.ToLower(r.Identity.PrincipalID)})
			}
			for uai, v := range r.Identity.UserAssignedIdentities {
				runsAs[i] = append(runsAs[i], azureRunsAs{assignment: "user_assigned", principalID: strings.ToLower(v.PrincipalID),
					identityResource: strings.ToLower(uai), clientID: strings.ToLower(v.ClientID)})
			}
		}
		// AKS nodes act as the kubelet identity, separate from the cluster's
		// own control-plane identity.
		if k := r.KubeletIdentity; k != nil && k.ObjectID != "" {
			runsAs[i] = append(runsAs[i], azureRunsAs{assignment: "kubelet", principalID: strings.ToLower(k.ObjectID),
				identityResource: strings.ToLower(k.ResourceID), clientID: strings.ToLower(k.ClientID)})
		}
		for _, ra := range runsAs[i] {
			principals = append(principals, ra.principalID)
			if ra.identityResource != "" {
				identityResources = append(identityResources, ra.identityResource)
			}
		}
	}
	idMap, err := s.inventory.IdentityIDs(workspaceID, principals)
	if err != nil {
		return surfaceFailure(surface, err, 0)
	}
	byResource, err := s.inventory.ManagedIdentityIDs(workspaceID, identityResources)
	if err != nil {
		return surfaceFailure(surface, err, 0)
	}

	var rows []models.CloudWorkload
	for i, r := range resources {
		id := strings.ToLower(r.ID)
		kind := strings.ToLower(r.Type)
		base := map[string]interface{}{"resource_id": id, "resource_kind": r.Kind}
		if kind == "microsoft.containerservice/managedclusters" {
			counters["aks_clusters"]++
			base["oidc_issuer_url"] = r.OIDCIssuer
			base["oidc_issuer"] = strings.TrimSuffix(strings.TrimPrefix(r.OIDCIssuer, "https://"), "/")
			base["workload_identity_enabled"] = r.WorkloadIdentity != nil && *r.WorkloadIdentity
			if r.WorkloadIdentity != nil && *r.WorkloadIdentity {
				counters["aks_workload_identity_clusters"]++
			}
		}
		if len(runsAs[i]) == 0 {
			// An AKS cluster read without an identity: still the cluster, and
			// still the issuer its pods federate through.
			rows = append(rows, models.CloudWorkload{RuntimeKind: kind, NativeID: id + "#cluster", Name: r.Name,
				Region: r.Location, Attrs: attrsJSON(base)})
			continue
		}
		for _, ra := range runsAs[i] {
			attrs := map[string]interface{}{}
			for k, v := range base {
				attrs[k] = v
			}
			attrs["identity_assignment"] = ra.assignment
			attrs["principal_id"] = ra.principalID
			if ra.identityResource != "" {
				attrs["user_assigned_identity_id"] = ra.identityResource
			}
			if ra.clientID != "" {
				attrs["client_id"] = ra.clientID
			}
			w := models.CloudWorkload{RuntimeKind: kind, Name: r.Name, Region: r.Location, Attrs: attrsJSON(attrs)}
			switch ra.assignment {
			case "system_assigned":
				w.NativeID = id + "#system"
			case "kubelet":
				w.NativeID = id + "#kubelet"
			default:
				w.NativeID = id + "#" + ra.identityResource
			}
			if iid, ok := idMap[ra.principalID]; ok {
				w.IdentityID = &iid
			} else if iid, ok := byResource[ra.identityResource]; ok && ra.identityResource != "" {
				w.IdentityID = &iid
			} else {
				counters["workloads_unattributed"]++
			}
			rows = append(rows, w)
		}
	}
	bots, botErr := s.collectBots(ctx, workspaceID, subscriptionID, armToken, counters)
	rows = append(rows, bots...)
	// Logic Apps agent loops: on the workflow's own rows, or a row of its own
	// for a workflow that runs as no managed identity.
	logicAgents, logicErr := s.collectLogicAgents(ctx, subscriptionID, armToken, counters)
	rows = attachLogicAgents(rows, logicAgents)
	if _, err := s.inventory.UpsertWorkloads(workspaceID, connectorID, generation, rows); err != nil {
		log.Printf("[azure] scan: could not record workloads for connector %s: %v", connectorID, err)
		surface.State, surface.Error = models.CloudCoveragePartial, "AuthSec could not record the workloads it read"
		return surface
	}
	counters["workloads"] = len(rows)
	surface.Count = len(rows)
	if capped {
		surface.State, surface.Error = models.CloudCoveragePartial, "stopped at the per-pass cap"
	}
	if botErr != nil && surface.State == models.CloudCoverageReached {
		surface.State, surface.Error = models.CloudCoveragePartial, "Azure Bot Service bots could not be read: "+botErr.Error()
	}
	if logicErr != nil && surface.State == models.CloudCoverageReached {
		surface.State, surface.Error = models.CloudCoveragePartial, "Logic Apps workflows could not all be read: "+logicErr.Error()
	}
	return surface
}

/* ------------------------------ Azure Bot Service ----------------------------- */

type azureBotRow struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	Kind                 string `json:"kind"`
	Location             string `json:"location"`
	SKU                  string `json:"sku"`
	DisplayName          string `json:"displayName"`
	MsaAppID             string `json:"msaAppId"`
	MsaAppType           string `json:"msaAppType"`
	MsaAppTenantID       string `json:"msaAppTenantId"`
	MsaAppMSIResourceID  string `json:"msaAppMSIResourceId"`
	Endpoint             string `json:"endpoint"`
	IsStreamingSupported *bool  `json:"isStreamingSupported"`
	DisableLocalAuth     *bool  `json:"disableLocalAuth"`
	PublicNetworkAccess  string `json:"publicNetworkAccess"`
}

// azureBotRuntimeKind is an Azure Bot Service bot's runtime kind (its ARM type).
const azureBotRuntimeKind = "microsoft.botservice/botservices"

// collectBots reads the subscription's Azure Bot Service bots -- Bot
// Framework and Teams bots, and the Azure channel of Copilot Studio agents --
// as workloads that run as the identity they authenticate with: the service
// principal of their Entra app (msaAppType SingleTenant or MultiTenant), or a
// user-assigned managed identity (UserAssignedMSI). A bot whose app has no
// service principal in this tenant (a multi-tenant app registered elsewhere)
// is recorded unattributed, never with an invented identity.
func (s *AzureOnboardingService) collectBots(ctx context.Context, workspaceID uuid.UUID, subscriptionID, armToken string, counters map[string]int) ([]models.CloudWorkload, error) {
	bots, err := azureQueryAll[azureBotRow](ctx, s, armToken, subscriptionID, azureBotQuery)
	if err != nil && !errors.Is(err, azure.ErrPageLimit) {
		logAzureError("bot services", err)
		return nil, err
	}
	capped := errors.Is(err, azure.ErrPageLimit)
	if len(bots) == 0 {
		return nil, nil
	}
	var appIDs, msiResources []string
	for _, b := range bots {
		if b.MsaAppMSIResourceID != "" {
			msiResources = append(msiResources, strings.ToLower(b.MsaAppMSIResourceID))
		}
		if b.MsaAppID != "" {
			appIDs = append(appIDs, strings.ToLower(b.MsaAppID))
		}
	}
	byApp, err := s.inventory.ServicePrincipalIDsByAppID(workspaceID, appIDs)
	if err != nil {
		return nil, err
	}
	byMSI, err := s.inventory.ManagedIdentityIDs(workspaceID, msiResources)
	if err != nil {
		return nil, err
	}
	rows := make([]models.CloudWorkload, 0, len(bots))
	for _, b := range bots {
		id := strings.ToLower(b.ID)
		attrs := map[string]interface{}{
			"resource_id": id, "resource_kind": b.Kind, "bot": true,
			"display_name": b.DisplayName, "sku": b.SKU,
			"bot_app_id": strings.ToLower(b.MsaAppID), "bot_app_type": b.MsaAppType,
			"bot_app_tenant_id": strings.ToLower(b.MsaAppTenantID),
			"endpoint":          b.Endpoint, "public_network_access": b.PublicNetworkAccess,
		}
		if b.DisableLocalAuth != nil {
			attrs["local_auth_enabled"] = !*b.DisableLocalAuth
		}
		w := models.CloudWorkload{RuntimeKind: azureBotRuntimeKind, NativeID: id + "#bot", Name: b.Name,
			Region: b.Location}
		if r := strings.ToLower(b.MsaAppMSIResourceID); r != "" {
			attrs["identity_assignment"] = "user_assigned"
			attrs["user_assigned_identity_id"] = r
			if iid, ok := byMSI[r]; ok {
				w.IdentityID = &iid
			}
		} else {
			attrs["identity_assignment"] = "entra_app"
		}
		if w.IdentityID == nil {
			if iid, ok := byApp[strings.ToLower(b.MsaAppID)]; ok {
				w.IdentityID = &iid
			}
		}
		if w.IdentityID == nil {
			counters["bots_unattributed"]++
		}
		w.Attrs = attrsJSON(attrs)
		rows = append(rows, w)
		counters["bot_services"]++
	}
	if capped {
		return rows, azure.ErrPageLimit
	}
	return rows, nil
}

/* ------------------------- managed identity federation ------------------------ */

// collectIdentityFederation reads the federated credentials of every
// user-assigned managed identity: who outside Azure (an AKS service account, a
// pipeline) may obtain the identity's tokens.
func (s *AzureOnboardingService) collectIdentityFederation(ctx context.Context, workspaceID, connectorID uuid.UUID, generation int, subscriptionID, armToken string, counters map[string]int) models.SurfaceCoverage {
	surface := models.SurfaceCoverage{State: models.CloudCoverageReached, API: "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials"}
	type uaiRow struct {
		ID          string `json:"id"`
		PrincipalID string `json:"principalId"`
	}
	uais, err := azureQueryAll[uaiRow](ctx, s, armToken, subscriptionID, azureUserAssignedIdentityQuery)
	if err != nil && !errors.Is(err, azure.ErrPageLimit) {
		logAzureError("user-assigned identities", err)
		return surfaceFailure(surface, err, 0)
	}
	principals := make([]string, 0, len(uais))
	for _, u := range uais {
		principals = append(principals, strings.ToLower(u.PrincipalID))
	}
	idMap, err := s.inventory.IdentityIDs(workspaceID, principals)
	if err != nil {
		return surfaceFailure(surface, err, 0)
	}

	var (
		mu       sync.Mutex
		edges    []models.CloudAssumeEdge
		failed   int
		firstErr error
	)
	forEachLimited(len(uais), azureAssignConcurrency, func(i int) {
		u := uais[i]
		creds, err := s.api.ListUserAssignedIdentityFederatedCredentials(ctx, armToken, u.ID)
		mu.Lock()
		defer mu.Unlock()
		if err != nil && !errors.Is(err, azure.ErrPageLimit) {
			failed++
			if firstErr == nil {
				firstErr = err
			}
			return
		}
		identityID, ok := idMap[strings.ToLower(u.PrincipalID)]
		if !ok {
			counters["managed_identity_federation_unresolved"] += len(creds)
			return
		}
		for _, c := range creds {
			edges = append(edges, azureFederationEdge(identityID, c.Properties.Issuer, c.Properties.Subject, map[string]interface{}{
				"credential_id":             strings.ToLower(c.ID),
				"credential_name":           c.Name,
				"audiences":                 c.Properties.Audiences,
				"user_assigned_identity_id": strings.ToLower(u.ID),
				"edge_owner":                "managed_identity",
			}))
		}
	})
	if _, err := s.inventory.UpsertAssumeEdges(workspaceID, connectorID, generation, edges); err != nil {
		log.Printf("[azure] scan: could not record managed identity federation for connector %s: %v", connectorID, err)
		surface.State, surface.Error = models.CloudCoveragePartial, "AuthSec could not record the federated credentials it read"
		return surface
	}
	counters["managed_identity_federated_credentials"] = len(edges)
	surface.Count = len(edges)
	if failed > 0 {
		surface = surfaceFailure(surface, firstErr, len(edges))
		surface.State = models.CloudCoveragePartial
		surface.Error = fmt.Sprintf("federated credentials of %d of %d user-assigned identities could not be read: %v", failed, len(uais), firstErr)
	}
	return surface
}

// azureLogicRuntimeKind is a Consumption Logic Apps workflow's runtime kind.
const azureLogicRuntimeKind = "microsoft.logic/workflows"

// attachLogicAgents puts each agent workflow's facts on the workflow's rows
// (one per identity it runs as), and adds a row for an agent workflow that
// runs as no managed identity, so every agent workflow is recorded.
func attachLogicAgents(rows []models.CloudWorkload, agents map[string]map[string]interface{}) []models.CloudWorkload {
	if len(agents) == 0 {
		return rows
	}
	seen := map[string]bool{}
	for i := range rows {
		if rows[i].RuntimeKind != azureLogicRuntimeKind {
			continue
		}
		var attrs map[string]interface{}
		_ = json.Unmarshal(rows[i].Attrs, &attrs)
		id := strings.ToLower(fmt.Sprint(attrs["resource_id"]))
		facts, ok := agents[id]
		if !ok {
			continue
		}
		attrs["agent_workflow"] = facts
		rows[i].Attrs = attrsJSON(attrs)
		seen[id] = true
	}
	ids := make([]string, 0, len(agents))
	for id := range agents {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if seen[id] {
			continue
		}
		facts := agents[id]
		rows = append(rows, models.CloudWorkload{RuntimeKind: azureLogicRuntimeKind, NativeID: id + "#agent",
			Name:  fmt.Sprint(facts["workflow_name"]),
			Attrs: attrsJSON(map[string]interface{}{"resource_id": id, "identity_assignment": "none", "agent_workflow": facts})})
	}
	return rows
}
