package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

/* azure_foundry_discovery.go is the Microsoft Foundry slice of a subscription
   pass: every Cognitive Services account (Foundry, Azure OpenAI, single
   service), each Foundry project, which models each account serves, and what
   each connection points at and how it authenticates. Read through
   armcognitiveservices with AuthSec's app-only ARM token under Reader.

   Accounts and projects are compute that runs as a managed identity, so they
   are cloud_workload rows under their ARM types, exactly as the workloads
   surface wrote them before; this surface owns those two runtime kinds
   (models.AzureFoundryRuntimeKinds) and adds what Resource Graph cannot see as
   attributes, the way AWS keeps an AgentCore gateway's targets on its row.

   Hub-based Foundry (Foundry classic) is read too, through armmachinelearning:
   each hub and hub-based project is a Machine Learning workspace, recorded
   with its hub, its connections, its managed network's outbound rule and the
   storage, key vault and registry it keeps its data in. A classic Machine
   Learning workspace is recorded as the compute it is, as before.

   The agents are in Foundry's data plane, which Reader does not reach; their
   identities are Entra agent identities, found by the tenant pass. A Foundry
   blueprint trusts its project's managed identity through a federated
   credential, which is how ListFoundry ties the two halves together. */

const azureFoundryAPI = "Microsoft.CognitiveServices (armcognitiveservices)"

// azureMLAPI is the API hub-based Foundry and Machine Learning workspaces are
// read through.
const azureMLAPI = "Microsoft.MachineLearningServices (armmachinelearning)"

// foundryAccountDetail is what the per-account reads returned.
type foundryAccountDetail struct {
	deployments []azure.FoundryDeployment
	connections []azure.FoundryConnection
	projects    []azure.FoundryProject
	// projectConnections is keyed by project id.
	projectConnections map[string][]azure.FoundryConnection
	// projectApps is each project's published agents, keyed by project id;
	// a project whose list was not read is absent.
	projectApps map[string]foundryProjectApps
	// The *Read flags say which lists were read; a list that was not is
	// left out of the row, never written as empty.
	deploymentsRead, connectionsRead, projectsRead bool
	// failed names the reads that did not complete.
	failed []string
}

// foundryProjectApps is what the list of a project's Agent Applications
// returned.
type foundryProjectApps struct {
	apps []foundryAgentApp
	// unavailable: the API is not offered for this account, so there is
	// nothing to read -- not a failed read.
	unavailable bool
}

// foundryAgentApp is one published agent and its deployments.
type foundryAgentApp struct {
	app             azure.FoundryAgentApplication
	deployments     []azure.FoundryAgentDeployment
	deploymentsRead bool
}

// collectFoundry records every Cognitive Services account and Foundry project
// in the subscription, one cloud_workload row per (resource, identity).
func (s *AzureOnboardingService) collectFoundry(ctx context.Context, workspaceID, connectorID uuid.UUID, generation int, subscriptionID, armToken string, counters map[string]int) models.SurfaceCoverage {
	surface := models.SurfaceCoverage{State: models.CloudCoverageReached, API: azureFoundryAPI}
	accounts, err := s.api.ListCognitiveAccounts(ctx, armToken, subscriptionID)
	if err != nil && !errors.Is(err, azure.ErrPageLimit) {
		logAzureError("cognitive services accounts", err)
		return surfaceFailure(surface, err, 0)
	}
	capped := errors.Is(err, azure.ErrPageLimit)

	details := make([]foundryAccountDetail, len(accounts))
	var (
		mu           sync.Mutex
		failed       int
		firstErr     error
		detailCapped bool
	)
	// read records one detail read's outcome; true when its list is usable.
	// A capped list is usable but not complete, so the surface is partial.
	read := func(d *foundryAccountDetail, what string, err error) bool {
		if err == nil {
			return true
		}
		mu.Lock()
		defer mu.Unlock()
		if errors.Is(err, azure.ErrPageLimit) {
			detailCapped = true
			d.failed = append(d.failed, what+": stopped at the page limit")
			return true
		}
		failed++
		if firstErr == nil {
			firstErr = err
		}
		d.failed = append(d.failed, what+": "+err.Error())
		return false
	}
	forEachLimited(len(accounts), azureAssignConcurrency, func(i int) {
		a, d := accounts[i], &details[i]
		if a.ServesModels() {
			deps, err := s.api.ListFoundryDeployments(ctx, armToken, subscriptionID, a.ResourceGroup, a.Name)
			if read(d, "deployments", err) {
				d.deployments, d.deploymentsRead = deps, true
			}
		}
		if !a.Foundry {
			return
		}
		conns, err := s.api.ListFoundryAccountConnections(ctx, armToken, subscriptionID, a.ResourceGroup, a.Name)
		if read(d, "connections", err) {
			d.connections, d.connectionsRead = conns, true
		}
		projects, err := s.api.ListFoundryProjects(ctx, armToken, subscriptionID, a.ResourceGroup, a.Name)
		if !read(d, "projects", err) {
			return
		}
		d.projects, d.projectsRead = projects, true
		d.projectConnections = map[string][]azure.FoundryConnection{}
		d.projectApps = map[string]foundryProjectApps{}
		for _, p := range projects {
			pc, err := s.api.ListFoundryProjectConnections(ctx, armToken, subscriptionID, a.ResourceGroup, a.Name, p.Name)
			if read(d, "connections of project "+p.Name, err) {
				d.projectConnections[p.ID] = pc
			}
			// Published agents (Agent Applications) and their deployments.
			apps, err := s.api.ListFoundryAgentApplications(ctx, armToken, subscriptionID, a.ResourceGroup, a.Name, p.Name)
			if azure.AgentApplicationsUnavailable(err) {
				d.projectApps[p.ID] = foundryProjectApps{unavailable: true}
				continue
			}
			if !read(d, "agent applications of project "+p.Name, err) {
				continue
			}
			pa := foundryProjectApps{apps: make([]foundryAgentApp, 0, len(apps))}
			for _, app := range apps {
				fa := foundryAgentApp{app: app}
				deps, err := s.api.ListFoundryAgentDeployments(ctx, armToken, subscriptionID, a.ResourceGroup, a.Name, p.Name, app.Name)
				if read(d, "deployments of agent application "+app.Name, err) {
					fa.deployments, fa.deploymentsRead = deps, true
				}
				pa.apps = append(pa.apps, fa)
			}
			d.projectApps[p.ID] = pa
		}
	})

	// Machine Learning workspaces: hub-based Foundry's hubs and projects in
	// detail, classic workspaces as the compute they are.
	mlw, mlErr := s.api.ListMLWorkspaces(ctx, armToken, subscriptionID)
	if mlErr != nil && !errors.Is(mlErr, azure.ErrPageLimit) {
		logAzureError("machine learning workspaces", mlErr)
		failed++
		if firstErr == nil {
			firstErr = mlErr
		}
	}
	if errors.Is(mlErr, azure.ErrPageLimit) {
		capped = true
	}
	mlDetails := make([]foundryAccountDetail, len(mlw))
	forEachLimited(len(mlw), azureAssignConcurrency, func(i int) {
		w, d := mlw[i], &mlDetails[i]
		if !w.HubBased() {
			return
		}
		conns, err := s.api.ListMLWorkspaceConnections(ctx, armToken, subscriptionID, w.ResourceGroup, w.Name)
		if read(d, "connections", err) {
			d.connections, d.connectionsRead = conns, true
		}
	})

	var principals, identityResources []string
	addRefs := func(ref *azure.ManagedIdentityRef) {
		for _, ra := range foundryRunsAs(ref) {
			principals = append(principals, ra.principalID)
			if ra.identityResource != "" {
				identityResources = append(identityResources, ra.identityResource)
			}
		}
	}
	for i, a := range accounts {
		addRefs(a.Identity)
		for _, p := range details[i].projects {
			addRefs(p.Identity)
		}
	}
	for _, w := range mlw {
		addRefs(w.Identity)
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
	emit := func(kind, id, name, region, noIdentitySuffix string, ref *azure.ManagedIdentityRef, base map[string]interface{}) {
		runsAs := foundryRunsAs(ref)
		if len(runsAs) == 0 {
			attrs := copyAttrs(base)
			attrs["identity_assignment"] = "none"
			rows = append(rows, models.CloudWorkload{RuntimeKind: kind, NativeID: id + noIdentitySuffix, Name: name,
				Region: region, Attrs: attrsJSON(attrs)})
			return
		}
		for _, ra := range runsAs {
			attrs := copyAttrs(base)
			attrs["identity_assignment"] = ra.assignment
			attrs["principal_id"] = ra.principalID
			w := models.CloudWorkload{RuntimeKind: kind, Name: name, Region: region}
			if ra.assignment == "system_assigned" {
				w.NativeID = id + "#system"
			} else {
				attrs["user_assigned_identity_id"] = ra.identityResource
				if ra.clientID != "" {
					attrs["client_id"] = ra.clientID
				}
				w.NativeID = id + "#" + ra.identityResource
			}
			w.Attrs = attrsJSON(attrs)
			if iid, ok := idMap[ra.principalID]; ok {
				w.IdentityID = &iid
			} else if iid, ok := byResource[ra.identityResource]; ok && ra.identityResource != "" {
				w.IdentityID = &iid
			} else {
				counters["foundry_unattributed"]++
			}
			rows = append(rows, w)
		}
	}

	for i, a := range accounts {
		d := details[i]
		counters["cognitive_accounts"]++
		// A single-service account with no identity runs as nothing and holds
		// no models or projects: not a workload, as before this surface.
		if !a.Foundry && !a.ServesModels() && a.Identity == nil {
			continue
		}
		base := map[string]interface{}{
			"resource_id": a.ID, "resource_kind": a.Kind, "foundry_kind": "account", "foundry": a.Foundry,
			"sku": a.SKU, "endpoint": a.Endpoint, "public_network_access": a.PublicNetworkAccess,
			"network_default_action": a.NetworkDefaultAction, "restrict_outbound_network": a.RestrictOutbound,
		}
		if a.LocalAuthEnabled != nil {
			base["local_auth_enabled"] = *a.LocalAuthEnabled
		}
		if a.ServesModels() {
			counters["model_accounts"]++
			if d.deploymentsRead {
				base["deployments"] = foundryDeploymentAttrs(d.deployments)
				counters["foundry_deployments"] += len(d.deployments)
			}
			if a.LocalAuthEnabled == nil || *a.LocalAuthEnabled {
				counters["model_accounts_api_keys_enabled"]++
			}
			if !strings.EqualFold(a.PublicNetworkAccess, "Disabled") && !strings.EqualFold(a.NetworkDefaultAction, "Deny") {
				counters["model_accounts_public_network"]++
			}
		}
		if a.Foundry {
			counters["foundry_accounts"]++
			if d.connectionsRead {
				base["connections"] = foundryConnectionAttrs(d.connections, counters)
			}
			if d.projectsRead {
				names := make([]string, 0, len(d.projects))
				for _, p := range d.projects {
					names = append(names, p.Name)
				}
				sort.Strings(names)
				base["projects"] = names
			}
		}
		if len(d.failed) > 0 {
			base["detail_incomplete"] = true
			base["detail_errors"] = d.failed
		}
		emit(models.AzureFoundryRuntimeKinds[0], a.ID, a.Name, a.Location, "#account", a.Identity, base)

		for _, p := range d.projects {
			counters["foundry_projects"]++
			pb := map[string]interface{}{
				"resource_id": p.ID, "resource_kind": "project", "foundry_kind": "project",
				"account_id": a.ID, "account_name": a.Name, "display_name": p.DisplayName, "is_default": p.IsDefault,
			}
			if conns, ok := d.projectConnections[p.ID]; ok {
				pb["connections"] = foundryConnectionAttrs(conns, counters)
			} else {
				pb["detail_incomplete"] = true
			}
			if pa, ok := d.projectApps[p.ID]; ok {
				if pa.unavailable {
					pb["agent_applications_unavailable"] = true
				} else {
					pb["agent_applications"] = foundryAgentAppAttrs(pa.apps, counters)
				}
			} else {
				pb["detail_incomplete"] = true
			}
			emit(models.AzureFoundryRuntimeKinds[1], p.ID, p.Name, p.Location, "#project", p.Identity, pb)
		}
	}

	hubName, hubProjects := map[string]string{}, map[string][]string{}
	for _, w := range mlw {
		if w.Kind == azure.MLKindHub {
			hubName[w.ID] = w.Name
		}
	}
	for _, w := range mlw {
		if w.Kind == azure.MLKindProject && w.HubResourceID != "" {
			hubProjects[w.HubResourceID] = append(hubProjects[w.HubResourceID], w.Name)
		}
	}
	for i, w := range mlw {
		counters["ml_workspaces"]++
		if !w.HubBased() {
			// A classic Machine Learning workspace: the compute it is, written
			// as the workloads surface wrote it before; one with no identity
			// runs as nothing.
			if w.Identity != nil {
				emit(models.AzureFoundryRuntimeKinds[2], w.ID, w.Name, w.Location, "", w.Identity,
					map[string]interface{}{"resource_id": w.ID, "resource_kind": w.Kind, "foundry_kind": "ml_workspace"})
			}
			continue
		}
		d := mlDetails[i]
		fk := "hub"
		base := map[string]interface{}{
			"resource_id": w.ID, "resource_kind": w.Kind, "display_name": w.FriendlyName,
			"public_network_access": w.PublicNetworkAccess, "isolation_mode": w.IsolationMode,
		}
		if w.Kind == azure.MLKindHub {
			counters["foundry_hubs"]++
			projects := append([]string{}, hubProjects[w.ID]...)
			sort.Strings(projects)
			base["projects"] = projects
			for k, v := range map[string]string{"storage_account": w.StorageAccount, "key_vault": w.KeyVault,
				"container_registry": w.ContainerRegistry, "application_insights": w.ApplicationInsights} {
				if v != "" {
					base[k] = v
				}
			}
		} else {
			fk = "hub_project"
			counters["foundry_hub_projects"]++
			base["hub_id"] = w.HubResourceID
			base["hub_name"] = hubName[w.HubResourceID]
		}
		base["foundry_kind"] = fk
		if d.connectionsRead {
			base["connections"] = foundryConnectionAttrs(d.connections, counters)
		}
		if len(d.failed) > 0 {
			base["detail_incomplete"] = true
			base["detail_errors"] = d.failed
		}
		emit(models.AzureFoundryRuntimeKinds[2], w.ID, w.Name, w.Location, "#"+fk, w.Identity, base)
	}

	if _, err := s.inventory.UpsertWorkloads(workspaceID, connectorID, generation, rows); err != nil {
		log.Printf("[azure] scan: could not record foundry resources for connector %s: %v", connectorID, err)
		surface.State, surface.Error = models.CloudCoveragePartial, "AuthSec could not record the Foundry resources it read"
		return surface
	}
	surface.Count = len(rows)
	switch {
	case failed > 0:
		surface = surfaceFailure(surface, firstErr, len(rows))
		surface.State = models.CloudCoveragePartial
		surface.Error = fmt.Sprintf("%d Foundry detail reads failed: %v", failed, firstErr)
	case capped || detailCapped:
		surface.State, surface.Error = models.CloudCoveragePartial, "stopped at the per-pass cap"
	}
	return surface
}

// foundryRunsAs lists the identities a Foundry resource runs as.
func foundryRunsAs(ref *azure.ManagedIdentityRef) []azureRunsAs {
	if ref == nil {
		return nil
	}
	var out []azureRunsAs
	if ref.PrincipalID != "" {
		out = append(out, azureRunsAs{assignment: "system_assigned", principalID: ref.PrincipalID})
	}
	ids := make([]string, 0, len(ref.UserAssigned))
	for id := range ref.UserAssigned {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		u := ref.UserAssigned[id]
		out = append(out, azureRunsAs{assignment: "user_assigned", principalID: u.PrincipalID, identityResource: id, clientID: u.ClientID})
	}
	return out
}

func copyAttrs(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m)+4)
	for k, v := range m {
		out[k] = v
	}
	return out
}

func foundryDeploymentAttrs(deps []azure.FoundryDeployment) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(deps))
	for _, d := range deps {
		out = append(out, map[string]interface{}{
			"name": d.Name, "model": d.Model, "model_version": d.ModelVersion, "model_format": d.ModelFormat,
			"publisher": d.ModelPublisher, "sku": d.SKU, "capacity": d.Capacity, "content_filter": d.ContentFilter,
			"version_upgrade": d.VersionUpgrade, "state": d.ProvisioningState,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["name"].(string) < out[j]["name"].(string) })
	return out
}

// foundryAgentAppAttrs is a project's published agents as recorded on its row:
// each Agent Application with the Entra blueprint and agent identity it names
// (by principal id, which the tenant pass records as Agent ID objects) and the
// deployments that run its agent versions.
func foundryAgentAppAttrs(apps []foundryAgentApp, counters map[string]int) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(apps))
	for _, fa := range apps {
		a := fa.app
		counters["foundry_agent_applications"]++
		m := map[string]interface{}{
			"name": a.Name, "display_name": a.DisplayName, "resource_id": a.ID,
			"provisioning_state": a.ProvisioningState, "authorization": a.Authorization,
			"agents": append([]string{}, a.Agents...),
		}
		if a.Description != "" {
			m["description"] = a.Description
		}
		if a.Enabled != nil {
			m["enabled"] = *a.Enabled
		}
		if a.BaseURL != "" {
			m["endpoint"] = safeTarget(a.BaseURL)
		}
		if b := a.Blueprint; b != nil {
			m["blueprint_principal_id"], m["blueprint_client_id"] = b.PrincipalID, b.ClientID
		}
		if ai := a.AgentIdentity; ai != nil {
			m["agent_identity_principal_id"], m["agent_identity_client_id"] = ai.PrincipalID, ai.ClientID
			m["agent_identity_kind"] = ai.Kind
		}
		if a.CreatedBy != "" {
			m["created_by"] = a.CreatedBy
		}
		if a.CreatedAt != nil {
			m["created_at"] = a.CreatedAt.UTC()
		}
		if a.ModifiedAt != nil {
			m["modified_at"] = a.ModifiedAt.UTC()
		}
		if fa.deploymentsRead {
			deps := make([]map[string]interface{}, 0, len(fa.deployments))
			for _, d := range fa.deployments {
				counters["foundry_agent_deployments"]++
				versions := make([]map[string]interface{}, 0, len(d.Agents))
				for _, v := range d.Agents {
					versions = append(versions, map[string]interface{}{"name": v.Name, "version": v.Version})
				}
				deps = append(deps, map[string]interface{}{
					"name": d.Name, "display_name": d.DisplayName, "type": d.Type, "state": d.State,
					"provisioning_state": d.ProvisioningState, "agents": versions, "protocols": append([]string{}, d.Protocols...),
				})
			}
			sort.Slice(deps, func(i, j int) bool { return deps[i]["name"].(string) < deps[j]["name"].(string) })
			m["deployments"] = deps
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["name"].(string) < out[j]["name"].(string) })
	return out
}

func foundryConnectionAttrs(conns []azure.FoundryConnection, counters map[string]int) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(conns))
	for _, c := range conns {
		counters["foundry_connections"]++
		if c.SecretBased() {
			counters["foundry_connections_secret_based"]++
		}
		m := map[string]interface{}{
			"name": c.Name, "category": c.Category, "auth_type": c.AuthType, "target": safeTarget(c.Target),
			"shared_to_all": c.SharedToAll, "uses_project_identity": c.UsesProjectIdentity, "secret_based": c.SecretBased(),
		}
		if c.TargetResourceID != "" {
			m["target_resource_id"] = c.TargetResourceID
		}
		if c.ExpiresAt != nil {
			m["expires_at"] = c.ExpiresAt.UTC()
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["name"].(string) < out[j]["name"].(string) })
	return out
}

// safeTarget keeps a connection target's scheme, host and path. A query
// string or user info can carry a SAS token or a password, so neither is
// stored.
func safeTarget(t string) string {
	t = strings.TrimSpace(t)
	u, err := url.Parse(t)
	if err != nil || u.Scheme == "" || u.Host == "" {
		if i := strings.IndexAny(t, "?#"); i >= 0 {
			t = t[:i]
		}
		if i := strings.LastIndex(t, "@"); i >= 0 {
			t = t[i+1:]
		}
		return t
	}
	u.User, u.RawQuery, u.Fragment, u.RawFragment = nil, "", "", ""
	return u.String()
}
