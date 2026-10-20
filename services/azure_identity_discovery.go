package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

/* azure_identity_discovery.go reads WHO exists and WHAT they hold:

     tenant pass (Microsoft Graph, AuthSec's app-only token)
       users, groups (+ direct members), app registrations, service principals
       (incl. managed identities)                    -> cloud_identity
       client secret / certificate METADATA         -> cloud_secret
       active Entra directory role memberships      -> cloud_permission plane=api
       API permissions, federated credentials, sign-in evidence, licences
       and guardrails                               (azure_access_discovery.go)

     subscription pass (ARM, AuthSec's app-only token, under Reader)
       resources (azure_discovery.go)               -> cloud_resource
       Azure RBAC role assignments                  -> cloud_permission plane=cloud

   Discovery runs in the background after Connect and Verify: a directory can
   hold far more objects than a 120-second request can page through. Progress
   and the outcome are the connector's coverage, which the connector list
   returns; status "running" means a pass is in flight.

   Same rules as the resource inventory: a surface that could not be fully
   read is recorded as such, and nothing is deleted unless every surface it
   depends on was read in full. */

const (
	// azureDiscoveryBudget bounds one background run (tenant + subscriptions).
	azureDiscoveryBudget = 20 * time.Minute
	// azureGroupMemberLimit caps how many groups have their members read in
	// one pass, and azureMemberIDLimit how many member ids one group stores.
	azureGroupMemberLimit = 2000
	azureMemberIDLimit    = 1000
	// azureSecretExpiringWindow is what "expiring soon" means in counters.
	azureSecretExpiringWindow = 30 * 24 * time.Hour
	// directoryReadersTemplateID is the one directory role that only reads.
	directoryReadersTemplateID = "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"
)

/* ---------------------------------- runner ---------------------------------- */

// azureScanTarget is one subscription connector to scan.
type azureScanTarget struct {
	ConnectorID    uuid.UUID
	SubscriptionID string
}

// azureDiscoveryRunning holds one in-flight run per (workspace, tenant), so a
// double click or a Verify during Connect's run does not start a second pass
// over the same directory. Process-local and only a fast path: between
// replicas, each pass is a cloud_scan_run row and uq_cloud_scan_run_live
// refuses a second live pass over the same connector (beginPass).
var azureDiscoveryRunning = struct {
	sync.Mutex
	keys map[string]bool
}{keys: map[string]bool{}}

// Discovery outcomes reported to callers.
const (
	AzureDiscoveryStarted        = "started"
	AzureDiscoveryAlreadyRunning = "already_running"
)

// resolveDiscoveryConfig is the credentials a tenant is read with: AuthSec's
// app, or the customer's own app from Vault. It fails closed: a tenant whose
// own-app credentials cannot be read is not read at all, never silently with
// AuthSec's credentials, which are not what the connection records.
func (s *AzureOnboardingService) resolveDiscoveryConfig(workspaceID uuid.UUID, tenantID string) (azure.AppConfig, error) {
	tc, err := s.connectors.GetByScope(workspaceID, models.CloudProviderAzure, tenantID)
	if err != nil || tc == nil {
		// No tenant connector (a subscription-only run): AuthSec's app.
		return s.cfg, nil
	}
	return s.resolveAppConfig(tc)
}

// startDiscovery runs the tenant pass (when tenantConnectorID is set) and then
// each subscription pass in the background, and returns at once. trigger is
// recorded on each pass's cloud_scan_run (AzureTrigger*).
func (s *AzureOnboardingService) startDiscovery(workspaceID uuid.UUID, tenantID string, tenantConnectorID *uuid.UUID, subs []azureScanTarget, trigger string) string {
	key := workspaceID.String() + "/" + tenantID
	azureDiscoveryRunning.Lock()
	if azureDiscoveryRunning.keys[key] {
		azureDiscoveryRunning.Unlock()
		return AzureDiscoveryAlreadyRunning
	}
	azureDiscoveryRunning.keys[key] = true
	azureDiscoveryRunning.Unlock()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[azure] discovery for tenant %s panicked: %v", tenantID, r)
			}
			azureDiscoveryRunning.Lock()
			delete(azureDiscoveryRunning.keys, key)
			azureDiscoveryRunning.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), azureDiscoveryBudget)
		defer cancel()

		cfg, err := s.resolveDiscoveryConfig(workspaceID, tenantID)
		if err != nil {
			log.Printf("[azure] discovery of tenant %s not started: its credentials could not be read: %v", tenantID, err)
			if tenantConnectorID != nil {
				if _, mErr := s.connectors.MarkError(workspaceID, *tenantConnectorID,
					"AuthSec could not read the stored credentials of your app, so this tenant was not read; "+
						"connect it again with your app's client secret", ConnErrCredentialInvalid); mErr != nil {
					log.Printf("[azure] could not record the credential failure on tenant %s: %v", tenantID, mErr)
				}
			}
			return
		}

		var tenantPass *azurePassResult
		if tenantConnectorID != nil {
			tenantPass = s.runTenantScan(ctx, workspaceID, *tenantConnectorID, tenantID, trigger, cfg)
		}
		var subPasses []*azurePassResult
		if len(subs) > 0 {
			armToken, err := s.api.AppToken(ctx, cfg, tenantID, azure.ScopeARMApp)
			if err != nil {
				logAzureError("arm app token for discovery", err)
			} else {
				// The Foundry data plane is a separate audience. A token is
				// issued without any role; the reads then say whether one is
				// assigned.
				foundryToken, ferr := s.api.AppToken(ctx, cfg, tenantID, azure.ScopeFoundry)
				if ferr != nil {
					logAzureError("foundry data-plane token", ferr)
					foundryToken = ""
				}
				for _, sub := range subs {
					if p := s.runSubscriptionScan(ctx, workspaceID, sub.ConnectorID, sub.SubscriptionID, armToken, foundryToken, trigger); p != nil {
						subPasses = append(subPasses, p)
					}
				}
			}
		}
		// Inference reads the tenant's AND the subscriptions' evidence (compute
		// an identity runs on comes from a subscription pass), so it waits for
		// every pass.
		if tenantPass != nil {
			agentsFrom := time.Now()
			inferredOK := s.logInferAgents(workspaceID, *tenantConnectorID, tenantID)
			declaredOK := s.logRegisterDeclaredAgents(workspaceID, *tenantConnectorID, tenantID)
			// Then close the agents neither step saw again.
			s.logRetireAzureAgents(workspaceID, *tenantConnectorID, tenantID, tenantPass.Coverage,
				azureSubscriptionsRead{wanted: len(subs), passes: subPasses, ids: azureTargetIDs(subs)}, agentsFrom, declaredOK, inferredOK)
			// Where each sign-in came from: needs the tenant's sign-ins and the
			// subscriptions' public addresses, so after every pass.
			s.logAttributeSignInIPs(ctx, workspaceID, *tenantConnectorID, tenantID)
		}
		s.projectGraph(ctx, workspaceID, tenantID, tenantPass, subPasses)
	}()
	return AzureDiscoveryStarted
}

/* ----------------------------------- passes ---------------------------------- */

const (
	// azureRunLease is how long a pass holds its connector without renewing;
	// azureRunHeartbeat how often it renews. A pass whose process stops is
	// abandoned by the next pass over the connector once the lease lapses.
	azureRunLease     = 3 * time.Minute
	azureRunHeartbeat = time.Minute
)

// azureRunOwner names this process on the runs it holds.
var azureRunOwner = func() string {
	host, _ := os.Hostname()
	return fmt.Sprintf("azure-discovery:%s:%d:%s", host, os.Getpid(), uuid.NewString()[:8])
}()

// azurePass is one pass over one connector, recorded as a cloud_scan_run and
// kept alive by a heartbeat until it finishes.
type azurePass struct {
	run  *models.CloudScanRun
	stop context.CancelFunc
	done chan struct{}
	// ctx is the pass's work context: cancelled when the pass loses its
	// lease, so a pass another one replaced stops reading and writing.
	ctx     context.Context
	release context.CancelFunc
}

// azurePassResult is a finished pass: what the graph projection needs to know
// which rows this pass confirmed and how much it read.
type azurePassResult struct {
	RunID       uuid.UUID
	ConnectorID uuid.UUID
	Generation  int
	Coverage    models.ScanCoverage
}

// beginPass records a running pass and starts its heartbeat.
// repositories.ErrScanAlreadyLive means another pass holds the connector.
func (s *AzureOnboardingService) beginPass(ctx context.Context, workspaceID, connectorID uuid.UUID, trigger string) (*azurePass, error) {
	run, err := s.inventory.BeginRun(workspaceID, connectorID, azureRunOwner, trigger, azureRunLease)
	if err != nil {
		return nil, err
	}
	hbCtx, stop := context.WithCancel(ctx)
	workCtx, lost := context.WithCancel(ctx)
	p := &azurePass{run: run, stop: stop, done: make(chan struct{}), ctx: workCtx, release: lost}
	go func() {
		defer close(p.done)
		t := time.NewTicker(azureRunHeartbeat)
		defer t.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-t.C:
				if err := s.inventory.RenewRun(run.ID, azureRunOwner, azureRunLease); err != nil {
					log.Printf("[azure] pass %s on connector %s lost its lease, stopping it: %v", run.ID, connectorID, err)
					lost()
					return
				}
			}
		}
	}()
	return p, nil
}

// finishPass stops the heartbeat and closes the run with the pass's coverage.
func (s *AzureOnboardingService) finishPass(p *azurePass, cov models.ScanCoverage) *azurePassResult {
	p.stop()
	<-p.done
	p.release()
	if err := s.inventory.FinishRun(p.run.ID, azureRunOwner, cov); err != nil {
		// Lease lost: a later pass abandoned this one. Its rows still carry this
		// generation, but no projection may treat it as the latest reading.
		log.Printf("[azure] pass %s could not be closed: %v", p.run.ID, err)
		return nil
	}
	return &azurePassResult{RunID: p.run.ID, ConnectorID: p.run.ConnectorID, Generation: p.run.Generation, Coverage: cov}
}

// startPassOrSkip begins a pass, logging and returning nil when it cannot.
func (s *AzureOnboardingService) startPassOrSkip(ctx context.Context, workspaceID, connectorID uuid.UUID, trigger, what string) *azurePass {
	p, err := s.beginPass(ctx, workspaceID, connectorID, trigger)
	switch {
	case errors.Is(err, repositories.ErrScanAlreadyLive):
		log.Printf("[azure] %s: connector %s already has a pass in flight; not starting another", what, connectorID)
		return nil
	case err != nil:
		log.Printf("[azure] %s: could not start a pass on connector %s: %v", what, connectorID, err)
		return nil
	}
	return p
}

/* -------------------------------- tenant pass -------------------------------- */

// runTenantScan reads the directory and records it under the tenant connector.
//
// It reads first and writes after: sign-in activity and app management
// policies decorate the identity rows, so they are read before any identity is
// written. Reconciliation is then decided per table, each by the surfaces that
// write it -- a guardrail read refused for want of Policy.Read.All must not
// stop a deleted user from leaving the inventory.
func (s *AzureOnboardingService) runTenantScan(ctx context.Context, workspaceID, connectorID uuid.UUID, tenantID, trigger string, cfg azure.AppConfig) *azurePassResult {
	pass := s.startPassOrSkip(ctx, workspaceID, connectorID, trigger, "tenant scan")
	if pass != nil {
		ctx = pass.ctx
	}
	if pass == nil {
		return nil
	}
	generation := pass.run.Generation
	started := time.Now()
	surfaceNames := []string{
		models.SurfaceEntraUsers, models.SurfaceEntraGroups, models.SurfaceEntraGroupMembers,
		models.SurfaceEntraApplications, models.SurfaceEntraServicePrincipals, models.SurfaceEntraDirectoryRoles,
		models.SurfaceEntraAppRoleAssignments, models.SurfaceEntraDelegatedGrants, models.SurfaceEntraFederatedCredentials,
		models.SurfaceEntraLicenses, models.SurfaceEntraSignInActivity, models.SurfaceEntraCredentialActivity,
		models.SurfaceEntraSignIns, models.SurfaceEntraAppManagementPolicies, models.SurfaceEntraConditionalAccess,
		models.SurfaceEntraAgentIdentities, models.SurfaceEntraAgentBlueprints,
		models.SurfaceEntraAgentBlueprintPrincipals, models.SurfaceEntraAgentUsers,
		models.SurfaceEntraOwners, models.SurfaceEntraAgentSponsors,
		models.SurfaceEntraAgentInheritance, models.SurfaceEntraAgentAudit, models.SurfaceEntraAgentRegistry,
		models.SurfaceEntraTeamsApps,
	}
	surfaces := map[string]models.SurfaceCoverage{}
	for _, n := range surfaceNames {
		surfaces[n] = models.SurfaceCoverage{State: models.CloudCoverageUnknown}
	}
	s.writeAzureCoverage(workspaceID, connectorID, generation, models.ScanCoverage{
		Generation: generation, Status: models.ScanStatusRunning, StartedAt: &started, Surfaces: surfaces,
	})

	counters := map[string]int{}
	finish := func() *azurePassResult {
		finished := time.Now()
		cov := models.ScanCoverage{
			Generation: generation, StartedAt: &started, FinishedAt: &finished,
			Surfaces: surfaces, Counters: counters,
		}
		cov.Status, cov.Error = scanStatusOf(surfaces)
		// Evidence needs the surfaces' final states, and the run's lease.
		s.recordEvidence(pass, models.CloudScopeTenant, cov, counters)
		s.writeAzureCoverage(workspaceID, connectorID, generation, cov)
		return s.finishPass(pass, cov)
	}
	markPartial := func(reason string, names ...string) {
		for _, n := range names {
			sc := surfaces[n]
			sc.State, sc.Error = models.CloudCoveragePartial, reason
			surfaces[n] = sc
		}
	}

	graphToken, err := s.api.AppToken(ctx, cfg, tenantID, azure.ScopeGraphApp)
	if err != nil {
		logAzureError("graph app token for discovery", err)
		for _, n := range surfaceNames {
			surfaces[n] = surfaceFailure(models.SurfaceCoverage{}, err, 0)
		}
		return finish()
	}

	/* ---- read ---- */

	users, err := s.api.ListUsers(ctx, graphToken)
	surfaces[models.SurfaceEntraUsers] = listSurface("GET /v1.0/users", len(users), err)
	groups, err := s.api.ListGroups(ctx, graphToken)
	surfaces[models.SurfaceEntraGroups] = listSurface("GET /v1.0/groups", len(groups), err)
	members, membersSurface := s.readGroupMembers(ctx, graphToken, groups)
	surfaces[models.SurfaceEntraGroupMembers] = membersSurface
	apps, err := s.api.ListApplications(ctx, graphToken)
	surfaces[models.SurfaceEntraApplications] = listSurface("GET /v1.0/applications", len(apps), err)
	sps, err := s.api.ListServicePrincipals(ctx, graphToken)
	surfaces[models.SurfaceEntraServicePrincipals] = listSurface("GET /v1.0/servicePrincipals", len(sps), err)
	// Microsoft Entra Agent ID: subtypes of the three listings above, merged
	// into them so the rest of the pass treats an agent as what it is built on.
	ungranted := s.ungrantedPermissions(workspaceID, connectorID)
	agents := s.readAgentObjects(ctx, graphToken, surfaces, ungranted)
	users, apps, sps = agents.mergeInto(users, apps, sps)
	// Who owns each app and service principal (azure_owners.go); each agent's
	// sponsors, what its blueprint lets it inherit, and what changed it
	// (azure_agent_details.go).
	owners := s.readOwners(ctx, graphToken, apps, sps, surfaces, counters)
	gov := s.readAgentDetails(ctx, graphToken, agents, surfaces, counters)
	trails, auditReadAt := s.readAgentAudit(ctx, graphToken, workspaceID, connectorID, agents, surfaces, counters)
	prevTrails := s.previousAgentAudit(workspaceID, connectorID)
	// The Microsoft 365 agent registry (azure_agent_registry.go). Unread, the
	// catalog the last pass stored still describes the agent identities.
	registry, registryRead := s.readAgentRegistry(ctx, graphToken, surfaces, counters, ungranted)
	if !registryRead {
		registry = s.tenantRegistry(workspaceID, connectorID)
	}
	registryByAgent := registryByIdentity(registry)
	// The organization's Teams apps with a bot (azure_agent_sources.go).
	teamsAgents, teamsRead := s.readTeamsAgents(ctx, graphToken, surfaces, counters, ungranted)

	licensing, sc := s.readLicensing(ctx, graphToken)
	surfaces[models.SurfaceEntraLicenses] = sc
	activity, sc := s.readSignInActivity(ctx, graphToken)
	surfaces[models.SurfaceEntraSignInActivity] = sc
	credActivity, sc := s.readCredentialActivity(ctx, graphToken)
	surfaces[models.SurfaceEntraCredentialActivity] = sc
	guardrails, appliesTo, amSurface, caSurface := s.readGuardrails(ctx, graphToken)
	surfaces[models.SurfaceEntraAppManagementPolicies] = amSurface
	surfaces[models.SurfaceEntraConditionalAccess] = caSurface

	/* ---- identities ---- */

	dir := azureDirectoryState{userEnabled: map[string]bool{}, spEnabled: map[string]bool{}, groups: map[string]bool{}}
	for _, u := range users {
		dir.userEnabled[strings.ToLower(u.ID)] = u.AccountEnabled == nil || *u.AccountEnabled
	}
	for _, g := range groups {
		dir.groups[strings.ToLower(g.ID)] = true
	}
	for _, sp := range sps {
		dir.spEnabled[strings.ToLower(sp.ID)] = sp.AccountEnabled == nil || *sp.AccountEnabled
	}
	decorate := func(ident *models.CloudIdentity) {
		owners.decorate(ident, dir)
		s.decorateAgent(ident, agents, gov, dir, trails, prevTrails)
		if e, ok := registryByAgent[ident.NativeID]; ok && ident.Kind == models.CloudIdentityEntraAgentIdentity {
			mergeAttrs(ident, map[string]interface{}{"registry": e})
		}
	}

	var identities []models.CloudIdentity
	for _, u := range users {
		ident := entraUserIdentity(u)
		agents.classifyUser(&ident, u, counters)
		decorate(&ident)
		identities = append(identities, ident)
		if ident.Kind == models.CloudIdentityEntraAgentUser {
			continue
		}
		counters["users"]++
		if strings.EqualFold(u.UserType, "Guest") {
			counters["guests"]++
		}
		if u.AccountEnabled != nil && !*u.AccountEnabled {
			counters["disabled_users"]++
		}
	}
	for _, g := range groups {
		identities = append(identities, entraGroupIdentity(g, members[strings.ToLower(g.ID)]))
		counters["groups"]++
	}
	for _, a := range apps {
		ident := entraApplicationIdentity(a)
		agents.classifyApplication(&ident, a, counters)
		if ids := appliesTo[strings.ToLower(a.ID)]; len(ids) > 0 {
			mergeAttrs(&ident, map[string]interface{}{"app_management_policy_ids": ids})
		}
		decorate(&ident)
		identities = append(identities, ident)
		counters["applications"]++
	}
	spByApp := make(map[string]string, len(sps))
	for _, sp := range sps {
		if sp.AppID != "" {
			spByApp[strings.ToLower(sp.AppID)] = strings.ToLower(sp.ID)
		}
		ident := entraServicePrincipalIdentity(sp)
		agents.classifyServicePrincipal(&ident, sp, counters)
		extra := map[string]interface{}{}
		if act, ok := activity[strings.ToLower(sp.AppID)]; ok {
			ident.LastUsedAt = act.Last
			extra["last_sign_in_at"] = act.Last
			extra["last_app_only_sign_in_at"] = act.AppOnly
			extra["last_delegated_sign_in_at"] = act.Delegated
		}
		if ids := appliesTo[strings.ToLower(sp.ID)]; len(ids) > 0 {
			extra["app_management_policy_ids"] = ids
		}
		if len(extra) > 0 {
			mergeAttrs(&ident, extra)
		}
		decorate(&ident)
		identities = append(identities, ident)
		switch {
		case ident.Kind == models.CloudIdentityEntraAgentIdentity:
			// Counted by the classification.
		case ident.Kind == models.CloudIdentityEntraManagedIdentity:
			counters["managed_identities"]++
		case azure.MicrosoftTenantIDs[strings.ToLower(sp.AppOwnerOrganizationID)]:
			counters["microsoft_service_principals"]++
		default:
			counters["service_principals"]++
		}
	}

	if _, err := s.inventory.UpsertIdentities(workspaceID, connectorID, generation, identities); err != nil {
		log.Printf("[azure] tenant scan: could not record identities for connector %s: %v", connectorID, err)
		markPartial("AuthSec could not record the directory objects it read", surfaceNames...)
		return finish()
	}
	objectIDs := make([]string, 0, len(identities))
	for _, i := range identities {
		objectIDs = append(objectIDs, i.NativeID)
	}
	idMap, err := s.inventory.IdentityIDs(workspaceID, objectIDs)
	if err != nil {
		log.Printf("[azure] tenant scan: could not resolve identities for connector %s: %v", connectorID, err)
		return finish()
	}

	/* ---- secrets ---- */

	secrets := entraSecrets(apps, sps, idMap, credActivity, counters)
	if _, err := s.inventory.UpsertSecrets(workspaceID, connectorID, generation, secrets); err != nil {
		log.Printf("[azure] tenant scan: could not record secrets for connector %s: %v", connectorID, err)
		markPartial("AuthSec could not record credential metadata",
			models.SurfaceEntraApplications, models.SurfaceEntraServicePrincipals)
	}

	/* ---- grants: directory roles and API permissions ---- */

	roleGrants, rolesSurface := s.readDirectoryRoles(ctx, graphToken, idMap, counters)
	surfaces[models.SurfaceEntraDirectoryRoles] = rolesSurface
	apiResources, apiGrants, appSurface, delSurface := s.readAPIPermissions(ctx, graphToken, tenantID, sps, idMap, counters)
	surfaces[models.SurfaceEntraAppRoleAssignments] = appSurface
	surfaces[models.SurfaceEntraDelegatedGrants] = delSurface
	// What each agent identity inherits from its blueprint's principal: in its
	// tokens, and shown nowhere else by Microsoft.
	apiGrants = append(apiGrants, gov.inheritedGrants(agents, apiGrants, sps, idMap, counters)...)

	grants := roleGrants
	if _, err := s.inventory.UpsertResources(workspaceID, connectorID, generation, apiResources); err != nil {
		log.Printf("[azure] tenant scan: could not record API permissions for connector %s: %v", connectorID, err)
		markPartial("AuthSec could not record the API permissions it read",
			models.SurfaceEntraAppRoleAssignments, models.SurfaceEntraDelegatedGrants)
	} else {
		natives := make([]string, 0, len(apiResources))
		for _, r := range apiResources {
			natives = append(natives, r.NativeID)
		}
		resIDs, err := s.inventory.ResourceIDs(workspaceID, natives)
		if err != nil {
			log.Printf("[azure] tenant scan: could not resolve API permissions for connector %s: %v", connectorID, err)
			resIDs = map[string]uuid.UUID{}
		}
		for _, g := range apiGrants {
			id, ok := resIDs[g.resourceNative]
			if !ok {
				counters["api_permissions_unrecorded"]++
				continue
			}
			p := g.perm
			p.ResourceID = &id
			grants = append(grants, p)
		}
		if counters["api_permissions_unrecorded"] > 0 {
			markPartial("AuthSec could not record some API permissions it read",
				models.SurfaceEntraAppRoleAssignments, models.SurfaceEntraDelegatedGrants)
		}
	}
	if _, err := s.inventory.UpsertPermissions(workspaceID, connectorID, generation, grants); err != nil {
		log.Printf("[azure] tenant scan: could not record grants for connector %s: %v", connectorID, err)
		markPartial("AuthSec could not record the grants it read", models.SurfaceEntraDirectoryRoles,
			models.SurfaceEntraAppRoleAssignments, models.SurfaceEntraDelegatedGrants)
	}

	/* ---- who may become an identity ---- */

	edges, ficSurface := s.readFederatedCredentials(ctx, graphToken, apps, spByApp, idMap, counters)
	surfaces[models.SurfaceEntraFederatedCredentials] = ficSurface
	// A blueprint's credentials act as its agents; an agent as its agent user.
	edges = append(edges, agents.agentAssumeEdges(spByApp, idMap, counters)...)
	// An owner can add a credential to what it owns, and so become it -- a
	// blueprint's owners become its agents.
	edges = append(edges, owners.edges(apps, sps, spByApp, idMap, counters)...)
	if _, err := s.inventory.UpsertAssumeEdges(workspaceID, connectorID, generation, edges); err != nil {
		log.Printf("[azure] tenant scan: could not record federated credentials for connector %s: %v", connectorID, err)
		markPartial("AuthSec could not record the federated credentials it read", models.SurfaceEntraFederatedCredentials)
	}

	/* ---- whether identities are used ---- */

	usage, usageSurface := s.readSignInUsage(ctx, graphToken, idMap, spByApp, counters)
	surfaces[models.SurfaceEntraSignIns] = usageSurface
	if _, err := s.inventory.UpsertUsage(workspaceID, connectorID, generation, usage); err != nil {
		log.Printf("[azure] tenant scan: could not record sign-in usage for connector %s: %v", connectorID, err)
		markPartial("AuthSec could not record the sign-in usage it read", models.SurfaceEntraSignIns)
	} else {
		s.markAppPermissionsExercised(workspaceID, connectorID, counters)
	}

	/* ---- licences and guardrails, on the tenant connector ---- */

	patch := map[string]interface{}{"guardrails": guardrails}
	if auditReadAt != nil {
		patch["agent_audit_read_at"] = auditReadAt.UTC()
	}
	if registryRead {
		patch["agent_registry"] = registry
	}
	if teamsRead {
		patch["teams_agents"] = teamsAgents
	}
	if licensing != nil {
		// What the sign-in read proved outranks what the plan list implies.
		switch usageSurface.ErrorCode {
		case "license_required":
			no := false
			licensing.SignInLogsAvailable = &no
		default:
			if usageSurface.State == models.CloudCoverageReached || usageSurface.State == models.CloudCoveragePartial {
				yes := true
				licensing.SignInLogsAvailable = &yes
			}
		}
		patch["licensing"] = licensing
	}
	if err := s.inventory.MergeAttrs(workspaceID, connectorID, generation, patch); err != nil {
		log.Printf("[azure] tenant scan: could not record licences and guardrails for connector %s: %v", connectorID, err)
	}

	/* ---- reconcile, table by table ---- */

	reached := func(names ...string) bool {
		for _, n := range names {
			if surfaces[n].State != models.CloudCoverageReached {
				return false
			}
		}
		return true
	}
	parts := repositories.AzureReconcileParts{
		Identities: reached(models.SurfaceEntraUsers, models.SurfaceEntraGroups,
			models.SurfaceEntraApplications, models.SurfaceEntraServicePrincipals),
		Secrets: reached(models.SurfaceEntraApplications, models.SurfaceEntraServicePrincipals),
		Permissions: reached(models.SurfaceEntraDirectoryRoles,
			models.SurfaceEntraAppRoleAssignments, models.SurfaceEntraDelegatedGrants,
			models.SurfaceEntraAgentInheritance),
		Resources: reached(models.SurfaceEntraServicePrincipals,
			models.SurfaceEntraAppRoleAssignments, models.SurfaceEntraDelegatedGrants),
		Edges: reached(models.SurfaceEntraApplications, models.SurfaceEntraFederatedCredentials,
			models.SurfaceEntraOwners),
		// What only Agent ID listed is not aged out by a pass that could not
		// read it -- not granted is a reading we lack, not an absence.
		KeepAgentListed: !reached(models.SurfaceEntraAgentIdentities, models.SurfaceEntraAgentBlueprints,
			models.SurfaceEntraAgentBlueprintPrincipals, models.SurfaceEntraAgentUsers),
		// Usage is never aged out by generation: the sign-in read covers a
		// week, and a resource last used a month ago was still last used then.
		// A usage row leaves with its identity.
	}
	counts, err := s.inventory.Reconcile(workspaceID, connectorID, generation, parts)
	if err != nil {
		log.Printf("[azure] tenant scan: reconciliation failed for connector %s: %v", connectorID, err)
	} else {
		counters["identities_removed"] = int(counts.Identities)
		counters["secrets_removed"] = int(counts.Secrets)
		counters["grants_removed"] = int(counts.Permissions)
		counters["api_permissions_removed"] = int(counts.Resources)
		counters["federated_credentials_removed"] = int(counts.Edges)
	}
	return finish()
}

// mergeAttrs adds keys to an identity's attrs.
func mergeAttrs(ident *models.CloudIdentity, extra map[string]interface{}) {
	m := map[string]interface{}{}
	if len(ident.Attrs) > 0 {
		_ = json.Unmarshal(ident.Attrs, &m)
	}
	for k, v := range extra {
		m[k] = v
	}
	ident.Attrs = attrsJSON(m)
}

// listSurface turns one directory listing's outcome into its coverage.
func listSurface(api string, read int, err error) models.SurfaceCoverage {
	sc := models.SurfaceCoverage{State: models.CloudCoverageReached, API: api, Count: read}
	if err == nil {
		return sc
	}
	logAzureError(api, err)
	if errors.Is(err, azure.ErrPageLimit) {
		sc.State = models.CloudCoveragePartial
		sc.Error = "stopped at the listing page limit"
		return sc
	}
	return surfaceFailure(sc, err, read)
}

// readGroupMembers reads each group's direct members, a few groups at a time.
func (s *AzureOnboardingService) readGroupMembers(ctx context.Context, graphToken string, groups []azure.GraphGroup) (map[string][]string, models.SurfaceCoverage) {
	surface := models.SurfaceCoverage{State: models.CloudCoverageReached, API: "GET /v1.0/groups/{id}/members"}
	out := make(map[string][]string, len(groups))
	limit := len(groups)
	if limit > azureGroupMemberLimit {
		limit = azureGroupMemberLimit
	}
	var mu sync.Mutex
	failed := 0
	var firstErr error
	forEachLimited(limit, azureAssignConcurrency, func(i int) {
		g := groups[i]
		m, err := s.api.ListGroupMembers(ctx, graphToken, g.ID)
		mu.Lock()
		defer mu.Unlock()
		if err != nil && !errors.Is(err, azure.ErrPageLimit) {
			failed++
			if firstErr == nil {
				firstErr = err
			}
			return
		}
		ids := make([]string, 0, len(m))
		for _, o := range m {
			ids = append(ids, strings.ToLower(o.ID))
		}
		out[strings.ToLower(g.ID)] = ids
	})
	surface.Count = len(out)
	switch {
	case failed > 0:
		surface = surfaceFailure(surface, firstErr, len(out))
		surface.State = models.CloudCoveragePartial
		surface.Error = "members of some groups could not be read: " + firstErr.Error()
	case limit < len(groups):
		surface.State = models.CloudCoveragePartial
		surface.Error = "members were read for the first 2000 groups only"
	}
	return out, surface
}

// readDirectoryRoles turns active Microsoft Entra role assignments into
// grants: built-in and custom roles, each with the actions its definition
// allows, and its scope -- the whole tenant, one administrative unit, or one
// application or service principal (a scoped Application Administrator can
// add a credential to that one app, and so become it).
func (s *AzureOnboardingService) readDirectoryRoles(ctx context.Context, graphToken string, idMap map[string]uuid.UUID, counters map[string]int) ([]models.CloudPermission, models.SurfaceCoverage) {
	surface := models.SurfaceCoverage{State: models.CloudCoverageReached,
		API: "GET /v1.0/roleManagement/directory/roleAssignments, /roleDefinitions"}
	defs, err := s.api.ListDirectoryRoleDefinitions(ctx, graphToken)
	if err != nil {
		logAzureError("list directory role definitions", err)
		return nil, surfaceFailure(surface, err, 0)
	}
	byID := make(map[string]azure.DirectoryRoleDefinition, len(defs))
	for _, d := range defs {
		byID[strings.ToLower(d.ID)] = d
	}
	assignments, err := s.api.ListDirectoryRoleAssignments(ctx, graphToken)
	if err != nil {
		logAzureError("list directory role assignments", err)
		return nil, surfaceFailure(surface, err, 0)
	}
	var grants []models.CloudPermission
	for _, a := range assignments {
		identityID, ok := idMap[strings.ToLower(a.PrincipalID)]
		if !ok {
			counters["directory_role_members_unresolved"]++
			continue
		}
		def, known := byID[strings.ToLower(a.RoleDefinitionID)]
		template := strings.ToLower(a.RoleDefinitionID)
		if known && def.TemplateID != "" {
			template = strings.ToLower(def.TemplateID)
		}
		roleName := def.DisplayName
		if roleName == "" {
			roleName = "Microsoft Entra role " + template
		}
		actions := directoryRoleActions(def)
		if len(actions) == 0 {
			// A definition not read names the role by its template, so the
			// grant stays exact.
			actions = []string{"microsoft.directory/roleTemplates/" + template}
		}
		sensitivity := directoryRoleSensitivity(template, def, actions)
		g := models.CloudPermission{
			IdentityID:      identityID,
			Plane:           "api",
			Effect:          "allow",
			RoleName:        &roleName,
			Actions:         pq.StringArray(actions),
			ConstraintState: "unconstrained",
			ScopeKind:       "account_wide",
			Derivation:      "granted",
			Sensitivity:     sensitivity,
			NativeID:        "roleManagement/directory/roleAssignments/" + strings.ToLower(a.ID),
		}
		if scope := directoryRoleScope(a); scope != nil {
			// Scoped to an administrative unit or one object: it does not reach
			// the whole tenant. The scope is stored as the condition on it.
			raw, _ := json.Marshal(scope)
			cond := string(raw)
			g.ScopeKind = "prefix"
			g.ConstraintState = models.ConstraintConditional
			g.Condition = &cond
			counters["directory_role_assignments_scoped"]++
		}
		if known && !def.IsBuiltIn {
			counters["directory_role_assignments_custom"]++
		}
		grants = append(grants, g)
		counters["directory_role_assignments"]++
		if sensitivity == models.SensitivityHigh {
			counters["privileged_role_assignments"]++
		}
	}
	surface.Count = len(grants)
	return grants, surface
}

// directoryRoleActions is every action a role definition allows, sorted.
func directoryRoleActions(def azure.DirectoryRoleDefinition) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range def.RolePermissions {
		for _, a := range p.AllowedResourceActions {
			a = strings.TrimSpace(a)
			if a != "" && !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	sort.Strings(out)
	return out
}

// directoryRoleSensitivity: Microsoft's privileged built-in roles are high,
// Directory Readers low. A custom role is high when it can change credentials,
// role assignments or every property of an object -- what makes a built-in
// role privileged -- and medium otherwise.
func directoryRoleSensitivity(template string, def azure.DirectoryRoleDefinition, actions []string) string {
	if _, ok := azure.PrivilegedDirectoryRoleTemplateIDs[template]; ok {
		return models.SensitivityHigh
	}
	if template == directoryReadersTemplateID {
		return models.SensitivityLow
	}
	if def.IsBuiltIn {
		return models.SensitivityMedium
	}
	for _, a := range actions {
		l := strings.ToLower(a)
		if strings.Contains(l, "/credentials/update") || strings.Contains(l, "/allproperties/alltasks") ||
			strings.Contains(l, "roleassignments/") || strings.HasSuffix(l, "/alltasks") {
			return models.SensitivityHigh
		}
	}
	return models.SensitivityMedium
}

// directoryRoleScope is the scope of a role assignment narrower than the
// tenant, or nil for a tenant-wide one.
func directoryRoleScope(a azure.DirectoryRoleAssignment) map[string]string {
	dir := strings.TrimSpace(a.DirectoryScopeID)
	app := strings.TrimSpace(a.AppScopeID)
	if (dir == "" || dir == "/") && (app == "" || app == "/") {
		return nil
	}
	out := map[string]string{}
	switch {
	case strings.HasPrefix(strings.ToLower(dir), "/administrativeunits/"):
		out["scope_kind"] = "administrative_unit"
		out["directory_scope_id"] = dir
	case dir != "" && dir != "/":
		out["scope_kind"] = "directory_object"
		out["directory_scope_id"] = dir
	}
	if app != "" && app != "/" {
		out["app_scope_id"] = app
		if out["scope_kind"] == "" {
			out["scope_kind"] = "application"
		}
	}
	return out
}

/* ---------------------------- subscription: RBAC ----------------------------- */

// collectRoleAssignments reads every role assignment that applies to the
// subscription and records it as a grant held by its principal.
func (s *AzureOnboardingService) collectRoleAssignments(ctx context.Context, workspaceID, connectorID uuid.UUID, generation int, subscriptionID, armToken string, counters map[string]int, containers azureContainers) models.SurfaceCoverage {
	surface := models.SurfaceCoverage{State: models.CloudCoverageReached, API: "Microsoft.Authorization/roleAssignments"}
	defs, err := s.api.ListRoleDefinitions(ctx, armToken, subscriptionID)
	if err != nil && !errors.Is(err, azure.ErrPageLimit) {
		logAzureError("list role definitions", err)
		return surfaceFailure(surface, err, 0)
	}
	defByID := make(map[string]azure.RoleDefinition, len(defs))
	for _, d := range defs {
		defByID[azure.GUIDSuffix(d.ID)] = d
	}

	assignments, err := s.api.ListRoleAssignments(ctx, armToken, subscriptionID)
	pageLimited := errors.Is(err, azure.ErrPageLimit)
	if err != nil && !pageLimited {
		logAzureError("list role assignments", err)
		return surfaceFailure(surface, err, 0)
	}
	counters["role_assignments_seen"] = len(assignments)

	subScope := azure.SubscriptionScope(subscriptionID)
	var principals, resourceScopes []string
	for _, ra := range assignments {
		principals = append(principals, strings.ToLower(ra.Properties.PrincipalID))
		if kind, sc := azureScopeKind(ra.Properties.Scope, subScope); kind == "resource" {
			resourceScopes = append(resourceScopes, sc)
		}
	}
	idMap, err := s.inventory.IdentityIDs(workspaceID, principals)
	if err != nil {
		return surfaceFailure(surface, err, 0)
	}
	resMap, err := s.inventory.ResourceIDs(workspaceID, resourceScopes)
	if err != nil {
		return surfaceFailure(surface, err, 0)
	}

	rows := make([]models.CloudPermission, 0, len(assignments))
	for _, ra := range assignments {
		identityID, ok := idMap[strings.ToLower(ra.Properties.PrincipalID)]
		if !ok {
			// A principal AuthSec has not read: deleted, from another tenant,
			// or the tenant pass has not run yet. Counted, never invented.
			counters["role_assignments_unresolved"]++
			continue
		}
		g := azureRoleAssignmentGrant(ra, defByID, identityID, subScope, resMap)
		// What a role reaches in production is worth one level more than the
		// same role in a dev subscription (PRD D3: scopes are high when prod).
		if kind, sc := azureScopeKind(ra.Properties.Scope, subScope); containers.prodScope(kind, sc, subScope) {
			g.Sensitivity = raiseForProduction(g.Sensitivity)
			counters["production_role_assignments"]++
		}
		rows = append(rows, g)
		if g.Sensitivity == models.SensitivityHigh {
			counters["privileged_role_assignments"]++
		}
	}
	if _, err := s.inventory.UpsertPermissions(workspaceID, connectorID, generation, rows); err != nil {
		log.Printf("[azure] scan: could not record role assignments for connector %s: %v", connectorID, err)
		surface.State, surface.Error = models.CloudCoveragePartial, "AuthSec could not record the role assignments it read"
		return surface
	}
	surface.Count = len(rows)
	if pageLimited {
		surface.State, surface.Error = models.CloudCoveragePartial, "stopped at the listing page limit"
	}
	return surface
}

// azureScopeKind classifies an assignment scope relative to the subscription:
// account_wide (the subscription, or a management group / root above it),
// prefix (a resource group) or resource. Returns the lowercased scope.
func azureScopeKind(scope, subScope string) (string, string) {
	sc := strings.ToLower(strings.TrimRight(scope, "/"))
	if sc == subScope || !strings.HasPrefix(sc, subScope+"/") {
		return "account_wide", sc
	}
	parts := strings.Split(strings.TrimPrefix(sc, subScope+"/"), "/")
	if len(parts) == 2 && parts[0] == "resourcegroups" {
		return "prefix", sc
	}
	return "resource", sc
}

// azureRoleAssignmentGrant maps one role assignment to a cloud_permission row.
func azureRoleAssignmentGrant(ra azure.RoleAssignment, defs map[string]azure.RoleDefinition, identityID uuid.UUID, subScope string, resMap map[string]uuid.UUID) models.CloudPermission {
	roleGUID := azure.GUIDSuffix(ra.Properties.RoleDefinitionID)
	def, known := defs[roleGUID]
	roleName := roleGUID
	var actions, notActions []string
	if known {
		roleName = def.Properties.RoleName
		for _, p := range def.Properties.Permissions {
			actions = append(actions, p.Actions...)
			actions = append(actions, p.DataActions...)
			notActions = append(notActions, p.NotActions...)
			notActions = append(notActions, p.NotDataActions...)
		}
	}
	if len(actions) == 0 && len(notActions) == 0 {
		actions = []string{"Microsoft.Authorization/roleDefinitions/" + roleGUID}
	}

	g := models.CloudPermission{
		IdentityID: identityID,
		Plane:      "cloud",
		Effect:     "allow",
		RoleName:   &roleName,
		Actions:    pq.StringArray(actions),
		Derivation: "granted",
		NativeID:   strings.ToLower(ra.ID),
	}
	if len(notActions) > 0 {
		g.NotActions = pq.StringArray(notActions)
	}

	switch {
	case ra.Properties.Condition != "":
		cond, _ := json.Marshal(map[string]string{"expression": ra.Properties.Condition})
		c := string(cond)
		g.Condition = &c
		g.ConstraintState = "conditional"
	case len(notActions) > 0:
		g.ConstraintState = "negated"
	default:
		g.ConstraintState = "unconstrained"
	}

	kind, sc := azureScopeKind(ra.Properties.Scope, subScope)
	if kind == "account_wide" && sc != subScope {
		// Assigned ABOVE the subscription (a management group or the root),
		// so every subscription below it lists the same assignment. Keyed by
		// its id alone, the one row would pass from subscription to
		// subscription on every run -- each pass taking it from the last -- and
		// each subscription's reconciliation would end what the other just
		// confirmed. Each subscription keeps its own copy: "applies here".
		g.NativeID += "#" + strings.TrimPrefix(subScope, "/subscriptions/")
	}
	if kind == "resource" {
		if rid, ok := resMap[sc]; ok {
			g.ResourceID = &rid
		} else {
			// A child resource or a type Resource Graph does not list: the
			// grant is real, but there is no row to point at.
			kind = "prefix"
		}
	}
	g.ScopeKind = kind

	_, grantsAccess := azure.AccessGrantingRoleIDs[roleGUID]
	perms := []azure.Permission{{Actions: actions, NotActions: notActions}}
	switch {
	case grantsAccess || azure.AllowsAction(perms, azure.RoleAssignmentWriteAction):
		g.Sensitivity = models.SensitivityHigh
	case roleGUID == azure.ContributorRoleID || azureWrites(actions):
		g.Sensitivity = models.SensitivityMedium
	default:
		g.Sensitivity = models.SensitivityLow
	}
	return g
}

// azureWrites reports whether any action can change something.
func azureWrites(actions []string) bool {
	for _, a := range actions {
		l := strings.ToLower(a)
		if l == "*" || strings.HasSuffix(l, "/write") || strings.HasSuffix(l, "/delete") || strings.HasSuffix(l, "/action") || strings.HasSuffix(l, "/*") {
			return true
		}
	}
	return false
}

/* ------------------------------ row builders --------------------------------- */

func boolOr(b *bool, fallback bool) bool {
	if b == nil {
		return fallback
	}
	return *b
}

func attrsJSON(m map[string]interface{}) json.RawMessage {
	raw, err := json.Marshal(m)
	if err != nil {
		return json.RawMessage("{}")
	}
	return raw
}

func entraUserIdentity(u azure.GraphUser) models.CloudIdentity {
	return models.CloudIdentity{
		Kind:              models.CloudIdentityEntraUser,
		NativeID:          strings.ToLower(u.ID),
		Name:              firstNonEmpty(u.DisplayName, u.UserPrincipalName, u.ID),
		ProviderCreatedAt: u.CreatedDateTime,
		Enabled:           boolOr(u.AccountEnabled, true),
		Attrs: attrsJSON(map[string]interface{}{
			"user_principal_name": u.UserPrincipalName,
			"mail":                u.Mail,
			"user_type":           u.UserType,
			"external_user_state": u.ExternalUserState,
		}),
	}
}

func entraGroupIdentity(g azure.GraphGroup, memberIDs []string) models.CloudIdentity {
	truncated := false
	count := len(memberIDs)
	if len(memberIDs) > azureMemberIDLimit {
		memberIDs, truncated = memberIDs[:azureMemberIDLimit], true
	}
	return models.CloudIdentity{
		Kind:              models.CloudIdentityEntraGroup,
		NativeID:          strings.ToLower(g.ID),
		Name:              firstNonEmpty(g.DisplayName, g.ID),
		ProviderCreatedAt: g.CreatedDateTime,
		Enabled:           true,
		Attrs: attrsJSON(map[string]interface{}{
			"description":       g.Description,
			"security_enabled":  g.SecurityEnabled,
			"mail_enabled":      g.MailEnabled,
			"group_types":       g.GroupTypes,
			"role_assignable":   boolOr(g.IsAssignableToRole, false),
			"member_count":      count,
			"member_ids":        memberIDs,
			"members_truncated": truncated,
		}),
	}
}

func entraApplicationIdentity(a azure.GraphApplication) models.CloudIdentity {
	return models.CloudIdentity{
		Kind:              models.CloudIdentityEntraApplication,
		NativeID:          strings.ToLower(a.ID),
		Name:              firstNonEmpty(a.DisplayName, a.AppID),
		ProviderCreatedAt: a.CreatedDateTime,
		Enabled:           true,
		Attrs: attrsJSON(map[string]interface{}{
			"app_id":            strings.ToLower(a.AppID),
			"sign_in_audience":  a.SignInAudience,
			"secret_count":      len(a.PasswordCredentials),
			"certificate_count": len(a.KeyCredentials),
		}),
	}
}

func entraServicePrincipalIdentity(sp azure.ServicePrincipal) models.CloudIdentity {
	attrs := map[string]interface{}{
		"app_id":                 strings.ToLower(sp.AppID),
		"service_principal_type": sp.ServicePrincipalType,
		"app_owner_tenant_id":    strings.ToLower(sp.AppOwnerOrganizationID),
		"microsoft_first_party":  azure.MicrosoftTenantIDs[strings.ToLower(sp.AppOwnerOrganizationID)],
	}
	kind := models.CloudIdentityEntraServicePrincipal
	if strings.EqualFold(sp.ServicePrincipalType, "ManagedIdentity") {
		kind = models.CloudIdentityEntraManagedIdentity
		// alternativeNames holds "isExplicit=True|False" and the ARM id of the
		// resource: the identity itself (user-assigned, explicit) or the
		// resource it belongs to (system-assigned).
		assignment := "system_assigned"
		for _, n := range sp.AlternativeNames {
			switch {
			case strings.EqualFold(n, "isExplicit=True"):
				assignment = "user_assigned"
			case strings.HasPrefix(strings.ToLower(n), "/subscriptions/"):
				attrs["managed_identity_resource"] = strings.ToLower(n)
			}
		}
		attrs["managed_identity_assignment"] = assignment
	}
	return models.CloudIdentity{
		Kind:     kind,
		NativeID: strings.ToLower(sp.ID),
		Name:     firstNonEmpty(sp.DisplayName, sp.AppID),
		Enabled:  boolOr(sp.AccountEnabled, true),
		Attrs:    attrsJSON(attrs),
	}
}

// entraSecrets turns the credential metadata of app registrations and service
// principals into cloud_secret rows.
//
// lastUsed is per-credential sign-in activity keyed "<owner>/<key id>"; nil
// when it was not read, which leaves last_used_at unknown.
func entraSecrets(apps []azure.GraphApplication, sps []azure.ServicePrincipal, idMap map[string]uuid.UUID, lastUsed map[string]*time.Time, counters map[string]int) []models.CloudSecret {
	now := time.Now()
	var out []models.CloudSecret
	seen := map[string]bool{}
	add := func(ownerID, ownerKind, kind string, c azure.Credential) {
		identityID, ok := idMap[strings.ToLower(ownerID)]
		if !ok || c.KeyID == "" {
			return
		}
		// One keyId can appear more than once on an owner: a SAML signing
		// certificate is listed as a "Sign" and a "Verify" key, and again as a
		// password credential. Kind and usage keep those apart; an exact
		// repeat is the same credential and is recorded once.
		nativeID := strings.ToLower(ownerID) + "/" + kind + "/" + strings.ToLower(c.KeyID)
		if c.Usage != "" {
			nativeID += "/" + strings.ToLower(c.Usage)
		}
		if seen[nativeID] {
			return
		}
		seen[nativeID] = true
		status := "active"
		if c.EndDateTime != nil && c.EndDateTime.Before(now) {
			status = "inactive"
			counters["secrets_expired"]++
		} else if c.EndDateTime != nil && c.EndDateTime.Before(now.Add(azureSecretExpiringWindow)) {
			counters["secrets_expiring_30d"]++
		}
		counters["secrets"]++
		used := lastUsed[strings.ToLower(ownerID)+"/"+strings.ToLower(c.KeyID)]
		if used != nil {
			counters["secrets_with_sign_in"]++
		}
		out = append(out, models.CloudSecret{
			IdentityID:        identityID,
			Kind:              kind,
			NativeID:          nativeID,
			ProviderCreatedAt: c.StartDateTime,
			ExpiresAt:         c.EndDateTime,
			LastUsedAt:        used,
			Status:            status,
			Attrs: attrsJSON(map[string]interface{}{
				"display_name": c.DisplayName,
				"owner_kind":   ownerKind,
				"key_id":       strings.ToLower(c.KeyID),
				"type":         c.Type,
				"usage":        c.Usage,
			}),
		})
	}
	for _, a := range apps {
		for _, c := range a.PasswordCredentials {
			add(a.ID, models.CloudIdentityEntraApplication, models.CloudSecretEntraClientSecret, c)
		}
		for _, c := range a.KeyCredentials {
			add(a.ID, models.CloudIdentityEntraApplication, models.CloudSecretEntraCertificate, c)
		}
	}
	for _, sp := range sps {
		for _, c := range sp.PasswordCredentials {
			add(sp.ID, models.CloudIdentityEntraServicePrincipal, models.CloudSecretEntraClientSecret, c)
		}
		for _, c := range sp.KeyCredentials {
			add(sp.ID, models.CloudIdentityEntraServicePrincipal, models.CloudSecretEntraCertificate, c)
		}
	}
	return out
}

// azureTargetIDs is the run's subscription ids, lowercased.
func azureTargetIDs(subs []azureScanTarget) map[string]bool {
	out := make(map[string]bool, len(subs))
	for _, t := range subs {
		out[strings.ToLower(t.SubscriptionID)] = true
	}
	return out
}
