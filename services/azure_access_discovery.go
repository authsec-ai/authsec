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
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

/* azure_access_discovery.go is the tenant pass's second half: not WHO exists
   (azure_identity_discovery.go) but what each identity may call, who may
   become it, whether it is used, and what the tenant itself forbids.

     API permissions        app role assignments + delegated grants
                            -> cloud_resource (one row per permission an API
                               exposes) + cloud_permission plane=api
     federated credentials  -> cloud_assume_edge (mechanism oidc_federation)
     sign-in evidence       per-app and per-credential last sign-in
                            -> cloud_identity.last_used_at, cloud_secret.last_used_at
                            service principal / managed identity sign-ins,
                            aggregated per identity per resource
                            -> cloud_usage source=entra_sign_in
     licences, guardrails   -> the tenant connector's attrs

   Everything is a read with AuthSec's app-only Graph token. Sign-in evidence
   needs Entra ID P1/P2 in the customer's tenant; without it the surfaces are
   recorded unsupported (Microsoft does not offer the data), never denied.
   Guardrails need Policy.Read.All, which a tenant that consented before
   AuthSec asked for it does not have: those surfaces are recorded denied
   and nothing else is held back by them. */

const (
	// azureSignInWindow is how far back the sign-in log is read each pass.
	// Usage rows keep the most recent sign-in ever seen (GREATEST on upsert),
	// so the window bounds the read, not the evidence.
	azureSignInWindow = 7 * 24 * time.Hour
	// azureSignInMaxPages caps one event type's read at 20,000 sign-ins, newest
	// first; beyond it the surface is partial and says so.
	azureSignInMaxPages = 20
	// azureUsageIPLimit caps how many distinct source addresses one usage row
	// keeps.
	azureUsageIPLimit = 10
	// cognitiveServicesAppID is the resource Azure OpenAI and every other
	// Azure AI service issues tokens for (audience cognitiveservices.azure.com).
	cognitiveServicesAppID = "7d312290-28c8-473c-a0ed-8e53749b6d6d"
)

/* --------------------------------- licences --------------------------------- */

// readLicensing reads the tenant's licences and what they unlock.
func (s *AzureOnboardingService) readLicensing(ctx context.Context, graphToken string) (*models.AzureLicensing, models.SurfaceCoverage) {
	surface := models.SurfaceCoverage{State: models.CloudCoverageReached, API: "GET /v1.0/subscribedSkus"}
	skus, err := s.api.ListSubscribedSkus(ctx, graphToken)
	if err != nil {
		logAzureError("list subscribed skus", err)
		return nil, surfaceFailure(surface, err, 0)
	}
	now := time.Now()
	lic := &models.AzureLicensing{SKUs: []string{}, ReadAt: &now}
	for _, sku := range skus {
		// Warning is a licence in its grace period: still in force.
		if !strings.EqualFold(sku.CapabilityStatus, "Enabled") && !strings.EqualFold(sku.CapabilityStatus, "Warning") {
			continue
		}
		lic.SKUs = append(lic.SKUs, sku.SkuPartNumber)
		if strings.Contains(strings.ToUpper(sku.SkuPartNumber), "WORKLOAD_IDENTIT") {
			lic.WorkloadIDPremium = true
		}
		for _, p := range sku.ServicePlans {
			if !strings.EqualFold(p.ProvisioningStatus, "Success") {
				continue
			}
			switch name := strings.ToUpper(p.ServicePlanName); {
			case name == "AAD_PREMIUM_P2":
				lic.EntraIDP1, lic.EntraIDP2 = true, true
			case name == "AAD_PREMIUM":
				lic.EntraIDP1 = true
			case strings.Contains(name, "WRKLDID"):
				lic.WorkloadIDPremium = true
			}
		}
	}
	sort.Strings(lic.SKUs)
	surface.Count = len(lic.SKUs)
	return lic, surface
}

/* ------------------------------ sign-in evidence ------------------------------ */

// signInSurfaceFailure records a sign-in read that did not complete. A refusal
// for licensing is unsupported -- the tenant does not have the data -- so it
// neither reads as a missing permission nor blocks reconciliation.
func signInSurfaceFailure(surface models.SurfaceCoverage, err error, read int) models.SurfaceCoverage {
	if azure.IsLicenseRequired(err) {
		surface.State = models.CloudCoverageUnsupported
		surface.Error = "the tenant's Entra ID licence does not include sign-in data (needs P1 or P2): " + err.Error()
		surface.ErrorCode = "license_required"
		return surface
	}
	return surfaceFailure(surface, err, read)
}

// azureAppActivity is one application's last sign-ins, by kind.
type azureAppActivity struct {
	Last, AppOnly, Delegated *time.Time
}

// readSignInActivity reads Entra's per-application sign-in summary, keyed by
// lowercased appId.
func (s *AzureOnboardingService) readSignInActivity(ctx context.Context, graphToken string) (map[string]azureAppActivity, models.SurfaceCoverage) {
	surface := models.SurfaceCoverage{State: models.CloudCoverageReached, API: "GET /beta/reports/servicePrincipalSignInActivities"}
	rows, err := s.api.ListServicePrincipalSignInActivities(ctx, graphToken)
	if err != nil && !errors.Is(err, azure.ErrPageLimit) {
		logAzureError("service principal sign-in activity", err)
		return nil, signInSurfaceFailure(surface, err, 0)
	}
	at := func(a *azure.SignInActivity) *time.Time {
		if a == nil {
			return nil
		}
		return a.LastSignInDateTime
	}
	out := make(map[string]azureAppActivity, len(rows))
	for _, r := range rows {
		out[strings.ToLower(r.AppID)] = azureAppActivity{
			Last:      at(r.LastSignInActivity),
			AppOnly:   at(r.ApplicationAuthenticationClientSignInActivity),
			Delegated: at(r.DelegatedClientSignInActivity),
		}
	}
	surface.Count = len(out)
	if errors.Is(err, azure.ErrPageLimit) {
		surface.State, surface.Error = models.CloudCoveragePartial, "stopped at the listing page limit"
	}
	return out, surface
}

// readCredentialActivity reads when each client secret and certificate was last
// used, keyed "<owner object id>/<key id>" (lowercased) -- the owner being the
// application or the service principal the credential is on.
func (s *AzureOnboardingService) readCredentialActivity(ctx context.Context, graphToken string) (map[string]*time.Time, models.SurfaceCoverage) {
	surface := models.SurfaceCoverage{State: models.CloudCoverageReached, API: "GET /beta/reports/appCredentialSignInActivities"}
	rows, err := s.api.ListAppCredentialSignInActivities(ctx, graphToken)
	if err != nil && !errors.Is(err, azure.ErrPageLimit) {
		logAzureError("credential sign-in activity", err)
		return nil, signInSurfaceFailure(surface, err, 0)
	}
	out := make(map[string]*time.Time, len(rows))
	for _, r := range rows {
		owner := r.AppObjectID
		if strings.EqualFold(r.CredentialOrigin, "servicePrincipal") {
			owner = r.ServicePrincipalObjectID
		}
		if owner == "" || r.KeyID == "" || r.SignInActivity == nil {
			continue
		}
		key := strings.ToLower(owner) + "/" + strings.ToLower(r.KeyID)
		out[key] = latest(out[key], r.SignInActivity.LastSignInDateTime)
	}
	surface.Count = len(out)
	if errors.Is(err, azure.ErrPageLimit) {
		surface.State, surface.Error = models.CloudCoveragePartial, "stopped at the listing page limit"
	}
	return out, surface
}

func latest(a, b *time.Time) *time.Time {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	case b.After(*a):
		return b
	}
	return a
}

// azureUsageAgg accumulates one identity's sign-ins for one resource.
type azureUsageAgg struct {
	identityID     uuid.UUID
	service        string
	resourceAppID  string
	last, lastFail *time.Time
	ok, failed     int
	ips            map[string]bool
	eventTypes     map[string]bool
	// agentTypes are the Entra Agent ID types the sign-ins named, if any.
	agentTypes map[string]bool
	// times are the successful sign-ins, for the cadence; never stored.
	times []time.Time
}

// readSignInUsage aggregates the last week of service principal and managed
// identity sign-ins into one cloud_usage row per identity per resource. Raw
// events are never stored: the grain is "this identity obtained tokens for
// this resource, this often, from these addresses".
func (s *AzureOnboardingService) readSignInUsage(ctx context.Context, graphToken string, idMap map[string]uuid.UUID, spByApp map[string]string, counters map[string]int) ([]models.CloudUsage, models.SurfaceCoverage) {
	surface := models.SurfaceCoverage{State: models.CloudCoverageReached, API: "GET /beta/auditLogs/signIns (servicePrincipal, managedIdentity)"}
	since := time.Now().Add(-azureSignInWindow)
	aggs := map[string]*azureUsageAgg{}
	read := 0
	for _, eventType := range []string{azure.SignInEventServicePrincipal, azure.SignInEventManagedIdentity} {
		signIns, err := s.api.ListSignIns(ctx, graphToken, eventType, since, azureSignInMaxPages)
		capped := errors.Is(err, azure.ErrPageLimit)
		if err != nil && !capped {
			logAzureError("sign-in log ("+eventType+")", err)
			// A licence refusal is the tenant's, and the same for both event
			// types: no point asking twice.
			return nil, signInSurfaceFailure(surface, err, read)
		}
		if capped {
			surface.State = models.CloudCoveragePartial
			surface.Error = fmt.Sprintf("read the most recent %d %s sign-ins of the last %d days only",
				len(signIns), eventType, int(azureSignInWindow.Hours()/24))
		}
		read += len(signIns)
		for _, si := range signIns {
			spID := strings.ToLower(si.ServicePrincipalID)
			if spID == "" {
				spID = spByApp[strings.ToLower(si.AppID)]
			}
			identityID, ok := idMap[spID]
			if !ok {
				counters["sign_ins_unresolved"]++
				continue
			}
			service := firstNonEmpty(si.ResourceDisplayName, strings.ToLower(si.ResourceID))
			if service == "" {
				continue
			}
			key := identityID.String() + "|" + service
			a := aggs[key]
			if a == nil {
				a = &azureUsageAgg{identityID: identityID, service: service, resourceAppID: strings.ToLower(si.ResourceID),
					ips: map[string]bool{}, eventTypes: map[string]bool{}, agentTypes: map[string]bool{}}
				aggs[key] = a
			}
			a.eventTypes[eventType] = true
			if t := si.AgentType(); t != "" {
				a.agentTypes[t] = true
			}
			if si.IPAddress != "" && len(a.ips) < azureUsageIPLimit {
				a.ips[si.IPAddress] = true
			}
			if si.Status.ErrorCode == 0 {
				a.ok++
				a.last = latest(a.last, si.CreatedDateTime)
				if si.CreatedDateTime != nil {
					a.times = append(a.times, *si.CreatedDateTime)
				}
			} else {
				a.failed++
				a.lastFail = latest(a.lastFail, si.CreatedDateTime)
			}
		}
	}

	now := time.Now()
	rows := make([]models.CloudUsage, 0, len(aggs))
	aiCallers := map[uuid.UUID]bool{}
	machine := map[uuid.UUID]bool{}
	for _, a := range aggs {
		ai := isAzureAIService(a.service, a.resourceAppID)
		cadence := cadenceOf(a.times)
		if cadence.machineLike() {
			machine[a.identityID] = true
		}
		if ai && a.ok > 0 {
			aiCallers[a.identityID] = true
		}
		rows = append(rows, models.CloudUsage{
			IdentityID: a.identityID,
			Service:    a.service,
			// nil: every sign-in for this resource in the window failed. The
			// identity tried and never obtained a token -- "never accessed".
			LastUsedAt:  a.last,
			Source:      models.UsageSourceEntraSignIn,
			GeneratedAt: &now,
			Attrs: attrsJSON(map[string]interface{}{
				"resource_app_id":     a.resourceAppID,
				"sign_ins":            a.ok,
				"failed_sign_ins":     a.failed,
				"last_failed_sign_in": a.lastFail,
				"ip_addresses":        sortedKeys(a.ips),
				"event_types":         sortedKeys(a.eventTypes),
				"agent_types":         sortedKeys(a.agentTypes),
				"window_days":         int(azureSignInWindow.Hours() / 24),
				"ai_service":          ai,
				"cadence":             cadence,
			}),
		})
	}
	counters["sign_ins_read"] = read
	counters["identities_signing_in"] = len(distinctIdentities(rows))
	counters["ai_service_callers"] = len(aiCallers)
	counters["machine_cadence_identities"] = len(machine)
	surface.Count = len(rows)
	return rows, surface
}

// isAzureAIService reports whether a sign-in's resource is an Azure AI service
// -- the PRD's strongest agent signal on Azure.
func isAzureAIService(name, appID string) bool {
	if strings.EqualFold(appID, cognitiveServicesAppID) {
		return true
	}
	n := strings.ToLower(name)
	for _, k := range []string{"cognitive services", "openai", "machine learning", "azure ai"} {
		if strings.Contains(n, k) {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func distinctIdentities(rows []models.CloudUsage) map[uuid.UUID]bool {
	out := map[uuid.UUID]bool{}
	for _, r := range rows {
		out[r.IdentityID] = true
	}
	return out
}

/* --------------------------------- guardrails --------------------------------- */

// readGuardrails reads the tenant's app management and Conditional Access
// policies, and which objects each per-app policy is attached to (keyed by
// lowercased object id).
func (s *AzureOnboardingService) readGuardrails(ctx context.Context, graphToken string) (*models.AzureGuardrails, map[string][]string, models.SurfaceCoverage, models.SurfaceCoverage) {
	now := time.Now()
	g := &models.AzureGuardrails{
		AppManagementPolicies:     []models.AzureAppManagementPolicy{},
		WorkloadConditionalAccess: []models.AzureWorkloadAccessPolicy{},
		AgentConditionalAccess:    []models.AzureAgentAccessPolicy{},
		ReadAt:                    &now,
	}
	appliesTo := map[string][]string{}

	am := models.SurfaceCoverage{State: models.CloudCoverageReached, API: "GET /v1.0/policies/defaultAppManagementPolicy, /v1.0/policies/appManagementPolicies"}
	if def, err := s.api.GetDefaultAppManagementPolicy(ctx, graphToken); err != nil {
		logAzureError("default app management policy", err)
		am = surfaceFailure(am, err, 0)
	} else {
		g.DefaultAppManagement = &models.AzureAppManagementPolicy{
			Enabled: def.IsEnabled,
			Rules: append(appManagementRules("application", def.ApplicationRestrictions),
				appManagementRules("service_principal", def.ServicePrincipalRestrictions)...),
		}
		policies, err := s.api.ListAppManagementPolicies(ctx, graphToken)
		if err != nil {
			logAzureError("app management policies", err)
			am = surfaceFailure(am, err, 1)
		}
		for _, p := range policies {
			targets, terr := s.api.ListAppManagementPolicyTargets(ctx, graphToken, p.ID)
			if terr != nil {
				logAzureError("app management policy targets", terr)
				am = surfaceFailure(am, terr, len(g.AppManagementPolicies))
				am.State = models.CloudCoveragePartial
			}
			for _, t := range targets {
				id := strings.ToLower(t.ID)
				appliesTo[id] = append(appliesTo[id], strings.ToLower(p.ID))
			}
			g.AppManagementPolicies = append(g.AppManagementPolicies, models.AzureAppManagementPolicy{
				ID: strings.ToLower(p.ID), Name: p.DisplayName, Enabled: p.IsEnabled,
				Rules: appManagementRules("app", p.Restrictions), AppliesTo: len(targets),
			})
		}
		am.Count = 1 + len(g.AppManagementPolicies)
	}

	ca := models.SurfaceCoverage{State: models.CloudCoverageReached, API: "GET /beta/identity/conditionalAccess/policies"}
	policies, err := s.api.ListConditionalAccessPolicies(ctx, graphToken)
	switch {
	case err != nil && azure.IsLicenseRequired(err):
		ca.State, ca.ErrorCode = models.CloudCoverageUnsupported, "license_required"
		ca.Error = "Conditional Access needs Entra ID P1: " + err.Error()
	case err != nil:
		logAzureError("conditional access policies", err)
		ca = surfaceFailure(ca, err, 0)
	}
	g.ConditionalAccessTotal = len(policies)
	for _, p := range policies {
		apps := p.Conditions.ClientApplications
		if apps == nil || len(apps.IncludeServicePrincipals) == 0 {
			continue
		}
		w := models.AzureWorkloadAccessPolicy{
			ID: strings.ToLower(p.ID), Name: p.DisplayName, State: p.State,
			IncludeSPs: apps.IncludeServicePrincipals, ExcludeSPs: apps.ExcludeServicePrincipals,
		}
		if l := p.Conditions.Locations; l != nil {
			w.IncludeLocations, w.ExcludeLocations = l.IncludeLocations, l.ExcludeLocations
		}
		if p.GrantControls != nil {
			w.GrantControls = p.GrantControls.BuiltInControls
		}
		g.WorkloadConditionalAccess = append(g.WorkloadConditionalAccess, w)
	}
	g.AgentConditionalAccess = agentAccessPolicies(policies)
	ca.Count = len(policies)

	switch {
	case am.State != models.CloudCoverageReached && am.Error != "":
		g.Error = am.Error
	case ca.State != models.CloudCoverageReached && ca.State != models.CloudCoverageUnsupported:
		g.Error = ca.Error
	}
	return g, appliesTo, am, ca
}

// appManagementRules renders one policy's credential rules as
// "<owner>.<credential>:<restrictionType>[=<maxLifetime>]". A rule switched
// off (state disabled) is not a guardrail and is left out.
func appManagementRules(owner string, r *azure.AppManagementRestrictions) []string {
	out := []string{}
	if r == nil {
		return out
	}
	add := func(cred string, list []azure.AppManagementRestriction) {
		for _, x := range list {
			if strings.EqualFold(x.State, "disabled") {
				continue
			}
			rule := owner + "." + cred + ":" + x.RestrictionType
			if x.MaxLifetime != nil && *x.MaxLifetime != "" {
				rule += "=" + *x.MaxLifetime
			}
			out = append(out, rule)
		}
	}
	add("password", r.PasswordCredentials)
	add("key", r.KeyCredentials)
	return out
}

/* ------------------------------- API permissions ------------------------------ */

// azureAPIGrant is a cloud_permission row waiting for its resource's row id.
type azureAPIGrant struct {
	perm           models.CloudPermission
	resourceNative string
}

// readAPIPermissions reads every application permission (app role assignment)
// and delegated permission (OAuth2 grant) in the tenant. Each permission an API
// exposes becomes a cloud_resource row -- Graph scopes are resources in the API
// plane -- and each grant a cloud_permission row pointing at it.
func (s *AzureOnboardingService) readAPIPermissions(ctx context.Context, graphToken, tenantID string, sps []azure.ServicePrincipal, idMap map[string]uuid.UUID, counters map[string]int) ([]models.CloudResource, []azureAPIGrant, models.SurfaceCoverage, models.SurfaceCoverage) {
	spName := make(map[string]string, len(sps))
	for _, sp := range sps {
		spName[strings.ToLower(sp.ID)] = firstNonEmpty(sp.DisplayName, sp.AppID)
	}

	appSurface := models.SurfaceCoverage{State: models.CloudCoverageReached, API: "GET /v1.0/servicePrincipals/{id}/appRoleAssignedTo"}
	// The app roles every API defines, read apart from the service principal
	// listing: they are most of its weight, and small pages keep Graph inside
	// the request timeout.
	withRoles, err := s.api.ListServicePrincipalAppRoles(ctx, graphToken)
	if err != nil && !errors.Is(err, azure.ErrPageLimit) {
		logAzureError("service principal app roles", err)
		appSurface = surfaceFailure(appSurface, err, 0)
		appSurface.API = "GET /v1.0/servicePrincipals?$select=appRoles"
	}
	if errors.Is(err, azure.ErrPageLimit) {
		appSurface.State, appSurface.Error = models.CloudCoveragePartial, "app roles: stopped at the listing page limit"
	}
	roleValue := map[string]string{}
	var resourceSPs []azure.ServicePrincipal
	for _, sp := range withRoles {
		id := strings.ToLower(sp.ID)
		for _, r := range sp.AppRoles {
			roleValue[id+"/"+strings.ToLower(r.ID)] = firstNonEmpty(r.Value, r.DisplayName)
		}
		// Only an API that defines app roles can have them assigned. Default
		// access to an app that defines none (a user assigned to an
		// enterprise app) is app access, not an API permission, and is not
		// read here.
		if len(sp.AppRoles) > 0 {
			resourceSPs = append(resourceSPs, sp)
		}
	}

	resources := map[string]models.CloudResource{}
	addResource := func(native, kind, apiID, value string) {
		if _, ok := resources[native]; ok {
			return
		}
		sensitivity, reason := apiPermissionSensitivity(value)
		resources[native] = models.CloudResource{
			Kind:              kind,
			NativeID:          native,
			Name:              firstNonEmpty(spName[apiID], apiID) + ": " + value,
			ResourceAccount:   strings.ToLower(tenantID),
			Sensitivity:       sensitivity,
			SensitivitySource: models.SensitivityFromHeuristic,
			SensitivityReason: reason,
		}
	}
	var grants []azureAPIGrant

	// Application permissions, read per API (resource) rather than per
	// principal: far fewer APIs than principals, and one call returns every
	// assignment on the API whoever holds it.
	var mu sync.Mutex
	failed := 0
	var firstErr error
	forEachLimited(len(resourceSPs), azureAssignConcurrency, func(i int) {
		api := resourceSPs[i]
		rows, err := s.api.ListAppRoleAssignedTo(ctx, graphToken, api.ID)
		mu.Lock()
		defer mu.Unlock()
		if err != nil && !errors.Is(err, azure.ErrPageLimit) {
			failed++
			if firstErr == nil {
				firstErr = err
			}
			return
		}
		apiID := strings.ToLower(api.ID)
		for _, a := range rows {
			identityID, ok := idMap[strings.ToLower(a.PrincipalID)]
			if !ok {
				counters["app_role_assignments_unresolved"]++
				continue
			}
			roleID := strings.ToLower(a.AppRoleID)
			value := roleValue[apiID+"/"+roleID]
			switch {
			case roleID == azure.DefaultAccessAppRoleID:
				value = "default_access"
			case value == "":
				// A role the API no longer defines, or one defined without a
				// value: keep the id, never guess a name.
				value = roleID
			}
			native := apiID + "/approles/" + roleID
			addResource(native, models.CloudResourceEntraAppRole, apiID, value)
			res := resources[native]
			name := res.Name
			grants = append(grants, azureAPIGrant{resourceNative: native, perm: models.CloudPermission{
				IdentityID:      identityID,
				Plane:           models.PermissionPlaneAPI,
				Effect:          models.PermissionEffectAllow,
				RoleName:        &name,
				Actions:         pq.StringArray{value},
				ConstraintState: models.ConstraintUnconstrained,
				ScopeKind:       models.PermissionScopeResource,
				Derivation:      models.PermissionDerivationGranted,
				Sensitivity:     res.Sensitivity,
				NativeID:        "approleassignments/" + strings.ToLower(a.ID),
			}})
			counters["application_permissions"]++
			if res.Sensitivity == models.SensitivityHigh {
				counters["high_risk_api_permissions"]++
			}
		}
	})
	appSurface.Count = counters["application_permissions"]
	if failed > 0 {
		appSurface = surfaceFailure(appSurface, firstErr, appSurface.Count)
		appSurface.State = models.CloudCoveragePartial
		appSurface.Error = fmt.Sprintf("assignments of %d of %d APIs could not be read: %v", failed, len(resourceSPs), firstErr)
	}

	// Delegated permissions: the client may call the API with these scopes,
	// but only on behalf of a signed-in user and never beyond that user's own
	// access -- recorded bounded, with whom it acts for in the condition.
	delSurface := models.SurfaceCoverage{State: models.CloudCoverageReached, API: "GET /v1.0/oauth2PermissionGrants"}
	delegated, err := s.api.ListOAuth2PermissionGrants(ctx, graphToken)
	if err != nil && !errors.Is(err, azure.ErrPageLimit) {
		logAzureError("oauth2 permission grants", err)
		delSurface = surfaceFailure(delSurface, err, 0)
	} else {
		if errors.Is(err, azure.ErrPageLimit) {
			delSurface.State, delSurface.Error = models.CloudCoveragePartial, "stopped at the listing page limit"
		}
		for _, g := range delegated {
			identityID, ok := idMap[strings.ToLower(g.ClientID)]
			if !ok {
				counters["delegated_grants_unresolved"]++
				continue
			}
			apiID := strings.ToLower(g.ResourceID)
			cond := map[string]string{"delegated": "true", "consent_type": g.ConsentType}
			if g.PrincipalID != "" {
				cond["on_behalf_of"] = strings.ToLower(g.PrincipalID)
			}
			raw, _ := json.Marshal(cond)
			condition := string(raw)
			for _, scope := range g.Scopes() {
				native := apiID + "/scopes/" + strings.ToLower(scope)
				addResource(native, models.CloudResourceEntraDelegatedScope, apiID, scope)
				res := resources[native]
				name := res.Name
				c := condition
				grants = append(grants, azureAPIGrant{resourceNative: native, perm: models.CloudPermission{
					IdentityID:      identityID,
					Plane:           models.PermissionPlaneAPI,
					Effect:          models.PermissionEffectAllow,
					RoleName:        &name,
					Actions:         pq.StringArray{scope},
					Condition:       &c,
					ConstraintState: models.ConstraintBounded,
					ScopeKind:       models.PermissionScopeResource,
					Derivation:      models.PermissionDerivationGranted,
					Sensitivity:     res.Sensitivity,
					NativeID:        "oauth2permissiongrants/" + strings.ToLower(g.ID),
				}})
				counters["delegated_permissions"]++
				if res.Sensitivity == models.SensitivityHigh {
					counters["high_risk_api_permissions"]++
				}
			}
		}
		delSurface.Count = counters["delegated_permissions"]
	}

	out := make([]models.CloudResource, 0, len(resources))
	for _, r := range resources {
		out = append(out, r)
	}
	return out, grants, appSurface, delSurface
}

// apiPermissionSensitivity rates one API permission by what it allows: the
// PRD's rule (*.ReadWrite.All and Directory.* are high) plus the permissions
// that hand out further access, and the sign-in basics as low. A starting
// rule, labelled heuristic.
func apiPermissionSensitivity(value string) (string, string) {
	v := strings.ToLower(value)
	switch {
	case v == "openid" || v == "profile" || v == "email" || v == "offline_access" ||
		v == "user.read" || v == "user.readbasic.all" || v == "default_access":
		return models.SensitivityLow, ""
	case strings.HasSuffix(v, ".readwrite.all") || strings.HasSuffix(v, ".fullcontrol.all") ||
		strings.HasPrefix(v, "directory.") || strings.HasPrefix(v, "rolemanagement.readwrite") ||
		strings.HasPrefix(v, "policy.readwrite.") || v == "full_access_as_app":
		return models.SensitivityHigh, fmt.Sprintf("AuthSec rule: %q writes tenant-wide or controls the directory", value)
	}
	return models.SensitivityMedium, ""
}

/* ---------------------------- federated credentials --------------------------- */

// readFederatedCredentials reads every app registration's federated identity
// credentials and records each as who may become the app's service principal.
func (s *AzureOnboardingService) readFederatedCredentials(ctx context.Context, graphToken string, apps []azure.GraphApplication, spByApp map[string]string, idMap map[string]uuid.UUID, counters map[string]int) ([]models.CloudAssumeEdge, models.SurfaceCoverage) {
	surface := models.SurfaceCoverage{State: models.CloudCoverageReached, API: "GET /v1.0/applications/{id}/federatedIdentityCredentials"}
	var (
		mu       sync.Mutex
		edges    []models.CloudAssumeEdge
		failed   int
		firstErr error
	)
	forEachLimited(len(apps), azureAssignConcurrency, func(i int) {
		app := apps[i]
		creds, err := s.api.ListFederatedCredentials(ctx, graphToken, app.ID)
		mu.Lock()
		defer mu.Unlock()
		if err != nil && !errors.Is(err, azure.ErrPageLimit) {
			failed++
			if firstErr == nil {
				firstErr = err
			}
			return
		}
		// Tokens are issued to the app's service principal in this tenant --
		// the identity that holds the grants -- so the edge lands there. An
		// app with no service principal here keeps it on the registration.
		identityID, ok := idMap[spByApp[strings.ToLower(app.AppID)]]
		owner := "service_principal"
		if !ok {
			identityID, ok = idMap[strings.ToLower(app.ID)]
			owner = "application"
		}
		if !ok {
			return
		}
		for _, c := range creds {
			edges = append(edges, azureFederationEdge(identityID, c.Issuer, c.Subject, map[string]interface{}{
				"credential_id":         strings.ToLower(c.ID),
				"credential_name":       c.Name,
				"audiences":             c.Audiences,
				"description":           c.Description,
				"application_object_id": strings.ToLower(app.ID),
				"edge_owner":            owner,
			}))
			counters["federated_credentials"]++
		}
	})
	surface.Count = len(edges)
	if failed > 0 {
		surface = surfaceFailure(surface, firstErr, len(edges))
		surface.State = models.CloudCoveragePartial
		surface.Error = fmt.Sprintf("federated credentials of %d of %d applications could not be read: %v", failed, len(apps), firstErr)
	}
	return edges, surface
}

// ciIssuerHosts are OIDC issuers that mint tokens for CI/CD pipelines.
var ciIssuerHosts = []string{
	"token.actions.githubusercontent.com",
	"gitlab.com",
	"app.terraform.io",
	"vstoken.dev.azure.com",
	"api.bitbucket.org",
	"oidc.circleci.com",
}

// azureFederationEdge classifies one federated credential by who the token
// comes from:
//
//	a Kubernetes service account   subject system:serviceaccount:<ns>:<sa>
//	                               (AKS workload identity, or any cluster's issuer)
//	a CI/CD pipeline               GitHub Actions, GitLab, Terraform Cloud, ...
//	another Entra identity         issuer login.microsoftonline.com / sts.windows.net
//	anything else                  an external OIDC issuer
//
// The issuer is stored without scheme or trailing slash, as AWS stores it, so
// the Kubernetes connector's pods join on (k8s_ref, issuer) whatever the cloud.
func azureFederationEdge(identityID uuid.UUID, issuer, subject string, attrs map[string]interface{}) models.CloudAssumeEdge {
	iss := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(issuer), "https://"), "http://"), "/")
	host := strings.ToLower(strings.SplitN(iss, "/", 2)[0])
	attrs["issuer_url"] = issuer
	e := models.CloudAssumeEdge{
		IdentityID: identityID,
		Subject:    subject,
		Issuer:     &iss,
		Mechanism:  models.AssumeMechanismOIDCFederation,
		Attrs:      attrsJSON(attrs),
	}
	switch {
	case strings.HasPrefix(subject, "system:serviceaccount:"):
		e.SubjectKind = models.AssumeSubjectK8sSA
		ref := subject
		e.K8sRef = &ref
	case host == "login.microsoftonline.com" || host == "sts.windows.net":
		e.SubjectKind = models.AssumeSubjectIdentity
	default:
		e.SubjectKind = models.AssumeSubjectExternal
		for _, h := range ciIssuerHosts {
			if host == h || strings.HasSuffix(host, "."+h) {
				e.SubjectKind = models.AssumeSubjectCIPipeline
				break
			}
		}
	}
	if e.Subject == "" {
		// A flexible credential matches on an expression, not one subject.
		e.Subject = "(claims expression)"
	}
	return e
}
