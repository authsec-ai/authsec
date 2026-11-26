package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

/* azure_activity_discovery.go reads what identities actually DID in a
   subscription, from the Azure Activity Log (management plane), and turns it
   into two things:

     cloud_usage source=activity_log   one row per identity per resource
                                       provider ("Microsoft.Compute"): how many
                                       operations, which, and when last
     cloud_permission.last_exercised_at  on each Azure RBAC grant, the last time
                                       an operation that grant allows was
                                       performed by its holder within its scope

   The second is what the PRD's unused-grant policy (POL-17) needs and what a
   sign-in cannot give: a token for Azure Resource Manager says nothing about
   WHICH role was used. Only succeeded operations count, and the attribution is
   to the grant that ALLOWS the action -- when an identity holds two roles that
   both allow it, both are marked, because the log cannot say which one Azure
   evaluated. Read with Reader; the log is kept 90 days, and each pass reads
   the most recent week. */

const (
	azureActivityWindow   = 7 * 24 * time.Hour
	azureActivityMaxPages = 20
	// azureActivityActionLimit caps how many distinct actions one usage row
	// lists.
	azureActivityActionLimit = 20
)

type azureActivityAgg struct {
	identityNative string
	namespace      string
	operations     int
	last           *time.Time
	actions        map[string]bool
}

// collectActivityLog reads the subscription's recent management operations.
func (s *AzureOnboardingService) collectActivityLog(ctx context.Context, workspaceID, connectorID uuid.UUID, generation int, subscriptionID, armToken string, counters map[string]int) models.SurfaceCoverage {
	surface := models.SurfaceCoverage{State: models.CloudCoverageReached, API: "Microsoft.Insights/eventtypes/management/values"}
	now := time.Now()
	events, err := s.api.ListActivityLog(ctx, armToken, subscriptionID, now.Add(-azureActivityWindow), now, azureActivityMaxPages)
	capped := errors.Is(err, azure.ErrPageLimit)
	if err != nil && !capped {
		logAzureError("activity log", err)
		return surfaceFailure(surface, err, 0)
	}
	if capped {
		surface.State = models.CloudCoveragePartial
		surface.Error = fmt.Sprintf("read the most recent %d operations of the last %d days only",
			len(events), int(azureActivityWindow.Hours()/24))
	}

	// Only operations Azure completed, attributed to an Entra object.
	type op struct {
		oid, action, scope string
		at                 time.Time
	}
	var ops []op
	for _, e := range events {
		oid := e.CallerObjectID()
		if oid == "" || e.Authorization == nil || e.Authorization.Action == "" || e.EventTimestamp == nil {
			continue
		}
		if e.Status == nil || !strings.EqualFold(e.Status.Value, "Succeeded") {
			continue
		}
		scope := firstNonEmpty(e.Authorization.Scope, e.ResourceID)
		ops = append(ops, op{oid: oid, action: e.Authorization.Action, scope: strings.ToLower(scope), at: *e.EventTimestamp})
	}
	counters["activity_operations"] = len(ops)

	// Usage, per identity per provider namespace.
	aggs := map[string]*azureActivityAgg{}
	var oids []string
	for _, o := range ops {
		ns := o.action
		if i := strings.Index(ns, "/"); i > 0 {
			ns = ns[:i]
		}
		key := o.oid + "|" + strings.ToLower(ns)
		a := aggs[key]
		if a == nil {
			a = &azureActivityAgg{identityNative: o.oid, namespace: ns, actions: map[string]bool{}}
			aggs[key] = a
			oids = append(oids, o.oid)
		}
		a.operations++
		at := o.at
		a.last = latest(a.last, &at)
		if len(a.actions) < azureActivityActionLimit {
			a.actions[o.action] = true
		}
	}
	idMap, err := s.inventory.IdentityIDs(workspaceID, oids)
	if err != nil {
		return surfaceFailure(surface, err, 0)
	}
	var rows []models.CloudUsage
	callers := map[uuid.UUID]bool{}
	for _, a := range aggs {
		identityID, ok := idMap[a.identityNative]
		if !ok {
			counters["activity_callers_unresolved"]++
			continue
		}
		callers[identityID] = true
		rows = append(rows, models.CloudUsage{
			IdentityID:  identityID,
			Service:     a.namespace,
			LastUsedAt:  a.last,
			Source:      models.UsageSourceActivityLog,
			GeneratedAt: &now,
			Attrs: attrsJSON(map[string]interface{}{
				"operations":      a.operations,
				"actions":         sortedKeys(a.actions),
				"subscription_id": strings.ToLower(subscriptionID),
				"window_days":     int(azureActivityWindow.Hours() / 24),
			}),
		})
	}
	if _, err := s.inventory.UpsertUsage(workspaceID, connectorID, generation, rows); err != nil {
		log.Printf("[azure] scan: could not record activity for connector %s: %v", connectorID, err)
		surface.State, surface.Error = models.CloudCoveragePartial, "AuthSec could not record the activity it read"
		return surface
	}
	counters["identities_active"] = len(callers)

	// Last use of each Azure RBAC grant held in this subscription.
	grants, err := s.inventory.RBACGrants(workspaceID, connectorID)
	if err != nil {
		log.Printf("[azure] scan: could not load role assignments to attribute activity for connector %s: %v", connectorID, err)
		surface.State, surface.Error = models.CloudCoveragePartial, "AuthSec could not attribute activity to role assignments"
		return surface
	}
	byOID := map[string][]op{}
	for _, o := range ops {
		byOID[o.oid] = append(byOID[o.oid], o)
	}
	exercised := map[uuid.UUID]time.Time{}
	for _, g := range grants {
		scope := rbacGrantScope(g.NativeID)
		perms := []azure.Permission{{Actions: g.Actions, NotActions: g.NotActions}}
		for _, o := range byOID[strings.ToLower(g.SubjectNativeID)] {
			if !scopeCovers(scope, o.scope) || !azure.AllowsAction(perms, o.action) {
				continue
			}
			if t, ok := exercised[g.ID]; !ok || o.at.After(t) {
				exercised[g.ID] = o.at
			}
		}
	}
	if err := s.inventory.SetLastExercised(workspaceID, connectorID, exercised); err != nil {
		log.Printf("[azure] scan: could not record grant use for connector %s: %v", connectorID, err)
		surface.State, surface.Error = models.CloudCoveragePartial, "AuthSec could not record which role assignments were used"
		return surface
	}
	counters["role_assignments_exercised"] = len(exercised)
	surface.Count = len(rows)
	return surface
}

// rbacGrantScope is a role assignment's scope from its ARM id, lowercased.
func rbacGrantScope(assignmentID string) string {
	id := strings.ToLower(assignmentID)
	const marker = "/providers/microsoft.authorization/roleassignments/"
	if i := strings.Index(id, marker); i >= 0 {
		if i == 0 {
			return "/"
		}
		return id[:i]
	}
	return id
}

// scopeCovers reports whether an assignment at scope applies to target. An
// assignment at the root or at a management group applies to everything in
// the subscriptions below it -- every operation this subscription's log holds.
func scopeCovers(scope, target string) bool {
	if scope == "/" || strings.HasPrefix(scope, "/providers/microsoft.management/managementgroups/") {
		return true
	}
	return target == scope || strings.HasPrefix(target, scope+"/")
}

// markAppPermissionsExercised stamps last use on application permissions from
// sign-ins: an identity that obtained a token for an API carried every
// application permission it holds on that API in the token. Logged, never
// fatal: it decorates rows the pass already wrote.
func (s *AzureOnboardingService) markAppPermissionsExercised(workspaceID, tenantConnectorID uuid.UUID, counters map[string]int) {
	n, err := s.inventory.MarkAppPermissionsExercised(workspaceID, tenantConnectorID)
	if err != nil {
		log.Printf("[azure] tenant scan: could not record application permission use for connector %s: %v", tenantConnectorID, err)
		return
	}
	counters["application_permissions_exercised"] = int(n)
}
