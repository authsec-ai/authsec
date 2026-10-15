package services

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

/* azure_owners.go reads who OWNS each app registration and service
   principal. An owner may change the object -- and in particular add a
   client secret or certificate to it -- so an owner can become it: an app
   registration's owner obtains its service principal's tokens, a service
   principal's owner its own. Recorded as attrs.owners on the object, and as
   a can_assume edge (mechanism entra_app_owner) from each owner.

   Read for every app registration, and every service principal the tenant
   itself controls: Microsoft's first-party service principals and managed
   identities have no owners worth a call each. Application.Read.All. */

// azureOwnerReadLimit caps how many objects have their owners read in one
// pass.
const azureOwnerReadLimit = 5000

// azureOwners are the owners read in one pass, by lowercase object id. read
// marks an object whose read succeeded: one missing from it was not read,
// which is not the same as "has none".
type azureOwners struct {
	refs map[string][]azure.DirectoryRef
	read map[string]bool
}

// readOwners reads the owners of every app registration and every service
// principal the tenant controls.
func (s *AzureOnboardingService) readOwners(ctx context.Context, graphToken string, apps []azure.GraphApplication, sps []azure.ServicePrincipal, surfaces map[string]models.SurfaceCoverage, counters map[string]int) *azureOwners {
	out := &azureOwners{refs: map[string][]azure.DirectoryRef{}, read: map[string]bool{}}
	type job struct {
		id  string
		app bool
	}
	var jobs []job
	for _, a := range apps {
		if azure.IsGUID(a.ID) {
			jobs = append(jobs, job{strings.ToLower(a.ID), true})
		}
	}
	for _, sp := range sps {
		if !azure.IsGUID(sp.ID) || ownerless(sp) {
			continue
		}
		jobs = append(jobs, job{strings.ToLower(sp.ID), false})
	}
	// One deterministic order, so a capped pass reads the same objects each time.
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].id < jobs[j].id })
	capped := 0
	if len(jobs) > azureOwnerReadLimit {
		capped = len(jobs) - azureOwnerReadLimit
		jobs = jobs[:azureOwnerReadLimit]
	}

	var mu sync.Mutex
	ok, failed := 0, 0
	var firstErr error
	forEachLimited(len(jobs), azureAssignConcurrency, func(i int) {
		j := jobs[i]
		var refs []azure.DirectoryRef
		var err error
		if j.app {
			refs, err = s.api.ListApplicationOwners(ctx, graphToken, j.id)
		} else {
			refs, err = s.api.ListServicePrincipalOwners(ctx, graphToken, j.id)
		}
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			failed++
			if firstErr == nil {
				firstErr = err
			}
			return
		}
		ok++
		out.refs[j.id], out.read[j.id] = refs, true
	})

	sc := models.SurfaceCoverage{State: models.CloudCoverageReached, Count: ok,
		API: "GET /v1.0/applications/{id}/owners, /v1.0/servicePrincipals/{id}/owners"}
	switch {
	case failed > 0:
		sc = surfaceFailure(sc, firstErr, ok)
		if ok > 0 {
			sc.State = models.CloudCoveragePartial
		}
		sc.Error = fmt.Sprintf("owners of %d of %d objects could not be read: %v", failed, ok+failed, firstErr)
	case capped > 0:
		sc.State = models.CloudCoveragePartial
		sc.Error = fmt.Sprintf("owners of %d objects past the first %d were not read", capped, azureOwnerReadLimit)
	}
	surfaces[models.SurfaceEntraOwners] = sc
	counters["owner_reads"] = ok
	return out
}

// ownerless reports whether a service principal has no owners worth reading:
// Microsoft's own first-party apps, and managed identities.
func ownerless(sp azure.ServicePrincipal) bool {
	return azure.MicrosoftTenantIDs[strings.ToLower(sp.AppOwnerOrganizationID)] ||
		strings.EqualFold(sp.ServicePrincipalType, "ManagedIdentity")
}

// decorate records an object's owners on its identity row, when they were read.
func (o *azureOwners) decorate(ident *models.CloudIdentity, dir azureDirectoryState) {
	if o.read[ident.NativeID] {
		mergeAttrs(ident, map[string]interface{}{"owners": dir.refs(o.refs[ident.NativeID])})
	}
}

// edges records that each owner can become what it owns: an app
// registration's owner its service principal (or, with none here, the app),
// a service principal's owner the service principal.
func (o *azureOwners) edges(apps []azure.GraphApplication, sps []azure.ServicePrincipal, spByApp map[string]string, idMap map[string]uuid.UUID, counters map[string]int) []models.CloudAssumeEdge {
	var out []models.CloudAssumeEdge
	add := func(targetNative, ownerOf, appID string, owners []azure.DirectoryRef) {
		target, ok := idMap[targetNative]
		if !ok {
			return
		}
		for _, r := range owners {
			out = append(out, models.CloudAssumeEdge{
				IdentityID: target, SubjectKind: models.AssumeSubjectIdentity, Subject: strings.ToLower(r.ID),
				Mechanism: models.AssumeMechanismEntraOwner,
				Attrs: attrsJSON(map[string]interface{}{
					"edge_owner": ownerOf, "app_id": appID, "owner_kind": r.Kind(),
					"why": "an owner can add a credential to the " + strings.ReplaceAll(ownerOf, "_", " ") + ", and so obtain its tokens",
				}),
			})
			counters["owner_edges"]++
		}
	}
	for _, a := range apps {
		id := strings.ToLower(a.ID)
		if len(o.refs[id]) == 0 {
			continue
		}
		appID := strings.ToLower(a.AppID)
		target := spByApp[appID]
		if _, ok := idMap[target]; target == "" || !ok {
			target = id
		}
		add(target, "application", appID, o.refs[id])
	}
	for _, sp := range sps {
		id := strings.ToLower(sp.ID)
		if len(o.refs[id]) > 0 {
			add(id, "service_principal", strings.ToLower(sp.AppID), o.refs[id])
		}
	}
	return out
}
