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
)

/* azure_agent_details.go reads what Microsoft Entra Agent ID says about each
   agent object beyond the object itself:

     sponsors             who sponsors each blueprint, agent identity and
                          agent user. (Owners, of every app and service
                          principal, are read by azure_owners.go.)
     inherited access     the permissions an agent identity INHERITS from its
                          blueprint. Microsoft merges them into the agent's
                          tokens and shows them nowhere else, so AuthSec
                          derives them: the blueprint principal's grants,
                          filtered by the blueprint's inheritable permissions.
     audit                directory audit events on an agent object, and the
                          changes an agent made itself.
     Conditional Access   the policies that target agent identities, as read.

   Discovery only: everything here reads, nothing changes an agent, and no
   judgement is drawn from it. */

const (
	// azureAgentDetailLimit caps how many Agent ID objects have their
	// owners, sponsors and inheritable permissions read in one pass.
	azureAgentDetailLimit = 2000
	// azureAgentAuditPages caps the audit read at 20 pages of 500 events.
	azureAgentAuditPages = 20
	// azureAgentAuditFirstWindow is how far a tenant's first audit read
	// reaches back (Entra keeps 7 days without P1/P2, 30 with), and
	// azureAgentAuditOverlap how far each later read reaches behind the last.
	azureAgentAuditFirstWindow = 30 * 24 * time.Hour
	azureAgentAuditOverlap     = time.Hour
	// azureAgentAuditKeep is how many events each object keeps per list.
	azureAgentAuditKeep = 20
)

/* ----------------------------------- sponsors ----------------------------------- */

// azureAgentDetails is what the detail reads returned, by lowercase
// object id. A read map entry is set only when that object's read succeeded:
// an object missing from it was not read, which is not the same as "has none".
type azureAgentDetails struct {
	sponsors     map[string][]azure.DirectoryRef
	sponsorsRead map[string]bool
	// ownSponsorsDenied: Graph refused an agent identity's own sponsors (it
	// documents a write permission for that read), so each agent identity
	// answers to its blueprint's sponsors.
	ownSponsorsDenied bool
	inheritable       map[string][]azure.InheritablePermission
	inheritableRead   map[string]bool
}

// readAgentDetails reads the sponsors of every blueprint, agent identity and
// agent user, and every blueprint's inheritable permissions.
func (s *AzureOnboardingService) readAgentDetails(ctx context.Context, graphToken string, agents *azureAgentObjects, surfaces map[string]models.SurfaceCoverage, counters map[string]int) *azureAgentDetails {
	gov := &azureAgentDetails{
		sponsors: map[string][]azure.DirectoryRef{}, sponsorsRead: map[string]bool{},
		inheritable: map[string][]azure.InheritablePermission{}, inheritableRead: map[string]bool{},
	}

	// One deterministic order, so a capped pass reads the same objects each time.
	type object struct{ id, kind string }
	var objects []object
	for _, id := range sortedMapKeys(agents.blueprints) {
		objects = append(objects, object{id, models.AgentTypeBlueprint})
	}
	for _, id := range sortedMapKeys(agents.identities) {
		objects = append(objects, object{id, models.CloudIdentityEntraAgentIdentity})
	}
	for _, id := range sortedMapKeys(agents.users) {
		objects = append(objects, object{id, models.CloudIdentityEntraAgentUser})
	}
	capped := 0
	if len(objects) > azureAgentDetailLimit {
		capped = len(objects) - azureAgentDetailLimit
		objects = objects[:azureAgentDetailLimit]
	}

	// An agent identity's own sponsors: probe once. Microsoft documents only a
	// write permission for this read; when the tenant refuses it, every agent
	// identity answers to its blueprint's sponsors instead of failing N times.
	probed := ""
	for _, o := range objects {
		if o.kind != models.CloudIdentityEntraAgentIdentity {
			continue
		}
		refs, err := s.api.ListAgentIdentitySponsors(ctx, graphToken, o.id)
		switch {
		case err == nil:
			gov.sponsors[o.id], gov.sponsorsRead[o.id] = refs, true
		case azure.APIStatus(err) == 401 || azure.APIStatus(err) == 403:
			gov.ownSponsorsDenied = true
		default:
			logAzureError("agent identity sponsors", err)
		}
		probed = o.id
		break
	}

	type job struct {
		id, what string
	}
	var jobs []job
	for _, o := range objects {
		switch o.kind {
		case models.AgentTypeBlueprint:
			jobs = append(jobs, job{o.id, "blueprint_sponsors"}, job{o.id, "inheritable"})
		case models.CloudIdentityEntraAgentIdentity:
			if !gov.ownSponsorsDenied && o.id != probed {
				jobs = append(jobs, job{o.id, "identity_sponsors"})
			}
		case models.CloudIdentityEntraAgentUser:
			jobs = append(jobs, job{o.id, "user_sponsors"})
		}
	}

	type tally struct {
		ok, failed int
		firstErr   error
	}
	var mu sync.Mutex
	sponsors, inherit := &tally{}, &tally{}
	if probed != "" {
		if gov.sponsorsRead[probed] {
			sponsors.ok++
		} else if !gov.ownSponsorsDenied {
			sponsors.failed++
		}
	}
	forEachLimited(len(jobs), azureAssignConcurrency, func(i int) {
		j := jobs[i]
		var refs []azure.DirectoryRef
		var perms []azure.InheritablePermission
		var err error
		switch j.what {
		case "blueprint_sponsors":
			refs, err = s.api.ListBlueprintSponsors(ctx, graphToken, j.id)
		case "identity_sponsors":
			refs, err = s.api.ListAgentIdentitySponsors(ctx, graphToken, j.id)
		case "user_sponsors":
			refs, err = s.api.ListUserSponsors(ctx, graphToken, j.id)
		case "inheritable":
			perms, err = s.api.ListInheritablePermissions(ctx, graphToken, j.id)
		}
		mu.Lock()
		defer mu.Unlock()
		t := sponsors
		if j.what == "inheritable" {
			t = inherit
		}
		if err != nil {
			t.failed++
			if t.firstErr == nil {
				t.firstErr = err
			}
			return
		}
		t.ok++
		if j.what == "inheritable" {
			gov.inheritable[j.id], gov.inheritableRead[j.id] = perms, true
		} else {
			gov.sponsors[j.id], gov.sponsorsRead[j.id] = refs, true
		}
	})

	agentsComplete := true
	for _, n := range agentSurfaceNames {
		if surfaces[n].State != models.CloudCoverageReached {
			agentsComplete = false
		}
	}
	surface := func(api string, t *tally) models.SurfaceCoverage {
		sc := models.SurfaceCoverage{State: models.CloudCoverageReached, API: api, Count: t.ok}
		switch {
		case t.failed > 0:
			sc = surfaceFailure(sc, t.firstErr, t.ok)
			if t.ok > 0 {
				sc.State = models.CloudCoveragePartial
			}
			sc.Error = fmt.Sprintf("%d of %d reads failed: %v", t.failed, t.ok+t.failed, t.firstErr)
		case capped > 0:
			sc.State = models.CloudCoveragePartial
			sc.Error = fmt.Sprintf("%d Agent ID objects past the first %d were not read", capped, azureAgentDetailLimit)
		case !agentsComplete:
			// Everything the Agent ID listings returned was read; an object they
			// did not return could not be.
			sc.Error = "the Agent ID listings were not read in full, so objects they did not return were not read here"
		}
		return sc
	}
	sponsorsSC := surface("GET /v1.0/applications/{id}/microsoft.graph.agentIdentityBlueprint/sponsors, "+
		"/v1.0/servicePrincipals/{id}/microsoft.graph.agentIdentity/sponsors, /v1.0/users/{id}/sponsors", sponsors)
	if gov.ownSponsorsDenied && sponsorsSC.State == models.CloudCoverageReached {
		// Not a shortfall of AuthSec's reading: Microsoft gates an agent
		// identity's own sponsors behind a write permission AuthSec does not ask
		// for. Every blueprint's sponsors were read, and each agent answers to
		// those.
		sponsorsSC.ErrorCode = "agent_sponsors_need_write_permission"
		sponsorsSC.Error = "Microsoft documents AgentIdentity.ReadWrite.All as the only permission that reads an agent identity's own sponsors; " +
			"AuthSec asks for read permissions only, so each agent identity is shown with its blueprint's sponsors"
	}
	surfaces[models.SurfaceEntraAgentSponsors] = sponsorsSC
	surfaces[models.SurfaceEntraAgentInheritance] = surface(
		"GET /v1.0/applications/{id}/microsoft.graph.agentIdentityBlueprint/inheritablePermissions", inherit)
	counters["agent_sponsor_reads"] = sponsors.ok
	return gov
}

// agentSurfaceNames are the four Agent ID listings.
var agentSurfaceNames = []string{
	models.SurfaceEntraAgentIdentities, models.SurfaceEntraAgentBlueprints,
	models.SurfaceEntraAgentBlueprintPrincipals, models.SurfaceEntraAgentUsers,
}

func sortedMapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// azureAgentRef is an owner or sponsor as recorded on an identity.
type azureAgentRef struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
}

// azureDirectoryState says whether a referenced object is active: an enabled
// user or service principal in this directory, or any group. A user or
// service principal the tenant pass did not see is gone (deleted, or never
// here), so not active.
type azureDirectoryState struct {
	userEnabled map[string]bool
	spEnabled   map[string]bool
	groups      map[string]bool
}

func (d azureDirectoryState) ref(r azure.DirectoryRef) azureAgentRef {
	id := strings.ToLower(r.ID)
	out := azureAgentRef{ID: id, Kind: r.Kind(), Name: firstNonEmpty(r.UserPrincipalName, r.DisplayName, id)}
	switch {
	case d.groups[id]:
		out.Active = true
	default:
		if on, ok := d.userEnabled[id]; ok {
			out.Active = on
		} else if on, ok := d.spEnabled[id]; ok {
			out.Active = on
		}
	}
	return out
}

func (d azureDirectoryState) refs(rs []azure.DirectoryRef) []azureAgentRef {
	out := make([]azureAgentRef, 0, len(rs))
	for _, r := range rs {
		out = append(out, d.ref(r))
	}
	return out
}

/* ---------------------------- inherited permissions ---------------------------- */

// inheritedGrants derives what each agent identity inherits: every grant its
// blueprint principal holds on an API the blueprint lists as inheritable, for
// the scopes or roles it lists. One derived row per (grant, agent), its
// native id the grant's with InheritedGrantMarker and the agent's object id.
//
// A blueprint homed in another tenant has its inheritable permissions there,
// out of this pass's reach: its agents' inheritance is not derived.
func (g *azureAgentDetails) inheritedGrants(agents *azureAgentObjects, grants []azureAPIGrant, sps []azure.ServicePrincipal, idMap map[string]uuid.UUID, counters map[string]int) []azureAPIGrant {
	appIDOf := make(map[string]string, len(sps))
	for _, sp := range sps {
		appIDOf[strings.ToLower(sp.ID)] = strings.ToLower(sp.AppID)
	}
	// The agents of each blueprint principal, by its identity row id.
	type heirs struct {
		perms  []azure.InheritablePermission
		agents []string
	}
	byPrincipal := map[uuid.UUID]*heirs{}
	for pid, p := range agents.principals {
		row, ok := idMap[pid]
		if !ok {
			continue
		}
		b, ok := agents.blueprintByApp[strings.ToLower(p.AppID)]
		if !ok || !g.inheritableRead[strings.ToLower(b.ID)] {
			continue
		}
		h := &heirs{perms: g.inheritable[strings.ToLower(b.ID)]}
		for xid, x := range agents.identities {
			if strings.EqualFold(x.AgentIdentityBlueprintID, p.AppID) {
				h.agents = append(h.agents, xid)
			}
		}
		if len(h.perms) > 0 && len(h.agents) > 0 {
			sort.Strings(h.agents)
			byPrincipal[row] = h
		}
	}

	var out []azureAPIGrant
	for _, gr := range grants {
		h, ok := byPrincipal[gr.perm.IdentityID]
		if !ok || len(gr.perm.Actions) == 0 {
			continue
		}
		apiObject, kind, found := strings.Cut(gr.resourceNative, "/")
		if !found {
			continue
		}
		value := gr.perm.Actions[0]
		if value == "default_access" {
			continue
		}
		appID := appIDOf[apiObject]
		inherited := false
		for _, ip := range h.perms {
			if !strings.EqualFold(ip.ResourceAppID, appID) {
				continue
			}
			if strings.HasPrefix(kind, "approles/") {
				inherited = ip.Roles.Allows(value)
			} else {
				inherited = ip.Scopes.Allows(value)
			}
			break
		}
		if !inherited {
			continue
		}
		for _, agent := range h.agents {
			target, ok := idMap[agent]
			if !ok {
				continue
			}
			d := gr
			d.perm.IdentityID = target
			d.perm.NativeID = gr.perm.NativeID + models.InheritedGrantMarker + agent
			out = append(out, d)
			counters["inherited_permissions"]++
		}
	}
	return out
}

/* ------------------------------------ audit ------------------------------------ */

// azureAuditEvent is one audit event as kept on an agent object.
type azureAuditEvent struct {
	ID       string     `json:"id"`
	At       *time.Time `json:"at,omitempty"`
	Activity string     `json:"activity"`
	Category string     `json:"category,omitempty"`
	Result   string     `json:"result,omitempty"`
	// By is who acted (a UPN or app name); ByKind "user", "app" or "agent".
	By     string `json:"by,omitempty"`
	ByKind string `json:"by_kind,omitempty"`
	ByID   string `json:"by_id,omitempty"`
	// Target is what an agent changed (its own actions only).
	Target     string `json:"target,omitempty"`
	TargetKind string `json:"target_kind,omitempty"`
	// Properties are the names of the properties a change modified, never
	// their values.
	Properties []string `json:"properties,omitempty"`
}

// azureAgentAuditTrail is an agent object's audit history: changes made to it,
// changes it made, and who created it, merged across passes.
type azureAgentAuditTrail struct {
	Changes   []azureAuditEvent `json:"audit_changes,omitempty"`
	Actions   []azureAuditEvent `json:"audit_actions,omitempty"`
	CreatedBy *azureAuditEvent  `json:"created_by,omitempty"`
}

// readAgentAudit reads the directory audit log since the last read and
// returns, per agent object, what this read found, and when it read -- nil
// when it did not (no agents, or the read failed), so the next pass starts
// from the last read that did. Trails stored earlier are kept either way.
func (s *AzureOnboardingService) readAgentAudit(ctx context.Context, graphToken string, workspaceID, connectorID uuid.UUID, agents *azureAgentObjects, surfaces map[string]models.SurfaceCoverage, counters map[string]int) (map[string]*azureAgentAuditTrail, *time.Time) {
	agentIDs := map[string]string{}
	for id := range agents.identities {
		agentIDs[id] = "agent_identity"
	}
	for id := range agents.blueprints {
		agentIDs[id] = "blueprint"
	}
	for id := range agents.principals {
		agentIDs[id] = "blueprint_principal"
	}
	for id := range agents.users {
		agentIDs[id] = "agent_user"
	}
	api := "GET /beta/auditLogs/directoryAudits"
	if len(agentIDs) == 0 {
		surfaces[models.SurfaceEntraAgentAudit] = models.SurfaceCoverage{State: models.CloudCoverageReached, API: api}
		return nil, nil
	}

	readAt := time.Now()
	since := readAt.Add(-azureAgentAuditFirstWindow)
	if last := s.agentAuditReadAt(workspaceID, connectorID); last != nil && last.After(since) {
		since = last.Add(-azureAgentAuditOverlap)
	}
	events, err := s.api.ListDirectoryAudits(ctx, graphToken, since, azureAgentAuditPages)
	sc := listSurface(api, len(events), err)
	if errors.Is(err, azure.ErrPageLimit) {
		sc.Error = fmt.Sprintf("the newest %d events since %s were read; older ones in that window were not", len(events), since.UTC().Format(time.RFC3339))
	}
	surfaces[models.SurfaceEntraAgentAudit] = sc
	if err != nil && !errors.Is(err, azure.ErrPageLimit) {
		return nil, nil
	}

	out := map[string]*azureAgentAuditTrail{}
	trail := func(id string) *azureAgentAuditTrail {
		if out[id] == nil {
			out[id] = &azureAgentAuditTrail{}
		}
		return out[id]
	}
	for _, e := range events {
		ev := azureAuditEvent{ID: e.ID, At: e.ActivityDateTime, Activity: e.ActivityDisplayName,
			Category: e.Category, Result: e.Result}
		if u := e.InitiatedBy.User; u != nil && u.ID != "" {
			ev.By, ev.ByKind, ev.ByID = firstNonEmpty(u.UserPrincipalName, u.DisplayName), "user", strings.ToLower(u.ID)
		} else if a := e.InitiatedBy.App; a != nil {
			ev.By, ev.ByKind, ev.ByID = firstNonEmpty(a.DisplayName, a.ServicePrincipalName, a.AppID), "app", strings.ToLower(a.ServicePrincipalID)
		}
		if _, isAgent := agentIDs[ev.ByID]; isAgent && ev.ByID != "" {
			ev.ByKind = "agent"
		}
		matched := false
		for _, t := range e.TargetResources {
			id := strings.ToLower(t.ID)
			if _, ok := agentIDs[id]; !ok {
				continue
			}
			change := ev
			for _, p := range t.ModifiedProperties {
				if p.DisplayName != "" {
					change.Properties = append(change.Properties, p.DisplayName)
				}
			}
			tr := trail(id)
			tr.Changes = append(tr.Changes, change)
			if azureCreationActivities[strings.ToLower(e.ActivityDisplayName)] {
				created := ev
				tr.CreatedBy = &created
			}
			matched = true
		}
		if _, ok := agentIDs[ev.ByID]; ok && ev.ByID != "" {
			action := ev
			if len(e.TargetResources) > 0 {
				t := e.TargetResources[0]
				action.Target, action.TargetKind = firstNonEmpty(t.UserPrincipalName, t.DisplayName, t.ID), t.Type
			}
			tr := trail(ev.ByID)
			tr.Actions = append(tr.Actions, action)
			matched = true
		}
		if matched {
			counters["agent_audit_events"]++
		}
	}
	return out, &readAt
}

// azureCreationActivities are the audit activities that create an Agent ID
// object: a blueprint is logged as an application, an agent identity or
// blueprint principal as a service principal, an agent user as a user.
var azureCreationActivities = map[string]bool{
	"add application": true, "add service principal": true, "add user": true,
}

// agentAuditReadAt is when this tenant's audit log was last read.
func (s *AzureOnboardingService) agentAuditReadAt(workspaceID, connectorID uuid.UUID) *time.Time {
	var row struct{ At *time.Time }
	if err := s.db.Model(&models.CloudConnector{}).
		Select("(attrs->>'agent_audit_read_at')::timestamptz AS at").
		Where("workspace_id = ? AND id = ?", workspaceID, connectorID).
		Scan(&row).Error; err != nil {
		return nil
	}
	return row.At
}

// previousAgentAudit returns the audit trails stored on this tenant's Agent ID
// objects, so a pass adds to the history rather than replacing it: Entra
// keeps at most 30 days.
func (s *AzureOnboardingService) previousAgentAudit(workspaceID, connectorID uuid.UUID) map[string]*azureAgentAuditTrail {
	var rows []struct {
		NativeID string
		Trail    []byte
	}
	out := map[string]*azureAgentAuditTrail{}
	if err := s.db.Model(&models.CloudIdentity{}).
		Select(`native_id, jsonb_build_object('audit_changes', attrs->'audit_changes',
			'audit_actions', attrs->'audit_actions', 'created_by', attrs->'created_by') AS trail`).
		Where(`workspace_id = ? AND connector_id = ? AND (attrs->'audit_changes' IS NOT NULL
			OR attrs->'audit_actions' IS NOT NULL OR attrs->'created_by' IS NOT NULL)`,
			workspaceID, connectorID).
		Scan(&rows).Error; err != nil {
		logAzureError("previous agent audit trails", err)
		return out
	}
	for _, r := range rows {
		var t azureAgentAuditTrail
		if json.Unmarshal(r.Trail, &t) == nil {
			out[r.NativeID] = &t
		}
	}
	return out
}

// mergeAuditTrail keeps every event once, newest first, at most
// azureAgentAuditKeep per list; the first creation found stays.
func mergeAuditTrail(prev, cur *azureAgentAuditTrail) *azureAgentAuditTrail {
	if prev == nil && cur == nil {
		return nil
	}
	if prev == nil {
		prev = &azureAgentAuditTrail{}
	}
	if cur == nil {
		cur = &azureAgentAuditTrail{}
	}
	merge := func(a, b []azureAuditEvent) []azureAuditEvent {
		seen := map[string]bool{}
		var all []azureAuditEvent
		for _, e := range append(append([]azureAuditEvent{}, b...), a...) {
			if seen[e.ID] {
				continue
			}
			seen[e.ID] = true
			all = append(all, e)
		}
		sort.SliceStable(all, func(i, j int) bool {
			ai, aj := all[i].At, all[j].At
			return ai != nil && (aj == nil || ai.After(*aj))
		})
		if len(all) > azureAgentAuditKeep {
			all = all[:azureAgentAuditKeep]
		}
		return all
	}
	out := &azureAgentAuditTrail{Changes: merge(prev.Changes, cur.Changes), Actions: merge(prev.Actions, cur.Actions), CreatedBy: prev.CreatedBy}
	if out.CreatedBy == nil {
		out.CreatedBy = cur.CreatedBy
	}
	return out
}

/* ----------------------------- Conditional Access ----------------------------- */

// agentAccessPolicies picks the Conditional Access policies that concern agent
// identities: they name agents (or all of them), select them by attribute, or
// apply at an agent risk level.
func agentAccessPolicies(policies []azure.ConditionalAccessPolicy) []models.AzureAgentAccessPolicy {
	out := []models.AzureAgentAccessPolicy{}
	for _, p := range policies {
		apps := p.Conditions.ClientApplications
		hasAgents := apps != nil && (len(apps.IncludeAgentIDServicePrincipals) > 0 || apps.AgentIDServicePrincipalFilter != nil)
		if !hasAgents && p.Conditions.AgentIDRiskLevels == "" {
			continue
		}
		a := models.AzureAgentAccessPolicy{ID: strings.ToLower(p.ID), Name: p.DisplayName, State: p.State, IncludeAgents: []string{}}
		if apps != nil {
			a.IncludeAgents = lowerGUIDs(apps.IncludeAgentIDServicePrincipals)
			a.ExcludeAgents = lowerGUIDs(apps.ExcludeAgentIDServicePrincipals)
			if f := apps.AgentIDServicePrincipalFilter; f != nil && f.Rule != "" {
				a.AgentFilter = f.Mode + ": " + f.Rule
			}
		}
		for _, l := range strings.Split(p.Conditions.AgentIDRiskLevels, ",") {
			if l = strings.TrimSpace(l); l != "" {
				a.AgentRiskLevels = append(a.AgentRiskLevels, l)
			}
		}
		if x := p.Conditions.Applications; x != nil {
			a.IncludeApplications = x.IncludeApplications
		}
		if p.GrantControls != nil {
			a.GrantControls = p.GrantControls.BuiltInControls
		}
		out = append(out, a)
	}
	return out
}

// lowerGUIDs lowercases object ids and keeps keywords ("All", ...) as written.
func lowerGUIDs(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if azure.IsGUID(id) {
			id = strings.ToLower(id)
		}
		out = append(out, id)
	}
	return out
}

/* ---------------------------------- decorate ---------------------------------- */

// decorateAgent writes what the detail reads found onto one Agent ID object's
// identity row: its sponsors, and its audit trail.
func (s *AzureOnboardingService) decorateAgent(ident *models.CloudIdentity, agents *azureAgentObjects, gov *azureAgentDetails,
	dir azureDirectoryState, trails, prevTrails map[string]*azureAgentAuditTrail) {
	id := ident.NativeID
	attrs := map[string]interface{}{}
	_ = json.Unmarshal(ident.Attrs, &attrs)
	agentType, _ := attrs["agent_type"].(string)

	isBlueprint := agentType == models.AgentTypeBlueprint
	isIdentity := ident.Kind == models.CloudIdentityEntraAgentIdentity
	isUser := ident.Kind == models.CloudIdentityEntraAgentUser
	isPrincipal := agentType == models.AgentTypeBlueprintPrincipal
	if !isBlueprint && !isIdentity && !isUser && !isPrincipal {
		return
	}
	extra := map[string]interface{}{}

	if t := mergeAuditTrail(prevTrails[id], trails[id]); t != nil {
		if len(t.Changes) > 0 {
			extra["audit_changes"] = t.Changes
		}
		if len(t.Actions) > 0 {
			extra["audit_actions"] = t.Actions
		}
		if t.CreatedBy != nil {
			extra["created_by"] = t.CreatedBy
		}
	}

	if gov.sponsorsRead[id] {
		extra["sponsors"], extra["sponsor_source"] = dir.refs(gov.sponsors[id]), "own"
	} else if isIdentity && gov.ownSponsorsDenied {
		// Microsoft gates an agent identity's own sponsors behind a write
		// permission; its blueprint's are the ones AuthSec can read.
		if x, ok := agents.identities[id]; ok {
			if b, ok := agents.blueprintByApp[strings.ToLower(x.AgentIdentityBlueprintID)]; ok {
				if bid := strings.ToLower(b.ID); gov.sponsorsRead[bid] {
					extra["sponsors"], extra["sponsor_source"] = dir.refs(gov.sponsors[bid]), "blueprint"
				}
			}
		}
	}
	if len(extra) > 0 {
		mergeAttrs(ident, extra)
	}
}
