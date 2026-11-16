package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/gcp"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"google.golang.org/api/cloudasset/v1"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

/* cloud_gcp_scan_bindings.go answers "who has which role on what, under which
   condition, and where is it attached".

   ONE CALL, TWO SURFACES. Cloud Asset searchAllIamPolicies over the connector's
   scope returns every IAM policy beneath it: organization, folder and project
   policies (surface allow_bindings) and resource-level policies on buckets,
   datasets, secrets and the rest (surface resource_iam). They come from the same
   read, so a read that is cut short -- a page ceiling, a deadline, a member that
   could not be parsed -- leaves BOTH not reached. Neither may reconcile.

   A BINDING IS STORED ONCE, WHERE IT IS ATTACHED. The search returns a policy at
   the resource that holds it, never an inherited copy, and so does this writer:
   attrs carries attached_to, the GCP scope kind and the ancestor chain, from
   which a descendant's inherited access is computed at read time. Writing a copy
   per descendant would multiply rows by project count and double-count later.

   ONE ROW PER (policy resource, role, member, condition). The condition is part
   of the row's native_id, because one member can hold one role twice under
   different conditions and the unique key would otherwise merge them. A changed
   condition is a new row; the old one is reconciled away.

   ORG/FOLDER/PROJECT BINDINGS ARE account_wide AND HAVE NO RESOURCE ROW. The
   shared scope_kind CHECK knows only resource | prefix | account_wide, and ties
   resource_id to it; the GCP-level scope kind lives in attrs.

   NOTHING IS EVALUATED. A condition's CEL is kept verbatim (condition column and
   attrs.binding_raw); only simple request.time bounds are read out, into
   attrs.expires_at / starts_at.

   EVERY MEMBER BECOMES AN IDENTITY FIRST (cloud_permission.identity_id is NOT
   NULL): users, groups, domains, allUsers, federated principals, Google's service
   agents, and principals deleted while their bindings stayed. A member that does
   not parse is counted and fails the surfaces, never silently skipped. */

const (
	gcpBindingsTimeout  = 20 * time.Minute
	gcpRolesTimeout     = 15 * time.Minute
	gcpBindingsPageSize = 500
)

// errGCPMembersUnparsed means a binding member could not be turned into an
// identity, so a permission row was not written. The surfaces are not reached.
var errGCPMembersUnparsed = errors.New("gcp: binding members could not be parsed")

// errGCPBindingsTruncated means the binding read stopped at its page ceiling.
var errGCPBindingsTruncated = fmt.Errorf("gcp: binding search exceeded %d pages", gcpMaxPages)

// errGCPNoQuotaProject: Cloud Asset bills every call to a quota project.
var errGCPNoQuotaProject = errors.New("gcp: cloud asset needs a quota project and the connector has none")

// gcpBindingAccs are the four surfaces this file owns. sa (service-account
// policies) is read separately only when Cloud Asset refuses; on the Cloud Asset
// path it mirrors resource, because those policies arrive in the same read.
type gcpBindingAccs struct {
	roles    *gcpSurfaceAcc
	allow    *gcpSurfaceAcc
	resource *gcpSurfaceAcc
	sa       *gcpSurfaceAcc
}

func newGCPBindingAccs() gcpBindingAccs {
	return gcpBindingAccs{
		roles:    newGCPSurfaceAcc(),
		allow:    newGCPSurfaceAcc(),
		resource: newGCPSurfaceAcc(),
		sa:       newGCPSurfaceAcc(),
	}
}

// failAll records a failure that happened before any read.
func (a gcpBindingAccs) failAll(err error) {
	a.roles.fail(err)
	a.failPolicies(err)
}

// failPolicies records one failure on every policy surface (not roles).
func (a gcpBindingAccs) failPolicies(err error) {
	a.allow.fail(err)
	a.resource.fail(err)
	a.sa.fail(err)
}

// gcpBindingScope is the Cloud Asset scope for a connector.
func gcpBindingScope(kind, id string) (string, error) {
	switch kind {
	case models.CloudScopeOrg:
		return "organizations/" + id, nil
	case models.CloudScopeFolder:
		return "folders/" + id, nil
	case models.CloudScopeProject:
		return "projects/" + id, nil
	}
	return "", fmt.Errorf("gcp: no binding scope for connector scope kind %q", kind)
}

// runBindingPhases reads custom roles, then every IAM policy under the scope.
func (s *GCPScanner) runBindingPhases(
	scanCtx context.Context, workspaceID uuid.UUID, snapshot *GCPScanSnapshot,
	attrs models.GCPConnectorAttrs, authOpt option.ClientOption, iamClient *iam.Service,
	governor *gcp.Governor, accs gcpBindingAccs, written []gcpWrittenIdentity,
) {
	// The two binding surfaces share one call, so one proof of unreadable skips
	// both: reading for one and not the other would split a single answer.
	reasonA, skipA := gcpProbeSaysUnreadable(attrs, gcp.SurfaceAllowBindings)
	reasonR, skipR := gcpProbeSaysUnreadable(attrs, gcp.SurfaceResourceIAM)
	if skipA || skipR {
		reason := reasonA
		if reason == "" {
			reason = reasonR
		}
		accs.allow.skipNotReadable(reason)
		accs.resource.skipNotReadable(reason)
		accs.sa.skipNotReadable(reason)
	}
	rolesReason, rolesSkip := gcpProbeSaysUnreadable(attrs, gcp.SurfaceRoles)
	if rolesSkip {
		accs.roles.skipNotReadable(rolesReason)
	}
	bindingsSkipped := skipA || skipR

	if bindingsSkipped && rolesSkip {
		return
	}

	// ---- role catalog ------------------------------------------------------
	rolesCtx, cancelRoles := context.WithTimeout(scanCtx, gcpRolesTimeout)
	defer cancelRoles()
	var catalog *gcp.RoleCatalog
	if !rolesSkip {
		catalog = s.loadRoleCatalog(rolesCtx, snapshot, iamClient, governor, accs.roles)
	}
	if bindingsSkipped {
		return
	}

	// ---- bindings ----------------------------------------------------------
	quota := attrs.CAIQuotaProject
	if quota == "" {
		quota = attrs.ReaderProjectID
	}
	if quota == "" {
		accs.failPolicies(errGCPNoQuotaProject)
		return
	}
	scope, err := gcpBindingScope(snapshot.ScopeKind, snapshot.ScopeID)
	if err != nil {
		accs.failPolicies(err)
		return
	}
	client, err := s.newCAIClient(scanCtx, authOpt, quota)
	if err != nil {
		accs.failPolicies(err)
		return
	}

	bindCtx, cancelBind := context.WithTimeout(scanCtx, gcpBindingsTimeout)
	defer cancelBind()
	// Cloud Asset can refuse the token's read-only scopes for this method (seen
	// live). Resource Manager's getIamPolicy is the fallback for the hierarchy
	// levels, so its client is built up front.
	rm, rmErr := s.newRMClient(scanCtx, authOpt)
	if rmErr != nil {
		rm = nil
	}
	s.collectBindings(bindCtx, rolesCtx, workspaceID, snapshot, client, rm, iamClient, scope, governor, catalog, accs, written)
}

// loadRoleCatalog lists custom roles under the scope's parents and records the
// outcome on the roles surface.
func (s *GCPScanner) loadRoleCatalog(
	ctx context.Context, snapshot *GCPScanSnapshot, iamClient *iam.Service,
	governor *gcp.Governor, acc *gcpSurfaceAcc,
) *gcp.RoleCatalog {
	var parents []string
	if snapshot.ScopeKind == models.CloudScopeOrg {
		parents = append(parents, "organizations/"+snapshot.ScopeID)
	}
	for _, p := range snapshot.Projects {
		parents = append(parents, "projects/"+p.ProjectID)
	}
	catalog, err := gcp.LoadCatalog(ctx, iamClient, governor, parents)
	if err != nil {
		if gcp.IsScopeInsufficient(err) {
			acc.skipNotReadable("not_readable: token scopes cannot list roles")
			return catalog
		}
		acc.observe(err, 0)
		return catalog
	}
	acc.observe(nil, 0)
	return catalog
}

// gcpBindingState is what one pass over the search results accumulates.
type gcpBindingState struct {
	workspaceID uuid.UUID
	snapshot    *GCPScanSnapshot
	written     []gcpWrittenIdentity
	catalog     *gcp.RoleCatalog
	rolesCtx    context.Context
	rolesAcc    *gcpSurfaceAcc
	readTime    string

	members   map[string]gcpWrittenIdentity // raw member -> identity row
	resources map[string]uuid.UUID          // asset name -> cloud_resource id
	roles     map[string]gcpRoleOutcome     // role name -> outcome, once per scan

	unparsed      int
	allowCount    int
	resourceCount int
	rolesResolved int
}

type gcpRoleOutcome struct {
	role  gcp.Role
	state string
	err   error
}

func (s *GCPScanner) collectBindings(
	ctx, rolesCtx context.Context, workspaceID uuid.UUID, snapshot *GCPScanSnapshot,
	client *cloudasset.Service, rm *cloudresourcemanager.Service, iamClient *iam.Service, scope string, governor *gcp.Governor,
	catalog *gcp.RoleCatalog, accs gcpBindingAccs, written []gcpWrittenIdentity,
) {
	st := &gcpBindingState{
		workspaceID: workspaceID, snapshot: snapshot, written: written,
		catalog: catalog, rolesCtx: rolesCtx, rolesAcc: accs.roles,
		members:   map[string]gcpWrittenIdentity{},
		resources: map[string]uuid.UUID{},
		roles:     map[string]gcpRoleOutcome{},
	}

	defer st.finishRoles()

	finish := func(err error) {
		if err != nil {
			// One read, two surfaces: a failure is both's failure.
			if gcp.IsScopeInsufficient(err) && rm != nil && st.allowCount+st.resourceCount == 0 {
				// Fall back to the hierarchy levels, which Resource Manager may read
				// with the same scopes. Only when nothing was written yet: a mid-read
				// refusal is not a reason to mix two sources.
				s.collectBindingsViaResourceManager(ctx, st, rm, governor, accs)
				s.collectServiceAccountPolicies(ctx, st, iamClient, governor, accs.sa)
				return
			}
			if gcp.IsScopeInsufficient(err) || gcp.IsServiceDisabled(err) {
				// Neither is "no bindings": the API is off, or the token cannot
				// cover it. Not attempted, so nothing is reconciled against it.
				reason := "not_readable: cloud asset search refused the token's scopes: " + sanitizedSurfaceReason(err)
				if gcp.IsServiceDisabled(err) {
					reason = "not_readable: cloud asset API is not enabled on the quota project: " + sanitizedSurfaceReason(err)
				}
				accs.allow.skipNotReadable(reason)
				accs.resource.skipNotReadable(reason)
				accs.sa.skipNotReadable(reason)
				return
			}
			accs.allow.observe(err, st.allowCount)
			accs.resource.observe(err, st.resourceCount)
			accs.sa.observe(err, 0)
			return
		}
		if st.unparsed > 0 {
			bad := fmt.Errorf("%w: %d member(s)", errGCPMembersUnparsed, st.unparsed)
			accs.allow.observe(bad, st.allowCount)
			accs.resource.observe(bad, st.resourceCount)
			accs.sa.observe(bad, 0)
			return
		}
		accs.allow.observe(nil, st.allowCount)
		accs.resource.observe(nil, st.resourceCount)
		// Service-account policies came in this same read; their rows are
		// counted under resource_iam.
		accs.sa.observe(nil, 0)
	}

	token := ""
	for page := 0; page < gcpMaxPages; page++ {
		var resp *cloudasset.SearchAllIamPoliciesResponse
		pageToken := token
		release, err := governor.AcquireCAI(ctx)
		if err != nil {
			finish(err)
			return
		}
		err = gcp.Retry(ctx, func() error {
			if err := governor.CAI.Wait(ctx); err != nil {
				return err
			}
			out, callErr := client.V1.SearchAllIamPolicies(scope).
				PageSize(gcpBindingsPageSize).
				PageToken(pageToken).
				Context(ctx).
				Do()
			if callErr != nil {
				return callErr
			}
			resp = out
			return nil
		})
		release()
		if err != nil {
			finish(err)
			return
		}
		st.readTime = time.Now().UTC().Format(time.RFC3339)
		for _, result := range resp.Results {
			if err := s.writeBindingsOf(ctx, st, result); err != nil {
				finish(err)
				return
			}
		}
		if resp.NextPageToken == "" {
			finish(nil)
			return
		}
		token = resp.NextPageToken
	}
	finish(errGCPBindingsTruncated)
}

// finishRoles records role-resolution failures on the roles surface. A custom
// listing outcome was recorded when the catalog loaded; a roles.get that could
// not be answered is recorded here, once per role.
func (st *gcpBindingState) finishRoles() {
	for _, o := range st.roles {
		if o.err != nil {
			if gcp.IsScopeInsufficient(o.err) {
				st.rolesAcc.skipNotReadable("not_readable: token scopes cannot read roles")
				continue
			}
			st.rolesAcc.observe(o.err, 0)
		}
	}
	if st.rolesResolved > 0 {
		// The distinct roles expanded this scan, reported as the surface's count.
		st.rolesAcc.observe(nil, st.rolesResolved)
	}
}

// resolveRole expands a role once per scan.
func (st *gcpBindingState) resolveRole(name string) gcpRoleOutcome {
	if o, ok := st.roles[name]; ok {
		return o
	}
	var o gcpRoleOutcome
	switch {
	case gcp.IsBasicRole(name):
		o = gcpRoleOutcome{role: gcp.Role{Name: name, Stage: gcp.RoleStageGA, Basic: true}, state: "basic"}
	case st.catalog == nil:
		// The roles surface was not attempted (the probe proved it unreadable).
		o = gcpRoleOutcome{role: gcp.Role{Name: name}, state: "unavailable"}
	default:
		role, err := st.catalog.Expand(st.rolesCtx, name)
		switch {
		case err != nil:
			o = gcpRoleOutcome{role: gcp.Role{Name: name}, state: "unavailable", err: err}
		case role.Unresolved:
			o = gcpRoleOutcome{role: role, state: "deleted"}
		default:
			o = gcpRoleOutcome{role: role, state: "expanded"}
			st.rolesResolved++
		}
	}
	st.roles[name] = o
	return o
}

// writeBindingsOf writes every (role, member) of one policy.
func (s *GCPScanner) writeBindingsOf(ctx context.Context, st *gcpBindingState, r *cloudasset.IamPolicySearchResult) error {
	if r == nil || r.Policy == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	kind := gcp.AssetKind(r.AssetType)
	isScope := gcp.IsScopeKind(kind)

	var resourceID *uuid.UUID
	scopeKind := models.GCPScopeResource
	permScope := "resource"
	switch kind {
	case gcp.KindOrganization:
		scopeKind, permScope = models.GCPScopeOrganization, "account_wide"
	case gcp.KindFolder:
		scopeKind, permScope = models.GCPScopeFolder, "account_wide"
	case gcp.KindProject:
		scopeKind, permScope = models.GCPScopeProject, "account_wide"
	}
	if !isScope {
		id, err := s.upsertBindingResource(st, r, kind)
		if err != nil {
			return err
		}
		resourceID = &id
	}
	ancestors := gcpAncestors(r, kind)
	projectRef := strings.TrimPrefix(r.Project, "projects/")

	for _, b := range r.Policy.Bindings {
		if b == nil || b.Role == "" {
			continue
		}
		role := st.resolveRole(b.Role)
		var cond *gcp.Condition
		if b.Condition != nil {
			cond = gcp.ParseCondition(b.Condition.Title, b.Condition.Description, b.Condition.Expression)
		}
		for _, raw := range b.Members {
			identity, ok, err := s.bindingMemberIdentity(st, raw)
			if err != nil {
				return err
			}
			if !ok {
				st.unparsed++
				continue
			}
			perm, err := buildGCPPermission(st, r, b, raw, role, cond, identity, resourceID, scopeKind, permScope, ancestors, projectRef, kind)
			if err != nil {
				return err
			}
			if role.state == "unavailable" && s.gcpRead != nil {
				// The role could not be read this scan: keep the permissions the row
				// was last expanded to instead of erasing them (the row still says
				// role_state=unavailable).
				if prev, ok, err := s.gcpRead.StoredActions(st.workspaceID, perm.IdentityID, perm.NativeID, perm.ResourceID); err != nil {
					return err
				} else if ok && len(prev) > 0 {
					perm.Actions = prev
				}
			}
			if _, _, err := s.permissions.UpsertPermission(perm); err != nil {
				return err
			}
			if isScope {
				st.allowCount++
			} else {
				st.resourceCount++
			}
		}
	}
	return nil
}

func (s *GCPScanner) bindingMemberIdentity(st *gcpBindingState, raw string) (gcpWrittenIdentity, bool, error) {
	if id, ok := st.members[raw]; ok {
		return id, true, nil
	}
	m, err := gcp.ParseMember(raw)
	if err != nil {
		return gcpWrittenIdentity{}, false, nil
	}
	id, err := s.upsertMemberIdentity(st.workspaceID, st.snapshot, m, st.written)
	if err != nil {
		return gcpWrittenIdentity{}, false, err
	}
	st.members[raw] = id
	return id, true, nil
}

func (s *GCPScanner) upsertBindingResource(st *gcpBindingState, r *cloudasset.IamPolicySearchResult, kind string) (uuid.UUID, error) {
	if id, ok := st.resources[r.Resource]; ok {
		return id, nil
	}
	project := strings.TrimPrefix(r.Project, "projects/")
	external := gcpProjectOutsideScope(project, st.snapshot.Projects)
	res := &models.CloudResource{
		WorkspaceID:        st.workspaceID,
		ConnectorID:        st.snapshot.ConnectorID,
		Kind:               kind,
		NativeID:           r.Resource,
		Name:               gcp.ResourceDisplayName(r.Resource),
		ResourceAccount:    project,
		IsExternal:         external && project != "",
		Sensitivity:        gcp.ResourceSensitivity(kind),
		SensitivitySource:  models.SensitivityFromHeuristic,
		LastSeenGeneration: st.snapshot.Generation,
	}
	stored, _, err := s.permissions.UpsertResource(res)
	if err != nil {
		return uuid.Nil, err
	}
	st.resources[r.Resource] = stored.ID
	return stored.ID, nil
}

// gcpProjectOutsideScope reports whether a project reference (id or number) is
// shown to lie outside the scanned set. Unknown is false: with no number to
// compare, nothing is shown to be outside.
func gcpProjectOutsideScope(ref string, projects []gcpProject) bool {
	if ref == "" || len(projects) == 0 {
		return false
	}
	for _, p := range projects {
		if p.ProjectID == ref || (p.Number != "" && p.Number == ref) {
			return false
		}
	}
	for _, p := range projects {
		if p.Number == "" {
			return false
		}
	}
	return true
}

// gcpAncestors is the chain above the attachment point, as Google returned it:
// the project (for a resource), then folders, then the organization.
func gcpAncestors(r *cloudasset.IamPolicySearchResult, kind string) []string {
	var out []string
	add := func(name string) {
		if name == "" || strings.HasSuffix(r.Resource, "/"+name) {
			return
		}
		out = append(out, name)
	}
	if kind != gcp.KindProject && kind != gcp.KindFolder && kind != gcp.KindOrganization {
		add(r.Project)
	}
	if kind != gcp.KindOrganization {
		for _, f := range r.Folders {
			add(f)
		}
		add(r.Organization)
	}
	return out
}

// gcpBindingNativeID is unique per (policy resource, role, condition); the
// identity and resource complete the key.
func gcpBindingNativeID(attachedTo, role string, cond *gcp.Condition) string {
	id := "//gcp/binding/" + attachedTo + "#" + role
	if h := cond.Hash(); h != "" {
		id += "#" + h
	}
	return id
}

func buildGCPPermission(
	st *gcpBindingState, r *cloudasset.IamPolicySearchResult, b *cloudasset.Binding, rawMember string,
	role gcpRoleOutcome, cond *gcp.Condition, identity gcpWrittenIdentity, resourceID *uuid.UUID,
	scopeKind, permScope string, ancestors []string, project, kind string,
) (*models.CloudPermission, error) {
	raw, err := json.Marshal(struct {
		Role      string           `json:"role"`
		Member    string           `json:"member"`
		Condition *cloudasset.Expr `json:"condition,omitempty"`
	}{b.Role, rawMember, b.Condition})
	if err != nil {
		return nil, err
	}
	pa := models.GCPPermissionAttrs{
		AttachedTo:     r.Resource,
		GCPScopeKind:   scopeKind,
		Ancestors:      ancestors,
		Project:        project,
		Member:         rawMember,
		ReadTime:       st.readTime,
		BindingRaw:     raw,
		RoleUnresolved: role.state == "deleted",
		BasicRole:      role.role.Basic,
		RoleStage:      role.role.Stage,
		RoleState:      role.state,
	}
	state := "unconstrained"
	var condJSON *string
	if cond != nil {
		state = "conditional"
		js, err := cond.JSON()
		if err != nil {
			return nil, err
		}
		condJSON = &js
		if cond.ExpiresAt != nil {
			pa.ExpiresAt = cond.ExpiresAt.Format(time.RFC3339)
		}
		if cond.StartsAt != nil {
			pa.StartsAt = cond.StartsAt.Format(time.RFC3339)
		}
	}
	attrs, err := json.Marshal(pa)
	if err != nil {
		return nil, err
	}
	roleName := b.Role
	actions := role.role.Permissions
	if role.state == "deleted" {
		// A deleted role grants nothing while it stays deleted (ticket: keep
		// role_name, empty actions, role_unresolved).
		actions = nil
	}
	if actions == nil {
		actions = []string{}
	}
	return &models.CloudPermission{
		WorkspaceID:        st.workspaceID,
		ConnectorID:        st.snapshot.ConnectorID,
		IdentityID:         identity.IdentityID,
		ResourceID:         resourceID,
		Plane:              "cloud",
		Effect:             "allow",
		RoleName:           &roleName,
		Actions:            actions,
		Condition:          condJSON,
		ConstraintState:    state,
		ScopeKind:          permScope,
		Derivation:         "granted",
		Sensitivity:        gcpPermissionSensitivity(b.Role, actions, kind),
		NativeID:           gcpBindingNativeID(r.Resource, b.Role, cond),
		Attrs:              attrs,
		LastSeenGeneration: st.snapshot.Generation,
	}, nil
}

// gcpPermissionSensitivity is the starting heuristic, never a verdict: broad
// legacy roles, admin roles and the permissions that move identity, keys or
// secrets are high; any write is medium; the rest low. A resource kind can only
// raise it.
func gcpPermissionSensitivity(role string, actions []string, resourceKind string) string {
	level := 0
	switch {
	case role == "roles/owner" || role == "roles/editor":
		level = 2
	case strings.HasSuffix(role, ".admin") || strings.HasSuffix(role, "Admin") || strings.HasSuffix(role, ".owner"):
		level = 2
	case strings.HasPrefix(role, "roles/viewer"):
		level = 0
	}
	for _, a := range actions {
		switch {
		case strings.HasPrefix(a, "secretmanager.versions.access"),
			strings.HasPrefix(a, "cloudkms."),
			strings.HasSuffix(a, ".setIamPolicy"),
			strings.HasPrefix(a, "iam.serviceAccounts.actAs"),
			strings.HasPrefix(a, "iam.serviceAccounts.getAccessToken"),
			strings.HasPrefix(a, "iam.serviceAccounts.implicitDelegation"),
			strings.HasPrefix(a, "iam.serviceAccountKeys.create"):
			level = 2
		case strings.Contains(a, ".create") || strings.Contains(a, ".update") ||
			strings.Contains(a, ".delete") || strings.Contains(a, ".set"):
			if level < 1 {
				level = 1
			}
		}
	}
	switch gcp.ResourceSensitivity(resourceKind) {
	case "high":
		if level < 2 {
			level = 2
		}
	case "med":
		if level < 1 {
			level = 1
		}
	}
	return [...]string{"low", "med", "high"}[level]
}

/* ----------------------- fallback: Resource Manager ------------------------- */

// collectBindingsViaResourceManager reads the allow policies of the scope's
// organization, folders and projects with Resource Manager's getIamPolicy, for
// when Cloud Asset refuses the token's scopes.
//
// IT IS HALF A READ, AND SAYS SO. Resource-level policies (a bucket's, a
// dataset's) are only reachable through Cloud Asset, so resource_iam is reported
// not_selected with the reason. allow_bindings is reached only if every level was
// read. Because resource_iam is not reached, permissions are not reconciled and
// the principals that only resource policies name are protected from reconcile.
func (s *GCPScanner) collectBindingsViaResourceManager(
	ctx context.Context, st *gcpBindingState, rm *cloudresourcemanager.Service,
	governor *gcp.Governor, accs gcpBindingAccs,
) {
	accs.resource.skipNotReadable(
		"not_readable: resource-level policies need Cloud Asset, which refused the token's read-only scopes " +
			"(hierarchy-level bindings were read through Resource Manager instead)")

	nodes := gcpHierarchyNodes(st.snapshot)
	byKey := map[string]gcp.ScopeNode{}
	for _, n := range nodes {
		byKey[gcpNodeResource(n)] = n
	}
	var readErr error
	for _, n := range nodes {
		if err := ctx.Err(); err != nil {
			readErr = err
			break
		}
		resource := gcpNodeResource(n)
		var policy *cloudresourcemanager.Policy
		err := gcp.Retry(ctx, func() error {
			if err := governor.ResourceManager.Wait(ctx); err != nil {
				return err
			}
			req := &cloudresourcemanager.GetIamPolicyRequest{
				Options: &cloudresourcemanager.GetPolicyOptions{RequestedPolicyVersion: 3},
			}
			var out *cloudresourcemanager.Policy
			var callErr error
			switch n.Kind {
			case gcp.ScopeNodeOrganization:
				out, callErr = rm.Organizations.GetIamPolicy(resource, req).Context(ctx).Do()
			case gcp.ScopeNodeFolder:
				out, callErr = rm.Folders.GetIamPolicy(resource, req).Context(ctx).Do()
			default:
				out, callErr = rm.Projects.GetIamPolicy(resource, req).Context(ctx).Do()
			}
			if callErr != nil {
				return callErr
			}
			policy = out
			return nil
		})
		if err != nil {
			readErr = err
			break
		}
		st.readTime = time.Now().UTC().Format(time.RFC3339)
		if err := s.writeBindingsOf(ctx, st, gcpResultFromPolicy(n, byKey, policy)); err != nil {
			readErr = err
			break
		}
	}

	switch {
	case readErr == nil && st.unparsed > 0:
		accs.allow.observe(fmt.Errorf("%w: %d member(s)", errGCPMembersUnparsed, st.unparsed), st.allowCount)
	case readErr == nil:
		accs.allow.observe(nil, st.allowCount)
	case gcp.IsScopeInsufficient(readErr) || gcp.IsServiceDisabled(readErr):
		accs.allow.skipNotReadable("not_readable: neither Cloud Asset nor Resource Manager accepted the token's scopes: " +
			sanitizedSurfaceReason(readErr))
	default:
		accs.allow.observe(readErr, st.allowCount)
	}
}

// gcpHierarchyNodes is every organization, folder and project the scan knows.
func gcpHierarchyNodes(snapshot *GCPScanSnapshot) []gcp.ScopeNode {
	if snapshot.Tree != nil && len(snapshot.Tree.Nodes) > 0 {
		out := make([]gcp.ScopeNode, 0, len(snapshot.Tree.Nodes))
		out = append(out, snapshot.Tree.Nodes...)
		return out
	}
	var out []gcp.ScopeNode
	for _, p := range snapshot.Projects {
		out = append(out, gcp.ScopeNode{ID: p.ProjectID, Kind: gcp.ScopeNodeProject, Number: p.Number})
	}
	return out
}

// gcpNodeResource is "organizations/1", "folders/2" or "projects/id".
func gcpNodeResource(n gcp.ScopeNode) string {
	switch n.Kind {
	case gcp.ScopeNodeOrganization:
		return "organizations/" + n.ID
	case gcp.ScopeNodeFolder:
		return "folders/" + n.ID
	}
	return "projects/" + n.ID
}

// gcpResultFromPolicy shapes a Resource Manager policy as the Cloud Asset result
// the writer already consumes, with the ancestor chain taken from the scope tree.
func gcpResultFromPolicy(n gcp.ScopeNode, byKey map[string]gcp.ScopeNode, p *cloudresourcemanager.Policy) *cloudasset.IamPolicySearchResult {
	res := &cloudasset.IamPolicySearchResult{
		Resource: "//cloudresourcemanager.googleapis.com/" + gcpNodeResource(n),
		Policy:   &cloudasset.Policy{},
	}
	switch n.Kind {
	case gcp.ScopeNodeOrganization:
		res.AssetType = "cloudresourcemanager.googleapis.com/Organization"
		res.Organization = gcpNodeResource(n)
	case gcp.ScopeNodeFolder:
		res.AssetType = "cloudresourcemanager.googleapis.com/Folder"
	default:
		res.AssetType = "cloudresourcemanager.googleapis.com/Project"
		if n.Number != "" {
			res.Project = "projects/" + n.Number
		}
	}
	gcpFillAncestors(res, n.Parent, byKey)
	if p != nil {
		for _, b := range p.Bindings {
			cb := &cloudasset.Binding{Role: b.Role, Members: b.Members}
			if b.Condition != nil {
				cb.Condition = &cloudasset.Expr{
					Title: b.Condition.Title, Description: b.Condition.Description, Expression: b.Condition.Expression,
				}
			}
			res.Policy.Bindings = append(res.Policy.Bindings, cb)
		}
	}
	return res
}

// gcpFillAncestors walks Parent links up from parent, nearest first, filling the
// result's folders and organization as Cloud Asset would.
func gcpFillAncestors(res *cloudasset.IamPolicySearchResult, parent string, byKey map[string]gcp.ScopeNode) {
	for hops := 0; parent != "" && hops < 64; hops++ {
		switch {
		case strings.HasPrefix(parent, "folders/"):
			res.Folders = append(res.Folders, parent)
		case strings.HasPrefix(parent, "organizations/"):
			res.Organization = parent
		}
		next, ok := byKey[parent]
		if !ok {
			return
		}
		parent = next.Parent
	}
}

/* ----------------------- fallback: service-account policies ----------------- */

// collectServiceAccountPolicies reads the IAM policy ON each service account the
// scan listed (who may act as it, mint tokens for it, or bind a Kubernetes
// service account to it), with the IAM API's getIamPolicy, for when Cloud Asset
// refuses the token's scopes. These are the bindings GCP-4's impersonation and
// GKE edges come from.
//
// Each policy is written exactly as a Cloud Asset result would be: a
// service_account cloud_resource named //iam.googleapis.com/projects/<p>/
// serviceAccounts/<unique id>, scope_kind resource. A policy with no bindings
// writes nothing. A service account deleted between list and get is skipped.
// Anything else that stops the read leaves the surface not reached, so these
// rows are not reconciled.
func (s *GCPScanner) collectServiceAccountPolicies(
	ctx context.Context, st *gcpBindingState, client *iam.Service, governor *gcp.Governor, acc *gcpSurfaceAcc,
) {
	if client == nil {
		acc.fail(errors.New("gcp: no IAM client for service-account policies"))
		return
	}
	byKey := map[string]gcp.ScopeNode{}
	projectNode := map[string]gcp.ScopeNode{}
	for _, n := range gcpHierarchyNodes(st.snapshot) {
		byKey[gcpNodeResource(n)] = n
		if n.Kind == gcp.ScopeNodeProject {
			projectNode[n.ID] = n
		}
	}

	startCount, startUnparsed := st.resourceCount, st.unparsed
	var readErr error
	for _, w := range st.written {
		if w.UniqueID == "" || w.Email == "" {
			continue // a principal named in a binding, not a listed service account
		}
		if err := ctx.Err(); err != nil {
			readErr = err
			break
		}
		var policy *iam.Policy
		err := gcp.Retry(ctx, func() error {
			if err := governor.IAM.Wait(ctx); err != nil {
				return err
			}
			// Policy version 3, so conditional bindings come back with their conditions.
			out, callErr := client.Projects.ServiceAccounts.GetIamPolicy("projects/-/serviceAccounts/"+w.Email).
				OptionsRequestedPolicyVersion(3).Context(ctx).Do()
			if callErr != nil {
				return callErr
			}
			policy = out
			return nil
		})
		if err != nil {
			if gcpIsNotFound(err) {
				continue // deleted since it was listed
			}
			readErr = err
			break
		}
		if policy == nil || len(policy.Bindings) == 0 {
			continue
		}
		st.readTime = time.Now().UTC().Format(time.RFC3339)
		res := gcpServiceAccountPolicyResult(w, policy)
		if n, ok := projectNode[w.ProjectID]; ok {
			gcpFillAncestors(res, n.Parent, byKey)
		}
		if err := s.writeBindingsOf(ctx, st, res); err != nil {
			readErr = err
			break
		}
	}

	written := st.resourceCount - startCount
	switch {
	case readErr == nil && st.unparsed > startUnparsed:
		acc.observe(fmt.Errorf("%w: %d member(s)", errGCPMembersUnparsed, st.unparsed-startUnparsed), written)
	case readErr == nil:
		acc.observe(nil, written)
	case gcp.IsScopeInsufficient(readErr) || gcp.IsServiceDisabled(readErr):
		acc.skipNotReadable("not_readable: service-account policies: " + sanitizedSurfaceReason(readErr))
	default:
		acc.observe(readErr, written)
	}
}

// gcpIsNotFound reports a 404 from a Google API.
func gcpIsNotFound(err error) bool {
	var gerr *googleapi.Error
	return errors.As(err, &gerr) && gerr.Code == 404
}

// gcpServiceAccountPolicyResult shapes a service account's own policy as the
// Cloud Asset result the binding writer consumes, under the name Cloud Asset
// would give it, so a later Cloud Asset read updates the same rows.
func gcpServiceAccountPolicyResult(w gcpWrittenIdentity, p *iam.Policy) *cloudasset.IamPolicySearchResult {
	res := &cloudasset.IamPolicySearchResult{
		Resource:  "//iam.googleapis.com/projects/" + w.ProjectID + "/serviceAccounts/" + w.UniqueID,
		AssetType: "iam.googleapis.com/ServiceAccount",
		Policy:    &cloudasset.Policy{},
	}
	if w.ProjectNumber != "" {
		res.Project = "projects/" + w.ProjectNumber
	}
	for _, b := range p.Bindings {
		if b == nil {
			continue
		}
		cb := &cloudasset.Binding{Role: b.Role, Members: b.Members}
		if b.Condition != nil {
			cb.Condition = &cloudasset.Expr{
				Title: b.Condition.Title, Description: b.Condition.Description, Expression: b.Condition.Expression,
			}
		}
		res.Policy.Bindings = append(res.Policy.Bindings, cb)
	}
	return res
}
