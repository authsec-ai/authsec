package services

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/gcp"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
)

/* cloud_gcp_scan_edges.go answers GCP-4's question: who can BECOME which
   identity. Everything is derived from the bindings GCP-3 stored; there is no
   API call here.

   THREE SHAPES OF EDGE, all in cloud_assume_edge (identity_id = what is become):
   - Impersonation (gcp_sa_impersonation): a member holds a role that lets it act
     as, mint tokens for, or create keys for a service account
     (gcp.ImpersonationCapabilities). On the service account's own policy the
     edge is on that account. On a project, folder or organization it is stored
     ONCE on that scope's row (gcp_project / gcp_folder / gcp_organization) with
     attrs.via_scope, and reaches every account beneath it at read time (GCP-6).
   - Federation (oidc_federation): a principal:// or principalSet:// member is an
     outside identity. Its issuer comes from the pools and providers the scan's
     federation read kept in the snapshot (GCP-2). If it holds an impersonation
     role on an account, the edge is on that account; if it holds roles directly,
     the edge is on its own federated row ("who can become this principal").
   - GKE Workload Identity (gke_workload_identity): a Kubernetes service account
     in a <project>.svc.id.goog pool, in either member form, with k8s_ref
     system:serviceaccount:<ns>:<ksa> -- the Kubernetes connector's own string.

   ONE ROW PER (identity, subject_kind, subject), the table's unique key. Two
   bindings that give the same member the same reach (serviceAccountUser and
   tokenCreator on one account) merge: roles, capabilities and source rows add up.

   ONLY CURRENT INPUT. A binding row this scan refreshed, or one of a family this
   scan did not read (kept, so still believed), is used. A row of a family that
   WAS read but not refreshed is about to be reconciled away and makes no edge.

   Reached only if allow_bindings was. */

// errGCPEdgesNeedBindings: the bindings were not read, so no edge can be derived
// and none may be reconciled.
var errGCPEdgesNeedBindings = errors.New("gcp: trust edges need allow_bindings, which was not reached")

// gcpEdgeKey is the table's unique key.
type gcpEdgeKey struct {
	identity    uuid.UUID
	subjectKind string
	subject     string
}

type gcpEdgeBuild struct {
	edge       models.CloudAssumeEdge
	attrs      models.GCPAssumeEdgeAttrs
	roles      map[string]bool
	caps       map[string]bool
	sources    map[string]bool
	allCond    bool
	// maxExpires is the latest expiry among the source bindings; unbounded is
	// set when some conditional source has no time bound, which makes the merged
	// edge's reach open-ended.
	maxExpires time.Time
	unbounded  bool
}

// runEdgePhase derives and writes trust edges.
func (s *GCPScanner) runEdgePhase(
	ctx context.Context, workspaceID uuid.UUID, snapshot *GCPScanSnapshot, bind gcpBindingAccs, acc *gcpSurfaceAcc,
) {
	switch bind.allow.coverage().State {
	case models.CloudCoverageReached:
	case models.CloudCoverageNotSelected:
		acc.skipNotReadable("not_readable: trust edges are derived from bindings, which were not read")
		return
	default:
		acc.fail(errGCPEdgesNeedBindings)
		return
	}
	// Which bindings let someone become an account depends on the roles'
	// permissions. A scan that could not read roles has every custom and
	// predefined role unexpanded, so deriving would silently drop (and then
	// reconcile away) the edges those roles create. Not attempted, kept as is.
	if bind.roles.coverage().State == models.CloudCoverageNotSelected {
		acc.skipNotReadable("not_readable: roles were not read, so which bindings allow impersonation is not known")
		return
	}
	if err := ctx.Err(); err != nil {
		acc.observe(err, 0)
		return
	}
	n, err := s.deriveEdges(workspaceID, snapshot, bind)
	acc.observe(err, n)
}

func (s *GCPScanner) deriveEdges(workspaceID uuid.UUID, snapshot *GCPScanSnapshot, bind gcpBindingAccs) (int, error) {
	rows, err := s.gcpRead.BindingsForConnector(workspaceID, snapshot.ConnectorID)
	if err != nil {
		return 0, err
	}
	idents, err := s.gcpRead.IdentitiesForConnector(workspaceID, snapshot.ConnectorID)
	if err != nil {
		return 0, err
	}
	byID := make(map[uuid.UUID]models.CloudIdentity, len(idents))
	saByKey := map[string]uuid.UUID{} // unique id or lower-case email -> service account row
	for _, i := range idents {
		byID[i.ID] = i
		if i.Kind != models.CloudIdentityGCPServiceAccount {
			continue
		}
		var a models.GCPIdentityAttrs
		_ = json.Unmarshal(i.Attrs, &a)
		if a.UniqueID != "" {
			saByKey[a.UniqueID] = i.ID
		}
		if a.Email != "" {
			saByKey[strings.ToLower(a.Email)] = i.ID
		}
	}

	resourceRead := bind.resource.coverage().State == models.CloudCoverageReached
	saRead := resourceRead || bind.sa.coverage().State == models.CloudCoverageReached
	current := func(r repositories.GCPBindingRow) bool {
		if r.LastSeenGeneration == snapshot.Generation {
			return true
		}
		switch {
		case r.ResourceID == nil:
			return false // hierarchy: allow_bindings was reached, so a stale row is going
		case r.ResourceKind == gcp.KindServiceAccount:
			return !saRead
		default:
			return !resourceRead
		}
	}

	scopes := newGCPScopeAnchors(s, workspaceID, snapshot)
	edges := map[gcpEdgeKey]*gcpEdgeBuild{}
	add := func(target uuid.UUID, kind, subject, mechanism string, issuer, k8sRef *string, r repositories.GCPBindingRow,
		pa models.GCPPermissionAttrs, caps []string, base models.GCPAssumeEdgeAttrs) {
		key := gcpEdgeKey{target, kind, subject}
		b, ok := edges[key]
		if !ok {
			b = &gcpEdgeBuild{
				edge: models.CloudAssumeEdge{
					WorkspaceID: workspaceID, ConnectorID: snapshot.ConnectorID, IdentityID: target,
					SubjectKind: kind, Subject: subject, Mechanism: mechanism, Issuer: issuer, K8sRef: k8sRef,
					LastSeenGeneration: snapshot.Generation,
				},
				attrs: base, roles: map[string]bool{}, caps: map[string]bool{}, sources: map[string]bool{}, allCond: true,
			}
			edges[key] = b
		}
		if r.RoleName != nil {
			b.roles[*r.RoleName] = true
		}
		for _, c := range caps {
			b.caps[c] = true
		}
		b.sources[r.ID.String()] = true
		if r.ConstraintState != "conditional" {
			b.allCond = false
		}
		if r.ConstraintState == "conditional" {
			if t, err := time.Parse(time.RFC3339, pa.ExpiresAt); err == nil {
				if t.After(b.maxExpires) {
					b.maxExpires = t
				}
			} else {
				b.unbounded = true
			}
		}
		if pa.BasicRole {
			b.attrs.BasicRole = true
		}
	}

	for _, r := range rows {
		if !current(r) {
			continue
		}
		var pa models.GCPPermissionAttrs
		if err := json.Unmarshal(r.Attrs, &pa); err != nil || pa.Member == "" {
			continue
		}
		m, err := gcp.ParseMember(pa.Member)
		if err != nil {
			continue
		}
		subj := byID[r.IdentityID]
		fed := gcpFederationOf(m, snapshot)

		// Who can become this federated principal: its outside issuer.
		if fed != nil {
			// The subject is the outside issuer, not a row: no subject_identity_id,
			// or the principal would list itself under "what it can become".
			base := fed.attrs
			base.Member = pa.Member
			add(r.IdentityID, fed.subjectKind, fed.subject, fed.mechanism, fed.issuer, fed.k8sRef, r, pa, nil, base)
		}

		role := ""
		if r.RoleName != nil {
			role = *r.RoleName
		}
		caps := gcp.ImpersonationCapabilities(role, r.Actions)
		if len(caps) == 0 {
			continue
		}

		// What is become: the account itself, or the scope row the grant sits on.
		var target uuid.UUID
		viaScope := ""
		switch {
		case r.ResourceID != nil && r.ResourceKind == gcp.KindServiceAccount:
			id, ok := saByKey[gcpSAKeyOf(r.ResourceNativeID)]
			if !ok {
				continue // an account this scan did not list (another project): no row to hang it on
			}
			target = id
		case r.ResourceID == nil:
			id, scope, ok, err := scopes.anchor(pa.AttachedTo)
			if err != nil {
				return 0, err
			}
			if !ok {
				continue
			}
			target, viaScope = id, scope
		default:
			continue // a role on a bucket or dataset does not reach any service account
		}

		base := models.GCPAssumeEdgeAttrs{
			ViaScope: viaScope, Member: pa.Member, SubjectIdentityID: r.IdentityID.String(),
			External: gcpIdentityExternal(subj),
		}
		switch {
		case fed != nil:
			fb := fed.attrs
			fb.ViaScope, fb.Member, fb.SubjectIdentityID, fb.External = viaScope, pa.Member, r.IdentityID.String(), true
			add(target, fed.subjectKind, pa.Member, fed.mechanism, fed.issuer, fed.k8sRef, r, pa, caps, fb)
		default:
			kind := models.AssumeSubjectIdentity
			if base.External || subj.Kind == models.CloudIdentityGCPPublic {
				kind = models.AssumeSubjectExternal
			}
			add(target, kind, pa.Member, models.AssumeMechanismGCPImpersonation, nil, nil, r, pa, caps, base)
		}
	}

	written := 0
	for _, b := range edges {
		b.attrs.Roles = sortedKeys(b.roles)
		b.attrs.Capabilities = sortedKeys(b.caps)
		b.attrs.SourcePermissionIDs = sortedKeys(b.sources)
		b.attrs.Conditional = b.allCond
		if b.allCond && !b.unbounded && !b.maxExpires.IsZero() {
			b.attrs.ExpiresAt = b.maxExpires.UTC().Format(time.RFC3339)
		}
		raw, err := json.Marshal(b.attrs)
		if err != nil {
			return written, err
		}
		e := b.edge
		e.Attrs = raw
		if _, _, err := s.permissions.UpsertAssumeEdge(&e); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

// gcpSAKeyOf is the unique id (or email) at the end of a service account's
// Cloud Asset name: //iam.googleapis.com/projects/<p>/serviceAccounts/<id>.
func gcpSAKeyOf(native string) string {
	return strings.ToLower(native[strings.LastIndex(native, "/")+1:])
}

func gcpIdentityExternal(i models.CloudIdentity) bool {
	var a models.GCPIdentityAttrs
	_ = json.Unmarshal(i.Attrs, &a)
	return a.IsExternal
}

/* --------------------------------- scope rows ------------------------------- */

// gcpScopeAnchors resolves a hierarchy binding's attachment point to the row its
// scope-level edges are stored on, upserting it once per scan.
type gcpScopeAnchors struct {
	s           *GCPScanner
	workspaceID uuid.UUID
	snapshot    *GCPScanSnapshot
	done        map[string]uuid.UUID
}

func newGCPScopeAnchors(s *GCPScanner, ws uuid.UUID, snapshot *GCPScanSnapshot) *gcpScopeAnchors {
	return &gcpScopeAnchors{s: s, workspaceID: ws, snapshot: snapshot, done: map[string]uuid.UUID{}}
}

// anchor returns the scope row for "//cloudresourcemanager.googleapis.com/<scope>"
// and the scope ("projects/p", "folders/1", "organizations/9").
func (a *gcpScopeAnchors) anchor(attachedTo string) (uuid.UUID, string, bool, error) {
	scope := strings.TrimPrefix(attachedTo, "//cloudresourcemanager.googleapis.com/")
	if scope == attachedTo || scope == "" {
		return uuid.Nil, "", false, nil
	}
	if id, ok := a.done[scope]; ok {
		return id, scope, true, nil
	}
	kind, ref, _ := strings.Cut(scope, "/")
	var (
		id  uuid.UUID
		err error
	)
	switch kind {
	case "projects":
		// Keyed by number, as the API-key phase keys the same row, so a project
		// has one row whichever form (id or number) the policy named it by.
		project, number := gcpProject{ProjectID: ref}, ""
		for _, p := range a.snapshot.Projects {
			if p.ProjectID == ref || (p.Number != "" && p.Number == ref) {
				project, number = p, p.Number
			}
		}
		if number == "" {
			number = ref // number unknown: the id is the best key there is
		}
		id, err = a.s.upsertProjectIdentity(a.workspaceID, a.snapshot, project, number)
	case "folders":
		id, err = a.s.upsertScopeIdentity(a.workspaceID, a.snapshot, models.CloudIdentityGCPFolder, scope, a.displayName(ref, gcp.ScopeNodeFolder))
	case "organizations":
		id, err = a.s.upsertScopeIdentity(a.workspaceID, a.snapshot, models.CloudIdentityGCPOrganization, scope, a.displayName(ref, gcp.ScopeNodeOrganization))
	default:
		return uuid.Nil, "", false, nil
	}
	if err != nil {
		return uuid.Nil, "", false, err
	}
	a.done[scope] = id
	return id, scope, true, nil
}

func (a *gcpScopeAnchors) displayName(id, kind string) string {
	if a.snapshot.Tree != nil {
		for _, n := range a.snapshot.Tree.Nodes {
			if n.ID == id && n.Kind == kind && n.DisplayName != "" {
				return n.DisplayName
			}
		}
	}
	return id
}

// upsertScopeIdentity writes the row a folder- or organization-level grant's
// edges hang on. Not a principal: a place in the hierarchy.
func (s *GCPScanner) upsertScopeIdentity(workspaceID uuid.UUID, snapshot *GCPScanSnapshot, kind, scope, name string) (uuid.UUID, error) {
	identity := &models.CloudIdentity{
		WorkspaceID:        workspaceID,
		ConnectorID:        snapshot.ConnectorID,
		Kind:               kind,
		NativeID:           "//cloudresourcemanager.googleapis.com/" + scope,
		Name:               name,
		Enabled:            true,
		LastSeenGeneration: snapshot.Generation,
	}
	if err := identity.SetGCPAttrs(models.GCPIdentityAttrs{IdentityKind: strings.TrimPrefix(kind, "gcp_")}); err != nil {
		return uuid.Nil, err
	}
	stored, _, err := s.identities.UpsertIdentity(identity)
	if err != nil {
		return uuid.Nil, err
	}
	return stored.ID, nil
}
