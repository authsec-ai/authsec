package services

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/authsec-ai/authsec/internal/gcp"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

/* cloud_gcp_scan_members.go turns an IAM member string into a cloud_identity row.

   WHY THIS EXISTS BEFORE ANY BINDING IS READ. cloud_permission.identity_id is
   NOT NULL, so every principal a binding names must already be a row. Most are
   not service accounts the project listing returns: users, groups, domains,
   allUsers, federated principals, Google's own service agents, and principals
   that were deleted while their bindings stayed behind.

   GCP-2 builds and tests this; GCP-3's binding phase calls it. Nothing in the
   GCP-2 scan calls it yet, so no member row exists until bindings are read --
   which is also why the identities reconcile target does not yet depend on
   allow_bindings.

   NO COLLISION WITH A REAL SERVICE ACCOUNT. A real one is keyed by unique id
   under //iam.googleapis.com/serviceAccounts/; every member row is keyed under
   //gcp/principal/ (gcp.Member.NativeID). The two namespaces cannot meet, so a
   member upsert can never overwrite a real service account's kind or attrs, and
   uq_cloud_identity_native, which is workspace-wide across AWS and Azure too,
   cannot be tripped by one.

   A live service account named in a binding is resolved to its real row by
   email instead of being given a second one: a binding names it by address and
   the row is keyed by unique id, so forking it would split one principal in two.
   Only a service account this scan did not read (another project, another org)
   gets a member row. */

// gcpMemberKind maps a parsed member to the cloud_identity kind it is stored as.
func gcpMemberKind(m gcp.Member) string {
	switch {
	case m.Deleted:
		return models.CloudIdentityGCPDeleted
	case m.IsGKEWorkloadIdentity():
		return models.CloudIdentityGCPFederated
	}
	switch m.Type {
	case gcp.MemberUser:
		return models.CloudIdentityGCPUser
	case gcp.MemberGroup, gcp.MemberProjectRole:
		return models.CloudIdentityGCPGroup
	case gcp.MemberDomain:
		return models.CloudIdentityGCPDomain
	case gcp.MemberAllUsers, gcp.MemberAllAuthUsers:
		return models.CloudIdentityGCPPublic
	case gcp.MemberPrincipal, gcp.MemberPrincipalSet:
		return models.CloudIdentityGCPFederated
	case gcp.MemberServiceAccount:
		if gcp.ClassifySA(m.Email) == gcp.SAClassServiceAgent {
			return models.CloudIdentityGCPServiceAgent
		}
		return models.CloudIdentityGCPServiceAccount
	}
	return models.CloudIdentityGCPUser
}

// upsertMemberIdentity records the principal an IAM member names, returning the
// row bindings should reference.
//
// live is the service accounts this scan wrote, for the by-email resolution
// described above.
func (s *GCPScanner) upsertMemberIdentity(
	workspaceID uuid.UUID, snapshot *GCPScanSnapshot, m gcp.Member, live []gcpWrittenIdentity,
) (gcpWrittenIdentity, error) {
	if m.Type == gcp.MemberServiceAccount && !m.Deleted && !m.IsGKEWorkloadIdentity() {
		for _, w := range live {
			if strings.EqualFold(w.Email, m.Email) {
				return w, nil
			}
		}
	}

	kind := gcpMemberKind(m)
	identity := &models.CloudIdentity{
		WorkspaceID: workspaceID,
		ConnectorID: snapshot.ConnectorID,
		Kind:        kind,
		NativeID:    m.NativeID(),
		Name:        gcpMemberName(m),
		// A deleted principal is not usable; everything else a binding names is
		// presumed enabled -- whether a user is suspended is the directory's word
		// (GCP-10), not the binding's.
		Enabled:            !m.Deleted,
		LastSeenGeneration: snapshot.Generation,
	}
	attrs := models.GCPIdentityAttrs{
		Email:      m.Email,
		MemberType: string(m.Type),
		IsExternal: gcpMemberOutsideScope(m, snapshot.Projects),
		Deleted:    m.Deleted,
		DeletedUID: m.UID,
	}
	if m.Type == gcp.MemberServiceAccount && !m.Deleted && !m.IsGKEWorkloadIdentity() {
		attrs.SAClass = gcp.ClassifySA(m.Email)
		attrs.IdentityKind = "service_account"
	}
	if err := identity.SetGCPAttrs(attrs); err != nil {
		return gcpWrittenIdentity{}, err
	}
	stored, _, err := s.identities.UpsertIdentity(identity)
	if err != nil {
		return gcpWrittenIdentity{}, err
	}
	return gcpWrittenIdentity{IdentityID: stored.ID, Email: m.Email}, nil
}

func gcpMemberName(m gcp.Member) string {
	switch {
	case m.Email != "":
		return m.Email
	case m.IsGKEWorkloadIdentity():
		return fmt.Sprintf("%s/%s (GKE %s)", m.GKENamespace, m.GKEServiceAccount, m.GKEProject)
	default:
		return m.ID
	}
}

var (
	saProjectIDFromEmail = regexp.MustCompile(`@([a-z][a-z0-9-]{4,28}[a-z0-9])\.iam\.gserviceaccount\.com$`)
	saNumberFromEmail    = regexp.MustCompile(`^(?:service-)?(\d+)(?:-compute)?@`)
)

// gcpMemberOutsideScope reports whether a member is KNOWN to belong to a project
// outside the ones this scan read.
//
// Only a service account carries a project in its address, so only a service
// account can be placed. A user, group or domain has no project, and whether its
// domain lies outside the organization needs the org's domain, which the
// directory surface (GCP-10) supplies; saying false for them is "not shown to be
// external", never "internal". An empty project set also answers false: with
// nothing to compare against, nothing is shown to be outside it.
func gcpMemberOutsideScope(m gcp.Member, projects []gcpProject) bool {
	if m.Type != gcp.MemberServiceAccount || m.Deleted || m.IsGKEWorkloadIdentity() || len(projects) == 0 {
		return false
	}
	// Number form first. A Google-managed account's host (gcp-sa-pubsub,
	// compute-system, ...) is a service name, NOT a project id, so it must be
	// placed by the project number in its local part and never by its host.
	if g := saNumberFromEmail.FindStringSubmatch(m.Email); g != nil {
		for _, p := range projects {
			if p.Number != "" && p.Number == g[1] {
				return false
			}
		}
		// A project connector knows no number, so a number it cannot match proves
		// nothing; only when every project's number is known is "no match" real.
		for _, p := range projects {
			if p.Number == "" {
				return false
			}
		}
		return true
	}
	// <name>@<project-id>.iam.gserviceaccount.com: a user-managed account.
	if g := saProjectIDFromEmail.FindStringSubmatch(m.Email); g != nil {
		for _, p := range projects {
			if p.ProjectID == g[1] {
				return false
			}
		}
		return true
	}
	return false
}
