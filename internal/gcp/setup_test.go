package gcp

import (
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/models"
)

func TestRender_ProducesExpectedContent(t *testing.T) {
	out, err := Render(Data{
		ReaderProjectID:    "reader-proj",
		ScopeKind:          "project",
		ScopeID:            "my-scope",
		PoolID:             "authsec-abc123",
		ProviderID:         "authsec-provider",
		WIFSubject:         "authsec:deadbeef",
		IssuerURL:          "https://app.authsec.dev",
		RoleSetStatus:      "candidate_pending_GCP-01",
		SetupScriptVersion: Version,
		RoleGrantCommands: []string{
			"gcloud projects add-iam-policy-binding my-scope \\\n  --member=\"serviceAccount:${READER_SA_EMAIL}\" --role=roles/browser",
		},
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	for _, want := range []string{
		"reader-proj",
		"authsec-abc123",
		"authsec-provider",
		"authsec:deadbeef",
		"https://app.authsec.dev",
		"candidate_pending_GCP-01",
		"roles/browser",
		"principal://iam.googleapis.com/",
		"iam.workloadIdentityUser",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered script missing %q", want)
		}
	}

	// The actual --member value must be the scoped principal://.../subject/<v>
	// form, never the wildcard principalSet://.../*. The script's own
	// cautionary comment mentions principalSet:// by name (warning against
	// it), so this checks the --member= usage specifically, not bare string
	// absence.
	if !strings.Contains(out, `--member="principal://iam.googleapis.com/`) {
		t.Error("rendered script must bind impersonation with the scoped principal://.../subject/<value> form")
	}
	if strings.Contains(out, `--member="principalSet://`) {
		t.Error("rendered script must never actually BIND the wildcard principalSet://.../* form")
	}

	// Federation is now the only option the script offers, so the key branch
	// must be gone entirely. Leaving it in would hand a customer a copyable
	// command for a credential onboarding will refuse to accept.
	for _, gone := range []string{"Option B", "keys create", "reader-key.json"} {
		if strings.Contains(out, gone) {
			t.Errorf("rendered script still offers the JSON key path (%q); onboarding no longer accepts it", gone)
		}
	}
	if !strings.Contains(out, "Workload Identity Federation") {
		t.Error("rendered script must still describe the federation path it does support")
	}
}

/* --------------------------- reader role set ------------------------------- */

// TestRoleGrantCommands_UnconditionalBinding proves every generated grant
// command carries --condition=None. Without it, gcloud refuses to run these
// commands non-interactively against any org/folder/project that already has
// a conditional binding elsewhere in its policy — live-confirmed against a
// real GCP project.
func TestRoleGrantCommands_UnconditionalBinding(t *testing.T) {
	for _, scopeKind := range []string{models.CloudScopeOrg, models.CloudScopeFolder, models.CloudScopeProject} {
		want := ReaderRolesFor(scopeKind)
		cmds := RoleGrantCommands(scopeKind, "my-scope-id")
		if len(cmds) != len(want) {
			t.Fatalf("%s: expected %d commands, got %d", scopeKind, len(want), len(cmds))
		}
		for _, cmd := range cmds {
			if !strings.Contains(cmd, "add-iam-policy-binding") {
				t.Errorf("%s: command missing add-iam-policy-binding: %q", scopeKind, cmd)
			}
			if !strings.Contains(cmd, "--condition=None") {
				t.Errorf("%s: command missing --condition=None, will fail non-interactively on scopes with conditional bindings: %q", scopeKind, cmd)
			}
		}
	}
}

// TestRoleGrantCommands_TargetsByScopeKind pins the gcloud resource type each
// scope kind renders — organizations, resource-manager folders, and projects
// each have their own subcommand, and mixing them up would silently target
// the wrong resource.
func TestRoleGrantCommands_TargetsByScopeKind(t *testing.T) {
	cases := map[string]string{
		models.CloudScopeOrg:     "gcloud organizations add-iam-policy-binding",
		models.CloudScopeFolder:  "gcloud resource-manager folders add-iam-policy-binding",
		models.CloudScopeProject: "gcloud projects add-iam-policy-binding",
	}
	for scopeKind, wantPrefix := range cases {
		cmds := RoleGrantCommands(scopeKind, "id")
		if len(cmds) == 0 || !strings.HasPrefix(cmds[0], wantPrefix) {
			t.Errorf("%s: expected command to start with %q, got %v", scopeKind, wantPrefix, cmds)
		}
	}
}

/* ----------------------- P1 role set, by scope kind (ONB-3) ------------------ */

// TestReaderRolesFor_RoleViewerDependsOnScopeKind pins the one role in the set
// that is not the same at every scope.
//
// roles/iam.organizationRoleViewer is what gives org-wide sight of custom role
// definitions, which is what expanding a binding returned by
// searchAllIamPolicies needs. It is an organization-level role, so at a folder
// or project the correct role is roles/iam.roleViewer -- not a narrower form
// of the same thing. Getting this backwards would either fail the grant or
// leave role expansion silently blind.
func TestReaderRolesFor_RoleViewerDependsOnScopeKind(t *testing.T) {
	org := ReaderRolesFor(models.CloudScopeOrg)
	if !containsRole(org, "roles/iam.organizationRoleViewer") {
		t.Errorf("org scope should grant organizationRoleViewer, got %v", org)
	}
	if containsRole(org, "roles/iam.roleViewer") {
		t.Errorf("org scope should NOT also grant the project-level roleViewer, got %v", org)
	}

	for _, scopeKind := range []string{models.CloudScopeFolder, models.CloudScopeProject} {
		roles := ReaderRolesFor(scopeKind)
		if !containsRole(roles, "roles/iam.roleViewer") {
			t.Errorf("%s scope should grant roleViewer, got %v", scopeKind, roles)
		}
		if containsRole(roles, "roles/iam.organizationRoleViewer") {
			t.Errorf("%s scope should NOT grant the org-level role viewer, got %v", scopeKind, roles)
		}
	}
}

// TestReaderRolesFor_IsTheP1SetAndNothingBeyond guards the boundary in both
// directions: securityReviewer must be present (P1 is incomplete without it,
// and auditConfigs are unreadable), and no P2/P5/P7 role may appear until its
// security review has actually happened. roles/aiplatform.viewer in particular
// also permits INVOKING an agent, so it must never arrive here by accident.
func TestReaderRolesFor_IsTheP1SetAndNothingBeyond(t *testing.T) {
	forbidden := []string{
		"roles/iam.denyReviewer",
		"roles/iam.principalAccessBoundaryViewer",
		"roles/aiplatform.viewer",
		"roles/agentregistry.viewer",
		"roles/logging.privateLogViewer",
		"roles/logging.viewer",
		"roles/policyanalyzer.activityAnalysisViewer",
		"roles/recommender.iamViewer",
		"roles/run.viewer",
		"roles/cloudfunctions.viewer",
		"roles/compute.viewer",
		"roles/container.clusterViewer",
	}
	for _, scopeKind := range []string{models.CloudScopeOrg, models.CloudScopeFolder, models.CloudScopeProject} {
		roles := ReaderRolesFor(scopeKind)
		if !containsRole(roles, "roles/iam.securityReviewer") {
			t.Errorf("%s: P1 requires roles/iam.securityReviewer, got %v", scopeKind, roles)
		}
		for _, f := range forbidden {
			if containsRole(roles, f) {
				t.Errorf("%s: %s is a later-phase role and must not be granted at onboarding, got %v", scopeKind, f, roles)
			}
		}
	}
}

// TestReaderRolesFor_NoWriteRoles is the cheap structural half of the
// zero-write guarantee: no role named here may be an admin, editor, owner or
// other write-capable role. Proving the APPLIED policy holds no write
// permission needs a live probe against the reader identity; this only stops a
// write role being typed into the list in the first place.
func TestReaderRolesFor_NoWriteRoles(t *testing.T) {
	writeish := []string{"admin", "editor", "owner", "writer", "creator", "Admin", "Editor", "Owner"}
	for _, scopeKind := range []string{models.CloudScopeOrg, models.CloudScopeFolder, models.CloudScopeProject} {
		for _, role := range ReaderRolesFor(scopeKind) {
			for _, w := range writeish {
				if strings.Contains(role, w) {
					t.Errorf("%s: %q looks write-capable; the reader set must be read-only", scopeKind, role)
				}
			}
		}
	}
}

func containsRole(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}
