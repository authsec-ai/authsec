package gcp

import (
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/models"
)

// TestRoleGrantCommands_UnconditionalBinding proves every generated grant
// command carries --condition=None. Without it, gcloud refuses to run these
// commands non-interactively against any org/folder/project that already has
// a conditional binding elsewhere in its policy — live-confirmed against a
// real GCP project.
func TestRoleGrantCommands_UnconditionalBinding(t *testing.T) {
	for _, scopeKind := range []string{models.CloudScopeOrg, models.CloudScopeFolder, models.CloudScopeProject} {
		cmds := RoleGrantCommands(scopeKind, "my-scope-id")
		if len(cmds) != len(CandidateReaderRoles) {
			t.Fatalf("%s: expected %d commands, got %d", scopeKind, len(CandidateReaderRoles), len(cmds))
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
