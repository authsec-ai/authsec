package gcp

import (
	"context"
	"fmt"

	"github.com/authsec-ai/authsec/models"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v3"
)

/* scope.go is GCP's scope-kind vocabulary: organizations, folders and
   projects each have their own Resource Manager surface, and there is no
   single call that works for all three. Every per-scope-kind dispatch this
   package performs lives here, moved verbatim out of provision.go -- the
   logic, error handling and strings are unchanged; only the file they live
   in is different. */

func scopeResourceName(scopeKind, scopeID string) (string, error) {
	switch scopeKind {
	case models.CloudScopeOrg:
		return "organizations/" + scopeID, nil
	case models.CloudScopeFolder:
		return "folders/" + scopeID, nil
	case models.CloudScopeProject:
		return "projects/" + scopeID, nil
	default:
		return "", fmt.Errorf("%w: unsupported scope_kind %q", ErrGoogleOAuthProvisioningFailed, scopeKind)
	}
}

func getScopeIamPolicy(ctx context.Context, rm *cloudresourcemanager.Service, scopeKind, resource string) (*cloudresourcemanager.Policy, error) {
	req := &cloudresourcemanager.GetIamPolicyRequest{}
	switch scopeKind {
	case models.CloudScopeOrg:
		return rm.Organizations.GetIamPolicy(resource, req).Context(ctx).Do()
	case models.CloudScopeFolder:
		return rm.Folders.GetIamPolicy(resource, req).Context(ctx).Do()
	default:
		return rm.Projects.GetIamPolicy(resource, req).Context(ctx).Do()
	}
}

func setScopeIamPolicy(ctx context.Context, rm *cloudresourcemanager.Service, scopeKind, resource string, policy *cloudresourcemanager.Policy) error {
	req := &cloudresourcemanager.SetIamPolicyRequest{Policy: policy}
	var err error
	switch scopeKind {
	case models.CloudScopeOrg:
		_, err = rm.Organizations.SetIamPolicy(resource, req).Context(ctx).Do()
	case models.CloudScopeFolder:
		_, err = rm.Folders.SetIamPolicy(resource, req).Context(ctx).Do()
	default:
		_, err = rm.Projects.SetIamPolicy(resource, req).Context(ctx).Do()
	}
	return err
}

func testMissingPermissions(ctx context.Context, rm *cloudresourcemanager.Service, scopeKind, scopeID string, want []string) ([]string, error) {
	resource, err := scopeResourceName(scopeKind, scopeID)
	if err != nil {
		return nil, err
	}
	req := &cloudresourcemanager.TestIamPermissionsRequest{Permissions: want}

	var allowed []string
	switch scopeKind {
	case models.CloudScopeOrg:
		resp, err := rm.Organizations.TestIamPermissions(resource, req).Context(ctx).Do()
		if err != nil {
			return nil, fmt.Errorf("%w: testIamPermissions at %s: %v", ErrGoogleOAuthProvisioningFailed, resource, err)
		}
		allowed = resp.Permissions
	case models.CloudScopeFolder:
		resp, err := rm.Folders.TestIamPermissions(resource, req).Context(ctx).Do()
		if err != nil {
			return nil, fmt.Errorf("%w: testIamPermissions at %s: %v", ErrGoogleOAuthProvisioningFailed, resource, err)
		}
		allowed = resp.Permissions
	default:
		resp, err := rm.Projects.TestIamPermissions(resource, req).Context(ctx).Do()
		if err != nil {
			return nil, fmt.Errorf("%w: testIamPermissions at %s: %v", ErrGoogleOAuthProvisioningFailed, resource, err)
		}
		allowed = resp.Permissions
	}

	missing := make([]string, 0, len(want))
	for _, p := range want {
		if !containsString(allowed, p) {
			missing = append(missing, p)
		}
	}
	return missing, nil
}

// ProvisioningScopePermission returns the single resourcemanager setIamPolicy
// permission required at whichever scope_kind the customer is connecting --
// distinct from the reader-project permission set above because the scope
// being granted access TO (org/folder/project) is not necessarily the same
// project the reader service account lives in (GCP-D9, point 2).
func ProvisioningScopePermission(scopeKind string) string {
	switch scopeKind {
	case models.CloudScopeOrg:
		return "resourcemanager.organizations.setIamPolicy"
	case models.CloudScopeFolder:
		return "resourcemanager.folders.setIamPolicy"
	default:
		return "resourcemanager.projects.setIamPolicy"
	}
}
