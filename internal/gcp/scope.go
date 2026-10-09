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

// testAllowedPermissions returns the subset of want the CALLER holds at
// (scopeKind, scopeID). Raw: the provider error is returned unwrapped so a
// caller that needs to tell an unsupported permission (400) from a denial
// (403) still can -- testMissingPermissions below wraps it for callers that
// do not care.
//
// want must be at most testIamPermissionsBatchSize long; callers probing more
// than that are responsible for chunking (see chunkPermissions).
func testAllowedPermissions(ctx context.Context, rm *cloudresourcemanager.Service, scopeKind, scopeID string, want []string) ([]string, error) {
	resource, err := scopeResourceName(scopeKind, scopeID)
	if err != nil {
		return nil, err
	}
	req := &cloudresourcemanager.TestIamPermissionsRequest{Permissions: want}

	switch scopeKind {
	case models.CloudScopeOrg:
		resp, err := rm.Organizations.TestIamPermissions(resource, req).Context(ctx).Do()
		if err != nil {
			return nil, err
		}
		return resp.Permissions, nil
	case models.CloudScopeFolder:
		resp, err := rm.Folders.TestIamPermissions(resource, req).Context(ctx).Do()
		if err != nil {
			return nil, err
		}
		return resp.Permissions, nil
	default:
		resp, err := rm.Projects.TestIamPermissions(resource, req).Context(ctx).Do()
		if err != nil {
			return nil, err
		}
		return resp.Permissions, nil
	}
}

func testMissingPermissions(ctx context.Context, rm *cloudresourcemanager.Service, scopeKind, scopeID string, want []string) ([]string, error) {
	allowed, err := testAllowedPermissions(ctx, rm, scopeKind, scopeID, want)
	if err != nil {
		resource, _ := scopeResourceName(scopeKind, scopeID)
		return nil, fmt.Errorf("%w: testIamPermissions at %s: %v", ErrGoogleOAuthProvisioningFailed, resource, err)
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

/* ------------------------- hierarchy limits (ONB-6) ------------------------- */

// Documented Google Cloud resource-hierarchy limits. Named here so a
// hierarchy walk imports a guard rather than rediscovering one at runtime
// against a customer's estate.
//
// These are ceilings to recurse defensively against, not values to assume: a
// walk that hits either has found something worth reporting, not a reason to
// silently stop.
const (
	// MaxFolderDepth is the deepest folder nesting under an organization.
	MaxFolderDepth = 10
	// MaxFoldersPerParent is the most folders one parent may directly contain.
	MaxFoldersPerParent = 300
)
