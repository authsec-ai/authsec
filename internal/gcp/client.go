package gcp

import (
	"context"
	"fmt"

	iam "google.golang.org/api/iam/v1"

	cloudasset "google.golang.org/api/cloudasset/v1"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/option"
)

// ReadOnlyScope is the ONLY OAuth scope any GCP client this package builds is
// ever granted. Every client-construction path below appends it explicitly
// rather than trusting the credential's own default scope, so a credential
// that could technically do more (a JSON key with broader IAM grants than the
// candidate role set, say) is still capped to read-only calls from AuthSec's
// side of the connection — least privilege enforced in the client, not just
// documented in the customer's role grants.
const ReadOnlyScope = "https://www.googleapis.com/auth/cloud-platform.read-only"

// IAMScope is the OAuth scope the IAM client alone is granted. Live-testing
// this connector against real GCP proved ReadOnlyScope insufficient for the
// IAM Admin API: google.iam.admin.v1.IAM.GetServiceAccount rejects a
// cloud-platform.read-only token with 403 ACCESS_TOKEN_SCOPE_INSUFFICIENT,
// even though the identical token works for Resource Manager and Cloud Asset
// Inventory calls. Google's IAM Admin API does not publish a read-only scope
// of its own — its documented scope set is exactly {cloud-platform, iam} — so
// https://www.googleapis.com/auth/iam is the narrowest scope this specific
// client can be granted; it is not widened to full cloud-platform, and
// NewCloudAssetClient / NewResourceManagerClient below are untouched and stay
// on ReadOnlyScope, since both are live-confirmed to work with it.
const IAMScope = "https://www.googleapis.com/auth/iam"

// NewIAMClient builds the IAM client (projects.serviceAccounts.*,
// projects.serviceAccounts.keys.*, projects.roles.get — GCP-01's §5 "IAM
// service accounts" / "Service-account keys" / "Roles" surfaces).
func NewIAMClient(ctx context.Context, authOpt option.ClientOption) (*iam.Service, error) {
	svc, err := iam.NewService(ctx, authOpt, option.WithScopes(IAMScope))
	if err != nil {
		return nil, fmt.Errorf("gcp: build iam client: %w", err)
	}
	return svc, nil
}

// NewCloudAssetClient builds the Cloud Asset Inventory client
// (searchAllIamPolicies — GCP-01's §5 "IAM allow policies" / "Resources"
// surfaces). Every call this client makes bills against a quota project; per
// authsec/docs/gcp/feasibility-validation.md's STEP 4 finding, the caller
// should pass the connector's own reader_project_id as that quota project —
// this factory does not set one, because the quota project is a per-call
// concern (X-Goog-User-Project / the API's own QuotaProject field), not a
// per-client one.
func NewCloudAssetClient(ctx context.Context, authOpt option.ClientOption) (*cloudasset.Service, error) {
	svc, err := cloudasset.NewService(ctx, authOpt, option.WithScopes(ReadOnlyScope))
	if err != nil {
		return nil, fmt.Errorf("gcp: build cloud asset client: %w", err)
	}
	return svc, nil
}

// NewResourceManagerClient builds the Resource Manager client
// (organizations.get, folders.get/.list, projects.get/.list — GCP-01's §5
// "Scope hierarchy" surface, and this ticket's ResolveReaderIdentity /
// connection-validation calls).
func NewResourceManagerClient(ctx context.Context, authOpt option.ClientOption) (*cloudresourcemanager.Service, error) {
	svc, err := cloudresourcemanager.NewService(ctx, authOpt, option.WithScopes(ReadOnlyScope))
	if err != nil {
		return nil, fmt.Errorf("gcp: build resource manager client: %w", err)
	}
	return svc, nil
}
