package services

import (
	"errors"
	"testing"

	"github.com/authsec-ai/authsec/internal/gcp"
	"github.com/authsec-ai/authsec/models"
	"google.golang.org/api/cloudasset/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iam/v1"
)

func TestServiceAccountPolicyResultMatchesCloudAssetShape(t *testing.T) {
	w := gcpWrittenIdentity{Email: "app-sa@p.iam.gserviceaccount.com", UniqueID: "1001", ProjectID: "p", ProjectNumber: "42"}
	res := gcpServiceAccountPolicyResult(w, &iam.Policy{Bindings: []*iam.Binding{
		{Role: "roles/iam.serviceAccountUser", Members: []string{"serviceAccount:d@p.iam.gserviceaccount.com"}},
		nil,
		{Role: "roles/iam.serviceAccountTokenCreator", Members: []string{"user:a@x.com"},
			Condition: &iam.Expr{Title: "t", Expression: `request.time < timestamp("2027-01-01T00:00:00Z")`}},
	}})
	if res.Resource != "//iam.googleapis.com/projects/p/serviceAccounts/1001" {
		t.Fatalf("resource = %q: must be the name Cloud Asset gives, so both paths write the same rows", res.Resource)
	}
	if gcp.AssetKind(res.AssetType) != gcp.KindServiceAccount || res.Project != "projects/42" {
		t.Fatalf("asset type %q / project %q", res.AssetType, res.Project)
	}
	if len(res.Policy.Bindings) != 2 || res.Policy.Bindings[1].Condition == nil ||
		res.Policy.Bindings[1].Condition.Expression != `request.time < timestamp("2027-01-01T00:00:00Z")` {
		t.Fatalf("bindings = %+v: conditions must be kept verbatim", res.Policy.Bindings)
	}
}

func TestFillAncestorsWalksTheTree(t *testing.T) {
	byKey := map[string]gcp.ScopeNode{
		"folders/2":       {ID: "2", Kind: gcp.ScopeNodeFolder, Parent: "folders/1"},
		"folders/1":       {ID: "1", Kind: gcp.ScopeNodeFolder, Parent: "organizations/9"},
		"organizations/9": {ID: "9", Kind: gcp.ScopeNodeOrganization},
	}
	res := &cloudasset.IamPolicySearchResult{}
	gcpFillAncestors(res, "folders/2", byKey)
	if len(res.Folders) != 2 || res.Folders[0] != "folders/2" || res.Organization != "organizations/9" {
		t.Fatalf("folders %v org %q", res.Folders, res.Organization)
	}
}

func TestGCPIsNotFound(t *testing.T) {
	if !gcpIsNotFound(&googleapi.Error{Code: 404}) || gcpIsNotFound(&googleapi.Error{Code: 403}) || gcpIsNotFound(errors.New("x")) {
		t.Fatal("only a Google 404 is not-found")
	}
}

// The service-account policy surface is registered once and fails with the other
// policy surfaces before any read.
func TestBindingAccsFailPoliciesIncludesSA(t *testing.T) {
	a := newGCPBindingAccs()
	a.failPolicies(errors.New("boom"))
	for name, acc := range map[string]*gcpSurfaceAcc{"allow": a.allow, "resource": a.resource, "sa": a.sa} {
		if acc.coverage().State == models.CloudCoverageReached || acc.coverage().State == models.CloudCoverageUnknown {
			t.Fatalf("%s = %q after failPolicies", name, acc.coverage().State)
		}
	}
	if a.roles.coverage().State != models.CloudCoverageUnknown {
		t.Fatal("failPolicies must not touch roles")
	}
}
