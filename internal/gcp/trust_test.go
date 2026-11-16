package gcp

import (
	"reflect"
	"testing"
)

func TestImpersonationCapabilities(t *testing.T) {
	cases := []struct {
		role  string
		perms []string
		want  []string
	}{
		{"roles/iam.serviceAccountUser", nil, []string{CapabilityActAs}},
		{"roles/iam.serviceAccountTokenCreator", nil, []string{CapabilityMintToken}},
		{"roles/iam.workloadIdentityUser", nil, []string{CapabilityFederate}},
		{"roles/iam.serviceAccountKeyAdmin", nil, []string{CapabilityCreateKey}},
		{"roles/owner", nil, []string{CapabilityActAs, CapabilityCreateKey}},
		{"roles/editor", nil, []string{CapabilityActAs, CapabilityCreateKey}},
		{"roles/viewer", nil, []string{}},
		{"projects/p/roles/igaDeployer", []string{"iam.serviceAccounts.actAs", "run.services.update"}, []string{CapabilityActAs}},
		{"roles/custom", []string{"iam.serviceAccounts.signJwt", "iam.serviceAccounts.getOpenIdToken"}, []string{CapabilityMintToken}},
		{"roles/storage.objectViewer", []string{"storage.objects.get"}, []string{}},
	}
	for _, c := range cases {
		if got := ImpersonationCapabilities(c.role, c.perms); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s %v = %v, want %v", c.role, c.perms, got, c.want)
		}
	}
}

func TestClassifyIssuer(t *testing.T) {
	cases := []struct{ typ, uri, kind, host string }{
		{"oidc", "https://token.actions.githubusercontent.com", IssuerCIPipeline, "token.actions.githubusercontent.com"},
		{"oidc", "https://gitlab.com", IssuerCIPipeline, "gitlab.com"},
		{"aws", "", IssuerExternal, "sts.amazonaws.com"},
		{"oidc", "https://container.googleapis.com/v1/projects/p/locations/l/clusters/c", IssuerK8s, "container.googleapis.com/v1/projects/p/locations/l/clusters/c"},
		{"oidc", "https://oidc.eks.us-east-1.amazonaws.com/id/ABC", IssuerK8s, "oidc.eks.us-east-1.amazonaws.com/id/ABC"},
		{"oidc", "https://login.example.com", IssuerExternal, "login.example.com"},
	}
	for _, c := range cases {
		kind, host := ClassifyIssuer(c.typ, c.uri)
		if kind != c.kind || host != c.host {
			t.Errorf("%s %s = %s %s, want %s %s", c.typ, c.uri, kind, host, c.kind, c.host)
		}
	}
}

func TestUnconditioned(t *testing.T) {
	for in, want := range map[string]bool{"": true, " true ": true, "assertion.repository=='o/r'": false} {
		if Unconditioned(in) != want {
			t.Errorf("Unconditioned(%q) != %v", in, want)
		}
	}
}

func TestGKEHelpers(t *testing.T) {
	if p, ok := GKEPool("projects/9/locations/global/workloadIdentityPools/proj-a.svc.id.goog"); !ok || p != "proj-a" {
		t.Fatalf("GKEPool = %q %v", p, ok)
	}
	if _, ok := GKEPool("projects/9/locations/global/workloadIdentityPools/iga-github"); ok {
		t.Fatal("a GitHub pool is not GKE")
	}
	if r, ok := GKEPrincipalK8sRef("subject/ns/iga/sa/direct-ksa"); !ok || r != "system:serviceaccount:iga:direct-ksa" {
		t.Fatalf("GKEPrincipalK8sRef = %q %v", r, ok)
	}
	if _, ok := GKEPrincipalK8sRef("attribute.namespace/iga"); ok {
		t.Fatal("a namespace set is not one service account")
	}
	if PoolProject("projects/9/locations/global/workloadIdentityPools/p") != "9" || PoolID("a/b/c") != "c" {
		t.Fatal("pool helpers")
	}
	if !IsWorkforcePool("locations/global/workforcePools/wf") || IsWorkforcePool("projects/1/locations/global/workloadIdentityPools/p") {
		t.Fatal("IsWorkforcePool")
	}
}
