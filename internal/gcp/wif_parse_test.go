package gcp

import "testing"

func TestParseProviderResource_Valid(t *testing.T) {
	poolID, providerID, ok := ParseProviderResource(
		"projects/123456789012/locations/global/workloadIdentityPools/authsec-abc123/providers/authsec-provider")
	if !ok {
		t.Fatal("expected ok=true for a well-formed provider resource")
	}
	if poolID != "authsec-abc123" {
		t.Errorf("poolID = %q, want %q", poolID, "authsec-abc123")
	}
	if providerID != "authsec-provider" {
		t.Errorf("providerID = %q, want %q", providerID, "authsec-provider")
	}
}

func TestParseProviderResource_Malformed(t *testing.T) {
	cases := []string{
		"",
		"not-a-resource-name",
		"//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/pr", // has the scheme prefix -- must NOT be accepted here
		"projects/not-a-number/locations/global/workloadIdentityPools/p/providers/pr",
		"projects/123/locations/us-central1/workloadIdentityPools/p/providers/pr", // wrong location
		"principal://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/subject/x",
	}
	for _, c := range cases {
		if _, _, ok := ParseProviderResource(c); ok {
			t.Errorf("ParseProviderResource(%q) = ok, want not-ok", c)
		}
	}
}
