package services

import "testing"

func TestRemediationDetectIaC(t *testing.T) {
	cases := []struct {
		tags        map[string]string
		managed     bool
		tool, stack string
	}{
		{map[string]string{"aws:cloudformation:stack-name": "agents-prod"}, true, "cloudformation", "agents-prod"},
		{map[string]string{"ManagedBy": "Terraform"}, true, "terraform", ""},
		{map[string]string{"terraform:workspace": "prod"}, true, "terraform", ""},
		{map[string]string{"tf_module": "iam"}, true, "terraform", ""},
		{map[string]string{"ManagedBy": "AuthSec", "owner": "terraform-team"}, false, "", ""},
		{nil, false, "", ""},
	}
	for i, c := range cases {
		got := detectIaC(c.tags)
		if got.Managed != c.managed || got.Tool != c.tool || got.Stack != c.stack {
			t.Errorf("case %d %v: %+v", i, c.tags, got)
		}
	}
}

func TestRemediationExternalIDDomains(t *testing.T) {
	ws := [16]byte{1}
	ext, err := MintRemediationExternalID(ws)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyRemediationExternalID(ws, ext) != nil {
		t.Fatal("own id refused")
	}
	if VerifyEnforcementExternalID(ws, ext) == nil {
		t.Fatal("a remediation ExternalId verifies as an enforcement one")
	}
	enf, _ := MintEnforcementExternalID(ws)
	if VerifyRemediationExternalID(ws, enf) == nil {
		t.Fatal("an enforcement ExternalId verifies as a remediation one")
	}
}
