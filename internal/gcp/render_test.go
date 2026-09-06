package gcp

import (
	"strings"
	"testing"
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

	// Both options present.
	if !strings.Contains(out, "Option A") || !strings.Contains(out, "Option B") {
		t.Error("rendered script must render BOTH the WIF and json_key branches")
	}
}
