package services

import (
	"errors"
	"strings"
	"testing"
)

// AS-166: a workspace user is told Slack is not set up, never which server
// setting is missing; the operator reads that in the startup log.
func TestSlackNotSetUpNamesNoServerSetting(t *testing.T) {
	for _, c := range []struct {
		name string
		svc  *SlackIntegrationService
	}{
		{"no service", nil},
		{"no signing secret", NewSlackIntegrationService(nil, nil, nil, SlackConfig{})},
		{"no Vault", NewSlackIntegrationService(nil, nil, nil, SlackConfig{SigningSecret: "x"})},
	} {
		if ok, why := c.svc.Configured(); ok || why == "" {
			t.Fatalf("%s: Configured() = %v, %q; want a reason for the log", c.name, ok, why)
		}
		var ge *GovError
		if err := c.svc.mustConfigured(); !errors.As(err, &ge) || ge.Code != SlackCodeNotConfigured || ge.Message != SlackNotSetUp {
			t.Fatalf("%s: mustConfigured() = %v, want %s %q", c.name, err, SlackCodeNotConfigured, SlackNotSetUp)
		}
	}
	if ok, why := SlackAvailable(); ok || why != SlackNotSetUp {
		t.Fatalf("SlackAvailable() = %v, %q", ok, why)
	}
	for _, leak := range []string{SlackSigningSecretEnv, "Vault", "client_secret", ".."} {
		if strings.Contains(SlackNotSetUp, leak) {
			t.Errorf("SlackNotSetUp names %q", leak)
		}
	}
}
