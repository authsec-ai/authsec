package services

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestAttributionTokenRejectsGenericNames(t *testing.T) {
	for _, generic := range []string{"Default project", "OPENAI_API_KEY", "anthropic-key", "prod", "Default Workspace", "api-key-dev", ""} {
		if tok := attributionToken(generic); tok != "" {
			t.Errorf("%q is generic, got token %q", generic, tok)
		}
	}
	for name, want := range map[string]string{"support-bot": "supportbot", "Billing Agent (prod)": "billingagentprod", "triage_v2": "triagev2"} {
		if got := attributionToken(name); got != want {
			t.Errorf("%q: token %q, want %q", name, got, want)
		}
	}
}

func TestAttributeKeyWeakLinksByName(t *testing.T) {
	conn, wl, ident := uuid.New(), uuid.New(), uuid.New()
	names := []attributionName{
		{Via: "secret_name", Name: "prod/support-bot/openai", norm: normalizeAttributionName("prod/support-bot/openai"),
			ConnectorID: conn, SecretARN: "arn:aws:secretsmanager:us-east-1:1:secret:prod/support-bot/openai-AbCdEf",
			WorkloadIDs: []uuid.UUID{wl}, IdentityIDs: []uuid.UUID{ident}},
		{Via: "env_var_name", Name: "BILLING_AGENT_KEY", norm: normalizeAttributionName("BILLING_AGENT_KEY"),
			ConnectorID: conn, WorkloadIDs: []uuid.UUID{wl}},
		{Via: "env_var_name", Name: "OPENAI_API_KEY", norm: normalizeAttributionName("OPENAI_API_KEY"), ConnectorID: conn},
	}
	l := attributeKey("support-bot", "Default project", names)
	if len(l) != 1 || l[0].Strength != "weak" || l[0].Via != "secret_name" || l[0].Matched != "key_name" ||
		l[0].SecretARN == "" || len(l[0].WorkloadIDs) != 1 || l[0].IdentityIDs[0] != ident {
		t.Fatalf("support-bot links: %+v", l)
	}
	l = attributeKey("laptop-7", "Billing Agent", names)
	if len(l) != 1 || l[0].Via != "env_var_name" || l[0].Matched != "project_name" || l[0].Name != "BILLING_AGENT_KEY" {
		t.Fatalf("project-name link: %+v", l)
	}
	// A key named like the generic variable ties to nothing.
	if l := attributeKey("openai-api-key", "Default project", names); len(l) != 0 {
		t.Fatalf("generic key linked: %+v", l)
	}
	if l := attributeKey("shadow-agent", "", names); len(l) != 0 {
		t.Fatalf("unrelated key linked: %+v", l)
	}
}

func TestUnaccountedAction(t *testing.T) {
	cases := []struct {
		linked, used7d, used30d, open bool
		want                          string
	}{
		{false, true, true, false, "open"},     // used this week, nothing names it
		{false, true, true, true, "open"},      // refreshed
		{true, true, true, true, "resolve"},    // a link appeared
		{true, true, true, false, ""},          // linked: never a finding
		{false, false, true, true, ""},         // quiet 8-29 days: stays open
		{false, false, false, true, "resolve"}, // quiet 30 days
		{false, false, true, false, ""},        // old usage only: not opened
	}
	for _, c := range cases {
		if got := unaccountedAction(c.linked, c.used7d, c.used30d, c.open); got != c.want {
			t.Errorf("%+v: %q", c, got)
		}
	}
}

func TestModelProviderFingerprintAndPaths(t *testing.T) {
	key := "sk-admin-abcdefghijklmnopqrstuvwxyz-WXYZ"
	fp := ModelProviderKeyFingerprint(key)
	if !strings.HasPrefix(fp, "...WXYZ sha256:") || len(fp) != len("...WXYZ sha256:")+12 || strings.Contains(fp, "abcdef") {
		t.Fatalf("fingerprint %q", fp)
	}
	ws, id := uuid.New(), uuid.New()
	p := ModelProviderSecretPath(ws, id, "n1")
	if !strings.HasPrefix(p, "kv/data/secret/workspaces/"+ws.String()+"/agent-runtime/model-provider-"+id.String()) {
		t.Fatalf("path %q", p)
	}
	if err := validateAdminKey("short"); err == nil {
		t.Fatal("short key accepted")
	}
	if err := validateAdminKey("sk-admin-has space in it-0000000"); err == nil {
		t.Fatal("key with spaces accepted")
	}
	if err := validateAdminKey(key); err != nil {
		t.Fatal(err)
	}
	if !FindingKinds[FindingUnaccountedModelUsage] {
		t.Fatal("findings filter does not admit unaccounted_model_usage")
	}
}
