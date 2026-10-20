package services

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func withUIOrigin(t *testing.T, origin string) {
	t.Helper()
	prev := config.AppConfig
	config.AppConfig = &config.Config{UIOrigin: origin}
	t.Cleanup(func() { config.AppConfig = prev })
}

func TestParseUIOriginAcceptsOnlyAnOrigin(t *testing.T) {
	ok := []string{
		"https://app.authsec.ai",
		"https://aman.app.authsec.ai/",
		"https://aman.app.authsec.ai:8443",
		"http://localhost:3000",
		"http://aman.localhost:3000",
		"http://127.0.0.1:3000",
	}
	for _, o := range ok {
		if _, good := parseUIOrigin(o); !good {
			t.Errorf("%q should be accepted as an origin", o)
		}
	}
	bad := []string{
		"", "null", "app.authsec.ai", "javascript:alert(1)", "ftp://app.authsec.ai",
		"http://aman.app.authsec.ai",              // plain http outside a local host
		"https://aman.app.authsec.ai/admin/login", // a path
		"https://aman.app.authsec.ai/?next=x",     // a query
		"https://user:pw@aman.app.authsec.ai",     // credentials
		"https://aman.app.authsec.ai/#frag",       // a fragment
	}
	for _, o := range bad {
		if _, good := parseUIOrigin(o); good {
			t.Errorf("%q must not be accepted as an origin", o)
		}
	}
}

func TestBareHost(t *testing.T) {
	cases := map[string]string{
		"aman.app.authsec.ai":        "aman.app.authsec.ai",
		"AMAN.App.AuthSec.ai":        "aman.app.authsec.ai",
		"https://iam.fabrikam.com/":  "iam.fabrikam.com",
		"iam.fabrikam.com:8443":      "iam.fabrikam.com",
		"iam.fabrikam.com/some/path": "iam.fabrikam.com",
		"":                           "",
	}
	for in, want := range cases {
		if got := bareHost(in); got != want {
			t.Errorf("bareHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// Without a database, only the configured UI origin is a known origin.
func TestAzureReturnOriginConfiguredOriginOnly(t *testing.T) {
	withUIOrigin(t, "https://app.authsec.ai")
	s := &AzureOnboardingService{}
	ws := uuid.New()
	if got := s.azureReturnOrigin(ws, "https://APP.authsec.ai/"); got != "https://app.authsec.ai" {
		t.Fatalf("the configured UI origin = %q", got)
	}
	for _, o := range []string{"https://evil.example", "https://app.authsec.ai.evil.example", "http://app.authsec.ai"} {
		if got := s.azureReturnOrigin(ws, o); got != "" {
			t.Errorf("%q was accepted as %q", o, got)
		}
	}
}

func setupReturnOriginDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping the workspace-origin database test")
	}
	requireThrowawayDatabase(t, dsn)
	raw, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer raw.Close()
	for _, stmt := range []string{"DROP SCHEMA IF EXISTS public CASCADE", "CREATE SCHEMA public"} {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("reset schema (%q): %v", stmt, err)
		}
	}
	p, _ := filepath.Abs(filepath.Join("..", "migrations", "master", "001_bootstrap.sql"))
	body, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read bootstrap: %v", err)
	}
	if _, err := raw.Exec(string(body)); err != nil {
		t.Fatalf("apply bootstrap: %v", err)
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("gorm open: %v", err)
	}
	return db
}

// Each workspace comes back to its own domain or a verified domain of its own;
// another workspace's domain, an unverified domain and a look-alike are not
// accepted.
func TestAzureReturnOriginIsTheWorkspacesOwn(t *testing.T) {
	db := setupReturnOriginDB(t)
	withUIOrigin(t, "https://app.authsec.ai")
	aman, contoso := uuid.New(), uuid.New()
	for _, w := range []struct {
		id     uuid.UUID
		domain string
	}{{aman, "aman.app.authsec.ai"}, {contoso, "contoso.app.authsec.ai"}} {
		if err := db.Exec(`INSERT INTO workspaces (id, name, workspace_domain) VALUES (?, ?, ?)`, w.id, w.domain, w.domain).Error; err != nil {
			t.Fatalf("workspace: %v", err)
		}
	}
	for _, d := range []struct {
		domain   string
		verified bool
	}{{"iam.aman-corp.com", true}, {"pending.aman-corp.com", false}} {
		if err := db.Exec(`INSERT INTO workspace_domains (id, workspace_id, domain, kind, is_verified, verification_token) VALUES (?, ?, ?, 'custom', ?, ?)`,
			uuid.New(), aman, d.domain, d.verified, "test-"+d.domain).Error; err != nil {
			t.Fatalf("workspace domain: %v", err)
		}
	}
	s := &AzureOnboardingService{db: db}

	accept := map[string]string{
		"https://aman.app.authsec.ai": "https://aman.app.authsec.ai",
		"https://iam.aman-corp.com/":  "https://iam.aman-corp.com",
		"https://app.authsec.ai":      "https://app.authsec.ai",
	}
	for in, want := range accept {
		if got := s.azureReturnOrigin(aman, in); got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
	reject := []string{
		"https://contoso.app.authsec.ai",           // another workspace's domain
		"https://pending.aman-corp.com",            // not verified
		"https://aman.app.authsec.ai.evil.example", // look-alike
		"https://evil.example",
		"http://aman.app.authsec.ai",
	}
	for _, in := range reject {
		if got := s.azureReturnOrigin(aman, in); got != "" {
			t.Errorf("%q was accepted for aman's workspace as %q", in, got)
		}
	}
	if got := s.azureReturnOrigin(contoso, "https://aman.app.authsec.ai"); got != "" {
		t.Errorf("contoso's onboarding could return to aman's domain: %q", got)
	}
}
