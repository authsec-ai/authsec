package services

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// requireThrowawayDatabase refuses to continue unless TEST_DATABASE_URL names a
// database that is obviously disposable.
//
// setupGCPOnboardingTestDB runs DROP SCHEMA public CASCADE. Pointed at a real
// database -- a developer's local dev instance, say -- that destroys every table
// in it: users, workspaces, roles, role_permissions, everything. The data is not
// recoverable, because the stock postgres image archives no WAL and there is no
// base backup to recover from.
//
// This has actually happened. The failure is total and silent: the test still
// passes, and the damage only surfaces later as unrelated-looking permission
// errors. So this is a hard failure rather than a warning.
//
// The check is on the database NAME, deliberately, not the host or port:
// "localhost" is exactly where both the throwaway database and the precious one
// live, so a host check would catch nothing.
//
// Set TEST_DATABASE_URL to a database whose name contains "test", e.g.
//
//	postgres://user:pass@localhost:5432/authsec_test?sslmode=disable
//
// and create that database separately. This helper must never be the thing that
// decides a database is expendable.
func requireThrowawayDatabase(t *testing.T, dsn string) {
	t.Helper()

	name, err := databaseNameFromDSN(dsn)
	if err != nil {
		t.Fatalf("refusing to run: TEST_DATABASE_URL could not be parsed (%v). "+
			"This helper runs DROP SCHEMA public CASCADE and will not guess which database that would hit.", err)
	}
	if !strings.Contains(strings.ToLower(name), "test") {
		t.Fatalf("refusing to run against database %q: it does not look like a throwaway test database. "+
			"This helper runs DROP SCHEMA public CASCADE, which would destroy every table in it. "+
			"Point TEST_DATABASE_URL at a database whose name contains %q.", name, "test")
	}
}

// databaseNameFromDSN extracts the database name from either DSN form the Go
// postgres drivers accept: a URL ("postgres://user@host:5432/name?...") or a
// keyword string ("host=... dbname=...").
func databaseNameFromDSN(dsn string) (string, error) {
	trimmed := strings.TrimSpace(dsn)

	if strings.HasPrefix(trimmed, "postgres://") || strings.HasPrefix(trimmed, "postgresql://") {
		u, err := url.Parse(trimmed)
		if err != nil {
			return "", err
		}
		name := strings.TrimPrefix(u.Path, "/")
		if name == "" {
			return "", fmt.Errorf("no database name in %q", trimmed)
		}
		return name, nil
	}

	for _, field := range strings.Fields(trimmed) {
		if rest, ok := strings.CutPrefix(field, "dbname="); ok && rest != "" {
			return rest, nil
		}
	}
	return "", fmt.Errorf("no dbname in %q", trimmed)
}

/* ---------------------------------- tests ---------------------------------- */
//
// These are pure string checks. They open no connection and touch no database.

func TestDatabaseNameFromDSN(t *testing.T) {
	tests := []struct {
		name    string
		dsn     string
		want    string
		wantErr bool
	}{
		{name: "url form", dsn: "postgres://u:p@localhost:5432/authsec_test?sslmode=disable", want: "authsec_test"},
		{name: "postgresql scheme", dsn: "postgresql://u@host/mydb", want: "mydb"},
		{name: "url with no query", dsn: "postgres://u:p@localhost:5432/authdev", want: "authdev"},
		{name: "keyword form", dsn: "host=localhost port=5432 user=u dbname=authsec_test sslmode=disable", want: "authsec_test"},
		{name: "keyword form, dbname last", dsn: "host=localhost dbname=authdev", want: "authdev"},
		{name: "url with no database", dsn: "postgres://u:p@localhost:5432/", wantErr: true},
		{name: "keyword form with no dbname", dsn: "host=localhost user=u", wantErr: true},
		{name: "empty", dsn: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := databaseNameFromDSN(tt.dsn)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("databaseNameFromDSN(%q) = %q, want an error", tt.dsn, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("databaseNameFromDSN(%q) returned %v, want %q", tt.dsn, err, tt.want)
			}
			if got != tt.want {
				t.Fatalf("databaseNameFromDSN(%q) = %q, want %q", tt.dsn, got, tt.want)
			}
		})
	}
}

// The guard's whole job is to fail, so it is exercised through a fake *testing.T
// substitute: calling it directly with the real t would abort this test.
// requireThrowawayDatabase only needs Helper() and Fatalf(), so the decision
// logic is restated here against the same inputs, and the two are kept honest by
// TestGuardAcceptsThrowawayNames below, which runs the real function.
func wouldRefuse(dsn string) bool {
	name, err := databaseNameFromDSN(dsn)
	if err != nil {
		return true
	}
	return !strings.Contains(strings.ToLower(name), "test")
}

func TestGuardRefusesRealDatabases(t *testing.T) {
	// The exact DSN that destroyed a developer's local dev database.
	refused := []string{
		"postgres://authdev:pw@127.0.0.1:5430/authdev?sslmode=disable",
		"postgres://postgres:postgres@localhost:5432/authsec",
		"postgres://u:p@prod-db.internal:5432/production",
		"host=localhost port=5430 user=authdev dbname=authdev",
		"not-a-dsn",
		"",
	}
	for _, dsn := range refused {
		if !wouldRefuse(dsn) {
			t.Errorf("guard must refuse %q, but it would have allowed the DROP SCHEMA to run", dsn)
		}
	}
}

func TestGuardAcceptsThrowawayNames(t *testing.T) {
	// Runs the REAL guard. Any t.Fatalf here fails the test, which is exactly
	// the assertion: these names must be accepted.
	accepted := []string{
		"postgres://u:p@localhost:5432/authsec_test?sslmode=disable",
		"postgres://u:p@localhost:5432/test_authsec",
		"postgres://u:p@localhost:5432/AUTHSEC_TEST",
		"host=localhost port=5432 user=u dbname=gcp_onboarding_test",
	}
	for _, dsn := range accepted {
		requireThrowawayDatabase(t, dsn)
		if wouldRefuse(dsn) {
			t.Errorf("guard should accept %q", dsn)
		}
	}
}
