package load

// The fixture's database guard (loadDSNRefusal), tested without a database:
// the T6.10 fixture must never be built in the integration package's
// IGA_TEST_DSN or tests/igagraph's TEST_DATABASE_URL. Its evidence junctions
// and publications reference cloud_observation and cloud_scan_run, which
// every p2 lab empties wholesale, so a fixture kept there (IGA_LOAD_KEEP=1)
// breaks the whole TestP2 gate in that database. These run in every
// `go test ./tests/load/`, IGA_LOAD_DSN or not.

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestP2LoadRefusesASharedDatabase: a DSN naming the same database as either
// shared suite's is refused however either is spelled; a different database,
// server or port is not; an unreadable shared DSN is refused (it cannot be
// shown to differ).
func TestP2LoadRefusesASharedDatabase(t *testing.T) {
	const mine = "postgres://authsec:pw@localhost:55433/iga_w_loadfx?sslmode=disable"
	for _, c := range []struct {
		name   string
		dsn    string
		env    map[string]string
		refuse string // a substring of the refusal; "" when none
	}{
		{"nothing else set", mine, nil, ""},
		{"a different integration database", mine,
			map[string]string{"IGA_TEST_DSN": "postgres://authsec:pw@localhost:55433/iga_w_load?sslmode=disable"}, ""},
		{"the integration database", mine,
			map[string]string{"IGA_TEST_DSN": mine}, "IGA_TEST_DSN"},
		{"the graph suite's database", mine,
			map[string]string{"IGA_TEST_DSN": "postgres://authsec:pw@localhost:55433/iga_w_load", "TEST_DATABASE_URL": mine},
			"TEST_DATABASE_URL"},
		{"the same database spelled differently", mine,
			map[string]string{"IGA_TEST_DSN": "postgresql://other:secret@127.0.0.1:55433/iga_w_loadfx"}, "IGA_TEST_DSN"},
		{"the same database as key=value pairs", mine,
			map[string]string{"IGA_TEST_DSN": "host=localhost port=55433 user=authsec password=pw dbname=iga_w_loadfx sslmode=disable"},
			"IGA_TEST_DSN"},
		{"the default port both ways", "postgres://authsec@db.internal/iga",
			map[string]string{"IGA_TEST_DSN": "host=db.internal dbname=iga"}, "IGA_TEST_DSN"},
		{"dbname defaults to the user", "postgres://authsec@localhost:55433",
			map[string]string{"IGA_TEST_DSN": "postgres://authsec@localhost:55433/authsec"}, "IGA_TEST_DSN"},
		{"the query overrides the path", mine,
			map[string]string{"IGA_TEST_DSN": "postgres://authsec@localhost:55433/other?dbname=iga_w_loadfx"}, "IGA_TEST_DSN"},
		{"another server", mine,
			map[string]string{"IGA_TEST_DSN": "postgres://authsec:pw@db.internal:55433/iga_w_loadfx"}, ""},
		{"another port", mine,
			map[string]string{"IGA_TEST_DSN": "postgres://authsec:pw@localhost:55434/iga_w_loadfx"}, ""},
		{"an unreadable shared DSN", mine,
			map[string]string{"TEST_DATABASE_URL": "localhost:55433/iga_w_loadfx"}, "cannot be read"},
		{"an unreadable load DSN", "iga_w_loadfx", nil, "IGA_LOAD_DSN"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := loadDSNRefusal(c.dsn, func(k string) string { return c.env[k] })
			switch {
			case c.refuse == "" && got != "":
				t.Errorf("a database of its own is refused: %s", got)
			case c.refuse != "" && !strings.Contains(got, c.refuse):
				t.Errorf("refusal %q, want one naming %q", got, c.refuse)
			}
			if strings.Contains(got, "pw") || strings.Contains(got, "secret") {
				t.Errorf("the refusal repeats a password: %s", got)
			}
		})
	}
}

// loadGuardChildEnv marks the child process TestP2LoadRefusalStopsTheFixture
// starts, so the child never starts one of its own.
const loadGuardChildEnv = "IGA_LOAD_GUARD_CHILD"

// TestP2LoadRefusalStopsTheFixture: the guard is wired into loadEnvFor ahead
// of the fixture -- a database test run with IGA_LOAD_DSN equal to
// IGA_TEST_DSN fails with the refusal and never opens the database. The child
// is this test binary running TestP2LoadFixtureIntegrity against a host that
// cannot resolve (.invalid, RFC 2606): were the guard skipped, the child
// would fail on connecting instead, and without the refusal in its output.
func TestP2LoadRefusalStopsTheFixture(t *testing.T) {
	if os.Getenv(loadGuardChildEnv) != "" {
		t.Skip("inside the guard's child process")
	}
	const shared = "postgres://authsec:pw@p2-load-guard.invalid:1/shared?sslmode=disable&connect_timeout=2"
	cmd := exec.Command(os.Args[0], "-test.run=^TestP2LoadFixtureIntegrity$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(),
		loadGuardChildEnv+"=1",
		loadDSNEnv+"="+shared,
		"IGA_TEST_DSN="+shared,
		"TEST_DATABASE_URL=",
		loadKeepEnv+"=",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("the fixture test passed with IGA_LOAD_DSN equal to IGA_TEST_DSN:\n%s", out)
	}
	if !strings.Contains(string(out), "refusing to build the T6.10 fixture") {
		t.Fatalf("the fixture test failed without the refusal (was the database opened?):\n%s", out)
	}
}
