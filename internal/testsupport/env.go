// Package testsupport provides a shared integration-test harness.
// No build tag — linked only by tagged test binaries (integration, smoke).
//
// Usage in TestMain:
//
//	func TestMain(m *testing.M) {
//	    config.ResetForTest()
//	    tokens.ResetForTest()
//	    env, err := testsupport.Boot()
//	    if err != nil { log.Fatalf("boot: %v", err) }
//	    code := m.Run()
//	    env.Teardown()
//	    os.Exit(code)
//	}
//
// Usage in tests:
//
//	func Test_Foo(t *testing.T) {
//	    env := testsupport.Get(t) // accessor only; no cleanup registered
//	    tok, _ := env.AsAdmin(userID, wsID, email)
//	    resp := env.Do("POST", "/api/path", myBody, tok)
//	    assert.Equal(t, 200, resp.Code)
//	}
package testsupport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/handlers"
	"github.com/authsec-ai/authsec/internal/migration"
	"github.com/authsec-ai/authsec/internal/session"
	"github.com/authsec-ai/authsec/internal/testsupport/fakes"
	"github.com/authsec-ai/authsec/monitoring"
	"github.com/authsec-ai/authsec/routes"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Env is the shared environment for one test binary. All fields are safe to
// read concurrently after Boot returns; write-mutations are forbidden outside
// of TestMain.
type Env struct {
	Router *gin.Engine
	Fakes  *fakes.Fakes
	PG     *PGContainer
}

var (
	sharedEnv  *Env
	sharedOnce sync.Once
	bootErr    error
)

// BootOption configures Boot.
type BootOption func(*bootCfg)

type bootCfg struct {
	xaaFlagsOff bool
}

// WithXAAFlagsOff sets all XAA feature flags to false so that controllers
// reject the corresponding grant types. Use this in the flagsoff/ sibling
// binary's TestMain to exercise denial paths.
func WithXAAFlagsOff() BootOption {
	return func(c *bootCfg) { c.xaaFlagsOff = true }
}

// Boot starts the test environment exactly once per test binary. Call it from
// TestMain (after config.ResetForTest and tokens.ResetForTest), then run
// m.Run(), then call env.Teardown().
func Boot(opts ...BootOption) (*Env, error) {
	cfg := &bootCfg{}
	for _, o := range opts {
		o(cfg)
	}

	sharedOnce.Do(func() {
		migrationsDir := MigrationsPath("master")

		// 1. Start fakes first — env vars must be written BEFORE LoadConfig.
		f, err := fakes.Start()
		if err != nil {
			bootErr = fmt.Errorf("start fakes: %w", err)
			return
		}
		setHarnessEnv(f, cfg)

		// 2. Start Postgres + bootstrap.
		pg, err := StartPostgres(migrationsDir)
		if err != nil {
			f.Stop()
			bootErr = fmt.Errorf("start postgres: %w", err)
			return
		}

		// 3. Point the config globals at the cloned working DB.
		os.Setenv("DB_HOST", pg.Host)
		os.Setenv("DB_PORT", pg.Port)
		os.Setenv("DB_USER", pgUser)
		os.Setenv("DB_PASSWORD", pgPassword)
		os.Setenv("DB_NAME", "authtest_work")
		os.Setenv("DB_SCHEMA", "public")

		// Allow MCP discovery to reach httptest servers on loopback.
		os.Setenv("MCP_ALLOW_LOOPBACK", "true")

		// 4. Load config + init DB — mirrors cmd/main.go startup sequence.
		monitoring.InitMetrics() // must precede NewAuditLogger so the logrus logger is non-nil
		appCfg := config.LoadConfig()
		config.InitDatabaseWithoutGORM(appCfg)
		config.AuditLogger = monitoring.NewAuditLogger(config.DB)

		if err := migration.AutoMigrateMigrationLogs(config.DB); err != nil {
			bootErr = fmt.Errorf("auto-migrate migration_logs: %w", err)
			return
		}

		// 5. Init token service (reads JWT_DEF_SECRET / JWT_SDK_SECRET from env).
		tokenSvc, err := services.NewAuthManagerTokenService()
		if err != nil {
			bootErr = fmt.Errorf("init token service: %w", err)
			return
		}
		config.TokenService = tokenSvc

		// 6. Build WebAuthn handlers + Gin router (same as cmd/main.go).
		gin.SetMode(gin.TestMode)
		waH, adminWAH, euWAH := buildWebAuthn()
		router := gin.New()
		router.Use(gin.Recovery())
		routes.SetupRoutes(router, waH, adminWAH, euWAH, nil)

		sharedEnv = &Env{
			Router: router,
			Fakes:  f,
			PG:     pg,
		}
	})

	if bootErr != nil {
		return nil, bootErr
	}
	return sharedEnv, nil
}

// Get returns the shared *Env. It is an ACCESSOR ONLY — no teardown is
// registered via t.Cleanup. Teardown happens exclusively in TestMain via
// env.Teardown() after m.Run().
func Get(t testing.TB) *Env {
	t.Helper()
	if sharedEnv == nil {
		t.Fatal("testsupport: Boot() was not called in TestMain")
	}
	return sharedEnv
}

// Teardown stops the Postgres container and all fakes. Call in TestMain after m.Run().
func (e *Env) Teardown() {
	if e.Fakes != nil {
		e.Fakes.Stop()
	}
	if e.PG != nil {
		e.PG.Terminate()
	}
}

// Do performs an HTTP request against the test router and returns the recorder.
//
//   - body = nil → no body
//   - body = url.Values → form-encoded (application/x-www-form-urlencoded)
//   - body = anything else → JSON-encoded (application/json)
//
// authToken is the raw Bearer token (empty string → no Authorization header).
func (e *Env) Do(method, path string, body interface{}, authToken string) *httptest.ResponseRecorder {
	reqBody, contentType := encodeBody(body)
	req, _ := http.NewRequest(method, path, reqBody)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}
	setCanonicalHost(req)
	w := httptest.NewRecorder()
	e.Router.ServeHTTP(w, req)
	return w
}

// DoBasicAuth performs a request with HTTP Basic auth (used by /oauth/introspect).
func (e *Env) DoBasicAuth(method, path string, body interface{}, user, pass string) *httptest.ResponseRecorder {
	reqBody, contentType := encodeBody(body)
	req, _ := http.NewRequest(method, path, reqBody)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.SetBasicAuth(user, pass)
	setCanonicalHost(req)
	w := httptest.NewRecorder()
	e.Router.ServeHTTP(w, req)
	return w
}

// setCanonicalHost makes the request Host match the configured OAuth issuer host.
// The /oauth/* group is wrapped in CanonicalIssuerOnly(), which 308-redirects any
// request whose Host != the canonical issuer host. httptest requests default to an
// empty/synthetic Host, so without this every /oauth call would redirect with an
// empty body instead of reaching the handler. No-op when no canonical host is set.
func setCanonicalHost(req *http.Request) {
	if config.AppConfig == nil {
		return
	}
	parsed, err := url.Parse(config.AppConfig.OAuthBaseURL())
	if err != nil || parsed.Host == "" {
		return
	}
	req.Host = parsed.Host
}

// AsAdmin mints a signed admin JWT for the given identity.
func (e *Env) AsAdmin(userID, workspaceID uuid.UUID, email string) (string, error) {
	return MintAdminToken(AdminTokenParams{
		UserID:      userID,
		WorkspaceID: workspaceID,
		Email:       email,
		Roles:       []string{"admin"},
	})
}

// AsUser mints a signed end-user JWT.
func (e *Env) AsUser(userID, workspaceID uuid.UUID, email string) (string, error) {
	return MintUserToken(UserTokenParams{
		UserID:      userID,
		WorkspaceID: workspaceID,
		Email:       email,
	})
}

// MustAsAdmin panics if minting fails (use in test setup, not assertions).
func (e *Env) MustAsAdmin(userID, workspaceID uuid.UUID, email string) string {
	tok, err := e.AsAdmin(userID, workspaceID, email)
	if err != nil {
		panic("MustAsAdmin: " + err.Error())
	}
	return tok
}

// MustAsUser panics if minting fails.
func (e *Env) MustAsUser(userID, workspaceID uuid.UUID, email string) string {
	tok, err := e.AsUser(userID, workspaceID, email)
	if err != nil {
		panic("MustAsUser: " + err.Error())
	}
	return tok
}

// JSON decodes the response body into dst and returns the HTTP status code.
func JSON(t testing.TB, w *httptest.ResponseRecorder, dst interface{}) int {
	t.Helper()
	if dst != nil {
		if err := json.Unmarshal(w.Body.Bytes(), dst); err != nil {
			t.Logf("response body: %s", w.Body.String())
			t.Fatalf("decode response JSON: %v", err)
		}
	}
	return w.Code
}

// encodeBody converts a body value into an io.Reader and a Content-Type header.
func encodeBody(body interface{}) (io.Reader, string) {
	switch b := body.(type) {
	case nil:
		return nil, ""
	case url.Values:
		return strings.NewReader(b.Encode()), "application/x-www-form-urlencoded"
	default:
		bs, _ := json.Marshal(b)
		return bytes.NewReader(bs), "application/json"
	}
}

// setHarnessEnv writes all env vars that must be set before config.LoadConfig.
// Env var names match what config.go reads via getEnvBool/getEnv.
func setHarnessEnv(f *fakes.Fakes, cfg *bootCfg) {
	os.Setenv("JWT_DEF_SECRET", HarnessJWTSecret)
	os.Setenv("JWT_SDK_SECRET", HarnessJWTSecret)
	os.Setenv("JWT_SECRET", HarnessJWTSecret)

	os.Setenv("REQUIRE_SERVER_AUTH", "false")
	os.Setenv("ENVIRONMENT", "development")

	os.Setenv("WEBAUTHN_RP_NAME", "AuthSec Test")
	os.Setenv("WEBAUTHN_RP_ID", "localhost")
	os.Setenv("WEBAUTHN_ORIGIN", "http://localhost:3000")

	os.Setenv("TOTP_ENCRYPTION_KEY", "6AB33320B8A8E177655F72CEDDAE56593D045BE5A47416FDE7C7CF983D5B80D6")

	// Use a predictable suffix so register's "domain.suffix" == what login sends back.
	os.Setenv("TENANT_DOMAIN_SUFFIX", "test.local")

	os.Setenv("HYDRA_ADMIN_URL", f.HydraAdminURL())
	os.Setenv("HYDRA_PUBLIC_URL", f.HydraAdminURL())
	os.Setenv("ICP_SERVICE_URL", f.ICPServiceURL())
	os.Setenv("REDIS_URL", f.RedisURL())

	// XAA feature flags — config.go reads XAA_NATIVE_SEALER, XAA_M2M, XAA_REDEMPTION,
	// XAA_CIBA, XAA_ISSUANCE via getEnvBool (default false). All ON for the main flows
	// binary; OFF for the flagsoff/ sibling binary (WithXAAFlagsOff option).
	xaaVal := "true"
	if cfg != nil && cfg.xaaFlagsOff {
		xaaVal = "false"
	}
	os.Setenv("XAA_NATIVE_SEALER", xaaVal)
	os.Setenv("XAA_M2M", xaaVal)
	os.Setenv("XAA_REDEMPTION", xaaVal)
	os.Setenv("XAA_CIBA", xaaVal)
	os.Setenv("XAA_ISSUANCE", xaaVal)

	// Billing is out of scope — leave unset (fail-open by design).
	os.Unsetenv("BILLING_SERVICE_URL")

	os.Unsetenv("SKIP_DB_INIT")
	os.Unsetenv("SKIP_MIGRATIONS")
}

func buildWebAuthn() (
	*handlers.WebAuthnHandler,
	*handlers.AdminWebAuthnHandler,
	*handlers.EndUserWebAuthnHandler,
) {
	const (
		rpName = "AuthSec Test"
		rpID   = "localhost"
		origin = "http://localhost:3000"
	)
	wa := config.SetupWebAuthn(rpName, rpID, origin)
	pgSM := session.NewPostgreSQLSessionManager(config.DB, "")
	sa := handlers.NewSessionManagerAdapter(pgSM)

	return &handlers.WebAuthnHandler{
			WebAuthn: wa, SessionManager: sa,
			RPDisplayName: rpName, RPID: rpID, RPOrigins: []string{origin},
		},
		&handlers.AdminWebAuthnHandler{
			WebAuthn: wa, SessionManager: sa,
			RPDisplayName: rpName, RPID: rpID, RPOrigins: []string{origin},
		},
		&handlers.EndUserWebAuthnHandler{
			WebAuthn: wa, SessionManager: sa,
			RPDisplayName: rpName, RPID: rpID, RPOrigins: []string{origin},
		}
}
