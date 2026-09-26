package collector

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	platform "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/routes"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

var (
	db      *gorm.DB
	pg      *testsupport.PGContainer
	router  *gin.Engine
	syncSvc *services.CollectorSyncService
	current time.Time
)

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	_ = os.Setenv("IGA_COLLECTOR_RESPONSE_KEY", "test-collector-response-key")
	_ = os.Setenv("IGA_V2_INGEST", "1")
	gin.SetMode(gin.TestMode)

	var err error
	pg, err = testsupport.StartPostgres(testsupport.MigrationsPath("master"))
	if err != nil {
		log.SetOutput(os.Stderr)
		log.Fatalf("postgres: %v", err)
	}
	gdb, err := gorm.Open(postgres.Open(pg.DSN), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		pg.Terminate()
		log.SetOutput(os.Stderr)
		log.Fatalf("gorm: %v", err)
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		pg.Terminate()
		log.SetOutput(os.Stderr)
		log.Fatalf("sql: %v", err)
	}
	sqlDB.SetMaxOpenConns(8)
	sqlDB.SetMaxIdleConns(4)
	db = gdb

	current = time.Date(2026, 9, 25, 8, 0, 0, 0, time.UTC)
	svc, err := services.NewCollectorEnrollmentService(db, func() time.Time { return current })
	if err != nil {
		pg.Terminate()
		log.SetOutput(os.Stderr)
		log.Fatalf("enrollment service: %v", err)
	}
	router = newRouter(platform.NewCollectorController(svc))
	code := m.Run()
	pg.Terminate()
	os.Exit(code)
}

func newRouter(ctl *platform.CollectorController) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	syncSvc = routes.MountCollectorV2(r, db, ctl, humanAuth)

	disc := platform.NewDiscoveryController(db)
	ingress := r.Group("/authsec/discovery")
	ingress.Use(middlewares.LegacyDiscoveryIngressGuard(db, 120, time.Minute, 1<<20))
	ingress.POST("/sightings", disc.ReportSighting)
	ingress.POST("/agent-registration", disc.RegisterAgent)

	authed := r.Group("/authsec/discovery")
	authed.Use(humanAuth)
	authed.PUT("/settings/legacy-ingress", middlewares.Require("discovery", "admin"), ctl.SetLegacyIngress)

	gov := platform.NewGovernanceController(db)
	r.GET("/authsec/provisioning/instructions", gov.LeaseInstructions)
	return r
}

func humanAuth(c *gin.Context) {
	c.Set("claims", jwt.MapClaims{"scope": c.GetHeader("X-Test-Scope")})
	c.Set("workspace_id", c.GetHeader("X-Test-Workspace"))
	c.Set("client_id", "test-actor")
	c.Next()
}

func resetClock(t *testing.T) {
	t.Helper()
	current = time.Date(2026, 9, 25, 8, 0, 0, 0, time.UTC)
}

func newWorkspace(t *testing.T) uuid.UUID {
	t.Helper()
	id := uuid.New()
	err := db.Exec(`INSERT INTO workspaces
        (id,name,slug,owner_user_id,workspace_type,workspace_domain,email,status,created_at,updated_at)
        VALUES (?,?,NULL,?,'team',?,?,'active',NOW(),NOW())`,
		id, "ws-"+id.String()[:8], id, id.String()+".test", id.String()+"@test.local").Error
	if err != nil {
		t.Fatalf("workspace: %v", err)
	}
	return id
}

func countRows(t *testing.T, table string, ws uuid.UUID) int64 {
	t.Helper()
	switch table {
	case "collector_enrollments", "collector_instances", "collector_credentials",
		"collector_integrations", "collector_batches", "discovered_agents",
		"iga_relationship", "iga_agents", "discovery_sources", "iga_estate_scopes",
		"iga_object_support", "iga_workload", "collector_outbox", "iga_observations",
		"iga_source_objects":
	default:
		t.Fatalf("refusing to count %s", table)
	}
	var n int64
	if err := db.Raw(`SELECT count(*) FROM `+table+` WHERE workspace_id = ?`, ws).Scan(&n).Error; err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

type apiResp struct {
	code int
	body []byte
	hdr  http.Header
}

func do(method, path, token, scope, ws string, body []byte) apiResp {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if scope != "" {
		req.Header.Set("X-Test-Scope", scope)
	}
	if ws != "" {
		req.Header.Set("X-Test-Workspace", ws)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return apiResp{code: w.Code, body: w.Body.Bytes(), hdr: w.Header()}
}

func doReader(method, path, token string, body io.Reader) apiResp {
	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return apiResp{code: w.Code, body: w.Body.Bytes(), hdr: w.Header()}
}

type enrolled struct {
	CollectorID       uuid.UUID
	DiscoverySourceID uuid.UUID
	IntegrationID     uuid.UUID
	EstateID          uuid.UUID
	Credential        string
	Scopes            []string
	Public            ed25519.PublicKey
	Private           ed25519.PrivateKey
	RowVersion        int64
}

func enrollCollector(t *testing.T, ws uuid.UUID, kind, ceiling string, hints map[string]any) enrolled {
	t.Helper()
	resetClock(t)
	payload := map[string]any{"kind": kind}
	if ceiling != "" {
		payload["capability_ceiling"] = json.RawMessage(ceiling)
	}
	raw, _ := json.Marshal(payload)
	issued := do(http.MethodPost, "/api/iga/v2/collector-enrollments", "", "discovery:admin", ws.String(), raw)
	if issued.code != http.StatusCreated {
		t.Fatalf("issue enrollment: %d %s", issued.code, issued.body)
	}
	var tok struct {
		EnrollmentID uuid.UUID `json:"enrollment_id"`
		Token        string    `json:"token"`
	}
	if err := json.Unmarshal(issued.body, &tok); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"installation_public_key": base64.StdEncoding.EncodeToString(pub),
		"installation_nonce":      uuid.NewString(),
		"kind":                    kind,
		"version":                 "0.1.0",
		"native_hints":            hints,
	}
	braw, _ := json.Marshal(body)
	got := do(http.MethodPost, "/api/iga/v2/collectors/enroll", tok.Token, "", "", braw)
	if got.code != http.StatusOK {
		t.Fatalf("enroll: %d %s", got.code, got.body)
	}
	var out struct {
		CollectorID       uuid.UUID `json:"collector_id"`
		DiscoverySourceID uuid.UUID `json:"discovery_source_id"`
		IntegrationID     uuid.UUID `json:"integration_id"`
		EstateID          uuid.UUID `json:"estate_id"`
		Credential        string    `json:"credential"`
		Scopes            []string  `json:"scopes"`
	}
	if err := json.Unmarshal(got.body, &out); err != nil {
		t.Fatal(err)
	}
	view := do(http.MethodGet, "/api/iga/v2/collectors/"+out.CollectorID.String(), "", "discovery:read", ws.String(), nil)
	if view.code != http.StatusOK {
		t.Fatalf("get collector: %d %s", view.code, view.body)
	}
	var v struct {
		RowVersion int64 `json:"row_version"`
	}
	_ = json.Unmarshal(view.body, &v)
	return enrolled{
		CollectorID: out.CollectorID, DiscoverySourceID: out.DiscoverySourceID,
		IntegrationID: out.IntegrationID, EstateID: out.EstateID,
		Credential: out.Credential, Scopes: out.Scopes,
		Public: pub, Private: priv, RowVersion: v.RowVersion,
	}
}
