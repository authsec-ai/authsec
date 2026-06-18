package services

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestValidateResourceServerAllowsDCRWithoutPreRegisteredClients(t *testing.T) {
	t.Parallel()

	db := newOnboardingTestDB(t)
	svc := NewResourceServerOnboardingService(db)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-protected-resource/mcp":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"resource":"ok"}`))
		case "/mcp":
			w.Header().Set("WWW-Authenticate", `Bearer realm="demo-server", resource_metadata="`+serverURLWithoutScheme(r)+`/.well-known/oauth-protected-resource/mcp"`)
			w.WriteHeader(http.StatusUnauthorized)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	rs := models.ResourceServer{
		ID:                       uuid.New(),
		WorkspaceID:              uuid.New(),
		Name:                     "demo-server",
		PublicBaseURL:            server.URL,
		ProtectedBasePath:        "/mcp",
		ResourceURI:              server.URL + "/mcp",
		RegistrationModes:        pq.StringArray{"dcr"},
		LastSuccessfulGeneration: 1,
		Active:                   true,
		Status:                   models.RSStateReady,
		State:                    models.RSStateReady,
		CreatedAt:                time.Now().UTC(),
		UpdatedAt:                time.Now().UTC(),
	}
	require.NoError(t, db.Create(&rs).Error)

	result, err := svc.ValidateResourceServer(&rs, 0, true)
	require.NoError(t, err)
	require.Equal(t, "passed", result.Status)
	require.Equal(t, "passing", validationCheckStatus(t, result, "client_registration"))
	require.Equal(t, "passing", validationCheckStatus(t, result, "browser_login"))
	require.Equal(t, "passing", validationCheckStatus(t, result, "tools_list_filter"))

	var stored models.ResourceServer
	require.NoError(t, db.First(&stored, "id = ?", rs.ID).Error)
	require.NotNil(t, stored.LastValidationStatus)
	require.Equal(t, "passed", *stored.LastValidationStatus)
	require.Nil(t, stored.LastValidationError)
}

func TestValidateResourceServerRequiresClientWhenDCRDisabled(t *testing.T) {
	t.Parallel()

	db := newOnboardingTestDB(t)
	svc := NewResourceServerOnboardingService(db)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-protected-resource/mcp":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"resource":"ok"}`))
		case "/mcp":
			w.Header().Set("WWW-Authenticate", `Bearer realm="demo-server", resource_metadata="`+serverURLWithoutScheme(r)+`/.well-known/oauth-protected-resource/mcp"`)
			w.WriteHeader(http.StatusUnauthorized)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	rs := models.ResourceServer{
		ID:                       uuid.New(),
		WorkspaceID:              uuid.New(),
		Name:                     "demo-server",
		PublicBaseURL:            server.URL,
		ProtectedBasePath:        "/mcp",
		ResourceURI:              server.URL + "/mcp",
		RegistrationModes:        pq.StringArray{"prereg"},
		LastSuccessfulGeneration: 1,
		Active:                   true,
		Status:                   models.RSStateReady,
		State:                    models.RSStateReady,
		CreatedAt:                time.Now().UTC(),
		UpdatedAt:                time.Now().UTC(),
	}
	require.NoError(t, db.Create(&rs).Error)

	result, err := svc.ValidateResourceServer(&rs, 0, true)
	require.NoError(t, err)
	require.Equal(t, "failed", result.Status)
	require.Equal(t, "failing", validationCheckStatus(t, result, "client_registration"))
	require.Equal(t, "failing", validationCheckStatus(t, result, "browser_login"))
	require.Equal(t, "failing", validationCheckStatus(t, result, "tools_list_filter"))
}

func newOnboardingTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.Exec(`
		CREATE TABLE resource_servers (
			id TEXT PRIMARY KEY,
			workspace_id TEXT NOT NULL,
			application_type TEXT NOT NULL DEFAULT 'mcp_server',
			legacy_client_id TEXT,
			name TEXT NOT NULL,
			public_base_url TEXT NOT NULL,
			protected_base_path TEXT NOT NULL,
			resource_uri TEXT NOT NULL,
			scopes_supported TEXT,
			registration_modes TEXT,
			introspection_secret TEXT,
			introspection_secret_hash TEXT,
			active NUMERIC,
			state TEXT NOT NULL,
			setup_completed_at DATETIME,
			setup_completed_by TEXT,
			status TEXT NOT NULL,
			scan_generation INTEGER NOT NULL DEFAULT 0,
			last_successful_generation INTEGER NOT NULL DEFAULT 0,
			scan_in_progress NUMERIC NOT NULL DEFAULT 0,
			last_scan_status TEXT,
			last_scan_error TEXT,
			last_scan_started_at DATETIME,
			last_scan_completed_at DATETIME,
			last_validated_at DATETIME,
			last_validation_status TEXT,
			last_validation_error TEXT,
			prm_source TEXT DEFAULT 'fetched',
			prm_override_expires_at DATETIME,
			metadata_stale NUMERIC DEFAULT 0,
			created_at DATETIME,
			updated_at DATETIME,
			deleted_at DATETIME
		)
	`).Error)
	return db
}

func validationCheckStatus(t *testing.T, result *ResourceServerValidationResult, key string) string {
	t.Helper()

	for _, check := range result.Checks {
		if check.Key == key {
			return check.Status
		}
	}
	t.Fatalf("missing validation check %q", key)
	return ""
}

func serverURLWithoutScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https://" + r.Host
	}
	return "http://" + r.Host
}
