package shared

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestADInventoryConfigOmitsSecrets(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := openADInventoryHTTPDB(t)
	ws, cfgID := uuid.New(), uuid.New()
	require.NoError(t, db.Exec(`INSERT INTO sync_configurations
		(id, workspace_id, sync_type, is_active, ad_server, ad_username, ad_password, ad_use_ssl)
		VALUES (?, ?, 'active_directory', 1, 'dc.authsec.test:636', 'svc', 'encrypted-not-a-password', 1)`,
		cfgID.String(), ws.String()).Error)

	h := NewADInventoryController(db)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("workspace_id", ws.String())
		c.Next()
	})
	r.PUT("/config", h.PutConfig)
	r.GET("/config", h.GetConfig)

	body := `{"config_id":"` + cfgID.String() + `","password":"CANARY-SECRET-DO-NOT-LEAK-7","ca_bundle":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n","scopes":[{"base_dn":"DC=authsec,DC=test"}],"use_ssl":true,"page_size":100}`
	req := httptest.NewRequest(http.MethodPut, "/config", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	if bytes.Contains(rec.Body.Bytes(), []byte("CANARY-SECRET-DO-NOT-LEAK-7")) || bytes.Contains(rec.Body.Bytes(), []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("config response leaked material: %s", rec.Body.String())
	}
	var saved services.InventoryConfig
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &saved))
	require.True(t, saved.CABundleSet)
	require.Len(t, saved.Scopes, 1)

	req = httptest.NewRequest(http.MethodGet, "/config?config_id="+cfgID.String(), nil)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	if bytes.Contains(rec.Body.Bytes(), []byte("BEGIN CERTIFICATE")) || bytes.Contains(rec.Body.Bytes(), []byte("encrypted-not-a-password")) {
		t.Fatalf("get leaked material: %s", rec.Body.String())
	}

	dirsync := `{"config_id":"` + cfgID.String() + `","tracking_mode":"dirsync","scopes":[{"base_dn":"DC=authsec,DC=test"}]}`
	req = httptest.NewRequest(http.MethodPut, "/config", bytes.NewBufferString(dirsync))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "dirsync not supported yet; use usn")

	bare := gin.New()
	bare.PUT("/config", h.PutConfig)
	req = httptest.NewRequest(http.MethodPut, "/config", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	bare.ServeHTTP(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func openADInventoryHTTPDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE sync_configurations (
		id text primary key, workspace_id text, sync_type text, is_active numeric,
		ad_server text, ad_username text, ad_password text, ad_base_dn text,
		ad_use_ssl numeric, ad_skip_verify numeric, ad_ca_bundle text,
		ad_page_size integer, ad_change_tracking numeric, ad_start_tls numeric, ad_tracking_mode text,
		updated_at datetime)`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE ad_inventory_scopes (
		id text primary key, workspace_id text, sync_config_id text, integration_scope_id text,
		base_dn text, object_classes text, enabled numeric, created_at datetime, updated_at datetime)`).Error)
	return db
}
