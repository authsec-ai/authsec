package shared

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestListPosturePaginatedIsolatedAndSecretFree(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := openPostureHTTPDB(t)
	ws, other := uuid.New(), uuid.New()
	runID := uuid.New()
	now := time.Unix(1_700_000_000, 0).UTC()
	require.NoError(t, db.Create(&models.ADInventoryRun{
		ID: runID, WorkspaceID: ws, SyncConfigID: uuid.New(), Status: "succeeded", Mode: "full",
		Coverage: datatypes.JSON("[]"), CreatedAt: now,
	}).Error)
	priv := true
	rows := []models.ADDirectoryPosture{
		postureRow(ws, runID, "00000000-0000-0000-0000-000000000001", "complete", &priv, now),
		postureRow(ws, runID, "00000000-0000-0000-0000-000000000002", "partial", nil, now),
		postureRow(ws, runID, "00000000-0000-0000-0000-000000000003", "complete", &priv, now),
	}
	for _, row := range rows {
		require.NoError(t, db.Create(&row).Error)
	}

	h := NewADInventoryController(db)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("workspace_id", ws.String())
		c.Next()
	})
	r.GET("/runs/:id/posture", h.ListPosture)

	req := httptest.NewRequest(http.MethodGet, "/runs/"+runID.String()+"/posture?limit=2", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var page struct {
		Posture    []map[string]any `json:"posture"`
		NextOffset *int             `json:"next_offset"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
	if len(page.Posture) != 2 || page.NextOffset == nil || *page.NextOffset != 2 {
		t.Fatalf("page: %s", rec.Body.String())
	}
	if page.Posture[1]["privileged"] != nil {
		t.Fatalf("partial privileged must be JSON null: %v", page.Posture[1]["privileged"])
	}
	assertNoSecretKeys(t, rec.Body.Bytes())

	req = httptest.NewRequest(http.MethodGet, "/runs/"+runID.String()+"/posture?limit=2&offset=2", nil)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var last struct {
		Posture    []map[string]any `json:"posture"`
		NextOffset *int             `json:"next_offset"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &last))
	if len(last.Posture) != 1 || last.NextOffset != nil {
		t.Fatalf("last page: %s", rec.Body.String())
	}

	otherRouter := gin.New()
	otherRouter.Use(func(c *gin.Context) {
		c.Set("workspace_id", other.String())
		c.Next()
	})
	otherRouter.GET("/runs/:id/posture", h.ListPosture)
	req = httptest.NewRequest(http.MethodGet, "/runs/"+runID.String()+"/posture", nil)
	rec = httptest.NewRecorder()
	otherRouter.ServeHTTP(rec, req)
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())

	req = httptest.NewRequest(http.MethodGet, "/runs/not-a-uuid/posture", nil)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
}

func postureRow(ws, run uuid.UUID, guid, coverage string, privileged *bool, now time.Time) models.ADDirectoryPosture {
	return models.ADDirectoryPosture{
		ID: uuid.New(), WorkspaceID: ws, RunID: run, ObjectGUID: guid, AccountKind: "ad_user",
		Coverage: coverage, PartialReasons: datatypes.JSON("[]"), DelegationTargets: datatypes.JSON("[]"),
		RBCDPrincipals: datatypes.JSON("[]"), PrivilegedPath: datatypes.JSON("[]"),
		Privileged: privileged, CreatedAt: now,
	}
}

func openPostureHTTPDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE ad_inventory_runs (
		id text primary key, workspace_id text, sync_config_id text, integration_id text, scan_run_id text,
		status text, mode text, started_at datetime, completed_at datetime, requested_by text,
		coverage text, error_text text, objects_seen integer, created_at datetime)`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE ad_directory_posture (
		id text primary key, workspace_id text not null, run_id text not null, object_guid text not null,
		object_sid text not null default '', account_kind text not null, distinguished_name text not null default '',
		sam_account_name text not null default '', coverage text not null, partial_reasons text not null default '[]',
		unconstrained_delegation numeric not null default 0, constrained_delegation numeric not null default 0,
		protocol_transition numeric not null default 0, delegation_targets text not null default '[]',
		rbcd_principals text not null default '[]', rbcd_asserted numeric not null default 0,
		privileged numeric, privileged_direct numeric not null default 0, privileged_nested numeric not null default 0,
		privileged_path text not null default '[]', admin_count numeric not null default 0, admin_count_orphan numeric,
		sensitive_not_delegated numeric not null default 0, protected_users numeric not null default 0, gmsa numeric not null default 0, smsa numeric not null default 0,
		depth_exceeded numeric not null default 0, account_disabled numeric not null default 0, created_at datetime)`).Error)
	return db
}

func assertNoSecretKeys(t *testing.T, raw []byte) {
	t.Helper()
	var v any
	require.NoError(t, json.Unmarshal(raw, &v))
	denied := []string{
		"msDS-ManagedPassword", "msDS-ManagedPasswordPreviousId", "unicodePwd", "userPassword",
		"supplementalCredentials", "ntPwdHistory", "lmPwdHistory", "unixUserPassword", "ms-Mcs-AdmPwd", "dBCSPwd",
	}
	var walk func(any)
	walk = func(n any) {
		switch x := n.(type) {
		case map[string]any:
			for k, child := range x {
				for _, name := range denied {
					if strings.EqualFold(k, name) {
						t.Fatalf("response contained secret key %s", k)
					}
				}
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	walk(v)
	if bytes.Contains(bytes.ToLower(raw), []byte("msds-managedpassword")) {
		t.Fatalf("response named a secret attribute: %s", raw)
	}
}
