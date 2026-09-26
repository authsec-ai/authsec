package admin

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authsec-ai/authsec/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestSyncConfigRejectsDirSync(t *testing.T) {
	gin.SetMode(gin.TestMode)
	scc := &SyncConfigController{}
	ws, client, id := uuid.New().String(), uuid.New().String(), uuid.New().String()

	r := gin.New()
	r.POST("/create", scc.CreateSyncConfig)
	r.POST("/update", scc.UpdateSyncConfig)

	create := `{"workspace_id":"` + ws + `","client_id":"` + client + `","project_id":"` + uuid.New().String() + `","sync_type":"active_directory","config_name":"ad","ad_config":{"server":"dc:389","tracking_mode":"DirSync"}}`
	req := httptest.NewRequest(http.MethodPost, "/create", bytes.NewBufferString(create))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), models.DirSyncUnsupportedMessage)

	update := `{"id":"` + id + `","workspace_id":"` + ws + `","client_id":"` + client + `","ad_config":{"tracking_mode":"dirsync"}}`
	req = httptest.NewRequest(http.MethodPost, "/update", bytes.NewBufferString(update))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), models.DirSyncUnsupportedMessage)
}
