package middlewares

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkspaceContractCompatibilityNormalizesJSONBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(WorkspaceContractCompatibility())
	router.POST("/echo", func(c *gin.Context) {
		var body map[string]any
		require.NoError(t, c.ShouldBindJSON(&body))
		c.JSON(http.StatusOK, body)
	})

	req := httptest.NewRequest(http.MethodPost, "/echo", bytes.NewBufferString(`{"tenant_id":"legacy","name":"demo"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "tenant_id", w.Header().Get("Deprecation"))

	var got map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, "legacy", got["tenant_id"])
	assert.Equal(t, "legacy", got["workspace_id"])
}

func TestWorkspaceContractCompatibilityNormalizesQueryAndForm(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(WorkspaceContractCompatibility())
	router.POST("/form", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"query_workspace_id": c.Query("workspace_id"),
			"query_tenant_id":    c.Query("tenant_id"),
			"form_workspace_id":  c.PostForm("workspace_id"),
			"form_tenant_id":     c.PostForm("tenant_id"),
		})
	})

	req := httptest.NewRequest(http.MethodPost, "/form?tenant_id=query-legacy", bytes.NewBufferString("tenant_id=form-legacy"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var got map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, "query-legacy", got["query_workspace_id"])
	assert.Equal(t, "query-legacy", got["query_tenant_id"])
	assert.Equal(t, "form-legacy", got["form_workspace_id"])
	assert.Equal(t, "form-legacy", got["form_tenant_id"])
}

func TestWorkspaceContractCompatibilityMirrorsNestedJSONResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(WorkspaceContractCompatibility())
	router.GET("/response", func(c *gin.Context) {
		c.JSON(http.StatusCreated, gin.H{
			"workspace_id": "root",
			"items": []gin.H{
				{"workspace_id": "child"},
			},
		})
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/response", nil))

	require.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "tenant_id", w.Header().Get("Deprecation"))

	var got map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, "root", got["workspace_id"])
	assert.Equal(t, "root", got["tenant_id"])

	items, ok := got["items"].([]any)
	require.True(t, ok)
	child, ok := items[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "child", child["workspace_id"])
	assert.Equal(t, "child", child["tenant_id"])
}

func TestWorkspaceContractCompatibilityLeavesNonWorkspaceJSONAlone(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(WorkspaceContractCompatibility())
	router.GET("/plain", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/plain", nil))

	require.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("Deprecation"))
	assert.JSONEq(t, `{"ok":true}`, w.Body.String())
}
