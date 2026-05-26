package middlewares

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

// WorkspaceContractCompatibility keeps the one-day Phase 5 API overlap small
// and centralized: requests may send tenant_id or workspace_id, while JSON
// responses mirror either field into the other and advertise tenant_id as
// deprecated.
func WorkspaceContractCompatibility() gin.HandlerFunc {
	return func(c *gin.Context) {
		normalizeWorkspaceRequest(c)

		recorder := &workspaceContractResponseWriter{
			ResponseWriter: c.Writer,
			status:         http.StatusOK,
		}
		c.Writer = recorder

		c.Next()

		body := recorder.body.Bytes()
		if len(body) == 0 || shouldSkipWorkspaceContract(c) {
			recorder.writeRaw(body)
			return
		}

		contentType := c.Writer.Header().Get("Content-Type")
		if !strings.Contains(strings.ToLower(contentType), "application/json") && !looksLikeJSON(body) {
			recorder.writeRaw(body)
			return
		}

		var payload any
		if err := json.Unmarshal(body, &payload); err != nil {
			recorder.writeRaw(body)
			return
		}

		hasDeprecatedTenantID := hasWorkspaceContractField(payload, "tenant_id")
		changed := mirrorWorkspaceTenantFields(payload)
		if !changed && !hasDeprecatedTenantID {
			recorder.writeRaw(body)
			return
		}

		c.Writer.Header().Set("Deprecation", "tenant_id")
		if !changed {
			recorder.writeRaw(body)
			return
		}

		encoded, err := json.Marshal(payload)
		if err != nil {
			recorder.writeRaw(body)
			return
		}

		c.Writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		c.Writer.Header().Del("Content-Length")
		recorder.writeRaw(encoded)
	}
}

type workspaceContractResponseWriter struct {
	gin.ResponseWriter
	body   bytes.Buffer
	status int
}

func (w *workspaceContractResponseWriter) WriteHeader(code int) {
	w.status = code
}

func (w *workspaceContractResponseWriter) WriteHeaderNow() {
	if w.status == 0 {
		w.status = http.StatusOK
	}
}

func (w *workspaceContractResponseWriter) Write(data []byte) (int, error) {
	return w.body.Write(data)
}

func (w *workspaceContractResponseWriter) WriteString(s string) (int, error) {
	return w.body.WriteString(s)
}

func (w *workspaceContractResponseWriter) Status() int {
	return w.status
}

func (w *workspaceContractResponseWriter) Size() int {
	return w.body.Len()
}

func (w *workspaceContractResponseWriter) Written() bool {
	return w.body.Len() > 0
}

func (w *workspaceContractResponseWriter) writeRaw(data []byte) {
	if w.status != 0 {
		w.ResponseWriter.WriteHeader(w.status)
	}
	if len(data) > 0 {
		_, _ = w.ResponseWriter.Write(data)
	}
}

func normalizeWorkspaceRequest(c *gin.Context) {
	if shouldSkipWorkspaceContract(c) {
		return
	}

	normalizeWorkspaceQuery(c.Request.URL.Query(), c.Request.URL)

	contentType := strings.ToLower(c.GetHeader("Content-Type"))
	if strings.Contains(contentType, "application/json") {
		normalizeWorkspaceJSONBody(c.Request)
		return
	}

	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		_ = c.Request.ParseForm()
		normalizeWorkspaceValues(c.Request.Form)
		normalizeWorkspaceValues(c.Request.PostForm)
	}
}

func normalizeWorkspaceJSONBody(r *http.Request) {
	if r.Body == nil {
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil || len(bytes.TrimSpace(body)) == 0 {
		r.Body = io.NopCloser(bytes.NewReader(body))
		return
	}

	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
		return
	}

	if !mirrorWorkspaceTenantFields(payload) {
		r.Body = io.NopCloser(bytes.NewReader(body))
		return
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(encoded))
	r.ContentLength = int64(len(encoded))
}

func normalizeWorkspaceQuery(values url.Values, u *url.URL) {
	if normalizeWorkspaceValues(values) {
		u.RawQuery = values.Encode()
	}
}

func normalizeWorkspaceValues(values url.Values) bool {
	changed := false
	if values.Get("workspace_id") == "" && values.Get("tenant_id") != "" {
		values.Set("workspace_id", values.Get("tenant_id"))
		changed = true
	}
	if values.Get("tenant_id") == "" && values.Get("workspace_id") != "" {
		values.Set("tenant_id", values.Get("workspace_id"))
		changed = true
	}
	return changed
}

func mirrorWorkspaceTenantFields(v any) bool {
	changed := false
	switch value := v.(type) {
	case map[string]any:
		if workspaceID, ok := value["workspace_id"]; ok {
			if _, exists := value["tenant_id"]; !exists {
				value["tenant_id"] = workspaceID
				changed = true
			}
		}
		if tenantID, ok := value["tenant_id"]; ok {
			if _, exists := value["workspace_id"]; !exists {
				value["workspace_id"] = tenantID
				changed = true
			}
		}
		for _, child := range value {
			if mirrorWorkspaceTenantFields(child) {
				changed = true
			}
		}
	case []any:
		for _, child := range value {
			if mirrorWorkspaceTenantFields(child) {
				changed = true
			}
		}
	}
	return changed
}

func hasWorkspaceContractField(v any, field string) bool {
	switch value := v.(type) {
	case map[string]any:
		if _, ok := value[field]; ok {
			return true
		}
		for _, child := range value {
			if hasWorkspaceContractField(child, field) {
				return true
			}
		}
	case []any:
		for _, child := range value {
			if hasWorkspaceContractField(child, field) {
				return true
			}
		}
	}
	return false
}

func looksLikeJSON(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
}

func shouldSkipWorkspaceContract(c *gin.Context) bool {
	path := c.Request.URL.Path
	return path == "/authsec/metrics" ||
		strings.HasPrefix(path, "/swagger/") ||
		strings.HasPrefix(path, "/debug/pprof/")
}
