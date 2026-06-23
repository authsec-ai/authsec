//go:build integration

package flows

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// readBody reads and returns the full response body as a string.
func readBody(w *httptest.ResponseRecorder) string {
	return w.Body.String()
}

// parseBody parses the response body as JSON into map[string]interface{}.
func parseBody(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	body := w.Body.Bytes()
	if err := json.Unmarshal(body, &m); err != nil {
		t.Errorf("parseBody: failed to unmarshal JSON body %q: %v", string(body), err)
		return nil
	}
	return m
}

// assertStatus asserts that the HTTP response status code equals code.
func assertStatus(t *testing.T, w *httptest.ResponseRecorder, code int) {
	t.Helper()
	if w.Code != code {
		t.Errorf("assertStatus: expected status %d, got %d (body: %s)", code, w.Code, readBody(w))
	}
}

// assertJSON parses the response body as JSON and asserts that body[key] == expected.
func assertJSON(t *testing.T, w *httptest.ResponseRecorder, key, expected string) {
	t.Helper()
	m := parseBody(t, w)
	if m == nil {
		return
	}
	val, ok := m[key]
	if !ok {
		t.Errorf("assertJSON: key %q not found in body %s", key, readBody(w))
		return
	}
	got := fmt.Sprintf("%v", val)
	if got != expected {
		t.Errorf("assertJSON: body[%q]: expected %q, got %q", key, expected, got)
	}
}

// assertActiveFalse asserts that the JSON body contains active:false.
func assertActiveFalse(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	m := parseBody(t, w)
	if m == nil {
		return
	}
	val, ok := m["active"]
	if !ok {
		t.Errorf("assertActiveFalse: key \"active\" not found in body %s", readBody(w))
		return
	}
	active, ok := val.(bool)
	if !ok {
		t.Errorf("assertActiveFalse: \"active\" is not a bool, got %T (%v)", val, val)
		return
	}
	if active {
		t.Errorf("assertActiveFalse: expected active=false, got active=true (body: %s)", readBody(w))
	}
}

// assertActiveTrue asserts that the JSON body contains active:true.
func assertActiveTrue(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	m := parseBody(t, w)
	if m == nil {
		return
	}
	val, ok := m["active"]
	if !ok {
		t.Errorf("assertActiveTrue: key \"active\" not found in body %s", readBody(w))
		return
	}
	active, ok := val.(bool)
	if !ok {
		t.Errorf("assertActiveTrue: \"active\" is not a bool, got %T (%v)", val, val)
		return
	}
	if !active {
		t.Errorf("assertActiveTrue: expected active=true, got active=false (body: %s)", readBody(w))
	}
}

// assertAudience asserts that the JSON body has an "aud" field containing expectedAud.
// The aud field may be a string or a []interface{} (JSON array of strings).
func assertAudience(t *testing.T, w *httptest.ResponseRecorder, expectedAud string) {
	t.Helper()
	m := parseBody(t, w)
	if m == nil {
		return
	}
	raw, ok := m["aud"]
	if !ok {
		t.Errorf("assertAudience: key \"aud\" not found in body %s", readBody(w))
		return
	}
	switch v := raw.(type) {
	case string:
		if v != expectedAud {
			t.Errorf("assertAudience: expected aud to contain %q, got %q", expectedAud, v)
		}
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok && s == expectedAud {
				return
			}
		}
		t.Errorf("assertAudience: expected aud array to contain %q, got %v", expectedAud, v)
	default:
		t.Errorf("assertAudience: unexpected aud type %T (%v)", raw, raw)
	}
}

// assertScopeSubset asserts that the "scope" field in the JSON response is a
// subset of requestedScope (both are space-separated scope strings).
func assertScopeSubset(t *testing.T, w *httptest.ResponseRecorder, requestedScope string) {
	t.Helper()
	m := parseBody(t, w)
	if m == nil {
		return
	}
	raw, ok := m["scope"]
	if !ok {
		// An absent scope field is vacuously a subset.
		return
	}
	returnedScope, ok := raw.(string)
	if !ok {
		t.Errorf("assertScopeSubset: \"scope\" is not a string, got %T (%v)", raw, raw)
		return
	}
	requested := splitScopes(requestedScope)
	returned := splitScopes(returnedScope)
	for s := range returned {
		if !requested[s] {
			t.Errorf("assertScopeSubset: returned scope %q is not in requested scope %q", s, requestedScope)
		}
	}
}

// splitScopes converts a space-separated scope string into a set.
func splitScopes(scope string) map[string]bool {
	m := make(map[string]bool)
	for _, tok := range strings.Fields(scope) {
		m[tok] = true
	}
	return m
}

// assertScopeLost asserts active:false (the scope was revoked).
func assertScopeLost(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	assertActiveFalse(t, w)
}

// assertRegistrationGate asserts active:false (client is not registered / pending).
func assertRegistrationGate(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	assertActiveFalse(t, w)
}

// assertCrossWorkspaceDenied asserts that the response status is 401 or 404.
func assertCrossWorkspaceDenied(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusUnauthorized && w.Code != http.StatusNotFound {
		t.Errorf("assertCrossWorkspaceDenied: expected 401 or 404, got %d (body: %s)", w.Code, readBody(w))
	}
}

// assertReplayRejected asserts that the response status is 400 or 401 and
// that the JSON body contains an "error" field.
func assertReplayRejected(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusBadRequest && w.Code != http.StatusUnauthorized {
		t.Errorf("assertReplayRejected: expected 400 or 401, got %d (body: %s)", w.Code, readBody(w))
	}
	m := parseBody(t, w)
	if m == nil {
		return
	}
	if _, ok := m["error"]; !ok {
		t.Errorf("assertReplayRejected: expected \"error\" field in body %s", readBody(w))
	}
}

// assertExpiredRejected asserts that the response status is 401.
func assertExpiredRejected(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusUnauthorized {
		t.Errorf("assertExpiredRejected: expected 401, got %d (body: %s)", w.Code, readBody(w))
	}
}

// assertForgedRejected asserts that the response status is 401.
func assertForgedRejected(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusUnauthorized {
		t.Errorf("assertForgedRejected: expected 401, got %d (body: %s)", w.Code, readBody(w))
	}
}

// assertWrongKidRejected asserts that either active:false is in the body or
// the status is 401.
func assertWrongKidRejected(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code == http.StatusUnauthorized {
		return
	}
	m := parseBody(t, w)
	if m == nil {
		// body is not JSON; fall back to status check
		t.Errorf("assertWrongKidRejected: expected active=false or 401, got status %d with non-JSON body %s", w.Code, readBody(w))
		return
	}
	val, ok := m["active"]
	if !ok {
		t.Errorf("assertWrongKidRejected: expected active=false or 401, got status %d with body %s", w.Code, readBody(w))
		return
	}
	active, ok := val.(bool)
	if !ok || active {
		t.Errorf("assertWrongKidRejected: expected active=false or 401, got active=%v status %d", val, w.Code)
	}
}

// assertSingleWorkspaceGuard asserts that the response status is 409.
func assertSingleWorkspaceGuard(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusConflict {
		t.Errorf("assertSingleWorkspaceGuard: expected 409, got %d (body: %s)", w.Code, readBody(w))
	}
}

// assertScopedRowCount queries SELECT COUNT(*) FROM <table> WHERE <column>=$1
// using the raw *sql.DB and asserts the result equals expected.
func assertScopedRowCount(t *testing.T, db *sql.DB, table, column, value string, expected int) {
	t.Helper()
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s=$1", table, column)
	var count int
	if err := db.QueryRow(query, value).Scan(&count); err != nil {
		t.Errorf("assertScopedRowCount: query %q with value %q failed: %v", query, value, err)
		return
	}
	if count != expected {
		t.Errorf("assertScopedRowCount: %s WHERE %s=%q: expected %d row(s), got %d", table, column, value, expected, count)
	}
}

// Ensure io and net/http are referenced so imports are not flagged unused
// when callers only use the recorder-based helpers.
var _ io.Reader
var _ = http.StatusOK
