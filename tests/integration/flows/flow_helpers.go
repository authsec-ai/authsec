//go:build integration

package flows

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
)

// RespBody is a convenience wrapper around an HTTP response recorder's result.
type RespBody struct {
	Code int
	Body map[string]interface{}
}

// parseResp reads the status code and JSON body from a ResponseRecorder into a RespBody.
func parseResp(w *httptest.ResponseRecorder) RespBody {
	var body map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&body)
	return RespBody{
		Code: w.Code,
		Body: body,
	}
}

// formBody builds a url.Values from alternating key/value string pairs.
func formBody(pairs ...string) url.Values {
	v := url.Values{}
	for i := 0; i+1 < len(pairs); i += 2 {
		v.Set(pairs[i], pairs[i+1])
	}
	return v
}

// jsonBody marshals v to JSON and back to obtain a clean map[string]interface{}.
func jsonBody(v interface{}) map[string]interface{} {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	return m
}

// basicAuthHeader returns a "Basic <base64>" Authorization header value for the given credentials.
func basicAuthHeader(user, pass string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	return "Basic " + encoded
}

// nonce returns a short deterministic string derived from t.Name(), safe for use in identifiers.
func nonce(t *testing.T) string {
	return testsupport.TestNonce(t)
}

// waitForScanIdle waits for the background DiscoverAndSync goroutine (triggered by Create)
// to complete. We wait for last_scan_status to become non-null because that field is only
// set when the goroutine finishes — checking scan_in_progress=false alone races with the
// goroutine startup (the poll may return true before the goroutine has acquired the lock).
func waitForScanIdle(t *testing.T, rsID string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		var status *string
		if err := config.DB.Raw("SELECT last_scan_status FROM resource_servers WHERE id = ?", rsID).Scan(&status).Error; err != nil {
			t.Logf("waitForScanIdle: query error: %v", err)
		}
		if status != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("waitForScanIdle: background scan never completed after 15s for RS %s", rsID)
}
