package middlewares

import "testing"

// The OTLP receiver shares the per-IP ingest budget with the EventBridge
// ingest (SPEC-agent-runtime-activity.md §4.3); its per-token limit applies
// after the token check.
func TestOTLPIngestUsesIngestRateLimit(t *testing.T) {
	if got := selectRateLimitConfig("/authsec/ingest/otlp/v1/traces"); got.Endpoint != IngestRateLimit.Endpoint {
		t.Errorf("/authsec/ingest/otlp/v1/traces: %q, want ingest", got.Endpoint)
	}
	if got := selectRateLimitConfig("/authsec/ingest/otlp/v1/metrics"); got.Endpoint != GeneralRateLimit.Endpoint {
		t.Errorf("/authsec/ingest/otlp/v1/metrics: %q, want general", got.Endpoint)
	}
}
