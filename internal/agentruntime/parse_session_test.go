package agentruntime

import (
	"testing"
	"time"
)

// The containment levels read the signing key, the session's SourceIdentity
// and its issue time (SecOps W2: key, source_identity, sessions_before).
func TestParseSessionContext(t *testing.T) {
	raw := `{"eventID":"e1","eventTime":"2026-11-24T10:00:00Z","eventSource":"s3.amazonaws.com","eventName":"ListBuckets",
	"eventType":"AwsApiCall","userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::111111111111:assumed-role/r/s",
	"principalId":"AROA1:s","accessKeyId":"ASIAEXAMPLE","sessionContext":{"sourceIdentity":"authsec-abc-a123",
	"attributes":{"creationDate":"2026-11-24T09:00:00Z","mfaAuthenticated":"false"},
	"sessionIssuer":{"type":"Role","arn":"arn:aws:iam::111111111111:role/r","principalId":"AROA1"}}}}`
	e, err := ParseCloudTrailRecord([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if e.AccessKeyID != "ASIAEXAMPLE" || e.SourceIdentity != "authsec-abc-a123" || e.SessionCreatedAt == nil ||
		!e.SessionCreatedAt.Equal(time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC)) {
		t.Fatalf("parsed %+v", e)
	}
}
