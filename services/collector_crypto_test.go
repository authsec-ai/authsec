package services

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestLoadResponseKey_RequiresEnvWhenIngestOn(t *testing.T) {
	t.Setenv(EnvV2Ingest, "1")
	t.Setenv(EnvCollectorResponseKey, "")
	var buf bytes.Buffer
	prev := responseKeyLogf
	responseKeyLogf = func(format string, args ...any) {
		fmt.Fprintf(&buf, format, args...)
	}
	t.Cleanup(func() { responseKeyLogf = prev })

	_, err := loadResponseKey()
	if err == nil {
		t.Fatal("expected an error when IGA_V2_INGEST is on and IGA_COLLECTOR_RESPONSE_KEY is unset")
	}
	logged := buf.String()
	if !strings.Contains(logged, "ERROR") || !strings.Contains(logged, EnvCollectorResponseKey) {
		t.Fatalf("log %q", logged)
	}
}

func TestLoadResponseKey_StableWhenEnvSet(t *testing.T) {
	t.Setenv(EnvV2Ingest, "1")
	t.Setenv(EnvCollectorResponseKey, "same-collector-response-key")
	a, err := loadResponseKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := loadResponseKey()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("response key changed between calls")
	}
	if len(a) != 32 {
		t.Fatalf("key length %d", len(a))
	}
}
