package services

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Env flags for TRD 2. All default off. Unset, empty, "0", "false" and "off"
// are off. Only 1, true, on and yes enable a flag.
const (
	EnvV2Ingest              = "IGA_V2_INGEST"
	EnvLegacyIngressDisabled = "IGA_LEGACY_INGRESS_DISABLED"
	EnvNextSyncSeconds       = "IGA_V2_NEXT_SYNC_SECONDS"
)

// FlagOn reports whether name is explicitly enabled.
func FlagOn(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "on", "yes":
		return true
	default:
		return false
	}
}

// V2IngestEnabled is the gate in front of /api/iga/v2 collector routes.
// When it is off those routes respond 404 and write nothing.
func V2IngestEnabled() bool { return FlagOn(EnvV2Ingest) }

// LegacyIngressGloballyDisabled is the process-wide kill switch. A workspace
// can also disable its own ingress without this flag.
func LegacyIngressGloballyDisabled() bool { return FlagOn(EnvLegacyIngressDisabled) }

// NextSyncSeconds is the agent-sync poll hint. Default 15.
func NextSyncSeconds() int {
	v := strings.TrimSpace(os.Getenv(EnvNextSyncSeconds))
	if v == "" {
		return 15
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 15
	}
	return n
}

// Clock is an injectable time source. Tests advance it; production leaves it nil.
type Clock func() time.Time

// Now returns the clock's instant, or the current UTC time.
func (c Clock) Now() time.Time {
	if c == nil {
		return time.Now().UTC()
	}
	return c().UTC()
}
