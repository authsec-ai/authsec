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
	EnvV2Ingest                = "IGA_V2_INGEST"
	EnvLegacyIngressDisabled   = "IGA_LEGACY_INGRESS_DISABLED"
	EnvNextSyncSeconds         = "IGA_V2_NEXT_SYNC_SECONDS"
	EnvCollectorResponseKey    = "IGA_COLLECTOR_RESPONSE_KEY"
	EnvLegacyIngressRatePerMin = "IGA_LEGACY_INGRESS_RATE_PER_MIN"
	EnvLegacyIngressMaxBody    = "IGA_LEGACY_INGRESS_MAX_BODY"
	EnvTrustedProxies          = "IGA_TRUSTED_PROXIES"
)

// DefaultLegacyIngressMaxBody is the legacy discovery body cap when
// IGA_LEGACY_INGRESS_MAX_BODY is unset. The historical ingress had no cap.
// 32 MiB still accepts a large cluster resync while rejecting an unbounded body.
const DefaultLegacyIngressMaxBody int64 = 32 << 20

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

// LegacyIngressRatePerMin is the per-workspace cap for the unauthenticated
// discovery ingress. Unset, empty, zero, or any non-integer means unlimited:
// the behaviour of that ingress before the collector registry. A positive
// value limits each workspace independently so many agents behind one egress
// address do not share a bucket. The workspace id in that key is
// caller-asserted: anyone who knows it can drain the bucket. The limit is
// never applied as zero to the sliding window; zero would deny every request.
func LegacyIngressRatePerMin() int {
	v := strings.TrimSpace(os.Getenv(EnvLegacyIngressRatePerMin))
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 0
	}
	return n
}

// LegacyIngressMaxBody is the legacy discovery body cap in bytes.
// Unset, empty, or a non-positive integer uses DefaultLegacyIngressMaxBody.
func LegacyIngressMaxBody() int64 {
	v := strings.TrimSpace(os.Getenv(EnvLegacyIngressMaxBody))
	if v == "" {
		return DefaultLegacyIngressMaxBody
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 1 {
		return DefaultLegacyIngressMaxBody
	}
	return n
}

// TrustedProxyList is IGA_TRUSTED_PROXIES: comma-separated IPs or CIDRs.
// An empty result means leave gin's trusted-proxy default alone, so
// ClientIP() is unchanged for tenant rate limits, audit, and request logs.
// A rollout behind a load balancer should set this to that proxy's CIDRs.
func TrustedProxyList() []string {
	raw := strings.TrimSpace(os.Getenv(EnvTrustedProxies))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

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
