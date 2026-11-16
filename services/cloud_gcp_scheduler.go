package services

import (
	"context"
	"errors"
	"log"
	"os"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/gcp"
	"github.com/authsec-ai/authsec/internal/tokens"
	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"gorm.io/gorm"
)

/* cloud_gcp_scheduler.go keeps every connected GCP scope current without anyone
   pressing Scan.

   Each tick it asks the database which active GCP connectors' last scan finished
   longer ago than the interval (or never finished) and scans each one, recorded
   with trigger "scheduled" on the coverage report.

   MODELLED ON azure_scheduler.go, not on the AWS scheduler. The AWS one stores a
   per-connector schedule an administrator edits (cloud_scan_schedule) and queues
   cloud_scan_run rows for a worker; GCP has neither an admin schedule API nor a
   run worker, and GCP-1 specifies the env-interval model. cloud_scan_schedule is
   generic in schema -- only its ClaimDue is AWS-only -- so per-connector
   schedules for GCP are a later, additive step.

   SAFE ON EVERY REPLICA. Two replicas picking the same connector in the same tick
   both call Scan. The in-flight guard stops the common case, and
   AllocateGeneration is one atomic statement, so the worst a slipped guard costs
   is duplicated work and one refused commit -- never interleaved writes at one
   generation. See GCPScanner.guardInFlight. */

const (
	// GCPDiscoveryIntervalEnv sets how stale a connector may get before it is
	// rescanned, as a Go duration ("12h", "30m"). "0" or "off" disables the
	// schedule.
	GCPDiscoveryIntervalEnv = "GCP_DISCOVERY_INTERVAL"

	gcpDefaultDiscoveryInterval = 12 * time.Hour
	// gcpSchedulerTick is how often due connectors are looked for, and
	// gcpSchedulerStartDelay how long after boot the first look waits, so a
	// restart does not open with a burst of Google calls.
	gcpSchedulerTick       = 5 * time.Minute
	gcpSchedulerStartDelay = time.Minute
	// gcpRunningStaleAfter is when a scan still reported running is taken to
	// have died with its process: the scan budget plus a margin.
	gcpRunningStaleAfter = gcpScanTimeout + 5*time.Minute
)

// GCPDiscoveryIntervalFromEnv reads the schedule interval; 0 means off.
func GCPDiscoveryIntervalFromEnv() time.Duration {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(GCPDiscoveryIntervalEnv)))
	switch v {
	case "":
		return gcpDefaultDiscoveryInterval
	case "0", "off", "false":
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		log.Printf("[gcp-sched] %s=%q is not a duration; using %s", GCPDiscoveryIntervalEnv, v, gcpDefaultDiscoveryInterval)
		return gcpDefaultDiscoveryInterval
	}
	return d
}

// NewGCPScannerFromEnv builds the scanner with the deployment's own wiring:
// Vault if configured (a WIF connector needs none) and the native token issuer
// that signs the federation assertion. Shared by the scan endpoint and the
// scheduler so the two can never authenticate differently.
func NewGCPScannerFromEnv(db *gorm.DB) *GCPScanner {
	var vc vault.VaultClient
	if addr, token := os.Getenv("VAULT_ADDR"), os.Getenv("VAULT_TOKEN"); addr != "" && token != "" {
		if c, err := vault.NewClient(addr, token); err == nil {
			vc = c
		}
	}
	appIssuerURL := ""
	if config.AppConfig != nil {
		appIssuerURL = config.AppConfig.OAuthBaseURL()
	}
	issuerURL := gcp.ResolveWIFIssuerURL(appIssuerURL)
	issuer := tokens.NewNativeIssuer(db, tokens.NativeKeys(), issuerURL)
	return NewGCPScanner(db, NewGCPAuthService(vc, issuer))
}

// GCPScanScheduler rescans stale GCP connectors.
type GCPScanScheduler struct {
	scans   repositories.CloudGCPScanRepository
	scanner *GCPScanner
	now     func() time.Time
}

// NewGCPScanScheduler constructs the scheduler.
func NewGCPScanScheduler(db *gorm.DB, scanner *GCPScanner) *GCPScanScheduler {
	return &GCPScanScheduler{
		scans:   repositories.NewCloudGCPScanRepository(db),
		scanner: scanner,
		now:     time.Now,
	}
}

// WithClock replaces time.Now, so a test can move through intervals.
func (s *GCPScanScheduler) WithClock(f func() time.Time) *GCPScanScheduler {
	if f != nil {
		s.now = f
	}
	return s
}

// RunScheduler rescans stale connectors until ctx ends. Returns at once when
// interval is 0.
func (s *GCPScanScheduler) RunScheduler(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		log.Printf("[gcp-sched] scheduled discovery is off (%s)", GCPDiscoveryIntervalEnv)
		return
	}
	log.Printf("[gcp-sched] scheduled discovery every %s", interval)
	timer := time.NewTimer(gcpSchedulerStartDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		s.RunOnce(ctx, interval)
		timer.Reset(gcpSchedulerTick)
	}
}

// RunOnce scans every connector whose last scan is older than interval, one
// after another, and returns how many scans it started. Separate from
// RunScheduler so a test drives exactly one pass.
//
// Sequential on purpose: each scan already fans out across projects under its
// own governor, and several customers' scans at once is how a restart turns into
// a quota incident.
func (s *GCPScanScheduler) RunOnce(ctx context.Context, interval time.Duration) int {
	now := s.now()
	due, err := s.scans.DueConnectors(now.Add(-interval), now.Add(-gcpRunningStaleAfter))
	if err != nil {
		log.Printf("[gcp-sched] could not list due connectors: %v", err)
		return 0
	}
	started := 0
	for i := range due {
		if ctx.Err() != nil {
			return started
		}
		c := &due[i]
		// Not ready is skipped here rather than handed to Scan: the scanner would
		// refuse it before allocating a generation, which leaves the connector due
		// again on the very next tick. Re-verify clears the verdict.
		if c.GCPAttrs().DiscoveryReadiness == models.GCPReadinessBlocked {
			continue
		}
		_, err := s.scanner.ScanWithTrigger(ctx, c.WorkspaceID, c.ID, models.CloudScanTriggerScheduled)
		switch {
		case err == nil:
			started++
		case errors.Is(err, ErrScanAlreadyRunning):
			// Busy: another replica or a manual scan owns it. Never a second scan.
		case errors.Is(err, ErrScanNotReady), errors.Is(err, ErrScanNotPermitted):
			// Revoked or not ready between the query and the scan.
		default:
			started++ // a generation was allocated and a failed report written
			log.Printf("[gcp-sched] scheduled scan of %s/%s failed: %v", c.ScopeKind, c.ScopeID, err)
		}
	}
	return started
}
