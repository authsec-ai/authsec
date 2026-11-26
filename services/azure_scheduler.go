package services

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
)

/* azure_scheduler.go keeps every connected Azure tenant current without anyone
   pressing Verify.

   Each tick it asks the database which tenant connectors' last pass finished
   longer ago than the interval (or never finished), and re-verifies each one:
   Graph consent is re-proven, the connector's status updated, and discovery of
   the tenant and its readable subscriptions started -- exactly what the Verify
   button does, recorded with trigger "schedule".

   Safe on every replica. Two replicas picking the same tenant in the same tick
   both call Verify, but each pass is a cloud_scan_run and
   uq_cloud_scan_run_live admits one live pass per connector: the second
   replica's pass is refused and it moves on. */

const (
	// AzureDiscoveryIntervalEnv sets how stale a tenant may get before it is
	// rediscovered, as a Go duration ("12h", "30m"). "0" or "off" disables
	// the schedule.
	AzureDiscoveryIntervalEnv = "AZURE_DISCOVERY_INTERVAL"

	azureDefaultDiscoveryInterval = 12 * time.Hour
	// azureSchedulerTick is how often due tenants are looked for, and
	// azureSchedulerStartDelay how long after boot the first look waits, so a
	// restart does not open with a burst of Microsoft calls.
	azureSchedulerTick       = 5 * time.Minute
	azureSchedulerStartDelay = time.Minute
	// azureRunningStaleAfter is when a pass still reported running is taken to
	// have died with its process: the discovery budget plus a lease.
	azureRunningStaleAfter = azureDiscoveryBudget + azureRunLease
)

// AzureDiscoveryIntervalFromEnv reads the schedule interval; 0 means off.
func AzureDiscoveryIntervalFromEnv() time.Duration {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(AzureDiscoveryIntervalEnv)))
	switch v {
	case "":
		return azureDefaultDiscoveryInterval
	case "0", "off", "false":
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		log.Printf("[azure] %s=%q is not a duration; using %s", AzureDiscoveryIntervalEnv, v, azureDefaultDiscoveryInterval)
		return azureDefaultDiscoveryInterval
	}
	return d
}

// RunScheduler rediscovers stale tenants until ctx ends. Returns at once when
// interval is 0 or Entra onboarding is not configured.
func (s *AzureOnboardingService) RunScheduler(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		log.Printf("[azure] scheduled discovery is off (%s)", AzureDiscoveryIntervalEnv)
		return
	}
	if !s.cfg.Configured() && s.vault == nil {
		log.Printf("[azure] scheduled discovery not started: neither Entra onboarding nor Vault is configured")
		return
	}
	log.Printf("[azure] scheduled discovery every %s", interval)
	timer := time.NewTimer(azureSchedulerStartDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		s.rediscoverDue(ctx, interval)
		timer.Reset(azureSchedulerTick)
	}
}

// rediscoverDue verifies, and so rediscovers, every tenant whose last pass is
// older than interval.
func (s *AzureOnboardingService) rediscoverDue(ctx context.Context, interval time.Duration) {
	now := time.Now()
	due, err := s.inventory.DueTenants(now.Add(-interval), now.Add(-azureRunningStaleAfter))
	if err != nil {
		log.Printf("[azure] scheduled discovery: could not list due tenants: %v", err)
		return
	}
	for _, c := range due {
		if ctx.Err() != nil {
			return
		}
		res, err := s.verify(ctx, c.WorkspaceID, c.ID, models.AzureTriggerSchedule)
		switch {
		case err != nil:
			log.Printf("[azure] scheduled discovery of tenant %s failed to start: %v", c.ScopeID, err)
		case res.Connector != nil && res.Connector.Status != models.CloudConnectorActive:
			log.Printf("[azure] scheduled discovery: tenant %s did not verify: %s", c.ScopeID, res.Connector.LastError)
		default:
			log.Printf("[azure] scheduled discovery of tenant %s: %s", c.ScopeID, res.Discovery)
		}
	}
}
