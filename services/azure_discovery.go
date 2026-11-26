package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
)

/* azure_discovery.go is the inventory pass of one Azure subscription: every
   resource Azure Resource Graph returns for it, read with AuthSec's OWN
   app-only token under the Reader assignment, written to cloud_resource.

   This is the one place an Azure resource row is created, and it differs on
   purpose from the AWS rule that a cloud_resource row exists only because a
   permission statement named it. Under Reader the subscription itself is the
   grant: everything in it is in scope of that one assignment, so the
   inventory IS the set of resources AuthSec's access reaches.

   Reconciliation follows the shared rule: rows not seen in this generation are
   deleted only when the pass read the whole subscription. A denied, throttled
   or capped pass records partial coverage and deletes nothing. */

const (
	azureInventoryPageSize = 1000
	// azureInventoryMaxPages caps one pass at 50,000 resources per
	// subscription; beyond it the pass is partial and says where it stopped.
	azureInventoryMaxPages = 50
	azureInventoryQuery    = "Resources | project id, name, type, location, resourceGroup, subscriptionId, tags | order by id asc"
	azureInventoryAPI      = "Microsoft.ResourceGraph/resources"
)

// azureResourceClass is the PRD's Azure resource table: what class a resource
// type belongs to, and the sensitivity it starts at. A starting rule, not a
// risk engine, and labelled heuristic so a customer classification wins.
type azureResourceClass struct {
	class string
	// base is the default; prod is what a production tag raises it to.
	base, prod string
}

var azureResourceClasses = map[string]azureResourceClass{
	// Secrets, keys and identities: high regardless of environment.
	"microsoft.keyvault/vaults":                        {"secrets", models.SensitivityHigh, models.SensitivityHigh},
	"microsoft.keyvault/managedhsms":                   {"keys", models.SensitivityHigh, models.SensitivityHigh},
	"microsoft.managedidentity/userassignedidentities": {"identity", models.SensitivityHigh, models.SensitivityHigh},
	// Databases: high in production, medium elsewhere.
	"microsoft.sql/servers":                        {"database", models.SensitivityMedium, models.SensitivityHigh},
	"microsoft.sql/servers/databases":              {"database", models.SensitivityMedium, models.SensitivityHigh},
	"microsoft.sql/managedinstances":               {"database", models.SensitivityMedium, models.SensitivityHigh},
	"microsoft.documentdb/databaseaccounts":        {"database", models.SensitivityMedium, models.SensitivityHigh},
	"microsoft.dbforpostgresql/flexibleservers":    {"database", models.SensitivityMedium, models.SensitivityHigh},
	"microsoft.dbforpostgresql/servers":            {"database", models.SensitivityMedium, models.SensitivityHigh},
	"microsoft.dbformysql/flexibleservers":         {"database", models.SensitivityMedium, models.SensitivityHigh},
	"microsoft.dbformysql/servers":                 {"database", models.SensitivityMedium, models.SensitivityHigh},
	"microsoft.cache/redis":                        {"database", models.SensitivityMedium, models.SensitivityHigh},
	"microsoft.storage/storageaccounts":            {"storage", models.SensitivityMedium, models.SensitivityHigh},
	"microsoft.servicebus/namespaces":              {"messaging", models.SensitivityMedium, models.SensitivityMedium},
	"microsoft.eventhub/namespaces":                {"messaging", models.SensitivityMedium, models.SensitivityMedium},
	"microsoft.eventgrid/topics":                   {"messaging", models.SensitivityMedium, models.SensitivityMedium},
	"microsoft.compute/virtualmachines":            {"compute", models.SensitivityMedium, models.SensitivityMedium},
	"microsoft.compute/virtualmachinescalesets":    {"compute", models.SensitivityMedium, models.SensitivityMedium},
	"microsoft.web/sites":                          {"compute", models.SensitivityMedium, models.SensitivityMedium},
	"microsoft.app/containerapps":                  {"compute", models.SensitivityMedium, models.SensitivityMedium},
	"microsoft.app/jobs":                           {"compute", models.SensitivityMedium, models.SensitivityMedium},
	"microsoft.containerservice/managedclusters":   {"compute", models.SensitivityMedium, models.SensitivityMedium},
	"microsoft.containerinstance/containergroups":  {"compute", models.SensitivityMedium, models.SensitivityMedium},
	"microsoft.logic/workflows":                    {"compute", models.SensitivityMedium, models.SensitivityMedium},
	"microsoft.cognitiveservices/accounts":         {"ai", models.SensitivityMedium, models.SensitivityMedium},
	"microsoft.machinelearningservices/workspaces": {"ai", models.SensitivityMedium, models.SensitivityMedium},
	"microsoft.search/searchservices":              {"ai", models.SensitivityMedium, models.SensitivityMedium},
	"microsoft.containerregistry/registries":       {"registry", models.SensitivityMedium, models.SensitivityMedium},
}

// azureProdTag reports whether a resource's tags mark it as production.
func azureProdTag(tags map[string]string) bool {
	for k, v := range tags {
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "env", "environment", "stage", "tier", "environment-type":
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "prod", "production", "prd", "live":
				return true
			}
		}
	}
	return false
}

// azureResourceSensitivity rates one resource and says why. A resource with
// no environment tag of its own takes its resource group's or subscription's
// (containerStage): a database in a production resource group is production.
func azureResourceSensitivity(kind string, tags map[string]string, containerStage string) (string, string) {
	c, ok := azureResourceClasses[kind]
	if !ok {
		return models.SensitivityLow, ""
	}
	if c.prod != c.base {
		switch {
		case azureProdTag(tags):
			return c.prod, fmt.Sprintf("AuthSec rule: %s (%q) tagged production", c.class, kind)
		case !azureNonProdTag(tags) && containerStage == models.AzureStageProduction:
			return c.prod, fmt.Sprintf("AuthSec rule: %s (%q) in a production resource group or subscription", c.class, kind)
		}
	}
	return c.base, fmt.Sprintf("AuthSec rule: %s (%q)", c.class, kind)
}

// runSubscriptionScan is one pass over a subscription with AuthSec's own
// app-only ARM token: every resource (Azure Resource Graph), every role
// assignment that applies to the subscription (Azure RBAC), Key Vault access
// policies, the resources that run as a managed identity, Microsoft Foundry,
// and the federated credentials of user-assigned identities. All surfaces
// share one generation.
// Never returns an error: every failure is written into the connector's
// coverage, which is where a reader looks for "could not read" versus "found
// nothing".
//
// foundryToken is AuthSec's Foundry data-plane token for the tenant, or "":
// Foundry projects' agents are read with it.
func (s *AzureOnboardingService) runSubscriptionScan(ctx context.Context, workspaceID, connectorID uuid.UUID, subscriptionID, armToken, foundryToken, trigger string) *azurePassResult {
	pass := s.startPassOrSkip(ctx, workspaceID, connectorID, trigger, "subscription scan")
	if pass == nil {
		return nil
	}
	generation := pass.run.Generation
	started := time.Now()
	surfaceNames := []string{
		models.SurfaceAzureContainers,
		models.SurfaceAzureResources, models.SurfaceAzureRoleAssignments, models.SurfaceAzureKeyVaultAccessPolicies,
		models.SurfaceAzureWorkloads, models.SurfaceAzureFoundry, models.SurfaceAzureFoundryAgents, models.SurfaceAzureIdentityFederation,
		models.SurfaceAzureActivityLog, models.SurfaceAzurePublicIPs,
	}
	surfaces := map[string]models.SurfaceCoverage{}
	for _, n := range surfaceNames {
		surfaces[n] = models.SurfaceCoverage{State: models.CloudCoverageUnknown}
	}
	s.writeAzureCoverage(workspaceID, connectorID, generation, models.ScanCoverage{
		Generation: generation, Status: models.ScanStatusRunning, StartedAt: &started, Surfaces: surfaces,
	})

	counters := map[string]int{}
	// The environment first: resources and grants are rated by it.
	containers, sc := s.collectContainers(ctx, workspaceID, connectorID, generation, subscriptionID, armToken, counters)
	surfaces[models.SurfaceAzureContainers] = sc
	// Resources next: every later surface points at the rows it writes.
	surfaces[models.SurfaceAzureResources] = s.collectResources(ctx, workspaceID, connectorID, generation, subscriptionID, armToken, containers)
	counters["resources_seen"] = surfaces[models.SurfaceAzureResources].Count
	surfaces[models.SurfaceAzureRoleAssignments] = s.collectRoleAssignments(ctx, workspaceID, connectorID, generation, subscriptionID, armToken, counters, containers)
	surfaces[models.SurfaceAzureKeyVaultAccessPolicies] = s.collectKeyVaultAccessPolicies(ctx, workspaceID, connectorID, generation, subscriptionID, armToken, counters)
	surfaces[models.SurfaceAzureWorkloads] = s.collectWorkloads(ctx, workspaceID, connectorID, generation, subscriptionID, armToken, counters)
	surfaces[models.SurfaceAzureFoundry] = s.collectFoundry(ctx, workspaceID, connectorID, generation, subscriptionID, armToken, counters)
	// After the projects are recorded: their agents go on their rows.
	surfaces[models.SurfaceAzureFoundryAgents] = s.collectFoundryAgents(ctx, workspaceID, connectorID, foundryToken, counters)
	surfaces[models.SurfaceAzureIdentityFederation] = s.collectIdentityFederation(ctx, workspaceID, connectorID, generation, subscriptionID, armToken, counters)
	// Where a sign-in from one of these addresses ran (azure_signin_origin.go).
	surfaces[models.SurfaceAzurePublicIPs] = s.collectPublicIPs(ctx, workspaceID, connectorID, generation, subscriptionID, armToken, counters)
	// After role assignments: activity is attributed to the grants just read.
	surfaces[models.SurfaceAzureActivityLog] = s.collectActivityLog(ctx, workspaceID, connectorID, generation, subscriptionID, armToken, counters)

	reached := func(names ...string) bool {
		for _, n := range names {
			if surfaces[n].State != models.CloudCoverageReached {
				return false
			}
		}
		return true
	}
	counts, err := s.inventory.Reconcile(workspaceID, connectorID, generation, repositories.AzureReconcileParts{
		Resources: reached(models.SurfaceAzureResources),
		// Role assignments and access policies share cloud_permission.
		Permissions: reached(models.SurfaceAzureRoleAssignments, models.SurfaceAzureKeyVaultAccessPolicies),
		Workloads:   reached(models.SurfaceAzureWorkloads),
		Foundry:     reached(models.SurfaceAzureFoundry),
		Edges:       reached(models.SurfaceAzureIdentityFederation),
	})
	if err != nil {
		log.Printf("[azure] scan: reconciliation failed for connector %s: %v", connectorID, err)
	} else {
		counters["resources_removed"] = int(counts.Resources)
		counters["grants_removed"] = int(counts.Permissions)
		counters["workloads_removed"] = int(counts.Workloads)
		counters["foundry_removed"] = int(counts.Foundry)
		counters["federated_credentials_removed"] = int(counts.Edges)
	}

	finished := time.Now()
	coverage := models.ScanCoverage{
		Generation: generation,
		StartedAt:  &started,
		FinishedAt: &finished,
		Surfaces:   surfaces,
		Counters:   counters,
	}
	coverage.Status, coverage.Error = scanStatusOf(coverage.Surfaces)
	// Evidence needs the surfaces' final states, and the run's lease.
	s.recordEvidence(pass, models.CloudScopeSubscription, coverage, counters)
	s.writeAzureCoverage(workspaceID, connectorID, generation, coverage)
	return s.finishPass(pass, coverage)
}

// scanStatusOf is complete when every surface was reached, failed when none
// read anything, partial otherwise. Unsupported (the tenant's licence does not
// include the data) and not_selected are not reads that fell short, matching
// ScanCoverage.Complete: they neither count against completeness nor for it.
func scanStatusOf(surfaces map[string]models.SurfaceCoverage) (string, string) {
	reached, read, attempted := 0, 0, 0
	firstErr := ""
	for _, sc := range surfaces {
		if sc.State == models.CloudCoverageUnsupported || sc.State == models.CloudCoverageNotSelected {
			continue
		}
		attempted++
		if sc.State == models.CloudCoverageReached {
			reached++
		}
		if sc.State == models.CloudCoverageReached || sc.Count > 0 {
			read++
		}
		if sc.Error != "" && firstErr == "" {
			firstErr = sc.Error
		}
	}
	switch {
	case reached == attempted:
		return models.ScanStatusComplete, ""
	case read == 0:
		return models.ScanStatusFailed, firstErr
	}
	return models.ScanStatusPartial, ""
}

// collectResources reads every resource in the subscription with Azure
// Resource Graph and records it.
func (s *AzureOnboardingService) collectResources(ctx context.Context, workspaceID, connectorID uuid.UUID, generation int, subscriptionID, armToken string, containers azureContainers) models.SurfaceCoverage {
	surface := models.SurfaceCoverage{State: models.CloudCoverageReached, API: azureInventoryAPI}
	written := 0
	skipToken := ""
	lastID := ""
	pages := 0
	for {
		page, err := s.queryResourcesWithGrace(ctx, armToken, subscriptionID, skipToken, pages == 0)
		if err != nil {
			logAzureError("resource graph query", err)
			surface = surfaceFailure(surface, err, written)
			break
		}
		rows := azureResourceRows(page.Data, subscriptionID, containers)
		n, err := s.inventory.UpsertResources(workspaceID, connectorID, generation, rows)
		if err != nil {
			log.Printf("[azure] scan: could not record resources for connector %s: %v", connectorID, err)
			surface.State = models.CloudCoveragePartial
			surface.Error = "AuthSec could not record the resources it read"
			break
		}
		written += n
		if len(rows) > 0 {
			lastID = rows[len(rows)-1].NativeID
		}
		pages++
		skipToken = page.SkipToken
		if skipToken == "" {
			break
		}
		if pages >= azureInventoryMaxPages {
			surface.State = models.CloudCoveragePartial
			surface.CappedAfter = lastID
			surface.Error = fmt.Sprintf("stopped after %d resources (the per-pass cap)", written)
			break
		}
		if ctx.Err() != nil {
			surface.State = models.CloudCoveragePartial
			surface.Error = fmt.Sprintf("stopped after %d resources: the time budget ran out", written)
			break
		}
	}
	surface.Count = written
	return surface
}

// surfaceFailure records why a surface was not fully read. The provider's
// code is kept; only the state is AuthSec's judgement.
func surfaceFailure(surface models.SurfaceCoverage, err error, read int) models.SurfaceCoverage {
	surface.State = azureCoverageStateFor(err, read)
	surface.Error = err.Error()
	var ae *azure.APIError
	if errors.As(err, &ae) {
		surface.ErrorCode = ae.Code
	}
	return surface
}

// azureInventoryDeniedAttempts bounds how long the first Resource Graph page
// waits out a 403: about a minute with retryBackoff's 3s/5s/8s/10s curve.
const azureInventoryDeniedAttempts = 8

// queryResourcesWithGrace runs one Resource Graph page. On the FIRST page a
// 403 is retried for a short while: Resource Graph keeps its own copy of role
// assignments and applies a new Reader later than the rest of ARM, so an
// inventory run seconds after Reader was granted is refused even though ARM
// itself already answers -- seen live: GET /subscriptions/{id} 200, then
// Resource Graph 403 AccessDenied the same second, and a complete pass a few
// minutes later. Callers only reach this after ARM proved the access, so a
// 403 here is lag far more often than a missing role; a real denial still
// ends as "denied" coverage once the attempts or the deadline run out.
func (s *AzureOnboardingService) queryResourcesWithGrace(ctx context.Context, armToken, subscriptionID, skipToken string, firstPage bool) (*azure.ResourceGraphPage, error) {
	for attempt := 1; ; attempt++ {
		page, err := s.api.QueryResources(ctx, armToken, []string{subscriptionID}, azureInventoryQuery, skipToken, azureInventoryPageSize)
		if err == nil || !firstPage || !errors.Is(err, azure.ErrARMForbidden) || attempt >= azureInventoryDeniedAttempts {
			return page, err
		}
		wait := retryBackoff(3*time.Second, attempt)
		if dl, ok := ctx.Deadline(); ok && time.Until(dl) < wait+5*time.Second {
			return page, err
		}
		log.Printf("[azure] inventory: resource graph not yet applying reader for subscription %s, retrying (attempt %d)", subscriptionID, attempt)
		if sleepCtx(ctx, wait) != nil {
			return page, err
		}
	}
}

func (s *AzureOnboardingService) writeAzureCoverage(workspaceID, connectorID uuid.UUID, generation int, cov models.ScanCoverage) {
	raw, err := json.Marshal(cov)
	if err != nil {
		return
	}
	if err := s.inventory.WriteCoverage(workspaceID, connectorID, generation, raw); err != nil {
		if errors.Is(err, repositories.ErrScanSuperseded) {
			log.Printf("[azure] inventory: connector %s generation %d was superseded by a newer pass", connectorID, generation)
			return
		}
		log.Printf("[azure] inventory: could not write coverage for connector %s: %v", connectorID, err)
	}
}

func azureCoverageStateFor(err error, written int) string {
	switch {
	case errors.Is(err, azure.ErrThrottled):
		return models.CloudCoverageThrottled
	case errors.Is(err, azure.ErrARMForbidden), azure.APIStatus(err) == 401, azure.APIStatus(err) == 403:
		return models.CloudCoverageDenied
	case errors.Is(err, azure.ErrPageLimit), written > 0:
		return models.CloudCoveragePartial
	}
	return models.CloudCoverageUnknown
}

// azureResourceRows converts one Resource Graph page into cloud_resource rows,
// deduplicated (one INSERT ... ON CONFLICT may not touch a row twice).
//
// ARM resource ids are case-insensitive and Azure returns them in mixed case,
// so the id is lowercased into native_id: the same resource must always map
// to the same row.
func azureResourceRows(data []azure.GraphResource, subscriptionID string, containers azureContainers) []models.CloudResource {
	seen := make(map[string]bool, len(data))
	rows := make([]models.CloudResource, 0, len(data))
	for _, d := range data {
		id := strings.ToLower(strings.TrimSpace(d.ID))
		kind := strings.ToLower(strings.TrimSpace(d.Type))
		if id == "" || kind == "" || seen[id] {
			continue
		}
		seen[id] = true
		account := strings.ToLower(d.SubscriptionID)
		if account == "" {
			account = subscriptionID
		}
		sensitivity, reason := azureResourceSensitivity(kind, d.Tags, containers.stageOfRG(d.ResourceGroup))
		rows = append(rows, models.CloudResource{
			Kind:              kind,
			NativeID:          id,
			Name:              d.Name,
			ResourceAccount:   account,
			Sensitivity:       sensitivity,
			SensitivitySource: models.SensitivityFromHeuristic,
			SensitivityReason: reason,
		})
	}
	return rows
}
