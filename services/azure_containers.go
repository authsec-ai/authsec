package services

import (
	"context"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

/* azure_containers.go reads whether a subscription, and each resource group in
   it, is production -- from the customer's own tags -- because the PRD's Azure
   resource table rates scopes and data stores by environment: a subscription
   or resource group tagged production is high, and so is what a write role
   reaches inside one.

   Tags are the customer's words, read verbatim; AuthSec decides only which
   words mean production (azureProdTag) and which mean the opposite
   (azureNonProdTag). A container with no environment tag is "unknown", never
   assumed either way. A resource group's own tag wins over its subscription's,
   so a dev resource group inside a production subscription stays dev. */

const azureContainersQuery = `ResourceContainers
| where type =~ 'microsoft.resources/subscriptions' or type =~ 'microsoft.resources/subscriptions/resourcegroups'
| project id, type, name, tags`

// azureContainers is the environment of one subscription and its resource
// groups.
type azureContainers struct {
	subStage string
	subTags  map[string]string
	// rgStage maps a lowercased resource group name to its own stage.
	rgStage map[string]string
}

// stageOfRG is a resource group's stage: its own tag, else its subscription's.
func (c azureContainers) stageOfRG(rg string) string {
	if s := c.rgStage[strings.ToLower(rg)]; s != "" && s != models.AzureStageUnknown {
		return s
	}
	if c.subStage == "" {
		return models.AzureStageUnknown
	}
	return c.subStage
}

// prodScope reports whether a grant's scope is production: the subscription
// (or above it) when the subscription is, a resource group or a resource when
// its resource group is.
func (c azureContainers) prodScope(kind, scope, subScope string) bool {
	if kind == "account_wide" {
		return c.subStage == models.AzureStageProduction
	}
	rest := strings.TrimPrefix(scope, subScope+"/resourcegroups/")
	rg := strings.SplitN(rest, "/", 2)[0]
	return c.stageOfRG(rg) == models.AzureStageProduction
}

// azureNonProdTag reports whether tags say a container is NOT production.
func azureNonProdTag(tags map[string]string) bool {
	for k, v := range tags {
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "env", "environment", "stage", "tier", "environment-type":
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "dev", "development", "test", "testing", "qa", "staging", "stage",
				"sandbox", "nonprod", "non-prod", "uat", "demo", "poc":
				return true
			}
		}
	}
	return false
}

// azureStageOf turns a container's tags into production, non_production or
// unknown.
func azureStageOf(tags map[string]string) string {
	switch {
	case azureProdTag(tags):
		return models.AzureStageProduction
	case azureNonProdTag(tags):
		return models.AzureStageNonProduction
	}
	return models.AzureStageUnknown
}

// raiseForProduction moves a grant up one sensitivity level because what it
// reaches is production: reading production is a finding, writing to it is.
func raiseForProduction(s string) string {
	switch s {
	case models.SensitivityLow:
		return models.SensitivityMedium
	case models.SensitivityMedium:
		return models.SensitivityHigh
	}
	return s
}

// collectContainers reads the subscription's and its resource groups' tags,
// and records the subscription's on its connector. It is the pass's FIRST
// Resource Graph call, so it waits out Resource Graph applying a Reader
// assignment made seconds ago, as the inventory's first page does.
func (s *AzureOnboardingService) collectContainers(ctx context.Context, workspaceID, connectorID uuid.UUID, generation int, subscriptionID, armToken string, counters map[string]int) (azureContainers, models.SurfaceCoverage) {
	out := azureContainers{subStage: models.AzureStageUnknown, rgStage: map[string]string{}}
	surface := models.SurfaceCoverage{State: models.CloudCoverageReached, API: "Microsoft.ResourceGraph/resources (ResourceContainers)"}
	type row struct {
		ID   string            `json:"id"`
		Type string            `json:"type"`
		Name string            `json:"name"`
		Tags map[string]string `json:"tags"`
	}
	var rows []row
	var err error
	for attempt := 1; ; attempt++ {
		rows, err = azureQueryAll[row](ctx, s, armToken, subscriptionID, azureContainersQuery)
		if err == nil || !errors.Is(err, azure.ErrARMForbidden) || attempt >= azureInventoryDeniedAttempts {
			break
		}
		wait := retryBackoff(3*time.Second, attempt)
		if dl, ok := ctx.Deadline(); ok && time.Until(dl) < wait+5*time.Second {
			break
		}
		log.Printf("[azure] containers: resource graph not yet applying reader for subscription %s, retrying (attempt %d)", subscriptionID, attempt)
		if sleepCtx(ctx, wait) != nil {
			break
		}
	}
	if err != nil && !errors.Is(err, azure.ErrPageLimit) {
		logAzureError("resource containers", err)
		return out, surfaceFailure(surface, err, 0)
	}
	for _, r := range rows {
		stage := azureStageOf(r.Tags)
		if strings.EqualFold(r.Type, "microsoft.resources/subscriptions") {
			out.subStage, out.subTags = stage, r.Tags
			continue
		}
		out.rgStage[strings.ToLower(r.Name)] = stage
		if stage == models.AzureStageProduction {
			counters["production_resource_groups"]++
		}
	}
	if out.subTags == nil {
		out.subTags = map[string]string{}
	}
	if err := s.inventory.MergeAttrs(workspaceID, connectorID, generation, map[string]interface{}{
		"tags": out.subTags, "stage": out.subStage,
	}); err != nil {
		log.Printf("[azure] scan: could not record the subscription's environment for connector %s: %v", connectorID, err)
	}
	surface.Count = len(rows)
	return out, surface
}
