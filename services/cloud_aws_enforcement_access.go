package services

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// AWSEnforcementAccess gives the deploy executor (IGAGovAWSExecutor, T3.10)
// its two AWS identities for a control's connector (§3.5, §4.4):
//
//   - the DISCOVERY role for every read (precondition, the check before each
//     op, recognition, version-selector resolution, readback): the
//     connector's existing session (AWSOnboardingService.ConfigForConnector).
//     A connector that is not active is §3.5's discovery_unavailable.
//   - the ENFORCEMENT role for the writes of one deployment run:
//     EnforcementBindingService.AssumeForDeployment (verified binding,
//     ExternalId from Vault, authsec-enforce-<deployment 16hex>, 900 s, SDK
//     retries off, never cached).
//
// It lives outside the iga_* files because it reads cloud_connector and the
// binding (the IGA isolation rule, scripts/ci-iga-isolation-check.sh).
type AWSEnforcementAccess struct {
	connectors repositories.CloudConnectorRepository
	onboarding *AWSOnboardingService
	binding    *EnforcementBindingService
	discovery  func(ctx context.Context, c *models.CloudConnector) (awsenforce.DiscoveryIAM, error)
	// trail builds the connector's CloudTrail client through the DISCOVERY
	// role, in the region CloudTrail records IAM events in (review P1-7).
	trail func(ctx context.Context, c *models.CloudConnector) (awsenforce.TrailAPI, error)
}

// EnfCodeDiscoveryUnavailable is §3.5's "deployments block with
// discovery_unavailable".
const EnfCodeDiscoveryUnavailable = "discovery_unavailable"

// NewAWSEnforcementAccess builds the production access.
func NewAWSEnforcementAccess(connectors repositories.CloudConnectorRepository, onboarding *AWSOnboardingService, binding *EnforcementBindingService) *AWSEnforcementAccess {
	a := &AWSEnforcementAccess{connectors: connectors, onboarding: onboarding, binding: binding}
	a.discovery = func(ctx context.Context, c *models.CloudConnector) (awsenforce.DiscoveryIAM, error) {
		cfg, _, err := onboarding.ConfigForConnector(ctx, c.WorkspaceID, c.ID, "")
		if err != nil {
			return nil, err
		}
		return awsenforce.NewLiveDiscoveryIAM(iam.NewFromConfig(cfg)), nil
	}
	a.trail = func(ctx context.Context, c *models.CloudConnector) (awsenforce.TrailAPI, error) {
		// DECISION (P1-7): IAM is global; CloudTrail records its events in
		// the commercial partition's home region. GovCloud and China
		// connectors are not onboarded in R1a.
		cfg, _, err := onboarding.ConfigForConnector(ctx, c.WorkspaceID, c.ID, awsenforce.TrailRegion("aws"))
		if err != nil {
			return nil, err
		}
		return awsenforce.NewLiveTrail(cfg), nil
	}
	return a
}

// WithTrail replaces how the CloudTrail client is built (tests: the fake
// account's trail). The connector checks still apply.
func (a *AWSEnforcementAccess) WithTrail(f func(ctx context.Context, c *models.CloudConnector) (awsenforce.TrailAPI, error)) *AWSEnforcementAccess {
	a.trail = f
	return a
}

// EnforcementSessionEvents implements GovEnforcementTrail: §8.1 step 2's
// CloudTrail lookup of one enforcement session's events for one operation,
// through the connector's discovery role (cloudtrail:LookupEvents). Any
// failure -- the connector not active, the session not obtainable, the
// lookup failing or incomplete -- is an error: the trail is unreadable, which
// is never evidence that a request was not applied.
func (a *AWSEnforcementAccess) EnforcementSessionEvents(ctx context.Context, ws, connectorID uuid.UUID, q GovTrailQuery) ([]GovTrailEvent, error) {
	c, err := a.connectors.Get(ws, connectorID)
	if err != nil {
		return nil, err
	}
	if c.Provider != models.CloudProviderAWS || c.Status != models.CloudConnectorActive {
		return nil, enfErr(http.StatusConflict, EnfCodeDiscoveryUnavailable, "The account's discovery connector is not active.",
			map[string]any{"connector_status": c.Status})
	}
	if a.trail == nil {
		return nil, errors.New("CloudTrail access is not configured")
	}
	api, err := a.trail(ctx, c)
	if err != nil {
		return nil, fmt.Errorf("CloudTrail through the discovery role: %w", err)
	}
	return awsenforce.LookupSessionEvents(ctx, api, q)
}

// WithDiscovery replaces how the discovery reader is built (tests: a fake
// account's discovery view). The connector checks still apply.
func (a *AWSEnforcementAccess) WithDiscovery(f func(ctx context.Context, c *models.CloudConnector) (awsenforce.DiscoveryIAM, error)) *AWSEnforcementAccess {
	a.discovery = f
	return a
}

// DiscoveryIAM returns the discovery-role reader of the connector, or a
// discovery_unavailable EnforcementError when the connector is missing, not
// AWS, or not active.
func (a *AWSEnforcementAccess) DiscoveryIAM(ctx context.Context, ws, connectorID uuid.UUID) (awsenforce.DiscoveryIAM, error) {
	c, err := a.connectors.Get(ws, connectorID)
	if errors.Is(err, repositories.ErrCloudConnectorNotFound) || (err == nil && (c.Provider != models.CloudProviderAWS || c.Status != models.CloudConnectorActive)) {
		state := "missing"
		if c != nil {
			state = c.Status
		}
		return nil, enfErr(http.StatusConflict, EnfCodeDiscoveryUnavailable, "The account's discovery connector is not active.",
			map[string]any{"connector_status": state})
	}
	if err != nil {
		return nil, err
	}
	r, err := a.discovery(ctx, c)
	if err != nil {
		return nil, enfErr(http.StatusConflict, EnfCodeDiscoveryUnavailable, "The account's discovery role could not be used.", nil)
	}
	return r, nil
}

// EnforcementIAM assumes the enforcement role for one deployment run.
func (a *AWSEnforcementAccess) EnforcementIAM(ctx context.Context, ws, connectorID, deploymentID uuid.UUID) (awsenforce.IAM, error) {
	return a.binding.AssumeForDeployment(ctx, ws, connectorID, deploymentID)
}
