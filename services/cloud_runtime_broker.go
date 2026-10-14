package services

import (
	"context"
	"errors"
	"sync"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsbroker"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// R3 brokered sessions (DECISION R3-12): what the runtime broker needs from
// the AWS connector -- the account it is bound to, the ExternalId AuthSec
// stored for it (Vault) and a signing region. It lives outside the iga_*
// files because it reads cloud_connector and the secrets store (the IGA
// isolation rule, scripts/ci-iga-isolation-check.sh), like
// cloud_aws_enforcement_access.go.

// RuntimeBrokerInputs is one connector's half of an AssumeRole.
type RuntimeBrokerInputs struct {
	AccountID  string
	ExternalID string
	Region     string
}

// ErrBrokerConnectorUnavailable means the connector is missing, not AWS, or
// not active.
var ErrBrokerConnectorUnavailable = errors.New("the AWS connector is not active")

// BrokerAssumeInputs returns the connector's account, ExternalId and signing
// region, only while the connector is an active AWS connector of the
// workspace. Another workspace's connector is ErrBrokerConnectorUnavailable.
// The connector row is read in a transaction under row-level security for
// ws; the ExternalId is read from the secrets store after it.
func (s *AWSOnboardingService) BrokerAssumeInputs(ctx context.Context, ws, connectorID uuid.UUID) (*RuntimeBrokerInputs, error) {
	var row *models.CloudConnector
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		row, err = repositories.NewCloudConnectorRepository(tx).Get(ws, connectorID)
		return err
	}); err != nil {
		return nil, ErrBrokerConnectorUnavailable
	}
	c, req, err := s.assumeRequestForConnector(ws, row)
	if err != nil {
		if c == nil {
			return nil, ErrBrokerConnectorUnavailable
		}
		return nil, err
	}
	if c.WorkspaceID != ws || c.Provider != models.CloudProviderAWS || c.Status != models.CloudConnectorActive {
		return nil, ErrBrokerConnectorUnavailable
	}
	return &RuntimeBrokerInputs{AccountID: c.ScopeID, ExternalID: req.ExternalID, Region: req.Region}, nil
}

// RuntimeBrokerDeps are the process's broker seams: the connector inputs
// (Vault) and the STS broker. main installs them once Vault is known; tests
// install fakes. Unset, brokered sessions answer 503 broker_unavailable.
type RuntimeBrokerDeps struct {
	Inputs func(ctx context.Context, ws, connectorID uuid.UUID) (*RuntimeBrokerInputs, error)
	Broker awsbroker.Broker
}

var (
	runtimeBrokerMu   sync.RWMutex
	runtimeBrokerDeps *RuntimeBrokerDeps
)

// SetRuntimeBrokerDeps installs the broker seams (nil uninstalls).
func SetRuntimeBrokerDeps(d *RuntimeBrokerDeps) {
	runtimeBrokerMu.Lock()
	defer runtimeBrokerMu.Unlock()
	runtimeBrokerDeps = d
}

// CurrentRuntimeBrokerDeps returns the installed seams, or nil.
func CurrentRuntimeBrokerDeps() *RuntimeBrokerDeps {
	runtimeBrokerMu.RLock()
	defer runtimeBrokerMu.RUnlock()
	return runtimeBrokerDeps
}

// LiveRuntimeBrokerDeps are production's: the onboarding service over Vault
// and the live STS broker (AuthSec's ambient AWS identity). UNVERIFIED
// against AWS.
func LiveRuntimeBrokerDeps(onboarding *AWSOnboardingService) *RuntimeBrokerDeps {
	return &RuntimeBrokerDeps{
		Inputs: func(ctx context.Context, ws, connectorID uuid.UUID) (*RuntimeBrokerInputs, error) {
			return onboarding.BrokerAssumeInputs(ctx, ws, connectorID)
		},
		Broker: awsbroker.NewLive(),
	}
}
