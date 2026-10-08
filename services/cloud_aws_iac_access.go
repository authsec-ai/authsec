package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// The legacy-table reads T3.17 needs, kept out of the iga_* files (the IGA
// isolation rule, scripts/ci-iga-isolation-check.sh): the GitHub discovery
// source an IaC source pushes through (discovery_sources, whose config names
// the iga_integrations installation), and the AWS connector's account and
// discovery template version (cloud_connector).

// ErrIaCSourceChannelNotFound: the discovery source does not exist in the
// workspace, or is not a GitHub repository source.
var ErrIaCSourceChannelNotFound = errors.New("github discovery source not found")

// IaCGitHubChannel is a GitHub discovery source as the channel an IaC source
// reads and writes its repository through.
type IaCGitHubChannel struct {
	SourceID          uuid.UUID
	IntegrationID     string
	InstallationID    string
	AppRegistrationID string
	ProviderHost      string
}

// LoadIaCGitHubChannel reads a workspace's GitHub (repo_scan) discovery
// source and its installation binding.
func LoadIaCGitHubChannel(db *gorm.DB, ws, sourceID uuid.UUID) (*IaCGitHubChannel, error) {
	var rows []struct {
		ID     uuid.UUID
		Kind   string
		Config json.RawMessage
	}
	if err := db.Raw(`SELECT id, kind, config FROM discovery_sources WHERE workspace_id = ? AND id = ?`, ws, sourceID).
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) != 1 || rows[0].Kind != models.DiscoverySourceRepoScan {
		return nil, ErrIaCSourceChannelNotFound
	}
	var cfg githubScannerConfig
	if len(rows[0].Config) > 0 {
		if err := json.Unmarshal(rows[0].Config, &cfg); err != nil {
			return nil, fmt.Errorf("discovery source %s config: %w", sourceID, err)
		}
	}
	host := cfg.ProviderHost
	if host == "" {
		host = "github.com"
	}
	return &IaCGitHubChannel{SourceID: rows[0].ID, IntegrationID: cfg.IntegrationID, InstallationID: cfg.InstallationID,
		AppRegistrationID: cfg.AppRegistrationID, ProviderHost: host}, nil
}

// IaCConnectorFacts are the connector facts IaC delivery and isolation use.
type IaCConnectorFacts struct {
	ConnectorID uuid.UUID
	AccountID   string
	Partition   string
	Active      bool
	// TemplateVersion is the discovery stack's recorded version;
	// MigrationEvidence is whether it grants §11's migration-evidence reads.
	TemplateVersion   string
	MigrationEvidence bool
}

// LoadIaCConnectorFacts reads an AWS connector of the workspace; another
// workspace's or a missing connector is repositories.ErrCloudConnectorNotFound.
func LoadIaCConnectorFacts(db *gorm.DB, ws, connectorID uuid.UUID) (*IaCConnectorFacts, error) {
	c, err := repositories.NewCloudConnectorRepository(db).Get(ws, connectorID)
	if err != nil {
		return nil, err
	}
	if c.Provider != models.CloudProviderAWS {
		return nil, repositories.ErrCloudConnectorNotFound
	}
	attrs := c.AWSAttrs()
	part := attrs.Partition
	if part == "" {
		part = awsdiscovery.PartitionOf(attrs.RoleARN)
	}
	if part == "" {
		part = "aws"
	}
	return &IaCConnectorFacts{ConnectorID: c.ID, AccountID: c.ScopeID, Partition: part, Active: c.Status == models.CloudConnectorActive,
		TemplateVersion: attrs.TemplateVersion, MigrationEvidence: awsdiscovery.GrantsResourcePolicyCollection(attrs.TemplateVersion)}, nil
}

// MigrationClientsFor builds one region's migration-evidence clients from
// the connector's discovery session (§11 "read by the discovery role").
func MigrationClientsFor(onboarding *AWSOnboardingService) func(ctx context.Context, ws, connectorID uuid.UUID, region string) (awsdiscovery.MigrationClients, error) {
	return func(ctx context.Context, ws, connectorID uuid.UUID, region string) (awsdiscovery.MigrationClients, error) {
		cfg, _, err := onboarding.ConfigForConnector(ctx, ws, connectorID, region)
		if err != nil {
			return awsdiscovery.MigrationClients{}, err
		}
		return awsdiscovery.NewMigrationClients(cfg), nil
	}
}
