package services

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// scopeRepo answers GetByScope only (the rest of the interface is unused here).
type scopeRepo struct {
	repositories.CloudConnectorRepository
	c   *models.CloudConnector
	err error
}

func (r scopeRepo) GetByScope(uuid.UUID, string, string) (*models.CloudConnector, error) { return r.c, r.err }

func managedTenant(t *testing.T, via string) *models.CloudConnector {
	t.Helper()
	c := &models.CloudConnector{ID: uuid.New(), WorkspaceID: uuid.New(), Provider: models.CloudProviderAzure, ScopeKind: models.CloudScopeTenant,
		ScopeID: "tid", AuthRef: azure.AppConfig{ClientID: "authsec-app"}.AuthRef()}
	if err := c.SetAzureTenantAttrs(models.AzureTenantAttrs{TenantID: "tid", ProvisionedVia: via}); err != nil {
		t.Fatal(err)
	}
	return c
}

// A tenant connected with AuthSec's app, on a server where that app is not
// configured, fails with the reason; it never reaches for a Vault path that
// only an own-app connection has.
func TestResolveAppConfigManagedNotConfigured(t *testing.T) {
	s := &AzureOnboardingService{}
	_, err := s.resolveAppConfig(managedTenant(t, models.AzureProvisionedViaAdminConsent))
	if !errors.Is(err, azure.ErrNotConfigured) || !strings.Contains(err.Error(), "AuthSec's Azure app") {
		t.Fatalf("managed tenant on an unconfigured server: %v", err)
	}
}

// The tenant connector could not be read: which app it uses is unknown, so
// discovery does not start with AuthSec's (it fails closed).
func TestResolveDiscoveryConfigFailsClosed(t *testing.T) {
	s := &AzureOnboardingService{cfg: azure.AppConfig{ClientID: "authsec-app", ClientSecret: "x"}, connectors: scopeRepo{err: errors.New("db down")}}
	if cfg, err := s.resolveDiscoveryConfig(uuid.New(), "tid"); err == nil {
		t.Fatalf("a read error fell back to %q", cfg.ClientID)
	}
	s.connectors = scopeRepo{err: repositories.ErrCloudConnectorNotFound}
	if cfg, err := s.resolveDiscoveryConfig(uuid.New(), "tid"); err != nil || cfg.ClientID != "authsec-app" {
		t.Fatalf("no tenant connector: %q %v", cfg.ClientID, err)
	}
}
