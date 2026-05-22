package services

import (
	"fmt"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// IdentityProviderService is the read-side abstraction over the workspace-owned
// identity_providers table. Reads return the IDP row plus, when the caller
// asks for it, the resolved underlying provider config (saml_providers,
// sync_configurations). This lets callers move off the per-type lookup paths
// (GetSAMLProvidersForTenant, GetSyncConfig, …) and use a single workspace API.
//
// Writes still flow through the legacy controllers — once those are migrated
// this service grows Create/Update/Delete and the legacy tables become
// derived data.
type IdentityProviderService struct {
	db *gorm.DB
}

func NewIdentityProviderService(db *gorm.DB) *IdentityProviderService {
	return &IdentityProviderService{db: db}
}

// ListByWorkspace returns all identity_providers for a workspace, optionally
// filtered by provider_type (empty string = no filter).
func (s *IdentityProviderService) ListByWorkspace(workspaceID uuid.UUID, providerType string) ([]models.IdentityProvider, error) {
	q := s.db.Where("workspace_id = ?", workspaceID)
	if providerType != "" {
		q = q.Where("provider_type = ?", providerType)
	}

	var rows []models.IdentityProvider
	if err := q.Order("created_at ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list identity_providers: %w", err)
	}
	return rows, nil
}

// GetByID loads a single IDP scoped to a workspace. Returns gorm.ErrRecordNotFound
// when the row does not exist or belongs to a different workspace.
func (s *IdentityProviderService) GetByID(workspaceID, providerID uuid.UUID) (*models.IdentityProvider, error) {
	var p models.IdentityProvider
	if err := s.db.Where("id = ? AND workspace_id = ?", providerID, workspaceID).First(&p).Error; err != nil {
		return nil, err
	}
	return &p, nil
}

// ListForApplication walks application_identity_provider_policies and returns
// the IDPs enabled for the given Application, scoped to the workspace.
// Disabled rows are filtered out.
func (s *IdentityProviderService) ListForApplication(workspaceID, applicationID uuid.UUID) ([]models.IdentityProvider, error) {
	var rows []models.IdentityProvider
	err := s.db.Table("identity_providers ip").
		Select("ip.*").
		Joins("JOIN application_identity_provider_policies p ON p.identity_provider_id = ip.id").
		Where("p.application_id = ? AND p.workspace_id = ? AND p.enabled = true", applicationID, workspaceID).
		Where("ip.workspace_id = ?", workspaceID).
		Order("ip.created_at ASC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("list identity_providers for application: %w", err)
	}
	return rows, nil
}

// ResolveSAMLConfig follows an IDP row of provider_type='saml' through to the
// underlying saml_providers row referenced by config_ref. Returns
// gorm.ErrRecordNotFound when the IDP is not SAML or the referenced row is
// missing.
//
// The function takes a generic destination so callers can use any saml
// provider struct (the model is owned by internal/hydra). We accept a
// pointer-to-anything that gorm can scan into the saml_providers row.
func (s *IdentityProviderService) ResolveSAMLConfig(idp *models.IdentityProvider, dest interface{}) error {
	if idp == nil {
		return fmt.Errorf("identity provider is nil")
	}
	if idp.ProviderType != models.IdentityProviderSAML {
		return fmt.Errorf("identity provider %s is not a SAML provider (type=%s)", idp.ID, idp.ProviderType)
	}
	configUUID, err := uuid.Parse(idp.ConfigRef)
	if err != nil {
		return fmt.Errorf("identity provider %s has invalid SAML config_ref: %w", idp.ID, err)
	}
	if err := s.db.Table("saml_providers").
		Where("id = ?", configUUID).
		First(dest).Error; err != nil {
		return err
	}
	return nil
}

// ResolveSyncConfig follows an IDP row of provider_type='ad' or 'entra'
// through to the underlying sync_configurations row referenced by config_ref.
func (s *IdentityProviderService) ResolveSyncConfig(idp *models.IdentityProvider, dest interface{}) error {
	if idp == nil {
		return fmt.Errorf("identity provider is nil")
	}
	if idp.ProviderType != models.IdentityProviderAD && idp.ProviderType != models.IdentityProviderEntra {
		return fmt.Errorf("identity provider %s is not a directory sync provider (type=%s)", idp.ID, idp.ProviderType)
	}
	configUUID, err := uuid.Parse(idp.ConfigRef)
	if err != nil {
		return fmt.Errorf("identity provider %s has invalid sync config_ref: %w", idp.ID, err)
	}
	if err := s.db.Table("sync_configurations").
		Where("id = ?", configUUID).
		First(dest).Error; err != nil {
		return err
	}
	return nil
}
