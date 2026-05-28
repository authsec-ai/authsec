package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// IdentityProviderService owns the workspace-scoped IDP lifecycle. Writes
// dispatch on provider_type and persist both the underlying provider config
// (saml_providers / oidc_providers / sync_configurations) and the
// identity_providers row in a single transaction. Reads expose the workspace
// IDP table and the resolved underlying config rows.
type IdentityProviderService struct {
	db *gorm.DB
}

var ErrIdentityProviderAlreadyExists = errors.New("identity provider already exists")

func NewIdentityProviderService(db *gorm.DB) *IdentityProviderService {
	return &IdentityProviderService{db: db}
}

// ──────────────────────────────────────────────────────────────────────────────
// Write request structs
// ──────────────────────────────────────────────────────────────────────────────

// CreateOIDCIDPRequest is the input for CreateOIDC. ClientSecret is plaintext
// and written to Vault only; never persisted in the relational store.
type CreateOIDCIDPRequest struct {
	WorkspaceID      uuid.UUID
	CreatedByUserID  uuid.UUID
	DisplayName      string
	ProviderName     string
	AuthorizationURL string
	TokenURL         string
	UserinfoURL      string
	ClientID         string
	ClientSecret     string
	Scopes           string
	IconURL          string
}

// CreateSAMLIDPRequest is the input for CreateSAML.
type CreateSAMLIDPRequest struct {
	WorkspaceID      uuid.UUID
	CreatedByUserID  uuid.UUID
	DisplayName      string
	ProviderName     string
	EntityID         string
	SSOUrl           string
	SLOUrl           string
	Certificate      string
	NameIDFormat     string
	AttributeMapping json.RawMessage
}

// ──────────────────────────────────────────────────────────────────────────────
// Writes
// ──────────────────────────────────────────────────────────────────────────────

// CreateOIDC registers a workspace-owned OIDC IDP in one transaction:
//
//  1. Insert into oidc_providers (workspace_id, provider_name, urls, …).
//  2. Write client_secret to Vault at the canonical workspace path.
//  3. Insert into identity_providers (provider_type='oidc', config_ref=<oidc_providers.id>).
//
// Rolls back the DB writes if the Vault write fails. Returns the new
// identity_providers row.
func (s *IdentityProviderService) CreateOIDC(req CreateOIDCIDPRequest) (*models.IdentityProvider, error) {
	if req.WorkspaceID == uuid.Nil {
		return nil, fmt.Errorf("workspace_id is required")
	}
	providerName := strings.ToLower(strings.TrimSpace(req.ProviderName))
	if providerName == "" {
		return nil, fmt.Errorf("provider_name is required")
	}
	if req.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if req.ClientSecret == "" {
		return nil, fmt.Errorf("client_secret is required")
	}

	var existingIDP models.IdentityProvider
	existingErr := s.db.Model(&models.IdentityProvider{}).
		Joins("JOIN oidc_providers op ON op.id::text = identity_providers.config_ref").
		Where("identity_providers.workspace_id = ?", req.WorkspaceID).
		Where("identity_providers.provider_type = ?", models.IdentityProviderOIDC).
		Where("op.provider_name = ?", providerName).
		First(&existingIDP).Error
	if existingErr == nil {
		return nil, fmt.Errorf("%w: oidc provider %q is already configured for this workspace", ErrIdentityProviderAlreadyExists, providerName)
	}
	if existingErr != gorm.ErrRecordNotFound {
		return nil, existingErr
	}

	vaultPath := config.WorkspaceIDPSecretPath(req.WorkspaceID.String(), models.IdentityProviderOIDC, providerName)

	var idp models.IdentityProvider
	txErr := s.db.Transaction(func(tx *gorm.DB) error {
		oidcRow := models.OIDCProvider{
			WorkspaceID:           req.WorkspaceID,
			ProviderName:          providerName,
			DisplayName:           coalesceString(req.DisplayName, providerName),
			ClientID:              req.ClientID,
			ClientSecretVaultPath: vaultPath,
			AuthorizationURL:      req.AuthorizationURL,
			TokenURL:              req.TokenURL,
			UserinfoURL:           req.UserinfoURL,
			Scopes:                coalesceString(req.Scopes, "openid email profile"),
			IconURL:               req.IconURL,
			IsActive:              true,
		}
		if err := tx.Create(&oidcRow).Error; err != nil {
			return fmt.Errorf("insert oidc_providers: %w", err)
		}

		idp = models.IdentityProvider{
			WorkspaceID:     req.WorkspaceID,
			ProviderType:    models.IdentityProviderOIDC,
			DisplayName:     coalesceString(req.DisplayName, providerName),
			ConfigRef:       oidcRow.ID.String(),
			Status:          "configured",
			CreatedByUserID: req.CreatedByUserID,
		}
		if err := tx.Create(&idp).Error; err != nil {
			return fmt.Errorf("insert identity_providers: %w", err)
		}
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}

	// Vault write happens after DB commit so the rollback path is simpler.
	// On failure, clean up the rows we just created.
	if err := config.SaveWorkspaceIDPSecret(req.WorkspaceID.String(), models.IdentityProviderOIDC, providerName,
		map[string]interface{}{"client_secret": req.ClientSecret}); err != nil {
		_ = s.deleteOIDCArtifacts(req.WorkspaceID, idp.ID, providerName)
		return nil, fmt.Errorf("write vault secret: %w", err)
	}

	return &idp, nil
}

// CreateSAML registers a workspace-owned SAML IDP. No Vault interaction —
// SAML IdP certificates are public and live on the saml_providers row.
func (s *IdentityProviderService) CreateSAML(req CreateSAMLIDPRequest) (*models.IdentityProvider, error) {
	if req.WorkspaceID == uuid.Nil {
		return nil, fmt.Errorf("workspace_id is required")
	}
	providerName := strings.ToLower(strings.TrimSpace(req.ProviderName))
	if providerName == "" {
		return nil, fmt.Errorf("provider_name is required")
	}
	if req.EntityID == "" || req.SSOUrl == "" || req.Certificate == "" {
		return nil, fmt.Errorf("entity_id, sso_url, and certificate are required")
	}

	var existingIDP models.IdentityProvider
	existingErr := s.db.Model(&models.IdentityProvider{}).
		Joins("JOIN saml_providers sp ON sp.id::text = identity_providers.config_ref").
		Where("identity_providers.workspace_id = ?", req.WorkspaceID).
		Where("identity_providers.provider_type = ?", models.IdentityProviderSAML).
		Where("sp.provider_name = ?", providerName).
		First(&existingIDP).Error
	if existingErr == nil {
		return nil, fmt.Errorf("%w: saml provider %q is already configured for this workspace", ErrIdentityProviderAlreadyExists, providerName)
	}
	if existingErr != gorm.ErrRecordNotFound {
		return nil, existingErr
	}

	nameIDFormat := req.NameIDFormat
	if nameIDFormat == "" {
		nameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	}

	var idp models.IdentityProvider
	txErr := s.db.Transaction(func(tx *gorm.DB) error {
		// Use map[string]interface{} so we don't have to import the hydra
		// SAML model here (would create an import cycle).
		now := time.Now()
		samlID := uuid.New()
		attrMapping := datatypes.JSON(req.AttributeMapping)
		samlRow := map[string]interface{}{
			"id":                samlID,
			"workspace_id":      req.WorkspaceID,
			"provider_name":     providerName,
			"display_name":      coalesceString(req.DisplayName, providerName),
			"entity_id":         req.EntityID,
			"sso_url":           req.SSOUrl,
			"slo_url":           req.SLOUrl,
			"certificate":       req.Certificate,
			"name_id_format":    nameIDFormat,
			"attribute_mapping": attrMapping,
			"is_active":         true,
			"sort_order":        0,
			"created_at":        now,
			"updated_at":        now,
		}
		if err := tx.Table("saml_providers").Create(samlRow).Error; err != nil {
			return fmt.Errorf("insert saml_providers: %w", err)
		}

		idp = models.IdentityProvider{
			WorkspaceID:     req.WorkspaceID,
			ProviderType:    models.IdentityProviderSAML,
			DisplayName:     coalesceString(req.DisplayName, providerName),
			ConfigRef:       samlID.String(),
			Status:          "configured",
			CreatedByUserID: req.CreatedByUserID,
		}
		if err := tx.Create(&idp).Error; err != nil {
			return fmt.Errorf("insert identity_providers: %w", err)
		}
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}
	return &idp, nil
}

// UpdateStatus flips an IDP between 'configured' and 'disabled'. Disabling an
// IDP makes the login-flow gates reject it without removing config data.
func (s *IdentityProviderService) UpdateStatus(workspaceID, idpID uuid.UUID, status string) error {
	if status != "configured" && status != "disabled" {
		return fmt.Errorf("status must be 'configured' or 'disabled'")
	}
	res := s.db.Model(&models.IdentityProvider{}).
		Where("id = ? AND workspace_id = ?", idpID, workspaceID).
		Updates(map[string]interface{}{
			"status":     status,
			"updated_at": time.Now(),
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// Delete removes the workspace IDP, its underlying provider config row, and
// (for OIDC) the Vault secret. application_identity_provider_policies rows
// referencing the deleted IDP are cascade-deleted by FK ON DELETE CASCADE.
func (s *IdentityProviderService) Delete(workspaceID, idpID uuid.UUID) error {
	idp, err := s.GetByID(workspaceID, idpID)
	if err != nil {
		return err
	}

	switch idp.ProviderType {
	case models.IdentityProviderOIDC:
		var oidcRow models.OIDCProvider
		if cfgErr := s.ResolveOIDCConfig(idp, &oidcRow); cfgErr == nil {
			return s.deleteOIDCArtifacts(workspaceID, idpID, oidcRow.ProviderName)
		}
		// If config_ref is broken, drop just the identity_providers row.
		return s.db.Where("id = ? AND workspace_id = ?", idpID, workspaceID).
			Delete(&models.IdentityProvider{}).Error
	case models.IdentityProviderSAML:
		configUUID, parseErr := uuid.Parse(idp.ConfigRef)
		if parseErr != nil {
			return s.db.Where("id = ? AND workspace_id = ?", idpID, workspaceID).
				Delete(&models.IdentityProvider{}).Error
		}
		return s.db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Table("saml_providers").Where("id = ?", configUUID).
				Delete(map[string]interface{}{}).Error; err != nil {
				return fmt.Errorf("delete saml_providers row: %w", err)
			}
			if err := tx.Where("id = ? AND workspace_id = ?", idpID, workspaceID).
				Delete(&models.IdentityProvider{}).Error; err != nil {
				return fmt.Errorf("delete identity_providers row: %w", err)
			}
			return nil
		})
	default:
		return s.db.Where("id = ? AND workspace_id = ?", idpID, workspaceID).
			Delete(&models.IdentityProvider{}).Error
	}
}

// deleteOIDCArtifacts removes the oidc_providers row, the Vault secret, and
// the identity_providers row in one shot. Best-effort on Vault — a Vault
// failure logs but doesn't block the DB cleanup.
func (s *IdentityProviderService) deleteOIDCArtifacts(workspaceID, idpID uuid.UUID, providerName string) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("workspace_id = ? AND provider_name = ?", workspaceID, providerName).
			Delete(&models.OIDCProvider{}).Error; err != nil {
			return fmt.Errorf("delete oidc_providers row: %w", err)
		}
		if err := tx.Where("id = ? AND workspace_id = ?", idpID, workspaceID).
			Delete(&models.IdentityProvider{}).Error; err != nil {
			return fmt.Errorf("delete identity_providers row: %w", err)
		}
		_ = config.DeleteWorkspaceIDPSecret(workspaceID.String(), models.IdentityProviderOIDC, providerName)
		return nil
	})
}

// ──────────────────────────────────────────────────────────────────────────────
// Application binding writes
// ──────────────────────────────────────────────────────────────────────────────

// PinIDPToApplication upserts an application_identity_provider_policies row.
// The Application and IDP must both belong to the workspace.
func (s *IdentityProviderService) PinIDPToApplication(workspaceID, applicationID, idpID uuid.UUID, enabled bool) (*models.ApplicationIdentityProviderPolicy, error) {
	// Confirm IDP and Application both belong to the workspace.
	if _, err := s.GetByID(workspaceID, idpID); err != nil {
		return nil, fmt.Errorf("identity provider not in workspace: %w", err)
	}
	var count int64
	if err := s.db.Table("resource_servers").
		Where("id = ? AND (workspace_id = ? OR workspace_id = ?)", applicationID, workspaceID, workspaceID).
		Count(&count).Error; err != nil {
		return nil, fmt.Errorf("verify application: %w", err)
	}
	if count == 0 {
		return nil, fmt.Errorf("application not in workspace")
	}

	row := models.ApplicationIdentityProviderPolicy{
		WorkspaceID:        workspaceID,
		ApplicationID:      applicationID,
		IdentityProviderID: idpID,
		Enabled:            enabled,
	}
	// Upsert on the (application_id, identity_provider_id) unique key.
	err := s.db.Where("application_id = ? AND identity_provider_id = ?", applicationID, idpID).
		Assign(map[string]interface{}{
			"workspace_id": workspaceID,
			"enabled":      enabled,
			"updated_at":   time.Now(),
		}).
		FirstOrCreate(&row).Error
	if err != nil {
		return nil, fmt.Errorf("upsert application_identity_provider_policies: %w", err)
	}
	return &row, nil
}

// UnpinIDPFromApplication removes the Application↔IDP binding.
func (s *IdentityProviderService) UnpinIDPFromApplication(workspaceID, applicationID, idpID uuid.UUID) error {
	res := s.db.Where("workspace_id = ? AND application_id = ? AND identity_provider_id = ?",
		workspaceID, applicationID, idpID).
		Delete(&models.ApplicationIdentityProviderPolicy{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// ListApplicationPolicies returns every policy row for an Application, even
// disabled ones. (Use ListForApplication for the enabled subset.)
func (s *IdentityProviderService) ListApplicationPolicies(workspaceID, applicationID uuid.UUID) ([]models.ApplicationIdentityProviderPolicy, error) {
	var rows []models.ApplicationIdentityProviderPolicy
	err := s.db.Where("workspace_id = ? AND application_id = ?", workspaceID, applicationID).
		Order("created_at ASC").
		Find(&rows).Error
	return rows, err
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

func coalesceString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
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

// ResolveOIDCConfig follows an IDP row of provider_type='oidc' through to the
// underlying oidc_providers row referenced by config_ref. Returns
// gorm.ErrRecordNotFound when the IDP is not OIDC or the referenced row is
// missing. dest should be *models.OIDCProvider.
func (s *IdentityProviderService) ResolveOIDCConfig(idp *models.IdentityProvider, dest interface{}) error {
	if idp == nil {
		return fmt.Errorf("identity provider is nil")
	}
	if idp.ProviderType != models.IdentityProviderOIDC {
		return fmt.Errorf("identity provider %s is not an OIDC provider (type=%s)", idp.ID, idp.ProviderType)
	}
	configUUID, err := uuid.Parse(idp.ConfigRef)
	if err != nil {
		return fmt.Errorf("identity provider %s has invalid OIDC config_ref: %w", idp.ID, err)
	}
	return s.db.Table("oidc_providers").Where("id = ?", configUUID).First(dest).Error
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
