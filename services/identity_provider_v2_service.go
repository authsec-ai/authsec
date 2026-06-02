package services

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// IdentityProviderV2Service owns the tenant-scoped IDP registry on the prod
// backport. Mirrors authsec-dev's services/identity_provider_service.go but
// tenant-scoped (tenant DB) instead of workspace-scoped.
//
// The underlying provider config rows (oidc_providers, saml_providers,
// sync_configurations) live in *master* on prod for now — adding tenant_id
// to oidc_providers is a follow-up. For this phase the identity_providers
// row's config_ref points at the global config row by string-stringified
// UUID.
type IdentityProviderV2Service struct{}

func NewIdentityProviderV2Service() *IdentityProviderV2Service {
	return &IdentityProviderV2Service{}
}

var ErrIdentityProviderAlreadyExists = errors.New("identity provider already exists for tenant")

// CreateOIDCIDPRequest is the input for CreateOIDC.
type CreateOIDCIDPRequest struct {
	TenantID        string
	CreatedByUserID uuid.UUID
	DisplayName     string
	ProviderName    string
	// ConfigRef is the stringified UUID of an existing oidc_providers row
	// (master DB) the tenant wants to use. Empty = caller hasn't provisioned
	// the protocol-specific config yet; the handler should reject.
	ConfigRef string
}

// CreateOIDC inserts a row into the tenant's identity_providers table
// pointing at the named oidc_providers row. Phase-4 minimum: we don't
// duplicate the protocol config per-tenant; tenants share global oidc_providers.
func (s *IdentityProviderV2Service) CreateOIDC(req CreateOIDCIDPRequest) (*models.IdentityProvider, error) {
	if req.TenantID == "" {
		return nil, fmt.Errorf("tenant_id required")
	}
	if req.ConfigRef == "" {
		return nil, fmt.Errorf("config_ref required (point at an existing oidc_providers row)")
	}
	providerName := strings.ToLower(strings.TrimSpace(req.ProviderName))
	if providerName == "" {
		return nil, fmt.Errorf("provider_name required")
	}
	tenantDB, err := config.GetTenantGORMDB(req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}

	// Uniqueness: at most one IDP row per (tenant_id, provider_type, config_ref).
	var existingCount int64
	if err := tenantDB.Model(&models.IdentityProvider{}).
		Where("tenant_id = ? AND provider_type = ? AND config_ref = ?",
			req.TenantID, models.IdentityProviderOIDC, req.ConfigRef).
		Count(&existingCount).Error; err != nil {
		return nil, fmt.Errorf("uniqueness check: %w", err)
	}
	if existingCount > 0 {
		return nil, ErrIdentityProviderAlreadyExists
	}

	row := models.IdentityProvider{
		TenantID:        req.TenantID,
		ProviderType:    models.IdentityProviderOIDC,
		DisplayName:     coalesce(req.DisplayName, providerName),
		ConfigRef:       req.ConfigRef,
		Status:          "configured",
		CreatedByUserID: req.CreatedByUserID,
	}
	if err := tenantDB.Create(&row).Error; err != nil {
		return nil, fmt.Errorf("insert identity_providers: %w", err)
	}
	return &row, nil
}

// List returns the tenant's identity_providers rows, optionally filtered by
// provider_type.
func (s *IdentityProviderV2Service) List(tenantID, providerType string) ([]models.IdentityProvider, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	q := tenantDB.Where("tenant_id = ?", tenantID)
	if providerType != "" {
		q = q.Where("provider_type = ?", providerType)
	}
	var rows []models.IdentityProvider
	if err := q.Order("created_at ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// GetByID loads a single IDP row for the tenant.
func (s *IdentityProviderV2Service) GetByID(tenantID string, id uuid.UUID) (*models.IdentityProvider, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	var row models.IdentityProvider
	if err := tenantDB.Where("id = ? AND tenant_id = ?", id, tenantID).First(&row).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

// UpdateStatus flips an IDP between 'configured' and 'disabled'.
func (s *IdentityProviderV2Service) UpdateStatus(tenantID string, id uuid.UUID, status string) error {
	if status != "configured" && status != "disabled" {
		return fmt.Errorf("status must be 'configured' or 'disabled'")
	}
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return fmt.Errorf("get tenant db: %w", err)
	}
	res := tenantDB.Model(&models.IdentityProvider{}).
		Where("id = ? AND tenant_id = ?", id, tenantID).
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

// Delete removes the IDP row (does NOT remove the underlying oidc_providers
// row — that's shared with other tenants on this prod schema).
func (s *IdentityProviderV2Service) Delete(tenantID string, id uuid.UUID) error {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return fmt.Errorf("get tenant db: %w", err)
	}
	res := tenantDB.Where("id = ? AND tenant_id = ?", id, tenantID).
		Delete(&models.IdentityProvider{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// ──────────────────────────────────────────────────────────────────────────
// Application ↔ IDP policy
// ──────────────────────────────────────────────────────────────────────────

// PinIDPToApplication upserts the application_identity_provider_policies row
// that whitelists an IDP for an Application.
func (s *IdentityProviderV2Service) PinIDPToApplication(tenantID string, applicationID, idpID uuid.UUID, enabled bool) (*models.ApplicationIdentityProviderPolicy, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}

	// Confirm both rows belong to the tenant.
	var idpCount int64
	if err := tenantDB.Model(&models.IdentityProvider{}).
		Where("id = ? AND tenant_id = ?", idpID, tenantID).Count(&idpCount).Error; err != nil {
		return nil, fmt.Errorf("verify idp: %w", err)
	}
	if idpCount == 0 {
		return nil, fmt.Errorf("identity provider not in tenant")
	}
	var rsCount int64
	if err := tenantDB.Model(&models.ResourceServer{}).
		Where("id = ? AND tenant_id = ?", applicationID, tenantID).Count(&rsCount).Error; err != nil {
		return nil, fmt.Errorf("verify application: %w", err)
	}
	if rsCount == 0 {
		return nil, fmt.Errorf("application not in tenant")
	}

	row := models.ApplicationIdentityProviderPolicy{
		TenantID:           tenantID,
		ApplicationID:      applicationID,
		IdentityProviderID: idpID,
		Enabled:            enabled,
	}
	err = tenantDB.Where("application_id = ? AND identity_provider_id = ?", applicationID, idpID).
		Assign(map[string]interface{}{
			"tenant_id":  tenantID,
			"enabled":    enabled,
			"updated_at": time.Now(),
		}).
		FirstOrCreate(&row).Error
	if err != nil {
		return nil, fmt.Errorf("upsert application_identity_provider_policies: %w", err)
	}
	return &row, nil
}

// UnpinIDPFromApplication removes the binding.
func (s *IdentityProviderV2Service) UnpinIDPFromApplication(tenantID string, applicationID, idpID uuid.UUID) error {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return fmt.Errorf("get tenant db: %w", err)
	}
	res := tenantDB.Where("tenant_id = ? AND application_id = ? AND identity_provider_id = ?",
		tenantID, applicationID, idpID).
		Delete(&models.ApplicationIdentityProviderPolicy{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// ListApplicationPolicies returns every policy row for an Application.
func (s *IdentityProviderV2Service) ListApplicationPolicies(tenantID string, applicationID uuid.UUID) ([]models.ApplicationIdentityProviderPolicy, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	var rows []models.ApplicationIdentityProviderPolicy
	err = tenantDB.Where("tenant_id = ? AND application_id = ?", tenantID, applicationID).
		Order("created_at ASC").Find(&rows).Error
	return rows, err
}

// CheckIDPAllowedForApplication is the policy gate called from /authorize.
// Default-allow when an Application has no policy rows; whitelist mode when
// any rows exist.
//
// Returns (allowed bool, err error). err is non-nil only on infrastructure
// failure, not on policy denials — denials are (false, nil).
func (s *IdentityProviderV2Service) CheckIDPAllowedForApplication(tenantID string, applicationID, idpID uuid.UUID) (bool, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return false, fmt.Errorf("get tenant db: %w", err)
	}
	var totalCount int64
	if err := tenantDB.Model(&models.ApplicationIdentityProviderPolicy{}).
		Where("tenant_id = ? AND application_id = ?", tenantID, applicationID).
		Count(&totalCount).Error; err != nil {
		return false, fmt.Errorf("count policies: %w", err)
	}
	if totalCount == 0 {
		return true, nil // default-allow
	}
	var enabledCount int64
	if err := tenantDB.Model(&models.ApplicationIdentityProviderPolicy{}).
		Where("tenant_id = ? AND application_id = ? AND identity_provider_id = ? AND enabled = true",
			tenantID, applicationID, idpID).
		Count(&enabledCount).Error; err != nil {
		return false, fmt.Errorf("count enabled: %w", err)
	}
	return enabledCount > 0, nil
}

func coalesce(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
