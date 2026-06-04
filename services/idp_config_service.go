package services

import (
	"errors"
	"fmt"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// IDPConfigService is the admin CRUD surface for tenant-DB IDP provider
// configurations (oidc_providers, saml_providers). Both tables hold the
// upstream credentials (Google OAuth client_id+secret, Okta SAML cert + SSO
// URL, etc.) that the federated login flow consumes.
//
// Per-MCP scoping (migration 035): each row can carry a non-NULL
// resource_server_id, scoping it to a specific Application. NULL rows are
// the tenant-wide default; per-MCP rows shadow them for matching
// (tenant, provider_name) pairs.
//
// Lookups in the federated callback path do:
//
//	WHERE provider_name = ?
//	  AND (resource_server_id = ? OR resource_server_id IS NULL)
//	ORDER BY resource_server_id NULLS LAST
//	LIMIT 1
//
// This service writes those rows. Tenant scoping is implicit — each row
// lives in its tenant's DB.
type IDPConfigService struct {
	rs *ResourceServerService
}

func NewIDPConfigService() *IDPConfigService {
	return &IDPConfigService{rs: NewResourceServerService()}
}

// ErrIDPConfigNotFound is returned when a CRUD operation targets a row that
// either doesn't exist or doesn't belong to the requested Application.
var ErrIDPConfigNotFound = errors.New("idp config not found")

// ─────────────────────────────────────────────────────────────────────────
// OIDC providers
// ─────────────────────────────────────────────────────────────────────────

// OIDCProviderInput is the body of POST + PUT. Fields not set on PUT keep
// their current value (partial update).
type OIDCProviderInput struct {
	ProviderName          string  `json:"provider_name"`
	DisplayName           string  `json:"display_name"`
	ClientID              string  `json:"client_id"`
	ClientSecret          *string `json:"client_secret,omitempty"`            // pointer: nil = don't change on PUT
	ClientSecretVaultPath *string `json:"client_secret_vault_path,omitempty"` // pointer: nil = don't change on PUT
	AuthorizationURL      string  `json:"authorization_url"`
	TokenURL              string  `json:"token_url"`
	UserinfoURL           string  `json:"userinfo_url"`
	Scopes                string  `json:"scopes,omitempty"`
	IconURL               string  `json:"icon_url,omitempty"`
	IsActive              *bool   `json:"is_active,omitempty"`
}

// ListOIDCProviders returns OIDC provider rows scoped to the given
// Application. Returns rows where resource_server_id = applicationID
// (per-MCP overrides) AND rows where resource_server_id IS NULL
// (tenant-wide defaults). UI distinguishes them via the JSON field.
func (s *IDPConfigService) ListOIDCProviders(tenantID string, applicationID uuid.UUID) ([]models.OIDCProvider, error) {
	if _, err := s.rs.GetByID(tenantID, applicationID); err != nil {
		return nil, err
	}
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	var rows []models.OIDCProvider
	if err := tenantDB.
		Where("resource_server_id = ? OR resource_server_id IS NULL", applicationID).
		Order("resource_server_id NULLS LAST, provider_name ASC").
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list oidc_providers: %w", err)
	}
	return rows, nil
}

// CreateOIDCProvider inserts a new per-MCP OIDC provider row scoped to the
// given Application. Tenant-wide rows (resource_server_id IS NULL) are
// managed via the legacy /oocmgr surface, not this endpoint — that's a
// deliberate split so per-MCP CRUD doesn't accidentally widen scope.
func (s *IDPConfigService) CreateOIDCProvider(tenantID string, applicationID uuid.UUID, in OIDCProviderInput) (*models.OIDCProvider, error) {
	if _, err := s.rs.GetByID(tenantID, applicationID); err != nil {
		return nil, err
	}
	if in.ProviderName == "" {
		return nil, errors.New("provider_name required")
	}
	if in.ClientID == "" {
		return nil, errors.New("client_id required")
	}
	if in.AuthorizationURL == "" || in.TokenURL == "" || in.UserinfoURL == "" {
		return nil, errors.New("authorization_url, token_url, and userinfo_url are all required")
	}

	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}

	rs := applicationID
	row := models.OIDCProvider{
		ResourceServerID: &rs,
		ProviderName:     in.ProviderName,
		DisplayName:      defaultStr(in.DisplayName, in.ProviderName),
		ClientID:         in.ClientID,
		AuthorizationURL: in.AuthorizationURL,
		TokenURL:         in.TokenURL,
		UserinfoURL:      in.UserinfoURL,
		Scopes:           defaultStr(in.Scopes, "openid email profile"),
		IconURL:          in.IconURL,
		IsActive:         in.IsActive == nil || *in.IsActive, // default true on create
	}
	if in.ClientSecret != nil {
		row.ClientSecret = *in.ClientSecret
	}
	if in.ClientSecretVaultPath != nil {
		row.ClientSecretVaultPath = *in.ClientSecretVaultPath
	}

	if err := tenantDB.Create(&row).Error; err != nil {
		return nil, fmt.Errorf("insert oidc_providers: %w", err)
	}
	return &row, nil
}

// UpdateOIDCProvider mutates the per-MCP row identified by providerID. Only
// non-zero / non-nil fields on the input are applied. The
// resource_server_id is treated as immutable — moving a provider across
// Applications requires delete + create to make the audit trail clear.
func (s *IDPConfigService) UpdateOIDCProvider(tenantID string, applicationID, providerID uuid.UUID, in OIDCProviderInput) (*models.OIDCProvider, error) {
	if _, err := s.rs.GetByID(tenantID, applicationID); err != nil {
		return nil, err
	}
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	var row models.OIDCProvider
	if err := tenantDB.
		Where("id = ? AND resource_server_id = ?", providerID, applicationID).
		First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrIDPConfigNotFound
		}
		return nil, err
	}

	updates := map[string]interface{}{}
	if in.ProviderName != "" {
		updates["provider_name"] = in.ProviderName
	}
	if in.DisplayName != "" {
		updates["display_name"] = in.DisplayName
	}
	if in.ClientID != "" {
		updates["client_id"] = in.ClientID
	}
	if in.ClientSecret != nil {
		updates["client_secret"] = *in.ClientSecret
	}
	if in.ClientSecretVaultPath != nil {
		updates["client_secret_vault_path"] = *in.ClientSecretVaultPath
	}
	if in.AuthorizationURL != "" {
		updates["authorization_url"] = in.AuthorizationURL
	}
	if in.TokenURL != "" {
		updates["token_url"] = in.TokenURL
	}
	if in.UserinfoURL != "" {
		updates["userinfo_url"] = in.UserinfoURL
	}
	if in.Scopes != "" {
		updates["scopes"] = in.Scopes
	}
	if in.IconURL != "" {
		updates["icon_url"] = in.IconURL
	}
	if in.IsActive != nil {
		updates["is_active"] = *in.IsActive
	}
	if len(updates) == 0 {
		return &row, nil
	}
	if err := tenantDB.Model(&row).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("update oidc_providers: %w", err)
	}
	if err := tenantDB.Where("id = ?", providerID).First(&row).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

// DeleteOIDCProvider removes a per-MCP OIDC provider row. The tenant-wide
// row (if any) is untouched — login simply falls back to it.
func (s *IDPConfigService) DeleteOIDCProvider(tenantID string, applicationID, providerID uuid.UUID) error {
	if _, err := s.rs.GetByID(tenantID, applicationID); err != nil {
		return err
	}
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return fmt.Errorf("get tenant db: %w", err)
	}
	res := tenantDB.
		Where("id = ? AND resource_server_id = ?", providerID, applicationID).
		Delete(&models.OIDCProvider{})
	if res.Error != nil {
		return fmt.Errorf("delete oidc_providers: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrIDPConfigNotFound
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────
// SAML providers
//
// SAML config types live in internal/hydra/models, which already imports
// the services package — so the services package can't import it back
// without creating a cycle. The SAML CRUD methods live on the
// applications_v2_controller (it's free to import both) and the
// `EnsureApplication` helper below is the only piece they need from
// here. Same orchestration pattern as the federated SAML controller wiring.
// ─────────────────────────────────────────────────────────────────────────

// EnsureApplication verifies the Application exists under the tenant and
// returns its row. Used by the controller-side SAML CRUD handlers.
func (s *IDPConfigService) EnsureApplication(tenantID string, applicationID uuid.UUID) (*models.ResourceServer, error) {
	return s.rs.GetByID(tenantID, applicationID)
}

// TenantDB returns the GORM connection for the tenant. Helper for the
// controller-side SAML CRUD (which can't reach into the package-private
// config.GetTenantGORMDB caller chain we use internally).
func (s *IDPConfigService) TenantDB(tenantID string) (*gorm.DB, error) {
	return config.GetTenantGORMDB(tenantID)
}

// ─────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────

func defaultStr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
