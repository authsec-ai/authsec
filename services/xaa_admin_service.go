package services

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// XAAAdminService is the admin CRUD for Cross-App Access.
//
// Two surfaces:
//
//   - xaa_client_apps (master DB) — the requesting agent identities. Admin
//     creates one, the response surfaces a one-time plaintext secret;
//     server-side only the bcrypt hash is persisted.
//
//   - application_xaa_policies (tenant DB) — per-(Application,
//     requesting_client) allowlist with scope set. Default-deny when no row
//     matches — see IDJAGService.IssueIDJAG / ExchangeForAccessToken.
//
// Until the admin UI lands these are the only programmatic way to seed XAA
// without dropping into psql; mitron-mcp/docs/xaa-end-to-end.md walks the
// curl chain.
type XAAAdminService struct {
	rs *ResourceServerService
}

func NewXAAAdminService(rs *ResourceServerService) *XAAAdminService {
	if rs == nil {
		rs = NewResourceServerService()
	}
	return &XAAAdminService{rs: rs}
}

// ── xaa_client_apps CRUD ─────────────────────────────────────────────────────

// CreateXAAClientInput is the body of POST /authsec/xaa/clients. ClientSecret
// is OPTIONAL — when omitted we mint one and return it in the response so the
// admin can paste it into their agent. Once-only display, never logged.
type CreateXAAClientInput struct {
	ClientID     string `json:"client_id"   binding:"required"`
	Name         string `json:"name"        binding:"required"`
	DisplayName  string `json:"display_name,omitempty"`
	IssuanceMode string `json:"issuance_mode,omitempty"` // "internal" | "external"
	// Optional. When empty the service generates a 32-byte secret and
	// returns it. Internal-mode clients NEED a secret to authenticate at
	// /idjag/token; external-mode clients leave it nil.
	ClientSecret string `json:"client_secret,omitempty"`
}

// XAAClientWithSecret wraps the persisted row with the one-time plaintext
// secret. The plaintext is only ever populated on the create / rotate
// response — list / get return XAAClientApp without it.
type XAAClientWithSecret struct {
	models.XAAClientApp
	ClientSecret string `json:"client_secret,omitempty"`
}

func (s *XAAAdminService) CreateClient(tenantID uuid.UUID, in CreateXAAClientInput) (*XAAClientWithSecret, error) {
	clientID := strings.TrimSpace(in.ClientID)
	if clientID == "" {
		return nil, errors.New("client_id required")
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, errors.New("name required")
	}

	mode := strings.TrimSpace(in.IssuanceMode)
	if mode == "" {
		mode = models.XAAIssuanceModeInternal
	}
	if mode != models.XAAIssuanceModeInternal && mode != models.XAAIssuanceModeExternal {
		return nil, fmt.Errorf("issuance_mode must be 'internal' or 'external'")
	}

	// Reject duplicate client_id up front. The unique index would catch this
	// too, but pre-checking gives a friendlier error.
	var existing int64
	if err := config.DB.Model(&models.XAAClientApp{}).
		Where("client_id = ? AND deleted_at IS NULL", clientID).
		Count(&existing).Error; err != nil {
		return nil, fmt.Errorf("check existing: %w", err)
	}
	if existing > 0 {
		return nil, fmt.Errorf("client_id %q already exists", clientID)
	}

	plaintext := strings.TrimSpace(in.ClientSecret)
	if mode == models.XAAIssuanceModeInternal && plaintext == "" {
		s, err := newRandomSecret(32)
		if err != nil {
			return nil, fmt.Errorf("generate secret: %w", err)
		}
		plaintext = s
	}

	hash := ""
	if plaintext != "" {
		h, err := hashAndStoreSecret(plaintext)
		if err != nil {
			return nil, err
		}
		hash = h
	}

	row := models.XAAClientApp{
		TenantID:         tenantID,
		ClientID:         clientID,
		ClientSecretHash: hash,
		Name:             name,
		DisplayName:      strings.TrimSpace(in.DisplayName),
		IssuanceMode:     mode,
		Active:           true,
	}
	if err := config.DB.Create(&row).Error; err != nil {
		return nil, fmt.Errorf("insert xaa_client_apps: %w", err)
	}
	out := &XAAClientWithSecret{XAAClientApp: row}
	// Only return the plaintext if we generated it OR the caller supplied
	// one. Either way the row's hash is already persisted; this is the
	// one-and-only chance to display it.
	if mode == models.XAAIssuanceModeInternal {
		out.ClientSecret = plaintext
	}
	return out, nil
}

func (s *XAAAdminService) ListClients(tenantID uuid.UUID) ([]models.XAAClientApp, error) {
	var rows []models.XAAClientApp
	err := config.DB.
		Where("tenant_id = ? AND deleted_at IS NULL", tenantID).
		Order("created_at DESC").Find(&rows).Error
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func (s *XAAAdminService) GetClient(tenantID, clientRowID uuid.UUID) (*models.XAAClientApp, error) {
	var row models.XAAClientApp
	err := config.DB.
		Where("id = ? AND tenant_id = ? AND deleted_at IS NULL", clientRowID, tenantID).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("xaa client not found")
	}
	return &row, err
}

// RotateSecret mints a fresh secret on the row, returns the new plaintext.
// The old secret stops working immediately — no grace window. Same trade-off
// as the introspection-secret rotation: admin's job to update consumers.
func (s *XAAAdminService) RotateSecret(tenantID, clientRowID uuid.UUID) (*XAAClientWithSecret, error) {
	row, err := s.GetClient(tenantID, clientRowID)
	if err != nil {
		return nil, err
	}
	if row.IssuanceMode == models.XAAIssuanceModeExternal {
		return nil, fmt.Errorf("rotate-secret is meaningless for external-issuance clients")
	}
	plaintext, err := newRandomSecret(32)
	if err != nil {
		return nil, err
	}
	hash, err := hashAndStoreSecret(plaintext)
	if err != nil {
		return nil, err
	}
	if err := config.DB.Model(row).Updates(map[string]any{
		"client_secret_hash": hash,
		"updated_at":         time.Now(),
	}).Error; err != nil {
		return nil, err
	}
	row.ClientSecretHash = hash
	return &XAAClientWithSecret{XAAClientApp: *row, ClientSecret: plaintext}, nil
}

// DeleteClient soft-deletes by setting deleted_at + active=false. Hard delete
// would orphan application_xaa_policies rows that reference the client_id by
// string; soft-delete is safer.
func (s *XAAAdminService) DeleteClient(tenantID, clientRowID uuid.UUID) error {
	row, err := s.GetClient(tenantID, clientRowID)
	if err != nil {
		return err
	}
	now := time.Now()
	return config.DB.Model(row).Updates(map[string]any{
		"active":     false,
		"deleted_at": now,
		"updated_at": now,
	}).Error
}

// ── application_xaa_policies CRUD ────────────────────────────────────────────

// XAAPolicyInput is the body of POST /authsec/applications/:id/xaa-policies.
// requesting_client_id refers to xaa_client_apps.client_id (the slug, not the
// row UUID). trusted_issuer defaults to "" for the internal IdP case.
type XAAPolicyInput struct {
	RequestingClientID string   `json:"requesting_client_id" binding:"required"`
	TrustedIssuer      string   `json:"trusted_issuer,omitempty"`
	AllowedScopes      []string `json:"allowed_scopes"`
	Enabled            *bool    `json:"enabled,omitempty"`
}

func (s *XAAAdminService) ListPolicies(tenantID string, applicationID uuid.UUID) ([]models.ApplicationXAAPolicy, error) {
	if _, err := s.rs.GetByID(tenantID, applicationID); err != nil {
		return nil, err
	}
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	var rows []models.ApplicationXAAPolicy
	err = tenantDB.
		Where("tenant_id = ? AND resource_server_id = ?", tenantID, applicationID).
		Order("created_at DESC").Find(&rows).Error
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func (s *XAAAdminService) CreatePolicy(tenantID string, applicationID uuid.UUID, in XAAPolicyInput) (*models.ApplicationXAAPolicy, error) {
	clientID := strings.TrimSpace(in.RequestingClientID)
	if clientID == "" {
		return nil, errors.New("requesting_client_id required")
	}
	if _, err := s.rs.GetByID(tenantID, applicationID); err != nil {
		return nil, err
	}
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant_id must be a uuid")
	}
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}

	// Sanity-check the requesting client exists. We don't enforce it (the
	// FK is a string across DBs anyway), just warn the caller they're
	// pinning a client that doesn't exist yet — useful to catch typos.
	var clientCount int64
	if err := config.DB.Model(&models.XAAClientApp{}).
		Where("tenant_id = ? AND client_id = ? AND deleted_at IS NULL", tenantUUID, clientID).
		Count(&clientCount).Error; err == nil && clientCount == 0 {
		return nil, fmt.Errorf("no xaa client with client_id=%q in this tenant", clientID)
	}

	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	row := models.ApplicationXAAPolicy{
		TenantID:           tenantUUID,
		ResourceServerID:   applicationID,
		RequestingClientID: clientID,
		TrustedIssuer:      strings.TrimSpace(in.TrustedIssuer),
		AllowedScopes:      pq.StringArray(in.AllowedScopes),
		Enabled:            enabled,
	}
	if err := tenantDB.Create(&row).Error; err != nil {
		return nil, fmt.Errorf("insert application_xaa_policies: %w", err)
	}
	return &row, nil
}

// UpdatePolicy is partial — nil fields keep their current value. Renames are
// not supported (RequestingClientID + TrustedIssuer are part of the unique key);
// if you need to change those, delete + recreate.
type UpdateXAAPolicyInput struct {
	AllowedScopes *[]string `json:"allowed_scopes,omitempty"`
	Enabled       *bool     `json:"enabled,omitempty"`
}

func (s *XAAAdminService) UpdatePolicy(tenantID string, applicationID, policyID uuid.UUID, in UpdateXAAPolicyInput) (*models.ApplicationXAAPolicy, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	var row models.ApplicationXAAPolicy
	err = tenantDB.
		Where("id = ? AND tenant_id = ? AND resource_server_id = ?",
			policyID, tenantID, applicationID).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("policy not found")
	}
	if err != nil {
		return nil, err
	}
	updates := map[string]any{"updated_at": time.Now()}
	if in.AllowedScopes != nil {
		updates["allowed_scopes"] = pq.StringArray(*in.AllowedScopes)
	}
	if in.Enabled != nil {
		updates["enabled"] = *in.Enabled
	}
	if err := tenantDB.Model(&row).Updates(updates).Error; err != nil {
		return nil, err
	}
	// Reload to return current state.
	if err := tenantDB.First(&row, "id = ?", policyID).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

func (s *XAAAdminService) DeletePolicy(tenantID string, applicationID, policyID uuid.UUID) error {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return fmt.Errorf("get tenant db: %w", err)
	}
	res := tenantDB.
		Where("id = ? AND tenant_id = ? AND resource_server_id = ?",
			policyID, tenantID, applicationID).
		Delete(&models.ApplicationXAAPolicy{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("policy not found")
	}
	return nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func newRandomSecret(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// URL-safe, no padding. Same flavour as our other one-time secrets so
	// admins don't have to special-case anything.
	return base64.RawURLEncoding.EncodeToString(b), nil
}
