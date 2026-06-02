package services

import (
	"errors"
	"fmt"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ResourceServerService owns the lifecycle of resource_servers rows (the
// Application concept) on the prod backport. resource_servers lives in the
// tenant DB; resource_server_tenant_index lives in master and is written in
// lockstep so the DCR handler can resolve resource_uri -> tenant_id without
// scanning every tenant DB.
type ResourceServerService struct{}

func NewResourceServerService() *ResourceServerService {
	return &ResourceServerService{}
}

var ErrResourceServerNotFound = errors.New("resource server not found")
var ErrResourceURIInUse = errors.New("resource_uri already in use")

// CreateResourceServerInput is the API-level input for creating an Application.
type CreateResourceServerInput struct {
	TenantID          string
	ApplicationType   string
	Name              string
	PublicBaseURL     string
	ProtectedBasePath string
	ResourceURI       string
	ScopesSupported   []string
	RegistrationModes []string
	SetupCompletedBy  *uuid.UUID
}

// Create writes the tenant-DB resource_servers row AND the master-DB
// resource_server_tenant_index row in a best-effort lockstep. If the master
// index write fails after the tenant row is written, the tenant row is
// rolled back to keep the invariant.
func (s *ResourceServerService) Create(in CreateResourceServerInput) (*models.ResourceServer, error) {
	if in.TenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}
	if in.ResourceURI == "" {
		return nil, fmt.Errorf("resource_uri is required")
	}
	if in.ApplicationType == "" {
		in.ApplicationType = models.ApplicationTypeMCPServer
	}
	if in.ProtectedBasePath == "" {
		in.ProtectedBasePath = "/mcp"
	}
	if len(in.RegistrationModes) == 0 {
		in.RegistrationModes = []string{"dcr", "cimd", "prereg"}
	}

	tenantUUID, err := uuid.Parse(in.TenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant_id not a valid uuid: %w", err)
	}

	// Master-side uniqueness check on the index — the source of truth for
	// "is this resource_uri already taken".
	var indexCount int64
	if err := config.DB.Model(&models.ResourceServerTenantIndex{}).
		Where("resource_uri = ?", in.ResourceURI).
		Count(&indexCount).Error; err != nil {
		return nil, fmt.Errorf("check master index: %w", err)
	}
	if indexCount > 0 {
		return nil, ErrResourceURIInUse
	}

	tenantDB, err := config.GetTenantGORMDB(in.TenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}

	row := models.ResourceServer{
		TenantID:          in.TenantID,
		ApplicationType:   in.ApplicationType,
		Name:              in.Name,
		PublicBaseURL:     in.PublicBaseURL,
		ProtectedBasePath: in.ProtectedBasePath,
		ResourceURI:       in.ResourceURI,
		ScopesSupported:   in.ScopesSupported,
		RegistrationModes: in.RegistrationModes,
		Active:            true,
		State:             "pending_scan",
		Status:            "pending_scan",
		SetupCompletedBy:  in.SetupCompletedBy,
	}
	if err := tenantDB.Create(&row).Error; err != nil {
		return nil, fmt.Errorf("insert resource_servers: %w", err)
	}

	indexRow := models.ResourceServerTenantIndex{
		ResourceURI:      in.ResourceURI,
		TenantID:         tenantUUID,
		ResourceServerID: row.ID,
		Active:           true,
	}
	if err := config.DB.Create(&indexRow).Error; err != nil {
		// Roll back the tenant-DB row to preserve the invariant that every
		// resource_servers row has a master index entry.
		_ = tenantDB.Delete(&row).Error
		return nil, fmt.Errorf("insert master index: %w", err)
	}

	return &row, nil
}

// GetByID loads the tenant's Application row by id.
func (s *ResourceServerService) GetByID(tenantID string, id uuid.UUID) (*models.ResourceServer, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	var row models.ResourceServer
	if err := tenantDB.Where("id = ? AND tenant_id = ?", id, tenantID).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrResourceServerNotFound
		}
		return nil, err
	}
	return &row, nil
}

// GetByResourceURI is the master-index lookup used by the DCR handler before
// it knows which tenant DB to query. Returns the resolved tenant_id along
// with the row.
func (s *ResourceServerService) GetByResourceURI(resourceURI string) (*models.ResourceServer, string, error) {
	var index models.ResourceServerTenantIndex
	if err := config.DB.Where("resource_uri = ? AND active = true", resourceURI).First(&index).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, "", ErrResourceServerNotFound
		}
		return nil, "", err
	}
	tenantIDStr := index.TenantID.String()
	tenantDB, err := config.GetTenantGORMDB(tenantIDStr)
	if err != nil {
		return nil, "", fmt.Errorf("get tenant db: %w", err)
	}
	var row models.ResourceServer
	if err := tenantDB.Where("id = ?", index.ResourceServerID).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, "", ErrResourceServerNotFound
		}
		return nil, "", err
	}
	return &row, tenantIDStr, nil
}

// List returns the tenant's Application rows (newest first).
func (s *ResourceServerService) List(tenantID string) ([]models.ResourceServer, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	var rows []models.ResourceServer
	if err := tenantDB.Where("tenant_id = ?", tenantID).
		Order("created_at DESC").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// AllowsRegistrationMode reports whether the resource server is configured to
// accept the given registration mode (e.g. "dcr").
func AllowsRegistrationMode(rs *models.ResourceServer, mode string) bool {
	if rs == nil {
		return false
	}
	for _, m := range rs.RegistrationModes {
		if m == mode {
			return true
		}
	}
	return false
}

// ApplicationClient is the join shape returned by ListClientsForApplication —
// the tenant-DB registration row plus the master-DB client metadata that
// makes it useful in a UI (client_name, scope, sync_status).
type ApplicationClient struct {
	RegistrationID   uuid.UUID `json:"registration_id"`
	ClientID         string    `json:"client_id"`
	ClientName       string    `json:"client_name,omitempty"`
	RegistrationType string    `json:"registration_type"`
	Status           string    `json:"status"`
	Scope            string    `json:"scope,omitempty"`
	SyncStatus       string    `json:"sync_status"`
	RegisteredAt     time.Time `json:"registered_at"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
}

// ListClientsForApplication walks resource_server_client_registrations in the
// tenant DB to find every client that registered against the given
// Application, then fans out to master to hydrate the rows with mcp_oauth_clients
// metadata. Cross-DB join, so we do it in two queries.
func (s *ResourceServerService) ListClientsForApplication(tenantID string, applicationID uuid.UUID) ([]ApplicationClient, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	// Confirm the Application belongs to the tenant (defence in depth — the
	// caller already passes tenant_id from JWT, but a malicious id param
	// would otherwise leak existence).
	var rsCount int64
	if err := tenantDB.Model(&models.ResourceServer{}).
		Where("id = ? AND tenant_id = ?", applicationID, tenantID).
		Count(&rsCount).Error; err != nil {
		return nil, fmt.Errorf("verify application: %w", err)
	}
	if rsCount == 0 {
		return nil, ErrResourceServerNotFound
	}

	var regs []models.ResourceServerClientRegistration
	if err := tenantDB.Where("resource_server_id = ?", applicationID).
		Order("created_at DESC").Find(&regs).Error; err != nil {
		return nil, fmt.Errorf("list registrations: %w", err)
	}
	if len(regs) == 0 {
		return []ApplicationClient{}, nil
	}

	clientIDs := make([]string, 0, len(regs))
	for _, r := range regs {
		clientIDs = append(clientIDs, r.ClientID)
	}
	var clients []models.MCPOAuthClient
	if err := config.DB.Where("client_id IN ?", clientIDs).
		Find(&clients).Error; err != nil {
		return nil, fmt.Errorf("hydrate clients: %w", err)
	}
	clientByID := make(map[string]models.MCPOAuthClient, len(clients))
	for _, c := range clients {
		clientByID[c.ClientID] = c
	}

	out := make([]ApplicationClient, 0, len(regs))
	for _, r := range regs {
		row := ApplicationClient{
			RegistrationID:   r.ID,
			ClientID:         r.ClientID,
			RegistrationType: r.RegistrationType,
			Status:           r.Status,
			RegisteredAt:     r.CreatedAt,
			RevokedAt:        r.RevokedAt,
		}
		if c, ok := clientByID[r.ClientID]; ok {
			row.ClientName = c.ClientName
			row.Scope = c.Scope
			row.SyncStatus = c.SyncStatus
		}
		out = append(out, row)
	}
	return out, nil
}

// SoftDelete marks the tenant-DB row and the master-DB index inactive.
func (s *ResourceServerService) SoftDelete(tenantID string, id uuid.UUID) error {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return fmt.Errorf("get tenant db: %w", err)
	}
	var row models.ResourceServer
	if err := tenantDB.Where("id = ? AND tenant_id = ?", id, tenantID).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrResourceServerNotFound
		}
		return err
	}
	now := time.Now()
	if err := tenantDB.Model(&row).Updates(map[string]interface{}{
		"active":     false,
		"deleted_at": now,
		"updated_at": now,
	}).Error; err != nil {
		return fmt.Errorf("soft delete resource_server: %w", err)
	}
	if err := config.DB.Model(&models.ResourceServerTenantIndex{}).
		Where("resource_uri = ?", row.ResourceURI).
		Updates(map[string]interface{}{
			"active":     false,
			"updated_at": now,
		}).Error; err != nil {
		return fmt.Errorf("deactivate master index: %w", err)
	}
	return nil
}
